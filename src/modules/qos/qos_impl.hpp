// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file qos_impl.hpp
 * @brief QoS Module Implementation (Module-Owned, Self-Contained)
 * @author Fleming Patel
 *
 * This file contains the token bucket QoS policing logic for the QoS module.
 * Its strict JSON contract corresponds to the module-owned
 * kinetum.module.qos.v1 schema and remains self-contained in the image.
 *
 * Design Philosophy:
 * - Module is the SOURCE OF TRUTH for QoS configuration schema
 * - Platform routes opaque config_blob without interpretation
 * - Module deserializes and applies its own config format
 *
 * Hot-Path Optimization (Context-Owner Design):
 * - Each admitted module context owns one preallocated policer
 * - NO LOCKS in hot path - one packet worker is the sole writer
 * - RSS keeps each flow on the same owner worker
 * - One bounded index pool recycles preallocated slab entries without growth
 * - Follows Platform Engineering Guide: "No locks on hot path"
 */

#include <cstdint>
#include <limits>
#include <memory_resource>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <kinetum/algo/bounded_index_pool.hpp>
#include <kinetum/algo/cuckoo.hpp>
#include "src/modules/module_config_json.hpp"

namespace kinetum::modules::qos
{

// =============================================================================
// Constants
// =============================================================================

/** @brief Default mask that schedules one GC cycle per 65,536 packets. */
inline constexpr uint64_t DEFAULT_QOS_GC_TRIGGER_MASK = 0xffffull;

/** @brief Default maximum number of flows reclaimed by one GC cycle. */
inline constexpr std::size_t DEFAULT_QOS_GC_MAX_EVICTIONS = 256;

/** @brief Default flow-bucket idle timeout in nanoseconds. */
inline constexpr uint64_t DEFAULT_QOS_IDLE_TIMEOUT_NS = 30ull * 1000000000ull;

/** @brief Default pre-allocated flow capacity for one context-local slab. */
inline constexpr uint32_t QOS_DEFAULT_MAX_FLOWS = 65536;

/** @brief Maximum slab entries inspected by one bounded GC cycle. */
inline constexpr uint32_t DEFAULT_QOS_GC_SCAN_LIMIT = 1024;

/** @brief Fractional bit count used by fixed-point token accounting. */
inline constexpr int QOS_FIXED_POINT_SHIFT = 20;

/** @brief Largest burst representable by the signed fixed-point accumulator. */
inline constexpr uint64_t QOS_MAX_BURST_BYTES =
	static_cast<uint64_t>(std::numeric_limits<int64_t>::max() >> QOS_FIXED_POINT_SHIFT);

/** @brief Largest `cbs_kb` accepted by the QoS config compiler. */
inline constexpr int64_t QOS_MAX_CBS_KB = static_cast<int64_t>(QOS_MAX_BURST_BYTES / 1024);

/** @brief Largest `cir_kbps` whose bytes-per-second conversion cannot overflow. */
inline constexpr int64_t QOS_MAX_CIR_KBPS = static_cast<int64_t>(std::numeric_limits<uint64_t>::max() / 1000ull);

/**
 * @brief Runtime GC tuning for lock-free QoS policer.
 */
struct qos_runtime_tuning {
	uint64_t gc_trigger_mask{DEFAULT_QOS_GC_TRIGGER_MASK};	     ///< Packet-counter mask that schedules GC.
	std::size_t gc_max_evictions{DEFAULT_QOS_GC_MAX_EVICTIONS};  ///< Maximum reclamations per GC cycle.
	uint64_t idle_timeout_ns{DEFAULT_QOS_IDLE_TIMEOUT_NS};	     ///< Flow idle timeout in nanoseconds.
};

// =============================================================================
// QoS Types
// =============================================================================

/**
 * @brief Compiled QoS profile
 */
struct qos_profile_compiled {
	/** @brief Construct variable storage. @param resource Exact policy-storage authority. */
	explicit qos_profile_compiled(std::pmr::memory_resource &resource)
		: name(&resource)
	{
	}
	/** @brief Reject copying because one PMR arena owns the profile name. */
	qos_profile_compiled(const qos_profile_compiled &) = delete;
	/** @brief Reject copy assignment because parsed publication is construction-fixed. */
	qos_profile_compiled &operator=(const qos_profile_compiled &) = delete;
	/** @brief Move-construct one unpublished profile with its exact allocator. */
	qos_profile_compiled(qos_profile_compiled &&) noexcept = default;
	/** @brief Reject move assignment because publication uses same-resource exchange. */
	qos_profile_compiled &operator=(qos_profile_compiled &&) = delete;

	std::pmr::string name;	      ///< Unique profile name within the compiled policy.
	uint64_t cir_bytes_per_s{0};  ///< Committed Information Rate in bytes/second
	uint64_t burst_bytes{0};      ///< Maximum burst size in bytes
	uint8_t conform_dscp{0};      ///< DSCP to remark on conform (0 = no remark)
};

static_assert(std::is_nothrow_move_constructible_v<qos_profile_compiled>,
	      "QoS profile transfer must remain nonthrowing");

/**
 * @brief Collection of QoS profiles
 */
struct qos_profiles_compiled {
	/** @brief Construct one immutable policy. @param resource Exact policy-storage authority. */
	explicit qos_profiles_compiled(std::pmr::memory_resource &resource)
		: default_profile(&resource)
		, profiles(&resource)
	{
	}
	/** @brief Reject copying because one PMR arena owns every profile. */
	qos_profiles_compiled(const qos_profiles_compiled &) = delete;
	/** @brief Reject copy assignment because policy publication is construction-fixed. */
	qos_profiles_compiled &operator=(const qos_profiles_compiled &) = delete;
	/** @brief Move-construct one unpublished policy with its exact allocator. */
	qos_profiles_compiled(qos_profiles_compiled &&) noexcept = default;
	/** @brief Reject move assignment because publication uses same-resource exchange. */
	qos_profiles_compiled &operator=(qos_profiles_compiled &&) = delete;

	std::pmr::string default_profile;		  ///< Default profile name from config.
	std::pmr::vector<qos_profile_compiled> profiles;  ///< Unique immutable profiles.
	qos_runtime_tuning runtime;			  ///< Bounded owner-local reclamation policy.

	/**
	 * @brief Resolve one exact profile without allocating.
	 * @param name Exact profile identity to find.
	 * @return Immutable profile pointer, or null when absent.
	 */
	[[nodiscard]] const qos_profile_compiled *find_profile(std::string_view name) const noexcept;
};

static_assert(std::is_nothrow_move_constructible_v<qos_profiles_compiled>,
	      "QoS compiled policy transfer must remain nonthrowing");

/**
 * @brief Per-flow token bucket policer (Single-Owner, Pre-Allocated)
 *
 * Implements rate limiting using token bucket algorithm with:
 * - Pre-allocated cuckoo_map + contiguous bucket slab (zero hot-path malloc)
 * - Fixed-point arithmetic (Q20) for precision
 * - Lock-free design for hot-path (no mutex, no shared_mutex)
 * - Incremental cursor-based garbage collection
 *
 * Storage Architecture (same pattern as NAT44):
 * - cuckoo_map: flow_key to slab index, O(1) worst-case, pre-allocated buckets
 * - Contiguous slab: cache-friendly bucket storage
 * - Bounded index pool: O(1) slot allocation/release without growth
 *
 * Thread Safety:
 * - Designed for one admitted context's sole packet worker
 * - RSS ensures the same flow always reaches the same owner worker
 * - NO LOCKS - caller must ensure single-writer access
 *
 * Hot-path properties:
 * - Cache-line aligned buckets
 * - No lock contention in the sole-owner access model
 * - Zero heap allocation on hot path
 * - Follows Platform Engineering Guide hot-path rules
 */
class qos_policer {
    public:
	/**
	 * @brief Construct a lock-free policer with pre-allocated capacity.
	 *
	 * All memory is allocated here (construction-time, cold path).
	 * No allocation occurs during allow() or GC (hot path).
	 *
	 * @param max_flows Maximum concurrent flows (slab capacity).
	 * @param memory_resource Exact context-lifetime storage authority.
	 *
	 * @note This policer is not thread-safe. The admitted module context must
	 *       preserve sole packet-worker ownership.
	 */
	explicit qos_policer(uint32_t max_flows, std::pmr::memory_resource &memory_resource);

	/** @return Current occupied flow-bucket population. */
	[[nodiscard]] uint64_t active_flows() const noexcept;

	/**
	 * @brief Check whether one packet conforms to its exact QoS profile.
	 *
	 * Existing flows retain token-bucket state across configuration activation,
	 * but retained credit is capped to the supplied profile's burst before
	 * refill or consumption. The method allocates no memory: existing flows use
	 * one cuckoo lookup, new flows consume a preallocated pool index, and
	 * capacity exhaustion drops fail-closed.
	 *
	 * @param now_ns Platform-stamped monotonic packet-arrival time in nanoseconds.
	 * @param profile Exact active profile containing rate and burst limits.
	 * @param runtime Bounded owner-local GC tuning.
	 * @param flow_key Stable flow identifier, normally the RSS five-tuple hash.
	 * @param bytes Packet length in bytes.
	 * @return true when the packet conforms; false when policing or capacity
	 *         admission drops it.
	 *
	 * @note Thread Safety: not thread-safe; call only on the context owner.
	 */
	[[nodiscard]] bool allow(uint64_t now_ns, const qos_profile_compiled &profile,
				 const qos_runtime_tuning &runtime, uint64_t flow_key, std::size_t bytes) noexcept;

    private:
	static constexpr int FP_SHIFT = QOS_FIXED_POINT_SHIFT;	///< Fixed-point fractional bit count.

	/** @brief Cache-line-isolated mutable state for one owner-local flow. */
	struct alignas(64) bucket {
		int64_t tokens_fp{0};  ///< Available bytes in Q20 fixed-point form.
		uint64_t last_ns{0};   ///< Monotonic packet-time high-watermark.
		uint64_t flow_key{0};  ///< Exact cuckoo-map key owning this slab slot.
		bool occupied{false};  ///< Whether the slot contributes live flow state.
	};

	/** @brief Supply one complete scalar identity for cuckoo candidate mixing. */
	struct flow_identity_hash {
		/**
		 * @brief Return one flow identity without reading object representation.
		 * @param flow_key Exact semantic flow identity.
		 * @return Complete scalar input to cuckoo's SplitMix64 candidate derivation.
		 */
		[[nodiscard]] std::size_t operator()(uint64_t flow_key) const noexcept
		{
			return static_cast<std::size_t>(flow_key);
		}
	};

	// -------------------------------------------------------------------------
	// Flow storage: contiguous slab + cuckoo index map + bounded index pool
	// -------------------------------------------------------------------------

	std::pmr::vector<bucket> slab_;	 ///< Fixed context-lifetime flow-bucket slab.

	kinetum::algo::bounded_index_pool free_indices_;  ///< Fixed owner-local slab-index recycler.

	kinetum::algo::cuckoo_map<uint64_t, uint32_t, flow_identity_hash> map_;	 ///< Flow-to-slab index.

	uint32_t max_flows_;	  ///< Fixed slab capacity.
	uint64_t gc_counter_{0};  ///< Packet-operation cadence for bounded GC.
	uint32_t gc_cursor_{0};	  ///< Cursor for incremental slab-walk GC.

	/**
	 * @brief Reclaim one bounded cursor slice of idle context-local flow buckets.
	 * @param now_ns Current monotonic packet-arrival time.
	 * @param runtime Exact bounded GC policy.
	 */
	void maybe_gc_(uint64_t now_ns, const qos_runtime_tuning &runtime) noexcept;
};

// =============================================================================
// QoS Compilation API
// =============================================================================

/**
 * @brief Compile one strict module-owned JSON QoS policy.
 *
 * Unknown or duplicate fields, alternate protobuf encodings, malformed UTF-8,
 * fractional numbers, invalid profile bounds, and trailing content reject.
 *
 * @param data Exact JSON bytes corresponding to QosProfiles field names.
 * @param len Exact byte count.
 * @param memory_resource Exact storage authority for the compiled policy.
 * @param out Output replaced only after complete successful compilation.
 * @param cancellation Cooperative cold-path cancellation probe.
 * @return OK, INVALID, or CANCELLED.
 */
[[nodiscard]] config::compile_result compile_qos_from_json(const void *data, std::size_t len,
							   std::pmr::memory_resource *memory_resource,
							   qos_profiles_compiled *out,
							   config::cancellation_probe cancellation = {});

}  // namespace kinetum::modules::qos
