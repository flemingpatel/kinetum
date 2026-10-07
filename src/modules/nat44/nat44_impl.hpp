// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file nat44_impl.hpp
 * @brief NAT44 Module Implementation (Module-Owned, Self-Contained)
 * @author Fleming Patel
 *
 * This file contains the NAT44 translation logic for the NAT44 module.
 * Its strict JSON contract corresponds to the module-owned
 * kinetum.module.nat44.v1 schema and remains self-contained in the image.
 *
 * Design contract:
 * - The module owns its NAT configuration schema
 * - Platform routes opaque config_blob without interpretation
 * - Module deserializes and applies its own config format
 *
 * Hot-path context-owner design:
 * - Lock-free session tables (no mutex in hot path)
 * - Each admitted module context owns one preallocated nat44_table
 * - Allocates only the public-port residues owned by its exact context
 * - Follows Platform Engineering Guide: "No locks on hot path"
 * - Pre-allocated cuckoo_map + contiguous session slab: zero hot-path allocation
 *   (Platform Engineering Guide: "No malloc/free on hot path")
 *
 * Session Storage:
 * - Contiguous PMR session slab pre-sized from the exact INIT arena
 * - out_map / in_map: cuckoo_map with explicit field-wise key hashers
 * - Single canonical last_seen_ns per session (both directions share one entry)
 * - Bounded index pool for O(1) slab slot acquisition/release without growth
 *
 * Context ownership:
 * - Outbound selection and translated return-port selection name one context
 * - Its ordinal and population remain fixed for the complete runtime generation
 * - Hardware RSS distributes receive work and does not own NAT session identity
 */

#include <cstdint>
#include <memory_resource>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <kinetum/algo/bounded_index_pool.hpp>
#include <kinetum/algo/cidr.hpp>    // Header-owned strict IPv4 parser
#include <kinetum/algo/cuckoo.hpp>  // cuckoo_map (Platform Engineering Guide)
#include <kinetum/algo/hash.hpp>    // FNV1A_OFFSET_BASIS, FNV1A_PRIME
#include "src/modules/module_config_json.hpp"

namespace kinetum::modules::nat44
{

// =============================================================================
// NAT Types
// =============================================================================

/** @brief Generation-fixed public-port ownership within one configured module. */
struct context_partition {
	uint32_t ordinal;  ///< Exact zero-based module-context ordinal.
	uint32_t count;	   ///< Positive complete context population.
	/** @return true when every context can be represented by a nonzero transport-port residue. */
	[[nodiscard]] constexpr bool valid() const noexcept
	{
		return count != 0u && count <= UINT16_MAX && ordinal < count;
	}
	/** @return true only for the same generation ownership arithmetic. */
	[[nodiscard]] bool operator==(const context_partition &) const noexcept = default;
};

/** @brief GC trigger mask (run GC every 16K packets). */
inline constexpr uint64_t NAT_GC_TRIGGER_MASK = 0x3fffull;

/** @brief Maximum flows to evict per GC cycle. */
inline constexpr std::size_t NAT_GC_MAX_EVICTIONS = 256;

/** @brief Maximum slab entries to scan per GC cycle (bounded work). */
inline constexpr uint32_t NAT_GC_SCAN_LIMIT = 1024;

/** @brief Maximum allocation attempts before declaring pool exhausted. */
inline constexpr uint32_t NAT_MAX_ALLOC_ATTEMPTS = 1024;

/** @brief Default session timeout in seconds. */
inline constexpr uint32_t NAT_DEFAULT_TIMEOUT_S = 300;

/** @brief Default pre-allocated session capacity for one context table. */
inline constexpr uint32_t NAT_DEFAULT_MAX_SESSIONS = 65536;

/**
 * @brief IP address range
 */
struct ip_range {
	uint32_t start{0};	     ///< Start of range (inclusive)
	uint32_t end{0};	     ///< End of range (inclusive)
	uint64_t cumulative_end{0};  ///< Exclusive pool address ordinal after this range.
};

/**
 * @brief Compiled NAT pool
 */
struct nat_pool_compiled {
	/** @brief Construct variable storage. @param resource Exact policy-storage authority. */
	explicit nat_pool_compiled(std::pmr::memory_resource &resource)
		: public_ranges(&resource)
	{
	}
	/** @brief Reject copying because one PMR arena owns every range. */
	nat_pool_compiled(const nat_pool_compiled &) = delete;
	/** @brief Reject copy assignment because parsed publication is construction-fixed. */
	nat_pool_compiled &operator=(const nat_pool_compiled &) = delete;
	/** @brief Move-construct one unpublished pool with its exact allocator. */
	nat_pool_compiled(nat_pool_compiled &&) noexcept = default;
	/** @brief Reject move assignment because publication uses same-resource exchange. */
	nat_pool_compiled &operator=(nat_pool_compiled &&) = delete;

	std::pmr::vector<ip_range> public_ranges;  ///< Sorted disjoint public address ranges.
	uint64_t total_public_ips{0};		   ///< Precomputed address-space cardinality.
	uint16_t port_min{1024};		   ///< Inclusive public transport-port minimum.
	uint16_t port_max{65535};		   ///< Inclusive public transport-port maximum.
	uint16_t first_owned_port{0};		   ///< First configured port with this context's residue.
	uint32_t owned_port_count{0};		   ///< Exact number of eligible ports for each public address.
};

static_assert(std::is_nothrow_move_constructible_v<nat_pool_compiled>, "NAT pool transfer must remain nonthrowing");

/**
 * @brief Compiled NAT pools configuration
 */
struct nat_pools_compiled {
	/**
	 * @brief Construct one immutable context-specific policy.
	 * @param resource Exact policy-storage authority.
	 * @param owner Generation-fixed context partition.
	 */
	nat_pools_compiled(std::pmr::memory_resource &resource, context_partition owner)
		: pools(&resource)
		, partition(owner)
	{
	}
	/** @brief Reject copying because one PMR arena owns every pool. */
	nat_pools_compiled(const nat_pools_compiled &) = delete;
	/** @brief Reject copy assignment because policy publication is construction-fixed. */
	nat_pools_compiled &operator=(const nat_pools_compiled &) = delete;
	/** @brief Move-construct one unpublished policy with its exact allocator. */
	nat_pools_compiled(nat_pools_compiled &&) noexcept = default;
	/** @brief Reject move assignment because publication uses same-resource exchange. */
	nat_pools_compiled &operator=(nat_pools_compiled &&) = delete;

	std::pmr::vector<nat_pool_compiled> pools;	    ///< Authored nonempty public-pool collection.
	const context_partition partition;		    ///< Exact immutable owner of every eligible port.
	uint32_t session_timeout_s{NAT_DEFAULT_TIMEOUT_S};  ///< Positive idle timeout in seconds.
	uint32_t max_sessions{NAT_DEFAULT_MAX_SESSIONS};    ///< Exact configured per-context capacity across its pools.
};

static_assert(std::is_nothrow_move_constructible_v<nat_pools_compiled>,
	      "NAT compiled policy transfer must remain nonthrowing");

/**
 * @brief NAT session entry (stored in contiguous slab)
 *
 * Field order: uint64_t first for natural 8-byte alignment, then 32-bit
 * fields, then 16-bit fields, then 8-bit fields. This avoids internal
 * padding and packs 2 entries per cache line (32 bytes each).
 *
 * The single canonical last_seen_ns is updated by both outbound and inbound
 * hits, ensuring GC sees the true most-recent activity for every session
 * regardless of traffic direction.
 */
struct nat_session {
	uint64_t last_seen_ns{0};   ///< Single canonical timestamp (both directions)
	uint32_t internal_ip{0};    ///< Internal-side IPv4 address.
	uint32_t remote_ip{0};	    ///< Remote peer IPv4 address.
	uint32_t public_ip{0};	    ///< Allocated public IPv4 address.
	uint16_t internal_port{0};  ///< Internal-side transport port.
	uint16_t remote_port{0};    ///< Remote peer transport port.
	uint16_t public_port{0};    ///< Allocated public transport port.
	uint8_t proto{0};	    ///< Exact IP protocol number.
	bool occupied{false};	    ///< True when slab slot is in use
};

/**
 * @brief Snapshot of NAT statistics (POD, copyable).
 */
struct nat_stats_snapshot {
	uint64_t active_sessions{0};	  ///< Current occupied session population.
	uint64_t total_created{0};	  ///< Sessions created since context initialization.
	uint64_t total_expired{0};	  ///< Sessions reclaimed after idle timeout.
	uint64_t allocation_failures{0};  ///< New-session attempts rejected by capacity.
	uint64_t inbound_misses{0};	  ///< Unsolicited inbound tuples without a session.
};

/**
 * @brief Owner-local NAT statistics.
 *
 * The module context's sole packet worker is the only reader and writer.
 */
struct nat_stats {
	uint64_t active_sessions{0};	  ///< Current occupied session population.
	uint64_t total_created{0};	  ///< Sessions created since context initialization.
	uint64_t total_expired{0};	  ///< Sessions reclaimed after idle timeout.
	uint64_t allocation_failures{0};  ///< New-session attempts rejected by capacity.
	uint64_t inbound_misses{0};	  ///< Unsolicited inbound tuples without a session.

	/** @return Stable copy of every current owner-local counter. */
	[[nodiscard]] nat_stats_snapshot snapshot() const noexcept
	{
		return nat_stats_snapshot{active_sessions, total_created, total_expired, allocation_failures,
					  inbound_misses};
	}
};

// =============================================================================
// NAT44 Session Table (Single-Owner, Pre-Allocated)
// =============================================================================

/**
 * @brief Single-owner NAT44 session table with preallocated storage.
 *
 * Implements stateful NAT with:
 * - Lock-free design (no mutex in hot path)
 * - One admitted context and one owner worker per table
 * - Deterministic port allocation (no RNG)
 * - Incremental garbage collection with cursor-based slab walk
 * - Pre-allocated cuckoo_map + contiguous session slab (zero hot-path malloc)
 * - Single canonical timestamp per session (GC-safe for both directions)
 *
 * Thread Safety:
 * - Designed for sole owner-worker access
 * - Compiled module selection sends each direction to the exact session owner
 * - NO LOCKS - caller must ensure single-writer access
 *
 * Performance (Platform Engineering Guide aligned):
 * - Context-local ownership eliminates lock contention
 * - cuckoo_map: O(1) worst-case lookup (2 bucket checks + prefetch)
 * - Contiguous slab: cache-friendly GC iteration
 * - Bounded index pool: O(1) slot acquisition/release without growth
 * - Follows Platform Engineering Guide hot-path rules
 */
class nat44_table {
    public:
	/**
	 * @brief Construct session table with pre-allocated capacity.
	 *
	 * All memory is allocated here (construction-time, cold path).
	 * No allocation occurs during translate() or GC (hot path).
	 *
	 * @param max_sessions Maximum concurrent sessions (slab capacity).
	 * @param memory_resource Exact context-lifetime storage authority.
	 * @param owner Exact generation-fixed context ordinal and population.
	 */
	nat44_table(uint32_t max_sessions, std::pmr::memory_resource &memory_resource, context_partition owner);

	/** @return Immutable generation identity retained by every live session. */
	[[nodiscard]] context_partition partition() const noexcept
	{
		return partition_;
	}

	/** @return Stable copy of owner-local session statistics. */
	[[nodiscard]] nat_stats_snapshot get_stats() const noexcept;

	/**
	 * @brief Translate packet addresses
	 *
	 * @param now_ns Current timestamp
	 * @param pools Prepared pools for the table's exact context partition.
	 * @pre pools.partition equals partition(); the module's activation gate proves this before packet execution.
	 * @param outbound true=SNAT (internal->public), false=DNAT (public->internal)
	 * @param proto L4 protocol
	 * @param src_ip Source IP
	 * @param src_port Source port
	 * @param dst_ip Destination IP
	 * @param dst_port Destination port
	 * @param out_ip Output translated IP
	 * @param out_port Output translated port
	 * @return true if translation succeeded
	 */
	[[nodiscard]] bool translate(uint64_t now_ns, const nat_pools_compiled &pools, bool outbound, uint8_t proto,
				     uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
				     uint32_t *out_ip, uint16_t *out_port);

    private:
	/** @brief Outbound protocol/internal/remote tuple indexing one session. */
	struct out_key {
		uint8_t proto;		 ///< Exact IP protocol number.
		uint32_t internal_ip;	 ///< Internal-side IPv4 address.
		uint16_t internal_port;	 ///< Internal-side transport port.
		uint32_t remote_ip;	 ///< Remote peer IPv4 address.
		uint16_t remote_port;	 ///< Remote peer transport port.

		/** @param o Candidate semantic key. @return True when every tuple field matches. */
		bool operator==(const out_key &o) const noexcept
		{
			return proto == o.proto && internal_ip == o.internal_ip && internal_port == o.internal_port &&
			       remote_ip == o.remote_ip && remote_port == o.remote_port;
		}
	};

	/** @brief Inbound protocol/public/remote tuple indexing one session. */
	struct in_key {
		uint8_t proto;	       ///< Exact IP protocol number.
		uint32_t public_ip;    ///< Allocated public IPv4 address.
		uint16_t public_port;  ///< Allocated public transport port.
		uint32_t remote_ip;    ///< Remote peer IPv4 address.
		uint16_t remote_port;  ///< Remote peer transport port.

		/** @param o Candidate semantic key. @return True when every tuple field matches. */
		bool operator==(const in_key &o) const noexcept
		{
			return proto == o.proto && public_ip == o.public_ip && public_port == o.public_port &&
			       remote_ip == o.remote_ip && remote_port == o.remote_port;
		}
	};

	/** @brief Field-wise FNV-1a hasher excluding @ref out_key padding. */
	struct out_key_hash {
		/** @param k Semantic key to hash. @return Field-wise hash excluding padding. */
		std::size_t operator()(const out_key &k) const noexcept
		{
			std::size_t h = kinetum::algo::FNV1A_OFFSET_BASIS;
			h ^= k.proto;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.internal_ip;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.internal_port;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.remote_ip;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.remote_port;
			return h;
		}
	};

	/** @brief Field-wise FNV-1a hasher excluding @ref in_key padding. */
	struct in_key_hash {
		/** @param k Semantic key to hash. @return Field-wise hash excluding padding. */
		std::size_t operator()(const in_key &k) const noexcept
		{
			std::size_t h = kinetum::algo::FNV1A_OFFSET_BASIS;
			h ^= k.proto;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.public_ip;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.public_port;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.remote_ip;
			h *= kinetum::algo::FNV1A_PRIME;
			h ^= k.remote_port;
			return h;
		}
	};

	// -------------------------------------------------------------------------
	// Session storage: contiguous slab + cuckoo index maps
	// -------------------------------------------------------------------------

	const context_partition partition_;   ///< Sole generation-fixed public-port ownership.
	std::pmr::vector<nat_session> slab_;  ///< Fixed context-lifetime session slab.

	kinetum::algo::bounded_index_pool free_indices_;  ///< Fixed owner-local slab-index recycler.

	kinetum::algo::cuckoo_map<out_key, uint32_t, out_key_hash> out_map_;  ///< Outbound-to-slab index.
	kinetum::algo::cuckoo_map<in_key, uint32_t, in_key_hash> in_map_;     ///< Inbound-to-slab index.

	uint32_t max_sessions_;	     ///< Slab capacity
	uint64_t alloc_counter_{0};  ///< Deterministic address/port selection sequence.
	uint64_t gc_counter_{0};     ///< Packet-operation cadence for bounded GC.
	uint32_t gc_cursor_{0};	     ///< Cursor for incremental slab-walk GC
	nat_stats stats_;	     ///< Owner-local cumulative session statistics.

	/**
	 * @brief Acquire one slab entry and publish both direction keys atomically.
	 * @param pools Exact immutable NAT policy.
	 * @param now_ns Monotonic packet-arrival timestamp.
	 * @param proto IP protocol number.
	 * @param internal_ip Internal-side IPv4 address.
	 * @param internal_port Internal-side transport port.
	 * @param remote_ip Remote peer IPv4 address.
	 * @param remote_port Remote peer transport port.
	 * @param[out] out Complete session copy written only on success.
	 * @return True after exact dual-map publication; false on policy or capacity rejection.
	 */
	bool allocate_and_insert_(const nat_pools_compiled &pools, uint64_t now_ns, uint8_t proto, uint32_t internal_ip,
				  uint16_t internal_port, uint32_t remote_ip, uint16_t remote_port,
				  nat_session *out) noexcept;
	/**
	 * @brief Reclaim one bounded cursor slice of idle context-local sessions.
	 * @param now_ns Current monotonic packet-arrival time.
	 * @param timeout_ns Exact positive idle timeout in nanoseconds.
	 */
	void maybe_gc_(uint64_t now_ns, uint64_t timeout_ns) noexcept;
};

// =============================================================================
// NAT Compilation API
// =============================================================================

/**
 * @brief Compile one strict module-owned JSON NAT policy.
 *
 * Unknown or duplicate fields, alternate protobuf encodings, malformed UTF-8,
 * fractional numbers, invalid address/port ranges, and trailing content reject.
 *
 * @param data Exact JSON bytes corresponding to NatPools field names.
 * @param len Exact byte count.
 * @param memory_resource Exact storage authority for the compiled policy.
 * @param out Output replaced only after complete successful compilation.
 * @param cancellation Cooperative cold-path cancellation probe.
 * @return OK, INVALID, or CANCELLED.
 */
[[nodiscard]] config::compile_result compile_nat_from_json(const void *data, std::size_t len,
							   std::pmr::memory_resource *memory_resource,
							   nat_pools_compiled *out,
							   config::cancellation_probe cancellation = {});

}  // namespace kinetum::modules::nat44
