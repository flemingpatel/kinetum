// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_staging.hpp
 * @brief Exact boundary future-output ownership.
 * @author Fleming Patel
 *
 * Each boundary owns one sender-NUMA pointer-only future-output hold. Worker
 * active/future role sets live in worker_packet_staging. Neither storage owner
 * decides epoch identity, commit, boundary gating, CUT/ACK, or activation policy.
 */

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/numa_spsc_ring.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

/**
 * @brief Sender-owned pointer-only future-output staging for one boundary.
 *
 * @par Ownership
 * The exact sender worker is the sole producer and consumer. Each successful
 * hold retains one packet credit until successful release. Destruction with
 * any retained record fails stop.
 *
 * @par Thread Safety
 * The compiled sender worker is the sole caller of hold, release, and
 * observation operations. Construction and destruction are externally
 * serialized with packet-worker lifetime.
 *
 * @par Performance
 * Construction allocates and binds once. Holding n pointers is bounded O(n)
 * work; scalar release and observation are O(1). No operation allocates or
 * performs a policy lookup.
 */
class boundary_future_output_hold final {
    public:
	/**
	 * @brief Materialize one exact empty hold from compiled boundary truth.
	 *
	 * @param facts Exact compact boundary identity and capacity.
	 * @param sender_numa_node Exact sender-worker host NUMA node.
	 * @return Unique hold owner, or a fail-closed shape/allocation status.
	 */
	[[nodiscard]] static common::status_or<numa_owner<boundary_future_output_hold>>
	create(const common::compiled_transition_boundary &facts, int32_t sender_numa_node);

	/** @brief Reject copying because packet ownership cannot be duplicated. */
	boundary_future_output_hold(const boundary_future_output_hold &) = delete;
	/** @brief Reject copy assignment because boundary identity is stable. */
	boundary_future_output_hold &operator=(const boundary_future_output_hold &) = delete;
	/** @brief Reject moving so kernel-held addresses remain stable. */
	boundary_future_output_hold(boundary_future_output_hold &&) = delete;
	/** @brief Reject move assignment so sender ownership cannot be replaced. */
	boundary_future_output_hold &operator=(boundary_future_output_hold &&) = delete;

	/** @brief Destroy only after every held packet transfers or retires. */
	~boundary_future_output_hold();

	/**
	 * @brief Retain the capacity-admitted prefix of exact future packet ownership.
	 *
	 * @param records At most one worker burst of nonnull packet pointers.
	 * @return Exact retained prefix length; the caller retains the suffix.
	 */
	[[nodiscard]] std::size_t try_hold(std::span<packet_record *const> records) noexcept;
	/**
	 * @brief Transfer one FIFO packet pointer back to the sender worker.
	 *
	 * @param[out] record Destination changed only when ownership is available.
	 * @return true after one transfer; false when empty.
	 */
	[[nodiscard]] bool try_release(packet_record *&record) noexcept;
	/** @return Borrowed FIFO front record, or null when empty. */
	[[nodiscard]] const packet_record *peek() const noexcept;
	/** @return true when no packet ownership remains held. */
	[[nodiscard]] bool empty() const noexcept;
	/** @return Observational number of retained packet pointers. */
	[[nodiscard]] std::size_t size_approx() const noexcept;
	/** @return Exact plan-owned usable capacity. */
	[[nodiscard]] std::size_t capacity() const noexcept;
	/** @return Exact compact boundary identity. */
	[[nodiscard]] uint32_t boundary_index() const noexcept;
	/** @return Exact sole sender-worker identity. */
	[[nodiscard]] uint32_t sender_worker_index() const noexcept;
	/** @return Exact sender-worker NUMA node. */
	[[nodiscard]] int32_t numa_node() const noexcept;

    private:
	/**
	 * @brief Adopt one complete exact empty pointer queue.
	 *
	 * @param facts Exact compact boundary identity and capacity.
	 * @param region Proved sender-node mapping containing this root and elements.
	 * @param elements Exact checked pointer-ring storage.
	 */
	boundary_future_output_hold(const common::compiled_transition_boundary &facts, const numa_memory_region &region,
				    std::span<std::byte> elements) noexcept;

	uint32_t boundary_index_{0};		 ///< Compact boundary identity.
	uint32_t sender_worker_index_{0};	 ///< Sole worker owner.
	numa_spsc_ring<packet_record *> queue_;	 ///< Pointer-only bounded ownership in the hold's mapping.
};

static_assert(sizeof(packet_record *) == sizeof(void *), "future-output hold must carry one machine-word pointer");
static_assert(std::is_trivially_copyable_v<packet_record *>, "future-output hold pointers must be trivially copyable");

}  // namespace kinetum::dp
