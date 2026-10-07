// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_staging.hpp
 * @brief Exact worker-input queue roles and boundary future-output ownership.
 * @author Fleming Patel
 *
 * Source workers own equal-capacity active/future queue pairs on their exact
 * NUMA node. Queue roles change only through an O(1) owner-pointer exchange;
 * elements are never scanned, copied, or resized. Each boundary separately
 * owns one sender-NUMA pointer-only future-output hold. Neither component owns
 * epoch identity, commit, boundary gating, CUT/ACK, or activation policy.
 */

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <type_traits>
#include <utility>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/numa_spsc_ring.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

/**
 * @brief Own active and optional future input queues for one worker/domain.
 *
 * @tparam value_type Exact owner-local work item stored in each role queue.
 *
 * @par Ownership
 * One packet worker owns every reservation, push, pop, and role rotation. A
 * successful reservation is linear until committed or released. Foreign code
 * receives no queue pointer or mutable reservation state.
 *
 * @par Thread Safety
 * The exact packet worker is the sole caller of every mutable operation and
 * role observation. Construction and destruction are cold-owner operations;
 * no foreign reader may inspect reservation or queue-role state. The complete
 * owner is cache-line aligned so another worker's reservation counters cannot
 * share its mutable line.
 *
 * @par Performance
 * Construction performs all allocation and NUMA placement. Reserve, commit,
 * release, and queue operations are O(1). Rotation is one unique-owner pointer
 * exchange and performs no element work.
 */
template <typename value_type>
class alignas(kinetum::algo::CACHE_LINE_SIZE) worker_epoch_input_staging final {
	static_assert(std::is_nothrow_move_constructible_v<value_type>,
		      "worker epoch-staging values must move-construct without failure");
	static_assert(std::is_nothrow_move_assignable_v<value_type>,
		      "worker epoch-staging values must move-assign without failure");

    public:
	/**
	 * @brief Materialize one active queue and an optional equal-capacity future queue.
	 *
	 * @param active_capacity Exact active-role capacity.
	 * @param future_capacity Equal future-role capacity for a source domain, or absent.
	 * @param numa_node Exact worker-local host NUMA node.
	 * @return Unique complete owner, or a fail-closed allocation/shape status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_epoch_input_staging>>
	create(std::size_t active_capacity, std::optional<std::size_t> future_capacity, int32_t numa_node)
	{
		if (future_capacity.has_value() && future_capacity.value() != active_capacity) {
			return common::status::invalid_argument(
				"worker epoch input queues require one exact capacity for both roles");
		}
		auto active_or = numa_spsc_ring<value_type>::create(active_capacity, numa_node);
		if (!active_or.is_ok()) {
			return active_or.error();
		}
		std::unique_ptr<numa_spsc_ring<value_type>> future;
		if (future_capacity.has_value()) {
			auto future_or = numa_spsc_ring<value_type>::create(future_capacity.value(), numa_node);
			if (!future_or.is_ok()) {
				return future_or.error();
			}
			future = std::move(future_or).value();
		}
		auto *owner = new (std::nothrow)
			worker_epoch_input_staging(std::move(active_or).value(), std::move(future), numa_node);
		if (owner == nullptr) {
			return common::status::resource_exhausted("worker epoch input-staging owner allocation failed");
		}
		return std::unique_ptr<worker_epoch_input_staging>(owner);
	}

	/** @brief Reject copying because queue and reservation ownership are linear. */
	worker_epoch_input_staging(const worker_epoch_input_staging &) = delete;
	/** @brief Reject copy assignment because role ownership cannot be duplicated. */
	worker_epoch_input_staging &operator=(const worker_epoch_input_staging &) = delete;
	/** @brief Reject moving so kernel-held staging addresses remain stable. */
	worker_epoch_input_staging(worker_epoch_input_staging &&) = delete;
	/** @brief Reject move assignment so role owners cannot be replaced. */
	worker_epoch_input_staging &operator=(worker_epoch_input_staging &&) = delete;

	/** @brief Destroy only empty queues with no unresolved slot reservation. */
	~worker_epoch_input_staging()
	{
		if (active_reservations_ != 0u || future_reservations_ != 0u || !active_->empty() ||
		    (future_ != nullptr && !future_->empty())) {
			std::terminate();
		}
	}

	/** @return true when this exact source domain owns a future role. */
	[[nodiscard]] bool has_future() const noexcept
	{
		return future_ != nullptr;
	}

	/** @return Exact active-role capacity. */
	[[nodiscard]] std::size_t active_capacity() const noexcept
	{
		return active_->capacity();
	}

	/** @return Exact future-role capacity, or zero when absent. */
	[[nodiscard]] std::size_t future_capacity() const noexcept
	{
		return future_ != nullptr ? future_->capacity() : 0u;
	}

	/** @return Exact proven worker-local NUMA node. */
	[[nodiscard]] int32_t numa_node() const noexcept
	{
		return numa_node_;
	}

	/** @return Observational active-role free slots after queue publication. */
	[[nodiscard]] std::size_t active_available() const noexcept
	{
		const std::size_t available = active_->available();
		if (available < active_reservations_) {
			std::terminate();
		}
		return available - active_reservations_;
	}

	/** @return Observational future-role free slots after queue publication. */
	[[nodiscard]] std::size_t future_available() const noexcept
	{
		if (future_ == nullptr) {
			return 0u;
		}
		const std::size_t available = future_->available();
		if (available < future_reservations_) {
			std::terminate();
		}
		return available - future_reservations_;
	}

	/** @return true after retaining one linear active-role publication slot. */
	[[nodiscard]] bool reserve_active() noexcept
	{
		return reserve_(*active_, active_reservations_);
	}

	/** @return true after retaining one linear future-role publication slot. */
	[[nodiscard]] bool reserve_future() noexcept
	{
		if (future_ == nullptr) {
			std::terminate();
		}
		return reserve_(*future_, future_reservations_);
	}

	/**
	 * @brief Publish one item through an exact active-role reservation.
	 *
	 * @param item Sole item consumed after the reservation is retired.
	 */
	void commit_active(value_type &&item) noexcept
	{
		commit_(*active_, active_reservations_, std::move(item));
	}

	/**
	 * @brief Publish one item through an exact future-role reservation.
	 *
	 * @param item Sole item consumed after the reservation is retired.
	 */
	void commit_future(value_type &&item) noexcept
	{
		if (future_ == nullptr) {
			std::terminate();
		}
		commit_(*future_, future_reservations_, std::move(item));
	}

	/** @brief Release one unused active-role reservation. */
	void release_active_reservation() noexcept
	{
		release_reservation_(active_reservations_);
	}

	/** @brief Release one unused future-role reservation. */
	void release_future_reservation() noexcept
	{
		if (future_ == nullptr) {
			std::terminate();
		}
		release_reservation_(future_reservations_);
	}

	/**
	 * @brief Consume one bounded active-role prefix into initialized storage.
	 *
	 * @param[out] out Contiguous initialized output; nonnull when @p count is nonzero.
	 * @param count Maximum number of values to consume.
	 * @return Number of values transferred, in `[0, count]`.
	 */
	[[nodiscard]] std::size_t pop_active_batch(value_type *out, std::size_t count) noexcept
		requires std::is_nothrow_move_assignable_v<value_type>
	{
		return active_->pop_batch(out, count);
	}

	/** @return Borrowed active-role front item, or null when empty. */
	[[nodiscard]] const value_type *peek_active() const noexcept
	{
		return active_->peek();
	}

	/** @return Borrowed future-role front item, or null when absent or empty. */
	[[nodiscard]] const value_type *peek_future() const noexcept
	{
		return future_ != nullptr ? future_->peek() : nullptr;
	}

	/** @return true when the active queue and its reservations are empty. */
	[[nodiscard]] bool active_empty() const noexcept
	{
		return active_reservations_ == 0u && active_->empty();
	}

	/** @return true when the absent/future queue and its reservations are empty. */
	[[nodiscard]] bool future_empty() const noexcept
	{
		return future_reservations_ == 0u && (future_ == nullptr || future_->empty());
	}

	/** @return true only when both role queues and reservation ledgers are empty. */
	[[nodiscard]] bool empty() const noexcept
	{
		return active_empty() && future_empty();
	}

	/**
	 * @brief Prove role rotation can complete without partial mutation.
	 *
	 * The future queue may contain target work. The old active queue and both
	 * unpublished reservation counts must be empty before any participant starts
	 * irreversible activation.
	 *
	 * @return true when `rotate_after_activation()` is a bounded pointer swap.
	 */
	[[nodiscard]] bool activation_ready() const noexcept
	{
		return future_ != nullptr && active_->empty() && active_reservations_ == 0u &&
		       future_reservations_ == 0u;
	}

	/**
	 * @brief Exchange active/future queue roles without touching an element.
	 *
	 * The old active queue must be empty and no callback reservation may survive
	 * the activation boundary. The future queue may contain staged work and
	 * becomes the new active queue immediately. Missing future ownership or any
	 * unresolved old state is terminate-class after commit.
	 */
	void rotate_after_activation() noexcept
	{
		if (!activation_ready()) {
			std::terminate();
		}
		std::swap(active_, future_);
	}

    private:
	/**
	 * @brief Retain one queue slot without publishing an element.
	 *
	 * @param queue Exact role queue whose free slots are observed.
	 * @param[in,out] reservations Sole owner-local unpublished-slot count.
	 * @return true after one reservation is retained; false when full.
	 */
	[[nodiscard]] static bool reserve_(const numa_spsc_ring<value_type> &queue, std::size_t &reservations) noexcept
	{
		const std::size_t available = queue.available();
		if (available < reservations) {
			std::terminate();
		}
		if (available == reservations) {
			return false;
		}
		++reservations;
		return true;
	}

	/**
	 * @brief Consume one reservation and publish its exact item.
	 *
	 * @param queue Exact role queue receiving the item.
	 * @param[in,out] reservations Sole owner-local unpublished-slot count.
	 * @param item Sole item transferred into @p queue.
	 */
	static void commit_(numa_spsc_ring<value_type> &queue, std::size_t &reservations, value_type &&item) noexcept
	{
		if (reservations == 0u) {
			std::terminate();
		}
		--reservations;
		if (!queue.try_push(std::move(item))) {
			std::terminate();
		}
	}

	/**
	 * @brief Consume one reservation without publishing an item.
	 *
	 * @param[in,out] reservations Sole owner-local unpublished-slot count.
	 */
	static void release_reservation_(std::size_t &reservations) noexcept
	{
		if (reservations == 0u) {
			std::terminate();
		}
		--reservations;
	}

	/**
	 * @brief Adopt complete active and optional future queue owners.
	 *
	 * @param active Sole exact active-role queue owner.
	 * @param future Sole exact future-role queue owner, or null when absent.
	 * @param numa_node Exact proven host NUMA node shared by present queues.
	 */
	worker_epoch_input_staging(std::unique_ptr<numa_spsc_ring<value_type>> active,
				   std::unique_ptr<numa_spsc_ring<value_type>> future, int32_t numa_node) noexcept
		: active_(std::move(active))
		, future_(std::move(future))
		, numa_node_(numa_node)
	{
		if (active_ == nullptr || !active_->empty() || (future_ != nullptr && !future_->empty()) ||
		    active_->numa_node() != numa_node_ || (future_ != nullptr && future_->numa_node() != numa_node_) ||
		    (future_ != nullptr && future_->capacity() != active_->capacity())) {
			std::terminate();
		}
	}

	std::unique_ptr<numa_spsc_ring<value_type>> active_;  ///< Current executable-role queue.
	std::unique_ptr<numa_spsc_ring<value_type>> future_;  ///< Future source-role queue, when present.
	std::size_t active_reservations_{0};		      ///< Linear unpublished active slots.
	std::size_t future_reservations_{0};		      ///< Linear unpublished future slots.
	int32_t numa_node_{-1};				      ///< Exact worker-local host NUMA node.
};

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
 * Construction allocates and binds once. Hold, release, and observation are
 * O(1), allocate nothing, and perform no policy lookup.
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
	[[nodiscard]] static common::status_or<std::unique_ptr<boundary_future_output_hold>>
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
	 * @brief Retain one exact packet pointer when hold capacity remains.
	 *
	 * @param record Nonnull packet ownership offered by the sender worker.
	 * @return true after transfer to the hold; false when full.
	 */
	[[nodiscard]] bool try_hold(packet_record *record) noexcept;
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
	 * @param sender_numa_node Exact sender-worker host NUMA node.
	 * @param queue Sole empty pointer-ring owner.
	 */
	boundary_future_output_hold(const common::compiled_transition_boundary &facts, int32_t sender_numa_node,
				    std::unique_ptr<numa_spsc_ring<packet_record *>> queue) noexcept;

	uint32_t boundary_index_{0};				  ///< Compact boundary identity.
	uint32_t sender_worker_index_{0};			  ///< Sole worker owner.
	int32_t numa_node_{-1};					  ///< Exact sender-worker host NUMA node.
	std::unique_ptr<numa_spsc_ring<packet_record *>> queue_;  ///< Pointer-only bounded ownership.
};

static_assert(sizeof(packet_record *) == sizeof(void *), "future-output hold must carry one machine-word pointer");
static_assert(std::is_trivially_copyable_v<packet_record *>, "future-output hold pointers must be trivially copyable");

}  // namespace kinetum::dp
