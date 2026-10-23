// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_packet_staging.hpp
 * @brief Grouped packet staging with shared role capacity in one worker NUMA region.
 * @author Fleming Patel
 *
 * Each domain has an active role and, for transition sources, an equal-capacity
 * future role. Keys name executable stages and continuations; their rings hold
 * pointers only. Queue occupancy and outstanding reservations share one bound.
 * The worker's complete domain/role population is constructed before launch.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

#include <kinetum/algo/queue.hpp>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/numa_layout.hpp"
#include "src/dp/packet.hpp"
#include "src/dp/packet_work_key.hpp"

namespace kinetum::dp
{

/** @brief Cold input for one exact worker/storage-domain role set. */
struct worker_packet_staging_domain {
	uint32_t storage_domain_index{UINT32_MAX};   ///< Exact compiled storage-domain identity.
	std::size_t capacity{0u};		     ///< Aggregate active population, including outstanding ownership.
	std::optional<std::size_t> future_capacity;  ///< Equal capacity for a source future role, or absent.
	std::span<const packet_work_key> keys;	     ///< Sorted unique stage/phase identities; may be empty.
};

class worker_packet_staging;

/**
 * @brief Borrow one domain's swappable queue roles from the worker allocation.
 *
 * @par Ownership
 * Reservations are linear until committed or released. Removing a batch from
 * a ring retains its capacity through execution and foreign calls. The epoch
 * ledger, not this capacity counter, owns logical packet credits.
 *
 * @par Thread Safety
 * One worker owns every operation, including role rotation. Controls, ready
 * membership and ring storage are on that worker's exact NUMA node. Foreign
 * readers consume separate coherent publications and never inspect this state.
 *
 * @par Performance
 * Scalar operations are O(1). One service handles at most 64 records and visits
 * each initially ready key at most once. Rotation exchanges two role pointers.
 * No hot operation allocates, locks, reads a clock or publishes across threads.
 */
class alignas(algo::CACHE_LINE_SIZE) packet_epoch_input_staging final {
	friend class worker_packet_staging;
	using packet_queue = algo::work_queue_view<packet_record *>;  ///< Shared owner-local pointer arithmetic.
	using ready_queue = algo::work_queue_view<uint32_t>;	      ///< Shared owner-local ready-key arithmetic.
	static constexpr uint32_t NO_SERVICE = UINT32_MAX;  ///< No key currently borrowed by a service callback.

	/** @brief Mutable key controls, separated from all pointer arrays by construction. */
	struct key_state {
		/**
		 * @brief Bind one empty pointer ring to its exact key-major storage extent.
		 * @param storage Uninitialized pointer slots in the worker mapping.
		 * @param capacity Exact physical ring extent, equal to the shared role bound.
		 */
		key_state(packet_queue::storage_type *storage, std::size_t capacity) noexcept
			: queue(storage, capacity)
		{
		}
		packet_queue queue;   ///< Sole pointer-ring indices and element lifetimes.
		bool claimed{false};  ///< Ready or being serviced; prevents duplicate ready publication.
	};

	/** @brief One complete role whose capacity includes queued and outstanding records. */
	struct alignas(algo::CACHE_LINE_SIZE) role_state {
		/**
		 * @brief Bind complete empty role controls to their preallocated key and ready storage.
		 * @param key_states Exact constructed key controls.
		 * @param capacity Exact aggregate capacity shared by all keys and reservations.
		 * @param ready_storage Ready ordinals, null only for an empty key set.
		 * @param ready_capacity Checked physical ready extent, zero only for no keys.
		 */
		role_state(std::span<key_state> key_states, std::size_t capacity,
			   ready_queue::storage_type *ready_storage, std::size_t ready_capacity) noexcept
			: keys(key_states)
			, capacity(capacity)
		{
			if (!keys.empty()) {
				ready.emplace(ready_storage, ready_capacity);
			}
		}
		std::span<key_state> keys;	   ///< Exact constructed per-key controls.
		std::optional<ready_queue> ready;  ///< Present only when an executable key exists.
		std::size_t capacity{0u};	   ///< Fixed aggregate role population.
		std::size_t occupied{0u};	   ///< Sole authority for queued plus outstanding capacity.
		std::size_t reservations{0u};	   ///< Unpublished portion of occupied capacity.
		uint32_t servicing{NO_SERVICE};	   ///< Exact key whose ready membership is temporarily borrowed.
	};

    public:
	/** @brief Domain views have one placement and cannot duplicate their role authority. */
	packet_epoch_input_staging(const packet_epoch_input_staging &) = delete;
	/** @brief Reject assignment of a different domain's role ownership. */
	packet_epoch_input_staging &operator=(const packet_epoch_input_staging &) = delete;
	/** @brief Keep kernel and activation borrows stable until worker teardown. */
	packet_epoch_input_staging(packet_epoch_input_staging &&) = delete;
	/** @brief Reject replacement of live role borrows. */
	packet_epoch_input_staging &operator=(packet_epoch_input_staging &&) = delete;
	/** @brief The worker allocation owner destroys this view after its empty roles. */
	~packet_epoch_input_staging() = default;

	/** @return Exact compiled storage-domain identity. */
	[[nodiscard]] uint32_t storage_domain_index() const noexcept
	{
		return storage_domain_index_;
	}
	/** @return Immutable key identities shared by both roles. */
	[[nodiscard]] std::span<const packet_work_key> keys() const noexcept
	{
		return keys_;
	}
	/** @return Exact worker-local NUMA node proved at construction. */
	[[nodiscard]] int32_t numa_node() const noexcept
	{
		return numa_node_;
	}
	/** @return Whether this source domain owns a future role. */
	[[nodiscard]] bool has_future() const noexcept
	{
		return future_ != nullptr;
	}
	/** @return Aggregate active-role capacity, never the sum of physical ring extents. */
	[[nodiscard]] std::size_t active_capacity() const noexcept
	{
		return active_->capacity;
	}
	/** @return Equal future-role capacity, or zero when absent. */
	[[nodiscard]] std::size_t future_capacity() const noexcept
	{
		return future_ != nullptr ? future_->capacity : 0u;
	}
	/** @return Active capacity available to new ownership. */
	[[nodiscard]] std::size_t active_available() const noexcept
	{
		return available_(*active_);
	}
	/** @return Future capacity available to RX, or zero when absent. */
	[[nodiscard]] std::size_t future_available() const noexcept
	{
		return future_ != nullptr ? available_(*future_) : 0u;
	}
	/** @param count Exact requested claims. @return True after reserving the complete active population. */
	[[nodiscard]] bool reserve_active(std::size_t count = 1u) noexcept
	{
		return reserve_(*active_, count);
	}
	/** @param count Exact requested claims. @return True after reserving the complete future population. */
	[[nodiscard]] bool reserve_future(std::size_t count = 1u) noexcept
	{
		if (future_ == nullptr) {
			std::terminate();
		}
		return reserve_(*future_, count);
	}

	/**
	 * @brief Publish a pointer through an existing active reservation.
	 * @param key Exact construction-time key ordinal.
	 * @param record Nonnull pointer whose current identity agrees with that key.
	 */
	void commit_active(uint32_t key, packet_record *record) noexcept
	{
		commit_(*active_, key, record);
	}
	/**
	 * @brief Publish future RX through an existing future reservation.
	 * @param key Exact RX_DELIVER key ordinal; no other future producer is permitted.
	 * @param record Nonnull source-epoch packet ownership.
	 */
	void commit_future(uint32_t key, packet_record *record) noexcept
	{
		if (future_ == nullptr || key >= keys_.size() || keys_[key].phase != packet_work_phase::RX_DELIVER) {
			std::terminate();
		}
		commit_(*future_, key, record);
	}
	/** @brief Retire outstanding active claims. @param count Exact transferred or unused population. */
	void release_active_reservation(std::size_t count = 1u) noexcept
	{
		release_(*active_, count);
	}
	/** @brief Retire unused future RX claims. @param count Exact unused population. */
	void release_future_reservation(std::size_t count = 1u) noexcept
	{
		if (future_ == nullptr) {
			std::terminate();
		}
		release_(*future_, count);
	}

	/**
	 * @brief Service one bounded original ready prefix without releasing dequeued capacity.
	 * @tparam consume_type Nonthrowing callback accepting one key and pointer prefix.
	 * @param scratch Initialized pointer scratch of at most the worker burst bound.
	 * @param consume Resolves or retains every record's existing reservation; may enqueue.
	 *
	 * Each key is serviced at most once. Newly ready keys wait for another turn;
	 * appends to an already waiting key retain FIFO order. A nonempty remainder
	 * reserves its next ready position before callback-produced keys. Recursive service and
	 * role rotation during a callback violate sole ownership and terminate.
	 */
	template <typename consume_type>
	void service_active(std::span<packet_record *> scratch, consume_type &&consume) noexcept
	{
		static_assert(std::is_nothrow_invocable_v<consume_type &, const packet_work_key &,
							  std::span<packet_record *const>>);
		auto &role = *active_;
		if (role.servicing != NO_SERVICE || scratch.size() > common::runtime_sizing::PACKET_MAX_BURST_SIZE) {
			std::terminate();
		}
		if (!role.ready.has_value() || scratch.empty()) {
			return;
		}
		std::size_t remaining_keys = role.ready->size();
		std::size_t remaining_records = scratch.size();
		while (remaining_keys != 0u && remaining_records != 0u) {
			uint32_t key = NO_SERVICE;
			if (!role.ready->try_pop(key) || key >= role.keys.size()) {
				std::terminate();
			}
			auto &state = role.keys[key];
			if (!state.claimed || state.queue.empty()) {
				std::terminate();
			}
			const std::size_t count = state.queue.pop_batch(scratch.data(), remaining_records);
			if (role.reservations > role.occupied || count > role.occupied - role.reservations) {
				std::terminate();
			}
			role.reservations += count;
			const bool requeued = !state.queue.empty();
			if (requeued && !role.ready->try_push(key)) {
				std::terminate();
			}
			role.servicing = key;
			consume(keys_[key], std::span<packet_record *const>(scratch.data(), count));
			role.servicing = NO_SERVICE;
			if (!requeued) {
				if (state.queue.empty()) {
					state.claimed = false;
				} else if (!role.ready->try_push(key)) {
					std::terminate();
				}
			}
			remaining_records -= count;
			--remaining_keys;
		}
	}

	/** @return True when the active role has no queued, outstanding or executing ownership. */
	[[nodiscard]] bool active_empty() const noexcept
	{
		return empty_(*active_);
	}
	/** @return True when the absent/future role has no ownership. */
	[[nodiscard]] bool future_empty() const noexcept
	{
		return future_ == nullptr || empty_(*future_);
	}
	/** @return True only when both roles have retired all ownership. */
	[[nodiscard]] bool empty() const noexcept
	{
		return active_empty() && future_empty();
	}
	/** @return True when complete role exchange is possible without a scan or partial mutation. */
	[[nodiscard]] bool activation_ready() const noexcept
	{
		return future_ != nullptr && empty_(*active_) && future_->reservations == 0u &&
		       future_->servicing == NO_SERVICE;
	}
	/** @brief Exchange complete roles after old drain; future pointers and ready state move together. */
	void rotate_after_activation() noexcept
	{
		if (!activation_ready()) {
			std::terminate();
		}
		std::swap(active_, future_);
	}

    private:
	/**
	 * @brief Adopt complete same-capacity roles and one immutable key projection.
	 * @param domain Exact compiled storage-domain identity.
	 * @param numa_node Proven worker allocation node.
	 * @param keys Immutable stage/phase identities common to both roles.
	 * @param active Complete initial active role.
	 * @param future Complete equal-capacity future role, or null when absent.
	 */
	packet_epoch_input_staging(uint32_t domain, int32_t numa_node, std::span<const packet_work_key> keys,
				   role_state *active, role_state *future) noexcept
		: keys_(keys)
		, physical_roles_{active, future}
		, active_(active)
		, future_(future)
		, storage_domain_index_(domain)
		, numa_node_(numa_node)
	{
	}
	/** @param role Exact selected role. @return Remaining capacity after validating both ownership counts. */
	[[nodiscard]] static std::size_t available_(const role_state &role) noexcept
	{
		if (role.occupied > role.capacity || role.reservations > role.occupied) {
			std::terminate();
		}
		return role.capacity - role.occupied;
	}
	/**
	 * @param role Exact selected role.
	 * @param count Exact requested population; zero changes no ownership.
	 * @return True after retaining the complete unpublished population, false before mutation on full.
	 */
	[[nodiscard]] static bool reserve_(role_state &role, std::size_t count) noexcept
	{
		if (count > available_(role)) {
			return false;
		}
		role.occupied += count;
		role.reservations += count;
		return true;
	}
	/**
	 * @brief Consume an existing claim and make its key ready exactly once.
	 * @param role Exact selected role.
	 * @param key Valid ordinal in that role's immutable key projection.
	 * @param record Nonnull packet ownership covered by the reservation.
	 */
	static void commit_(role_state &role, uint32_t key, packet_record *record) noexcept
	{
		if (key >= role.keys.size() || record == nullptr || role.reservations == 0u) {
			std::terminate();
		}
		auto &state = role.keys[key];
		--role.reservations;
		if (!state.queue.try_push(record)) {
			std::terminate();
		}
		if (!state.claimed) {
			state.claimed = true;
			if (!role.ready.has_value() || !role.ready->try_push(key)) {
				std::terminate();
			}
		}
	}
	/**
	 * @brief Release an exact outstanding population after transfer or unused admission.
	 * @param role Exact selected role.
	 * @param count Exact resolved population; zero changes no ownership.
	 */
	static void release_(role_state &role, std::size_t count) noexcept
	{
		if (count > role.reservations || role.reservations > role.occupied || role.occupied > role.capacity) {
			std::terminate();
		}
		role.reservations -= count;
		role.occupied -= count;
	}
	/** @param role Exact selected role. @return Constant-time emptiness including ready membership and service. */
	[[nodiscard]] static bool empty_(const role_state &role) noexcept
	{
		return role.occupied == 0u && role.reservations == 0u && role.servicing == NO_SERVICE &&
		       (!role.ready.has_value() || role.ready->empty());
	}

	std::span<const packet_work_key> keys_;		    ///< Immutable stage/phase identities used by both roles.
	const std::array<role_state *, 2> physical_roles_;  ///< Construction-order borrows retained through role swaps.
	role_state *active_{nullptr};			    ///< Complete currently executable role.
	role_state *future_{nullptr};		     ///< Complete future role, absent for non-sources/fixed execution.
	uint32_t storage_domain_index_{UINT32_MAX};  ///< Exact compiled domain.
	int32_t numa_node_{-1};			     ///< Exact proven worker NUMA node.
};

static_assert(alignof(packet_epoch_input_staging) == algo::CACHE_LINE_SIZE &&
		      sizeof(packet_epoch_input_staging) % algo::CACHE_LINE_SIZE == 0u,
	      "worker role controls must occupy complete cache lines");

/**
 * @brief Own every local packet role in one checked, prefaulted worker-NUMA region.
 *
 * The allocation contains domain views, role and key controls, ready storage,
 * and key-major pointer arrays. Controls end before a cache-line-aligned pointer
 * area. Domain borrows remain stable until the worker has joined and every
 * queued, reserved and executing claim is empty.
 */
class worker_packet_staging final {
    public:
	/**
	 * @brief Construct one complete worker staging population before packet admission.
	 * @param domains Sorted unique domains with exact capacities and sorted unique keys.
	 * @param numa_node Exact nonnegative worker host-memory node.
	 * @return Complete owner, or shape/overflow/allocation failure with no live packet ownership.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_packet_staging>>
	create(std::span<const worker_packet_staging_domain> domains, int32_t numa_node);
	/** @brief A region and its roles have one reclamation owner. */
	worker_packet_staging(const worker_packet_staging &) = delete;
	/** @brief Reject duplicate region ownership. */
	worker_packet_staging &operator=(const worker_packet_staging &) = delete;
	/** @brief Keep every borrowed domain address stable. */
	worker_packet_staging(worker_packet_staging &&) = delete;
	/** @brief Reject replacement beneath kernel or activation borrows. */
	worker_packet_staging &operator=(worker_packet_staging &&) = delete;
	/** @brief Prove all roles empty, destroy controls in reverse order, then unmap once. */
	~worker_packet_staging();
	/** @return Stable domain views in their admitted order. */
	[[nodiscard]] std::span<packet_epoch_input_staging> domains() noexcept
	{
		return domains_;
	}
	/** @return Exact mapped usable byte count, including controls and pointer arrays. */
	[[nodiscard]] std::size_t storage_bytes() const noexcept
	{
		return storage_.size();
	}
	/** @return Borrowed allocation geometry for cold inspection; valid until this owner is destroyed. */
	[[nodiscard]] const numa_memory_region &storage_region() const noexcept
	{
		return storage_;
	}

    private:
	/** @brief Begin empty cold construction before acquiring any mapping. */
	worker_packet_staging() noexcept = default;
	numa_memory_region storage_;			 ///< Sole complete worker staging region.
	std::span<packet_epoch_input_staging> domains_;	 ///< Completed placement-constructed domain prefix.
};

}  // namespace kinetum::dp
