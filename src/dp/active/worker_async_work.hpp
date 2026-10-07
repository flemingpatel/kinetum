// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_async_work.hpp
 * @brief Exact foreign-work token and completion ownership for one packet worker.
 * @author Fleming Patel
 *
 * One caller-placed tracker owns a plan-bounded slot set and one MPMC
 * completion queue. The owner worker begins, aborts, drains, and retires work;
 * foreign threads may only publish one terminal outcome or query cancellation
 * through a copied SDK token. All storage is supplied by the owning exact-NUMA
 * scheduler slab.
 *
 * @par Thread Safety
 * Exactly one packet worker calls mutable owner methods. Any foreign thread may
 * call the token operation table concurrently. Construction, drain completion,
 * and destruction require external generation serialization.
 *
 * @par Performance
 * Begin is O(1) owner-local work plus one release publication. Foreign
 * completion is one slot CAS plus one MPMC publication. Owner drain is bounded
 * by its caller-supplied budget. No operation allocates, locks, reads a clock,
 * logs, formats, performs a syscall, or invokes module code.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/queue.hpp>
#include <kinetum/kinetum_sdk.h>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"

namespace kinetum::dp
{

/** @brief Exact owner-worker result of one pre-transfer token abort. */
struct worker_async_abort_result {
	uint32_t owner_index{0};	     ///< Exact active scheduler row.
	uint32_t released_slot{0};	     ///< Exact async slot returned to its row.
	uint32_t retained_slot{UINT32_MAX};  ///< Bound retained slot, or UINT32_MAX.
	bool standalone{false};		     ///< Whether one independent credit retired.
};

/** @brief Exact owner-worker transfer from completion queue to callback delivery. */
struct worker_async_delivery {
	kinetum_async_completion completion{};	///< Public fixed completion projection.
	uint64_t epoch{0};			///< Exact callback-owned credit epoch.
	uint32_t owner_index{0};		///< Exact active scheduler row.
	uint32_t released_slot{0};		///< Exact async slot returned to its row.
	uint32_t retained_slot{UINT32_MAX};	///< Bound retained slot, or UINT32_MAX.
	uint32_t callback_generation{0};	///< Exact callback-claim reuse generation.
	uint8_t callback_slot{UINT8_MAX};	///< Bounded callback-claim slot.
	bool standalone{false};			///< Whether callback completion retires one credit.
	uint8_t padding[2]{};			///< Fixed value padding.
};
static_assert(std::is_standard_layout_v<worker_async_delivery>);
static_assert(std::is_trivially_copyable_v<worker_async_delivery>);

/** @brief Caller-storage exact foreign-work tracker for one packet worker. */
class worker_async_work final {
	static_assert(std::atomic<uint64_t>::is_always_lock_free,
		      "foreign token and cancellation publication requires lock-free uint64 atomics");
	static constexpr std::size_t MAX_CALLBACK_DELIVERIES =
		common::runtime_sizing::PACKET_MAX_BURST_SIZE;	///< Shared burst-bounded callback-claim population.
	static_assert(MAX_CALLBACK_DELIVERIES > 0u && MAX_CALLBACK_DELIVERIES <= std::numeric_limits<uint64_t>::digits,
		      "async callback claims must fit the exact ownership mask");

    public:
	/** @brief Exact foreign-visible state of one generation slot. */
	enum class slot_state : uint8_t {
		EMPTY = 0,   ///< Slot is owner-worker free-list storage.
		LIVE,	     ///< Token is foreign-visible and unresolved.
		PUBLISHING,  ///< One foreign thread won terminal publication.
		PUBLISHED,   ///< Exact completion is queue-owned.
	};

	/** @brief One cache-line-isolated exact token slot. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) slot_storage {
		std::atomic<uint64_t> identity_state{0};  ///< Packed reuse generation and slot_state.
		std::atomic<uint64_t> epoch{0};		  ///< Exact work-credit/cancellation epoch.
		uint64_t user_tag{0};			  ///< Module correlation value.
		uint32_t owner_index{0};		  ///< Exact active scheduler row.
		uint32_t retained_slot{UINT32_MAX};	  ///< Bound retained slot, or UINT32_MAX.
		uint32_t next_free{UINT32_MAX};		  ///< Owner-worker intrusive free link.
		bool standalone{false};			  ///< Independent-credit ownership kind.
		bool owner_claimed{false};		  ///< Scheduler free-list ownership state.
		uint8_t padding[26]{};			  ///< Complete cache-line isolation.
	};
	static_assert(sizeof(slot_storage) == kinetum::algo::CACHE_LINE_SIZE);
	static_assert(alignof(slot_storage) == kinetum::algo::CACHE_LINE_SIZE);
	static_assert(std::is_standard_layout_v<slot_storage>);

	/** @brief Queue-owned terminal token identity. */
	struct completion_cell {
		/** @brief Construct one empty queue cell before publication. */
		completion_cell() noexcept = default;

		/**
		 * @brief Construct one complete terminal publication.
		 * @param handle_value Exact resolved token identity.
		 * @param outcome_value Exact declared terminal outcome.
		 */
		completion_cell(kinetum_async_work_handle handle_value, kinetum_async_outcome outcome_value) noexcept
			: handle(handle_value)
			, outcome(outcome_value)
		{
		}

		kinetum_async_work_handle handle{};				   ///< Exact published token.
		kinetum_async_outcome outcome{KINETUM_ASYNC_OUTCOME_UNSPECIFIED};  ///< Exact terminal outcome.
		uint32_t padding{0};						   ///< Fixed alignment padding.
	};
	static_assert(std::is_trivially_copyable_v<completion_cell>);
	static_assert(std::is_nothrow_copy_assignable_v<completion_cell>);
	static_assert(std::is_nothrow_move_assignable_v<completion_cell>);

	using completion_queue = kinetum::algo::mpmc_queue_view<completion_cell>;  ///< Sole shared completion core.
	using completion_queue_storage = completion_queue::storage_type;  ///< Caller-owned physical queue cell.

	/** @brief Exact immutable identity retained while one owner callback runs. */
	struct callback_claim {
		uint64_t token_handle{KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE};	 ///< Exact terminal token identity.
		uint64_t epoch{0};						 ///< Exact callback credit epoch.
		uint64_t user_tag{0};						 ///< Exact module correlation value.
		uint32_t owner_index{UINT32_MAX};				 ///< Exact active scheduler row.
		uint32_t released_slot{UINT32_MAX};				 ///< Exact resolved async slot.
		uint32_t retained_slot{UINT32_MAX};  ///< Bound retained slot, or UINT32_MAX.
		kinetum_async_outcome outcome{KINETUM_ASYNC_OUTCOME_UNSPECIFIED};  ///< Exact terminal outcome.
		bool standalone{false};	 ///< Independent-credit ownership kind.
		uint8_t padding[3]{};	 ///< Fixed value padding.
	};
	static_assert(std::is_standard_layout_v<callback_claim>);
	static_assert(std::is_trivially_copyable_v<callback_claim>);

	/** @brief One cache-line-isolated owner-to-foreign cancellation publication. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) cancellation_publication {
		std::atomic<uint64_t> epoch{0};	 ///< Exact cancelled work epoch, or zero while OPEN.
		uint8_t padding[kinetum::algo::CACHE_LINE_SIZE - sizeof(std::atomic<uint64_t>)]{};  ///< Isolation.
	};
	static_assert(sizeof(cancellation_publication) == kinetum::algo::CACHE_LINE_SIZE);
	static_assert(alignof(cancellation_publication) == kinetum::algo::CACHE_LINE_SIZE);

	/** @brief Complete caller-owned storage and identity binding for construction. */
	struct construction_binding {
		uint64_t runtime_generation{0};			   ///< Exact nonzero runtime generation.
		uint32_t worker_index{UINT32_MAX};		   ///< Exact compact worker identity.
		worker_epoch_ledger *ledger{nullptr};		   ///< Sole worker credit authority.
		slot_storage *slots{nullptr};			   ///< Exact logical token-slot extent.
		uint32_t slot_count{0};				   ///< Positive logical token capacity.
		completion_queue_storage *queue_storage{nullptr};  ///< Exact physical cell extent.
		std::size_t queue_capacity{0};			   ///< Power-of-two physical capacity.
	};

	/** @brief Complete exact owner request for one new foreign token. */
	struct begin_request {
		uint32_t slot_index{UINT32_MAX};     ///< Exact owner-reserved empty slot.
		uint32_t owner_index{UINT32_MAX};    ///< Exact scheduler row.
		uint64_t epoch{0};		     ///< Exact active work epoch.
		uint64_t user_tag{0};		     ///< Module correlation value.
		uint32_t retained_slot{UINT32_MAX};  ///< Bound retained slot, or UINT32_MAX.
		bool standalone{false};		     ///< Whether to acquire one independent credit.
	};

	/**
	 * @brief Construct one tracker in caller-owned exact-NUMA storage.
	 * @param binding Complete exact identities and caller-owned storage extents.
	 */
	explicit worker_async_work(construction_binding binding) noexcept;

	worker_async_work(const worker_async_work &) = delete;
	worker_async_work &operator=(const worker_async_work &) = delete;
	worker_async_work(worker_async_work &&) = delete;
	worker_async_work &operator=(worker_async_work &&) = delete;
	/** @brief Destroy only after exact token, queue, callback, and cancellation retirement. */
	~worker_async_work();

	/**
	 * @brief Derive the sole physical completion capacity from logical slots.
	 * @param logical_slots Positive complete worker token-slot population.
	 * @return Smallest representable power of two, at least two, covering the
	 *         supplied population; otherwise a cold range status.
	 */
	[[nodiscard]] static common::status_or<std::size_t> queue_capacity_for(std::size_t logical_slots) noexcept;

	/**
	 * @brief Publish one exact token after optional standalone-credit acquisition.
	 * @param request Complete exact owner request.
	 * @return Exact foreign token; malformed owner state terminates.
	 */
	[[nodiscard]] kinetum_async_token begin(begin_request request) noexcept;

	/**
	 * @brief Abort one token before foreign terminal publication.
	 * @param token Exact candidate token.
	 * @param expected_owner Exact scheduler row invoking abort.
	 * @return Exact restored ownership or no value after foreign publication wins.
	 */
	[[nodiscard]] std::optional<worker_async_abort_result> abort(const kinetum_async_token &token,
								     uint32_t expected_owner) noexcept;

	/**
	 * @brief Take one exact published completion into owner-callback ownership.
	 * @param[out] out Changed only after one valid completion transfer.
	 * @return true after one queue/slot transfer; false when the queue is empty.
	 */
	[[nodiscard]] bool try_take(worker_async_delivery &out) noexcept;

	/**
	 * @brief Test whether one resolved slot can return to its scheduler free list.
	 * @param slot_index Exact worker-global logical slot.
	 * @return true only after all tracker-owned state has returned to EMPTY.
	 */
	[[nodiscard]] bool slot_release_ready(uint32_t slot_index) const noexcept;

	/**
	 * @brief Retire one exact callback-owned completion.
	 * @param delivery Exact delivery returned by try_take().
	 */
	void complete_delivery(const worker_async_delivery &delivery) noexcept;

	/**
	 * @brief Release-publish cancellation for every exact token at one epoch.
	 * @param epoch Exact current active epoch.
	 */
	void begin_cancellation(uint64_t epoch) noexcept;
	/**
	 * @brief Clear one drained cancellation generation before target activation.
	 * @param epoch Exact cancelled source epoch.
	 */
	void finish_cancellation(uint64_t epoch) noexcept;

	/** @return Exact logical slot population. */
	[[nodiscard]] uint32_t slot_count() const noexcept;
	/** @return Exact plain owner-worker live-token count. */
	[[nodiscard]] uint32_t live_count() const noexcept;
	/** @return Exact plain owner-worker callback-delivery count. */
	[[nodiscard]] uint32_t callback_count() const noexcept;
	/** @return Exact release-published cancellation epoch, or zero while OPEN. */
	[[nodiscard]] uint64_t cancellation_epoch() const noexcept;
	/** @return true when every token, queue cell, and callback delivery is retired. */
	[[nodiscard]] bool drained() const noexcept;
	/** @return true only when slots, completion queue, callbacks, and cancellation are empty. */
	[[nodiscard]] bool empty() const noexcept;

    private:
	/**
	 * @brief Foreign completion operation installed into every token.
	 * @param token Exact copied foreign capability.
	 * @param outcome One valid terminal outcome.
	 * @return true only for the sole winning terminal publication.
	 */
	[[nodiscard]] static bool complete_foreign_(const kinetum_async_token *token,
						    kinetum_async_outcome outcome) noexcept;
	/**
	 * @brief Foreign cancellation query installed into every token.
	 * @param token Exact copied foreign capability.
	 * @return true for cancellation, stale identity, or malformed input.
	 */
	[[nodiscard]] static bool cancellation_requested_foreign_(const kinetum_async_token *token) noexcept;
	/** @param generation Reuse generation. @param state Exact slot state. @return Packed identity. */
	[[nodiscard]] static constexpr uint64_t pack_identity_(uint32_t generation, slot_state state) noexcept;
	/** @param identity Packed slot identity. @return Reuse generation. */
	[[nodiscard]] static constexpr uint32_t generation_(uint64_t identity) noexcept;
	/** @param identity Packed slot identity. @return Exact slot state. */
	[[nodiscard]] static constexpr slot_state state_(uint64_t identity) noexcept;
	/** @param identity Packed slot identity. @return true when reserved state bits are zero. */
	[[nodiscard]] static constexpr bool state_encoding_valid_(uint64_t identity) noexcept;
	/** @param claim Candidate callback identity. @return true only for one inactive claim slot. */
	[[nodiscard]] static constexpr bool callback_claim_empty_(const callback_claim &claim) noexcept;
	/** @param handle Raw async handle. @return Encoded slot index. */
	[[nodiscard]] static constexpr uint32_t handle_slot_(uint64_t handle) noexcept;
	/** @param handle Raw async handle. @return Encoded reuse generation. */
	[[nodiscard]] static constexpr uint32_t handle_generation_(uint64_t handle) noexcept;
	/**
	 * @param generation Nonzero reuse generation.
	 * @param slot Exact compact slot index.
	 * @return One exact non-invalid async handle.
	 */
	[[nodiscard]] static uint64_t make_handle_(uint32_t generation, uint32_t slot) noexcept;

	const kinetum_async_token_ops token_ops_{
		.complete = &worker_async_work::complete_foreign_,
		.cancellation_requested = &worker_async_work::cancellation_requested_foreign_,
	};  ///< Exact tracker-bound foreign portal.
	uint64_t runtime_generation_{0};				  ///< Exact materialized generation.
	uint32_t worker_index_{0};					  ///< Exact compact worker identity.
	worker_epoch_ledger *ledger_{nullptr};				  ///< Sole exact work-credit authority.
	slot_storage *slots_{nullptr};					  ///< Caller-owned token slots.
	uint32_t slot_count_{0};					  ///< Exact logical token capacity.
	completion_queue queue_;					  ///< Caller-storage foreign completion queue.
	cancellation_publication cancellation_{};			  ///< Sole foreign-readable cancellation line.
	alignas(kinetum::algo::CACHE_LINE_SIZE) uint32_t live_count_{0};  ///< Owner unresolved token count.
	uint32_t callback_count_{0};	   ///< Plain owner-worker callback-owned delivery count.
	uint64_t callback_owned_mask_{0};  ///< Exact bounded callback-claim ownership bits.
	std::array<uint32_t, MAX_CALLBACK_DELIVERIES> callback_generations_{};	 ///< Callback-claim generations.
	std::array<callback_claim, MAX_CALLBACK_DELIVERIES> callback_claims_{};	 ///< Exact live callback identities.
};

}  // namespace kinetum::dp
