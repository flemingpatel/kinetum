// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_epoch_ledger.hpp
 * @brief Owner-local packet-work credits with coherent foreign observation.
 * @author Fleming Patel
 *
 * One packet worker owns one ledger. Packet admission and independent fan-out
 * create credits; terminal disposition and successful ownership transfer out
 * of the worker retire them. Owner-local queue movement and storage-domain
 * conversion preserve the existing logical credit. The packet's sole
 * `packet_private.epoch` value selects one of the exact active/future slots;
 * the ledger never caches a per-packet epoch or introduces another packet
 * representation.
 *
 * Owner-mutated counters occupy a cache line disjoint from the coherent
 * publication channel. Packet operations consequently use only predicted
 * comparisons and plain integer arithmetic. Foreign readers observe only a
 * fixed `single_writer_snapshot` published once per bounded worker turn.
 *
 * @par Thread Safety
 * Exactly one packet-worker thread may bind, acquire, retire, or publish. Any
 * thread may call try_read(). Destruction requires zero outstanding credits.
 *
 * @par Performance
 * Acquire and retire are allocation-free, lock-free O(1) operations with no
 * atomic read-modify-write. Publication is fixed work over seven uint64 fields
 * and must run at a worker turn boundary, never once per packet.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <type_traits>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/single_writer_snapshot.hpp>
#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp
{

class worker_runtime_telemetry;

/** @brief Cold plan-derived inputs to one worker's complete credit ceiling. */
struct worker_epoch_credit_budget_input {
	uint64_t packet_storage_capacity{0};	 ///< Sum of reachable physical record populations.
	uint64_t synchronous_event_capacity{0};	 ///< Callback, control, and PULL overlap.
	uint64_t timer_capacity{0};		 ///< Complete armed timer population.
	uint64_t async_work_capacity{0};	 ///< Complete live foreign-token population.
	uint64_t handoff_limit{0};		 ///< Shared bounded callback-prefix limit.
};

/** @brief Exact checked additive terms accepted by one worker ledger. */
struct worker_epoch_credit_budget {
	uint64_t packet_storage_capacity{0};	 ///< Physical-record representability term.
	uint64_t synchronous_event_capacity{0};	 ///< Sequential callback/control/PULL term.
	uint64_t timer_capacity{0};		 ///< Armed timer term.
	uint64_t timer_handoff_capacity{0};	 ///< Timer expiry/callback overlap.
	uint64_t async_work_capacity{0};	 ///< Live standalone foreign-work term.
	uint64_t async_handoff_capacity{0};	 ///< Completion/resubmission overlap.
	uint64_t total{0};			 ///< Exact complete ledger ceiling.
};

/**
 * @brief Compile one overflow-checked worker credit budget from exact plan facts.
 * @param input Complete cold capacity facts and shared handoff bound.
 * @return Exact additive budget, or INVALID_ARGUMENT/OUT_OF_RANGE.
 */
[[nodiscard]] common::status_or<worker_epoch_credit_budget>
compile_worker_epoch_credit_budget(worker_epoch_credit_budget_input input) noexcept;

/**
 * @brief One coherent observer-owned worker epoch-accounting value.
 *
 * try_read() copies one completed publication into this independent value; it
 * contains no pointer or borrow into owner-local state.
 *
 * @par Thread Safety
 * Each instance belongs exclusively to its observer. Distinct observers may
 * read the same ledger concurrently into distinct instances.
 *
 * @par Performance
 * The value is exactly one cache line, standard-layout, and trivially copyable.
 */
struct alignas(kinetum::algo::CACHE_LINE_SIZE) worker_epoch_ledger_snapshot {
	uint64_t publication_generation{0};  ///< Monotonic coherent-publication generation.
	uint64_t runtime_generation{0};	     ///< Exact materialized runtime generation.
	uint64_t worker_index{0};	     ///< Exact compact packet-worker identity.
	uint64_t active_epoch{0};	     ///< Exact epoch currently executable by the worker.
	uint64_t source_epoch{0};	     ///< Exact epoch stamped on newly originated work.
	uint64_t active_unretired{0};	     ///< Worker-owned work carrying @ref active_epoch.
	uint64_t future_epoch{0};	     ///< Exact staged future epoch, or zero while unbound.
	uint64_t future_unretired{0};	     ///< Worker-owned work carrying @ref future_epoch.
};

static_assert(sizeof(worker_epoch_ledger_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "worker epoch observation must occupy exactly one cache line");
static_assert(alignof(worker_epoch_ledger_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "worker epoch observation must retain cache-line alignment");
static_assert(std::is_standard_layout_v<worker_epoch_ledger_snapshot>,
	      "worker epoch observation must retain standard layout");
static_assert(std::is_trivially_copyable_v<worker_epoch_ledger_snapshot>,
	      "worker epoch observation must remain trivially copyable");

/** @brief Exact two-slot packet, synchronous-active, and tracked-async accounting for one owner worker. */
class alignas(kinetum::algo::CACHE_LINE_SIZE) worker_epoch_ledger final {
    public:
	/**
	 * @brief Construct one unpublished empty ledger from compiled capacity truth.
	 *
	 * @param worker_index Exact non-sentinel compact packet-worker identity.
	 * @param runtime_generation Nonzero generation representable by the provider ABI.
	 * @param maximum_unretired Checked physical-record, synchronous-active,
	 *        tracked-async, and bounded completion-handoff credit ceiling.
	 * @return Unique ledger, or a cold validation/allocation status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_epoch_ledger>>
	create(uint32_t worker_index, uint64_t runtime_generation, uint64_t maximum_unretired);

	/** @brief Disable copying because one worker is the sole counter writer. */
	worker_epoch_ledger(const worker_epoch_ledger &) = delete;
	/** @brief Disable copy assignment because publication identity is stable. */
	worker_epoch_ledger &operator=(const worker_epoch_ledger &) = delete;
	/** @brief Disable moving because observers retain the publication address. */
	worker_epoch_ledger(worker_epoch_ledger &&) = delete;
	/** @brief Disable move assignment because owner identity cannot be replaced. */
	worker_epoch_ledger &operator=(worker_epoch_ledger &&) = delete;

	/** @brief Destroy only an empty ledger; live packet work is terminate-class. */
	~worker_epoch_ledger();

	/**
	 * @brief Bind and publish the exact fixed-bootstrap epoch once.
	 *
	 * This method runs on the future packet-owner thread after every module view
	 * has activated and before PACKET_READY. Rebinding, a zero or reserved-wrap
	 * epoch, or any pre-existing slot/counter state terminates because owner
	 * activation is already irreversible.
	 *
	 * @param bootstrap_epoch Exact valid active and source epoch.
	 */
	void bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept;

	/**
	 * @brief Prove one committed future binding without changing owner state.
	 * @param from_epoch Exact currently active and source epoch.
	 * @param future_epoch Exact greater target epoch to bind.
	 * @return true only when the future slot is empty and no future credit exists.
	 */
	[[nodiscard]] bool preflight_begin_transition(uint64_t from_epoch, uint64_t future_epoch) const noexcept;

	/**
	 * @brief Bind one exact future slot after owner observation of commit.
	 *
	 * The method changes no active or source identity and publishes nothing.
	 * The owner completes any source advance and emits one coherent end-of-turn
	 * publication. Invalid, stale, duplicate, or overlapping binding terminates.
	 *
	 * @param future_epoch Exact valid target epoch greater than active_epoch().
	 */
	void bind_future_epoch(uint64_t future_epoch) noexcept;

	/**
	 * @brief Advance origination to the exact already bound future epoch.
	 *
	 * This non-failing owner operation does not activate execution or rotate
	 * credits. Newly originated records enter future staging and remain
	 * non-executable until the later activation owner rotates exact roles.
	 *
	 * @param future_epoch Exact target previously bound by bind_future_epoch().
	 */
	void advance_source_epoch(uint64_t future_epoch) noexcept;

	/**
	 * @brief Prove one future-to-active promotion without changing owner truth.
	 *
	 * @param future_epoch Exact target already bound as future and source.
	 * @return OK only when old active ownership is zero and complete future
	 *         ownership can move as one value.
	 */
	[[nodiscard]] common::status preflight_promote_future_epoch(uint64_t future_epoch) const noexcept;

	/**
	 * @brief Promote the complete future slot to active after exact preflight.
	 *
	 * Future credits move whole into the active count, the aggregate is
	 * unchanged, and the future identity/count clear together. A violated
	 * precondition after irreversible participant activation terminates.
	 *
	 * @param future_epoch Exact preflighted target epoch.
	 */
	void promote_future_epoch(uint64_t future_epoch) noexcept;

	/**
	 * @brief Return the exact epoch currently executable by the owner worker.
	 *
	 * Only the sole packet-worker thread may call this owner-state accessor.
	 * Foreign code must use try_read().
	 *
	 * @return Nonzero bound active epoch, or zero before Bootstrap binding.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint64_t active_epoch() const noexcept
	{
		return owner_.active_epoch;
	}

	/**
	 * @brief Return the exact epoch stamped on new owner-originated work.
	 *
	 * Only the sole packet-worker thread may call this owner-state accessor.
	 * Foreign code must use try_read().
	 *
	 * @return Nonzero bound source epoch, or zero before Bootstrap binding.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint64_t source_epoch() const noexcept
	{
		return owner_.source_epoch;
	}

	/**
	 * @brief Return the exact staged future epoch owned by this worker.
	 *
	 * Only the sole packet-worker thread may call this owner-state accessor.
	 * Foreign code must use try_read().
	 *
	 * @return Exact future epoch, or zero while no commit is bound.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint64_t future_epoch() const noexcept
	{
		return owner_.future_epoch;
	}

	/**
	 * @brief Return the owner-local active-slot credit count.
	 *
	 * Only the sole packet-worker thread may call this accessor. It is the exact
	 * seal precondition and does not publish, synchronize, or expose the owner
	 * line to a foreign reader.
	 *
	 * @return Plain current active-epoch credit count.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint64_t active_unretired() const noexcept
	{
		return owner_.active_unretired;
	}

	/** @return Immutable compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept
	{
		return worker_index_;
	}

	/** @return Immutable materialized runtime generation. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept
	{
		return runtime_generation_;
	}

	/**
	 * @brief Bind the sole owner-local counter bank and process fault latch.
	 * @param telemetry Exact worker/runtime telemetry authority.
	 * @param faults Process-generation first-fault and transition-success authority.
	 * @return OK for first or exact repeated binding; FAILED_PRECONDITION otherwise.
	 */
	[[nodiscard]] common::status bind_protocol_faults(worker_runtime_telemetry &telemetry,
							  epoch_protocol_fault_latch &faults) noexcept;

	/**
	 * @brief Create one worker-owned work credit in an exact bound epoch slot.
	 *
	 * @param epoch Sole immutable epoch read from packet metadata.
	 *
	 * @par Hot-Path Constraints
	 * Predicted active-slot comparison and plain integer increments only. An
	 * unknown epoch or capacity overflow terminates without publishing a false
	 * observation.
	 */
	KINETUM_ALWAYS_INLINE void acquire(uint64_t epoch) noexcept
	{
		if (KINETUM_LIKELY(epoch != 0u && epoch == owner_.active_epoch)) {
			if (KINETUM_UNLIKELY(owner_.future_unretired > maximum_unretired_ ||
					     owner_.active_unretired >= maximum_unretired_ - owner_.future_unretired)) {
				record_fault_and_terminate_(epoch_protocol_fault_code::OWNERSHIP_OVERFLOW, epoch,
							    maximum_unretired_, owner_.active_unretired);
			}
			++owner_.active_unretired;
			return;
		}
		if (epoch != 0u && epoch == owner_.future_epoch) {
			if (KINETUM_UNLIKELY(owner_.active_unretired > maximum_unretired_ ||
					     owner_.future_unretired >= maximum_unretired_ - owner_.active_unretired)) {
				record_fault_and_terminate_(epoch_protocol_fault_code::OWNERSHIP_OVERFLOW, epoch,
							    maximum_unretired_, owner_.future_unretired);
			}
			++owner_.future_unretired;
			return;
		}
		record_fault_and_terminate_(epoch_protocol_fault_code::OWNERSHIP_WRONG_SLOT, epoch, owner_.active_epoch,
					    epoch);
	}

	/**
	 * @brief Retire one worker-owned work credit from an exact bound epoch slot.
	 *
	 * @param epoch Sole immutable epoch retained for the terminal disposition.
	 *
	 * @par Hot-Path Constraints
	 * Predicted active-slot comparison and plain integer decrements only. An
	 * unknown epoch, underflow, or double retirement that reaches zero
	 * terminates without manufacturing quiescence.
	 */
	KINETUM_ALWAYS_INLINE void retire(uint64_t epoch) noexcept
	{
		if (KINETUM_LIKELY(epoch != 0u && epoch == owner_.active_epoch)) {
			if (KINETUM_UNLIKELY(owner_.active_unretired == 0u)) {
				record_fault_and_terminate_(epoch_protocol_fault_code::OWNERSHIP_DOUBLE_RETIRE, epoch,
							    1u, 0u);
			}
			--owner_.active_unretired;
			return;
		}
		if (epoch != 0u && epoch == owner_.future_epoch) {
			if (KINETUM_UNLIKELY(owner_.future_unretired == 0u)) {
				record_fault_and_terminate_(epoch_protocol_fault_code::OWNERSHIP_DOUBLE_RETIRE, epoch,
							    1u, 0u);
			}
			--owner_.future_unretired;
			return;
		}
		if (epoch == 0u) {
			record_fault_and_terminate_(epoch_protocol_fault_code::OWNERSHIP_UNDERFLOW, epoch, 1u, 0u);
		}
		record_fault_and_terminate_(epoch_protocol_fault_code::OWNERSHIP_WRONG_SLOT, epoch, owner_.active_epoch,
					    epoch);
	}

	/**
	 * @brief Publish one coherent generation-tagged owner observation.
	 *
	 * The active/source/future identity relation, slot-count shape, and aggregate
	 * credit ceiling are revalidated before the release publication. Invalid
	 * state or publication-sequence exhaustion terminates.
	 */
	void publish() noexcept;

	/**
	 * @brief Attempt one bounded coherent foreign observation.
	 *
	 * @param[out] out Observer-owned value updated only on complete validation.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result try_read(worker_epoch_ledger_snapshot &out) const noexcept;

	/**
	 * @brief Return whether no packet work remains owned by this worker.
	 *
	 * This owner-only predicate is used for final shutdown proof. Foreign code
	 * must consume try_read() instead of reading mutable counters.
	 *
	 * @return true only when both exact slot counts are zero.
	 */
	[[nodiscard]] bool empty() const noexcept;

    private:
	/**
	 * @brief Plain owner-only counters isolated from every observer cache line.
	 *
	 * The sole packet-worker thread mutates this value. Foreign observers never
	 * access it and instead consume the separate coherent publication line.
	 */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) owner_state {
		uint64_t active_epoch{0};	    ///< Exact currently executable epoch.
		uint64_t source_epoch{0};	    ///< Exact current origination epoch.
		uint64_t active_unretired{0};	    ///< Current active-slot work credits.
		uint64_t future_epoch{0};	    ///< Exact future slot identity, or zero.
		uint64_t future_unretired{0};	    ///< Current future-slot work credits.
		std::array<uint64_t, 3> padding{};  ///< Preserve one complete private cache line.
	};

	static_assert(sizeof(owner_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "worker epoch owner state must occupy one cache line");
	static_assert(alignof(owner_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "worker epoch owner state must retain cache-line alignment");
	static_assert(std::is_standard_layout_v<owner_state>, "worker epoch owner state must retain standard layout");
	static_assert(std::is_trivially_copyable_v<owner_state>,
		      "worker epoch owner state must remain trivially copyable");

	/** @brief Fixed field order in the generic coherent publication. */
	enum publication_field : std::size_t {
		RUNTIME_GENERATION = 0,	 ///< Exact materialized generation.
		WORKER_INDEX,		 ///< Exact compact worker identity.
		ACTIVE_EPOCH,		 ///< Exact executable epoch.
		SOURCE_EPOCH,		 ///< Exact origination epoch.
		ACTIVE_UNRETIRED,	 ///< Published active-slot credits.
		FUTURE_EPOCH,		 ///< Exact future slot, or zero.
		FUTURE_UNRETIRED,	 ///< Published future-slot credits.
	};

	static constexpr std::size_t PUBLICATION_FIELD_COUNT = FUTURE_UNRETIRED + 1u;  ///< Exact payload width.
	static constexpr std::size_t OBSERVATION_ATTEMPTS = 8u;	 ///< Bounded coherent-read attempts.

	/**
	 * @brief Adopt validated immutable identity and capacity.
	 *
	 * @param worker_index Exact non-sentinel compact worker identity.
	 * @param runtime_generation Exact nonzero runtime generation.
	 * @param maximum_unretired Exact checked worker credit ceiling.
	 */
	worker_epoch_ledger(uint32_t worker_index, uint64_t runtime_generation, uint64_t maximum_unretired) noexcept;

	/**
	 * @brief Capture one impossible credit mutation and terminate.
	 * @param code Violated ledger invariant.
	 * @param observed_epoch Epoch associated with the rejected mutation.
	 * @param expected_value Expected credit bound or identity selected by @p code.
	 * @param observed_value Actual value that violated that expectation.
	 */
	[[noreturn]] void record_fault_and_terminate_(epoch_protocol_fault_code code, uint64_t observed_epoch,
						      uint64_t expected_value, uint64_t observed_value) noexcept;

	uint32_t worker_index_{0};				///< Immutable compact worker identity.
	uint64_t runtime_generation_{0};			///< Immutable materialized generation.
	uint64_t maximum_unretired_{0};				///< Immutable compiled worker credit ceiling.
	worker_runtime_telemetry *telemetry_{nullptr};		///< Bound owner-local typed fault counters.
	epoch_protocol_fault_latch *protocol_faults_{nullptr};	///< Process-generation first-fault authority.
	owner_state owner_{};					///< Sole packet-worker mutable accounting.
	kinetum::algo::single_writer_snapshot<PUBLICATION_FIELD_COUNT> publication_;  ///< Foreign observation only.
};

static_assert(sizeof(kinetum::algo::single_writer_snapshot<7>) == kinetum::algo::CACHE_LINE_SIZE,
	      "seven-field worker publication must occupy one cache line");
static_assert(sizeof(worker_epoch_ledger) == 3u * kinetum::algo::CACHE_LINE_SIZE,
	      "worker epoch identity, owner counters, and publication must occupy disjoint cache lines");
static_assert(alignof(worker_epoch_ledger) == kinetum::algo::CACHE_LINE_SIZE,
	      "worker epoch ledger must retain cache-line alignment");

}  // namespace kinetum::dp
