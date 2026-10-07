// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_epoch_activation.hpp
 * @brief Exact local participant activation preflight and commit order.
 * @author Fleming Patel
 *
 * One packet worker owns one immutable projection of its module stores and
 * source input-role pairs. This component validates all fallible state before
 * the first module ACTIVATE callback, then performs modules, O(1) queue-role
 * swaps, and one ledger promotion in that order. It does not own transition
 * phase, CUT/ACK policy, source admission, or global completion.
 *
 * @par Thread Safety
 * Construction and Bootstrap binding are externally serialized. After packet
 * launch, only the exact worker calls preflight/activation methods. Borrowed
 * stores, staging owners, and ledger outlive this object.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/single_writer_snapshot.hpp>

#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/packet_work_item.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp::module
{
class module_epoch_store;
class worker_module_health;
}  // namespace kinetum::dp::module

namespace kinetum::dp
{

class worker_active_stage_scheduler;
class worker_runtime_telemetry;

/** @brief Exact packet-kernel staging specialization consumed by activation. */
using packet_epoch_input_staging = worker_epoch_input_staging<packet_work_item>;

/**
 * @brief Coherent proof of one complete worker-local activation edge.
 *
 * Bootstrap publishes one baseline. A live transition publishes once only
 * after every module callback, source-role exchange, and ledger promotion has
 * completed. The value therefore proves the old-credit preflight without
 * treating live target-epoch credit as old work.
 */
struct alignas(kinetum::algo::CACHE_LINE_SIZE) worker_epoch_activation_snapshot {
	uint64_t publication_generation{0};   ///< Coherent publication generation.
	uint64_t runtime_generation{0};	      ///< Exact materialized runtime generation.
	uint64_t worker_index{0};	      ///< Exact compact worker identity.
	uint64_t transition_generation{0};    ///< Exact mutation generation, or zero at Bootstrap.
	uint64_t from_epoch{0};		      ///< Exact old epoch, or zero at Bootstrap.
	uint64_t to_epoch{0};		      ///< Exact target or Bootstrap epoch.
	uint64_t active_epoch{0};	      ///< Exact epoch active after publication.
	uint64_t activation_complete{0};      ///< One only for a completed live activation.
	uint64_t activation_monotonic_ns{0};  ///< Exact owner sample for a completed live activation.
	std::array<uint8_t, 56> padding{};    ///< Explicit two-cache-line completion.
};

static_assert(sizeof(worker_epoch_activation_snapshot) == 2u * kinetum::algo::CACHE_LINE_SIZE,
	      "worker activation observation must occupy two cache lines");
static_assert(alignof(worker_epoch_activation_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "worker activation observation must retain cache-line alignment");
static_assert(std::is_standard_layout_v<worker_epoch_activation_snapshot> &&
		      std::is_trivially_copyable_v<worker_epoch_activation_snapshot>,
	      "worker activation observation must retain value semantics");

/**
 * @brief Sole local activation-order owner for one packet worker.
 *
 * @par Ownership
 * The object owns only immutable participant projections and completed local
 * activation identity. It borrows every module store, source staging owner,
 * and the exact worker ledger; all borrowed authorities must outlive it. It
 * owns no prepared artifact, packet pointer, queue storage, or global phase.
 */
class worker_epoch_activation final {
    public:
	/**
	 * @brief Create one immutable exact participant binding.
	 *
	 * @param worker_index Exact compact packet-worker identity.
	 * @param runtime_generation Exact materialized generation.
	 * @param module_stores Complete exact worker-owned module-store set.
	 * @param source_staging Complete exact source-domain staging set.
	 * @param ledger Sole same-worker epoch and credit authority.
	 * @param active_scheduler Exact synchronous active owner, or null for a
	 *        passive-only worker.
	 * @param module_health Exact owner-worker health claim authority.
	 * @param telemetry Exact worker telemetry-bank owner.
	 * @return Unique unbound activation owner or a fail-closed shape status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_epoch_activation>>
	create(uint32_t worker_index, uint64_t runtime_generation,
	       std::span<module::module_epoch_store *const> module_stores,
	       std::span<packet_epoch_input_staging *const> source_staging, worker_epoch_ledger &ledger,
	       worker_active_stage_scheduler *active_scheduler, module::worker_module_health *module_health,
	       worker_runtime_telemetry &telemetry);

	/** @brief Reject copying because participant activation is single-owner. */
	worker_epoch_activation(const worker_epoch_activation &) = delete;
	/** @brief Reject copy assignment because bindings cannot be duplicated. */
	worker_epoch_activation &operator=(const worker_epoch_activation &) = delete;
	/** @brief Reject moving so kernel-held binding addresses remain stable. */
	worker_epoch_activation(worker_epoch_activation &&) = delete;
	/** @brief Reject move assignment so activated truth cannot be replaced. */
	worker_epoch_activation &operator=(worker_epoch_activation &&) = delete;

	/** @brief Default destruction; borrowed authorities retain their ownership. */
	~worker_epoch_activation() = default;

	/**
	 * @brief Bind and validate the already activated fixed Bootstrap epoch.
	 *
	 * @param bootstrap_epoch Exact active epoch for every bound authority.
	 */
	void bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept;

	/**
	 * @brief Prove complete local ownership before a commit trigger is consumed.
	 * @param transition_generation Exact new mutation generation.
	 * @param from_epoch Exact currently active epoch.
	 * @param to_epoch Exact greater prepared target epoch.
	 * @return true only when every module store owns PREPARED N, every source
	 *         future role is empty, and the ledger can bind N without mutation.
	 */
	[[nodiscard]] bool preflight_begin_transition(uint64_t transition_generation, uint64_t from_epoch,
						      uint64_t to_epoch) const noexcept;

	/**
	 * @brief Prove the complete local activation transaction without mutation.
	 *
	 * @param transition_generation Exact new mutation generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared future epoch.
	 * @return OK only when every callback input, queue role, and ledger identity
	 *         is ready before the first irreversible callback.
	 */
	[[nodiscard]] common::status preflight(uint64_t transition_generation, uint64_t from_epoch,
					       uint64_t to_epoch) const noexcept;

	/**
	 * @brief Activate modules, rotate source queues, then promote ledger truth.
	 *
	 * The method reruns the complete nonmutating preflight. After the first
	 * callback, any disagreement is terminate-class; no partial rollback path
	 * exists across foreign module ownership.
	 *
	 * @param transition_generation Exact preflighted mutation generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @param now_ns Sole worker-cached monotonic timestamp for telemetry publication.
	 * @return OK after complete activation, or a pre-callback failure with no mutation.
	 */
	[[nodiscard]] common::status activate(uint64_t transition_generation, uint64_t from_epoch, uint64_t to_epoch,
					      uint64_t now_ns) noexcept;

	/** @return Exact currently active local epoch, or zero before Bootstrap. */
	[[nodiscard]] uint64_t active_epoch() const noexcept;
	/** @return Last exact activated transition generation, or zero before one. */
	[[nodiscard]] uint64_t last_transition_generation() const noexcept;
	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;
	/** @return Exact materialized runtime generation. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;
	/**
	 * @brief Verify this activation owner borrowed one exact worker ledger.
	 *
	 * @param ledger Candidate immutable ledger identity.
	 * @return true only for the exact ledger used by activation preflight/commit.
	 */
	[[nodiscard]] bool owns_ledger(const worker_epoch_ledger &ledger) const noexcept;
	/** @return Number of exact worker-owned module stores. */
	[[nodiscard]] std::size_t module_store_count() const noexcept;
	/** @return Number of exact source-domain queue-role pairs. */
	[[nodiscard]] std::size_t source_staging_count() const noexcept;
	/**
	 * @brief Read one coherent Bootstrap baseline or completed live activation.
	 *
	 * @param[out] out Observer-owned value updated only on exact publication.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result try_read(worker_epoch_activation_snapshot &out) const noexcept;

    private:
	/** @brief Exact activation-proof field order. */
	enum publication_field : std::size_t {
		PUBLICATION_RUNTIME_GENERATION = 0,
		PUBLICATION_WORKER_INDEX,
		PUBLICATION_TRANSITION_GENERATION,
		PUBLICATION_FROM_EPOCH,
		PUBLICATION_TO_EPOCH,
		PUBLICATION_ACTIVE_EPOCH,
		PUBLICATION_ACTIVATION_COMPLETE,
		PUBLICATION_ACTIVATION_NS,
		PUBLICATION_FIELD_COUNT,
	};
	/** @brief Bounded coherent-reader attempts. */
	static constexpr std::size_t OBSERVATION_ATTEMPTS = 4u;
	/** @brief Complete immutable worker identity adopted by the private constructor. */
	struct owner_identity {
		uint32_t worker_index{0};	 ///< Exact compact packet-worker identity.
		uint64_t runtime_generation{0};	 ///< Exact materialized generation.
	};

	/**
	 * @brief Adopt one validated immutable binding.
	 *
	 * @param identity Exact worker and runtime identity.
	 * @param module_stores Complete exact context-store projection.
	 * @param source_staging Complete exact source-role projection.
	 * @param ledger Sole same-worker epoch and credit authority.
	 * @param active_scheduler Exact synchronous active owner, or null.
	 * @param module_health Exact health claim owner, or null without module contexts.
	 * @param telemetry Exact worker telemetry-bank owner.
	 */
	worker_epoch_activation(owner_identity identity, std::vector<module::module_epoch_store *> module_stores,
				std::vector<packet_epoch_input_staging *> source_staging, worker_epoch_ledger &ledger,
				worker_active_stage_scheduler *active_scheduler,
				module::worker_module_health *module_health,
				worker_runtime_telemetry &telemetry) noexcept;
	/**
	 * @brief Publish one Bootstrap baseline or completed live activation proof.
	 *
	 * @param activation_complete Whether the live module/queue/ledger edge completed.
	 */
	void publish_(bool activation_complete) noexcept;

	uint32_t worker_index_{0};				    ///< Exact compact worker identity.
	uint64_t runtime_generation_{0};			    ///< Exact materialized generation.
	std::vector<module::module_epoch_store *> module_stores_;   ///< Immutable context projection.
	std::vector<packet_epoch_input_staging *> source_staging_;  ///< Immutable source-domain projection.
	worker_epoch_ledger *ledger_{nullptr};			    ///< Sole epoch/credit authority.
	worker_active_stage_scheduler *active_scheduler_{nullptr};  ///< Exact synchronous active owner when present.
	module::worker_module_health *module_health_{nullptr};	    ///< Exact health callback claim owner.
	worker_runtime_telemetry *telemetry_{nullptr};		    ///< Exact worker telemetry-bank owner.
	uint64_t active_epoch_{0};				    ///< Exact completed local activation epoch.
	uint64_t last_transition_generation_{0};		    ///< Last exact activated mutation generation.
	uint64_t last_from_epoch_{0};				    ///< Last exact activation source epoch.
	uint64_t last_to_epoch_{0};				    ///< Last exact activation target/Bootstrap epoch.
	uint64_t last_activation_monotonic_ns_{0};		    ///< Live activation timestamp; zero at Bootstrap.
	kinetum::algo::single_writer_snapshot<PUBLICATION_FIELD_COUNT>
		publication_;  ///< Baseline and one-shot completed activation proofs.
};

}  // namespace kinetum::dp
