// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_active_stage_scheduler.hpp
 * @brief Instance-scoped active-stage ownership for one packet worker.
 * @author Fleming Patel
 *
 * One scheduler owns every active stage instance assigned to one compiled
 * packet worker. It binds exact module contexts, active-origin storage,
 * retained packet handles, owner-local timers, copied control mailboxes, PULL
 * bits, tracked foreign completions, same-instance recirculation, and
 * transition drain beneath the existing worker epoch ledger. It owns no
 * routing, provider-selection, global transition, or telemetry authority.
 *
 * @par Thread Safety
 * Construction and destruction belong to the runtime generation owner. After
 * binding, every method is called by the one packet-worker thread except cold
 * const observations made before launch or after join. Module callbacks are
 * invoked only by that owner and never while a platform lock is held.
 *
 * @par Performance
 * Construction performs all allocation, identity resolution, and topology
 * validation. Owner turns and callback services allocate nothing, read no
 * clock, take no lock, perform no string or topology lookup, and mutate only
 * owner-local state plus the worker ledger. A passive-only worker constructs
 * no scheduler and executes no scheduler branch.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include <kinetum/kinetum_sdk.h>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/packet.hpp"
#include "src/dp/packet_mechanism.hpp"

namespace kinetum::provider
{
struct compiled_provider_topology;
}  // namespace kinetum::provider

namespace kinetum::dp
{

class worker_epoch_ledger;

/** @brief One exact active stage to admitted context/view binding. */
struct active_stage_context_binding {
	uint32_t stage_instance_index{0};	     ///< Exact compiled stage identity.
	uint32_t module_context_index{0};	     ///< Exact admitted context identity.
	module::module_epoch_store *store{nullptr};  ///< Stable exact epoch/view owner.
	const kinetum_module *descriptor{nullptr};   ///< Stable admitted ACTIVE callback table.
};

/**
 * @brief Narrow packet-operation surface borrowed from the owning kernel.
 *
 * The scheduler selects no route or provider. It supplies an exact active
 * stage identity and transfers work only after one of these pre-resolved
 * kernel operations accepts it.
 */
struct active_stage_packet_operations {
	void *state{nullptr};  ///< Stable packet-kernel owner.
	/**
	 * @brief Copy and publish one exact active-origin prefix.
	 * @param state Stable packet-kernel owner.
	 * @param stage_instance_index Exact active source stage.
	 * @param epoch Exact active/source epoch.
	 * @param now_ns Sole worker-cached timestamp.
	 * @param batch Complete validated candidate batch.
	 * @param budget Maximum accepted prefix for this callback.
	 * @param origin_scratch Exact scheduler-NUMA provider-origin projection.
	 * @param record_scratch Exact scheduler-NUMA provider-result projection.
	 * @return Exact prefix transferred into common packet ownership.
	 *
	 * Both scratch spans remain scheduler-owned and contain no borrowed source
	 * pointer or record ownership when this operation returns.
	 */
	uint32_t (*emit_origins)(void *state, uint32_t stage_instance_index, uint64_t epoch, uint64_t now_ns,
				 const kinetum_emit_batch_t *batch, uint32_t budget,
				 std::span<packet_origin_view> origin_scratch,
				 std::span<packet_record *> record_scratch) noexcept {nullptr};
	/**
	 * @brief Transfer one retained record into common dispatch or drop staging.
	 * @param state Stable packet-kernel owner.
	 * @param stage_instance_index Exact active source stage.
	 * @param record Sole retained packet ownership.
	 * @param next_stage Logical target or KINETUM_NEXT_STAGE_UNSET.
	 * @param drop true for terminal release; false for common dispatch.
	 * @return true only after common dispatch or grouped release accepts ownership.
	 */
	bool (*publish_retained)(void *state, uint32_t stage_instance_index, packet_record *record, uint16_t next_stage,
				 bool drop) noexcept {nullptr};
	/**
	 * @brief Publish one retained record back to the same active stage instance.
	 * @param state Stable packet-kernel owner.
	 * @param stage_instance_index Exact same-instance recirculation target.
	 * @param record Sole retained packet ownership.
	 * @return true only after exact active local staging accepts ownership.
	 */
	bool (*publish_recirculated)(void *state, uint32_t stage_instance_index,
				     packet_record *record) noexcept {nullptr};

	/** @return true only when all exact nonvirtual packet operations are complete. */
	[[nodiscard]] bool valid() const noexcept
	{
		return state != nullptr && emit_origins != nullptr && publish_retained != nullptr &&
		       publish_recirculated != nullptr;
	}
};

/** @brief Disjoint dispositions derived after complete ACTIVE batch validation. */
struct active_ingest_result {
	uint64_t forwarded_mask{0};  ///< Caller routes these records with their existing credits.
	uint64_t retained_mask{0};   ///< Exact active handles own these records and credits.
	/** @return true when both complete derived dispositions agree. */
	[[nodiscard]] bool operator==(const active_ingest_result &) const noexcept = default;
};

static_assert(sizeof(active_ingest_result) == 16);
static_assert(alignof(active_ingest_result) == 8);
static_assert(offsetof(active_ingest_result, forwarded_mask) == 0);
static_assert(offsetof(active_ingest_result, retained_mask) == 8);

/** @brief Sole active-stage owner for one compiled worker. */
class worker_active_stage_scheduler final {
    public:
	/**
	 * @brief Construct one exact instance-scoped scheduler.
	 *
	 * @param worker_index Exact compact owner-worker identity.
	 * @param topology Sole compiled provider and active-schedule authority.
	 * @param contexts Complete exact stage/context/view binding set.
	 * @param ledger Sole worker-local epoch-work authority.
	 * @param packet_operations Narrow pre-resolved kernel packet operations.
	 * @return Scheduler for a nonempty active schedule, or exact validation,
	 *         representability, NUMA-allocation, or ownership failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_active_stage_scheduler>>
	create(uint32_t worker_index, const provider::compiled_provider_topology &topology,
	       std::span<const active_stage_context_binding> contexts, worker_epoch_ledger &ledger,
	       active_stage_packet_operations packet_operations);

	worker_active_stage_scheduler(const worker_active_stage_scheduler &) = delete;
	worker_active_stage_scheduler &operator=(const worker_active_stage_scheduler &) = delete;
	worker_active_stage_scheduler(worker_active_stage_scheduler &&) = delete;
	worker_active_stage_scheduler &operator=(worker_active_stage_scheduler &&) = delete;
	/** @brief Destroy only after every synchronous and asynchronous ownership source is empty. */
	~worker_active_stage_scheduler();

	/** @return Exact compact owner-worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;
	/** @return Number of exact active stage-instance rows. */
	[[nodiscard]] std::size_t size() const noexcept;
	/** @return Exact NUMA node of the scheduler's sole worker slab. */
	[[nodiscard]] int32_t numa_node() const noexcept;
	/** @return Exact usable bytes in the scheduler's sole worker slab. */
	[[nodiscard]] std::size_t storage_bytes() const noexcept;
	/** @return Exact active epoch, or zero before Bootstrap binding. */
	[[nodiscard]] uint64_t active_epoch() const noexcept;
	/**
	 * @brief Test whether this scheduler borrows one exact ledger object.
	 * @param ledger Candidate worker-ledger authority.
	 * @return true only for the construction-bound ledger object.
	 */
	[[nodiscard]] bool owns_ledger(const worker_epoch_ledger &ledger) const noexcept;

	/**
	 * @brief Bind exact Bootstrap views after every module ACTIVATE completed.
	 * @param epoch Exact active Bootstrap epoch.
	 */
	void bind_bootstrap_epoch(uint64_t epoch) noexcept;

	/**
	 * @brief Prove one exact transition drain can begin without mutation.
	 * @param generation Nonzero transition generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @return true only when every instance and service is clean and exact.
	 */
	[[nodiscard]] bool preflight_begin_transition(uint64_t generation, uint64_t from_epoch,
						      uint64_t to_epoch) const noexcept;
	/**
	 * @brief Enter transition drain after complete worker preflight.
	 * @param generation Nonzero transition generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @return true after one exact non-failing bind; false without mutation.
	 *
	 * The worker ledger's future slot must already be bound to @p to_epoch;
	 * source admission must still name @p from_epoch.
	 */
	[[nodiscard]] bool begin_transition(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch) noexcept;
	/** @brief Enter shutdown drain and permanently close new active work. */
	void begin_shutdown() noexcept;

	/** @return true only when this worker owns a nonempty tracked-async projection. */
	[[nodiscard]] bool has_async_work() const noexcept;
	/**
	 * @brief Service one bounded synchronous-only owner-worker active turn.
	 * @param cached_now_ns Sole worker-cached monotonic timestamp for this turn.
	 */
	void service_turn_synchronous(uint64_t cached_now_ns) noexcept;
	/**
	 * @brief Service one bounded tracked-async owner-worker active turn.
	 * @param cached_now_ns Sole worker-cached monotonic timestamp for this turn.
	 */
	void service_turn_async(uint64_t cached_now_ns) noexcept;

	/**
	 * @brief Invoke exact active INGEST and resolve forward/retain/drop ownership.
	 *
	 * @param stage_instance_index Exact current active stage instance.
	 * @param records Borrowed input prefix whose records are already represented by the ledger.
	 * @param region_id Exact owner region.
	 * @param scratch Sole reusable module-batch projection.
	 * @param cached_now_ns Sole worker-cached timestamp.
	 * @return Disjoint forward/retain masks; every remaining occupied lane is a caller-owned drop.
	 */
	[[nodiscard]] active_ingest_result ingest_synchronous(uint32_t stage_instance_index,
							      std::span<packet_record *const> records,
							      int32_t region_id, module_batch_scratch &scratch,
							      uint64_t cached_now_ns) noexcept;
	/**
	 * @brief Invoke tracked-async-capable INGEST with the same exact packet ownership.
	 * @param stage_instance_index Exact current active stage instance.
	 * @param records Borrowed input prefix whose records are already represented by the ledger.
	 * @param region_id Exact owner region.
	 * @param scratch Sole reusable module-batch projection.
	 * @param cached_now_ns Sole worker-cached timestamp.
	 * @return Disjoint forward/retain masks; every remaining occupied lane is a caller-owned drop.
	 */
	[[nodiscard]] active_ingest_result ingest_async(uint32_t stage_instance_index,
							std::span<packet_record *const> records, int32_t region_id,
							module_batch_scratch &scratch, uint64_t cached_now_ns) noexcept;

	/**
	 * @brief Test whether this scheduler owns one exact active transition.
	 * @param generation Nonzero transition generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @return true only when transition drain owns the exact supplied identity.
	 */
	[[nodiscard]] bool transition_active(uint64_t generation, uint64_t from_epoch,
					     uint64_t to_epoch) const noexcept;
	/**
	 * @brief Test whether every synchronous and tracked-async old owner is drained.
	 * @param generation Nonzero transition generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @return true only when every instance has zero old ownership.
	 */
	[[nodiscard]] bool activation_ready(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch) const noexcept;
	/**
	 * @brief Preflight target publication after module stores have prepared N.
	 * @param generation Nonzero transition generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @return true only when activation is bounded and non-failing.
	 */
	[[nodiscard]] bool preflight_activate(uint64_t generation, uint64_t from_epoch,
					      uint64_t to_epoch) const noexcept;
	/**
	 * @brief Publish every exact active instance at N after module/queue/ledger activation.
	 * @param generation Nonzero transition generation.
	 * @param from_epoch Exact prior active epoch.
	 * @param to_epoch Exact newly activated target epoch.
	 */
	void activate(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch) noexcept;

	/** @return true when no synchronous or tracked-async ownership survives. */
	[[nodiscard]] bool empty() const noexcept;

    private:
	class implementation;
	/**
	 * @brief Adopt one completely validated implementation owner.
	 * @param implementation Sole validated private implementation.
	 */
	explicit worker_active_stage_scheduler(std::unique_ptr<implementation> implementation) noexcept;

	std::unique_ptr<implementation> implementation_;  ///< Sole instance-scoped scheduler state.
};

}  // namespace kinetum::dp
