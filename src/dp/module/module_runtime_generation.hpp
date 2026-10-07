// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_runtime_generation.hpp
 * @brief Exact module and cold-lifecycle ownership for one packet generation.
 * @author Fleming Patel
 *
 * The generation owner admits the exact compiled module image/context set,
 * binds every context to the sole compiled NUMA lifecycle executor, and owns
 * the complete INIT/PREPARE/ACTIVATE/RETIRE/FINI lifetime. Context-lifetime
 * and per-epoch memory are enforced from compiled plan facts; this layer has no
 * sizing default, sentinel, provider inference, or module-configuration-based
 * capacity rule.
 *
 * PREPARE and exact rollback run on planned cold lifecycle services. ACTIVATE
 * runs only on the sole packet-owner worker and is followed by one non-failing
 * generation publication. Final RETIRE runs after every packet worker joins,
 * before lifecycle services stop and before module FINI/image unload.
 *
 * @par Thread Safety
 * Creation, preparation, publication, retirement, and service shutdown belong
 * to the sole runtime-service-bound coordinator. activate_worker() is called
 * once on each exact owner worker while packet bodies remain closed. Contexts
 * owned by distinct workers are disjoint; no method is generally reentrant.
 *
 * @par Performance
 * This type is cold-path orchestration. Packet workers retain direct module
 * store/view pointers through module_manager and never call this owner from
 * packet execution after activation.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_transition_module_completion.hpp"
#include "src/dp/lifecycle/config_lifecycle_executor.hpp"
#include "src/dp/module/module_manager.hpp"

namespace kinetum::control::v1
{
class ConfigSnapshot;
}  // namespace kinetum::control::v1

namespace kinetum::provider
{
class materialized_provider_runtime;
struct compiled_provider_topology;
}  // namespace kinetum::provider

namespace kinetum::dp
{
class epoch_transition_preparation;
class worker_telemetry_channel;
}  // namespace kinetum::dp

namespace kinetum::dp::module
{

/** @brief Nonmovable exact module/lifecycle owner for one runtime generation. */
class module_runtime_generation final : public ::kinetum::dp::epoch_transition_module_completion {
    public:
	/**
	 * @brief Admit the complete module generation before provider materialization.
	 *
	 * Logical and image execution modes must match each exact context; tracked
	 * asynchronous capability and authored resources must agree exactly; and
	 * every compiled context/resource/placement fact must match one admitted
	 * context in both directions.
	 * Module-free plans retain the mandatory lifecycle-service topology but admit
	 * no synthetic module.
	 *
	 * @param topology Sole compiled provider and lifecycle topology authority.
	 * @param module_images Strictly sorted exact main-image authority transferred
	 *        into module admission.
	 * @return Complete generation owner, or a recoverable validation, allocation,
	 *         image-admission, or INIT failure before provider materialization.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<module_runtime_generation>>
	create(const provider::compiled_provider_topology &topology, std::vector<module_image_spec> module_images);

	/** @brief Module generations cannot be copied. */
	module_runtime_generation(const module_runtime_generation &) = delete;
	/** @brief Module generations cannot be copy-assigned. */
	module_runtime_generation &operator=(const module_runtime_generation &) = delete;
	/** @brief Module generations cannot be moved. */
	module_runtime_generation(module_runtime_generation &&) = delete;
	/** @brief Module generations cannot be move-assigned. */
	module_runtime_generation &operator=(module_runtime_generation &&) = delete;
	/** @brief Destroy only after exact retirement and lifecycle-service shutdown. */
	~module_runtime_generation() override;

	/**
	 * @brief Launch every exact compiled lifecycle executor after materialization.
	 *
	 * The caller is bound/proved as the sole compiled coordinator. No lifecycle
	 * callback executes unless the complete service set launches successfully.
	 *
	 * @param materialized Complete provider generation that outlives this owner.
	 * @return OK after all-or-none service launch; otherwise no callback ran.
	 */
	[[nodiscard]] common::status
	start_lifecycle_services(const provider::materialized_provider_runtime &materialized);

	/**
	 * @brief Prepare and preflight one exact bootstrap epoch transactionally.
	 *
	 * Every module context receives its module's canonical opaque configuration
	 * and one arena at the exact compiled capacity. A failure retires every
	 * earlier prepared token in reverse context order before returning.
	 *
	 * @param snapshot Canonical plan-bound bootstrap snapshot.
	 * @param bootstrap_epoch Exact nonzero bootstrap epoch.
	 * @return OK only after every context is PREPARED and complete activation
	 *         preflight succeeds; otherwise the generation remains unprepared.
	 */
	[[nodiscard]] common::status prepare_bootstrap(const kinetum::control::v1::ConfigSnapshot &snapshot,
						       uint64_t bootstrap_epoch);

	/**
	 * @brief Activate every module context owned by one packet worker.
	 *
	 * All fallible generation-wide preflight has completed. Any missing context,
	 * callback failure, or publication disagreement after this point terminates
	 * the process without unwinding the admitted generation.
	 *
	 * @param worker_index Exact compact owner-worker identity.
	 * @param bootstrap_epoch Exact prepared bootstrap epoch.
	 * @param now_ns Exact owner-worker monotonic activation timestamp.
	 */
	void activate_worker(uint32_t worker_index, uint64_t bootstrap_epoch, uint64_t now_ns) noexcept;

	/**
	 * @brief Publish completion after every owner-worker ACTIVATE has returned.
	 *
	 * @param bootstrap_epoch Exact activated bootstrap epoch.
	 */
	void publish_bootstrap_activation(uint64_t bootstrap_epoch) noexcept;

	/**
	 * @brief Retire an unactivated prepared bootstrap transaction exactly.
	 *
	 * @param bootstrap_epoch Exact prepared epoch being abandoned.
	 */
	void abort_prepared_bootstrap(uint64_t bootstrap_epoch) noexcept;

	/**
	 * @brief Retire the sole published epoch after all workers join.
	 *
	 * @param epoch Exact active epoch proven packet-quiescent.
	 */
	void retire_published_generation(uint64_t epoch) noexcept;

	/** @brief Stop, drain, and join every lifecycle executor exactly once. */
	void stop_lifecycle_services() noexcept;

	/** @return Stable admitted module manager for worker construction. */
	[[nodiscard]] module_manager &modules() noexcept;

	/**
	 * @brief Bind every admitted context to its exact worker telemetry channel.
	 * @param runtime_generation Exact nonzero materialized runtime generation.
	 * @param channels Compact worker-indexed complete channel table.
	 * @return OK after all contexts bind exactly once.
	 */
	[[nodiscard]] common::status
	bind_telemetry_channels(uint64_t runtime_generation,
				std::span<worker_telemetry_channel *const> channels) noexcept;
	/** @brief Release every telemetry-channel borrow after all banks retire. */
	void unbind_telemetry_channels() noexcept;
	/**
	 * @brief Resolve one owner worker's context telemetry list.
	 * @param worker_index Exact compact owner-worker identity.
	 * @return Context telemetry owners serviced by that worker's packet-loop cadence.
	 */
	[[nodiscard]] std::span<lifecycle::lifecycle_context_owner *const>
	worker_telemetry_contexts(uint32_t worker_index) noexcept;
	/** @return Exact admitted context count in the telemetry ownership projection. */
	[[nodiscard]] std::size_t telemetry_context_count() const noexcept;
	/**
	 * @brief Resolve one context telemetry owner.
	 * @param context_index Exact compact context identity.
	 * @return Admitted context telemetry owner, or null when unbound or unknown.
	 */
	[[nodiscard]] lifecycle::lifecycle_context_owner *telemetry_context(uint32_t context_index) noexcept;
	/**
	 * @brief Reserve every context's target telemetry bank all-or-none before PREPARE callbacks.
	 * @param from_epoch Exact currently published epoch.
	 * @param to_epoch Exact advancing target epoch.
	 * @return OK after every context reserves the same target generation.
	 */
	[[nodiscard]] common::status reserve_transition_telemetry(uint64_t from_epoch, uint64_t to_epoch) noexcept;
	/**
	 * @brief Release every unused target telemetry reserve after exact abort cleanup.
	 * @param to_epoch Exact abandoned target epoch.
	 */
	void discard_transition_telemetry(uint64_t to_epoch) noexcept;
	/** @brief Mark every context owner quiescent after its packet worker joins. */
	void mark_telemetry_workers_quiesced() noexcept;

	/** @return true when the exact lifecycle-service set is running. */
	[[nodiscard]] bool lifecycle_services_running() const noexcept;

	/** @return Aggregate nonblocking wake descriptor for lifecycle results. */
	[[nodiscard]] int lifecycle_notification_descriptor() const noexcept;

	/**
	 * @brief Consume one coalesced wake without consuming result ownership.
	 * @return Coalesced wake count, zero when already drained, or descriptor failure.
	 */
	[[nodiscard]] common::status_or<uint64_t> consume_lifecycle_notification() noexcept;

    private:
	friend class ::kinetum::dp::epoch_transition_preparation;

	class implementation;

	/** @copydoc epoch_transition_module_completion::completion_context_count */
	[[nodiscard]] std::size_t completion_context_count() const noexcept override;
	/** @copydoc epoch_transition_module_completion::completion_image_count */
	[[nodiscard]] std::size_t completion_image_count() const noexcept override;
	/** @copydoc epoch_transition_module_completion::completion_executor_count */
	[[nodiscard]] std::size_t completion_executor_count() const noexcept override;
	/** @copydoc epoch_transition_module_completion::completion_context_index */
	[[nodiscard]] uint32_t completion_context_index(std::size_t ordinal) const noexcept override;
	/** @copydoc epoch_transition_module_completion::completion_image_index */
	[[nodiscard]] uint32_t completion_image_index(std::size_t ordinal) const noexcept override;
	/** @copydoc epoch_transition_module_completion::completion_executor_index */
	[[nodiscard]] std::size_t completion_executor_index(std::size_t ordinal) const noexcept override;
	/** @copydoc epoch_transition_module_completion::next_completion_task_sequence */
	[[nodiscard]] uint64_t next_completion_task_sequence() noexcept override;
	/** @copydoc epoch_transition_module_completion::preflight_future_completion */
	[[nodiscard]] common::status preflight_future_completion(uint64_t from_epoch,
								 uint64_t to_epoch) const noexcept override;
	/** @copydoc epoch_transition_module_completion::preflight_completion_activation */
	[[nodiscard]] common::status preflight_completion_activation(uint64_t from_epoch,
								     uint64_t to_epoch) const noexcept override;
	/** @copydoc epoch_transition_module_completion::publish_completion_activation */
	void publish_completion_activation(uint64_t from_epoch, uint64_t to_epoch) noexcept override;
	/** @copydoc epoch_transition_module_completion::preflight_completion_retained */
	[[nodiscard]] common::status preflight_completion_retained(std::size_t ordinal,
								   uint64_t epoch) const noexcept override;
	/** @copydoc epoch_transition_module_completion::claim_completion_retained */
	[[nodiscard]] common::status_or<module_retirement_claim>
	claim_completion_retained(std::size_t ordinal, uint64_t epoch) noexcept override;
	/** @copydoc epoch_transition_module_completion::submit_completion_retire */
	[[nodiscard]] common::status submit_completion_retire(epoch_transition_retire_submission submission,
							      lifecycle::lifecycle_operation_control &control,
							      const module_retirement_claim &claim) noexcept override;
	/** @copydoc epoch_transition_module_completion::try_take_completion_result */
	[[nodiscard]] std::optional<lifecycle::config_lifecycle_result> try_take_completion_result() noexcept override;
	/** @copydoc epoch_transition_module_completion::complete_completion_retirement */
	void complete_completion_retirement(std::size_t ordinal, module_retirement_claim &claim) noexcept override;
	/** @copydoc epoch_transition_module_completion::completion_retirement_complete */
	[[nodiscard]] bool completion_retirement_complete(uint64_t active_epoch) const noexcept override;

	/** @return Exact number of transition-preparable module contexts. */
	[[nodiscard]] std::size_t transition_context_count_() const noexcept;
	/** @return Exact number of loaded module-image serialization domains. */
	[[nodiscard]] std::size_t transition_image_count_() const noexcept;
	/** @return Exact number of NUMA lifecycle executors. */
	[[nodiscard]] std::size_t transition_executor_count_() const noexcept;
	/**
	 * @brief Resolve one exact context's loaded-image owner.
	 * @param context_ordinal Dense context-table ordinal.
	 * @return Exact image index, or an out-of-range sentinel.
	 */
	[[nodiscard]] uint32_t transition_context_image_index_(std::size_t context_ordinal) const noexcept;
	/**
	 * @brief Resolve one exact context identity from its dense operation ordinal.
	 * @param context_ordinal Dense context-table ordinal.
	 * @return Exact compiled context index, or UINT32_MAX when out of range.
	 */
	[[nodiscard]] uint32_t transition_context_index_(std::size_t context_ordinal) const noexcept;
	/**
	 * @brief Resolve one exact context's NUMA executor.
	 * @param context_ordinal Dense context-table ordinal.
	 * @return Exact executor ordinal, or executor-count sentinel.
	 */
	[[nodiscard]] std::size_t transition_context_executor_index_(std::size_t context_ordinal) const noexcept;
	/** @return Next never-reused lifecycle task identity. */
	[[nodiscard]] uint64_t next_transition_task_sequence_() noexcept;
	/**
	 * @brief Validate candidate module configuration against admitted images.
	 * @param snapshot Immutable canonical candidate snapshot.
	 * @return OK on exact sorted coverage and one live baseline epoch.
	 */
	[[nodiscard]] common::status
	validate_transition_snapshot_(const kinetum::control::v1::ConfigSnapshot &snapshot) const;
	/**
	 * @brief Allocate one exact authored arena before callback dispatch.
	 * @param context_ordinal Dense context-table ordinal.
	 * @param epoch Exact advancing target epoch.
	 * @return Sole arena ownership or exact allocation/admission failure.
	 */
	[[nodiscard]] common::status_or<lifecycle::epoch_arena_ownership>
	allocate_transition_arena_(std::size_t context_ordinal, uint64_t epoch) noexcept;
	/**
	 * @brief Construct and transfer one PREPARE task to its exact executor.
	 * @param context_ordinal Dense exact context ordinal.
	 * @param task_sequence Never-reused lifecycle task identity.
	 * @param epoch Exact target epoch.
	 * @param snapshot Immutable candidate retaining config bytes through result.
	 * @param control Stable deadline/cancellation owner.
	 * @param arena Sole exact epoch arena transferred only on accepted construction.
	 * @return OK after executor ownership transfer; otherwise no callback ran.
	 */
	[[nodiscard]] common::status submit_transition_prepare_(std::size_t context_ordinal, uint64_t task_sequence,
								uint64_t epoch,
								const kinetum::control::v1::ConfigSnapshot &snapshot,
								lifecycle::lifecycle_operation_control &control,
								lifecycle::epoch_arena_ownership &&arena) noexcept;
	/**
	 * @brief Construct and transfer one direct-token RETIRE task.
	 * @param context_ordinal Dense exact context ordinal.
	 * @param task_sequence Never-reused lifecycle task identity.
	 * @param control Stable non-cancelled RETIRE operation control.
	 * @param prepared Exact token retained by the transient owner through result.
	 * @return OK after executor ownership transfer; otherwise no callback ran.
	 */
	[[nodiscard]] common::status
	submit_transition_retire_(std::size_t context_ordinal, uint64_t task_sequence,
				  lifecycle::lifecycle_operation_control &control,
				  const lifecycle::prepared_config_ownership &prepared) noexcept;
	/** @return One currently available executor result, or nullopt after a complete scan. */
	[[nodiscard]] std::optional<lifecycle::config_lifecycle_result> try_take_transition_result_() noexcept;
	/**
	 * @brief Transfer one successful token into its exact context store.
	 * @param context_ordinal Dense exact context ordinal.
	 * @param prepared Sole token consumed only on successful staging.
	 * @return OK after PREPARED publication; otherwise caller retains ownership.
	 */
	[[nodiscard]] common::status
	stage_transition_prepared_(std::size_t context_ordinal,
				   lifecycle::prepared_config_ownership &prepared) noexcept;
	/**
	 * @brief Withdraw one exact PREPARED token for abort cleanup.
	 * @param context_ordinal Dense exact context ordinal.
	 * @param epoch Exact prepared target epoch.
	 * @return Sole token ownership or exact state/identity failure.
	 */
	[[nodiscard]] common::status_or<lifecycle::prepared_config_ownership>
	discard_transition_prepared_(std::size_t context_ordinal, uint64_t epoch) noexcept;
	/**
	 * @brief Preflight every context's non-failing target activation.
	 * @param epoch Exact prepared target epoch.
	 * @return OK only after complete context-store proof.
	 */
	[[nodiscard]] common::status preflight_transition_prepared_(uint64_t epoch) const noexcept;
	/**
	 * @brief Publish complete module-side PREPARED ownership after preflight.
	 * @param epoch Exact target now owned by every context store.
	 */
	void publish_transition_prepared_(uint64_t epoch) noexcept;
	/**
	 * @brief Clear module-side PREPARED identity after complete retirement.
	 * @param epoch Exact target removed from every context store.
	 */
	void clear_transition_prepared_(uint64_t epoch) noexcept;
	/**
	 * @brief Consume one exact direct token after matching RETIRE completion.
	 * @param context_ordinal Dense exact context ordinal.
	 * @param prepared Sole token whose callback completion was identity-checked.
	 */
	void complete_transition_retirement_(std::size_t context_ordinal,
					     lifecycle::prepared_config_ownership &prepared) noexcept;
	/**
	 * @brief Adopt one fully admitted cold generation implementation.
	 *
	 * @param implementation Sole module/lifecycle generation owner.
	 */
	explicit module_runtime_generation(std::unique_ptr<implementation> implementation) noexcept;

	std::unique_ptr<implementation> implementation_;  ///< Sole module/lifecycle generation owner.
};

}  // namespace kinetum::dp::module
