// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_telemetry_aggregator.hpp
 * @brief Sole cold merger of immutable owner-worker telemetry banks.
 * @author Fleming Patel
 *
 * Packet workers transfer completed banks through exact SPSC channels and
 * publish context health through coherent latest-value snapshots. This owner
 * validates every identity against frozen compiled truth, merges each bank
 * once, and reads no live packet-worker or module state.
 *
 * @par Thread Safety
 * One coordinator thread owns service, bank lifecycle, and retirement state.
 * Foreign source readers serialize aggregate copying, bounded health-snapshot
 * reads, and nonregression checks under `aggregate_mutex_`. A health read is
 * only an atomic coherent-publication read; the mutex is never held while
 * invoking a mutable bank owner, module callback, provider, or source-lifetime
 * operation.
 *
 * @par Performance
 * This owner is cold. Token service is allocation-free after construction.
 * Histogram merging advances by a fixed bucket prefix per call; no worker
 * waits for it and no plan capacity becomes a work-per-call target.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_transition_telemetry_completion.hpp"
#include "src/dp/runtime_telemetry_bank.hpp"
#include "src/dp/runtime_telemetry.hpp"

namespace kinetum::provider
{
struct compiled_provider_topology;
}  // namespace kinetum::provider

namespace kinetum::dp
{

namespace module
{
class module_runtime_generation;
}  // namespace module

namespace lifecycle
{
class lifecycle_context_owner;
struct lifecycle_module_telemetry_bank_view;
}  // namespace lifecycle

class runtime_status_publication;
class worker_runtime_telemetry;
class worker_telemetry_channel;

/** @brief Generation-scoped immutable-bank aggregator and telemetry source. */
class runtime_telemetry_aggregator final : public epoch_transition_telemetry_completion {
    public:
	/**
	 * @brief Construct complete aggregate rows before CONTROL_READY.
	 * @param runtime_generation Exact nonzero runtime generation.
	 * @param topology Sole compiled identity authority.
	 * @param channels Compact worker-indexed channel table.
	 * @param workers Compact worker-indexed bank-owner table.
	 * @param modules Exact admitted module/context owner.
	 * @param runtime_status Sole readiness/epoch publication.
	 * @return Complete aggregator or a fail-closed allocation/identity status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<runtime_telemetry_aggregator>>
	create(uint64_t runtime_generation, const provider::compiled_provider_topology &topology,
	       std::span<worker_telemetry_channel *const> channels, std::span<worker_runtime_telemetry *const> workers,
	       module::module_runtime_generation &modules, const runtime_status_publication &runtime_status);

	runtime_telemetry_aggregator(const runtime_telemetry_aggregator &) = delete;
	runtime_telemetry_aggregator &operator=(const runtime_telemetry_aggregator &) = delete;
	runtime_telemetry_aggregator(runtime_telemetry_aggregator &&) = delete;
	runtime_telemetry_aggregator &operator=(runtime_telemetry_aggregator &&) = delete;
	/** @brief Destroy only after every channel and bank is reclaimed. */
	~runtime_telemetry_aggregator();

	/**
	 * @brief Perform at most one bounded prefix per service unit.
	 * @param budget Maximum completed-token or histogram-prefix service units.
	 * @return Number of bounded service units performed.
	 */
	[[nodiscard]] std::size_t service(std::size_t budget) noexcept;
	/** @return true when a bank token or incremental histogram merge remains pending. */
	[[nodiscard]] bool work_pending() const noexcept;
	/** @brief Drain every currently published token after workers are quiescent. */
	void drain_quiescent() noexcept;

	/**
	 * @param epoch Exact candidate old epoch.
	 * @return true only when every worker old-epoch bank is aggregated.
	 */
	[[nodiscard]] bool worker_epoch_aggregated(uint64_t epoch) const noexcept override;
	/**
	 * @param epoch Exact candidate old epoch.
	 * @return true only when every module-context old-epoch bank is aggregated.
	 */
	[[nodiscard]] bool module_epoch_aggregated(uint64_t epoch) const noexcept override;
	/**
	 * @brief Reconcile module-bank retirement and any target-bank transfer.
	 * @param epoch Exact old epoch already retired from every module store.
	 * @param active_epoch Exact target epoch, or zero for final shutdown.
	 */
	void complete_module_epoch_retirement(uint64_t epoch, uint64_t active_epoch) noexcept override;
	/**
	 * @brief Reclaim every worker's old banks after exact reader grace.
	 * @param epoch Exact old epoch.
	 * @param active_epoch Exact target epoch, or zero for final shutdown.
	 */
	void retire_worker_epoch(uint64_t epoch, uint64_t active_epoch) noexcept override;
	/**
	 * @brief Mark packet workers quiescent before post-join reclamation.
	 *
	 * This one-way edge permits cold target-bank promotion without publishing a
	 * return token to an exited worker.
	 */
	void mark_workers_quiesced() noexcept;

	/**
	 * @brief Copy the last coherent aggregate through the production source shape.
	 * @param request Exact row selection requested by the cold caller.
	 * @return Coherent generation snapshot or unavailable runtime-status truth.
	 */
	[[nodiscard]] common::status_or<runtime_telemetry_snapshot>
	collect(const runtime_telemetry_request &request) const;
	/** @return Exact compiled worker count. */
	[[nodiscard]] uint32_t expected_workers() const noexcept;

    private:
	/** @brief Track one worker or context owner's cold bank-return state. */
	struct owner_aggregation_state {
		std::optional<runtime_telemetry_bank_token> returned;  ///< Cleared bank not yet reused/retained.
		std::array<uint64_t, RUNTIME_TELEMETRY_BANK_COUNT> retained_epochs{};  ///< Epoch per retained slot.
	};

	/** @brief Accumulate one registered histogram into preallocated cold storage. */
	struct histogram_accumulator {
		runtime_module_histogram_statistics row;  ///< Current exact aggregate projection.
		std::vector<uint64_t> counts;		  ///< Preallocated merged bucket counts.
		kinetum_histogram geometry{};		  ///< Stable cold percentile geometry.
	};

	/** @brief Bind one module context to its exact aggregate rows and bank owner. */
	struct module_binding {
		uint32_t context_index{0};			     ///< Exact compact context identity.
		int32_t region_id{-1};				     ///< Exact owner execution region.
		lifecycle::lifecycle_context_owner *owner{nullptr};  ///< Exact bank owner.
		std::vector<std::size_t> counter_rows;		     ///< Descriptor ordinal to aggregate row.
		std::vector<std::size_t> histogram_rows;	     ///< Descriptor ordinal to aggregate row.
		std::size_t mismatch_row{0};			     ///< Exact coherent mismatch row.
		std::size_t health_row{0};			     ///< Exact context health row.
		bool health_callback_available{false};		     ///< Immutable admitted callback presence.
		owner_aggregation_state aggregation;		     ///< Cold bank-lifecycle truth.
		bool observed{false};				     ///< Whether one complete bank committed.
	};

	/** @brief Last health identity accepted by the serialized cold reader. */
	struct health_observation_state {
		uint64_t publication_generation{0};    ///< Last coherent publication generation.
		uint64_t observation_epoch{0};	       ///< Last nonregressing attempt epoch.
		uint64_t observed_at_ns{0};	       ///< Last nonregressing attempt timestamp.
		uint64_t callback_duration_ns{0};      ///< Last exact callback duration.
		uint64_t contract_fault_count{0};      ///< Last nonregressing fault population.
		uint64_t first_fault_epoch{0};	       ///< Immutable accepted first-fault epoch.
		uint64_t first_fault_timestamp_ns{0};  ///< Immutable accepted first-fault timestamp.
		uint64_t first_fault_duration_ns{0};   ///< Immutable accepted first-fault duration.
		kinetum_health_signal signal{};	       ///< Last exact normalized signal or zero value.
		uint16_t latest_fault_mask{0};	       ///< Last attempted-callback fault bits.
		uint16_t first_fault_mask{0};	       ///< Immutable accepted first-fault bits.
		uint8_t signal_available{0};	       ///< Whether @c signal is semantic.
	};

	/**
	 * @brief Adopt fully allocated immutable authority references.
	 * @param runtime_generation Exact nonzero generation.
	 * @param topology Frozen compiled identity authority.
	 * @param channels Compact worker-indexed channel table.
	 * @param workers Compact worker-indexed bank-owner table.
	 * @param modules Exact module-context generation.
	 * @param runtime_status Sole readiness/epoch publication.
	 */
	runtime_telemetry_aggregator(uint64_t runtime_generation, const provider::compiled_provider_topology &topology,
				     std::vector<worker_telemetry_channel *> channels,
				     std::vector<worker_runtime_telemetry *> workers,
				     module::module_runtime_generation &modules,
				     const runtime_status_publication &runtime_status) noexcept;

	/** @return OK after preallocating and auditing every aggregate row. */
	[[nodiscard]] common::status initialize_();
	/**
	 * @brief Consume one exact completed token or retained-return acknowledgment.
	 * @param token Sole token removed from its worker's completed ring.
	 */
	void consume_(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @brief Merge and resolve one exact immutable worker bank.
	 * @param token Exact completed-bank identity.
	 * @param owner Worker bank owner named by @p token.
	 */
	void merge_worker_(const runtime_telemetry_bank_token &token, worker_runtime_telemetry &owner) noexcept;
	/**
	 * @brief Begin one bounded module-bank merge and capture absolute rows once.
	 * @param token Exact completed-bank identity.
	 * @param binding Exact module owner and aggregate-row projection.
	 */
	void begin_module_merge_(const runtime_telemetry_bank_token &token, module_binding &binding) noexcept;
	/** @return true after the pending module bank is completely merged. */
	[[nodiscard]] bool progress_module_merge_() noexcept;
	/**
	 * @brief Resolve one fully merged module bank into return or retention state.
	 * @param token Exact completed-bank identity.
	 * @param binding Exact module owner and aggregate-row projection.
	 */
	void complete_module_merge_(const runtime_telemetry_bank_token &token, module_binding &binding) noexcept;
	/**
	 * @brief Commit all aggregate rows from one merged module bank under the aggregate lock.
	 * @param token Exact completed-bank identity.
	 * @param binding Exact module owner and aggregate-row projection.
	 * @param bank Immutable completed-bank view already validated without the lock.
	 */
	void commit_module_rows_(const runtime_telemetry_bank_token &token, module_binding &binding,
				 const lifecycle::lifecycle_module_telemetry_bank_view &bank) noexcept;
	/**
	 * @brief Consume one exact worker acknowledgment that a returned bank stayed old.
	 * @param token Exact acknowledgment removed from the completed ring.
	 */
	void consume_return_retained_(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @brief Retire an outstanding return proven reused by a later bank publication.
	 * @param state Coordinator-owned lifecycle for the exact owner.
	 * @param token Later bank publication proving return consumption.
	 */
	void reconcile_reused_return_(owner_aggregation_state &state,
				      const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @brief Add one exact retained bank identity to coordinator-owned state.
	 * @param state Coordinator-owned lifecycle for the exact owner.
	 * @param epoch Exact retained epoch.
	 * @param bank_index Exact retained bank slot.
	 */
	void record_retained_(owner_aggregation_state &state, uint64_t epoch, uint8_t bank_index) noexcept;
	/**
	 * @brief Publish a complete worker-bank epoch verdict when two slots exist.
	 * @param state Coordinator-owned lifecycle for the worker.
	 * @param owner Exact worker bank owner.
	 * @param epoch Exact epoch whose retained slots are being tested.
	 */
	void mark_complete_(owner_aggregation_state &state, worker_runtime_telemetry &owner, uint64_t epoch) noexcept;
	/**
	 * @brief Publish a complete module-bank epoch verdict when two slots exist.
	 * @param state Coordinator-owned lifecycle for the module context.
	 * @param owner Exact module bank owner.
	 * @param epoch Exact epoch whose retained slots are being tested.
	 */
	void mark_complete_(owner_aggregation_state &state, lifecycle::lifecycle_context_owner &owner,
			    uint64_t epoch) noexcept;
	/**
	 * @brief Remember one cleared bank transferred asynchronously to its worker.
	 * @param state Coordinator-owned lifecycle for the exact owner.
	 * @param token Exact cleared-bank transfer.
	 */
	void remember_return_(owner_aggregation_state &state, const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @brief Reconcile one post-grace reclaimed-bank transfer.
	 * @param state Coordinator-owned lifecycle for the exact owner.
	 * @param token Exact returned or cold-retained reclaimed bank.
	 * @param owner_kind Expected worker or module namespace.
	 * @param worker_index Exact compact worker owner.
	 * @param owner_index Exact worker or module-context owner.
	 * @param stage_instance_index Exact module stage, or UINT16_MAX for a worker bank.
	 */
	void consume_retirement_transfer_(owner_aggregation_state &state, const runtime_telemetry_bank_token &token,
					  runtime_telemetry_bank_owner_kind owner_kind, uint32_t worker_index,
					  uint32_t owner_index, uint16_t stage_instance_index) noexcept;
	/**
	 * @param context_index Compiled module-context identity to locate.
	 * @return Borrowed exact module binding, or nullptr when absent.
	 */
	[[nodiscard]] module_binding *find_module_(uint32_t context_index) noexcept;
	uint64_t runtime_generation_{0};			   ///< Exact materialized generation.
	const provider::compiled_provider_topology &topology_;	   ///< Frozen compiled identities.
	std::vector<worker_telemetry_channel *> channels_;	   ///< Compact bank-token channels.
	std::vector<worker_runtime_telemetry *> workers_;	   ///< Compact worker bank owners.
	std::vector<owner_aggregation_state> worker_aggregation_;  ///< Coordinator-owned worker-bank truth.
	std::vector<uint8_t> worker_observed_;			   ///< One after each worker's first complete bank.
	module::module_runtime_generation &modules_;		   ///< Exact module telemetry lookup.
	const runtime_status_publication &runtime_status_;	   ///< Sole readiness/epoch observation.
	mutable std::mutex aggregate_mutex_;			   ///< Cold aggregate copy/merge serialization.
	runtime_telemetry_snapshot aggregate_;			   ///< Last coherent cumulative aggregate.
	std::vector<module_binding> module_bindings_;		   ///< Sorted exact context bindings.
	mutable std::vector<health_observation_state> health_observations_;  ///< Serialized reader exactness.
	std::vector<histogram_accumulator> histograms_;			     ///< Preallocated histogram aggregates.
	std::size_t service_cursor_{0};					     ///< Cold fair worker-channel cursor.
	std::optional<runtime_telemetry_bank_token> pending_module_token_;   ///< Aggregator-owned bank token.
	module_binding *pending_module_binding_{nullptr};		     ///< Exact binding for the pending token.
	std::size_t pending_histogram_ordinal_{0};			     ///< Current histogram within the bank.
	std::size_t pending_bucket_{0};					     ///< Next bucket in the current histogram.
	uint64_t pending_histogram_source_count_{0};  ///< Exact mass in the current source buckets.
	bool pending_histogram_started_{false};	      ///< Whether summary metadata merged once.
	bool pending_histogram_replace_{false};	      ///< Whether prefixes overwrite a prior epoch's buckets.
	bool module_commit_in_progress_{false};	      ///< Aggregate lock guards a partially merged module bank.
	bool stream_accounting_exhausted_{false};     ///< Aggregate lock guards permanent loss of exact counter range.
	bool workers_quiesced_{false};		      ///< Whether all bank producers have exited.
};

}  // namespace kinetum::dp
