// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_telemetry_snapshot_source.hpp
 * @brief Complete generation-scoped runtime telemetry composition authority.
 * @author Fleming Patel
 *
 * The source composes completed counter banks, coherent ordered-transition
 * publications, the immutable certificate graph, typed provider observations,
 * and compiled static identity into one all-or-none cold snapshot.
 *
 * @par Thread Safety
 * `runtime_telemetry_source_owner` serializes collect() and fences retirement.
 * Provider callbacks run with no platform lock held. Every borrowed authority
 * outlives this source and is retired only after source-owner quiescence.
 *
 * @par Performance
 * Cold gRPC/coordinator work only. Static identity projections and provider
 * callback buffers are preallocated at construction; each requested immutable
 * result may allocate its own bounded value storage. No method is reachable
 * from a packet worker.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/epoch/epoch_transition_certificate.hpp"
#include "src/dp/epoch/epoch_transition_completion.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/runtime_status.hpp"
#include "src/dp/runtime_telemetry.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_runtime_materialization.hpp"

namespace kinetum::dp
{

class runtime_telemetry_aggregator;

/**
 * @brief Classify the runtime epoch tuple against stable coordinator authority.
 * @param status Intrinsically validated runtime publication.
 * @param transition Coordinator publication fenced unchanged across both runtime reads.
 * @return AVAILABLE for alignment, UNAVAILABLE for a legal publication gap, or INVALID_STATE.
 */
[[nodiscard]] publication_read_result
classify_runtime_status_transition(const runtime_status_snapshot &status,
				   const epoch_transition_progress_snapshot &transition) noexcept;

/**
 * @brief Project completion evidence against one stable coordinator observation.
 * @param read Availability and intrinsic validity of this attempt's completion read.
 * @param value Completion value, consumed only when AVAILABLE.
 * @param progress Coordinator progress fenced unchanged across the collection.
 * @param transactions Transactions from the same coordinator publication.
 * @return Exact current/latest evidence, absence for no applicable completion, or a failure.
 */
[[nodiscard]] common::status_or<std::optional<epoch_transition_completion_progress_snapshot>>
project_runtime_completion_progress(publication_read_result read,
				    const epoch_transition_completion_progress_snapshot &value,
				    const epoch_transition_progress_snapshot &progress,
				    const epoch_transition_telemetry_snapshot &transactions);

/** @brief One final source published through the generation claim owner. */
class runtime_telemetry_snapshot_source final : public runtime_telemetry_source {
    public:
	/**
	 * @brief Preallocate and audit one complete source projection.
	 * @param runtime_generation Exact materialized runtime generation.
	 * @param topology Sole immutable compiled topology.
	 * @param providers Complete materialized provider generation.
	 * @param aggregator Sole completed-bank aggregation authority.
	 * @param runtime_status Sole coherent runtime status publication.
	 * @param coordinator Sole transition phase/transaction authority.
	 * @param certificate Sole immutable worker/boundary source graph.
	 * @param completion Completion progress owner, or null when transitions are disabled.
	 * @param protocol_faults Process-generation protocol safety-fault authority.
	 * @return Complete source or a cold allocation/membership failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<runtime_telemetry_snapshot_source>>
	create(uint64_t runtime_generation, const provider::compiled_provider_topology &topology,
	       const provider::materialized_provider_runtime &providers, runtime_telemetry_aggregator &aggregator,
	       const runtime_status_publication &runtime_status, const epoch_transition_coordinator &coordinator,
	       const epoch_transition_certificate &certificate, const epoch_transition_completion *completion,
	       const epoch_protocol_fault_latch &protocol_faults);

	runtime_telemetry_snapshot_source(const runtime_telemetry_snapshot_source &) = delete;
	runtime_telemetry_snapshot_source &operator=(const runtime_telemetry_snapshot_source &) = delete;
	runtime_telemetry_snapshot_source(runtime_telemetry_snapshot_source &&) = delete;
	runtime_telemetry_snapshot_source &operator=(runtime_telemetry_snapshot_source &&) = delete;
	~runtime_telemetry_snapshot_source() override = default;

	/** @copydoc runtime_telemetry_source::collect */
	[[nodiscard]] common::status_or<runtime_telemetry_snapshot>
	collect(const runtime_telemetry_request &request) const override;

    private:
	/** @brief One preallocated whole-driver callback projection. */
	struct driver_binding {
		const kinetum_provider_io_driver_operations *operations{nullptr};  ///< Exact immutable callback table.
		std::vector<std::size_t> port_rows{};  ///< Driver-local to global port-row projection.
		std::vector<kinetum_provider_port_observation> ports{};	 ///< Caller-owned complete port batch.
	};

	/**
	 * @brief Retain the immutable identities and cold observation authorities for one runtime generation.
	 * @param runtime_generation Exact generation shared by every borrowed owner.
	 * @param topology Compiled row identities and provider bindings.
	 * @param providers Materialized provider callbacks and their lifetime owner.
	 * @param aggregator Coherent worker and module observation authority.
	 * @param runtime_status Published runtime readiness and lifecycle state.
	 * @param coordinator Current transition state authority.
	 * @param certificate Participant completion and reader-grace evidence.
	 * @param completion Optional transition completion owner.
	 * @param protocol_faults Retained first-fault authority.
	 */
	runtime_telemetry_snapshot_source(
		uint64_t runtime_generation, const provider::compiled_provider_topology &topology,
		const provider::materialized_provider_runtime &providers, runtime_telemetry_aggregator &aggregator,
		const runtime_status_publication &runtime_status, const epoch_transition_coordinator &coordinator,
		const epoch_transition_certificate &certificate, const epoch_transition_completion *completion,
		const epoch_protocol_fault_latch &protocol_faults) noexcept;
	/** @return OK after preallocating and validating every static row and callback. */
	[[nodiscard]] common::status initialize_();
	/**
	 * @brief Fill selected provider rows through exact cold callbacks.
	 * @param[in,out] snapshot Complete source-owned result under construction.
	 * @param request Exact selected provider row families.
	 * @return OK after complete typed observations, or a provider,
	 *         identity, or bounded-resource failure without partial success.
	 */
	[[nodiscard]] common::status observe_providers_(runtime_telemetry_snapshot &snapshot,
							const runtime_telemetry_request &request) const;

	uint64_t runtime_generation_{0};			       ///< Exact materialized generation.
	const provider::compiled_provider_topology &topology_;	       ///< Sole static identity authority.
	const provider::materialized_provider_runtime &providers_;     ///< Exact cold provider operations.
	runtime_telemetry_aggregator &aggregator_;		       ///< Sole completed-bank aggregate.
	const runtime_status_publication &runtime_status_;	       ///< Coherent runtime/epoch truth.
	const epoch_transition_coordinator &coordinator_;	       ///< Sole transaction/phase publication.
	const epoch_transition_certificate &certificate_;	       ///< Immutable worker/boundary source graph.
	const epoch_transition_completion *completion_{nullptr};       ///< Optional committed progress source.
	const epoch_protocol_fault_latch &protocol_faults_;	       ///< Process-generation safety-fault authority.
	std::vector<runtime_storage_domain_statistics> storage_rows_;  ///< Immutable compiled storage rows.
	std::vector<runtime_io_port_statistics> port_rows_;	       ///< Immutable compiled port rows.
	std::vector<runtime_traffic_steering_statistics> steering_rows_;  ///< Immutable steering rows.
	std::vector<runtime_module_context_domain> module_context_rows_;  ///< Immutable module-context populations.
	mutable std::vector<driver_binding> drivers_;  ///< Serialized caller-owned provider output storage.
};

}  // namespace kinetum::dp
