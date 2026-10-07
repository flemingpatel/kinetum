// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file transition_plan_lowering.cpp
 * @brief Transactional epoch-transition policy lowering implementation.
 * @author Fleming Patel
 */

#include "src/gluon/transition_plan_lowering.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>

#include "src/common/transition_topology.hpp"

namespace kinetum::gluon
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_code;

/** @brief Stable owner key used while emitting source-worker capacity. */
struct worker_owner_key {
	int32_t region_id{-1};	///< Logical region.
	std::string lane_id;	///< Execution lane.

	/**
	 * @brief Compare owner keys deterministically.
	 *
	 * @param other Key to compare.
	 * @return true when this key precedes @p other.
	 */
	[[nodiscard]] bool operator<(const worker_owner_key &other) const noexcept
	{
		return std::tie(region_id, lane_id) < std::tie(other.region_id, other.lane_id);
	}
};

}  // namespace

status lower_transition_plan(kinetum::gluon::v1::DeploymentPlan &plan)
{
	if (plan.has_epoch_transition_plan()) {
		return status(status_code::INVALID_ARGUMENT,
			      "transition-plan lowering requires absent epoch_transition_plan");
	}
	for (const auto &worker : plan.worker_placements()) {
		if (worker.source_epoch_staging_capacity() != 0 || worker.module_health_poll_interval_ms() != 0 ||
		    worker.module_health_callback_budget_ns() != 0) {
			return status(status_code::INVALID_ARGUMENT,
				      "transition-plan lowering requires zero preexisting worker transition fields",
				      worker.worker_id());
		}
	}

	kinetum::gluon::v1::DeploymentPlan candidate = plan;
	for (const auto &stage : candidate.pipeline().stages()) {
		const auto &limits = stage.active_stage_limits();
		const bool async_capacity_present = limits.async_work_capacity() != 0u;
		const bool async_grace_present = limits.async_cancel_grace_ms() != 0u;
		if (async_capacity_present != async_grace_present ||
		    (stage.execution_mode() != kinetum::axiom::v1::EXECUTION_MODE_ACTIVE &&
		     (async_capacity_present || async_grace_present))) {
			return status(status_code::INVALID_ARGUMENT,
				      "transition-plan lowering found contradictory tracked-async resources",
				      stage.stage_id());
		}
		if (async_grace_present && limits.async_cancel_grace_ms() >= TRANSITION_COMMIT_TIMEOUT_MS) {
			return status(status_code::INVALID_ARGUMENT,
				      "tracked-async cancellation grace must be shorter than commit timeout",
				      stage.stage_id());
		}
	}
	std::unordered_map<std::string, kinetum::axiom::v1::StageKind> stage_kinds;
	std::unordered_map<std::string, kinetum::axiom::v1::ExecutionMode> stage_execution_modes;
	stage_kinds.reserve(static_cast<std::size_t>(candidate.pipeline().stages_size()));
	stage_execution_modes.reserve(static_cast<std::size_t>(candidate.pipeline().stages_size()));
	for (const auto &stage : candidate.pipeline().stages()) {
		stage_kinds.emplace(stage.stage_id(), stage.kind());
		stage_execution_modes.emplace(stage.stage_id(), stage.execution_mode());
	}

	std::map<worker_owner_key, uint32_t> worker_index_by_owner;
	for (const auto &worker : candidate.worker_placements()) {
		worker_index_by_owner.emplace(worker_owner_key{worker.region_id(), worker.lane_id()},
					      worker.worker_index());
	}
	std::set<uint32_t> source_worker_indices;
	for (const auto &instance : candidate.stage_instances()) {
		const auto stage_it = stage_kinds.find(instance.logical_stage_id());
		if (stage_it == stage_kinds.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "transition-plan lowering encountered unknown logical stage '" +
					      instance.logical_stage_id() + "'",
				      instance.stage_instance_id());
		}
		const auto execution_mode_it = stage_execution_modes.find(instance.logical_stage_id());
		if (execution_mode_it == stage_execution_modes.end()) {
			return status::internal_error("transition-plan lowering lost logical-stage execution mode");
		}
		const bool active = execution_mode_it->second == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE;
		const bool has_active_origin = !instance.active_origin_storage_domain_id().empty();
		if (active != has_active_origin) {
			return status(status_code::INVALID_ARGUMENT,
				      active ? "active stage instance requires one exact origin storage domain" :
					       "passive stage instance must not carry an origin storage domain",
				      instance.stage_instance_id());
		}
		if (stage_it->second != kinetum::axiom::v1::STAGE_KIND_RX && !has_active_origin) {
			continue;
		}
		const auto worker_it =
			worker_index_by_owner.find(worker_owner_key{instance.region_id(), instance.lane_id()});
		if (worker_it == worker_index_by_owner.end()) {
			return status(status_code::INVALID_ARGUMENT,
				      "originating stage instance '" + instance.stage_instance_id() +
					      " has no exact source worker",
				      instance.stage_instance_id());
		}
		source_worker_indices.insert(worker_it->second);
	}

	for (auto &worker : *candidate.mutable_worker_placements()) {
		worker.set_source_epoch_staging_capacity(
			source_worker_indices.contains(worker.worker_index()) ? SOURCE_EPOCH_STAGING_CAPACITY : 0u);
		worker.set_module_health_poll_interval_ms(MODULE_HEALTH_POLL_INTERVAL_MS);
		worker.set_module_health_callback_budget_ns(MODULE_HEALTH_CALLBACK_BUDGET_NS);
	}

	auto *policy = candidate.mutable_epoch_transition_plan();
	for (const auto &service : candidate.runtime_service_placements()) {
		switch (service.service_kind()) {
		case kinetum::gluon::v1::RUNTIME_SERVICE_KIND_EPOCH_TRANSITION_COORDINATOR:
			policy->set_coordinator_service_id(service.service_id());
			break;
		case kinetum::gluon::v1::RUNTIME_SERVICE_KIND_CONFIG_LIFECYCLE_EXECUTOR:
			policy->add_lifecycle_executor_service_ids(service.service_id());
			break;
		case kinetum::gluon::v1::RUNTIME_SERVICE_KIND_UNSPECIFIED:
		case kinetum::gluon::v1::RuntimeServiceKind_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::RuntimeServiceKind_INT_MAX_SENTINEL_DO_NOT_USE_:
			// The shared compiler owns the exact rejection and diagnostic.
			break;
		}
	}
	policy->set_prepare_timeout_ms(TRANSITION_PREPARE_TIMEOUT_MS);
	policy->set_prepare_cancel_grace_ms(TRANSITION_PREPARE_CANCEL_GRACE_MS);
	policy->set_prepared_lease_timeout_ms(TRANSITION_PREPARED_LEASE_TIMEOUT_MS);
	policy->set_commit_timeout_ms(TRANSITION_COMMIT_TIMEOUT_MS);
	policy->set_retirement_timeout_ms(TRANSITION_RETIREMENT_TIMEOUT_MS);
	policy->set_result_history_capacity(TRANSITION_RESULT_HISTORY_CAPACITY);

	auto compiled_or = kinetum::common::compile_transition_topology(candidate);
	if (!compiled_or.is_ok()) {
		return compiled_or.error();
	}
	if (!compiled_or.value().policy.enabled) {
		return status(status_code::INTERNAL_ERROR, "transition-plan lowering produced a fixed-epoch candidate");
	}

	plan.Swap(&candidate);
	return status::ok();
}

}  // namespace kinetum::gluon
