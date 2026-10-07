// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file deployment_plan_identity.cpp
 * @brief Provider-aware canonical DeploymentPlan identity implementation.
 * @author Fleming Patel
 */

#include "src/provider/deployment_plan_identity.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/provider/provider_contract_catalog.hpp"

namespace kinetum::provider
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_or;

/**
 * @brief Validate and normalize one declared facility-reference set.
 *
 * @param owner_kind Stable owner category used in diagnostics.
 * @param owner_id Exact provider-instance identity.
 * @param refs Mutable repeated facility references.
 * @return OK after duplicate rejection and lexical sorting.
 */
[[nodiscard]] status normalize_facility_references(std::string_view owner_kind, std::string_view owner_id,
						   google::protobuf::RepeatedPtrField<std::string> *refs)
{
	if (refs == nullptr) {
		return status::internal_error("facility-reference destination must not be null");
	}

	std::vector<std::string> normalized;
	normalized.reserve(static_cast<std::size_t>(refs->size()));
	std::unordered_set<std::string> observed;
	observed.reserve(static_cast<std::size_t>(refs->size()));
	for (const auto &facility_id : *refs) {
		if (facility_id.size() > MAX_PROVIDER_ID_BYTES ||
		    !kinetum::common::execution_topology::is_topology_identifier(facility_id)) {
			return status::invalid_argument(std::string(owner_kind) + " '" + std::string(owner_id) +
							"' has invalid facility_instance_id '" + facility_id + "'");
		}
		if (!observed.insert(facility_id).second) {
			return status::invalid_argument(std::string(owner_kind) + " '" + std::string(owner_id) +
							"' has duplicate facility_instance_id '" + facility_id + "'");
		}
		normalized.push_back(facility_id);
	}
	std::sort(normalized.begin(), normalized.end());
	refs->Clear();
	for (auto &facility_id : normalized) {
		refs->Add(std::move(facility_id));
	}
	return status::ok();
}

/**
 * @brief Validate one provider-instance identity and uniqueness set.
 *
 * @param kind Stable owner category.
 * @param id Candidate exact identity.
 * @param observed Per-category identity set.
 * @return OK for one valid first occurrence.
 */
[[nodiscard]] status validate_instance_identity(std::string_view kind, const std::string &id,
						std::unordered_set<std::string> &observed)
{
	if (id.size() > MAX_PROVIDER_ID_BYTES) {
		return status::invalid_argument(std::string(kind) + " exceeds the " +
						std::to_string(MAX_PROVIDER_ID_BYTES) + "-byte identity bound");
	}
	if (!kinetum::common::execution_topology::is_topology_identifier(id)) {
		return status::invalid_argument(std::string(kind) + " has invalid identity '" + id + "'");
	}
	if (!observed.insert(id).second) {
		return status::invalid_argument("duplicate " + std::string(kind) + " identity '" + id + "'");
	}
	return status::ok();
}

/**
 * @brief Canonicalize one role-owned provider Any in place.
 *
 * @param role Exact role required by the enclosing plan record.
 * @param configuration Mutable provider envelope.
 * @return OK after exact catalog repack or the catalog failure.
 */
[[nodiscard]] status canonicalize_configuration(provider_contract_role role, google::protobuf::Any *configuration)
{
	if (configuration == nullptr) {
		return status::internal_error("provider configuration destination must not be null");
	}
	auto canonical_or = canonicalize_provider_configuration(role, *configuration);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}
	configuration->CopyFrom(canonical_or.value().configuration);
	return status::ok();
}

}  // namespace

common::status canonicalize_tx_storage_binding(kinetum::gluon::v1::TxStorageBinding *binding)
{
	if (binding == nullptr || binding->storage_domain_ids().empty()) {
		return common::status::invalid_argument("TX storage admission requires a nonempty domain set");
	}
	if (const auto unknown = common::reject_unknown_protobuf_fields_recursive(*binding, "TxStorageBinding");
	    !unknown.is_ok()) {
		return unknown;
	}
	std::unordered_set<std::string> observed;
	observed.reserve(static_cast<std::size_t>(binding->storage_domain_ids_size()));
	for (const auto &id : binding->storage_domain_ids()) {
		if (const auto valid = validate_instance_identity("TX storage_domain_id", id, observed);
		    !valid.is_ok()) {
			return valid;
		}
	}
	auto *ids = binding->mutable_storage_domain_ids();
	std::sort(ids->begin(), ids->end());
	return common::status::ok();
}

common::status canonicalize_deployment_plan(kinetum::gluon::v1::DeploymentPlan *plan)
{
	if (plan == nullptr) {
		return status::invalid_argument("DeploymentPlan canonicalization destination must not be null");
	}
	if (const auto unknown_status = common::reject_unknown_protobuf_fields_recursive(*plan, "DeploymentPlan");
	    !unknown_status.is_ok()) {
		return unknown_status;
	}
	if (const auto enum_status = common::reject_invalid_protobuf_enum_values_recursive(*plan, "DeploymentPlan");
	    !enum_status.is_ok()) {
		return enum_status;
	}

	std::unordered_set<std::string> facility_ids;
	facility_ids.reserve(static_cast<std::size_t>(plan->process_facility_instances_size()));
	for (auto &facility : *plan->mutable_process_facility_instances()) {
		if (const auto id_status = validate_instance_identity("facility_instance_id",
								      facility.facility_instance_id(), facility_ids);
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto config_status = canonicalize_configuration(provider_contract_role::PROCESS_FACILITY,
									  facility.mutable_configuration());
		    !config_status.is_ok()) {
			return config_status;
		}
	}

	std::unordered_set<std::string> driver_ids;
	driver_ids.reserve(static_cast<std::size_t>(plan->io_driver_instances_size()));
	for (auto &driver : *plan->mutable_io_driver_instances()) {
		if (const auto id_status = validate_instance_identity("io_driver_instance_id",
								      driver.io_driver_instance_id(), driver_ids);
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto refs_status = normalize_facility_references("I/O driver instance",
									   driver.io_driver_instance_id(),
									   driver.mutable_facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
		if (const auto config_status = canonicalize_configuration(provider_contract_role::IO_DRIVER,
									  driver.mutable_configuration());
		    !config_status.is_ok()) {
			return config_status;
		}
	}

	std::unordered_set<std::string> storage_ids;
	storage_ids.reserve(static_cast<std::size_t>(plan->packet_storage_domains_size()));
	for (auto &storage : *plan->mutable_packet_storage_domains()) {
		if (const auto id_status =
			    validate_instance_identity("storage_domain_id", storage.storage_domain_id(), storage_ids);
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto refs_status = normalize_facility_references("packet storage domain",
									   storage.storage_domain_id(),
									   storage.mutable_facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
		if (const auto config_status = canonicalize_configuration(provider_contract_role::PACKET_STORAGE,
									  storage.mutable_configuration());
		    !config_status.is_ok()) {
			return config_status;
		}
	}

	for (auto &stream : *plan->mutable_io_streams()) {
		switch (stream.direction()) {
		case kinetum::gluon::v1::IO_STREAM_DIRECTION_RX:
			if (!stream.has_rx_storage_domain_id() ||
			    stream.rx_storage_domain_id().size() > MAX_PROVIDER_ID_BYTES ||
			    !common::execution_topology::is_topology_identifier(stream.rx_storage_domain_id())) {
				return common::status::invalid_argument(
					"RX stream requires one exact allocation domain");
			}
			break;
		case kinetum::gluon::v1::IO_STREAM_DIRECTION_TX:
			if (!stream.has_tx_storage()) {
				return common::status::invalid_argument("TX stream requires its storage admission set");
			}
			if (const auto normalized = canonicalize_tx_storage_binding(stream.mutable_tx_storage());
			    !normalized.is_ok()) {
				return normalized;
			}
			break;
		case kinetum::gluon::v1::IO_STREAM_DIRECTION_UNSPECIFIED:
		case kinetum::gluon::v1::IoStreamDirection_INT_MIN_SENTINEL_DO_NOT_USE_:
		case kinetum::gluon::v1::IoStreamDirection_INT_MAX_SENTINEL_DO_NOT_USE_:
			return common::status::invalid_argument("I/O stream requires an exact direction");
		}
	}

	std::unordered_set<std::string> execution_ids;
	execution_ids.reserve(static_cast<std::size_t>(plan->execution_provider_instances_size()));
	for (auto &execution : *plan->mutable_execution_provider_instances()) {
		if (const auto id_status = validate_instance_identity("execution_provider_instance_id",
								      execution.execution_provider_instance_id(),
								      execution_ids);
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto refs_status = normalize_facility_references("execution provider instance",
									   execution.execution_provider_instance_id(),
									   execution.mutable_facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
		if (const auto config_status = canonicalize_configuration(provider_contract_role::EXECUTION,
									  execution.mutable_configuration());
		    !config_status.is_ok()) {
			return config_status;
		}
	}

	std::unordered_set<std::string> transition_ids;
	transition_ids.reserve(static_cast<std::size_t>(plan->storage_transitions_size()));
	for (auto &transition : *plan->mutable_storage_transitions()) {
		if (const auto id_status =
			    validate_instance_identity("transition_id", transition.transition_id(), transition_ids);
		    !id_status.is_ok()) {
			return id_status;
		}
		if (const auto refs_status = normalize_facility_references("storage transition",
									   transition.transition_id(),
									   transition.mutable_facility_instance_ids());
		    !refs_status.is_ok()) {
			return refs_status;
		}
		if (const auto config_status = canonicalize_configuration(provider_contract_role::STORAGE_TRANSITION,
									  transition.mutable_configuration());
		    !config_status.is_ok()) {
			return config_status;
		}
	}

	return status::ok();
}

common::status_or<std::string> compute_deployment_plan_content_hash(const kinetum::gluon::v1::DeploymentPlan &plan)
{
	auto canonical = plan;
	if (const auto canonical_status = canonicalize_deployment_plan(&canonical); !canonical_status.is_ok()) {
		return canonical_status;
	}
	canonical.clear_content_hash();
	if (canonical.has_metadata()) {
		canonical.mutable_metadata()->clear_planned_unix_ms();
		canonical.mutable_metadata()->clear_planning_duration_ms();
	}

	auto serialized_or = common::serialize_protobuf_deterministically(canonical);
	if (!serialized_or.is_ok()) {
		return serialized_or.error();
	}
	return common::sha256_hex(serialized_or.value());
}

common::status finalize_deployment_plan_identity(kinetum::gluon::v1::DeploymentPlan *plan)
{
	if (const auto canonical_status = canonicalize_deployment_plan(plan); !canonical_status.is_ok()) {
		return canonical_status;
	}
	auto hash_or = compute_deployment_plan_content_hash(*plan);
	if (!hash_or.is_ok()) {
		return hash_or.error();
	}
	plan->set_content_hash(std::move(hash_or).value());
	return status::ok();
}

common::status verify_deployment_plan_content_hash(const kinetum::gluon::v1::DeploymentPlan &plan)
{
	if (plan.content_hash().empty()) {
		return status::invalid_argument("DeploymentPlan.content_hash is required and must not be empty");
	}
	if (const auto format_status =
		    common::validate_sha256_hex_claim(plan.content_hash(), "DeploymentPlan.content_hash");
	    !format_status.is_ok()) {
		return format_status;
	}

	auto admitted_bytes_or = common::serialize_protobuf_deterministically(plan);
	if (!admitted_bytes_or.is_ok()) {
		return admitted_bytes_or.error();
	}
	auto canonical = plan;
	if (const auto canonical_status = canonicalize_deployment_plan(&canonical); !canonical_status.is_ok()) {
		return canonical_status;
	}
	auto canonical_bytes_or = common::serialize_protobuf_deterministically(canonical);
	if (!canonical_bytes_or.is_ok()) {
		return canonical_bytes_or.error();
	}
	if (admitted_bytes_or.value() != canonical_bytes_or.value()) {
		return status::invalid_argument(
			"DeploymentPlan provider configuration or facility references are not canonical");
	}

	auto expected_or = compute_deployment_plan_content_hash(canonical);
	if (!expected_or.is_ok()) {
		return expected_or.error();
	}
	if (plan.content_hash() != expected_or.value()) {
		return status::data_loss("DeploymentPlan.content_hash does not match canonical content");
	}
	return status::ok();
}

}  // namespace kinetum::provider
