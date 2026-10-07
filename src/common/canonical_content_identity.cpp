// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file canonical_content_identity.cpp
 * @brief Canonical protobuf validation and SHA-256 content identity.
 * @author Fleming Patel
 *
 * The implementation walks only protobuf message fields. Scalar bytes fields,
 * including module-owned config_blob, are never interpreted recursively.
 * Canonicalization copies caller messages, applies the owning field taxonomy,
 * serializes with the pinned protobuf runtime, and hashes the resulting bytes.
 *
 * @par Thread Safety
 * All helpers are stateless and may run concurrently for distinct inputs.
 * Callers must not mutate an input protobuf while an operation reads it.
 *
 * @par Performance
 * Message traversal, copying, sorting, deterministic serialization, and SHA-256
 * are cold-path work. These helpers must not execute on packet workers or from
 * module packet callbacks.
 */

#include "src/common/canonical_content_identity.hpp"

#include <algorithm>
#include <cstddef>
#include <new>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"

namespace kinetum::common
{

namespace
{

/**
 * @brief Extract the exact unique module-image set named by a plan pipeline.
 *
 * Multiple stage instances may use one module image, so repeated use of the
 * same module_id across stages collapses to one expected snapshot entry. A
 * module stage must still carry one exact typed module configuration.
 *
 * @param plan Validated plan whose embedded pipeline is authoritative.
 * @return Sorted unique module IDs, or INVALID_ARGUMENT for malformed module
 *         stage parameters.
 */
[[nodiscard]] status_or<std::set<std::string>> expected_plan_module_ids(const kinetum::gluon::v1::DeploymentPlan &plan)
{
	try {
		std::set<std::string> expected;
		for (const auto &stage : plan.pipeline().stages()) {
			if (stage.kind() != kinetum::axiom::v1::STAGE_KIND_MODULE) {
				continue;
			}

			if (!stage.has_module() || stage.module().module_id().empty()) {
				return status::invalid_argument("module stage " + stage.stage_id() +
								" must carry one nonempty module_id");
			}
			expected.insert(stage.module().module_id());
		}
		return expected;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("expected plan module-set construction exhausted memory");
	}
}

/**
 * @brief Normalize module hashes and ordering against one admitted expected set.
 *
 * Module identity, set equality, and textual claim shape are validated before
 * any blob hashing, so malformed bounded input cannot force avoidable provider
 * work. The second pass hashes exact opaque bytes and verifies claim content.
 *
 * @param snapshot Mutable snapshot copy whose module entries are normalized.
 * @param expected Sorted exact module-image set derived from a plan or its
 *        terminal active snapshot projection.
 * @return OK after exact set equality, claim verification, hash recomputation,
 *         and module_id ordering; otherwise the first validation/provider
 *         failure.
 */
[[nodiscard]] status normalize_snapshot_modules(kinetum::control::v1::ConfigSnapshot *snapshot,
						const std::set<std::string> &expected)
{
	if (snapshot == nullptr) {
		return status::invalid_argument("canonical ConfigSnapshot output must not be null");
	}

	std::set<std::string> observed;
	for (const auto &module : snapshot->modules()) {
		if (module.module_id().empty()) {
			return status::invalid_argument("ConfigSnapshot.modules[] contains an empty module_id");
		}
		if (!observed.insert(module.module_id()).second) {
			return status::invalid_argument("ConfigSnapshot.modules[] contains duplicate module_id: " +
							module.module_id());
		}
		if (expected.find(module.module_id()) == expected.end()) {
			return status::invalid_argument(
				"ConfigSnapshot.modules[] contains module_id outside the expected set: " +
				module.module_id());
		}
		if (!module.content_hash().empty()) {
			const auto format_status =
				validate_sha256_hex_claim(module.content_hash(), "ModuleConfig.content_hash");
			if (!format_status.is_ok()) {
				return format_status;
			}
		}
	}

	for (const auto &module_id : expected) {
		if (observed.find(module_id) == observed.end()) {
			return status::invalid_argument("ConfigSnapshot.modules[] is missing required module_id: " +
							module_id);
		}
	}

	std::vector<kinetum::control::v1::ModuleConfig> normalized;
	normalized.reserve(static_cast<std::size_t>(snapshot->modules_size()));
	for (const auto &module : snapshot->modules()) {
		auto hash_or = sha256_hex(module.config_blob().data(), module.config_blob().size());
		if (!hash_or.is_ok()) {
			return hash_or.error();
		}
		if (!module.content_hash().empty()) {
			if (module.content_hash() != hash_or.value()) {
				return status::data_loss("ModuleConfig.content_hash mismatch for module_id: " +
							 module.module_id());
			}
		}

		auto canonical_module = module;
		canonical_module.set_content_hash(hash_or.value());
		normalized.push_back(std::move(canonical_module));
	}

	std::sort(normalized.begin(), normalized.end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.module_id() < rhs.module_id(); });
	snapshot->clear_modules();
	for (const auto &module : normalized) {
		snapshot->add_modules()->CopyFrom(module);
	}
	return status::ok();
}

/**
 * @brief Check an admitted or canonical snapshot against the shared wire bound.
 *
 * @param size_bytes Serialized protobuf size in bytes.
 * @param representation Stable representation name used in diagnostics.
 * @return OK at or below MAX_CONFIG_SNAPSHOT_BYTES; RESOURCE_EXHAUSTED above
 *         the bound.
 */
[[nodiscard]] status validate_snapshot_size(std::size_t size_bytes, std::string_view representation)
{
	if (size_bytes > MAX_CONFIG_SNAPSHOT_BYTES) {
		return status::resource_exhausted(std::string(representation) +
						  " ConfigSnapshot exceeds the 10 MiB admission bound");
	}
	return status::ok();
}

/**
 * @brief Validate the shared plan-independent ConfigSnapshot scalars.
 *
 * @param snapshot Candidate snapshot.
 * @return OK for one bounded nonempty identity and revision in 0..2^48;
 *         otherwise INVALID_ARGUMENT.
 */
[[nodiscard]] status validate_snapshot_scalar_contract(const kinetum::control::v1::ConfigSnapshot &snapshot)
{
	if (!valid_config_snapshot_id(snapshot.snapshot_id())) {
		return status::invalid_argument("ConfigSnapshot.snapshot_id must contain 1..256 bytes");
	}
	if (!valid_config_snapshot_revision(snapshot.revision())) {
		return status::invalid_argument("ConfigSnapshot.revision must be in the closed range 0..2^48");
	}
	return status::ok();
}

/**
 * @brief Canonicalize one candidate against an already derived module set.
 *
 * @param snapshot Candidate complete configuration snapshot.
 * @param expected Exact sorted module identities owned by the caller's
 *        independently admitted plan or active snapshot.
 * @return Canonical bytes/raw hash, or the first validation or provider error.
 */
[[nodiscard]] status_or<canonical_config_snapshot>
canonicalize_for_expected_modules(const kinetum::control::v1::ConfigSnapshot &snapshot,
				  const std::set<std::string> &expected)
{
	try {
		const auto input_size_status = validate_snapshot_size(snapshot.ByteSizeLong(), "input");
		if (!input_size_status.is_ok()) {
			return input_size_status;
		}
		const auto snapshot_unknown_status =
			reject_unknown_protobuf_fields_recursive(snapshot, "ConfigSnapshot");
		if (!snapshot_unknown_status.is_ok()) {
			return snapshot_unknown_status;
		}
		const auto snapshot_enum_status =
			reject_invalid_protobuf_enum_values_recursive(snapshot, "ConfigSnapshot");
		if (!snapshot_enum_status.is_ok()) {
			return snapshot_enum_status;
		}
		const auto scalar_status = validate_snapshot_scalar_contract(snapshot);
		if (!scalar_status.is_ok()) {
			return scalar_status;
		}
		if (!snapshot.content_hash().empty()) {
			const auto format_status =
				validate_sha256_hex_claim(snapshot.content_hash(), "ConfigSnapshot.content_hash");
			if (!format_status.is_ok()) {
				return format_status;
			}
		}

		auto canonical = snapshot;
		const std::string claimed_snapshot_hash = canonical.content_hash();
		const auto module_status = normalize_snapshot_modules(&canonical, expected);
		if (!module_status.is_ok()) {
			return module_status;
		}

		canonical.clear_content_hash();
		auto preimage_or = serialize_protobuf_deterministically(canonical);
		if (!preimage_or.is_ok()) {
			return preimage_or.error();
		}
		const auto preimage_size_status =
			validate_snapshot_size(preimage_or.value().size(), "canonical preimage");
		if (!preimage_size_status.is_ok()) {
			return preimage_size_status;
		}

		auto validation_hash_or = sha256_raw(preimage_or.value());
		if (!validation_hash_or.is_ok()) {
			return validation_hash_or.error();
		}
		const auto &validation_hash = validation_hash_or.value();
		const std::string validation_hash_hex = bytes_to_hex(validation_hash.data(), validation_hash.size());
		if (!claimed_snapshot_hash.empty() && claimed_snapshot_hash != validation_hash_hex) {
			return status::data_loss("ConfigSnapshot.content_hash does not match canonical content");
		}

		canonical.set_content_hash(validation_hash_hex);
		auto serialized_or = serialize_protobuf_deterministically(canonical);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		const auto output_size_status =
			validate_snapshot_size(serialized_or.value().size(), "canonical output");
		if (!output_size_status.is_ok()) {
			return output_size_status;
		}

		canonical_config_snapshot result{
			.serialized_bytes = std::move(serialized_or).value(),
			.validation_hash = validation_hash,
		};
		kinetum::control::v1::ConfigSnapshot terminal;
		const auto terminal_status = admit_terminal_config_snapshot(result, &terminal);
		if (!terminal_status.is_ok()) {
			return terminal_status;
		}
		return result;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("ConfigSnapshot canonicalization exhausted memory");
	}
}

}  // namespace

status validate_sha256_hex_claim(std::string_view claim, std::string_view field_name)
{
	if (claim.size() != SHA256_HEX_LENGTH) {
		return status::invalid_argument(std::string(field_name) +
						" must contain exactly 64 lowercase hexadecimal characters");
	}
	const bool lowercase_hex = std::all_of(claim.begin(), claim.end(), [](char value) {
		return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
	});
	if (!lowercase_hex) {
		return status::invalid_argument(std::string(field_name) +
						" must contain exactly 64 lowercase hexadecimal characters");
	}
	return status::ok();
}

status admit_terminal_config_snapshot(const canonical_config_snapshot &canonical,
				      kinetum::control::v1::ConfigSnapshot *snapshot)
{
	if (snapshot == nullptr) {
		return status::invalid_argument("terminal ConfigSnapshot destination must not be null");
	}
	snapshot->Clear();
	if (canonical.serialized_bytes.empty()) {
		return status::invalid_argument("canonical configuration snapshot bytes must be nonempty");
	}
	const auto size_status = validate_snapshot_size(canonical.serialized_bytes.size(), "terminal");
	if (!size_status.is_ok()) {
		return size_status;
	}

	try {
		kinetum::control::v1::ConfigSnapshot candidate;
		if (!candidate.ParseFromString(canonical.serialized_bytes)) {
			return status::invalid_argument("canonical configuration snapshot bytes are malformed");
		}
		const auto unknown_status = reject_unknown_protobuf_fields_recursive(candidate, "ConfigSnapshot");
		if (!unknown_status.is_ok()) {
			return unknown_status;
		}
		const auto enum_status = reject_invalid_protobuf_enum_values_recursive(candidate, "ConfigSnapshot");
		if (!enum_status.is_ok()) {
			return enum_status;
		}
		const auto scalar_status = validate_snapshot_scalar_contract(candidate);
		if (!scalar_status.is_ok()) {
			return scalar_status;
		}

		auto deterministic_or = serialize_protobuf_deterministically(candidate);
		if (!deterministic_or.is_ok()) {
			return deterministic_or.error();
		}
		if (deterministic_or.value() != canonical.serialized_bytes) {
			return status::data_loss(
				"configuration snapshot bytes are not the exact canonical representation");
		}

		std::string_view previous_module_id;
		for (const auto &module : candidate.modules()) {
			if (module.module_id().empty() ||
			    (!previous_module_id.empty() && previous_module_id.compare(module.module_id()) >= 0)) {
				return status::invalid_argument(
					"ConfigSnapshot.modules[] identities must be nonempty, strictly sorted, and unique");
			}
			const auto module_hash_status =
				validate_sha256_hex_claim(module.content_hash(), "ModuleConfig.content_hash");
			if (!module_hash_status.is_ok()) {
				return module_hash_status;
			}
			auto module_hash_or = sha256_hex(module.config_blob().data(), module.config_blob().size());
			if (!module_hash_or.is_ok()) {
				return module_hash_or.error();
			}
			if (module_hash_or.value() != module.content_hash()) {
				return status::data_loss(
					"ModuleConfig.content_hash does not match its exact config_blob");
			}
			previous_module_id = module.module_id();
		}

		const auto hash_status =
			validate_sha256_hex_claim(candidate.content_hash(), "ConfigSnapshot.content_hash");
		if (!hash_status.is_ok()) {
			return hash_status;
		}
		const std::string embedded_hash = candidate.content_hash();
		candidate.clear_content_hash();
		auto preimage_or = serialize_protobuf_deterministically(candidate);
		if (!preimage_or.is_ok()) {
			return preimage_or.error();
		}
		const auto preimage_size_status =
			validate_snapshot_size(preimage_or.value().size(), "terminal preimage");
		if (!preimage_size_status.is_ok()) {
			return preimage_size_status;
		}
		auto recomputed_hash_or = sha256_raw(preimage_or.value());
		if (!recomputed_hash_or.is_ok()) {
			return recomputed_hash_or.error();
		}
		if (recomputed_hash_or.value() != canonical.validation_hash) {
			return status::data_loss(
				"canonical configuration snapshot validation hash does not match its exact preimage");
		}
		const std::string expected_hash =
			bytes_to_hex(canonical.validation_hash.data(), canonical.validation_hash.size());
		if (embedded_hash != expected_hash) {
			return status::data_loss(
				"ConfigSnapshot.content_hash does not match the exact raw validation hash");
		}
		candidate.set_content_hash(embedded_hash);
		snapshot->Swap(&candidate);
		return status::ok();
	} catch (const std::bad_alloc &) {
		snapshot->Clear();
		return status::resource_exhausted("terminal ConfigSnapshot admission exhausted memory");
	}
}

status_or<canonical_config_snapshot>
canonical_config_snapshot_from_terminal(const kinetum::control::v1::ConfigSnapshot &snapshot)
{
	const auto size_status = validate_snapshot_size(snapshot.ByteSizeLong(), "terminal message");
	if (!size_status.is_ok()) {
		return size_status;
	}
	const auto format_status = validate_sha256_hex_claim(snapshot.content_hash(), "ConfigSnapshot.content_hash");
	if (!format_status.is_ok()) {
		return format_status;
	}
	auto digest_bytes_or = hex_to_bytes(snapshot.content_hash());
	if (!digest_bytes_or.is_ok() || digest_bytes_or->size() != SHA256_DIGEST_SIZE) {
		return status::invalid_argument("ConfigSnapshot.content_hash does not decode to 32 bytes");
	}
	sha256_digest validation_hash{};
	std::copy(digest_bytes_or->begin(), digest_bytes_or->end(), validation_hash.begin());
	auto serialized_or = serialize_protobuf_deterministically(snapshot);
	if (!serialized_or.is_ok()) {
		return serialized_or.error();
	}
	canonical_config_snapshot canonical{
		.serialized_bytes = std::move(serialized_or).value(),
		.validation_hash = validation_hash,
	};
	kinetum::control::v1::ConfigSnapshot admitted;
	const auto admission_status = admit_terminal_config_snapshot(canonical, &admitted);
	if (!admission_status.is_ok()) {
		return admission_status;
	}
	return canonical;
}

status_or<canonical_config_snapshot> canonicalize_config_snapshot(const kinetum::control::v1::ConfigSnapshot &snapshot,
								  const kinetum::gluon::v1::DeploymentPlan &plan)
{
	const auto plan_unknown_status = reject_unknown_protobuf_fields_recursive(plan, "DeploymentPlan");
	if (!plan_unknown_status.is_ok()) {
		return plan_unknown_status;
	}
	const auto plan_enum_status = reject_invalid_protobuf_enum_values_recursive(plan, "DeploymentPlan");
	if (!plan_enum_status.is_ok()) {
		return plan_enum_status;
	}
	auto expected_or = expected_plan_module_ids(plan);
	if (!expected_or.is_ok()) {
		return expected_or.error();
	}
	return canonicalize_for_expected_modules(snapshot, expected_or.value());
}

status_or<canonical_config_snapshot>
canonicalize_config_snapshot(const kinetum::control::v1::ConfigSnapshot &snapshot,
			     const kinetum::control::v1::ConfigSnapshot &active_snapshot)
{
	try {
		auto active_or = canonical_config_snapshot_from_terminal(active_snapshot);
		if (!active_or.is_ok()) {
			return status(active_or.error().code(), "active ConfigSnapshot failed terminal re-admission",
				      std::string(active_or.error().message()));
		}
		std::set<std::string> expected;
		for (const auto &module : active_snapshot.modules()) {
			expected.insert(module.module_id());
		}
		return canonicalize_for_expected_modules(snapshot, expected);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("active module-set canonicalization exhausted memory");
	}
}

}  // namespace kinetum::common
