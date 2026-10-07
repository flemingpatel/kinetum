// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file bootstrap_startup.cpp
 * @brief Implementation of Control Plane bootstrap-authority startup admission.
 * @author Fleming Patel
 */

#include "src/cp/bootstrap_startup.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <sys/stat.h>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/held_file.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"

#include "gen/kinetum/control/v1/control.pb.h"

namespace kinetum::cp
{
using kinetum::common::status;

namespace
{

/** @brief Fixed bootstrap protobuf-text source bound (64 MiB). */
constexpr uint64_t MAX_BOOTSTRAP_SNAPSHOT_SOURCE_BYTES = 64u * 1024u * 1024u;

}  // namespace

kinetum::common::status_or<std::optional<bootstrap_startup_authority>>
admit_bootstrap_startup_authority(std::string_view snapshot_path, std::string_view plan_content_hash)
{
	if (snapshot_path.empty() && plan_content_hash.empty()) {
		return std::optional<bootstrap_startup_authority>{};
	}
	if (snapshot_path.empty() || plan_content_hash.empty()) {
		return status::invalid_argument(
			"--bootstrap-snapshot and --bootstrap-plan-content-hash must be supplied together");
	}

	const auto hash_status =
		kinetum::common::validate_sha256_hex_claim(plan_content_hash, "--bootstrap-plan-content-hash");
	if (!hash_status.is_ok()) {
		return hash_status;
	}

	try {
		const std::filesystem::path supplied{std::string(snapshot_path)};
		kinetum::common::held_file_policy source_policy;
		source_policy.required_owner_uid = std::nullopt;
		source_policy.forbidden_mode_bits = S_IWGRP | S_IWOTH;
		source_policy.require_single_link = true;
		source_policy.maximum_size_bytes = MAX_BOOTSTRAP_SNAPSHOT_SOURCE_BYTES;
		auto source_or = kinetum::common::open_held_regular_file(supplied, source_policy);
		if (!source_or.is_ok()) {
			return source_or.error();
		}
		auto source = std::move(source_or).value();

		auto text_or = kinetum::common::read_held_file(source, MAX_BOOTSTRAP_SNAPSHOT_SOURCE_BYTES);
		if (!text_or.is_ok()) {
			return text_or.error();
		}
		kinetum::control::v1::ConfigSnapshot parsed_snapshot;
		const auto parse_status =
			kinetum::common::parse_pbtxt_text(text_or.value(), supplied.string(), &parsed_snapshot);
		if (!parse_status.is_ok()) {
			return parse_status;
		}
		if (parsed_snapshot.ByteSizeLong() > kinetum::common::MAX_CONFIG_SNAPSHOT_BYTES) {
			return status::resource_exhausted(
				"bootstrap ConfigSnapshot exceeds the 10 MiB admission bound");
		}

		const auto embedded_hash_status = kinetum::common::validate_sha256_hex_claim(
			parsed_snapshot.content_hash(), "ConfigSnapshot.content_hash");
		if (!embedded_hash_status.is_ok()) {
			return embedded_hash_status;
		}
		auto validation_bytes_or = kinetum::common::hex_to_bytes(parsed_snapshot.content_hash());
		if (!validation_bytes_or.is_ok() ||
		    validation_bytes_or->size() != kinetum::common::SHA256_DIGEST_SIZE) {
			return status::invalid_argument("ConfigSnapshot.content_hash does not decode to 32 bytes");
		}
		kinetum::common::sha256_digest validation_hash{};
		std::copy(validation_bytes_or->begin(), validation_bytes_or->end(), validation_hash.begin());

		auto serialized_or = kinetum::common::serialize_protobuf_deterministically(parsed_snapshot);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		kinetum::common::canonical_config_snapshot canonical{
			.serialized_bytes = std::move(serialized_or).value(),
			.validation_hash = validation_hash,
		};
		kinetum::control::v1::ConfigSnapshot terminal_snapshot;
		const auto terminal_status =
			kinetum::common::admit_terminal_config_snapshot(canonical, &terminal_snapshot);
		if (!terminal_status.is_ok()) {
			return terminal_status;
		}

		auto plan_bytes_or = kinetum::common::hex_to_bytes(plan_content_hash);
		if (!plan_bytes_or.is_ok() || plan_bytes_or->size() != kinetum::common::SHA256_DIGEST_SIZE) {
			return status::invalid_argument("--bootstrap-plan-content-hash does not decode to 32 bytes");
		}
		kinetum::common::sha256_digest plan_hash_bytes{};
		std::copy(plan_bytes_or->begin(), plan_bytes_or->end(), plan_hash_bytes.begin());

		bootstrap_startup_authority authority{
			.snapshot_source = std::move(source),
			.snapshot = std::move(canonical),
			.plan_content_hash = std::string(plan_content_hash),
			.plan_content_hash_bytes = plan_hash_bytes,
		};
		return std::optional<bootstrap_startup_authority>{std::move(authority)};
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("bootstrap startup admission exhausted memory");
	}
}

}  // namespace kinetum::cp
