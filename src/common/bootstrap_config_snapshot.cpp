// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file bootstrap_config_snapshot.cpp
 * @brief Shared exact fixed-epoch bootstrap-request admission implementation.
 * @author Fleming Patel
 */

#include "src/common/bootstrap_config_snapshot.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"

namespace kinetum::common
{
namespace
{

/** @brief Domain and user-visible prefix for deterministic bootstrap keys. */
constexpr std::string_view BOOTSTRAP_KEY_DOMAIN = "kinetum-bootstrap-v1";

/**
 * @brief Append one uint64 in network byte order.
 *
 * @param value Exact integer.
 * @param[out] bytes Destination preimage.
 */
void append_u64_be(uint64_t value, std::string *bytes)
{
	for (uint32_t shift = 56u;; shift -= 8u) {
		bytes->push_back(static_cast<char>((value >> shift) & 0xffu));
		if (shift == 0u) {
			break;
		}
	}
}

/**
 * @brief Construct a terminal canonical value from one nested snapshot.
 *
 * @param snapshot Candidate complete snapshot.
 * @return Exact canonical bytes/raw hash after plan-independent re-admission.
 */
status_or<canonical_config_snapshot> terminal_bootstrap_snapshot(const kinetum::control::v1::ConfigSnapshot &snapshot)
{
	return canonical_config_snapshot_from_terminal(snapshot);
}

}  // namespace

status_or<sha256_digest> decode_sha256_digest_claim(std::string_view claim, std::string_view field_name)
{
	const auto format_status = validate_sha256_hex_claim(claim, field_name);
	if (!format_status.is_ok()) {
		return format_status;
	}
	auto bytes_or = hex_to_bytes(claim);
	if (!bytes_or.is_ok() || bytes_or->size() != SHA256_DIGEST_SIZE) {
		return status::invalid_argument(std::string(field_name) + " does not decode to 32 bytes");
	}
	sha256_digest digest{};
	std::copy(bytes_or->begin(), bytes_or->end(), digest.begin());
	return digest;
}

status_or<std::string> derive_bootstrap_config_snapshot_idempotency_key(const sha256_digest &snapshot_hash,
									const sha256_digest &plan_hash,
									uint64_t active_epoch,
									uint64_t allocated_high_watermark,
									uint64_t mutation_high_watermark)
{
	std::string preimage;
	preimage.reserve(BOOTSTRAP_KEY_DOMAIN.size() + 1u + (2u * SHA256_DIGEST_SIZE) + 24u);
	preimage.append(BOOTSTRAP_KEY_DOMAIN);
	preimage.push_back('\0');
	preimage.append(reinterpret_cast<const char *>(snapshot_hash.data()), snapshot_hash.size());
	preimage.append(reinterpret_cast<const char *>(plan_hash.data()), plan_hash.size());
	append_u64_be(active_epoch, &preimage);
	append_u64_be(allocated_high_watermark, &preimage);
	append_u64_be(mutation_high_watermark, &preimage);
	auto digest_or = sha256_hex(preimage);
	if (!digest_or.is_ok()) {
		return digest_or.error();
	}
	return std::string(BOOTSTRAP_KEY_DOMAIN) + "-" + std::move(digest_or).value();
}

status_or<validated_bootstrap_config_snapshot>
validate_bootstrap_config_snapshot_request(const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request)
{
	const auto unknown_status = reject_unknown_protobuf_fields_recursive(request, "BootstrapConfigSnapshotRequest");
	if (!unknown_status.is_ok()) {
		return unknown_status;
	}
	const auto enum_status =
		reject_invalid_protobuf_enum_values_recursive(request, "BootstrapConfigSnapshotRequest");
	if (!enum_status.is_ok()) {
		return enum_status;
	}
	if (!valid_epoch_id(request.active_epoch())) {
		return status::invalid_argument(
			"active bootstrap epoch must be nonzero and below the reserved wrap sentinel");
	}
	if (!valid_epoch_id(request.allocated_epoch_high_watermark())) {
		return status::invalid_argument(
			"allocated epoch high watermark must be nonzero and below the reserved wrap sentinel");
	}
	if (request.allocated_epoch_high_watermark() < request.active_epoch()) {
		return status::invalid_argument("allocated epoch high watermark precedes the active bootstrap epoch");
	}
	if (!valid_mutation_sequence(request.mutation_sequence_high_watermark())) {
		return status::invalid_argument(
			"mutation sequence high watermark must be nonzero and below the reserved wrap sentinel");
	}

	auto snapshot_or = terminal_bootstrap_snapshot(request.snapshot());
	if (!snapshot_or.is_ok()) {
		return snapshot_or.error();
	}
	auto plan_hash_or = decode_sha256_digest_claim(request.plan_content_hash(), "plan_content_hash");
	if (!plan_hash_or.is_ok()) {
		return plan_hash_or.error();
	}
	auto key_or = derive_bootstrap_config_snapshot_idempotency_key(snapshot_or->validation_hash,
								       plan_hash_or.value(), request.active_epoch(),
								       request.allocated_epoch_high_watermark(),
								       request.mutation_sequence_high_watermark());
	if (!key_or.is_ok()) {
		return key_or.error();
	}
	if (request.idempotency_key() != key_or.value()) {
		return status::data_loss("active bootstrap idempotency key does not match its exact durable preimage");
	}

	auto serialized_or = serialize_protobuf_deterministically(request);
	if (!serialized_or.is_ok()) {
		return serialized_or.error();
	}
	if (serialized_or->size() > MAX_BOOTSTRAP_CONFIG_SNAPSHOT_REQUEST_BYTES) {
		return status::resource_exhausted("active bootstrap record exceeds its exact binary bound");
	}
	return validated_bootstrap_config_snapshot{
		.snapshot = std::move(snapshot_or).value(),
		.plan_content_hash = std::move(plan_hash_or).value(),
		.active_epoch = request.active_epoch(),
		.watermarks = epoch_transition_watermarks{request.allocated_epoch_high_watermark(),
							  request.mutation_sequence_high_watermark()},
		.serialized_request = std::move(serialized_or).value(),
	};
}

}  // namespace kinetum::common
