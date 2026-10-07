// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file generated_snapshot_identity.cpp
 * @brief Deterministic generated-snapshot identity implementation.
 * @author Fleming Patel
 */

#include "src/common/generated_snapshot_identity.hpp"

#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/common/transition_idempotency_key.hpp"

namespace kinetum::common
{

status_or<std::string> derive_generated_snapshot_id(const generated_snapshot_identity_spec &spec)
{
	if (spec.domain.empty() || spec.prefix.empty()) {
		return status::invalid_argument("generated snapshot identity requires domain and prefix");
	}
	const auto key_status = validate_transition_idempotency_key(spec.idempotency_key);
	if (!key_status.is_ok()) {
		return key_status;
	}
	try {
		std::string preimage(spec.domain);
		preimage.push_back('\0');
		preimage.append(spec.idempotency_key);
		auto digest_or = sha256_hex(preimage);
		if (!digest_or.is_ok()) {
			return digest_or.error();
		}
		std::string identity = std::string(spec.prefix) + std::move(digest_or).value();
		if (!valid_config_snapshot_id(identity)) {
			return status::invalid_argument("generated snapshot identity is outside the exact domain");
		}
		return identity;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("generated snapshot identity exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "generated snapshot identity exceeded host size limits");
	}
}

}  // namespace kinetum::common
