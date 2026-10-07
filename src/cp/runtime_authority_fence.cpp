// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_authority_fence.cpp
 * @brief Exact Control Plane to Data Plane runtime-content reconciliation.
 * @author Fleming Patel
 */

#include "src/cp/runtime_authority_fence.hpp"

#include <cstddef>
#include <new>
#include <string>
#include <string_view>
#include <utility>

#include "src/common/application_status.hpp"
#include "src/common/status.hpp"

namespace kinetum::cp
{
namespace
{

/** @brief Maximum bytes retained from each remote application-status diagnostic. */
constexpr std::size_t MAX_REMOTE_DIAGNOSTIC_BYTES = 512u;

/**
 * @brief Borrow one fixed digest as exact binary string bytes.
 * @param digest Digest whose lifetime exceeds the returned view.
 * @return Thirty-two-byte immutable view.
 */
[[nodiscard]] std::string_view digest_view(const kinetum::common::sha256_digest &digest) noexcept
{
	return {reinterpret_cast<const char *>(digest.data()), digest.size()};
}

/**
 * @brief Recognize the one lawful CP-ahead allocation window.
 *
 * CP persists both adjacent allocation values before its first Prepare
 * attempt. A surviving packet-ready DP may therefore still publish the prior
 * pair while the durable record is ALLOCATED, a pre-admission local abort is
 * pending, or that local abort is already terminal. Exact active content and
 * an idle DP make that lag safe to reconcile; every DP-admitted phase requires
 * exact watermark equality.
 *
 * @param authority Lock-coherent durable CP authority.
 * @param transition Intrinsically validated DP transition telemetry.
 * @return true only for one adjacent, idle, pre-admission lag.
 */
[[nodiscard]] bool
durable_allocation_leads_idle_dataplane(const durable_runtime_authority_view &authority,
					const kinetum::telemetry::v1::EpochTransitionTelemetry &transition) noexcept
{
	if (!authority.transition.has_value()) {
		return false;
	}
	const auto phase = authority.transition->phase;
	if (phase != kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED &&
	    phase != kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING &&
	    phase != kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
		return false;
	}
	const auto &identity = authority.transition->identity;
	return transition.state() == kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE &&
	       !transition.has_active_transaction() &&
	       identity.target_epoch == authority.active.allocated_epoch_high_watermark &&
	       identity.mutation_sequence == authority.active.mutation_sequence_high_watermark &&
	       authority.active.allocated_epoch_high_watermark > 1u &&
	       authority.active.mutation_sequence_high_watermark > 1u &&
	       transition.allocated_epoch_high_watermark() == authority.active.allocated_epoch_high_watermark - 1u &&
	       transition.mutation_sequence_high_watermark() == authority.active.mutation_sequence_high_watermark - 1u;
}

}  // namespace

kinetum::common::status map_dataplane_response_validation_failure(const kinetum::common::status &failure,
								  std::string_view malformed_message)
{
	if (failure.is_ok() || malformed_message.empty()) {
		return kinetum::common::status::internal_error(
			"Data Plane response validation mapping requires one failure and diagnostic");
	}
	if (failure.code() == kinetum::common::status_code::RESOURCE_EXHAUSTED ||
	    failure.code() == kinetum::common::status_code::OUT_OF_RANGE) {
		return failure;
	}
	return kinetum::common::status::data_loss(std::string(malformed_message));
}

kinetum::common::status map_dataplane_application_status(const kinetum::common::v1::Status &wire,
							 std::string_view failure_message)
{
	kinetum::common::status_code code{};
	if (!kinetum::common::decode_exact_application_status(wire, code) || failure_message.empty()) {
		return kinetum::common::status::data_loss("Data Plane returned malformed application status");
	}
	if (code == kinetum::common::status_code::OK) {
		return wire.message().empty() && wire.details().empty() ?
			       kinetum::common::status::ok() :
			       kinetum::common::status::data_loss(
				       "Data Plane success status retained unsupported fields");
	}
	std::string details(wire.message(), 0u, MAX_REMOTE_DIAGNOSTIC_BYTES);
	if (!wire.details().empty()) {
		if (!details.empty()) {
			details.append(": ");
		}
		details.append(wire.details(), 0u, MAX_REMOTE_DIAGNOSTIC_BYTES);
	}
	return kinetum::common::status(code, std::string(failure_message), std::move(details));
}

bool same_active_runtime_authority(const durable_runtime_authority_view &before,
				   const durable_runtime_authority_view &after) noexcept
{
	const auto &left = before.active;
	const auto &right = after.active;
	return left.snapshot_id == right.snapshot_id && left.revision == right.revision &&
	       left.active_epoch == right.active_epoch &&
	       left.allocated_epoch_high_watermark == right.allocated_epoch_high_watermark &&
	       left.mutation_sequence_high_watermark == right.mutation_sequence_high_watermark &&
	       left.plan_content_hash == right.plan_content_hash &&
	       left.active_validation_hash == right.active_validation_hash;
}

kinetum::common::status_or<runtime_authority_relation>
classify_runtime_authority(const durable_runtime_authority_view &authority,
			   const kinetum::telemetry::v1::RuntimeTelemetry &telemetry)
{
	try {
		if (!telemetry.has_runtime() || !telemetry.has_transition()) {
			return kinetum::common::status::data_loss(
				"runtime telemetry lacks mandatory runtime or transition authority");
		}
		const auto &transition = telemetry.transition();
		const bool watermarks_exact = transition.allocated_epoch_high_watermark() ==
						      authority.active.allocated_epoch_high_watermark &&
					      transition.mutation_sequence_high_watermark() ==
						      authority.active.mutation_sequence_high_watermark;
		if (telemetry.runtime().runtime_generation() == 0u ||
		    (!watermarks_exact && !durable_allocation_leads_idle_dataplane(authority, transition)) ||
		    transition.plan_content_hash() != digest_view(authority.active.plan_content_hash)) {
			return kinetum::common::status::data_loss(
				"Data Plane runtime generation, plan, or allocation watermarks contradict durable authority");
		}

		if (transition.active_epoch() == authority.active.active_epoch &&
		    transition.active_validation_hash() == digest_view(authority.active.active_validation_hash)) {
			return runtime_authority_relation::ACTIVE_EXACT;
		}

		if (!authority.transition.has_value() ||
		    authority.transition->phase !=
			    kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING ||
		    transition.state() != kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE ||
		    transition.active_epoch() != authority.transition->identity.target_epoch ||
		    transition.active_validation_hash() !=
			    digest_view(authority.transition->identity.validation_hash) ||
		    !transition.has_latest_terminal()) {
			return kinetum::common::status::data_loss(
				"Data Plane active content has no exact durable Control Plane explanation");
		}

		const auto &terminal = transition.latest_terminal();
		if (terminal.outcome() != kinetum::telemetry::v1::EPOCH_TRANSITION_OUTCOME_COMPLETE ||
		    terminal.failure_code() != kinetum::telemetry::v1::EPOCH_TRANSITION_FAILURE_CODE_NONE ||
		    terminal.retirement_frozen() ||
		    terminal.mutation_sequence() != authority.transition->identity.mutation_sequence ||
		    terminal.from_epoch() != authority.active.active_epoch ||
		    terminal.to_epoch() != authority.transition->identity.target_epoch ||
		    terminal.validation_hash() != digest_view(authority.transition->identity.validation_hash) ||
		    terminal.idempotency_key_digest() !=
			    digest_view(authority.transition->identity.idempotency_key_digest)) {
			return kinetum::common::status::data_loss(
				"Data Plane completed target does not match the durable pending transition");
		}

		return runtime_authority_relation::TARGET_COMPLETE_EXACT;
	} catch (const std::bad_alloc &) {
		return kinetum::common::status::resource_exhausted("runtime authority classification exhausted memory");
	}
}

}  // namespace kinetum::cp
