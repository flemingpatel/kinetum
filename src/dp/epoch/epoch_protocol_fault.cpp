// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_protocol_fault.cpp
 * @brief Write-once ordered-transition safety-fault publication.
 * @author Fleming Patel
 */

#include "src/dp/epoch/epoch_protocol_fault.hpp"

#include <algorithm>
#include <exception>

namespace kinetum::dp
{
namespace
{

/**
 * @brief Check one internal protocol-fault disposition value.
 * @param disposition Candidate immediate disposition.
 * @return true only for a declared disposition value.
 */
[[nodiscard]] constexpr bool valid_disposition(epoch_protocol_fault_disposition disposition) noexcept
{
	const auto raw = static_cast<uint8_t>(disposition);
	return raw >= static_cast<uint8_t>(epoch_protocol_fault_disposition::DROP_AND_RETIRE) &&
	       raw <= static_cast<uint8_t>(epoch_protocol_fault_disposition::RESOURCE_REFUSED);
}

/**
 * @brief Check the exact fault-code/disposition relation.
 * @param code Candidate fault classification.
 * @param disposition Candidate immediate disposition.
 * @return true only when the code and disposition agree.
 */
[[nodiscard]] constexpr bool disposition_matches_fault(epoch_protocol_fault_code code,
						       epoch_protocol_fault_disposition disposition) noexcept
{
	if (code == epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED) {
		return disposition == epoch_protocol_fault_disposition::RESOURCE_REFUSED;
	}
	if (code == epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH) {
		return disposition == epoch_protocol_fault_disposition::DROP_AND_RETIRE ||
		       disposition == epoch_protocol_fault_disposition::TERMINATE;
	}
	return disposition == epoch_protocol_fault_disposition::TERMINATE;
}

/**
 * @brief Validate one immutable first-fault candidate.
 * @param fault Candidate immutable first-fault record.
 * @return true only for a complete record with normalized padding.
 */
[[nodiscard]] bool valid_fault(const epoch_protocol_first_fault &fault) noexcept
{
	return fault.runtime_generation != 0u && fault.observed_monotonic_ns != 0u &&
	       valid_epoch_protocol_fault_code(fault.code) && valid_disposition(fault.disposition) &&
	       disposition_matches_fault(fault.code, fault.disposition) &&
	       std::all_of(fault.padding.begin(), fault.padding.end(), [](uint8_t byte) { return byte == 0u; });
}

}  // namespace

bool epoch_protocol_fault_latch::record(const epoch_protocol_first_fault &fault) noexcept
{
	if (!valid_fault(fault)) {
		std::terminate();
	}
	if (fault.code != epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED) {
		transition_blocked_.store(1u, std::memory_order_release);
	}
	uint8_t expected = static_cast<uint8_t>(publication_state::EMPTY);
	if (!state_.compare_exchange_strong(expected, static_cast<uint8_t>(publication_state::WRITING),
					    std::memory_order_acq_rel, std::memory_order_acquire)) {
		return false;
	}
	first_ = fault;
	state_.store(static_cast<uint8_t>(publication_state::READY), std::memory_order_release);
	return true;
}

bool epoch_protocol_fault_latch::try_read(epoch_protocol_first_fault &out) const noexcept
{
	if (state_.load(std::memory_order_acquire) != static_cast<uint8_t>(publication_state::READY)) {
		return false;
	}
	out = first_;
	if (!valid_fault(out)) {
		std::terminate();
	}
	return true;
}

bool epoch_protocol_fault_latch::transition_success_blocked() const noexcept
{
	return transition_blocked_.load(std::memory_order_acquire) != 0u;
}

}  // namespace kinetum::dp
