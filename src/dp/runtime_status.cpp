// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_status.cpp
 * @brief Coherent packet-runtime status publication implementation.
 * @author Fleming Patel
 */

#include "src/dp/runtime_status.hpp"

#include <array>
#include <limits>

#include "src/common/epoch_transition_contract.hpp"

namespace kinetum::dp
{
bool runtime_status_publication::publish_control_ready(uint64_t runtime_generation, uint32_t expected_workers) noexcept
{
	if (control_ready_published_ || packet_ready_published_ || runtime_generation == 0u || expected_workers == 0u) {
		return false;
	}

	const std::array<uint64_t, FIELD_COUNT> fields{
		static_cast<uint64_t>(runtime_readiness::CONTROL_READY),
		runtime_generation,
		0u,
		0u,
		0u,
		0u,
		expected_workers,
	};
	if (!publication_.publish(fields)) {
		return false;
	}

	owner_runtime_generation_ = runtime_generation;
	owner_expected_workers_ = expected_workers;
	control_ready_published_ = true;
	return true;
}

bool runtime_status_publication::publish_packet_ready(uint64_t bootstrap_epoch, uint32_t active_workers) noexcept
{
	if (!control_ready_published_ || packet_ready_published_ || bootstrap_epoch == 0u ||
	    active_workers != owner_expected_workers_) {
		return false;
	}

	const std::array<uint64_t, FIELD_COUNT> fields{
		static_cast<uint64_t>(runtime_readiness::PACKET_READY),
		owner_runtime_generation_,
		bootstrap_epoch,
		bootstrap_epoch,
		bootstrap_epoch,
		active_workers,
		owner_expected_workers_,
	};
	if (!publication_.publish(fields)) {
		return false;
	}

	packet_ready_published_ = true;
	owner_active_epoch_ = bootstrap_epoch;
	owner_minimum_retained_epoch_ = bootstrap_epoch;
	owner_last_activated_epoch_ = bootstrap_epoch;
	return true;
}

bool runtime_status_publication::owns_runtime_generation(uint64_t runtime_generation) const noexcept
{
	return control_ready_published_ && runtime_generation != 0u && owner_runtime_generation_ == runtime_generation;
}

bool runtime_status_publication::can_publish_transition(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	if (!control_ready_published_ || !packet_ready_published_ || !common::valid_epoch_id(from_epoch) ||
	    !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch || owner_active_epoch_ != from_epoch ||
	    owner_minimum_retained_epoch_ != from_epoch || owner_last_activated_epoch_ != from_epoch) {
		return false;
	}
	const uint64_t generation = publication_.completed_generation();
	if (generation > (std::numeric_limits<uint64_t>::max() - 5u) / 2u) {
		return false;
	}
	const uint64_t sequence = generation * 2u;
	return kinetum::algo::single_writer_snapshot<FIELD_COUNT>::can_advance_sequence(sequence) &&
	       kinetum::algo::single_writer_snapshot<FIELD_COUNT>::can_advance_sequence(sequence + 2u);
}

bool runtime_status_publication::publish_transition_activated(uint64_t from_epoch, uint64_t to_epoch) noexcept
{
	if (!can_publish_transition(from_epoch, to_epoch)) {
		return false;
	}
	const std::array<uint64_t, FIELD_COUNT> fields{
		static_cast<uint64_t>(runtime_readiness::PACKET_READY),
		owner_runtime_generation_,
		to_epoch,
		from_epoch,
		to_epoch,
		owner_expected_workers_,
		owner_expected_workers_,
	};
	if (!publication_.publish(fields)) {
		return false;
	}
	owner_active_epoch_ = to_epoch;
	owner_minimum_retained_epoch_ = from_epoch;
	owner_last_activated_epoch_ = to_epoch;
	return true;
}

bool runtime_status_publication::publish_transition_complete(uint64_t epoch) noexcept
{
	if (!common::valid_epoch_id(epoch) || owner_active_epoch_ != epoch || owner_last_activated_epoch_ != epoch ||
	    owner_minimum_retained_epoch_ == 0u || owner_minimum_retained_epoch_ >= epoch) {
		return false;
	}
	const uint64_t generation = publication_.completed_generation();
	if (generation > (std::numeric_limits<uint64_t>::max() - 3u) / 2u ||
	    !kinetum::algo::single_writer_snapshot<FIELD_COUNT>::can_advance_sequence(generation * 2u)) {
		return false;
	}
	const std::array<uint64_t, FIELD_COUNT> fields{
		static_cast<uint64_t>(runtime_readiness::PACKET_READY),
		owner_runtime_generation_,
		epoch,
		epoch,
		epoch,
		owner_expected_workers_,
		owner_expected_workers_,
	};
	if (!publication_.publish(fields)) {
		return false;
	}
	owner_minimum_retained_epoch_ = epoch;
	return true;
}

publication_read_result runtime_status_publication::try_read(runtime_status_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<FIELD_COUNT>::snapshot observed{};
	if (!publication_.try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}

	const uint64_t readiness = observed.fields[READINESS];
	const uint64_t runtime_generation = observed.fields[RUNTIME_GENERATION];
	const uint64_t active_epoch = observed.fields[ACTIVE_EPOCH];
	const uint64_t minimum_retained_epoch = observed.fields[MINIMUM_RETAINED_EPOCH];
	const uint64_t last_activated_epoch = observed.fields[LAST_ACTIVATED_EPOCH];
	const uint64_t active_workers = observed.fields[ACTIVE_WORKERS];
	const uint64_t expected_workers = observed.fields[EXPECTED_WORKERS];
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (expected_workers == 0u || active_workers > std::numeric_limits<uint32_t>::max() ||
	    expected_workers > std::numeric_limits<uint32_t>::max()) {
		return publication_read_result::INVALID_STATE;
	}

	runtime_readiness decoded_readiness = runtime_readiness::CONTROL_READY;
	if (readiness == static_cast<uint64_t>(runtime_readiness::CONTROL_READY)) {
		if (active_epoch != 0u || minimum_retained_epoch != 0u || last_activated_epoch != 0u ||
		    active_workers != 0u) {
			return publication_read_result::INVALID_STATE;
		}
		decoded_readiness = runtime_readiness::CONTROL_READY;
	} else if (readiness == static_cast<uint64_t>(runtime_readiness::PACKET_READY)) {
		if (!common::valid_epoch_id(active_epoch) || !common::valid_epoch_id(minimum_retained_epoch) ||
		    minimum_retained_epoch > active_epoch || last_activated_epoch != active_epoch ||
		    active_workers != expected_workers) {
			return publication_read_result::INVALID_STATE;
		}
		decoded_readiness = runtime_readiness::PACKET_READY;
	} else {
		return publication_read_result::INVALID_STATE;
	}

	runtime_status_snapshot decoded{
		.publication_generation = observed.generation,
		.readiness = decoded_readiness,
		.runtime_generation = runtime_generation,
		.active_epoch = active_epoch,
		.minimum_retained_epoch = minimum_retained_epoch,
		.last_activated_epoch = last_activated_epoch,
		.active_workers = static_cast<uint32_t>(active_workers),
		.expected_workers = static_cast<uint32_t>(expected_workers),
	};
	out = decoded;
	return publication_read_result::AVAILABLE;
}

}  // namespace kinetum::dp
