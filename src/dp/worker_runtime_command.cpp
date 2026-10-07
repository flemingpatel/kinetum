// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_runtime_command.cpp
 * @brief One-load packet-worker command publication implementation.
 * @author Fleming Patel
 */

#include "src/dp/worker_runtime_command.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <new>

#include "src/common/epoch_transition_contract.hpp"

namespace kinetum::dp
{

bool worker_runtime_command_record::valid() const noexcept
{
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max() ||
	    !std::all_of(padding.begin(), padding.end(), [](uint8_t value) { return value == 0u; })) {
		return false;
	}
	switch (kind) {
	case worker_runtime_command_kind::RUN:
	case worker_runtime_command_kind::STOP:
		return transition_generation == 0u && from_epoch == 0u && to_epoch == 0u;
	case worker_runtime_command_kind::TRANSITION:
		return common::valid_mutation_sequence(transition_generation) && common::valid_epoch_id(from_epoch) &&
		       common::valid_epoch_id(to_epoch) && to_epoch > from_epoch;
	}
	return false;
}

common::status_or<std::unique_ptr<worker_runtime_command_publication>>
worker_runtime_command_publication::create(uint64_t runtime_generation) noexcept
{
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(kinetum::common::static_status_text(
			"worker command publication requires one representable runtime generation"));
	}
	auto *publication = new (std::nothrow) worker_runtime_command_publication(runtime_generation);
	if (publication == nullptr) {
		return common::status::resource_exhausted(
			kinetum::common::static_status_text("failed to allocate worker command publication"));
	}
	return std::unique_ptr<worker_runtime_command_publication>(publication);
}

worker_runtime_command_publication::worker_runtime_command_publication(uint64_t runtime_generation) noexcept
	: runtime_generation_(runtime_generation)
{
	run_record_.runtime_generation = runtime_generation;
	run_record_.kind = worker_runtime_command_kind::RUN;
	stop_record_.runtime_generation = runtime_generation;
	stop_record_.kind = worker_runtime_command_kind::STOP;
	publication_.active.store(&run_record_, std::memory_order_relaxed);
}

worker_runtime_command_publication::~worker_runtime_command_publication()
{
	const auto *active = publication_.active.load(std::memory_order_relaxed);
	const bool active_owned = active == &run_record_ || active == &stop_record_ || active == &transitions_[0] ||
				  active == &transitions_[1];
	if (!active_owned || published_transition_generation_ != completed_transition_generation_) {
		std::terminate();
	}
}

common::status worker_runtime_command_publication::preflight_transition(uint64_t transition_generation,
									uint64_t from_epoch,
									uint64_t to_epoch) const noexcept
{
	if (stop_published_) {
		return common::status::failed_precondition(
			kinetum::common::static_status_text("worker command publication is permanently stopped"));
	}
	if (!common::valid_mutation_sequence(transition_generation) || !common::valid_epoch_id(from_epoch) ||
	    !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch) {
		return common::status::invalid_argument(
			kinetum::common::static_status_text("worker transition command identity is malformed"));
	}
	if (published_transition_generation_ != completed_transition_generation_) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker command publication still owns an incomplete transition"));
	}
	if (published_transition_generation_ != 0u && transition_generation <= published_transition_generation_) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker transition command does not advance the published generation"));
	}
	if (next_transition_slot_ >= transitions_.size() ||
	    publication_.active.load(std::memory_order_relaxed) == &transitions_[next_transition_slot_]) {
		return common::status::internal_error(kinetum::common::static_status_text(
			"worker transition command has no inactive immutable slot"));
	}
	return common::status::ok();
}

void worker_runtime_command_publication::publish_transition_or_terminate(uint64_t transition_generation,
									 uint64_t from_epoch,
									 uint64_t to_epoch) noexcept
{
	if (!preflight_transition(transition_generation, from_epoch, to_epoch).is_ok()) {
		std::terminate();
	}
	auto &record = transitions_[next_transition_slot_];
	record = worker_runtime_command_record{
		.runtime_generation = runtime_generation_,
		.transition_generation = transition_generation,
		.from_epoch = from_epoch,
		.to_epoch = to_epoch,
		.kind = worker_runtime_command_kind::TRANSITION,
		.padding = {},
	};
	if (!record.valid()) {
		std::terminate();
	}
	publication_.active.store(&record, std::memory_order_release);
	published_transition_generation_ = transition_generation;
	next_transition_slot_ = next_transition_slot_ == 0u ? 1u : 0u;
}

void worker_runtime_command_publication::complete_transition_or_terminate(uint64_t transition_generation) noexcept
{
	if (transition_generation == 0u || transition_generation != published_transition_generation_ ||
	    completed_transition_generation_ == published_transition_generation_) {
		std::terminate();
	}
	completed_transition_generation_ = transition_generation;
}

void worker_runtime_command_publication::request_stop() noexcept
{
	if (stop_published_) {
		return;
	}
	if (!stop_record_.valid()) {
		std::terminate();
	}
	stop_published_ = true;
	publication_.active.store(&stop_record_, std::memory_order_release);
}

uint64_t worker_runtime_command_publication::runtime_generation() const noexcept
{
	return runtime_generation_;
}

}  // namespace kinetum::dp
