// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_epoch_ledger.cpp
 * @brief Worker-local packet-work accounting and coherent publication.
 * @author Fleming Patel
 */

#include "src/dp/epoch/worker_epoch_ledger.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <new>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/time.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"

namespace kinetum::dp
{

common::status_or<worker_epoch_credit_budget>
compile_worker_epoch_credit_budget(worker_epoch_credit_budget_input input) noexcept
{
	if (input.packet_storage_capacity == 0u || input.handoff_limit == 0u) {
		return common::status::invalid_argument(kinetum::common::static_status_text(
			"worker epoch credit budget requires storage and handoff authority"));
	}
	worker_epoch_credit_budget budget{
		.packet_storage_capacity = input.packet_storage_capacity,
		.synchronous_event_capacity = input.synchronous_event_capacity,
		.timer_capacity = input.timer_capacity,
		.timer_handoff_capacity = std::min(input.timer_capacity, input.handoff_limit),
		.async_work_capacity = input.async_work_capacity,
		.async_handoff_capacity = std::min(input.async_work_capacity, input.handoff_limit),
		.total = 0u,
	};
	for (const uint64_t term :
	     {budget.packet_storage_capacity, budget.synchronous_event_capacity, budget.timer_capacity,
	      budget.timer_handoff_capacity, budget.async_work_capacity, budget.async_handoff_capacity}) {
		if (term > std::numeric_limits<uint64_t>::max() - budget.total) {
			return common::status(
				common::status_code::OUT_OF_RANGE,
				kinetum::common::static_status_text("worker epoch credit budget overflows uint64"));
		}
		budget.total += term;
	}
	return budget;
}

common::status_or<std::unique_ptr<worker_epoch_ledger>>
worker_epoch_ledger::create(uint32_t worker_index, uint64_t runtime_generation, uint64_t maximum_unretired)
{
	if (worker_index == std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"worker epoch ledger requires a non-sentinel compact worker identity");
	}
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"worker epoch ledger requires a runtime generation representable by the provider ABI");
	}
	if (maximum_unretired == 0u) {
		return common::status::invalid_argument(
			"worker epoch ledger requires a nonzero compiled credit ceiling");
	}
	auto *ledger = new (std::nothrow) worker_epoch_ledger(worker_index, runtime_generation, maximum_unretired);
	if (ledger == nullptr) {
		return common::status::resource_exhausted("worker epoch ledger allocation failed");
	}
	return std::unique_ptr<worker_epoch_ledger>(ledger);
}

worker_epoch_ledger::worker_epoch_ledger(uint32_t worker_index, uint64_t runtime_generation,
					 uint64_t maximum_unretired) noexcept
	: worker_index_(worker_index)
	, runtime_generation_(runtime_generation)
	, maximum_unretired_(maximum_unretired)
{
}

worker_epoch_ledger::~worker_epoch_ledger()
{
	if (!empty()) {
		std::terminate();
	}
}

common::status worker_epoch_ledger::bind_protocol_faults(worker_runtime_telemetry &telemetry,
							 epoch_protocol_fault_latch &faults) noexcept
{
	if (telemetry.runtime_generation() != runtime_generation_ || telemetry.worker_index() != worker_index_) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker epoch ledger protocol-fault authorities disagree with owner identity"));
	}
	if (telemetry_ == nullptr && protocol_faults_ == nullptr) {
		telemetry_ = &telemetry;
		protocol_faults_ = &faults;
		return common::status::ok();
	}
	return telemetry_ == &telemetry && protocol_faults_ == &faults ?
		       common::status::ok() :
		       common::status::failed_precondition(kinetum::common::static_status_text(
			       "worker epoch ledger protocol-fault authority changed identity"));
}

void worker_epoch_ledger::bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept
{
	if (!common::valid_epoch_id(bootstrap_epoch) || owner_.active_epoch != 0u || owner_.source_epoch != 0u ||
	    owner_.future_epoch != 0u || !empty()) {
		std::terminate();
	}
	owner_.active_epoch = bootstrap_epoch;
	owner_.source_epoch = bootstrap_epoch;
	publish();
}

bool worker_epoch_ledger::preflight_begin_transition(uint64_t from_epoch, uint64_t future_epoch) const noexcept
{
	return common::valid_epoch_id(from_epoch) && common::valid_epoch_id(future_epoch) &&
	       future_epoch > from_epoch && owner_.active_epoch == from_epoch && owner_.source_epoch == from_epoch &&
	       owner_.future_epoch == 0u && owner_.future_unretired == 0u;
}

void worker_epoch_ledger::bind_future_epoch(uint64_t future_epoch) noexcept
{
	if (!preflight_begin_transition(owner_.active_epoch, future_epoch)) {
		std::terminate();
	}
	owner_.future_epoch = future_epoch;
}

void worker_epoch_ledger::advance_source_epoch(uint64_t future_epoch) noexcept
{
	if (future_epoch == 0u || owner_.source_epoch != owner_.active_epoch || owner_.future_epoch != future_epoch) {
		std::terminate();
	}
	owner_.source_epoch = future_epoch;
}

common::status worker_epoch_ledger::preflight_promote_future_epoch(uint64_t future_epoch) const noexcept
{
	if (!common::valid_epoch_id(future_epoch) || !common::valid_epoch_id(owner_.active_epoch) ||
	    owner_.source_epoch != future_epoch || owner_.future_epoch != future_epoch ||
	    future_epoch <= owner_.active_epoch) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker epoch promotion requires the exact active/source/future identity"));
	}
	if (owner_.active_unretired != 0u) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker epoch promotion requires zero old active ownership"));
	}
	if (owner_.future_unretired > maximum_unretired_) {
		return common::status::internal_error(kinetum::common::static_status_text(
			"worker epoch promotion future ownership exceeds its compiled ceiling"));
	}
	return common::status::ok();
}

void worker_epoch_ledger::promote_future_epoch(uint64_t future_epoch) noexcept
{
	if (!preflight_promote_future_epoch(future_epoch).is_ok()) {
		std::terminate();
	}
	owner_.active_epoch = future_epoch;
	owner_.active_unretired = owner_.future_unretired;
	owner_.future_epoch = 0u;
	owner_.future_unretired = 0u;
}

void worker_epoch_ledger::publish() noexcept
{
	if (!common::valid_epoch_id(owner_.active_epoch) || !common::valid_epoch_id(owner_.source_epoch) ||
	    (owner_.future_epoch != 0u && !common::valid_epoch_id(owner_.future_epoch)) ||
	    (owner_.source_epoch != owner_.active_epoch && owner_.source_epoch != owner_.future_epoch) ||
	    (owner_.future_epoch == 0u && owner_.future_unretired != 0u) ||
	    (owner_.future_epoch != 0u && owner_.future_epoch <= owner_.active_epoch) ||
	    owner_.active_unretired > maximum_unretired_ || owner_.future_unretired > maximum_unretired_ ||
	    owner_.active_unretired > maximum_unretired_ - owner_.future_unretired) {
		std::terminate();
	}

	const std::array<uint64_t, PUBLICATION_FIELD_COUNT> fields{
		runtime_generation_,	 worker_index_,	      owner_.active_epoch,     owner_.source_epoch,
		owner_.active_unretired, owner_.future_epoch, owner_.future_unretired,
	};
	if (!publication_.publish(fields)) {
		std::terminate();
	}
}

publication_read_result worker_epoch_ledger::try_read(worker_epoch_ledger_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<PUBLICATION_FIELD_COUNT>::snapshot observed{};
	if (!publication_.try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}

	const uint64_t runtime_generation = observed.fields[RUNTIME_GENERATION];
	const uint64_t worker_index = observed.fields[WORKER_INDEX];
	const uint64_t active_epoch = observed.fields[ACTIVE_EPOCH];
	const uint64_t source_epoch = observed.fields[SOURCE_EPOCH];
	const uint64_t active_unretired = observed.fields[ACTIVE_UNRETIRED];
	const uint64_t future_epoch = observed.fields[FUTURE_EPOCH];
	const uint64_t future_unretired = observed.fields[FUTURE_UNRETIRED];
	if (runtime_generation != runtime_generation_ || worker_index != worker_index_) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (!common::valid_epoch_id(active_epoch) || !common::valid_epoch_id(source_epoch) ||
	    (future_epoch != 0u && !common::valid_epoch_id(future_epoch)) ||
	    (source_epoch != active_epoch && source_epoch != future_epoch) ||
	    (future_epoch == 0u && future_unretired != 0u) || (future_epoch != 0u && future_epoch <= active_epoch) ||
	    active_unretired > maximum_unretired_ || future_unretired > maximum_unretired_ ||
	    active_unretired > maximum_unretired_ - future_unretired) {
		return publication_read_result::INVALID_STATE;
	}

	out = worker_epoch_ledger_snapshot{
		.publication_generation = observed.generation,
		.runtime_generation = runtime_generation,
		.worker_index = worker_index,
		.active_epoch = active_epoch,
		.source_epoch = source_epoch,
		.active_unretired = active_unretired,
		.future_epoch = future_epoch,
		.future_unretired = future_unretired,
	};
	return publication_read_result::AVAILABLE;
}

bool worker_epoch_ledger::empty() const noexcept
{
	return owner_.active_unretired == 0u && owner_.future_unretired == 0u;
}

[[noreturn]] void worker_epoch_ledger::record_fault_and_terminate_(epoch_protocol_fault_code code,
								   uint64_t observed_epoch, uint64_t expected_value,
								   uint64_t observed_value) noexcept
{
	if (telemetry_ != nullptr && protocol_faults_ != nullptr) {
		telemetry_->record_protocol_fault(code);
		(void)protocol_faults_->record(epoch_protocol_first_fault{
			.runtime_generation = runtime_generation_,
			.transition_generation = 0u,
			.from_epoch = owner_.active_epoch,
			.to_epoch = owner_.future_epoch,
			.observed_epoch = observed_epoch,
			.expected_value = expected_value,
			.observed_value = observed_value,
			.observed_monotonic_ns = common::cached_ns(),
			.worker_index = worker_index_,
			.boundary_index = UINT32_MAX,
			.context_index = UINT32_MAX,
			.stage_instance_index = UINT32_MAX,
			.code = code,
			.disposition = epoch_protocol_fault_disposition::TERMINATE,
			.padding = {},
		});
	}
	std::terminate();
}

}  // namespace kinetum::dp
