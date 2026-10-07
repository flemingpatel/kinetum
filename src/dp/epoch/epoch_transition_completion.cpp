// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_transition_completion.cpp
 * @brief Exact cold completion and reclamation implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/epoch_transition_completion.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "src/common/time.hpp"
#include "src/dp/epoch/epoch_transition_preparation.hpp"
#include "src/dp/epoch/epoch_transition_telemetry_completion.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;
using kinetum::dp::lifecycle::config_lifecycle_operation;
using kinetum::dp::lifecycle::config_lifecycle_result;
using kinetum::dp::lifecycle::config_lifecycle_result_code;

status_or<std::unique_ptr<epoch_transition_completion>> epoch_transition_completion::create(
	uint64_t runtime_generation, epoch_transition_coordinator &coordinator,
	const epoch_transition_certificate &certificate, kinetum::algo::quiescence_domain &domain,
	epoch_transition_prepared_completion &preparation, epoch_transition_module_completion &modules,
	runtime_status_publication &runtime_status, epoch_transition_telemetry_completion &telemetry,
	epoch_protocol_fault_latch &protocol_faults, const common::compiled_epoch_transition_policy &policy)
{
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return status::invalid_argument("transition completion runtime generation is outside the exact domain");
	}
	if (!policy.enabled || policy.commit_timeout <= std::chrono::steady_clock::duration::zero() ||
	    policy.retirement_timeout < policy.commit_timeout) {
		return status::invalid_argument("transition completion compiled policy is incomplete or inconsistent");
	}
	if (certificate.runtime_generation() != runtime_generation) {
		return status::failed_precondition("transition completion certificate belongs to another generation");
	}
	if (!certificate.owns_participants(coordinator.participants()) || !certificate.owns_domain(domain) ||
	    certificate.execution_participant_count() != domain.reader_count() ||
	    !coordinator.owns_protocol_faults(runtime_generation, protocol_faults)) {
		return status::failed_precondition(
			"transition completion certificate, participants, and reader domain are not one authority");
	}
	if (coordinator.phase() != epoch_transition_phase::AWAITING_BOOTSTRAP) {
		return status::failed_precondition(
			"transition completion must be constructed before Bootstrap publication");
	}

	const std::size_t context_count = modules.completion_context_count();
	const std::size_t image_count = modules.completion_image_count();
	const std::size_t executor_count = modules.completion_executor_count();
	if ((context_count == 0u) != (image_count == 0u) || executor_count == 0u ||
	    context_count > std::numeric_limits<uint32_t>::max() ||
	    context_count != coordinator.participants().module_context_count()) {
		return status::failed_precondition(
			"transition completion module context/image/executor cardinality is incomplete");
	}

	auto contexts =
		context_count == 0u ?
			nullptr :
			std::unique_ptr<context_operation[]>(new (std::nothrow) context_operation[context_count]);
	if (context_count != 0u && contexts == nullptr) {
		return status::resource_exhausted("failed to allocate transition completion context table");
	}
	try {
		std::vector<uint8_t> image_busy(image_count, uint8_t{0});
		std::vector<uint8_t> executor_busy(executor_count, uint8_t{0});
		std::vector<std::size_t> image_frontier(image_count, INVALID_CONTEXT_ORDINAL);
		std::vector<std::size_t> executor_frontier(executor_count, INVALID_CONTEXT_ORDINAL);
		std::vector<std::size_t> ready_ordinals(context_count, INVALID_CONTEXT_ORDINAL);
		uint32_t previous_context = 0u;
		bool have_previous = false;
		for (std::size_t ordinal = 0u; ordinal < context_count; ++ordinal) {
			const uint32_t context_index = modules.completion_context_index(ordinal);
			const uint32_t image_index = modules.completion_image_index(ordinal);
			const std::size_t executor_index = modules.completion_executor_index(ordinal);
			if (context_index != static_cast<uint32_t>(ordinal) || image_index >= image_count ||
			    executor_index >= executor_count || (have_previous && context_index <= previous_context)) {
				return status::failed_precondition(
					"transition completion context projection is not exact, sorted, and complete");
			}
			contexts[ordinal].context_index = context_index;
			contexts[ordinal].module_image_index = image_index;
			contexts[ordinal].executor_index = executor_index;
			contexts[ordinal].previous_image_ordinal = image_frontier[image_index];
			contexts[ordinal].previous_executor_ordinal = executor_frontier[executor_index];
			image_frontier[image_index] = ordinal;
			executor_frontier[executor_index] = ordinal;
			image_busy[image_index] = 1u;
			executor_busy[executor_index] = 1u;
			previous_context = context_index;
			have_previous = true;
		}
		if (context_count != 0u && (!std::all_of(image_busy.begin(), image_busy.end(), [](uint8_t value) {
			    return value == 1u;
		    }) || !std::all_of(executor_busy.begin(), executor_busy.end(), [](uint8_t value) {
			    return value == 1u;
		    }))) {
			return status::failed_precondition(
				"transition completion image/executor projection has unowned members");
		}
		std::fill(image_busy.begin(), image_busy.end(), uint8_t{0});
		std::fill(executor_busy.begin(), executor_busy.end(), uint8_t{0});
		std::fill(image_frontier.begin(), image_frontier.end(), INVALID_CONTEXT_ORDINAL);
		std::fill(executor_frontier.begin(), executor_frontier.end(), INVALID_CONTEXT_ORDINAL);
		return std::unique_ptr<epoch_transition_completion>(new epoch_transition_completion(
			runtime_generation, coordinator, certificate, domain, preparation, modules, runtime_status,
			telemetry, protocol_faults, std::move(contexts), context_count,
			serialization_state{
				.image_busy = std::move(image_busy),
				.executor_busy = std::move(executor_busy),
				.image_frontier = std::move(image_frontier),
				.executor_frontier = std::move(executor_frontier),
				.ready_ordinals = std::move(ready_ordinals),
			},
			behavior_timeouts{.commit = policy.commit_timeout, .retirement = policy.retirement_timeout}));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate transition completion owner");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      "transition completion metadata exceeds bounded host containers");
	}
}

epoch_transition_completion::epoch_transition_completion(
	uint64_t runtime_generation, epoch_transition_coordinator &coordinator,
	const epoch_transition_certificate &certificate, kinetum::algo::quiescence_domain &domain,
	epoch_transition_prepared_completion &preparation, epoch_transition_module_completion &modules,
	runtime_status_publication &runtime_status, epoch_transition_telemetry_completion &telemetry,
	epoch_protocol_fault_latch &protocol_faults, std::unique_ptr<context_operation[]> contexts,
	std::size_t context_count, serialization_state serialization, behavior_timeouts timeouts) noexcept
	: runtime_generation_(runtime_generation)
	, coordinator_(&coordinator)
	, certificate_(&certificate)
	, domain_(&domain)
	, preparation_(&preparation)
	, modules_(&modules)
	, runtime_status_(&runtime_status)
	, telemetry_(&telemetry)
	, protocol_faults_(&protocol_faults)
	, contexts_(std::move(contexts))
	, context_count_(context_count)
	, image_busy_(std::move(serialization.image_busy))
	, executor_busy_(std::move(serialization.executor_busy))
	, image_frontier_(std::move(serialization.image_frontier))
	, executor_frontier_(std::move(serialization.executor_frontier))
	, ready_ordinals_(std::move(serialization.ready_ordinals))
	, commit_timeout_(timeouts.commit)
	, retirement_timeout_(timeouts.retirement)
{
}

epoch_transition_completion::~epoch_transition_completion()
{
	bool rows_idle = true;
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		const auto &row = contexts_[ordinal];
		rows_idle = rows_idle && row.phase == context_phase::IDLE && row.task_sequence == 0u &&
			    !row.control.has_value() && !row.claim.has_value();
	}
	if (active() || grace_generation_ != 0u || commit_deadline_ != std::chrono::steady_clock::time_point{} ||
	    retirement_deadline_ != std::chrono::steady_clock::time_point{} ||
	    latest_retirement_deadline_ != std::chrono::steady_clock::time_point{} ||
	    next_probe_ != std::chrono::steady_clock::time_point{} || ownership_withdrawn_ || failed_stop_ ||
	    !rows_idle ||
	    std::any_of(image_busy_.begin(), image_busy_.end(), [](uint8_t value) { return value != 0u; }) ||
	    std::any_of(executor_busy_.begin(), executor_busy_.end(), [](uint8_t value) { return value != 0u; }) ||
	    std::any_of(image_frontier_.begin(), image_frontier_.end(),
			[](std::size_t ordinal) { return ordinal != INVALID_CONTEXT_ORDINAL; }) ||
	    std::any_of(executor_frontier_.begin(), executor_frontier_.end(),
			[](std::size_t ordinal) { return ordinal != INVALID_CONTEXT_ORDINAL; }) ||
	    ready_count_ != 0u || in_flight_count_ != 0u || retired_count_ != 0u ||
	    std::any_of(ready_ordinals_.begin(), ready_ordinals_.end(),
			[](std::size_t ordinal) { return ordinal != INVALID_CONTEXT_ORDINAL; })) {
		std::terminate();
	}
}

status epoch_transition_completion::arm_before_prepared(const common::epoch_transition_identity &identity) noexcept
{
	if (active() || !identity.valid() || coordinator_ == nullptr || certificate_ == nullptr || domain_ == nullptr ||
	    preparation_ == nullptr || modules_ == nullptr || runtime_status_ == nullptr || telemetry_ == nullptr ||
	    protocol_faults_ == nullptr || certificate_->runtime_generation() != runtime_generation_ ||
	    !certificate_->owns_participants(coordinator_->participants()) || !certificate_->owns_domain(*domain_) ||
	    certificate_->execution_participant_count() != domain_->reader_count() || !module_membership_exact_() ||
	    !runtime_status_->owns_runtime_generation(runtime_generation_) ||
	    coordinator_->phase() != epoch_transition_phase::PREPARING ||
	    !preparation_->completion_prepared(identity) || domain_->active_generation() != 0u) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"completion arm lacks one exact PREPARING/PREPARED ownership pair"));
	}
	const uint64_t from_epoch = coordinator_->active_epoch();
	auto snapshot_preflight = coordinator_->preflight_completion_arm(identity);
	if (!snapshot_preflight.is_ok()) {
		return snapshot_preflight;
	}
	auto module_preflight = modules_->preflight_future_completion(from_epoch, identity.target_epoch);
	if (!module_preflight.is_ok()) {
		return module_preflight;
	}
	if (!runtime_status_->can_publish_transition(from_epoch, identity.target_epoch)) {
		return status::resource_exhausted(kinetum::common::static_status_text(
			"runtime status cannot represent both transition completion publications"));
	}
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		const auto &row = contexts_[ordinal];
		if (row.phase != context_phase::IDLE || row.task_sequence != 0u || row.control.has_value() ||
		    row.claim.has_value()) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"completion arm found retained context operation state"));
		}
	}
	if (std::any_of(image_busy_.begin(), image_busy_.end(), [](uint8_t value) { return value != 0u; }) ||
	    std::any_of(executor_busy_.begin(), executor_busy_.end(), [](uint8_t value) { return value != 0u; }) ||
	    std::any_of(image_frontier_.begin(), image_frontier_.end(),
			[](std::size_t ordinal) { return ordinal != INVALID_CONTEXT_ORDINAL; }) ||
	    std::any_of(executor_frontier_.begin(), executor_frontier_.end(),
			[](std::size_t ordinal) { return ordinal != INVALID_CONTEXT_ORDINAL; }) ||
	    ready_count_ != 0u || in_flight_count_ != 0u || retired_count_ != 0u ||
	    std::any_of(ready_ordinals_.begin(), ready_ordinals_.end(),
			[](std::size_t ordinal) { return ordinal != INVALID_CONTEXT_ORDINAL; })) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"completion arm found retained serialization scheduling state"));
	}
	auto armed = coordinator_->arm_completion(identity);
	if (!armed.is_ok()) {
		return armed;
	}

	identity_ = identity;
	last_progress_ = {};
	last_progress_.runtime_generation = runtime_generation_;
	last_progress_.transition_generation = identity.mutation_sequence;
	last_progress_.from_epoch = from_epoch;
	last_progress_.to_epoch = identity.target_epoch;
	last_progress_.execution_total = static_cast<uint32_t>(certificate_->execution_participant_count());
	last_progress_.boundary_total = static_cast<uint32_t>(certificate_->boundary_count());
	last_progress_.reader_total = static_cast<uint32_t>(certificate_->reader_count());
	last_progress_.fault_index = UINT32_MAX;
	last_progress_.certificate_state = epoch_transition_certificate_state::INCOMPLETE;
	last_progress_.certificate_fault = epoch_transition_certificate_fault::NONE;
	last_progress_.transaction_active = true;
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		contexts_[ordinal].control.emplace(std::chrono::steady_clock::time_point{});
		contexts_[ordinal].phase = context_phase::ARMED;
	}
	publish_progress_or_terminate_();
	return status::ok();
}

void epoch_transition_completion::disarm_after_abort(const common::epoch_transition_identity &identity) noexcept
{
	if (!active() || identity_ != identity || grace_generation_ != 0u || ownership_withdrawn_ || failed_stop_ ||
	    coordinator_->phase() != epoch_transition_phase::IDLE || preparation_->completion_prepared(identity)) {
		std::terminate();
	}
	last_progress_.transaction_active = false;
	publish_progress_or_terminate_();
	reset_clean_();
}

status epoch_transition_completion::begin_commit(const common::epoch_transition_identity &identity,
						 std::chrono::steady_clock::time_point now) noexcept
{
	if (!active() || identity_ != identity || grace_generation_ != 0u || ownership_withdrawn_ || failed_stop_ ||
	    now == std::chrono::steady_clock::time_point{} ||
	    coordinator_->phase() != epoch_transition_phase::PREPARED || !preparation_->completion_prepared(identity)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("completion commit lacks exact armed PREPARED ownership"));
	}
	auto commit_deadline_or = checked_transition_deadline(now, commit_timeout_);
	if (!commit_deadline_or.is_ok()) {
		return std::move(commit_deadline_or).error();
	}
	auto latest_retirement_or = checked_transition_deadline(commit_deadline_or.value(), retirement_timeout_);
	if (!latest_retirement_or.is_ok()) {
		return std::move(latest_retirement_or).error();
	}
	const uint64_t commit_ns = monotonic_nanoseconds_(now);
	if (protocol_faults_ == nullptr) {
		std::terminate();
	}
	if (protocol_faults_->transition_success_blocked()) {
		const auto observed_at = std::max(now, std::chrono::steady_clock::now());
		coordinator_->fail_active_or_terminate(identity, monotonic_nanoseconds_(observed_at),
						       epoch_transition_failure_code::PROTOCOL_FAULT,
						       "protocol safety fault blocked transition success");
		failed_stop_ = true;
		last_progress_.transaction_active = true;
		publish_progress_or_terminate_();
		return status::failed_precondition(
			kinetum::common::static_status_text("protocol safety fault blocked transition success"));
	}
	auto coordinator_preflight = coordinator_->preflight_begin_commit(identity, commit_ns);
	if (!coordinator_preflight.is_ok()) {
		return coordinator_preflight;
	}
	if (!domain_->can_start_grace_period()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"completion commit cannot start one exact adjacent reader grace"));
	}

	const uint64_t grace = domain_->start_grace_period();
	if (grace == 0u) {
		std::terminate();
	}
	coordinator_->begin_commit_or_terminate(identity, commit_ns);
	preparation_->release_completion_preparation(identity);
	grace_generation_ = grace;
	last_progress_.grace_generation = grace;
	last_progress_.grace_started_monotonic_ns = commit_ns;
	last_progress_.transaction_active = true;
	publish_progress_or_terminate_();
	commit_deadline_ = commit_deadline_or.value();
	latest_retirement_deadline_ = latest_retirement_or.value();
	schedule_next_probe_(now);
	return status::ok();
}

status epoch_transition_completion::service_progress(std::chrono::steady_clock::time_point now) noexcept
{
	if (!active() || grace_generation_ == 0u || failed_stop_ || coordinator_->retirement_frozen()) {
		return status::ok();
	}
	if (now == std::chrono::steady_clock::time_point{}) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"completion progress requires one exact steady-clock sample"));
	}
	if (next_probe_ == std::chrono::steady_clock::time_point{}) {
		std::terminate();
	}
	if (now < next_probe_) {
		return status::ok();
	}
	if (protocol_faults_ == nullptr) {
		std::terminate();
	}
	if (protocol_faults_->transition_success_blocked()) {
		const auto observed_at = std::max(now, std::chrono::steady_clock::now());
		return fail_stop_(
			epoch_transition_failure_code::PROTOCOL_FAULT,
			kinetum::common::static_status_text("protocol safety fault blocked transition success"),
			observed_at);
	}
	auto deadline_status = service_deadline(now);
	if (!deadline_status.is_ok() || failed_stop_ || coordinator_->retirement_frozen()) {
		return deadline_status;
	}

	const epoch_transition_certificate_request request{
		.runtime_generation = runtime_generation_,
		.transition_generation = identity_.mutation_sequence,
		.from_epoch = coordinator_->active_epoch(),
		.to_epoch = identity_.target_epoch,
		.grace_generation = grace_generation_,
	};
	const auto progress = certificate_->evaluate(request);
	last_progress_.evaluated_monotonic_ns = monotonic_nanoseconds_(now);
	last_progress_.execution_complete = progress.execution_complete;
	last_progress_.execution_total = progress.execution_total;
	last_progress_.boundary_complete = progress.boundary_complete;
	last_progress_.boundary_total = progress.boundary_total;
	last_progress_.reader_complete = progress.reader_complete;
	last_progress_.reader_total = progress.reader_total;
	last_progress_.fault_index = progress.fault_index;
	last_progress_.certificate_state = progress.state;
	last_progress_.certificate_fault = progress.fault;
	if (progress.reader_total != 0u && progress.reader_complete == progress.reader_total &&
	    last_progress_.grace_completion_observed_monotonic_ns == 0u) {
		last_progress_.grace_completion_observed_monotonic_ns = last_progress_.evaluated_monotonic_ns;
	}
	publish_progress_or_terminate_();
	if (progress.state == epoch_transition_certificate_state::CONTRADICTION) {
		return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
				  kinetum::common::static_status_text(
					  "transition certificate reported one coherent contradiction"),
				  now);
	}

	if (coordinator_->phase() == epoch_transition_phase::COMMITTING &&
	    (progress.state == epoch_transition_certificate_state::EXECUTION_COMPLETE ||
	     progress.state == epoch_transition_certificate_state::RECLAMATION_READY)) {
		const uint64_t retiring_ns = monotonic_nanoseconds_(now);
		auto retirement_deadline_or = checked_transition_deadline(now, retirement_timeout_);
		if (retiring_ns == 0u || !retirement_deadline_or.is_ok() ||
		    retirement_deadline_or.value() > latest_retirement_deadline_) {
			std::terminate();
		}
		const auto module_preflight =
			modules_->preflight_completion_activation(coordinator_->active_epoch(), identity_.target_epoch);
		const auto coordinator_preflight = coordinator_->preflight_begin_retiring(identity_, retiring_ns);
		if (!module_preflight.is_ok() || !coordinator_preflight.is_ok() ||
		    !runtime_status_->can_publish_transition(coordinator_->active_epoch(), identity_.target_epoch)) {
			return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
					  kinetum::common::static_status_text(
						  "execution certificate disagrees with exact activation ownership"),
					  now);
		}
		const uint64_t from_epoch = coordinator_->active_epoch();
		modules_->publish_completion_activation(from_epoch, identity_.target_epoch);
		coordinator_->publish_target_snapshot_or_terminate(identity_);
		if (!runtime_status_->publish_transition_activated(from_epoch, identity_.target_epoch)) {
			std::terminate();
		}
		coordinator_->enter_retiring_or_terminate(identity_, retiring_ns);
		retirement_deadline_ = retirement_deadline_or.value();
		commit_deadline_ = {};
		schedule_next_probe_(now);
		if (progress.state == epoch_transition_certificate_state::RECLAMATION_READY) {
			if (!telemetry_->worker_epoch_aggregated(from_epoch) ||
			    !telemetry_->module_epoch_aggregated(from_epoch)) {
				schedule_next_probe_(now);
				return status::ok();
			}
			return begin_reclamation_(now);
		}
		return status::ok();
	}

	if (coordinator_->phase() == epoch_transition_phase::RETIRING && !ownership_withdrawn_ &&
	    progress.state == epoch_transition_certificate_state::RECLAMATION_READY) {
		const uint64_t from_epoch = coordinator_->active_epoch();
		if (!telemetry_->worker_epoch_aggregated(from_epoch) ||
		    !telemetry_->module_epoch_aggregated(from_epoch)) {
			schedule_next_probe_(now);
			return status::ok();
		}
		return begin_reclamation_(now);
	}
	schedule_next_probe_(now);
	return status::ok();
}

status epoch_transition_completion::service_results(std::chrono::steady_clock::time_point now) noexcept
{
	if (!active() || failed_stop_ || !ownership_withdrawn_) {
		return status::ok();
	}
	if (now == std::chrono::steady_clock::time_point{}) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"completion result service requires one exact steady-clock sample"));
	}
	if (protocol_faults_ == nullptr) {
		std::terminate();
	}
	if (protocol_faults_->transition_success_blocked()) {
		const auto observed_at = std::max(now, std::chrono::steady_clock::now());
		return fail_stop_(
			epoch_transition_failure_code::PROTOCOL_FAULT,
			kinetum::common::static_status_text("protocol safety fault blocked transition completion"),
			observed_at);
	}
	auto deadline_status = service_deadline(now);
	if (!deadline_status.is_ok() || failed_stop_) {
		return deadline_status;
	}
	// Each accepted in-flight task can publish exactly one result, and this
	// owner dispatches no successor until the bounded drain completes.
	const std::size_t result_bound = in_flight_count_;
	for (std::size_t result_index = 0u; result_index < result_bound; ++result_index) {
		auto result = modules_->try_take_completion_result();
		if (!result.has_value()) {
			break;
		}
		auto consumed = consume_result_(std::move(*result), now);
		if (!consumed.is_ok()) {
			return consumed;
		}
	}
	auto dispatched = dispatch_eligible_();
	if (!dispatched.is_ok()) {
		return fail_stop_(epoch_transition_failure_code::RETIRE_CALLBACK_FAILURE, std::move(dispatched), now);
	}
	if (all_contexts_retired_()) {
		return publish_complete_or_fail_stop_(now);
	} else if (in_flight_count_ == 0u) {
		return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
				  kinetum::common::static_status_text(
					  "claimed RETIRE scheduler has no ready or in-flight context"),
				  now);
	}
	return status::ok();
}

status epoch_transition_completion::service_deadline(std::chrono::steady_clock::time_point now) noexcept
{
	if (!active() || grace_generation_ == 0u || failed_stop_ || coordinator_->retirement_frozen()) {
		return status::ok();
	}
	if (now == std::chrono::steady_clock::time_point{}) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"completion deadline service requires one exact steady-clock sample"));
	}
	if (coordinator_->phase() == epoch_transition_phase::COMMITTING &&
	    commit_deadline_ != std::chrono::steady_clock::time_point{} && now >= commit_deadline_) {
		return fail_stop_(
			epoch_transition_failure_code::COMMIT_DEADLINE_EXCEEDED,
			kinetum::common::static_status_text("compiled completion-only commit deadline expired"), now);
	}
	if (coordinator_->phase() == epoch_transition_phase::RETIRING &&
	    retirement_deadline_ != std::chrono::steady_clock::time_point{} && now >= retirement_deadline_) {
		if (!ownership_withdrawn_) {
			const uint64_t frozen_ns = monotonic_nanoseconds_(now);
			coordinator_->freeze_retirement_or_terminate(
				identity_, frozen_ns,
				"compiled reader-grace retirement deadline expired before ownership withdrawal");
			last_progress_.update_frozen = true;
			publish_progress_or_terminate_();
			next_probe_ = {};
			retirement_deadline_ = {};
			latest_retirement_deadline_ = {};
			return status::ok();
		}
		return fail_stop_(epoch_transition_failure_code::RETIRE_CALLBACK_DEADLINE_EXCEEDED,
				  kinetum::common::static_status_text(
					  "claimed module RETIRE exceeded the compiled retirement deadline"),
				  now);
	}
	return status::ok();
}

std::optional<std::chrono::steady_clock::time_point> epoch_transition_completion::next_deadline() const noexcept
{
	if (!active() || grace_generation_ == 0u || failed_stop_ || coordinator_->retirement_frozen() ||
	    next_probe_ == std::chrono::steady_clock::time_point{}) {
		return std::nullopt;
	}
	return next_probe_;
}

bool epoch_transition_completion::active() const noexcept
{
	return identity_.valid();
}

bool epoch_transition_completion::ownership_withdrawn() const noexcept
{
	return ownership_withdrawn_;
}

const common::epoch_transition_identity *epoch_transition_completion::identity() const noexcept
{
	return active() ? &identity_ : nullptr;
}

publication_read_result
validate_epoch_completion_progress(const epoch_transition_completion_progress_snapshot &value) noexcept
{
	bool fault_index_valid = false;
	switch (value.certificate_fault) {
	case epoch_transition_certificate_fault::NONE:
	case epoch_transition_certificate_fault::REQUEST_IDENTITY:
	case epoch_transition_certificate_fault::READER_MEMBERSHIP:
		fault_index_valid = value.fault_index == UINT32_MAX;
		break;
	case epoch_transition_certificate_fault::EXECUTION_MEMBERSHIP:
	case epoch_transition_certificate_fault::EXECUTION_STATE:
		fault_index_valid = value.fault_index < value.execution_total;
		break;
	case epoch_transition_certificate_fault::BOUNDARY_MEMBERSHIP:
	case epoch_transition_certificate_fault::BOUNDARY_STATE:
	case epoch_transition_certificate_fault::CUT_IDENTITY:
		fault_index_valid = value.fault_index < value.boundary_total;
		break;
	}
	const bool execution_complete = value.execution_complete == value.execution_total &&
					value.boundary_complete == value.boundary_total;
	const bool readers_complete = value.reader_complete == value.reader_total;
	const bool contradiction = value.certificate_state == epoch_transition_certificate_state::CONTRADICTION;
	bool certificate_shape = false;
	switch (value.certificate_state) {
	case epoch_transition_certificate_state::INCOMPLETE:
		certificate_shape = !execution_complete;
		break;
	case epoch_transition_certificate_state::EXECUTION_COMPLETE:
		certificate_shape = execution_complete && !readers_complete;
		break;
	case epoch_transition_certificate_state::RECLAMATION_READY:
		certificate_shape = execution_complete && readers_complete;
		break;
	case epoch_transition_certificate_state::CONTRADICTION:
		certificate_shape = true;
		break;
	}
	if (value.publication_generation == 0u || value.execution_total == 0u ||
	    value.reader_total != value.execution_total || !certificate_shape || !fault_index_valid ||
	    (contradiction != (value.certificate_fault != epoch_transition_certificate_fault::NONE)) ||
	    (value.evaluated_monotonic_ns == 0u &&
	     (value.certificate_state != epoch_transition_certificate_state::INCOMPLETE ||
	      value.execution_complete != 0u || value.boundary_complete != 0u || value.reader_complete != 0u ||
	      value.ownership_withdrawn || value.update_frozen)) ||
	    (value.update_frozen &&
	     (!value.transaction_active || value.ownership_withdrawn || value.grace_generation == 0u)) ||
	    (value.grace_finished_monotonic_ns != 0u && value.transaction_active) ||
	    (value.evaluated_monotonic_ns != 0u &&
	     (value.grace_generation == 0u || value.evaluated_monotonic_ns < value.grace_started_monotonic_ns)) ||
	    !common::valid_mutation_sequence(value.transition_generation) ||
	    !common::valid_epoch_id(value.from_epoch) || !common::valid_epoch_id(value.to_epoch) ||
	    value.to_epoch <= value.from_epoch || value.execution_complete > value.execution_total ||
	    value.boundary_complete > value.boundary_total || value.reader_complete > value.reader_total ||
	    (value.ownership_withdrawn && value.grace_generation == 0u) ||
	    (!value.transaction_active && value.grace_generation != 0u && value.grace_finished_monotonic_ns == 0u) ||
	    (value.grace_generation == 0u &&
	     (value.grace_started_monotonic_ns != 0u || value.grace_completion_observed_monotonic_ns != 0u ||
	      value.grace_finished_monotonic_ns != 0u)) ||
	    (value.grace_generation != 0u && value.grace_started_monotonic_ns == 0u) ||
	    (value.grace_completion_observed_monotonic_ns != 0u &&
	     value.grace_completion_observed_monotonic_ns < value.grace_started_monotonic_ns) ||
	    (value.grace_finished_monotonic_ns != 0u &&
	     (value.grace_completion_observed_monotonic_ns == 0u ||
	      value.grace_finished_monotonic_ns < value.grace_completion_observed_monotonic_ns))) {
		return publication_read_result::INVALID_STATE;
	}
	return publication_read_result::AVAILABLE;
}

publication_read_result
epoch_transition_completion::try_read_progress(epoch_transition_completion_progress_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<PROGRESS_FIELD_COUNT>::snapshot observed{};
	if (!progress_.try_read(observed, PROGRESS_OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}
	if (observed.fields[0] != runtime_generation_ ||
	    observed.fields[10] != certificate_->execution_participant_count() ||
	    observed.fields[12] != certificate_->boundary_count() ||
	    observed.fields[14] != certificate_->reader_count()) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (observed.fields[16] > static_cast<uint64_t>(epoch_transition_certificate_state::CONTRADICTION) ||
	    observed.fields[17] > static_cast<uint64_t>(epoch_transition_certificate_fault::READER_MEMBERSHIP) ||
	    observed.fields[18] > 1u || observed.fields[19] > 1u || observed.fields[20] > 1u ||
	    observed.fields[9] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[10] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[11] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[12] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[13] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[14] > std::numeric_limits<uint32_t>::max() ||
	    observed.fields[15] > std::numeric_limits<uint32_t>::max()) {
		return publication_read_result::INVALID_STATE;
	}
	epoch_transition_completion_progress_snapshot decoded{
		.publication_generation = observed.generation,
		.runtime_generation = observed.fields[0],
		.transition_generation = observed.fields[1],
		.from_epoch = observed.fields[2],
		.to_epoch = observed.fields[3],
		.evaluated_monotonic_ns = observed.fields[4],
		.grace_generation = observed.fields[5],
		.grace_started_monotonic_ns = observed.fields[6],
		.grace_completion_observed_monotonic_ns = observed.fields[7],
		.grace_finished_monotonic_ns = observed.fields[8],
		.execution_complete = static_cast<uint32_t>(observed.fields[9]),
		.execution_total = static_cast<uint32_t>(observed.fields[10]),
		.boundary_complete = static_cast<uint32_t>(observed.fields[11]),
		.boundary_total = static_cast<uint32_t>(observed.fields[12]),
		.reader_complete = static_cast<uint32_t>(observed.fields[13]),
		.reader_total = static_cast<uint32_t>(observed.fields[14]),
		.fault_index = static_cast<uint32_t>(observed.fields[15]),
		.certificate_state = static_cast<epoch_transition_certificate_state>(observed.fields[16]),
		.certificate_fault = static_cast<epoch_transition_certificate_fault>(observed.fields[17]),
		.transaction_active = observed.fields[18] != 0u,
		.ownership_withdrawn = observed.fields[19] != 0u,
		.update_frozen = observed.fields[20] != 0u,
		.padding = {},
	};
	const auto validation = validate_epoch_completion_progress(decoded);
	if (validation != publication_read_result::AVAILABLE) {
		return validation;
	}
	out = decoded;
	return publication_read_result::AVAILABLE;
}

status epoch_transition_completion::dispatch_eligible_() noexcept
{
	if (!active() || !ownership_withdrawn_ || retirement_deadline_ == std::chrono::steady_clock::time_point{}) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"claimed RETIRE dispatch lacks exact completion ownership"));
	}
	while (ready_count_ != 0u) {
		const std::size_t ready_index = ready_count_ - 1u;
		const std::size_t ordinal = ready_ordinals_[ready_index];
		if (ordinal >= context_count_) {
			std::terminate();
		}
		auto &row = contexts_[ordinal];
		if (row.phase != context_phase::READY || image_frontier_[row.module_image_index] != ordinal ||
		    executor_frontier_[row.executor_index] != ordinal || image_busy_[row.module_image_index] != 0u ||
		    executor_busy_[row.executor_index] != 0u) {
			std::terminate();
		}
		if (!row.control.has_value() || !row.claim.has_value() || row.task_sequence != 0u ||
		    !row.control->bind_deadline_before_publication_(retirement_deadline_)) {
			return status::internal_error(kinetum::common::static_status_text(
				"claimed RETIRE row lost exact preallocated control or claim"));
		}
		const uint64_t task_sequence = modules_->next_completion_task_sequence();
		auto submitted = modules_->submit_completion_retire(
			epoch_transition_retire_submission{.task_sequence = task_sequence,
							   .context_ordinal = static_cast<uint32_t>(ordinal),
							   .padding = 0u},
			*row.control, *row.claim);
		if (!submitted.is_ok()) {
			return submitted;
		}
		ready_ordinals_[ready_index] = INVALID_CONTEXT_ORDINAL;
		--ready_count_;
		row.task_sequence = task_sequence;
		row.phase = context_phase::IN_FLIGHT;
		image_busy_[row.module_image_index] = 1u;
		executor_busy_[row.executor_index] = 1u;
		if (in_flight_count_ >= context_count_) {
			std::terminate();
		}
		++in_flight_count_;
	}
	return status::ok();
}

void epoch_transition_completion::enqueue_if_ready_(std::size_t ordinal) noexcept
{
	if (ordinal == INVALID_CONTEXT_ORDINAL) {
		return;
	}
	if (ordinal >= context_count_) {
		std::terminate();
	}
	auto &row = contexts_[ordinal];
	if (row.phase != context_phase::CLAIMED || image_frontier_[row.module_image_index] != ordinal ||
	    executor_frontier_[row.executor_index] != ordinal) {
		return;
	}
	if (ready_count_ >= ready_ordinals_.size() || ready_ordinals_[ready_count_] != INVALID_CONTEXT_ORDINAL) {
		std::terminate();
	}
	ready_ordinals_[ready_count_++] = ordinal;
	row.phase = context_phase::READY;
}

status epoch_transition_completion::consume_result_(config_lifecycle_result &&result,
						    std::chrono::steady_clock::time_point now) noexcept
{
	const std::size_t match_ordinal = static_cast<std::size_t>(result.context_index());
	context_operation *match = match_ordinal < context_count_ ? &contexts_[match_ordinal] : nullptr;
	if (match == nullptr || match->context_index != result.context_index() ||
	    match->phase != context_phase::IN_FLIGHT || !match->claim.has_value() || match->task_sequence == 0u ||
	    result.task_sequence() != match->task_sequence ||
	    result.module_image_index() != match->module_image_index ||
	    result.epoch() != coordinator_->active_epoch() ||
	    result.operation() != config_lifecycle_operation::RETIRE ||
	    result.retirement_claim_id() != match->claim->claim_id() || image_busy_[match->module_image_index] != 1u ||
	    executor_busy_[match->executor_index] != 1u ||
	    image_frontier_[match->module_image_index] != match_ordinal ||
	    executor_frontier_[match->executor_index] != match_ordinal || in_flight_count_ == 0u) {
		return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
				  kinetum::common::static_status_text(
					  "claimed RETIRE result did not echo exact operation identity"),
				  now);
	}
	if (result.code() != config_lifecycle_result_code::SUCCESS || result.has_prepared_ownership()) {
		const auto failure_code = result.code() == config_lifecycle_result_code::DEADLINE_EXCEEDED ?
						  epoch_transition_failure_code::RETIRE_CALLBACK_DEADLINE_EXCEEDED :
						  epoch_transition_failure_code::RETIRE_CALLBACK_FAILURE;
		return fail_stop_(failure_code,
				  kinetum::common::static_status_text(
					  "claimed module RETIRE callback did not return exact SUCCESS"),
				  now);
	}
	image_busy_[match->module_image_index] = 0u;
	executor_busy_[match->executor_index] = 0u;
	--in_flight_count_;
	match->task_sequence = 0u;
	modules_->complete_completion_retirement(match_ordinal, *match->claim);
	match->claim.reset();
	match->phase = context_phase::RETIRED;
	if (retired_count_ >= context_count_) {
		std::terminate();
	}
	++retired_count_;
	const std::size_t image_candidate = match->previous_image_ordinal;
	const std::size_t executor_candidate = match->previous_executor_ordinal;
	image_frontier_[match->module_image_index] = image_candidate;
	executor_frontier_[match->executor_index] = executor_candidate;
	if (image_candidate < executor_candidate) {
		enqueue_if_ready_(image_candidate);
		enqueue_if_ready_(executor_candidate);
	} else {
		enqueue_if_ready_(executor_candidate);
		enqueue_if_ready_(image_candidate);
	}
	return status::ok();
}

status epoch_transition_completion::begin_reclamation_(std::chrono::steady_clock::time_point now) noexcept
{
	if (!active() || ownership_withdrawn_ || coordinator_->phase() != epoch_transition_phase::RETIRING ||
	    coordinator_->retirement_frozen() || retirement_deadline_ == std::chrono::steady_clock::time_point{} ||
	    now >= retirement_deadline_) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"reclamation begin lacks exact unfrozen reader-ready ownership"));
	}
	if (protocol_faults_ == nullptr) {
		std::terminate();
	}
	if (protocol_faults_->transition_success_blocked()) {
		const auto observed_at = std::max(now, std::chrono::steady_clock::now());
		return fail_stop_(
			epoch_transition_failure_code::PROTOCOL_FAULT,
			kinetum::common::static_status_text("protocol safety fault blocked ownership withdrawal"),
			observed_at);
	}
	if (!domain_->grace_period_complete(grace_generation_)) {
		const uint64_t observed_ns = monotonic_nanoseconds_(now);
		coordinator_->record_protocol_fault_(epoch_protocol_first_fault{
			.runtime_generation = runtime_generation_,
			.transition_generation = identity_.mutation_sequence,
			.from_epoch = coordinator_->active_epoch(),
			.to_epoch = identity_.target_epoch,
			.observed_epoch = coordinator_->active_epoch(),
			.expected_value = certificate_->reader_count(),
			.observed_value = last_progress_.reader_complete,
			.observed_monotonic_ns = observed_ns,
			.worker_index = UINT32_MAX,
			.boundary_index = UINT32_MAX,
			.context_index = UINT32_MAX,
			.stage_instance_index = UINT32_MAX,
			.code = epoch_protocol_fault_code::RETIREMENT_BEFORE_QUIESCENCE,
			.disposition = epoch_protocol_fault_disposition::TERMINATE,
			.padding = {},
		});
		return fail_stop_(
			epoch_transition_failure_code::PROTOCOL_FAULT,
			kinetum::common::static_status_text("reclamation was attempted before exact reader quiescence"),
			now);
	}
	const bool local_rows_ready =
		ready_count_ == 0u && in_flight_count_ == 0u && retired_count_ == 0u &&
		std::all_of(ready_ordinals_.begin(), ready_ordinals_.end(),
			    [](std::size_t ordinal) { return ordinal == INVALID_CONTEXT_ORDINAL; }) &&
		std::all_of(image_busy_.begin(), image_busy_.end(), [](uint8_t value) { return value == 0u; }) &&
		std::all_of(executor_busy_.begin(), executor_busy_.end(), [](uint8_t value) { return value == 0u; }) &&
		std::all_of(image_frontier_.begin(), image_frontier_.end(),
			    [](std::size_t ordinal) { return ordinal == INVALID_CONTEXT_ORDINAL; }) &&
		std::all_of(executor_frontier_.begin(), executor_frontier_.end(),
			    [](std::size_t ordinal) { return ordinal == INVALID_CONTEXT_ORDINAL; });
	if (!local_rows_ready) {
		return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
				  kinetum::common::static_status_text(
					  "reclamation preflight found retained local scheduling state"),
				  now);
	}
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		const auto &row = contexts_[ordinal];
		if (row.phase != context_phase::ARMED || row.task_sequence != 0u || !row.control.has_value() ||
		    row.control->deadline_bound() || row.claim.has_value()) {
			return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
					  kinetum::common::static_status_text(
						  "reclamation preflight found an inexact preallocated context row"),
					  now);
		}
	}
	auto snapshot_preflight = coordinator_->preflight_retained_snapshot(identity_);
	if (!snapshot_preflight.is_ok()) {
		return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
				  std::move(snapshot_preflight), now);
	}
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		auto preflight = modules_->preflight_completion_retained(ordinal, coordinator_->active_epoch());
		if (!preflight.is_ok()) {
			return fail_stop_(epoch_transition_failure_code::CERTIFICATE_CONTRADICTION,
					  std::move(preflight), now);
		}
	}
	for (std::size_t ordinal = context_count_; ordinal != 0u; --ordinal) {
		auto claim_or = modules_->claim_completion_retained(ordinal - 1u, coordinator_->active_epoch());
		if (!claim_or.is_ok()) {
			std::terminate();
		}
		contexts_[ordinal - 1u].claim.emplace(std::move(claim_or).value());
		contexts_[ordinal - 1u].phase = context_phase::CLAIMED;
	}
	std::fill(image_frontier_.begin(), image_frontier_.end(), INVALID_CONTEXT_ORDINAL);
	std::fill(executor_frontier_.begin(), executor_frontier_.end(), INVALID_CONTEXT_ORDINAL);
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		const auto &row = contexts_[ordinal];
		image_frontier_[row.module_image_index] = ordinal;
		executor_frontier_[row.executor_index] = ordinal;
	}
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		enqueue_if_ready_(ordinal);
	}
	if (context_count_ != 0u && ready_count_ == 0u) {
		std::terminate();
	}
	ownership_withdrawn_ = true;
	last_progress_.ownership_withdrawn = true;
	publish_progress_or_terminate_();
	if (context_count_ == 0u) {
		return publish_complete_or_fail_stop_(now);
	}
	auto dispatched = dispatch_eligible_();
	if (!dispatched.is_ok()) {
		return fail_stop_(epoch_transition_failure_code::RETIRE_CALLBACK_FAILURE, std::move(dispatched), now);
	}
	return status::ok();
}

status epoch_transition_completion::publish_complete_or_fail_stop_(std::chrono::steady_clock::time_point now) noexcept
{
	if (!active() || !ownership_withdrawn_ || !all_contexts_retired_() ||
	    !modules_->completion_retirement_complete(identity_.target_epoch) ||
	    !coordinator_->preflight_retained_snapshot(identity_).is_ok()) {
		std::terminate();
	}
	if (protocol_faults_ == nullptr) {
		std::terminate();
	}
	// This acquire load is the terminal-success linearization point. A fault
	// observed before it cannot race through old-object retirement into
	// COMPLETE; a later fault remains sticky for the next admission.
	if (protocol_faults_->transition_success_blocked()) {
		const auto observed_at = std::max(now, std::chrono::steady_clock::now());
		return fail_stop_(epoch_transition_failure_code::PROTOCOL_FAULT,
				  kinetum::common::static_status_text(
					  "protocol safety fault blocked final transition publication"),
				  observed_at);
	}
	const uint64_t from_epoch = coordinator_->active_epoch();
	telemetry_->complete_module_epoch_retirement(from_epoch, identity_.target_epoch);
	telemetry_->retire_worker_epoch(from_epoch, identity_.target_epoch);
	coordinator_->retire_retained_snapshot_or_terminate(identity_);
	if (!domain_->finish_grace_period(grace_generation_) ||
	    !runtime_status_->publish_transition_complete(identity_.target_epoch)) {
		std::terminate();
	}
	const uint64_t terminal_ns = monotonic_nanoseconds_(now);
	if (terminal_ns == 0u ||
	    (last_progress_.evaluated_monotonic_ns != 0u && terminal_ns < last_progress_.evaluated_monotonic_ns)) {
		std::terminate();
	}
	last_progress_.grace_finished_monotonic_ns = terminal_ns;
	last_progress_.transaction_active = false;
	publish_progress_or_terminate_();
	coordinator_->complete_retirement_or_terminate(identity_, terminal_ns);
	reset_clean_();
	return status::ok();
}

status epoch_transition_completion::fail_stop_(epoch_transition_failure_code failure_code,
					       common::static_status_text diagnostic,
					       std::chrono::steady_clock::time_point now) noexcept
{
	return fail_stop_(failure_code, status(status_code::INTERNAL_ERROR, diagnostic), now);
}

status epoch_transition_completion::fail_stop_(epoch_transition_failure_code failure_code, status failure,
					       std::chrono::steady_clock::time_point now) noexcept
{
	if (!active() || failed_stop_ || failure_code == epoch_transition_failure_code::NONE ||
	    failure_code == epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED || failure.is_ok() ||
	    !failure.details().empty()) {
		std::terminate();
	}
	const uint64_t failure_ns = monotonic_nanoseconds_(now);
	coordinator_->fail_active_or_terminate(identity_, failure_ns, failure_code, failure.message());
	failed_stop_ = true;
	last_progress_.transaction_active = true;
	publish_progress_or_terminate_();
	commit_deadline_ = {};
	retirement_deadline_ = {};
	latest_retirement_deadline_ = {};
	next_probe_ = {};
	const bool deadline = failure_code == epoch_transition_failure_code::COMMIT_DEADLINE_EXCEEDED ||
			      failure_code == epoch_transition_failure_code::RETIRE_CALLBACK_DEADLINE_EXCEEDED;
	return std::move(failure).reclassified(deadline ? status_code::DEADLINE_EXCEEDED : status_code::INTERNAL_ERROR);
}

bool epoch_transition_completion::all_contexts_retired_() const noexcept
{
	if (retired_count_ != context_count_) {
		return false;
	}
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		const auto &row = contexts_[ordinal];
		if (row.phase != context_phase::RETIRED || row.task_sequence != 0u || row.claim.has_value()) {
			return false;
		}
	}
	return ready_count_ == 0u && in_flight_count_ == 0u &&
	       std::all_of(image_busy_.begin(), image_busy_.end(), [](uint8_t value) { return value == 0u; }) &&
	       std::all_of(executor_busy_.begin(), executor_busy_.end(), [](uint8_t value) { return value == 0u; }) &&
	       std::all_of(ready_ordinals_.begin(), ready_ordinals_.end(),
			   [](std::size_t ordinal) { return ordinal == INVALID_CONTEXT_ORDINAL; }) &&
	       std::all_of(image_frontier_.begin(), image_frontier_.end(),
			   [](std::size_t ordinal) { return ordinal == INVALID_CONTEXT_ORDINAL; }) &&
	       std::all_of(executor_frontier_.begin(), executor_frontier_.end(),
			   [](std::size_t ordinal) { return ordinal == INVALID_CONTEXT_ORDINAL; });
}

bool epoch_transition_completion::module_membership_exact_() const noexcept
{
	if (modules_->completion_context_count() != context_count_ ||
	    modules_->completion_image_count() != image_busy_.size() ||
	    modules_->completion_executor_count() != executor_busy_.size() ||
	    image_frontier_.size() != image_busy_.size() || executor_frontier_.size() != executor_busy_.size() ||
	    ready_ordinals_.size() != context_count_) {
		return false;
	}
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		const auto &row = contexts_[ordinal];
		if (modules_->completion_context_index(ordinal) != row.context_index ||
		    modules_->completion_image_index(ordinal) != row.module_image_index ||
		    modules_->completion_executor_index(ordinal) != row.executor_index) {
			return false;
		}
	}
	return true;
}

void epoch_transition_completion::reset_clean_() noexcept
{
	if (failed_stop_ || (grace_generation_ != 0u && domain_->active_generation() != 0u)) {
		std::terminate();
	}
	for (std::size_t ordinal = 0u; ordinal < context_count_; ++ordinal) {
		auto &row = contexts_[ordinal];
		if ((row.phase != context_phase::ARMED && row.phase != context_phase::RETIRED) ||
		    row.task_sequence != 0u || row.claim.has_value()) {
			std::terminate();
		}
		row.control.reset();
		row.phase = context_phase::IDLE;
	}
	std::fill(image_busy_.begin(), image_busy_.end(), uint8_t{0});
	std::fill(executor_busy_.begin(), executor_busy_.end(), uint8_t{0});
	std::fill(image_frontier_.begin(), image_frontier_.end(), INVALID_CONTEXT_ORDINAL);
	std::fill(executor_frontier_.begin(), executor_frontier_.end(), INVALID_CONTEXT_ORDINAL);
	std::fill(ready_ordinals_.begin(), ready_ordinals_.end(), INVALID_CONTEXT_ORDINAL);
	ready_count_ = 0u;
	in_flight_count_ = 0u;
	retired_count_ = 0u;
	identity_ = {};
	grace_generation_ = 0u;
	commit_deadline_ = {};
	retirement_deadline_ = {};
	latest_retirement_deadline_ = {};
	next_probe_ = {};
	ownership_withdrawn_ = false;
}

uint64_t epoch_transition_completion::monotonic_nanoseconds_(std::chrono::steady_clock::time_point now) noexcept
{
	const auto count = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
	return count > 0 ? static_cast<uint64_t>(count) : 0u;
}

void epoch_transition_completion::schedule_next_probe_(std::chrono::steady_clock::time_point now) noexcept
{
	const auto behavior_deadline =
		coordinator_->phase() == epoch_transition_phase::COMMITTING ? commit_deadline_ :
		coordinator_->phase() == epoch_transition_phase::RETIRING   ? retirement_deadline_ :
									      std::chrono::steady_clock::time_point{};
	if (behavior_deadline == std::chrono::steady_clock::time_point{}) {
		next_probe_ = {};
		return;
	}
	if (now > std::chrono::steady_clock::time_point::max() - OBSERVATION_INTERVAL) {
		next_probe_ = behavior_deadline;
		return;
	}
	next_probe_ = std::min(now + OBSERVATION_INTERVAL, behavior_deadline);
}

void epoch_transition_completion::publish_progress_or_terminate_() noexcept
{
	if (last_progress_.runtime_generation != runtime_generation_ ||
	    !common::valid_mutation_sequence(last_progress_.transition_generation) ||
	    !common::valid_epoch_id(last_progress_.from_epoch) || !common::valid_epoch_id(last_progress_.to_epoch) ||
	    last_progress_.to_epoch <= last_progress_.from_epoch ||
	    last_progress_.execution_complete > last_progress_.execution_total ||
	    last_progress_.boundary_complete > last_progress_.boundary_total ||
	    last_progress_.reader_complete > last_progress_.reader_total ||
	    last_progress_.execution_total != certificate_->execution_participant_count() ||
	    last_progress_.boundary_total != certificate_->boundary_count() ||
	    last_progress_.reader_total != certificate_->reader_count()) {
		std::terminate();
	}
	const std::array<uint64_t, PROGRESS_FIELD_COUNT> fields{
		last_progress_.runtime_generation,
		last_progress_.transition_generation,
		last_progress_.from_epoch,
		last_progress_.to_epoch,
		last_progress_.evaluated_monotonic_ns,
		last_progress_.grace_generation,
		last_progress_.grace_started_monotonic_ns,
		last_progress_.grace_completion_observed_monotonic_ns,
		last_progress_.grace_finished_monotonic_ns,
		last_progress_.execution_complete,
		last_progress_.execution_total,
		last_progress_.boundary_complete,
		last_progress_.boundary_total,
		last_progress_.reader_complete,
		last_progress_.reader_total,
		last_progress_.fault_index,
		static_cast<uint64_t>(last_progress_.certificate_state),
		static_cast<uint64_t>(last_progress_.certificate_fault),
		last_progress_.transaction_active ? 1u : 0u,
		last_progress_.ownership_withdrawn ? 1u : 0u,
		last_progress_.update_frozen ? 1u : 0u,
	};
	if (!progress_.publish(fields)) {
		std::terminate();
	}
}

}  // namespace kinetum::dp
