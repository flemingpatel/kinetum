// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_transition_preparation.cpp
 * @brief Exact asynchronous module PREPARE and abort cleanup orchestration.
 * @author Fleming Patel
 */

#include "src/dp/epoch/epoch_transition_preparation.hpp"

#include <algorithm>
#include <charconv>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include "gen/kinetum/control/v1/control.pb.h"
#include "src/dp/module/module_runtime_generation.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;
using kinetum::dp::lifecycle::config_lifecycle_operation;
using kinetum::dp::lifecycle::config_lifecycle_result;
using kinetum::dp::lifecycle::config_lifecycle_result_code;

status_or<std::chrono::steady_clock::time_point>
checked_transition_deadline(std::chrono::steady_clock::time_point base,
			    std::chrono::steady_clock::duration duration) noexcept
{
	if (duration <= std::chrono::steady_clock::duration::zero() ||
	    base > std::chrono::steady_clock::time_point::max() - duration) {
		return status(
			status_code::OUT_OF_RANGE,
			kinetum::common::static_status_text("compiled lifecycle deadline exceeds steady-clock range"));
	}
	return base + duration;
}

namespace
{

static_assert(common::MAX_TRANSITION_DIAGNOSTIC_BYTES <= std::numeric_limits<uint16_t>::max(),
	      "transition preparation diagnostics must fit their fixed length field");

/**
 * @brief Map one executor PREPARE result to its stable terminal cause.
 * @param code Exact non-success executor result code.
 * @return Stable coordinator failure classification.
 */
[[nodiscard]] constexpr epoch_transition_failure_code
failure_code_for_result(config_lifecycle_result_code code) noexcept
{
	switch (code) {
	case config_lifecycle_result_code::CANCELLED:
		return epoch_transition_failure_code::PREPARE_CANCELLED;
	case config_lifecycle_result_code::DEADLINE_EXCEEDED:
		return epoch_transition_failure_code::PREPARE_DEADLINE_EXCEEDED;
	case config_lifecycle_result_code::CALLBACK_FAILURE:
	case config_lifecycle_result_code::CONTEXT_REJECTED:
		return epoch_transition_failure_code::PREPARE_FAILURE;
	case config_lifecycle_result_code::SUCCESS:
		return epoch_transition_failure_code::NONE;
	}
	return epoch_transition_failure_code::PREPARE_FAILURE;
}

/**
 * @brief Build one cold bounded-source diagnostic from an executor result.
 * @param result Exact identity-validated non-success result.
 * @return Human-readable source diagnostic later bounded into the journal.
 */
[[nodiscard]] epoch_transition_diagnostic result_diagnostic(const config_lifecycle_result &result) noexcept
{
	epoch_transition_diagnostic diagnostic;
	std::string_view prefix;
	switch (result.code()) {
	case config_lifecycle_result_code::CANCELLED:
		prefix = "module PREPARE callback returned cooperative cancellation; code=";
		break;
	case config_lifecycle_result_code::DEADLINE_EXCEEDED:
		prefix = "module PREPARE was not dispatched before its compiled deadline; code=";
		break;
	case config_lifecycle_result_code::CALLBACK_FAILURE:
		prefix = "module PREPARE callback failed; code=";
		break;
	case config_lifecycle_result_code::CONTEXT_REJECTED:
		prefix = "module PREPARE context admission failed; code=";
		break;
	case config_lifecycle_result_code::SUCCESS:
		prefix = "successful module PREPARE was interpreted as failure; code=";
		break;
	}
	const std::size_t prefix_size = std::min(prefix.size(), diagnostic.bytes.size());
	std::copy_n(prefix.begin(), prefix_size, diagnostic.bytes.data());
	auto *first = diagnostic.bytes.data() + prefix_size;
	auto *last = diagnostic.bytes.data() + diagnostic.bytes.size();
	const auto converted = std::to_chars(first, last, result.diagnostic_code());
	std::size_t diagnostic_size = prefix_size;
	if (converted.ec == std::errc{}) {
		const auto converted_size = converted.ptr - diagnostic.bytes.data();
		if (converted_size < 0 || static_cast<std::size_t>(converted_size) > diagnostic.bytes.size()) {
			std::terminate();
		}
		diagnostic_size = static_cast<std::size_t>(converted_size);
	}
	diagnostic.size = static_cast<uint16_t>(diagnostic_size);
	return diagnostic;
}

}  // namespace

status_or<std::unique_ptr<epoch_transition_preparation>>
epoch_transition_preparation::create(module::module_runtime_generation &modules,
				     const common::compiled_epoch_transition_policy &policy)
{
	if (!policy.enabled || policy.prepare_timeout <= std::chrono::steady_clock::duration::zero() ||
	    policy.prepare_cancel_grace <= std::chrono::steady_clock::duration::zero() ||
	    policy.prepare_cancel_grace > policy.prepare_timeout) {
		return status::invalid_argument(
			"transition preparation requires enabled positive compiled timeout and cancellation grace");
	}
	try {
		return std::unique_ptr<epoch_transition_preparation>(
			new epoch_transition_preparation(modules, policy.prepare_timeout, policy.prepare_cancel_grace));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate epoch transition preparation owner");
	}
}

epoch_transition_preparation::epoch_transition_preparation(
	module::module_runtime_generation &modules, std::chrono::steady_clock::duration prepare_timeout,
	std::chrono::steady_clock::duration cancellation_grace) noexcept
	: modules_(&modules)
	, prepare_timeout_(prepare_timeout)
	, cancellation_grace_(cancellation_grace)
{
}

epoch_transition_preparation::~epoch_transition_preparation()
{
	if (phase_ != epoch_transition_preparation_phase::IDLE || !contexts_.empty() || snapshot_ != nullptr ||
	    failure_code_ != epoch_transition_failure_code::NONE || diagnostic_.size != 0u ||
	    module_prepared_published_ || prepare_deadline_ != std::chrono::steady_clock::time_point{} ||
	    cancellation_deadline_ != std::chrono::steady_clock::time_point{} ||
	    retire_deadline_ != std::chrono::steady_clock::time_point{} ||
	    prepared_lease_deadline_ != std::chrono::steady_clock::time_point{}) {
		std::terminate();
	}
}

status epoch_transition_preparation::begin(const common::epoch_transition_identity &identity,
					   const kinetum::control::v1::ConfigSnapshot &snapshot,
					   std::chrono::steady_clock::time_point admitted_at)
{
	if (phase_ != epoch_transition_preparation_phase::IDLE || !identity.valid() ||
	    admitted_at == std::chrono::steady_clock::time_point{}) {
		return status::failed_precondition("epoch preparation begin lacks one exact idle transaction");
	}
	auto deadline_or = checked_transition_deadline(admitted_at, prepare_timeout_);
	if (!deadline_or.is_ok()) {
		return deadline_or.error();
	}
	auto snapshot_status = modules_->validate_transition_snapshot_(snapshot);
	if (!snapshot_status.is_ok()) {
		return snapshot_status;
	}

	const std::size_t context_count = modules_->transition_context_count_();
	const std::size_t image_count = modules_->transition_image_count_();
	const std::size_t executor_count = modules_->transition_executor_count_();
	if ((context_count == 0u) != (image_count == 0u) || executor_count == 0u) {
		return status::failed_precondition(
			"module transition preparation has incomplete context/image/executor membership");
	}

	try {
		contexts_.clear();
		contexts_.reserve(context_count);
		image_busy_.assign(image_count, uint8_t{0});
		executor_busy_.assign(executor_count, uint8_t{0});
		for (std::size_t ordinal = 0; ordinal < context_count; ++ordinal) {
			const uint32_t image_index = modules_->transition_context_image_index_(ordinal);
			const std::size_t executor_index = modules_->transition_context_executor_index_(ordinal);
			if (image_index >= image_count || executor_index >= executor_count) {
				contexts_.clear();
				image_busy_.clear();
				executor_busy_.clear();
				return status::failed_precondition(
					"module transition context has no exact image/executor ownership");
			}
			auto arena_or = modules_->allocate_transition_arena_(ordinal, identity.target_epoch);
			if (!arena_or.is_ok()) {
				contexts_.clear();
				image_busy_.clear();
				executor_busy_.clear();
				return arena_or.error();
			}
			context_operation operation;
			operation.module_image_index = image_index;
			operation.executor_index = executor_index;
			operation.phase = context_phase::WAITING_PREPARE;
			operation.prepare_control =
				std::make_unique<lifecycle::lifecycle_operation_control>(deadline_or.value());
			operation.retire_control = std::make_unique<lifecycle::lifecycle_operation_control>(
				std::chrono::steady_clock::time_point{});
			operation.arena.emplace(std::move(arena_or).value());
			contexts_.push_back(std::move(operation));
		}
	} catch (const std::bad_alloc &) {
		contexts_.clear();
		image_busy_.clear();
		executor_busy_.clear();
		return status::resource_exhausted("failed to preallocate complete epoch preparation operation state");
	} catch (const std::length_error &) {
		contexts_.clear();
		image_busy_.clear();
		executor_busy_.clear();
		return status(status_code::OUT_OF_RANGE,
			      "epoch preparation operation table exceeds host container bounds");
	}

	identity_ = identity;
	snapshot_ = &snapshot;
	prepare_deadline_ = deadline_or.value();
	cancellation_deadline_ = {};
	retire_deadline_ = {};
	prepared_lease_deadline_ = {};
	failure_code_ = epoch_transition_failure_code::NONE;
	diagnostic_ = {};
	module_prepared_published_ = false;
	phase_ = epoch_transition_preparation_phase::PREPARING;

	if (contexts_.empty()) {
		const auto staged = stage_complete_prepare_();
		if (!staged.is_ok()) {
			const auto failed_at = std::chrono::steady_clock::now();
			begin_cancellation_(epoch_transition_failure_code::PREPARE_FAILURE, staged.message(),
					    failed_at);
			const auto retired = begin_retirement_();
			if (!retired.is_ok()) {
				enter_failed_stop_();
			}
		}
		return status::ok();
	}

	const auto dispatched = dispatch_eligible_prepare_();
	if (!dispatched.is_ok()) {
		const auto failed_at = std::chrono::steady_clock::now();
		begin_cancellation_(epoch_transition_failure_code::PREPARE_FAILURE, dispatched.message(), failed_at);
		if (!prepare_in_flight_()) {
			const auto retired = begin_retirement_();
			if (!retired.is_ok()) {
				enter_failed_stop_();
			}
		}
	}
	return status::ok();
}

status epoch_transition_preparation::service_results() noexcept
{
	if (!active() || phase_ == epoch_transition_preparation_phase::FAILED_STOP ||
	    phase_ == epoch_transition_preparation_phase::ABORTED ||
	    phase_ == epoch_transition_preparation_phase::PREPARED) {
		return status::ok();
	}
	for (;;) {
		auto result = modules_->try_take_transition_result_();
		if (!result.has_value()) {
			break;
		}
		auto consumed = consume_result_(std::move(*result));
		if (!consumed.is_ok()) {
			return consumed;
		}
		if (phase_ == epoch_transition_preparation_phase::FAILED_STOP) {
			return status::ok();
		}
	}

	if (phase_ == epoch_transition_preparation_phase::PREPARING) {
		const auto dispatched = dispatch_eligible_prepare_();
		if (!dispatched.is_ok()) {
			begin_cancellation_(epoch_transition_failure_code::PREPARE_FAILURE, dispatched.message(),
					    std::chrono::steady_clock::now());
		}
		if (phase_ == epoch_transition_preparation_phase::PREPARING && all_prepare_succeeded_()) {
			const auto staged = stage_complete_prepare_();
			if (!staged.is_ok()) {
				begin_cancellation_(epoch_transition_failure_code::PREPARE_FAILURE, staged.message(),
						    std::chrono::steady_clock::now());
			}
		}
	}
	if (phase_ == epoch_transition_preparation_phase::CANCELLING && !prepare_in_flight_()) {
		auto retiring = begin_retirement_();
		if (!retiring.is_ok()) {
			enter_failed_stop_();
			return retiring;
		}
	}
	if (phase_ == epoch_transition_preparation_phase::RETIRING) {
		auto retiring = dispatch_next_retire_();
		if (!retiring.is_ok()) {
			enter_failed_stop_();
			return retiring;
		}
	}
	return status::ok();
}

status epoch_transition_preparation::service_deadline(std::chrono::steady_clock::time_point now) noexcept
{
	if (phase_ == epoch_transition_preparation_phase::PREPARING && now >= prepare_deadline_) {
		return request_abort(epoch_transition_failure_code::PREPARE_DEADLINE_EXCEEDED,
				     "compiled module preparation deadline expired", now);
	}
	if (phase_ == epoch_transition_preparation_phase::CANCELLING && prepare_in_flight_() &&
	    now >= cancellation_deadline_) {
		enter_failed_stop_();
		return status::deadline_exceeded(kinetum::common::static_status_text(
			"module PREPARE callback did not return within compiled cancellation grace"));
	}
	if (phase_ == epoch_transition_preparation_phase::RETIRING &&
	    retire_deadline_ != std::chrono::steady_clock::time_point{} && now >= retire_deadline_) {
		enter_failed_stop_();
		return status::deadline_exceeded(kinetum::common::static_status_text(
			"module RETIRE callback did not return within compiled cancellation grace"));
	}
	if (phase_ == epoch_transition_preparation_phase::PREPARED &&
	    prepared_lease_deadline_ != std::chrono::steady_clock::time_point{} && now >= prepared_lease_deadline_) {
		return request_abort(epoch_transition_failure_code::PREPARED_LEASE_EXPIRED,
				     "prepared transaction lease expired before commit", now);
	}
	return status::ok();
}

status epoch_transition_preparation::request_abort(epoch_transition_failure_code failure_code,
						   std::string_view diagnostic,
						   std::chrono::steady_clock::time_point now) noexcept
{
	if (!is_precommit_failure(failure_code) || now == std::chrono::steady_clock::time_point{}) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"epoch preparation abort requires an exact cause and clock sample"));
	}
	if (phase_ == epoch_transition_preparation_phase::CANCELLING ||
	    phase_ == epoch_transition_preparation_phase::RETIRING) {
		return status::ok();
	}
	if (phase_ != epoch_transition_preparation_phase::PREPARING &&
	    phase_ != epoch_transition_preparation_phase::PREPARED) {
		return status::failed_precondition(
			kinetum::common::static_status_text("epoch preparation is not pre-commit abortable"));
	}
	begin_cancellation_(failure_code, diagnostic, now);
	if (!prepare_in_flight_()) {
		auto retiring = begin_retirement_();
		if (!retiring.is_ok()) {
			enter_failed_stop_();
			return retiring;
		}
	}
	return status::ok();
}

void epoch_transition_preparation::arm_prepared_lease(std::chrono::steady_clock::time_point deadline) noexcept
{
	if (phase_ != epoch_transition_preparation_phase::PREPARED ||
	    deadline == std::chrono::steady_clock::time_point{} ||
	    prepared_lease_deadline_ != std::chrono::steady_clock::time_point{}) {
		std::terminate();
	}
	prepared_lease_deadline_ = deadline;
	prepare_deadline_ = {};
}

void epoch_transition_preparation::release_completion_preparation(
	const common::epoch_transition_identity &identity) noexcept
{
	const bool rows_staged = std::all_of(contexts_.begin(), contexts_.end(), [](const auto &operation) {
		return operation.phase == context_phase::STAGED && operation.task_sequence == 0u &&
		       !operation.arena.has_value() && !operation.prepared.has_value();
	});
	if (phase_ != epoch_transition_preparation_phase::PREPARED || identity_ != identity ||
	    !module_prepared_published_ || !rows_staged ||
	    std::any_of(image_busy_.begin(), image_busy_.end(), [](uint8_t busy) { return busy != 0u; }) ||
	    std::any_of(executor_busy_.begin(), executor_busy_.end(), [](uint8_t busy) { return busy != 0u; }) ||
	    prepared_lease_deadline_ == std::chrono::steady_clock::time_point{}) {
		std::terminate();
	}
	contexts_.clear();
	image_busy_.clear();
	executor_busy_.clear();
	identity_ = {};
	snapshot_ = nullptr;
	prepare_deadline_ = {};
	cancellation_deadline_ = {};
	retire_deadline_ = {};
	prepared_lease_deadline_ = {};
	failure_code_ = epoch_transition_failure_code::NONE;
	diagnostic_ = {};
	module_prepared_published_ = false;
	phase_ = epoch_transition_preparation_phase::IDLE;
}

bool epoch_transition_preparation::completion_prepared(const common::epoch_transition_identity &identity) const noexcept
{
	return phase_ == epoch_transition_preparation_phase::PREPARED && identity_ == identity &&
	       module_prepared_published_;
}

void epoch_transition_preparation::reset_after_abort() noexcept
{
	if (phase_ != epoch_transition_preparation_phase::ABORTED || !all_contexts_clean_() ||
	    module_prepared_published_) {
		std::terminate();
	}
	contexts_.clear();
	image_busy_.clear();
	executor_busy_.clear();
	identity_ = {};
	snapshot_ = nullptr;
	prepare_deadline_ = {};
	cancellation_deadline_ = {};
	retire_deadline_ = {};
	prepared_lease_deadline_ = {};
	failure_code_ = epoch_transition_failure_code::NONE;
	diagnostic_ = {};
	phase_ = epoch_transition_preparation_phase::IDLE;
}

epoch_transition_preparation_phase epoch_transition_preparation::phase() const noexcept
{
	return phase_;
}

bool epoch_transition_preparation::active() const noexcept
{
	return phase_ != epoch_transition_preparation_phase::IDLE;
}

const common::epoch_transition_identity *epoch_transition_preparation::identity() const noexcept
{
	return active() ? &identity_ : nullptr;
}

epoch_transition_failure_code epoch_transition_preparation::failure_code() const noexcept
{
	return failure_code_;
}

std::string_view epoch_transition_preparation::diagnostic() const noexcept
{
	return std::string_view(diagnostic_.bytes.data(), diagnostic_.size);
}

std::optional<std::chrono::steady_clock::time_point> epoch_transition_preparation::next_deadline() const noexcept
{
	switch (phase_) {
	case epoch_transition_preparation_phase::PREPARING:
		return prepare_deadline_;
	case epoch_transition_preparation_phase::CANCELLING:
		return prepare_in_flight_() ? std::optional(cancellation_deadline_) : std::nullopt;
	case epoch_transition_preparation_phase::PREPARED:
		return prepared_lease_deadline_ == std::chrono::steady_clock::time_point{} ?
			       std::optional(prepare_deadline_) :
			       std::optional(prepared_lease_deadline_);
	case epoch_transition_preparation_phase::RETIRING:
		return retire_deadline_ == std::chrono::steady_clock::time_point{} ? std::nullopt :
										     std::optional(retire_deadline_);
	case epoch_transition_preparation_phase::IDLE:
	case epoch_transition_preparation_phase::ABORTED:
	case epoch_transition_preparation_phase::FAILED_STOP:
		return std::nullopt;
	}
	return std::nullopt;
}

status epoch_transition_preparation::dispatch_eligible_prepare_() noexcept
{
	if (phase_ != epoch_transition_preparation_phase::PREPARING || snapshot_ == nullptr) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module PREPARE dispatch lacks exact active candidate"));
	}
	for (std::size_t ordinal = 0; ordinal < contexts_.size(); ++ordinal) {
		auto &operation = contexts_[ordinal];
		if (operation.phase != context_phase::WAITING_PREPARE) {
			continue;
		}
		if (image_busy_[operation.module_image_index] != 0u || executor_busy_[operation.executor_index] != 0u) {
			continue;
		}
		if (!operation.arena.has_value() || !operation.prepare_control || !operation.retire_control) {
			return status::internal_error(kinetum::common::static_status_text(
				"module PREPARE operation table lost preallocated ownership"));
		}
		const uint64_t task_sequence = modules_->next_transition_task_sequence_();
		auto arena = std::move(*operation.arena);
		operation.arena.reset();
		auto submitted = modules_->submit_transition_prepare_(ordinal, task_sequence, identity_.target_epoch,
								      *snapshot_, *operation.prepare_control,
								      std::move(arena));
		if (!submitted.is_ok()) {
			operation.phase = context_phase::EMPTY;
			return submitted;
		}
		operation.task_sequence = task_sequence;
		operation.phase = context_phase::PREPARE_IN_FLIGHT;
		image_busy_[operation.module_image_index] = 1u;
		executor_busy_[operation.executor_index] = 1u;
	}
	return status::ok();
}

status epoch_transition_preparation::consume_result_(config_lifecycle_result &&result) noexcept
{
	if (result.context_index() >= contexts_.size()) {
		enter_failed_stop_();
		return status::internal_error(kinetum::common::static_status_text(
			"lifecycle result context identity is outside the exact operation table"));
	}
	auto *operation = &contexts_[result.context_index()];
	if (operation->task_sequence == 0u || operation->task_sequence != result.task_sequence() ||
	    result.module_image_index() != operation->module_image_index || result.epoch() != identity_.target_epoch ||
	    result.retirement_claim_id() != 0u || image_busy_[operation->module_image_index] != 1u ||
	    executor_busy_[operation->executor_index] != 1u) {
		enter_failed_stop_();
		return status::internal_error(kinetum::common::static_status_text(
			"lifecycle result does not echo exact transition task identity"));
	}
	image_busy_[operation->module_image_index] = 0u;
	executor_busy_[operation->executor_index] = 0u;
	operation->task_sequence = 0u;

	if (operation->phase == context_phase::PREPARE_IN_FLIGHT) {
		if (result.operation() != config_lifecycle_operation::PREPARE) {
			enter_failed_stop_();
			return status::internal_error(kinetum::common::static_status_text(
				"PREPARE operation received a foreign lifecycle result kind"));
		}
		if (result.code() == config_lifecycle_result_code::SUCCESS) {
			if (!result.has_prepared_ownership()) {
				enter_failed_stop_();
				return status::internal_error(kinetum::common::static_status_text(
					"successful PREPARE result owns no exact artifact"));
			}
			auto prepared_or = result.take_prepared_ownership();
			if (!prepared_or.is_ok()) {
				enter_failed_stop_();
				return std::move(prepared_or).error();
			}
			operation->prepared.emplace(std::move(prepared_or).value());
			operation->phase = context_phase::PREPARED_TOKEN;
			return status::ok();
		}
		if (result.has_prepared_ownership()) {
			enter_failed_stop_();
			return status::internal_error(kinetum::common::static_status_text(
				"failed PREPARE result retained foreign artifact ownership"));
		}
		operation->phase = context_phase::EMPTY;
		if (phase_ == epoch_transition_preparation_phase::PREPARING) {
			const auto cause = failure_code_for_result(result.code());
			const auto diagnostic = result_diagnostic(result);
			begin_cancellation_(cause, std::string_view(diagnostic.bytes.data(), diagnostic.size),
					    std::chrono::steady_clock::now());
		}
		return status::ok();
	}

	if (operation->phase != context_phase::RETIRE_IN_FLIGHT ||
	    result.operation() != config_lifecycle_operation::RETIRE ||
	    result.code() != config_lifecycle_result_code::SUCCESS || result.has_prepared_ownership() ||
	    !operation->prepared.has_value()) {
		enter_failed_stop_();
		return status::internal_error(
			kinetum::common::static_status_text("RETIRE result does not prove exact callback completion"));
	}
	const std::size_t ordinal = static_cast<std::size_t>(operation - contexts_.data());
	modules_->complete_transition_retirement_(ordinal, *operation->prepared);
	operation->prepared.reset();
	operation->phase = context_phase::RETIRED;
	retire_deadline_ = {};
	return status::ok();
}

status epoch_transition_preparation::stage_complete_prepare_() noexcept
{
	if (phase_ != epoch_transition_preparation_phase::PREPARING || !all_prepare_succeeded_()) {
		return status::failed_precondition(
			kinetum::common::static_status_text("complete module PREPARE staging lacks every exact token"));
	}
	for (std::size_t ordinal = 0; ordinal < contexts_.size(); ++ordinal) {
		auto &operation = contexts_[ordinal];
		if (!operation.prepared.has_value()) {
			std::terminate();
		}
		auto staged = modules_->stage_transition_prepared_(ordinal, *operation.prepared);
		if (!staged.is_ok()) {
			return staged;
		}
		operation.prepared.reset();
		operation.phase = context_phase::STAGED;
	}
	auto preflight = modules_->preflight_transition_prepared_(identity_.target_epoch);
	if (!preflight.is_ok()) {
		return preflight;
	}
	modules_->publish_transition_prepared_(identity_.target_epoch);
	module_prepared_published_ = true;
	snapshot_ = nullptr;
	phase_ = epoch_transition_preparation_phase::PREPARED;
	return status::ok();
}

void epoch_transition_preparation::begin_cancellation_(epoch_transition_failure_code failure_code,
						       std::string_view diagnostic,
						       std::chrono::steady_clock::time_point now) noexcept
{
	if (failure_code_ == epoch_transition_failure_code::NONE) {
		failure_code_ = failure_code;
		const std::size_t size = std::min(diagnostic.size(), diagnostic_.bytes.size());
		std::copy_n(diagnostic.begin(), size, diagnostic_.bytes.data());
		diagnostic_.size = static_cast<uint16_t>(size);
	}
	if (phase_ == epoch_transition_preparation_phase::PREPARING) {
		phase_ = epoch_transition_preparation_phase::CANCELLING;
		auto grace_or = checked_transition_deadline(now, cancellation_grace_);
		if (!grace_or.is_ok()) {
			enter_failed_stop_();
			return;
		}
		cancellation_deadline_ = grace_or.value();
		prepare_deadline_ = {};
		for (auto &operation : contexts_) {
			if (operation.phase == context_phase::PREPARE_IN_FLIGHT) {
				operation.prepare_control->request_cancellation();
			}
		}
		return;
	}
	if (phase_ == epoch_transition_preparation_phase::PREPARED) {
		phase_ = epoch_transition_preparation_phase::CANCELLING;
		prepare_deadline_ = {};
		cancellation_deadline_ = {};
		prepared_lease_deadline_ = {};
	}
}

status epoch_transition_preparation::begin_retirement_() noexcept
{
	if (phase_ != epoch_transition_preparation_phase::CANCELLING || prepare_in_flight_()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"module retirement requires completed PREPARE cancellation"));
	}
	for (std::size_t ordinal = contexts_.size(); ordinal != 0u; --ordinal) {
		auto &operation = contexts_[ordinal - 1u];
		switch (operation.phase) {
		case context_phase::STAGED: {
			auto ownership_or =
				modules_->discard_transition_prepared_(ordinal - 1u, identity_.target_epoch);
			if (!ownership_or.is_ok()) {
				return std::move(ownership_or).error();
			}
			operation.prepared.emplace(std::move(ownership_or).value());
			operation.phase = context_phase::RETIRE_READY;
			break;
		}
		case context_phase::PREPARED_TOKEN:
			if (!operation.prepared.has_value()) {
				return status::internal_error(kinetum::common::static_status_text(
					"partial module PREPARE lost exact token ownership"));
			}
			operation.phase = context_phase::RETIRE_READY;
			break;
		case context_phase::WAITING_PREPARE:
			operation.arena.reset();
			operation.phase = context_phase::EMPTY;
			break;
		case context_phase::EMPTY:
		case context_phase::RETIRED:
			break;
		case context_phase::PREPARE_IN_FLIGHT:
		case context_phase::RETIRE_READY:
		case context_phase::RETIRE_IN_FLIGHT:
			return status::internal_error(kinetum::common::static_status_text(
				"module retirement encountered impossible transient ownership"));
		}
	}
	if (module_prepared_published_) {
		modules_->clear_transition_prepared_(identity_.target_epoch);
		module_prepared_published_ = false;
	}
	cancellation_deadline_ = {};
	phase_ = epoch_transition_preparation_phase::RETIRING;
	return dispatch_next_retire_();
}

status epoch_transition_preparation::dispatch_next_retire_() noexcept
{
	if (phase_ != epoch_transition_preparation_phase::RETIRING) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module RETIRE dispatch lacks exact cleanup ownership"));
	}
	if (std::any_of(contexts_.begin(), contexts_.end(),
			[](const auto &operation) { return operation.phase == context_phase::RETIRE_IN_FLIGHT; })) {
		return status::ok();
	}
	for (std::size_t ordinal = contexts_.size(); ordinal != 0u; --ordinal) {
		auto &operation = contexts_[ordinal - 1u];
		if (operation.phase != context_phase::RETIRE_READY) {
			continue;
		}
		if (!operation.prepared.has_value() || !operation.retire_control) {
			return status::internal_error(kinetum::common::static_status_text(
				"module RETIRE row lost exact token/control ownership"));
		}
		const auto now = std::chrono::steady_clock::now();
		auto deadline_or = checked_transition_deadline(now, cancellation_grace_);
		if (!deadline_or.is_ok()) {
			return std::move(deadline_or).error();
		}
		if (!operation.retire_control->bind_deadline_before_publication_(deadline_or.value())) {
			return status::internal_error(kinetum::common::static_status_text(
				"module RETIRE control deadline was already bound"));
		}
		const uint64_t task_sequence = modules_->next_transition_task_sequence_();
		auto submitted = modules_->submit_transition_retire_(ordinal - 1u, task_sequence,
								     *operation.retire_control, *operation.prepared);
		if (!submitted.is_ok()) {
			return submitted;
		}
		operation.task_sequence = task_sequence;
		operation.phase = context_phase::RETIRE_IN_FLIGHT;
		image_busy_[operation.module_image_index] = 1u;
		executor_busy_[operation.executor_index] = 1u;
		retire_deadline_ = deadline_or.value();
		return status::ok();
	}
	publish_aborted_if_clean_();
	return status::ok();
}

void epoch_transition_preparation::publish_aborted_if_clean_() noexcept
{
	if (phase_ != epoch_transition_preparation_phase::RETIRING || !all_contexts_clean_() ||
	    failure_code_ == epoch_transition_failure_code::NONE || module_prepared_published_) {
		std::terminate();
	}
	snapshot_ = nullptr;
	phase_ = epoch_transition_preparation_phase::ABORTED;
}

void epoch_transition_preparation::enter_failed_stop_() noexcept
{
	phase_ = epoch_transition_preparation_phase::FAILED_STOP;
}

bool epoch_transition_preparation::prepare_in_flight_() const noexcept
{
	return std::any_of(contexts_.begin(), contexts_.end(),
			   [](const auto &operation) { return operation.phase == context_phase::PREPARE_IN_FLIGHT; });
}

bool epoch_transition_preparation::all_prepare_succeeded_() const noexcept
{
	return std::all_of(contexts_.begin(), contexts_.end(), [](const auto &operation) {
		return operation.phase == context_phase::PREPARED_TOKEN && operation.prepared.has_value();
	});
}

bool epoch_transition_preparation::all_contexts_clean_() const noexcept
{
	const bool rows_clean = std::all_of(contexts_.begin(), contexts_.end(), [](const auto &operation) {
		const bool terminal = operation.phase == context_phase::EMPTY ||
				      operation.phase == context_phase::RETIRED;
		return terminal && operation.task_sequence == 0u && !operation.arena.has_value() &&
		       !operation.prepared.has_value();
	});
	return rows_clean &&
	       std::all_of(image_busy_.begin(), image_busy_.end(), [](uint8_t busy) { return busy == 0u; }) &&
	       std::all_of(executor_busy_.begin(), executor_busy_.end(), [](uint8_t busy) { return busy == 0u; }) &&
	       prepare_deadline_ == std::chrono::steady_clock::time_point{} &&
	       cancellation_deadline_ == std::chrono::steady_clock::time_point{} &&
	       retire_deadline_ == std::chrono::steady_clock::time_point{} &&
	       prepared_lease_deadline_ == std::chrono::steady_clock::time_point{};
}

}  // namespace kinetum::dp
