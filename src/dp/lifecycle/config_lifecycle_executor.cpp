// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file config_lifecycle_executor.cpp
 * @brief Bounded cold lifecycle-executor implementation.
 * @author Fleming Patel
 */

#include "src/dp/lifecycle/config_lifecycle_executor.hpp"

#include <exception>
#include <limits>
#include <utility>

namespace kinetum::dp::lifecycle
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

config_lifecycle_task::config_lifecycle_task(uint64_t task_sequence, config_lifecycle_operation operation,
					     lifecycle_context_owner &owner, config_lifecycle_adapter &adapter,
					     lifecycle_operation_control &control, uint64_t epoch, const void *payload,
					     std::size_t payload_size,
					     std::variant<std::monostate, epoch_arena_ownership> ownership,
					     const prepared_config_ownership *retire_prepared,
					     uint64_t retirement_claim_id) noexcept
	: task_sequence_(task_sequence)
	, operation_(operation)
	, module_image_index_(owner.identity().module_image_index)
	, context_index_(owner.identity().context_index)
	, epoch_(epoch)
	, owner_(&owner)
	, adapter_(&adapter)
	, control_(&control)
	, payload_(payload)
	, payload_size_(payload_size)
	, ownership_(std::move(ownership))
	, retire_prepared_(retire_prepared)
	, retirement_claim_id_(retirement_claim_id)
{
}

config_lifecycle_task::config_lifecycle_task(config_lifecycle_task &&other) noexcept = default;

status_or<config_lifecycle_task>
config_lifecycle_task::create_prepare(uint64_t task_sequence, lifecycle_context_owner &owner,
				      config_lifecycle_adapter &adapter, lifecycle_operation_control &control,
				      uint64_t epoch, const void *payload, std::size_t payload_size,
				      epoch_arena_ownership &&arena) noexcept
{
	if (task_sequence == 0 || epoch == 0) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "PREPARE task requires nonzero task sequence and exact epoch"));
	}
	if (!control.deadline_bound()) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text("PREPARE task requires one bound monotonic deadline"));
	}
	if (!valid_lifecycle_payload_span(payload, payload_size)) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "PREPARE task payload pointer and size do not describe one exact byte span"));
	}
	const auto &identity = owner.identity();
	if (!arena.owns_memory() || arena.context_index() != identity.context_index || arena.epoch() != epoch ||
	    arena.numa_node() != identity.numa_node || arena.capacity() != owner.epoch_arena_capacity_bytes()) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text(
				"PREPARE task arena does not match context, epoch, NUMA, and authored capacity ownership"));
	}

	std::variant<std::monostate, epoch_arena_ownership> ownership(std::in_place_type<epoch_arena_ownership>,
								      std::move(arena));
	return config_lifecycle_task(task_sequence, config_lifecycle_operation::PREPARE, owner, adapter, control, epoch,
				     payload, payload_size, std::move(ownership), nullptr, 0u);
}

status_or<config_lifecycle_task>
config_lifecycle_task::create_retire(uint64_t task_sequence, lifecycle_context_owner &owner,
				     config_lifecycle_adapter &adapter, lifecycle_operation_control &control,
				     const prepared_config_ownership &prepared) noexcept
{
	return create_retire_(task_sequence, owner, adapter, control, prepared, 0u);
}

status_or<config_lifecycle_task> config_lifecycle_task::create_claimed_retire(uint64_t task_sequence,
									      lifecycle_context_owner &owner,
									      config_lifecycle_adapter &adapter,
									      lifecycle_operation_control &control,
									      const prepared_config_ownership &prepared,
									      uint64_t retirement_claim_id) noexcept
{
	if (retirement_claim_id == 0u) {
		return status::invalid_argument(
			kinetum::common::static_status_text("claimed RETIRE requires a nonzero store claim identity"));
	}
	return create_retire_(task_sequence, owner, adapter, control, prepared, retirement_claim_id);
}

status_or<config_lifecycle_task>
config_lifecycle_task::create_retire_(uint64_t task_sequence, lifecycle_context_owner &owner,
				      config_lifecycle_adapter &adapter, lifecycle_operation_control &control,
				      const prepared_config_ownership &prepared, uint64_t retirement_claim_id) noexcept
{
	if (task_sequence == 0u) {
		return status::invalid_argument(
			kinetum::common::static_status_text("RETIRE task requires a nonzero task sequence"));
	}
	if (!control.deadline_bound()) {
		return status::invalid_argument(
			kinetum::common::static_status_text("RETIRE task requires one bound monotonic deadline"));
	}
	const auto &identity = owner.identity();
	auto record_or = prepared.borrow_exact(identity.module_image_index, identity.context_index, prepared.epoch());
	if (!record_or.is_ok()) {
		return std::move(record_or).error();
	}
	std::variant<std::monostate, epoch_arena_ownership> ownership;
	return config_lifecycle_task(task_sequence, config_lifecycle_operation::RETIRE, owner, adapter, control,
				     prepared.epoch(), nullptr, 0, std::move(ownership), &prepared,
				     retirement_claim_id);
}

uint64_t config_lifecycle_task::task_sequence() const noexcept
{
	return task_sequence_;
}

config_lifecycle_operation config_lifecycle_task::operation() const noexcept
{
	return operation_;
}

uint32_t config_lifecycle_task::module_image_index() const noexcept
{
	return module_image_index_;
}

uint32_t config_lifecycle_task::context_index() const noexcept
{
	return context_index_;
}

uint64_t config_lifecycle_task::epoch() const noexcept
{
	return epoch_;
}

uint64_t config_lifecycle_task::retirement_claim_id() const noexcept
{
	return retirement_claim_id_;
}

config_lifecycle_result::config_lifecycle_result(uint64_t task_sequence, config_lifecycle_operation operation,
						 config_lifecycle_result_code code, uint32_t diagnostic_code,
						 uint32_t module_image_index, uint32_t context_index, uint64_t epoch,
						 uint64_t retirement_claim_id,
						 std::optional<prepared_config_ownership> prepared) noexcept
	: task_sequence_(task_sequence)
	, operation_(operation)
	, code_(code)
	, diagnostic_code_(diagnostic_code)
	, module_image_index_(module_image_index)
	, context_index_(context_index)
	, epoch_(epoch)
	, retirement_claim_id_(retirement_claim_id)
	, prepared_(std::move(prepared))
{
}

config_lifecycle_result::config_lifecycle_result(config_lifecycle_result &&other) noexcept = default;

uint64_t config_lifecycle_result::task_sequence() const noexcept
{
	return task_sequence_;
}

config_lifecycle_operation config_lifecycle_result::operation() const noexcept
{
	return operation_;
}

config_lifecycle_result_code config_lifecycle_result::code() const noexcept
{
	return code_;
}

uint32_t config_lifecycle_result::diagnostic_code() const noexcept
{
	return diagnostic_code_;
}

uint32_t config_lifecycle_result::module_image_index() const noexcept
{
	return module_image_index_;
}

uint32_t config_lifecycle_result::context_index() const noexcept
{
	return context_index_;
}

uint64_t config_lifecycle_result::epoch() const noexcept
{
	return epoch_;
}

uint64_t config_lifecycle_result::retirement_claim_id() const noexcept
{
	return retirement_claim_id_;
}

bool config_lifecycle_result::has_prepared_ownership() const noexcept
{
	return prepared_.has_value() && prepared_->owns_state();
}

status_or<prepared_config_ownership> config_lifecycle_result::take_prepared_ownership() noexcept
{
	if (!prepared_.has_value() || !prepared_->owns_state()) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("lifecycle result owns no prepared configuration token"));
	}
	prepared_config_ownership ownership(std::move(*prepared_));
	prepared_.reset();
	return ownership;
}

config_lifecycle_executor::config_lifecycle_executor(uint32_t service_index, int32_t numa_node) noexcept
	: service_index_(service_index)
	, numa_node_(numa_node)
{
}

config_lifecycle_executor::~config_lifecycle_executor()
{
	if (launch_reserved_ || accepting_.load(std::memory_order_acquire) ||
	    running_.load(std::memory_order_acquire) || !tasks_.empty() || !results_.empty() ||
	    accepted_task_count_.load(std::memory_order_acquire) !=
		    published_result_count_.load(std::memory_order_acquire)) {
		std::terminate();
	}
}

status config_lifecycle_executor::submit(config_lifecycle_task &&task) noexcept
{
	std::lock_guard<std::mutex> lock(wake_mutex_);
	if (!accepting_.load(std::memory_order_acquire) || stop_requested_.load(std::memory_order_acquire)) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("lifecycle executor is not accepting coordinator tasks"));
	}
	const uint64_t accepted = accepted_task_count_.load(std::memory_order_relaxed);
	if (accepted == std::numeric_limits<uint64_t>::max()) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text(
				      "lifecycle executor task sequence accounting is exhausted"));
	}
	if (!tasks_.try_push(std::move(task))) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text("lifecycle executor task channel is full"));
	}
	accepted_task_count_.store(accepted + 1u, std::memory_order_release);
	wake_cv_.notify_all();
	return status::ok();
}

std::optional<config_lifecycle_result> config_lifecycle_executor::try_take_result() noexcept
{
	// Result publication and removal participate in the wake mutex so neither
	// side can notify between the other side's predicate check and wait.
	std::lock_guard<std::mutex> lock(wake_mutex_);
	auto result = results_.try_pop();
	if (result.has_value()) {
		wake_cv_.notify_all();
	}
	return result;
}

std::optional<config_lifecycle_result>
config_lifecycle_executor::wait_take_result_until(std::chrono::steady_clock::time_point deadline) noexcept
{
	std::unique_lock<std::mutex> lock(wake_mutex_);
	(void)wake_cv_.wait_until(lock, deadline,
				  [this]() { return !results_.empty() || stopped_.load(std::memory_order_acquire); });
	lock.unlock();
	return try_take_result();
}

void config_lifecycle_executor::run() noexcept
{
	bool expected = false;
	if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
		std::terminate();
	}
	stopped_.store(false, std::memory_order_release);

	for (;;) {
		std::unique_lock<std::mutex> lock(wake_mutex_);
		wake_cv_.wait(lock, [this]() {
			return (stop_requested_.load(std::memory_order_acquire) && tasks_.empty()) ||
			       (!tasks_.empty() && !results_.full());
		});
		if (stop_requested_.load(std::memory_order_acquire) && tasks_.empty()) {
			break;
		}

		auto task = tasks_.try_pop();
		if (!task.has_value()) {
			continue;
		}
		lock.unlock();

		// The call owns the task, so its untransferred arena is released before
		// result publication. Module callbacks and allocator cleanup both run
		// outside the wake mutex.
		auto result = execute_(std::move(*task));
		{
			// Rejoin the condition-variable protocol only after foreign code has
			// returned. Capacity cannot shrink while this producer owns the mutex.
			std::lock_guard<std::mutex> result_lock(wake_mutex_);
			const uint64_t published = published_result_count_.load(std::memory_order_relaxed);
			if (published == std::numeric_limits<uint64_t>::max()) {
				std::terminate();
			}
			if (!results_.try_push(std::move(result))) {
				// The consumer is unique and the loop proved capacity before popping
				// the task. Failure here means the no-lost-result invariant is broken.
				std::terminate();
			}
			published_result_count_.store(published + 1u, std::memory_order_release);
		}
		if (result_notifier_ != nullptr) {
			result_notifier_->notify_result();
		}
		wake_cv_.notify_all();
	}

	if (accepted_task_count_.load(std::memory_order_acquire) !=
	    published_result_count_.load(std::memory_order_acquire)) {
		std::terminate();
	}
	{
		// Terminal publication shares the wait predicate's mutex; otherwise a
		// waiter can check stopped_, miss the notification, and sleep forever.
		std::lock_guard<std::mutex> lock(wake_mutex_);
		running_.store(false, std::memory_order_release);
		stopped_.store(true, std::memory_order_release);
	}
	wake_cv_.notify_all();
}

void config_lifecycle_executor::request_stop() noexcept
{
	std::lock_guard<std::mutex> lock(wake_mutex_);
	accepting_.store(false, std::memory_order_release);
	stop_requested_.store(true, std::memory_order_release);
	wake_cv_.notify_all();
}

bool config_lifecycle_executor::stopped() const noexcept
{
	return stopped_.load(std::memory_order_acquire);
}

uint32_t config_lifecycle_executor::service_index() const noexcept
{
	return service_index_;
}

int32_t config_lifecycle_executor::numa_node() const noexcept
{
	return numa_node_;
}

uint64_t config_lifecycle_executor::accepted_task_count() const noexcept
{
	return accepted_task_count_.load(std::memory_order_acquire);
}

uint64_t config_lifecycle_executor::published_result_count() const noexcept
{
	return published_result_count_.load(std::memory_order_acquire);
}

status config_lifecycle_executor::bind_result_notifier(config_lifecycle_result_notifier &notifier) noexcept
{
	std::lock_guard<std::mutex> lock(wake_mutex_);
	if (result_notifier_ != nullptr || launch_reserved_ || accepting_.load(std::memory_order_acquire) ||
	    running_.load(std::memory_order_acquire) || stop_requested_.load(std::memory_order_acquire)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("lifecycle result notifier must bind once before launch"));
	}
	result_notifier_ = &notifier;
	return status::ok();
}

status config_lifecycle_executor::reserve_launch_() noexcept
{
	std::lock_guard<std::mutex> lock(wake_mutex_);
	if (launch_reserved_ || accepting_.load(std::memory_order_acquire) ||
	    stop_requested_.load(std::memory_order_acquire) || running_.load(std::memory_order_acquire) ||
	    stopped_.load(std::memory_order_acquire) || !tasks_.empty() || !results_.empty() ||
	    accepted_task_count_.load(std::memory_order_acquire) != 0 ||
	    published_result_count_.load(std::memory_order_acquire) != 0) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text(
				      "lifecycle executor is not an idle unreserved launch target"));
	}
	launch_reserved_ = true;
	return status::ok();
}

void config_lifecycle_executor::cancel_launch_reservation_() noexcept
{
	std::lock_guard<std::mutex> lock(wake_mutex_);
	if (!launch_reserved_ || accepting_.load(std::memory_order_acquire) ||
	    running_.load(std::memory_order_acquire)) {
		std::terminate();
	}
	launch_reserved_ = false;
}

void config_lifecycle_executor::publish_launch_() noexcept
{
	std::lock_guard<std::mutex> lock(wake_mutex_);
	if (!launch_reserved_ || accepting_.load(std::memory_order_acquire) ||
	    stop_requested_.load(std::memory_order_acquire) || running_.load(std::memory_order_acquire) ||
	    stopped_.load(std::memory_order_acquire)) {
		std::terminate();
	}
	launch_reserved_ = false;
	accepting_.store(true, std::memory_order_release);
}

void config_lifecycle_executor::wait_for_result_or_stop_() noexcept
{
	std::unique_lock<std::mutex> lock(wake_mutex_);
	wake_cv_.wait(lock, [this]() { return !results_.empty() || stopped_.load(std::memory_order_acquire); });
}

config_lifecycle_result config_lifecycle_executor::execute_(config_lifecycle_task task) noexcept
{
	switch (task.operation_) {
	case config_lifecycle_operation::PREPARE:
		return execute_prepare_(task);
	case config_lifecycle_operation::RETIRE:
		return execute_retire_(task);
	}
	std::terminate();
}

config_lifecycle_result config_lifecycle_executor::execute_prepare_(config_lifecycle_task &task) noexcept
{
	const auto make_result = [&task](config_lifecycle_result_code code, uint32_t module_error_code,
					 std::optional<prepared_config_ownership> prepared = std::nullopt) {
		return config_lifecycle_result(task.task_sequence_, task.operation_, code, module_error_code,
					       task.module_image_index_, task.context_index_, task.epoch_,
					       task.retirement_claim_id_, std::move(prepared));
	};

	if (task.control_->cancellation_requested()) {
		return make_result(config_lifecycle_result_code::CANCELLED, 0);
	}
	if (task.control_->deadline_expired(std::chrono::steady_clock::now())) {
		return make_result(config_lifecycle_result_code::DEADLINE_EXCEEDED, 0);
	}

	auto *task_arena = std::get_if<epoch_arena_ownership>(&task.ownership_);
	if (task_arena == nullptr) {
		std::terminate();
	}
	auto operation_or =
		task.owner_->begin_operation(lifecycle_phase::PREPARE, task.epoch_, *task.control_, task_arena);
	if (!operation_or.is_ok()) {
		return make_result(config_lifecycle_result_code::CONTEXT_REJECTED,
				   static_cast<uint32_t>(operation_or.error().code()));
	}
	auto operation = std::move(operation_or).value();
	const auto callback_result = task.adapter_->prepare(operation.context(), task.payload_, task.payload_size_);
	operation.release();

	switch (callback_result.code) {
	case lifecycle_prepare_callback_code::CANCELLED:
		return make_result(config_lifecycle_result_code::CANCELLED, callback_result.module_error_code);
	case lifecycle_prepare_callback_code::FAILURE:
		return make_result(config_lifecycle_result_code::CALLBACK_FAILURE, callback_result.module_error_code);
	case lifecycle_prepare_callback_code::SUCCESS:
		break;
	default:
		return make_result(config_lifecycle_result_code::CALLBACK_FAILURE, callback_result.module_error_code);
	}

	std::optional<epoch_arena_ownership> arena;
	arena.emplace(std::move(*task_arena));
	task.ownership_.emplace<std::monostate>();
	auto prepared_or = prepared_config_ownership::create(task.module_image_index_, task.context_index_, task.epoch_,
							     callback_result.prepared, std::move(arena));
	if (!prepared_or.is_ok()) {
		// PREPARE already transferred foreign ownership. Every constructor input
		// was validated before callback entry, so rejection here is an internal
		// contradiction with no lawful recovery or token-discard path.
		std::terminate();
	}
	std::optional<prepared_config_ownership> prepared;
	prepared.emplace(std::move(prepared_or).value());
	return make_result(config_lifecycle_result_code::SUCCESS, 0, std::move(prepared));
}

config_lifecycle_result config_lifecycle_executor::execute_retire_(const config_lifecycle_task &task) noexcept
{
	const auto make_result = [&task](config_lifecycle_result_code code, uint32_t module_error_code) {
		return config_lifecycle_result(task.task_sequence_, task.operation_, code, module_error_code,
					       task.module_image_index_, task.context_index_, task.epoch_,
					       task.retirement_claim_id_, std::nullopt);
	};

	if (task.retire_prepared_ == nullptr) {
		return make_result(config_lifecycle_result_code::CONTEXT_REJECTED,
				   static_cast<uint32_t>(status_code::FAILED_PRECONDITION));
	}
	auto record_or =
		task.retire_prepared_->borrow_exact(task.module_image_index_, task.context_index_, task.epoch_);
	if (!record_or.is_ok()) {
		return make_result(config_lifecycle_result_code::CONTEXT_REJECTED,
				   static_cast<uint32_t>(record_or.error().code()));
	}
	auto operation_or = task.owner_->begin_operation(lifecycle_phase::RETIRE, task.epoch_, *task.control_);
	if (!operation_or.is_ok()) {
		return make_result(config_lifecycle_result_code::CONTEXT_REJECTED,
				   static_cast<uint32_t>(operation_or.error().code()));
	}
	auto operation = std::move(operation_or).value();
	task.adapter_->retire(operation.context(), record_or.value());
	operation.release();
	return make_result(config_lifecycle_result_code::SUCCESS, 0);
}

}  // namespace kinetum::dp::lifecycle
