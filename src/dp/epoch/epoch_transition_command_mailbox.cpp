// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_transition_command_mailbox.cpp
 * @brief Bounded coordinator-command mailbox implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/epoch_transition_command_mailbox.hpp"

#include <cerrno>
#include <cstring>
#include <exception>
#include <new>
#include <stdexcept>
#include <string>

#include <sys/eventfd.h>
#include <unistd.h>

#include "src/common/transition_topology.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/**
 * @brief Check the independently enforced mailbox-capacity contract.
 *
 * @param capacity Candidate physical command slots.
 * @return true only for a power of two in the shared closed range.
 */
[[nodiscard]] constexpr bool valid_mailbox_capacity(uint32_t capacity) noexcept
{
	return capacity >= common::MIN_COORDINATOR_COMMAND_MAILBOX_CAPACITY &&
	       capacity <= common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY && (capacity & (capacity - 1u)) == 0u;
}

/**
 * @brief Reject undeclared command discriminants before context transfer.
 *
 * @param kind Candidate command kind.
 * @return true only for one exact declared command operation.
 */
[[nodiscard]] constexpr bool valid_command_kind(epoch_transition_command_kind kind) noexcept
{
	switch (kind) {
	case epoch_transition_command_kind::BOOTSTRAP:
	case epoch_transition_command_kind::PREPARE:
	case epoch_transition_command_kind::ACTIVATE:
	case epoch_transition_command_kind::ABORT:
	case epoch_transition_command_kind::STATUS:
		return true;
	}
	return false;
}

}  // namespace

epoch_transition_command_context::~epoch_transition_command_context()
{
	std::lock_guard<std::mutex> lock(completion_mutex_);
	if (ownership_ == ownership_state::SUBMITTING || ownership_ == ownership_state::QUEUED ||
	    ownership_ == ownership_state::CONSUMER) {
		std::terminate();
	}
}

void epoch_transition_command_context::wait_for_completion() noexcept
{
	std::unique_lock<std::mutex> lock(completion_mutex_);
	if (ownership_ == ownership_state::LOCAL || ownership_ == ownership_state::SUBMITTING) {
		std::terminate();
	}
	completion_cv_.wait(lock, [this]() { return ownership_ == ownership_state::COMPLETED; });
}

bool epoch_transition_command_context::claim_for_submit_() noexcept
{
	std::lock_guard<std::mutex> lock(completion_mutex_);
	if (ownership_ != ownership_state::LOCAL) {
		return false;
	}
	ownership_ = ownership_state::SUBMITTING;
	return true;
}

void epoch_transition_command_context::release_failed_submit_() noexcept
{
	std::lock_guard<std::mutex> lock(completion_mutex_);
	if (ownership_ != ownership_state::SUBMITTING && ownership_ != ownership_state::QUEUED) {
		std::terminate();
	}
	ownership_ = ownership_state::LOCAL;
}

void epoch_transition_command_context::publish_mailbox_ownership_() noexcept
{
	std::lock_guard<std::mutex> lock(completion_mutex_);
	if (ownership_ != ownership_state::SUBMITTING) {
		std::terminate();
	}
	ownership_ = ownership_state::QUEUED;
}

void epoch_transition_command_context::publish_consumer_ownership_() noexcept
{
	std::lock_guard<std::mutex> lock(completion_mutex_);
	if (ownership_ != ownership_state::QUEUED) {
		std::terminate();
	}
	ownership_ = ownership_state::CONSUMER;
}

status_or<std::unique_ptr<epoch_transition_command_mailbox>>
epoch_transition_command_mailbox::create(const common::compiled_transition_topology &topology)
{
	if (!topology.lifecycle_services.has_value() || topology.runtime_services.empty()) {
		return status::invalid_argument(
			"coordinator command mailbox requires complete compiled lifecycle services");
	}
	const auto &lifecycle = topology.lifecycle_services.value();
	if (lifecycle.coordinator_service_index != 0u ||
	    lifecycle.coordinator_service_index >= topology.runtime_services.size() ||
	    topology.runtime_services.size() != lifecycle.lifecycle_executor_service_indices.size() + 1u) {
		return status::invalid_argument(
			"coordinator command mailbox has a noncanonical coordinator projection");
	}
	const auto &coordinator = topology.runtime_services[lifecycle.coordinator_service_index];
	if (coordinator.service_index != lifecycle.coordinator_service_index ||
	    coordinator.role != common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR) {
		return status::invalid_argument("compiled command mailbox has no exact coordinator owner");
	}
	if (!valid_mailbox_capacity(coordinator.command_mailbox_capacity)) {
		return status(
			status_code::OUT_OF_RANGE,
			"compiled coordinator command-mailbox capacity must be a power of two in the closed range 2..64");
	}
	std::size_t coordinator_count = 0;
	std::size_t executor_count = 0;
	for (std::size_t index = 0; index < topology.runtime_services.size(); ++index) {
		const auto &service = topology.runtime_services[index];
		if (service.service_index != index) {
			return status::invalid_argument("compiled runtime service indices are not dense and exact");
		}
		if (service.role == common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR) {
			++coordinator_count;
			if (index != lifecycle.coordinator_service_index ||
			    !valid_mailbox_capacity(service.command_mailbox_capacity)) {
				return status::invalid_argument(
					"compiled coordinator mailbox ownership is not exact in both directions");
			}
		} else if (service.role == common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR) {
			++executor_count;
			if (service.command_mailbox_capacity != 0u) {
				return status::invalid_argument(
					"compiled lifecycle executor must not own coordinator command-mailbox capacity");
			}
		} else {
			return status::invalid_argument(
				"compiled command mailbox encountered an unsupported runtime-service role");
		}
	}
	if (coordinator_count != 1u || executor_count != lifecycle.lifecycle_executor_service_indices.size()) {
		return status::invalid_argument("compiled command-mailbox service membership is incomplete");
	}
	for (std::size_t ordinal = 0; ordinal < lifecycle.lifecycle_executor_service_indices.size(); ++ordinal) {
		const uint32_t service_index = lifecycle.lifecycle_executor_service_indices[ordinal];
		const std::size_t expected_index = ordinal + 1u;
		if (static_cast<std::size_t>(service_index) != expected_index ||
		    service_index >= topology.runtime_services.size() ||
		    topology.runtime_services[service_index].role !=
			    common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR) {
			return status::invalid_argument(
				"compiled command-mailbox executor projection is not canonical and complete");
		}
	}
	return create_with_capacity_(coordinator.command_mailbox_capacity);
}

status_or<std::unique_ptr<epoch_transition_command_mailbox>>
epoch_transition_command_mailbox::create_with_capacity_(uint32_t capacity)
{
	if (!valid_mailbox_capacity(capacity)) {
		return status(status_code::OUT_OF_RANGE,
			      "coordinator command-mailbox capacity must be a power of two in the closed range 2..64");
	}

	const int descriptor = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (descriptor < 0) {
		const int error = errno;
		return status(status_code::RESOURCE_EXHAUSTED,
			      "failed to create coordinator command notification descriptor: " +
				      std::string(std::strerror(error)));
	}
	try {
		return std::unique_ptr<epoch_transition_command_mailbox>(
			new epoch_transition_command_mailbox(capacity, descriptor));
	} catch (const std::bad_alloc &) {
		(void)::close(descriptor);
		return status::resource_exhausted("failed to allocate coordinator command mailbox");
	} catch (const std::invalid_argument &) {
		(void)::close(descriptor);
		return status::internal_error("validated coordinator mailbox capacity was rejected by the queue");
	}
}

epoch_transition_command_mailbox::epoch_transition_command_mailbox(uint32_t capacity, int notification_descriptor)
	: commands_(capacity)
	, notification_descriptor_(notification_descriptor)
{
}

epoch_transition_command_mailbox::~epoch_transition_command_mailbox()
{
	{
		std::lock_guard<std::mutex> lock(gate_);
		if (unresolved_count_ != 0u || commands_.size_approx() != 0u ||
		    (consumer_bound_ && !admission_closed_)) {
			std::terminate();
		}
	}
	if (notification_descriptor_ >= 0) {
		(void)::close(notification_descriptor_);
	}
}

status epoch_transition_command_mailbox::bind_consumer_to_current_thread() noexcept
{
	std::lock_guard<std::mutex> lock(gate_);
	if (consumer_bound_ || admission_closed_ || unresolved_count_ != 0u || commands_.size_approx() != 0u) {
		return status::failed_precondition(
			kinetum::common::static_status_text("coordinator command mailbox cannot rebind its consumer"));
	}
	consumer_thread_ = std::this_thread::get_id();
	consumer_bound_ = true;
	return status::ok();
}

status epoch_transition_command_mailbox::submit(const epoch_transition_command &command) noexcept
{
	if (command.context == nullptr) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"coordinator command requires one live completion context"));
	}
	if (!valid_command_kind(command.kind)) {
		return status::invalid_argument(
			kinetum::common::static_status_text("coordinator command kind is not declared"));
	}
	if (!command.context->claim_for_submit_()) {
		return status::failed_precondition(
			kinetum::common::static_status_text("coordinator command context is not locally submit-ready"));
	}
	std::lock_guard<std::mutex> lock(gate_);
	if (!consumer_bound_) {
		command.context->release_failed_submit_();
		return status::failed_precondition(
			kinetum::common::static_status_text("coordinator command consumer is not bound"));
	}
	if (std::this_thread::get_id() == consumer_thread_) {
		command.context->release_failed_submit_();
		return status::failed_precondition(
			kinetum::common::static_status_text("coordinator consumer cannot submit a command to itself"));
	}
	if (admission_closed_) {
		command.context->release_failed_submit_();
		return status::unavailable(
			kinetum::common::static_status_text("coordinator command admission is closed"));
	}
	command.context->publish_mailbox_ownership_();
	if (!commands_.try_enqueue(command)) {
		command.context->release_failed_submit_();
		return status::resource_exhausted(
			kinetum::common::static_status_text("coordinator command mailbox is full"));
	}
	++unresolved_count_;

	eventfd_t wake = 1u;
	for (;;) {
		if (::eventfd_write(notification_descriptor_, wake) == 0) {
			return status::ok();
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN) {
			// A saturated event counter is already readable, so no wake credit
			// is lost while the sole consumer services repeated bounded turns.
			return status::ok();
		}
		std::terminate();
	}
}

status_or<uint64_t> epoch_transition_command_mailbox::consume_notification() noexcept
{
	require_consumer_();
	eventfd_t observed = 0;
	for (;;) {
		if (::eventfd_read(notification_descriptor_, &observed) == 0) {
			if (observed == 0u || observed > commands_.capacity()) {
				std::terminate();
			}
			return static_cast<uint64_t>(observed);
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN) {
			return uint64_t{0};
		}
		return status::internal_error(
			kinetum::common::static_status_text("failed to consume coordinator command notification"));
	}
}

void epoch_transition_command_mailbox::defer_notifications(uint64_t count) noexcept
{
	require_consumer_();
	if (count == 0u) {
		return;
	}
	if (count > commands_.capacity()) {
		std::terminate();
	}
	for (;;) {
		if (::eventfd_write(notification_descriptor_, static_cast<eventfd_t>(count)) == 0) {
			return;
		}
		if (errno == EINTR) {
			continue;
		}
		std::terminate();
	}
}

bool epoch_transition_command_mailbox::try_take(epoch_transition_command &command) noexcept
{
	require_consumer_();
	if (!commands_.try_dequeue(command)) {
		return false;
	}
	if (command.context == nullptr) {
		std::terminate();
	}
	command.context->publish_consumer_ownership_();
	return true;
}

void epoch_transition_command_mailbox::complete(epoch_transition_command_context *context) noexcept
{
	require_consumer_();
	if (context == nullptr) {
		std::terminate();
	}
	std::unique_lock<std::mutex> context_lock(context->completion_mutex_);
	if (context->ownership_ != epoch_transition_command_context::ownership_state::CONSUMER) {
		std::terminate();
	}
	{
		std::lock_guard<std::mutex> lock(gate_);
		if (unresolved_count_ == 0u) {
			std::terminate();
		}
		--unresolved_count_;
	}
	context->ownership_ = epoch_transition_command_context::ownership_state::COMPLETED;
	context_lock.unlock();
	context->completion_cv_.notify_one();
}

void epoch_transition_command_mailbox::close_admission() noexcept
{
	require_consumer_();
	std::lock_guard<std::mutex> lock(gate_);
	admission_closed_ = true;
}

int epoch_transition_command_mailbox::notification_descriptor() const noexcept
{
	return notification_descriptor_;
}

std::size_t epoch_transition_command_mailbox::capacity() const noexcept
{
	return commands_.capacity();
}

std::size_t epoch_transition_command_mailbox::unresolved_count() const noexcept
{
	std::lock_guard<std::mutex> lock(gate_);
	return unresolved_count_;
}

bool epoch_transition_command_mailbox::admission_closed() const noexcept
{
	std::lock_guard<std::mutex> lock(gate_);
	return admission_closed_;
}

bool epoch_transition_command_mailbox::current_thread_is_consumer() const noexcept
{
	std::lock_guard<std::mutex> lock(gate_);
	return consumer_bound_ && std::this_thread::get_id() == consumer_thread_;
}

bool epoch_transition_command_mailbox::ready_for_generation_adoption() const noexcept
{
	std::lock_guard<std::mutex> lock(gate_);
	return !consumer_bound_ && !admission_closed_ && unresolved_count_ == 0u && commands_.size_approx() == 0u;
}

void epoch_transition_command_mailbox::require_consumer_() const noexcept
{
	std::lock_guard<std::mutex> lock(gate_);
	if (!consumer_bound_ || std::this_thread::get_id() != consumer_thread_) {
		std::terminate();
	}
}

}  // namespace kinetum::dp
