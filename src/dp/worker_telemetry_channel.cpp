// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_telemetry_channel.cpp
 * @brief Poller-local telemetry-bank transfer implementation.
 * @author Fleming Patel
 */

#include "src/dp/worker_telemetry_channel.hpp"

#include <limits>
#include <new>

namespace kinetum::dp
{

common::status_or<std::size_t> worker_telemetry_channel::capacity_for(std::size_t module_context_count) noexcept
{
	if (module_context_count > (std::numeric_limits<std::size_t>::max() / 2u) - 1u) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "telemetry bank-owner population exceeds the host size domain"));
	}
	const std::size_t required = 2u * (module_context_count + 1u);
	std::size_t capacity = 2u;
	while (capacity < required) {
		if (capacity > std::numeric_limits<std::size_t>::max() / 2u) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      kinetum::common::static_status_text(
						      "telemetry channel capacity exceeds the host size domain"));
		}
		capacity *= 2u;
	}
	return capacity;
}

common::status_or<std::unique_ptr<worker_telemetry_channel>>
worker_telemetry_channel::create(uint32_t worker_index, std::size_t module_context_count, int32_t worker_numa_node,
				 int32_t coordinator_numa_node)
{
	if (worker_index == UINT32_MAX || worker_numa_node < 0 || coordinator_numa_node < 0) {
		return common::status::invalid_argument("telemetry channel requires exact worker and NUMA identities");
	}
	auto capacity_or = capacity_for(module_context_count);
	if (!capacity_or.is_ok()) {
		return capacity_or.error();
	}
	auto completed_or =
		numa_spsc_ring<runtime_telemetry_bank_token>::create(capacity_or.value(), coordinator_numa_node);
	if (!completed_or.is_ok()) {
		return completed_or.error();
	}
	auto returned_or = numa_spsc_ring<runtime_telemetry_bank_token>::create(capacity_or.value(), worker_numa_node);
	if (!returned_or.is_ok()) {
		return returned_or.error();
	}
	auto owner = std::unique_ptr<worker_telemetry_channel>(new (std::nothrow) worker_telemetry_channel(
		worker_index, capacity_or.value(), std::move(completed_or).value(), std::move(returned_or).value()));
	if (owner == nullptr) {
		return common::status::resource_exhausted("failed to allocate telemetry channel owner");
	}
	return owner;
}

worker_telemetry_channel::worker_telemetry_channel(
	uint32_t worker_index, std::size_t capacity,
	std::unique_ptr<numa_spsc_ring<runtime_telemetry_bank_token>> completed,
	std::unique_ptr<numa_spsc_ring<runtime_telemetry_bank_token>> returned) noexcept
	: worker_index_(worker_index)
	, capacity_(capacity)
	, completed_(std::move(completed))
	, returned_(std::move(returned))
{
	if (worker_index_ == UINT32_MAX || capacity_ < 2u || completed_ == nullptr || returned_ == nullptr ||
	    completed_->capacity() != capacity_ || returned_->capacity() != capacity_) {
		std::terminate();
	}
}

worker_telemetry_channel::~worker_telemetry_channel()
{
	if (!empty()) {
		std::terminate();
	}
}

bool worker_telemetry_channel::publish_completed(const runtime_telemetry_bank_token &token) noexcept
{
	return completed_->try_push(token);
}

bool worker_telemetry_channel::take_completed(runtime_telemetry_bank_token &token) noexcept
{
	return completed_->try_pop(token);
}

bool worker_telemetry_channel::return_cleared(const runtime_telemetry_bank_token &token) noexcept
{
	return returned_->try_push(token);
}

bool worker_telemetry_channel::take_returned(runtime_telemetry_bank_token &token) noexcept
{
	return returned_->try_pop(token);
}

std::size_t worker_telemetry_channel::completed_available() const noexcept
{
	return completed_->available();
}

uint32_t worker_telemetry_channel::worker_index() const noexcept
{
	return worker_index_;
}

std::size_t worker_telemetry_channel::capacity() const noexcept
{
	return capacity_;
}

int32_t worker_telemetry_channel::completed_numa_node() const noexcept
{
	return completed_->numa_node();
}

int32_t worker_telemetry_channel::returned_numa_node() const noexcept
{
	return returned_->numa_node();
}

bool worker_telemetry_channel::completed_empty() const noexcept
{
	return completed_->empty();
}

bool worker_telemetry_channel::returned_empty() const noexcept
{
	return returned_->empty();
}

bool worker_telemetry_channel::empty() const noexcept
{
	return completed_empty() && returned_empty();
}

}  // namespace kinetum::dp
