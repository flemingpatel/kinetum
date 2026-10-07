// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_transition_staging.cpp
 * @brief Exact boundary future-output staging implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/epoch_transition_staging.hpp"

#include <exception>
#include <new>
#include <utility>

namespace kinetum::dp
{

common::status_or<std::unique_ptr<boundary_future_output_hold>>
boundary_future_output_hold::create(const common::compiled_transition_boundary &facts, int32_t sender_numa_node)
{
	if (facts.sender_worker_index == facts.receiver_worker_index) {
		return common::status::failed_precondition(
			"boundary future-output hold requires distinct sender and receiver workers");
	}
	if (sender_numa_node < 0) {
		return common::status::failed_precondition(
			"boundary future-output hold requires an exact sender NUMA node");
	}
	auto queue_or = numa_spsc_ring<packet_record *>::create(facts.future_output_hold_capacity, sender_numa_node);
	if (!queue_or.is_ok()) {
		return queue_or.error();
	}
	auto *hold = new (std::nothrow)
		boundary_future_output_hold(facts, sender_numa_node, std::move(queue_or).value());
	if (hold == nullptr) {
		return common::status::resource_exhausted("boundary future-output hold owner allocation failed");
	}
	return std::unique_ptr<boundary_future_output_hold>(hold);
}

boundary_future_output_hold::boundary_future_output_hold(const common::compiled_transition_boundary &facts,
							 int32_t sender_numa_node,
							 std::unique_ptr<numa_spsc_ring<packet_record *>> queue) noexcept
	: boundary_index_(facts.boundary_index)
	, sender_worker_index_(facts.sender_worker_index)
	, numa_node_(sender_numa_node)
	, queue_(std::move(queue))
{
	if (queue_ == nullptr || !queue_->empty() || queue_->capacity() != facts.future_output_hold_capacity ||
	    queue_->numa_node() != numa_node_) {
		std::terminate();
	}
}

boundary_future_output_hold::~boundary_future_output_hold()
{
	if (queue_ != nullptr && !queue_->empty()) {
		std::terminate();
	}
}

bool boundary_future_output_hold::try_hold(packet_record *record) noexcept
{
	if (record == nullptr) {
		std::terminate();
	}
	return queue_->try_push(record);
}

bool boundary_future_output_hold::try_release(packet_record *&record) noexcept
{
	return queue_->try_pop(record);
}

const packet_record *boundary_future_output_hold::peek() const noexcept
{
	const auto *slot = queue_->peek();
	return slot != nullptr ? *slot : nullptr;
}

bool boundary_future_output_hold::empty() const noexcept
{
	return queue_->empty();
}

std::size_t boundary_future_output_hold::size_approx() const noexcept
{
	return queue_->size_approx();
}

std::size_t boundary_future_output_hold::capacity() const noexcept
{
	return queue_->capacity();
}

uint32_t boundary_future_output_hold::boundary_index() const noexcept
{
	return boundary_index_;
}

uint32_t boundary_future_output_hold::sender_worker_index() const noexcept
{
	return sender_worker_index_;
}

int32_t boundary_future_output_hold::numa_node() const noexcept
{
	return numa_node_;
}

}  // namespace kinetum::dp
