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

#include "src/common/runtime_sizing.hpp"

namespace kinetum::dp
{

common::status_or<numa_owner<boundary_future_output_hold>>
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
	auto bytes_or = numa_spsc_ring<packet_record *>::required_element_bytes(facts.future_output_hold_capacity);
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	numa_layout layout;
	std::size_t root_offset = 0u;
	std::size_t elements_offset = 0u;
	if (!layout.append<boundary_future_output_hold>(1u, root_offset) ||
	    !layout.append<std::byte>(bytes_or.value(), elements_offset, algo::CACHE_LINE_SIZE)) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "boundary future-output hold layout overflows");
	}
	auto region_or = layout.allocate(sender_numa_node);
	if (!region_or.is_ok()) {
		return region_or.error();
	}
	auto region = std::move(region_or).value();
	auto *hold = new (numa_layout::storage<boundary_future_output_hold>(region, root_offset).data())
		boundary_future_output_hold(facts, region,
					    numa_layout::storage<std::byte>(region, elements_offset, bytes_or.value()));
	return adopt_numa_owner(hold, std::move(region));
}

boundary_future_output_hold::boundary_future_output_hold(const common::compiled_transition_boundary &facts,
							 const numa_memory_region &region,
							 std::span<std::byte> elements) noexcept
	: boundary_index_(facts.boundary_index)
	, sender_worker_index_(facts.sender_worker_index)
	, queue_(region, elements, facts.future_output_hold_capacity)
{
}

boundary_future_output_hold::~boundary_future_output_hold() = default;

std::size_t boundary_future_output_hold::try_hold(std::span<packet_record *const> records) noexcept
{
	if (records.size() > common::runtime_sizing::PACKET_MAX_BURST_SIZE) {
		std::terminate();
	}
	for (const auto *record : records) {
		if (record == nullptr) {
			std::terminate();
		}
	}
	return queue_.push_batch(records.data(), records.size());
}

bool boundary_future_output_hold::try_release(packet_record *&record) noexcept
{
	return queue_.try_pop(record);
}

const packet_record *boundary_future_output_hold::peek() const noexcept
{
	const auto *slot = queue_.peek();
	return slot != nullptr ? *slot : nullptr;
}

bool boundary_future_output_hold::empty() const noexcept
{
	return queue_.empty();
}

std::size_t boundary_future_output_hold::size_approx() const noexcept
{
	return queue_.size_approx();
}

std::size_t boundary_future_output_hold::capacity() const noexcept
{
	return queue_.capacity();
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
	return queue_.numa_node();
}

}  // namespace kinetum::dp
