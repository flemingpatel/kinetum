// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_input_scheduler.cpp
 * @brief Cold construction of exact worker-local fair admission state.
 * @author Fleming Patel
 */

#include "src/dp/worker_input_scheduler.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
#include <new>
#include <tuple>
#include <utility>

#include <kinetum/algo/platform.hpp>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"

namespace kinetum::dp
{

common::status_or<numa_owner<worker_input_scheduler>>
worker_input_scheduler::create(std::span<const worker_input_binding> bindings, int32_t numa_node)
{
	using order_type = algo::bounded_service_order;
	using entry_type = order_type::entry;
	static_assert(std::is_trivially_destructible_v<worker_input_endpoint>);
	static_assert(std::is_trivially_destructible_v<entry_type>);
	if (numa_node < 0 || bindings.size() >= std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"input schedule requires an exact NUMA node and compact population");
	}
	for (std::size_t index = 0; index < bindings.size(); ++index) {
		const auto &binding = bindings[index];
		if ((binding.endpoint.kind != worker_input_kind::RX_STREAM &&
		     binding.endpoint.kind != worker_input_kind::BOUNDARY) ||
		    binding.endpoint.ordinal == std::numeric_limits<uint32_t>::max() || binding.quantum == 0u ||
		    binding.quantum > common::runtime_sizing::PACKET_MAX_BURST_SIZE) {
			return common::status::invalid_argument(
				"input schedule contains an invalid endpoint or burst ceiling");
		}
		if (index != 0u) {
			const auto &previous = bindings[index - 1u].endpoint;
			if (std::tie(previous.kind, previous.ordinal) >=
			    std::tie(binding.endpoint.kind, binding.endpoint.ordinal)) {
				return common::status::invalid_argument(
					"input schedule endpoints are not sorted and unique");
			}
		}
	}

	numa_layout layout;
	std::size_t root_offset = 0u;
	std::size_t order_offset = 0u;
	std::size_t endpoints_offset = 0u;
	std::size_t entries_offset = 0u;
	if (!layout.append<worker_input_scheduler>(1u, root_offset) ||
	    !layout.append<order_type>(bindings.empty() ? 0u : 1u, order_offset) ||
	    !layout.append<worker_input_endpoint>(bindings.size(), endpoints_offset) ||
	    !layout.append<entry_type>(bindings.size(), entries_offset)) {
		return common::status(common::status_code::OUT_OF_RANGE, "input schedule storage extent overflows");
	}
	auto storage_or = layout.allocate(numa_node);
	if (!storage_or.is_ok()) {
		return storage_or.error();
	}
	auto storage = std::move(storage_or).value();
	auto endpoints = numa_layout::storage<worker_input_endpoint>(storage, endpoints_offset, bindings.size());
	auto entries = numa_layout::storage<entry_type>(storage, entries_offset, bindings.size());
	for (std::size_t index = 0u; index < bindings.size(); ++index) {
		std::construct_at(&endpoints[index], bindings[index].endpoint);
		std::construct_at(&entries[index], bindings[index].quantum);
	}
	order_type *order = nullptr;
	if (!bindings.empty()) {
		order = std::construct_at(numa_layout::storage<order_type>(storage, order_offset).data(), entries);
	}
	auto *owner = new (numa_layout::storage<worker_input_scheduler>(storage, root_offset).data())
		worker_input_scheduler(order, endpoints);
	return adopt_numa_owner(owner, std::move(storage));
}

worker_input_scheduler::worker_input_scheduler(algo::bounded_service_order *order,
					       std::span<const worker_input_endpoint> endpoints) noexcept
	: order_(order)
	, endpoints_(endpoints)
{
}

worker_input_scheduler::~worker_input_scheduler()
{
	if (order_ != nullptr) {
		std::destroy_at(order_);
	}
}

}  // namespace kinetum::dp
