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
#include <new>
#include <optional>
#include <tuple>
#include <utility>

#include <kinetum/algo/platform.hpp>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"

namespace kinetum::dp
{
namespace
{

/**
 * @brief Append one aligned cell per input without overflowing the storage size.
 * @tparam value_type Exact cell type determining size and alignment.
 * @param bindings Sole input population shared by all schedule tables.
 * @param[in,out] extent Current total, changed only on success.
 * @return Aligned array offset, or no value when the complete extent overflows.
 */
template <typename value_type>
[[nodiscard]] std::optional<std::size_t> append_extent(std::span<const worker_input_binding> bindings,
						       std::size_t &extent) noexcept
{
	constexpr auto MAXIMUM = std::numeric_limits<std::size_t>::max();
	constexpr auto ALIGNMENT = alignof(value_type);
	if (extent > MAXIMUM - (ALIGNMENT - 1u)) {
		return std::nullopt;
	}
	const std::size_t aligned = (extent + ALIGNMENT - 1u) & ~(ALIGNMENT - 1u);
	if (bindings.size() > (MAXIMUM - aligned) / sizeof(value_type)) {
		return std::nullopt;
	}
	extent = aligned + bindings.size() * sizeof(value_type);
	return aligned;
}

}  // namespace

common::status_or<std::unique_ptr<worker_input_scheduler>>
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

	numa_memory_region storage;
	order_type *order = nullptr;
	std::span<const worker_input_endpoint> endpoints;
	if (!bindings.empty()) {
		std::size_t extent = sizeof(order_type);
		const auto endpoint_offset = append_extent<worker_input_endpoint>(bindings, extent);
		const auto entry_offset = append_extent<entry_type>(bindings, extent);
		if (!endpoint_offset.has_value() || !entry_offset.has_value()) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "input schedule storage extent overflows");
		}
		auto storage_or = numa_memory_region::allocate({
			.usable_bytes = extent,
			.alignment_bytes =
				std::max({static_cast<std::size_t>(algo::CACHE_LINE_SIZE), alignof(order_type),
					  alignof(worker_input_endpoint), alignof(entry_type)}),
			.host_numa_node = numa_node,
		});
		if (!storage_or.is_ok()) {
			return storage_or.error();
		}
		storage = std::move(storage_or).value();
		auto *base = static_cast<std::byte *>(storage.data());
		auto *endpoint_data = reinterpret_cast<worker_input_endpoint *>(base + endpoint_offset.value());
		auto *entry_data = reinterpret_cast<entry_type *>(base + entry_offset.value());
		for (std::size_t index = 0u; index < bindings.size(); ++index) {
			std::construct_at(endpoint_data + index, bindings[index].endpoint);
			std::construct_at(entry_data + index, bindings[index].quantum);
		}
		// The complete population and every quantum were proved before mapping.
		order = std::construct_at(static_cast<order_type *>(storage.data()),
					  std::span<entry_type>(entry_data, bindings.size()));
		endpoints = {endpoint_data, bindings.size()};
	}
	auto *owner = new (std::nothrow) worker_input_scheduler(std::move(storage), order, endpoints);
	if (owner == nullptr) {
		if (order != nullptr) {
			std::destroy_at(order);
		}
		return common::status::resource_exhausted("input schedule owner allocation failed");
	}
	return std::unique_ptr<worker_input_scheduler>(owner);
}

worker_input_scheduler::worker_input_scheduler(numa_memory_region storage, algo::bounded_service_order *order,
					       std::span<const worker_input_endpoint> endpoints) noexcept
	: storage_(std::move(storage))
	, order_(order)
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
