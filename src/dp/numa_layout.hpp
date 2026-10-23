// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file numa_layout.hpp
 * @brief Checked typed extents and object ownership over exact NUMA mappings.
 * @author Fleming Patel
 *
 * Cold builders append fixed extents before allocating. Subsystem owners keep
 * object lifetimes explicit; this mechanism stores no destructor registry and
 * performs no packet-path allocation. The mapping owner outlives every object
 * constructed in its range, including the root object itself.
 */

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <span>
#include <type_traits>
#include <utility>

#include <kinetum/algo/cache.hpp>

#include "src/common/status.hpp"
#include "src/dp/numa_memory.hpp"

namespace kinetum::dp
{

/**
 * @brief Accumulate one checked allocation geometry without acquiring storage.
 *
 * One cold owner appends extents, allocates once, then placement-constructs
 * the described objects. Failed append operations leave every output intact.
 * Byte offsets belong here; subsystem code consumes typed spans.
 */
class numa_layout final {
    public:
	/**
	 * @brief Append one contiguous typed extent.
	 * @tparam value_type Object type defining element size and minimum alignment.
	 * @param count Exact element population; zero adds no storage.
	 * @param[out] offset First element's byte offset on success.
	 * @param alignment Required power-of-two alignment, at least the type alignment.
	 * @return True only after representable alignment and extent addition.
	 */
	template <typename value_type>
	[[nodiscard]] bool append(std::size_t count, std::size_t &offset,
				  std::size_t alignment = alignof(value_type)) noexcept
	{
		constexpr auto MAXIMUM = std::numeric_limits<std::size_t>::max();
		if (alignment < alignof(value_type) || !std::has_single_bit(alignment)) {
			return false;
		}
		if (count == 0u) {
			offset = size_;
			return true;
		}
		std::size_t start = 0u;
		if (!align_(size_, alignment, start) || count > (MAXIMUM - start) / sizeof(value_type)) {
			return false;
		}
		size_ = start + count * sizeof(value_type);
		alignment_ = std::max(alignment_, alignment);
		offset = start;
		return true;
	}

	/**
	 * @brief Append equal-sized rows whose starts satisfy an explicit alignment.
	 * @tparam value_type Exact row element type.
	 * @param rows Row population.
	 * @param columns Elements per row.
	 * @param[out] offset First row's byte offset on success.
	 * @param[out] stride Aligned byte distance between row starts, zero for an empty population.
	 * @param alignment Required row alignment, at least the type alignment.
	 * @return True only after checked multiplication, alignment and addition.
	 */
	template <typename value_type>
	[[nodiscard]] bool append_rows(std::size_t rows, std::size_t columns, std::size_t &offset, std::size_t &stride,
				       std::size_t alignment = alignof(value_type)) noexcept
	{
		constexpr auto MAXIMUM = std::numeric_limits<std::size_t>::max();
		if (alignment < alignof(value_type) || !std::has_single_bit(alignment)) {
			return false;
		}
		if (rows == 0u || columns == 0u) {
			offset = size_;
			stride = 0u;
			return true;
		}
		if (columns > MAXIMUM / sizeof(value_type)) {
			return false;
		}
		std::size_t start = 0u;
		std::size_t row_stride = 0u;
		if (!align_(size_, alignment, start) || !align_(columns * sizeof(value_type), alignment, row_stride) ||
		    rows > (MAXIMUM - start) / row_stride) {
			return false;
		}
		size_ = start + rows * row_stride;
		alignment_ = std::max(alignment_, alignment);
		offset = start;
		stride = row_stride;
		return true;
	}

	/**
	 * @brief Materialize this complete nonempty geometry on one exact node.
	 * @param numa_node Nonnegative compiled owner node; no default placement exists.
	 * @return Bound, prefaulted and residency-checked storage, or the exact cold error.
	 */
	[[nodiscard]] common::status_or<numa_memory_region> allocate(int32_t numa_node) const noexcept
	{
		return allocate(numa_node, [](const numa_memory_options &options) noexcept {
			return numa_memory_region::allocate(options);
		});
	}

	/**
	 * @brief Acquire the same checked extent through an existing cold ownership adapter.
	 *
	 * The adapter preserves its own allocation token and accounting. Its
	 * production implementation must prove the exact requested placement before
	 * returning; this overload supplies geometry, never an alternate node.
	 *
	 * @tparam acquire_type Cold callable returning a status-or allocation owner/block.
	 * @param numa_node Exact compiled node.
	 * @param acquire Existing allocation authority receiving the complete options.
	 * @return The adapter's exact result, or shape rejection before its first call.
	 */
	template <typename acquire_type>
	[[nodiscard]] auto allocate(int32_t numa_node, acquire_type &&acquire) const
		noexcept(std::is_nothrow_invocable_v<acquire_type &, const numa_memory_options &>)
			-> std::invoke_result_t<acquire_type &, const numa_memory_options &>
	{
		if (numa_node < 0 || size_ == 0u) {
			return common::status::invalid_argument(
				common::static_status_text("NUMA layout requires an exact node and nonempty extent"));
		}
		return std::invoke(acquire, numa_memory_options{size_, alignment_, numa_node});
	}

	/** @return Maximum alignment required by any appended extent. */
	[[nodiscard]] std::size_t alignment() const noexcept
	{
		return alignment_;
	}

	/** @return Complete checked usable byte extent, including explicit row padding. */
	[[nodiscard]] std::size_t size() const noexcept
	{
		return size_;
	}

	/**
	 * @brief Resolve one typed storage extent after checking its exact mapping bounds.
	 *
	 * This operation does not start element lifetimes. The caller constructs the
	 * complete required prefix before reading its values or publishing the span.
	 *
	 * @tparam value_type Exact representation of each element.
	 * @param region Completed mapping retained by the cold owner.
	 * @param offset Checked byte offset from the layout.
	 * @param count Element population; zero returns an empty span.
	 * @return Exact aligned typed storage, or termination for a construction contradiction.
	 */
	template <typename value_type>
	[[nodiscard]] static std::span<value_type> storage(numa_memory_region &region, std::size_t offset,
							   std::size_t count = 1u) noexcept
	{
		return storage<value_type>(std::span<std::byte>(static_cast<std::byte *>(region.data()), region.size()),
					   offset, count);
	}

	/**
	 * @brief Resolve storage supplied by an admitted cold allocation adapter.
	 * @tparam value_type Exact element type.
	 * @param region Complete byte extent after allocator identity and placement validation.
	 * @param offset Checked layout offset.
	 * @param count Exact element population; zero returns an empty span.
	 * @return Aligned contained storage; object lifetimes remain with the caller.
	 */
	template <typename value_type>
	[[nodiscard]] static std::span<value_type> storage(std::span<std::byte> region, std::size_t offset,
							   std::size_t count = 1u) noexcept
	{
		if (count == 0u) {
			return {};
		}
		if (region.data() == nullptr || offset > region.size() ||
		    count > (region.size() - offset) / sizeof(value_type)) {
			std::terminate();
		}
		auto *address = region.data() + offset;
		if (reinterpret_cast<std::uintptr_t>(address) % alignof(value_type) != 0u) {
			std::terminate();
		}
		return {reinterpret_cast<value_type *>(address), count};
	}

	/**
	 * @brief Resolve one separately aligned row through the same bounds authority.
	 * @tparam value_type Exact row element type.
	 * @param region Complete mapping owner.
	 * @param offset First row's checked offset.
	 * @param stride Checked physical byte stride.
	 * @param row Zero-based selected row.
	 * @param rows Exact population reserved by append_rows().
	 * @param columns Exact elements in the selected row.
	 * @return The row's typed storage; empty rows consume no bytes.
	 */
	template <typename value_type>
	[[nodiscard]] static std::span<value_type> row(numa_memory_region &region, std::size_t offset,
						       std::size_t stride, std::size_t row, std::size_t rows,
						       std::size_t columns) noexcept
	{
		if (row >= rows) {
			std::terminate();
		}
		if (columns == 0u) {
			return {};
		}
		if (stride == 0u || offset > region.size() || rows > (region.size() - offset) / stride ||
		    columns > stride / sizeof(value_type)) {
			std::terminate();
		}
		return storage<value_type>(region, offset + row * stride, columns);
	}

	/**
	 * @brief Prove one constructed object lies entirely inside its allocation.
	 * @tparam value_type Exact complete object type.
	 * @param region Sole mapping owner.
	 * @param object Candidate constructed object.
	 * @return True only for a nonnull aligned complete object within the usable extent.
	 */
	template <typename value_type>
	[[nodiscard]] static bool contains(const numa_memory_region &region, const value_type *object) noexcept
	{
		return contains(std::span<const std::byte>(static_cast<const std::byte *>(region.data()),
							   region.size()),
				object);
	}

	/**
	 * @brief Validate a constructed root against its admitted adapter's byte extent.
	 * @tparam value_type Exact complete root type.
	 * @param region Full live allocation extent.
	 * @param object Candidate root.
	 * @return True only for a complete aligned object contained by the extent.
	 */
	template <typename value_type>
	[[nodiscard]] static bool contains(std::span<const std::byte> region, const value_type *object) noexcept
	{
		const auto base = reinterpret_cast<std::uintptr_t>(region.data());
		const auto address = reinterpret_cast<std::uintptr_t>(object);
		return region.data() != nullptr && object != nullptr && address % alignof(value_type) == 0u &&
		       address >= base && address - base <= region.size() &&
		       sizeof(value_type) <= region.size() - (address - base);
	}

	/**
	 * @brief Prove a borrowed byte extent belongs entirely to one live allocation.
	 * @param region Exact mapping owner.
	 * @param extent Candidate byte range; empty ranges own no storage.
	 * @return True only for complete containment without address-addition overflow.
	 */
	[[nodiscard]] static bool contains_extent(const numa_memory_region &region,
						  std::span<const std::byte> extent) noexcept
	{
		if (extent.empty()) {
			return true;
		}
		const auto base = reinterpret_cast<std::uintptr_t>(region.data());
		const auto address = reinterpret_cast<std::uintptr_t>(extent.data());
		return region && extent.data() != nullptr && address >= base && address - base <= region.size() &&
		       extent.size() <= region.size() - (address - base);
	}

	/**
	 * @brief Prove two constructed/storage extents cannot overlap.
	 * @param left First complete byte extent.
	 * @param right Second complete byte extent.
	 * @return True for disjoint ranges, including either empty range.
	 */
	[[nodiscard]] static bool disjoint(std::span<const std::byte> left, std::span<const std::byte> right) noexcept
	{
		if (left.empty() || right.empty()) {
			return true;
		}
		const auto first = reinterpret_cast<std::uintptr_t>(left.data());
		const auto second = reinterpret_cast<std::uintptr_t>(right.data());
		return first <= second ? left.size() <= second - first : right.size() <= first - second;
	}

    private:
	/**
	 * @brief Round one extent to its validated power-of-two alignment.
	 * @param value Unaligned extent.
	 * @param alignment Nonzero power-of-two alignment.
	 * @param[out] result Representable rounded extent on success.
	 * @return False without changing the output when addition would overflow.
	 */
	[[nodiscard]] static bool align_(std::size_t value, std::size_t alignment, std::size_t &result) noexcept
	{
		if (value > std::numeric_limits<std::size_t>::max() - (alignment - 1u)) {
			return false;
		}
		result = (value + alignment - 1u) & ~(alignment - 1u);
		return true;
	}

	std::size_t size_{0u};				///< Complete checked layout end.
	std::size_t alignment_{algo::CACHE_LINE_SIZE};	///< Maximum required allocation alignment.
};

/**
 * @brief Destroy a root while its full mapping is still alive, then reclaim the mapping.
 * @tparam value_type Complete root type whose nonthrowing destructor retires its owned typed arrays.
 */
template <typename value_type>
struct numa_object_deleter {
	numa_memory_region region;  ///< Sole mapping, outside the placement-constructed root.

	/** @brief Construct empty reclamation state for an empty owner. */
	numa_object_deleter() noexcept = default;
	/** @param allocation Complete mapping whose already-constructed root this deleter will retire. */
	explicit numa_object_deleter(numa_memory_region allocation) noexcept
		: region(std::move(allocation))
	{
	}
	/** @brief Mapping reclamation cannot be duplicated. */
	numa_object_deleter(const numa_object_deleter &) = delete;
	/** @brief Mapping reclamation cannot be copied over an existing owner. */
	numa_object_deleter &operator=(const numa_object_deleter &) = delete;
	/** @brief Transfer the mapping and leave the source empty. */
	numa_object_deleter(numa_object_deleter &&) noexcept = default;
	/** @param other Sole source. @return This empty-or-self destination after transfer. */
	numa_object_deleter &operator=(numa_object_deleter &&other) noexcept
	{
		if (this != &other) {
			if (region) {
				std::terminate();
			}
			region = std::move(other.region);
		}
		return *this;
	}
	/** @brief An abandoned root may not silently lose its backing mapping. */
	~numa_object_deleter()
	{
		if (region) {
			std::terminate();
		}
	}

	/** @param object Sole live root; its existing quiescence contract governs destruction. */
	void operator()(value_type *object) noexcept
	{
		static_assert(std::is_nothrow_destructible_v<value_type>);
		if (!numa_layout::contains(region, object)) {
			std::terminate();
		}
		std::destroy_at(object);
		region = numa_memory_region{};
	}
};

/** @brief Standard move-only object ownership with exact NUMA mapping retirement. */
template <typename value_type>
using numa_owner = std::unique_ptr<value_type, numa_object_deleter<value_type>>;

/**
 * @brief Transfer a complete mapped root and its allocation to one typed owner.
 * @tparam value_type Constructed root type.
 * @param object Exact root whose destructor owns nested object retirement.
 * @param region Completed mapping transferred only after the root is constructed.
 * @return Sole cold owner; packet callers borrow its unchanged direct pointer.
 */
template <typename value_type>
[[nodiscard]] numa_owner<value_type> adopt_numa_owner(value_type *object, numa_memory_region region) noexcept
{
	if (!numa_layout::contains(region, object) || !region.host_numa_node().has_value()) {
		std::terminate();
	}
	return numa_owner<value_type>(object, numa_object_deleter<value_type>{std::move(region)});
}

/**
 * @brief Construct one fixed-size root using the shared checked layout mechanism.
 * @tparam value_type Exact root type.
 * @tparam construct_type Nonthrowing placement constructor callable.
 * @param numa_node Exact admitted owner node.
 * @param construct Constructs and returns one root at the supplied address.
 * @return Complete owner or exact mapping refusal; no root exists on refusal.
 */
template <typename value_type, typename construct_type>
[[nodiscard]] common::status_or<numa_owner<value_type>> make_numa_owner(int32_t numa_node,
									construct_type &&construct) noexcept
{
	static_assert(std::is_nothrow_invocable_r_v<value_type *, construct_type &, void *>);
	numa_layout layout;
	std::size_t offset = 0u;
	if (!layout.append<value_type>(1u, offset)) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      common::static_status_text("NUMA root layout overflows"));
	}
	auto region_or = layout.allocate(numa_node);
	if (!region_or.is_ok()) {
		return std::move(region_or).error();
	}
	auto region = std::move(region_or).value();
	void *address = numa_layout::storage<value_type>(region, offset).data();
	auto *object = std::invoke(construct, address);
	if (object != address) {
		std::terminate();
	}
	return adopt_numa_owner(object, std::move(region));
}

}  // namespace kinetum::dp
