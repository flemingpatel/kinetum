// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file numa_memory.hpp
 * @brief Exact prefaulted anonymous-memory ownership for packet-runtime storage.
 * @author Fleming Patel
 *
 * This mechanism owns one aligned anonymous mapping and, when requested,
 * proves strict Linux NUMA placement before returning it to a packet-runtime
 * owner. Allocation, policy installation, prefault, and resident-page proof
 * are cold-path operations. No packet-path operation is exposed here.
 *
 * @par Thread Safety
 * One cold-path owner constructs, moves, and destroys a region. Callers may
 * publish the immutable address and extent only after construction succeeds;
 * destruction requires every borrower to be quiescent.
 */

#include <cstddef>
#include <cstdint>
#include <optional>

#include "src/common/status_or.hpp"

namespace kinetum::dp
{

/** @brief Exact allocation contract for one packet-runtime memory region. */
struct numa_memory_options {
	std::size_t usable_bytes{0};	 ///< Exact usable byte extent.
	std::size_t alignment_bytes{0};	 ///< Nonzero power-of-two usable-address alignment.
	/** Exact Linux memory node; absent only when the owning contract permits ordinary host placement. */
	std::optional<int32_t> host_numa_node;
};

/** @brief Move-only owner of one aligned, prefaulted anonymous mapping. */
class numa_memory_region final {
    public:
	/**
	 * @brief Allocate, optionally bind, prefault, and prove one exact region.
	 *
	 * @param options Exact usable extent, alignment, and optional NUMA node.
	 * @return Completed region, or a fail-closed validation/allocation status.
	 */
	[[nodiscard]] static kinetum::common::status_or<numa_memory_region>
	allocate(const numa_memory_options &options);

	/** @brief Construct an empty region with no mapping ownership. */
	numa_memory_region() noexcept = default;
	/** @brief Reject copying because one mapping has one reclamation owner. */
	numa_memory_region(const numa_memory_region &) = delete;
	/** @brief Reject copy assignment because one mapping has one reclamation owner. */
	numa_memory_region &operator=(const numa_memory_region &) = delete;
	/**
	 * @brief Transfer the complete mapping and usable-range identity.
	 *
	 * @param other Sole source owner, left empty after transfer.
	 */
	numa_memory_region(numa_memory_region &&other) noexcept;
	/**
	 * @brief Reclaim the current mapping, then transfer one complete identity.
	 *
	 * @param other Sole source owner, left empty after transfer.
	 * @return This replacement owner.
	 */
	numa_memory_region &operator=(numa_memory_region &&other) noexcept;
	/** @brief Reclaim the exact mapping; a failed kernel reclamation fails stop. */
	~numa_memory_region();

	/** @return Aligned first usable byte, or null for an empty owner. */
	[[nodiscard]] void *data() noexcept
	{
		return usable_;
	}

	/** @return Aligned first usable byte, or null for an empty owner. */
	[[nodiscard]] const void *data() const noexcept
	{
		return usable_;
	}

	/** @return Exact usable byte extent. */
	[[nodiscard]] std::size_t size() const noexcept
	{
		return usable_bytes_;
	}

	/** @return Exact requested NUMA node, or no value for ordinary host placement. */
	[[nodiscard]] const std::optional<int32_t> &host_numa_node() const noexcept
	{
		return host_numa_node_;
	}

	/** @return true when this owner contains one completed mapping. */
	[[nodiscard]] explicit operator bool() const noexcept
	{
		return mapping_ != nullptr;
	}

    private:
	/**
	 * @brief Construct one already validated and proven mapping owner.
	 *
	 * @param mapping Page-aligned mmap base and sole reclamation identity.
	 * @param mapping_bytes Exact munmap extent.
	 * @param usable First requested-alignment usable byte within @p mapping.
	 * @param usable_bytes Exact caller-visible byte extent.
	 * @param host_numa_node Exact proven placement constraint when present.
	 */
	numa_memory_region(void *mapping, std::size_t mapping_bytes, void *usable, std::size_t usable_bytes,
			   std::optional<int32_t> host_numa_node) noexcept;

	/** @brief Reclaim current ownership and return to the empty state. */
	void reset_() noexcept;

	void *mapping_{nullptr};		 ///< Page-aligned base returned by mmap.
	std::size_t mapping_bytes_{0};		 ///< Exact munmap extent.
	void *usable_{nullptr};			 ///< Requested-alignment first usable byte.
	std::size_t usable_bytes_{0};		 ///< Exact usable extent.
	std::optional<int32_t> host_numa_node_;	 ///< Exact placement constraint when present.
};

}  // namespace kinetum::dp
