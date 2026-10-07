// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file numa_memory.cpp
 * @brief Exact prefaulted anonymous-memory ownership implementation.
 * @author Fleming Patel
 */

#include "src/dp/numa_memory.hpp"

#include <climits>
#include <linux/mempolicy.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <utility>

#include "src/common/status.hpp"

namespace kinetum::dp
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_code;

/** @brief Transactional mapping guard used until all placement proofs pass. */
class mapping_guard final {
    public:
	/**
	 * @brief Adopt one exact anonymous mapping.
	 * @param mapping Sole mapping base transferred into this guard.
	 * @param mapping_bytes Exact mapped extent required by munmap.
	 */
	mapping_guard(void *mapping, std::size_t mapping_bytes) noexcept
		: mapping_(mapping)
		, mapping_bytes_(mapping_bytes)
	{
	}

	/** @brief Mapping guards cannot be copied. */
	mapping_guard(const mapping_guard &) = delete;
	/** @brief Mapping guards cannot be copy-assigned. */
	mapping_guard &operator=(const mapping_guard &) = delete;
	/** @brief Reclaim an uncommitted mapping exactly once. */
	~mapping_guard()
	{
		if (mapping_ != nullptr && ::munmap(mapping_, mapping_bytes_) != 0) {
			std::terminate();
		}
	}

	/** @brief Relinquish ownership after a completed region adopts the mapping. */
	void release() noexcept
	{
		mapping_ = nullptr;
		mapping_bytes_ = 0;
	}

    private:
	void *mapping_;		     ///< Mapping base owned until release.
	std::size_t mapping_bytes_;  ///< Exact mapping extent.
};

/**
 * @brief Round a nonnegative value up to one power-of-two alignment.
 *
 * @param value Value to round.
 * @param alignment Nonzero power-of-two alignment.
 * @param[out] rounded Exact rounded value on success.
 * @return true when the result is representable.
 */
[[nodiscard]] bool round_up_checked(std::size_t value, std::size_t alignment, std::size_t &rounded) noexcept
{
	const std::size_t mask = alignment - 1u;
	if (value > std::numeric_limits<std::size_t>::max() - mask) {
		return false;
	}
	rounded = (value + mask) & ~mask;
	return true;
}

}  // namespace

kinetum::common::status_or<numa_memory_region> numa_memory_region::allocate(const numa_memory_options &options)
{
	if (options.usable_bytes == 0) {
		return status(status_code::INVALID_ARGUMENT, "NUMA memory region has zero usable_bytes");
	}
	if (options.alignment_bytes == 0 || (options.alignment_bytes & (options.alignment_bytes - 1u)) != 0u) {
		return status(status_code::INVALID_ARGUMENT,
			      "NUMA memory region alignment_bytes must be a nonzero power of two");
	}
	if (options.host_numa_node.has_value() && options.host_numa_node.value() < 0) {
		return status(status_code::INVALID_ARGUMENT, "NUMA memory region host node must be nonnegative");
	}

	const long page_size_result = ::sysconf(_SC_PAGESIZE);
	if (page_size_result <= 0) {
		return status(status_code::FAILED_PRECONDITION, "NUMA memory region cannot determine Linux page size");
	}
	const auto page_size = static_cast<std::size_t>(page_size_result);
	if ((page_size & (page_size - 1u)) != 0u) {
		return status(status_code::FAILED_PRECONDITION,
			      "NUMA memory region requires a power-of-two Linux page size");
	}
	// mmap already returns a page-aligned base. Because both alignments are
	// powers of two, no slack is needed at or below page alignment; above it,
	// the largest possible gap is one requested alignment minus one page.
	const std::size_t alignment_slack = options.alignment_bytes > page_size ? options.alignment_bytes - page_size :
										  0u;
	if (options.usable_bytes > std::numeric_limits<std::size_t>::max() - alignment_slack) {
		return status(status_code::OUT_OF_RANGE, "NUMA memory region alignment overflows size_t");
	}
	std::size_t mapping_bytes = 0;
	if (!round_up_checked(options.usable_bytes + alignment_slack, page_size, mapping_bytes)) {
		return status(status_code::OUT_OF_RANGE, "NUMA memory region mapping extent overflows size_t");
	}

	void *mapping = ::mmap(nullptr, mapping_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED) {
		return status(status_code::RESOURCE_EXHAUSTED, "NUMA memory region anonymous mapping failed");
	}
	mapping_guard guard(mapping, mapping_bytes);

	const auto mapping_address = reinterpret_cast<std::uintptr_t>(mapping);
	if (mapping_bytes > std::numeric_limits<std::uintptr_t>::max() - mapping_address) {
		return status(status_code::OUT_OF_RANGE, "NUMA memory region mapping end overflows uintptr_t");
	}
	const auto mapping_end = mapping_address + mapping_bytes;
	const auto alignment_mask = static_cast<std::uintptr_t>(options.alignment_bytes - 1u);
	if (mapping_address > std::numeric_limits<std::uintptr_t>::max() - alignment_mask) {
		return status(status_code::OUT_OF_RANGE, "NUMA memory region aligned address overflows uintptr_t");
	}
	const auto usable_address = (mapping_address + alignment_mask) & ~alignment_mask;
	std::size_t policy_bytes = 0;
	if (!round_up_checked(options.usable_bytes, page_size, policy_bytes) || usable_address > mapping_end ||
	    policy_bytes > mapping_end - usable_address) {
		return status(status_code::INTERNAL_ERROR,
			      "NUMA memory mapping cannot contain its aligned usable range");
	}
	auto *usable = reinterpret_cast<void *>(usable_address);

	std::unique_ptr<unsigned long[]> node_mask;
	unsigned long max_node = 0;
	if (options.host_numa_node.has_value()) {
		constexpr std::size_t BITS_PER_MASK_WORD = sizeof(unsigned long) * CHAR_BIT;
		if (page_size > std::numeric_limits<std::size_t>::max() / CHAR_BIT) {
			return status(status_code::OUT_OF_RANGE, "NUMA memory kernel nodemask bound overflows size_t");
		}
		const std::size_t kernel_max_node_bits = page_size * CHAR_BIT;
		const auto node = static_cast<std::size_t>(options.host_numa_node.value());
		if (node > std::numeric_limits<std::size_t>::max() - 2u) {
			return status(status_code::OUT_OF_RANGE,
				      "NUMA memory host node overflows the Linux nodemask ABI");
		}

		// Linux interprets maxnode - 1 represented bits. Pass the required
		// trailing extent so node zero never collapses to an empty nodemask.
		const std::size_t represented_node_bits = node + 1u;
		const std::size_t syscall_max_node = represented_node_bits + 1u;
		if (represented_node_bits > kernel_max_node_bits ||
		    syscall_max_node > static_cast<std::size_t>(std::numeric_limits<unsigned long>::max())) {
			return status(status_code::OUT_OF_RANGE,
				      "NUMA memory host node exceeds the Linux nodemask bound");
		}
		if (represented_node_bits > std::numeric_limits<std::size_t>::max() - (BITS_PER_MASK_WORD - 1u)) {
			return status(status_code::OUT_OF_RANGE, "NUMA memory nodemask extent overflows size_t");
		}
		const std::size_t mask_words = (represented_node_bits + BITS_PER_MASK_WORD - 1u) / BITS_PER_MASK_WORD;
		node_mask.reset(new (std::nothrow) unsigned long[mask_words]());
		if (node_mask == nullptr) {
			return status(status_code::RESOURCE_EXHAUSTED, "NUMA memory nodemask allocation failed");
		}
		node_mask[node / BITS_PER_MASK_WORD] |= 1ul << (node % BITS_PER_MASK_WORD);
		max_node = static_cast<unsigned long>(syscall_max_node);
		const int mode = MPOL_BIND | MPOL_F_STATIC_NODES;
		if (::syscall(SYS_mbind, usable, policy_bytes, mode, node_mask.get(), max_node, 0ul) != 0) {
			return status(status_code::FAILED_PRECONDITION, "NUMA memory cannot bind the exact host node");
		}
	}

	// The cold owner faults every usable page before publication so packet
	// execution never pays an anonymous-page fault for this region.
	std::memset(usable, 0, options.usable_bytes);
	if (options.host_numa_node.has_value()) {
		const int mode = MPOL_BIND | MPOL_F_STATIC_NODES;
		if (::syscall(SYS_mbind, usable, policy_bytes, mode, node_mask.get(), max_node,
			      static_cast<unsigned long>(MPOL_MF_STRICT)) != 0) {
			return status(status_code::FAILED_PRECONDITION,
				      "NUMA memory resident pages violate exact host placement");
		}
	}

	numa_memory_region region(mapping, mapping_bytes, usable, options.usable_bytes, options.host_numa_node);
	guard.release();
	return region;
}

numa_memory_region::numa_memory_region(void *mapping, std::size_t mapping_bytes, void *usable, std::size_t usable_bytes,
				       std::optional<int32_t> host_numa_node) noexcept
	: mapping_(mapping)
	, mapping_bytes_(mapping_bytes)
	, usable_(usable)
	, usable_bytes_(usable_bytes)
	, host_numa_node_(host_numa_node)
{
}

numa_memory_region::numa_memory_region(numa_memory_region &&other) noexcept
	: mapping_(std::exchange(other.mapping_, nullptr))
	, mapping_bytes_(std::exchange(other.mapping_bytes_, 0))
	, usable_(std::exchange(other.usable_, nullptr))
	, usable_bytes_(std::exchange(other.usable_bytes_, 0))
	, host_numa_node_(std::exchange(other.host_numa_node_, std::nullopt))
{
}

numa_memory_region &numa_memory_region::operator=(numa_memory_region &&other) noexcept
{
	if (this != &other) {
		reset_();
		mapping_ = std::exchange(other.mapping_, nullptr);
		mapping_bytes_ = std::exchange(other.mapping_bytes_, 0);
		usable_ = std::exchange(other.usable_, nullptr);
		usable_bytes_ = std::exchange(other.usable_bytes_, 0);
		host_numa_node_ = std::exchange(other.host_numa_node_, std::nullopt);
	}
	return *this;
}

numa_memory_region::~numa_memory_region()
{
	reset_();
}

void numa_memory_region::reset_() noexcept
{
	if (mapping_ != nullptr && ::munmap(mapping_, mapping_bytes_) != 0) {
		std::terminate();
	}
	mapping_ = nullptr;
	mapping_bytes_ = 0;
	usable_ = nullptr;
	usable_bytes_ = 0;
	host_numa_node_.reset();
}

}  // namespace kinetum::dp
