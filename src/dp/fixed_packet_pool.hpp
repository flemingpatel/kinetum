// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file fixed_packet_pool.hpp
 * @brief Fixed-capacity host packet storage domain for UDP/dev and tests.
 * @author Fleming Patel
 *
 * The pool allocates its complete record population, payload backing, and free
 * index bitmap before packet admission. Acquires, writable clones, origin copies, and
 * burst retirement perform no allocation or locking. Each payload slot begins
 * on a cache-line boundary so concurrent owners never share writable payload
 * cache lines merely because the configured maximum length is unaligned.
 *
 * @par Thread Safety
 * Atomic availability bits permit concurrent acquisition and retirement of
 * distinct records; each acquired record still has one exact owner. Destruction
 * requires complete quiescence and zero outstanding records.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include <kinetum/algo/atomic_index_pool.hpp>
#include "src/common/status_or.hpp"
#include "src/dp/numa_memory.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

/** @brief Construction contract for one fixed host storage domain. */
struct fixed_packet_pool_options {
	uint32_t record_count{0};			///< Exact logical packet-credit population.
	uint32_t data_room_bytes{0};			///< Authored data-room size, including headroom.
	uint32_t headroom_bytes{0};			///< Authored headroom before aligned packet data.
	uint32_t alignment_bytes{0};			///< Exact record and packet-data alignment.
	uint16_t domain_index{INVALID_STORAGE_DOMAIN};	///< Compiled storage-domain index.
	uint32_t generation{1};				///< Nonzero materialization generation.
	/** Exact Linux memory node for index controls, words, records and payload; negative rejects. */
	int32_t host_numa_node{-1};
};

/** @brief Fixed, concurrently reclaimable packet-record and payload pool. */
class fixed_packet_pool final {
    public:
	/**
	 * @brief Construct and seed one complete fixed pool transactionally.
	 *
	 * @param options Exact pool shape.
	 * @return Owned pool, or a fail-closed validation/allocation status.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<fixed_packet_pool>>
	create(const fixed_packet_pool_options &options);

	/** @brief Disable copying because each record credit has one storage owner. */
	fixed_packet_pool(const fixed_packet_pool &) = delete;
	/** @brief Disable copy assignment because storage-domain identity is unique. */
	fixed_packet_pool &operator=(const fixed_packet_pool &) = delete;
	/** @brief Disable moving so published operation-state pointers remain stable. */
	fixed_packet_pool(fixed_packet_pool &&) = delete;
	/** @brief Disable move assignment so record and payload addresses never change. */
	fixed_packet_pool &operator=(fixed_packet_pool &&) = delete;
	/** @brief Destroy a quiescent pool; outstanding ownership is a fatal invariant violation. */
	~fixed_packet_pool();

	/**
	 * @brief Return the immutable storage operation record owned by this pool.
	 *
	 * @return Borrowed record valid for the complete pool lifetime.
	 */
	[[nodiscard]] const packet_storage_domain_operations &operations() const noexcept
	{
		return operations_;
	}

	/**
	 * @brief Acquire and initialize up to capacity records.
	 *
	 * @param records Destination record-pointer array.
	 * @param capacity Maximum records to acquire.
	 * @return Exact acquired prefix length; exhaustion or contention may shorten it.
	 */
	[[nodiscard]] uint16_t acquire_burst(packet_record **records, uint16_t capacity) noexcept;

	/** @return Exact logical record population admitted at construction. */
	[[nodiscard]] uint32_t capacity() const noexcept
	{
		return options_.record_count;
	}

	/** @return Cold O(words) in-use observation, bounded by capacity; exact after quiescence. */
	[[nodiscard]] uint32_t outstanding() const noexcept;

	/** @return Cold O(words) free-population scan; approximate concurrently, exact after quiescence. */
	[[nodiscard]] uint32_t available_approx() const noexcept;

	/** @return Complete live bitmap/record/payload mapping for cold placement inspection. */
	[[nodiscard]] const numa_memory_region &storage_region() const noexcept
	{
		return backing_;
	}

    private:
	/** @brief Initialize an acquired prefix; the internal span has at most UINT16_MAX slots. */
	template <std::size_t extent>
	uint16_t acquire_records_(std::span<packet_record *, extent> records) noexcept;
	/** @brief Validate and retire one exact nonempty prefix without reading published records. */
	template <std::size_t extent>
	void release_records_(std::span<packet_record *const, extent> records) noexcept;
	/** @brief Cold checked geometry; all byte offsets are computed by numa_layout. */
	struct storage_layout;
	/** @brief Caller-storage free-credit publication mechanism. */
	using free_index_pool = algo::atomic_index_pool_view;
	/**
	 * @brief Bind the admitted pool to its complete prefaulted mapping.
	 *
	 * @param options Exact storage-domain shape.
	 * @param layout Checked bitmap, record and payload geometry.
	 * @param backing Complete aligned and prefaulted memory-region owner.
	 */
	fixed_packet_pool(fixed_packet_pool_options options, const storage_layout &layout,
			  numa_memory_region backing) noexcept;

	/**
	 * @brief Acquire through the exact C storage-domain operation table.
	 * @param state Borrowed pool instance.
	 * @param records Destination for newly owned record pointers.
	 * @param capacity Maximum records to acquire.
	 * @return Acquired prefix length, or zero for invalid input, exhaustion, or contention.
	 */
	[[nodiscard]] static uint16_t acquire_burst_(void *state, packet_record **records, uint16_t capacity) noexcept;

	/**
	 * @brief Produce one independent writable record in this exact domain.
	 * @param state Borrowed destination pool instance.
	 * @param source Live record from this pool, borrowed without ownership transfer.
	 * @return Newly owned deep copy, or nullptr on invalid source, exhaustion, or contention.
	 */
	[[nodiscard]] static packet_record *clone_writable_(void *state, const packet_record *source) noexcept;

	/**
	 * @brief Validate every borrowed origin, then copy an available prefix.
	 * @param state Borrowed destination pool instance.
	 * @param origins Complete borrowed input array.
	 * @param records Destination for newly owned records.
	 * @param count Number of origins and available output slots.
	 * @return Copied prefix length; malformed input acquires no records and returns zero.
	 */
	[[nodiscard]] static uint16_t copy_origins_burst_(void *state, const packet_origin_view *origins,
							  packet_record **records, uint16_t count) noexcept;

	/**
	 * @brief Retire exact leases; malformed ownership, within-burst duplicates, and returns before reacquisition fail stop.
	 * @param state Borrowed pool instance that owns every record.
	 * @param records Non-null array of distinct live records transferred back to the pool.
	 * @param count Positive number of records to retire.
	 * Stale pointers racing or following a later owner violate the caller contract
	 * and are outside duplicate detection. No record is read after its bit is returned.
	 */
	static void release_burst_(void *state, packet_record *const *records, uint16_t count) noexcept;
	/**
	 * @brief Publish one cold O(words) approximate occupancy observation.
	 * @param state Borrowed pool instance.
	 * @param observation Destination for generation, domain identity, and occupancy state.
	 * @param diagnostic Optional caller-owned diagnostic buffer, cleared on success.
	 * @return OK with approximate counts or a READ_FAILED observation; INVALID_ARGUMENT for malformed arguments.
	 */
	[[nodiscard]] static kinetum_provider_status
	observe_statistics_(void *state, kinetum_provider_storage_observation *observation,
			    kinetum_provider_diagnostic *diagnostic) noexcept;

	/**
	 * @param record Candidate address, which may be null or outside this pool.
	 * @return true only for an exactly aligned record slot owned by this pool.
	 */
	[[nodiscard]] bool owns_(const packet_record *record) const noexcept;

	/**
	 * @param record Candidate record address.
	 * @return Reserved payload address, or nullptr for a foreign or misaligned slot.
	 */
	[[nodiscard]] uint8_t *payload_for_(const packet_record *record) const noexcept;

	/**
	 * @param index Slot index below the configured record population.
	 * @return Address of the corresponding record slot in aligned backing storage.
	 */
	[[nodiscard]] packet_record *record_for_index_(std::size_t index) const noexcept;

	fixed_packet_pool_options options_;		 ///< Immutable materialized pool shape.
	numa_memory_region backing_;			 ///< Complete aligned and prefaulted backing owner.
	std::size_t record_shift_{0};			 ///< Log2 of the exact power-of-two record stride in bytes.
	std::size_t payload_stride_{0};			 ///< Cache-line-isolated payload-slot stride.
	std::size_t payload_data_offset_{0};		 ///< Offset preserving headroom before aligned data.
	packet_storage_domain_operations operations_{};	 ///< Immutable published storage table.
	uint8_t *record_storage_{nullptr};		 ///< Aligned backing for placement-constructed records.
	uint8_t *payload_storage_{nullptr};		 ///< Aligned backing for exact payload slots.
	free_index_pool *free_records_{nullptr};	 ///< Shared prefix-search control placed in backing_.
	std::span<free_index_pool::storage_type>
		free_words_;  ///< Availability words with the same exact node and lifetime.
};

}  // namespace kinetum::dp
