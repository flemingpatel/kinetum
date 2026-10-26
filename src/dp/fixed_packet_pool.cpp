// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file fixed_packet_pool.cpp
 * @brief Fixed-capacity host packet storage-domain implementation.
 * @author Fleming Patel
 */

#include "src/dp/fixed_packet_pool.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

#include "src/common/status.hpp"
#include "src/dp/numa_layout.hpp"

namespace kinetum::dp
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_code;

}  // namespace

/** @brief Checked cold extents for the one storage-domain mapping. */
struct fixed_packet_pool::storage_layout {
	numa_layout memory;		     ///< Sole allocation geometry authority.
	std::size_t word_count{0};	     ///< Exact availability-word population.
	std::size_t control_offset{0};	     ///< Shared prefix-search control.
	std::size_t words_offset{0};	     ///< Cache-line-separated availability words.
	std::size_t record_offset{0};	     ///< First record row.
	std::size_t record_stride{0};	     ///< Cache-line-isolated record extent.
	std::size_t payload_offset{0};	     ///< First payload row.
	std::size_t payload_stride{0};	     ///< Cache-line-isolated payload extent.
	std::size_t payload_data_offset{0};  ///< Aligned data after the authored headroom.
};

kinetum::common::status_or<std::unique_ptr<fixed_packet_pool>>
fixed_packet_pool::create(const fixed_packet_pool_options &options)
{
	if (options.record_count == 0) {
		return status(status_code::INVALID_ARGUMENT, "fixed packet pool has zero record_count");
	}
	if (options.data_room_bytes == 0) {
		return status(status_code::INVALID_ARGUMENT, "fixed packet pool has zero data_room_bytes");
	}
	if (options.headroom_bytes >= options.data_room_bytes) {
		return status(status_code::INVALID_ARGUMENT,
			      "fixed packet pool headroom_bytes must be smaller than data_room_bytes");
	}
	if (options.alignment_bytes == 0 || (options.alignment_bytes & (options.alignment_bytes - 1u)) != 0u) {
		return status(status_code::INVALID_ARGUMENT,
			      "fixed packet pool alignment_bytes must be a nonzero power of two");
	}
	if (options.domain_index == INVALID_STORAGE_DOMAIN) {
		return status(status_code::INVALID_ARGUMENT, "fixed packet pool has invalid domain_index");
	}
	if (options.generation == 0) {
		return status(status_code::INVALID_ARGUMENT, "fixed packet pool has zero generation");
	}
	if (options.host_numa_node < 0) {
		return status(status_code::INVALID_ARGUMENT, "fixed packet pool host NUMA node must be nonnegative");
	}

	const uint32_t maximum_packet_length = options.data_room_bytes - options.headroom_bytes;
	if (maximum_packet_length > std::numeric_limits<uint16_t>::max()) {
		return status(status_code::OUT_OF_RANGE,
			      "fixed packet pool maximum packet length exceeds the packet-record ABI");
	}

	storage_layout layout;
	layout.word_count = free_index_pool::word_count(options.record_count);
	const std::size_t alignment = std::max<std::size_t>(alignof(packet_record), options.alignment_bytes);
	numa_layout payload_row;
	std::size_t headroom_offset = 0;
	if (!payload_row.append<uint8_t>(options.headroom_bytes, headroom_offset) ||
	    !payload_row.append<uint8_t>(maximum_packet_length, layout.payload_data_offset, options.alignment_bytes) ||
	    !layout.memory.append<free_index_pool>(1u, layout.control_offset, algo::CACHE_LINE_SIZE) ||
	    !layout.memory.append<free_index_pool::storage_type>(layout.word_count, layout.words_offset) ||
	    !layout.memory.append_rows<packet_record>(options.record_count, 1u, layout.record_offset,
						      layout.record_stride, alignment) ||
	    !layout.memory.append_rows<uint8_t>(options.record_count, payload_row.size(), layout.payload_offset,
						layout.payload_stride, alignment)) {
		return status(status_code::OUT_OF_RANGE, "fixed packet pool layout overflows");
	}
	if (!std::has_single_bit(layout.record_stride)) {
		std::terminate();
	}
	auto backing_or = layout.memory.allocate(options.host_numa_node);
	if (!backing_or.is_ok()) {
		return backing_or.error();
	}
	auto *pool = new (std::nothrow) fixed_packet_pool(options, layout, std::move(*backing_or));
	if (pool == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED, "fixed packet pool owner allocation failed");
	}
	return std::unique_ptr<fixed_packet_pool>(pool);
}

fixed_packet_pool::fixed_packet_pool(fixed_packet_pool_options options, const storage_layout &layout,
				     numa_memory_region backing) noexcept
	: options_(options)
	, backing_(std::move(backing))
	, record_shift_(static_cast<std::size_t>(std::countr_zero(layout.record_stride)))
	, payload_stride_(layout.payload_stride)
	, payload_data_offset_(layout.payload_data_offset)
	, record_storage_(reinterpret_cast<uint8_t *>(numa_layout::row<packet_record>(backing_, layout.record_offset,
										      layout.record_stride, 0u,
										      options.record_count, 1u)
							      .data()))
	, payload_storage_(numa_layout::row<uint8_t>(backing_, layout.payload_offset, layout.payload_stride, 0u,
						     options.record_count, layout.payload_stride)
				   .data())
	, free_words_(
		  numa_layout::storage<free_index_pool::storage_type>(backing_, layout.words_offset, layout.word_count))
{
	static_assert(std::is_nothrow_default_constructible_v<free_index_pool::storage_type>);
	static_assert(std::is_nothrow_default_constructible_v<packet_record>);
	std::uninitialized_value_construct_n(free_words_.data(), free_words_.size());
	free_records_ = std::construct_at(numa_layout::storage<free_index_pool>(backing_, layout.control_offset).data(),
					  free_words_, options.record_count);

	operations_.state = this;
	operations_.acquire_burst = &fixed_packet_pool::acquire_burst_;
	operations_.clone_writable = &fixed_packet_pool::clone_writable_;
	operations_.copy_origins_burst = &fixed_packet_pool::copy_origins_burst_;
	operations_.release_burst = &fixed_packet_pool::release_burst_;
	operations_.observe_statistics = &fixed_packet_pool::observe_statistics_;
	operations_.generation = options_.generation;
	operations_.domain_index = options_.domain_index;
	operations_.maximum_packet_length = static_cast<uint16_t>(options_.data_room_bytes - options_.headroom_bytes);
	operations_.capabilities = packet_storage_capabilities::CPU_CONTIGUOUS_READ |
				   packet_storage_capabilities::CPU_CONTIGUOUS_WRITE |
				   packet_storage_capabilities::WRITABLE_CLONE;

	for (uint32_t i = 0; i < options_.record_count; ++i) {
		auto *record = new (record_for_index_(i)) packet_record{};
		record->storage.native_handle = nullptr;
		record->storage.data =
			payload_storage_ + static_cast<std::size_t>(i) * payload_stride_ + payload_data_offset_;
		record->storage.operations = &operations_;
		record->storage.length = 0;
		record->storage.contiguous_length = 0;
		record->storage.generation = options_.generation;
		record->storage.domain_index = options_.domain_index;
		record->storage.segment_count = 1;
		record->storage.capabilities = operations_.capabilities;
		initialize_packet_record(*record);
	}
}

fixed_packet_pool::~fixed_packet_pool()
{
	// Destruction is a cold ownership boundary. Any outstanding record means a
	// packet owner escaped runtime shutdown; reclaiming the backing would turn
	// that invariant violation into use-after-free.
	if (available_approx() != options_.record_count) {
		std::terminate();
	}
	for (uint32_t i = 0; i < options_.record_count; ++i) {
		record_for_index_(i)->~packet_record();
	}
	std::destroy_at(free_records_);
	std::destroy_n(free_words_.data(), free_words_.size());
}

template <std::size_t extent>
uint16_t fixed_packet_pool::acquire_records_(std::span<packet_record *, extent> records) noexcept
{
	const auto accepted = free_records_->acquire_prefix(
		static_cast<uint16_t>(records.size()),
		[this, output = records.data()](std::size_t ordinal, uint32_t index) noexcept {
			if (index >= options_.record_count) {
				std::terminate();
			}
			auto *record = record_for_index_(index);
			if (record->storage.native_handle != nullptr ||
			    record->storage.data != payload_storage_ +
							    static_cast<std::size_t>(index) * payload_stride_ +
							    payload_data_offset_ ||
			    record->storage.operations != &operations_ ||
			    record->storage.generation != options_.generation ||
			    record->storage.domain_index != options_.domain_index ||
			    record->storage.segment_count != 1 ||
			    record->storage.capabilities != operations_.capabilities) {
				std::terminate();
			}
			initialize_packet_record(*record);
			record->storage.native_handle = record;
			record->storage.length = 0;
			record->storage.contiguous_length = 0;
			output[ordinal] = record;
		});
	return accepted;
}

uint16_t fixed_packet_pool::acquire_burst(packet_record **records, uint16_t capacity) noexcept
{
	if (records == nullptr || capacity == 0) {
		return 0;
	}
	if (capacity == 1) {
		return acquire_records_(std::span<packet_record *, 1>(records, 1));
	}
	return acquire_records_(std::span<packet_record *>(records, capacity));
}

uint16_t fixed_packet_pool::acquire_burst_(void *state, packet_record **records, uint16_t capacity) noexcept
{
	auto *pool = static_cast<fixed_packet_pool *>(state);
	return pool != nullptr ? pool->acquire_burst(records, capacity) : 0;
}

uint32_t fixed_packet_pool::outstanding() const noexcept
{
	const uint32_t available = available_approx();
	return available <= options_.record_count ? options_.record_count - available : options_.record_count;
}

uint32_t fixed_packet_pool::available_approx() const noexcept
{
	return free_records_->available_approx();
}

packet_record *fixed_packet_pool::clone_writable_(void *state, const packet_record *source) noexcept
{
	auto *pool = static_cast<fixed_packet_pool *>(state);
	if (pool == nullptr || source == nullptr || source->storage.operations != &pool->operations_ ||
	    source->storage.native_handle != source || source->storage.data != pool->payload_for_(source) ||
	    source->storage.generation != pool->options_.generation ||
	    source->storage.domain_index != pool->options_.domain_index || source->storage.data == nullptr ||
	    source->storage.length > pool->operations_.maximum_packet_length ||
	    source->storage.contiguous_length != source->storage.length || source->storage.segment_count != 1 ||
	    source->storage.capabilities != pool->operations_.capabilities) {
		return nullptr;
	}

	packet_record *clone = nullptr;
	if (pool->acquire_burst(&clone, 1) != 1) {
		return nullptr;
	}
	std::memcpy(clone->storage.data, source->storage.data, source->storage.length);
	clone->storage.length = source->storage.length;
	clone->storage.contiguous_length = source->storage.length;
	clone->metadata = source->metadata;
	return clone;
}

uint16_t fixed_packet_pool::copy_origins_burst_(void *state, const packet_origin_view *origins, packet_record **records,
						uint16_t count) noexcept
{
	auto *pool = static_cast<fixed_packet_pool *>(state);
	if (pool == nullptr || origins == nullptr || records == nullptr || count == 0) {
		return 0;
	}

	// Malformed origin metadata is not a capacity result. Validate the entire
	// authored batch before consuming one storage credit so every provider
	// implements the same fail-before-side-effects contract.
	const auto maximum_length = pool->operations_.maximum_packet_length;
	for (const auto &origin : std::span{origins, count}) {
		if (origin.data == nullptr || origin.length == 0 || origin.padding != 0 ||
		    origin.length > maximum_length) {
			return 0;
		}
	}

	const uint16_t accepted = pool->acquire_burst(records, count);
	for (uint16_t index = 0; index < accepted; ++index) {
		auto *record = records[index];
		std::memcpy(record->storage.data, origins[index].data, origins[index].length);
		record->storage.length = origins[index].length;
		record->storage.contiguous_length = origins[index].length;
	}
	return accepted;
}

template <std::size_t extent>
void fixed_packet_pool::release_records_(std::span<packet_record *const, extent> records) noexcept
{
	const auto count = records.size();
	// Validate the complete burst before publishing any free credit. The second
	// pass then claims every record by clearing its native ownership marker. If
	// one pointer appears twice, the second claim fails before another worker can
	// reacquire the first occurrence. This checks within-burst duplicates before
	// publication; it cannot identify a stale pointer after a later acquisition.
	for (std::size_t i = 0; i < count; ++i) {
		auto *record = records[i];
		if (record == nullptr) {
			std::terminate();
		}
		if (!owns_(record) || record->storage.native_handle != record ||
		    record->storage.data != payload_for_(record) || record->storage.operations != &operations_ ||
		    record->storage.generation != options_.generation ||
		    record->storage.domain_index != options_.domain_index || record->storage.segment_count != 1 ||
		    record->storage.capabilities != operations_.capabilities) {
			std::terminate();
		}
	}
	for (std::size_t i = 0; i < count; ++i) {
		auto *record = records[i];
		if (record->storage.native_handle != record) {
			std::terminate();
		}
		record->storage.native_handle = nullptr;
	}
	free_records_->release_prefix(count, [&](std::size_t ordinal) noexcept -> uint32_t {
		auto *record = records[ordinal];
		return static_cast<uint32_t>((reinterpret_cast<std::uintptr_t>(record) -
					      reinterpret_cast<std::uintptr_t>(record_storage_)) >>
					     record_shift_);
	});
}

void fixed_packet_pool::release_burst_(void *state, packet_record *const *records, uint16_t count) noexcept
{
	auto *pool = static_cast<fixed_packet_pool *>(state);
	if (pool == nullptr || records == nullptr || count == 0) {
		std::terminate();
	}
	if (count == 1) {
		pool->release_records_(std::span<packet_record *const, 1>(records, 1));
	} else {
		pool->release_records_(std::span<packet_record *const>(records, count));
	}
}

kinetum_provider_status fixed_packet_pool::observe_statistics_(void *state,
							       kinetum_provider_storage_observation *observation,
							       kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *pool = static_cast<fixed_packet_pool *>(state);
	if (pool == nullptr || observation == nullptr ||
	    (diagnostic != nullptr && diagnostic->data == nullptr && diagnostic->capacity != 0u)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	*observation = {};
	observation->runtime_generation = pool->options_.generation;
	observation->storage_domain_index = pool->options_.domain_index;
	const uint32_t available = pool->available_approx();
	if (available > pool->options_.record_count) {
		observation->state = KINETUM_PROVIDER_OBSERVATION_READ_FAILED;
	} else {
		observation->state = KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE;
		observation->in_use = pool->options_.record_count - available;
		observation->available = available;
	}
	if (diagnostic != nullptr) {
		diagnostic->size = 0u;
	}
	return KINETUM_PROVIDER_STATUS_OK;
}

bool fixed_packet_pool::owns_(const packet_record *record) const noexcept
{
	if (record == nullptr || record_storage_ == nullptr) {
		return false;
	}
	const auto begin = reinterpret_cast<std::uintptr_t>(record_storage_);
	const auto address = reinterpret_cast<std::uintptr_t>(record);
	const auto bytes = (static_cast<std::size_t>(options_.record_count) << record_shift_);
	return address >= begin && address - begin < bytes &&
	       ((address - begin) & ((std::size_t{1} << record_shift_) - 1u)) == 0;
}

uint8_t *fixed_packet_pool::payload_for_(const packet_record *record) const noexcept
{
	if (!owns_(record)) {
		return nullptr;
	}
	const auto byte_offset =
		reinterpret_cast<std::uintptr_t>(record) - reinterpret_cast<std::uintptr_t>(record_storage_);
	const auto index = byte_offset >> record_shift_;
	return payload_storage_ + index * payload_stride_ + payload_data_offset_;
}

packet_record *fixed_packet_pool::record_for_index_(std::size_t index) const noexcept
{
	return reinterpret_cast<packet_record *>(record_storage_ + (index << record_shift_));
}

}  // namespace kinetum::dp
