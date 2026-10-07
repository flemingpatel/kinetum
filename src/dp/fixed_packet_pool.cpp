// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file fixed_packet_pool.cpp
 * @brief Fixed-capacity host packet storage-domain implementation.
 * @author Fleming Patel
 */

#include "src/dp/fixed_packet_pool.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <utility>

#include "src/common/status.hpp"

namespace kinetum::dp
{

namespace
{

using kinetum::common::status;
using kinetum::common::status_code;

/**
 * @brief Round a logical record population up to the free queue's power-of-two capacity.
 *
 * @param value Nonzero logical population.
 * @return Rounded capacity, or a value below input when size_t cannot represent the result.
 */
[[nodiscard]] std::size_t next_power_of_two(std::size_t value) noexcept
{
	std::size_t result = 2;
	while (result < value && result <= std::numeric_limits<std::size_t>::max() / 2) {
		result <<= 1;
	}
	return result;
}

/**
 * @brief Round a nonnegative value up to one nonzero power-of-two alignment.
 *
 * @param value Value to round.
 * @param alignment Nonzero power-of-two alignment.
 * @param[out] rounded Exact rounded value on success.
 * @return true when the rounded value is representable.
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

/**
 * @brief Multiply two allocation dimensions without wrapping size_t.
 *
 * @param count Logical slot count.
 * @param stride Physical bytes per slot.
 * @param[out] bytes Exact allocation bytes on success.
 * @return true when the product is representable.
 */
[[nodiscard]] bool allocation_size_checked(uint32_t count, std::size_t stride, std::size_t &bytes) noexcept
{
	if (stride == 0 || static_cast<std::size_t>(count) > std::numeric_limits<std::size_t>::max() / stride) {
		return false;
	}
	bytes = static_cast<std::size_t>(count) * stride;
	return true;
}

}  // namespace

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
	if (options.host_numa_node.has_value() && options.host_numa_node.value() < 0) {
		return status(status_code::INVALID_ARGUMENT, "fixed packet pool host NUMA node must be nonnegative");
	}

	const auto queue_capacity = next_power_of_two(options.record_count);
	if (queue_capacity < options.record_count) {
		return status(status_code::OUT_OF_RANGE, "fixed packet pool free queue capacity overflows size_t");
	}
	const uint32_t maximum_packet_length = options.data_room_bytes - options.headroom_bytes;
	if (maximum_packet_length > std::numeric_limits<uint16_t>::max()) {
		return status(status_code::OUT_OF_RANGE,
			      "fixed packet pool maximum packet length exceeds the packet-record ABI");
	}

	const std::size_t requested_alignment = options.alignment_bytes;
	const std::size_t allocation_alignment = std::max<std::size_t>(alignof(packet_record), requested_alignment);
	std::size_t record_stride = 0;
	std::size_t aligned_headroom = 0;
	if (!round_up_checked(sizeof(packet_record), allocation_alignment, record_stride) ||
	    !round_up_checked(options.headroom_bytes, requested_alignment, aligned_headroom)) {
		return status(status_code::OUT_OF_RANGE, "fixed packet pool alignment rounding overflows size_t");
	}
	const std::size_t payload_prefix = aligned_headroom - options.headroom_bytes;
	if (payload_prefix > std::numeric_limits<std::size_t>::max() - options.data_room_bytes) {
		return status(status_code::OUT_OF_RANGE, "fixed packet pool payload span overflows size_t");
	}
	const std::size_t payload_span = payload_prefix + options.data_room_bytes;
	std::size_t payload_stride = 0;
	if (!round_up_checked(payload_span, allocation_alignment, payload_stride)) {
		return status(status_code::OUT_OF_RANGE, "fixed packet pool payload stride overflows size_t");
	}
	std::size_t record_bytes = 0;
	std::size_t payload_bytes = 0;
	if (!allocation_size_checked(options.record_count, record_stride, record_bytes) ||
	    !allocation_size_checked(options.record_count, payload_stride, payload_bytes)) {
		return status(status_code::OUT_OF_RANGE, "fixed packet pool backing allocation overflows size_t");
	}
	std::size_t payload_storage_offset = 0;
	if (!round_up_checked(record_bytes, allocation_alignment, payload_storage_offset) ||
	    payload_storage_offset > std::numeric_limits<std::size_t>::max() - payload_bytes) {
		return status(status_code::OUT_OF_RANGE, "fixed packet pool combined backing overflows size_t");
	}
	const std::size_t backing_bytes = payload_storage_offset + payload_bytes;

	std::unique_ptr<kinetum::algo::mpmc_queue_dynamic<packet_record *>> free_records;
	try {
		free_records = std::make_unique<kinetum::algo::mpmc_queue_dynamic<packet_record *>>(queue_capacity);
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED, "fixed packet pool free-credit allocation failed");
	}

	auto backing_or = numa_memory_region::allocate({
		.usable_bytes = backing_bytes,
		.alignment_bytes = allocation_alignment,
		.host_numa_node = options.host_numa_node,
	});
	if (!backing_or.is_ok()) {
		return backing_or.error();
	}
	auto *pool = new (std::nothrow)
		fixed_packet_pool(options, queue_capacity, std::move(*backing_or), record_stride,
				  payload_storage_offset, payload_stride, aligned_headroom, std::move(free_records));
	if (pool == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED, "fixed packet pool owner allocation failed");
	}
	return std::unique_ptr<fixed_packet_pool>(pool);
}

fixed_packet_pool::fixed_packet_pool(
	fixed_packet_pool_options options, std::size_t free_queue_capacity, numa_memory_region backing,
	std::size_t record_stride, std::size_t payload_storage_offset, std::size_t payload_stride,
	std::size_t payload_data_offset,
	std::unique_ptr<kinetum::algo::mpmc_queue_dynamic<packet_record *>> free_records) noexcept
	: options_(options)
	, backing_(std::move(backing))
	, record_stride_(record_stride)
	, payload_stride_(payload_stride)
	, payload_data_offset_(payload_data_offset)
	, record_storage_(static_cast<uint8_t *>(backing_.data()))
	, payload_storage_(static_cast<uint8_t *>(backing_.data()) + payload_storage_offset)
	, free_records_(std::move(free_records))
{
	if (!backing_ || backing_.size() == 0 || record_storage_ == nullptr || payload_storage_ == nullptr ||
	    free_records_ == nullptr || free_records_->capacity() != free_queue_capacity) {
		std::terminate();
	}

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
		if (!free_records_->try_enqueue(record)) {
			std::terminate();
		}
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
}

uint16_t fixed_packet_pool::acquire_burst(packet_record **records, uint16_t capacity) noexcept
{
	if (records == nullptr || capacity == 0) {
		return 0;
	}

	uint16_t acquired = 0;
	for (; acquired < capacity; ++acquired) {
		packet_record *record = nullptr;
		if (!free_records_->try_dequeue(record)) {
			break;
		}
		if (!owns_(record) || record->storage.native_handle != nullptr ||
		    record->storage.data != payload_for_(record) || record->storage.operations != &operations_ ||
		    record->storage.generation != options_.generation ||
		    record->storage.domain_index != options_.domain_index || record->storage.segment_count != 1 ||
		    record->storage.capabilities != operations_.capabilities) {
			std::terminate();
		}
		initialize_packet_record(*record);
		record->storage.native_handle = record;
		record->storage.length = 0;
		record->storage.contiguous_length = 0;
		records[acquired] = record;
	}
	return acquired;
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
	const auto available = free_records_->size_approx();
	return available > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(available);
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
	for (uint16_t index = 0; index < count; ++index) {
		if (origins[index].data == nullptr || origins[index].length == 0 || origins[index].padding != 0 ||
		    origins[index].length > pool->operations_.maximum_packet_length) {
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

void fixed_packet_pool::release_burst_(void *state, packet_record *const *records, uint16_t count) noexcept
{
	auto *pool = static_cast<fixed_packet_pool *>(state);
	if (pool == nullptr || records == nullptr || count == 0) {
		std::terminate();
	}

	// Validate the complete burst before publishing any free credit. The second
	// pass then claims every record by clearing its native ownership marker. If
	// one pointer appears twice, the second claim fails before another worker can
	// reacquire the first occurrence from the free queue; this closes the
	// otherwise possible release/reacquire ABA window without allocation or a
	// lock on the hot path.
	for (uint16_t i = 0; i < count; ++i) {
		auto *record = records[i];
		if (record == nullptr) {
			std::terminate();
		}
		if (!pool->owns_(record) || record->storage.native_handle != record ||
		    record->storage.data != pool->payload_for_(record) ||
		    record->storage.operations != &pool->operations_ ||
		    record->storage.generation != pool->options_.generation ||
		    record->storage.domain_index != pool->options_.domain_index || record->storage.segment_count != 1 ||
		    record->storage.capabilities != pool->operations_.capabilities) {
			std::terminate();
		}
	}
	for (uint16_t i = 0; i < count; ++i) {
		auto *record = records[i];
		if (record->storage.native_handle != record) {
			std::terminate();
		}
		record->storage.native_handle = nullptr;
	}
	for (uint16_t i = 0; i < count; ++i) {
		auto *record = records[i];
		initialize_packet_record(*record);
		record->storage.length = 0;
		record->storage.contiguous_length = 0;
		if (!pool->free_records_->try_enqueue(record)) {
			// A full free queue can only mean duplicate retirement or corrupted
			// ownership accounting; continuing would publish the same record twice.
			std::terminate();
		}
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
	const auto bytes = static_cast<std::size_t>(options_.record_count) * record_stride_;
	return address >= begin && address - begin < bytes && ((address - begin) % record_stride_) == 0;
}

uint8_t *fixed_packet_pool::payload_for_(const packet_record *record) const noexcept
{
	if (!owns_(record)) {
		return nullptr;
	}
	const auto byte_offset =
		reinterpret_cast<std::uintptr_t>(record) - reinterpret_cast<std::uintptr_t>(record_storage_);
	const auto index = byte_offset / record_stride_;
	return payload_storage_ + index * payload_stride_ + payload_data_offset_;
}

packet_record *fixed_packet_pool::record_for_index_(std::size_t index) const noexcept
{
	return reinterpret_cast<packet_record *>(record_storage_ + index * record_stride_);
}

}  // namespace kinetum::dp
