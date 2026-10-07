// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_runtime_telemetry.cpp
 * @brief Exact-NUMA owner-local engine, stream, and stage telemetry implementation.
 * @author Fleming Patel
 */

#include "src/dp/worker_runtime_telemetry.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include <kinetum/algo/cache.hpp>

namespace kinetum::dp
{
namespace
{

/**
 * @brief Add one aligned extent to a checked telemetry mapping layout.
 * @tparam value_type Placement element type.
 * @param count Element population.
 * @param[in,out] cursor Current checked layout end.
 * @param[out] offset Aligned start of this extent.
 * @return true after exact representable arithmetic.
 */
template <typename value_type>
[[nodiscard]] bool append_extent(std::size_t count, std::size_t &cursor, std::size_t &offset) noexcept
{
	if (count == 0u) {
		offset = cursor;
		return true;
	}
	const std::size_t alignment = alignof(value_type);
	const std::size_t mask = alignment - 1u;
	if (cursor > std::numeric_limits<std::size_t>::max() - mask) {
		return false;
	}
	offset = (cursor + mask) & ~mask;
	if (count > std::numeric_limits<std::size_t>::max() / sizeof(value_type) ||
	    count * sizeof(value_type) > std::numeric_limits<std::size_t>::max() - offset) {
		return false;
	}
	cursor = offset + count * sizeof(value_type);
	return true;
}

/**
 * @brief Round one extent without overflowing its size domain.
 * @param value Unaligned byte count or offset.
 * @param alignment Required nonzero power-of-two alignment.
 * @param[out] rounded Aligned result written only on success.
 * @return true when the rounded value is representable.
 */
[[nodiscard]] bool round_up_checked(std::size_t value, std::size_t alignment, std::size_t &rounded) noexcept
{
	if (alignment == 0u || (alignment & (alignment - 1u)) != 0u ||
	    value > std::numeric_limits<std::size_t>::max() - (alignment - 1u)) {
		return false;
	}
	rounded = (value + alignment - 1u) & ~(alignment - 1u);
	return true;
}

/**
 * @brief Append three separately cache-aligned counter banks with checked bounds.
 * @tparam value_type Plain counter row owned by one worker.
 * @param count Exact rows per bank; zero allocates no extent.
 * @param[in,out] cursor Current layout end, advanced only on success.
 * @param[out] offset First counter bank offset.
 * @param[out] stride Cache-line-complete bytes per bank, or zero when empty.
 * @return true only for representable layout arithmetic.
 */
template <typename value_type>
[[nodiscard]] bool append_counter_banks(std::size_t count, std::size_t &cursor, std::size_t &offset,
					std::size_t &stride) noexcept
{
	if (count == 0u) {
		offset = cursor;
		stride = 0u;
		return true;
	}
	if (count > std::numeric_limits<std::size_t>::max() / sizeof(value_type) ||
	    !round_up_checked(cursor, kinetum::algo::CACHE_LINE_SIZE, offset) ||
	    !round_up_checked(count * sizeof(value_type), kinetum::algo::CACHE_LINE_SIZE, stride) || stride == 0u ||
	    RUNTIME_TELEMETRY_BANK_COUNT > (std::numeric_limits<std::size_t>::max() - offset) / stride) {
		return false;
	}
	cursor = offset + RUNTIME_TELEMETRY_BANK_COUNT * stride;
	return true;
}

}  // namespace

common::status_or<worker_runtime_telemetry::storage_layout>
worker_runtime_telemetry::compute_layout(std::size_t stage_count, std::size_t stream_count) noexcept
{
	if (stage_count == 0u || stage_count > UINT32_MAX || stream_count > UINT32_MAX) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "worker telemetry requires compact stage and stream populations"));
	}
	storage_layout layout;
	std::size_t cursor = 0u;
	if (!append_extent<hot_bank_view>(1u, cursor, layout.hot_offset) ||
	    !append_extent<bank_header>(RUNTIME_TELEMETRY_BANK_COUNT, cursor, layout.headers_offset) ||
	    !append_counter_banks<worker_stage_telemetry_counters>(stage_count, cursor, layout.stages_offset,
								   layout.stage_bank_stride) ||
	    !append_counter_banks<worker_stream_telemetry_counters>(stream_count, cursor, layout.streams_offset,
								    layout.stream_bank_stride)) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "worker telemetry slab extent exceeds the host size domain"));
	}
	layout.total_bytes = cursor;
	return layout;
}

common::status_or<std::unique_ptr<worker_runtime_telemetry>>
worker_runtime_telemetry::create(uint64_t runtime_generation, uint32_t worker_index, int32_t worker_numa_node,
				 std::span<const uint32_t> stage_instance_indices,
				 std::span<const uint32_t> io_stream_indices, uint64_t cadence_ns,
				 worker_telemetry_channel &channel)
{
	if (runtime_generation == 0u || worker_index == UINT32_MAX || worker_numa_node < 0 || cadence_ns == 0u ||
	    channel.worker_index() != worker_index || channel.returned_numa_node() != worker_numa_node ||
	    stage_instance_indices.empty()) {
		return common::status::invalid_argument(
			"worker telemetry requires exact generation, worker, NUMA, cadence, and stage ownership");
	}
	auto layout_or = compute_layout(stage_instance_indices.size(), io_stream_indices.size());
	if (!layout_or.is_ok()) {
		return layout_or.error();
	}
	const auto layout = layout_or.value();
	try {
		std::vector<uint32_t> stage_indices(stage_instance_indices.begin(), stage_instance_indices.end());
		if (!std::is_sorted(stage_indices.begin(), stage_indices.end()) ||
		    std::adjacent_find(stage_indices.begin(), stage_indices.end()) != stage_indices.end()) {
			return common::status::invalid_argument(
				"worker telemetry stage membership must be sorted and unique");
		}
		std::vector<uint32_t> stream_indices(io_stream_indices.begin(), io_stream_indices.end());
		if (!std::is_sorted(stream_indices.begin(), stream_indices.end()) ||
		    std::adjacent_find(stream_indices.begin(), stream_indices.end()) != stream_indices.end() ||
		    (!stream_indices.empty() && stream_indices.back() == UINT32_MAX)) {
			return common::status::invalid_argument(
				"worker telemetry stream membership must be sorted and unique");
		}
		const uint32_t maximum_stage = stage_indices.back();
		if (maximum_stage == UINT32_MAX) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "worker telemetry stage identity reaches the reserved sentinel");
		}
		std::vector<uint32_t> stage_to_ordinal(static_cast<std::size_t>(maximum_stage) + 1u, UINT32_MAX);
		for (std::size_t ordinal = 0u; ordinal < stage_indices.size(); ++ordinal) {
			stage_to_ordinal[stage_indices[ordinal]] = static_cast<uint32_t>(ordinal);
		}
		auto region_or = numa_memory_region::allocate({
			.usable_bytes = layout.total_bytes,
			.alignment_bytes = kinetum::algo::CACHE_LINE_SIZE,
			.host_numa_node = worker_numa_node,
		});
		if (!region_or.is_ok()) {
			return region_or.error();
		}
		auto region = std::move(region_or).value();
		auto *base = static_cast<std::byte *>(region.data());
		auto *hot = reinterpret_cast<hot_bank_view *>(base + layout.hot_offset);
		auto *headers = reinterpret_cast<bank_header *>(base + layout.headers_offset);
		auto *stages = reinterpret_cast<worker_stage_telemetry_counters *>(base + layout.stages_offset);
		auto *streams =
			stream_indices.empty() ?
				nullptr :
				reinterpret_cast<worker_stream_telemetry_counters *>(base + layout.streams_offset);
		std::construct_at(hot);
		for (std::size_t index = 0u; index < RUNTIME_TELEMETRY_BANK_COUNT; ++index) {
			std::construct_at(&headers[index]);
		}
		for (std::size_t bank_index = 0u; bank_index < RUNTIME_TELEMETRY_BANK_COUNT; ++bank_index) {
			auto *bank = reinterpret_cast<worker_stage_telemetry_counters *>(
				base + layout.stages_offset + bank_index * layout.stage_bank_stride);
			for (std::size_t stage_index = 0u; stage_index < stage_indices.size(); ++stage_index) {
				std::construct_at(&bank[stage_index]);
			}
		}
		for (std::size_t bank_index = 0u; !stream_indices.empty() && bank_index < RUNTIME_TELEMETRY_BANK_COUNT;
		     ++bank_index) {
			auto *bank = reinterpret_cast<worker_stream_telemetry_counters *>(
				base + layout.streams_offset + bank_index * layout.stream_bank_stride);
			for (std::size_t stream_index = 0u; stream_index < stream_indices.size(); ++stream_index) {
				std::construct_at(&bank[stream_index]);
			}
		}
		auto owner = std::unique_ptr<worker_runtime_telemetry>(new (std::nothrow) worker_runtime_telemetry(
			runtime_generation, worker_index, worker_numa_node, cadence_ns, channel,
			std::move(stage_indices), std::move(stage_to_ordinal), std::move(stream_indices),
			std::move(region), hot, headers, stages, layout.stage_bank_stride, streams,
			layout.stream_bank_stride));
		if (owner == nullptr) {
			for (std::size_t bank_index = 0u;
			     !io_stream_indices.empty() && bank_index < RUNTIME_TELEMETRY_BANK_COUNT; ++bank_index) {
				auto *bank = reinterpret_cast<worker_stream_telemetry_counters *>(
					base + layout.streams_offset + bank_index * layout.stream_bank_stride);
				for (std::size_t stream_index = 0u; stream_index < io_stream_indices.size();
				     ++stream_index) {
					std::destroy_at(&bank[stream_index]);
				}
			}
			for (std::size_t bank_index = 0u; bank_index < RUNTIME_TELEMETRY_BANK_COUNT; ++bank_index) {
				auto *bank = reinterpret_cast<worker_stage_telemetry_counters *>(
					base + layout.stages_offset + bank_index * layout.stage_bank_stride);
				for (std::size_t stage_index = 0u; stage_index < stage_instance_indices.size();
				     ++stage_index) {
					std::destroy_at(&bank[stage_index]);
				}
			}
			for (std::size_t index = 0u; index < RUNTIME_TELEMETRY_BANK_COUNT; ++index) {
				std::destroy_at(&headers[index]);
			}
			std::destroy_at(hot);
			return common::status::resource_exhausted("failed to allocate worker telemetry owner");
		}
		return owner;
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("failed to allocate worker telemetry construction state");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "worker telemetry construction extent exceeds the host size domain");
	}
}

worker_runtime_telemetry::worker_runtime_telemetry(
	uint64_t runtime_generation, uint32_t worker_index, int32_t numa_node, uint64_t cadence_ns,
	worker_telemetry_channel &channel, std::vector<uint32_t> stage_indices, std::vector<uint32_t> stage_to_ordinal,
	std::vector<uint32_t> stream_indices, numa_memory_region region, hot_bank_view *hot, bank_header *headers,
	worker_stage_telemetry_counters *stages, std::size_t stage_bank_stride,
	worker_stream_telemetry_counters *streams, std::size_t stream_bank_stride) noexcept
	: runtime_generation_(runtime_generation)
	, worker_index_(worker_index)
	, numa_node_(numa_node)
	, cadence_ns_(cadence_ns)
	, channel_(channel)
	, stage_indices_(std::move(stage_indices))
	, stage_to_ordinal_(std::move(stage_to_ordinal))
	, stream_indices_(std::move(stream_indices))
	, region_(std::move(region))
	, hot_(hot)
	, banks_(headers)
	, stage_counters_(stages)
	, stream_counters_(streams)
	, stream_bank_stride_(stream_bank_stride)
	, stage_bank_stride_(stage_bank_stride)
{
	if (runtime_generation_ == 0u || worker_index_ == UINT32_MAX || numa_node_ < 0 || cadence_ns_ == 0u ||
	    channel_.worker_index() != worker_index_ || channel_.returned_numa_node() != numa_node_ ||
	    stage_indices_.empty() || !region_ || hot_ == nullptr || banks_ == nullptr || stage_counters_ == nullptr ||
	    stage_bank_stride_ == 0u || stage_bank_stride_ % kinetum::algo::CACHE_LINE_SIZE != 0u ||
	    stage_indices_.size() > stage_bank_stride_ / sizeof(worker_stage_telemetry_counters) ||
	    stream_indices_.empty() != (stream_counters_ == nullptr) ||
	    stream_indices_.empty() != (stream_bank_stride_ == 0u) ||
	    stream_bank_stride_ % kinetum::algo::CACHE_LINE_SIZE != 0u ||
	    stream_indices_.size() > stream_bank_stride_ / sizeof(worker_stream_telemetry_counters) ||
	    !region_.host_numa_node().has_value() || *region_.host_numa_node() != numa_node_ ||
	    hot_->engine != nullptr || hot_->stages != nullptr || hot_->streams != nullptr ||
	    hot_->stream_count != 0u || hot_->protocol_faults != nullptr || hot_->stage_count != 0u ||
	    hot_->bank_index != UINT8_MAX) {
		std::terminate();
	}
}

worker_runtime_telemetry::~worker_runtime_telemetry()
{
	if (!empty()) {
		std::terminate();
	}
	for (std::size_t bank_index = 0u; bank_index < RUNTIME_TELEMETRY_BANK_COUNT; ++bank_index) {
		auto *bank = stage_bank_(static_cast<uint8_t>(bank_index));
		for (std::size_t stage_index = 0u; stage_index < stage_indices_.size(); ++stage_index) {
			std::destroy_at(&bank[stage_index]);
		}
	}
	for (uint8_t bank_index = 0u; bank_index < RUNTIME_TELEMETRY_BANK_COUNT; ++bank_index) {
		auto *bank = stream_bank_(bank_index);
		for (std::size_t stream_index = 0u; stream_index < stream_indices_.size(); ++stream_index) {
			std::destroy_at(&bank[stream_index]);
		}
	}
	for (std::size_t index = 0u; index < RUNTIME_TELEMETRY_BANK_COUNT; ++index) {
		std::destroy_at(&banks_[index]);
	}
	std::destroy_at(hot_);
}

worker_stage_telemetry_counters *worker_runtime_telemetry::stage_bank_(uint8_t bank_index) noexcept
{
	return reinterpret_cast<worker_stage_telemetry_counters *>(reinterpret_cast<std::byte *>(stage_counters_) +
								   static_cast<std::size_t>(bank_index) *
									   stage_bank_stride_);
}

const worker_stage_telemetry_counters *worker_runtime_telemetry::stage_bank_(uint8_t bank_index) const noexcept
{
	return reinterpret_cast<const worker_stage_telemetry_counters *>(
		reinterpret_cast<const std::byte *>(stage_counters_) +
		static_cast<std::size_t>(bank_index) * stage_bank_stride_);
}

worker_stream_telemetry_counters *worker_runtime_telemetry::stream_bank_(uint8_t bank_index) noexcept
{
	return stream_counters_ == nullptr ? nullptr :
					     reinterpret_cast<worker_stream_telemetry_counters *>(
						     reinterpret_cast<std::byte *>(stream_counters_) +
						     static_cast<std::size_t>(bank_index) * stream_bank_stride_);
}

const worker_stream_telemetry_counters *worker_runtime_telemetry::stream_bank_(uint8_t bank_index) const noexcept
{
	return stream_counters_ == nullptr ? nullptr :
					     reinterpret_cast<const worker_stream_telemetry_counters *>(
						     reinterpret_cast<const std::byte *>(stream_counters_) +
						     static_cast<std::size_t>(bank_index) * stream_bank_stride_);
}

void worker_runtime_telemetry::select_active_bank_(uint8_t bank_index) noexcept
{
	if (bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	active_bank_ = bank_index;
	hot_->engine = &banks_[bank_index].engine;
	hot_->stages = stage_bank_(bank_index);
	hot_->streams = stream_bank_(bank_index);
	hot_->stream_count = static_cast<uint32_t>(stream_indices_.size());
	hot_->protocol_faults = banks_[bank_index].protocol_faults.data();
	hot_->stage_count = static_cast<uint32_t>(stage_indices_.size());
	hot_->bank_index = bank_index;
}

void worker_runtime_telemetry::clear_bank_(uint8_t bank_index) noexcept
{
	if (bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	auto &bank = banks_[bank_index];
	bank.engine = {};
	bank.protocol_faults = {};
	bank.skipped_publications = 0u;
	std::fill_n(stage_bank_(bank_index), stage_indices_.size(), worker_stage_telemetry_counters{});
	if (!stream_indices_.empty()) {
		std::fill_n(stream_bank_(bank_index), stream_indices_.size(), worker_stream_telemetry_counters{});
	}
}

void worker_runtime_telemetry::reset_bank_transfer_(uint8_t bank_index) noexcept
{
	if (bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	banks_[bank_index].transfer = {};
}

void worker_runtime_telemetry::bind_bootstrap_epoch(uint64_t epoch, uint64_t now_ns) noexcept
{
	if (epoch == 0u || now_ns == 0u || active_epoch_ != 0u || prepared_epoch_ != 0u || active_bank_ != UINT8_MAX ||
	    standby_bank_ != UINT8_MAX || reserved_bank_ != UINT8_MAX || free_bank_ != UINT8_MAX ||
	    aggregated_epoch_ != 0u || owner_quiesced_ || old_banks_retained_for_transition_ ||
	    hot_->engine != nullptr || hot_->stages != nullptr || hot_->streams != nullptr ||
	    hot_->stream_count != 0u || hot_->protocol_faults != nullptr || hot_->stage_count != 0u ||
	    hot_->bank_index != UINT8_MAX || !channel_.empty()) {
		std::terminate();
	}
	for (uint8_t index = 0u; index < RUNTIME_TELEMETRY_BANK_COUNT; ++index) {
		if (banks_[index].state != bank_state::FREE || banks_[index].epoch != 0u ||
		    !runtime_telemetry_bank_token_is_empty(banks_[index].transfer)) {
			std::terminate();
		}
		clear_bank_(index);
		reset_bank_transfer_(index);
	}
	active_epoch_ = epoch;
	select_active_bank_(0u);
	standby_bank_ = 1u;
	free_bank_ = 2u;
	banks_[active_bank_].epoch = epoch;
	banks_[active_bank_].state = bank_state::ACTIVE;
	banks_[standby_bank_].epoch = epoch;
	banks_[standby_bank_].state = bank_state::STANDBY;
	next_publication_ns_ = now_ns;
}

common::status worker_runtime_telemetry::reserve_target_epoch(uint64_t from_epoch, uint64_t to_epoch) noexcept
{
	if (from_epoch == 0u || to_epoch <= from_epoch || active_epoch_ != from_epoch || prepared_epoch_ != 0u ||
	    reserved_bank_ != UINT8_MAX || free_bank_ >= RUNTIME_TELEMETRY_BANK_COUNT || aggregated_epoch_ != 0u ||
	    owner_quiesced_ || banks_[free_bank_].state != bank_state::FREE || banks_[free_bank_].epoch != 0u) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker telemetry cannot reserve the requested target epoch"));
	}
	if (!runtime_telemetry_bank_token_is_empty(banks_[free_bank_].transfer)) {
		return common::status::failed_precondition(
			kinetum::common::static_status_text("worker telemetry free bank retains a transfer identity"));
	}
	const uint8_t target = free_bank_;
	banks_[target].epoch = to_epoch;
	banks_[target].state = bank_state::RESERVED;
	reserved_bank_ = target;
	free_bank_ = UINT8_MAX;
	prepared_epoch_ = to_epoch;
	return common::status::ok();
}

void worker_runtime_telemetry::discard_target_epoch(uint64_t to_epoch) noexcept
{
	if (to_epoch == 0u || prepared_epoch_ != to_epoch || reserved_bank_ >= RUNTIME_TELEMETRY_BANK_COUNT ||
	    free_bank_ != UINT8_MAX || banks_[reserved_bank_].state != bank_state::RESERVED ||
	    banks_[reserved_bank_].epoch != to_epoch ||
	    !runtime_telemetry_bank_token_is_empty(banks_[reserved_bank_].transfer)) {
		std::terminate();
	}
	const uint8_t discarded = reserved_bank_;
	banks_[discarded].epoch = 0u;
	banks_[discarded].state = bank_state::FREE;
	reserved_bank_ = UINT8_MAX;
	free_bank_ = discarded;
	prepared_epoch_ = 0u;
}

bool worker_runtime_telemetry::preflight_activate(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	return from_epoch != 0u && to_epoch > from_epoch && active_epoch_ == from_epoch &&
	       prepared_epoch_ == to_epoch && aggregated_epoch_ == 0u && !owner_quiesced_ && free_bank_ == UINT8_MAX &&
	       active_bank_ < RUNTIME_TELEMETRY_BANK_COUNT && reserved_bank_ < RUNTIME_TELEMETRY_BANK_COUNT &&
	       hot_->engine == &banks_[active_bank_].engine && hot_->stages == stage_bank_(active_bank_) &&
	       hot_->streams == stream_bank_(active_bank_) && hot_->stream_count == stream_indices_.size() &&
	       hot_->protocol_faults == banks_[active_bank_].protocol_faults.data() &&
	       hot_->stage_count == stage_indices_.size() && hot_->bank_index == active_bank_ &&
	       banks_[active_bank_].state == bank_state::ACTIVE && banks_[active_bank_].epoch == from_epoch &&
	       runtime_telemetry_bank_token_is_empty(banks_[active_bank_].transfer) &&
	       banks_[reserved_bank_].state == bank_state::RESERVED && banks_[reserved_bank_].epoch == to_epoch &&
	       runtime_telemetry_bank_token_is_empty(banks_[reserved_bank_].transfer) &&
	       (standby_bank_ >= RUNTIME_TELEMETRY_BANK_COUNT ||
		(banks_[standby_bank_].state == bank_state::STANDBY && banks_[standby_bank_].epoch == from_epoch &&
		 runtime_telemetry_bank_token_is_empty(banks_[standby_bank_].transfer))) &&
	       channel_.completed_available() >= 1u;
}

bool worker_runtime_telemetry::activation_timestamp_representable(uint64_t now_ns) const noexcept
{
	return now_ns != 0u && cadence_ns_ <= UINT64_MAX - now_ns;
}

bool worker_runtime_telemetry::preflight_completed_publications(std::size_t publication_count) const noexcept
{
	return publication_count != 0u && publication_count <= channel_.capacity() &&
	       channel_.completed_available() >= publication_count;
}

void worker_runtime_telemetry::activate_target_epoch(uint64_t from_epoch, uint64_t to_epoch, uint64_t now_ns) noexcept
{
	if (!activation_timestamp_representable(now_ns) || !preflight_activate(from_epoch, to_epoch)) {
		std::terminate();
	}
	const uint8_t old_active = active_bank_;
	const uint8_t old_standby = standby_bank_;
	if (old_standby < RUNTIME_TELEMETRY_BANK_COUNT) {
		if (banks_[old_standby].state != bank_state::STANDBY || banks_[old_standby].epoch != from_epoch) {
			std::terminate();
		}
		banks_[old_standby].state = bank_state::AGGREGATED_RETAINED;
	}
	publish_bank_(old_active, runtime_telemetry_publication_reason::ACTIVATION, now_ns, old_standby);
	select_active_bank_(reserved_bank_);
	reserved_bank_ = UINT8_MAX;
	standby_bank_ = UINT8_MAX;
	old_banks_retained_for_transition_ = true;
	prepared_epoch_ = 0u;
	active_epoch_ = to_epoch;
	banks_[active_bank_].state = bank_state::ACTIVE;
	next_publication_ns_ = now_ns + cadence_ns_;
}

void worker_runtime_telemetry::accept_returned(const runtime_telemetry_bank_token &token) noexcept
{
	if (token.owner_kind != runtime_telemetry_bank_owner_kind::WORKER ||
	    token.runtime_generation != runtime_generation_ || token.worker_index != worker_index_ ||
	    token.owner_index != worker_index_ || token.stage_instance_index != UINT16_MAX ||
	    token.bank_index >= RUNTIME_TELEMETRY_BANK_COUNT || token.companion_bank_index != UINT8_MAX ||
	    token.kind != runtime_telemetry_bank_token_kind::BANK ||
	    (token.reason != runtime_telemetry_publication_reason::CADENCE &&
	     token.reason != runtime_telemetry_publication_reason::RECLAIMED) ||
	    !runtime_telemetry_bank_token_padding_zero(token)) {
		std::terminate();
	}
	auto &bank = banks_[token.bank_index];
	if (bank.state != bank_state::RETURNING || !runtime_telemetry_bank_tokens_equal(token, bank.transfer) ||
	    (token.reason == runtime_telemetry_publication_reason::CADENCE && token.published_at_ns == 0u) ||
	    (token.reason == runtime_telemetry_publication_reason::RECLAIMED && token.published_at_ns != 0u)) {
		std::terminate();
	}
	if (token.epoch == active_epoch_ && standby_bank_ == UINT8_MAX) {
		clear_bank_(token.bank_index);
		reset_bank_transfer_(token.bank_index);
		bank.epoch = active_epoch_;
		bank.state = bank_state::STANDBY;
		standby_bank_ = token.bank_index;
		old_banks_retained_for_transition_ = false;
		return;
	}
	if (channel_.completed_available() == 0u) {
		std::terminate();
	}
	bank.state = bank_state::AGGREGATED_RETAINED;
	auto acknowledgment = token;
	acknowledgment.kind = runtime_telemetry_bank_token_kind::RETURN_RETAINED;
	if (!channel_.publish_completed(acknowledgment)) {
		std::terminate();
	}
}

bool worker_runtime_telemetry::take_returned(runtime_telemetry_bank_token &token) noexcept
{
	return channel_.take_returned(token);
}

bool worker_runtime_telemetry::returned_tokens_pending() const noexcept
{
	return !channel_.returned_empty();
}

void worker_runtime_telemetry::publish_bank_(uint8_t bank_index, runtime_telemetry_publication_reason reason,
					     uint64_t now_ns, uint8_t companion_bank_index) noexcept
{
	if (bank_index >= RUNTIME_TELEMETRY_BANK_COUNT || now_ns == 0u ||
	    (companion_bank_index != UINT8_MAX &&
	     (companion_bank_index >= RUNTIME_TELEMETRY_BANK_COUNT || companion_bank_index == bank_index)) ||
	    (reason == runtime_telemetry_publication_reason::CADENCE && companion_bank_index != UINT8_MAX) ||
	    (reason != runtime_telemetry_publication_reason::CADENCE &&
	     reason != runtime_telemetry_publication_reason::ACTIVATION &&
	     reason != runtime_telemetry_publication_reason::SHUTDOWN)) {
		std::terminate();
	}
	auto &bank = banks_[bank_index];
	if ((bank.state != bank_state::ACTIVE && bank.state != bank_state::STANDBY) || bank.epoch == 0u ||
	    bank.generation == UINT64_MAX || !runtime_telemetry_bank_token_is_empty(bank.transfer)) {
		std::terminate();
	}
	if (companion_bank_index != UINT8_MAX &&
	    (banks_[companion_bank_index].state != bank_state::AGGREGATED_RETAINED ||
	     banks_[companion_bank_index].epoch != bank.epoch)) {
		std::terminate();
	}
	++bank.generation;
	bank.state = bank_state::PUBLISHED;
	const runtime_telemetry_bank_token token{
		.runtime_generation = runtime_generation_,
		.epoch = bank.epoch,
		.bank_generation = bank.generation,
		.published_at_ns = now_ns,
		.worker_index = worker_index_,
		.owner_index = worker_index_,
		.stage_instance_index = UINT16_MAX,
		.bank_index = bank_index,
		.companion_bank_index = companion_bank_index,
		.owner_kind = runtime_telemetry_bank_owner_kind::WORKER,
		.reason = reason,
		.kind = runtime_telemetry_bank_token_kind::BANK,
		.padding = {},
	};
	bank.transfer = token;
	if (!channel_.publish_completed(token)) {
		std::terminate();
	}
}

worker_runtime_telemetry_service_result worker_runtime_telemetry::service_due_(uint64_t now_ns) noexcept
{
	if (active_epoch_ == 0u || active_bank_ >= RUNTIME_TELEMETRY_BANK_COUNT || now_ns == 0u || owner_quiesced_ ||
	    now_ns < next_publication_ns_ || hot_->engine != &banks_[active_bank_].engine ||
	    hot_->stages != stage_bank_(active_bank_) || hot_->streams != stream_bank_(active_bank_) ||
	    hot_->stream_count != stream_indices_.size() ||
	    hot_->protocol_faults != banks_[active_bank_].protocol_faults.data() ||
	    hot_->stage_count != stage_indices_.size() || hot_->bank_index != active_bank_ ||
	    banks_[active_bank_].state != bank_state::ACTIVE || banks_[active_bank_].epoch != active_epoch_ ||
	    !runtime_telemetry_bank_token_is_empty(banks_[active_bank_].transfer)) {
		std::terminate();
	}
	if (cadence_ns_ > UINT64_MAX - now_ns) {
		std::terminate();
	}
	next_publication_ns_ = now_ns + cadence_ns_;
	if (standby_bank_ >= RUNTIME_TELEMETRY_BANK_COUNT) {
		auto &active = banks_[active_bank_];
		if (active.skipped_publications != UINT64_MAX) {
			++active.skipped_publications;
		}
		return {
			.return_need = runtime_telemetry_return_need::POLL_REQUIRED,
			.cadence_due = true,
		};
	}
	if (banks_[standby_bank_].state != bank_state::STANDBY || banks_[standby_bank_].epoch != active_epoch_ ||
	    !runtime_telemetry_bank_token_is_empty(banks_[standby_bank_].transfer)) {
		std::terminate();
	}
	if (channel_.completed_available() == 0u) {
		auto &active = banks_[active_bank_];
		if (active.skipped_publications != UINT64_MAX) {
			++active.skipped_publications;
		}
		return {
			.return_need = runtime_telemetry_return_need::POLL_REQUIRED,
			.cadence_due = true,
		};
	}
	const uint8_t completed = active_bank_;
	select_active_bank_(standby_bank_);
	standby_bank_ = UINT8_MAX;
	publish_bank_(completed, runtime_telemetry_publication_reason::CADENCE, now_ns);
	banks_[active_bank_].state = bank_state::ACTIVE;
	return {
		.return_need = runtime_telemetry_return_need::EXPECTED,
		.cadence_due = true,
	};
}

bool worker_runtime_telemetry::preflight_shutdown(uint64_t epoch) const noexcept
{
	if (epoch == 0u || epoch != active_epoch_ || active_bank_ >= RUNTIME_TELEMETRY_BANK_COUNT ||
	    prepared_epoch_ != 0u || reserved_bank_ != UINT8_MAX || hot_->engine != &banks_[active_bank_].engine ||
	    hot_->stages != stage_bank_(active_bank_) || hot_->streams != stream_bank_(active_bank_) ||
	    hot_->stream_count != stream_indices_.size() ||
	    hot_->protocol_faults != banks_[active_bank_].protocol_faults.data() ||
	    hot_->stage_count != stage_indices_.size() || hot_->bank_index != active_bank_ ||
	    banks_[active_bank_].state != bank_state::ACTIVE || banks_[active_bank_].epoch != epoch ||
	    !runtime_telemetry_bank_token_is_empty(banks_[active_bank_].transfer) || owner_quiesced_ ||
	    channel_.completed_available() == 0u) {
		return false;
	}
	if (standby_bank_ < RUNTIME_TELEMETRY_BANK_COUNT) {
		return free_bank_ < RUNTIME_TELEMETRY_BANK_COUNT && banks_[free_bank_].state == bank_state::FREE &&
		       banks_[free_bank_].epoch == 0u &&
		       runtime_telemetry_bank_token_is_empty(banks_[free_bank_].transfer) &&
		       banks_[standby_bank_].state == bank_state::STANDBY && banks_[standby_bank_].epoch == epoch &&
		       runtime_telemetry_bank_token_is_empty(banks_[standby_bank_].transfer);
	}
	return free_bank_ == UINT8_MAX && old_banks_retained_for_transition_;
}

void worker_runtime_telemetry::publish_shutdown(uint64_t epoch, uint64_t now_ns) noexcept
{
	if (now_ns == 0u || !preflight_shutdown(epoch)) {
		std::terminate();
	}
	const uint8_t completed = active_bank_;
	const uint8_t companion = standby_bank_;
	if (standby_bank_ < RUNTIME_TELEMETRY_BANK_COUNT) {
		banks_[standby_bank_].state = bank_state::AGGREGATED_RETAINED;
	}
	publish_bank_(completed, runtime_telemetry_publication_reason::SHUTDOWN, now_ns, companion);
	active_bank_ = UINT8_MAX;
	standby_bank_ = UINT8_MAX;
	hot_->engine = nullptr;
	hot_->stages = nullptr;
	hot_->streams = nullptr;
	hot_->stream_count = 0u;
	hot_->protocol_faults = nullptr;
	hot_->stage_count = 0u;
	hot_->bank_index = UINT8_MAX;
	active_epoch_ = 0u;
	next_publication_ns_ = 0u;
	old_banks_retained_for_transition_ = false;
}

void worker_runtime_telemetry::mark_owner_quiesced() noexcept
{
	if (owner_quiesced_ || active_epoch_ != 0u || active_bank_ != UINT8_MAX || standby_bank_ != UINT8_MAX ||
	    prepared_epoch_ != 0u || reserved_bank_ != UINT8_MAX || hot_->engine != nullptr ||
	    hot_->stages != nullptr || hot_->streams != nullptr || hot_->stream_count != 0u ||
	    hot_->protocol_faults != nullptr || hot_->stage_count != 0u || hot_->bank_index != UINT8_MAX ||
	    old_banks_retained_for_transition_) {
		std::terminate();
	}
	owner_quiesced_ = true;
}

uint32_t worker_runtime_telemetry::stage_ordinal(uint32_t stage_instance_index) const noexcept
{
	return stage_instance_index < stage_to_ordinal_.size() ? stage_to_ordinal_[stage_instance_index] : UINT32_MAX;
}

uint64_t worker_runtime_telemetry::active_epoch() const noexcept
{
	return active_epoch_;
}

uint64_t worker_runtime_telemetry::runtime_generation() const noexcept
{
	return runtime_generation_;
}

uint32_t worker_runtime_telemetry::worker_index() const noexcept
{
	return worker_index_;
}

uint64_t worker_runtime_telemetry::cadence_ns() const noexcept
{
	return cadence_ns_;
}

int32_t worker_runtime_telemetry::numa_node() const noexcept
{
	return numa_node_;
}

std::size_t worker_runtime_telemetry::storage_bytes() const noexcept
{
	return region_.size();
}

std::span<const uint32_t> worker_runtime_telemetry::stage_instance_indices() const noexcept
{
	return stage_indices_;
}

std::span<const uint32_t> worker_runtime_telemetry::io_stream_indices() const noexcept
{
	return stream_indices_;
}

uint32_t worker_runtime_telemetry::stream_ordinal(uint32_t io_stream_index) const noexcept
{
	const auto found = std::lower_bound(stream_indices_.begin(), stream_indices_.end(), io_stream_index);
	return found != stream_indices_.end() && *found == io_stream_index ?
		       static_cast<uint32_t>(found - stream_indices_.begin()) :
		       UINT32_MAX;
}

bool worker_runtime_telemetry::owns_channel(const worker_telemetry_channel &channel) const noexcept
{
	return &channel_ == &channel;
}

bool worker_runtime_telemetry::token_matches_(const runtime_telemetry_bank_token &token,
					      const bank_header &bank) const noexcept
{
	return token.runtime_generation == runtime_generation_ && token.worker_index == worker_index_ &&
	       token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER && token.owner_index == worker_index_ &&
	       token.stage_instance_index == UINT16_MAX && token.bank_index < RUNTIME_TELEMETRY_BANK_COUNT &&
	       token.epoch == bank.epoch && token.bank_generation == bank.generation && token.published_at_ns != 0u &&
	       token.kind == runtime_telemetry_bank_token_kind::BANK &&
	       runtime_telemetry_bank_token_padding_zero(token) &&
	       runtime_telemetry_bank_tokens_equal(token, bank.transfer);
}

common::status_or<worker_runtime_telemetry_bank_view>
worker_runtime_telemetry::completed_bank(const runtime_telemetry_bank_token &token) const noexcept
{
	if (token.bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
		return common::status::invalid_argument(
			kinetum::common::static_status_text("worker telemetry token bank index is invalid"));
	}
	const auto &bank = banks_[token.bank_index];
	if (bank.state != bank_state::PUBLISHED || !token_matches_(token, bank)) {
		return common::status::failed_precondition(
			kinetum::common::static_status_text("worker telemetry token does not own its exact bank"));
	}
	return worker_runtime_telemetry_bank_view{
		.engine = bank.engine,
		.streams = std::span<const worker_stream_telemetry_counters>(stream_bank_(token.bank_index),
									     stream_indices_.size()),
		.stages = std::span<const worker_stage_telemetry_counters>(stage_bank_(token.bank_index),
									   stage_indices_.size()),
		.protocol_faults = bank.protocol_faults,
		.skipped_publications = bank.skipped_publications,
	};
}

void worker_runtime_telemetry::complete_aggregation(const runtime_telemetry_bank_token &token) noexcept
{
	if (token.bank_index >= RUNTIME_TELEMETRY_BANK_COUNT || !completed_bank(token).is_ok()) {
		std::terminate();
	}
	auto &bank = banks_[token.bank_index];
	clear_bank_(token.bank_index);
	if (token.reason == runtime_telemetry_publication_reason::CADENCE) {
		bank.state = bank_state::RETURNING;
		if (!channel_.return_cleared(token)) {
			std::terminate();
		}
		return;
	}
	bank.state = bank_state::AGGREGATED_RETAINED;
}

bool worker_runtime_telemetry::epoch_aggregated(uint64_t epoch) const noexcept
{
	return epoch != 0u && aggregated_epoch_ == epoch;
}

void worker_runtime_telemetry::mark_epoch_aggregated(uint64_t epoch) noexcept
{
	if (epoch == 0u || aggregated_epoch_ != 0u) {
		std::terminate();
	}
	std::size_t retained = 0u;
	for (const auto &bank : std::span<const bank_header>(banks_, RUNTIME_TELEMETRY_BANK_COUNT)) {
		if (bank.epoch != epoch) {
			continue;
		}
		if (bank.state != bank_state::AGGREGATED_RETAINED) {
			std::terminate();
		}
		++retained;
	}
	if (retained != 2u) {
		std::terminate();
	}
	aggregated_epoch_ = epoch;
}

std::optional<runtime_telemetry_bank_token> worker_runtime_telemetry::retire_epoch(uint64_t epoch,
										   uint64_t active_epoch) noexcept
{
	if (!epoch_aggregated(epoch) || (active_epoch != 0u && free_bank_ != UINT8_MAX) ||
	    (active_epoch != 0u && !owner_quiesced_ && active_epoch != active_epoch_)) {
		std::terminate();
	}
	uint8_t return_index = UINT8_MAX;
	std::size_t retired_bank_count = 0u;
	std::size_t successor_bank_count = 0u;
	std::size_t free_bank_count = 0u;
	for (uint8_t index = 0u; index < RUNTIME_TELEMETRY_BANK_COUNT; ++index) {
		const auto &bank = banks_[index];
		if (bank.epoch != epoch) {
			if (active_epoch == 0u && index == free_bank_ && bank.epoch == 0u &&
			    bank.state == bank_state::FREE && runtime_telemetry_bank_token_is_empty(bank.transfer)) {
				++free_bank_count;
			}
			if (active_epoch != 0u && bank.epoch == active_epoch &&
			    bank.state == (owner_quiesced_ ? bank_state::AGGREGATED_RETAINED : bank_state::ACTIVE) &&
			    (owner_quiesced_ || index == active_bank_) &&
			    (owner_quiesced_ ? !runtime_telemetry_bank_token_is_empty(bank.transfer) :
					       runtime_telemetry_bank_token_is_empty(bank.transfer))) {
				++successor_bank_count;
			}
			continue;
		}
		if (bank.state != bank_state::AGGREGATED_RETAINED) {
			std::terminate();
		}
		++retired_bank_count;
		if (active_epoch != 0u && return_index == UINT8_MAX && bank.generation != 0u) {
			return_index = index;
		}
	}
	if (retired_bank_count != 2u || (active_epoch == 0u && free_bank_count != 1u) ||
	    (active_epoch != 0u && (return_index == UINT8_MAX || successor_bank_count != 1u))) {
		std::terminate();
	}
	std::optional<runtime_telemetry_bank_token> transfer;
	uint8_t returned = UINT8_MAX;
	uint8_t freed = UINT8_MAX;
	for (uint8_t index = 0u; index < RUNTIME_TELEMETRY_BANK_COUNT; ++index) {
		auto &bank = banks_[index];
		if (bank.epoch != epoch) {
			continue;
		}
		clear_bank_(index);
		reset_bank_transfer_(index);
		if (active_epoch != 0u && index == return_index) {
			bank.epoch = active_epoch;
			bank.state = owner_quiesced_ ? bank_state::AGGREGATED_RETAINED : bank_state::RETURNING;
			runtime_telemetry_bank_token token{
				.runtime_generation = runtime_generation_,
				.epoch = active_epoch,
				.bank_generation = bank.generation,
				.published_at_ns = 0u,
				.worker_index = worker_index_,
				.owner_index = worker_index_,
				.stage_instance_index = UINT16_MAX,
				.bank_index = index,
				.companion_bank_index = UINT8_MAX,
				.owner_kind = runtime_telemetry_bank_owner_kind::WORKER,
				.reason = runtime_telemetry_publication_reason::RECLAIMED,
				.kind = owner_quiesced_ ? runtime_telemetry_bank_token_kind::RETURN_RETAINED :
							  runtime_telemetry_bank_token_kind::BANK,
				.padding = {},
			};
			bank.transfer = token;
			if (!owner_quiesced_ && !channel_.return_cleared(token)) {
				std::terminate();
			}
			transfer = token;
			returned = index;
		} else {
			bank.epoch = 0u;
			bank.state = bank_state::FREE;
			if (active_epoch != 0u) {
				if (freed != UINT8_MAX) {
					std::terminate();
				}
				freed = index;
			}
		}
	}
	if (active_epoch != 0u) {
		if (returned == UINT8_MAX || freed == UINT8_MAX) {
			std::terminate();
		}
		free_bank_ = freed;
	} else {
		for (const auto &bank : std::span<const bank_header>(banks_, RUNTIME_TELEMETRY_BANK_COUNT)) {
			if (bank.state != bank_state::FREE || bank.epoch != 0u ||
			    !runtime_telemetry_bank_token_is_empty(bank.transfer)) {
				std::terminate();
			}
		}
		free_bank_ = UINT8_MAX;
	}
	aggregated_epoch_ = 0u;
	return transfer;
}

bool worker_runtime_telemetry::empty() const noexcept
{
	if (active_epoch_ != 0u || prepared_epoch_ != 0u || active_bank_ != UINT8_MAX || standby_bank_ != UINT8_MAX ||
	    reserved_bank_ != UINT8_MAX || free_bank_ != UINT8_MAX || aggregated_epoch_ != 0u ||
	    hot_->engine != nullptr || hot_->stages != nullptr || hot_->streams != nullptr ||
	    hot_->stream_count != 0u || hot_->protocol_faults != nullptr || hot_->stage_count != 0u ||
	    hot_->bank_index != UINT8_MAX || old_banks_retained_for_transition_ || !channel_.empty()) {
		return false;
	}
	for (uint8_t index = 0u; index < RUNTIME_TELEMETRY_BANK_COUNT; ++index) {
		if (banks_[index].state != bank_state::FREE || banks_[index].epoch != 0u ||
		    !runtime_telemetry_bank_token_is_empty(banks_[index].transfer)) {
			return false;
		}
	}
	return true;
}

}  // namespace kinetum::dp
