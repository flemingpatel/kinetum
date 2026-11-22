// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_native_handoff.cpp
 * @brief Stage service and receipt retirement for a synchronous native handoff.
 * @author Fleming Patel
 */

#include "src/dp/worker_native_handoff.hpp"

#include <algorithm>
#include <exception>
#include <memory>

#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"

namespace kinetum::dp
{
worker_native_handoff::worker_native_handoff(native_packet_binding binding, uint32_t tx_key,
					     packet_epoch_input_staging &staging, worker_epoch_ledger &ledger,
					     worker_runtime_telemetry &telemetry, std::span<native_packet_slot> slots,
					     std::span<native_packet_slot *> free_slots) noexcept
	: binding_(binding)
	, tx_key_(tx_key)
	, staging_(staging)
	, ledger_(ledger)
	, telemetry_(telemetry)
	, free_slots_(free_slots)
	, free_count_(slots.size())
{
	if (slots.size() != free_slots.size() ||
	    free_slots.size() != staging.active_capacity() + staging.future_capacity()) {
		std::terminate();
	}
	for (std::size_t index = 0; index < slots.size(); ++index) {
		std::construct_at(&free_slots_[index], std::construct_at(&slots[index]));
	}
}

kinetum_packet_rx_burst_result worker_native_handoff::receive(const admission &input, uint64_t &bytes) noexcept
{
	const auto capacity = input.capacity;
	if (capacity > MAX_BURST || capacity > free_count_) {
		std::terminate();
	}
	const auto result = binding_.rx->receive_native(binding_.rx->state, incoming_.data(), capacity);
	const auto count = result.transferred_count;
	if (!kinetum_packet_rx_burst_result_is_valid(result, capacity)) {
		std::terminate();
	}
	for (uint16_t index = count; index < capacity; ++index) {
		const auto &view = incoming_[index];
		if (view.handle != nullptr || view.data_start != nullptr || view.length != 0u || view.reserved != 0u) {
			std::terminate();
		}
	}
	bytes = 0u;
	if (count == 0u) {
		return result;
	}
	for (uint16_t index = 0; index < count; ++index) {
		const auto view = incoming_[index];
		if (view.handle == nullptr || view.data_start == nullptr || view.length == 0u ||
		    view.length > binding_.storage->owner->maximum_packet_length || view.reserved != 0u) {
			std::terminate();
		}
		auto *slot = free_slots_[--free_count_];
		*slot = {view, input.timestamp, input.epoch};
		scratch_[index] = slot;
		incoming_[index] = {};
		bytes += view.length;
	}
	ledger_.acquire(input.epoch, count);
	const std::span<native_packet_slot *const> prefix(scratch_.data(), count);
	if (input.future) {
		staging_.commit_future_prefix(input.key, prefix);
	} else {
		staging_.commit_active_prefix(input.key, prefix);
	}
	return result;
}

void worker_native_handoff::service(uint64_t epoch) noexcept
{
	staging_.service_native(scratch_, [&](const packet_work_key &key,
					      std::span<native_packet_slot *const> slots) noexcept {
		const bool ingress = key.phase == packet_work_phase::RX_DELIVER &&
				     key.stage_instance_index == binding_.rx_stage;
		if (!ingress &&
		    (key.phase != packet_work_phase::EXECUTE || key.stage_instance_index != binding_.tx_stage)) {
			std::terminate();
		}
		uint64_t bytes = 0u;
		for (const auto *slot : slots) {
			if (slot == nullptr || slot->epoch != epoch) {
				std::terminate();
			}
			bytes += slot->view.length;
		}
		const auto count = static_cast<uint16_t>(slots.size());
		const auto stage = ingress ? binding_.rx_stage_counter : binding_.tx_stage_counter;
		telemetry_.record_stage_input(stage, count, bytes);
		if (ingress) {
			staging_.commit_active_prefix(tx_key_, slots);
			telemetry_.record_stage_output(stage, bytes, count);
			return;
		}
		for (auto *slot : slots) {
			pending_[tx_count_++] = slot;
			if (tx_count_ == binding_.tx->maximum_burst) {
				flush();
			}
		}
	});
}

void worker_native_handoff::flush() noexcept
{
	const uint16_t count = tx_count_;
	if (count == 0u) {
		return;
	}
	std::array<kinetum_packet_native_view, MAX_BURST> offered;
	const auto epoch = pending_[0]->epoch;
	for (uint16_t index = 0u; index < count; ++index) {
		if (pending_[index]->epoch != epoch) {
			std::terminate();
		}
		offered[index] = pending_[index]->view;
	}
	const uint16_t accepted = binding_.tx->transmit_native(binding_.tx->state, offered.data(), count);
	if (accepted > count || count > free_slots_.size() - free_count_) {
		std::terminate();
	}
	const auto refused = static_cast<uint16_t>(count - accepted);
	for (uint16_t index = accepted; index < count; ++index) {
		const auto &saved = pending_[index]->view;
		const auto &returned = offered[index];
		if (saved.handle != returned.handle || saved.data_start != returned.data_start ||
		    saved.length != returned.length || saved.reserved != returned.reserved) {
			std::terminate();
		}
	}
	const auto &storage = *binding_.storage;
	if (refused != 0u && storage.verify(storage.owner->state, offered.data() + accepted, refused) != 1u) {
		std::terminate();
	}
	uint64_t bytes = 0u;
	for (uint16_t index = 0u; index < accepted; ++index) {
		bytes += pending_[index]->view.length;
	}
	if (accepted != 0u) {
		telemetry_.record_stage_output(binding_.tx_stage_counter, bytes, accepted);
	}
	if (refused != 0u) {
		storage.release(storage.owner->state, offered.data() + accepted, refused);
		for (uint16_t index = accepted; index < count; ++index) {
			telemetry_.record_stage_drop(binding_.tx_stage_counter);
			telemetry_.record_drop();
		}
	}
	telemetry_.record_stream(binding_.tx_stream_counter, accepted, bytes, refused);
	ledger_.retire(epoch, count);
	staging_.release_active_reservation(count);
	std::copy_n(pending_.begin(), count, free_slots_.subspan(free_count_, count).begin());
	free_count_ += count;
	tx_count_ = 0u;
}
}  // namespace kinetum::dp
