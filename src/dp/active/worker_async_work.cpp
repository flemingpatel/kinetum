// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_async_work.cpp
 * @brief Exact foreign-work token and completion ownership implementation.
 * @author Fleming Patel
 */

#include "src/dp/active/worker_async_work.hpp"

#include <bit>
#include <exception>
#include <limits>

#include "src/common/status.hpp"

namespace kinetum::dp
{

constexpr uint64_t worker_async_work::pack_identity_(uint32_t generation, slot_state state) noexcept
{
	return (static_cast<uint64_t>(generation) << 32u) | static_cast<uint8_t>(state);
}

constexpr uint32_t worker_async_work::generation_(uint64_t identity) noexcept
{
	return static_cast<uint32_t>(identity >> 32u);
}

constexpr worker_async_work::slot_state worker_async_work::state_(uint64_t identity) noexcept
{
	return static_cast<slot_state>(identity & UINT8_MAX);
}

constexpr bool worker_async_work::state_encoding_valid_(uint64_t identity) noexcept
{
	return (identity & UINT32_MAX) <= static_cast<uint8_t>(slot_state::PUBLISHED);
}

constexpr bool worker_async_work::callback_claim_empty_(const callback_claim &claim) noexcept
{
	return claim.token_handle == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE && claim.epoch == 0u &&
	       claim.user_tag == 0u && claim.owner_index == UINT32_MAX && claim.released_slot == UINT32_MAX &&
	       claim.retained_slot == UINT32_MAX && claim.outcome == KINETUM_ASYNC_OUTCOME_UNSPECIFIED &&
	       !claim.standalone && claim.padding[0] == 0u && claim.padding[1] == 0u && claim.padding[2] == 0u;
}

constexpr uint32_t worker_async_work::handle_slot_(uint64_t handle) noexcept
{
	return static_cast<uint32_t>(handle & UINT32_MAX);
}

constexpr uint32_t worker_async_work::handle_generation_(uint64_t handle) noexcept
{
	return static_cast<uint32_t>(handle >> 32u);
}

uint64_t worker_async_work::make_handle_(uint32_t generation, uint32_t slot) noexcept
{
	const uint64_t handle = (static_cast<uint64_t>(generation) << 32u) | slot;
	if (generation == 0u || handle == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE) {
		std::terminate();
	}
	return handle;
}

worker_async_work::worker_async_work(construction_binding binding) noexcept
	: runtime_generation_(binding.runtime_generation)
	, worker_index_(binding.worker_index)
	, ledger_(binding.ledger)
	, slots_(binding.slots)
	, slot_count_(binding.slot_count)
	, queue_(binding.queue_storage, binding.queue_capacity)
{
	if (runtime_generation_ == 0u || worker_index_ == UINT32_MAX || ledger_ == nullptr ||
	    ledger_->runtime_generation() != runtime_generation_ || ledger_->worker_index() != worker_index_ ||
	    slots_ == nullptr || slot_count_ == 0u) {
		std::terminate();
	}
	auto exact_capacity_or = queue_capacity_for(slot_count_);
	if (!exact_capacity_or.is_ok() || binding.queue_capacity != exact_capacity_or.value()) {
		std::terminate();
	}
	for (uint32_t index = 0u; index < slot_count_; ++index) {
		const auto &slot = slots_[index];
		if (slot.identity_state.load(std::memory_order_relaxed) != 0u ||
		    slot.epoch.load(std::memory_order_relaxed) != 0u || slot.user_tag != 0u || slot.owner_index != 0u ||
		    slot.retained_slot != UINT32_MAX || slot.next_free != UINT32_MAX || slot.standalone ||
		    slot.owner_claimed) {
			std::terminate();
		}
		for (const uint8_t byte : slot.padding) {
			if (byte != 0u) {
				std::terminate();
			}
		}
	}
}

worker_async_work::~worker_async_work()
{
	if (!empty()) {
		std::terminate();
	}
	for (const auto &claim : callback_claims_) {
		if (!callback_claim_empty_(claim)) {
			std::terminate();
		}
	}
	for (uint32_t index = 0u; index < slot_count_; ++index) {
		const auto &slot = slots_[index];
		const uint64_t identity = slot.identity_state.load(std::memory_order_relaxed);
		if (!state_encoding_valid_(identity) || state_(identity) != slot_state::EMPTY ||
		    slot.epoch.load(std::memory_order_relaxed) != 0u || slot.user_tag != 0u || slot.owner_index != 0u ||
		    slot.retained_slot != UINT32_MAX || slot.standalone || slot.owner_claimed) {
			std::terminate();
		}
		for (const uint8_t byte : slot.padding) {
			if (byte != 0u) {
				std::terminate();
			}
		}
	}
}

common::status_or<std::size_t> worker_async_work::queue_capacity_for(std::size_t logical_slots) noexcept
{
	if (logical_slots == 0u || logical_slots > UINT32_MAX) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "async logical token capacity is outside the compact slot domain"));
	}
	std::size_t capacity = 2u;
	while (capacity < logical_slots) {
		if (capacity > std::numeric_limits<std::size_t>::max() / 2u) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      kinetum::common::static_status_text(
						      "async completion queue capacity is not representable"));
		}
		capacity *= 2u;
	}
	if (!completion_queue::valid_capacity(capacity)) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "async completion queue exceeds the MPMC modular counter domain"));
	}
	return capacity;
}

kinetum_async_token worker_async_work::begin(begin_request request) noexcept
{
	if (request.slot_index >= slot_count_ || request.owner_index == UINT32_MAX || request.epoch == 0u ||
	    ledger_ == nullptr || request.epoch != ledger_->active_epoch() ||
	    !slots_[request.slot_index].owner_claimed ||
	    (request.standalone == (request.retained_slot != UINT32_MAX))) {
		std::terminate();
	}
	if (live_count_ >= slot_count_) {
		std::terminate();
	}
	auto &slot = slots_[request.slot_index];
	const uint64_t current = slot.identity_state.load(std::memory_order_acquire);
	if (!state_encoding_valid_(current) || state_(current) != slot_state::EMPTY ||
	    slot.epoch.load(std::memory_order_relaxed) != 0u || slot.user_tag != 0u || slot.owner_index != 0u ||
	    slot.retained_slot != UINT32_MAX || slot.next_free != UINT32_MAX || slot.standalone) {
		std::terminate();
	}
	for (const uint8_t byte : slot.padding) {
		if (byte != 0u) {
			std::terminate();
		}
	}
	const uint32_t old_generation = generation_(current);
	if (old_generation == UINT32_MAX) {
		std::terminate();
	}
	const uint32_t generation = old_generation + 1u;
	if (request.standalone) {
		ledger_->acquire(request.epoch);
	}
	slot.epoch.store(request.epoch, std::memory_order_relaxed);
	slot.user_tag = request.user_tag;
	slot.owner_index = request.owner_index;
	slot.retained_slot = request.retained_slot;
	slot.standalone = request.standalone;
	slot.identity_state.store(pack_identity_(generation, slot_state::LIVE), std::memory_order_release);
	++live_count_;
	return kinetum_async_token{
		.handle = {make_handle_(generation, request.slot_index)},
		.ops = &token_ops_,
		.platform_opaque = this,
	};
}

std::optional<worker_async_abort_result> worker_async_work::abort(const kinetum_async_token &token,
								  uint32_t expected_owner) noexcept
{
	if (token.ops != &token_ops_ || token.platform_opaque != this ||
	    token.handle.value == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE) {
		return std::nullopt;
	}
	const uint32_t slot_index = handle_slot_(token.handle.value);
	const uint32_t generation = handle_generation_(token.handle.value);
	if (slot_index >= slot_count_ || generation == 0u) {
		return std::nullopt;
	}
	auto &slot = slots_[slot_index];
	const uint64_t identity = slot.identity_state.load(std::memory_order_acquire);
	const uint64_t slot_epoch = slot.epoch.load(std::memory_order_relaxed);
	if (identity != pack_identity_(generation, slot_state::LIVE) || slot.owner_index != expected_owner) {
		return std::nullopt;
	}
	if (slot_epoch == 0u || ledger_ == nullptr || slot_epoch != ledger_->active_epoch() || live_count_ == 0u ||
	    !slot.owner_claimed || slot.owner_index == UINT32_MAX || slot.next_free != UINT32_MAX ||
	    (slot.standalone == (slot.retained_slot != UINT32_MAX))) {
		std::terminate();
	}
	for (const uint8_t byte : slot.padding) {
		if (byte != 0u) {
			std::terminate();
		}
	}
	uint64_t expected = pack_identity_(generation, slot_state::LIVE);
	if (!slot.identity_state.compare_exchange_strong(expected, pack_identity_(generation, slot_state::EMPTY),
							 std::memory_order_acq_rel, std::memory_order_acquire)) {
		return std::nullopt;
	}
	const worker_async_abort_result result{
		.owner_index = slot.owner_index,
		.released_slot = slot_index,
		.retained_slot = slot.retained_slot,
		.standalone = slot.standalone,
	};
	if (slot.standalone) {
		ledger_->retire(slot_epoch);
	}
	--live_count_;
	slot.epoch.store(0u, std::memory_order_relaxed);
	slot.user_tag = 0u;
	slot.owner_index = 0u;
	slot.retained_slot = UINT32_MAX;
	slot.standalone = false;
	return result;
}

bool worker_async_work::try_take(worker_async_delivery &out) noexcept
{
	if (static_cast<uint32_t>(std::popcount(callback_owned_mask_)) != callback_count_) {
		std::terminate();
	}
	if (callback_count_ >= MAX_CALLBACK_DELIVERIES) {
		return false;
	}
	completion_cell cell{};
	if (!queue_.try_dequeue(cell)) {
		return false;
	}
	const uint32_t slot_index = handle_slot_(cell.handle.value);
	const uint32_t generation = handle_generation_(cell.handle.value);
	if (slot_index >= slot_count_ || generation == 0u || cell.outcome <= KINETUM_ASYNC_OUTCOME_UNSPECIFIED ||
	    cell.outcome > KINETUM_ASYNC_OUTCOME_FAILED || cell.padding != 0u) {
		std::terminate();
	}
	auto &slot = slots_[slot_index];
	const uint64_t identity = slot.identity_state.load(std::memory_order_acquire);
	const uint64_t slot_epoch = slot.epoch.load(std::memory_order_relaxed);
	if (identity != pack_identity_(generation, slot_state::PUBLISHED) || slot_epoch == 0u ||
	    slot_epoch != ledger_->active_epoch() || live_count_ == 0u || !slot.owner_claimed ||
	    slot.owner_index == UINT32_MAX || slot.next_free != UINT32_MAX ||
	    (slot.standalone == (slot.retained_slot != UINT32_MAX))) {
		std::terminate();
	}
	for (const uint8_t byte : slot.padding) {
		if (byte != 0u) {
			std::terminate();
		}
	}
	const uint64_t free_mask = ~callback_owned_mask_;
	if (free_mask == 0u) {
		std::terminate();
	}
	const uint8_t callback_slot = static_cast<uint8_t>(std::countr_zero(free_mask));
	if (callback_slot >= callback_generations_.size() || callback_generations_[callback_slot] == UINT32_MAX ||
	    !callback_claim_empty_(callback_claims_[callback_slot])) {
		std::terminate();
	}
	const uint32_t callback_generation = ++callback_generations_[callback_slot];
	callback_owned_mask_ |= UINT64_C(1) << callback_slot;
	++callback_count_;
	--live_count_;
	callback_claims_[callback_slot] = callback_claim{
		.token_handle = cell.handle.value,
		.epoch = slot_epoch,
		.user_tag = slot.user_tag,
		.owner_index = slot.owner_index,
		.released_slot = slot_index,
		.retained_slot = slot.retained_slot,
		.outcome = cell.outcome,
		.standalone = slot.standalone,
		.padding = {},
	};
	out = worker_async_delivery{
		.completion =
			{
				.handle = cell.handle,
				.retained = {KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE},
				.user_tag = slot.user_tag,
				.outcome = cell.outcome,
				._padding = 0u,
			},
		.epoch = slot_epoch,
		.owner_index = slot.owner_index,
		.released_slot = slot_index,
		.retained_slot = slot.retained_slot,
		.callback_generation = callback_generation,
		.callback_slot = callback_slot,
		.standalone = slot.standalone,
		.padding = {},
	};
	slot.epoch.store(0u, std::memory_order_relaxed);
	slot.user_tag = 0u;
	slot.owner_index = 0u;
	slot.retained_slot = UINT32_MAX;
	slot.standalone = false;
	slot.identity_state.store(pack_identity_(generation, slot_state::EMPTY), std::memory_order_release);
	return true;
}

bool worker_async_work::slot_release_ready(uint32_t slot_index) const noexcept
{
	if (slot_index >= slot_count_) {
		return false;
	}
	const auto &slot = slots_[slot_index];
	const uint64_t identity = slot.identity_state.load(std::memory_order_acquire);
	if (!state_encoding_valid_(identity) || state_(identity) != slot_state::EMPTY || generation_(identity) == 0u ||
	    slot.epoch.load(std::memory_order_relaxed) != 0u || slot.user_tag != 0u || slot.owner_index != 0u ||
	    slot.retained_slot != UINT32_MAX || slot.next_free != UINT32_MAX || slot.standalone ||
	    !slot.owner_claimed) {
		return false;
	}
	for (const uint8_t byte : slot.padding) {
		if (byte != 0u) {
			return false;
		}
	}
	return true;
}

void worker_async_work::complete_delivery(const worker_async_delivery &delivery) noexcept
{
	if (static_cast<uint32_t>(std::popcount(callback_owned_mask_)) != callback_count_) {
		std::terminate();
	}
	const callback_claim *claim =
		delivery.callback_slot < callback_claims_.size() ? &callback_claims_[delivery.callback_slot] : nullptr;
	if (delivery.callback_slot >= callback_generations_.size() || delivery.callback_generation == 0u ||
	    callback_generations_[delivery.callback_slot] != delivery.callback_generation ||
	    (callback_owned_mask_ & (UINT64_C(1) << delivery.callback_slot)) == 0u || callback_count_ == 0u ||
	    delivery.epoch == 0u || delivery.epoch != ledger_->active_epoch() || delivery.owner_index == UINT32_MAX ||
	    delivery.released_slot >= slot_count_ ||
	    delivery.completion.handle.value == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE ||
	    handle_slot_(delivery.completion.handle.value) != delivery.released_slot ||
	    handle_generation_(delivery.completion.handle.value) == 0u ||
	    delivery.completion.outcome <= KINETUM_ASYNC_OUTCOME_UNSPECIFIED ||
	    delivery.completion.outcome > KINETUM_ASYNC_OUTCOME_FAILED || delivery.completion._padding != 0u ||
	    delivery.standalone == (delivery.retained_slot != UINT32_MAX) || claim == nullptr ||
	    claim->token_handle != delivery.completion.handle.value || claim->epoch != delivery.epoch ||
	    claim->user_tag != delivery.completion.user_tag || claim->owner_index != delivery.owner_index ||
	    claim->released_slot != delivery.released_slot || claim->retained_slot != delivery.retained_slot ||
	    claim->outcome != delivery.completion.outcome || claim->standalone != delivery.standalone) {
		std::terminate();
	}
	for (const uint8_t byte : delivery.padding) {
		if (byte != 0u) {
			std::terminate();
		}
	}
	for (const uint8_t byte : claim->padding) {
		if (byte != 0u) {
			std::terminate();
		}
	}
	if (delivery.standalone) {
		if (delivery.completion.retained.value != KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
			std::terminate();
		}
		ledger_->retire(delivery.epoch);
	} else if (delivery.completion.retained.value == KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
		std::terminate();
	}
	callback_owned_mask_ &= ~(UINT64_C(1) << delivery.callback_slot);
	--callback_count_;
	callback_claims_[delivery.callback_slot] = {};
}

void worker_async_work::begin_cancellation(uint64_t epoch) noexcept
{
	if (epoch == 0u || ledger_ == nullptr || ledger_->active_epoch() != epoch ||
	    cancellation_.epoch.load(std::memory_order_relaxed) != 0u) {
		std::terminate();
	}
	cancellation_.epoch.store(epoch, std::memory_order_release);
}

void worker_async_work::finish_cancellation(uint64_t epoch) noexcept
{
	if (epoch == 0u || ledger_ == nullptr || !drained() ||
	    cancellation_.epoch.load(std::memory_order_relaxed) != epoch) {
		std::terminate();
	}
	cancellation_.epoch.store(0u, std::memory_order_release);
}

uint32_t worker_async_work::slot_count() const noexcept
{
	return slot_count_;
}

uint32_t worker_async_work::live_count() const noexcept
{
	return live_count_;
}

uint32_t worker_async_work::callback_count() const noexcept
{
	return callback_count_;
}

uint64_t worker_async_work::cancellation_epoch() const noexcept
{
	return cancellation_.epoch.load(std::memory_order_acquire);
}

bool worker_async_work::empty() const noexcept
{
	return drained() && cancellation_.epoch.load(std::memory_order_relaxed) == 0u;
}

bool worker_async_work::drained() const noexcept
{
	return live_count_ == 0u && callback_count_ == 0u && callback_owned_mask_ == 0u && queue_.empty();
}

bool worker_async_work::complete_foreign_(const kinetum_async_token *token, kinetum_async_outcome outcome) noexcept
{
	if (token == nullptr || token->ops == nullptr || token->platform_opaque == nullptr ||
	    token->handle.value == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE ||
	    outcome <= KINETUM_ASYNC_OUTCOME_UNSPECIFIED || outcome > KINETUM_ASYNC_OUTCOME_FAILED) {
		return false;
	}
	auto *owner = static_cast<worker_async_work *>(token->platform_opaque);
	if (token->ops != &owner->token_ops_) {
		return false;
	}
	const uint32_t slot_index = handle_slot_(token->handle.value);
	const uint32_t generation = handle_generation_(token->handle.value);
	if (slot_index >= owner->slot_count_ || generation == 0u) {
		return false;
	}
	auto &slot = owner->slots_[slot_index];
	uint64_t expected = pack_identity_(generation, slot_state::LIVE);
	if (!slot.identity_state.compare_exchange_strong(expected, pack_identity_(generation, slot_state::PUBLISHING),
							 std::memory_order_acq_rel, std::memory_order_acquire)) {
		return false;
	}
	if (slot.epoch.load(std::memory_order_relaxed) == 0u || !slot.owner_claimed || slot.owner_index == UINT32_MAX ||
	    slot.next_free != UINT32_MAX || (slot.standalone == (slot.retained_slot != UINT32_MAX))) {
		std::terminate();
	}
	for (const uint8_t byte : slot.padding) {
		if (byte != 0u) {
			std::terminate();
		}
	}
	slot.identity_state.store(pack_identity_(generation, slot_state::PUBLISHED), std::memory_order_release);
	if (!owner->queue_.try_enqueue(completion_cell{token->handle, outcome})) {
		std::terminate();
	}
	return true;
}

bool worker_async_work::cancellation_requested_foreign_(const kinetum_async_token *token) noexcept
{
	if (token == nullptr || token->ops == nullptr || token->platform_opaque == nullptr ||
	    token->handle.value == KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE) {
		return true;
	}
	auto *owner = static_cast<worker_async_work *>(token->platform_opaque);
	if (token->ops != &owner->token_ops_) {
		return true;
	}
	const uint32_t slot_index = handle_slot_(token->handle.value);
	const uint32_t generation = handle_generation_(token->handle.value);
	if (slot_index >= owner->slot_count_ || generation == 0u) {
		return true;
	}
	const auto &slot = owner->slots_[slot_index];
	const uint64_t identity = slot.identity_state.load(std::memory_order_acquire);
	if (identity != pack_identity_(generation, slot_state::LIVE)) {
		return true;
	}
	const uint64_t slot_epoch = slot.epoch.load(std::memory_order_relaxed);
	const uint64_t cancellation_epoch = owner->cancellation_.epoch.load(std::memory_order_acquire);
	return slot_epoch == 0u || cancellation_epoch != 0u;
}

}  // namespace kinetum::dp
