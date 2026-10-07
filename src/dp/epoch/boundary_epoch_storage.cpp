// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file boundary_epoch_storage.cpp
 * @brief Checked worker-local boundary endpoint slab implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/boundary_epoch_storage.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <new>
#include <utility>

#include "src/common/status.hpp"

namespace kinetum::dp
{

namespace
{

/**
 * @brief Round one extent to a nonzero power-of-two alignment.
 *
 * @param value Candidate byte extent.
 * @param alignment Required nonzero power-of-two alignment.
 * @param[out] out Exact aligned extent on success.
 * @return true when the alignment contract and result are representable.
 */
[[nodiscard]] bool round_up_checked(std::size_t value, std::size_t alignment, std::size_t &out) noexcept
{
	if (alignment == 0u || (alignment & (alignment - 1u)) != 0u) {
		return false;
	}
	const std::size_t mask = alignment - 1u;
	if (value > std::numeric_limits<std::size_t>::max() - mask) {
		return false;
	}
	out = (value + mask) & ~mask;
	return true;
}

/**
 * @brief Append one aligned fixed-stride array to a checked slab layout.
 *
 * @param cursor Current complete byte extent.
 * @param count Number of array elements.
 * @param stride Exact nonzero element stride.
 * @param alignment Exact nonzero power-of-two element alignment.
 * @param[out] offset First array byte, or the unchanged cursor for zero count.
 * @return true when alignment and multiplication are representable.
 */
[[nodiscard]] bool append_array_checked(std::size_t &cursor, std::size_t count, std::size_t stride,
					std::size_t alignment, std::size_t &offset) noexcept
{
	if (count == 0u) {
		offset = cursor;
		return true;
	}
	if (stride == 0u || count > std::numeric_limits<std::size_t>::max() / stride) {
		return false;
	}
	std::size_t aligned = 0u;
	if (!round_up_checked(cursor, alignment, aligned)) {
		return false;
	}
	const std::size_t bytes = count * stride;
	if (bytes > std::numeric_limits<std::size_t>::max() - aligned) {
		return false;
	}
	offset = aligned;
	cursor = aligned + bytes;
	return true;
}

}  // namespace

bool boundary_epoch_worker_slab::sender_slot::empty() const noexcept
{
	return !owner.cut_pending && ack_ring.empty() && policy.transition_generation == 0u &&
	       policy.open_epoch == 0u && policy.from_epoch == 0u && policy.to_epoch == 0u &&
	       policy.cut_sequence == 0u && policy.duplicate_ack_count == 0u &&
	       policy.phase == boundary_epoch_sender_phase::UNBOUND && timing.cut_published_monotonic_ns == 0u &&
	       timing.ack_observed_monotonic_ns == 0u &&
	       std::all_of(timing.padding.begin(), timing.padding.end(), [](uint8_t byte) { return byte == 0u; });
}

bool boundary_epoch_worker_slab::sender_slot::pristine() const noexcept
{
	return empty() && !owner.closed && owner.data_enqueued.value() == 0u && owner.data_backpressure_events == 0u &&
	       policy_publication.completed_generation() == 0u && publication.completed_generation() == 0u;
}

bool boundary_epoch_worker_slab::receiver_slot::empty() const noexcept
{
	return !owner.ack_pending && owner.unsequenced_record == nullptr && cut_ring.empty() &&
	       policy.active_epoch == 0u && policy.accepted_cut == boundary_epoch_cut{} &&
	       policy.duplicate_cut_count == 0u && policy.phase == boundary_epoch_receiver_phase::UNBOUND &&
	       timing.cut_observed_monotonic_ns == 0u && timing.cut_drained_monotonic_ns == 0u &&
	       timing.activation_monotonic_ns == 0u && timing.ack_published_monotonic_ns == 0u &&
	       std::all_of(timing.padding.begin(), timing.padding.end(), [](uint8_t byte) { return byte == 0u; });
}

bool boundary_epoch_worker_slab::receiver_slot::pristine() const noexcept
{
	return empty() && owner.data_dequeued.value() == 0u && publication.completed_generation() == 0u &&
	       policy_publication.completed_generation() == 0u && !sender_closed.load(std::memory_order_relaxed);
}

common::status_or<boundary_epoch_worker_slab::storage_layout>
boundary_epoch_worker_slab::compute_layout_(std::size_t sender_slot_count, std::size_t receiver_slot_count)
{
	storage_layout layout{};
	std::size_t cursor = 0u;
	if (!append_array_checked(cursor, sender_slot_count, sizeof(sender_slot), alignof(sender_slot),
				  layout.sender_slots_offset) ||
	    !append_array_checked(cursor, receiver_slot_count, sizeof(receiver_slot), alignof(receiver_slot),
				  layout.receiver_slots_offset) ||
	    !append_array_checked(cursor, sender_slot_count, sizeof(slot_claim), alignof(slot_claim),
				  layout.sender_claims_offset) ||
	    !append_array_checked(cursor, receiver_slot_count, sizeof(slot_claim), alignof(slot_claim),
				  layout.receiver_claims_offset)) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "boundary endpoint slab layout exceeds the host size domain");
	}
	layout.storage_bytes = cursor;
	return layout;
}

common::status_or<std::size_t> boundary_epoch_worker_slab::checked_storage_bytes(std::size_t sender_slot_count,
										 std::size_t receiver_slot_count)
{
	auto layout_or = compute_layout_(sender_slot_count, receiver_slot_count);
	if (!layout_or.is_ok()) {
		return layout_or.error();
	}
	return layout_or->storage_bytes;
}

common::status_or<std::unique_ptr<boundary_epoch_worker_slab>>
boundary_epoch_worker_slab::create(uint32_t worker_index, int32_t numa_node, std::size_t sender_slot_count,
				   std::size_t receiver_slot_count)
{
	if (worker_index == std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"boundary endpoint slab requires a non-sentinel compact worker identity");
	}
	if (numa_node < 0) {
		return common::status::invalid_argument("boundary endpoint slab requires an exact worker NUMA node");
	}
	auto layout_or = compute_layout_(sender_slot_count, receiver_slot_count);
	if (!layout_or.is_ok()) {
		return layout_or.error();
	}
	const storage_layout layout = layout_or.value();

	numa_memory_region region;
	if (layout.storage_bytes != 0u) {
		auto region_or = numa_memory_region::allocate({
			.usable_bytes = layout.storage_bytes,
			.alignment_bytes = kinetum::algo::CACHE_LINE_SIZE,
			.host_numa_node = numa_node,
		});
		if (!region_or.is_ok()) {
			return region_or.error();
		}
		region = std::move(region_or).value();
	}

	boundary_epoch_worker_slab *slab = nullptr;
	try {
		slab = new (std::nothrow) boundary_epoch_worker_slab(worker_index, numa_node, sender_slot_count,
								     receiver_slot_count, layout, std::move(region));
	} catch (const std::exception &) {
		return common::status::internal_error("boundary endpoint slab construction failed");
	} catch (...) {
		return common::status::internal_error("boundary endpoint slab construction raised an unknown failure");
	}
	if (slab == nullptr) {
		return common::status::resource_exhausted("boundary endpoint slab owner allocation failed");
	}
	return std::unique_ptr<boundary_epoch_worker_slab>(slab);
}

boundary_epoch_worker_slab::boundary_epoch_worker_slab(uint32_t worker_index, int32_t numa_node,
						       std::size_t sender_slot_count, std::size_t receiver_slot_count,
						       const storage_layout &layout, numa_memory_region region)
	: worker_index_(worker_index)
	, numa_node_(numa_node)
	, sender_slot_count_(sender_slot_count)
	, receiver_slot_count_(receiver_slot_count)
	, storage_bytes_(layout.storage_bytes)
	, region_(std::move(region))
{
	const bool has_storage = storage_bytes_ != 0u;
	if (has_storage != static_cast<bool>(region_) || region_.size() != storage_bytes_ ||
	    (region_ && (!region_.host_numa_node().has_value() || region_.host_numa_node().value() != numa_node_))) {
		std::terminate();
	}
	if (!has_storage) {
		return;
	}

	auto *base = static_cast<std::byte *>(region_.data());
	sender_slots_ = sender_slot_count_ != 0u ? reinterpret_cast<sender_slot *>(base + layout.sender_slots_offset) :
						   nullptr;
	receiver_slots_ = receiver_slot_count_ != 0u ?
				  reinterpret_cast<receiver_slot *>(base + layout.receiver_slots_offset) :
				  nullptr;
	sender_claims_ = sender_slot_count_ != 0u ? reinterpret_cast<slot_claim *>(base + layout.sender_claims_offset) :
						    nullptr;
	receiver_claims_ = receiver_slot_count_ != 0u ?
				   reinterpret_cast<slot_claim *>(base + layout.receiver_claims_offset) :
				   nullptr;
	if ((sender_slot_count_ != 0u &&
	     reinterpret_cast<std::uintptr_t>(sender_slots_) % alignof(sender_slot) != 0u) ||
	    (receiver_slot_count_ != 0u &&
	     reinterpret_cast<std::uintptr_t>(receiver_slots_) % alignof(receiver_slot) != 0u) ||
	    (sender_slot_count_ != 0u &&
	     reinterpret_cast<std::uintptr_t>(sender_claims_) % alignof(slot_claim) != 0u) ||
	    (receiver_slot_count_ != 0u &&
	     reinterpret_cast<std::uintptr_t>(receiver_claims_) % alignof(slot_claim) != 0u)) {
		std::terminate();
	}

	std::size_t constructed_sender_slots = 0u;
	std::size_t constructed_receiver_slots = 0u;
	std::size_t constructed_sender_claims = 0u;
	std::size_t constructed_receiver_claims = 0u;
	try {
		for (std::size_t index = 0u; index < sender_slot_count_; ++index) {
			new (&sender_claims_[index]) slot_claim();
			++constructed_sender_claims;
			new (&sender_slots_[index]) sender_slot();
			++constructed_sender_slots;
		}
		for (std::size_t index = 0u; index < receiver_slot_count_; ++index) {
			new (&receiver_claims_[index]) slot_claim();
			++constructed_receiver_claims;
			new (&receiver_slots_[index]) receiver_slot();
			++constructed_receiver_slots;
		}
	} catch (...) {
		while (constructed_receiver_slots != 0u) {
			--constructed_receiver_slots;
			receiver_slots_[constructed_receiver_slots].~receiver_slot();
		}
		while (constructed_receiver_claims != 0u) {
			--constructed_receiver_claims;
			receiver_claims_[constructed_receiver_claims].~slot_claim();
		}
		while (constructed_sender_slots != 0u) {
			--constructed_sender_slots;
			sender_slots_[constructed_sender_slots].~sender_slot();
		}
		while (constructed_sender_claims != 0u) {
			--constructed_sender_claims;
			sender_claims_[constructed_sender_claims].~slot_claim();
		}
		throw;
	}
}

boundary_epoch_worker_slab::~boundary_epoch_worker_slab()
{
	for (std::size_t index = 0u; index < sender_slot_count_; ++index) {
		if (sender_claims_[index].channel_state == claim_state::CLAIMED ||
		    sender_claims_[index].policy_state == claim_state::CLAIMED ||
		    (sealed_ && (sender_claims_[index].channel_state != claim_state::RETIRED ||
				 sender_claims_[index].policy_state != claim_state::RETIRED)) ||
		    !sender_slots_[index].empty()) {
			std::terminate();
		}
	}
	for (std::size_t index = 0u; index < receiver_slot_count_; ++index) {
		if (receiver_claims_[index].channel_state == claim_state::CLAIMED ||
		    receiver_claims_[index].policy_state == claim_state::CLAIMED ||
		    (sealed_ && (receiver_claims_[index].channel_state != claim_state::RETIRED ||
				 receiver_claims_[index].policy_state != claim_state::RETIRED)) ||
		    !receiver_slots_[index].empty()) {
			std::terminate();
		}
	}
	for (std::size_t index = receiver_slot_count_; index != 0u; --index) {
		receiver_slots_[index - 1u].~receiver_slot();
	}
	for (std::size_t index = sender_slot_count_; index != 0u; --index) {
		sender_slots_[index - 1u].~sender_slot();
	}
	for (std::size_t index = receiver_slot_count_; index != 0u; --index) {
		receiver_claims_[index - 1u].~slot_claim();
	}
	for (std::size_t index = sender_slot_count_; index != 0u; --index) {
		sender_claims_[index - 1u].~slot_claim();
	}
}

common::status boundary_epoch_worker_slab::seal()
{
	if (sealed_) {
		return common::status::failed_precondition("boundary endpoint slab is already sealed");
	}
	for (std::size_t index = 0u; index < sender_slot_count_; ++index) {
		if (sender_claims_[index].channel_state != claim_state::CLAIMED ||
		    sender_claims_[index].policy_state != claim_state::CLAIMED) {
			return common::status::failed_precondition(
				"boundary endpoint slab sender channel/policy coverage is incomplete");
		}
	}
	for (std::size_t index = 0u; index < receiver_slot_count_; ++index) {
		if (receiver_claims_[index].channel_state != claim_state::CLAIMED ||
		    receiver_claims_[index].policy_state != claim_state::CLAIMED) {
			return common::status::failed_precondition(
				"boundary endpoint slab receiver channel/policy coverage is incomplete");
		}
	}
	sealed_ = true;
	return common::status::ok();
}

common::status_or<boundary_epoch_worker_slab::sender_slot *>
boundary_epoch_worker_slab::claim_sender_slot_(std::size_t slot_index, uint32_t boundary_index)
{
	if (!sender_slot_claimable_(slot_index)) {
		return common::status::failed_precondition("boundary endpoint sender slot is unavailable");
	}
	auto &claim = sender_claims_[slot_index];
	claim.boundary_index = boundary_index;
	claim.channel_state = claim_state::CLAIMED;
	return &sender_slots_[slot_index];
}

common::status_or<boundary_epoch_worker_slab::receiver_slot *>
boundary_epoch_worker_slab::claim_receiver_slot_(std::size_t slot_index, uint32_t boundary_index)
{
	if (!receiver_slot_claimable_(slot_index)) {
		return common::status::failed_precondition("boundary endpoint receiver slot is unavailable");
	}
	auto &claim = receiver_claims_[slot_index];
	claim.boundary_index = boundary_index;
	claim.channel_state = claim_state::CLAIMED;
	return &receiver_slots_[slot_index];
}

bool boundary_epoch_worker_slab::sender_slot_claimable_(std::size_t slot_index) const noexcept
{
	return !sealed_ && slot_index < sender_slot_count_ &&
	       sender_claims_[slot_index].channel_state == claim_state::UNCLAIMED &&
	       sender_claims_[slot_index].policy_state == claim_state::UNCLAIMED &&
	       sender_slots_[slot_index].pristine();
}

bool boundary_epoch_worker_slab::receiver_slot_claimable_(std::size_t slot_index) const noexcept
{
	return !sealed_ && slot_index < receiver_slot_count_ &&
	       receiver_claims_[slot_index].channel_state == claim_state::UNCLAIMED &&
	       receiver_claims_[slot_index].policy_state == claim_state::UNCLAIMED &&
	       receiver_slots_[slot_index].pristine();
}

bool boundary_epoch_worker_slab::sender_claim_matches_(std::size_t slot_index, uint32_t boundary_index) const noexcept
{
	return slot_index < sender_slot_count_ && sender_claims_[slot_index].channel_state == claim_state::CLAIMED &&
	       sender_claims_[slot_index].boundary_index == boundary_index;
}

bool boundary_epoch_worker_slab::receiver_claim_matches_(std::size_t slot_index, uint32_t boundary_index) const noexcept
{
	return slot_index < receiver_slot_count_ &&
	       receiver_claims_[slot_index].channel_state == claim_state::CLAIMED &&
	       receiver_claims_[slot_index].boundary_index == boundary_index;
}

common::status_or<boundary_epoch_worker_slab::sender_policy_state *>
boundary_epoch_worker_slab::claim_sender_policy_(std::size_t slot_index, uint32_t boundary_index)
{
	if (sealed_ || !sender_claim_matches_(slot_index, boundary_index) ||
	    sender_claims_[slot_index].policy_state != claim_state::UNCLAIMED ||
	    !sender_slots_[slot_index].pristine()) {
		return common::status::failed_precondition("boundary sender policy slot is unavailable");
	}
	sender_claims_[slot_index].policy_state = claim_state::CLAIMED;
	return &sender_slots_[slot_index].policy;
}

common::status_or<boundary_epoch_worker_slab::receiver_policy_state *>
boundary_epoch_worker_slab::claim_receiver_policy_(std::size_t slot_index, uint32_t boundary_index)
{
	if (sealed_ || !receiver_claim_matches_(slot_index, boundary_index) ||
	    receiver_claims_[slot_index].policy_state != claim_state::UNCLAIMED ||
	    !receiver_slots_[slot_index].pristine()) {
		return common::status::failed_precondition("boundary receiver policy slot is unavailable");
	}
	receiver_claims_[slot_index].policy_state = claim_state::CLAIMED;
	return &receiver_slots_[slot_index].policy;
}

void boundary_epoch_worker_slab::release_sender_policy_(std::size_t slot_index, uint32_t boundary_index) noexcept
{
	if (!sender_claim_matches_(slot_index, boundary_index) ||
	    sender_claims_[slot_index].policy_state != claim_state::CLAIMED ||
	    sender_slots_[slot_index].policy.phase != boundary_epoch_sender_phase::UNBOUND ||
	    sender_slots_[slot_index].policy.transition_generation != 0u ||
	    sender_slots_[slot_index].policy.open_epoch != 0u || sender_slots_[slot_index].policy.from_epoch != 0u ||
	    sender_slots_[slot_index].policy.to_epoch != 0u || sender_slots_[slot_index].policy.cut_sequence != 0u ||
	    sender_slots_[slot_index].policy.duplicate_ack_count != 0u ||
	    sender_slots_[slot_index].timing.cut_published_monotonic_ns != 0u ||
	    sender_slots_[slot_index].timing.ack_observed_monotonic_ns != 0u) {
		std::terminate();
	}
	sender_claims_[slot_index].policy_state = claim_state::RETIRED;
}

void boundary_epoch_worker_slab::release_receiver_policy_(std::size_t slot_index, uint32_t boundary_index) noexcept
{
	if (slot_index >= receiver_slot_count_) {
		std::terminate();
	}
	const auto &policy = receiver_slots_[slot_index].policy;
	if (!receiver_claim_matches_(slot_index, boundary_index) ||
	    receiver_claims_[slot_index].policy_state != claim_state::CLAIMED || policy.active_epoch != 0u ||
	    !(policy.accepted_cut == boundary_epoch_cut{}) || policy.duplicate_cut_count != 0u ||
	    policy.phase != boundary_epoch_receiver_phase::UNBOUND ||
	    receiver_slots_[slot_index].timing.cut_observed_monotonic_ns != 0u ||
	    receiver_slots_[slot_index].timing.cut_drained_monotonic_ns != 0u ||
	    receiver_slots_[slot_index].timing.activation_monotonic_ns != 0u ||
	    receiver_slots_[slot_index].timing.ack_published_monotonic_ns != 0u) {
		std::terminate();
	}
	receiver_claims_[slot_index].policy_state = claim_state::RETIRED;
}

void boundary_epoch_worker_slab::release_sender_slot_(std::size_t slot_index, uint32_t boundary_index) noexcept
{
	if (!sender_claim_matches_(slot_index, boundary_index) || !sender_slots_[slot_index].empty() ||
	    (sealed_ ? sender_claims_[slot_index].policy_state != claim_state::RETIRED :
		       sender_claims_[slot_index].policy_state == claim_state::CLAIMED)) {
		std::terminate();
	}
	sender_claims_[slot_index].channel_state = claim_state::RETIRED;
}

void boundary_epoch_worker_slab::release_receiver_slot_(std::size_t slot_index, uint32_t boundary_index) noexcept
{
	if (!receiver_claim_matches_(slot_index, boundary_index) || !receiver_slots_[slot_index].empty() ||
	    (sealed_ ? receiver_claims_[slot_index].policy_state != claim_state::RETIRED :
		       receiver_claims_[slot_index].policy_state == claim_state::CLAIMED)) {
		std::terminate();
	}
	receiver_claims_[slot_index].channel_state = claim_state::RETIRED;
}

uint32_t boundary_epoch_worker_slab::worker_index() const noexcept
{
	return worker_index_;
}

int32_t boundary_epoch_worker_slab::numa_node() const noexcept
{
	return numa_node_;
}

std::size_t boundary_epoch_worker_slab::sender_slot_count() const noexcept
{
	return sender_slot_count_;
}

std::size_t boundary_epoch_worker_slab::receiver_slot_count() const noexcept
{
	return receiver_slot_count_;
}

std::size_t boundary_epoch_worker_slab::storage_bytes() const noexcept
{
	return storage_bytes_;
}

std::size_t boundary_epoch_worker_slab::mapping_count() const noexcept
{
	return region_ ? 1u : 0u;
}

bool boundary_epoch_worker_slab::sealed() const noexcept
{
	return sealed_;
}

}  // namespace kinetum::dp
