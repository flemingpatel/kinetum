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
	return !owner.ack_pending && !owner.receive_in_progress && cut_ring.empty() && policy.active_epoch == 0u &&
	       policy.accepted_cut == boundary_epoch_cut{} && policy.duplicate_cut_count == 0u &&
	       policy.phase == boundary_epoch_receiver_phase::UNBOUND && timing.cut_observed_monotonic_ns == 0u &&
	       timing.cut_drained_monotonic_ns == 0u && timing.activation_monotonic_ns == 0u &&
	       timing.ack_published_monotonic_ns == 0u &&
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
	if (!layout.allocation.append<sender_slot>(sender_slot_count, layout.sender_slots_offset) ||
	    !layout.allocation.append<receiver_slot>(receiver_slot_count, layout.receiver_slots_offset) ||
	    !layout.allocation.append<slot_claim>(sender_slot_count, layout.sender_claims_offset) ||
	    !layout.allocation.append<slot_claim>(receiver_slot_count, layout.receiver_claims_offset)) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "boundary endpoint slab layout exceeds the host size domain");
	}
	return layout;
}

common::status_or<std::size_t> boundary_epoch_worker_slab::checked_storage_bytes(std::size_t sender_slot_count,
										 std::size_t receiver_slot_count)
{
	auto layout_or = compute_layout_(sender_slot_count, receiver_slot_count);
	if (!layout_or.is_ok()) {
		return layout_or.error();
	}
	return layout_or->allocation.size();
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
	if (layout.allocation.size() != 0u) {
		auto region_or = layout.allocation.allocate(numa_node);
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
	, storage_bytes_(layout.allocation.size())
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

	sender_slots_ =
		numa_layout::storage<sender_slot>(region_, layout.sender_slots_offset, sender_slot_count_).data();
	receiver_slots_ =
		numa_layout::storage<receiver_slot>(region_, layout.receiver_slots_offset, receiver_slot_count_).data();
	sender_claims_ =
		numa_layout::storage<slot_claim>(region_, layout.sender_claims_offset, sender_slot_count_).data();
	receiver_claims_ =
		numa_layout::storage<slot_claim>(region_, layout.receiver_claims_offset, receiver_slot_count_).data();

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
