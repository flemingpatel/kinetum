// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file boundary_epoch_channel.cpp
 * @brief Exact boundary DATA sequence and typed control transport implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/boundary_epoch_channel.hpp"

#include <array>
#include <atomic>
#include <exception>
#include <limits>
#include <new>
#include <utility>

#include <kinetum/algo/single_writer_snapshot.hpp>

#include "src/common/status.hpp"

namespace kinetum::dp
{

common::status_or<std::unique_ptr<boundary_epoch_channel>>
boundary_epoch_channel::create(const common::compiled_transition_boundary &facts, uint64_t runtime_generation,
			       boundary_epoch_worker_slab &sender_slab, std::size_t sender_slot_index,
			       boundary_epoch_worker_slab &receiver_slab, std::size_t receiver_slot_index)
{
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"boundary epoch channel requires a runtime generation representable by the provider ABI");
	}
	if (facts.sender_worker_index == facts.receiver_worker_index) {
		return common::status::failed_precondition(
			"boundary epoch channel requires distinct sender and receiver workers");
	}
	if (facts.data_ring_numa_node < 0) {
		return common::status::failed_precondition(
			"boundary epoch channel requires an exact receiver DATA NUMA node");
	}
	if (sender_slab.worker_index() != facts.sender_worker_index ||
	    receiver_slab.worker_index() != facts.receiver_worker_index) {
		return common::status::failed_precondition(
			"boundary epoch channel endpoint slabs do not match compiled worker ownership");
	}
	if (sender_slab.numa_node() < 0 || receiver_slab.numa_node() != facts.data_ring_numa_node) {
		return common::status::failed_precondition(
			"boundary epoch channel endpoint slabs do not match compiled NUMA ownership");
	}
	if (sender_slot_index >= sender_slab.sender_slot_count() ||
	    receiver_slot_index >= receiver_slab.receiver_slot_count()) {
		return common::status::failed_precondition(
			"boundary epoch channel endpoint ordinal is outside its worker slab");
	}
	if (!sender_slab.sender_slot_claimable_(sender_slot_index) ||
	    !receiver_slab.receiver_slot_claimable_(receiver_slot_index)) {
		return common::status::failed_precondition(
			"boundary epoch channel endpoint slot was already consumed or sealed");
	}

	auto data_ring_or =
		numa_spsc_ring<packet_record *>::create(facts.data_ring_capacity, facts.data_ring_numa_node);
	if (!data_ring_or.is_ok() && data_ring_or.error().code() == common::status_code::INVALID_ARGUMENT) {
		return common::status::failed_precondition(
			"boundary epoch channel DATA capacity is not an admitted SPSC capacity");
	}
	if (!data_ring_or.is_ok()) {
		return data_ring_or.error();
	}
	// Reserve the semantic owner before either linear slot claim. A recoverable
	// owner-allocation failure therefore leaves both slabs reusable; after the
	// two preflights, external construction serialization makes claim failure a
	// violated ownership contract rather than a partial transaction to repair.
	void *channel_storage = ::operator new(sizeof(boundary_epoch_channel), std::nothrow);
	if (channel_storage == nullptr) {
		return common::status::resource_exhausted("boundary epoch channel owner allocation failed");
	}
	auto sender_slot_or = sender_slab.claim_sender_slot_(sender_slot_index, facts.boundary_index);
	auto receiver_slot_or = receiver_slab.claim_receiver_slot_(receiver_slot_index, facts.boundary_index);
	if (!sender_slot_or.is_ok() || !receiver_slot_or.is_ok()) {
		std::terminate();
	}

	auto *channel = new (channel_storage)
		boundary_epoch_channel(facts, runtime_generation, std::move(data_ring_or).value(), sender_slab,
				       sender_slot_index, *sender_slot_or.value(), receiver_slab, receiver_slot_index,
				       *receiver_slot_or.value());
	return std::unique_ptr<boundary_epoch_channel>(channel);
}

boundary_epoch_channel::boundary_epoch_channel(const common::compiled_transition_boundary &facts,
					       uint64_t runtime_generation,
					       std::unique_ptr<numa_spsc_ring<packet_record *>> data_ring,
					       boundary_epoch_worker_slab &sender_slab, std::size_t sender_slot_index,
					       boundary_epoch_worker_slab::sender_slot &sender_slot,
					       boundary_epoch_worker_slab &receiver_slab,
					       std::size_t receiver_slot_index,
					       boundary_epoch_worker_slab::receiver_slot &receiver_slot) noexcept
	: boundary_index_(facts.boundary_index)
	, from_stage_instance_index_(facts.from_stage_instance_index)
	, to_stage_instance_index_(facts.to_stage_instance_index)
	, sender_worker_index_(facts.sender_worker_index)
	, receiver_worker_index_(facts.receiver_worker_index)
	, runtime_generation_(runtime_generation)
	, data_ring_numa_node_(facts.data_ring_numa_node)
	, data_ring_(std::move(data_ring))
	, sender_slab_(&sender_slab)
	, sender_slot_index_(sender_slot_index)
	, sender_slot_(&sender_slot)
	, receiver_slab_(&receiver_slab)
	, receiver_slot_index_(receiver_slot_index)
	, receiver_slot_(&receiver_slot)
{
	if (data_ring_ == nullptr || !data_ring_->empty() || data_ring_->capacity() != facts.data_ring_capacity ||
	    data_ring_->numa_node() != data_ring_numa_node_ || sender_slab_ == nullptr || sender_slot_ == nullptr ||
	    receiver_slab_ == nullptr || receiver_slot_ == nullptr || !sender_slot_->pristine() ||
	    !receiver_slot_->pristine() || !sender_slab_->sender_claim_matches_(sender_slot_index_, boundary_index_) ||
	    !receiver_slab_->receiver_claim_matches_(receiver_slot_index_, boundary_index_)) {
		std::terminate();
	}
}

boundary_epoch_channel::~boundary_epoch_channel()
{
	if (!empty() || sender_slab_ == nullptr || receiver_slab_ == nullptr ||
	    !sender_slab_->sender_claim_matches_(sender_slot_index_, boundary_index_) ||
	    !receiver_slab_->receiver_claim_matches_(receiver_slot_index_, boundary_index_)) {
		std::terminate();
	}
	sender_slab_->release_sender_slot_(sender_slot_index_, boundary_index_);
	receiver_slab_->release_receiver_slot_(receiver_slot_index_, boundary_index_);
}

boundary_data_publication_result boundary_epoch_channel::try_send_data(packet_record *record) noexcept
{
	auto &sender = sender_slot_->owner;
	if (KINETUM_UNLIKELY(record == nullptr || sender.closed)) {
		std::terminate();
	}
	if (KINETUM_UNLIKELY(!successful_data_sequence::can_advance(sender.data_enqueued.value()))) {
		return boundary_data_publication_result::SEQUENCE_EXHAUSTED;
	}
	if (!data_ring_->try_push(record)) {
		if (sender.data_backpressure_events != std::numeric_limits<uint64_t>::max()) {
			++sender.data_backpressure_events;
		}
		return boundary_data_publication_result::BACKPRESSURED;
	}
	if (KINETUM_UNLIKELY(!sender.data_enqueued.record_success())) {
		std::terminate();
	}
	return boundary_data_publication_result::TRANSFERRED;
}

boundary_data_receive_result boundary_epoch_channel::try_receive_data(packet_record *&record) noexcept
{
	auto &receiver = receiver_slot_->owner;
	if (KINETUM_UNLIKELY(receiver.unsequenced_record != nullptr)) {
		std::terminate();
	}
	if (KINETUM_UNLIKELY(!successful_data_sequence::can_advance(receiver.data_dequeued.value()))) {
		return data_ring_->empty() ? boundary_data_receive_result::EMPTY :
					     boundary_data_receive_result::SEQUENCE_EXHAUSTED;
	}
	packet_record *candidate = nullptr;
	if (!data_ring_->try_pop(candidate)) {
		return boundary_data_receive_result::EMPTY;
	}
	if (KINETUM_UNLIKELY(candidate == nullptr)) {
		std::terminate();
	}
	receiver.unsequenced_record = candidate;
	record = candidate;
	return boundary_data_receive_result::RECEIVED;
}

void boundary_epoch_channel::complete_data_receive(packet_record *record) noexcept
{
	auto &receiver = receiver_slot_->owner;
	if (KINETUM_UNLIKELY(record == nullptr || receiver.unsequenced_record != record ||
			     !receiver.data_dequeued.record_success())) {
		std::terminate();
	}
	receiver.unsequenced_record = nullptr;
}

const packet_record *boundary_epoch_channel::peek_data() const noexcept
{
	const auto *slot = data_ring_->peek();
	return slot != nullptr ? *slot : nullptr;
}

boundary_control_publication_result boundary_epoch_channel::submit_cut(const boundary_epoch_cut &cut) noexcept
{
	auto &sender = sender_slot_->owner;
	if (KINETUM_UNLIKELY(!cut.valid() || sender.cut_pending || sender.closed)) {
		std::terminate();
	}
	if (receiver_slot_->cut_ring.try_push(cut)) {
		return boundary_control_publication_result::PUBLISHED;
	}
	sender.pending_cut = cut;
	sender.cut_pending = true;
	return boundary_control_publication_result::PENDING;
}

boundary_control_publication_result boundary_epoch_channel::service_pending_cut() noexcept
{
	auto &sender = sender_slot_->owner;
	if (!sender.cut_pending) {
		return boundary_control_publication_result::ABSENT;
	}
	if (KINETUM_UNLIKELY(!sender.pending_cut.valid() || sender.closed)) {
		std::terminate();
	}
	if (!receiver_slot_->cut_ring.try_push(sender.pending_cut)) {
		return boundary_control_publication_result::PENDING;
	}
	sender.pending_cut = {};
	sender.cut_pending = false;
	return boundary_control_publication_result::PUBLISHED;
}

bool boundary_epoch_channel::try_receive_cut(boundary_epoch_cut &cut) noexcept
{
	boundary_epoch_cut candidate{};
	if (!receiver_slot_->cut_ring.try_pop(candidate)) {
		return false;
	}
	if (KINETUM_UNLIKELY(!candidate.valid())) {
		std::terminate();
	}
	cut = candidate;
	return true;
}

boundary_control_publication_result boundary_epoch_channel::submit_ack(const boundary_epoch_ack &ack) noexcept
{
	auto &receiver = receiver_slot_->owner;
	if (KINETUM_UNLIKELY(!ack.valid() || receiver.ack_pending)) {
		std::terminate();
	}
	if (sender_slot_->ack_ring.try_push(ack)) {
		return boundary_control_publication_result::PUBLISHED;
	}
	receiver.pending_ack = ack;
	receiver.ack_pending = true;
	return boundary_control_publication_result::PENDING;
}

boundary_control_publication_result boundary_epoch_channel::service_pending_ack() noexcept
{
	auto &receiver = receiver_slot_->owner;
	if (!receiver.ack_pending) {
		return boundary_control_publication_result::ABSENT;
	}
	if (KINETUM_UNLIKELY(!receiver.pending_ack.valid())) {
		std::terminate();
	}
	if (!sender_slot_->ack_ring.try_push(receiver.pending_ack)) {
		return boundary_control_publication_result::PENDING;
	}
	receiver.pending_ack = {};
	receiver.ack_pending = false;
	return boundary_control_publication_result::PUBLISHED;
}

bool boundary_epoch_channel::try_receive_ack(boundary_epoch_ack &ack) noexcept
{
	boundary_epoch_ack candidate{};
	if (!sender_slot_->ack_ring.try_pop(candidate)) {
		return false;
	}
	if (KINETUM_UNLIKELY(!candidate.valid())) {
		std::terminate();
	}
	ack = candidate;
	return true;
}

bool boundary_epoch_channel::has_pending_cut() const noexcept
{
	return sender_slot_->owner.cut_pending;
}

bool boundary_epoch_channel::has_pending_ack() const noexcept
{
	return receiver_slot_->owner.ack_pending;
}

bool boundary_epoch_channel::cut_lane_empty() const noexcept
{
	return receiver_slot_->cut_ring.empty();
}

bool boundary_epoch_channel::ack_lane_empty() const noexcept
{
	return sender_slot_->ack_ring.empty();
}

void boundary_epoch_channel::publish_sender_transport() noexcept
{
	const auto &sender = sender_slot_->owner;
	const uint64_t pending_epoch = sender.cut_pending ? sender.pending_cut.next_epoch : 0u;
	const uint64_t pending_sequence = sender.cut_pending ? sender.pending_cut.data_cut_sequence : 0u;
	if (!valid_boundary_data_sequence(sender.data_enqueued.value()) ||
	    (sender.cut_pending && !sender.pending_cut.valid())) {
		std::terminate();
	}
	const std::array<uint64_t, SENDER_PUBLICATION_FIELD_COUNT> fields{
		runtime_generation_, boundary_index_,  sender.data_enqueued.value(), sender.data_backpressure_events,
		pending_epoch,	     pending_sequence,
	};
	if (!sender_slot_->publication.publish(fields)) {
		std::terminate();
	}
}

void boundary_epoch_channel::publish_receiver_transport() noexcept
{
	const auto &receiver = receiver_slot_->owner;
	const uint64_t pending_epoch = receiver.ack_pending ? receiver.pending_ack.ready_epoch : 0u;
	const uint64_t pending_sequence = receiver.ack_pending ? receiver.pending_ack.consumed_cut_sequence : 0u;
	if (receiver.unsequenced_record != nullptr || !valid_boundary_data_sequence(receiver.data_dequeued.value()) ||
	    (receiver.ack_pending && !receiver.pending_ack.valid())) {
		std::terminate();
	}
	const std::array<uint64_t, RECEIVER_PUBLICATION_FIELD_COUNT> fields{
		runtime_generation_, boundary_index_, receiver.data_dequeued.value(), pending_epoch, pending_sequence,
	};
	if (!receiver_slot_->publication.publish(fields)) {
		std::terminate();
	}
}

publication_read_result validate_boundary_sender_transport(const boundary_sender_transport_snapshot &value,
							   uint64_t runtime_generation,
							   uint32_t boundary_index) noexcept
{
	if (value.runtime_generation != runtime_generation || value.boundary_index != boundary_index) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (value.publication_generation == 0u || !valid_boundary_data_sequence(value.data_enqueued_sequence) ||
	    (value.pending_cut_epoch == 0u && value.pending_cut_sequence != 0u) ||
	    (value.pending_cut_epoch != 0u &&
	     !boundary_epoch_cut{value.pending_cut_epoch, value.pending_cut_sequence}.valid())) {
		return publication_read_result::INVALID_STATE;
	}
	return publication_read_result::AVAILABLE;
}

publication_read_result validate_boundary_receiver_transport(const boundary_receiver_transport_snapshot &value,
							     uint64_t runtime_generation,
							     uint32_t boundary_index) noexcept
{
	if (value.runtime_generation != runtime_generation || value.boundary_index != boundary_index) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (value.publication_generation == 0u || !valid_boundary_data_sequence(value.data_dequeued_sequence) ||
	    (value.pending_ack_epoch == 0u && value.pending_ack_sequence != 0u) ||
	    (value.pending_ack_epoch != 0u &&
	     !boundary_epoch_ack{value.pending_ack_epoch, value.pending_ack_sequence}.valid())) {
		return publication_read_result::INVALID_STATE;
	}
	return publication_read_result::AVAILABLE;
}

publication_read_result
boundary_epoch_channel::try_read_sender_transport(boundary_sender_transport_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<SENDER_PUBLICATION_FIELD_COUNT>::snapshot observed{};
	if (!sender_slot_->publication.try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}
	const uint64_t pending_epoch = observed.fields[SENDER_PENDING_CUT_EPOCH];
	const uint64_t pending_sequence = observed.fields[SENDER_PENDING_CUT_SEQUENCE];
	const boundary_sender_transport_snapshot decoded{
		.publication_generation = observed.generation,
		.runtime_generation = observed.fields[SENDER_RUNTIME_GENERATION],
		.boundary_index = observed.fields[SENDER_BOUNDARY_INDEX],
		.data_enqueued_sequence = observed.fields[SENDER_DATA_SEQUENCE],
		.data_backpressure_events = observed.fields[SENDER_BACKPRESSURE_EVENTS],
		.pending_cut_epoch = pending_epoch,
		.pending_cut_sequence = pending_sequence,
	};
	const auto result = validate_boundary_sender_transport(decoded, runtime_generation_, boundary_index_);
	if (result == publication_read_result::AVAILABLE) {
		out = decoded;
	}
	return result;
}

publication_read_result
boundary_epoch_channel::try_read_receiver_transport(boundary_receiver_transport_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<RECEIVER_PUBLICATION_FIELD_COUNT>::snapshot observed{};
	if (!receiver_slot_->publication.try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}
	const uint64_t pending_epoch = observed.fields[RECEIVER_PENDING_ACK_EPOCH];
	const uint64_t pending_sequence = observed.fields[RECEIVER_PENDING_ACK_SEQUENCE];
	const boundary_receiver_transport_snapshot decoded{
		.publication_generation = observed.generation,
		.runtime_generation = observed.fields[RECEIVER_RUNTIME_GENERATION],
		.boundary_index = observed.fields[RECEIVER_BOUNDARY_INDEX],
		.data_dequeued_sequence = observed.fields[RECEIVER_DATA_SEQUENCE],
		.pending_ack_epoch = pending_epoch,
		.pending_ack_sequence = pending_sequence,
	};
	const auto result = validate_boundary_receiver_transport(decoded, runtime_generation_, boundary_index_);
	if (result == publication_read_result::AVAILABLE) {
		out = decoded;
	}
	return result;
}

void boundary_epoch_channel::close_sender() noexcept
{
	auto &sender = sender_slot_->owner;
	if (sender.closed || sender.cut_pending) {
		std::terminate();
	}
	sender.closed = true;
	receiver_slot_->sender_closed.store(true, std::memory_order_release);
}

bool boundary_epoch_channel::sender_closed() const noexcept
{
	return receiver_slot_->sender_closed.load(std::memory_order_acquire);
}

uint32_t boundary_epoch_channel::boundary_index() const noexcept
{
	return boundary_index_;
}

uint32_t boundary_epoch_channel::from_stage_instance_index() const noexcept
{
	return from_stage_instance_index_;
}

uint32_t boundary_epoch_channel::to_stage_instance_index() const noexcept
{
	return to_stage_instance_index_;
}

uint32_t boundary_epoch_channel::sender_worker_index() const noexcept
{
	return sender_worker_index_;
}

uint32_t boundary_epoch_channel::receiver_worker_index() const noexcept
{
	return receiver_worker_index_;
}

uint64_t boundary_epoch_channel::runtime_generation() const noexcept
{
	return runtime_generation_;
}

int32_t boundary_epoch_channel::data_ring_numa_node() const noexcept
{
	return data_ring_numa_node_;
}

int32_t boundary_epoch_channel::sender_endpoint_numa_node() const noexcept
{
	return sender_slab_->numa_node();
}

int32_t boundary_epoch_channel::receiver_endpoint_numa_node() const noexcept
{
	return receiver_slab_->numa_node();
}

int32_t boundary_epoch_channel::cut_ring_numa_node() const noexcept
{
	return receiver_slab_->numa_node();
}

int32_t boundary_epoch_channel::ack_ring_numa_node() const noexcept
{
	return sender_slab_->numa_node();
}

bool boundary_epoch_channel::endpoint_storage_sealed() const noexcept
{
	return sender_slab_->sealed() && receiver_slab_->sealed();
}

std::size_t boundary_epoch_channel::data_capacity() const noexcept
{
	return data_ring_->capacity();
}

uint64_t boundary_epoch_channel::data_enqueued_sequence() const noexcept
{
	return sender_slot_->owner.data_enqueued.value();
}

uint64_t boundary_epoch_channel::data_dequeued_sequence() const noexcept
{
	return receiver_slot_->owner.data_dequeued.value();
}

bool boundary_epoch_channel::data_empty() const noexcept
{
	if (receiver_slot_->owner.unsequenced_record != nullptr || !data_ring_->empty()) {
		return false;
	}
	if (sender_slot_->owner.data_enqueued.value() != receiver_slot_->owner.data_dequeued.value()) {
		std::terminate();
	}
	return true;
}

bool boundary_epoch_channel::control_empty() const noexcept
{
	return !sender_slot_->owner.cut_pending && !receiver_slot_->owner.ack_pending &&
	       receiver_slot_->cut_ring.empty() && sender_slot_->ack_ring.empty();
}

bool boundary_epoch_channel::empty() const noexcept
{
	return data_empty() && control_empty();
}

}  // namespace kinetum::dp
