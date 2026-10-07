// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_boundary_sender.cpp
 * @brief Exact worker-owned boundary sender policy implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/worker_boundary_sender.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <iterator>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include <kinetum/algo/platform.hpp>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"
#include "src/common/time.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"

namespace kinetum::dp
{

common::status_or<std::unique_ptr<worker_boundary_sender>>
worker_boundary_sender::create(uint32_t worker_index, uint64_t runtime_generation,
			       std::span<boundary_epoch_channel *const> channels,
			       std::span<boundary_future_output_hold *const> holds)
{
	if (worker_index == std::numeric_limits<uint32_t>::max() || runtime_generation == 0u ||
	    runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"boundary sender requires exact representable worker and runtime identities");
	}
	if (channels.size() != holds.size() || channels.size() > std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"boundary sender requires equal representable channel and hold populations");
	}

	std::vector<endpoint> endpoints;
	try {
		endpoints.reserve(channels.size());
		uint32_t previous_boundary = 0u;
		bool have_previous = false;
		for (std::size_t index = 0u; index < channels.size(); ++index) {
			auto *channel = channels[index];
			auto *hold = holds[index];
			if (channel == nullptr || hold == nullptr || channel->sender_worker_index() != worker_index ||
			    hold->sender_worker_index() != worker_index ||
			    channel->runtime_generation() != runtime_generation ||
			    channel->boundary_index() != hold->boundary_index() ||
			    channel->sender_endpoint_numa_node() != hold->numa_node() || channel->sender_closed() ||
			    !channel->empty() || !hold->empty() || channel->endpoint_storage_sealed()) {
				return common::status::failed_precondition(
					"boundary sender endpoint does not equal one clean unsealed compiled ownership");
			}
			const uint32_t boundary_index = channel->boundary_index();
			if (have_previous && boundary_index <= previous_boundary) {
				return common::status::failed_precondition(
					"boundary sender endpoints must be strictly sorted and unique");
			}
			endpoints.push_back({boundary_index, channel, hold, nullptr, nullptr, nullptr});
			previous_boundary = boundary_index;
			have_previous = true;
		}
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("boundary sender endpoint table allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "boundary sender endpoint table exceeds a bounded host container");
	}

	auto *raw = new (std::nothrow)
		worker_boundary_sender(sender_identity{worker_index, runtime_generation}, std::move(endpoints));
	if (raw == nullptr) {
		return common::status::resource_exhausted("boundary sender owner allocation failed");
	}
	std::unique_ptr<worker_boundary_sender> owner(raw);
	for (auto &entry : owner->endpoints_) {
		auto policy_or = entry.channel->sender_slab_->claim_sender_policy_(entry.channel->sender_slot_index_,
										   entry.boundary_index);
		if (!policy_or.is_ok()) {
			return policy_or.error();
		}
		entry.policy = policy_or.value();
		entry.timing = &entry.channel->sender_slab_->sender_slots_[entry.channel->sender_slot_index_].timing;
		entry.publication = &entry.channel->sender_slab_->sender_slots_[entry.channel->sender_slot_index_]
					     .policy_publication;
	}
	return owner;
}

worker_boundary_sender::worker_boundary_sender(sender_identity identity, std::vector<endpoint> endpoints) noexcept
	: worker_index_(identity.worker_index)
	, runtime_generation_(identity.runtime_generation)
	, endpoints_(std::move(endpoints))
{
}

worker_boundary_sender::~worker_boundary_sender()
{
	if (transition_active_) {
		std::terminate();
	}
	for (auto iterator = endpoints_.rbegin(); iterator != endpoints_.rend(); ++iterator) {
		auto &entry = *iterator;
		if (entry.policy == nullptr) {
			continue;
		}
		if ((entry.policy->phase != boundary_epoch_sender_phase::UNBOUND &&
		     entry.policy->phase != boundary_epoch_sender_phase::OPEN) ||
		    entry.channel == nullptr || entry.hold == nullptr || !entry.hold->empty() ||
		    !entry.channel->control_empty()) {
			std::terminate();
		}
		*entry.policy = {};
		if (entry.timing == nullptr) {
			std::terminate();
		}
		*entry.timing = {};
		entry.channel->sender_slab_->release_sender_policy_(entry.channel->sender_slot_index_,
								    entry.boundary_index);
		entry.policy = nullptr;
		entry.timing = nullptr;
		entry.publication = nullptr;
	}
}

common::status worker_boundary_sender::bind_ledger(worker_epoch_ledger &ledger)
{
	if (ledger_ != nullptr || ledger.worker_index() != worker_index_ ||
	    ledger.runtime_generation() != runtime_generation_ || bootstrap_epoch_ != 0u || transition_active_) {
		return common::status::failed_precondition(
			"boundary sender ledger does not match one unbound worker generation");
	}
	ledger_ = &ledger;
	return common::status::ok();
}

common::status worker_boundary_sender::bind_protocol_faults(worker_runtime_telemetry &telemetry,
							    epoch_protocol_fault_latch &faults) noexcept
{
	if (telemetry_ != nullptr || faults_ != nullptr || telemetry.worker_index() != worker_index_ ||
	    telemetry.runtime_generation() != runtime_generation_ || bootstrap_epoch_ != 0u || transition_active_) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"boundary sender protocol diagnostics do not match one unbound worker generation"));
	}
	telemetry_ = &telemetry;
	faults_ = &faults;
	return common::status::ok();
}

void worker_boundary_sender::bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept
{
	if (ledger_ == nullptr || bootstrap_epoch_ != 0u || transition_active_ ||
	    !common::valid_epoch_id(bootstrap_epoch) || ledger_->active_epoch() != bootstrap_epoch ||
	    ledger_->source_epoch() != bootstrap_epoch || ledger_->future_epoch() != 0u) {
		std::terminate();
	}
	for (const auto &entry : endpoints_) {
		if (!policy_unbound_(entry) || entry.channel->sender_closed() || !entry.channel->control_empty() ||
		    !entry.hold->empty()) {
			std::terminate();
		}
	}
	bootstrap_epoch_ = bootstrap_epoch;
	for (auto &entry : endpoints_) {
		entry.policy->open_epoch = bootstrap_epoch;
		entry.policy->phase = boundary_epoch_sender_phase::OPEN;
		publish_transition_(entry);
	}
}

bool worker_boundary_sender::preflight_begin_transition(uint64_t transition_generation, uint64_t from_epoch,
							uint64_t to_epoch) const noexcept
{
	if (ledger_ == nullptr || bootstrap_epoch_ == 0u || !common::valid_mutation_sequence(transition_generation) ||
	    !common::valid_epoch_id(from_epoch) || !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch ||
	    ledger_->active_epoch() != from_epoch) {
		return false;
	}
	const bool future_unbound = ledger_->source_epoch() == from_epoch && ledger_->future_epoch() == 0u;
	const bool future_bound = (ledger_->source_epoch() == from_epoch || ledger_->source_epoch() == to_epoch) &&
				  ledger_->future_epoch() == to_epoch;
	if (!future_unbound && !future_bound) {
		return false;
	}
	if (transition_active_) {
		return transition_generation == transition_generation_ && from_epoch == transition_from_epoch_ &&
		       to_epoch == transition_to_epoch_;
	}
	if (transition_generation_ != 0u && transition_generation <= transition_generation_) {
		return false;
	}
	for (const auto &entry : endpoints_) {
		if (!clean_for_begin_(entry) || entry.policy->open_epoch != from_epoch) {
			return false;
		}
	}
	return true;
}

bool worker_boundary_sender::begin_transition(uint64_t transition_generation, uint64_t from_epoch,
					      uint64_t to_epoch) noexcept
{
	if (!preflight_begin_transition(transition_generation, from_epoch, to_epoch) ||
	    ledger_->future_epoch() != to_epoch) {
		std::terminate();
	}
	if (transition_active_) {
		if (transition_generation != transition_generation_ || from_epoch != transition_from_epoch_ ||
		    to_epoch != transition_to_epoch_) {
			std::terminate();
		}
		for (const auto &entry : endpoints_) {
			if (entry.policy == nullptr || entry.policy->transition_generation != transition_generation ||
			    entry.policy->from_epoch != from_epoch || entry.policy->to_epoch != to_epoch ||
			    entry.policy->phase == boundary_epoch_sender_phase::UNBOUND) {
				std::terminate();
			}
		}
		return false;
	}
	transition_generation_ = transition_generation;
	transition_from_epoch_ = from_epoch;
	transition_to_epoch_ = to_epoch;
	transition_active_ = true;
	outbound_sealed_ = false;
	for (auto &entry : endpoints_) {
		if (entry.timing == nullptr) {
			std::terminate();
		}
		*entry.timing = {};
		entry.policy->transition_generation = transition_generation;
		entry.policy->from_epoch = from_epoch;
		entry.policy->to_epoch = to_epoch;
		entry.policy->cut_sequence = 0u;
		entry.policy->duplicate_ack_count = 0u;
		entry.policy->phase = boundary_epoch_sender_phase::DRAINING;
		publish_transition_(entry);
	}
	return true;
}

boundary_epoch_send_result worker_boundary_sender::try_send(uint32_t sender_ordinal, packet_record *record) noexcept
{
	auto &entry = endpoint_(sender_ordinal);
	if (ledger_ == nullptr || record == nullptr || entry.policy == nullptr) {
		std::terminate();
	}
	const uint64_t packet_epoch = record->metadata.epoch;
	const auto transfer = [&]() noexcept {
		const auto result = entry.channel->try_send_data(record);
		if (KINETUM_UNLIKELY(result != boundary_data_publication_result::TRANSFERRED)) {
			if (result == boundary_data_publication_result::BACKPRESSURED) {
				return boundary_epoch_send_result::BACKPRESSURED;
			}
			if (result != boundary_data_publication_result::SEQUENCE_EXHAUSTED) {
				std::terminate();
			}
			record_fault_(entry, epoch_protocol_fault_code::SEQUENCE_EXHAUSTED,
				      epoch_protocol_fault_disposition::TERMINATE, packet_epoch,
				      MAX_BOUNDARY_DATA_SEQUENCE, entry.channel->data_enqueued_sequence());
			std::terminate();
		}
		ledger_->retire(packet_epoch);
		return boundary_epoch_send_result::TRANSFERRED;
	};
	const auto hold = [&]() noexcept {
		return entry.hold->try_hold(record) ? boundary_epoch_send_result::HELD :
						      boundary_epoch_send_result::BACKPRESSURED;
	};
	if (KINETUM_LIKELY(!transition_active_ && entry.policy->phase == boundary_epoch_sender_phase::OPEN &&
			   packet_epoch == entry.policy->open_epoch)) {
		return transfer();
	}
	if (!transition_active_) {
		std::terminate();
	}

	switch (entry.policy->phase) {
	case boundary_epoch_sender_phase::OPEN:
		if (packet_epoch != entry.policy->open_epoch) {
			record_fault_(entry,
				      packet_epoch == entry.policy->from_epoch ?
					      epoch_protocol_fault_code::OLD_DATA_AFTER_SEAL :
					      epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH,
				      epoch_protocol_fault_disposition::TERMINATE, packet_epoch,
				      entry.policy->open_epoch, packet_epoch);
			std::terminate();
		}
		// Once an ACK opens the target gate, the existing hold is a finite
		// prefix. New target work remains caller-owned until that prefix drains,
		// preventing sustained ingress from postponing transition completion.
		return !entry.hold->empty() ? boundary_epoch_send_result::BACKPRESSURED : transfer();
	case boundary_epoch_sender_phase::DRAINING:
		if (packet_epoch == entry.policy->from_epoch) {
			return transfer();
		}
		if (packet_epoch == entry.policy->to_epoch) {
			return hold();
		}
		record_fault_(entry, epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH,
			      epoch_protocol_fault_disposition::TERMINATE, packet_epoch, entry.policy->from_epoch,
			      packet_epoch);
		std::terminate();
	case boundary_epoch_sender_phase::CUT_PENDING:
	case boundary_epoch_sender_phase::WAITING_ACK:
		if (packet_epoch == entry.policy->to_epoch) {
			return hold();
		}
		record_fault_(entry,
			      packet_epoch == entry.policy->from_epoch ?
				      epoch_protocol_fault_code::OLD_DATA_AFTER_SEAL :
				      epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH,
			      epoch_protocol_fault_disposition::TERMINATE, packet_epoch, entry.policy->to_epoch,
			      packet_epoch);
		std::terminate();
	case boundary_epoch_sender_phase::UNBOUND:
		std::terminate();
	}
	std::terminate();
}

bool worker_boundary_sender::try_seal_after_old_work_drained() noexcept
{
	if (!transition_active_ || ledger_ == nullptr || ledger_->active_epoch() != transition_from_epoch_ ||
	    ledger_->future_epoch() != transition_to_epoch_) {
		std::terminate();
	}
	const uint64_t source_epoch = ledger_->source_epoch();
	if (source_epoch != transition_from_epoch_ && source_epoch != transition_to_epoch_) {
		std::terminate();
	}
	if (outbound_sealed_) {
		return true;
	}
	if (source_epoch != transition_to_epoch_ || ledger_->active_unretired() != 0u) {
		return false;
	}
	for (const auto &entry : endpoints_) {
		if (entry.policy == nullptr || entry.policy->phase != boundary_epoch_sender_phase::DRAINING ||
		    entry.policy->transition_generation != transition_generation_ ||
		    entry.policy->from_epoch != transition_from_epoch_ ||
		    entry.policy->to_epoch != transition_to_epoch_ || entry.channel->sender_closed() ||
		    entry.channel->has_pending_cut()) {
			std::terminate();
		}
	}
	for (auto &entry : endpoints_) {
		entry.policy->cut_sequence = entry.channel->data_enqueued_sequence();
	}
	for (auto &entry : endpoints_) {
		entry.policy->phase = boundary_epoch_sender_phase::CUT_PENDING;
	}
	outbound_sealed_ = true;
	// The receiver may free a CUT slot concurrently, so a separate availability
	// observation cannot predict the following push. Sample once before the
	// complete attempt batch and retain it only for records that publish.
	const uint64_t cut_publication_ns = endpoints_.empty() ? 0u : common::now_ns();
	if (!endpoints_.empty() && cut_publication_ns == 0u) {
		std::terminate();
	}
	for (auto &entry : endpoints_) {
		if (entry.timing == nullptr) {
			std::terminate();
		}
		const auto result = entry.channel->submit_cut({entry.policy->to_epoch, entry.policy->cut_sequence});
		switch (result) {
		case boundary_control_publication_result::PUBLISHED:
			if (cut_publication_ns == 0u) {
				std::terminate();
			}
			entry.timing->cut_published_monotonic_ns = cut_publication_ns;
			entry.policy->phase = boundary_epoch_sender_phase::WAITING_ACK;
			break;
		case boundary_control_publication_result::PENDING:
			break;
		case boundary_control_publication_result::ABSENT:
			std::terminate();
		}
		publish_transition_(entry);
	}
	return true;
}

void worker_boundary_sender::service_control() noexcept
{
	if (!transition_active_) {
		return;
	}
	const bool pending_cut_attempt = std::any_of(endpoints_.begin(), endpoints_.end(), [](const endpoint &entry) {
		return entry.policy != nullptr && entry.policy->phase == boundary_epoch_sender_phase::CUT_PENDING;
	});
	const uint64_t pending_cut_ns = pending_cut_attempt ? common::now_ns() : 0u;
	if (pending_cut_attempt && pending_cut_ns == 0u) {
		std::terminate();
	}
	bool ack_observed = false;
	for (auto &entry : endpoints_) {
		if (entry.policy == nullptr || entry.timing == nullptr) {
			std::terminate();
		}
		if (entry.policy->phase == boundary_epoch_sender_phase::CUT_PENDING) {
			const auto result = entry.channel->service_pending_cut();
			if (result == boundary_control_publication_result::PUBLISHED) {
				if (pending_cut_ns == 0u) {
					std::terminate();
				}
				entry.timing->cut_published_monotonic_ns = pending_cut_ns;
				entry.policy->phase = boundary_epoch_sender_phase::WAITING_ACK;
				publish_transition_(entry);
			} else if (result == boundary_control_publication_result::ABSENT) {
				std::terminate();
			}
		}

		boundary_epoch_ack ack{};
		if (!entry.channel->try_receive_ack(ack)) {
			continue;
		}
		const boundary_epoch_ack expected{entry.policy->to_epoch, entry.policy->cut_sequence};
		if (!expected.valid() || !(ack == expected)) {
			record_fault_(entry, epoch_protocol_fault_code::CUT_IDENTITY_MISMATCH,
				      epoch_protocol_fault_disposition::TERMINATE, ack.ready_epoch,
				      entry.policy->cut_sequence, ack.consumed_cut_sequence);
			std::terminate();
		}
		if (entry.policy->phase == boundary_epoch_sender_phase::WAITING_ACK) {
			entry.policy->open_epoch = entry.policy->to_epoch;
			entry.policy->phase = boundary_epoch_sender_phase::OPEN;
			ack_observed = true;
			continue;
		}
		if (entry.policy->phase != boundary_epoch_sender_phase::OPEN ||
		    entry.policy->open_epoch != entry.policy->to_epoch ||
		    entry.policy->duplicate_ack_count == std::numeric_limits<uint64_t>::max()) {
			record_fault_(entry, epoch_protocol_fault_code::ACK_BEFORE_ACTIVATION,
				      epoch_protocol_fault_disposition::TERMINATE, ack.ready_epoch,
				      entry.policy->to_epoch, ack.ready_epoch);
			std::terminate();
		}
		++entry.policy->duplicate_ack_count;
		if (entry.timing->ack_observed_monotonic_ns != 0u) {
			publish_transition_(entry);
		} else {
			std::terminate();
		}
	}
	if (ack_observed) {
		const uint64_t ack_observed_ns = common::now_ns();
		for (auto &entry : endpoints_) {
			if (entry.timing == nullptr || entry.policy == nullptr) {
				std::terminate();
			}
			if (entry.policy->phase != boundary_epoch_sender_phase::OPEN ||
			    entry.policy->open_epoch != entry.policy->to_epoch ||
			    entry.timing->ack_observed_monotonic_ns != 0u) {
				continue;
			}
			if (entry.timing->cut_published_monotonic_ns == 0u ||
			    ack_observed_ns < entry.timing->cut_published_monotonic_ns) {
				std::terminate();
			}
			entry.timing->ack_observed_monotonic_ns = ack_observed_ns;
			publish_transition_(entry);
		}
	}
}

std::size_t worker_boundary_sender::service_held_output(std::size_t maximum_attempts) noexcept
{
	if (maximum_attempts == 0u || maximum_attempts > common::runtime_sizing::PACKET_MAX_BURST_SIZE) {
		std::terminate();
	}
	if (!transition_active_ || endpoints_.empty()) {
		return 0u;
	}
	std::size_t remaining_attempts = maximum_attempts;
	std::size_t visited_endpoints = 0u;
	std::size_t transferred = 0u;
	while (remaining_attempts != 0u && visited_endpoints < endpoints_.size()) {
		if (round_robin_cursor_ >= endpoints_.size()) {
			std::terminate();
		}
		auto &entry = endpoints_[round_robin_cursor_];
		// Preserve a predictable wrap branch instead of runtime integer division.
		++round_robin_cursor_;
		if (round_robin_cursor_ == endpoints_.size()) {
			round_robin_cursor_ = 0u;
		}
		++visited_endpoints;
		if (entry.policy == nullptr || entry.policy->transition_generation != transition_generation_ ||
		    entry.policy->from_epoch != transition_from_epoch_ ||
		    entry.policy->to_epoch != transition_to_epoch_) {
			std::terminate();
		}
		if (entry.policy->phase != boundary_epoch_sender_phase::OPEN) {
			--remaining_attempts;
			continue;
		}
		if (entry.policy->open_epoch != transition_to_epoch_) {
			std::terminate();
		}
		const packet_record *front = entry.hold->peek();
		if (front == nullptr) {
			--remaining_attempts;
			continue;
		}
		for (;;) {
			if (front->metadata.epoch != transition_to_epoch_) {
				std::terminate();
			}
			auto *record = const_cast<packet_record *>(front);
			const uint64_t packet_epoch = record->metadata.epoch;
			--remaining_attempts;
			const auto result = entry.channel->try_send_data(record);
			if (KINETUM_UNLIKELY(result != boundary_data_publication_result::TRANSFERRED)) {
				if (result == boundary_data_publication_result::BACKPRESSURED) {
					break;
				}
				if (result != boundary_data_publication_result::SEQUENCE_EXHAUSTED) {
					std::terminate();
				}
				record_fault_(entry, epoch_protocol_fault_code::SEQUENCE_EXHAUSTED,
					      epoch_protocol_fault_disposition::TERMINATE, packet_epoch,
					      MAX_BOUNDARY_DATA_SEQUENCE, entry.channel->data_enqueued_sequence());
				std::terminate();
			}
			packet_record *released = nullptr;
			if (!entry.hold->try_release(released) || released != record) {
				std::terminate();
			}
			ledger_->retire(packet_epoch);
			++transferred;
			if (remaining_attempts == 0u) {
				break;
			}
			front = entry.hold->peek();
			if (front == nullptr) {
				break;
			}
		}
	}
	return transferred;
}

void worker_boundary_sender::complete_sender_transition(uint64_t transition_generation) noexcept
{
	if (!transition_active_ || transition_generation != transition_generation_ || ledger_ == nullptr ||
	    ledger_->active_epoch() != transition_to_epoch_ || ledger_->source_epoch() != transition_to_epoch_ ||
	    ledger_->future_epoch() != 0u) {
		std::terminate();
	}
	for (std::size_t attempt = 0u; attempt < common::runtime_sizing::BOUNDARY_ACK_RING_CAPACITY; ++attempt) {
		service_control();
	}
	if (!all_gates_open() || !packet_ownership_empty()) {
		std::terminate();
	}
	for (const auto &entry : endpoints_) {
		if (entry.channel->has_pending_cut()) {
			std::terminate();
		}
	}
	transition_active_ = false;
}

void worker_boundary_sender::publish_transport() noexcept
{
	for (auto &entry : endpoints_) {
		entry.channel->publish_sender_transport();
	}
}

void worker_boundary_sender::close_for_shutdown() noexcept
{
	if (transition_active_ || !packet_ownership_empty()) {
		std::terminate();
	}
	for (auto &entry : endpoints_) {
		if (entry.policy == nullptr || entry.policy->phase != boundary_epoch_sender_phase::OPEN ||
		    entry.channel->sender_closed() || entry.channel->has_pending_cut()) {
			std::terminate();
		}
		boundary_epoch_ack unexpected_ack{};
		if (entry.channel->try_receive_ack(unexpected_ack)) {
			std::terminate();
		}
		entry.channel->close_sender();
	}
}

bool worker_boundary_sender::transition_active() const noexcept
{
	return transition_active_;
}

bool worker_boundary_sender::outbound_sealed() const noexcept
{
	return transition_active_ && outbound_sealed_;
}

bool worker_boundary_sender::all_gates_open() const noexcept
{
	if (!transition_active_ || !outbound_sealed_ || ledger_ == nullptr ||
	    ledger_->active_epoch() != transition_to_epoch_ || ledger_->source_epoch() != transition_to_epoch_ ||
	    ledger_->future_epoch() != 0u) {
		return false;
	}
	return std::all_of(endpoints_.begin(), endpoints_.end(), [this](const endpoint &entry) {
		return entry.policy != nullptr && entry.policy->phase == boundary_epoch_sender_phase::OPEN &&
		       entry.policy->transition_generation == transition_generation_ &&
		       entry.policy->open_epoch == transition_to_epoch_;
	});
}

bool worker_boundary_sender::all_cuts_published() const noexcept
{
	if (!transition_active_ || !outbound_sealed_) {
		return false;
	}
	return std::all_of(endpoints_.begin(), endpoints_.end(), [this](const endpoint &entry) {
		return entry.policy != nullptr && entry.policy->transition_generation == transition_generation_ &&
		       entry.policy->to_epoch == transition_to_epoch_ && !entry.channel->has_pending_cut() &&
		       (entry.policy->phase == boundary_epoch_sender_phase::WAITING_ACK ||
			entry.policy->phase == boundary_epoch_sender_phase::OPEN);
	});
}

bool worker_boundary_sender::packet_ownership_empty() const noexcept
{
	return std::all_of(endpoints_.begin(), endpoints_.end(),
			   [](const endpoint &entry) { return entry.hold != nullptr && entry.hold->empty(); });
}

std::size_t worker_boundary_sender::size() const noexcept
{
	return endpoints_.size();
}

uint32_t worker_boundary_sender::worker_index() const noexcept
{
	return worker_index_;
}

uint64_t worker_boundary_sender::runtime_generation() const noexcept
{
	return runtime_generation_;
}

bool worker_boundary_sender::owns_ledger(const worker_epoch_ledger &ledger) const noexcept
{
	return ledger_ == &ledger;
}

uint64_t worker_boundary_sender::transition_generation() const noexcept
{
	return transition_generation_;
}

uint64_t worker_boundary_sender::transition_from_epoch() const noexcept
{
	return transition_from_epoch_;
}

uint64_t worker_boundary_sender::transition_to_epoch() const noexcept
{
	return transition_to_epoch_;
}

common::status_or<uint32_t> worker_boundary_sender::sender_ordinal(uint32_t boundary_index) const
{
	const auto iterator = std::lower_bound(endpoints_.begin(), endpoints_.end(), boundary_index,
					       [](const endpoint &entry, uint32_t candidate) {
						       return entry.boundary_index < candidate;
					       });
	if (iterator == endpoints_.end() || iterator->boundary_index != boundary_index) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "boundary is not owned by this exact sender worker");
	}
	return static_cast<uint32_t>(std::distance(endpoints_.begin(), iterator));
}

uint32_t worker_boundary_sender::boundary_index(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).boundary_index;
}

bool worker_boundary_sender::owns_boundary_channel(uint32_t sender_ordinal,
						   const boundary_epoch_channel &channel) const noexcept
{
	return endpoint_(sender_ordinal).channel == &channel;
}

boundary_epoch_sender_phase worker_boundary_sender::phase(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).policy->phase;
}

uint64_t worker_boundary_sender::open_epoch(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).policy->open_epoch;
}

uint64_t worker_boundary_sender::from_epoch(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).policy->from_epoch;
}

uint64_t worker_boundary_sender::to_epoch(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).policy->to_epoch;
}

uint64_t worker_boundary_sender::cut_sequence(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).policy->cut_sequence;
}

uint64_t worker_boundary_sender::duplicate_ack_count(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).policy->duplicate_ack_count;
}

std::size_t worker_boundary_sender::held_size(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).hold->size_approx();
}

std::size_t worker_boundary_sender::hold_capacity(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).hold->capacity();
}

int32_t worker_boundary_sender::policy_numa_node(uint32_t sender_ordinal) const noexcept
{
	return endpoint_(sender_ordinal).channel->sender_endpoint_numa_node();
}

publication_read_result
worker_boundary_sender::try_read_transition(uint32_t sender_ordinal,
					    boundary_sender_transition_snapshot &out) const noexcept
{
	if (sender_ordinal >= endpoints_.size()) {
		return publication_read_result::INVALID_IDENTITY;
	}
	const auto &entry = endpoint_(sender_ordinal);
	if (entry.publication == nullptr) {
		return publication_read_result::UNAVAILABLE;
	}
	kinetum::algo::single_writer_snapshot<POLICY_PUBLICATION_FIELD_COUNT>::snapshot observed{};
	if (!entry.publication->try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}
	const uint64_t runtime_generation = observed.fields[POLICY_RUNTIME_GENERATION];
	const uint64_t boundary_index = observed.fields[POLICY_BOUNDARY_INDEX];
	const uint64_t transition_generation = observed.fields[POLICY_TRANSITION_GENERATION];
	const uint64_t from_epoch = observed.fields[POLICY_FROM_EPOCH];
	const uint64_t to_epoch = observed.fields[POLICY_TO_EPOCH];
	const uint64_t cut_sequence = observed.fields[POLICY_CUT_SEQUENCE];
	const uint64_t ack_observed = observed.fields[POLICY_ACK_OBSERVED];
	const uint64_t raw_phase = observed.fields[POLICY_PHASE];
	const uint64_t cut_published_ns = observed.fields[POLICY_CUT_PUBLISHED_NS];
	const uint64_t ack_observed_ns = observed.fields[POLICY_ACK_OBSERVED_NS];
	const uint64_t duplicate_ack_count = observed.fields[POLICY_DUPLICATE_ACK_COUNT];
	const uint64_t open_epoch = observed.fields[POLICY_OPEN_EPOCH];
	if (runtime_generation != runtime_generation_ || boundary_index != entry.boundary_index) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (raw_phase > static_cast<uint64_t>(boundary_epoch_sender_phase::WAITING_ACK)) {
		return publication_read_result::INVALID_STATE;
	}
	const auto phase = static_cast<boundary_epoch_sender_phase>(raw_phase);
	const bool bootstrap_shape = transition_generation == 0u && from_epoch == 0u &&
				     common::valid_epoch_id(to_epoch) && cut_sequence == 0u && ack_observed == 0u &&
				     phase == boundary_epoch_sender_phase::OPEN && open_epoch == to_epoch &&
				     cut_published_ns == 0u && ack_observed_ns == 0u && duplicate_ack_count == 0u;
	const bool transition_shape =
		common::valid_mutation_sequence(transition_generation) && common::valid_epoch_id(from_epoch) &&
		common::valid_epoch_id(to_epoch) && to_epoch > from_epoch &&
		valid_boundary_data_sequence(cut_sequence) &&
		((phase == boundary_epoch_sender_phase::DRAINING && cut_sequence == 0u && ack_observed == 0u &&
		  cut_published_ns == 0u && ack_observed_ns == 0u && open_epoch == from_epoch) ||
		 (phase == boundary_epoch_sender_phase::CUT_PENDING && ack_observed == 0u && cut_published_ns == 0u &&
		  ack_observed_ns == 0u && open_epoch == from_epoch) ||
		 (phase == boundary_epoch_sender_phase::WAITING_ACK && ack_observed == 0u && cut_published_ns != 0u &&
		  ack_observed_ns == 0u && open_epoch == from_epoch) ||
		 (phase == boundary_epoch_sender_phase::OPEN && ack_observed == 1u && cut_published_ns != 0u &&
		  ack_observed_ns >= cut_published_ns && open_epoch == to_epoch));
	if (!bootstrap_shape && !transition_shape) {
		return publication_read_result::INVALID_STATE;
	}
	out = boundary_sender_transition_snapshot{
		.publication_generation = observed.generation,
		.runtime_generation = runtime_generation,
		.boundary_index = boundary_index,
		.transition_generation = transition_generation,
		.from_epoch = from_epoch,
		.to_epoch = to_epoch,
		.cut_sequence = cut_sequence,
		.ack_observed = ack_observed,
		.cut_published_monotonic_ns = cut_published_ns,
		.ack_observed_monotonic_ns = ack_observed_ns,
		.duplicate_ack_count = duplicate_ack_count,
		.open_epoch = open_epoch,
		.phase = phase,
		.padding = {},
	};
	return publication_read_result::AVAILABLE;
}

worker_boundary_sender::endpoint &worker_boundary_sender::endpoint_(uint32_t sender_ordinal) noexcept
{
	if (KINETUM_UNLIKELY(sender_ordinal >= endpoints_.size() || endpoints_[sender_ordinal].policy == nullptr)) {
		std::terminate();
	}
	return endpoints_[sender_ordinal];
}

const worker_boundary_sender::endpoint &worker_boundary_sender::endpoint_(uint32_t sender_ordinal) const noexcept
{
	if (KINETUM_UNLIKELY(sender_ordinal >= endpoints_.size() || endpoints_[sender_ordinal].policy == nullptr)) {
		std::terminate();
	}
	return endpoints_[sender_ordinal];
}

bool worker_boundary_sender::clean_for_begin_(const endpoint &entry) noexcept
{
	return entry.policy != nullptr && entry.policy->phase == boundary_epoch_sender_phase::OPEN &&
	       common::valid_epoch_id(entry.policy->open_epoch) && entry.channel != nullptr && entry.hold != nullptr &&
	       !entry.channel->sender_closed() && !entry.channel->has_pending_cut() &&
	       entry.channel->ack_lane_empty() && entry.hold->empty();
}

bool worker_boundary_sender::policy_unbound_(const endpoint &entry) noexcept
{
	return entry.policy != nullptr && entry.policy->phase == boundary_epoch_sender_phase::UNBOUND &&
	       entry.policy->transition_generation == 0u && entry.policy->open_epoch == 0u &&
	       entry.policy->from_epoch == 0u && entry.policy->to_epoch == 0u && entry.policy->cut_sequence == 0u &&
	       entry.policy->duplicate_ack_count == 0u;
}

void worker_boundary_sender::record_fault_(const endpoint &entry, epoch_protocol_fault_code code,
					   epoch_protocol_fault_disposition disposition, uint64_t observed_epoch,
					   uint64_t expected_value, uint64_t observed_value) noexcept
{
	if (telemetry_ == nullptr || faults_ == nullptr || entry.boundary_index == UINT32_MAX) {
		std::terminate();
	}
	telemetry_->record_protocol_fault(code);
	(void)faults_->record(epoch_protocol_first_fault{
		.runtime_generation = runtime_generation_,
		.transition_generation = transition_generation_,
		.from_epoch = transition_from_epoch_,
		.to_epoch = transition_to_epoch_,
		.observed_epoch = observed_epoch,
		.expected_value = expected_value,
		.observed_value = observed_value,
		.observed_monotonic_ns = common::cached_ns(),
		.worker_index = worker_index_,
		.boundary_index = entry.boundary_index,
		.context_index = UINT32_MAX,
		.stage_instance_index = UINT32_MAX,
		.code = code,
		.disposition = disposition,
		.padding = {},
	});
}

void worker_boundary_sender::publish_transition_(endpoint &entry) noexcept
{
	if (entry.policy == nullptr || entry.timing == nullptr || entry.publication == nullptr) {
		std::terminate();
	}
	const bool bootstrap = entry.policy->transition_generation == 0u;
	const bool transition = common::valid_mutation_sequence(entry.policy->transition_generation) &&
				common::valid_epoch_id(entry.policy->from_epoch) &&
				common::valid_epoch_id(entry.policy->to_epoch) &&
				entry.policy->to_epoch > entry.policy->from_epoch;
	if (bootstrap) {
		if (bootstrap_epoch_ == 0u || entry.policy->phase != boundary_epoch_sender_phase::OPEN ||
		    entry.policy->open_epoch != bootstrap_epoch_ || entry.policy->from_epoch != 0u ||
		    entry.policy->to_epoch != 0u || entry.policy->cut_sequence != 0u ||
		    entry.timing->cut_published_monotonic_ns != 0u || entry.timing->ack_observed_monotonic_ns != 0u) {
			std::terminate();
		}
	} else if (!transition) {
		std::terminate();
	}
	const bool cut_published = entry.timing->cut_published_monotonic_ns != 0u;
	const bool ack_observed = entry.timing->ack_observed_monotonic_ns != 0u;
	const bool phase_shape = bootstrap ||
				 (entry.policy->phase == boundary_epoch_sender_phase::DRAINING &&
				  entry.policy->open_epoch == entry.policy->from_epoch &&
				  entry.policy->cut_sequence == 0u && !cut_published && !ack_observed) ||
				 (entry.policy->phase == boundary_epoch_sender_phase::CUT_PENDING && outbound_sealed_ &&
				  !cut_published && !ack_observed) ||
				 (entry.policy->phase == boundary_epoch_sender_phase::WAITING_ACK && outbound_sealed_ &&
				  cut_published && !ack_observed) ||
				 (entry.policy->phase == boundary_epoch_sender_phase::OPEN && outbound_sealed_ &&
				  entry.policy->open_epoch == entry.policy->to_epoch && cut_published && ack_observed &&
				  entry.timing->ack_observed_monotonic_ns >= entry.timing->cut_published_monotonic_ns);
	if (!phase_shape) {
		std::terminate();
	}
	const std::array<uint64_t, POLICY_PUBLICATION_FIELD_COUNT> fields{
		runtime_generation_,
		entry.boundary_index,
		entry.policy->transition_generation,
		entry.policy->from_epoch,
		bootstrap ? entry.policy->open_epoch : entry.policy->to_epoch,
		entry.policy->cut_sequence,
		ack_observed ? 1u : 0u,
		static_cast<uint64_t>(entry.policy->phase),
		entry.timing->cut_published_monotonic_ns,
		entry.timing->ack_observed_monotonic_ns,
		entry.policy->duplicate_ack_count,
		entry.policy->open_epoch,
	};
	if (!entry.publication->publish(fields)) {
		std::terminate();
	}
}

}  // namespace kinetum::dp
