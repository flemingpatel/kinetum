// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_boundary_receiver.cpp
 * @brief Exact worker-owned boundary receiver policy implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/worker_boundary_receiver.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/time.hpp"
#include "src/dp/epoch/ordered_cut.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"

namespace kinetum::dp
{

common::status_or<std::unique_ptr<worker_boundary_receiver>>
worker_boundary_receiver::create(uint32_t worker_index, uint64_t runtime_generation,
				 std::span<boundary_epoch_channel *const> channels)
{
	if (worker_index == std::numeric_limits<uint32_t>::max() || runtime_generation == 0u ||
	    runtime_generation > std::numeric_limits<uint32_t>::max() ||
	    channels.size() > std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"boundary receiver requires exact representable worker, generation, and endpoint identities");
	}

	std::vector<endpoint> endpoints;
	try {
		endpoints.reserve(channels.size());
		uint32_t previous_boundary = 0u;
		bool have_previous = false;
		for (auto *channel : channels) {
			if (channel == nullptr || channel->receiver_worker_index() != worker_index ||
			    channel->runtime_generation() != runtime_generation || channel->sender_closed() ||
			    !channel->empty() || channel->endpoint_storage_sealed()) {
				return common::status::failed_precondition(
					"boundary receiver endpoint does not equal one clean unsealed compiled ownership");
			}
			const uint32_t boundary_index = channel->boundary_index();
			if (have_previous && boundary_index <= previous_boundary) {
				return common::status::failed_precondition(
					"boundary receiver endpoints must be strictly sorted and unique");
			}
			endpoints.push_back({boundary_index, channel, nullptr, nullptr, nullptr});
			previous_boundary = boundary_index;
			have_previous = true;
		}
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("boundary receiver endpoint table allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "boundary receiver endpoint table exceeds a bounded host container");
	}

	auto *raw = new (std::nothrow) worker_boundary_receiver(worker_index, runtime_generation, std::move(endpoints));
	if (raw == nullptr) {
		return common::status::resource_exhausted("boundary receiver owner allocation failed");
	}
	std::unique_ptr<worker_boundary_receiver> owner(raw);
	for (auto &entry : owner->endpoints_) {
		auto policy_or = entry.channel->receiver_slab_->claim_receiver_policy_(
			entry.channel->receiver_slot_index_, entry.boundary_index);
		if (!policy_or.is_ok()) {
			return policy_or.error();
		}
		entry.policy = policy_or.value();
		entry.timing =
			&entry.channel->receiver_slab_->receiver_slots_[entry.channel->receiver_slot_index_].timing;
		entry.publication = &entry.channel->receiver_slab_->receiver_slots_[entry.channel->receiver_slot_index_]
					     .policy_publication;
	}
	return owner;
}

worker_boundary_receiver::worker_boundary_receiver(uint32_t worker_index, uint64_t runtime_generation,
						   std::vector<endpoint> endpoints) noexcept
	: worker_index_(worker_index)
	, runtime_generation_(runtime_generation)
	, endpoints_(std::move(endpoints))
{
}

worker_boundary_receiver::~worker_boundary_receiver()
{
	if (transition_active_) {
		std::terminate();
	}
	for (auto iterator = endpoints_.rbegin(); iterator != endpoints_.rend(); ++iterator) {
		auto &entry = *iterator;
		if (entry.policy == nullptr) {
			continue;
		}
		if ((entry.policy->phase != boundary_epoch_receiver_phase::UNBOUND &&
		     entry.policy->phase != boundary_epoch_receiver_phase::OPEN) ||
		    entry.channel == nullptr || !entry.channel->control_empty()) {
			std::terminate();
		}
		*entry.policy = {};
		if (entry.timing == nullptr) {
			std::terminate();
		}
		*entry.timing = {};
		entry.channel->receiver_slab_->release_receiver_policy_(entry.channel->receiver_slot_index_,
									entry.boundary_index);
		entry.policy = nullptr;
		entry.timing = nullptr;
		entry.publication = nullptr;
	}
}

common::status worker_boundary_receiver::bind_ledger(worker_epoch_ledger &ledger)
{
	if (ledger_ != nullptr || ledger.worker_index() != worker_index_ ||
	    ledger.runtime_generation() != runtime_generation_ || bootstrap_epoch_ != 0u || transition_active_) {
		return common::status::failed_precondition(
			"boundary receiver ledger does not match one unbound worker generation");
	}
	ledger_ = &ledger;
	return common::status::ok();
}

common::status worker_boundary_receiver::bind_protocol_faults(worker_runtime_telemetry &telemetry,
							      epoch_protocol_fault_latch &faults) noexcept
{
	if (telemetry_ != nullptr || faults_ != nullptr || telemetry.worker_index() != worker_index_ ||
	    telemetry.runtime_generation() != runtime_generation_ || bootstrap_epoch_ != 0u || transition_active_) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"boundary receiver protocol diagnostics do not match one unbound worker generation"));
	}
	telemetry_ = &telemetry;
	faults_ = &faults;
	return common::status::ok();
}

void worker_boundary_receiver::bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept
{
	if (ledger_ == nullptr || bootstrap_epoch_ != 0u || transition_active_ ||
	    !common::valid_epoch_id(bootstrap_epoch) || ledger_->active_epoch() != bootstrap_epoch ||
	    ledger_->source_epoch() != bootstrap_epoch || ledger_->future_epoch() != 0u) {
		std::terminate();
	}
	for (const auto &entry : endpoints_) {
		if (!policy_unbound_(entry) || entry.channel->sender_closed() || !entry.channel->control_empty()) {
			std::terminate();
		}
	}
	bootstrap_epoch_ = bootstrap_epoch;
	for (auto &entry : endpoints_) {
		entry.policy->active_epoch = bootstrap_epoch;
		entry.policy->phase = boundary_epoch_receiver_phase::OPEN;
		publish_transition_(entry);
	}
}

bool worker_boundary_receiver::preflight_begin_transition(uint64_t transition_generation, uint64_t from_epoch,
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
		if (!clean_for_begin_(entry) || entry.policy->active_epoch != from_epoch) {
			return false;
		}
	}
	return true;
}

bool worker_boundary_receiver::begin_transition(uint64_t transition_generation, uint64_t from_epoch,
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
			if (entry.policy == nullptr ||
			    (entry.policy->active_epoch != from_epoch && entry.policy->active_epoch != to_epoch) ||
			    entry.policy->phase == boundary_epoch_receiver_phase::UNBOUND ||
			    entry.policy->phase == boundary_epoch_receiver_phase::OPEN) {
				std::terminate();
			}
		}
		return false;
	}
	transition_generation_ = transition_generation;
	transition_from_epoch_ = from_epoch;
	transition_to_epoch_ = to_epoch;
	transition_active_ = true;
	activation_acknowledged_ = false;
	for (auto &entry : endpoints_) {
		if (entry.timing == nullptr) {
			std::terminate();
		}
		*entry.timing = {};
		entry.policy->accepted_cut = {};
		entry.policy->duplicate_cut_count = 0u;
		entry.policy->phase = boundary_epoch_receiver_phase::WAITING_CUT;
		publish_transition_(entry);
	}
	return true;
}

void worker_boundary_receiver::service_control() noexcept
{
	if (!transition_active_) {
		return;
	}
	const bool pending_ack_attempt = std::any_of(endpoints_.begin(), endpoints_.end(), [](const endpoint &entry) {
		return entry.policy != nullptr && entry.policy->phase == boundary_epoch_receiver_phase::ACK_PENDING;
	});
	// The sender may free an ACK slot concurrently, so availability cannot be
	// pre-observed without a TOCTOU race. Sample once before the complete retry
	// batch and retain it only for records that publish.
	const uint64_t pending_ack_ns = pending_ack_attempt ? common::now_ns() : 0u;
	if (pending_ack_attempt && pending_ack_ns == 0u) {
		std::terminate();
	}
	for (auto &entry : endpoints_) {
		if (entry.policy == nullptr || entry.timing == nullptr ||
		    (entry.policy->active_epoch != transition_from_epoch_ &&
		     entry.policy->active_epoch != transition_to_epoch_)) {
			std::terminate();
		}

		boundary_epoch_cut cut{};
		if (entry.channel->try_receive_cut(cut)) {
			if (cut.next_epoch != transition_to_epoch_) {
				record_fault_(entry, epoch_protocol_fault_code::CUT_IDENTITY_MISMATCH,
					      epoch_protocol_fault_disposition::TERMINATE, cut.next_epoch,
					      transition_to_epoch_, cut.next_epoch);
				std::terminate();
			}
			const bool present = entry.policy->phase != boundary_epoch_receiver_phase::WAITING_CUT;
			const exact_record_result result =
				classify_exact_protocol_record(present, entry.policy->accepted_cut, cut);
			switch (result) {
			case exact_record_result::ACCEPTED:
				entry.policy->accepted_cut = cut;
				(void)refresh_cut_progress_(entry);
				break;
			case exact_record_result::DUPLICATE:
				if (entry.policy->duplicate_cut_count == std::numeric_limits<uint64_t>::max()) {
					std::terminate();
				}
				++entry.policy->duplicate_cut_count;
				publish_transition_(entry);
				break;
			case exact_record_result::INVALID:
			case exact_record_result::CONFLICT:
				record_fault_(entry, epoch_protocol_fault_code::CUT_IDENTITY_MISMATCH,
					      epoch_protocol_fault_disposition::TERMINATE, cut.next_epoch,
					      entry.policy->accepted_cut.data_cut_sequence, cut.data_cut_sequence);
				std::terminate();
			}
		}
		if (entry.policy->phase == boundary_epoch_receiver_phase::ACK_PENDING) {
			const auto result = entry.channel->service_pending_ack();
			if (result == boundary_control_publication_result::PUBLISHED) {
				if (pending_ack_ns == 0u || entry.timing->activation_monotonic_ns == 0u) {
					std::terminate();
				}
				entry.timing->ack_published_monotonic_ns = pending_ack_ns;
				entry.policy->phase = boundary_epoch_receiver_phase::ACK_PUBLISHED;
				publish_transition_(entry);
			} else if (result == boundary_control_publication_result::ABSENT) {
				std::terminate();
			}
		}
	}
}

void worker_boundary_receiver::refresh_cut_progress() noexcept
{
	if (!transition_active_) {
		return;
	}
	bool timing_changed = false;
	for (auto &entry : endpoints_) {
		if (entry.policy == nullptr || entry.timing == nullptr) {
			std::terminate();
		}
		if (entry.policy->accepted_cut.valid() && entry.timing->cut_observed_monotonic_ns == 0u) {
			timing_changed = true;
		}
		if (entry.policy->phase == boundary_epoch_receiver_phase::CUT_DRAINING) {
			timing_changed = refresh_cut_progress_(entry) || timing_changed;
		}
	}
	if (timing_changed) {
		const uint64_t receiver_batch_ns = common::now_ns();
		if (receiver_batch_ns == 0u) {
			std::terminate();
		}
		for (auto &entry : endpoints_) {
			bool publish = false;
			if (entry.policy->accepted_cut.valid() && entry.timing->cut_observed_monotonic_ns == 0u) {
				entry.timing->cut_observed_monotonic_ns = receiver_batch_ns;
				publish = true;
			}
			if (entry.policy->phase == boundary_epoch_receiver_phase::CUT_DRAINED &&
			    entry.timing->cut_drained_monotonic_ns == 0u) {
				if (entry.timing->cut_observed_monotonic_ns == 0u ||
				    receiver_batch_ns < entry.timing->cut_observed_monotonic_ns) {
					std::terminate();
				}
				entry.timing->cut_drained_monotonic_ns = receiver_batch_ns;
				publish = true;
			}
			if (publish) {
				publish_transition_(entry);
			}
		}
	}
}

bool worker_boundary_receiver::activation_ready() const noexcept
{
	if (!transition_active_ || activation_acknowledged_ || ledger_ == nullptr ||
	    ledger_->active_epoch() != transition_from_epoch_ || ledger_->source_epoch() != transition_to_epoch_ ||
	    ledger_->future_epoch() != transition_to_epoch_ || ledger_->active_unretired() != 0u) {
		return false;
	}
	return all_cuts_drained();
}

void worker_boundary_receiver::acknowledge_activation(uint64_t transition_generation, uint64_t to_epoch) noexcept
{
	if (!transition_active_ || activation_acknowledged_ || transition_generation != transition_generation_ ||
	    to_epoch != transition_to_epoch_ || ledger_ == nullptr) {
		std::terminate();
	}
	if (ledger_->active_epoch() != to_epoch || ledger_->source_epoch() != to_epoch ||
	    ledger_->future_epoch() != 0u) {
		if (!endpoints_.empty()) {
			record_fault_(endpoints_.front(), epoch_protocol_fault_code::ACK_BEFORE_ACTIVATION,
				      epoch_protocol_fault_disposition::TERMINATE, ledger_->active_epoch(), to_epoch,
				      ledger_->active_epoch());
		}
		std::terminate();
	}
	if (!all_cuts_drained()) {
		if (!endpoints_.empty()) {
			record_fault_(endpoints_.front(), epoch_protocol_fault_code::ACK_BEFORE_CUT_DRAIN,
				      epoch_protocol_fault_disposition::TERMINATE, to_epoch, 1u, 0u);
		}
		std::terminate();
	}
	for (const auto &entry : endpoints_) {
		if (entry.channel->has_pending_ack()) {
			std::terminate();
		}
	}
	activation_acknowledged_ = true;
	// This is the one approved pre-ACK batch sample. Reusing it for the
	// immediately preceding activation edge keeps CUT-drain <= activation <= ACK
	// publication causal without adding another clock read.
	const uint64_t ack_publication_ns = endpoints_.empty() ? 0u : common::now_ns();
	if (!endpoints_.empty() && ack_publication_ns == 0u) {
		std::terminate();
	}
	for (auto &entry : endpoints_) {
		if (entry.timing == nullptr) {
			std::terminate();
		}
		entry.policy->active_epoch = to_epoch;
		entry.policy->phase = boundary_epoch_receiver_phase::ACK_PENDING;
		entry.timing->activation_monotonic_ns = ack_publication_ns;
		publish_transition_(entry);
	}
	for (auto &entry : endpoints_) {
		const boundary_epoch_ack ack{to_epoch, entry.policy->accepted_cut.data_cut_sequence};
		const auto result = entry.channel->submit_ack(ack);
		switch (result) {
		case boundary_control_publication_result::PUBLISHED:
			if (ack_publication_ns == 0u) {
				std::terminate();
			}
			entry.timing->ack_published_monotonic_ns = ack_publication_ns;
			entry.policy->phase = boundary_epoch_receiver_phase::ACK_PUBLISHED;
			publish_transition_(entry);
			break;
		case boundary_control_publication_result::PENDING:
			break;
		case boundary_control_publication_result::ABSENT:
			std::terminate();
		}
	}
}

void worker_boundary_receiver::complete_receiver_transition(uint64_t transition_generation) noexcept
{
	if (!transition_active_ || transition_generation != transition_generation_ || !activation_acknowledged_ ||
	    !all_acks_published()) {
		std::terminate();
	}
	for (auto &entry : endpoints_) {
		if (entry.channel->has_pending_ack()) {
			std::terminate();
		}
		entry.policy->phase = boundary_epoch_receiver_phase::OPEN;
		publish_transition_(entry);
	}
	transition_active_ = false;
}

bool worker_boundary_receiver::transition_active() const noexcept
{
	return transition_active_;
}

bool worker_boundary_receiver::all_cuts_drained() const noexcept
{
	if (!transition_active_ || activation_acknowledged_) {
		return false;
	}
	return std::all_of(endpoints_.begin(), endpoints_.end(), [](const endpoint &entry) {
		return entry.policy != nullptr && entry.channel != nullptr &&
		       entry.policy->phase == boundary_epoch_receiver_phase::CUT_DRAINED &&
		       entry.policy->accepted_cut.valid() && !entry.channel->has_pending_ack();
	});
}

bool worker_boundary_receiver::all_acks_published() const noexcept
{
	if (!transition_active_ || !activation_acknowledged_) {
		return false;
	}
	return std::all_of(endpoints_.begin(), endpoints_.end(), [](const endpoint &entry) {
		return entry.policy != nullptr && entry.channel != nullptr &&
		       entry.policy->phase == boundary_epoch_receiver_phase::ACK_PUBLISHED &&
		       !entry.channel->has_pending_ack() && entry.channel->cut_lane_empty();
	});
}

std::size_t worker_boundary_receiver::size() const noexcept
{
	return endpoints_.size();
}

uint32_t worker_boundary_receiver::worker_index() const noexcept
{
	return worker_index_;
}

uint64_t worker_boundary_receiver::runtime_generation() const noexcept
{
	return runtime_generation_;
}

bool worker_boundary_receiver::owns_ledger(const worker_epoch_ledger &ledger) const noexcept
{
	return ledger_ == &ledger;
}

uint64_t worker_boundary_receiver::transition_generation() const noexcept
{
	return transition_generation_;
}

uint64_t worker_boundary_receiver::transition_from_epoch() const noexcept
{
	return transition_from_epoch_;
}

uint64_t worker_boundary_receiver::transition_to_epoch() const noexcept
{
	return transition_to_epoch_;
}

uint32_t worker_boundary_receiver::boundary_index(uint32_t receiver_ordinal) const noexcept
{
	return endpoint_(receiver_ordinal).boundary_index;
}

bool worker_boundary_receiver::owns_boundary_channel(uint32_t receiver_ordinal,
						     const boundary_epoch_channel &channel) const noexcept
{
	return endpoint_(receiver_ordinal).channel == &channel;
}

boundary_epoch_receiver_phase worker_boundary_receiver::phase(uint32_t receiver_ordinal) const noexcept
{
	return endpoint_(receiver_ordinal).policy->phase;
}

uint64_t worker_boundary_receiver::active_epoch(uint32_t receiver_ordinal) const noexcept
{
	return endpoint_(receiver_ordinal).policy->active_epoch;
}

boundary_epoch_cut worker_boundary_receiver::accepted_cut(uint32_t receiver_ordinal) const noexcept
{
	return endpoint_(receiver_ordinal).policy->accepted_cut;
}

uint64_t worker_boundary_receiver::duplicate_cut_count(uint32_t receiver_ordinal) const noexcept
{
	return endpoint_(receiver_ordinal).policy->duplicate_cut_count;
}

int32_t worker_boundary_receiver::policy_numa_node(uint32_t receiver_ordinal) const noexcept
{
	return endpoint_(receiver_ordinal).channel->receiver_endpoint_numa_node();
}

publication_read_result
worker_boundary_receiver::try_read_transition(uint32_t receiver_ordinal,
					      boundary_receiver_transition_snapshot &out) const noexcept
{
	if (receiver_ordinal >= endpoints_.size()) {
		return publication_read_result::INVALID_IDENTITY;
	}
	const auto &entry = endpoint_(receiver_ordinal);
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
	const uint64_t ack_published = observed.fields[POLICY_ACK_PUBLISHED];
	const uint64_t raw_phase = observed.fields[POLICY_PHASE];
	const uint64_t cut_observed_ns = observed.fields[POLICY_CUT_OBSERVED_NS];
	const uint64_t cut_drained_ns = observed.fields[POLICY_CUT_DRAINED_NS];
	const uint64_t activation_ns = observed.fields[POLICY_ACTIVATION_NS];
	const uint64_t ack_published_ns = observed.fields[POLICY_ACK_PUBLISHED_NS];
	const uint64_t duplicate_cut_count = observed.fields[POLICY_DUPLICATE_CUT_COUNT];
	const uint64_t active_epoch = observed.fields[POLICY_ACTIVE_EPOCH];
	if (runtime_generation != runtime_generation_ || boundary_index != entry.boundary_index) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (raw_phase > static_cast<uint64_t>(boundary_epoch_receiver_phase::ACK_PUBLISHED)) {
		return publication_read_result::INVALID_STATE;
	}
	const auto phase = static_cast<boundary_epoch_receiver_phase>(raw_phase);
	const bool bootstrap_shape = transition_generation == 0u && from_epoch == 0u &&
				     common::valid_epoch_id(to_epoch) && cut_sequence == 0u && ack_published == 0u &&
				     phase == boundary_epoch_receiver_phase::OPEN && active_epoch == to_epoch &&
				     cut_observed_ns == 0u && cut_drained_ns == 0u && activation_ns == 0u &&
				     ack_published_ns == 0u && duplicate_cut_count == 0u;
	const bool transition_shape =
		common::valid_mutation_sequence(transition_generation) && common::valid_epoch_id(from_epoch) &&
		common::valid_epoch_id(to_epoch) && to_epoch > from_epoch &&
		valid_boundary_data_sequence(cut_sequence) &&
		((phase == boundary_epoch_receiver_phase::WAITING_CUT && cut_sequence == 0u && ack_published == 0u &&
		  cut_observed_ns == 0u && cut_drained_ns == 0u && activation_ns == 0u && ack_published_ns == 0u &&
		  active_epoch == from_epoch) ||
		 (phase == boundary_epoch_receiver_phase::CUT_DRAINING && ack_published == 0u &&
		  cut_observed_ns != 0u && cut_drained_ns == 0u && activation_ns == 0u && ack_published_ns == 0u &&
		  active_epoch == from_epoch) ||
		 (phase == boundary_epoch_receiver_phase::CUT_DRAINED && ack_published == 0u && cut_observed_ns != 0u &&
		  cut_drained_ns >= cut_observed_ns && activation_ns == 0u && ack_published_ns == 0u &&
		  active_epoch == from_epoch) ||
		 (phase == boundary_epoch_receiver_phase::ACK_PENDING && ack_published == 0u && cut_observed_ns != 0u &&
		  cut_drained_ns >= cut_observed_ns && activation_ns != 0u && ack_published_ns == 0u &&
		  active_epoch == to_epoch) ||
		 ((phase == boundary_epoch_receiver_phase::ACK_PUBLISHED ||
		   phase == boundary_epoch_receiver_phase::OPEN) &&
		  ack_published == 1u && cut_observed_ns != 0u && cut_drained_ns >= cut_observed_ns &&
		  activation_ns != 0u && ack_published_ns != 0u && active_epoch == to_epoch));
	if (!bootstrap_shape && !transition_shape) {
		return publication_read_result::INVALID_STATE;
	}
	out = boundary_receiver_transition_snapshot{
		.publication_generation = observed.generation,
		.runtime_generation = runtime_generation,
		.boundary_index = boundary_index,
		.transition_generation = transition_generation,
		.from_epoch = from_epoch,
		.to_epoch = to_epoch,
		.cut_sequence = cut_sequence,
		.ack_published = ack_published,
		.cut_observed_monotonic_ns = cut_observed_ns,
		.cut_drained_monotonic_ns = cut_drained_ns,
		.activation_monotonic_ns = activation_ns,
		.ack_published_monotonic_ns = ack_published_ns,
		.duplicate_cut_count = duplicate_cut_count,
		.active_epoch = active_epoch,
		.phase = phase,
		.padding = {},
	};
	return publication_read_result::AVAILABLE;
}

worker_boundary_receiver::endpoint &worker_boundary_receiver::endpoint_(uint32_t receiver_ordinal) noexcept
{
	if (receiver_ordinal >= endpoints_.size() || endpoints_[receiver_ordinal].policy == nullptr) {
		std::terminate();
	}
	return endpoints_[receiver_ordinal];
}

const worker_boundary_receiver::endpoint &worker_boundary_receiver::endpoint_(uint32_t receiver_ordinal) const noexcept
{
	if (receiver_ordinal >= endpoints_.size() || endpoints_[receiver_ordinal].policy == nullptr) {
		std::terminate();
	}
	return endpoints_[receiver_ordinal];
}

bool worker_boundary_receiver::clean_for_begin_(const endpoint &entry) noexcept
{
	// A remote sender may consume the same immutable transition command first
	// and publish this generation's CUT before the receiver binds. Do not inspect
	// or consume that record here: service_control() admits only the exact target
	// epoch after binding. ACK ownership remains strict because an ACK causally
	// follows this endpoint's begin, CUT drain, and local activation.
	return entry.policy != nullptr && entry.policy->phase == boundary_epoch_receiver_phase::OPEN &&
	       common::valid_epoch_id(entry.policy->active_epoch) && entry.channel != nullptr &&
	       !entry.channel->has_pending_ack();
}

bool worker_boundary_receiver::policy_unbound_(const endpoint &entry) noexcept
{
	return entry.policy != nullptr && entry.policy->phase == boundary_epoch_receiver_phase::UNBOUND &&
	       entry.policy->active_epoch == 0u && entry.policy->accepted_cut == boundary_epoch_cut{} &&
	       entry.policy->duplicate_cut_count == 0u;
}

void worker_boundary_receiver::record_fault_(const endpoint &entry, epoch_protocol_fault_code code,
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

bool worker_boundary_receiver::refresh_cut_progress_(endpoint &entry) noexcept
{
	if (entry.policy == nullptr || !entry.policy->accepted_cut.valid() ||
	    (entry.policy->phase != boundary_epoch_receiver_phase::WAITING_CUT &&
	     entry.policy->phase != boundary_epoch_receiver_phase::CUT_DRAINING)) {
		std::terminate();
	}
	const sequence_cut_progress progress = classify_sequence_cut(entry.channel->data_dequeued_sequence(),
								     entry.policy->accepted_cut.data_cut_sequence);
	switch (progress) {
	case sequence_cut_progress::PENDING:
		entry.policy->phase = boundary_epoch_receiver_phase::CUT_DRAINING;
		return false;
	case sequence_cut_progress::REACHED:
		entry.policy->phase = boundary_epoch_receiver_phase::CUT_DRAINED;
		return true;
	case sequence_cut_progress::CONTRADICTION:
		record_fault_(entry, epoch_protocol_fault_code::CUT_IDENTITY_MISMATCH,
			      epoch_protocol_fault_disposition::TERMINATE, entry.policy->accepted_cut.next_epoch,
			      entry.policy->accepted_cut.data_cut_sequence, entry.channel->data_dequeued_sequence());
		std::terminate();
	case sequence_cut_progress::INVALID:
		std::terminate();
	}
	std::terminate();
}

void worker_boundary_receiver::publish_transition_(endpoint &entry) noexcept
{
	if (entry.policy == nullptr || entry.timing == nullptr || entry.publication == nullptr) {
		std::terminate();
	}
	const bool bootstrap = transition_generation_ == 0u;
	const bool transition = common::valid_mutation_sequence(transition_generation_) &&
				common::valid_epoch_id(transition_from_epoch_) &&
				common::valid_epoch_id(transition_to_epoch_) &&
				transition_to_epoch_ > transition_from_epoch_;
	if (bootstrap) {
		if (bootstrap_epoch_ == 0u || entry.policy->phase != boundary_epoch_receiver_phase::OPEN ||
		    entry.policy->active_epoch != bootstrap_epoch_ || entry.policy->accepted_cut.valid() ||
		    entry.timing->cut_observed_monotonic_ns != 0u || entry.timing->cut_drained_monotonic_ns != 0u ||
		    entry.timing->activation_monotonic_ns != 0u || entry.timing->ack_published_monotonic_ns != 0u) {
			std::terminate();
		}
	} else if (!transition) {
		std::terminate();
	}
	const bool cut_observed = entry.timing->cut_observed_monotonic_ns != 0u;
	const bool cut_drained = entry.timing->cut_drained_monotonic_ns != 0u;
	const bool activated = entry.timing->activation_monotonic_ns != 0u;
	const bool ack_published = entry.timing->ack_published_monotonic_ns != 0u;
	const bool phase_shape =
		bootstrap ||
		(entry.policy->phase == boundary_epoch_receiver_phase::WAITING_CUT &&
		 !entry.policy->accepted_cut.valid() && !cut_observed && !cut_drained && !activated &&
		 !ack_published) ||
		(entry.policy->phase == boundary_epoch_receiver_phase::CUT_DRAINING &&
		 entry.policy->accepted_cut.valid() && cut_observed && !cut_drained && !activated && !ack_published) ||
		(entry.policy->phase == boundary_epoch_receiver_phase::CUT_DRAINED &&
		 entry.policy->accepted_cut.valid() && cut_observed && cut_drained &&
		 entry.timing->cut_drained_monotonic_ns >= entry.timing->cut_observed_monotonic_ns && !activated &&
		 !ack_published) ||
		(entry.policy->phase == boundary_epoch_receiver_phase::ACK_PENDING &&
		 entry.policy->accepted_cut.valid() && cut_observed && cut_drained && activated && !ack_published &&
		 entry.policy->active_epoch == transition_to_epoch_) ||
		((entry.policy->phase == boundary_epoch_receiver_phase::ACK_PUBLISHED ||
		  entry.policy->phase == boundary_epoch_receiver_phase::OPEN) &&
		 entry.policy->accepted_cut.valid() && cut_observed && cut_drained && activated && ack_published &&
		 entry.policy->active_epoch == transition_to_epoch_);
	if (!phase_shape) {
		std::terminate();
	}
	const uint64_t cut_sequence =
		entry.policy->accepted_cut.valid() ? entry.policy->accepted_cut.data_cut_sequence : 0u;
	const std::array<uint64_t, POLICY_PUBLICATION_FIELD_COUNT> fields{
		runtime_generation_,
		entry.boundary_index,
		transition_generation_,
		transition_from_epoch_,
		bootstrap ? entry.policy->active_epoch : transition_to_epoch_,
		cut_sequence,
		ack_published ? 1u : 0u,
		static_cast<uint64_t>(entry.policy->phase),
		entry.timing->cut_observed_monotonic_ns,
		entry.timing->cut_drained_monotonic_ns,
		entry.timing->activation_monotonic_ns,
		entry.timing->ack_published_monotonic_ns,
		entry.policy->duplicate_cut_count,
		entry.policy->active_epoch,
	};
	if (!entry.publication->publish(fields)) {
		std::terminate();
	}
}

}  // namespace kinetum::dp
