// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file epoch_transition_certificate.cpp
 * @brief Exact global certificate source validation and aggregation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/epoch_transition_certificate.hpp"

#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"

namespace kinetum::dp
{

bool epoch_transition_certificate_request::valid() const noexcept
{
	return runtime_generation != 0u && runtime_generation <= std::numeric_limits<uint32_t>::max() &&
	       common::valid_mutation_sequence(transition_generation) && common::valid_epoch_id(from_epoch) &&
	       common::valid_epoch_id(to_epoch) && to_epoch > from_epoch && grace_generation != 0u &&
	       grace_generation < std::numeric_limits<uint64_t>::max();
}

epoch_transition_certificate_record_observation
classify_execution_certificate(const epoch_transition_certificate_request &request, uint32_t expected_worker,
			       const epoch_transition_certificate_worker_read &observed) noexcept
{
	if (!request.valid()) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::REQUEST_IDENTITY};
	}
	const auto read = observed.result();
	const auto &ledger = observed.value.ledger;
	const auto &activation = observed.value.activation;
	const bool has_ledger = observed.ledger == publication_read_result::AVAILABLE;
	const bool has_activation = observed.activation == publication_read_result::AVAILABLE;
	if (read == publication_read_result::INVALID_IDENTITY ||
	    (has_ledger &&
	     (ledger.runtime_generation != request.runtime_generation || ledger.worker_index != expected_worker)) ||
	    (has_activation && (activation.runtime_generation != request.runtime_generation ||
				activation.worker_index != expected_worker))) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::EXECUTION_MEMBERSHIP};
	}
	if (read == publication_read_result::INVALID_STATE ||
	    (has_activation && activation.transition_generation > request.transition_generation) ||
	    (has_ledger && (ledger.active_epoch > request.to_epoch || ledger.source_epoch > request.to_epoch ||
			    ledger.future_epoch > request.to_epoch))) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::EXECUTION_STATE};
	}
	const bool current_activation = has_activation &&
					activation.transition_generation == request.transition_generation;
	if (current_activation &&
	    (activation.from_epoch != request.from_epoch || activation.to_epoch != request.to_epoch ||
	     activation.active_epoch != request.to_epoch || activation.activation_complete != 1u)) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::EXECUTION_STATE};
	}
	if (has_ledger && ledger.active_epoch == request.from_epoch) {
		const bool pending_shape =
			(ledger.source_epoch == request.from_epoch || ledger.source_epoch == request.to_epoch) &&
			(ledger.future_epoch == 0u || ledger.future_epoch == request.to_epoch);
		if (!pending_shape) {
			return {epoch_transition_certificate_record_result::CONTRADICTION,
				epoch_transition_certificate_fault::EXECUTION_STATE};
		}
	}
	if (has_ledger && ledger.active_epoch >= request.from_epoch && ledger.active_epoch != request.from_epoch &&
	    (ledger.active_epoch != request.to_epoch || ledger.source_epoch != request.to_epoch ||
	     ledger.future_epoch != 0u || ledger.future_unretired != 0u)) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::EXECUTION_STATE};
	}
	if (read != publication_read_result::AVAILABLE || !current_activation ||
	    ledger.active_epoch < request.to_epoch) {
		return {epoch_transition_certificate_record_result::INCOMPLETE,
			epoch_transition_certificate_fault::NONE};
	}
	return {epoch_transition_certificate_record_result::COMPLETE, epoch_transition_certificate_fault::NONE};
}

epoch_transition_certificate_record_observation
classify_boundary_certificate(const epoch_transition_certificate_request &request, uint32_t expected_boundary,
			      const epoch_transition_certificate_boundary_read &observed) noexcept
{
	if (!request.valid()) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::REQUEST_IDENTITY};
	}
	const auto read = observed.result();
	const auto &sender = observed.value.sender;
	const auto &receiver = observed.value.receiver;
	const auto &sender_transport = observed.value.sender_transport;
	const auto &receiver_transport = observed.value.receiver_transport;
	const bool has_sender = observed.sender == publication_read_result::AVAILABLE;
	const bool has_receiver = observed.receiver == publication_read_result::AVAILABLE;
	const auto identity_invalid = [&request, expected_boundary](publication_read_result result,
								    const auto &value) noexcept {
		return result == publication_read_result::AVAILABLE &&
		       (value.runtime_generation != request.runtime_generation ||
			value.boundary_index != expected_boundary);
	};
	if (read == publication_read_result::INVALID_IDENTITY || identity_invalid(observed.sender, sender) ||
	    identity_invalid(observed.receiver, receiver) ||
	    identity_invalid(observed.sender_transport, sender_transport) ||
	    identity_invalid(observed.receiver_transport, receiver_transport)) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::BOUNDARY_MEMBERSHIP};
	}
	if (read == publication_read_result::INVALID_STATE ||
	    (has_sender && sender.transition_generation > request.transition_generation) ||
	    (has_receiver && receiver.transition_generation > request.transition_generation)) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::BOUNDARY_STATE};
	}
	const bool current_sender = has_sender && sender.transition_generation == request.transition_generation;
	const bool current_receiver = has_receiver && receiver.transition_generation == request.transition_generation;
	if ((current_sender && (sender.from_epoch != request.from_epoch || sender.to_epoch != request.to_epoch)) ||
	    (current_receiver &&
	     (receiver.from_epoch != request.from_epoch || receiver.to_epoch != request.to_epoch))) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::BOUNDARY_STATE};
	}
	const bool sender_complete = current_sender && sender.phase == boundary_epoch_sender_phase::OPEN;
	const bool sender_cut_captured = current_sender &&
					 (sender_complete || sender.phase == boundary_epoch_sender_phase::CUT_PENDING ||
					  sender.phase == boundary_epoch_sender_phase::WAITING_ACK);
	const bool receiver_complete = current_receiver &&
				       (receiver.phase == boundary_epoch_receiver_phase::OPEN ||
					receiver.phase == boundary_epoch_receiver_phase::ACK_PUBLISHED);
	const bool receiver_cut_captured = current_receiver &&
					   (receiver_complete ||
					    receiver.phase == boundary_epoch_receiver_phase::CUT_DRAINING ||
					    receiver.phase == boundary_epoch_receiver_phase::CUT_DRAINED ||
					    receiver.phase == boundary_epoch_receiver_phase::ACK_PENDING);
	if ((current_sender && ((!sender_cut_captured && sender.phase != boundary_epoch_sender_phase::DRAINING) ||
				sender.ack_observed != (sender_complete ? 1u : 0u))) ||
	    (current_receiver &&
	     ((!receiver_cut_captured && receiver.phase != boundary_epoch_receiver_phase::WAITING_CUT) ||
	      receiver.ack_published != (receiver_complete ? 1u : 0u)))) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::BOUNDARY_STATE};
	}
	if (sender_cut_captured && receiver_cut_captured && sender.cut_sequence != receiver.cut_sequence) {
		return {epoch_transition_certificate_record_result::CONTRADICTION,
			epoch_transition_certificate_fault::CUT_IDENTITY};
	}
	if (read != publication_read_result::AVAILABLE || !sender_complete || !receiver_complete) {
		return {epoch_transition_certificate_record_result::INCOMPLETE,
			epoch_transition_certificate_fault::NONE};
	}
	if (sender_transport.data_enqueued_sequence < sender.cut_sequence ||
	    receiver_transport.data_dequeued_sequence < sender.cut_sequence ||
	    sender_transport.pending_cut_epoch != 0u || sender_transport.pending_cut_sequence != 0u ||
	    receiver_transport.pending_ack_epoch != 0u || receiver_transport.pending_ack_sequence != 0u) {
		return {epoch_transition_certificate_record_result::INCOMPLETE,
			epoch_transition_certificate_fault::NONE};
	}
	return {epoch_transition_certificate_record_result::COMPLETE, epoch_transition_certificate_fault::NONE};
}

common::status_or<std::unique_ptr<epoch_transition_certificate>>
epoch_transition_certificate::create(uint64_t runtime_generation, const frozen_transition_participants &participants,
				     std::span<const epoch_transition_certificate_worker_source> workers,
				     std::span<boundary_epoch_channel *const> boundaries,
				     const kinetum::algo::quiescence_domain &domain)
{
	if (runtime_generation == 0u || runtime_generation > std::numeric_limits<uint32_t>::max() || workers.empty() ||
	    workers.size() != participants.execution_participant_count() ||
	    boundaries.size() != participants.boundary_count() || domain.reader_count() != workers.size() ||
	    participants.quiescence_reader_count() != workers.size() ||
	    workers.size() > std::numeric_limits<uint32_t>::max() ||
	    boundaries.size() > std::numeric_limits<uint32_t>::max()) {
		return common::status::invalid_argument(
			"transition certificate source cardinality or runtime identity is not exact");
	}

	try {
		std::vector<epoch_transition_certificate_worker_source> worker_sources(workers.begin(), workers.end());
		std::vector<boundary_source> boundary_sources(boundaries.size());
		const auto reader_indices = participants.quiescence_reader_indices();
		if (reader_indices.size() != worker_sources.size()) {
			return common::status::failed_precondition(
				"transition certificate reader identities disagree with frozen membership");
		}
		for (std::size_t worker_index = 0u; worker_index < worker_sources.size(); ++worker_index) {
			const auto *participant =
				participants.execution_participant(static_cast<uint32_t>(worker_index));
			const auto &source = worker_sources[worker_index];
			if (participant == nullptr || participant->participant_index != worker_index ||
			    participant->worker_index != worker_index ||
			    participant->quiescence_reader_index != worker_index ||
			    reader_indices[worker_index] != worker_index || source.ledger == nullptr ||
			    source.activation == nullptr || source.sender == nullptr || source.receiver == nullptr ||
			    source.reader == nullptr || source.ledger->worker_index() != worker_index ||
			    source.ledger->runtime_generation() != runtime_generation ||
			    source.activation->worker_index() != worker_index ||
			    source.activation->runtime_generation() != runtime_generation ||
			    !source.activation->owns_ledger(*source.ledger) ||
			    source.activation->module_store_count() !=
				    participants.module_context_indices(static_cast<uint32_t>(worker_index)).size() ||
			    source.sender->worker_index() != worker_index ||
			    source.sender->runtime_generation() != runtime_generation ||
			    !source.sender->owns_ledger(*source.ledger) ||
			    source.receiver->worker_index() != worker_index ||
			    source.receiver->runtime_generation() != runtime_generation ||
			    !source.receiver->owns_ledger(*source.ledger) ||
			    source.sender->size() !=
				    participants.outbound_boundary_indices(static_cast<uint32_t>(worker_index)).size() ||
			    source.receiver->size() !=
				    participants.inbound_boundary_indices(static_cast<uint32_t>(worker_index)).size() ||
			    !domain.owns_reader(worker_index, *source.reader)) {
				return common::status::failed_precondition(
					"transition certificate worker source disagrees with frozen membership");
			}

			const auto outbound =
				participants.outbound_boundary_indices(static_cast<uint32_t>(worker_index));
			for (std::size_t ordinal = 0u; ordinal < outbound.size(); ++ordinal) {
				const uint32_t boundary_index = outbound[ordinal];
				if (boundary_index >= boundary_sources.size() ||
				    boundary_sources[boundary_index].sender_worker != UINT32_MAX ||
				    source.sender->boundary_index(static_cast<uint32_t>(ordinal)) != boundary_index) {
					return common::status::failed_precondition(
						"transition certificate outbound membership is duplicate or malformed");
				}
				boundary_sources[boundary_index].sender_worker = static_cast<uint32_t>(worker_index);
				boundary_sources[boundary_index].sender_ordinal = static_cast<uint32_t>(ordinal);
			}

			const auto inbound = participants.inbound_boundary_indices(static_cast<uint32_t>(worker_index));
			for (std::size_t ordinal = 0u; ordinal < inbound.size(); ++ordinal) {
				const uint32_t boundary_index = inbound[ordinal];
				if (boundary_index >= boundary_sources.size() ||
				    boundary_sources[boundary_index].receiver_worker != UINT32_MAX ||
				    source.receiver->boundary_index(static_cast<uint32_t>(ordinal)) != boundary_index) {
					return common::status::failed_precondition(
						"transition certificate inbound membership is duplicate or malformed");
				}
				boundary_sources[boundary_index].receiver_worker = static_cast<uint32_t>(worker_index);
				boundary_sources[boundary_index].receiver_ordinal = static_cast<uint32_t>(ordinal);
			}
		}

		for (std::size_t boundary_index = 0u; boundary_index < boundary_sources.size(); ++boundary_index) {
			auto &source = boundary_sources[boundary_index];
			auto *channel = boundaries[boundary_index];
			if (source.sender_worker == UINT32_MAX || source.sender_ordinal == UINT32_MAX ||
			    source.receiver_worker == UINT32_MAX || source.receiver_ordinal == UINT32_MAX ||
			    source.sender_worker >= worker_sources.size() ||
			    source.receiver_worker >= worker_sources.size() || channel == nullptr ||
			    channel->boundary_index() != boundary_index ||
			    channel->runtime_generation() != runtime_generation ||
			    channel->sender_worker_index() != source.sender_worker ||
			    channel->receiver_worker_index() != source.receiver_worker ||
			    !worker_sources[source.sender_worker].sender->owns_boundary_channel(source.sender_ordinal,
												*channel) ||
			    !worker_sources[source.receiver_worker].receiver->owns_boundary_channel(
				    source.receiver_ordinal, *channel)) {
				return common::status::failed_precondition(
					"transition certificate boundary source disagrees with frozen ownership");
			}
			source.channel = channel;
		}

		return std::unique_ptr<epoch_transition_certificate>(
			new epoch_transition_certificate(runtime_generation, participants, std::move(worker_sources),
							 std::move(boundary_sources), domain));
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("transition certificate source allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "transition certificate source graph exceeds a bounded host container");
	}
}

epoch_transition_certificate::epoch_transition_certificate(
	uint64_t runtime_generation, const frozen_transition_participants &participants,
	std::vector<epoch_transition_certificate_worker_source> workers, std::vector<boundary_source> boundaries,
	const kinetum::algo::quiescence_domain &domain) noexcept
	: runtime_generation_(runtime_generation)
	, participants_(&participants)
	, workers_(std::move(workers))
	, boundaries_(std::move(boundaries))
	, domain_(&domain)
{
}

epoch_transition_certificate_progress
epoch_transition_certificate::evaluate(const epoch_transition_certificate_request &request) const noexcept
{
	epoch_transition_certificate_progress progress{
		.runtime_generation = request.runtime_generation,
		.transition_generation = request.transition_generation,
		.from_epoch = request.from_epoch,
		.to_epoch = request.to_epoch,
		.execution_total = static_cast<uint32_t>(workers_.size()),
		.boundary_total = static_cast<uint32_t>(boundaries_.size()),
		.reader_total = static_cast<uint32_t>(domain_ != nullptr ? domain_->reader_count() : 0u),
	};
	const auto fault = [&progress](epoch_transition_certificate_fault kind, uint32_t index) noexcept {
		if (progress.fault == epoch_transition_certificate_fault::NONE) {
			progress.fault = kind;
			progress.fault_index = index;
		}
	};
	if (!request.valid() || request.runtime_generation != runtime_generation_ || participants_ == nullptr ||
	    domain_ == nullptr) {
		fault(epoch_transition_certificate_fault::REQUEST_IDENTITY, UINT32_MAX);
		progress.state = epoch_transition_certificate_state::CONTRADICTION;
		return progress;
	}

	for (std::size_t worker_index = 0u; worker_index < workers_.size(); ++worker_index) {
		const auto observed = observe_worker(static_cast<uint32_t>(worker_index));
		const auto result =
			classify_execution_certificate(request, static_cast<uint32_t>(worker_index), observed);
		if (result.result == epoch_transition_certificate_record_result::COMPLETE) {
			++progress.execution_complete;
		} else if (result.result == epoch_transition_certificate_record_result::CONTRADICTION) {
			fault(result.fault, static_cast<uint32_t>(worker_index));
		}
	}

	for (std::size_t boundary_index = 0u; boundary_index < boundaries_.size(); ++boundary_index) {
		const auto observed = observe_boundary(static_cast<uint32_t>(boundary_index));
		const auto result =
			classify_boundary_certificate(request, static_cast<uint32_t>(boundary_index), observed);
		if (result.result == epoch_transition_certificate_record_result::COMPLETE) {
			++progress.boundary_complete;
		} else if (result.result == epoch_transition_certificate_record_result::CONTRADICTION) {
			fault(result.fault, static_cast<uint32_t>(boundary_index));
		}
	}

	const auto readers = domain_->quiescent_reader_count(request.grace_generation);
	if (!readers.has_value() || *readers > domain_->reader_count()) {
		fault(epoch_transition_certificate_fault::READER_MEMBERSHIP, UINT32_MAX);
	} else {
		progress.reader_complete = static_cast<uint32_t>(*readers);
	}

	if (progress.fault != epoch_transition_certificate_fault::NONE) {
		progress.state = epoch_transition_certificate_state::CONTRADICTION;
		return progress;
	}
	const bool execution_complete = progress.execution_complete == progress.execution_total &&
					progress.boundary_complete == progress.boundary_total;
	if (!execution_complete) {
		progress.state = epoch_transition_certificate_state::INCOMPLETE;
	} else if (progress.reader_complete != progress.reader_total) {
		progress.state = epoch_transition_certificate_state::EXECUTION_COMPLETE;
	} else {
		progress.state = epoch_transition_certificate_state::RECLAMATION_READY;
	}
	return progress;
}

epoch_transition_certificate_worker_read
epoch_transition_certificate::observe_worker(uint32_t worker_index) const noexcept
{
	epoch_transition_certificate_worker_read observed{};
	if (worker_index >= workers_.size()) {
		observed.ledger = publication_read_result::INVALID_IDENTITY;
		observed.activation = publication_read_result::INVALID_IDENTITY;
		return observed;
	}
	const auto &source = workers_[worker_index];
	if (source.ledger == nullptr || source.activation == nullptr) {
		std::terminate();
	}
	observed.ledger = source.ledger->try_read(observed.value.ledger);
	observed.activation = source.activation->try_read(observed.value.activation);
	if (observed.ledger == publication_read_result::AVAILABLE &&
	    (observed.value.ledger.worker_index != worker_index ||
	     observed.value.ledger.runtime_generation != runtime_generation_)) {
		observed.ledger = publication_read_result::INVALID_IDENTITY;
	}
	if (observed.activation == publication_read_result::AVAILABLE &&
	    (observed.value.activation.worker_index != worker_index ||
	     observed.value.activation.runtime_generation != runtime_generation_)) {
		observed.activation = publication_read_result::INVALID_IDENTITY;
	}
	return observed;
}

epoch_transition_certificate_boundary_read
epoch_transition_certificate::observe_boundary(uint32_t boundary_index) const noexcept
{
	epoch_transition_certificate_boundary_read observed{};
	if (boundary_index >= boundaries_.size()) {
		observed.sender = publication_read_result::INVALID_IDENTITY;
		observed.receiver = publication_read_result::INVALID_IDENTITY;
		observed.sender_transport = publication_read_result::INVALID_IDENTITY;
		observed.receiver_transport = publication_read_result::INVALID_IDENTITY;
		return observed;
	}
	const auto &source = boundaries_[boundary_index];
	if (source.sender_worker >= workers_.size() || source.receiver_worker >= workers_.size() ||
	    source.channel == nullptr || workers_[source.sender_worker].sender == nullptr ||
	    workers_[source.receiver_worker].receiver == nullptr) {
		std::terminate();
	}
	observed.sender = workers_[source.sender_worker].sender->try_read_transition(source.sender_ordinal,
										     observed.value.sender);
	observed.receiver = workers_[source.receiver_worker].receiver->try_read_transition(source.receiver_ordinal,
											   observed.value.receiver);
	observed.sender_transport = source.channel->try_read_sender_transport(observed.value.sender_transport);
	observed.receiver_transport = source.channel->try_read_receiver_transport(observed.value.receiver_transport);
	const auto check_identity = [this, boundary_index](publication_read_result read, const auto &value) noexcept {
		return read == publication_read_result::AVAILABLE && (value.runtime_generation != runtime_generation_ ||
								      value.boundary_index != boundary_index) ?
			       publication_read_result::INVALID_IDENTITY :
			       read;
	};
	observed.sender = check_identity(observed.sender, observed.value.sender);
	observed.receiver = check_identity(observed.receiver, observed.value.receiver);
	observed.sender_transport = check_identity(observed.sender_transport, observed.value.sender_transport);
	observed.receiver_transport = check_identity(observed.receiver_transport, observed.value.receiver_transport);
	return observed;
}

std::size_t epoch_transition_certificate::execution_participant_count() const noexcept
{
	return workers_.size();
}

std::size_t epoch_transition_certificate::boundary_count() const noexcept
{
	return boundaries_.size();
}

std::size_t epoch_transition_certificate::reader_count() const noexcept
{
	return domain_ != nullptr ? domain_->reader_count() : 0u;
}

uint64_t epoch_transition_certificate::runtime_generation() const noexcept
{
	return runtime_generation_;
}

bool epoch_transition_certificate::owns_participants(const frozen_transition_participants &participants) const noexcept
{
	return participants_ == &participants;
}

bool epoch_transition_certificate::owns_domain(const kinetum::algo::quiescence_domain &domain) const noexcept
{
	return domain_ == &domain;
}

}  // namespace kinetum::dp
