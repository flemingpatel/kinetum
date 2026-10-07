// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_telemetry_snapshot_source.cpp
 * @brief Complete generation-scoped runtime telemetry composition.
 * @author Fleming Patel
 */

#include "src/dp/runtime_telemetry_snapshot_source.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <iterator>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <utility>

#include "src/common/time.hpp"
#include "src/dp/runtime_telemetry_aggregator.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Bounded provider diagnostic storage for one cold callback. */
constexpr std::size_t PROVIDER_DIAGNOSTIC_BYTES = 256u;

/**
 * @brief Add one cold aggregate value without wrapping.
 * @param[in,out] target Aggregate destination.
 * @param value Value to add with uint64 saturation.
 */
void add_saturating(uint64_t &target, uint64_t value) noexcept
{
	target = value > UINT64_MAX - target ? UINT64_MAX : target + value;
}

/**
 * @brief Map one compiled steering kind to its provider-neutral wire value.
 * @param kind Exact compiled steering mechanism.
 * @return Provider-neutral steering wire value.
 */
[[nodiscard]] kinetum::gluon::v1::TrafficSteeringKind steering_kind(provider::compiled_steering_kind kind) noexcept
{
	switch (kind) {
	case provider::compiled_steering_kind::NONE:
		return kinetum::gluon::v1::TRAFFIC_STEERING_KIND_NONE;
	case provider::compiled_steering_kind::RSS:
		return kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS;
	}
	std::terminate();
}

/**
 * @brief Map one fixed provider callback result without parsing prose.
 * @param result Fixed provider callback status.
 * @param operation Stable cold operation identity for bounded diagnostics.
 * @return Exact provider-neutral status without parsing provider prose.
 */
[[nodiscard]] common::status provider_status(kinetum_provider_status result, std::string_view operation)
{
	switch (result) {
	case KINETUM_PROVIDER_STATUS_OK:
		return common::status::ok();
	case KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT:
		return common::status::invalid_argument(std::string(operation) +
							" rejected its exact observation shape");
	case KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION:
		return common::status::failed_precondition(std::string(operation) + " rejected observation state");
	case KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED:
		return common::status::resource_exhausted(std::string(operation) +
							  " exhausted bounded observation work");
	case KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR:
		return common::status::internal_error(std::string(operation) + " reported an implementation failure");
	default:
		return common::status::data_loss(std::string(operation) + " returned an unknown provider status");
	}
}

/**
 * @brief Check one fixed observation-padding array.
 * @tparam array_type Fixed byte-array type.
 * @param bytes Candidate explicit padding.
 * @return true only when every byte remains zero.
 */
template <typename array_type>
[[nodiscard]] bool bytes_zero(const array_type &bytes) noexcept
{
	return std::all_of(std::begin(bytes), std::end(bytes), [](uint8_t byte) { return byte == 0u; });
}

/** @brief Relationship between independently published worker edge records. */
enum class worker_publication_relation : uint8_t {
	ALIGNED = 0,	///< Ledger and activation describe one directly publishable row.
	TEMPORAL_SKEW,	///< Activation reached N before this turn's ledger publication.
	CONTRADICTION,	///< No legal publication order can produce the observed pair.
};

/**
 * @brief Classify one intrinsically coherent ledger/activation pair.
 * @param ledger Coherent per-turn worker ledger publication.
 * @param activation Coherent event-edge activation publication.
 * @return Aligned, one legal activation-leading-ledger window, or contradiction.
 */
[[nodiscard]] worker_publication_relation
classify_worker_publications(const worker_epoch_ledger_snapshot &ledger,
			     const worker_epoch_activation_snapshot &activation) noexcept
{
	if (activation.active_epoch == ledger.active_epoch) {
		return worker_publication_relation::ALIGNED;
	}
	const bool activation_leads_ledger =
		activation.activation_complete == 1u && activation.from_epoch == ledger.active_epoch &&
		activation.to_epoch == activation.active_epoch &&
		(ledger.source_epoch == activation.from_epoch || ledger.source_epoch == activation.to_epoch) &&
		(ledger.future_epoch == 0u || ledger.future_epoch == activation.to_epoch);
	return activation_leads_ledger ? worker_publication_relation::TEMPORAL_SKEW :
					 worker_publication_relation::CONTRADICTION;
}

/**
 * @brief Validate available boundary evidence without hiding contradictions behind temporal skew.
 * @param read Independent policy and transport results from this attempt.
 * @param authority Stable coordinator progress, or null while its identity moves.
 * @param transactions Transactions from that same stable coordinator publication.
 * @return DATA_LOSS for immutable contradictions, UNAVAILABLE for legal skew, or OK.
 */
[[nodiscard]] common::status validate_boundary_observation(const epoch_transition_certificate_boundary_read &read,
							   const epoch_transition_progress_snapshot *authority,
							   const epoch_transition_telemetry_snapshot &transactions)
{
	const auto &value = read.value;
	const bool has_sender = read.sender == publication_read_result::AVAILABLE;
	const bool has_receiver = read.receiver == publication_read_result::AVAILABLE;
	const bool has_sender_transport = read.sender_transport == publication_read_result::AVAILABLE;
	const bool has_receiver_transport = read.receiver_transport == publication_read_result::AVAILABLE;
	const bool same_transition = has_sender && has_receiver &&
				     value.sender.transition_generation == value.receiver.transition_generation;
	const bool sender_cut_captured = has_sender && value.sender.transition_generation != 0u &&
					 value.sender.phase != boundary_epoch_sender_phase::DRAINING;
	const bool receiver_cut_captured = has_receiver && value.receiver.transition_generation != 0u &&
					   value.receiver.phase != boundary_epoch_receiver_phase::WAITING_CUT;
	if (same_transition && value.sender.transition_generation != 0u) {
		if (value.sender.from_epoch != value.receiver.from_epoch ||
		    value.sender.to_epoch != value.receiver.to_epoch) {
			return common::status::data_loss("policies contradict one immutable transition identity");
		}
		if (sender_cut_captured && receiver_cut_captured &&
		    value.sender.cut_sequence != value.receiver.cut_sequence) {
			return common::status::data_loss("policies captured different cuts for one transition");
		}
	}
	if (authority == nullptr) {
		return common::status::ok();
	}

	common::status failure;
	const auto check_policy = [&](publication_read_result result, const auto &policy) {
		if (result != publication_read_result::AVAILABLE) {
			return;
		}
		if (policy.transition_generation > authority->mutation_sequence_high_watermark ||
		    policy.to_epoch > authority->allocated_epoch_high_watermark) {
			merge_runtime_telemetry_failure(
				failure, common::status::data_loss("policy exceeds the stable allocation authority"));
		}
		if (transactions.active.present && transactions.active.commit_started_monotonic_ns != 0u) {
			if (policy.transition_generation < transactions.active.identity.mutation_sequence) {
				merge_runtime_telemetry_failure(
					failure,
					common::status::unavailable("policy has not reached the committed transition"));
			} else if (policy.transition_generation != transactions.active.identity.mutation_sequence ||
				   policy.from_epoch != transactions.active.from_epoch ||
				   policy.to_epoch != transactions.active.to_epoch) {
				merge_runtime_telemetry_failure(
					failure,
					common::status::data_loss("policy contradicts the committed transition"));
			}
		}
	};
	check_policy(read.sender, value.sender);
	check_policy(read.receiver, value.receiver);
	if (has_sender && has_receiver && !same_transition) {
		merge_runtime_telemetry_failure(
			failure, common::status::unavailable("endpoints belong to different publication generations"));
	}
	if (has_sender_transport && has_receiver_transport &&
	    value.receiver_transport.data_dequeued_sequence > value.sender_transport.data_enqueued_sequence) {
		merge_runtime_telemetry_failure(
			failure, common::status::unavailable("transport publications are temporally misaligned"));
	}
	if (has_sender_transport && has_sender) {
		const bool pending = value.sender_transport.pending_cut_epoch != 0u;
		if (pending != (value.sender.phase == boundary_epoch_sender_phase::CUT_PENDING)) {
			merge_runtime_telemetry_failure(
				failure, common::status::unavailable(
						 "sender control and policy publications are temporally misaligned"));
		} else if (pending && (value.sender_transport.pending_cut_epoch != value.sender.to_epoch ||
				       value.sender_transport.pending_cut_sequence != value.sender.cut_sequence)) {
			merge_runtime_telemetry_failure(
				failure, common::status::data_loss("pending CUT contradicts sender policy identity"));
		}
		if ((pending &&
		     value.sender_transport.pending_cut_sequence > value.sender_transport.data_enqueued_sequence) ||
		    (sender_cut_captured &&
		     value.sender.cut_sequence > value.sender_transport.data_enqueued_sequence)) {
			merge_runtime_telemetry_failure(
				failure, common::status::unavailable(
						 "sender policy and DATA publications are temporally misaligned"));
		}
	}
	if (has_receiver_transport && has_receiver) {
		const bool pending = value.receiver_transport.pending_ack_epoch != 0u;
		if (pending != (value.receiver.phase == boundary_epoch_receiver_phase::ACK_PENDING)) {
			merge_runtime_telemetry_failure(
				failure, common::status::unavailable(
						 "receiver control and policy publications are temporally misaligned"));
		} else if (pending && (value.receiver_transport.pending_ack_epoch != value.receiver.to_epoch ||
				       value.receiver_transport.pending_ack_sequence != value.receiver.cut_sequence)) {
			merge_runtime_telemetry_failure(
				failure, common::status::data_loss("pending ACK contradicts receiver policy identity"));
		}
		const bool drained = receiver_cut_captured &&
				     value.receiver.phase != boundary_epoch_receiver_phase::CUT_DRAINING;
		if ((pending &&
		     value.receiver_transport.pending_ack_sequence > value.receiver_transport.data_dequeued_sequence) ||
		    (drained && value.receiver.cut_sequence > value.receiver_transport.data_dequeued_sequence)) {
			merge_runtime_telemetry_failure(
				failure, common::status::unavailable(
						 "receiver policy and DATA publications are temporally misaligned"));
		}
	}
	if (same_transition &&
	    ((value.receiver.cut_observed_monotonic_ns != 0u && value.sender.cut_published_monotonic_ns == 0u) ||
	     (value.sender.ack_observed_monotonic_ns != 0u && value.receiver.ack_published_monotonic_ns == 0u))) {
		merge_runtime_telemetry_failure(
			failure, common::status::unavailable("causal edge publications are temporally misaligned"));
	}
	return failure;
}

/**
 * @brief Validate immutable first-fault identity independently of counter availability.
 * @param first Complete immutable fault publication.
 * @param topology Frozen participant and context membership.
 * @param runtime_generation Exact claimed generation.
 * @return OK for one exact owner, or DATA_LOSS for an invalid identity.
 */
[[nodiscard]] common::status validate_first_fault_identity(const epoch_protocol_first_fault &first,
							   const provider::compiled_provider_topology &topology,
							   uint64_t runtime_generation)
{
	const bool has_worker = first.worker_index != UINT32_MAX;
	const bool has_boundary = first.boundary_index != UINT32_MAX;
	const bool has_context = first.context_index != UINT32_MAX;
	const bool has_stage = first.stage_instance_index != UINT32_MAX;
	if (first.runtime_generation != runtime_generation ||
	    epoch_protocol_fault_ordinal(first.code) >= EPOCH_PROTOCOL_FAULT_COUNT ||
	    (has_worker && first.worker_index >= topology.transition_topology.workers.size()) ||
	    (has_boundary && first.boundary_index >= topology.transition_topology.boundaries.size()) ||
	    (has_context && first.context_index >= topology.module_contexts.size()) ||
	    (has_stage && first.stage_instance_index >= topology.stage_instances.size()) ||
	    ((has_boundary || has_context || has_stage) && !has_worker) || (has_boundary && has_context)) {
		return common::status::data_loss("runtime protocol first-fault identity is outside frozen membership");
	}
	if (has_stage && topology.stage_instances[first.stage_instance_index].worker_index != first.worker_index) {
		return common::status::data_loss("runtime protocol first-fault stage has a foreign worker owner");
	}
	if (has_context) {
		const auto &context = topology.module_contexts[first.context_index];
		if (!has_stage || context.worker_index != first.worker_index ||
		    context.stage_instance_index != first.stage_instance_index) {
			return common::status::data_loss(
				"runtime protocol first-fault context identity is contradictory");
		}
	}
	if (has_boundary) {
		const auto &boundary = topology.transition_topology.boundaries[first.boundary_index];
		if ((first.worker_index != boundary.sender_worker_index &&
		     first.worker_index != boundary.receiver_worker_index) ||
		    (has_stage && first.stage_instance_index != boundary.from_stage_instance_index &&
		     first.stage_instance_index != boundary.to_stage_instance_index)) {
			return common::status::data_loss(
				"runtime protocol first-fault boundary identity is contradictory");
		}
	}
	return common::status::ok();
}

}  // namespace

publication_read_result
classify_runtime_status_transition(const runtime_status_snapshot &status,
				   const epoch_transition_progress_snapshot &transition) noexcept
{
	if (status.readiness == runtime_readiness::CONTROL_READY) {
		return publication_read_result::UNAVAILABLE;
	}
	if (status.readiness != runtime_readiness::PACKET_READY) {
		return publication_read_result::INVALID_STATE;
	}
	const bool stable_active = status.active_epoch == transition.active_epoch &&
				   status.minimum_retained_epoch == transition.active_epoch &&
				   status.last_activated_epoch == transition.active_epoch;
	const bool activated_with_retained_old = transition.target_epoch != 0u &&
						 status.active_epoch == transition.target_epoch &&
						 status.minimum_retained_epoch == transition.active_epoch &&
						 status.last_activated_epoch == transition.target_epoch;
	const bool completed_target = transition.target_epoch != 0u && status.active_epoch == transition.target_epoch &&
				      status.minimum_retained_epoch == transition.target_epoch &&
				      status.last_activated_epoch == transition.target_epoch;
	switch (transition.phase) {
	case epoch_transition_phase::IDLE:
	case epoch_transition_phase::PREPARING:
	case epoch_transition_phase::PREPARED:
		return stable_active ? publication_read_result::AVAILABLE : publication_read_result::INVALID_STATE;
	case epoch_transition_phase::COMMITTING:
		if (activated_with_retained_old) {
			// Runtime activation publishes before the coordinator enters RETIRING.
			return publication_read_result::UNAVAILABLE;
		}
		return stable_active ? publication_read_result::AVAILABLE : publication_read_result::INVALID_STATE;
	case epoch_transition_phase::RETIRING:
		if (completed_target) {
			// Runtime reclamation publishes before the coordinator returns to IDLE.
			return publication_read_result::UNAVAILABLE;
		}
		return activated_with_retained_old ? publication_read_result::AVAILABLE :
						     publication_read_result::INVALID_STATE;
	case epoch_transition_phase::FAILED_STOP:
		return stable_active || activated_with_retained_old ? publication_read_result::AVAILABLE :
								      publication_read_result::INVALID_STATE;
	case epoch_transition_phase::AWAITING_BOOTSTRAP:
	case epoch_transition_phase::BOOTSTRAPPING:
		return publication_read_result::INVALID_STATE;
	}
	return publication_read_result::INVALID_STATE;
}

common::status_or<std::optional<epoch_transition_completion_progress_snapshot>> project_runtime_completion_progress(
	publication_read_result read, const epoch_transition_completion_progress_snapshot &value,
	const epoch_transition_progress_snapshot &progress, const epoch_transition_telemetry_snapshot &transactions)
{
	const bool active_required = progress.phase == epoch_transition_phase::PREPARED ||
				     progress.phase == epoch_transition_phase::COMMITTING ||
				     progress.phase == epoch_transition_phase::RETIRING ||
				     (progress.phase == epoch_transition_phase::FAILED_STOP &&
				      transactions.active.present && transactions.active.prepared_monotonic_ns != 0u);
	if (read == publication_read_result::UNAVAILABLE) {
		if (active_required ||
		    (transactions.active.present && transactions.active.prepared_monotonic_ns != 0u) ||
		    (transactions.latest_terminal.present &&
		     transactions.latest_terminal.prepared_monotonic_ns != 0u)) {
			return common::status::unavailable("runtime completion progress is not coherently observable");
		}
		return std::optional<epoch_transition_completion_progress_snapshot>{};
	}
	if (read != publication_read_result::AVAILABLE) {
		return common::status::data_loss("runtime completion publication is invalid");
	}
	const bool active_generation = transactions.active.present &&
				       value.transition_generation == transactions.active.identity.mutation_sequence;
	const bool terminal_generation = transactions.latest_terminal.present &&
					 value.transition_generation ==
						 transactions.latest_terminal.identity.mutation_sequence;
	if (value.transition_generation > progress.mutation_sequence_high_watermark ||
	    value.to_epoch > progress.allocated_epoch_high_watermark ||
	    (active_generation &&
	     (value.from_epoch != transactions.active.from_epoch || value.to_epoch != transactions.active.to_epoch)) ||
	    (terminal_generation && (value.from_epoch != transactions.latest_terminal.from_epoch ||
				     value.to_epoch != transactions.latest_terminal.to_epoch))) {
		return common::status::data_loss("runtime completion publication contradicts its transaction owner");
	}
	if (active_required && !active_generation) {
		return common::status::unavailable(
			"runtime completion publication has not reached the active transaction");
	}
	if (!active_generation && !terminal_generation) {
		const bool retired = !value.transaction_active && !value.update_frozen &&
				     (value.grace_generation == 0u || value.grace_finished_monotonic_ns != 0u);
		if (retired && transactions.latest_terminal.present &&
		    value.transition_generation < transactions.latest_terminal.identity.mutation_sequence) {
			// A later pre-PREPARED abort can replace the terminal row without ever arming completion.
			return std::optional<epoch_transition_completion_progress_snapshot>{};
		}
		return common::status::unavailable(
			"runtime completion and transaction publications have not converged");
	}
	if ((active_generation && !value.transaction_active) || (terminal_generation && value.transaction_active) ||
	    (active_generation &&
	     ((transactions.active.commit_started_monotonic_ns != 0u) != (value.grace_generation != 0u)))) {
		return common::status::unavailable(
			"runtime completion and transaction publications are between state edges");
	}
	return std::optional<epoch_transition_completion_progress_snapshot>{value};
}

common::status_or<std::unique_ptr<runtime_telemetry_snapshot_source>> runtime_telemetry_snapshot_source::create(
	uint64_t runtime_generation, const provider::compiled_provider_topology &topology,
	const provider::materialized_provider_runtime &providers, runtime_telemetry_aggregator &aggregator,
	const runtime_status_publication &runtime_status, const epoch_transition_coordinator &coordinator,
	const epoch_transition_certificate &certificate, const epoch_transition_completion *completion,
	const epoch_protocol_fault_latch &protocol_faults)
{
	if (runtime_generation == 0u || providers.runtime_generation() != runtime_generation ||
	    certificate.runtime_generation() != runtime_generation ||
	    !certificate.owns_participants(coordinator.participants()) ||
	    !coordinator.owns_protocol_faults(runtime_generation, protocol_faults) ||
	    aggregator.expected_workers() != topology.transition_topology.workers.size() ||
	    (topology.transition_topology.policy.enabled != (completion != nullptr))) {
		return common::status::failed_precondition(
			"runtime telemetry source authorities do not describe one materialized generation");
	}
	try {
		auto source = std::unique_ptr<runtime_telemetry_snapshot_source>(new runtime_telemetry_snapshot_source(
			runtime_generation, topology, providers, aggregator, runtime_status, coordinator, certificate,
			completion, protocol_faults));
		auto initialized = source->initialize_();
		if (!initialized.is_ok()) {
			return initialized;
		}
		return source;
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("failed to allocate complete runtime telemetry source");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "runtime telemetry source extent exceeds the host size domain");
	}
}

runtime_telemetry_snapshot_source::runtime_telemetry_snapshot_source(
	uint64_t runtime_generation, const provider::compiled_provider_topology &topology,
	const provider::materialized_provider_runtime &providers, runtime_telemetry_aggregator &aggregator,
	const runtime_status_publication &runtime_status, const epoch_transition_coordinator &coordinator,
	const epoch_transition_certificate &certificate, const epoch_transition_completion *completion,
	const epoch_protocol_fault_latch &protocol_faults) noexcept
	: runtime_generation_(runtime_generation)
	, topology_(topology)
	, providers_(providers)
	, aggregator_(aggregator)
	, runtime_status_(runtime_status)
	, coordinator_(coordinator)
	, certificate_(certificate)
	, completion_(completion)
	, protocol_faults_(protocol_faults)
{
}

common::status runtime_telemetry_snapshot_source::initialize_()
{
	storage_rows_.reserve(topology_.storage_domains.size());
	for (const auto &storage : topology_.storage_domains) {
		const auto *operations = providers_.storage_domain(storage.storage_domain_index);
		if (storage.storage_domain_index != storage_rows_.size() ||
		    storage.budget.storage_domain_id != storage.storage_domain_id || storage.buffer_count == 0u ||
		    storage.budget.required_min_buffers == 0u || storage.budget.safety_margin == 0u ||
		    !kinetum_provider_packet_storage_operations_are_valid(operations) ||
		    operations->generation != runtime_generation_ ||
		    operations->domain_index != storage.storage_domain_index) {
			return common::status::failed_precondition(
				"telemetry storage budget projection is noncanonical");
		}
		storage_rows_.push_back(runtime_storage_domain_statistics{
			.storage_domain_id = storage.storage_domain_id,
			.host_numa_node = storage.host_numa_node,
			.buffer_count = storage.buffer_count,
			.required_min_buffers = storage.budget.required_min_buffers,
			.safety_margin = storage.budget.safety_margin,
		});
	}

	port_rows_.reserve(topology_.ports.size());
	for (const auto &port : topology_.ports) {
		if (port.port_index != port_rows_.size() || port.io_driver_index >= topology_.io_drivers.size()) {
			return common::status::failed_precondition(
				"telemetry port identity projection is noncanonical");
		}
		const auto &driver = topology_.io_drivers[port.io_driver_index];
		if (port.driver_port_index >= driver.attachments.size()) {
			return common::status::failed_precondition("telemetry port driver attachment is absent");
		}
		port_rows_.push_back(runtime_io_port_statistics{
			.logical_port_id = port.logical_port_id,
			.logical_name = port.logical_name,
			.io_driver_instance_id = driver.io_driver_instance_id,
			.driver_port_id = driver.attachments[port.driver_port_index].driver_port_id,
		});
	}

	steering_rows_.reserve(topology_.steering_profiles.size());
	for (const auto &profile : topology_.steering_profiles) {
		if (profile.steering_profile_index != steering_rows_.size()) {
			return common::status::failed_precondition("telemetry steering identity is noncanonical");
		}
		runtime_traffic_steering_statistics row{
			.steering_profile_id = profile.steering_profile_id,
			.kind = steering_kind(profile.kind),
			.symmetric = profile.symmetric,
		};
		row.io_stream_ids.reserve(profile.io_stream_indices.size());
		for (uint32_t stream_index : profile.io_stream_indices) {
			if (stream_index >= topology_.io_streams.size()) {
				return common::status::failed_precondition(
					"telemetry steering profile references an unknown stream");
			}
			row.io_stream_ids.push_back(topology_.io_streams[stream_index].io_stream_id);
		}
		std::sort(row.io_stream_ids.begin(), row.io_stream_ids.end());
		if (row.io_stream_ids.empty() ||
		    std::adjacent_find(row.io_stream_ids.begin(), row.io_stream_ids.end()) != row.io_stream_ids.end()) {
			return common::status::failed_precondition(
				"telemetry steering profile contains duplicate stream identity");
		}
		steering_rows_.push_back(std::move(row));
	}
	module_context_rows_.reserve(topology_.module_context_domains.size());
	for (const auto &domain : topology_.module_context_domains) {
		if (domain.module_id.empty() || domain.module_context_indices.empty() ||
		    (!module_context_rows_.empty() && module_context_rows_.back().module_id >= domain.module_id)) {
			return common::status::failed_precondition(
				"telemetry module-context population is noncanonical");
		}
		runtime_module_context_domain row{.module_id = domain.module_id};
		row.context_instance_ids.reserve(domain.module_context_indices.size());
		for (uint32_t context_index : domain.module_context_indices) {
			if (context_index >= topology_.module_contexts.size()) {
				return common::status::failed_precondition(
					"telemetry module domain references an unknown context");
			}
			const auto &context = topology_.module_contexts[context_index];
			if (context.module_id != domain.module_id ||
			    context.module_context_count != domain.module_context_indices.size() ||
			    context.module_context_ordinal != row.context_instance_ids.size() ||
			    (!row.context_instance_ids.empty() &&
			     row.context_instance_ids.back() >= context.context_instance_id)) {
				return common::status::failed_precondition(
					"telemetry context identity disagrees with its module domain");
			}
			row.context_instance_ids.push_back(context.context_instance_id);
		}
		module_context_rows_.push_back(std::move(row));
	}

	drivers_.reserve(topology_.io_drivers.size());
	for (const auto &driver : topology_.io_drivers) {
		if (driver.io_driver_index != drivers_.size()) {
			return common::status::failed_precondition("telemetry I/O-driver identity is noncanonical");
		}
		driver_binding binding;
		binding.operations = providers_.io_driver(driver.io_driver_index);
		if (!kinetum_provider_io_driver_operations_are_valid(binding.operations) ||
		    binding.operations->io_driver_index != driver.io_driver_index) {
			return common::status::failed_precondition("telemetry I/O-driver operations are incomplete");
		}
		std::size_t expected_rx = 0u;
		std::size_t expected_tx = 0u;
		for (const auto &port : topology_.ports) {
			if (port.io_driver_index == driver.io_driver_index) {
				binding.port_rows.push_back(port.port_index);
			}
		}
		for (const auto &stream : topology_.io_streams) {
			if (topology_.ports[stream.port_index].io_driver_index == driver.io_driver_index) {
				if (stream.direction == provider::compiled_io_stream_direction::RX) {
					++expected_rx;
				} else {
					++expected_tx;
				}
			}
		}
		if (expected_rx > UINT32_MAX || expected_tx > UINT32_MAX ||
		    binding.operations->rx_queue_count != static_cast<uint32_t>(expected_rx) ||
		    binding.operations->tx_queue_count != static_cast<uint32_t>(expected_tx)) {
			return common::status::failed_precondition(
				"telemetry I/O-driver queue projection is incomplete");
		}
		binding.ports.resize(binding.port_rows.size());
		drivers_.push_back(std::move(binding));
	}
	return common::status::ok();
}

common::status runtime_telemetry_snapshot_source::observe_providers_(runtime_telemetry_snapshot &snapshot,
								     const runtime_telemetry_request &request) const
{
	common::status failure;
	std::array<char, PROVIDER_DIAGNOSTIC_BYTES> diagnostic_bytes{};
	kinetum_provider_diagnostic diagnostic{
		.data = diagnostic_bytes.data(),
		.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
		.size = 0u,
	};
	if (request.include_storage_domain_stats) {
		for (std::size_t index = 0u; index < snapshot.storage_domains.size(); ++index) {
			const auto *operations = providers_.storage_domain(static_cast<uint32_t>(index));
			if (!kinetum_provider_packet_storage_operations_are_valid(operations)) {
				return common::status::data_loss("telemetry storage operation identity changed");
			}
			kinetum_provider_storage_observation observation{};
			diagnostic = {diagnostic_bytes.data(), static_cast<uint32_t>(diagnostic_bytes.size()), 0u};
			auto invoked = provider_status(operations->observe_statistics(operations->state, &observation,
										      &diagnostic),
						       "provider storage statistics");
			if (diagnostic.data != diagnostic_bytes.data() ||
			    diagnostic.capacity != diagnostic_bytes.size() ||
			    diagnostic.size > diagnostic_bytes.size()) {
				return common::status::data_loss(
					"provider storage statistics mutated diagnostic authority");
			}
			if (!invoked.is_ok()) {
				merge_runtime_telemetry_failure(failure, std::move(invoked));
				continue;
			}
			const uint64_t observed_at_ns = common::now_ns();
			if (observed_at_ns == 0u) {
				return common::status::internal_error(
					"provider storage statistics post-callback timestamp is invalid");
			}
			if (diagnostic.data != diagnostic_bytes.data() ||
			    diagnostic.capacity != diagnostic_bytes.size() || diagnostic.size != 0u ||
			    observation.runtime_generation != runtime_generation_ ||
			    observation.storage_domain_index != index ||
			    !kinetum_provider_observation_state_is_valid(observation.state) ||
			    !bytes_zero(observation.identity_padding) || !bytes_zero(observation.padding) ||
			    (!kinetum_provider_observation_has_values(observation.state) &&
			     (observation.in_use != 0u || observation.available != 0u)) ||
			    (kinetum_provider_observation_has_values(observation.state) &&
			     (observation.in_use > UINT64_MAX - observation.available ||
			      observation.in_use + observation.available !=
				      snapshot.storage_domains[index].buffer_count))) {
				return common::status::data_loss(
					"provider storage statistics returned malformed identity");
			}
			auto &row = snapshot.storage_domains[index];
			row.observation_state = observation.state;
			if (kinetum_provider_observation_has_values(observation.state)) {
				row.observed_monotonic_ns = observed_at_ns;
				row.in_use = observation.in_use;
				row.available = observation.available;
			}
		}
	}

	if (!request.include_port_stats) {
		return failure;
	}
	for (std::size_t driver_index = 0u; driver_index < drivers_.size(); ++driver_index) {
		auto &driver = drivers_[driver_index];
		if (driver.operations == nullptr ||
		    driver.operations != providers_.io_driver(static_cast<uint32_t>(driver_index)) ||
		    !kinetum_provider_io_driver_operations_are_valid(driver.operations) ||
		    driver.operations->io_driver_index != static_cast<uint32_t>(driver_index)) {
			return common::status::data_loss("provider I/O statistics lost one driver operation table");
		}
		std::fill(driver.ports.begin(), driver.ports.end(), kinetum_provider_port_observation{});
		kinetum_provider_io_observation_batch batch{
			.ports = driver.ports.empty() ? nullptr : driver.ports.data(),
			.port_count = static_cast<uint32_t>(driver.ports.size()),
			.port_padding = 0u,
			.padding = {},
		};
		diagnostic = {diagnostic_bytes.data(), static_cast<uint32_t>(diagnostic_bytes.size()), 0u};
		auto invoked = provider_status(driver.operations->observe_statistics(driver.operations->state, &batch,
										     &diagnostic),
					       "provider I/O statistics");
		if (diagnostic.data != diagnostic_bytes.data() || diagnostic.capacity != diagnostic_bytes.size() ||
		    diagnostic.size > diagnostic_bytes.size() ||
		    batch.ports != (driver.ports.empty() ? nullptr : driver.ports.data()) ||
		    batch.port_count != driver.ports.size() || batch.port_padding != 0u || !bytes_zero(batch.padding)) {
			return common::status::data_loss("provider I/O statistics mutated caller-owned authority");
		}
		if (!invoked.is_ok()) {
			merge_runtime_telemetry_failure(failure, std::move(invoked));
			continue;
		}
		const uint64_t observed_at_ns = common::now_ns();
		if (observed_at_ns == 0u) {
			return common::status::internal_error(
				"provider I/O statistics post-callback timestamp is invalid");
		}
		if (diagnostic.data != diagnostic_bytes.data() || diagnostic.capacity != diagnostic_bytes.size() ||
		    diagnostic.size != 0u || batch.ports != (driver.ports.empty() ? nullptr : driver.ports.data()) ||
		    batch.port_count != driver.ports.size() || batch.port_padding != 0u || !bytes_zero(batch.padding)) {
			return common::status::data_loss(
				"provider I/O statistics mutated its caller-owned batch authority");
		}
		for (std::size_t ordinal = 0u; ordinal < driver.port_rows.size(); ++ordinal) {
			const std::size_t row_index = driver.port_rows[ordinal];
			const auto &source = driver.ports[ordinal];
			if (row_index >= port_rows_.size() || source.port_index != row_index ||
			    !kinetum_provider_observation_state_is_valid(source.state) ||
			    !bytes_zero(source.identity_padding) || !bytes_zero(source.padding) ||
			    (!kinetum_provider_observation_has_values(source.state) &&
			     (source.rx_packets != 0u || source.tx_packets != 0u || source.rx_bytes != 0u ||
			      source.tx_bytes != 0u || source.rx_missed != 0u || source.rx_errors != 0u ||
			      source.tx_errors != 0u || source.rx_no_buffer != 0u))) {
				return common::status::data_loss(
					"provider port statistics returned malformed identity");
			}
			if (!request.include_port_stats) {
				continue;
			}
			auto &target = snapshot.ports[row_index];
			target.observation_state = source.state;
			if (kinetum_provider_observation_has_values(source.state)) {
				target.observed_monotonic_ns = observed_at_ns;
				target.rx_packets = source.rx_packets;
				target.tx_packets = source.tx_packets;
				target.rx_bytes = source.rx_bytes;
				target.tx_bytes = source.tx_bytes;
				target.rx_missed = source.rx_missed;
				target.rx_errors = source.rx_errors;
				target.tx_errors = source.tx_errors;
				target.rx_no_buffer = source.rx_no_buffer;
			}
		}
	}
	return failure;
}

common::status_or<runtime_telemetry_snapshot>
runtime_telemetry_snapshot_source::collect(const runtime_telemetry_request &request) const
{
	try {
		common::status failure;
		const auto record_read = [&failure](publication_read_result result, std::string_view source,
						    uint32_t index = UINT32_MAX) {
			if (result == publication_read_result::AVAILABLE) {
				return;
			}
			std::string message = "runtime ";
			message.append(source);
			if (index != UINT32_MAX) {
				message.append(" ").append(std::to_string(index));
			}
			switch (result) {
			case publication_read_result::AVAILABLE:
				std::terminate();
			case publication_read_result::UNAVAILABLE:
				message.append(" publication is unavailable");
				merge_runtime_telemetry_failure(failure,
								common::status::unavailable(std::move(message)));
				return;
			case publication_read_result::INVALID_IDENTITY:
				message.append(" publication has invalid identity");
				break;
			case publication_read_result::INVALID_STATE:
				message.append(" publication has invalid state");
				break;
			}
			merge_runtime_telemetry_failure(failure, common::status::data_loss(std::move(message)));
		};
		const auto record_runtime_identity = [this, &failure](publication_read_result read,
								      const runtime_status_snapshot &value) {
			if (read == publication_read_result::AVAILABLE &&
			    (value.runtime_generation != runtime_generation_ ||
			     value.expected_workers != topology_.transition_topology.workers.size())) {
				merge_runtime_telemetry_failure(
					failure,
					common::status::data_loss(
						"runtime telemetry status has foreign generation or membership"));
			}
		};

		runtime_status_snapshot before{};
		const auto before_read = runtime_status_.try_read(before);
		record_read(before_read, "status");
		record_runtime_identity(before_read, before);
		if (before_read == publication_read_result::AVAILABLE &&
		    before.readiness != runtime_readiness::PACKET_READY) {
			merge_runtime_telemetry_failure(
				failure, common::status::unavailable("runtime telemetry is not packet-ready"));
		}

		epoch_transition_progress_snapshot transition{};
		epoch_transition_telemetry_snapshot transactions{};
		const auto progress_read = coordinator_.try_read_progress(transition);
		const auto transactions_read = coordinator_.try_read_telemetry(transactions);
		record_read(progress_read, "coordinator progress");
		record_read(transactions_read, "coordinator transactions");

		auto aggregate_or = aggregator_.collect(request);
		const bool aggregate_available = aggregate_or.is_ok();
		runtime_telemetry_snapshot snapshot;
		if (aggregate_available) {
			snapshot = std::move(aggregate_or).value();
		} else {
			merge_runtime_telemetry_failure(failure, aggregate_or.error());
		}
		snapshot.runtime_status = before;
		snapshot.transition_progress = transition;
		snapshot.transition_transactions = transactions;
		snapshot.plan_content_hash = topology_.source_plan_content_hash;

		epoch_transition_completion_progress_snapshot completion{};
		auto completion_read = publication_read_result::UNAVAILABLE;
		if (completion_ != nullptr) {
			completion_read = completion_->try_read_progress(completion);
			if (completion_read != publication_read_result::UNAVAILABLE) {
				record_read(completion_read, "completion progress");
			}
			if (completion_read == publication_read_result::AVAILABLE) {
				snapshot.completion_progress = completion;
			}
		}

		snapshot.transition_success_blocked = protocol_faults_.transition_success_blocked();
		epoch_protocol_first_fault first{};
		if (protocol_faults_.try_read(first)) {
			auto identity = validate_first_fault_identity(first, topology_, runtime_generation_);
			if (identity.is_ok()) {
				snapshot.first_protocol_fault = first;
			}
			merge_runtime_telemetry_failure(failure, std::move(identity));
		}

		// Read every independent selected publication before deciding availability.
		// A missing earlier row cannot suppress a coherent invalid later row.
		const bool observe_workers = request.include_worker_epoch_stats || request.include_region_epoch_stats;
		std::vector<runtime_worker_epoch_statistics> observed_workers;
		std::vector<epoch_transition_certificate_worker_read> worker_reads;
		std::vector<epoch_transition_certificate_boundary_read> boundary_reads;
		if (observe_workers) {
			observed_workers.reserve(topology_.transition_topology.workers.size());
			worker_reads.reserve(topology_.transition_topology.workers.size());
			for (const auto &worker : topology_.transition_topology.workers) {
				const auto &read =
					worker_reads.emplace_back(certificate_.observe_worker(worker.worker_index));
				record_read(read.ledger, "worker ledger", worker.worker_index);
				record_read(read.activation, "worker activation", worker.worker_index);
				if (read.result() != publication_read_result::AVAILABLE) {
					continue;
				}
				observed_workers.push_back(runtime_worker_epoch_statistics{
					.worker_id = worker.worker_id,
					.worker_index = worker.worker_index,
					.region_id = worker.region_id,
					.lane_id = worker.lane_id,
					.ledger = read.value.ledger,
					.activation = read.value.activation,
				});
			}
		}
		if (request.include_boundary_epoch_stats) {
			snapshot.boundaries.reserve(topology_.transition_topology.boundaries.size());
			boundary_reads.reserve(topology_.transition_topology.boundaries.size());
			for (const auto &boundary : topology_.transition_topology.boundaries) {
				const auto &read = boundary_reads.emplace_back(
					certificate_.observe_boundary(boundary.boundary_index));
				record_read(read.sender, "boundary sender policy", boundary.boundary_index);
				record_read(read.receiver, "boundary receiver policy", boundary.boundary_index);
				record_read(read.sender_transport, "boundary sender transport",
					    boundary.boundary_index);
				record_read(read.receiver_transport, "boundary receiver transport",
					    boundary.boundary_index);
				if (boundary.from_stage_instance_index >= topology_.stage_instances.size() ||
				    boundary.to_stage_instance_index >= topology_.stage_instances.size()) {
					merge_runtime_telemetry_failure(
						failure,
						common::status::data_loss(
							"runtime boundary endpoint identity is outside topology"));
					continue;
				}
				const auto &from_stage = topology_.stage_instances[boundary.from_stage_instance_index];
				const auto &to_stage = topology_.stage_instances[boundary.to_stage_instance_index];
				if (from_stage.region_index >= topology_.execution_regions.size() ||
				    to_stage.region_index >= topology_.execution_regions.size()) {
					merge_runtime_telemetry_failure(
						failure,
						common::status::data_loss(
							"runtime boundary endpoint region identity is outside topology"));
					continue;
				}
				if (read.result() != publication_read_result::AVAILABLE) {
					continue;
				}
				snapshot.boundaries.push_back(runtime_boundary_epoch_statistics{
					.boundary_id = boundary.boundary_id,
					.boundary_index = boundary.boundary_index,
					.from_stage_instance_index = boundary.from_stage_instance_index,
					.to_stage_instance_index = boundary.to_stage_instance_index,
					.sender_worker_index = boundary.sender_worker_index,
					.receiver_worker_index = boundary.receiver_worker_index,
					.from_region_id =
						topology_.execution_regions[from_stage.region_index].region_id,
					.to_region_id = topology_.execution_regions[to_stage.region_index].region_id,
					.data_ring_capacity = boundary.data_ring_capacity,
					.future_output_hold_capacity = boundary.future_output_hold_capacity,
					.observation = read.value,
				});
			}
		}

		if (request.include_storage_domain_stats) {
			snapshot.storage_domains = storage_rows_;
		}
		if (request.include_port_stats) {
			snapshot.ports = port_rows_;
		}
		if (request.include_topology_stats) {
			snapshot.steering_profiles = steering_rows_;
			snapshot.module_context_domains = module_context_rows_;
		}
		merge_runtime_telemetry_failure(failure, observe_providers_(snapshot, request));

		epoch_transition_progress_snapshot transition_after{};
		epoch_transition_telemetry_snapshot transactions_after{};
		const auto progress_after_read = coordinator_.try_read_progress(transition_after);
		const auto transactions_after_read = coordinator_.try_read_telemetry(transactions_after);
		record_read(progress_after_read, "closing coordinator progress");
		record_read(transactions_after_read, "closing coordinator transactions");
		epoch_transition_completion_progress_snapshot completion_after{};
		auto completion_after_read = publication_read_result::UNAVAILABLE;
		if (completion_ != nullptr) {
			completion_after_read = completion_->try_read_progress(completion_after);
			if (completion_after_read != publication_read_result::UNAVAILABLE ||
			    completion_read == publication_read_result::AVAILABLE) {
				record_read(completion_after_read, "closing completion progress");
			}
		}
		runtime_status_snapshot after{};
		const auto after_read = runtime_status_.try_read(after);
		record_read(after_read, "closing status");
		record_runtime_identity(after_read, after);
		const bool fault_blocked_after = protocol_faults_.transition_success_blocked();
		epoch_protocol_first_fault first_after{};
		const bool first_present_after = protocol_faults_.try_read(first_after);
		if (first_present_after) {
			merge_runtime_telemetry_failure(failure, validate_first_fault_identity(first_after, topology_,
											       runtime_generation_));
		}
		if (fault_blocked_after != snapshot.transition_success_blocked ||
		    first_present_after != snapshot.first_protocol_fault.has_value() ||
		    (first_present_after && snapshot.first_protocol_fault.has_value() &&
		     std::memcmp(&first_after, &*snapshot.first_protocol_fault, sizeof(first_after)) != 0)) {
			merge_runtime_telemetry_failure(
				failure,
				common::status::unavailable(
					"runtime protocol fault authority changed during telemetry collection"));
		}

		const bool authority_stable =
			before_read == publication_read_result::AVAILABLE &&
			after_read == publication_read_result::AVAILABLE &&
			progress_read == publication_read_result::AVAILABLE &&
			transactions_read == publication_read_result::AVAILABLE &&
			progress_after_read == publication_read_result::AVAILABLE &&
			transactions_after_read == publication_read_result::AVAILABLE &&
			transition.publication_generation == transactions.publication_generation &&
			transition_after.publication_generation == transition.publication_generation &&
			transactions_after.publication_generation == transactions.publication_generation &&
			after.publication_generation == before.publication_generation &&
			after.runtime_generation == before.runtime_generation &&
			after.active_epoch == before.active_epoch &&
			after.minimum_retained_epoch == before.minimum_retained_epoch &&
			after.last_activated_epoch == before.last_activated_epoch;
		if (!authority_stable) {
			merge_runtime_telemetry_failure(
				failure,
				common::status::unavailable(
					"runtime authority changed or was unavailable during telemetry collection"));
		}
		if (completion_read == publication_read_result::AVAILABLE &&
		    (completion_after_read != publication_read_result::AVAILABLE ||
		     completion_after.publication_generation != completion.publication_generation)) {
			merge_runtime_telemetry_failure(
				failure, common::status::unavailable(
						 "runtime completion progress changed during telemetry collection"));
		}

		// Only stable authority can classify transition-relative disagreement.
		// Intrinsic invalidity collected above is never downgraded by movement.
		if (authority_stable) {
			const auto runtime_relation = classify_runtime_status_transition(before, transition);
			if (runtime_relation == publication_read_result::UNAVAILABLE) {
				merge_runtime_telemetry_failure(
					failure,
					common::status::unavailable(
						"runtime status and transition phase are between coherent publication edges"));
			} else if (runtime_relation != publication_read_result::AVAILABLE) {
				merge_runtime_telemetry_failure(
					failure, common::status::data_loss(
							 "runtime status contradicts stable transition authority"));
			}
			const auto completion_or = project_runtime_completion_progress(completion_read, completion,
										       transition, transactions);
			if (completion_or.is_ok()) {
				snapshot.completion_progress = completion_or.value();
			} else {
				merge_runtime_telemetry_failure(failure, completion_or.error());
			}

			for (std::size_t ordinal = 0u; ordinal < worker_reads.size(); ++ordinal) {
				const auto &read = worker_reads[ordinal];
				const auto &worker = topology_.transition_topology.workers[ordinal];
				const auto &ledger = read.value.ledger;
				const auto &activation = read.value.activation;
				if ((read.ledger == publication_read_result::AVAILABLE &&
				     (ledger.active_epoch > transition.allocated_epoch_high_watermark ||
				      ledger.source_epoch > transition.allocated_epoch_high_watermark ||
				      ledger.future_epoch > transition.allocated_epoch_high_watermark)) ||
				    (read.activation == publication_read_result::AVAILABLE &&
				     (activation.transition_generation > transition.mutation_sequence_high_watermark ||
				      activation.active_epoch > transition.allocated_epoch_high_watermark ||
				      (transactions.active.present &&
				       activation.transition_generation ==
					       transactions.active.identity.mutation_sequence &&
				       (activation.from_epoch != transactions.active.from_epoch ||
					activation.to_epoch != transactions.active.to_epoch))))) {
					merge_runtime_telemetry_failure(
						failure,
						common::status::data_loss(
							"runtime worker " + std::to_string(worker.worker_index) +
							" publication contradicts the stable allocation authority"));
				}
			}
			for (const auto &worker : observed_workers) {
				switch (classify_worker_publications(worker.ledger, worker.activation)) {
				case worker_publication_relation::ALIGNED:
					break;
				case worker_publication_relation::TEMPORAL_SKEW:
					merge_runtime_telemetry_failure(
						failure,
						common::status::unavailable(
							"runtime worker " + std::to_string(worker.worker_index) +
							" activation leads its per-turn ledger publication"));
					break;
				case worker_publication_relation::CONTRADICTION:
					merge_runtime_telemetry_failure(
						failure,
						common::status::data_loss(
							"runtime worker " + std::to_string(worker.worker_index) +
							" ledger and activation publications contradict identity"));
					break;
				}
			}
		}

		for (std::size_t ordinal = 0u; ordinal < boundary_reads.size(); ++ordinal) {
			const auto relationship = validate_boundary_observation(
				boundary_reads[ordinal], authority_stable ? &transition : nullptr, transactions);
			if (!relationship.is_ok()) {
				const auto boundary_index =
					topology_.transition_topology.boundaries[ordinal].boundary_index;
				merge_runtime_telemetry_failure(
					failure, common::status(relationship.code(),
								"runtime boundary " + std::to_string(boundary_index) +
									" " + std::string(relationship.message())));
			}
		}

		if (aggregate_available && transactions_read == publication_read_result::AVAILABLE) {
			for (std::size_t index = 0u; index < snapshot.protocol_fault_counts.size(); ++index) {
				add_saturating(snapshot.protocol_fault_counts[index],
					       transactions.protocol_fault_counts[index]);
			}
			if (snapshot.first_protocol_fault.has_value()) {
				const auto ordinal = epoch_protocol_fault_ordinal(snapshot.first_protocol_fault->code);
				if (snapshot.protocol_fault_counts[ordinal] == 0u) {
					merge_runtime_telemetry_failure(
						failure,
						common::status::unavailable(
							"runtime protocol first-fault counter publication is incomplete"));
				}
			} else if (snapshot.transition_success_blocked ||
				   std::any_of(snapshot.protocol_fault_counts.begin(),
					       snapshot.protocol_fault_counts.end(),
					       [](uint64_t count) { return count != 0u; })) {
				merge_runtime_telemetry_failure(
					failure, common::status::unavailable(
							 "runtime protocol first-fault publication is incomplete"));
			}
			const auto allocator_fault =
				epoch_protocol_fault_ordinal(epoch_protocol_fault_code::EPOCH_ALLOCATOR_EXHAUSTED);
			bool blocking_count_observed = false;
			for (std::size_t index = 0u; index < snapshot.protocol_fault_counts.size(); ++index) {
				blocking_count_observed =
					blocking_count_observed ||
					(index != allocator_fault && snapshot.protocol_fault_counts[index] != 0u);
			}
			if (snapshot.transition_success_blocked != blocking_count_observed) {
				merge_runtime_telemetry_failure(
					failure,
					common::status::unavailable(
						"runtime protocol fault counters lag the transition-success latch"));
			}
		}

		if (request.include_worker_epoch_stats) {
			snapshot.workers = observed_workers;
		}
		if (request.include_region_epoch_stats && aggregate_available &&
		    observed_workers.size() == topology_.transition_topology.workers.size()) {
			if (snapshot.regions.size() != topology_.execution_regions.size()) {
				merge_runtime_telemetry_failure(
					failure,
					common::status::data_loss("runtime region aggregate membership changed"));
			} else {
				for (auto &region : snapshot.regions) {
					region.minimum_active_epoch = UINT64_MAX;
					region.minimum_source_epoch = UINT64_MAX;
					region.maximum_active_epoch = 0u;
					region.maximum_source_epoch = 0u;
					region.active_unretired = 0u;
					region.future_unretired = 0u;
					region.activated_participants = 0u;
					region.minimum_activation_monotonic_ns.reset();
					region.maximum_activation_monotonic_ns.reset();
				}
				for (const auto &worker : observed_workers) {
					if (worker.region_id < 0 ||
					    static_cast<std::size_t>(worker.region_id) >= snapshot.regions.size()) {
						merge_runtime_telemetry_failure(
							failure,
							common::status::data_loss(
								"runtime worker references an unknown region"));
						continue;
					}
					auto &region = snapshot.regions[static_cast<std::size_t>(worker.region_id)];
					region.minimum_active_epoch =
						std::min(region.minimum_active_epoch, worker.ledger.active_epoch);
					region.minimum_source_epoch =
						std::min(region.minimum_source_epoch, worker.ledger.source_epoch);
					region.maximum_active_epoch =
						std::max(region.maximum_active_epoch, worker.ledger.active_epoch);
					region.maximum_source_epoch =
						std::max(region.maximum_source_epoch, worker.ledger.source_epoch);
					add_saturating(region.active_unretired, worker.ledger.active_unretired);
					add_saturating(region.future_unretired, worker.ledger.future_unretired);
					if (worker.activation.activation_complete == 1u &&
					    worker.activation.active_epoch == before.active_epoch &&
					    worker.activation.activation_monotonic_ns != 0u) {
						++region.activated_participants;
						region.minimum_activation_monotonic_ns =
							region.minimum_activation_monotonic_ns.has_value() ?
								std::min(*region.minimum_activation_monotonic_ns,
									 worker.activation.activation_monotonic_ns) :
								worker.activation.activation_monotonic_ns;
						region.maximum_activation_monotonic_ns =
							region.maximum_activation_monotonic_ns.has_value() ?
								std::max(*region.maximum_activation_monotonic_ns,
									 worker.activation.activation_monotonic_ns) :
								worker.activation.activation_monotonic_ns;
					}
				}
				for (const auto &region : snapshot.regions) {
					if (region.minimum_active_epoch == UINT64_MAX ||
					    region.minimum_source_epoch == UINT64_MAX) {
						merge_runtime_telemetry_failure(
							failure, common::status::data_loss(
									 "runtime region has no worker observation"));
					}
				}
			}
		}
		if (!failure.is_ok()) {
			return failure;
		}
		snapshot.collection_monotonic_ns = common::now_ns();
		if (snapshot.collection_monotonic_ns == 0u) {
			return common::status::internal_error("runtime telemetry completion timestamp is invalid");
		}
		return snapshot;
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("failed to allocate complete runtime telemetry snapshot");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "runtime telemetry snapshot extent exceeds the host size domain");
	}
}

}  // namespace kinetum::dp
