// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_telemetry_aggregator.cpp
 * @brief Sole cold merger of immutable owner-worker telemetry banks.
 * @author Fleming Patel
 */

#include "src/dp/runtime_telemetry_aggregator.hpp"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/module/module_manager.hpp"
#include "src/dp/module/module_runtime_generation.hpp"
#include "src/dp/runtime_status.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/provider/compiled_provider_topology.hpp"

namespace kinetum::dp
{
namespace
{

/**
 * @brief Add one value without wrapping a cold aggregate.
 * @param[in,out] target Aggregate updated in place.
 * @param value Value to add with saturation at UINT64_MAX.
 */
void add_saturating(uint64_t &target, uint64_t value) noexcept
{
	target = value > UINT64_MAX - target ? UINT64_MAX : target + value;
}

/**
 * @brief Compare every semantic and normalized padding byte in two health signals.
 * @param left First immutable signal.
 * @param right Second immutable signal.
 * @return true only when both signals are exact value equals.
 */
[[nodiscard]] bool health_signals_equal(const kinetum_health_signal &left, const kinetum_health_signal &right) noexcept
{
	return left.assessment.health_score == right.assessment.health_score &&
	       std::equal(std::begin(left.assessment._padding), std::end(left.assessment._padding),
			  std::begin(right.assessment._padding)) &&
	       left.assessment.flags == right.assessment.flags &&
	       std::equal(std::begin(left.assessment.reason), std::end(left.assessment.reason),
			  std::begin(right.assessment.reason)) &&
	       left.epoch == right.epoch && left.timestamp_ns == right.timestamp_ns;
}

/**
 * @brief Compare one returned-bank acknowledgment with its exact transfer.
 * @param left Remembered cleared-bank transfer.
 * @param right Worker-published retention acknowledgment.
 * @return true only when every immutable identity field agrees.
 */
[[nodiscard]] bool same_return_identity(const runtime_telemetry_bank_token &left,
					const runtime_telemetry_bank_token &right) noexcept
{
	return left.runtime_generation == right.runtime_generation && left.epoch == right.epoch &&
	       left.bank_generation == right.bank_generation && left.published_at_ns == right.published_at_ns &&
	       left.worker_index == right.worker_index && left.owner_index == right.owner_index &&
	       left.stage_instance_index == right.stage_instance_index && left.bank_index == right.bank_index &&
	       left.companion_bank_index == UINT8_MAX && right.companion_bank_index == UINT8_MAX &&
	       left.owner_kind == right.owner_kind && left.reason == right.reason &&
	       runtime_telemetry_bank_token_padding_zero(left) && runtime_telemetry_bank_token_padding_zero(right);
}

/**
 * @brief Map one compiled direction to its provider-neutral wire value.
 * @param direction Exact compiled stream direction.
 * @return Provider-neutral direction wire value.
 */
[[nodiscard]] kinetum::gluon::v1::IoStreamDirection
stream_direction(provider::compiled_io_stream_direction direction) noexcept
{
	switch (direction) {
	case provider::compiled_io_stream_direction::RX:
		return kinetum::gluon::v1::IO_STREAM_DIRECTION_RX;
	case provider::compiled_io_stream_direction::TX:
		return kinetum::gluon::v1::IO_STREAM_DIRECTION_TX;
	}
	std::terminate();
}

}  // namespace

common::status_or<std::unique_ptr<runtime_telemetry_aggregator>> runtime_telemetry_aggregator::create(
	uint64_t runtime_generation, const provider::compiled_provider_topology &topology,
	std::span<worker_telemetry_channel *const> channels, std::span<worker_runtime_telemetry *const> workers,
	module::module_runtime_generation &modules, const runtime_status_publication &runtime_status)
{
	if (runtime_generation == 0u || channels.empty() || channels.size() > UINT32_MAX ||
	    channels.size() != workers.size() || channels.size() != topology.transition_topology.workers.size()) {
		return common::status::invalid_argument(
			"runtime telemetry aggregator requires exact worker membership");
	}
	for (std::size_t index = 0u; index < channels.size(); ++index) {
		if (channels[index] == nullptr || workers[index] == nullptr) {
			return common::status::invalid_argument(
				"runtime telemetry aggregator requires nonnull worker authorities");
		}
		if (!channels[index]->empty() || !workers[index]->empty()) {
			return common::status::failed_precondition(
				"runtime telemetry aggregator requires pristine worker authorities");
		}
	}
	try {
		std::vector<worker_telemetry_channel *> channel_copy(channels.begin(), channels.end());
		std::vector<worker_runtime_telemetry *> worker_copy(workers.begin(), workers.end());
		auto owner = std::unique_ptr<runtime_telemetry_aggregator>(
			new runtime_telemetry_aggregator(runtime_generation, topology, std::move(channel_copy),
							 std::move(worker_copy), modules, runtime_status));
		auto initialized = owner->initialize_();
		if (!initialized.is_ok()) {
			return initialized;
		}
		return owner;
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("failed to allocate runtime telemetry aggregator");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "runtime telemetry aggregate extent exceeds the host size domain");
	}
}

runtime_telemetry_aggregator::runtime_telemetry_aggregator(uint64_t runtime_generation,
							   const provider::compiled_provider_topology &topology,
							   std::vector<worker_telemetry_channel *> channels,
							   std::vector<worker_runtime_telemetry *> workers,
							   module::module_runtime_generation &modules,
							   const runtime_status_publication &runtime_status) noexcept
	: runtime_generation_(runtime_generation)
	, topology_(topology)
	, channels_(std::move(channels))
	, workers_(std::move(workers))
	, modules_(modules)
	, runtime_status_(runtime_status)
{
}

common::status runtime_telemetry_aggregator::initialize_()
{
	aggregate_.streams.reserve(topology_.io_streams.size());
	for (const auto &stream : topology_.io_streams) {
		if (stream.io_stream_index != aggregate_.streams.size() ||
		    stream.port_index >= topology_.ports.size() ||
		    stream.stage_instance_index >= topology_.stage_instances.size()) {
			return common::status::failed_precondition(
				"telemetry stream identity projection is noncanonical");
		}
		const auto &port = topology_.ports[stream.port_index];
		const auto &stage = topology_.stage_instances[stream.stage_instance_index];
		if (stream.worker_index >= workers_.size() || stage.worker_index != stream.worker_index ||
		    stage.stage_instance_index != stream.stage_instance_index || !stage.io_stream_index.has_value() ||
		    *stage.io_stream_index != stream.io_stream_index ||
		    stage.region_index >= topology_.execution_regions.size()) {
			return common::status::failed_precondition(
				"telemetry stream worker/region projection disagrees");
		}
		aggregate_.streams.push_back(runtime_io_stream_statistics{
			.io_stream_id = stream.io_stream_id,
			.logical_port_id = port.logical_port_id,
			.direction = stream_direction(stream.direction),
			.owning_region_id = topology_.execution_regions[stage.region_index].region_id,
			.worker_index = stream.worker_index,
			.driver_queue_id = stream.driver_queue_id,
		});
	}

	aggregate_.stages.reserve(topology_.logical_stages.size());
	for (const auto &logical : topology_.logical_stages) {
		if (logical.logical_stage_index != aggregate_.stages.size()) {
			return common::status::failed_precondition(
				"runtime telemetry logical-stage identity is not compact");
		}
		aggregate_.stages.push_back(runtime_stage_statistics{.stage_id = logical.logical_stage_id});
	}
	aggregate_.regions.reserve(topology_.execution_regions.size());
	for (const auto &region : topology_.execution_regions) {
		if (region.region_id < 0 || static_cast<std::size_t>(region.region_id) != aggregate_.regions.size() ||
		    region.worker_indices.empty() ||
		    region.worker_indices.size() > std::numeric_limits<uint32_t>::max()) {
			return common::status::failed_precondition(
				"runtime telemetry region identity or worker membership is not compact");
		}
		aggregate_.regions.push_back(runtime_region_epoch_statistics{
			.region_id = region.region_id,
			.worker_count = static_cast<uint32_t>(region.worker_indices.size()),
		});
	}
	if (topology_.worker_schedules.size() != workers_.size() ||
	    modules_.telemetry_context_count() != topology_.module_contexts.size() ||
	    !topology_.transition_topology.lifecycle_services.has_value()) {
		return common::status::failed_precondition(
			"runtime telemetry worker schedules or lifecycle services are incomplete");
	}
	const uint32_t coordinator_index = topology_.transition_topology.lifecycle_services->coordinator_service_index;
	if (coordinator_index >= topology_.transition_topology.runtime_services.size()) {
		return common::status::failed_precondition("runtime telemetry coordinator service identity is invalid");
	}
	const int32_t coordinator_numa = topology_.transition_topology.runtime_services[coordinator_index].numa_node;
	if (coordinator_numa < 0) {
		return common::status::failed_precondition("runtime telemetry coordinator NUMA identity is invalid");
	}
	std::vector<std::size_t> module_counts(workers_.size(), 0u);
	for (const auto &context : topology_.module_contexts) {
		if (context.worker_index >= module_counts.size() ||
		    module_counts[context.worker_index] == std::numeric_limits<std::size_t>::max()) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "runtime telemetry module/worker population is not representable");
		}
		++module_counts[context.worker_index];
	}
	for (std::size_t index = 0u; index < workers_.size(); ++index) {
		auto capacity_or = worker_telemetry_channel::capacity_for(module_counts[index]);
		if (!capacity_or.is_ok()) {
			return capacity_or.error();
		}
		const auto &compiled_worker = topology_.transition_topology.workers[index];
		const auto &schedule = topology_.worker_schedules[index];
		const auto cadence =
			std::chrono::duration_cast<std::chrono::nanoseconds>(compiled_worker.health_poll_interval);
		const auto worker_stages = workers_[index] != nullptr ? workers_[index]->stage_instance_indices() :
									std::span<const uint32_t>{};
		const auto worker_streams = workers_[index] != nullptr ? workers_[index]->io_stream_indices() :
									 std::span<const uint32_t>{};
		if (workers_[index] == nullptr || channels_[index] == nullptr ||
		    workers_[index]->runtime_generation() != runtime_generation_ ||
		    workers_[index]->worker_index() != index || channels_[index]->worker_index() != index ||
		    !workers_[index]->owns_channel(*channels_[index]) || compiled_worker.worker_index != index ||
		    schedule.worker_index != index || workers_[index]->numa_node() != compiled_worker.numa_node ||
		    channels_[index]->returned_numa_node() != compiled_worker.numa_node ||
		    channels_[index]->completed_numa_node() != coordinator_numa ||
		    channels_[index]->capacity() != capacity_or.value() || cadence.count() <= 0 ||
		    workers_[index]->cadence_ns() != static_cast<uint64_t>(cadence.count()) ||
		    worker_stages.size() != schedule.stage_instance_indices.size() ||
		    !std::equal(worker_stages.begin(), worker_stages.end(), schedule.stage_instance_indices.begin())) {
			return common::status::failed_precondition(
				"runtime telemetry worker/channel membership is not exact");
		}
		if (worker_streams.size() != schedule.rx_stream_indices.size() + schedule.tx_stream_indices.size()) {
			return common::status::failed_precondition("worker telemetry stream membership is incomplete");
		}
		for (const uint32_t stream_index : worker_streams) {
			if (stream_index >= topology_.io_streams.size() ||
			    topology_.io_streams[stream_index].worker_index != index) {
				return common::status::failed_precondition(
					"worker telemetry stream belongs to a foreign owner");
			}
			const auto &stream = topology_.io_streams[stream_index];
			const auto &expected = stream.direction == provider::compiled_io_stream_direction::RX ?
						       schedule.rx_stream_indices :
						       schedule.tx_stream_indices;
			if (!std::binary_search(expected.begin(), expected.end(), stream_index)) {
				return common::status::failed_precondition(
					"worker telemetry stream disagrees with the compiled schedule");
			}
		}
	}
	worker_aggregation_.resize(workers_.size());
	worker_observed_.assign(workers_.size(), uint8_t{0});

	std::size_t counter_count = 0u;
	std::size_t histogram_count = 0u;
	for (const auto &context : topology_.module_contexts) {
		auto *owner = modules_.telemetry_context(context.module_context_index);
		auto *module_context = modules_.modules().context(context.module_context_index);
		const auto *identity = owner != nullptr ? &owner->identity() : nullptr;
		const auto *descriptor = module_context != nullptr && module_context->image != nullptr ?
						 module_context->image->descriptor :
						 nullptr;
		if (identity == nullptr || module_context == nullptr || descriptor == nullptr ||
		    descriptor->module_id == nullptr || module_context->lifecycle_owner.get() != owner ||
		    module_context->context_index != context.module_context_index ||
		    module_context->context_instance_id != context.context_instance_id ||
		    module_context->image->module_id != context.module_id ||
		    context.module_id != descriptor->module_id ||
		    module_context->packet_context.worker_index != context.worker_index ||
		    module_context->packet_context.cpu_core_id != context.cpu_core_id ||
		    module_context->packet_context.numa_node != context.numa_node ||
		    owner->health_callback_available() != (descriptor->health_check != nullptr) ||
		    identity->module_id != context.module_id ||
		    identity->module_image_index != module_context->image->module_image_index ||
		    identity->context_instance_id != context.context_instance_id ||
		    identity->context_index != context.module_context_index ||
		    identity->worker_index != context.worker_index || identity->cpu_core_id != context.cpu_core_id ||
		    identity->numa_node != context.numa_node || context.stage_instance_index > UINT16_MAX ||
		    owner->telemetry_runtime_generation() != runtime_generation_ ||
		    owner->telemetry_stage_instance_index() != static_cast<uint16_t>(context.stage_instance_index) ||
		    !owner->owns_telemetry_channel(*channels_[context.worker_index]) ||
		    !owner->module_health_owner_claimed() || !owner->telemetry_empty()) {
			return common::status::failed_precondition(
				"runtime telemetry module-context membership is not exact");
		}
		for (std::size_t handle = 1u; handle <= owner->telemetry_handle_count(); ++handle) {
			const auto *telemetry_descriptor =
				owner->telemetry_descriptor(static_cast<lifecycle::lifecycle_telemetry_handle>(handle));
			if (telemetry_descriptor == nullptr) {
				return common::status::internal_error(
					"runtime telemetry descriptor prefix is incomplete");
			}
			switch (telemetry_descriptor->kind) {
			case lifecycle::lifecycle_telemetry_kind::COUNTER:
				if (counter_count == std::numeric_limits<std::size_t>::max()) {
					return common::status(common::status_code::OUT_OF_RANGE,
							      "runtime telemetry counter population overflow");
				}
				++counter_count;
				break;
			case lifecycle::lifecycle_telemetry_kind::HISTOGRAM:
				if (histogram_count == std::numeric_limits<std::size_t>::max()) {
					return common::status(common::status_code::OUT_OF_RANGE,
							      "runtime telemetry histogram population overflow");
				}
				++histogram_count;
				break;
			default:
				return common::status::internal_error(
					"runtime telemetry descriptor kind is outside the admitted domain");
			}
		}
	}
	aggregate_.module_counters.reserve(counter_count);
	aggregate_.module_histograms.reserve(histogram_count);
	aggregate_.module_epoch_mismatches.reserve(topology_.module_contexts.size());
	aggregate_.module_health.reserve(topology_.module_contexts.size());
	histograms_.reserve(histogram_count);
	module_bindings_.reserve(topology_.module_contexts.size());
	health_observations_.resize(topology_.module_contexts.size());

	for (const auto &context : topology_.module_contexts) {
		if (context.module_context_index != module_bindings_.size()) {
			return common::status::failed_precondition(
				"runtime telemetry module-context identity is not compact");
		}
		auto *owner = modules_.telemetry_context(context.module_context_index);
		module_binding binding{};
		binding.context_index = context.module_context_index;
		binding.region_id = context.region_id;
		binding.owner = owner;
		binding.mismatch_row = aggregate_.module_epoch_mismatches.size();
		binding.health_row = aggregate_.module_health.size();
		binding.health_callback_available = owner->health_callback_available();
		aggregate_.module_epoch_mismatches.push_back(runtime_module_epoch_mismatch_statistics{
			.module_id = context.module_id,
			.context_instance_id = context.context_instance_id,
			.context_index = context.module_context_index,
			.worker_index = context.worker_index,
		});
		runtime_module_health_statistics health_row{};
		health_row.module_id = context.module_id;
		health_row.context_instance_id = context.context_instance_id;
		health_row.context_index = context.module_context_index;
		health_row.worker_index = context.worker_index;
		health_row.stage_instance_index = static_cast<uint16_t>(context.stage_instance_index);
		health_row.callback_available = binding.health_callback_available;
		aggregate_.module_health.push_back(std::move(health_row));
		binding.counter_rows.reserve(KINETUM_MAX_COUNTERS);
		binding.histogram_rows.reserve(KINETUM_MAX_HISTOGRAMS);
		for (std::size_t handle = 1u; handle <= owner->telemetry_handle_count(); ++handle) {
			const auto *descriptor =
				owner->telemetry_descriptor(static_cast<lifecycle::lifecycle_telemetry_handle>(handle));
			if (descriptor->kind == lifecycle::lifecycle_telemetry_kind::COUNTER) {
				binding.counter_rows.push_back(aggregate_.module_counters.size());
				aggregate_.module_counters.push_back(runtime_module_counter_statistics{
					.module_id = context.module_id,
					.context_instance_id = context.context_instance_id,
					.context_index = context.module_context_index,
					.worker_index = context.worker_index,
					.name = descriptor->counter.name,
				});
				continue;
			}
			if (descriptor->kind != lifecycle::lifecycle_telemetry_kind::HISTOGRAM) {
				return common::status::internal_error(
					"runtime telemetry descriptor kind changed after admission");
			}
			if (descriptor->histogram.counts == nullptr || descriptor->histogram.counts_len == 0u) {
				return common::status::failed_precondition(
					"runtime telemetry histogram storage is incomplete");
			}
			binding.histogram_rows.push_back(histograms_.size());
			histogram_accumulator histogram;
			histogram.row = runtime_module_histogram_statistics{
				.module_id = context.module_id,
				.context_instance_id = context.context_instance_id,
				.context_index = context.module_context_index,
				.worker_index = context.worker_index,
				.name = descriptor->histogram.name,
			};
			histogram.counts.assign(descriptor->histogram.counts_len, 0u);
			histogram.geometry = descriptor->histogram;
			histogram.geometry.counts = histogram.counts.data();
			histogram.geometry.total_count = 0u;
			histogram.geometry.min_value = UINT64_MAX;
			histogram.geometry.max_value = 0u;
			histogram.geometry.sum = 0u;
			histograms_.push_back(std::move(histogram));
			aggregate_.module_histograms.push_back(histograms_.back().row);
		}
		module_bindings_.push_back(std::move(binding));
	}
	return common::status::ok();
}

runtime_telemetry_aggregator::~runtime_telemetry_aggregator()
{
	if (pending_module_token_.has_value() || pending_module_binding_ != nullptr ||
	    pending_histogram_ordinal_ != 0u || pending_bucket_ != 0u || pending_histogram_source_count_ != 0u ||
	    pending_histogram_started_ || pending_histogram_replace_ || module_commit_in_progress_) {
		std::terminate();
	}
	const auto state_empty = [](const owner_aggregation_state &state) {
		return !state.returned.has_value() &&
		       std::all_of(state.retained_epochs.begin(), state.retained_epochs.end(),
				   [](uint64_t epoch) { return epoch == 0u; });
	};
	if (!std::all_of(worker_aggregation_.begin(), worker_aggregation_.end(), state_empty) ||
	    !std::all_of(module_bindings_.begin(), module_bindings_.end(),
			 [&](const module_binding &binding) { return state_empty(binding.aggregation); })) {
		std::terminate();
	}
	for (const auto *channel : channels_) {
		if (channel == nullptr || !channel->empty()) {
			std::terminate();
		}
	}
}

runtime_telemetry_aggregator::module_binding *
runtime_telemetry_aggregator::find_module_(uint32_t context_index) noexcept
{
	auto found = std::lower_bound(module_bindings_.begin(), module_bindings_.end(), context_index,
				      [](const module_binding &binding, uint32_t value) {
					      return binding.context_index < value;
				      });
	return found != module_bindings_.end() && found->context_index == context_index ? &*found : nullptr;
}

void runtime_telemetry_aggregator::record_retained_(owner_aggregation_state &state, uint64_t epoch,
						    uint8_t bank_index) noexcept
{
	if (epoch == 0u || bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	if (state.retained_epochs[bank_index] != 0u) {
		std::terminate();
	}
	state.retained_epochs[bank_index] = epoch;
	if (std::count(state.retained_epochs.begin(), state.retained_epochs.end(), epoch) > 2) {
		std::terminate();
	}
}

void runtime_telemetry_aggregator::mark_complete_(owner_aggregation_state &state, worker_runtime_telemetry &owner,
						  uint64_t epoch) noexcept
{
	if (epoch == 0u || std::count(state.retained_epochs.begin(), state.retained_epochs.end(), epoch) != 2) {
		return;
	}
	if (state.returned.has_value() || owner.epoch_aggregated(epoch)) {
		std::terminate();
	}
	owner.mark_epoch_aggregated(epoch);
}

void runtime_telemetry_aggregator::mark_complete_(owner_aggregation_state &state,
						  lifecycle::lifecycle_context_owner &owner, uint64_t epoch) noexcept
{
	if (epoch == 0u || std::count(state.retained_epochs.begin(), state.retained_epochs.end(), epoch) != 2) {
		return;
	}
	if (state.returned.has_value() || owner.telemetry_epoch_aggregated(epoch)) {
		std::terminate();
	}
	owner.mark_telemetry_epoch_aggregated(epoch);
}

void runtime_telemetry_aggregator::remember_return_(owner_aggregation_state &state,
						    const runtime_telemetry_bank_token &token) noexcept
{
	if (state.returned.has_value() || token.kind != runtime_telemetry_bank_token_kind::BANK ||
	    (token.reason != runtime_telemetry_publication_reason::CADENCE &&
	     token.reason != runtime_telemetry_publication_reason::RECLAIMED) ||
	    token.companion_bank_index != UINT8_MAX || token.bank_index >= RUNTIME_TELEMETRY_BANK_COUNT ||
	    (token.reason == runtime_telemetry_publication_reason::CADENCE && token.published_at_ns == 0u) ||
	    (token.reason == runtime_telemetry_publication_reason::RECLAIMED && token.published_at_ns != 0u) ||
	    !runtime_telemetry_bank_token_padding_zero(token)) {
		std::terminate();
	}
	state.returned = token;
}

void runtime_telemetry_aggregator::reconcile_reused_return_(owner_aggregation_state &state,
							    const runtime_telemetry_bank_token &token) noexcept
{
	if (!state.returned.has_value() || state.returned->bank_index != token.bank_index) {
		if (!state.returned.has_value() || token.reason != runtime_telemetry_publication_reason::CADENCE) {
			return;
		}
		const auto &returned = *state.returned;
		if (token.kind != runtime_telemetry_bank_token_kind::BANK || token.epoch != returned.epoch ||
		    token.worker_index != returned.worker_index || token.owner_index != returned.owner_index ||
		    token.stage_instance_index != returned.stage_instance_index ||
		    token.owner_kind != returned.owner_kind) {
			std::terminate();
		}
		// A cadence swap requires a consumed clean standby. With one returned
		// bank outstanding per owner, this publication proves that exact return
		// was accepted even when the newly completed bank is the other slot.
		state.returned.reset();
		return;
	}
	const auto &returned = *state.returned;
	if (token.kind != runtime_telemetry_bank_token_kind::BANK || token.epoch != returned.epoch ||
	    token.bank_generation <= returned.bank_generation || token.worker_index != returned.worker_index ||
	    token.owner_index != returned.owner_index || token.stage_instance_index != returned.stage_instance_index ||
	    token.owner_kind != returned.owner_kind) {
		std::terminate();
	}
	state.returned.reset();
}

void runtime_telemetry_aggregator::consume_retirement_transfer_(owner_aggregation_state &state,
								const runtime_telemetry_bank_token &token,
								runtime_telemetry_bank_owner_kind owner_kind,
								uint32_t worker_index, uint32_t owner_index,
								uint16_t stage_instance_index) noexcept
{
	if (token.runtime_generation != runtime_generation_ || token.epoch == 0u || token.bank_generation == 0u ||
	    token.worker_index != worker_index || token.owner_index != owner_index ||
	    token.stage_instance_index != stage_instance_index || token.owner_kind != owner_kind ||
	    token.bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	if (token.kind == runtime_telemetry_bank_token_kind::BANK) {
		if (workers_quiesced_) {
			std::terminate();
		}
		if (state.returned.has_value()) {
			const auto &later = *state.returned;
			if (later.kind != runtime_telemetry_bank_token_kind::BANK ||
			    later.reason != runtime_telemetry_publication_reason::CADENCE ||
			    later.runtime_generation != token.runtime_generation || later.epoch != token.epoch ||
			    later.worker_index != token.worker_index || later.owner_index != token.owner_index ||
			    later.stage_instance_index != token.stage_instance_index ||
			    later.owner_kind != token.owner_kind ||
			    (later.bank_index == token.bank_index && later.bank_generation <= token.bank_generation)) {
				std::terminate();
			}
			// This later cadence publication could occur only after the worker
			// accepted the reclaimed bank. Keep the cadence return as the one
			// current outstanding transfer.
			return;
		}
		remember_return_(state, token);
		return;
	}
	if (token.kind != runtime_telemetry_bank_token_kind::RETURN_RETAINED || !workers_quiesced_ ||
	    token.reason != runtime_telemetry_publication_reason::RECLAIMED || token.published_at_ns != 0u ||
	    token.companion_bank_index != UINT8_MAX || !runtime_telemetry_bank_token_padding_zero(token)) {
		std::terminate();
	}
	if (state.returned.has_value()) {
		std::terminate();
	}
	record_retained_(state, token.epoch, token.bank_index);
}

void runtime_telemetry_aggregator::merge_worker_(const runtime_telemetry_bank_token &token,
						 worker_runtime_telemetry &owner) noexcept
{
	auto &state = worker_aggregation_[token.worker_index];
	reconcile_reused_return_(state, token);
	auto bank_or = owner.completed_bank(token);
	if (!bank_or.is_ok()) {
		std::terminate();
	}
	const auto bank = bank_or.value();
	const auto stage_indices = owner.stage_instance_indices();
	const auto stream_indices = owner.io_stream_indices();
	if (bank.stages.size() != stage_indices.size() || bank.streams.size() != stream_indices.size()) {
		std::terminate();
	}
	{
		std::lock_guard<std::mutex> lock(aggregate_mutex_);
		add_saturating(aggregate_.engine.dropped_packets, bank.engine.dropped_packets);
		add_saturating(aggregate_.engine.fanout_overflow, bank.engine.fanout_overflow);
		const int32_t region_id = topology_.transition_topology.workers[token.worker_index].region_id;
		if (region_id < 0 || static_cast<std::size_t>(region_id) >= aggregate_.regions.size()) {
			std::terminate();
		}
		add_saturating(aggregate_.regions[static_cast<std::size_t>(region_id)].fanout_overflow,
			       bank.engine.fanout_overflow);
		for (std::size_t index = 0u; index < bank.protocol_faults.size(); ++index) {
			add_saturating(aggregate_.protocol_fault_counts[index], bank.protocol_faults[index]);
		}
		add_saturating(aggregate_.skipped_publications, bank.skipped_publications);
		for (std::size_t ordinal = 0u; ordinal < stage_indices.size(); ++ordinal) {
			const uint32_t stage_index = stage_indices[ordinal];
			if (stage_index >= topology_.stage_instances.size()) {
				std::terminate();
			}
			const uint16_t logical_index = topology_.stage_instances[stage_index].logical_stage_index;
			if (logical_index >= aggregate_.stages.size()) {
				std::terminate();
			}
			auto &target = aggregate_.stages[logical_index];
			const auto &source = bank.stages[ordinal];
			add_saturating(target.in_packets, source.in_packets);
			add_saturating(target.out_packets, source.out_packets);
			add_saturating(target.dropped_packets, source.dropped_packets);
			add_saturating(target.in_bytes, source.in_bytes);
			add_saturating(target.out_bytes, source.out_bytes);
		}
		for (std::size_t ordinal = 0u; ordinal < stream_indices.size(); ++ordinal) {
			const uint32_t stream_index = stream_indices[ordinal];
			if (stream_index >= aggregate_.streams.size()) {
				std::terminate();
			}
			auto &target = aggregate_.streams[stream_index];
			if (target.worker_index != token.worker_index ||
			    token.published_at_ns < target.published_monotonic_ns) {
				std::terminate();
			}
			const auto &source = bank.streams[ordinal];
			add_saturating(target.packets, source.packets);
			add_saturating(target.bytes, source.bytes);
			add_saturating(target.rejected_packets, source.rejected_packets);
			target.published_monotonic_ns = token.published_at_ns;
			stream_accounting_exhausted_ = stream_accounting_exhausted_ || target.packets == UINT64_MAX ||
						       target.bytes == UINT64_MAX ||
						       target.rejected_packets == UINT64_MAX;
		}
		aggregate_.latest_bank_publication_monotonic_ns =
			std::max(aggregate_.latest_bank_publication_monotonic_ns, token.published_at_ns);
		worker_observed_[token.worker_index] = 1u;
	}
	owner.complete_aggregation(token);
	if (token.reason == runtime_telemetry_publication_reason::CADENCE) {
		remember_return_(state, token);
		return;
	}
	record_retained_(state, token.epoch, token.bank_index);
	if (token.companion_bank_index != UINT8_MAX) {
		if (state.returned.has_value()) {
			if (state.returned->bank_index != token.companion_bank_index ||
			    state.returned->epoch != token.epoch) {
				std::terminate();
			}
			state.returned.reset();
		}
		record_retained_(state, token.epoch, token.companion_bank_index);
	}
	mark_complete_(state, owner, token.epoch);
}

void runtime_telemetry_aggregator::begin_module_merge_(const runtime_telemetry_bank_token &token,
						       module_binding &binding) noexcept
{
	if (pending_module_token_.has_value() || pending_module_binding_ != nullptr) {
		std::terminate();
	}
	reconcile_reused_return_(binding.aggregation, token);
	auto bank_or = binding.owner->completed_telemetry_bank(token);
	if (!bank_or.is_ok()) {
		std::terminate();
	}
	const auto bank = bank_or.value();
	if (bank.counter_values.size() != binding.counter_rows.size() ||
	    bank.histograms.size() != binding.histogram_rows.size()) {
		std::terminate();
	}
	if (binding.histogram_rows.empty()) {
		{
			std::lock_guard<std::mutex> lock(aggregate_mutex_);
			if (module_commit_in_progress_) {
				std::terminate();
			}
			commit_module_rows_(token, binding, bank);
		}
		complete_module_merge_(token, binding);
		return;
	}
	pending_module_token_ = token;
	pending_module_binding_ = &binding;
	pending_histogram_ordinal_ = 0u;
	pending_bucket_ = 0u;
	pending_histogram_source_count_ = 0u;
	pending_histogram_started_ = false;
	pending_histogram_replace_ = false;
	{
		std::lock_guard<std::mutex> lock(aggregate_mutex_);
		if (module_commit_in_progress_) {
			std::terminate();
		}
		module_commit_in_progress_ = true;
	}
}

void runtime_telemetry_aggregator::commit_module_rows_(
	const runtime_telemetry_bank_token &token, module_binding &binding,
	const lifecycle::lifecycle_module_telemetry_bank_view &bank) noexcept
{
	for (std::size_t index = 0u; index < binding.counter_rows.size(); ++index) {
		if (binding.counter_rows[index] >= aggregate_.module_counters.size()) {
			std::terminate();
		}
		auto &row = aggregate_.module_counters[binding.counter_rows[index]];
		row.epoch = token.epoch;
		row.value = bank.counter_values[index];
	}
	for (const std::size_t row_index : binding.histogram_rows) {
		if (row_index >= histograms_.size() || row_index >= aggregate_.module_histograms.size()) {
			std::terminate();
		}
		auto &target = aggregate_.module_histograms[row_index];
		const auto &source = histograms_[row_index].row;
		if (target.module_id != source.module_id || target.context_instance_id != source.context_instance_id ||
		    target.context_index != source.context_index || target.worker_index != source.worker_index ||
		    target.name != source.name) {
			std::terminate();
		}
		target.epoch = source.epoch;
		target.count = source.count;
		target.minimum = source.minimum;
		target.maximum = source.maximum;
		target.sum = source.sum;
	}
	if (binding.mismatch_row >= aggregate_.module_epoch_mismatches.size()) {
		std::terminate();
	}
	auto &mismatch = aggregate_.module_epoch_mismatches[binding.mismatch_row];
	const auto &source = bank.mismatch;
	if (source.reserved != 0u ||
	    !std::all_of(std::begin(source.padding), std::end(source.padding),
			 [](uint8_t byte) { return byte == 0u; }) ||
	    source.mismatch_count < mismatch.mismatch_count ||
	    (source.mismatch_count == 0u &&
	     (source.first_fault_valid != 0u || source.sticky_fault != 0u || source.packet_epoch != 0u ||
	      source.active_epoch != 0u || source.context_index != 0u || source.worker_index != 0u ||
	      source.stage_instance_index != 0u || source.region_id != -1)) ||
	    (source.mismatch_count != 0u &&
	     (source.first_fault_valid != 1u || source.sticky_fault != 1u || source.packet_epoch == 0u ||
	      source.active_epoch == 0u || source.context_index != binding.context_index ||
	      source.worker_index != token.worker_index || source.stage_instance_index != token.stage_instance_index ||
	      source.region_id != binding.region_id))) {
		std::terminate();
	}
	if (mismatch.first_fault_valid && source.mismatch_count != 0u &&
	    (mismatch.packet_epoch != source.packet_epoch || mismatch.active_epoch != source.active_epoch ||
	     mismatch.stage_instance_index != source.stage_instance_index || mismatch.region_id != source.region_id)) {
		std::terminate();
	}
	add_saturating(aggregate_.protocol_fault_counts[epoch_protocol_fault_ordinal(
			       epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH)],
		       source.mismatch_count - mismatch.mismatch_count);
	mismatch.observation_epoch = token.epoch;
	mismatch.mismatch_count = source.mismatch_count;
	mismatch.packet_epoch = source.packet_epoch;
	mismatch.active_epoch = source.active_epoch;
	mismatch.stage_instance_index = source.stage_instance_index;
	mismatch.region_id = source.region_id;
	mismatch.first_fault_valid = source.first_fault_valid != 0u;
	mismatch.sticky_fault = source.sticky_fault != 0u;
	add_saturating(aggregate_.skipped_publications, bank.skipped_publications);
	aggregate_.latest_bank_publication_monotonic_ns =
		std::max(aggregate_.latest_bank_publication_monotonic_ns, token.published_at_ns);
	binding.observed = true;
}

void runtime_telemetry_aggregator::complete_module_merge_(const runtime_telemetry_bank_token &token,
							  module_binding &binding) noexcept
{
	binding.owner->complete_telemetry_aggregation(token);
	auto &state = binding.aggregation;
	if (token.reason == runtime_telemetry_publication_reason::CADENCE) {
		remember_return_(state, token);
		return;
	}
	record_retained_(state, token.epoch, token.bank_index);
	if (token.companion_bank_index != UINT8_MAX) {
		if (state.returned.has_value()) {
			if (state.returned->bank_index != token.companion_bank_index ||
			    state.returned->epoch != token.epoch) {
				std::terminate();
			}
			state.returned.reset();
		}
		record_retained_(state, token.epoch, token.companion_bank_index);
	}
	mark_complete_(state, *binding.owner, token.epoch);
}

bool runtime_telemetry_aggregator::progress_module_merge_() noexcept
{
	if (!pending_module_token_.has_value() || pending_module_binding_ == nullptr) {
		return true;
	}
	const auto token = *pending_module_token_;
	auto &binding = *pending_module_binding_;
	auto bank_or = binding.owner->completed_telemetry_bank(token);
	if (!bank_or.is_ok() || pending_histogram_ordinal_ >= binding.histogram_rows.size()) {
		std::terminate();
	}
	const auto bank = bank_or.value();
	if (bank.bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	const std::size_t histogram_ordinal = pending_histogram_ordinal_;
	if (histogram_ordinal > UINT32_MAX) {
		std::terminate();
	}
	auto source_or = binding.owner->completed_telemetry_histogram(token, static_cast<uint32_t>(histogram_ordinal));
	if (!source_or.is_ok()) {
		std::terminate();
	}
	auto &histogram = histograms_[binding.histogram_rows[histogram_ordinal]];
	const auto source = source_or.value();
	if (source.size() != histogram.counts.size() || pending_bucket_ >= source.size()) {
		std::terminate();
	}
	const std::size_t begin = pending_bucket_;
	const std::size_t end = std::min(source.size(), begin + lifecycle::LIFECYCLE_TELEMETRY_BUCKET_PREFIX);
	bool bank_complete = false;
	{
		std::unique_lock<std::mutex> lock(aggregate_mutex_);
		if (!module_commit_in_progress_) {
			std::terminate();
		}
		if (!pending_histogram_started_) {
			if (pending_histogram_source_count_ != 0u) {
				std::terminate();
			}
			pending_histogram_replace_ = histogram.row.epoch != token.epoch;
			if (pending_histogram_replace_) {
				histogram.geometry.total_count = 0u;
				histogram.geometry.min_value = UINT64_MAX;
				histogram.geometry.max_value = 0u;
				histogram.geometry.sum = 0u;
			}
			const auto &summary = bank.histograms[histogram_ordinal];
			if ((summary.total_count == 0u &&
			     (summary.min_value != UINT64_MAX || summary.max_value != 0u || summary.sum != 0u)) ||
			    (summary.total_count != 0u &&
			     (summary.min_value > summary.max_value ||
			      summary.max_value > histogram.geometry.highest_trackable_value))) {
				std::terminate();
			}
			add_saturating(histogram.geometry.total_count, summary.total_count);
			if (summary.total_count != 0u) {
				histogram.geometry.min_value =
					std::min(histogram.geometry.min_value, summary.min_value);
				histogram.geometry.max_value =
					std::max(histogram.geometry.max_value, summary.max_value);
			}
			add_saturating(histogram.geometry.sum, summary.sum);
			histogram.row.epoch = token.epoch;
			pending_histogram_started_ = true;
		}
		for (std::size_t bucket = begin; bucket < end; ++bucket) {
			if (source[bucket] > UINT64_MAX - pending_histogram_source_count_) {
				std::terminate();
			}
			pending_histogram_source_count_ += source[bucket];
			if (pending_histogram_replace_) {
				histogram.counts[bucket] = source[bucket];
			} else {
				add_saturating(histogram.counts[bucket], source[bucket]);
			}
		}
		pending_bucket_ = end;
		if (pending_bucket_ == histogram.counts.size()) {
			if (pending_histogram_source_count_ != bank.histograms[histogram_ordinal].total_count) {
				std::terminate();
			}
			histogram.row.count = histogram.geometry.total_count;
			histogram.row.minimum = histogram.geometry.total_count == 0u ? UINT64_MAX :
										       histogram.geometry.min_value;
			histogram.row.maximum = histogram.geometry.max_value;
			histogram.row.sum = histogram.geometry.sum;
			++pending_histogram_ordinal_;
			pending_bucket_ = 0u;
			pending_histogram_source_count_ = 0u;
			pending_histogram_started_ = false;
			pending_histogram_replace_ = false;
		}
		bank_complete = pending_histogram_ordinal_ == binding.histogram_rows.size();
	}
	const bool buckets_cleared = binding.owner->clear_completed_telemetry_histogram_prefix(
		token, static_cast<uint32_t>(histogram_ordinal), begin, end - begin);
	if (buckets_cleared != bank_complete) {
		std::terminate();
	}
	if (!bank_complete) {
		return false;
	}
	{
		std::lock_guard<std::mutex> lock(aggregate_mutex_);
		if (!module_commit_in_progress_) {
			std::terminate();
		}
		commit_module_rows_(token, binding, bank);
		module_commit_in_progress_ = false;
	}
	complete_module_merge_(token, binding);
	pending_module_token_.reset();
	pending_module_binding_ = nullptr;
	pending_histogram_ordinal_ = 0u;
	pending_histogram_source_count_ = 0u;
	pending_histogram_replace_ = false;
	return true;
}

void runtime_telemetry_aggregator::consume_return_retained_(const runtime_telemetry_bank_token &token) noexcept
{
	if (token.kind != runtime_telemetry_bank_token_kind::RETURN_RETAINED ||
	    (token.reason != runtime_telemetry_publication_reason::CADENCE &&
	     token.reason != runtime_telemetry_publication_reason::RECLAIMED) ||
	    token.companion_bank_index != UINT8_MAX || token.bank_index >= RUNTIME_TELEMETRY_BANK_COUNT ||
	    (token.reason == runtime_telemetry_publication_reason::CADENCE && token.published_at_ns == 0u) ||
	    (token.reason == runtime_telemetry_publication_reason::RECLAIMED && token.published_at_ns != 0u) ||
	    !runtime_telemetry_bank_token_padding_zero(token)) {
		std::terminate();
	}
	if (token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER) {
		if (token.worker_index >= workers_.size() || token.owner_index != token.worker_index ||
		    token.stage_instance_index != UINT16_MAX) {
			std::terminate();
		}
		auto &state = worker_aggregation_[token.worker_index];
		if (!state.returned.has_value() || !same_return_identity(*state.returned, token)) {
			std::terminate();
		}
		state.returned.reset();
		record_retained_(state, token.epoch, token.bank_index);
		mark_complete_(state, *workers_[token.worker_index], token.epoch);
		return;
	}
	if (token.owner_kind == runtime_telemetry_bank_owner_kind::MODULE) {
		auto *binding = find_module_(token.owner_index);
		if (binding == nullptr || binding->owner == nullptr ||
		    binding->owner->identity().worker_index != token.worker_index ||
		    binding->owner->identity().context_index != token.owner_index ||
		    !binding->aggregation.returned.has_value() ||
		    !same_return_identity(*binding->aggregation.returned, token)) {
			std::terminate();
		}
		binding->aggregation.returned.reset();
		record_retained_(binding->aggregation, token.epoch, token.bank_index);
		mark_complete_(binding->aggregation, *binding->owner, token.epoch);
		return;
	}
	std::terminate();
}

void runtime_telemetry_aggregator::consume_(const runtime_telemetry_bank_token &token) noexcept
{
	if (token.runtime_generation != runtime_generation_ || token.worker_index >= workers_.size() ||
	    (token.reason == runtime_telemetry_publication_reason::RECLAIMED ? token.published_at_ns != 0u :
									       token.published_at_ns == 0u) ||
	    !runtime_telemetry_bank_token_padding_zero(token)) {
		std::terminate();
	}
	if (token.kind == runtime_telemetry_bank_token_kind::RETURN_RETAINED) {
		consume_return_retained_(token);
		return;
	}
	if (token.kind != runtime_telemetry_bank_token_kind::BANK ||
	    (token.reason != runtime_telemetry_publication_reason::CADENCE &&
	     token.reason != runtime_telemetry_publication_reason::ACTIVATION &&
	     token.reason != runtime_telemetry_publication_reason::SHUTDOWN)) {
		std::terminate();
	}
	if (token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER) {
		merge_worker_(token, *workers_[token.worker_index]);
		return;
	}
	if (token.owner_kind == runtime_telemetry_bank_owner_kind::MODULE) {
		auto *binding = find_module_(token.owner_index);
		if (binding == nullptr || binding->owner == nullptr ||
		    binding->owner->identity().worker_index != token.worker_index) {
			std::terminate();
		}
		begin_module_merge_(token, *binding);
		return;
	}
	std::terminate();
}

std::size_t runtime_telemetry_aggregator::service(std::size_t budget) noexcept
{
	if (budget == 0u) {
		return 0u;
	}
	if (pending_module_token_.has_value()) {
		(void)progress_module_merge_();
		return 1u;
	}
	std::size_t consumed = 0u;
	std::size_t inspected = 0u;
	while (consumed < budget && inspected < channels_.size()) {
		if (service_cursor_ >= channels_.size()) {
			service_cursor_ = 0u;
		}
		auto *channel = channels_[service_cursor_++];
		++inspected;
		runtime_telemetry_bank_token token{};
		if (!channel->take_completed(token)) {
			continue;
		}
		consume_(token);
		++consumed;
		if (pending_module_token_.has_value()) {
			break;
		}
		inspected = 0u;
	}
	return consumed;
}

bool runtime_telemetry_aggregator::work_pending() const noexcept
{
	if (pending_module_token_.has_value()) {
		return true;
	}
	return std::any_of(channels_.begin(), channels_.end(),
			   [](const auto *channel) { return channel != nullptr && !channel->completed_empty(); });
}

void runtime_telemetry_aggregator::drain_quiescent() noexcept
{
	for (;;) {
		const std::size_t consumed = service(std::numeric_limits<std::size_t>::max());
		if (consumed == 0u) {
			break;
		}
	}
}

bool runtime_telemetry_aggregator::worker_epoch_aggregated(uint64_t epoch) const noexcept
{
	return epoch != 0u && worker_aggregation_.size() == workers_.size() &&
	       std::all_of(worker_aggregation_.begin(), worker_aggregation_.end(), [epoch](const auto &state) {
		       return std::count(state.retained_epochs.begin(), state.retained_epochs.end(), epoch) == 2;
	       });
}

bool runtime_telemetry_aggregator::module_epoch_aggregated(uint64_t epoch) const noexcept
{
	return epoch != 0u &&
	       std::all_of(module_bindings_.begin(), module_bindings_.end(), [epoch](const auto &binding) {
		       return std::count(binding.aggregation.retained_epochs.begin(),
					 binding.aggregation.retained_epochs.end(), epoch) == 2;
	       });
}

void runtime_telemetry_aggregator::complete_module_epoch_retirement(uint64_t epoch, uint64_t active_epoch) noexcept
{
	if (epoch == 0u) {
		std::terminate();
	}
	for (auto &binding : module_bindings_) {
		auto &state = binding.aggregation;
		if (binding.owner == nullptr ||
		    std::count(state.retained_epochs.begin(), state.retained_epochs.end(), epoch) != 2 ||
		    binding.owner->telemetry_epoch_aggregated(epoch)) {
			std::terminate();
		}
		for (auto &retained_epoch : state.retained_epochs) {
			if (retained_epoch == epoch) {
				retained_epoch = 0u;
			}
		}
		if (active_epoch == 0u) {
			if (binding.owner->take_reclaimed_telemetry_transfer(active_epoch).has_value()) {
				std::terminate();
			}
			continue;
		}
		auto transfer = binding.owner->take_reclaimed_telemetry_transfer(active_epoch);
		if (!transfer.has_value()) {
			std::terminate();
		}
		consume_retirement_transfer_(state, *transfer, runtime_telemetry_bank_owner_kind::MODULE,
					     binding.owner->identity().worker_index, binding.context_index,
					     binding.owner->telemetry_stage_instance_index());
		mark_complete_(state, *binding.owner, active_epoch);
	}
}

void runtime_telemetry_aggregator::retire_worker_epoch(uint64_t epoch, uint64_t active_epoch) noexcept
{
	if (!worker_epoch_aggregated(epoch)) {
		std::terminate();
	}
	for (std::size_t index = 0u; index < workers_.size(); ++index) {
		auto *worker = workers_[index];
		auto &state = worker_aggregation_[index];
		if (worker == nullptr ||
		    std::count(state.retained_epochs.begin(), state.retained_epochs.end(), epoch) != 2 ||
		    !worker->epoch_aggregated(epoch)) {
			std::terminate();
		}
		auto transfer = worker->retire_epoch(epoch, active_epoch);
		for (auto &retained_epoch : state.retained_epochs) {
			if (retained_epoch == epoch) {
				retained_epoch = 0u;
			}
		}
		if (active_epoch == 0u) {
			if (transfer.has_value()) {
				std::terminate();
			}
			continue;
		}
		if (!transfer.has_value()) {
			std::terminate();
		}
		consume_retirement_transfer_(state, *transfer, runtime_telemetry_bank_owner_kind::WORKER,
					     static_cast<uint32_t>(index), static_cast<uint32_t>(index), UINT16_MAX);
		mark_complete_(state, *worker, active_epoch);
	}
}

void runtime_telemetry_aggregator::mark_workers_quiesced() noexcept
{
	if (workers_quiesced_) {
		std::terminate();
	}
	for (auto *worker : workers_) {
		if (worker == nullptr) {
			std::terminate();
		}
		worker->mark_owner_quiesced();
	}
	modules_.mark_telemetry_workers_quiesced();
	workers_quiesced_ = true;
}

common::status_or<runtime_telemetry_snapshot>
runtime_telemetry_aggregator::collect(const runtime_telemetry_request &request) const
{
	try {
		common::status availability;
		const auto defer_unavailable = [&availability](common::status failure) {
			if (availability.is_ok()) {
				availability = std::move(failure);
			}
		};
		runtime_status_snapshot status{};
		const auto status_read = runtime_status_.try_read(status);
		if (status_read == publication_read_result::INVALID_IDENTITY ||
		    status_read == publication_read_result::INVALID_STATE ||
		    (status_read == publication_read_result::AVAILABLE &&
		     (status.runtime_generation != runtime_generation_ ||
		      static_cast<std::size_t>(status.expected_workers) != workers_.size()))) {
			return common::status::data_loss("runtime telemetry status contradicts its generation");
		}
		if (status_read != publication_read_result::AVAILABLE ||
		    status.readiness != runtime_readiness::PACKET_READY) {
			defer_unavailable(
				common::status::unavailable("runtime telemetry lacks coherent runtime status"));
		}

		std::lock_guard<std::mutex> lock(aggregate_mutex_);
		if (module_commit_in_progress_) {
			defer_unavailable(
				common::status::unavailable("runtime telemetry module-bank merge is incomplete"));
		}
		if (std::any_of(worker_observed_.begin(), worker_observed_.end(),
				[](uint8_t value) { return value > 1u; })) {
			return common::status::data_loss("runtime telemetry worker-observation state is invalid");
		}
		if (aggregate_.latest_bank_publication_monotonic_ns == 0u ||
		    std::any_of(worker_observed_.begin(), worker_observed_.end(),
				[](uint8_t value) { return value != 1u; }) ||
		    std::any_of(module_bindings_.begin(), module_bindings_.end(),
				[](const module_binding &binding) { return !binding.observed; })) {
			defer_unavailable(
				common::status::unavailable("runtime telemetry has no complete owner-bank baseline"));
		}
		if (stream_accounting_exhausted_) {
			return common::status::data_loss("runtime stream accounting exhausted its exact counter range");
		}
		runtime_telemetry_snapshot result = aggregate_;
		for (const auto &stream : result.streams) {
			if (stream.published_monotonic_ns == 0u) {
				defer_unavailable(common::status::unavailable(
					"runtime stream accounting lacks a completed owner bank"));
			}
			if (stream.direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				add_saturating(result.engine.rx_packets, stream.packets);
				add_saturating(result.engine.rx_bytes, stream.bytes);
			} else if (stream.direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_TX) {
				add_saturating(result.engine.tx_packets, stream.packets);
				add_saturating(result.engine.tx_bytes, stream.bytes);
			} else {
				return common::status::data_loss("runtime stream accounting lost its direction");
			}
		}
		if (result.engine.rx_packets == UINT64_MAX || result.engine.tx_packets == UINT64_MAX ||
		    result.engine.rx_bytes == UINT64_MAX || result.engine.tx_bytes == UINT64_MAX) {
			return common::status::data_loss("runtime stream totals exhausted the engine counter range");
		}
		if (!request.include_stream_stats) {
			result.streams.clear();
		}
		if (result.module_histograms.size() != histograms_.size() ||
		    result.module_health.size() != module_bindings_.size() ||
		    health_observations_.size() != module_bindings_.size()) {
			return common::status::data_loss("runtime telemetry aggregate membership changed");
		}
		for (std::size_t index = 0u; index < histograms_.size(); ++index) {
			auto geometry = histograms_[index].geometry;
			// The byte-frozen C helper retains a mutable-handle typedef but performs
			// read-only summarization. This cast does not expose aggregate storage.
			geometry.counts = const_cast<uint64_t *>(histograms_[index].counts.data());
			kinetum_percentiles summary{};
			kinetum_histogram_percentiles(&geometry, &summary);
			auto &row = result.module_histograms[index];
			row.count = summary.count;
			row.minimum = summary.count == 0u ? UINT64_MAX : summary.min;
			row.maximum = summary.max;
			row.sum = summary.sum;
			row.p50 = summary.p50;
			row.p90 = summary.p90;
			row.p99 = summary.p99;
			row.p999 = summary.p999;
		}
		if (!request.include_stage_stats) {
			result.stages.clear();
		}
		if (!request.include_region_epoch_stats) {
			result.regions.clear();
		}
		for (std::size_t index = 0u; index < module_bindings_.size(); ++index) {
			const auto &binding = module_bindings_[index];
			if (binding.owner == nullptr || binding.health_row >= result.module_health.size()) {
				return common::status::data_loss(
					"runtime telemetry health binding lost exact membership");
			}
			auto &row = result.module_health[binding.health_row];
			if (!binding.health_callback_available) {
				if (row.callback_available || row.signal_available) {
					return common::status::data_loss(
						"runtime telemetry unavailable health row gained a signal");
				}
				continue;
			}
			if (!row.callback_available) {
				return common::status::data_loss(
					"runtime telemetry available health binding lost callback identity");
			}
			lifecycle::lifecycle_module_health_observation observation{};
			if (!binding.owner->try_read_module_health(observation)) {
				continue;
			}
			if (observation.runtime_generation != runtime_generation_ ||
			    observation.worker_index != row.worker_index ||
			    observation.context_index != row.context_index ||
			    observation.stage_instance_index != row.stage_instance_index ||
			    observation.callback_available != 1u) {
				return common::status::data_loss(
					"runtime telemetry health publication contradicts compiled identity");
			}
			auto &accepted = health_observations_[index];
			const bool same_publication = observation.publication_generation ==
						      accepted.publication_generation;
			const bool accepted_first_fault = accepted.first_fault_mask != 0u;
			if (observation.publication_generation < accepted.publication_generation ||
			    (same_publication &&
			     (observation.observation_epoch != accepted.observation_epoch ||
			      observation.observed_at_ns != accepted.observed_at_ns ||
			      observation.callback_duration_ns != accepted.callback_duration_ns ||
			      observation.contract_fault_count != accepted.contract_fault_count ||
			      observation.latest_fault_mask != accepted.latest_fault_mask ||
			      observation.first_fault_mask != accepted.first_fault_mask ||
			      observation.first_fault_epoch != accepted.first_fault_epoch ||
			      observation.first_fault_timestamp_ns != accepted.first_fault_timestamp_ns ||
			      observation.first_fault_duration_ns != accepted.first_fault_duration_ns ||
			      observation.signal_available != accepted.signal_available ||
			      !health_signals_equal(observation.signal, accepted.signal))) ||
			    (!same_publication &&
			     (observation.observation_epoch < accepted.observation_epoch ||
			      observation.observed_at_ns < accepted.observed_at_ns ||
			      observation.contract_fault_count < accepted.contract_fault_count ||
			      (accepted_first_fault &&
			       (observation.first_fault_mask != accepted.first_fault_mask ||
				observation.first_fault_epoch != accepted.first_fault_epoch ||
				observation.first_fault_timestamp_ns != accepted.first_fault_timestamp_ns ||
				observation.first_fault_duration_ns != accepted.first_fault_duration_ns))))) {
				return common::status::data_loss(
					"runtime telemetry health publication regressed or changed immutable identity");
			}
			accepted.publication_generation = observation.publication_generation;
			accepted.observation_epoch = observation.observation_epoch;
			accepted.observed_at_ns = observation.observed_at_ns;
			accepted.callback_duration_ns = observation.callback_duration_ns;
			accepted.contract_fault_count = observation.contract_fault_count;
			accepted.latest_fault_mask = observation.latest_fault_mask;
			accepted.first_fault_mask = observation.first_fault_mask;
			accepted.first_fault_epoch = observation.first_fault_epoch;
			accepted.first_fault_timestamp_ns = observation.first_fault_timestamp_ns;
			accepted.first_fault_duration_ns = observation.first_fault_duration_ns;
			accepted.signal_available = observation.signal_available;
			accepted.signal = observation.signal;
			if (observation.observation_epoch > status.active_epoch) {
				defer_unavailable(common::status::unavailable(
					"module health publication is ahead of coherent runtime active truth"));
			}
			row.publication_generation = observation.publication_generation;
			row.observation_epoch = observation.observation_epoch;
			row.observed_at_ns = observation.observed_at_ns;
			row.callback_duration_ns = observation.callback_duration_ns;
			row.contract_fault_count = observation.contract_fault_count;
			row.latest_fault_mask = observation.latest_fault_mask;
			row.first_fault_mask = observation.first_fault_mask;
			row.first_fault_epoch = observation.first_fault_epoch;
			row.first_fault_timestamp_ns = observation.first_fault_timestamp_ns;
			row.first_fault_duration_ns = observation.first_fault_duration_ns;
			if (observation.observation_epoch == status.active_epoch &&
			    observation.signal_available == 1u) {
				row.signal_available = true;
				row.signal = observation.signal;
			} else {
				row.signal_available = false;
				row.signal = {};
			}
		}
		result.runtime_status = status;
		if (!request.include_module_metrics) {
			result.module_counters.clear();
			result.module_histograms.clear();
			result.module_epoch_mismatches.clear();
		}
		if (!request.include_module_health) {
			result.module_health.clear();
		}
		if (!availability.is_ok()) {
			return availability;
		}
		return result;
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("failed to allocate runtime telemetry snapshot");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "runtime telemetry snapshot extent exceeds the host size domain");
	}
}

uint32_t runtime_telemetry_aggregator::expected_workers() const noexcept
{
	return static_cast<uint32_t>(workers_.size());
}

}  // namespace kinetum::dp
