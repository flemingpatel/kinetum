// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file partitioned_runtime.cpp
 * @brief Complete packet-runtime generation ownership.
 * @author Fleming Patel
 */

#include "src/dp/partitioned_runtime.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <iterator>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>

#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_sizing.hpp"
#include "src/common/time.hpp"
#include "src/dp/dp_control_event_loop.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/boundary_epoch_storage.hpp"
#include "src/dp/epoch/epoch_transition_certificate.hpp"
#include "src/dp/epoch/epoch_transition_completion.hpp"
#include "src/dp/epoch/epoch_transition_coordinator.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/epoch/epoch_transition_preparation.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "src/dp/module/module_runtime_generation.hpp"
#include "src/dp/packet_worker_kernel.hpp"
#include "src/dp/region_worker_launcher.hpp"
#include "src/dp/runtime_telemetry_aggregator.hpp"
#include "src/dp/runtime_telemetry_snapshot_source.hpp"
#include "src/dp/runtime_telemetry_source_owner.hpp"
#include "src/dp/thread_affinity.hpp"
#include "src/dp/worker_runtime_command.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/provider/provider_runtime_materialization.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/**
 * @brief Validate packet-worker construction facts before provider side effects.
 *
 * @param topology Sole compiled topology authority.
 * @return OK for one dense exact worker/boundary set; otherwise a recoverable
 *         pre-materialization status.
 */
status validate_runtime_construction_facts(const provider::compiled_provider_topology &topology)
{
	const auto &workers = topology.transition_topology.workers;
	if (workers.empty()) {
		return status::invalid_argument("packet runtime requires at least one compiled worker");
	}
	if (workers.size() > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max()) ||
	    workers.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
		return status(status_code::OUT_OF_RANGE, "packet worker count exceeds compact launcher range");
	}
	if (topology.worker_schedules.size() != workers.size()) {
		return status::invalid_argument("packet worker schedules do not cover the exact worker set");
	}
	for (std::size_t i = 0; i < workers.size(); ++i) {
		if (workers[i].worker_index != i || topology.worker_schedules[i].worker_index != i ||
		    workers[i].cpu_core_ids.size() != 1 || workers[i].cpu_core_ids.front() < 0) {
			return status::invalid_argument(
				"packet worker identity and sole CPU ownership must be dense and exact");
		}
	}
	for (std::size_t i = 0; i < topology.transition_topology.boundaries.size(); ++i) {
		const auto &boundary = topology.transition_topology.boundaries[i];
		if (boundary.boundary_index != i || boundary.sender_worker_index >= workers.size() ||
		    boundary.receiver_worker_index >= workers.size()) {
			return status::invalid_argument("compiled boundary channel ownership is incomplete");
		}
	}
	return status::ok();
}

/**
 * @brief Log one post-materialization startup failure without throwing.
 *
 * @param failure Exact failure that cannot return to a reusable process.
 */
void log_materialized_failure(const status &failure) noexcept
{
	const auto message = failure.message();
	std::fprintf(stderr, "packet_runtime: materialized runtime construction failed [%s]: %.*s\n",
		     kinetum::common::status_code_name(failure.code()),
		     static_cast<int>(std::min(message.size(), std::size_t{8192})), message.data());
	(void)std::fflush(stderr);
}

/**
 * @brief Log one bounded post-materialization exception diagnostic.
 *
 * @param message Stable diagnostic that requires no exception inspection.
 */
void log_materialized_failure(const char *message) noexcept
{
	std::fprintf(stderr, "packet_runtime: %.8192s\n", message);
	(void)std::fflush(stderr);
}

/**
 * @brief Clean pre-runtime owners and terminate after materialization succeeded.
 *
 * @param message Stable post-materialization failure diagnostic.
 * @param modules Module generation retired before provider code.
 * @param providers Materialized provider generation retired last.
 */
[[noreturn]] void
terminate_after_materialization(const char *message, std::unique_ptr<module::module_runtime_generation> &modules,
				std::unique_ptr<provider::materialized_provider_runtime> &providers) noexcept
{
	log_materialized_failure(message);
	if (modules && modules->lifecycle_services_running()) {
		modules->stop_lifecycle_services();
	}
	modules.reset();
	providers.reset();
	std::terminate();
}

/**
 * @brief Copy one dynamic status into the fixed command-result contract.
 *
 * @param code Exact application status code.
 * @param diagnostic Exact source diagnostic to bound.
 * @param resolution Typed transaction classification retained by callers.
 * @return Fixed-width operation result with a bounded diagnostic prefix.
 */
[[nodiscard]] epoch_transition_operation_result
fixed_operation_failure(status_code code, std::string_view diagnostic,
			common::transition_identity_resolution resolution) noexcept
{
	static_assert(common::MAX_TRANSITION_DIAGNOSTIC_BYTES <= std::numeric_limits<uint16_t>::max());
	epoch_transition_operation_result result;
	result.code = code;
	result.observation.resolution = resolution;
	const std::size_t size = std::min(diagnostic.size(), result.observation.diagnostic.bytes.size());
	std::copy_n(diagnostic.begin(), size, result.observation.diagnostic.bytes.data());
	result.observation.diagnostic.size = static_cast<uint16_t>(size);
	return result;
}

/**
 * @brief Project one ordinary status through the fixed diagnostic overload.
 *
 * @param source Exact cold-path status to project.
 * @param resolution Typed transaction classification retained by callers.
 * @return Fixed-width operation result.
 */
[[nodiscard]] epoch_transition_operation_result
fixed_operation_failure(const status &source, common::transition_identity_resolution resolution) noexcept
{
	return fixed_operation_failure(source.code(), source.message(), resolution);
}

/**
 * @brief Replace only the application status of one exact operation result.
 * @param result Exact coordinator observation whose identity/state is retained.
 * @param code Non-OK application category for the attempted operation.
 * @param diagnostic Stable diagnostic to retain as a bounded prefix.
 */
void set_exact_operation_failure(epoch_transition_operation_result &result, status_code code,
				 std::string_view diagnostic) noexcept
{
	if (code == status_code::OK) {
		std::terminate();
	}
	result.code = code;
	result.observation.diagnostic = {};
	const std::size_t size = std::min(diagnostic.size(), result.observation.diagnostic.bytes.size());
	std::copy_n(diagnostic.begin(), size, result.observation.diagnostic.bytes.data());
	result.observation.diagnostic.size = static_cast<uint16_t>(size);
}

/**
 * @brief Project one explicit steady-clock sample into the coordinator nanosecond domain.
 *
 * @param now Exact steady-clock sample.
 * @return Positive nanoseconds since the clock's unspecified epoch, or zero
 *         only when the platform clock representation is invalid.
 */
[[nodiscard]] uint64_t monotonic_nanoseconds(std::chrono::steady_clock::time_point now) noexcept
{
	const auto count = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
	return count > 0 ? static_cast<uint64_t>(count) : 0u;
}

/**
 * @brief Convert one prepared-lease duration into an informational Unix deadline.
 * @param duration Exact positive compiled lease duration.
 * @return Positive Unix millisecond projection or OUT_OF_RANGE.
 */
[[nodiscard]] status_or<uint64_t> prepared_lease_unix_deadline(std::chrono::steady_clock::duration duration) noexcept
{
	const int64_t now_ms = common::unix_time_ms();
	const auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
	if (now_ms <= 0 || delta <= 0 || delta > std::numeric_limits<int64_t>::max() - now_ms) {
		return status(
			status_code::OUT_OF_RANGE,
			kinetum::common::static_status_text("prepared lease Unix projection exceeds integer range"));
	}
	return static_cast<uint64_t>(now_ms + delta);
}

/**
 * @brief Validate one complete internal transition-request protobuf tree.
 *
 * @tparam request_type Generated transition request type.
 * @param request Candidate request tree.
 * @param contract_name Stable generated-message identity for diagnostics.
 * @return OK only when no unknown field or undeclared enum value exists.
 */
template <typename request_type>
[[nodiscard]] status validate_transition_request_wire(const request_type &request, std::string_view contract_name)
{
	auto unknown_status = common::reject_unknown_protobuf_fields_recursive(request, contract_name);
	if (!unknown_status.is_ok()) {
		return unknown_status;
	}
	return common::reject_invalid_protobuf_enum_values_recursive(request, contract_name);
}

/** @brief Stack-owned Bootstrap payload retained until unconditional completion. */
class bootstrap_command_context final : public epoch_transition_command_context {
    public:
	std::string serialized_request;					///< Deterministic complete retry identity.
	common::sha256_digest validation_hash{};			///< Canonical snapshot identity.
	common::epoch_transition_watermarks watermarks{};		///< Durable allocator authority.
	uint64_t active_epoch{0};					///< Exact fixed epoch restored by this command.
	std::unique_ptr<const config_snapshot_artifact> artifact;	///< Exact immutable snapshot ownership.
	std::optional<status_or<fixed_epoch_bootstrap_result>> result;	///< Consumer-owned completion.
};

/** @brief Stack-owned live-transition payload retained until unconditional completion. */
class transaction_command_context final : public epoch_transition_command_context {
    public:
	common::epoch_transition_identity identity{};		    ///< Exact fixed-width transaction identity.
	std::unique_ptr<const config_snapshot_artifact> candidate;  ///< PREPARE candidate only.
	epoch_transition_operation_result result{};		    ///< Consumer-owned fixed completion.
};

}  // namespace

/** @brief Complete generation transaction, command consumer, and reverse-retirement owner. */
class partitioned_runtime::implementation final {
    public:
	/**
	 * @brief Adopt every stable generation owner after provider materialization.
	 *
	 * @param plan Exact canonical deployment plan.
	 * @param topology Sole stable compiled topology owner.
	 * @param coordinator Sole global generation, participant, and snapshot owner.
	 * @param command_mailbox Preallocated exact coordinator command authority.
	 * @param worker_commands Sole one-load transition/stop publication.
	 * @param providers Complete materialized provider generation.
	 * @param modules Complete admitted module/lifecycle generation.
	 * @param runtime_generation Exact nonzero generation identity.
	 */
	implementation(kinetum::gluon::v1::DeploymentPlan plan,
		       std::unique_ptr<provider::compiled_provider_topology> topology,
		       std::unique_ptr<epoch_transition_coordinator> coordinator,
		       std::unique_ptr<epoch_transition_command_mailbox> command_mailbox,
		       std::unique_ptr<worker_runtime_command_publication> worker_commands,
		       std::unique_ptr<provider::materialized_provider_runtime> providers,
		       std::unique_ptr<module::module_runtime_generation> modules, uint64_t runtime_generation) noexcept
		: plan_(std::move(plan))
		, topology_(std::move(topology))
		, coordinator_(std::move(coordinator))
		, command_mailbox_(std::move(command_mailbox))
		, worker_commands_(std::move(worker_commands))
		, providers_(std::move(providers))
		, modules_(std::move(modules))
		, runtime_generation_(runtime_generation)
	{
	}

	/** @brief Generation implementations cannot be copied. */
	implementation(const implementation &) = delete;
	/** @brief Generation implementations cannot be copy-assigned. */
	implementation &operator=(const implementation &) = delete;
	/** @brief Generation implementations cannot be moved. */
	implementation(implementation &&) = delete;
	/** @brief Generation implementations cannot be move-assigned. */
	implementation &operator=(implementation &&) = delete;

	/** @brief Enforce explicit generation shutdown before member destruction. */
	~implementation()
	{
		shutdown();
	}

	/** @return OK after building all cold owners and publishing CONTROL_READY. */
	[[nodiscard]] status complete_construction()
	{
		if (worker_commands_ == nullptr || worker_commands_->runtime_generation() != runtime_generation_) {
			return status::internal_error(
				"packet runtime lost its exact worker-command publication authority");
		}
		if (coordinator_ == nullptr) {
			return status::internal_error("packet runtime lost its transition coordinator");
		}
		auto fault_binding = coordinator_->bind_protocol_faults(runtime_generation_, protocol_faults_);
		if (!fault_binding.is_ok()) {
			return fault_binding;
		}
		auto boundary_status = materialize_boundary_transport_();
		if (!boundary_status.is_ok()) {
			return boundary_status;
		}
		auto telemetry_status = materialize_worker_telemetry_();
		if (!telemetry_status.is_ok()) {
			return telemetry_status;
		}

		const std::size_t worker_count = topology_->transition_topology.workers.size();
		if (boundary_senders_.size() != worker_count || boundary_receivers_.size() != worker_count) {
			return status::internal_error(
				"packet runtime endpoint-policy cardinality does not equal compiled workers");
		}
		kernels_.reserve(worker_count);
		for (std::size_t worker_index = 0; worker_index < worker_count; ++worker_index) {
			if (worker_index >= worker_telemetry_.size() || worker_telemetry_[worker_index] == nullptr) {
				return status::internal_error("packet worker lost its exact telemetry owner");
			}
			auto kernel_or = packet_worker_kernel::create(
				static_cast<uint32_t>(worker_index), *topology_, *providers_, modules_->modules(),
				*worker_commands_, boundary_views_, std::move(boundary_senders_[worker_index]),
				std::move(boundary_receivers_[worker_index]), *worker_telemetry_[worker_index],
				protocol_faults_,
				modules_->worker_telemetry_contexts(static_cast<uint32_t>(worker_index)));
			if (!kernel_or.is_ok()) {
				return kernel_or.error();
			}
			kernels_.push_back(std::move(kernel_or).value());
		}
		boundary_senders_.clear();
		boundary_receivers_.clear();
		auto certificate_status = materialize_transition_certificate_();
		if (!certificate_status.is_ok()) {
			return certificate_status;
		}
		std::vector<worker_telemetry_channel *> telemetry_channel_views;
		std::vector<worker_runtime_telemetry *> worker_telemetry_views;
		telemetry_channel_views.reserve(worker_count);
		worker_telemetry_views.reserve(worker_count);
		for (std::size_t worker_index = 0u; worker_index < worker_count; ++worker_index) {
			telemetry_channel_views.push_back(telemetry_channels_[worker_index].get());
			worker_telemetry_views.push_back(worker_telemetry_[worker_index].get());
		}
		auto aggregator_or =
			runtime_telemetry_aggregator::create(runtime_generation_, *topology_, telemetry_channel_views,
							     worker_telemetry_views, *modules_, runtime_status_);
		if (!aggregator_or.is_ok()) {
			return aggregator_or.error();
		}
		telemetry_aggregator_ = std::move(aggregator_or).value();
		telemetry_service_interval_ = topology_->transition_topology.workers.front().health_poll_interval;
		for (const auto &worker : topology_->transition_topology.workers) {
			telemetry_service_interval_ =
				std::min(telemetry_service_interval_, worker.health_poll_interval);
		}
		if (telemetry_service_interval_ <= std::chrono::steady_clock::duration::zero()) {
			return status::failed_precondition("runtime telemetry service interval is not exact");
		}
		auto telemetry_deadline =
			checked_transition_deadline(std::chrono::steady_clock::now(), telemetry_service_interval_);
		if (!telemetry_deadline.is_ok()) {
			return telemetry_deadline.error();
		}
		next_telemetry_service_ = telemetry_deadline.value();

		worker_contexts_ = std::make_unique<worker_lifecycle_context[]>(worker_count);
		worker_count_ = worker_count;
		auto services = modules_->start_lifecycle_services(*providers_);
		if (!services.is_ok()) {
			return services;
		}
		if (topology_->transition_topology.policy.enabled) {
			auto preparation_or =
				epoch_transition_preparation::create(*modules_, topology_->transition_topology.policy);
			if (!preparation_or.is_ok()) {
				return preparation_or.error();
			}
			preparation_ = std::move(preparation_or).value();
			if (transition_certificate_ == nullptr || quiescence_domain_ == nullptr) {
				return status::internal_error(
					"transition completion lacks its exact certificate or reader domain");
			}
			auto completion_or = epoch_transition_completion::create(
				runtime_generation_, *coordinator_, *transition_certificate_, *quiescence_domain_,
				*preparation_, *modules_, runtime_status_, *telemetry_aggregator_, protocol_faults_,
				topology_->transition_topology.policy);
			if (!completion_or.is_ok()) {
				return completion_or.error();
			}
			completion_ = std::move(completion_or).value();
		}
		auto telemetry_source_or = runtime_telemetry_snapshot_source::create(
			runtime_generation_, *topology_, *providers_, *telemetry_aggregator_, runtime_status_,
			*coordinator_, *transition_certificate_, completion_.get(), protocol_faults_);
		if (!telemetry_source_or.is_ok()) {
			return telemetry_source_or.error();
		}
		auto source_published =
			telemetry_source_owner_.publish(runtime_generation_, std::move(telemetry_source_or).value());
		if (!source_published.is_ok()) {
			return source_published;
		}
		auto consumer_binding = command_mailbox_->bind_consumer_to_current_thread();
		if (!consumer_binding.is_ok()) {
			return consumer_binding;
		}
		epoch_transition_progress_snapshot coordinator_progress{};
		if (coordinator_->try_read_progress(coordinator_progress) != publication_read_result::AVAILABLE ||
		    coordinator_progress.phase != epoch_transition_phase::AWAITING_BOOTSTRAP ||
		    coordinator_progress.active_epoch != 0u || coordinator_progress.target_epoch != 0u ||
		    coordinator_progress.execution_participant_count != worker_count_) {
			return status::internal_error(
				"coordinator truth is incomplete before CONTROL_READY publication");
		}
		if (!runtime_status_.publish_control_ready(runtime_generation_,
							   coordinator_progress.execution_participant_count)) {
			return status::internal_error("failed to publish initial CONTROL_READY runtime status");
		}
		return status::ok();
	}

	/**
	 * @brief Clean every constructed owner, then terminate without process reuse.
	 *
	 * @param failure Exact post-materialization failure status to diagnose.
	 */
	[[noreturn]] void fail_stop_construction(const status &failure) noexcept
	{
		log_materialized_failure(failure);
		retire_construction_owners_();
		std::terminate();
	}

	/**
	 * @brief Fail stop after an exception without allocating a diagnostic status.
	 *
	 * @param message Stable bounded diagnostic.
	 */
	[[noreturn]] void fail_stop_construction(const char *message) noexcept
	{
		log_materialized_failure(message);
		retire_construction_owners_();
		std::terminate();
	}

    private:
	/**
	 * @brief Materialize exact-NUMA telemetry channels and worker bank owners.
	 * @return OK after complete worker/context binding; otherwise no live bank exists.
	 */
	[[nodiscard]] status materialize_worker_telemetry_()
	{
		if (!telemetry_channels_.empty() || !worker_telemetry_.empty()) {
			return status::internal_error("worker telemetry materialization requires empty owner tables");
		}
		const auto &transition = topology_->transition_topology;
		if (!transition.lifecycle_services.has_value()) {
			return status::failed_precondition("worker telemetry requires the exact lifecycle coordinator");
		}
		const uint32_t coordinator_index = transition.lifecycle_services->coordinator_service_index;
		if (coordinator_index >= transition.runtime_services.size()) {
			return status::internal_error("worker telemetry coordinator index is invalid");
		}
		const int32_t coordinator_numa = transition.runtime_services[coordinator_index].numa_node;
		if (coordinator_numa < 0 || topology_->worker_schedules.size() != transition.workers.size()) {
			return status::failed_precondition("worker telemetry topology is incomplete");
		}
		std::vector<std::size_t> module_counts(transition.workers.size(), 0u);
		for (const auto &context : topology_->module_contexts) {
			if (context.worker_index >= module_counts.size()) {
				return status::failed_precondition("module telemetry references an unknown worker");
			}
			++module_counts[context.worker_index];
		}
		telemetry_channels_.reserve(transition.workers.size());
		worker_telemetry_.reserve(transition.workers.size());
		std::vector<worker_telemetry_channel *> channel_views;
		channel_views.reserve(transition.workers.size());
		for (std::size_t index = 0u; index < transition.workers.size(); ++index) {
			const auto &worker = transition.workers[index];
			const auto &schedule = topology_->worker_schedules[index];
			const auto cadence =
				std::chrono::duration_cast<std::chrono::nanoseconds>(worker.health_poll_interval);
			if (worker.worker_index != index || worker.numa_node < 0 || schedule.worker_index != index ||
			    cadence.count() <= 0 ||
			    std::chrono::duration_cast<std::chrono::steady_clock::duration>(cadence) !=
				    worker.health_poll_interval) {
				return status::failed_precondition(
					"worker telemetry cadence or ownership is not exact");
			}
			auto channel_or = worker_telemetry_channel::create(
				static_cast<uint32_t>(index), module_counts[index], worker.numa_node, coordinator_numa);
			if (!channel_or.is_ok()) {
				return channel_or.error();
			}
			channel_views.push_back(channel_or->get());
			telemetry_channels_.push_back(std::move(channel_or).value());
			std::vector<uint32_t> stream_indices;
			stream_indices.reserve(schedule.rx_stream_indices.size() + schedule.tx_stream_indices.size());
			std::merge(schedule.rx_stream_indices.begin(), schedule.rx_stream_indices.end(),
				   schedule.tx_stream_indices.begin(), schedule.tx_stream_indices.end(),
				   std::back_inserter(stream_indices));
			auto telemetry_or = worker_runtime_telemetry::create(
				runtime_generation_, static_cast<uint32_t>(index), worker.numa_node,
				schedule.stage_instance_indices, stream_indices, static_cast<uint64_t>(cadence.count()),
				*telemetry_channels_.back());
			if (!telemetry_or.is_ok()) {
				return telemetry_or.error();
			}
			worker_telemetry_.push_back(std::move(telemetry_or).value());
		}
		return modules_->bind_telemetry_channels(runtime_generation_, channel_views);
	}

	/**
	 * @brief Reserve every worker and module target bank all-or-none.
	 * @param from_epoch Exact active epoch.
	 * @param to_epoch Exact PREPARING target epoch.
	 * @return OK after complete reservation; failure rolls back the exact prefix.
	 */
	[[nodiscard]] status reserve_transition_telemetry_(uint64_t from_epoch, uint64_t to_epoch) noexcept
	{
		if (telemetry_reservation_epoch_ != 0u || from_epoch == 0u || to_epoch <= from_epoch ||
		    worker_telemetry_.size() != topology_->transition_topology.workers.size()) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"runtime telemetry target reservation identity is invalid"));
		}
		std::size_t reserved_workers = 0u;
		for (const auto &owner : worker_telemetry_) {
			if (owner == nullptr) {
				std::terminate();
			}
			auto reserved = owner->reserve_target_epoch(from_epoch, to_epoch);
			if (!reserved.is_ok()) {
				while (reserved_workers != 0u) {
					--reserved_workers;
					worker_telemetry_[reserved_workers]->discard_target_epoch(to_epoch);
				}
				return reserved;
			}
			++reserved_workers;
		}
		auto modules_reserved = modules_->reserve_transition_telemetry(from_epoch, to_epoch);
		if (!modules_reserved.is_ok()) {
			while (reserved_workers != 0u) {
				--reserved_workers;
				worker_telemetry_[reserved_workers]->discard_target_epoch(to_epoch);
			}
			return modules_reserved;
		}
		telemetry_reservation_epoch_ = to_epoch;
		return status::ok();
	}

	/**
	 * @brief Release one unused complete target reservation after module cleanup.
	 * @param to_epoch Exact aborted target epoch.
	 */
	void discard_transition_telemetry_(uint64_t to_epoch) noexcept
	{
		if (to_epoch == 0u || telemetry_reservation_epoch_ != to_epoch) {
			std::terminate();
		}
		modules_->discard_transition_telemetry(to_epoch);
		for (const auto &owner : worker_telemetry_) {
			owner->discard_target_epoch(to_epoch);
		}
		telemetry_reservation_epoch_ = 0u;
	}

	/**
	 * @brief Service one bounded cold telemetry prefix and schedule its next probe.
	 * @param now Exact coordinator monotonic sample.
	 */
	void service_telemetry_(std::chrono::steady_clock::time_point now) noexcept
	{
		if (telemetry_aggregator_ == nullptr ||
		    telemetry_service_interval_ <= std::chrono::steady_clock::duration::zero()) {
			std::terminate();
		}
		(void)telemetry_aggregator_->service(common::runtime_sizing::PACKET_MAX_BURST_SIZE);
		const auto delay = telemetry_aggregator_->work_pending() ? std::chrono::milliseconds(1) :
									   telemetry_service_interval_;
		auto deadline = checked_transition_deadline(now, delay);
		if (!deadline.is_ok()) {
			std::terminate();
		}
		next_telemetry_service_ = deadline.value();
	}

	/**
	 * @brief Materialize every slab, channel, hold, and role-correct endpoint policy exactly once.
	 *
	 * The compiled worker's inbound/outbound boundary order is the sole slot
	 * assignment authority. All worker-local slabs exist before the first
	 * channel claims a stable slot. Every channel and sender/receiver policy
	 * claim exists before each slab seals and before kernel creation.
	 *
	 * @return OK after complete two-directional coverage and sealing; otherwise
	 *         a fail-closed construction status.
	 */
	[[nodiscard]] status materialize_boundary_transport_()
	{
		if (!endpoint_slabs_.empty() || !boundaries_.empty() || !boundary_views_.empty() ||
		    !future_output_holds_.empty() || !future_output_hold_views_.empty() || !boundary_senders_.empty() ||
		    !boundary_receivers_.empty()) {
			return status::internal_error(
				"boundary transport materialization requires one empty owner graph");
		}
		const auto &workers = topology_->transition_topology.workers;
		const auto &compiled_boundaries = topology_->transition_topology.boundaries;
		constexpr std::size_t UNASSIGNED_SLOT = std::numeric_limits<std::size_t>::max();
		std::vector<std::size_t> sender_slots(compiled_boundaries.size(), UNASSIGNED_SLOT);
		std::vector<std::size_t> receiver_slots(compiled_boundaries.size(), UNASSIGNED_SLOT);

		endpoint_slabs_.reserve(workers.size());
		for (std::size_t worker_index = 0u; worker_index < workers.size(); ++worker_index) {
			const auto &worker = workers[worker_index];
			if (worker.worker_index != worker_index || worker.numa_node < 0) {
				return status::failed_precondition(
					"boundary endpoint slab worker identity or NUMA ownership is malformed");
			}
			for (std::size_t slot = 0u; slot < worker.outbound_boundary_indices.size(); ++slot) {
				const uint32_t boundary_index = worker.outbound_boundary_indices[slot];
				if (boundary_index >= compiled_boundaries.size() ||
				    sender_slots[boundary_index] != UNASSIGNED_SLOT ||
				    compiled_boundaries[boundary_index].sender_worker_index != worker_index) {
					return status::failed_precondition(
						"boundary sender slot coverage does not equal compiled worker ownership");
				}
				sender_slots[boundary_index] = slot;
			}
			for (std::size_t slot = 0u; slot < worker.inbound_boundary_indices.size(); ++slot) {
				const uint32_t boundary_index = worker.inbound_boundary_indices[slot];
				if (boundary_index >= compiled_boundaries.size() ||
				    receiver_slots[boundary_index] != UNASSIGNED_SLOT ||
				    compiled_boundaries[boundary_index].receiver_worker_index != worker_index) {
					return status::failed_precondition(
						"boundary receiver slot coverage does not equal compiled worker ownership");
				}
				receiver_slots[boundary_index] = slot;
			}

			auto slab_or = boundary_epoch_worker_slab::create(static_cast<uint32_t>(worker_index),
									  worker.numa_node,
									  worker.outbound_boundary_indices.size(),
									  worker.inbound_boundary_indices.size());
			if (!slab_or.is_ok()) {
				return slab_or.error();
			}
			endpoint_slabs_.push_back(std::move(slab_or).value());
		}

		boundary_views_.reserve(compiled_boundaries.size());
		boundaries_.reserve(compiled_boundaries.size());
		future_output_hold_views_.reserve(compiled_boundaries.size());
		future_output_holds_.reserve(compiled_boundaries.size());
		for (std::size_t index = 0u; index < compiled_boundaries.size(); ++index) {
			const auto &facts = compiled_boundaries[index];
			if (facts.boundary_index != index || facts.sender_worker_index >= endpoint_slabs_.size() ||
			    facts.receiver_worker_index >= endpoint_slabs_.size() ||
			    sender_slots[index] == UNASSIGNED_SLOT || receiver_slots[index] == UNASSIGNED_SLOT) {
				return status::failed_precondition(
					"boundary endpoint slab coverage is incomplete or noncanonical");
			}
			auto boundary_or = boundary_epoch_channel::create(facts, runtime_generation_,
									  *endpoint_slabs_[facts.sender_worker_index],
									  sender_slots[index],
									  *endpoint_slabs_[facts.receiver_worker_index],
									  receiver_slots[index]);
			if (!boundary_or.is_ok()) {
				return boundary_or.error();
			}

			const int32_t sender_numa = workers[facts.sender_worker_index].numa_node;
			auto hold_or = boundary_future_output_hold::create(facts, sender_numa);
			if (!hold_or.is_ok()) {
				return hold_or.error();
			}
			boundary_views_.push_back(boundary_or->get());
			boundaries_.push_back(std::move(boundary_or).value());
			future_output_hold_views_.push_back(hold_or->get());
			future_output_holds_.push_back(std::move(hold_or).value());
		}

		boundary_senders_.reserve(workers.size());
		boundary_receivers_.reserve(workers.size());
		for (std::size_t worker_index = 0u; worker_index < workers.size(); ++worker_index) {
			std::vector<boundary_epoch_channel *> sender_channels;
			std::vector<boundary_future_output_hold *> sender_holds;
			const auto &outbound = workers[worker_index].outbound_boundary_indices;
			sender_channels.reserve(outbound.size());
			sender_holds.reserve(outbound.size());
			for (const uint32_t boundary_index : outbound) {
				if (boundary_index >= boundary_views_.size() ||
				    boundary_index >= future_output_hold_views_.size()) {
					return status::failed_precondition(
						"boundary sender policy references an unknown compiled edge");
				}
				sender_channels.push_back(boundary_views_[boundary_index]);
				sender_holds.push_back(future_output_hold_views_[boundary_index]);
			}
			auto sender_or = worker_boundary_sender::create(static_cast<uint32_t>(worker_index),
									runtime_generation_, sender_channels,
									sender_holds);
			if (!sender_or.is_ok()) {
				return sender_or.error();
			}
			boundary_senders_.push_back(std::move(sender_or).value());

			std::vector<boundary_epoch_channel *> receiver_channels;
			const auto &inbound = workers[worker_index].inbound_boundary_indices;
			receiver_channels.reserve(inbound.size());
			for (const uint32_t boundary_index : inbound) {
				if (boundary_index >= boundary_views_.size()) {
					return status::failed_precondition(
						"boundary receiver policy references an unknown compiled edge");
				}
				receiver_channels.push_back(boundary_views_[boundary_index]);
			}
			auto receiver_or = worker_boundary_receiver::create(static_cast<uint32_t>(worker_index),
									    runtime_generation_, receiver_channels);
			if (!receiver_or.is_ok()) {
				return receiver_or.error();
			}
			boundary_receivers_.push_back(std::move(receiver_or).value());
		}

		for (const auto &slab : endpoint_slabs_) {
			if (slab == nullptr) {
				return status::internal_error("boundary endpoint slab table contains an empty owner");
			}
			const auto sealed = slab->seal();
			if (!sealed.is_ok()) {
				return sealed;
			}
		}
		return status::ok();
	}

	/**
	 * @brief Bind exact worker readers and construct the immutable certificate graph.
	 *
	 * Kernels already own every publication source. The domain binds their stable
	 * reader records in frozen-worker order, then the certificate revalidates all
	 * worker/reader/boundary relations in both directions before CONTROL_READY.
	 *
	 * @return OK after complete graph construction or a fail-closed cold status.
	 */
	[[nodiscard]] status materialize_transition_certificate_()
	{
		if (quiescence_domain_ != nullptr || transition_certificate_ != nullptr || kernels_.empty() ||
		    kernels_.size() != coordinator_->participants().execution_participant_count()) {
			return status::internal_error(
				"transition certificate materialization requires one complete unbound kernel set");
		}
		std::vector<kinetum::algo::quiescence_reader *> readers;
		readers.reserve(kernels_.size());
		for (std::size_t worker_index = 0u; worker_index < kernels_.size(); ++worker_index) {
			if (kernels_[worker_index] == nullptr ||
			    kernels_[worker_index]->worker_index() != worker_index) {
				return status::failed_precondition(
					"transition certificate kernel set is not one compact worker projection");
			}
			readers.push_back(&kernels_[worker_index]->quiescence_reader_registration());
		}
		try {
			quiescence_domain_ = std::make_unique<kinetum::algo::quiescence_domain>(readers);
		} catch (const std::invalid_argument &) {
			return status::failed_precondition(
				"transition certificate reader domain rejected frozen worker membership");
		} catch (const std::length_error &) {
			return status(status_code::OUT_OF_RANGE,
				      "transition certificate reader domain exceeds a bounded host container");
		} catch (const std::bad_alloc &) {
			return status::resource_exhausted("transition certificate reader domain allocation failed");
		}

		std::vector<epoch_transition_certificate_worker_source> sources;
		sources.reserve(kernels_.size());
		for (const auto &kernel : kernels_) {
			sources.push_back(kernel->transition_certificate_source());
		}
		auto certificate_or = epoch_transition_certificate::create(runtime_generation_,
									   coordinator_->participants(), sources,
									   boundary_views_, *quiescence_domain_);
		if (!certificate_or.is_ok()) {
			return certificate_or.error();
		}
		transition_certificate_ = std::move(certificate_or).value();
		if (transition_certificate_->execution_participant_count() != kernels_.size() ||
		    transition_certificate_->boundary_count() != boundary_views_.size() ||
		    transition_certificate_->reader_count() != kernels_.size()) {
			return status::internal_error(
				"transition certificate did not retain exact frozen source cardinality");
		}
		return status::ok();
	}

	/** @brief Retire every owner created after provider materialization. */
	void retire_construction_owners_() noexcept
	{
		if (preparation_ && preparation_->active()) {
			std::terminate();
		}
		if (completion_ && completion_->active()) {
			std::terminate();
		}
		telemetry_source_owner_.retire();
		completion_.reset();
		preparation_.reset();
		if (modules_ && modules_->lifecycle_services_running()) {
			modules_->stop_lifecycle_services();
		}
		transition_certificate_.reset();
		quiescence_domain_.reset();
		kernels_.clear();
		telemetry_aggregator_.reset();
		if (modules_ != nullptr && !telemetry_channels_.empty()) {
			modules_->unbind_telemetry_channels();
		}
		worker_telemetry_.clear();
		telemetry_channels_.clear();
		worker_commands_.reset();
		boundary_senders_.clear();
		boundary_receivers_.clear();
		future_output_hold_views_.clear();
		future_output_holds_.clear();
		boundary_views_.clear();
		boundaries_.clear();
		endpoint_slabs_.clear();
		worker_contexts_.reset();
		worker_count_ = 0;
		modules_.reset();
		providers_.reset();
	}

    public:
	/**
	 * @brief Admit, prepare, activate, and publish one exact fixed epoch.
	 *
	 * @param request Complete six-field durable CP authority.
	 * @return Exact activated bootstrap observation or a pre-activation status.
	 */
	[[nodiscard]] status_or<fixed_epoch_bootstrap_result>
	bootstrap(const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request)
	{
		try {
			if (command_mailbox_->current_thread_is_consumer()) {
				return status::failed_precondition(
					"coordinator consumer cannot submit Bootstrap to itself");
			}
			if (command_mailbox_->admission_closed()) {
				return status::unavailable("packet runtime generation is shutting down");
			}
			epoch_transition_progress_snapshot progress{};
			const auto progress_read = coordinator_->try_read_progress(progress);
			if (progress_read == publication_read_result::INVALID_IDENTITY ||
			    progress_read == publication_read_result::INVALID_STATE) {
				return status::data_loss(
					"coordinator publication is invalid before Bootstrap admission");
			}
			if (progress_read == publication_read_result::AVAILABLE &&
			    progress.phase == epoch_transition_phase::IDLE && progress.active_epoch != 0u) {
				return status::unavailable("fixed-epoch bootstrap is unavailable after PACKET_READY");
			}

			bootstrap_command_context context;
			{
				auto validated_or = common::validate_bootstrap_config_snapshot_request(request);
				if (!validated_or.is_ok()) {
					return validated_or.error();
				}
				auto validated = std::move(validated_or).value();
				if (request.plan_content_hash() != coordinator_->participants().plan_content_hash()) {
					return status::failed_precondition(
						"bootstrap plan identity does not match the materialized generation");
				}
				auto plan_bound_or = common::canonicalize_config_snapshot(request.snapshot(), plan_);
				if (!plan_bound_or.is_ok()) {
					return plan_bound_or.error();
				}
				if (plan_bound_or->serialized_bytes != validated.snapshot.serialized_bytes ||
				    plan_bound_or->validation_hash != validated.snapshot.validation_hash) {
					return status::data_loss(
						"bootstrap snapshot is not the exact canonical plan-bound representation");
				}
				auto artifact_or = config_snapshot_artifact::create(validated.snapshot);
				if (!artifact_or.is_ok()) {
					return artifact_or.error();
				}
				context.serialized_request = std::move(validated.serialized_request);
				context.validation_hash = validated.snapshot.validation_hash;
				context.watermarks = validated.watermarks;
				context.active_epoch = validated.active_epoch;
				context.artifact = std::move(artifact_or).value();
			}
			const auto submitted = command_mailbox_->submit(
				epoch_transition_command{epoch_transition_command_kind::BOOTSTRAP, &context});
			if (!submitted.is_ok()) {
				return submitted;
			}
			context.wait_for_completion();
			if (!context.result.has_value()) {
				std::terminate();
			}
			return std::move(context.result).value();
		} catch (const std::bad_alloc &) {
			return status::resource_exhausted("Bootstrap producer admission exhausted memory");
		} catch (...) {
			return status::internal_error("Bootstrap producer admission raised an unexpected exception");
		}
	}

	/** @copydoc partitioned_runtime::prepare_epoch_transition */
	[[nodiscard]] epoch_transition_operation_result
	prepare_epoch_transition(const kinetum::dataplane::v1::PrepareConfigSnapshotRequest &request) noexcept
	{
		try {
			if (command_mailbox_->current_thread_is_consumer()) {
				return fixed_operation_failure(
					status::failed_precondition(kinetum::common::static_status_text(
						"coordinator consumer cannot submit PREPARE to itself")),
					common::transition_identity_resolution::STATE_UNAVAILABLE);
			}
			const auto wire_status =
				validate_transition_request_wire(request, "PrepareConfigSnapshotRequest");
			if (!wire_status.is_ok()) {
				return fixed_operation_failure(wire_status,
							       common::transition_identity_resolution::INVALID);
			}
			transaction_command_context context;
			{
				auto canonical_or = common::canonicalize_config_snapshot(request.snapshot(), plan_);
				if (!canonical_or.is_ok()) {
					return fixed_operation_failure(canonical_or.error(),
								       common::transition_identity_resolution::INVALID);
				}
				const std::string_view validation_hash(
					reinterpret_cast<const char *>(canonical_or->validation_hash.data()),
					canonical_or->validation_hash.size());
				auto identity_or = common::make_epoch_transition_identity(request.mutation_sequence(),
											  request.target_epoch(),
											  validation_hash,
											  request.idempotency_key());
				if (!identity_or.is_ok()) {
					return fixed_operation_failure(identity_or.error(),
								       common::transition_identity_resolution::INVALID);
				}
				auto candidate_or = config_snapshot_artifact::create(canonical_or.value());
				if (!candidate_or.is_ok()) {
					return fixed_operation_failure(candidate_or.error(),
								       common::transition_identity_resolution::INVALID);
				}
				context.identity = identity_or.value();
				context.candidate = std::move(candidate_or).value();
			}
			const auto submitted = command_mailbox_->submit(
				epoch_transition_command{epoch_transition_command_kind::PREPARE, &context});
			if (!submitted.is_ok()) {
				auto failure = fixed_operation_failure(
					submitted, common::transition_identity_resolution::STATE_UNAVAILABLE);
				failure.observation.identity = context.identity;
				return failure;
			}
			context.wait_for_completion();
			return context.result;
		} catch (const std::bad_alloc &) {
			return fixed_operation_failure(status_code::RESOURCE_EXHAUSTED,
						       "PREPARE producer admission exhausted memory",
						       common::transition_identity_resolution::INVALID);
		} catch (...) {
			return fixed_operation_failure(status_code::INTERNAL_ERROR,
						       "PREPARE producer admission raised an unexpected exception",
						       common::transition_identity_resolution::INVALID);
		}
	}

	/** @copydoc partitioned_runtime::activate_epoch_transition */
	[[nodiscard]] epoch_transition_operation_result
	activate_epoch_transition(const kinetum::dataplane::v1::ActivateConfigSnapshotRequest &request) noexcept
	{
		return submit_identity_command_(epoch_transition_command_kind::ACTIVATE, request,
						"ActivateConfigSnapshotRequest");
	}

	/** @copydoc partitioned_runtime::abort_epoch_transition */
	[[nodiscard]] epoch_transition_operation_result
	abort_epoch_transition(const kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest &request) noexcept
	{
		return submit_identity_command_(epoch_transition_command_kind::ABORT, request,
						"AbortPreparedConfigSnapshotRequest");
	}

	/** @copydoc partitioned_runtime::query_epoch_transition */
	[[nodiscard]] epoch_transition_operation_result
	query_epoch_transition(const kinetum::dataplane::v1::GetEpochTransitionStatusRequest &request) noexcept
	{
		return submit_identity_command_(epoch_transition_command_kind::STATUS, request,
						"GetEpochTransitionStatusRequest");
	}

	/** @copydoc partitioned_runtime::command_notification_descriptor */
	[[nodiscard]] int command_notification_descriptor() const noexcept
	{
		return command_mailbox_->notification_descriptor();
	}

	/** @copydoc partitioned_runtime::lifecycle_notification_descriptor */
	[[nodiscard]] std::optional<int> lifecycle_notification_descriptor() const noexcept
	{
		if (modules_ == nullptr) {
			return std::nullopt;
		}
		return modules_->lifecycle_notification_descriptor();
	}

	/** @copydoc partitioned_runtime::service_command_notifications */
	[[nodiscard]] status service_command_notifications() noexcept
	{
		service_telemetry_(std::chrono::steady_clock::now());
		auto notification = command_mailbox_->consume_notification();
		if (!notification.is_ok()) {
			return std::move(notification).error();
		}
		if (notification.value() == 0u) {
			return status::ok();
		}
		epoch_transition_command command;
		if (!command_mailbox_->try_take(command)) {
			std::terminate();
		}
		execute_command_(command);
		command_mailbox_->defer_notifications(notification.value() - 1u);
		if (completion_ != nullptr && completion_->next_deadline().has_value()) {
			const auto progressed = completion_->service_progress(std::chrono::steady_clock::now());
			if (!progressed.is_ok()) {
				log_materialized_failure(progressed);
				std::terminate();
			}
		}
		complete_activate_context_if_terminal_();
		return status::ok();
	}

	/** @copydoc partitioned_runtime::service_lifecycle_notifications */
	[[nodiscard]] status service_lifecycle_notifications() noexcept
	{
		if (!command_mailbox_->current_thread_is_consumer()) {
			std::terminate();
		}
		if (modules_ == nullptr) {
			return status::unavailable(kinetum::common::static_status_text(
				"lifecycle result service is unavailable after generation teardown"));
		}
		service_telemetry_(std::chrono::steady_clock::now());
		auto notification_or = modules_->consume_lifecycle_notification();
		if (!notification_or.is_ok()) {
			return std::move(notification_or).error();
		}
		if (preparation_ != nullptr && preparation_->active()) {
			auto serviced = preparation_->service_results();
			if (!serviced.is_ok() &&
			    preparation_->phase() != epoch_transition_preparation_phase::FAILED_STOP) {
				return serviced;
			}
			advance_preparation_or_terminate_();
			return status::ok();
		}
		if (completion_ != nullptr && completion_->active() && completion_->ownership_withdrawn()) {
			const auto serviced = completion_->service_results(std::chrono::steady_clock::now());
			if (!serviced.is_ok()) {
				log_materialized_failure(serviced);
				std::terminate();
			}
		}
		if (completion_ != nullptr && completion_->next_deadline().has_value()) {
			const auto progressed = completion_->service_progress(std::chrono::steady_clock::now());
			if (!progressed.is_ok()) {
				log_materialized_failure(progressed);
				std::terminate();
			}
		}
		complete_activate_context_if_terminal_();
		return status::ok();
	}

	/** @copydoc partitioned_runtime::service_control_deadline */
	[[nodiscard]] status service_control_deadline() noexcept
	{
		if (!command_mailbox_->current_thread_is_consumer()) {
			std::terminate();
		}
		const auto telemetry_now = std::chrono::steady_clock::now();
		if (next_telemetry_service_.has_value() && telemetry_now >= *next_telemetry_service_) {
			service_telemetry_(telemetry_now);
		}
		if (preparation_ != nullptr && preparation_->active()) {
			auto phase = preparation_->phase();
			if (phase == epoch_transition_preparation_phase::CANCELLING ||
			    phase == epoch_transition_preparation_phase::RETIRING) {
				auto drained = service_lifecycle_notifications();
				if (!drained.is_ok() || !preparation_->active()) {
					return drained;
				}
			}
			const auto now = std::chrono::steady_clock::now();
			bool prepared_cleanup = false;
			if (preparation_->phase() == epoch_transition_preparation_phase::PREPARED) {
				const auto deadline = preparation_->next_deadline();
				if (deadline.has_value() && now >= *deadline) {
					begin_prepared_cleanup_or_terminate_();
					prepared_cleanup = true;
				}
			}
			auto serviced = preparation_->service_deadline(now);
			if (!serviced.is_ok() &&
			    preparation_->phase() != epoch_transition_preparation_phase::FAILED_STOP) {
				if (prepared_cleanup) {
					std::terminate();
				}
				return serviced;
			}
			advance_preparation_or_terminate_();
			if (preparation_ != nullptr && preparation_->active()) {
				phase = preparation_->phase();
				if (phase == epoch_transition_preparation_phase::CANCELLING ||
				    phase == epoch_transition_preparation_phase::RETIRING) {
					return service_lifecycle_notifications();
				}
			}
			return status::ok();
		}
		if (completion_ != nullptr && completion_->active()) {
			const auto serviced = completion_->service_progress(std::chrono::steady_clock::now());
			if (!serviced.is_ok()) {
				log_materialized_failure(serviced);
				std::terminate();
			}
			complete_activate_context_if_terminal_();
		}
		return status::ok();
	}

	/** @copydoc partitioned_runtime::next_control_deadline */
	[[nodiscard]] std::optional<std::chrono::steady_clock::time_point> next_control_deadline() const noexcept
	{
		if (!command_mailbox_->current_thread_is_consumer()) {
			std::terminate();
		}
		const auto preparation_deadline = preparation_ != nullptr ? preparation_->next_deadline() :
									    std::nullopt;
		const auto completion_deadline = completion_ != nullptr ? completion_->next_deadline() : std::nullopt;
		std::optional<std::chrono::steady_clock::time_point> result = next_telemetry_service_;
		for (const auto &candidate : {preparation_deadline, completion_deadline}) {
			if (candidate.has_value() && (!result.has_value() || *candidate < *result)) {
				result = candidate;
			}
		}
		return result;
	}

	/** @copydoc partitioned_runtime::close_command_admission */
	void close_command_admission() noexcept
	{
		command_mailbox_->close_admission();
		if (!command_mailbox_->consume_notification().is_ok()) {
			std::terminate();
		}
		epoch_transition_command command;
		while (command_mailbox_->try_take(command)) {
			complete_unavailable_(command);
		}
	}

    private:
	/**
	 * @brief Validate, submit, and unconditionally await one fixed identity command.
	 *
	 * @param kind ACTIVATE, ABORT, or STATUS command kind.
	 * @tparam request_type Generated exact-identity request type.
	 * @param request Complete candidate request tree.
	 * @param contract_name Stable generated-message identity for diagnostics.
	 * @return Fixed typed command result.
	 */
	template <typename request_type>
	[[nodiscard]] epoch_transition_operation_result
	submit_identity_command_(epoch_transition_command_kind kind, const request_type &request,
				 std::string_view contract_name) noexcept
	{
		try {
			if (kind != epoch_transition_command_kind::ACTIVATE &&
			    kind != epoch_transition_command_kind::ABORT &&
			    kind != epoch_transition_command_kind::STATUS) {
				std::terminate();
			}
			if (command_mailbox_->current_thread_is_consumer()) {
				return fixed_operation_failure(
					status::failed_precondition(kinetum::common::static_status_text(
						"coordinator consumer cannot submit an identity command to itself")),
					common::transition_identity_resolution::STATE_UNAVAILABLE);
			}
			const auto wire_status = validate_transition_request_wire(request, contract_name);
			if (!wire_status.is_ok()) {
				return fixed_operation_failure(wire_status,
							       common::transition_identity_resolution::INVALID);
			}
			const std::string_view validation_hash = request.validation_hash();
			const std::string_view idempotency_key = request.idempotency_key();
			auto identity_or = common::make_epoch_transition_identity(
				request.mutation_sequence(), request.epoch(), validation_hash, idempotency_key);
			if (!identity_or.is_ok()) {
				return fixed_operation_failure(identity_or.error(),
							       common::transition_identity_resolution::INVALID);
			}

			transaction_command_context context;
			context.identity = identity_or.value();
			const auto submitted = command_mailbox_->submit(epoch_transition_command{kind, &context});
			if (!submitted.is_ok()) {
				auto failure = fixed_operation_failure(
					submitted, common::transition_identity_resolution::STATE_UNAVAILABLE);
				failure.observation.identity = context.identity;
				return failure;
			}
			context.wait_for_completion();
			return context.result;
		} catch (const std::bad_alloc &) {
			return fixed_operation_failure(status_code::RESOURCE_EXHAUSTED,
						       "identity-command producer admission exhausted memory",
						       common::transition_identity_resolution::INVALID);
		} catch (...) {
			return fixed_operation_failure(
				status_code::INTERNAL_ERROR,
				"identity-command producer admission raised an unexpected exception",
				common::transition_identity_resolution::INVALID);
		}
	}

	/**
	 * @brief Execute one queue-owned command and publish completion exactly once.
	 *
	 * @param command Exact taken command record.
	 */
	void execute_command_(const epoch_transition_command &command) noexcept
	{
		if (command.context == nullptr) {
			std::terminate();
		}
		bool completion_deferred = false;
		try {
			switch (command.kind) {
			case epoch_transition_command_kind::BOOTSTRAP: {
				auto *context = static_cast<bootstrap_command_context *>(command.context);
				context->result.emplace(bootstrap_owned_(*context));
				break;
			}
			case epoch_transition_command_kind::PREPARE: {
				auto *context = static_cast<transaction_command_context *>(command.context);
				completion_deferred = execute_prepare_command_(*context);
				break;
			}
			case epoch_transition_command_kind::ACTIVATE: {
				auto *context = static_cast<transaction_command_context *>(command.context);
				completion_deferred = execute_activate_command_(*context);
				break;
			}
			case epoch_transition_command_kind::ABORT: {
				auto *context = static_cast<transaction_command_context *>(command.context);
				completion_deferred = execute_abort_command_(*context);
				break;
			}
			case epoch_transition_command_kind::STATUS: {
				auto *context = static_cast<transaction_command_context *>(command.context);
				context->result = preparation_cleanup_in_progress_(context->identity) ?
							  cleanup_observation_unavailable_(context->identity) :
							  coordinator_->query_transaction(context->identity);
				break;
			}
			default:
				std::terminate();
			}
		} catch (...) {
			log_materialized_failure("coordinator command execution raised an exception");
			std::terminate();
		}
		if (!completion_deferred) {
			command_mailbox_->complete(command.context);
		}
	}

	/**
	 * @brief Admit and start one exact asynchronous PREPARE command.
	 * @param context Consumer-owned command context.
	 * @return true when completion was deferred or already published by the
	 *         preparation advancement path; false for immediate caller completion.
	 */
	[[nodiscard]] bool execute_prepare_command_(transaction_command_context &context) noexcept
	{
		if (preparation_cleanup_in_progress_(context.identity)) {
			context.result = cleanup_observation_unavailable_(context.identity);
			return false;
		}
		const auto now = std::chrono::steady_clock::now();
		const uint64_t admitted_ns = monotonic_nanoseconds(now);
		if (admitted_ns == 0u) {
			std::terminate();
		}
		context.result = coordinator_->admit_prepare(context.identity, context.candidate, admitted_ns);
		if (!context.result.is_ok() ||
		    context.result.observation.resolution != common::transition_identity_resolution::ADMISSIBLE) {
			return false;
		}
		if (preparation_ == nullptr || preparation_->active() || held_prepare_context_ != nullptr) {
			std::terminate();
		}
		const auto *snapshot = coordinator_->preparing_candidate_snapshot(context.identity);
		if (snapshot == nullptr) {
			std::terminate();
		}
		const uint64_t from_epoch = coordinator_->active_epoch();
		const auto telemetry_reserved =
			reserve_transition_telemetry_(from_epoch, context.identity.target_epoch);
		if (!telemetry_reserved.is_ok()) {
			const uint64_t terminal_ns = monotonic_nanoseconds(std::chrono::steady_clock::now());
			if (terminal_ns == 0u) {
				std::terminate();
			}
			context.result = coordinator_->abort_before_commit(
				context.identity, terminal_ns, epoch_transition_failure_code::PREPARE_FAILURE,
				telemetry_reserved.message());
			return false;
		}
		const auto started = preparation_->begin(context.identity, *snapshot, now);
		if (!started.is_ok()) {
			discard_transition_telemetry_(context.identity.target_epoch);
			const uint64_t terminal_ns = monotonic_nanoseconds(std::chrono::steady_clock::now());
			if (terminal_ns == 0u) {
				std::terminate();
			}
			context.result = coordinator_->abort_before_commit(
				context.identity, terminal_ns, epoch_transition_failure_code::PREPARE_FAILURE,
				started.message());
			if (!context.result.is_ok() ||
			    context.result.observation.outcome != epoch_transition_outcome::ABORTED) {
				std::terminate();
			}
			return false;
		}
		held_prepare_context_ = &context;
		advance_preparation_or_terminate_();
		return true;
	}

	/**
	 * @brief Commit or exactly observe one PREPARED transaction.
	 * @param context Consumer-owned Activate context.
	 * @return true only when the first exact caller is retained through terminal
	 *         completion or update-frozen RETIRING.
	 */
	[[nodiscard]] bool execute_activate_command_(transaction_command_context &context) noexcept
	{
		context.result = coordinator_->query_transaction(context.identity);
		if (!context.result.is_ok() ||
		    context.result.observation.resolution != common::transition_identity_resolution::ACTIVE_EXACT ||
		    context.result.observation.phase != epoch_transition_phase::PREPARED) {
			return false;
		}
		if (completion_ == nullptr || !completion_->active() || completion_->identity() == nullptr ||
		    *completion_->identity() != context.identity || worker_commands_ == nullptr ||
		    held_activate_context_ != nullptr) {
			std::terminate();
		}
		const uint64_t from_epoch = coordinator_->active_epoch();
		const auto trigger_preflight = worker_commands_->preflight_transition(
			context.identity.mutation_sequence, from_epoch, context.identity.target_epoch);
		if (!trigger_preflight.is_ok()) {
			context.result = fixed_operation_failure(
				trigger_preflight, common::transition_identity_resolution::STATE_UNAVAILABLE);
			context.result.observation.identity = context.identity;
			return false;
		}
		const auto committed = completion_->begin_commit(context.identity, std::chrono::steady_clock::now());
		if (!committed.is_ok()) {
			context.result = fixed_operation_failure(
				committed, common::transition_identity_resolution::STATE_UNAVAILABLE);
			context.result.observation.identity = context.identity;
			return false;
		}
		worker_commands_->publish_transition_or_terminate(context.identity.mutation_sequence, from_epoch,
								  context.identity.target_epoch);
		if (telemetry_reservation_epoch_ != context.identity.target_epoch) {
			std::terminate();
		}
		telemetry_reservation_epoch_ = 0u;
		held_activate_context_ = &context;
		return true;
	}

	/** @brief Suppress foreign PREPARED observation before module withdrawal. */
	void begin_prepared_cleanup_or_terminate_() noexcept
	{
		if (preparation_ == nullptr || preparation_->identity() == nullptr ||
		    preparation_->phase() != epoch_transition_preparation_phase::PREPARED ||
		    !coordinator_->begin_prepared_abort_cleanup(*preparation_->identity()).is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Start exact cleanup for one active PREPARING/PREPARED identity.
	 * @param context Consumer-owned Abort context.
	 * @return true when completion is held by cleanup; false for immediate result.
	 */
	[[nodiscard]] bool execute_abort_command_(transaction_command_context &context) noexcept
	{
		if (preparation_cleanup_in_progress_(context.identity)) {
			context.result = cleanup_observation_unavailable_(context.identity);
			return false;
		}
		context.result = coordinator_->query_transaction(context.identity);
		if (!context.result.is_ok() ||
		    context.result.observation.resolution != common::transition_identity_resolution::ACTIVE_EXACT) {
			return false;
		}
		if (context.result.observation.phase != epoch_transition_phase::PREPARING &&
		    context.result.observation.phase != epoch_transition_phase::PREPARED) {
			set_exact_operation_failure(context.result, status_code::FAILED_PRECONDITION,
						    "prepared transaction abort is unavailable after the commit edge");
			return false;
		}
		if (preparation_ == nullptr || !preparation_->active() || preparation_->identity() == nullptr ||
		    *preparation_->identity() != context.identity) {
			std::terminate();
		}
		if (held_abort_context_ != nullptr) {
			return false;
		}
		held_abort_context_ = &context;
		const auto now = std::chrono::steady_clock::now();
		const bool prepared_cleanup = preparation_->phase() == epoch_transition_preparation_phase::PREPARED;
		if (prepared_cleanup) {
			begin_prepared_cleanup_or_terminate_();
		}
		const auto requested =
			preparation_->request_abort(epoch_transition_failure_code::EXPLICIT_ABORT,
						    "exact pre-commit abort requested by the control plane", now);
		if (!requested.is_ok()) {
			if (prepared_cleanup) {
				std::terminate();
			}
			held_abort_context_ = nullptr;
			context.result = fixed_operation_failure(
				requested, common::transition_identity_resolution::STATE_UNAVAILABLE);
			context.result.observation.identity = context.identity;
			return false;
		}
		advance_preparation_or_terminate_();
		return true;
	}

	/**
	 * @brief Return whether one exact identity is inside transient abort cleanup.
	 * @param identity Candidate command identity.
	 * @return true only while module ownership is CANCELLING or RETIRING.
	 */
	[[nodiscard]] bool
	preparation_cleanup_in_progress_(const common::epoch_transition_identity &identity) const noexcept
	{
		if (preparation_ == nullptr || preparation_->identity() == nullptr ||
		    *preparation_->identity() != identity) {
			return false;
		}
		return preparation_->phase() == epoch_transition_preparation_phase::CANCELLING ||
		       preparation_->phase() == epoch_transition_preparation_phase::RETIRING;
	}

	/**
	 * @brief Refuse a transient cleanup observation without fabricating PREPARED.
	 * @param identity Exact active identity currently cleaning ownership.
	 * @return Status-only unavailable classification carrying the queried identity.
	 */
	[[nodiscard]] static epoch_transition_operation_result
	cleanup_observation_unavailable_(const common::epoch_transition_identity &identity) noexcept
	{
		auto result = fixed_operation_failure(status::unavailable(kinetum::common::static_status_text(
							      "transition ownership cleanup is still in progress")),
						      common::transition_identity_resolution::STATE_UNAVAILABLE);
		result.observation.identity = identity;
		return result;
	}

	/**
	 * @brief Publish coordinator PREPARED/ABORTED truth after module ownership converges.
	 *
	 * Completion time is sampled inside this method, after transient module
	 * staging/preflight or retirement work whose completion the publication
	 * asserts.
	 */
	void advance_preparation_or_terminate_() noexcept
	{
		if (preparation_ == nullptr || !preparation_->active()) {
			return;
		}
		if (preparation_->phase() == epoch_transition_preparation_phase::FAILED_STOP) {
			const auto *identity = preparation_->identity();
			const uint64_t failed_ns = monotonic_nanoseconds(std::chrono::steady_clock::now());
			if (identity == nullptr || failed_ns == 0u ||
			    preparation_->failure_code() == epoch_transition_failure_code::NONE) {
				std::terminate();
			}
			coordinator_->fail_active_or_terminate(*identity, failed_ns, preparation_->failure_code(),
							       preparation_->diagnostic());
			log_materialized_failure(
				"module lifecycle callback failed to return with provable ownership; terminating");
			std::terminate();
		}
		if (preparation_->phase() == epoch_transition_preparation_phase::PREPARED &&
		    coordinator_->phase() == epoch_transition_phase::PREPARING) {
			const auto now = std::chrono::steady_clock::now();
			const auto completion_deadline = preparation_->next_deadline();
			if (!completion_deadline.has_value()) {
				std::terminate();
			}
			if (now >= *completion_deadline) {
				const auto requested = preparation_->request_abort(
					epoch_transition_failure_code::PREPARE_DEADLINE_EXCEEDED,
					"module preparation completed after its compiled deadline", now);
				if (!requested.is_ok()) {
					std::terminate();
				}
				advance_preparation_or_terminate_();
				return;
			}
			const auto lease_duration = coordinator_->prepared_lease_timeout();
			auto lease_deadline_or = checked_transition_deadline(now, lease_duration);
			auto unix_deadline_or = prepared_lease_unix_deadline(lease_duration);
			if (!lease_deadline_or.is_ok() || !unix_deadline_or.is_ok()) {
				const status &failure = !lease_deadline_or.is_ok() ? lease_deadline_or.error() :
										     unix_deadline_or.error();
				const auto failed_at = std::chrono::steady_clock::now();
				const auto requested = preparation_->request_abort(
					epoch_transition_failure_code::PREPARE_FAILURE, failure.message(), failed_at);
				if (!requested.is_ok()) {
					std::terminate();
				}
				advance_preparation_or_terminate_();
				return;
			}
			const uint64_t lease_monotonic_ns = monotonic_nanoseconds(lease_deadline_or.value());
			const uint64_t prepared_monotonic_ns = monotonic_nanoseconds(now);
			const auto *identity = preparation_->identity();
			if (identity == nullptr || prepared_monotonic_ns == 0u || lease_monotonic_ns == 0u) {
				std::terminate();
			}
			if (telemetry_reservation_epoch_ != identity->target_epoch) {
				const auto failed_at = std::chrono::steady_clock::now();
				const auto requested = preparation_->request_abort(
					epoch_transition_failure_code::PREPARE_FAILURE,
					"transition telemetry target reservation is not exact", failed_at);
				if (!requested.is_ok()) {
					std::terminate();
				}
				advance_preparation_or_terminate_();
				return;
			}
			if (completion_ == nullptr) {
				std::terminate();
			}
			const auto completion_armed = completion_->arm_before_prepared(*identity);
			if (!completion_armed.is_ok()) {
				const auto failed_at = std::chrono::steady_clock::now();
				const auto requested =
					preparation_->request_abort(epoch_transition_failure_code::PREPARE_FAILURE,
								    completion_armed.message(), failed_at);
				if (!requested.is_ok()) {
					std::terminate();
				}
				advance_preparation_or_terminate_();
				return;
			}
			const auto prepared = coordinator_->mark_prepared(*identity, prepared_monotonic_ns,
									  lease_monotonic_ns, unix_deadline_or.value());
			if (!prepared.is_ok()) {
				const auto diagnostic = std::string_view(prepared.observation.diagnostic.bytes.data(),
									 prepared.observation.diagnostic.size);
				const auto failed_at = std::chrono::steady_clock::now();
				const auto requested = preparation_->request_abort(
					epoch_transition_failure_code::PREPARE_FAILURE, diagnostic, failed_at);
				if (!requested.is_ok()) {
					std::terminate();
				}
				advance_preparation_or_terminate_();
				return;
			}
			preparation_->arm_prepared_lease(lease_deadline_or.value());
			if (held_prepare_context_ == nullptr) {
				std::terminate();
			}
			held_prepare_context_->result = prepared;
			command_mailbox_->complete(held_prepare_context_);
			held_prepare_context_ = nullptr;
			return;
		}
		if (preparation_->phase() != epoch_transition_preparation_phase::ABORTED) {
			return;
		}

		const auto *identity = preparation_->identity();
		const uint64_t terminal_ns = monotonic_nanoseconds(std::chrono::steady_clock::now());
		if (identity == nullptr || terminal_ns == 0u ||
		    preparation_->failure_code() == epoch_transition_failure_code::NONE) {
			std::terminate();
		}
		discard_transition_telemetry_(identity->target_epoch);
		const auto terminal = coordinator_->abort_before_commit(
			*identity, terminal_ns, preparation_->failure_code(), preparation_->diagnostic());
		if (!terminal.is_ok() || terminal.observation.outcome != epoch_transition_outcome::ABORTED) {
			std::terminate();
		}
		const auto completed_identity = *identity;
		preparation_->reset_after_abort();
		if (completion_ != nullptr && completion_->active()) {
			completion_->disarm_after_abort(completed_identity);
		}
		if (held_prepare_context_ != nullptr) {
			held_prepare_context_->result = terminal;
			command_mailbox_->complete(held_prepare_context_);
			held_prepare_context_ = nullptr;
		}
		if (held_abort_context_ != nullptr) {
			held_abort_context_->result = terminal;
			command_mailbox_->complete(held_abort_context_);
			held_abort_context_ = nullptr;
		}
	}

	/** @brief Resolve the original Activate context at COMPLETE or exact update freeze. */
	void complete_activate_context_if_terminal_() noexcept
	{
		if (held_activate_context_ == nullptr) {
			return;
		}
		if (completion_ == nullptr || worker_commands_ == nullptr) {
			std::terminate();
		}
		if (completion_->active() && !coordinator_->retirement_frozen()) {
			return;
		}
		auto result = coordinator_->query_transaction(held_activate_context_->identity);
		if (completion_->active()) {
			if (!result.is_ok() ||
			    result.observation.resolution != common::transition_identity_resolution::ACTIVE_EXACT ||
			    result.observation.phase != epoch_transition_phase::RETIRING ||
			    result.observation.failure_code !=
				    epoch_transition_failure_code::RETIREMENT_GRACE_DEADLINE_EXCEEDED) {
				std::terminate();
			}
		} else {
			if (!result.is_ok() ||
			    result.observation.resolution != common::transition_identity_resolution::TERMINAL_EXACT ||
			    result.observation.outcome != epoch_transition_outcome::COMPLETE ||
			    result.observation.failure_code != epoch_transition_failure_code::NONE) {
				std::terminate();
			}
			worker_commands_->complete_transition_or_terminate(
				held_activate_context_->identity.mutation_sequence);
		}
		held_activate_context_->result = result;
		command_mailbox_->complete(held_activate_context_);
		held_activate_context_ = nullptr;
	}

	/**
	 * @brief Complete one accepted but unstarted command during process shutdown.
	 *
	 * @param command Exact taken command record.
	 */
	void complete_unavailable_(const epoch_transition_command &command) noexcept
	{
		if (command.context == nullptr) {
			std::terminate();
		}
		switch (command.kind) {
		case epoch_transition_command_kind::BOOTSTRAP: {
			auto *context = static_cast<bootstrap_command_context *>(command.context);
			context->result.emplace(status::unavailable(
				kinetum::common::static_status_text("packet runtime generation is shutting down")));
			break;
		}
		case epoch_transition_command_kind::PREPARE:
		case epoch_transition_command_kind::ACTIVATE:
		case epoch_transition_command_kind::ABORT:
		case epoch_transition_command_kind::STATUS: {
			auto *context = static_cast<transaction_command_context *>(command.context);
			context->result =
				fixed_operation_failure(status::unavailable(kinetum::common::static_status_text(
								"packet runtime generation is shutting down")),
							common::transition_identity_resolution::STATE_UNAVAILABLE);
			context->result.observation.identity = context->identity;
			break;
		}
		default:
			std::terminate();
		}
		command_mailbox_->complete(command.context);
	}

	/**
	 * @brief Execute one admitted bootstrap transaction on the sole coordinator.
	 *
	 * @param context Exact producer-admitted Bootstrap ownership.
	 * @return Exact activated bootstrap observation or a recoverable pre-activation status.
	 */
	[[nodiscard]] status_or<fixed_epoch_bootstrap_result> bootstrap_owned_(bootstrap_command_context &context)
	{
		if (coordinator_->phase() == epoch_transition_phase::IDLE && coordinator_->active_epoch() != 0u) {
			return status::unavailable("fixed-epoch bootstrap is unavailable after PACKET_READY");
		}
		if (coordinator_->phase() != epoch_transition_phase::AWAITING_BOOTSTRAP) {
			return status::unavailable("fixed-epoch bootstrap is unavailable during another generation");
		}
		const uint64_t epoch = context.active_epoch;
		const auto bound = coordinator_->bind_bootstrap_request(
			context.serialized_request, coordinator_->participants().plan_content_hash(), epoch,
			context.watermarks);
		if (!bound.is_ok()) {
			return bound;
		}
		std::string{}.swap(context.serialized_request);

		const auto *artifact_view = context.artifact.get();
		auto staged = coordinator_->stage_bootstrap_snapshot(epoch, context.artifact);
		if (!staged.is_ok()) {
			return staged;
		}
		auto snapshot_preflight = coordinator_->preflight_bootstrap_publication(epoch);
		if (!snapshot_preflight.is_ok()) {
			if (!coordinator_->abort_bootstrap(epoch).is_ok()) {
				std::terminate();
			}
			return snapshot_preflight;
		}

		if (artifact_view == nullptr) {
			std::terminate();
		}
		auto prepared = modules_->prepare_bootstrap(artifact_view->snapshot(), epoch);
		if (!prepared.is_ok()) {
			if (!coordinator_->abort_bootstrap(epoch).is_ok()) {
				std::terminate();
			}
			return prepared;
		}
		auto launched = launch_workers_(epoch);
		if (!launched.is_ok()) {
			modules_->abort_prepared_bootstrap(epoch);
			if (!coordinator_->abort_bootstrap(epoch).is_ok()) {
				std::terminate();
			}
			return launched;
		}

		return fixed_epoch_bootstrap_result{
			.restored_epoch = epoch,
			.validation_hash = context.validation_hash,
			.allocated_epoch_high_watermark = context.watermarks.allocated_epoch,
			.mutation_sequence_high_watermark = context.watermarks.mutation_sequence,
		};
	}

    public:
	/** @brief Stop and retire every owner in strict reverse dependency order. */
	void shutdown() noexcept
	{
		if (!command_mailbox_->current_thread_is_consumer()) {
			std::terminate();
		}
		if (shutdown_complete_) {
			return;
		}
		close_command_admission();
		if (coordinator_->phase() == epoch_transition_phase::COMMITTING) {
			const auto *identity = completion_ != nullptr ? completion_->identity() : nullptr;
			const uint64_t failed_ns = monotonic_nanoseconds(std::chrono::steady_clock::now());
			if (identity == nullptr || failed_ns == 0u) {
				std::terminate();
			}
			coordinator_->fail_active_or_terminate(
				*identity, failed_ns, epoch_transition_failure_code::COMMIT_SHUTDOWN,
				"runtime shutdown interrupted completion-only COMMITTING");
			std::terminate();
		}
		if (coordinator_->phase() == epoch_transition_phase::RETIRING) {
			shutdown_retiring_or_terminate_();
		}
		if (preparation_ != nullptr && preparation_->active()) {
			drain_preparation_for_shutdown_();
		}
		if (command_mailbox_->unresolved_count() != 0u || held_prepare_context_ != nullptr ||
		    held_activate_context_ != nullptr || held_abort_context_ != nullptr ||
		    coordinator_->phase() == epoch_transition_phase::PREPARING ||
		    coordinator_->phase() == epoch_transition_phase::PREPARED) {
			std::terminate();
		}
		shutdown_owned_();
		shutdown_complete_ = true;
	}

	/** @return Sole coherent runtime-status publication. */
	[[nodiscard]] const runtime_status_publication &status_publication() const noexcept
	{
		return runtime_status_;
	}

	/** @copydoc partitioned_runtime::collect_runtime_telemetry */
	[[nodiscard]] status_or<runtime_telemetry_snapshot>
	collect_runtime_telemetry(const runtime_telemetry_request &request) const
	{
		return telemetry_source_owner_.collect(runtime_generation_, request);
	}

	/** @copydoc partitioned_runtime::try_read_transition_progress */
	[[nodiscard]] publication_read_result
	try_read_transition_progress(epoch_transition_progress_snapshot &out) const noexcept
	{
		return coordinator_->try_read_progress(out);
	}

	/** @copydoc partitioned_runtime::try_read_worker_epoch_ownership */
	[[nodiscard]] publication_read_result
	try_read_worker_epoch_ownership(uint32_t worker_index, worker_epoch_ledger_snapshot &out) const noexcept
	{
		if (worker_index >= kernels_.size()) {
			return publication_read_result::INVALID_IDENTITY;
		}
		return kernels_[worker_index] != nullptr ? kernels_[worker_index]->try_read_epoch_ownership(out) :
							   publication_read_result::UNAVAILABLE;
	}

	/** @copydoc partitioned_runtime::transition_plan_content_hash */
	[[nodiscard]] std::string_view transition_plan_content_hash() const noexcept
	{
		return coordinator_->participants().plan_content_hash();
	}

    private:
	/** @brief Cancel and drain one abortable operation before dependency teardown. */
	void drain_preparation_for_shutdown_() noexcept
	{
		if (preparation_ == nullptr || !preparation_->active()) {
			return;
		}
		const auto initial_now = std::chrono::steady_clock::now();
		if (preparation_->phase() == epoch_transition_preparation_phase::PREPARING ||
		    preparation_->phase() == epoch_transition_preparation_phase::PREPARED) {
			if (preparation_->phase() == epoch_transition_preparation_phase::PREPARED) {
				begin_prepared_cleanup_or_terminate_();
			}
			const auto requested = preparation_->request_abort(
				epoch_transition_failure_code::SHUTDOWN_ABORT,
				"runtime shutdown aborted the active pre-commit transaction", initial_now);
			if (!requested.is_ok()) {
				std::terminate();
			}
		}

		while (preparation_->active()) {
			const auto now = std::chrono::steady_clock::now();
			advance_preparation_or_terminate_();
			if (!preparation_->active()) {
				break;
			}
			if (preparation_->phase() == epoch_transition_preparation_phase::FAILED_STOP) {
				const auto *identity = preparation_->identity();
				if (identity == nullptr ||
				    preparation_->failure_code() == epoch_transition_failure_code::NONE) {
					std::terminate();
				}
				coordinator_->fail_active_or_terminate(*identity, monotonic_nanoseconds(now),
								       preparation_->failure_code(),
								       preparation_->diagnostic());
				std::terminate();
			}

			pollfd descriptor{
				.fd = modules_->lifecycle_notification_descriptor(),
				.events = POLLIN,
				.revents = 0,
			};
			const auto deadline = preparation_->next_deadline();
			const int timeout = control_poll_timeout(deadline, now);
			int result = 0;
			do {
				result = ::poll(&descriptor, 1, timeout);
			} while (result < 0 && errno == EINTR);
			if (result < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
				std::terminate();
			}
			if (result == 0) {
				const auto serviced = service_control_deadline();
				if (!serviced.is_ok()) {
					std::terminate();
				}
			} else if ((descriptor.revents & POLLIN) != 0) {
				const auto serviced = service_lifecycle_notifications();
				if (!serviced.is_ok()) {
					std::terminate();
				}
			}
		}
	}

	/**
	 * @brief Stop and join workers, then retire packet-I/O activation exactly once.
	 *
	 * The coordinator services immutable completed banks while workers finish so
	 * final publication cannot wait behind an unreturned cadence bank. It marks
	 * bank owners quiescent only after every worker publishes EXITED and joins.
	 */
	void stop_workers_and_io_() noexcept
	{
		if (worker_threads_.empty()) {
			return;
		}
		if (worker_commands_ == nullptr) {
			std::terminate();
		}
		worker_commands_->request_stop();
		request_region_worker_exit(std::span<worker_lifecycle_context>(worker_contexts_.get(), worker_count_));
		if (telemetry_aggregator_ == nullptr) {
			std::terminate();
		}
		const auto all_workers_exited = [this]() noexcept {
			return std::all_of(worker_contexts_.get(), worker_contexts_.get() + worker_count_,
					   [](const worker_lifecycle_context &context) {
						   return context.get_state() == worker_lifecycle_state::EXITED;
					   });
		};
		while (!all_workers_exited()) {
			(void)telemetry_aggregator_->service(common::runtime_sizing::PACKET_MAX_BURST_SIZE);
			std::this_thread::yield();
		}
		const auto joined = worker_launcher_.join({.threads = &worker_threads_});
		if (!joined.is_ok()) {
			std::terminate();
		}
		worker_threads_.clear();
		telemetry_aggregator_->mark_workers_quiesced();
		const auto io_deactivated = providers_->deactivate_packet_io();
		if (!io_deactivated.is_ok()) {
			log_materialized_failure(io_deactivated);
			std::terminate();
		}
	}

	/** @brief Join RETIRING workers and finish only an exactly provable reclamation. */
	void shutdown_retiring_or_terminate_() noexcept
	{
		if (completion_ == nullptr || !completion_->active() ||
		    coordinator_->phase() != epoch_transition_phase::RETIRING) {
			std::terminate();
		}
		stop_workers_and_io_();
		if (coordinator_->retirement_frozen()) {
			std::terminate();
		}
		while (completion_->active()) {
			const auto now = std::chrono::steady_clock::now();
			service_telemetry_(now);
			const auto progressed = completion_->service_progress(now);
			if (!progressed.is_ok() || coordinator_->retirement_frozen()) {
				std::terminate();
			}
			if (!completion_->active()) {
				complete_activate_context_if_terminal_();
				break;
			}
			const auto completion_deadline = completion_->next_deadline();
			if (!completion_deadline.has_value() || !next_telemetry_service_.has_value()) {
				std::terminate();
			}
			const auto wake_deadline = std::min(*completion_deadline, *next_telemetry_service_);
			pollfd descriptor{
				.fd = modules_->lifecycle_notification_descriptor(),
				.events = POLLIN,
				.revents = 0,
			};
			const int timeout = control_poll_timeout(wake_deadline, now);
			int result = 0;
			do {
				result = ::poll(&descriptor, 1, timeout);
			} while (result < 0 && errno == EINTR);
			if (result < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
				std::terminate();
			}
			if (result == 0) {
				continue;
			}
			if ((descriptor.revents & POLLIN) != 0) {
				auto notification = modules_->consume_lifecycle_notification();
				if (!notification.is_ok() ||
				    !completion_->service_results(std::chrono::steady_clock::now()).is_ok()) {
					std::terminate();
				}
				complete_activate_context_if_terminal_();
			}
		}
		if (coordinator_->phase() != epoch_transition_phase::IDLE || completion_->active()) {
			std::terminate();
		}
	}

	/** @brief Retire the claimed generation without retaining the gate mutex. */
	void shutdown_owned_() noexcept
	{
		if (!worker_threads_.empty()) {
			if (coordinator_->phase() != epoch_transition_phase::IDLE ||
			    coordinator_->active_epoch() == 0u) {
				std::terminate();
			}
			stop_workers_and_io_();
		}
		if (coordinator_->phase() == epoch_transition_phase::IDLE && coordinator_->active_epoch() != 0u &&
		    !coordinator_->snapshot_store_empty()) {
			const uint64_t epoch = coordinator_->active_epoch();
			if (telemetry_aggregator_ == nullptr) {
				std::terminate();
			}
			telemetry_aggregator_->drain_quiescent();
			if (!telemetry_aggregator_->worker_epoch_aggregated(epoch) ||
			    !telemetry_aggregator_->module_epoch_aggregated(epoch)) {
				std::terminate();
			}
			modules_->retire_published_generation(epoch);
			telemetry_aggregator_->complete_module_epoch_retirement(epoch, 0u);
			telemetry_aggregator_->retire_worker_epoch(epoch, 0u);
			if (!coordinator_->retire_published_after_quiescence(epoch).is_ok()) {
				std::terminate();
			}
		}
		if (modules_ && modules_->lifecycle_services_running()) {
			modules_->stop_lifecycle_services();
		}
		if (preparation_ && preparation_->active()) {
			std::terminate();
		}
		if ((completion_ && completion_->active()) || held_activate_context_ != nullptr) {
			std::terminate();
		}
		telemetry_source_owner_.retire();
		completion_.reset();
		preparation_.reset();
		telemetry_aggregator_.reset();
		transition_certificate_.reset();
		quiescence_domain_.reset();
		kernels_.clear();
		modules_->unbind_telemetry_channels();
		worker_telemetry_.clear();
		telemetry_channels_.clear();
		worker_commands_.reset();
		boundary_senders_.clear();
		boundary_receivers_.clear();
		future_output_hold_views_.clear();
		future_output_holds_.clear();
		boundary_views_.clear();
		boundaries_.clear();
		endpoint_slabs_.clear();
		worker_contexts_.reset();
		worker_count_ = 0;
		modules_.reset();
		providers_.reset();
	}

	/**
	 * @brief Launch every packet worker behind the complete activation gate.
	 *
	 * @param epoch Exact prepared bootstrap epoch.
	 * @return OK after all workers cross PACKET_READY; otherwise no worker remains.
	 */
	[[nodiscard]] status launch_workers_(uint64_t epoch)
	{
		try {
			region_worker_launch_spec spec{
				.worker_contexts =
					std::span<worker_lifecycle_context>(worker_contexts_.get(), worker_count_),
				.threads = &worker_threads_,
				.configure_worker =
					[this](int worker_id) {
						return configure_worker_(static_cast<uint32_t>(worker_id));
					},
				.activate_worker =
					[this, epoch](int worker_id) {
						const auto worker_index = static_cast<uint32_t>(worker_id);
						const uint64_t now_ns = common::update_cached_ns();
						modules_->activate_worker(worker_index, epoch, now_ns);
						kernels_[worker_index]->bind_bootstrap_epoch(epoch, now_ns);
					},
				.commit_activation =
					[this, epoch]() {
						if (telemetry_aggregator_ == nullptr) {
							std::terminate();
						}
						telemetry_aggregator_->drain_quiescent();
						modules_->publish_bootstrap_activation(epoch);
						coordinator_->publish_bootstrap_or_terminate(epoch);
					},
				.activate_packet_io =
					[this]() {
						const auto activated = providers_->activate_packet_io();
						if (!activated.is_ok()) {
							log_materialized_failure(activated);
							std::terminate();
						}
					},
				.publish_running_generation =
					[this]() {
						epoch_transition_progress_snapshot progress{};
						if (coordinator_->try_read_progress(progress) !=
							    publication_read_result::AVAILABLE ||
						    progress.phase != epoch_transition_phase::IDLE ||
						    progress.active_epoch == 0u || progress.target_epoch != 0u ||
						    progress.participants_frozen ||
						    progress.execution_participant_count != worker_count_ ||
						    !runtime_status_.publish_packet_ready(
							    progress.active_epoch,
							    progress.execution_participant_count)) {
							std::terminate();
						}
					},
				.release_worker =
					[this](int worker_id) { release_worker_(static_cast<uint32_t>(worker_id)); },
				.run_worker =
					[this](int worker_id) { kernels_[static_cast<std::size_t>(worker_id)]->run(); },
			};
			return worker_launcher_.launch(spec);
		} catch (const std::bad_alloc &) {
			return status::resource_exhausted("failed to allocate packet-worker launch transaction");
		}
	}

	/**
	 * @brief Bind one worker to its compiled CPU before registering its facilities.
	 *
	 * @param worker_index Exact compact worker identity.
	 * @return OK after exact affinity binding and every required facility registration.
	 */
	[[nodiscard]] status configure_worker_(uint32_t worker_index) noexcept
	{
		if (worker_index >= worker_count_) {
			return status::internal_error(kinetum::common::static_status_text(
				"packet worker configure identity is out of range"));
		}
		const auto &worker = topology_->transition_topology.workers[worker_index];
		try {
			auto bound = bind_current_thread_to_cpu(worker.cpu_core_ids.front(), "packet worker");
			if (!bound.is_ok()) {
				return bound;
			}
			return providers_->worker_uses_process_facility(worker_index) ?
				       providers_->register_worker_thread(worker_index) :
				       status::ok();
		} catch (const std::bad_alloc &) {
			return status::resource_exhausted(kinetum::common::static_status_text(
				"packet-worker affinity diagnostic exhausted memory"));
		} catch (const std::length_error &) {
			return status(status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "packet-worker affinity diagnostic exceeded a representation bound"));
		}
	}

	/**
	 * @brief Release exact facility ownership on the same packet-worker thread.
	 *
	 * @param worker_index Exact compact worker identity.
	 */
	void release_worker_(uint32_t worker_index) noexcept
	{
		if (worker_index >= worker_count_) {
			std::terminate();
		}
		if (providers_->worker_uses_process_facility(worker_index)) {
			providers_->unregister_worker_thread(worker_index);
		}
	}

	kinetum::gluon::v1::DeploymentPlan plan_;			       ///< Exact canonical generation plan.
	std::unique_ptr<provider::compiled_provider_topology> topology_;       ///< Stable sole compiled authority.
	std::unique_ptr<epoch_transition_coordinator> coordinator_;	       ///< Sole phase/store/participant owner.
	std::unique_ptr<epoch_transition_command_mailbox> command_mailbox_;    ///< Plan-sized command authority.
	std::unique_ptr<worker_runtime_command_publication> worker_commands_;  ///< One-load worker command owner.
	std::unique_ptr<provider::materialized_provider_runtime> providers_;   ///< Provider instances and code.
	std::unique_ptr<module::module_runtime_generation> modules_;	       ///< Module and lifecycle generation.
	epoch_protocol_fault_latch protocol_faults_;  ///< Process-generation transition-safety fault authority.
	std::vector<std::unique_ptr<worker_telemetry_channel>> telemetry_channels_;  ///< Poller-local bank channels.
	std::vector<std::unique_ptr<worker_runtime_telemetry>> worker_telemetry_;    ///< Exact-NUMA worker banks.
	std::unique_ptr<runtime_telemetry_aggregator> telemetry_aggregator_;  ///< Sole cold completed-bank merger.
	std::chrono::steady_clock::duration telemetry_service_interval_{};    ///< Plan-derived cold cadence.
	std::optional<std::chrono::steady_clock::time_point> next_telemetry_service_;  ///< Next cold service time.
	std::unique_ptr<epoch_transition_preparation> preparation_;  ///< Sole transient PREPARE/abort owner.
	std::unique_ptr<epoch_transition_completion> completion_;    ///< Sole COMMITTING/RETIRING owner.
	/** Declared before channel borrowers so reverse member destruction retires slabs afterward. */
	std::vector<std::unique_ptr<boundary_epoch_worker_slab>> endpoint_slabs_;
	std::vector<std::unique_ptr<boundary_epoch_channel>> boundaries_;  ///< Exact DATA/CUT/ACK owners.
	std::vector<boundary_epoch_channel *> boundary_views_;		   ///< Compact direct boundary table.
	std::vector<std::unique_ptr<boundary_future_output_hold>> future_output_holds_;	 ///< Future queues.
	std::vector<boundary_future_output_hold *> future_output_hold_views_;		 ///< Compact sender table.
	std::vector<std::unique_ptr<worker_boundary_sender>> boundary_senders_;		 ///< Pre-kernel policy claims.
	std::vector<std::unique_ptr<worker_boundary_receiver>> boundary_receivers_;  ///< Pre-kernel receiver claims.
	std::vector<std::unique_ptr<packet_worker_kernel>> kernels_;		     ///< Pre-resolved packet workers.
	std::unique_ptr<kinetum::algo::quiescence_domain> quiescence_domain_;	     ///< Exact frozen reader domain.
	std::unique_ptr<epoch_transition_certificate> transition_certificate_;	     ///< Immutable proof graph.
	std::unique_ptr<worker_lifecycle_context[]> worker_contexts_;		     ///< Dense lifecycle publications.
	std::size_t worker_count_{0};				 ///< Exact worker array and kernel population.
	std_thread_worker_launcher worker_launcher_;		 ///< Provider-neutral all-or-none launch gate.
	std::vector<std::thread> worker_threads_;		 ///< Exact joinable packet-worker owners.
	runtime_status_publication runtime_status_;		 ///< Sole foreign readiness/epoch observation.
	runtime_telemetry_source_owner telemetry_source_owner_;	 ///< Generation-scoped complete source claims.
	uint64_t runtime_generation_{0};  ///< Exact nonzero provider/runtime generation identity.
	transaction_command_context *held_prepare_context_{nullptr};   ///< Unresolved original PREPARE producer.
	transaction_command_context *held_activate_context_{nullptr};  ///< Original Activate through completion/freeze.
	transaction_command_context *held_abort_context_{nullptr};     ///< Unresolved exact Abort producer.
	uint64_t telemetry_reservation_epoch_{0};  ///< Complete pre-commit target-bank reservation, or zero.
	bool shutdown_complete_{false};		   ///< Owner-thread idempotent retirement publication.
};

status_or<std::unique_ptr<partitioned_runtime>> partitioned_runtime::create(packet_runtime_generation_input input)
{
	std::unique_ptr<provider::compiled_provider_topology> topology;
	try {
		topology = std::make_unique<provider::compiled_provider_topology>(std::move(input.topology_));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate stable compiled runtime topology");
	}
	const auto construction_facts = validate_runtime_construction_facts(*topology);
	if (!construction_facts.is_ok()) {
		return construction_facts;
	}
	auto coordinator_or = epoch_transition_coordinator::create(*topology);
	if (!coordinator_or.is_ok()) {
		return coordinator_or.error();
	}
	auto coordinator = std::move(coordinator_or).value();
	auto command_mailbox = std::move(input.command_mailbox_);
	if (!command_mailbox) {
		return status::internal_error("packet runtime generation lost its command-mailbox authority");
	}
	auto worker_commands_or = worker_runtime_command_publication::create(input.runtime_generation_);
	if (!worker_commands_or.is_ok()) {
		return worker_commands_or.error();
	}
	auto worker_commands = std::move(worker_commands_or).value();

	auto modules_or = module::module_runtime_generation::create(*topology, std::move(input.module_images_));
	if (!modules_or.is_ok()) {
		return modules_or.error();
	}
	auto modules = std::move(modules_or).value();
	auto providers_or = provider::materialized_provider_runtime::create(std::move(input.admitted_), *topology,
									    input.runtime_generation_);
	if (!providers_or.is_ok()) {
		return providers_or.error();
	}
	auto providers = std::move(providers_or).value();

	std::unique_ptr<implementation> implementation;
	try {
		implementation = std::make_unique<partitioned_runtime::implementation>(
			std::move(input.plan_), std::move(topology), std::move(coordinator), std::move(command_mailbox),
			std::move(worker_commands), std::move(providers), std::move(modules),
			input.runtime_generation_);
	} catch (const std::bad_alloc &) {
		terminate_after_materialization("failed to allocate packet runtime owner", modules, providers);
	} catch (...) {
		terminate_after_materialization("packet runtime owner construction raised an exception", modules,
						providers);
	}

	try {
		const auto completed = implementation->complete_construction();
		if (!completed.is_ok()) {
			implementation->fail_stop_construction(completed);
		}
	} catch (const std::bad_alloc &) {
		implementation->fail_stop_construction("failed to allocate materialized packet runtime graph");
	} catch (...) {
		implementation->fail_stop_construction("materialized packet runtime construction raised an exception");
	}

	try {
		return std::unique_ptr<partitioned_runtime>(new partitioned_runtime(std::move(implementation)));
	} catch (const std::bad_alloc &) {
		implementation->fail_stop_construction("failed to allocate packet runtime generation handle");
	} catch (...) {
		implementation->fail_stop_construction("packet runtime generation handle raised an exception");
	}
}

partitioned_runtime::partitioned_runtime(std::unique_ptr<implementation> implementation) noexcept
	: implementation_(std::move(implementation))
{
}

partitioned_runtime::~partitioned_runtime() = default;

status_or<fixed_epoch_bootstrap_result>
partitioned_runtime::bootstrap(const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request)
{
	return implementation_->bootstrap(request);
}

epoch_transition_operation_result partitioned_runtime::prepare_epoch_transition(
	const kinetum::dataplane::v1::PrepareConfigSnapshotRequest &request) noexcept
{
	return implementation_->prepare_epoch_transition(request);
}

epoch_transition_operation_result partitioned_runtime::activate_epoch_transition(
	const kinetum::dataplane::v1::ActivateConfigSnapshotRequest &request) noexcept
{
	return implementation_->activate_epoch_transition(request);
}

epoch_transition_operation_result partitioned_runtime::abort_epoch_transition(
	const kinetum::dataplane::v1::AbortPreparedConfigSnapshotRequest &request) noexcept
{
	return implementation_->abort_epoch_transition(request);
}

epoch_transition_operation_result partitioned_runtime::query_epoch_transition(
	const kinetum::dataplane::v1::GetEpochTransitionStatusRequest &request) noexcept
{
	return implementation_->query_epoch_transition(request);
}

int partitioned_runtime::command_notification_descriptor() const noexcept
{
	return implementation_->command_notification_descriptor();
}

std::optional<int> partitioned_runtime::lifecycle_notification_descriptor() const noexcept
{
	return implementation_->lifecycle_notification_descriptor();
}

status partitioned_runtime::service_command_notifications() noexcept
{
	return implementation_->service_command_notifications();
}

status partitioned_runtime::service_lifecycle_notifications() noexcept
{
	return implementation_->service_lifecycle_notifications();
}

status partitioned_runtime::service_control_deadline() noexcept
{
	return implementation_->service_control_deadline();
}

std::optional<std::chrono::steady_clock::time_point> partitioned_runtime::next_control_deadline() const noexcept
{
	return implementation_->next_control_deadline();
}

void partitioned_runtime::close_command_admission() noexcept
{
	implementation_->close_command_admission();
}

void partitioned_runtime::shutdown() noexcept
{
	implementation_->shutdown();
}

const runtime_status_publication &partitioned_runtime::status_publication() const noexcept
{
	return implementation_->status_publication();
}

status_or<runtime_telemetry_snapshot>
partitioned_runtime::collect_runtime_telemetry(const runtime_telemetry_request &request) const
{
	return implementation_->collect_runtime_telemetry(request);
}

publication_read_result
partitioned_runtime::try_read_transition_progress(epoch_transition_progress_snapshot &out) const noexcept
{
	return implementation_->try_read_transition_progress(out);
}

publication_read_result
partitioned_runtime::try_read_worker_epoch_ownership(uint32_t worker_index,
						     worker_epoch_ledger_snapshot &out) const noexcept
{
	return implementation_->try_read_worker_epoch_ownership(worker_index, out);
}

std::string_view partitioned_runtime::transition_plan_content_hash() const noexcept
{
	return implementation_->transition_plan_content_hash();
}

}  // namespace kinetum::dp
