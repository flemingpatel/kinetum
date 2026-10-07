// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module_runtime_generation.cpp
 * @brief Exact module and cold-lifecycle generation ownership.
 * @author Fleming Patel
 */

#include "src/dp/module/module_runtime_generation.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <sys/eventfd.h>
#include <unistd.h>

#include <kinetum/algo/cache.hpp>
#include <kinetum/kinetum_sdk.h>
#include "gen/kinetum/control/v1/control.pb.h"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/log.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "src/dp/lifecycle/config_lifecycle_executor.hpp"
#include "src/dp/lifecycle/materialized_runtime_service_backend.hpp"
#include "src/dp/lifecycle/numa_lifecycle_memory_provider.hpp"
#include "src/dp/lifecycle/runtime_service_launcher.hpp"
#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/module/module_lifecycle_adapter.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_runtime_materialization.hpp"

namespace kinetum::dp::module
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;
using kinetum::dp::lifecycle::config_lifecycle_executor;
using kinetum::dp::lifecycle::config_lifecycle_operation;
using kinetum::dp::lifecycle::config_lifecycle_result;
using kinetum::dp::lifecycle::config_lifecycle_result_code;
using kinetum::dp::lifecycle::config_lifecycle_task;
using kinetum::dp::lifecycle::epoch_arena_ownership;
using kinetum::dp::lifecycle::lifecycle_log_level;
using kinetum::dp::lifecycle::lifecycle_operation_control;
using kinetum::dp::lifecycle::numa_lifecycle_memory_budget;
using kinetum::provider::compiled_module_context;
using kinetum::provider::compiled_module_memory_budget;
using kinetum::provider::compiled_provider_topology;

namespace
{

/** @brief Production sink for bounded cold module-lifecycle diagnostics. */
class production_lifecycle_log_provider final : public kinetum::dp::lifecycle::lifecycle_log_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_log_provider::write */
	void write(const kinetum::dp::lifecycle::lifecycle_log_record_view &record) noexcept override
	{
		if (kinetum::common::reject_packet_thread_log()) {
			return;
		}
		std::optional<kinetum::common::log_level> mapped;
		switch (record.level) {
		case lifecycle_log_level::DEBUG:
			mapped = kinetum::common::log_level::DEBUG;
			break;
		case lifecycle_log_level::INFO:
			mapped = kinetum::common::log_level::INFO;
			break;
		case lifecycle_log_level::WARNING:
			mapped = kinetum::common::log_level::WARN;
			break;
		case lifecycle_log_level::ERROR:
			mapped = kinetum::common::log_level::ERROR;
			break;
		}
		std::string_view phase;
		switch (record.phase) {
		case kinetum::dp::lifecycle::lifecycle_phase::INIT:
			phase = "INIT";
			break;
		case kinetum::dp::lifecycle::lifecycle_phase::PREPARE:
			phase = "PREPARE";
			break;
		case kinetum::dp::lifecycle::lifecycle_phase::RETIRE:
			phase = "RETIRE";
			break;
		case kinetum::dp::lifecycle::lifecycle_phase::FINI:
			phase = "FINI";
			break;
		}
		if (!mapped.has_value()) {
			std::terminate();
		}
		kinetum::common::log_foreign_lazy(
			{*mapped, "module", "module.lifecycle", {}}, [&](std::span<char> output) {
				return static_cast<std::size_t>(
					std::format_to_n(
						output.data(), static_cast<std::ptrdiff_t>(output.size()),
						"module={} context={} worker={} cpu={} numa={} phase={} epoch={}: {}",
						record.identity.module_id, record.identity.context_instance_id,
						record.identity.worker_index, record.identity.cpu_core_id,
						record.identity.numa_node, phase, record.epoch, record.message)
						.size);
			});
	}
};

/**
 * @brief Narrow one required compiled capacity to the native allocation width.
 *
 * @param value Exact compiled uint64 capacity.
 * @param name Stable diagnostic field name.
 * @return Positive native capacity, or an exact zero/narrowing rejection.
 */
status_or<std::size_t> narrow_required_capacity(uint64_t value, std::string_view name)
{
	if (value == 0) {
		return status::invalid_argument(std::string(name) + " must be nonzero");
	}
	if (value > std::numeric_limits<std::size_t>::max()) {
		return status(status_code::OUT_OF_RANGE, std::string(name) + " exceeds native allocation width");
	}
	return static_cast<std::size_t>(value);
}

/**
 * @brief Add one compiled lifecycle-memory term with exact overflow detection.
 *
 * @param total Accumulator updated only on success.
 * @param term Nonnegative term.
 * @param name Stable diagnostic term name.
 * @return OK after addition, otherwise OUT_OF_RANGE without mutation.
 */
status add_capacity(uint64_t &total, uint64_t term, std::string_view name)
{
	if (term > std::numeric_limits<uint64_t>::max() - total) {
		return status(status_code::OUT_OF_RANGE,
			      "module lifecycle-memory total overflows while adding " + std::string(name));
	}
	total += term;
	return status::ok();
}

/**
 * @brief Multiply exact lifecycle-memory terms with overflow detection.
 *
 * @param lhs First nonnegative factor.
 * @param rhs Second nonnegative factor.
 * @param name Stable diagnostic product name.
 * @return Exact product or OUT_OF_RANGE.
 */
status_or<uint64_t> multiply_capacity(uint64_t lhs, uint64_t rhs, std::string_view name)
{
	if (lhs != 0 && rhs > std::numeric_limits<uint64_t>::max() / lhs) {
		return status(status_code::OUT_OF_RANGE,
			      "module lifecycle-memory total overflows while multiplying " + std::string(name));
	}
	return lhs * rhs;
}

/**
 * @brief Convert one recoverable lifecycle callback result into a status.
 *
 * @param result Exact identity-validated result.
 * @return Non-OK status for every non-success result code.
 */
status lifecycle_result_failure(const config_lifecycle_result &result)
{
	const std::string diagnostic = std::to_string(result.diagnostic_code());
	switch (result.code()) {
	case config_lifecycle_result_code::SUCCESS:
		return status::internal_error("successful lifecycle result was interpreted as a failure");
	case config_lifecycle_result_code::CANCELLED:
		return status::cancelled("module lifecycle PREPARE was cancelled");
	case config_lifecycle_result_code::DEADLINE_EXCEEDED:
		return status::deadline_exceeded("module lifecycle PREPARE deadline expired");
	case config_lifecycle_result_code::CALLBACK_FAILURE:
		return status(status_code::MODULE_ERROR,
			      "module lifecycle PREPARE callback failed with code " + diagnostic);
	case config_lifecycle_result_code::CONTEXT_REJECTED:
		return status::failed_precondition("module lifecycle PREPARE context rejected with code " + diagnostic);
	}
	return status::internal_error("module lifecycle executor returned an unknown result code");
}

/** @brief One pre-resolved lifecycle executor indexed by exact NUMA identity. */
struct executor_binding {
	int32_t numa_node{-1};			       ///< Exact compiled executor NUMA node.
	std::size_t executor_index{0};		       ///< Dense executor ordinal.
	config_lifecycle_executor *executor{nullptr};  ///< Stable executor owner.
};

/** @brief One admitted context's direct cold-lifecycle dependencies. */
struct context_binding {
	uint32_t context_index{0};		       ///< Exact module-context index.
	uint32_t worker_index{0};		       ///< Sole owner-worker index.
	uint32_t stage_instance_index{0};	       ///< Exact module stage instance.
	uint32_t module_image_index{0};		       ///< Exact admitted module-image index.
	std::size_t adapter_index{0};		       ///< Direct lifecycle-adapter index.
	std::size_t executor_index{0};		       ///< Dense exact NUMA executor ordinal.
	config_lifecycle_executor *executor{nullptr};  ///< Exact NUMA executor.
	module_context_instance *context{nullptr};     ///< Stable admitted context.
};

/** @brief Per-NUMA recomputation used to prove compiled budget equality. */
struct observed_memory_budget {
	int32_t numa_node{-1};	       ///< Exact NUMA identity.
	uint32_t context_count{0};     ///< Observed context population.
	uint64_t context_capacity{0};  ///< Observed context-lifetime sum.
	uint64_t epoch_capacity{0};    ///< Observed one-epoch sum.
};

}  // namespace

/** @brief Complete cold lifecycle state and sole transition owner for one module generation. */
class module_runtime_generation::implementation final
	: public kinetum::dp::lifecycle::config_lifecycle_result_consumer,
	  public kinetum::dp::lifecycle::config_lifecycle_result_notifier {
    public:
	/**
	 * @brief Construct and admit one complete module/lifecycle generation.
	 *
	 * @param topology Borrowed compiled authority that outlives this owner.
	 * @param module_images Exact sorted main-image authority.
	 * @return Complete owner or a pre-provider-effect admission failure.
	 */
	[[nodiscard]] static status_or<std::unique_ptr<implementation>>
	create(const compiled_provider_topology &topology, std::vector<module_image_spec> module_images)
	{
		try {
			auto result = std::unique_ptr<implementation>(new implementation(topology));
			result->result_notification_descriptor_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
			if (result->result_notification_descriptor_ < 0) {
				return status::resource_exhausted(
					"failed to create lifecycle result notification descriptor");
			}
			auto admitted = result->admit_(std::move(module_images));
			if (!admitted.is_ok()) {
				return admitted;
			}
			return result;
		} catch (const std::bad_alloc &) {
			return status::resource_exhausted("failed to allocate module runtime generation");
		}
	}

	/** @brief Generation implementations cannot be copied. */
	implementation(const implementation &) = delete;
	/** @brief Generation implementations cannot be copy-assigned. */
	implementation &operator=(const implementation &) = delete;
	/** @brief Generation implementations cannot be moved. */
	implementation(implementation &&) = delete;
	/** @brief Generation implementations cannot be move-assigned. */
	implementation &operator=(implementation &&) = delete;

	/** @brief Enforce explicit retirement and service shutdown before destruction. */
	~implementation() override
	{
		if (prepared_epoch_ != 0 || live_prepared_epoch_ != 0 || published_epoch_ != 0 ||
		    service_launcher_.running() || telemetry_channels_bound_) {
			std::terminate();
		}
		if (result_notification_descriptor_ >= 0) {
			(void)::close(result_notification_descriptor_);
		}
	}

	/**
	 * @brief Launch the exact lifecycle service set over materialized facilities.
	 *
	 * @param materialized Complete provider generation that outlives all services.
	 * @return OK after all-or-none launch; otherwise no lifecycle callback ran.
	 */
	[[nodiscard]] status start_lifecycle_services(const provider::materialized_provider_runtime &materialized)
	{
		if (service_launcher_.running() || service_backend_) {
			return status::failed_precondition("module lifecycle services already own a generation");
		}

		auto backend_or =
			kinetum::dp::lifecycle::materialized_runtime_service_backend::create(topology_, materialized);
		if (!backend_or.is_ok()) {
			return backend_or.error();
		}
		service_backend_ = std::move(backend_or).value();
		const auto &lifecycle_topology = topology_.transition_topology.lifecycle_services;
		if (!lifecycle_topology.has_value()) {
			service_backend_.reset();
			return status::internal_error("compiled packet generation lacks lifecycle-service topology");
		}
		auto launched = service_launcher_.launch(*lifecycle_topology,
							 topology_.transition_topology.runtime_services,
							 executor_views_, *service_backend_);
		if (!launched.is_ok()) {
			service_backend_.reset();
			return launched;
		}
		return status::ok();
	}

	/**
	 * @brief Prepare and preflight every exact context for one bootstrap epoch.
	 *
	 * @param snapshot Canonical plan-bound bootstrap snapshot.
	 * @param bootstrap_epoch Exact nonzero bootstrap epoch.
	 * @return OK after all contexts stage and preflight; otherwise the staged
	 *         prefix is retired exactly.
	 */
	[[nodiscard]] status prepare_bootstrap(const kinetum::control::v1::ConfigSnapshot &snapshot,
					       uint64_t bootstrap_epoch)
	{
		if (!service_launcher_.running()) {
			return status::failed_precondition("module lifecycle services are not running");
		}
		if (bootstrap_epoch == 0) {
			return status::invalid_argument("module bootstrap epoch must be nonzero");
		}
		if (prepared_epoch_ != 0 || live_prepared_epoch_ != 0 || published_epoch_ != 0) {
			return status::failed_precondition("module generation already owns bootstrap state");
		}

		auto config_status = validate_exact_module_configs_(snapshot);
		if (!config_status.is_ok()) {
			return config_status;
		}
		std::size_t staged_count = 0;
		for (const auto &binding : contexts_) {
			const auto &config = snapshot.modules(static_cast<int>(binding.module_image_index));
			auto arena_or = epoch_arena_ownership::create(
				*memory_provider_, binding.context_index, bootstrap_epoch,
				binding.context->lifecycle_owner->identity().numa_node,
				binding.context->lifecycle_owner->epoch_arena_capacity_bytes(),
				kinetum::algo::CACHE_LINE_SIZE);
			if (!arena_or.is_ok()) {
				rollback_staged_prefix_or_terminate_(staged_count, bootstrap_epoch);
				return arena_or.error();
			}

			const void *payload = config.config_blob().empty() ? nullptr : config.config_blob().data();
			lifecycle_operation_control control(std::chrono::steady_clock::time_point::max());
			auto task_or = config_lifecycle_task::create_prepare(
				next_task_sequence_or_terminate_(), *binding.context->lifecycle_owner,
				*adapters_[binding.adapter_index], control, bootstrap_epoch, payload,
				config.config_blob().size(), std::move(arena_or).value());
			if (!task_or.is_ok()) {
				rollback_staged_prefix_or_terminate_(staged_count, bootstrap_epoch);
				return task_or.error();
			}

			auto result_or = dispatch_(binding, std::move(task_or).value());
			if (!result_or.is_ok()) {
				rollback_staged_prefix_or_terminate_(staged_count, bootstrap_epoch);
				return result_or.error();
			}
			auto result = std::move(result_or).value();
			require_result_identity_or_terminate_(result, binding, config_lifecycle_operation::PREPARE,
							      bootstrap_epoch, 0u);
			if (result.code() != config_lifecycle_result_code::SUCCESS) {
				if (result.has_prepared_ownership()) {
					std::terminate();
				}
				auto failure = lifecycle_result_failure(result);
				rollback_staged_prefix_or_terminate_(staged_count, bootstrap_epoch);
				return failure;
			}
			if (!result.has_prepared_ownership()) {
				std::terminate();
			}
			auto ownership_or = result.take_prepared_ownership();
			if (!ownership_or.is_ok()) {
				std::terminate();
			}
			auto ownership = std::move(ownership_or).value();
			auto staged = binding.context->epoch_store->stage_prepared(ownership);
			if (!staged.is_ok()) {
				retire_ownership_or_terminate_(binding, ownership);
				rollback_staged_prefix_or_terminate_(staged_count, bootstrap_epoch);
				return staged;
			}
			++staged_count;
		}

		for (const auto &binding : contexts_) {
			auto preflight = binding.context->epoch_store->preflight_activate_prepared(bootstrap_epoch);
			if (!preflight.is_ok()) {
				rollback_staged_prefix_or_terminate_(contexts_.size(), bootstrap_epoch);
				return preflight;
			}
		}
		prepared_epoch_ = bootstrap_epoch;
		return status::ok();
	}

	/**
	 * @brief Activate one worker's disjoint module-context set.
	 *
	 * @param worker_index Exact compact owner-worker identity.
	 * @param bootstrap_epoch Exact preflighted bootstrap epoch.
	 * @param now_ns Exact owner-worker monotonic activation timestamp.
	 */
	void activate_worker(uint32_t worker_index, uint64_t bootstrap_epoch, uint64_t now_ns) noexcept
	{
		if (prepared_epoch_ != bootstrap_epoch || bootstrap_epoch == 0 || now_ns == 0u ||
		    live_prepared_epoch_ != 0 || published_epoch_ != 0 ||
		    worker_index >= context_indices_by_worker_.size() || worker_activated_[worker_index] != 0) {
			std::terminate();
		}
		for (const auto binding_index : context_indices_by_worker_[worker_index]) {
			const auto &binding = contexts_[binding_index];
			const auto activated = binding.context->epoch_store->activate_prepared(bootstrap_epoch, now_ns);
			if (!activated.is_ok()) {
				std::terminate();
			}
		}
		worker_activated_[worker_index] = 1;
	}

	/**
	 * @brief Publish complete module activation after the worker barrier.
	 *
	 * @param bootstrap_epoch Exact owner-activated bootstrap epoch.
	 */
	void publish_bootstrap_activation(uint64_t bootstrap_epoch) noexcept
	{
		if (prepared_epoch_ != bootstrap_epoch || bootstrap_epoch == 0 || live_prepared_epoch_ != 0 ||
		    published_epoch_ != 0 ||
		    std::any_of(worker_activated_.begin(), worker_activated_.end(),
				[](uint8_t activated) { return activated != 1; })) {
			std::terminate();
		}
		for (const auto &binding : contexts_) {
			if (binding.context->epoch_store->active_epoch() != bootstrap_epoch ||
			    binding.context->epoch_store->prepared_epoch() != 0) {
				std::terminate();
			}
		}
		prepared_epoch_ = 0;
		published_epoch_ = bootstrap_epoch;
	}

	/**
	 * @brief Retire all staged contexts in reverse order before activation.
	 *
	 * @param bootstrap_epoch Exact prepared epoch being abandoned.
	 */
	void abort_prepared_bootstrap(uint64_t bootstrap_epoch) noexcept
	{
		if (prepared_epoch_ != bootstrap_epoch || bootstrap_epoch == 0 || live_prepared_epoch_ != 0 ||
		    published_epoch_ != 0 ||
		    std::any_of(worker_activated_.begin(), worker_activated_.end(),
				[](uint8_t activated) { return activated != 0; })) {
			std::terminate();
		}
		rollback_staged_prefix_or_terminate_(contexts_.size(), bootstrap_epoch);
		prepared_epoch_ = 0;
	}

	/**
	 * @brief Retire every published context after packet-worker quiescence.
	 *
	 * @param epoch Exact published epoch proven packet-quiescent.
	 */
	void retire_published_generation(uint64_t epoch) noexcept
	{
		if (published_epoch_ != epoch || epoch == 0 || prepared_epoch_ != 0 || live_prepared_epoch_ != 0 ||
		    std::any_of(worker_activated_.begin(), worker_activated_.end(),
				[](uint8_t activated) { return activated != 1; })) {
			std::terminate();
		}
		for (auto it = contexts_.rbegin(); it != contexts_.rend(); ++it) {
			auto claim_or = it->context->epoch_store->claim_published_for_shutdown(epoch);
			if (!claim_or.is_ok()) {
				std::terminate();
			}
			auto claim = std::move(claim_or).value();
			retire_claim_or_terminate_(*it, claim);
		}
		published_epoch_ = 0;
		std::fill(worker_activated_.begin(), worker_activated_.end(), uint8_t{0});
	}

	/** @brief Stop, drain, and join the exact lifecycle service set. */
	void stop_lifecycle_services() noexcept
	{
		if (prepared_epoch_ != 0 || live_prepared_epoch_ != 0 || published_epoch_ != 0 ||
		    !service_launcher_.running()) {
			std::terminate();
		}
		const auto stopped = service_launcher_.stop_and_join(*this);
		if (!stopped.is_ok()) {
			std::terminate();
		}
		service_backend_.reset();
	}

	/** @return Stable manager used by pre-resolved packet kernels. */
	[[nodiscard]] module_manager &modules() noexcept
	{
		return modules_;
	}

	/** @copydoc module_runtime_generation::bind_telemetry_channels */
	[[nodiscard]] status bind_telemetry_channels(uint64_t runtime_generation,
						     std::span<worker_telemetry_channel *const> channels) noexcept
	{
		if (runtime_generation == 0u || telemetry_channels_bound_ ||
		    channels.size() != context_indices_by_worker_.size()) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"module telemetry channel table is already bound or incomplete"));
		}
		for (const auto &binding : contexts_) {
			if (binding.worker_index >= channels.size() || channels[binding.worker_index] == nullptr ||
			    binding.stage_instance_index > UINT16_MAX || binding.context == nullptr ||
			    binding.context->lifecycle_owner == nullptr) {
				return status::failed_precondition(kinetum::common::static_status_text(
					"module telemetry binding lost exact context ownership"));
			}
		}
		try {
			telemetry_contexts_by_worker_.assign(channels.size(), {});
			for (std::size_t worker_index = 0u; worker_index < channels.size(); ++worker_index) {
				telemetry_contexts_by_worker_[worker_index].resize(
					context_indices_by_worker_[worker_index].size(), nullptr);
			}
		} catch (const std::bad_alloc &) {
			telemetry_contexts_by_worker_.clear();
			return status::resource_exhausted(kinetum::common::static_status_text(
				"failed to allocate module telemetry worker projection"));
		} catch (const std::length_error &) {
			telemetry_contexts_by_worker_.clear();
			return status(status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "module telemetry worker projection exceeds the host size domain"));
		}
		std::size_t projected_count = 0u;
		for (std::size_t worker_index = 0u; worker_index < channels.size(); ++worker_index) {
			const auto &indices = context_indices_by_worker_[worker_index];
			auto &projection = telemetry_contexts_by_worker_[worker_index];
			for (std::size_t ordinal = 0u; ordinal < indices.size(); ++ordinal) {
				const std::size_t binding_index = indices[ordinal];
				if (binding_index >= contexts_.size() || projected_count >= contexts_.size() ||
				    (ordinal != 0u && indices[ordinal - 1u] >= binding_index) ||
				    contexts_[binding_index].worker_index != worker_index) {
					telemetry_contexts_by_worker_.clear();
					return status::internal_error(kinetum::common::static_status_text(
						"module telemetry worker projection is not two-directionally exact"));
				}
				projection[ordinal] = contexts_[binding_index].context->lifecycle_owner.get();
				++projected_count;
			}
		}
		if (projected_count != contexts_.size()) {
			telemetry_contexts_by_worker_.clear();
			return status::internal_error(kinetum::common::static_status_text(
				"module telemetry worker projection is not two-directionally exact"));
		}
		std::size_t bound = 0u;
		for (const auto &binding : contexts_) {
			auto result = binding.context->lifecycle_owner->bind_telemetry(
				runtime_generation, static_cast<uint16_t>(binding.stage_instance_index),
				*channels[binding.worker_index],
				binding.context->image->descriptor->health_check != nullptr);
			if (!result.is_ok()) {
				for (std::size_t index = 0u; index < bound; ++index) {
					contexts_[index].context->lifecycle_owner->unbind_telemetry();
				}
				telemetry_contexts_by_worker_.clear();
				return result;
			}
			++bound;
		}
		telemetry_channels_bound_ = true;
		return status::ok();
	}

	/** @copydoc module_runtime_generation::unbind_telemetry_channels */
	void unbind_telemetry_channels() noexcept
	{
		if (!telemetry_channels_bound_) {
			return;
		}
		for (const auto &binding : contexts_) {
			if (binding.context == nullptr || binding.context->lifecycle_owner == nullptr) {
				std::terminate();
			}
			binding.context->lifecycle_owner->unbind_telemetry();
		}
		telemetry_contexts_by_worker_.clear();
		telemetry_channels_bound_ = false;
	}

	/** @copydoc module_runtime_generation::worker_telemetry_contexts */
	[[nodiscard]] std::span<lifecycle::lifecycle_context_owner *const>
	worker_telemetry_contexts(uint32_t worker_index) noexcept
	{
		if (!telemetry_channels_bound_ || worker_index >= telemetry_contexts_by_worker_.size()) {
			return {};
		}
		return telemetry_contexts_by_worker_[worker_index];
	}

	/** @copydoc module_runtime_generation::telemetry_context */
	[[nodiscard]] lifecycle::lifecycle_context_owner *telemetry_context(uint32_t context_index) noexcept
	{
		auto *context = modules_.context(context_index);
		return telemetry_channels_bound_ && context != nullptr ? context->lifecycle_owner.get() : nullptr;
	}

	/** @copydoc module_runtime_generation::reserve_transition_telemetry */
	[[nodiscard]] status reserve_transition_telemetry(uint64_t from_epoch, uint64_t to_epoch) noexcept
	{
		if (!telemetry_channels_bound_ || from_epoch == 0u || to_epoch <= from_epoch) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"module telemetry target reservation identity is invalid"));
		}
		std::size_t reserved = 0u;
		for (const auto &binding : contexts_) {
			auto *owner = binding.context->lifecycle_owner.get();
			auto result = owner->reserve_telemetry_epoch(from_epoch, to_epoch);
			if (!result.is_ok()) {
				while (reserved != 0u) {
					--reserved;
					contexts_[reserved].context->lifecycle_owner->discard_telemetry_epoch(to_epoch);
				}
				return result;
			}
			++reserved;
		}
		return status::ok();
	}

	/** @copydoc module_runtime_generation::discard_transition_telemetry */
	void discard_transition_telemetry(uint64_t to_epoch) noexcept
	{
		if (!telemetry_channels_bound_ || to_epoch == 0u) {
			std::terminate();
		}
		for (const auto &binding : contexts_) {
			binding.context->lifecycle_owner->discard_telemetry_epoch(to_epoch);
		}
	}

	/** @copydoc module_runtime_generation::mark_telemetry_workers_quiesced */
	void mark_telemetry_workers_quiesced() noexcept
	{
		if (!telemetry_channels_bound_) {
			std::terminate();
		}
		for (const auto &binding : contexts_) {
			if (binding.context == nullptr || binding.context->lifecycle_owner == nullptr) {
				std::terminate();
			}
			binding.context->lifecycle_owner->mark_telemetry_worker_quiesced();
		}
	}

	/** @return true when the exact lifecycle executor set is live. */
	[[nodiscard]] bool lifecycle_services_running() const noexcept
	{
		return service_launcher_.running();
	}

	/** @copydoc module_runtime_generation::lifecycle_notification_descriptor */
	[[nodiscard]] int lifecycle_notification_descriptor() const noexcept
	{
		return result_notification_descriptor_;
	}

	/** @copydoc module_runtime_generation::consume_lifecycle_notification */
	[[nodiscard]] status_or<uint64_t> consume_lifecycle_notification() noexcept
	{
		uint64_t count = 0u;
		ssize_t bytes = 0;
		do {
			bytes = ::read(result_notification_descriptor_, &count, sizeof(count));
		} while (bytes < 0 && errno == EINTR);
		if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return uint64_t{0};
		}
		if (bytes != static_cast<ssize_t>(sizeof(count)) || count == 0u) {
			return status::internal_error(kinetum::common::static_status_text(
				"lifecycle result notification descriptor returned invalid data"));
		}
		return count;
	}

	/** @copydoc lifecycle::config_lifecycle_result_notifier::notify_result */
	void notify_result() noexcept override
	{
		const uint64_t increment = 1u;
		ssize_t bytes = 0;
		do {
			bytes = ::write(result_notification_descriptor_, &increment, sizeof(increment));
		} while (bytes < 0 && errno == EINTR);
		if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			// A saturated event counter is already readable. Result-ring
			// ownership remains authoritative and the coordinator drains all rings.
			return;
		}
		if (bytes != static_cast<ssize_t>(sizeof(increment))) {
			std::terminate();
		}
	}

	/** @brief Reject any result not synchronously consumed by its operation owner. */
	void consume(config_lifecycle_result &&) noexcept override
	{
		std::terminate();
	}

	/** @return Exact dense module-context population. */
	[[nodiscard]] std::size_t transition_context_count() const noexcept
	{
		return contexts_.size();
	}

	/** @return Exact loaded-image serialization-domain population. */
	[[nodiscard]] std::size_t transition_image_count() const noexcept
	{
		return modules_.image_count();
	}

	/** @return Exact NUMA lifecycle-executor population. */
	[[nodiscard]] std::size_t transition_executor_count() const noexcept
	{
		return executors_.size();
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @return Exact image index, or UINT32_MAX when out of range.
	 */
	[[nodiscard]] uint32_t transition_context_image_index(std::size_t context_ordinal) const noexcept
	{
		return context_ordinal < contexts_.size() ? contexts_[context_ordinal].module_image_index :
							    std::numeric_limits<uint32_t>::max();
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @return Exact compiled context index, or UINT32_MAX when out of range.
	 */
	[[nodiscard]] uint32_t transition_context_index(std::size_t context_ordinal) const noexcept
	{
		return context_ordinal < contexts_.size() ? contexts_[context_ordinal].context_index :
							    std::numeric_limits<uint32_t>::max();
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @return Exact executor ordinal, or executor count when out of range.
	 */
	[[nodiscard]] std::size_t transition_context_executor_index(std::size_t context_ordinal) const noexcept
	{
		return context_ordinal < contexts_.size() ? contexts_[context_ordinal].executor_index :
							    executors_.size();
	}

	/** @return Next never-reused lifecycle task identity. */
	[[nodiscard]] uint64_t next_transition_task_sequence() noexcept
	{
		return next_task_sequence_or_terminate_();
	}

	/**
	 * @param snapshot Canonical candidate configuration snapshot.
	 * @return OK only for one exact admitted-image configuration set.
	 */
	[[nodiscard]] status validate_transition_snapshot(const kinetum::control::v1::ConfigSnapshot &snapshot) const
	{
		if (published_epoch_ == 0u || prepared_epoch_ != 0u || live_prepared_epoch_ != 0u) {
			return status::failed_precondition(
				"live module preparation requires one published epoch and no prepared generation");
		}
		return validate_exact_module_configs_(snapshot);
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @param epoch Exact advancing target epoch.
	 * @return One exact context/epoch arena allocated before callback dispatch.
	 */
	[[nodiscard]] status_or<epoch_arena_ownership> allocate_transition_arena(std::size_t context_ordinal,
										 uint64_t epoch) noexcept
	{
		if (context_ordinal >= contexts_.size() || epoch == 0u || memory_provider_ == nullptr ||
		    published_epoch_ == 0u || epoch <= published_epoch_ || prepared_epoch_ != 0u ||
		    live_prepared_epoch_ != 0u) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"live module arena allocation lacks exact generation ownership"));
		}
		const auto &binding = contexts_[context_ordinal];
		return epoch_arena_ownership::create(*memory_provider_, binding.context_index, epoch,
						     binding.context->lifecycle_owner->identity().numa_node,
						     binding.context->lifecycle_owner->epoch_arena_capacity_bytes(),
						     kinetum::algo::CACHE_LINE_SIZE);
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @param task_sequence Never-reused lifecycle task identity.
	 * @param epoch Exact advancing target epoch.
	 * @param snapshot Canonical candidate configuration snapshot.
	 * @param control Shared cancellation and deadline control.
	 * @param arena Exact context/epoch arena transferred into the task.
	 * @return OK after exact PREPARE task transfer to one NUMA executor.
	 */
	[[nodiscard]] status submit_transition_prepare(std::size_t context_ordinal, uint64_t task_sequence,
						       uint64_t epoch,
						       const kinetum::control::v1::ConfigSnapshot &snapshot,
						       lifecycle_operation_control &control,
						       epoch_arena_ownership &&arena) noexcept
	{
		if (context_ordinal >= contexts_.size()) {
			return status::invalid_argument(kinetum::common::static_status_text(
				"live module PREPARE context ordinal is out of range"));
		}
		const auto &binding = contexts_[context_ordinal];
		if (binding.module_image_index >= static_cast<uint32_t>(snapshot.modules_size())) {
			return status::invalid_argument(kinetum::common::static_status_text(
				"live module PREPARE has no exact canonical config"));
		}
		const auto &config = snapshot.modules(static_cast<int>(binding.module_image_index));
		const void *payload = config.config_blob().empty() ? nullptr : config.config_blob().data();
		auto task_or = config_lifecycle_task::create_prepare(task_sequence, *binding.context->lifecycle_owner,
								     *adapters_[binding.adapter_index], control, epoch,
								     payload, config.config_blob().size(),
								     std::move(arena));
		if (!task_or.is_ok()) {
			return std::move(task_or).error();
		}
		auto task = std::move(task_or).value();
		return binding.executor->submit(std::move(task));
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @param task_sequence Never-reused lifecycle task identity.
	 * @param control Shared cancellation and deadline control.
	 * @param prepared Exact prepared token borrowed through callback completion.
	 * @return OK after exact direct-token RETIRE task transfer.
	 */
	[[nodiscard]] status submit_transition_retire(std::size_t context_ordinal, uint64_t task_sequence,
						      lifecycle_operation_control &control,
						      const lifecycle::prepared_config_ownership &prepared) noexcept
	{
		if (context_ordinal >= contexts_.size()) {
			return status::invalid_argument(kinetum::common::static_status_text(
				"live module RETIRE context ordinal is out of range"));
		}
		const auto &binding = contexts_[context_ordinal];
		auto task_or = config_lifecycle_task::create_retire(task_sequence, *binding.context->lifecycle_owner,
								    *adapters_[binding.adapter_index], control,
								    prepared);
		if (!task_or.is_ok()) {
			return std::move(task_or).error();
		}
		auto task = std::move(task_or).value();
		return binding.executor->submit(std::move(task));
	}

	/** @return First available result across a complete executor scan. */
	[[nodiscard]] std::optional<config_lifecycle_result> try_take_transition_result() noexcept
	{
		for (auto &executor : executors_) {
			auto result = executor->try_take_result();
			if (result.has_value()) {
				return result;
			}
		}
		return std::nullopt;
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @param prepared Exact prepared token transferred into the context store.
	 * @return OK after one exact token enters its context PREPARED slot.
	 */
	[[nodiscard]] status stage_transition_prepared(std::size_t context_ordinal,
						       lifecycle::prepared_config_ownership &prepared) noexcept
	{
		if (context_ordinal >= contexts_.size()) {
			return status::invalid_argument(kinetum::common::static_status_text(
				"live module stage context ordinal is out of range"));
		}
		return contexts_[context_ordinal].context->epoch_store->stage_prepared(prepared);
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @param epoch Exact prepared epoch being withdrawn.
	 * @return Exact token withdrawn from one context PREPARED slot.
	 */
	[[nodiscard]] status_or<lifecycle::prepared_config_ownership>
	discard_transition_prepared(std::size_t context_ordinal, uint64_t epoch) noexcept
	{
		if (context_ordinal >= contexts_.size()) {
			return status::invalid_argument(kinetum::common::static_status_text(
				"live module discard context ordinal is out of range"));
		}
		return contexts_[context_ordinal].context->epoch_store->discard_prepared(epoch);
	}

	/**
	 * @param epoch Exact prepared target epoch.
	 * @return OK when every context store can activate the exact target.
	 */
	[[nodiscard]] status preflight_transition_prepared(uint64_t epoch) const noexcept
	{
		if (epoch == 0u || epoch <= published_epoch_ || prepared_epoch_ != 0u || live_prepared_epoch_ != 0u) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"live module preflight lacks exact epoch ownership"));
		}
		for (const auto &binding : contexts_) {
			auto preflight = binding.context->epoch_store->preflight_prepared_for_commit(epoch);
			if (!preflight.is_ok()) {
				return preflight;
			}
		}
		return status::ok();
	}

	/**
	 * @brief Publish complete module-side PREPARED ownership.
	 * @param epoch Exact prepared target epoch.
	 */
	void publish_transition_prepared(uint64_t epoch) noexcept
	{
		if (epoch == 0u || epoch <= published_epoch_ || prepared_epoch_ != 0u || live_prepared_epoch_ != 0u) {
			std::terminate();
		}
		for (const auto &binding : contexts_) {
			if (binding.context->epoch_store->prepared_epoch() != epoch) {
				std::terminate();
			}
		}
		live_prepared_epoch_ = epoch;
	}

	/**
	 * @brief Clear module-side PREPARED identity after every slot is empty.
	 * @param epoch Exact abandoned or activated target epoch.
	 */
	void clear_transition_prepared(uint64_t epoch) noexcept
	{
		if (live_prepared_epoch_ != epoch || epoch == 0u) {
			std::terminate();
		}
		for (const auto &binding : contexts_) {
			if (binding.context->epoch_store->prepared_epoch() != 0u) {
				std::terminate();
			}
		}
		live_prepared_epoch_ = 0u;
	}

	/**
	 * @brief Consume one direct token after exact matching RETIRE completion.
	 * @param context_ordinal Dense context-table ordinal.
	 * @param prepared Exact retired token to consume.
	 */
	void complete_transition_retirement(std::size_t context_ordinal,
					    lifecycle::prepared_config_ownership &prepared) noexcept
	{
		if (context_ordinal >= contexts_.size()) {
			std::terminate();
		}
		const auto &binding = contexts_[context_ordinal];
		if (!prepared.retire_exact(binding.module_image_index, binding.context_index, prepared.epoch()).is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @param from_epoch Exact currently published epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @return OK only when every store can retain the current epoch after target activation.
	 */
	[[nodiscard]] status preflight_future_retirement(uint64_t from_epoch, uint64_t to_epoch) const noexcept
	{
		if (published_epoch_ != from_epoch || from_epoch == 0u || to_epoch <= from_epoch ||
		    prepared_epoch_ != 0u || live_prepared_epoch_ != to_epoch) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"module generation cannot represent the exact future retained epoch"));
		}
		for (const auto &binding : contexts_) {
			auto preflight = binding.context->epoch_store->preflight_future_retained(from_epoch, to_epoch);
			if (!preflight.is_ok()) {
				return preflight;
			}
		}
		return status::ok();
	}

	/**
	 * @param from_epoch Exact retained baseline epoch.
	 * @param to_epoch Exact activated target epoch.
	 * @return OK only when every worker store has switched and retained the exact baseline.
	 */
	[[nodiscard]] status preflight_transition_activation(uint64_t from_epoch, uint64_t to_epoch) const noexcept
	{
		if (published_epoch_ != from_epoch || from_epoch == 0u || to_epoch <= from_epoch ||
		    prepared_epoch_ != 0u || live_prepared_epoch_ != to_epoch) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"module aggregate activation identity is incomplete"));
		}
		for (const auto &binding : contexts_) {
			if (binding.context->epoch_store->active_epoch() != to_epoch ||
			    binding.context->epoch_store->prepared_epoch() != 0u ||
			    !binding.context->epoch_store->preflight_claim_retained(from_epoch).is_ok()) {
				return status::failed_precondition(kinetum::common::static_status_text(
					"module aggregate activation lacks one exact retained context"));
			}
		}
		return status::ok();
	}

	/**
	 * @brief Publish aggregate target activation after every worker store has switched.
	 * @param from_epoch Exact retained baseline epoch.
	 * @param to_epoch Exact activated target epoch.
	 */
	void publish_transition_activation(uint64_t from_epoch, uint64_t to_epoch) noexcept
	{
		if (!preflight_transition_activation(from_epoch, to_epoch).is_ok()) {
			std::terminate();
		}
		published_epoch_ = to_epoch;
		live_prepared_epoch_ = 0u;
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @param epoch Exact retained old epoch.
	 * @return OK when one exact context can transfer its retained old artifact.
	 */
	[[nodiscard]] status preflight_transition_retained(std::size_t context_ordinal, uint64_t epoch) const noexcept
	{
		if (context_ordinal >= contexts_.size() || published_epoch_ <= epoch || prepared_epoch_ != 0u ||
		    live_prepared_epoch_ != 0u) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"module retained retirement lacks exact aggregate activation truth"));
		}
		return contexts_[context_ordinal].context->epoch_store->preflight_claim_retained(epoch);
	}

	/**
	 * @param context_ordinal Dense context-table ordinal.
	 * @param epoch Exact retained old epoch.
	 * @return Sole store-bound retained claim for one exact context.
	 */
	[[nodiscard]] status_or<module_retirement_claim> claim_transition_retained(std::size_t context_ordinal,
										   uint64_t epoch) noexcept
	{
		auto preflight = preflight_transition_retained(context_ordinal, epoch);
		if (!preflight.is_ok()) {
			return preflight;
		}
		return contexts_[context_ordinal].context->epoch_store->claim_retained(epoch);
	}

	/**
	 * @param submission Complete fixed retirement submission identity.
	 * @param control Shared cancellation and deadline control.
	 * @param claim Sole store-bound retained ownership claim.
	 * @return OK after one exact claimed RETIRE task enters its NUMA executor.
	 */
	[[nodiscard]] status submit_transition_claimed_retire(epoch_transition_retire_submission submission,
							      lifecycle_operation_control &control,
							      const module_retirement_claim &claim) noexcept
	{
		const std::size_t context_ordinal = static_cast<std::size_t>(submission.context_ordinal);
		if (context_ordinal >= contexts_.size() || submission.task_sequence == 0u || submission.padding != 0u ||
		    claim.claim_id() == 0u || claim.epoch() == 0u) {
			return status::invalid_argument(
				kinetum::common::static_status_text("claimed module RETIRE identity is incomplete"));
		}
		const auto &binding = contexts_[context_ordinal];
		if (claim.ownership().module_image_index() != binding.module_image_index ||
		    claim.ownership().context_index() != binding.context_index) {
			return status::failed_precondition(kinetum::common::static_status_text(
				"claimed module RETIRE belongs to a different context"));
		}
		auto task_or = config_lifecycle_task::create_claimed_retire(submission.task_sequence,
									    *binding.context->lifecycle_owner,
									    *adapters_[binding.adapter_index], control,
									    claim.ownership(), claim.claim_id());
		if (!task_or.is_ok()) {
			return std::move(task_or).error();
		}
		return binding.executor->submit(std::move(task_or).value());
	}

	/**
	 * @brief Complete one exact claimed RETIRE after result identity validation.
	 * @param context_ordinal Dense context-table ordinal.
	 * @param claim Sole retired ownership claim to consume.
	 */
	void complete_transition_claimed_retirement(std::size_t context_ordinal,
						    module_retirement_claim &claim) noexcept
	{
		if (context_ordinal >= contexts_.size()) {
			std::terminate();
		}
		const auto &binding = contexts_[context_ordinal];
		if (claim.ownership().module_image_index() != binding.module_image_index ||
		    claim.ownership().context_index() != binding.context_index ||
		    !claim.consume_after_retire().is_ok() ||
		    !binding.context->epoch_store->complete_retirement(claim).is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @param active_epoch Exact target epoch expected in every context.
	 * @return true only when every context retains one exact active target and no old slot.
	 */
	[[nodiscard]] bool transition_retirement_complete(uint64_t active_epoch) const noexcept
	{
		if (published_epoch_ != active_epoch || active_epoch == 0u || prepared_epoch_ != 0u ||
		    live_prepared_epoch_ != 0u) {
			return false;
		}
		for (const auto &binding : contexts_) {
			const auto *store = binding.context->epoch_store.get();
			if (store == nullptr || store->active_epoch() != active_epoch ||
			    store->prepared_epoch() != 0u) {
				return false;
			}
			std::size_t published_count = 0u;
			for (std::size_t slot_index = 0u; slot_index < EXACT_EPOCH_SLOT_COUNT; ++slot_index) {
				const auto *slot = store->slot(slot_index);
				if (slot == nullptr || (slot->state != epoch_slot_state::EMPTY &&
							slot->state != epoch_slot_state::PUBLISHED)) {
					return false;
				}
				if (slot->state == epoch_slot_state::PUBLISHED) {
					if (slot->epoch != active_epoch) {
						return false;
					}
					++published_count;
				}
			}
			if (published_count != 1u) {
				return false;
			}
		}
		return true;
	}

    private:
	/**
	 * @brief Bind one empty implementation to its immutable compiled authority.
	 *
	 * @param topology Sole compiled generation authority.
	 */
	explicit implementation(const compiled_provider_topology &topology) noexcept
		: topology_(topology)
	{
	}

	/**
	 * @brief Validate and build every pre-materialization lifecycle owner.
	 *
	 * @param module_images Strictly sorted exact main-module image authority.
	 * @return OK after complete admission, or a recoverable pre-provider failure.
	 */
	[[nodiscard]] status admit_(std::vector<module_image_spec> module_images)
	{
		auto topology_status = admit_lifecycle_topology_();
		if (!topology_status.is_ok()) {
			return topology_status;
		}
		if (topology_.module_contexts.empty()) {
			if (!module_images.empty() || !topology_.module_memory_budgets.empty()) {
				return status::invalid_argument(
					"module-free topology cannot carry image or lifecycle-memory authority");
			}
			return status::ok();
		}
		if (module_images.empty() || topology_.module_memory_budgets.empty()) {
			return status::invalid_argument(
				"module contexts require exact image and lifecycle-memory authority");
		}

		auto image_status = validate_module_images_(module_images);
		if (!image_status.is_ok()) {
			return image_status;
		}
		auto budgets_or = validate_and_narrow_memory_budgets_();
		if (!budgets_or.is_ok()) {
			return budgets_or.error();
		}
		auto budgets = std::move(budgets_or).value();
		auto context_specs_or = context_specs_();
		if (!context_specs_or.is_ok()) {
			return context_specs_or.error();
		}
		auto memory_or = kinetum::dp::lifecycle::numa_lifecycle_memory_provider::create(budgets);
		if (!memory_or.is_ok()) {
			return memory_or.error();
		}
		memory_provider_ = std::move(memory_or).value();

		lifecycle_operation_control control(std::chrono::steady_clock::time_point::max());
		auto admitted = modules_.admit_generation(std::move(module_images), std::move(context_specs_or).value(),
							  *memory_provider_, log_provider_, control);
		if (!admitted.is_ok()) {
			return admitted;
		}
		return bind_admitted_contexts_();
	}

	/** @return OK after validating topology and allocating every exact executor. */
	[[nodiscard]] status admit_lifecycle_topology_()
	{
		const auto &transition = topology_.transition_topology;
		if (transition.workers.empty() || !transition.lifecycle_services.has_value()) {
			return status::invalid_argument(
				"packet runtime requires nonempty workers and complete lifecycle-service topology");
		}
		const auto &services = transition.runtime_services;
		const auto &lifecycle = *transition.lifecycle_services;
		if (lifecycle.coordinator_service_index >= services.size() ||
		    services[lifecycle.coordinator_service_index].service_index !=
			    lifecycle.coordinator_service_index ||
		    services[lifecycle.coordinator_service_index].role !=
			    kinetum::common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR) {
			return status::invalid_argument("compiled lifecycle coordinator ownership is incomplete");
		}
		if (lifecycle.lifecycle_executor_service_indices.empty()) {
			return status::invalid_argument("compiled lifecycle executor set is empty");
		}

		int32_t previous_numa = -1;
		for (const auto service_index : lifecycle.lifecycle_executor_service_indices) {
			if (service_index >= services.size() ||
			    services[service_index].service_index != service_index ||
			    services[service_index].role !=
				    kinetum::common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR ||
			    services[service_index].numa_node < 0 ||
			    services[service_index].numa_node <= previous_numa) {
				return status::invalid_argument(
					"compiled lifecycle executors must be exact and strictly NUMA ordered");
			}
			auto executor = std::make_unique<config_lifecycle_executor>(service_index,
										    services[service_index].numa_node);
			auto notifier_status = executor->bind_result_notifier(*this);
			if (!notifier_status.is_ok()) {
				return notifier_status;
			}
			const std::size_t executor_index = executors_.size();
			executor_bindings_.push_back(
				{services[service_index].numa_node, executor_index, executor.get()});
			executor_views_.push_back(executor.get());
			executors_.push_back(std::move(executor));
			previous_numa = services[service_index].numa_node;
		}

		context_indices_by_worker_.resize(transition.workers.size());
		worker_activated_.assign(transition.workers.size(), uint8_t{0});
		return status::ok();
	}

	/**
	 * @brief Validate the image set independently at the module-owner boundary.
	 *
	 * @param module_images Candidate exact sorted main-image authority.
	 * @return OK only when image identity and canonical paths equal compiled truth.
	 */
	[[nodiscard]] status validate_module_images_(const std::vector<module_image_spec> &module_images) const
	{
		if (module_images.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
			return status(status_code::OUT_OF_RANGE,
				      "module image count exceeds protobuf repeated-field index range");
		}
		std::vector<std::string> expected_ids;
		expected_ids.reserve(topology_.module_contexts.size());
		for (const auto &context : topology_.module_contexts) {
			expected_ids.push_back(context.module_id);
		}
		std::sort(expected_ids.begin(), expected_ids.end());
		expected_ids.erase(std::unique(expected_ids.begin(), expected_ids.end()), expected_ids.end());
		if (module_images.size() != expected_ids.size()) {
			return status::invalid_argument("module images do not equal the compiled module identity set");
		}
		for (std::size_t i = 0; i < module_images.size(); ++i) {
			if (module_images[i].module_id != expected_ids[i] || module_images[i].canonical_path.empty() ||
			    !module_images[i].canonical_path.is_absolute() ||
			    module_images[i].canonical_path != module_images[i].canonical_path.lexically_normal()) {
				return status::invalid_argument(
					"module image authority is not exact, sorted, absolute, and normalized");
			}
		}
		return status::ok();
	}

	/** @return Recomputed native NUMA budgets, or an exact mismatch/overflow status. */
	[[nodiscard]] status_or<std::vector<numa_lifecycle_memory_budget>> validate_and_narrow_memory_budgets_() const
	{
		std::vector<observed_memory_budget> observed;
		observed.reserve(topology_.module_memory_budgets.size());
		int32_t previous_numa = -1;
		for (const auto &budget : topology_.module_memory_budgets) {
			if (budget.numa_node < 0 || budget.numa_node <= previous_numa || budget.context_count == 0) {
				return status::invalid_argument(
					"compiled module-memory budgets must be nonempty and strictly NUMA ordered");
			}
			observed.push_back({.numa_node = budget.numa_node});
			previous_numa = budget.numa_node;
		}

		for (const auto &context : topology_.module_contexts) {
			auto it = std::lower_bound(observed.begin(), observed.end(), context.numa_node,
						   [](const auto &entry, int32_t node) {
							   return entry.numa_node < node;
						   });
			if (it == observed.end() || it->numa_node != context.numa_node ||
			    it->context_count == std::numeric_limits<uint32_t>::max()) {
				return status::invalid_argument(
					"compiled module context lacks exact lifecycle-memory NUMA authority");
			}
			++it->context_count;
			auto context_sum = add_capacity(it->context_capacity, context.context_memory_capacity_bytes,
							"context-lifetime capacities");
			if (!context_sum.is_ok()) {
				return context_sum;
			}
			auto epoch_sum = add_capacity(it->epoch_capacity, context.epoch_arena_capacity_bytes,
						      "per-epoch arena capacities");
			if (!epoch_sum.is_ok()) {
				return epoch_sum;
			}
		}

		std::vector<numa_lifecycle_memory_budget> narrowed;
		narrowed.reserve(topology_.module_memory_budgets.size());
		for (std::size_t i = 0; i < topology_.module_memory_budgets.size(); ++i) {
			const compiled_module_memory_budget &compiled = topology_.module_memory_budgets[i];
			const observed_memory_budget &actual = observed[i];
			auto all_epochs_or = multiply_capacity(actual.epoch_capacity,
							       kinetum::common::EXACT_EPOCH_SLOT_COUNT,
							       "per-epoch arena capacity by exact slot count");
			if (!all_epochs_or.is_ok()) {
				return all_epochs_or.error();
			}
			uint64_t complete = actual.context_capacity;
			auto complete_status =
				add_capacity(complete, all_epochs_or.value(), "complete lifecycle memory");
			if (!complete_status.is_ok()) {
				return complete_status;
			}
			if (compiled.numa_node != actual.numa_node || compiled.context_count != actual.context_count ||
			    compiled.context_memory_capacity_bytes != actual.context_capacity ||
			    compiled.epoch_arena_capacity_bytes != actual.epoch_capacity ||
			    compiled.complete_memory_capacity_bytes != complete) {
				return status::failed_precondition(
					"compiled module-memory budget disagrees with exact context facts");
			}
			auto native_complete = narrow_required_capacity(compiled.complete_memory_capacity_bytes,
									"complete module-memory capacity");
			if (!native_complete.is_ok()) {
				return native_complete.error();
			}
			const std::size_t telemetry_bytes =
				lifecycle::lifecycle_context_owner::telemetry_storage_bytes();
			if (actual.context_count > std::numeric_limits<std::size_t>::max() / telemetry_bytes ||
			    static_cast<std::size_t>(actual.context_count) * telemetry_bytes >
				    std::numeric_limits<std::size_t>::max() - native_complete.value()) {
				return status(status_code::OUT_OF_RANGE,
					      "platform telemetry storage exceeds the lifecycle NUMA byte domain");
			}
			const std::size_t provider_capacity =
				native_complete.value() +
				static_cast<std::size_t>(actual.context_count) * telemetry_bytes;
			narrowed.push_back({
				.numa_node = compiled.numa_node,
				.context_count = compiled.context_count,
				.complete_memory_capacity_bytes = provider_capacity,
			});
		}
		return narrowed;
	}

	/** @return Exact manager context specifications, or an ownership/capacity failure. */
	[[nodiscard]] status_or<std::vector<module_context_spec>> context_specs_() const
	{
		std::vector<module_context_spec> specs;
		specs.reserve(topology_.module_contexts.size());
		for (std::size_t i = 0; i < topology_.module_contexts.size(); ++i) {
			const compiled_module_context &context = topology_.module_contexts[i];
			if (context.module_context_index != i || context.module_id.empty() ||
			    context.context_instance_id.empty() ||
			    context.stage_instance_index >= topology_.stage_instances.size() ||
			    context.logical_stage_index >= topology_.logical_stages.size() ||
			    context.worker_index >= topology_.transition_topology.workers.size() ||
			    context.worker_index >= topology_.worker_schedules.size() || context.cpu_core_id < 0 ||
			    context.region_id < 0 || context.numa_node < 0 || context.module_context_count == 0u ||
			    context.module_context_ordinal >= context.module_context_count) {
				return status::invalid_argument("compiled module-context ownership is incomplete");
			}
			const auto &stage = topology_.stage_instances[context.stage_instance_index];
			const auto &logical = topology_.logical_stages[context.logical_stage_index];
			if (stage.region_index >= topology_.execution_regions.size()) {
				return status::invalid_argument("compiled module stage has no exact execution region");
			}
			const auto &worker = topology_.transition_topology.workers[context.worker_index];
			const auto &schedule = topology_.worker_schedules[context.worker_index];
			const auto &region = topology_.execution_regions[stage.region_index];
			if (stage.stage_instance_index != context.stage_instance_index ||
			    !stage.module_context_index.has_value() ||
			    *stage.module_context_index != context.module_context_index ||
			    stage.logical_stage_index != context.logical_stage_index ||
			    stage.worker_index != context.worker_index ||
			    logical.kind != provider::compiled_stage_kind::MODULE ||
			    logical.module_id != context.module_id) {
				return status::failed_precondition(
					"compiled module context disagrees with its exact executable stage");
			}
			if (context.context_instance_id != stage.stage_instance_id ||
			    worker.worker_index != context.worker_index || worker.region_id != context.region_id ||
			    worker.numa_node != context.numa_node || worker.cpu_core_ids.size() != 1u ||
			    worker.cpu_core_ids.front() != context.cpu_core_id ||
			    region.region_id != context.region_id || region.numa_node != context.numa_node ||
			    schedule.worker_index != context.worker_index ||
			    !std::binary_search(worker.stage_instance_indices.begin(),
						worker.stage_instance_indices.end(), context.stage_instance_index) ||
			    !std::binary_search(region.stage_instance_indices.begin(),
						region.stage_instance_indices.end(), context.stage_instance_index) ||
			    !std::binary_search(region.worker_indices.begin(), region.worker_indices.end(),
						context.worker_index) ||
			    !std::binary_search(schedule.stage_instance_indices.begin(),
						schedule.stage_instance_indices.end(), context.stage_instance_index)) {
				return status::failed_precondition(
					"compiled module context disagrees with its exact owner placement");
			}
			if (executor_for_numa_(context.numa_node) == nullptr ||
			    executor_index_for_numa_(context.numa_node) >= executors_.size()) {
				return status::failed_precondition(
					"compiled module context has no exact NUMA lifecycle executor");
			}

			auto context_capacity = narrow_required_capacity(context.context_memory_capacity_bytes,
									 "module context memory capacity");
			if (!context_capacity.is_ok()) {
				return context_capacity.error();
			}
			auto epoch_capacity = narrow_required_capacity(context.epoch_arena_capacity_bytes,
								       "module epoch arena capacity");
			if (!epoch_capacity.is_ok()) {
				return epoch_capacity.error();
			}
			specs.push_back({
				.context_instance_id = context.context_instance_id,
				.module_id = context.module_id,
				.context_index = context.module_context_index,
				.worker_index = context.worker_index,
				.cpu_core_id = context.cpu_core_id,
				.numa_node = context.numa_node,
				.context_memory_capacity_bytes = context_capacity.value(),
				.epoch_arena_capacity_bytes = epoch_capacity.value(),
				.module_context_ordinal = context.module_context_ordinal,
				.module_context_count = context.module_context_count,
			});
		}
		return specs;
	}

	/**
	 * @brief Preflight mode-specific callback and tracked-work coverage before provider effects.
	 * @return OK only when every exact module context can execute its compiled role.
	 */
	[[nodiscard]] status validate_callback_shapes_()
	{
		std::vector<bool> has_packet_input(topology_.stage_instances.size(), false);
		for (const auto &stage : topology_.stage_instances) {
			for (const auto &route : stage.packet_routes) {
				if (route.destination_stage_instance_indices.empty()) {
					return status::failed_precondition(
						"compiled module callback admission found an empty destination set");
				}
				for (const uint16_t destination : route.destination_stage_instance_indices) {
					if (destination >= has_packet_input.size()) {
						return status::failed_precondition(
							"compiled module callback admission found an invalid packet route");
					}
					has_packet_input[destination] = true;
				}
			}
		}

		for (const auto &compiled : topology_.module_contexts) {
			if (compiled.module_context_index >= modules_.context_count() ||
			    compiled.stage_instance_index >= topology_.stage_instances.size() ||
			    compiled.logical_stage_index >= topology_.logical_stages.size()) {
				return status::failed_precondition(
					"compiled module callback admission lost exact context identity");
			}
			const auto *context = modules_.context(compiled.module_context_index);
			if (context == nullptr || context->image == nullptr || context->image->descriptor == nullptr) {
				return status::failed_precondition(
					"admitted module callback table is absent from one exact context");
			}
			const auto &stage = topology_.stage_instances[compiled.stage_instance_index];
			const auto &logical = topology_.logical_stages[compiled.logical_stage_index];
			const auto *descriptor = context->image->descriptor;
			const bool selects_contexts = logical.context_selection ==
						      provider::compiled_module_context_selection::MODULE;
			if (selects_contexts != ((descriptor->flags & KINETUM_MOD_F_CONTEXT_SELECTION) != 0u) ||
			    selects_contexts != (descriptor->select_contexts != nullptr)) {
				return status::failed_precondition(
					"module selector capability disagrees with the authored context-selection mode");
			}
			const kinetum_module_mode expected_mode =
				logical.execution_mode == provider::compiled_stage_execution_mode::PASSIVE ?
					KINETUM_MODULE_PASSIVE :
					KINETUM_MODULE_ACTIVE;
			if (stage.logical_stage_index != compiled.logical_stage_index ||
			    descriptor->mode != expected_mode) {
				return status::failed_precondition(
					"admitted module mode disagrees with its exact logical-stage execution mode");
			}
			const bool tracked_async = (descriptor->flags & KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK) != 0u;
			const bool async_capacity_present = logical.async_work_capacity != 0u;
			const bool async_grace_present = logical.async_cancel_grace !=
							 std::chrono::steady_clock::duration::zero();
			const auto async_grace_ms =
				std::chrono::duration_cast<std::chrono::milliseconds>(logical.async_cancel_grace);
			const bool async_grace_exact = !async_grace_present ||
						       (async_grace_ms > std::chrono::milliseconds::zero() &&
							std::chrono::duration_cast<std::chrono::steady_clock::duration>(
								async_grace_ms) == logical.async_cancel_grace);
			const bool async_resources = expected_mode == KINETUM_MODULE_ACTIVE && async_capacity_present;
			if (async_capacity_present != async_grace_present || !async_grace_exact ||
			    tracked_async != async_resources ||
			    (async_resources && topology_.transition_topology.policy.enabled &&
			     logical.async_cancel_grace >= topology_.transition_topology.policy.commit_timeout)) {
				return status::failed_precondition(
					"tracked-async module capability and exact active resources disagree");
			}
			if (expected_mode != KINETUM_MODULE_ACTIVE) {
				continue;
			}
			const bool control =
				(logical.trigger_mask &
				 static_cast<uint32_t>(provider::compiled_active_stage_trigger::CONTROL)) != 0u;
			if (!stage.active_origin_storage_domain_index.has_value() || descriptor->run == nullptr ||
			    (has_packet_input[compiled.stage_instance_index] && descriptor->ingest == nullptr) ||
			    (control && descriptor->on_control == nullptr)) {
				return status::failed_precondition(
					"active module callbacks do not cover exact origin, packet-input, run, and CONTROL ownership");
			}
		}
		return status::ok();
	}

	/** @return OK after descriptors and contexts agree with compiled truth both ways. */
	[[nodiscard]] status bind_admitted_contexts_()
	{
		if (modules_.image_count() == 0 || modules_.context_count() != topology_.module_contexts.size()) {
			return status::failed_precondition("admitted module generation cardinality is incomplete");
		}
		if (const auto callback_status = validate_callback_shapes_(); !callback_status.is_ok()) {
			return callback_status;
		}
		for (std::size_t image_index = 0; image_index < modules_.image_count(); ++image_index) {
			const auto *image = modules_.image(static_cast<uint32_t>(image_index));
			if (!image || !image->descriptor || image->module_image_index != image_index) {
				return status::failed_precondition("admitted module image identity is incomplete");
			}
			if (topology_.transition_topology.policy.enabled &&
			    (image->descriptor->flags & KINETUM_MOD_F_LIVE_EPOCH_TRANSITION) == 0u) {
				return status::unimplemented(
					"live-transition policy requires every module image to declare exact lifecycle capability");
			}
		}

		contexts_.reserve(topology_.module_contexts.size());
		adapters_.reserve(topology_.module_contexts.size());
		for (const auto &compiled : topology_.module_contexts) {
			auto *context = modules_.context(compiled.module_context_index);
			if (!context || !context->image || !context->image->descriptor || !context->lifecycle_owner ||
			    !context->epoch_store || context->context_instance_id != compiled.context_instance_id ||
			    context->context_index != compiled.module_context_index ||
			    context->image->module_id != compiled.module_id ||
			    context->lifecycle_owner->identity().worker_index != compiled.worker_index ||
			    context->lifecycle_owner->identity().cpu_core_id != compiled.cpu_core_id ||
			    context->lifecycle_owner->identity().numa_node != compiled.numa_node ||
			    context->lifecycle_owner->identity().module_context_ordinal !=
				    compiled.module_context_ordinal ||
			    context->lifecycle_owner->identity().module_context_count !=
				    compiled.module_context_count ||
			    context->lifecycle_owner->context_memory_capacity_bytes() !=
				    compiled.context_memory_capacity_bytes ||
			    context->lifecycle_owner->epoch_arena_capacity_bytes() !=
				    compiled.epoch_arena_capacity_bytes ||
			    !context->epoch_store->empty()) {
				return status::failed_precondition(
					"admitted module context disagrees with compiled generation truth");
			}
			const auto &logical = topology_.logical_stages[compiled.logical_stage_index];
			const kinetum_module_mode expected_mode =
				logical.execution_mode == provider::compiled_stage_execution_mode::PASSIVE ?
					KINETUM_MODULE_PASSIVE :
					KINETUM_MODULE_ACTIVE;
			if (context->image->descriptor->mode != expected_mode) {
				return status::failed_precondition(
					"admitted module mode disagrees with its exact logical-stage execution mode");
			}
			auto adapter_or = modules_.make_lifecycle_adapter(compiled.module_context_index);
			if (!adapter_or.is_ok()) {
				return adapter_or.error();
			}
			const std::size_t adapter_index = adapters_.size();
			adapters_.push_back(std::move(adapter_or).value());
			contexts_.push_back({
				.context_index = compiled.module_context_index,
				.worker_index = compiled.worker_index,
				.stage_instance_index = compiled.stage_instance_index,
				.module_image_index = context->image->module_image_index,
				.adapter_index = adapter_index,
				.executor_index = executor_index_for_numa_(compiled.numa_node),
				.executor = executor_for_numa_(compiled.numa_node),
				.context = context,
			});
			context_indices_by_worker_[compiled.worker_index].push_back(contexts_.size() - 1u);
		}
		return status::ok();
	}

	/**
	 * @brief Resolve one prevalidated executor through sorted NUMA bindings.
	 *
	 * @param numa_node Exact nonnegative host NUMA identity.
	 * @return Bound lifecycle executor, or null when the node is absent.
	 */
	[[nodiscard]] config_lifecycle_executor *executor_for_numa_(int32_t numa_node) const noexcept
	{
		const auto it = std::lower_bound(executor_bindings_.begin(), executor_bindings_.end(), numa_node,
						 [](const executor_binding &binding, int32_t node) {
							 return binding.numa_node < node;
						 });
		return it != executor_bindings_.end() && it->numa_node == numa_node ? it->executor : nullptr;
	}

	/**
	 * @brief Resolve one dense executor ordinal through the same NUMA authority.
	 * @param numa_node Exact nonnegative context NUMA node.
	 * @return Dense executor ordinal, or executors_.size() when absent.
	 */
	[[nodiscard]] std::size_t executor_index_for_numa_(int32_t numa_node) const noexcept
	{
		const auto it = std::lower_bound(executor_bindings_.begin(), executor_bindings_.end(), numa_node,
						 [](const executor_binding &binding, int32_t node) {
							 return binding.numa_node < node;
						 });
		return it != executor_bindings_.end() && it->numa_node == numa_node ? it->executor_index :
										      executors_.size();
	}

	/**
	 * @brief Require exact canonical module configuration coverage.
	 *
	 * @param snapshot Canonical plan-bound bootstrap snapshot.
	 * @return OK only when snapshot modules equal admitted images in exact order.
	 */
	[[nodiscard]] status validate_exact_module_configs_(const kinetum::control::v1::ConfigSnapshot &snapshot) const
	{
		if (static_cast<std::size_t>(snapshot.modules_size()) != modules_.image_count()) {
			return status::invalid_argument(
				"bootstrap snapshot module set does not equal the admitted image set");
		}
		for (std::size_t i = 0; i < modules_.image_count(); ++i) {
			const auto *image = modules_.image(static_cast<uint32_t>(i));
			const auto &config = snapshot.modules(static_cast<int>(i));
			if (!image || config.module_id() != image->module_id) {
				return status::invalid_argument(
					"bootstrap snapshot modules must be exact, sorted, and unique");
			}
		}
		return status::ok();
	}

	/**
	 * @brief Dispatch one task and wait without inventing a lifecycle timeout.
	 *
	 * @param binding Exact context/executor ownership record.
	 * @param task Sole lifecycle task ownership transferred to the executor.
	 * @return Exact completed result, or a submission/service-lifetime failure.
	 */
	[[nodiscard]] status_or<config_lifecycle_result> dispatch_(const context_binding &binding,
								   config_lifecycle_task &&task) noexcept
	{
		if (!binding.executor) {
			return status::internal_error(
				kinetum::common::static_status_text("module context has no bound lifecycle executor"));
		}
		auto submitted = binding.executor->submit(std::move(task));
		if (!submitted.is_ok()) {
			return submitted;
		}
		auto result = binding.executor->wait_take_result_until(std::chrono::steady_clock::time_point::max());
		if (!result.has_value()) {
			return status::internal_error(kinetum::common::static_status_text(
				"lifecycle executor stopped without its accepted result"));
		}
		return std::move(*result);
	}

	/**
	 * @brief Require one executor result to echo every submitted identity.
	 *
	 * @param result Completed executor result.
	 * @param binding Exact submitted context binding.
	 * @param operation Exact submitted lifecycle operation.
	 * @param epoch Exact submitted epoch.
	 * @param retirement_claim_id Exact submitted retirement claim, or zero for direct ownership.
	 */
	static void require_result_identity_or_terminate_(const config_lifecycle_result &result,
							  const context_binding &binding,
							  config_lifecycle_operation operation, uint64_t epoch,
							  uint64_t retirement_claim_id) noexcept
	{
		if (result.operation() != operation || result.module_image_index() != binding.module_image_index ||
		    result.context_index() != binding.context_index || result.epoch() != epoch ||
		    result.retirement_claim_id() != retirement_claim_id) {
			std::terminate();
		}
	}

	/** @return Next never-reused task identity; exhaustion fails stop. */
	[[nodiscard]] uint64_t next_task_sequence_or_terminate_() noexcept
	{
		if (next_task_sequence_ == 0) {
			std::terminate();
		}
		const uint64_t result = next_task_sequence_;
		if (next_task_sequence_ == std::numeric_limits<uint64_t>::max()) {
			next_task_sequence_ = 0;
		} else {
			++next_task_sequence_;
		}
		return result;
	}

	/**
	 * @brief RETIRE and consume one unstaged prepared token exactly.
	 *
	 * @param binding Exact context/executor ownership record.
	 * @param ownership Sole mutable prepared-token ownership.
	 */
	void retire_ownership_or_terminate_(const context_binding &binding,
					    kinetum::dp::lifecycle::prepared_config_ownership &ownership) noexcept
	{
		lifecycle_operation_control control(std::chrono::steady_clock::time_point::max());
		auto task_or = config_lifecycle_task::create_retire(next_task_sequence_or_terminate_(),
								    *binding.context->lifecycle_owner,
								    *adapters_[binding.adapter_index], control,
								    ownership);
		if (!task_or.is_ok()) {
			std::terminate();
		}
		auto result_or = dispatch_(binding, std::move(task_or).value());
		if (!result_or.is_ok()) {
			std::terminate();
		}
		auto result = std::move(result_or).value();
		require_result_identity_or_terminate_(result, binding, config_lifecycle_operation::RETIRE,
						      ownership.epoch(), 0u);
		if (result.code() != config_lifecycle_result_code::SUCCESS || result.has_prepared_ownership()) {
			std::terminate();
		}
		const auto retired =
			ownership.retire_exact(binding.module_image_index, binding.context_index, ownership.epoch());
		if (!retired.is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Restore one unexecuted store claim, then fail stop.
	 * @param binding Exact issuing context/store binding.
	 * @param claim Sole still-live claim rejected before callback completion.
	 */
	[[noreturn]] static void restore_claim_and_terminate_(const context_binding &binding,
							      module_retirement_claim &claim) noexcept
	{
		const auto restored = binding.context->epoch_store->restore_retirement(claim);
		if (!restored.is_ok()) {
			std::terminate();
		}
		std::terminate();
	}

	/**
	 * @brief RETIRE and complete one store-bound published claim exactly.
	 *
	 * @param binding Exact context/executor ownership record.
	 * @param claim Sole store-bound retirement claim.
	 */
	void retire_claim_or_terminate_(const context_binding &binding, module_retirement_claim &claim) noexcept
	{
		lifecycle_operation_control control(std::chrono::steady_clock::time_point::max());
		auto task_or = config_lifecycle_task::create_claimed_retire(next_task_sequence_or_terminate_(),
									    *binding.context->lifecycle_owner,
									    *adapters_[binding.adapter_index], control,
									    claim.ownership(), claim.claim_id());
		if (!task_or.is_ok()) {
			restore_claim_and_terminate_(binding, claim);
		}
		auto task = std::move(task_or).value();
		const auto submitted = binding.executor->submit(std::move(task));
		if (!submitted.is_ok()) {
			restore_claim_and_terminate_(binding, claim);
		}
		auto result_or = binding.executor->wait_take_result_until(std::chrono::steady_clock::time_point::max());
		if (!result_or.has_value()) {
			std::terminate();
		}
		auto result = std::move(*result_or);
		require_result_identity_or_terminate_(result, binding, config_lifecycle_operation::RETIRE,
						      claim.epoch(), claim.claim_id());
		if (result.has_prepared_ownership()) {
			std::terminate();
		}
		if (result.code() != config_lifecycle_result_code::SUCCESS) {
			restore_claim_and_terminate_(binding, claim);
		}
		const auto consumed = claim.consume_after_retire();
		if (!consumed.is_ok()) {
			std::terminate();
		}
		const auto completed = binding.context->epoch_store->complete_retirement(claim);
		if (!completed.is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Discard and RETIRE one staged prefix in reverse context order.
	 *
	 * @param staged_count Exact number of successfully staged leading contexts.
	 * @param epoch Exact prepared epoch to discard.
	 */
	void rollback_staged_prefix_or_terminate_(std::size_t staged_count, uint64_t epoch) noexcept
	{
		if (staged_count > contexts_.size()) {
			std::terminate();
		}
		while (staged_count != 0) {
			const auto &binding = contexts_[--staged_count];
			auto ownership_or = binding.context->epoch_store->discard_prepared(epoch);
			if (!ownership_or.is_ok()) {
				std::terminate();
			}
			auto ownership = std::move(ownership_or).value();
			retire_ownership_or_terminate_(binding, ownership);
		}
	}

	const compiled_provider_topology &topology_;	  ///< Borrowed immutable generation truth.
	production_lifecycle_log_provider log_provider_;  ///< Stable cold diagnostic authority.
	std::unique_ptr<kinetum::dp::lifecycle::numa_lifecycle_memory_provider>
		memory_provider_;		 ///< Exact compiled NUMA allocation authority for module contexts.
	module_manager modules_;		 ///< Admitted images, contexts, stores, and INIT/FINI lifetime.
	std::vector<context_binding> contexts_;	 ///< Direct context/adapter/executor ownership table.
	std::vector<std::vector<std::size_t>> context_indices_by_worker_;  ///< Exact owner-local context sets.
	std::vector<std::vector<lifecycle::lifecycle_context_owner *>>
		telemetry_contexts_by_worker_;	 ///< Telemetry owners.
	bool telemetry_channels_bound_{false};	 ///< Complete context-to-worker channel binding.
	std::vector<uint8_t> worker_activated_;	 ///< Disjoint owner-written bootstrap activation evidence.
	std::vector<std::unique_ptr<module_lifecycle_adapter>> adapters_;    ///< Stable exact context adapters.
	std::vector<std::unique_ptr<config_lifecycle_executor>> executors_;  ///< Planned cold services.
	std::vector<executor_binding> executor_bindings_;		     ///< Strict NUMA-to-executor lookup table.
	std::vector<config_lifecycle_executor *> executor_views_;	     ///< Launcher-order non-owning views.
	std::unique_ptr<kinetum::dp::lifecycle::materialized_runtime_service_backend>
		service_backend_;  ///< Materialized facility/native dispatch owner while services run.
	kinetum::dp::lifecycle::runtime_service_launcher service_launcher_;  ///< All-or-none service lifetime.
	uint64_t next_task_sequence_{1};	  ///< Never-reused generation-local lifecycle task identity.
	uint64_t prepared_epoch_{0};		  ///< Exact fully preflighted bootstrap epoch.
	uint64_t live_prepared_epoch_{0};	  ///< Exact fully preflighted live target epoch.
	uint64_t published_epoch_{0};		  ///< Exact aggregate published execution epoch.
	int result_notification_descriptor_{-1};  ///< Wake-only aggregate lifecycle result eventfd.
};

status_or<std::unique_ptr<module_runtime_generation>>
module_runtime_generation::create(const compiled_provider_topology &topology,
				  std::vector<module_image_spec> module_images)
{
	auto implementation_or = implementation::create(topology, std::move(module_images));
	if (!implementation_or.is_ok()) {
		return implementation_or.error();
	}
	try {
		return std::unique_ptr<module_runtime_generation>(
			new module_runtime_generation(std::move(implementation_or).value()));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate module runtime generation owner");
	}
}

module_runtime_generation::module_runtime_generation(std::unique_ptr<implementation> implementation) noexcept
	: implementation_(std::move(implementation))
{
}

module_runtime_generation::~module_runtime_generation() = default;

status module_runtime_generation::start_lifecycle_services(const provider::materialized_provider_runtime &materialized)
{
	return implementation_->start_lifecycle_services(materialized);
}

status module_runtime_generation::prepare_bootstrap(const kinetum::control::v1::ConfigSnapshot &snapshot,
						    uint64_t bootstrap_epoch)
{
	return implementation_->prepare_bootstrap(snapshot, bootstrap_epoch);
}

void module_runtime_generation::activate_worker(uint32_t worker_index, uint64_t bootstrap_epoch,
						uint64_t now_ns) noexcept
{
	implementation_->activate_worker(worker_index, bootstrap_epoch, now_ns);
}

void module_runtime_generation::publish_bootstrap_activation(uint64_t bootstrap_epoch) noexcept
{
	implementation_->publish_bootstrap_activation(bootstrap_epoch);
}

void module_runtime_generation::abort_prepared_bootstrap(uint64_t bootstrap_epoch) noexcept
{
	implementation_->abort_prepared_bootstrap(bootstrap_epoch);
}

void module_runtime_generation::retire_published_generation(uint64_t epoch) noexcept
{
	implementation_->retire_published_generation(epoch);
}

void module_runtime_generation::stop_lifecycle_services() noexcept
{
	implementation_->stop_lifecycle_services();
}

module_manager &module_runtime_generation::modules() noexcept
{
	return implementation_->modules();
}

status module_runtime_generation::bind_telemetry_channels(uint64_t runtime_generation,
							  std::span<worker_telemetry_channel *const> channels) noexcept
{
	return implementation_->bind_telemetry_channels(runtime_generation, channels);
}

void module_runtime_generation::unbind_telemetry_channels() noexcept
{
	implementation_->unbind_telemetry_channels();
}

std::span<lifecycle::lifecycle_context_owner *const>
module_runtime_generation::worker_telemetry_contexts(uint32_t worker_index) noexcept
{
	return implementation_->worker_telemetry_contexts(worker_index);
}

std::size_t module_runtime_generation::telemetry_context_count() const noexcept
{
	return implementation_->transition_context_count();
}

lifecycle::lifecycle_context_owner *module_runtime_generation::telemetry_context(uint32_t context_index) noexcept
{
	return implementation_->telemetry_context(context_index);
}

status module_runtime_generation::reserve_transition_telemetry(uint64_t from_epoch, uint64_t to_epoch) noexcept
{
	return implementation_->reserve_transition_telemetry(from_epoch, to_epoch);
}

void module_runtime_generation::discard_transition_telemetry(uint64_t to_epoch) noexcept
{
	implementation_->discard_transition_telemetry(to_epoch);
}

void module_runtime_generation::mark_telemetry_workers_quiesced() noexcept
{
	implementation_->mark_telemetry_workers_quiesced();
}

bool module_runtime_generation::lifecycle_services_running() const noexcept
{
	return implementation_->lifecycle_services_running();
}

int module_runtime_generation::lifecycle_notification_descriptor() const noexcept
{
	return implementation_->lifecycle_notification_descriptor();
}

status_or<uint64_t> module_runtime_generation::consume_lifecycle_notification() noexcept
{
	return implementation_->consume_lifecycle_notification();
}

std::size_t module_runtime_generation::completion_context_count() const noexcept
{
	return implementation_->transition_context_count();
}

std::size_t module_runtime_generation::completion_image_count() const noexcept
{
	return implementation_->transition_image_count();
}

std::size_t module_runtime_generation::completion_executor_count() const noexcept
{
	return implementation_->transition_executor_count();
}

uint32_t module_runtime_generation::completion_context_index(std::size_t ordinal) const noexcept
{
	return implementation_->transition_context_index(ordinal);
}

uint32_t module_runtime_generation::completion_image_index(std::size_t ordinal) const noexcept
{
	return implementation_->transition_context_image_index(ordinal);
}

std::size_t module_runtime_generation::completion_executor_index(std::size_t ordinal) const noexcept
{
	return implementation_->transition_context_executor_index(ordinal);
}

uint64_t module_runtime_generation::next_completion_task_sequence() noexcept
{
	return implementation_->next_transition_task_sequence();
}

status module_runtime_generation::preflight_future_completion(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	return implementation_->preflight_future_retirement(from_epoch, to_epoch);
}

status module_runtime_generation::preflight_completion_activation(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	return implementation_->preflight_transition_activation(from_epoch, to_epoch);
}

void module_runtime_generation::publish_completion_activation(uint64_t from_epoch, uint64_t to_epoch) noexcept
{
	implementation_->publish_transition_activation(from_epoch, to_epoch);
}

status module_runtime_generation::preflight_completion_retained(std::size_t ordinal, uint64_t epoch) const noexcept
{
	return implementation_->preflight_transition_retained(ordinal, epoch);
}

status_or<module_retirement_claim> module_runtime_generation::claim_completion_retained(std::size_t ordinal,
											uint64_t epoch) noexcept
{
	return implementation_->claim_transition_retained(ordinal, epoch);
}

status module_runtime_generation::submit_completion_retire(epoch_transition_retire_submission submission,
							   lifecycle_operation_control &control,
							   const module_retirement_claim &claim) noexcept
{
	return implementation_->submit_transition_claimed_retire(submission, control, claim);
}

std::optional<config_lifecycle_result> module_runtime_generation::try_take_completion_result() noexcept
{
	return implementation_->try_take_transition_result();
}

void module_runtime_generation::complete_completion_retirement(std::size_t ordinal,
							       module_retirement_claim &claim) noexcept
{
	implementation_->complete_transition_claimed_retirement(ordinal, claim);
}

bool module_runtime_generation::completion_retirement_complete(uint64_t active_epoch) const noexcept
{
	return implementation_->transition_retirement_complete(active_epoch);
}

std::size_t module_runtime_generation::transition_context_count_() const noexcept
{
	return implementation_->transition_context_count();
}

std::size_t module_runtime_generation::transition_image_count_() const noexcept
{
	return implementation_->transition_image_count();
}

std::size_t module_runtime_generation::transition_executor_count_() const noexcept
{
	return implementation_->transition_executor_count();
}

uint32_t module_runtime_generation::transition_context_image_index_(std::size_t context_ordinal) const noexcept
{
	return implementation_->transition_context_image_index(context_ordinal);
}

uint32_t module_runtime_generation::transition_context_index_(std::size_t context_ordinal) const noexcept
{
	return implementation_->transition_context_index(context_ordinal);
}

std::size_t module_runtime_generation::transition_context_executor_index_(std::size_t context_ordinal) const noexcept
{
	return implementation_->transition_context_executor_index(context_ordinal);
}

uint64_t module_runtime_generation::next_transition_task_sequence_() noexcept
{
	return implementation_->next_transition_task_sequence();
}

status
module_runtime_generation::validate_transition_snapshot_(const kinetum::control::v1::ConfigSnapshot &snapshot) const
{
	return implementation_->validate_transition_snapshot(snapshot);
}

status_or<epoch_arena_ownership> module_runtime_generation::allocate_transition_arena_(std::size_t context_ordinal,
										       uint64_t epoch) noexcept
{
	return implementation_->allocate_transition_arena(context_ordinal, epoch);
}

status module_runtime_generation::submit_transition_prepare_(std::size_t context_ordinal, uint64_t task_sequence,
							     uint64_t epoch,
							     const kinetum::control::v1::ConfigSnapshot &snapshot,
							     lifecycle_operation_control &control,
							     epoch_arena_ownership &&arena) noexcept
{
	return implementation_->submit_transition_prepare(context_ordinal, task_sequence, epoch, snapshot, control,
							  std::move(arena));
}

status
module_runtime_generation::submit_transition_retire_(std::size_t context_ordinal, uint64_t task_sequence,
						     lifecycle_operation_control &control,
						     const lifecycle::prepared_config_ownership &prepared) noexcept
{
	return implementation_->submit_transition_retire(context_ordinal, task_sequence, control, prepared);
}

std::optional<config_lifecycle_result> module_runtime_generation::try_take_transition_result_() noexcept
{
	return implementation_->try_take_transition_result();
}

status module_runtime_generation::stage_transition_prepared_(std::size_t context_ordinal,
							     lifecycle::prepared_config_ownership &prepared) noexcept
{
	return implementation_->stage_transition_prepared(context_ordinal, prepared);
}

status_or<lifecycle::prepared_config_ownership>
module_runtime_generation::discard_transition_prepared_(std::size_t context_ordinal, uint64_t epoch) noexcept
{
	return implementation_->discard_transition_prepared(context_ordinal, epoch);
}

status module_runtime_generation::preflight_transition_prepared_(uint64_t epoch) const noexcept
{
	return implementation_->preflight_transition_prepared(epoch);
}

void module_runtime_generation::publish_transition_prepared_(uint64_t epoch) noexcept
{
	implementation_->publish_transition_prepared(epoch);
}

void module_runtime_generation::clear_transition_prepared_(uint64_t epoch) noexcept
{
	implementation_->clear_transition_prepared(epoch);
}

void module_runtime_generation::complete_transition_retirement_(std::size_t context_ordinal,
								lifecycle::prepared_config_ownership &prepared) noexcept
{
	implementation_->complete_transition_retirement(context_ordinal, prepared);
}

}  // namespace kinetum::dp::module
