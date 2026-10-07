// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_service_launcher.cpp
 * @brief Transactional native and backend-neutral runtime-service launch.
 * @author Fleming Patel
 */

#include "src/dp/lifecycle/runtime_service_launcher.hpp"

#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include "src/common/runtime_service_ids.hpp"
#include "src/dp/thread_affinity.hpp"

namespace kinetum::dp::lifecycle
{

using kinetum::common::compiled_lifecycle_service_topology;
using kinetum::common::compiled_runtime_service;
using kinetum::common::compiled_runtime_service_role;
using kinetum::common::status;
using kinetum::common::status_code;

namespace
{

/**
 * @brief Preserve one native exception diagnostic without escaping a backend boundary.
 *
 * @param code Typed failure category.
 * @param prefix Static operation context prepended to @p error.
 * @param error Exact native exception text.
 * @param fallback Allocation-free diagnostic used only when composition cannot complete.
 * @return Exact composed status, or the same typed category with @p fallback.
 */
[[nodiscard]] status native_service_exception_status(status_code code, std::string_view prefix,
						     const std::system_error &error,
						     kinetum::common::static_status_text fallback) noexcept
{
	try {
		std::string message(prefix);
		message.append(error.what());
		return status(code, std::move(message));
	} catch (const std::bad_alloc &) {
		return status(code, fallback);
	} catch (const std::length_error &) {
		return status(code, fallback);
	}
}

/** @brief Closed all-or-none gate shared by every launch entry context. */
class service_start_gate {
    public:
	/** @return true after complete launch opens the gate; false when rollback cancels it. */
	[[nodiscard]] bool wait() noexcept
	{
		std::unique_lock<std::mutex> lock(mutex_);
		cv_.wait(lock, [this]() { return state_ != state::WAITING; });
		return state_ == state::OPEN;
	}

	/** @brief Release every service into its pre-created executor loop. */
	void open() noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		state_ = state::OPEN;
		cv_.notify_all();
	}

	/** @brief Release every service directly to rollback without callback work. */
	void cancel() noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		state_ = state::CANCELLED;
		cv_.notify_all();
	}

    private:
	/** One-way all-or-none launch decision shared by the waiting service entries. */
	enum class state : uint8_t {
		WAITING = 0,  ///< No backend entry may execute the service loop.
		OPEN,	      ///< Complete launch admits every service loop.
		CANCELLED,    ///< Rollback releases every entry without callbacks.
	};

	std::mutex mutex_;	       ///< Protects the one-way gate transition.
	std::condition_variable cv_;   ///< Wakes every backend entry on terminal state.
	state state_{state::WAITING};  ///< Current all-or-none gate state.
};

/** @brief Stable backend-entry argument owned for the complete service lifetime. */
struct service_entry_context {
	service_start_gate *gate{nullptr};	       ///< Launcher-owned all-or-none gate.
	config_lifecycle_executor *executor{nullptr};  ///< Exact pre-created executor.
};

/**
 * @brief Enter one executor only after complete all-or-none launch.
 *
 * @param argument Pointer to one stable service_entry_context.
 * @return Zero after cancellation or normal executor shutdown.
 */
int32_t runtime_service_entry(void *argument) noexcept
{
	auto *context = static_cast<service_entry_context *>(argument);
	if (!context || !context->gate || !context->executor) {
		return -1;
	}
	if (!context->gate->wait()) {
		return 0;
	}
	context->executor->run();
	return 0;
}

/**
 * @brief Validate exact service/executor cardinality before backend effects.
 *
 * @param topology Non-optional compiled lifecycle placement.
 * @param services Plan-order compiled services.
 * @param executors Pre-created executors in topology order.
 * @return OK for one coordinator plus exact executor mapping.
 */
[[nodiscard]] status validate_launch_topology(const compiled_lifecycle_service_topology &topology,
					      const std::vector<compiled_runtime_service> &services,
					      const std::vector<config_lifecycle_executor *> &executors)
{
	if (topology.lifecycle_executor_service_indices.empty()) {
		return status(status_code::INVALID_ARGUMENT,
			      "lifecycle service topology requires at least one exact executor");
	}
	if (services.size() != topology.lifecycle_executor_service_indices.size() + 1u) {
		return status(status_code::INVALID_ARGUMENT,
			      "runtime services contain an extra or missing lifecycle placement");
	}
	if (executors.size() != topology.lifecycle_executor_service_indices.size()) {
		return status(status_code::INVALID_ARGUMENT,
			      "pre-created executor count does not match compiled lifecycle topology");
	}
	if (topology.coordinator_service_index != 0 || topology.coordinator_service_index >= services.size()) {
		return status(status_code::INVALID_ARGUMENT,
			      "compiled lifecycle coordinator index is not the canonical first service");
	}
	const auto &coordinator = services[topology.coordinator_service_index];
	if (coordinator.service_index != topology.coordinator_service_index ||
	    coordinator.service_id != kinetum::common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID ||
	    coordinator.role != compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR ||
	    coordinator.cpu_core_id < 0 || coordinator.numa_node < 0 ||
	    coordinator.command_mailbox_capacity < kinetum::common::MIN_COORDINATOR_COMMAND_MAILBOX_CAPACITY ||
	    coordinator.command_mailbox_capacity > kinetum::common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY ||
	    (coordinator.command_mailbox_capacity & (coordinator.command_mailbox_capacity - 1u)) != 0u) {
		return status(status_code::INVALID_ARGUMENT, "compiled lifecycle coordinator placement is malformed");
	}

	// Runtime-service cardinality is bounded by the plan's NUMA-node set. Pairwise
	// scans keep this pre-backend validation allocation-free and deterministic.
	int32_t previous_numa = -1;
	for (std::size_t i = 0; i < topology.lifecycle_executor_service_indices.size(); ++i) {
		const uint32_t service_index = topology.lifecycle_executor_service_indices[i];
		if (service_index >= services.size() || service_index == topology.coordinator_service_index ||
		    !executors[i]) {
			return status(status_code::INVALID_ARGUMENT,
				      "compiled lifecycle executor index is duplicate, missing, or out of range");
		}
		for (std::size_t previous = 0; previous < i; ++previous) {
			if (topology.lifecycle_executor_service_indices[previous] == service_index) {
				return status(
					status_code::INVALID_ARGUMENT,
					"compiled lifecycle executor index is duplicate, missing, or out of range");
			}
		}
		const auto &service = services[service_index];
		bool core_is_disjoint = service.cpu_core_id != coordinator.cpu_core_id;
		for (std::size_t previous = 0; previous < i && core_is_disjoint; ++previous) {
			const uint32_t previous_index = topology.lifecycle_executor_service_indices[previous];
			core_is_disjoint = service.cpu_core_id != services[previous_index].cpu_core_id;
		}
		if (service.service_index != service_index ||
		    service.role != compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR ||
		    service.cpu_core_id < 0 || service.numa_node < 0 || service.command_mailbox_capacity != 0u ||
		    service.service_id !=
			    kinetum::common::runtime_services::make_lifecycle_executor_id(service.numa_node) ||
		    service.numa_node <= previous_numa || !core_is_disjoint ||
		    executors[i]->service_index() != service_index || executors[i]->numa_node() != service.numa_node) {
			return status(status_code::INVALID_ARGUMENT,
				      "pre-created lifecycle executor disagrees with exact service placement");
		}
		previous_numa = service.numa_node;
	}
	return status::ok();
}

}  // namespace

/** @brief Own every native lifecycle-service thread until exact join. */
struct native_runtime_service_backend::implementation {
	/** @brief One joinable native executor and its exact service identity. */
	struct thread_record {
		uint32_t service_index{0};  ///< Exact compiled service index.
		std::thread thread;	    ///< Joinable native executor thread.
	};

	std::vector<std::unique_ptr<thread_record>> threads;  ///< Currently launched native services.
};

native_runtime_service_backend::native_runtime_service_backend()
	: implementation_(std::make_unique<implementation>())
{
}

native_runtime_service_backend::~native_runtime_service_backend()
{
	if (std::any_of(implementation_->threads.begin(), implementation_->threads.end(),
			[](const auto &record) { return record->thread.joinable(); })) {
		std::terminate();
	}
}

status native_runtime_service_backend::bind_coordinator(const compiled_runtime_service &coordinator) noexcept
{
	if (coordinator.role != compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "native coordinator binding requires a coordinator service record"));
	}
	try {
		return kinetum::dp::bind_current_thread_to_cpu(coordinator.cpu_core_id, "runtime service");
	} catch (const std::bad_alloc &) {
		return status(
			status_code::RESOURCE_EXHAUSTED,
			kinetum::common::static_status_text("runtime-service affinity diagnostic exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "runtime-service affinity diagnostic exceeded a representation bound"));
	}
}

status native_runtime_service_backend::launch_executor(const compiled_runtime_service &service,
						       runtime_service_entry_fn entry, void *argument) noexcept
{
	if (service.role != compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR || !entry || !argument) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "native lifecycle launch requires an exact executor and entry context"));
	}
	if (std::any_of(implementation_->threads.begin(), implementation_->threads.end(),
			[service_index = service.service_index](const auto &record) {
				return record->service_index == service_index;
			})) {
		return status(status_code::ALREADY_EXISTS,
			      kinetum::common::static_status_text("native lifecycle executor is already launched"));
	}

	/** @brief One-shot affinity handshake from a new thread to its launcher. */
	struct startup_state {
		std::mutex mutex;	     ///< Protects one-shot readiness publication.
		std::condition_variable cv;  ///< Wakes the coordinator after affinity.
		bool ready{false};	     ///< True after affinity_result is final.
		int affinity_result{0};	     ///< Raw errno-style result; meaningful only when ready is true.
	};

	std::shared_ptr<startup_state> startup;
	implementation::thread_record *record = nullptr;
	try {
		startup = std::make_shared<startup_state>();
		auto owned_record = std::make_unique<implementation::thread_record>();
		owned_record->service_index = service.service_index;
		implementation_->threads.push_back(std::move(owned_record));
		record = implementation_->threads.back().get();
		record->thread = std::thread([startup, cpu_core_id = service.cpu_core_id, entry, argument]() noexcept {
			const int affinity_result = bind_current_thread_to_cpu_raw(cpu_core_id);
			{
				std::lock_guard<std::mutex> lock(startup->mutex);
				startup->affinity_result = affinity_result;
				startup->ready = true;
			}
			startup->cv.notify_all();
			if (affinity_result == 0) {
				(void)entry(argument);
			}
		});
	} catch (const std::system_error &error) {
		if (record && record->thread.joinable()) {
			record->thread.join();
		}
		if (record) {
			implementation_->threads.pop_back();
		}
		return native_service_exception_status(
			status_code::RESOURCE_EXHAUSTED, "failed to create native lifecycle service: ", error,
			kinetum::common::static_status_text("failed to create native lifecycle service"));
	} catch (const std::bad_alloc &) {
		if (record && record->thread.joinable()) {
			record->thread.join();
		}
		if (record) {
			implementation_->threads.pop_back();
		}
		return status(
			status_code::RESOURCE_EXHAUSTED,
			kinetum::common::static_status_text("failed to allocate native lifecycle service ownership"));
	} catch (const std::length_error &) {
		if (record && record->thread.joinable()) {
			record->thread.join();
		}
		if (record) {
			implementation_->threads.pop_back();
		}
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "native lifecycle service ownership exceeds the host size domain"));
	}

	std::unique_lock<std::mutex> lock(startup->mutex);
	startup->cv.wait(lock, [&startup]() { return startup->ready; });
	const int affinity_result = startup->affinity_result;
	lock.unlock();
	if (affinity_result != 0) {
		record->thread.join();
		implementation_->threads.pop_back();
		if (affinity_result == ENOMEM) {
			return status(status_code::RESOURCE_EXHAUSTED,
				      kinetum::common::static_status_text(
					      "failed to allocate exact runtime service CPU affinity set"));
		}
		if (affinity_result == EOVERFLOW) {
			return status(status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "runtime service CPU exceeds the platform affinity representation"));
		}
		try {
			std::string message = "failed to bind runtime service to CPU ";
			message.append(std::to_string(service.cpu_core_id));
			message.append(" (sched_setaffinity=");
			message.append(std::to_string(affinity_result));
			message.push_back(')');
			return status(status_code::FAILED_PRECONDITION, std::move(message));
		} catch (const std::bad_alloc &) {
			return status(status_code::FAILED_PRECONDITION,
				      kinetum::common::static_status_text("failed to bind runtime service to its CPU"));
		} catch (const std::length_error &) {
			return status(status_code::FAILED_PRECONDITION,
				      kinetum::common::static_status_text("failed to bind runtime service to its CPU"));
		}
	}
	return status::ok();
}

status native_runtime_service_backend::join_executor(const compiled_runtime_service &service) noexcept
{
	const auto record_it = std::find_if(implementation_->threads.begin(), implementation_->threads.end(),
					    [service_index = service.service_index](const auto &record) {
						    return record->service_index == service_index;
					    });
	if (record_it == implementation_->threads.end()) {
		return status(status_code::NOT_FOUND,
			      kinetum::common::static_status_text("native lifecycle executor was not launched"));
	}
	try {
		if ((*record_it)->thread.joinable()) {
			(*record_it)->thread.join();
		}
	} catch (const std::system_error &error) {
		return native_service_exception_status(
			status_code::INTERNAL_ERROR, "failed to join native lifecycle service: ", error,
			kinetum::common::static_status_text("failed to join native lifecycle service"));
	}
	implementation_->threads.erase(record_it);
	return status::ok();
}

/** @brief Complete ownership retained from successful gate publication to join. */
struct runtime_service_launcher::launch_state {
	service_start_gate gate;				  ///< Stable all-or-none entry gate.
	runtime_service_backend *backend{nullptr};		  ///< Exact backend authority through final join.
	std::vector<compiled_runtime_service> executor_services;  ///< Exact launched service records.
	std::vector<config_lifecycle_executor *> executors;	  ///< Pre-created executors in topology order.
	std::vector<service_entry_context> entries;		  ///< Stable backend entry arguments.
	std::vector<bool> joined;				  ///< Per-service successful-join evidence.
};

runtime_service_launcher::runtime_service_launcher() = default;

runtime_service_launcher::~runtime_service_launcher()
{
	if (state_) {
		std::terminate();
	}
}

status runtime_service_launcher::launch(const compiled_lifecycle_service_topology &topology,
					const std::vector<compiled_runtime_service> &runtime_services,
					const std::vector<config_lifecycle_executor *> &executors,
					runtime_service_backend &backend)
{
	if (state_) {
		return status(status_code::FAILED_PRECONDITION, "runtime lifecycle services are already launched");
	}
	if (const auto topology_status = validate_launch_topology(topology, runtime_services, executors);
	    !topology_status.is_ok()) {
		return topology_status;
	}

	std::unique_ptr<launch_state> candidate;
	try {
		candidate = std::make_unique<launch_state>();
		candidate->backend = &backend;
		candidate->executors = executors;
		candidate->executor_services.reserve(topology.lifecycle_executor_service_indices.size());
		candidate->entries.reserve(executors.size());
		candidate->joined.assign(executors.size(), false);
		for (std::size_t i = 0; i < executors.size(); ++i) {
			candidate->executor_services.push_back(
				runtime_services[topology.lifecycle_executor_service_indices[i]]);
			candidate->entries.push_back(service_entry_context{&candidate->gate, executors[i]});
		}
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED, "failed to allocate exact runtime-service launch state");
	}

	std::size_t reserved = 0;
	for (auto *executor : candidate->executors) {
		const auto reserve_status = executor->reserve_launch_();
		if (!reserve_status.is_ok()) {
			for (std::size_t i = reserved; i > 0; --i) {
				candidate->executors[i - 1u]->cancel_launch_reservation_();
			}
			return reserve_status;
		}
		++reserved;
	}
	const auto cancel_reservations = [&candidate]() noexcept {
		for (auto *executor : candidate->executors) {
			executor->cancel_launch_reservation_();
		}
	};

	std::size_t launched = 0;
	for (std::size_t i = 0; i < candidate->executor_services.size(); ++i) {
		const auto launch_status = backend.launch_executor(candidate->executor_services[i],
								   runtime_service_entry, &candidate->entries[i]);
		if (!launch_status.is_ok()) {
			candidate->gate.cancel();
			for (std::size_t j = launched; j > 0; --j) {
				if (!backend.join_executor(candidate->executor_services[j - 1u]).is_ok()) {
					// Destroying candidate entry state while a backend may still
					// execute it would create an immediate use-after-free.
					std::terminate();
				}
			}
			cancel_reservations();
			return launch_status;
		}
		++launched;
	}

	auto coordinator_status = backend.bind_coordinator(runtime_services[topology.coordinator_service_index]);
	if (!coordinator_status.is_ok()) {
		candidate->gate.cancel();
		for (std::size_t i = launched; i > 0; --i) {
			if (!backend.join_executor(candidate->executor_services[i - 1u]).is_ok()) {
				std::terminate();
			}
		}
		cancel_reservations();
		return coordinator_status;
	}

	// No fallible operation remains after exact coordinator binding. Submission
	// becomes available for the complete set before one gate publication makes
	// every executor runnable.
	for (auto *executor : candidate->executors) {
		executor->publish_launch_();
	}
	state_ = std::move(candidate);
	state_->gate.open();
	return status::ok();
}

status runtime_service_launcher::stop_and_join(config_lifecycle_result_consumer &consumer) noexcept
{
	if (!state_) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text("runtime lifecycle services are not launched"));
	}
	for (auto *executor : state_->executors) {
		executor->request_stop();
	}

	for (;;) {
		bool all_stopped = true;
		config_lifecycle_executor *wait_executor = nullptr;
		for (auto *executor : state_->executors) {
			while (auto result = executor->try_take_result()) {
				consumer.consume(std::move(*result));
			}
			if (!executor->stopped()) {
				all_stopped = false;
				if (!wait_executor) {
					wait_executor = executor;
				}
			}
		}
		if (all_stopped) {
			break;
		}
		wait_executor->wait_for_result_or_stop_();
	}

	// stopped() is release-published only after accepted == published. A final
	// drain therefore consumes every durable completion without racing a later
	// producer publication.
	for (auto *executor : state_->executors) {
		while (auto result = executor->try_take_result()) {
			consumer.consume(std::move(*result));
		}
	}

	status join_status = status::ok();
	for (std::size_t i = state_->executor_services.size(); i > 0; --i) {
		if (state_->joined[i - 1u]) {
			continue;
		}
		auto current = state_->backend->join_executor(state_->executor_services[i - 1u]);
		if (current.is_ok()) {
			state_->joined[i - 1u] = true;
		} else if (join_status.is_ok()) {
			join_status = std::move(current);
		}
	}
	if (join_status.is_ok()) {
		state_.reset();
	}
	return join_status;
}

bool runtime_service_launcher::running() const noexcept
{
	return state_ != nullptr;
}

}  // namespace kinetum::dp::lifecycle
