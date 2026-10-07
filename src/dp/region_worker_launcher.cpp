// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file region_worker_launcher.cpp
 * @brief Provider-neutral packet-worker launch protocol.
 * @author Fleming Patel
 */

#include "src/dp/region_worker_launcher.hpp"

#include <condition_variable>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "src/common/packet_thread_log_guard.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;

namespace
{

/** @brief All-or-none setup gate for one standard-thread worker generation. */
struct std_thread_start_gate {
	std::mutex mutex;		    ///< Protects every predicate field below.
	std::condition_variable cv;	    ///< Wakes the launch owner and setup waiters.
	std::size_t configured{0};	    ///< Workers that completed owner-local setup.
	std::size_t activated{0};	    ///< Workers that completed owner-local activation.
	std::size_t running{0};		    ///< Workers that published exact RUNNING state.
	int failed_worker_id{-1};	    ///< Compact worker whose setup threw, or -1.
	bool failed{false};		    ///< Setup or thread creation failed.
	bool release_activation{false};	    ///< Launch owner released the activation phase.
	bool release_workers{false};	    ///< Launch owner released owner threads into RUNNING.
	bool release_worker_bodies{false};  ///< Launch owner released all packet bodies together.
	std::optional<status> failure;	    ///< Exact first setup failure when one was returned.
};

/**
 * @brief Publish one setup failure without executing a worker body.
 *
 * @param gate Shared launch gate.
 * @param worker_id Compact worker whose setup failed.
 * @param failure Optional detailed setup error transferred into the gate for the first failing worker.
 */
void publish_std_thread_setup_failure(const std::shared_ptr<std_thread_start_gate> &gate, int worker_id,
				      std::optional<status> failure = std::nullopt)
{
	{
		std::lock_guard<std::mutex> lock(gate->mutex);
		if (!gate->failed) {
			gate->failed = true;
			gate->failed_worker_id = worker_id;
			gate->failure = std::move(failure);
		}
	}
	gate->cv.notify_all();
}

}  // namespace

status validate_region_worker_launch_spec(const region_worker_launch_spec &spec)
{
	if (spec.threads == nullptr) {
		return status(status_code::INVALID_ARGUMENT, "worker thread output is required");
	}
	if (!spec.run_worker) {
		return status(status_code::INVALID_ARGUMENT, "runtime worker body is required");
	}
	if (!spec.activate_worker) {
		return status(status_code::INVALID_ARGUMENT, "runtime worker activation callback is required");
	}
	if (!spec.commit_activation) {
		return status(status_code::INVALID_ARGUMENT, "runtime generation activation commit is required");
	}
	if (!spec.activate_packet_io) {
		return status(status_code::INVALID_ARGUMENT, "runtime packet-I/O activation callback is required");
	}
	if (!spec.publish_running_generation) {
		return status(status_code::INVALID_ARGUMENT, "runtime running-generation publication is required");
	}
	if (spec.worker_contexts.empty()) {
		return status(status_code::INVALID_ARGUMENT, "runtime worker set cannot be empty");
	}
	for (const auto &thread : *spec.threads) {
		if (thread.joinable()) {
			return status(status_code::FAILED_PRECONDITION, "worker thread vector already owns a thread");
		}
	}
	return status::ok();
}

status validate_region_worker_join_spec(const region_worker_join_spec &spec)
{
	if (spec.threads == nullptr) {
		return status(status_code::INVALID_ARGUMENT, "worker thread vector is required");
	}
	return status::ok();
}

void request_region_worker_exit(std::span<worker_lifecycle_context> contexts) noexcept
{
	for (auto &context : contexts) {
		context.request_exit();
	}
}

void reset_region_worker_launch_reservation(std::span<worker_lifecycle_context> contexts) noexcept
{
	for (auto &context : contexts) {
		context.reset();
	}
}

status join_region_worker_threads(std::vector<std::thread> &threads) noexcept
{
	for (auto &thread : threads) {
		try {
			if (thread.joinable()) {
				thread.join();
			}
		} catch (...) {
			// A join failure cannot be followed by endpoint or storage teardown:
			// the thread may still execute through their borrowed operation tables.
			std::terminate();
		}
	}
	return status::ok();
}

status std_thread_worker_launcher::launch(const region_worker_launch_spec &spec)
{
	if (auto validation = validate_region_worker_launch_spec(spec); !validation.is_ok()) {
		return validation;
	}

	spec.threads->clear();
	for (auto &context : spec.worker_contexts) {
		context.reset();
		context.set_state(worker_lifecycle_state::STARTING);
	}

	std::shared_ptr<std_thread_start_gate> gate;
	try {
		gate = std::make_shared<std_thread_start_gate>();
		spec.threads->reserve(spec.worker_contexts.size());
		for (std::size_t worker_index = 0; worker_index < spec.worker_contexts.size(); ++worker_index) {
			if (worker_index > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
				throw std::length_error("compact worker index exceeds launcher callback range");
			}
			const auto worker_id = static_cast<int>(worker_index);
			spec.threads->emplace_back([gate, configure_worker = spec.configure_worker,
						    activate_worker = spec.activate_worker,
						    release_worker = spec.release_worker, run_worker = spec.run_worker,
						    worker_contexts = spec.worker_contexts, worker_id]() mutable {
				kinetum::common::packet_thread_log_guard packet_diagnostics;
				bool configured = false;
				try {
					if (configure_worker) {
						auto configure_status = configure_worker(worker_id);
						if (!configure_status.is_ok()) {
							publish_std_thread_setup_failure(gate, worker_id,
											 std::move(configure_status));
							return;
						}
						configured = true;
					}
				} catch (...) {
					// A throwing setup callback leaves external ownership unknowable.
					// The status-returning contract is the only recoverable channel.
					std::terminate();
				}

				std::unique_lock<std::mutex> lock(gate->mutex);
				++gate->configured;
				gate->cv.notify_all();
				gate->cv.wait(lock, [&gate]() { return gate->failed || gate->release_activation; });
				if (gate->failed) {
					lock.unlock();
					if (configured && release_worker) {
						try {
							release_worker(worker_id);
						} catch (...) {
							std::terminate();
						}
					}
					return;
				}
				lock.unlock();
				try {
					activate_worker(worker_id);
				} catch (...) {
					// Activation is the irreversible owner publication. A thrown
					// exception cannot be represented as recoverable rollback.
					std::terminate();
				}

				lock.lock();
				++gate->activated;
				gate->cv.notify_all();
				gate->cv.wait(lock, [&gate]() { return gate->release_workers; });
				lock.unlock();

				auto &worker_context = worker_contexts[static_cast<std::size_t>(worker_id)];
				if (try_enter_worker_running(worker_context) != worker_enter_running_result::RUNNING) {
					// Every module ACTIVATE and the generation commit have completed.
					// A competing or malformed lifecycle state can no longer be
					// represented as recoverable startup rollback.
					std::terminate();
				}
				lock.lock();
				++gate->running;
				gate->cv.notify_all();
				gate->cv.wait(lock, [&gate]() { return gate->release_worker_bodies; });
				lock.unlock();
				gate.reset();
				try {
					run_worker(worker_id);
				} catch (...) {
					if (configured && release_worker) {
						try {
							release_worker(worker_id);
						} catch (...) {
							std::terminate();
						}
					}
					std::terminate();
				}
				worker_context.set_state(worker_lifecycle_state::EXITED);
				if (configured && release_worker) {
					try {
						release_worker(worker_id);
					} catch (...) {
						std::terminate();
					}
				}
			});
		}
	} catch (const std::exception &exception) {
		if (gate) {
			publish_std_thread_setup_failure(gate, -1);
		}
		request_region_worker_exit(spec.worker_contexts);
		(void)join_region_worker_threads(*spec.threads);
		spec.threads->clear();
		reset_region_worker_launch_reservation(spec.worker_contexts);
		return status(status_code::RESOURCE_EXHAUSTED,
			      std::string("failed to launch runtime workers: ") + exception.what());
	} catch (...) {
		if (gate) {
			publish_std_thread_setup_failure(gate, -1);
		}
		request_region_worker_exit(spec.worker_contexts);
		(void)join_region_worker_threads(*spec.threads);
		spec.threads->clear();
		reset_region_worker_launch_reservation(spec.worker_contexts);
		return status(status_code::RESOURCE_EXHAUSTED, "failed to launch runtime workers: unknown exception");
	}

	std::unique_lock<std::mutex> lock(gate->mutex);
	gate->cv.wait(lock, [&gate, expected = spec.worker_contexts.size()]() {
		return gate->failed || gate->configured == expected;
	});
	if (gate->failed) {
		const int failed_worker_id = gate->failed_worker_id;
		auto failure = std::move(gate->failure);
		lock.unlock();
		request_region_worker_exit(spec.worker_contexts);
		(void)join_region_worker_threads(*spec.threads);
		spec.threads->clear();
		reset_region_worker_launch_reservation(spec.worker_contexts);
		if (failure.has_value()) {
			return std::move(*failure);
		}
		return status(status_code::FAILED_PRECONDITION,
			      failed_worker_id >= 0 ? "runtime worker setup failed for compact worker " +
							      std::to_string(failed_worker_id) :
						      "runtime worker setup failed before complete launch");
	}

	// Setup is complete for the full generation, so no activation can observe a
	// partially configured owner set.
	gate->release_activation = true;
	lock.unlock();
	gate->cv.notify_all();

	lock.lock();
	gate->cv.wait(lock, [&gate, expected = spec.worker_contexts.size()]() { return gate->activated == expected; });
	lock.unlock();
	try {
		// Every owner-local activation completed while packet bodies remain closed.
		// The sole coordinator now publishes generation-wide snapshot/phase truth
		// before any packet or RX work can observe the activated module views.
		spec.commit_activation();
	} catch (...) {
		std::terminate();
	}
	lock.lock();
	gate->release_workers = true;
	lock.unlock();
	gate->cv.notify_all();

	lock.lock();
	gate->cv.wait(lock, [&gate, expected = spec.worker_contexts.size()]() { return gate->running == expected; });
	lock.unlock();
	try {
		// Every owner has published RUNNING and every packet body remains behind
		// the set-wide gate. The cold provider edge can now make the exact ingress
		// set live without racing a packet consumer.
		spec.activate_packet_io();
		// Provider ingress and every worker owner are coherent. Readiness is the
		// final publication before packet bodies are released together.
		spec.publish_running_generation();
	} catch (...) {
		std::terminate();
	}
	lock.lock();
	gate->release_worker_bodies = true;
	lock.unlock();
	gate->cv.notify_all();

	return status::ok();
}

status std_thread_worker_launcher::join(const region_worker_join_spec &spec)
{
	if (auto validation = validate_region_worker_join_spec(spec); !validation.is_ok()) {
		return validation;
	}
	return join_region_worker_threads(*spec.threads);
}

}  // namespace kinetum::dp
