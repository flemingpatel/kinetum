// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file region_worker_launcher.hpp
 * @brief Provider-neutral cold-path launch boundary for packet workers.
 * @author Fleming Patel
 *
 * A launcher binds a fixed compact-worker set to an execution facility before
 * any worker callback runs. Core lifecycle state remains indexed by compact
 * worker identity; provider-native thread or scheduler identities stay inside
 * the provider implementation that establishes them.
 */

#include <functional>
#include <span>
#include <thread>
#include <vector>

#include "src/common/status.hpp"
#include "src/dp/worker_lifecycle.hpp"

namespace kinetum::dp
{

/** @brief Complete launch request for one exact compact-worker set. */
struct region_worker_launch_spec {
	std::span<worker_lifecycle_context> worker_contexts;  ///< Contexts indexed by compact worker ID.
	std::vector<std::thread> *threads{nullptr};	      ///< Runtime-owned worker thread handles.
	/** Optional fallible owner-thread setup completed before any activation. */
	std::function<kinetum::common::status(int worker_id)> configure_worker;
	/** Required non-failing owner-thread activation after complete setup. */
	std::function<void(int worker_id)> activate_worker;
	/** Required non-failing coordinator publication after every activation. */
	std::function<void()> commit_activation;
	/** Required non-failing cold activation of the complete provider ingress set. */
	std::function<void()> activate_packet_io;
	/** Required non-failing readiness publication after every worker is RUNNING. */
	std::function<void()> publish_running_generation;
	/** Optional non-failing owner-thread release after rollback or body completion. */
	std::function<void(int worker_id)> release_worker;
	std::function<void(int worker_id)> run_worker;	///< Packet body entered only after set-wide activation.
};

/** @brief Complete join request for one previously launched worker set. */
struct region_worker_join_spec {
	std::vector<std::thread> *threads{nullptr};  ///< Runtime-owned worker thread handles.
};

/**
 * @brief Validate the provider-neutral launch contract without side effects.
 *
 * @param spec Candidate launch request.
 * @return OK for exact contexts, callbacks, and empty thread ownership.
 */
[[nodiscard]] kinetum::common::status validate_region_worker_launch_spec(const region_worker_launch_spec &spec);

/**
 * @brief Validate the provider-neutral join contract without side effects.
 *
 * @param spec Candidate join request.
 * @return OK when the runtime supplies its thread vector.
 */
[[nodiscard]] kinetum::common::status validate_region_worker_join_spec(const region_worker_join_spec &spec);

/**
 * @brief Publish immediate exit to every context in one launch transaction.
 *
 * @param contexts Exact compact worker contexts reserved by the transaction.
 */
void request_region_worker_exit(std::span<worker_lifecycle_context> contexts) noexcept;

/**
 * @brief Restore a failed, fully joined launch reservation to canonical INIT.
 *
 * This is legal only when the all-or-none setup gate proved that no worker body
 * was released and every setup thread has been joined.
 *
 * @param contexts Exact compact worker contexts owned by the failed launch.
 */
void reset_region_worker_launch_reservation(std::span<worker_lifecycle_context> contexts) noexcept;

/**
 * @brief Join every joinable worker or fail-stop on an ownership violation.
 *
 * @param threads Runtime-owned worker handles.
 * @return OK after every joinable thread joined.
 *
 * A join exception means the caller is attempting an illegal self-join or no
 * longer owns the thread represented by the handle. Releasing worker-owned
 * packet state after either condition is unsafe, so no recoverable error is
 * returned.
 */
[[nodiscard]] kinetum::common::status join_region_worker_threads(std::vector<std::thread> &threads) noexcept;

/** @brief Cold-path interface for exact packet-worker launch and join. */
class region_worker_launcher {
    public:
	/** @brief Destroy a launcher after every owned worker has joined. */
	virtual ~region_worker_launcher() = default;

	/** @return Stable static diagnostic name for this launcher. */
	[[nodiscard]] virtual const char *name() const noexcept = 0;

	/**
	 * @brief Launch the complete requested worker set or roll it back.
	 *
	 * Every owner thread completes optional fallible setup before any activation
	 * callback runs. Activation is then invoked on each owner thread without a
	 * platform lock held. It is a non-failing publication boundary: an exception
	 * terminates the process. After every owner activation returns, the launcher
	 * invokes the coordinator's one non-failing generation commit with packet
	 * bodies still closed. Each owner then publishes RUNNING. After observing the
	 * complete running set, the launcher invokes the one non-failing provider-I/O
	 * activation with every packet body still closed, publishes readiness, and
	 * only then releases every packet body together.
	 * A pre-activation failure rolls back each successfully configured owner on
	 * that same thread.
	 *
	 * @param spec Exact launch transaction.
	 * @return OK only when every requested worker has published RUNNING, the
	 *         provider ingress and the complete generation have been published
	 *         ready, and every packet body has been released.
	 */
	[[nodiscard]] virtual kinetum::common::status launch(const region_worker_launch_spec &spec) = 0;

	/**
	 * @brief Join every worker previously launched by this instance.
	 *
	 * @param spec Runtime-owned join transaction.
	 * @return OK after every worker is joined.
	 */
	[[nodiscard]] virtual kinetum::common::status join(const region_worker_join_spec &spec) = 0;
};

/** @brief Standard-thread launcher for facilities using caller-owned worker threads. */
class std_thread_worker_launcher final : public region_worker_launcher {
    public:
	/** @return Stable standard-thread launcher name. */
	[[nodiscard]] const char *name() const noexcept override
	{
		return "std_thread_worker_launcher";
	}

	/** @copydoc region_worker_launcher::launch */
	[[nodiscard]] kinetum::common::status launch(const region_worker_launch_spec &spec) override;

	/** @copydoc region_worker_launcher::join */
	[[nodiscard]] kinetum::common::status join(const region_worker_join_spec &spec) override;
};

}  // namespace kinetum::dp
