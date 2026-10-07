// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file runtime_service_launcher.hpp
 * @brief Transactional launch boundary for planned cold lifecycle services.
 * @author Fleming Patel
 *
 * The launcher consumes a non-optional compiled lifecycle-service topology.
 * It cannot infer service identities, CPU placement, NUMA placement, or a
 * coordinator from worker topology. The coordinator carries one independently
 * verified bounded command-mailbox capacity; every executor carries zero and
 * is pre-created and mapped one-to-one to its compiled service record.
 *
 * Executor entry points wait behind one all-or-none gate. If any launch, CPU
 * binding, or topology check fails, the gate is cancelled, every created
 * service is joined, and no lifecycle callback executes. On normal stop, task
 * admission closes first, accepted tasks drain to durable results, every result
 * is handed to the coordinator-owned consumer, and only then are services
 * joined.
 *
 * @par Thread Safety
 * launch() and stop_and_join() are coordinator-thread operations. The launcher
 * owns no packet worker and is not reentrant. Backend entry functions execute
 * on native service threads or backend lcores.
 *
 * @par Performance
 * This is startup/shutdown and configuration cold-path code. Generic types do
 * not expose DPDK state and are unreachable from packet execution.
 */

#include <cstdint>
#include <memory>
#include <vector>

#include "src/common/status.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/lifecycle/config_lifecycle_executor.hpp"

namespace kinetum::dp::lifecycle
{

/** @brief Backend entry-point shape shared with native threads and DPDK lcores. */
using runtime_service_entry_fn = int32_t (*)(void *argument) noexcept;

/**
 * @brief Backend-specific placement and lifecycle for planned runtime services.
 */
class runtime_service_backend {
    public:
	/** @brief Destroy one backend placement/lifecycle authority. */
	virtual ~runtime_service_backend() = default;

	/**
	 * @brief Bind the caller-owned coordinator to its exact backend placement.
	 *
	 * Native backends pin the calling thread. DPDK backends verify that the
	 * caller already is the planned EAL main lcore; they never launch a second
	 * coordinator thread.
	 *
	 * @param coordinator Exact compiled coordinator placement.
	 * @return OK after exact binding/proof; non-OK otherwise.
	 */
	[[nodiscard]] virtual kinetum::common::status
	bind_coordinator(const kinetum::common::compiled_runtime_service &coordinator) noexcept = 0;

	/**
	 * @brief Launch one lifecycle executor at its exact backend placement.
	 *
	 * @param service Exact compiled lifecycle-executor placement.
	 * @param entry Stable executor service entry point.
	 * @param argument Opaque launcher-owned entry context.
	 * @return OK when the backend owns one joinable service. A non-OK result
	 *         guarantees that no service or argument reference was retained.
	 */
	[[nodiscard]] virtual kinetum::common::status
	launch_executor(const kinetum::common::compiled_runtime_service &service, runtime_service_entry_fn entry,
			void *argument) noexcept = 0;

	/**
	 * @brief Join one previously launched lifecycle executor.
	 *
	 * @param service Exact placement originally passed to launch_executor().
	 * @return OK after backend service completion. A non-OK result retains
	 *         backend ownership so the coordinator may retry the join.
	 */
	[[nodiscard]] virtual kinetum::common::status
	join_executor(const kinetum::common::compiled_runtime_service &service) noexcept = 0;
};

/**
 * @brief Linux native-thread backend for cold runtime services.
 *
 * The coordinator remains on the caller. Each lifecycle executor receives one
 * dedicated std::thread pinned to the exact single CPU before it reaches the
 * launcher's all-or-none gate.
 */
class native_runtime_service_backend final : public runtime_service_backend {
    public:
	/** @brief Construct an empty native service backend. */
	native_runtime_service_backend();
	native_runtime_service_backend(const native_runtime_service_backend &) = delete;
	native_runtime_service_backend &operator=(const native_runtime_service_backend &) = delete;
	native_runtime_service_backend(native_runtime_service_backend &&) = delete;
	native_runtime_service_backend &operator=(native_runtime_service_backend &&) = delete;
	/** @brief Destroy a backend with no remaining joinable service threads. */
	~native_runtime_service_backend() override;

	/** @copydoc runtime_service_backend::bind_coordinator */
	[[nodiscard]] kinetum::common::status
	bind_coordinator(const kinetum::common::compiled_runtime_service &coordinator) noexcept override;

	/** @copydoc runtime_service_backend::launch_executor */
	[[nodiscard]] kinetum::common::status launch_executor(const kinetum::common::compiled_runtime_service &service,
							      runtime_service_entry_fn entry,
							      void *argument) noexcept override;

	/** @copydoc runtime_service_backend::join_executor */
	[[nodiscard]] kinetum::common::status
	join_executor(const kinetum::common::compiled_runtime_service &service) noexcept override;

    private:
	/** @brief Native backend thread ownership hidden from generic consumers. */
	struct implementation;
	std::unique_ptr<implementation> implementation_;  ///< Joinable native service ownership.
};

/**
 * @brief Coordinator-owned sink for exact shutdown/drain results.
 */
class config_lifecycle_result_consumer {
    public:
	/** @brief Destroy one coordinator-owned result consumer. */
	virtual ~config_lifecycle_result_consumer() = default;

	/**
	 * @brief Consume one durable executor result during stop/drain.
	 *
	 * A result carrying a live prepared token must transfer or exactly retire
	 * that token before returning; dropping it is a fatal ownership violation.
	 *
	 * @param result Exact move-only result.
	 */
	virtual void consume(config_lifecycle_result &&result) noexcept = 0;
};

/**
 * @brief All-or-none launcher for one compiled lifecycle-service topology.
 */
class runtime_service_launcher {
    public:
	/** @brief Construct an empty launcher with no backend ownership. */
	runtime_service_launcher();
	runtime_service_launcher(const runtime_service_launcher &) = delete;
	runtime_service_launcher &operator=(const runtime_service_launcher &) = delete;
	runtime_service_launcher(runtime_service_launcher &&) = delete;
	runtime_service_launcher &operator=(runtime_service_launcher &&) = delete;
	/** @brief Destroy an empty launcher; unjoined service ownership is fatal. */
	~runtime_service_launcher();

	/**
	 * @brief Launch the exact coordinator and lifecycle-executor service set.
	 *
	 * The non-optional @p topology makes launching absent placement
	 * unrepresentable. Executor order must exactly match the compiled lifecycle
	 * executor index vector.
	 *
	 * @param topology Complete compiled placement facts.
	 * @param runtime_services Compiled plan-order service records.
	 * @param executors Pre-created executor pointers in topology order; every
	 *        executor must outlive this launcher's running state.
	 * @param backend Backend-specific placement/lifecycle authority that must
	 *        outlive this launcher's running state.
	 * @return OK only after complete launch and gate release; failure leaves no
	 *         launched service and executes zero lifecycle callbacks.
	 */
	[[nodiscard]] kinetum::common::status
	launch(const kinetum::common::compiled_lifecycle_service_topology &topology,
	       const std::vector<kinetum::common::compiled_runtime_service> &runtime_services,
	       const std::vector<config_lifecycle_executor *> &executors, runtime_service_backend &backend);

	/**
	 * @brief Stop admission, drain every accepted task/result, and join services.
	 *
	 * @param consumer Coordinator-owned exact result consumer.
	 * @return OK after every service joins. A backend join error retains all
	 *         unjoined ownership in this launcher so the coordinator may retry.
	 */
	[[nodiscard]] kinetum::common::status stop_and_join(config_lifecycle_result_consumer &consumer) noexcept;

	/** @return true when the launcher still owns a launched service set. */
	[[nodiscard]] bool running() const noexcept;

    private:
	/** @brief Complete launcher-owned gate, service, and join state. */
	struct launch_state;
	std::unique_ptr<launch_state> state_;  ///< Live launched set, including retryable unjoined ownership.
};

}  // namespace kinetum::dp::lifecycle
