// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file config_lifecycle_executor.hpp
 * @brief Bounded NUMA-local executor for cold prepare and retire operations.
 * @author Fleming Patel
 *
 * A coordinator is the sole task producer and result consumer. One pre-created
 * lifecycle service is the sole task consumer and result producer. Both
 * channels use fixed-capacity SPSC rings; accepted tasks and their results are
 * never placed in strings, protobuf objects, or dynamically resized queues.
 *
 * The executor refuses to remove a task unless the result ring has capacity.
 * Consequently every accepted task yields exactly one durable result even
 * during stop/drain. Task-owned memory is released or transferred into the
 * result's prepared token before publication. Foreign callbacks and allocator
 * cleanup execute only after all platform locks have been released.
 *
 * @par Thread Safety
 * submit() and try_take_result() are coordinator-thread operations. run() is
 * called once by the planned lifecycle service. request_stop() may be called by
 * the coordinator. Adapter callbacks execute serially on the service thread.
 *
 * @par Performance
 * This is cold-path infrastructure. It is isolated from packet workers and
 * introduces no packet-path dependency.
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <type_traits>
#include <variant>

#include <kinetum/algo/queue.hpp>
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/lifecycle/prepared_config_ownership.hpp"

namespace kinetum::dp::lifecycle
{

/** @brief Fixed task-channel capacity for each lifecycle executor. */
inline constexpr std::size_t CONFIG_LIFECYCLE_TASK_CAPACITY = 64;

/** @brief Fixed result-channel capacity for each lifecycle executor. */
inline constexpr std::size_t CONFIG_LIFECYCLE_RESULT_CAPACITY = 64;

/**
 * @brief Validate one exact borrowed lifecycle payload span.
 *
 * Empty payloads have no address, while non-empty payloads require a stable
 * address through result delivery. This mirrors the module PREPARE ABI and
 * prevents different producers from assigning meaning to a non-null,
 * zero-length pointer.
 *
 * @param payload Borrowed payload address.
 * @param payload_size Exact number of payload bytes.
 * @return true when pointer presence and byte count describe one exact span.
 */
[[nodiscard]] constexpr bool valid_lifecycle_payload_span(const void *payload, std::size_t payload_size) noexcept
{
	return (payload == nullptr) == (payload_size == 0);
}

/** @brief Cold operation dispatched through a lifecycle executor. */
enum class config_lifecycle_operation : uint8_t {
	PREPARE = 0,
	RETIRE,
};

/** @brief Outcome returned directly by the module-lifecycle adapter. */
enum class lifecycle_prepare_callback_code : uint8_t {
	SUCCESS = 0,
	CANCELLED,
	FAILURE,
};

/** @brief Fixed prepare-callback result with no allocation-owning diagnostics. */
struct lifecycle_prepare_callback_result {
	lifecycle_prepare_callback_code code{lifecycle_prepare_callback_code::FAILURE};	 ///< Explicit outcome.
	uint32_t module_error_code{0};	    ///< Module-defined bounded diagnostic code.
	prepared_config_record prepared{};  ///< Meaningful only when code is SUCCESS.
};

/**
 * @brief Cold adapter boundary for module configuration lifecycle callbacks.
 *
 * Deterministic component adapters may implement this interface without a
 * loaded module. The production SDK bridge is supplied only by module-ABI
 * integration and never exposes live kinetum_ctx through this boundary.
 */
class config_lifecycle_adapter {
    public:
	/** @brief Destroy one cold lifecycle callback adapter. */
	virtual ~config_lifecycle_adapter() = default;

	/**
	 * @brief Prepare immutable config through one borrowed lifecycle context.
	 *
	 * @param context Exact PREPARE lifecycle context.
	 * @param payload Immutable config bytes owned by the coordinator; null
	 *        exactly when @p payload_size is zero.
	 * @param payload_size Number of payload bytes.
	 * @return Explicit callback outcome and prepared values.
	 */
	[[nodiscard]] virtual lifecycle_prepare_callback_result
	prepare(const ::kinetum_lifecycle_ctx &context, const void *payload, std::size_t payload_size) noexcept = 0;

	/**
	 * @brief Retire one exact prepared record.
	 *
	 * @param context Exact RETIRE lifecycle context.
	 * @param prepared Borrowed record owned by the platform token for this call.
	 */
	virtual void retire(const ::kinetum_lifecycle_ctx &context, prepared_config_record prepared) noexcept = 0;
};

/**
 * @brief Wake-only sink invoked after one result-ring publication.
 *
 * Multiple lifecycle executors may invoke the same sink concurrently. The
 * implementation must be nonblocking and thread-safe. A notification count is
 * never result ownership; the coordinator drains every owning result ring.
 */
class config_lifecycle_result_notifier {
    public:
	/** @brief Destroy one stable notifier after every executor stops. */
	virtual ~config_lifecycle_result_notifier() = default;
	/** @brief Signal that one or more result rings may now be nonempty. */
	virtual void notify_result() noexcept = 0;
};

/** @brief Fixed executor result classification independent of common::status strings. */
enum class config_lifecycle_result_code : uint8_t {
	SUCCESS = 0,
	CANCELLED,
	DEADLINE_EXCEEDED,
	CALLBACK_FAILURE,
	CONTEXT_REJECTED,
};

/**
 * @brief Move-only compact task transferred from coordinator to executor.
 */
class config_lifecycle_task {
    public:
	config_lifecycle_task(const config_lifecycle_task &) = delete;
	config_lifecycle_task &operator=(const config_lifecycle_task &) = delete;
	/**
	 * @brief Transfer one exact unconsumed task.
	 *
	 * @param other Source task emptied by this move.
	 */
	config_lifecycle_task(config_lifecycle_task &&other) noexcept;
	config_lifecycle_task &operator=(config_lifecycle_task &&other) = delete;
	/**
	 * @brief Destroy one task and its local PREPARE ownership.
	 *
	 * An unaccepted or unsuccessful PREPARE releases its arena. RETIRE borrows
	 * a token whose issuing store-bound claim must outlive result delivery.
	 */
	~config_lifecycle_task() = default;

	/**
	 * @brief Build one exact PREPARE task without consuming invalid input.
	 *
	 * @param task_sequence Nonzero coordinator-owned task identity.
	 * @param owner Exact context owner that must remain alive through result
	 *        delivery.
	 * @param adapter Exact cold module-lifecycle adapter that must remain alive
	 *        through result delivery.
	 * @param control Stable deadline/cancellation control that must remain alive
	 *        through result delivery.
	 * @param epoch Nonzero target epoch.
	 * @param payload Immutable config bytes valid until result delivery; null
	 *        exactly when @p payload_size is zero.
	 * @param payload_size Number of payload bytes.
	 * @param arena Exact context/epoch/NUMA/capacity arena transferred only on
	 *        success.
	 * @return Move-only task, or failure while @p arena remains caller-owned.
	 */
	[[nodiscard]] static kinetum::common::status_or<config_lifecycle_task>
	create_prepare(uint64_t task_sequence, lifecycle_context_owner &owner, config_lifecycle_adapter &adapter,
		       lifecycle_operation_control &control, uint64_t epoch, const void *payload,
		       std::size_t payload_size, epoch_arena_ownership &&arena) noexcept;

	/**
	 * @brief Build one exact RETIRE task over a read-only ownership borrow.
	 *
	 * @param task_sequence Nonzero coordinator-owned task identity.
	 * @param owner Exact context owner that must remain alive through result
	 *        delivery.
	 * @param adapter Exact cold module-lifecycle adapter that must remain alive
	 *        through result delivery.
	 * @param control Stable deadline/cancellation control that must remain alive
	 *        through result delivery.
	 * @param prepared Live exact token retained by its issuing owner through
	 *        result delivery.
	 * @return Move-only task, or failure without retaining the borrow.
	 */
	[[nodiscard]] static kinetum::common::status_or<config_lifecycle_task>
	create_retire(uint64_t task_sequence, lifecycle_context_owner &owner, config_lifecycle_adapter &adapter,
		      lifecycle_operation_control &control, const prepared_config_ownership &prepared) noexcept;

	/**
	 * @brief Build RETIRE over one read-only store-bound claim borrow.
	 * @param task_sequence Nonzero coordinator-owned task identity.
	 * @param owner Exact context owner retained through result delivery.
	 * @param adapter Exact cold callback adapter retained through result delivery.
	 * @param control Stable deadline/cancellation control.
	 * @param prepared Immutable token borrow retained by the issuing claim.
	 * @param retirement_claim_id Nonzero echo from the issuing store claim. The
	 *        scalar is result identity, never claim or token authority.
	 * @return Move-only task, or failure without retaining either borrow.
	 */
	[[nodiscard]] static kinetum::common::status_or<config_lifecycle_task>
	create_claimed_retire(uint64_t task_sequence, lifecycle_context_owner &owner, config_lifecycle_adapter &adapter,
			      lifecycle_operation_control &control, const prepared_config_ownership &prepared,
			      uint64_t retirement_claim_id) noexcept;

	/**
	 * @brief Return the nonzero coordinator task sequence.
	 *
	 * @return Stable sequence assigned at task construction.
	 */
	[[nodiscard]] uint64_t task_sequence() const noexcept;

	/**
	 * @brief Return PREPARE or RETIRE.
	 *
	 * @return Exact cold operation carried by this task.
	 */
	[[nodiscard]] config_lifecycle_operation operation() const noexcept;

	/**
	 * @brief Return the compact module-image index.
	 *
	 * @return Exact module-image owner index.
	 */
	[[nodiscard]] uint32_t module_image_index() const noexcept;

	/**
	 * @brief Return the compact context index.
	 *
	 * @return Exact executable-context owner index.
	 */
	[[nodiscard]] uint32_t context_index() const noexcept;

	/**
	 * @brief Return the exact nonzero task epoch.
	 *
	 * @return PREPARE or RETIRE epoch carried by this task.
	 */
	[[nodiscard]] uint64_t epoch() const noexcept;
	/** @return Zero for direct RETIRE or the exact store-bound claim identity. */
	[[nodiscard]] uint64_t retirement_claim_id() const noexcept;

    private:
	friend class config_lifecycle_executor;
	/**
	 * @brief Build one direct or store-claimed RETIRE through one validator.
	 * @param task_sequence Nonzero coordinator-owned task identity.
	 * @param owner Exact context owner retained through result delivery.
	 * @param adapter Exact cold callback adapter retained through result delivery.
	 * @param control Stable bound deadline/cancellation control.
	 * @param prepared Immutable token borrow retained by its owner or claim.
	 * @param retirement_claim_id Zero for direct ownership or exact nonzero claim identity.
	 * @return Move-only task, or failure without retaining the borrow.
	 */
	[[nodiscard]] static kinetum::common::status_or<config_lifecycle_task>
	create_retire_(uint64_t task_sequence, lifecycle_context_owner &owner, config_lifecycle_adapter &adapter,
		       lifecycle_operation_control &control, const prepared_config_ownership &prepared,
		       uint64_t retirement_claim_id) noexcept;

	/**
	 * @brief Construct one task after exact operation-specific admission.
	 *
	 * @param task_sequence Nonzero coordinator task identity.
	 * @param operation Exact PREPARE or RETIRE operation.
	 * @param owner Exact lifecycle-context owner.
	 * @param adapter Exact cold callback adapter.
	 * @param control Stable deadline/cancellation control.
	 * @param epoch Exact nonzero operation epoch.
	 * @param payload Immutable PREPARE bytes, otherwise nullptr.
	 * @param payload_size PREPARE payload size, otherwise zero.
	 * @param ownership Exact PREPARE arena ownership.
	 * @param retire_prepared Borrowed RETIRE token, otherwise nullptr.
	 * @param retirement_claim_id Zero for direct RETIRE/PREPARE or exact
	 *        nonzero issuing-store claim identity.
	 */
	config_lifecycle_task(uint64_t task_sequence, config_lifecycle_operation operation,
			      lifecycle_context_owner &owner, config_lifecycle_adapter &adapter,
			      lifecycle_operation_control &control, uint64_t epoch, const void *payload,
			      std::size_t payload_size, std::variant<std::monostate, epoch_arena_ownership> ownership,
			      const prepared_config_ownership *retire_prepared, uint64_t retirement_claim_id) noexcept;

	uint64_t task_sequence_{0};						     ///< Exact task identity.
	config_lifecycle_operation operation_{config_lifecycle_operation::PREPARE};  ///< Exact cold operation.
	uint32_t module_image_index_{0};					     ///< Exact loaded-image index.
	uint32_t context_index_{0};						     ///< Exact context index.
	uint64_t epoch_{0};							     ///< Exact operation epoch.
	lifecycle_context_owner *owner_{nullptr};				     ///< Stable context owner.
	config_lifecycle_adapter *adapter_{nullptr};				     ///< Stable callback authority.
	lifecycle_operation_control *control_{nullptr};				     ///< Stable deadline/cancel state.
	const void *payload_{nullptr};						     ///< Borrowed PREPARE payload.
	std::size_t payload_size_{0};						     ///< Borrowed payload byte count.
	std::variant<std::monostate, epoch_arena_ownership> ownership_;	 ///< Linear PREPARE arena ownership.
	const prepared_config_ownership *retire_prepared_{nullptr};	 ///< Borrowed store-bound RETIRE token.
	uint64_t retirement_claim_id_{0};  ///< Zero for direct RETIRE; otherwise exact claim echo.
};

/**
 * @brief Move-only exact result transferred from executor to coordinator.
 *
 * PREPARE success carries one live prepared token. RETIRE carries only exact
 * callback-completion evidence; its store-bound ownership never enters the
 * task or result channel.
 */
class config_lifecycle_result {
    public:
	config_lifecycle_result(const config_lifecycle_result &) = delete;
	config_lifecycle_result &operator=(const config_lifecycle_result &) = delete;
	/**
	 * @brief Transfer one exact result and any live prepared token.
	 *
	 * @param other Source result emptied by this move.
	 */
	config_lifecycle_result(config_lifecycle_result &&other) noexcept;
	config_lifecycle_result &operator=(config_lifecycle_result &&other) = delete;
	/**
	 * @brief Destroy one result after ownership has been handled.
	 *
	 * Destruction with a live prepared token is fatal through the token's
	 * linear-ownership contract.
	 */
	~config_lifecycle_result() = default;

	/**
	 * @brief Return the exact coordinator task sequence.
	 *
	 * @return Sequence copied unchanged from the accepted task.
	 */
	[[nodiscard]] uint64_t task_sequence() const noexcept;

	/**
	 * @brief Return PREPARE or RETIRE.
	 *
	 * @return Exact completed cold operation.
	 */
	[[nodiscard]] config_lifecycle_operation operation() const noexcept;

	/**
	 * @brief Return fixed success/failure classification.
	 *
	 * @return Allocation-free executor result code.
	 */
	[[nodiscard]] config_lifecycle_result_code code() const noexcept;

	/**
	 * @brief Return the bounded callback or platform diagnostic code.
	 *
	 * CALLBACK_FAILURE carries the module-defined code. CONTEXT_REJECTED
	 * carries the common status-code value that prevented callback execution.
	 *
	 * @return Zero when no diagnostic code applies.
	 */
	[[nodiscard]] uint32_t diagnostic_code() const noexcept;

	/**
	 * @brief Return the exact compact module-image index.
	 *
	 * @return Module-image index copied from the accepted task.
	 */
	[[nodiscard]] uint32_t module_image_index() const noexcept;

	/**
	 * @brief Return the exact compact context index.
	 *
	 * @return Context index copied from the accepted task.
	 */
	[[nodiscard]] uint32_t context_index() const noexcept;

	/**
	 * @brief Return the exact nonzero task epoch.
	 *
	 * @return Epoch copied from the accepted task.
	 */
	[[nodiscard]] uint64_t epoch() const noexcept;
	/** @return Zero for direct RETIRE or the exact store-bound claim identity. */
	[[nodiscard]] uint64_t retirement_claim_id() const noexcept;

	/**
	 * @brief Return whether a PREPARE result owns a live prepared token.
	 *
	 * @return true until the coordinator transfers the token.
	 */
	[[nodiscard]] bool has_prepared_ownership() const noexcept;

	/**
	 * @brief Transfer the live PREPARE token to the result consumer.
	 *
	 * @return Exact token, or FAILED_PRECONDITION when none is owned.
	 */
	[[nodiscard]] kinetum::common::status_or<prepared_config_ownership> take_prepared_ownership() noexcept;

    private:
	friend class config_lifecycle_executor;

	/**
	 * @brief Construct one complete durable executor result.
	 *
	 * @param task_sequence Exact coordinator task identity.
	 * @param operation Completed PREPARE or RETIRE operation.
	 * @param code Fixed result classification.
	 * @param diagnostic_code Bounded module or platform diagnostic.
	 * @param module_image_index Exact loaded-image index.
	 * @param context_index Exact executable-context index.
	 * @param epoch Exact nonzero operation epoch.
	 * @param retirement_claim_id Zero for direct RETIRE/PREPARE or exact
	 *        nonzero issuing-store claim identity.
	 * @param prepared Optional live PREPARE ownership returned to the coordinator.
	 */
	config_lifecycle_result(uint64_t task_sequence, config_lifecycle_operation operation,
				config_lifecycle_result_code code, uint32_t diagnostic_code,
				uint32_t module_image_index, uint32_t context_index, uint64_t epoch,
				uint64_t retirement_claim_id,
				std::optional<prepared_config_ownership> prepared) noexcept;

	uint64_t task_sequence_{0};						     ///< Exact task identity.
	config_lifecycle_operation operation_{config_lifecycle_operation::PREPARE};  ///< Completed cold operation.
	config_lifecycle_result_code code_{config_lifecycle_result_code::CONTEXT_REJECTED};  ///< Exact outcome.
	uint32_t diagnostic_code_{0};			     ///< Bounded module/platform code.
	uint32_t module_image_index_{0};		     ///< Exact loaded-image index.
	uint32_t context_index_{0};			     ///< Exact context index.
	uint64_t epoch_{0};				     ///< Exact operation epoch.
	uint64_t retirement_claim_id_{0};		     ///< Exact claimed-RETIRE echo, or zero.
	std::optional<prepared_config_ownership> prepared_;  ///< Optional live PREPARE token ownership.
};

static_assert(std::is_nothrow_move_constructible_v<config_lifecycle_task>);
static_assert(std::is_nothrow_move_constructible_v<config_lifecycle_result>);
static_assert(sizeof(config_lifecycle_task) <= 224,
	      "lifecycle task must remain a compact fixed record without strings or protobuf state");
static_assert(sizeof(config_lifecycle_result) <= 192,
	      "lifecycle result must remain a compact fixed record without strings or protobuf state");

/**
 * @brief Pre-created bounded lifecycle executor for one service placement.
 */
class config_lifecycle_executor {
    public:
	/**
	 * @brief Construct one inactive executor for an exact service placement.
	 *
	 * @param service_index Plan-order lifecycle service index.
	 * @param numa_node Exact nonnegative executor NUMA node.
	 */
	config_lifecycle_executor(uint32_t service_index, int32_t numa_node) noexcept;

	config_lifecycle_executor(const config_lifecycle_executor &) = delete;
	config_lifecycle_executor &operator=(const config_lifecycle_executor &) = delete;
	config_lifecycle_executor(config_lifecycle_executor &&) = delete;
	config_lifecycle_executor &operator=(config_lifecycle_executor &&) = delete;
	/** @brief Destroy an empty stopped executor; residual work is fatal. */
	~config_lifecycle_executor();

	/**
	 * @brief Submit one task after all-or-none service launch succeeds.
	 *
	 * Failure never moves from @p task. A full channel returns
	 * RESOURCE_EXHAUSTED and leaves ownership with the coordinator.
	 *
	 * @param task Exact move-only lifecycle task.
	 * @return OK after SPSC ownership transfer; non-OK otherwise.
	 */
	[[nodiscard]] kinetum::common::status submit(config_lifecycle_task &&task) noexcept;

	/**
	 * @brief Take one completed result on the coordinator thread.
	 *
	 * @return Move-only result, or nullopt when no completion is available.
	 */
	[[nodiscard]] std::optional<config_lifecycle_result> try_take_result() noexcept;

	/**
	 * @brief Wait boundedly for one result or executor stop.
	 *
	 * @param deadline Absolute steady-clock deadline.
	 * @return Move-only result, or nullopt on deadline/stopped-without-result.
	 */
	[[nodiscard]] std::optional<config_lifecycle_result>
	wait_take_result_until(std::chrono::steady_clock::time_point deadline) noexcept;

	/**
	 * @brief Run the single-consumer service loop until stop and complete drain.
	 *
	 * This method is called once by a successfully launched runtime service and
	 * returns only after every accepted task has a retained result.
	 */
	void run() noexcept;

	/** @brief Stop accepting work and request complete drain of accepted tasks. */
	void request_stop() noexcept;

	/**
	 * @brief Return whether the executor has completed its service loop.
	 *
	 * @return true after stop drains every accepted task into a result.
	 */
	[[nodiscard]] bool stopped() const noexcept;

	/**
	 * @brief Return exact service placement index.
	 *
	 * @return Plan-order lifecycle-service index.
	 */
	[[nodiscard]] uint32_t service_index() const noexcept;

	/**
	 * @brief Return exact executor NUMA node.
	 *
	 * @return Nonnegative compiled NUMA ownership.
	 */
	[[nodiscard]] int32_t numa_node() const noexcept;

	/**
	 * @brief Return total tasks accepted into the SPSC channel.
	 *
	 * @return Monotonic accepted-task count.
	 */
	[[nodiscard]] uint64_t accepted_task_count() const noexcept;

	/**
	 * @brief Return total durable results published into the SPSC channel.
	 *
	 * @return Monotonic published-result count.
	 */
	[[nodiscard]] uint64_t published_result_count() const noexcept;

	/**
	 * @brief Bind one stable wake-only notifier before launch reservation.
	 * @param notifier Stable notifier that outlives this executor service.
	 * @return OK after first binding; otherwise no state change.
	 */
	[[nodiscard]] kinetum::common::status bind_result_notifier(config_lifecycle_result_notifier &notifier) noexcept;

    private:
	friend class runtime_service_launcher;

	/**
	 * @brief Reserve one idle executor before any backend launch side effect.
	 *
	 * @return OK after exclusive reservation; FAILED_PRECONDITION when this
	 *         executor is already reserved, launched, stopped, or nonempty.
	 */
	[[nodiscard]] kinetum::common::status reserve_launch_() noexcept;
	/** @brief Cancel one unpublished launch reservation during rollback. */
	void cancel_launch_reservation_() noexcept;
	/** @brief Publish coordinator submission after complete backend launch. */
	void publish_launch_() noexcept;
	/** @brief Wait until one result exists or the service loop stops. */
	void wait_for_result_or_stop_() noexcept;
	/**
	 * @brief Consume one accepted task through its exact cold operation.
	 *
	 * @param task Exact accepted ownership moved into this call.
	 * @return One result carrying all surviving ownership. Untransferred task
	 *         storage retires by the end of the calling full-expression.
	 */
	[[nodiscard]] config_lifecycle_result execute_(config_lifecycle_task task) noexcept;
	/**
	 * @brief Execute PREPARE and preserve explicit artifact ownership.
	 *
	 * @param task PREPARE task borrowed from the owning execution call.
	 * @return One durable PREPARE result.
	 */
	[[nodiscard]] config_lifecycle_result execute_prepare_(config_lifecycle_task &task) noexcept;
	/**
	 * @brief Execute RETIRE over an exact store-bound read-only borrow.
	 *
	 * @param task RETIRE task borrowed from the owning execution call.
	 * @return One durable RETIRE result.
	 */
	[[nodiscard]] config_lifecycle_result execute_retire_(const config_lifecycle_task &task) noexcept;

	uint32_t service_index_{0};  ///< Exact plan-order lifecycle-service index.
	int32_t numa_node_{-1};	     ///< Exact executor NUMA ownership.
	kinetum::algo::spsc_ring_static<config_lifecycle_task, CONFIG_LIFECYCLE_TASK_CAPACITY>
		tasks_;	 ///< Accepted work.
	kinetum::algo::spsc_ring_static<config_lifecycle_result, CONFIG_LIFECYCLE_RESULT_CAPACITY>
		results_;				   ///< Durable results.
	bool launch_reserved_{false};			   ///< Pre-backend exclusive launch reservation.
	std::atomic<bool> accepting_{false};		   ///< Coordinator submission gate.
	std::atomic<bool> stop_requested_{false};	   ///< One-way complete-drain request.
	std::atomic<bool> running_{false};		   ///< Service-loop ownership flag.
	std::atomic<bool> stopped_{false};		   ///< Complete-drain publication.
	std::atomic<uint64_t> accepted_task_count_{0};	   ///< Monotonic accepted ownership count.
	std::atomic<uint64_t> published_result_count_{0};  ///< Monotonic durable-result count.
	mutable std::mutex wake_mutex_;			   ///< Serializes condition predicates and notifications.
	std::condition_variable wake_cv_;		   ///< Task/result/stop progress notification.
	config_lifecycle_result_notifier *result_notifier_{nullptr};  ///< Wake-only result publication sink.
};

}  // namespace kinetum::dp::lifecycle
