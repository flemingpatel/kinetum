// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_command_mailbox.hpp
 * @brief Plan-sized MPMC admission and sole-consumer ownership for DP commands.
 * @author Fleming Patel
 *
 * Concurrent control producers publish fixed-width command records containing
 * only a kind and a pointer to caller-owned completion context. The exact
 * runtime-service placement supplies the physical queue capacity. Successful
 * enqueue is the sole ownership transfer; an event descriptor merely wakes the
 * already-bound coordinator thread and never supplies capacity or ordering.
 *
 * @par Thread Safety
 * Any foreign thread may call submit(). Exactly one thread binds as consumer
 * and thereafter exclusively calls consume_notification(),
 * defer_notifications(), try_take(), complete(), and close_admission(). The
 * consumer may not submit. A submitted context must outlive complete();
 * mailbox destruction with unresolved context ownership terminates.
 *
 * @par Performance
 * Construction allocates the complete cache-line-separated MPMC queue. Later
 * submit/take operations are bounded cold-path work and allocate no queue
 * storage. This class is unreachable from packet workers.
 */

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>

#include <kinetum/algo/queue.hpp>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"

namespace kinetum::dp
{

/**
 * @brief Linear stack-context lifetime shared by every command payload.
 *
 * The only wait operation is unconditional. A context cannot be destroyed
 * while submission or mailbox ownership remains unresolved, making gRPC
 * cancellation and deadlines incapable of abandoning the queued pointer.
 *
 * @par Thread Safety
 * One producer owns construction, submission, wait, and destruction. The sole
 * mailbox consumer performs the QUEUED-to-COMPLETED half under the same
 * predicate mutex; no third thread may access a derived payload.
 */
class epoch_transition_command_context {
    public:
	/** @brief Construct one producer-owned never-submitted context. */
	epoch_transition_command_context() noexcept = default;
	/** @brief Linear completion contexts cannot be copied. */
	epoch_transition_command_context(const epoch_transition_command_context &) = delete;
	/** @brief Linear completion contexts cannot be copy-assigned. */
	epoch_transition_command_context &operator=(const epoch_transition_command_context &) = delete;
	/** @brief Published stack identity cannot move. */
	epoch_transition_command_context(epoch_transition_command_context &&) = delete;
	/** @brief Published stack identity cannot be move-assigned. */
	epoch_transition_command_context &operator=(epoch_transition_command_context &&) = delete;

	/** @brief Destroy only local never-submitted or completely resolved context. */
	~epoch_transition_command_context();

	/** @brief Wait without timeout or cancellation until the sole consumer resolves ownership. */
	void wait_for_completion() noexcept;

    private:
	friend class epoch_transition_command_mailbox;

	/** @brief Linear ownership phases guarded by completion_mutex_. */
	enum class ownership_state : uint8_t {
		LOCAL = 0,   ///< Producer exclusively owns an unsubmitted context.
		SUBMITTING,  ///< One submit call has reserved the context.
		QUEUED,	     ///< A published queue record borrows the context.
		CONSUMER,    ///< The sole consumer has taken the queue record.
		COMPLETED,   ///< Consumer result and mailbox resolution are final.
	};

	/** @return true after claiming LOCAL for one submit attempt. */
	[[nodiscard]] bool claim_for_submit_() noexcept;
	/** @brief Return a rejected SUBMITTING or unpublished QUEUED claim to LOCAL. */
	void release_failed_submit_() noexcept;
	/** @brief Publish QUEUED ownership before the queue record becomes reachable. */
	void publish_mailbox_ownership_() noexcept;
	/** @brief Transfer one dequeued context from QUEUED to the sole CONSUMER. */
	void publish_consumer_ownership_() noexcept;

	std::mutex completion_mutex_;			     ///< Owns the wait predicate and linear state.
	std::condition_variable completion_cv_;		     ///< Wakes only for final COMPLETED state.
	ownership_state ownership_{ownership_state::LOCAL};  ///< Exact context owner.
};

/** @brief Operations serialized through the sole coordinator consumer. */
enum class epoch_transition_command_kind : uint8_t {
	BOOTSTRAP = 0,	///< Restore one exact startup epoch.
	PREPARE,	///< Admit one exact live-transition candidate.
	ACTIVATE,	///< Commit one exact PREPARED transaction.
	ABORT,		///< Abort one exact pre-commit transaction.
	STATUS,		///< Resolve one exact active or terminal identity.
};

static_assert(sizeof(epoch_transition_command_kind) == sizeof(uint8_t), "transition command kind must remain one byte");

/** @brief Fixed-width queue record borrowing one unresolved caller context. */
struct epoch_transition_command {
	epoch_transition_command_kind kind{epoch_transition_command_kind::BOOTSTRAP};  ///< Exact operation.
	epoch_transition_command_context *context{nullptr};  ///< Borrowed until consumer resolution.
};

static_assert(std::is_trivially_copyable_v<epoch_transition_command>,
	      "transition command records must remain fixed-width trivially copyable values");
static_assert(std::is_standard_layout_v<epoch_transition_command>,
	      "transition command records must retain standard layout");
static_assert(sizeof(epoch_transition_command) == 16u,
	      "transition command records must remain exactly 16 bytes on supported tuples");
static_assert(alignof(epoch_transition_command) == alignof(void *),
	      "transition command records must retain natural pointer alignment");

/**
 * @brief Own one bounded coordinator command mailbox and wake descriptor.
 */
class epoch_transition_command_mailbox final {
    public:
	/**
	 * @brief Create one unbound open mailbox with exact physical capacity.
	 *
	 * @param topology Sole compiled topology carrying role-correct service bounds.
	 * @return Unique mailbox, or exact capacity, descriptor, or allocation error.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<epoch_transition_command_mailbox>>
	create(const common::compiled_transition_topology &topology);

	/** @brief Mailbox queue and descriptor identity cannot be copied. */
	epoch_transition_command_mailbox(const epoch_transition_command_mailbox &) = delete;
	/** @brief Mailbox queue and descriptor identity cannot be copy-assigned. */
	epoch_transition_command_mailbox &operator=(const epoch_transition_command_mailbox &) = delete;
	/** @brief Published mailbox identity cannot move. */
	epoch_transition_command_mailbox(epoch_transition_command_mailbox &&) = delete;
	/** @brief Published mailbox identity cannot be move-assigned. */
	epoch_transition_command_mailbox &operator=(epoch_transition_command_mailbox &&) = delete;

	/**
	 * @brief Release an unused mailbox or one closed after exact resolution.
	 *
	 * A bound mailbox must be closed and contain no queued or unresolved command.
	 */
	~epoch_transition_command_mailbox();

	/**
	 * @brief Bind the current thread as sole command consumer exactly once.
	 *
	 * @return OK after first binding; FAILED_PRECONDITION on rebinding.
	 */
	[[nodiscard]] common::status bind_consumer_to_current_thread() noexcept;

	/**
	 * @brief Publish one foreign-thread command and wake the consumer.
	 *
	 * The call rejects an unknown kind, null context, pre-binding submission,
	 * self-submission, closed admission, or queue exhaustion before ownership
	 * transfer.
	 *
	 * @param command Fixed command borrowing a live completion context.
	 * @return OK only after queue publication and unresolved-count acquisition.
	 */
	[[nodiscard]] common::status submit(const epoch_transition_command &command) noexcept;

	/**
	 * @brief Consume one coalesced wake indication on the bound thread.
	 *
	 * @return Exact coalesced queued-record credit count, zero for an already-drained
	 *         nonblocking descriptor, or an unrecoverable descriptor failure.
	 */
	[[nodiscard]] common::status_or<uint64_t> consume_notification() noexcept;

	/**
	 * @brief Re-arm a bounded unprocessed wake count on the consumer thread.
	 *
	 * @param count Number of already-published records left for a later process
	 *        loop turn; zero performs no descriptor operation.
	 */
	void defer_notifications(uint64_t count) noexcept;

	/**
	 * @brief Take one published command on the bound consumer thread.
	 *
	 * @param[out] command Destination replaced only when a command exists.
	 * @return true when one queue record transferred to the consumer.
	 */
	[[nodiscard]] bool try_take(epoch_transition_command &command) noexcept;

	/**
	 * @brief Publish completion and resolve one previously taken context.
	 *
	 * Consumer-owned result fields must be final before this call. The method
	 * resolves the mailbox count while holding the context predicate mutex,
	 * then wakes the producer, preventing context destruction before resolution.
	 *
	 * @param context Exact context named by the taken command.
	 */
	void complete(epoch_transition_command_context *context) noexcept;

	/** @brief Permanently reject later submission on the bound consumer thread. */
	void close_admission() noexcept;

	/** @return Nonblocking descriptor polled by the bound process owner. */
	[[nodiscard]] int notification_descriptor() const noexcept;

	/** @return Immutable plan-authored physical queue capacity. */
	[[nodiscard]] std::size_t capacity() const noexcept;

	/** @return Exact unresolved context count under the admission gate. */
	[[nodiscard]] std::size_t unresolved_count() const noexcept;

	/** @return Whether the mailbox has permanently closed submission. */
	[[nodiscard]] bool admission_closed() const noexcept;

	/** @return Whether the current thread is the exact bound consumer. */
	[[nodiscard]] bool current_thread_is_consumer() const noexcept;

	/** @return Whether one empty unbound mailbox may enter generation ownership. */
	[[nodiscard]] bool ready_for_generation_adoption() const noexcept;

    private:
	/**
	 * @brief Allocate one mailbox after complete topology validation.
	 *
	 * @param capacity Exact validated coordinator command slots.
	 * @return Unique mailbox or descriptor/allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<epoch_transition_command_mailbox>>
	create_with_capacity_(uint32_t capacity);

	/**
	 * @brief Adopt one validated descriptor and queue capacity.
	 *
	 * @param capacity Exact already-validated physical capacity.
	 * @param notification_descriptor Owned nonblocking event descriptor.
	 */
	epoch_transition_command_mailbox(uint32_t capacity, int notification_descriptor);

	/** @brief Terminate unless invoked by the exact bound consumer. */
	void require_consumer_() const noexcept;

	kinetum::algo::mpmc_queue_dynamic<epoch_transition_command> commands_;	///< Sole queue storage.
	const int notification_descriptor_{-1};					///< Owned eventfd wake source.
	mutable std::mutex gate_;	     ///< Serializes bind/close/submit/context counts.
	std::thread::id consumer_thread_{};  ///< Exact consumer identity after binding.
	std::size_t unresolved_count_{0};    ///< Submitted contexts not yet resolved.
	bool consumer_bound_{false};	     ///< Whether consumer_thread_ is authoritative.
	bool admission_closed_{false};	     ///< Permanent submission fence.
};

}  // namespace kinetum::dp
