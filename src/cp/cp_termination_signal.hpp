// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file cp_termination_signal.hpp
 * @brief Descriptor-owned Control Plane termination-signal authority.
 * @author Fleming Patel
 *
 * The process-owner thread blocks SIGINT, SIGTERM, and SIGUSR1 before creating any
 * Kinetum or gRPC thread. One signalfd then converts each signal into an
 * ordinary main-thread event; no asynchronous handler calls C++ or foreign
 * library code.
 *
 * @par Thread Safety
 * Creation, wait, and destruction belong to one process-owner thread. The
 * owner must outlive every thread that inherits its blocked signal mask.
 *
 * @par Performance
 * This is a cold process-lifecycle mechanism. It is unreachable from packet
 * workers and creates no recurring runtime work outside the blocking wait.
 */

#include <csignal>
#include <memory>

#include <pthread.h>

#include "src/common/status_or.hpp"

namespace kinetum::cp
{

/** @brief Own the CP process's blocked termination set and exact signalfd. */
class cp_termination_signal final {
    public:
	/**
	 * @brief Block SIGINT/SIGTERM/SIGUSR1 and create their sole descriptor consumer.
	 *
	 * The caller must invoke this before any thread or externally visible
	 * process effect. Failure restores the caller's original signal mask and
	 * publishes no owner.
	 *
	 * @return Unique process owner, or the exact setup/ownership failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<cp_termination_signal>> create();

	/** @brief Signal ownership cannot be copied. */
	cp_termination_signal(const cp_termination_signal &) = delete;
	/** @brief Signal ownership cannot be copy-assigned. */
	cp_termination_signal &operator=(const cp_termination_signal &) = delete;
	/** @brief Signal ownership cannot move after mask publication. */
	cp_termination_signal(cp_termination_signal &&) = delete;
	/** @brief Signal ownership cannot be move-assigned. */
	cp_termination_signal &operator=(cp_termination_signal &&) = delete;

	/**
	 * @brief Retire pending control records, close, and restore the creating thread's mask.
	 *
	 * Destruction is legal only after every thread that inherited the blocked
	 * mask has joined and on the same thread that called create(). Foreign-thread
	 * destruction or an unrepresentable mask restoration terminates.
	 */
	~cp_termination_signal() noexcept;

	/**
	 * @brief Wait for one exact termination or log-reopen record.
	 *
	 * EINTR is retried. Short reads, descriptor faults, waits after termination,
	 * and any signal outside the declared set fail closed. SIGUSR1 does not
	 * consume the owner's termination authority and permits another wait.
	 *
	 * @return SIGINT, SIGTERM, SIGUSR1, or an exact descriptor/record failure.
	 */
	[[nodiscard]] common::status_or<int> wait();

	/**
	 * @brief Return the owned descriptor for lifecycle verification.
	 * @return Nonnegative signalfd valid through this owner's lifetime.
	 */
	[[nodiscard]] int descriptor() const noexcept;

    private:
	/**
	 * @brief Adopt one descriptor after exact signal-mask publication.
	 * @param descriptor Owned nonblocking close-on-exec signalfd.
	 * @param previous_mask Exact creating-thread mask restored at destruction.
	 */
	cp_termination_signal(int descriptor, const sigset_t &previous_mask) noexcept;

	const int descriptor_{-1};	  ///< Owned nonblocking signalfd.
	const sigset_t previous_mask_{};  ///< Exact creating-thread mask before admission.
	const pthread_t owner_thread_{};  ///< Thread whose signal mask must be restored.
	bool consumed_{false};		  ///< Whether the sole termination record was consumed.
};

}  // namespace kinetum::cp
