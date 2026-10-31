// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dp_control_event_loop.hpp
 * @brief Descriptor-driven wait authority for coordinator work and termination.
 * @author Fleming Patel
 *
 * The DP main/coordinator thread waits on one blocked-signal descriptor, the
 * runtime's borrowed command and lifecycle notification descriptors, and an
 * optional monotonic deadline. Signals remain blocked in every process thread;
 * no asynchronous handler or second control thread participates in shutdown.
 *
 * @par Thread Safety
 * Creation, wait(), and destruction belong to one process-owner thread. Both
 * borrowed runtime descriptors must remain valid through each wait call.
 *
 * @par Performance
 * This cold control loop blocks in poll and uses bounded descriptor reads.
 * Packet workers never enter it.
 */

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>

#include "src/common/status_or.hpp"

namespace kinetum::dp
{

/** @brief Exact reason the coordinator process loop became runnable. */
enum class dp_control_event_kind : uint8_t {
	COMMAND = 0,  ///< One or more coordinator commands may be published.
	LIFECYCLE,    ///< One or more lifecycle result rings may be nonempty.
	DEADLINE,     ///< One exact monotonic transition deadline is due.
	TERMINATE,    ///< SIGINT or SIGTERM is pending on the blocked signal set.
	REOPEN_LOG,   ///< SIGUSR1 requests the logger's cold writer to reopen its files.
};

/** @brief One validated control-loop event. */
struct dp_control_event {
	dp_control_event_kind kind{dp_control_event_kind::COMMAND};  ///< Exact event class.
	int signal_number{0};  ///< Signal identity for TERMINATE/REOPEN_LOG; zero otherwise.
};

/**
 * @brief Convert one optional steady deadline into poll's timeout domain.
 * @param deadline Current behavior-driving deadline, or nullopt.
 * @param now Current steady-clock sample.
 * @return -1 without a deadline, zero when due, otherwise ceiling milliseconds
 *         capped at the native poll range.
 */
[[nodiscard]] int control_poll_timeout(std::optional<std::chrono::steady_clock::time_point> deadline,
				       std::chrono::steady_clock::time_point now) noexcept;

/**
 * @brief Retry an interrupted control wait against its original absolute deadline.
 *
 * Each attempt derives a fresh relative timeout. Interrupted waits consume the
 * same deadline; they never restart its duration. Scheduling and the native
 * wait still determine when the caller resumes.
 *
 * @tparam clock_type Nonthrowing callable returning a steady-clock sample.
 * @tparam poll_type Nonthrowing callable with poll's result and errno contract.
 * @param deadline Original deadline, or nullopt for an indefinite wait.
 * @param read_clock Clock sampled immediately before every attempt.
 * @param poll_once Borrowed operation receiving the computed millisecond timeout.
 * @return First non-interrupted native result, preserving its errno on failure.
 */
template <typename clock_type, typename poll_type>
[[nodiscard]] int poll_control_deadline(std::optional<std::chrono::steady_clock::time_point> deadline,
					clock_type &&read_clock, poll_type &&poll_once) noexcept
{
	static_assert(std::is_nothrow_invocable_r_v<std::chrono::steady_clock::time_point, clock_type &>);
	static_assert(std::is_nothrow_invocable_r_v<int, poll_type &, int>);
	for (;;) {
		const int result = poll_once(control_poll_timeout(deadline, read_clock()));
		if (result >= 0 || errno != EINTR) {
			return result;
		}
	}
}

/** @brief Own one nonblocking signalfd and poll borrowed runtime descriptors. */
class dp_control_event_loop final {
    public:
	/**
	 * @brief Create a signalfd over an already-blocked termination set.
	 *
	 * @param blocked_signals Exact process signal set containing SIGINT/SIGTERM/SIGUSR1.
	 * @return Unique loop owner, or descriptor-creation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<dp_control_event_loop>>
	create(const sigset_t &blocked_signals);

	/** @brief Signal-descriptor authority cannot be copied. */
	dp_control_event_loop(const dp_control_event_loop &) = delete;
	/** @brief Signal-descriptor authority cannot be copy-assigned. */
	dp_control_event_loop &operator=(const dp_control_event_loop &) = delete;
	/** @brief Signal-descriptor authority cannot move after publication. */
	dp_control_event_loop(dp_control_event_loop &&) = delete;
	/** @brief Signal-descriptor authority cannot be move-assigned. */
	dp_control_event_loop &operator=(dp_control_event_loop &&) = delete;
	/** @brief Close the exact signal descriptor. */
	~dp_control_event_loop();

	/**
	 * @brief Wait for a coordinator command wake or termination signal.
	 *
	 * A simultaneously ready termination signal takes precedence; the runtime
	 * shutdown path closes admission and resolves every queued command. A due
	 * monotonic deadline precedes ordinary runtime work. Simultaneously ready
	 * command and lifecycle descriptors alternate, so neither bounded source can
	 * starve the other.
	 *
	 * @param command_descriptor Borrowed nonblocking runtime eventfd, distinct
	 *        from both other descriptors.
	 * @param lifecycle_descriptor Borrowed wake-only lifecycle result eventfd,
	 *        distinct from both other descriptors.
	 * @param deadline Current behavior-driving steady deadline, or nullopt.
	 * @return Exact event, or a poll/read contract failure.
	 * @throws std::bad_alloc If a dynamic native-failure diagnostic cannot be allocated.
	 * @throws std::length_error If that diagnostic exceeds its representable size.
	 */
	[[nodiscard]] common::status_or<dp_control_event>
	wait(int command_descriptor, int lifecycle_descriptor,
	     std::optional<std::chrono::steady_clock::time_point> deadline);

    private:
	/**
	 * @brief Adopt one valid owned signal descriptor.
	 * @param signal_descriptor Sole nonblocking signalfd transferred into the event loop.
	 */
	explicit dp_control_event_loop(int signal_descriptor) noexcept;

	const int signal_descriptor_{-1};					      ///< Owned nonblocking signalfd.
	dp_control_event_kind last_runtime_event_{dp_control_event_kind::LIFECYCLE};  ///< Tie-break alternation state.
	bool reopen_pending_{false};   ///< A consumed SIGUSR1 remains owned across a higher-priority deadline.
	bool last_was_reopen_{false};  ///< A reopen request cannot starve ready runtime work.
};

}  // namespace kinetum::dp
