// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dp_control_event_loop.cpp
 * @brief Descriptor-driven DP control-loop implementation.
 * @author Fleming Patel
 */

#include "src/dp/dp_control_event_loop.hpp"

#include <cerrno>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>
#include <string>

#include <poll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "src/common/status.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

[[nodiscard]] int control_poll_timeout(std::optional<std::chrono::steady_clock::time_point> deadline,
				       std::chrono::steady_clock::time_point now) noexcept
{
	if (!deadline.has_value()) {
		return -1;
	}
	if (*deadline <= now) {
		return 0;
	}
	const auto remaining = *deadline - now;
	auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
	if (milliseconds < remaining) {
		milliseconds += std::chrono::milliseconds(1);
	}
	if (milliseconds.count() > std::numeric_limits<int>::max()) {
		return std::numeric_limits<int>::max();
	}
	return static_cast<int>(milliseconds.count());
}

status_or<std::unique_ptr<dp_control_event_loop>> dp_control_event_loop::create(const sigset_t &blocked_signals)
{
	if (::sigismember(&blocked_signals, SIGINT) != 1 || ::sigismember(&blocked_signals, SIGTERM) != 1 ||
	    ::sigismember(&blocked_signals, SIGUSR1) != 1) {
		return status::invalid_argument("DP control signal set must contain SIGINT, SIGTERM, and SIGUSR1");
	}
	const int descriptor = ::signalfd(-1, &blocked_signals, SFD_CLOEXEC | SFD_NONBLOCK);
	if (descriptor < 0) {
		const int error = errno;
		return status(status_code::RESOURCE_EXHAUSTED, "failed to create DP termination signal descriptor: " +
								       std::string(std::strerror(error)));
	}
	try {
		return std::unique_ptr<dp_control_event_loop>(new dp_control_event_loop(descriptor));
	} catch (const std::bad_alloc &) {
		(void)::close(descriptor);
		return status::resource_exhausted("failed to allocate DP control event loop");
	}
}

dp_control_event_loop::dp_control_event_loop(int signal_descriptor) noexcept
	: signal_descriptor_(signal_descriptor)
{
}

dp_control_event_loop::~dp_control_event_loop()
{
	if (signal_descriptor_ >= 0) {
		(void)::close(signal_descriptor_);
	}
}

status_or<dp_control_event> dp_control_event_loop::wait(int command_descriptor, int lifecycle_descriptor,
							std::optional<std::chrono::steady_clock::time_point> deadline)
{
	if (command_descriptor < 0 || lifecycle_descriptor < 0 || command_descriptor == lifecycle_descriptor ||
	    command_descriptor == signal_descriptor_ || lifecycle_descriptor == signal_descriptor_) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"DP control loop requires pairwise-distinct runtime descriptors"));
	}
	pollfd descriptors[3]{
		pollfd{.fd = signal_descriptor_, .events = POLLIN, .revents = 0},
		pollfd{.fd = command_descriptor, .events = POLLIN, .revents = 0},
		pollfd{.fd = lifecycle_descriptor, .events = POLLIN, .revents = 0},
	};
	for (;;) {
		const int timeout = reopen_pending_ ? 0 :
						      control_poll_timeout(deadline, std::chrono::steady_clock::now());
		const int result = ::poll(descriptors, 3, timeout);
		if (result < 0 && errno == EINTR) {
			continue;
		}
		if (result < 0) {
			return status::internal_error("DP control poll failed: " + std::string(std::strerror(errno)));
		}
		if (result == 0) {
			if (deadline.has_value() && std::chrono::steady_clock::now() >= *deadline) {
				return dp_control_event{.kind = dp_control_event_kind::DEADLINE, .signal_number = 0};
			}
			if (reopen_pending_) {
				reopen_pending_ = false;
				last_was_reopen_ = true;
				return dp_control_event{.kind = dp_control_event_kind::REOPEN_LOG,
							.signal_number = SIGUSR1};
			}
			continue;
		}
		if ((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			return status::internal_error(kinetum::common::static_status_text(
				"DP control poll observed an invalid signal descriptor state"));
		}
		if ((descriptors[0].revents & POLLIN) != 0) {
			std::array<signalfd_siginfo, 3> information{};
			ssize_t bytes = 0;
			do {
				bytes = ::read(signal_descriptor_, information.data(), sizeof(information));
			} while (bytes < 0 && errno == EINTR);
			if (bytes <= 0 || static_cast<std::size_t>(bytes) % sizeof(signalfd_siginfo) != 0) {
				return status::internal_error(kinetum::common::static_status_text(
					"DP signal descriptor returned an invalid control record"));
			}
			int termination = 0;
			for (std::size_t index = 0; index < static_cast<std::size_t>(bytes) / sizeof(signalfd_siginfo);
			     ++index) {
				const auto signal = information[index].ssi_signo;
				if (signal == static_cast<uint32_t>(SIGINT) ||
				    signal == static_cast<uint32_t>(SIGTERM)) {
					termination = static_cast<int>(signal);
				} else if (signal == static_cast<uint32_t>(SIGUSR1)) {
					reopen_pending_ = true;
				} else {
					return status::internal_error(kinetum::common::static_status_text(
						"DP signal descriptor returned an unexpected signal"));
				}
			}
			if (termination != 0) {
				return dp_control_event{.kind = dp_control_event_kind::TERMINATE,
							.signal_number = termination};
			}
		}
		if ((descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			return status::internal_error(kinetum::common::static_status_text(
				"DP control poll observed an invalid command descriptor state"));
		}
		if ((descriptors[2].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			return status::internal_error(kinetum::common::static_status_text(
				"DP control poll observed an invalid lifecycle descriptor state"));
		}
		if (deadline.has_value() && std::chrono::steady_clock::now() >= *deadline) {
			return dp_control_event{.kind = dp_control_event_kind::DEADLINE, .signal_number = 0};
		}
		const bool command_ready = (descriptors[1].revents & POLLIN) != 0;
		const bool lifecycle_ready = (descriptors[2].revents & POLLIN) != 0;
		if (reopen_pending_ && (!last_was_reopen_ || (!command_ready && !lifecycle_ready))) {
			reopen_pending_ = false;
			last_was_reopen_ = true;
			return dp_control_event{.kind = dp_control_event_kind::REOPEN_LOG, .signal_number = SIGUSR1};
		}
		last_was_reopen_ = false;
		if (command_ready && lifecycle_ready) {
			const auto selected = last_runtime_event_ == dp_control_event_kind::COMMAND ?
						      dp_control_event_kind::LIFECYCLE :
						      dp_control_event_kind::COMMAND;
			last_runtime_event_ = selected;
			return dp_control_event{.kind = selected, .signal_number = 0};
		}
		if (command_ready) {
			last_runtime_event_ = dp_control_event_kind::COMMAND;
			return dp_control_event{.kind = dp_control_event_kind::COMMAND, .signal_number = 0};
		}
		if (lifecycle_ready) {
			last_runtime_event_ = dp_control_event_kind::LIFECYCLE;
			return dp_control_event{.kind = dp_control_event_kind::LIFECYCLE, .signal_number = 0};
		}
	}
}

}  // namespace kinetum::dp
