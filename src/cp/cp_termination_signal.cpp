// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file cp_termination_signal.cpp
 * @brief Descriptor-owned Control Plane termination-signal implementation.
 * @author Fleming Patel
 */

#include "src/cp/cp_termination_signal.hpp"

#include <atomic>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <new>
#include <string>

#include <poll.h>
#include <pthread.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "src/common/status.hpp"

namespace kinetum::cp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/** @brief Process-wide linear claim for the sole CP termination descriptor. */
std::atomic<bool> termination_owner_claimed{false};

/**
 * @brief Restore a mask after pre-publication construction failure.
 * @param mask Exact mask observed before attempted admission.
 */
void restore_mask_or_terminate(const sigset_t &mask) noexcept
{
	if (::pthread_sigmask(SIG_SETMASK, &mask, nullptr) != 0) {
		std::terminate();
	}
}

}  // namespace

status_or<std::unique_ptr<cp_termination_signal>> cp_termination_signal::create()
{
	bool expected = false;
	if (!termination_owner_claimed.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
							       std::memory_order_acquire)) {
		return status::failed_precondition("Control Plane termination signal owner is already live");
	}

	sigset_t termination_set{};
	if (::sigemptyset(&termination_set) != 0 || ::sigaddset(&termination_set, SIGINT) != 0 ||
	    ::sigaddset(&termination_set, SIGTERM) != 0 || ::sigaddset(&termination_set, SIGUSR1) != 0) {
		const int error = errno;
		termination_owner_claimed.store(false, std::memory_order_release);
		return status::internal_error("failed to construct Control Plane termination signal set: " +
					      std::string(std::strerror(error)));
	}

	sigset_t previous_mask{};
	const int mask_error = ::pthread_sigmask(SIG_BLOCK, &termination_set, &previous_mask);
	if (mask_error != 0) {
		termination_owner_claimed.store(false, std::memory_order_release);
		return status::internal_error("failed to block Control Plane termination signals: " +
					      std::string(std::strerror(mask_error)));
	}

	const int descriptor = ::signalfd(-1, &termination_set, SFD_CLOEXEC | SFD_NONBLOCK);
	if (descriptor < 0) {
		const int error = errno;
		restore_mask_or_terminate(previous_mask);
		termination_owner_claimed.store(false, std::memory_order_release);
		return status(status_code::RESOURCE_EXHAUSTED,
			      "failed to create Control Plane termination signal descriptor: " +
				      std::string(std::strerror(error)));
	}

	try {
		return std::unique_ptr<cp_termination_signal>(new cp_termination_signal(descriptor, previous_mask));
	} catch (const std::bad_alloc &) {
		(void)::close(descriptor);
		restore_mask_or_terminate(previous_mask);
		termination_owner_claimed.store(false, std::memory_order_release);
		return status::resource_exhausted("failed to allocate Control Plane termination signal owner");
	}
}

cp_termination_signal::cp_termination_signal(int descriptor, const sigset_t &previous_mask) noexcept
	: descriptor_(descriptor)
	, previous_mask_(previous_mask)
	, owner_thread_(::pthread_self())
{
}

cp_termination_signal::~cp_termination_signal() noexcept
{
	if (::pthread_equal(::pthread_self(), owner_thread_) == 0) {
		std::fputs("cp_termination_signal: owner destroyed outside its creating thread\n", stderr);
		(void)std::fflush(stderr);
		std::terminate();
	}
	if (descriptor_ >= 0) {
		// Standard control signals coalesce. Retire the pending set before its
		// former default dispositions can become active again at mask restore.
		std::array<signalfd_siginfo, 3> pending{};
		ssize_t bytes;
		do {
			bytes = ::read(descriptor_, pending.data(), sizeof(pending));
		} while (bytes < 0 && errno == EINTR);
		if ((bytes < 0 && errno != EAGAIN) ||
		    (bytes >= 0 && (bytes == 0 || static_cast<std::size_t>(bytes) % sizeof(signalfd_siginfo) != 0))) {
			std::fputs("cp_termination_signal: pending control records could not retire\n", stderr);
			std::terminate();
		}
		(void)::close(descriptor_);
	}
	restore_mask_or_terminate(previous_mask_);
	termination_owner_claimed.store(false, std::memory_order_release);
}

status_or<int> cp_termination_signal::wait()
{
	if (consumed_) {
		return status::failed_precondition("Control Plane termination signal was already consumed");
	}

	pollfd observed{.fd = descriptor_, .events = POLLIN, .revents = 0};
	for (;;) {
		const int poll_result = ::poll(&observed, 1u, -1);
		if (poll_result < 0 && errno == EINTR) {
			continue;
		}
		if (poll_result < 0) {
			return status::internal_error("Control Plane termination signal poll failed: " +
						      std::string(std::strerror(errno)));
		}
		if ((observed.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			return status::internal_error(
				"Control Plane termination signal descriptor entered an invalid state");
		}
		if ((observed.revents & POLLIN) == 0) {
			continue;
		}

		signalfd_siginfo information{};
		ssize_t bytes = 0;
		do {
			bytes = ::read(descriptor_, &information, sizeof(information));
		} while (bytes < 0 && errno == EINTR);
		if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			continue;
		}
		if (bytes != static_cast<ssize_t>(sizeof(information))) {
			return status::internal_error("Control Plane signal descriptor returned a short record");
		}
		if (information.ssi_signo != static_cast<uint32_t>(SIGINT) &&
		    information.ssi_signo != static_cast<uint32_t>(SIGTERM) &&
		    information.ssi_signo != static_cast<uint32_t>(SIGUSR1)) {
			return status::internal_error("Control Plane signal descriptor returned an unexpected signal");
		}
		consumed_ = information.ssi_signo != static_cast<uint32_t>(SIGUSR1);
		return static_cast<int>(information.ssi_signo);
	}
}

int cp_termination_signal::descriptor() const noexcept
{
	return descriptor_;
}

}  // namespace kinetum::cp
