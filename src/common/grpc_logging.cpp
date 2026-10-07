// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file grpc_logging.cpp
 * @brief Native diagnostic callback admission and quiescence without retained views.
 * @author Fleming Patel
 */

#include "src/common/grpc_logging.hpp"

#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <new>

#include <grpc/grpc.h>

#include "src/common/log.hpp"
#include "src/common/packet_thread_log_guard.hpp"

namespace kinetum::common
{
namespace
{

/** @brief Process-wide registration and accepted-callback ownership. */
struct callback_state {
	std::mutex mutex;		  ///< Protects registration, admission, and the drain predicate.
	std::condition_variable drained;  ///< Notification after the final admitted callback returns.
	bool owned{false};		  ///< One native hook owner exists.
	bool open{false};		  ///< New callbacks may borrow the live platform frontend.
	uint64_t active{0};		  ///< Accepted callbacks that have not returned.
};

/** Remains alive while every process-owned gRPC producer and hook is retired. */
callback_state CALLBACKS;

/** @brief One callback claim; no gate lock spans formatter or frontend invocation. */
class callback_claim final {
    public:
	/** @brief Enter only before explicit callback admission closes. */
	callback_claim() noexcept
	{
		std::lock_guard lock(CALLBACKS.mutex);
		if (CALLBACKS.open) {
			++CALLBACKS.active;
			accepted_ = true;
		}
	}
	/** @brief Return the exact accepted claim and wake the retirement predicate. */
	~callback_claim()
	{
		if (accepted_) {
			std::lock_guard lock(CALLBACKS.mutex);
			--CALLBACKS.active;
			if (CALLBACKS.active == 0) {
				CALLBACKS.drained.notify_all();
			}
		}
	}
	callback_claim(const callback_claim &) = delete;
	callback_claim &operator=(const callback_claim &) = delete;
	/** @return True when the scope owns an admitted callback. */
	[[nodiscard]] bool accepted() const noexcept
	{
		return accepted_;
	}

    private:
	bool accepted_{false};	///< Sole claim, consumed once at scope exit.
};

}  // namespace

status_or<std::unique_ptr<grpc_logging>> grpc_logging::create()
{
	std::unique_ptr<grpc_logging> owner;
	try {
		owner.reset(new grpc_logging());
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("gRPC logging owner allocation failed"));
	}
	{
		std::lock_guard lock(CALLBACKS.mutex);
		if (CALLBACKS.owned) {
			return status::failed_precondition(
				static_status_text("gRPC logging already has a process owner"));
		}
		CALLBACKS.owned = true;
		CALLBACKS.open = true;
		owner->owned_ = true;
	}
	detail::install_grpc_log_capture();
	::grpc_init();
	detail::configure_grpc_log_capture();
	return owner;
}

grpc_logging::~grpc_logging()
{
	if (!owned_) {
		return;
	}
	::grpc_shutdown_blocking();
	detail::remove_grpc_log_capture();
	std::unique_lock lock(CALLBACKS.mutex);
	CALLBACKS.open = false;
	CALLBACKS.drained.wait(lock, [] { return CALLBACKS.active == 0; });
	CALLBACKS.owned = false;
}

void detail::capture_grpc_log(grpc_log_record_view record) noexcept
{
	if (reject_packet_thread_log()) {
		return;
	}
	callback_claim claim;
	if (!claim.accepted()) {
		return;
	}
	const log_site site{
		.level = record.level,
		.component = "grpc",
		.event = "grpc.message",
		.function = {},
		.truncated = record.file.size() > 1024 || record.message.size() > LOG_MESSAGE_BYTES,
	};
	log_foreign_lazy(site, [&](std::span<char> output) -> std::size_t {
		if (record.file.empty()) {
			return static_cast<std::size_t>(
				std::format_to_n(output.data(), static_cast<std::ptrdiff_t>(output.size()), "{}",
						 record.message.substr(0, LOG_MESSAGE_BYTES + 1))
					.size);
		}
		return static_cast<std::size_t>(std::format_to_n(output.data(),
								 static_cast<std::ptrdiff_t>(output.size()),
								 "{}:{}: {}", record.file.substr(0, 1024), record.line,
								 record.message.substr(0, LOG_MESSAGE_BYTES + 1))
							.size);
	});
}

}  // namespace kinetum::common
