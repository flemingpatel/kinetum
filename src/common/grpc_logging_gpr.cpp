// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file grpc_logging_gpr.cpp
 * @brief GPR callback integration for the pinned gRPC dependency.
 * @author Fleming Patel
 */

#include "src/common/grpc_logging.hpp"

#include <cstring>
#include <optional>

#include <grpc/support/log.h>

#include "src/common/log.hpp"
#include "src/common/packet_thread_log_guard.hpp"

namespace kinetum::common::detail
{
namespace
{

/**
 * @param text Nullable native C string borrowed during the callback.
 * @param bound Maximum bytes inspected.
 * @return Bounded borrowed prefix, or empty for absent text.
 */
[[nodiscard]] std::string_view bounded(const char *text, std::size_t bound) noexcept
{
	return text == nullptr ? std::string_view{} : std::string_view(text, ::strnlen(text, bound));
}

/**
 * @brief Copy actual GPR severity, source, and bytes before the native callback returns.
 * @param arguments Native facts borrowed until this invocation returns.
 */
void native_message(gpr_log_func_args *arguments) noexcept
{
	if (reject_packet_thread_log()) {
		return;
	}
	if (arguments == nullptr || arguments->message == nullptr) {
		reject_log_record();
		return;
	}
	std::optional<log_level> level;
	switch (arguments->severity) {
	case GPR_LOG_SEVERITY_DEBUG:
		level = log_level::DEBUG;
		break;
	case GPR_LOG_SEVERITY_INFO:
		level = log_level::INFO;
		break;
	case GPR_LOG_SEVERITY_ERROR:
		level = log_level::ERROR;
		break;
	}
	if (!level.has_value()) {
		reject_log_record();
		return;
	}
	capture_grpc_log({*level, bounded(arguments->file, 1025), arguments->line,
			  bounded(arguments->message, LOG_MESSAGE_BYTES + 1)});
}

}  // namespace

void install_grpc_log_capture() noexcept
{
	::gpr_set_log_function(native_message);
	configure_grpc_log_capture();
}

void configure_grpc_log_capture() noexcept
{
	::gpr_set_log_verbosity(log_enabled(log_level::DEBUG, "grpc") ? GPR_LOG_SEVERITY_DEBUG :
				log_enabled(log_level::INFO, "grpc")  ? GPR_LOG_SEVERITY_INFO :
									GPR_LOG_SEVERITY_ERROR);
}

void remove_grpc_log_capture() noexcept
{
	::gpr_set_log_function(nullptr);
}

}  // namespace kinetum::common::detail
