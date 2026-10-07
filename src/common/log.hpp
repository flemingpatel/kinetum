// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file log.hpp
 * @brief Sole cold logging frontend for services, finite tools, and native adapters.
 * @author Fleming Patel
 *
 * Service admission selects a bounded owned-record queue. Finite tools and
 * startup before service admission use checked synchronous stderr delivery.
 * There is no destination substitution after a service writer fails. Every
 * formatter runs synchronously on its cold caller before bytes are published;
 * no lock is held across a formatter and no borrowed object survives the call.
 * This header must not be reachable from packet-worker code or worker callbacks.
 */

#include <cstddef>
#include <format>
#include <span>
#include <string_view>
#include <type_traits>

#include "src/common/log_record.hpp"

namespace kinetum::common
{

/**
 * @brief Set a finite tool's application identity before any producer starts.
 * @param application Fixed executable role, at most 48 PRINTUSASCII bytes.
 * @note No background thread or persistent destination is created.
 */
void set_command_log_identity(std::string_view application) noexcept;

/**
 * @brief Check immutable severity filters before evaluating message arguments.
 * @param level Declared severity; an undeclared value is a contract violation.
 * @param component Name in the closed component registry.
 * @return True if this diagnostic should be constructed; filtering is not loss.
 * @note Services use their configured thresholds. Finite commands admit gRPC
 *       ERROR and higher, and other components at INFO and higher.
 */
[[nodiscard]] bool log_enabled(log_level level, std::string_view component) noexcept;

/** @brief Complete borrowed frontend identity; copied before publication. */
struct log_site {
	log_level level;			   ///< Declared diagnostic severity.
	std::string_view component;		   ///< Closed platform component.
	std::string_view event;			   ///< Stable event identity, 1..32 printable non-space bytes.
	std::string_view function;		   ///< Actual emitting function, or empty for unavailable.
	std::optional<uint8_t> native_severity{};  ///< Optional native syslog severity; never inferred from text.
	bool truncated{false};			   ///< Adapter already bounded a native metadata or text field.
};

/**
 * @brief Construct a message in a borrowed bounded destination.
 * @param context Borrowed formatter closure, valid only during submit_log().
 * @param output Owned raw message extent.
 * @return Full untruncated size; at most output.size() bytes may be written.
 * @note Exceptions are caught and counted at the logging boundary.
 */
using log_message_builder = std::size_t (*)(void *context, std::span<char> output);

/**
 * @brief Submit one cold diagnostic without propagating formatting or I/O failure.
 * @param site Complete emitter identity.
 * @param context Borrowed builder state.
 * @param builder Synchronous bounded formatter; never retained or called under a lock.
 */
void submit_log(log_site site, void *context, log_message_builder builder) noexcept;

/**
 * @brief Submit a foreign diagnostic with exact ERROR+ delivery confirmation.
 * @param site Actual native/provider identity; ERROR+ cannot be filtered out.
 * @param context Borrowed formatter state, never retained.
 * @param builder Synchronous bounded formatter, called only from an admitted cold thread.
 * @note Packet-owner calls reject and count before construction. Cold ERROR+
 *       waits at most 100 ms for its own file outcome; known failure or timeout
 *       attempts emergency stderr. That write is best effort and may block.
 */
void submit_foreign_log(log_site site, void *context, log_message_builder builder) noexcept;

/**
 * @brief Bind a foreign diagnostic formatter without retaining caller storage.
 * @tparam builder_type Exact borrowed closure type.
 * @param site Actual emitter identity and severity.
 * @param builder Formatter evaluated at most once and only on a cold thread.
 */
template <typename builder_type>
void log_foreign_lazy(log_site site, builder_type &&builder) noexcept
{
	submit_foreign_log(site, &builder, [](void *context, std::span<char> output) -> std::size_t {
		return (*static_cast<std::remove_reference_t<builder_type> *>(context))(output);
	});
}

/**
 * @brief Bind a caller-owned formatter for the duration of one submission.
 * @tparam builder_type Exact closure type, never stored by the logger.
 * @param site Complete emitter identity.
 * @param builder Closure evaluated only during this call.
 */
template <typename builder_type>
void log_lazy(log_site site, builder_type &&builder) noexcept
{
	submit_log(site, &builder, [](void *context, std::span<char> output) -> std::size_t {
		return (*static_cast<std::remove_reference_t<builder_type> *>(context))(output);
	});
}

/**
 * @brief Copy already formatted foreign text through the same bounded frontend.
 * @param site Actual borrowed emitter identity, copied before return.
 * @param message Borrowed raw bytes; excess bytes are visibly truncated.
 */
void log_text(log_site site, std::string_view message) noexcept;

/** @brief Account one malformed native diagnostic that cannot enter record construction. */
void reject_log_record() noexcept;

/**
 * @brief Report complete finite-tool diagnostic delivery before publishing results.
 * @return False after any synchronous formatting/delivery failure. In service
 *         mode, true only if the accepted prefix has already been delivered.
 * @note Never blocks waiting for the background service writer.
 */
[[nodiscard]] bool flush_logs() noexcept;

/**
 * @brief Offer a preformatted fatal record without ordinary queue dependency.
 * @param site Actual fatal emitter identity.
 * @param message Borrowed bounded diagnostic, copied immediately if admitted.
 * @note A reserved record gets at most 100 ms to complete. Failed reservation
 *       returns immediately; the caller retains its raw breadcrumb and abort.
 */
void offer_fatal_log(log_site site, std::string_view message) noexcept;

/** @brief Filter before evaluating any message expression or foreign formatter. */
#define KINETUM_LOG(level_value, component_value, event_value, ...)                                             \
	do {                                                                                                    \
		if (::kinetum::common::log_enabled((level_value), (component_value))) {                         \
			::kinetum::common::log_lazy(                                                            \
				{(level_value), (component_value), (event_value), __func__},                    \
				[&](std::span<char> kinetum_log_output) -> std::size_t {                        \
					return static_cast<std::size_t>(                                        \
						std::format_to_n(                                               \
							kinetum_log_output.data(),                              \
							static_cast<std::ptrdiff_t>(kinetum_log_output.size()), \
							__VA_ARGS__)                                            \
							.size);                                                 \
				});                                                                             \
		}                                                                                               \
	} while (false)

/** @brief Submit a cold debug diagnostic when enabled. */
#define KINETUM_LOG_DEBUG(component, event, ...) \
	KINETUM_LOG(::kinetum::common::log_level::DEBUG, component, event, __VA_ARGS__)
/** @brief Submit an informational diagnostic. */
#define KINETUM_LOG_INFO(component, event, ...) \
	KINETUM_LOG(::kinetum::common::log_level::INFO, component, event, __VA_ARGS__)
/** @brief Submit a warning diagnostic. */
#define KINETUM_LOG_WARN(component, event, ...) \
	KINETUM_LOG(::kinetum::common::log_level::WARN, component, event, __VA_ARGS__)
/** @brief Submit an operation-failure diagnostic without changing that operation. */
#define KINETUM_LOG_ERROR(component, event, ...) \
	KINETUM_LOG(::kinetum::common::log_level::ERROR, component, event, __VA_ARGS__)

}  // namespace kinetum::common
