// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file log_record.hpp
 * @brief Owned cold diagnostic records and bounded readable text encoding.
 * @author Fleming Patel
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace kinetum::common
{

/** @brief Diagnostic severity; severity alone never selects a service action. */
enum class log_level : uint8_t {
	DEBUG = 1,  ///< Detailed cold diagnostic.
	INFO = 2,   ///< Ordinary lifecycle observation.
	WARN = 3,   ///< Degraded or unexpected condition.
	ERROR = 4,  ///< Failed operation.
	FATAL = 5,  ///< Critical diagnostic; the caller owns the terminal action.
};

/** Maximum owned, unescaped message bytes. */
inline constexpr std::size_t LOG_MESSAGE_BYTES = 8192;
/** Maximum complete encoded record, including its terminating newline. */
inline constexpr std::size_t LOG_ENCODED_BYTES = std::size_t{34} * 1024;

/**
 * @brief Complete diagnostic ownership transferred from one cold emitter.
 *
 * No pointer, formatter, or module/provider code survives publication. A zero
 * timestamp or identifier denotes unavailable metadata and encodes as a dash;
 * it must not be replaced with a writer-thread observation.
 */
struct log_record {
	int64_t realtime_us{0};				///< Emitter's UTC microseconds since the Unix epoch.
	uint64_t process_id{0};				///< Actual emitting process, or unavailable.
	uint64_t thread_id{0};				///< Actual emitting thread, or unavailable.
	log_level level{log_level::INFO};		///< Validated severity.
	std::optional<uint8_t> native_severity;		///< Native syslog severity, 0 (emergency) through 7 (debug).
	bool truncated{false};				///< At least one input exceeded its owned extent.
	bool console{false};				///< Caller selected the independent console mirror.
	std::array<char, 256> hostname{};		///< Host identity, at most 255 printable bytes.
	std::array<char, 49> application{};		///< Fixed application identity, at most 48 printable bytes.
	std::array<char, 33> event{};			///< Stable event identity, at most 32 printable bytes.
	std::array<char, 49> component{};		///< Platform component or admitted native source.
	std::array<char, 129> function{};		///< Actual source function when supplied.
	std::array<char, LOG_MESSAGE_BYTES> message{};	///< Owned unescaped message, including embedded NULs.
	std::size_t message_size{0};			///< Occupied message prefix.
};

static_assert(sizeof(log_record) <= LOG_MESSAGE_BYTES + 2048);

/**
 * @brief Copy a bounded metadata field and terminate it.
 * @param destination Nonempty owned field.
 * @param source Borrowed bytes, copied before return.
 * @return True if every byte fit; false after explicit truncation.
 */
[[nodiscard]] bool copy_log_field(std::span<char> destination, std::string_view source) noexcept;

/**
 * @brief Encode one complete escaped record with UTC, named severity, and application[PID:TID].
 * @param record Complete owned emitter facts.
 * @param output At least LOG_ENCODED_BYTES writable bytes.
 * @return Occupied output bytes including newline, or zero for invalid input.
 * @note No allocation, clock read, I/O, or mutable shared state.
 */
[[nodiscard]] std::size_t encode_log_record(const log_record &record, std::span<char> output) noexcept;

/**
 * @param level Candidate fixed severity.
 * @return True exactly for a declared severity.
 */
[[nodiscard]] bool valid_log_level(log_level level) noexcept;

}  // namespace kinetum::common
