// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_log_capture.hpp
 * @brief Owned cold diagnostic receiver for provider factory and lifetime tests.
 * @author Fleming Patel
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string_view>

#include "src/provider/provider_component_abi.h"
#include "src/common/packet_thread_log_guard.hpp"

namespace kinetum::test_support
{

/** @brief Own a factory's logging capability until every resulting instance retires. */
class provider_log_capture final {
    public:
	/** @brief Complete copied observation; no provider view survives its callback. */
	struct observation {
		uint64_t records{0};		      ///< Number of submitted diagnostics.
		uint64_t malformed{0};		      ///< Number of invalid callback records.
		kinetum_provider_log_level level{0};  ///< Last submitted native level.
		std::array<char, 33> event{};	      ///< Last bounded stable event ID.
		std::array<char, 129> function{};     ///< Last bounded actual function.
		std::array<char, 8193> message{};     ///< Last bounded message plus terminator.
		uint32_t message_size{0};	      ///< Occupied message bytes, preserving embedded NULs.
	};

	/** @return A capability borrowing this capture through final instance destruction. */
	[[nodiscard]] kinetum_provider_cold_log capability() noexcept
	{
		return {.context = this, .write = receive};
	}
	/** @return One complete callback observation, copied under the capture lock. */
	[[nodiscard]] observation read() const
	{
		std::lock_guard lock(mutex_);
		return observation_;
	}

    private:
	/**
	 * @tparam capacity Complete owned field extent, including its terminator.
	 * @param output Test-owned destination.
	 * @param input Validated callback-borrowed bytes.
	 * @return Copied prefix length, excluding the appended terminator.
	 */
	template <std::size_t capacity>
	static uint32_t copy(std::array<char, capacity> &output, kinetum_provider_text_view input) noexcept
	{
		const auto size = std::min(static_cast<std::size_t>(input.size), capacity - 1);
		if (size != 0) {
			std::memcpy(output.data(), input.data, size);
		}
		output[size] = '\0';
		return static_cast<uint32_t>(size);
	}
	/**
	 * @brief Consume a real provider callback without retaining any borrowed record.
	 * @param context Capture owner retained through every provider destruction.
	 * @param level Native fixed-width severity.
	 * @param event Borrowed stable event identifier.
	 * @param function Borrowed actual function name, or empty.
	 * @param message Borrowed raw message bytes.
	 */
	static void receive(void *context, kinetum_provider_log_level level, kinetum_provider_text_view event,
			    kinetum_provider_text_view function, kinetum_provider_text_view message) noexcept
	{
		if (kinetum::common::reject_packet_thread_log()) {
			return;
		}
		auto &self = *static_cast<provider_log_capture *>(context);
		std::lock_guard lock(self.mutex_);
		++self.observation_.records;
		if (level < KINETUM_PROVIDER_LOG_DEBUG || level > KINETUM_PROVIDER_LOG_EMERGENCY ||
		    !kinetum_provider_text_view_is_valid(event) || !kinetum_provider_text_view_is_valid(function) ||
		    !kinetum_provider_text_view_is_valid(message) || event.size == 0 || event.size > 32) {
			++self.observation_.malformed;
			return;
		}
		self.observation_.level = level;
		(void)copy(self.observation_.event, event);
		(void)copy(self.observation_.function, function);
		self.observation_.message_size = copy(self.observation_.message, message);
	}

	mutable std::mutex mutex_;   ///< Protects complete diagnostic observations across native emitters.
	observation observation_{};  ///< Sole owned callback evidence.
};

}  // namespace kinetum::test_support
