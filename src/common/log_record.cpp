// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file log_record.cpp
 * @brief Bounded readable record construction without deferred foreign code.
 * @author Fleming Patel
 */

#include "src/common/log_record.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <ctime>
#include <limits>

namespace kinetum::common
{
namespace
{

/** @brief Bounds-checked writer for the sole encoding pass. */
class record_encoder final {
    public:
	/** @param output Complete encoding extent borrowed until construction finishes. */
	explicit record_encoder(std::span<char> output) noexcept
		: output_(output)
	{
	}
	/** @param value Borrowed literal bytes; overflow invalidates the complete record. */
	void text(std::string_view value) noexcept
	{
		if (value.size() > output_.size() - size_) {
			valid_ = false;
			return;
		}
		if (!value.empty()) {
			std::memcpy(output_.data() + size_, value.data(), value.size());
		}
		size_ += value.size();
	}
	/** @param value Unsigned integer to append in base ten without locale or allocation. */
	void number(uint64_t value) noexcept
	{
		std::array<char, 20> digits{};
		const auto result = std::to_chars(digits.data(), digits.data() + digits.size(), value);
		if (result.ec != std::errc{}) {
			valid_ = false;
			return;
		}
		text(std::string_view(digits.data(), static_cast<std::size_t>(result.ptr - digits.data())));
	}
	/** @param value Borrowed printable header token; missing or malformed metadata becomes a dash. */
	void token(std::string_view value) noexcept
	{
		if (value.empty() || !std::all_of(value.begin(), value.end(),
						  [](unsigned char byte) { return byte >= 33 && byte <= 126; })) {
			text("-");
			return;
		}
		text(value);
	}
	/** @param value Borrowed raw bytes, escaped into one unambiguous ASCII record. */
	void escaped(std::string_view value) noexcept
	{
		constexpr char HEX[] = "0123456789abcdef";
		for (const char character : value) {
			const auto byte = static_cast<unsigned char>(character);
			if (byte == '\\') {
				text("\\\\");
			} else if (byte < 32 || byte >= 127) {
				const std::array<char, 4> escape{'\\', 'x', HEX[byte >> 4u], HEX[byte & 15u]};
				text(std::string_view(escape.data(), escape.size()));
			} else {
				text(std::string_view(&character, 1));
			}
		}
	}
	/** @return Complete occupied bytes or zero after any overflow. */
	[[nodiscard]] std::size_t size() const noexcept
	{
		return valid_ ? size_ : 0;
	}

    private:
	std::span<char> output_;  ///< Borrowed writer-owned encoded buffer.
	std::size_t size_{0};	  ///< Occupied prefix.
	bool valid_{true};	  ///< Sticky overflow rejection.
};

/**
 * @tparam size Exact owned metadata extent.
 * @param value Bounded NUL-terminated array.
 * @return Borrowed occupied prefix without its terminator.
 */
template <std::size_t size>
[[nodiscard]] std::string_view field(const std::array<char, size> &value) noexcept
{
	const auto end = std::find(value.begin(), value.end(), '\0');
	return std::string_view(value.data(), static_cast<std::size_t>(end - value.begin()));
}

/**
 * @param output Sole bounded encoding destination.
 * @param realtime_us Native UTC microseconds; unavailable or unrepresentable input becomes a dash.
 */
void timestamp(record_encoder &output, int64_t realtime_us) noexcept
{
	if (realtime_us <= 0) {
		output.text("-");
		return;
	}
	const auto seconds = static_cast<time_t>(realtime_us / 1000000);
	std::tm utc{};
	std::array<char, 21> text{};
	if (::gmtime_r(&seconds, &utc) == nullptr || utc.tm_year < 0 || utc.tm_year > 8099 ||
	    std::strftime(text.data(), text.size(), "%Y-%m-%dT%H:%M:%S", &utc) != 19) {
		output.text("-");
		return;
	}
	output.text(std::string_view(text.data(), 19));
	output.text(".");
	std::array<char, 6> fraction{};
	auto remaining = static_cast<uint32_t>(realtime_us % 1000000);
	for (std::size_t index = fraction.size(); index != 0; --index) {
		fraction[index - 1] = static_cast<char>('0' + remaining % 10u);
		remaining /= 10u;
	}
	output.text(std::string_view(fraction.data(), fraction.size()));
	output.text("Z");
}

}  // namespace

bool valid_log_level(log_level level) noexcept
{
	switch (level) {
	case log_level::DEBUG:
	case log_level::INFO:
	case log_level::WARN:
	case log_level::ERROR:
	case log_level::FATAL:
		return true;
	}
	return false;
}

bool copy_log_field(std::span<char> destination, std::string_view source) noexcept
{
	if (destination.empty()) {
		return false;
	}
	const auto size = std::min(source.size(), destination.size() - 1);
	if (size != 0) {
		std::memcpy(destination.data(), source.data(), size);
	}
	destination[size] = '\0';
	return size == source.size();
}

std::size_t encode_log_record(const log_record &record, std::span<char> output) noexcept
{
	if (output.size() < LOG_ENCODED_BYTES || record.message_size > record.message.size() ||
	    !valid_log_level(record.level) || (record.native_severity.has_value() && *record.native_severity > 7)) {
		return 0;
	}
	constexpr std::array<std::string_view, 5> LEVEL_NAMES{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
	constexpr std::array<std::string_view, 8> NATIVE_LEVEL_NAMES{"EMERG", "ALERT",	"CRIT", "ERROR",
								     "WARN",  "NOTICE", "INFO", "DEBUG"};
	record_encoder encoder(output);
	timestamp(encoder, record.realtime_us);
	encoder.text(" [");
	encoder.text(record.native_severity.has_value() ? NATIVE_LEVEL_NAMES[*record.native_severity] :
							  LEVEL_NAMES[static_cast<std::size_t>(record.level) - 1]);
	encoder.text("] ");
	encoder.token(field(record.hostname));
	encoder.text(" ");
	encoder.token(field(record.application));
	encoder.text("[");
	if (record.process_id == 0) {
		encoder.text("-");
	} else {
		encoder.number(record.process_id);
		if (record.thread_id != 0) {
			encoder.text(":");
			encoder.number(record.thread_id);
		}
	}
	encoder.text("] ");
	encoder.token(field(record.event));
	encoder.text(" - ");
	encoder.escaped(field(record.component));
	if (!field(record.function).empty()) {
		encoder.text("/");
		encoder.escaped(field(record.function));
	}
	encoder.text(": ");
	encoder.escaped(std::string_view(record.message.data(), record.message_size));
	if (record.truncated) {
		encoder.text("...[truncated]");
	}
	encoder.text("\n");
	return encoder.size();
}

}  // namespace kinetum::common
