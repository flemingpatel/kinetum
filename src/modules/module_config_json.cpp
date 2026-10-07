// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module_config_json.cpp
 * @brief Strict module-owned JSON reader implementation.
 * @author Fleming Patel
 */

#include "src/modules/module_config_json.hpp"

#include <array>
#include <limits>
#include <utility>

namespace kinetum::modules::config
{
namespace
{

/**
 * @brief Convert one hexadecimal digit or return an invalid sentinel.
 * @param character Candidate ASCII digit byte.
 * @return Value in 0..15, or UINT8_MAX for a non-hexadecimal byte.
 */
[[nodiscard]] constexpr uint8_t hex_value(uint8_t character) noexcept
{
	if (character >= '0' && character <= '9') {
		return static_cast<uint8_t>(character - '0');
	}
	if (character >= 'a' && character <= 'f') {
		return static_cast<uint8_t>(character - 'a' + 10u);
	}
	if (character >= 'A' && character <= 'F') {
		return static_cast<uint8_t>(character - 'A' + 10u);
	}
	return UINT8_MAX;
}

/**
 * @brief Append one Unicode scalar as canonical UTF-8.
 * @param code_point Previously validated Unicode scalar value.
 * @param append Borrowed byte appender returning whether each byte was accepted.
 * @return true after every encoded byte is accepted; false leaves the previously appended prefix intact.
 * @tparam append_type Callable accepting one byte and returning bool.
 */
template <typename append_type>
[[nodiscard]] bool append_code_point(uint32_t code_point, append_type &&append)
{
	if (code_point <= 0x7fu) {
		return append(static_cast<char>(code_point));
	}
	if (code_point <= 0x7ffu) {
		return append(static_cast<char>(0xc0u | (code_point >> 6u))) &&
		       append(static_cast<char>(0x80u | (code_point & 0x3fu)));
	}
	if (code_point >= 0xd800u && code_point <= 0xdfffu) {
		return false;
	}
	if (code_point <= 0xffffu) {
		return append(static_cast<char>(0xe0u | (code_point >> 12u))) &&
		       append(static_cast<char>(0x80u | ((code_point >> 6u) & 0x3fu))) &&
		       append(static_cast<char>(0x80u | (code_point & 0x3fu)));
	}
	if (code_point <= 0x10ffffu) {
		return append(static_cast<char>(0xf0u | (code_point >> 18u))) &&
		       append(static_cast<char>(0x80u | ((code_point >> 12u) & 0x3fu))) &&
		       append(static_cast<char>(0x80u | ((code_point >> 6u) & 0x3fu))) &&
		       append(static_cast<char>(0x80u | (code_point & 0x3fu)));
	}
	return false;
}

}  // namespace

json_reader::json_reader(const void *data, std::size_t size, cancellation_probe cancellation) noexcept
	: data_(static_cast<const uint8_t *>(data))
	, size_(size)
	, next_cancellation_poll_(CANCELLATION_POLL_BYTES)
	, cancellation_(cancellation)
{
	if (data_ == nullptr && size_ != 0) {
		result_ = compile_result::INVALID;
	}
}

bool json_reader::healthy_() const noexcept
{
	return result_ == compile_result::OK;
}

void json_reader::invalidate_() noexcept
{
	if (result_ == compile_result::OK) {
		result_ = compile_result::INVALID;
	}
}

bool json_reader::poll_cancellation_() noexcept
{
	if (!healthy_()) {
		return false;
	}
	if (position_ < next_cancellation_poll_) {
		return true;
	}
	next_cancellation_poll_ = position_ + CANCELLATION_POLL_BYTES;
	if (cancellation_.cancelled()) {
		result_ = compile_result::CANCELLED;
		return false;
	}
	return true;
}

void json_reader::skip_whitespace_() noexcept
{
	while (position_ < size_) {
		const uint8_t character = data_[position_];
		if (character != ' ' && character != '\t' && character != '\n' && character != '\r') {
			break;
		}
		++position_;
	}
	(void)poll_cancellation_();
}

bool json_reader::consume_(char expected) noexcept
{
	if (!healthy_()) {
		return false;
	}
	skip_whitespace_();
	if (!healthy_() || position_ >= size_ || data_[position_] != static_cast<uint8_t>(expected)) {
		invalidate_();
		return false;
	}
	++position_;
	return poll_cancellation_();
}

bool json_reader::begin_object() noexcept
{
	return consume_('{');
}

bool json_reader::begin_array() noexcept
{
	return consume_('[');
}

bool json_reader::next_object_member(bool *first) noexcept
{
	if (first == nullptr || !healthy_()) {
		invalidate_();
		return false;
	}
	skip_whitespace_();
	if (!healthy_() || position_ >= size_) {
		invalidate_();
		return false;
	}
	if (data_[position_] == '}') {
		++position_;
		return false;
	}
	if (*first) {
		*first = false;
		return true;
	}
	if (data_[position_] != ',') {
		invalidate_();
		return false;
	}
	++position_;
	skip_whitespace_();
	if (!healthy_() || position_ >= size_ || data_[position_] == '}') {
		invalidate_();
		return false;
	}
	return true;
}

bool json_reader::next_array_element(bool *first) noexcept
{
	if (first == nullptr || !healthy_()) {
		invalidate_();
		return false;
	}
	skip_whitespace_();
	if (!healthy_() || position_ >= size_) {
		invalidate_();
		return false;
	}
	if (data_[position_] == ']') {
		++position_;
		return false;
	}
	if (*first) {
		*first = false;
		return true;
	}
	if (data_[position_] != ',') {
		invalidate_();
		return false;
	}
	++position_;
	skip_whitespace_();
	if (!healthy_() || position_ >= size_ || data_[position_] == ']') {
		invalidate_();
		return false;
	}
	return true;
}

bool json_reader::consume_colon() noexcept
{
	return consume_(':');
}

bool json_reader::consume_hex_quad_(uint32_t *code_point) noexcept
{
	if (code_point == nullptr || size_ - position_ < 4) {
		invalidate_();
		return false;
	}
	uint32_t value = 0;
	for (std::size_t index = 0; index < 4; ++index) {
		const uint8_t digit = hex_value(data_[position_++]);
		if (digit == UINT8_MAX) {
			invalidate_();
			return false;
		}
		value = (value << 4u) | digit;
	}
	*code_point = value;
	return poll_cancellation_();
}

bool json_reader::consume_utf8_sequence_(uint8_t first, uint8_t *bytes, std::size_t *count) noexcept
{
	if (bytes == nullptr || count == nullptr) {
		invalidate_();
		return false;
	}
	std::size_t length = 0;
	uint32_t code_point = 0;
	uint32_t minimum = 0;
	if (first >= 0xc2u && first <= 0xdfu) {
		length = 2;
		code_point = first & 0x1fu;
		minimum = 0x80u;
	} else if (first >= 0xe0u && first <= 0xefu) {
		length = 3;
		code_point = first & 0x0fu;
		minimum = 0x800u;
	} else if (first >= 0xf0u && first <= 0xf4u) {
		length = 4;
		code_point = first & 0x07u;
		minimum = 0x10000u;
	} else {
		invalidate_();
		return false;
	}
	if (size_ - position_ < length - 1u) {
		invalidate_();
		return false;
	}
	bytes[0] = first;
	for (std::size_t index = 1; index < length; ++index) {
		const uint8_t continuation = data_[position_++];
		if ((continuation & 0xc0u) != 0x80u) {
			invalidate_();
			return false;
		}
		bytes[index] = continuation;
		code_point = (code_point << 6u) | (continuation & 0x3fu);
	}
	if (code_point < minimum || code_point > 0x10ffffu || (code_point >= 0xd800u && code_point <= 0xdfffu)) {
		invalidate_();
		return false;
	}
	*count = length;
	return poll_cancellation_();
}

template <typename append_type>
bool json_reader::read_string_impl_(append_type &&append)
{
	if (!consume_('"')) {
		return false;
	}
	while (position_ < size_) {
		const uint8_t character = data_[position_++];
		if (character == '"') {
			return poll_cancellation_();
		}
		if (character < 0x20u) {
			invalidate_();
			return false;
		}
		if (character == '\\') {
			if (position_ >= size_) {
				invalidate_();
				return false;
			}
			const uint8_t escape = data_[position_++];
			switch (escape) {
			case '"':
			case '\\':
			case '/':
				if (!append(static_cast<char>(escape))) {
					invalidate_();
					return false;
				}
				break;
			case 'b':
			case 'f':
			case 'n':
			case 'r':
			case 't': {
				constexpr std::array<char, 5> DECODED{'\b', '\f', '\n', '\r', '\t'};
				constexpr std::array<uint8_t, 5> ESCAPES{'b', 'f', 'n', 'r', 't'};
				std::size_t index = 0;
				while (ESCAPES[index] != escape) {
					++index;
				}
				if (!append(DECODED[index])) {
					invalidate_();
					return false;
				}
				break;
			}
			case 'u': {
				uint32_t code_point = 0;
				if (!consume_hex_quad_(&code_point)) {
					return false;
				}
				if (code_point >= 0xd800u && code_point <= 0xdbffu) {
					if (size_ - position_ < 6 || data_[position_] != '\\' ||
					    data_[position_ + 1] != 'u') {
						invalidate_();
						return false;
					}
					position_ += 2;
					uint32_t low = 0;
					if (!consume_hex_quad_(&low) || low < 0xdc00u || low > 0xdfffu) {
						invalidate_();
						return false;
					}
					code_point = 0x10000u + ((code_point - 0xd800u) << 10u) + (low - 0xdc00u);
				} else if (code_point >= 0xdc00u && code_point <= 0xdfffu) {
					invalidate_();
					return false;
				}
				if (!append_code_point(code_point, append)) {
					invalidate_();
					return false;
				}
				break;
			}
			default:
				invalidate_();
				return false;
			}
		} else if (character < 0x80u) {
			if (!append(static_cast<char>(character))) {
				invalidate_();
				return false;
			}
		} else {
			uint8_t bytes[4]{};
			std::size_t count = 0;
			if (!consume_utf8_sequence_(character, bytes, &count)) {
				return false;
			}
			for (std::size_t index = 0; index < count; ++index) {
				if (!append(static_cast<char>(bytes[index]))) {
					invalidate_();
					return false;
				}
			}
		}
		if (!poll_cancellation_()) {
			return false;
		}
	}
	invalidate_();
	return false;
}

bool json_reader::read_string(char *output, std::size_t capacity, std::size_t *out_size) noexcept
{
	if (output == nullptr || out_size == nullptr || capacity == 0) {
		invalidate_();
		return false;
	}
	std::size_t written = 0;
	const bool ok = read_string_impl_([&](char character) noexcept {
		if (written + 1u >= capacity) {
			return false;
		}
		output[written++] = character;
		return true;
	});
	if (!ok) {
		return false;
	}
	output[written] = '\0';
	*out_size = written;
	return true;
}

bool json_reader::read_string(std::pmr::string *output)
{
	if (output == nullptr) {
		invalidate_();
		return false;
	}
	output->clear();
	return read_string_impl_([output](char character) {
		output->push_back(character);
		return true;
	});
}

bool json_reader::discard_string() noexcept
{
	return read_string_impl_([](char) noexcept { return true; });
}

bool json_reader::read_integer_magnitude_(bool *negative, uint64_t *magnitude) noexcept
{
	if (negative == nullptr || magnitude == nullptr || !healthy_()) {
		invalidate_();
		return false;
	}
	skip_whitespace_();
	if (!healthy_() || position_ >= size_) {
		invalidate_();
		return false;
	}
	*negative = data_[position_] == '-';
	if (*negative) {
		++position_;
	}
	if (position_ >= size_ || data_[position_] < '0' || data_[position_] > '9') {
		invalidate_();
		return false;
	}
	if (data_[position_] == '0' && position_ + 1u < size_ && data_[position_ + 1u] >= '0' &&
	    data_[position_ + 1u] <= '9') {
		invalidate_();
		return false;
	}
	uint64_t value = 0;
	while (position_ < size_ && data_[position_] >= '0' && data_[position_] <= '9') {
		const uint64_t digit = static_cast<uint64_t>(data_[position_] - '0');
		if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10u) {
			invalidate_();
			return false;
		}
		value = value * 10u + digit;
		++position_;
		if (!poll_cancellation_()) {
			return false;
		}
	}
	if (position_ < size_ && (data_[position_] == '.' || data_[position_] == 'e' || data_[position_] == 'E')) {
		invalidate_();
		return false;
	}
	*magnitude = value;
	return true;
}

bool json_reader::read_int64(int64_t *output) noexcept
{
	bool negative = false;
	uint64_t magnitude = 0;
	if (output == nullptr || !read_integer_magnitude_(&negative, &magnitude)) {
		invalidate_();
		return false;
	}
	constexpr uint64_t MAX = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
	if ((!negative && magnitude > MAX) || (negative && magnitude > MAX + 1u)) {
		invalidate_();
		return false;
	}
	if (negative && magnitude == MAX + 1u) {
		*output = std::numeric_limits<int64_t>::min();
	} else {
		const int64_t signed_magnitude = static_cast<int64_t>(magnitude);
		*output = negative ? -signed_magnitude : signed_magnitude;
	}
	return true;
}

bool json_reader::read_uint64(uint64_t *output) noexcept
{
	bool negative = false;
	uint64_t magnitude = 0;
	if (output == nullptr || !read_integer_magnitude_(&negative, &magnitude) || negative) {
		invalidate_();
		return false;
	}
	*output = magnitude;
	return true;
}

bool json_reader::read_bool(bool *output) noexcept
{
	if (output == nullptr || !healthy_()) {
		invalidate_();
		return false;
	}
	skip_whitespace_();
	if (!healthy_()) {
		return false;
	}
	constexpr char TRUE_LITERAL[] = "true";
	constexpr char FALSE_LITERAL[] = "false";
	const char *literal = nullptr;
	std::size_t length = 0;
	bool value = false;
	if (size_ - position_ >= 4 && data_[position_] == 't') {
		literal = TRUE_LITERAL;
		length = 4;
		value = true;
	} else if (size_ - position_ >= 5 && data_[position_] == 'f') {
		literal = FALSE_LITERAL;
		length = 5;
	} else {
		invalidate_();
		return false;
	}
	for (std::size_t index = 0; index < length; ++index) {
		if (data_[position_ + index] != static_cast<uint8_t>(literal[index])) {
			invalidate_();
			return false;
		}
	}
	position_ += length;
	*output = value;
	return poll_cancellation_();
}

compile_result json_reader::finish() noexcept
{
	if (!healthy_()) {
		return result_;
	}
	skip_whitespace_();
	if (healthy_() && position_ != size_) {
		invalidate_();
	}
	if (healthy_() && cancellation_.cancelled()) {
		result_ = compile_result::CANCELLED;
	}
	return result_;
}

compile_result json_reader::result() const noexcept
{
	return result_;
}

}  // namespace kinetum::modules::config
