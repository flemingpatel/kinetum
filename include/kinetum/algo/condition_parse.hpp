// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file condition_parse.hpp
 * @brief Shared parser for simple packet-field edge conditions.
 * @author Fleming Patel
 *
 * Parses the platform condition syntax:
 *
 *   field op decimal_uint32
 *
 * This header owns syntax only. Callers remain responsible for mapping the
 * parsed field name to their local enum or whitelist. Keeping the parser in
 * the canonical public algorithm surface prevents authoring-time validation
 * and runtime route compilation
 * from drifting apart.
 *
 * @par Thread Safety
 * All functions are stateless and reentrant. Returned string_views point into
 * the caller-provided input string_view and must not outlive that input.
 */

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <system_error>

namespace kinetum::algo
{

/**
 * @brief Parsed comparison operator for an edge condition expression.
 */
enum class condition_op : uint8_t {
	EQ,  ///< Equality: `==`.
	NE,  ///< Inequality: `!=`.
	LT,  ///< Less-than: `<`.
	LE,  ///< Less-than-or-equal: `<=`.
	GT,  ///< Greater-than: `>`.
	GE,  ///< Greater-than-or-equal: `>=`.
};

/**
 * @brief Parser failure reason for condition syntax validation.
 */
enum class condition_parse_error : uint8_t {
	NONE,		   ///< Parse succeeded.
	EMPTY_CONDITION,   ///< Input was empty or whitespace-only.
	INVALID_FIELD,	   ///< Field token was missing or malformed.
	MISSING_OPERATOR,  ///< Field parsed but no operator was present.
	INVALID_OPERATOR,  ///< Operator token was not one of the supported comparisons.
	INVALID_VALUE,	   ///< Value token was missing, negative, overflowed, or not decimal uint32.
	TRAILING_TEXT,	   ///< Non-space trailing content remained after the value.
};

/**
 * @brief Parsed `field op value` expression.
 */
struct condition_expression {
	std::string_view field{};	    ///< Field token, backed by the caller's input string.
	condition_op op{condition_op::EQ};  ///< Parsed comparison operator.
	uint32_t value{0};		    ///< Parsed decimal uint32 comparison value.
};

/** @cond INTERNAL_IMPLEMENTATION */
namespace detail
{

/**
 * @brief Return whether a byte is ASCII whitespace.
 *
 * @param c Input byte.
 * @return True only for the six ASCII whitespace bytes.
 */
[[nodiscard]] constexpr bool condition_is_ascii_space(char c) noexcept
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/**
 * @brief Return whether a byte is an ASCII decimal digit.
 *
 * @param c Input byte.
 * @return True when `c` is `0` through `9`.
 */
[[nodiscard]] constexpr bool condition_is_ascii_digit(char c) noexcept
{
	return c >= '0' && c <= '9';
}

/**
 * @brief Return whether a byte is valid inside a condition field identifier.
 *
 * @param c Input byte.
 * @return True for ASCII alphanumeric bytes and underscore.
 */
[[nodiscard]] constexpr bool condition_is_identifier_char(char c) noexcept
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || condition_is_ascii_digit(c) || c == '_';
}

/**
 * @brief Match one exact two-byte operator at a bounded cursor.
 * @param text Complete condition text.
 * @param pos Candidate first-byte cursor.
 * @param first Required first operator byte.
 * @param second Required second operator byte.
 * @return True only when both bytes are present and equal.
 */
[[nodiscard]] constexpr bool condition_matches_pair(std::string_view text, std::size_t pos, char first,
						    char second) noexcept
{
	return pos <= text.size() && text.size() - pos >= 2u && text[pos] == first && text[pos + 1u] == second;
}

/**
 * @brief Advance past ASCII whitespace.
 *
 * @param text Input text.
 * @param pos Cursor to update in place.
 */
inline void condition_skip_ascii_spaces(std::string_view text, std::size_t &pos) noexcept
{
	while (pos < text.size() && condition_is_ascii_space(text[pos])) {
		++pos;
	}
}

/**
 * @brief Parse a complete decimal uint32 token at the current cursor.
 *
 * The cursor advances over decimal digits only. The caller checks for trailing
 * text after this function returns.
 *
 * @param text Input text.
 * @param pos Cursor to update in place.
 * @param value Parsed output value on success.
 * @return True when a non-empty decimal token fits in `uint32_t`.
 */
[[nodiscard]] inline bool condition_parse_uint32(std::string_view text, std::size_t &pos, uint32_t &value) noexcept
{
	if (pos >= text.size() || !condition_is_ascii_digit(text[pos])) {
		return false;
	}

	const std::size_t value_start = pos;
	while (pos < text.size() && condition_is_ascii_digit(text[pos])) {
		++pos;
	}

	uint64_t parsed = 0;
	const char *first = text.data() + value_start;
	const char *last = text.data() + pos;
	const auto result = std::from_chars(first, last, parsed, 10);
	if (result.ec != std::errc{} || result.ptr != last || parsed > std::numeric_limits<uint32_t>::max()) {
		return false;
	}

	value = static_cast<uint32_t>(parsed);
	return true;
}

}  // namespace detail
/** @endcond */

/**
 * @brief Parse one `field op decimal_uint32` expression.
 *
 * Leading and trailing whitespace are accepted. Empty input is not accepted;
 * callers represent unconditional edges with an empty condition string before
 * calling this function.
 *
 * @param text Condition expression text.
 * @param out Parsed expression on success. Reset to defaults before parsing.
 * @param error Optional detailed parse error output.
 * @return True when the expression is syntactically valid.
 */
[[nodiscard]] inline bool parse_condition_expression(std::string_view text, condition_expression &out,
						     condition_parse_error *error = nullptr) noexcept
{
	auto fail = [error](condition_parse_error e) noexcept {
		if (error != nullptr) {
			*error = e;
		}
		return false;
	};

	out = condition_expression{};
	if (error != nullptr) {
		*error = condition_parse_error::NONE;
	}

	std::size_t pos = 0;
	detail::condition_skip_ascii_spaces(text, pos);
	if (pos == text.size()) {
		return fail(condition_parse_error::EMPTY_CONDITION);
	}

	const std::size_t field_start = pos;
	while (pos < text.size() && detail::condition_is_identifier_char(text[pos])) {
		++pos;
	}
	if (field_start == pos) {
		return fail(condition_parse_error::INVALID_FIELD);
	}
	out.field = std::string_view(text.data() + field_start, pos - field_start);

	detail::condition_skip_ascii_spaces(text, pos);
	if (pos >= text.size()) {
		return fail(condition_parse_error::MISSING_OPERATOR);
	}

	if (detail::condition_matches_pair(text, pos, '=', '=')) {
		out.op = condition_op::EQ;
		pos += 2;
	} else if (detail::condition_matches_pair(text, pos, '!', '=')) {
		out.op = condition_op::NE;
		pos += 2;
	} else if (detail::condition_matches_pair(text, pos, '<', '=')) {
		out.op = condition_op::LE;
		pos += 2;
	} else if (detail::condition_matches_pair(text, pos, '>', '=')) {
		out.op = condition_op::GE;
		pos += 2;
	} else if (text[pos] == '<') {
		out.op = condition_op::LT;
		pos += 1;
	} else if (text[pos] == '>') {
		out.op = condition_op::GT;
		pos += 1;
	} else {
		return fail(condition_parse_error::INVALID_OPERATOR);
	}

	detail::condition_skip_ascii_spaces(text, pos);
	if (!detail::condition_parse_uint32(text, pos, out.value)) {
		return fail(condition_parse_error::INVALID_VALUE);
	}

	detail::condition_skip_ascii_spaces(text, pos);
	if (pos != text.size()) {
		return fail(condition_parse_error::TRAILING_TEXT);
	}

	return true;
}

/**
 * @brief Return stable text for a parser error.
 *
 * @param error Error enum to describe.
 * @return Static string view naming the error.
 */
[[nodiscard]] inline std::string_view condition_parse_error_name(condition_parse_error error) noexcept
{
	switch (error) {
	case condition_parse_error::NONE:
		return "none";
	case condition_parse_error::EMPTY_CONDITION:
		return "empty condition";
	case condition_parse_error::INVALID_FIELD:
		return "invalid field";
	case condition_parse_error::MISSING_OPERATOR:
		return "missing operator";
	case condition_parse_error::INVALID_OPERATOR:
		return "invalid operator";
	case condition_parse_error::INVALID_VALUE:
		return "invalid value";
	case condition_parse_error::TRAILING_TEXT:
		return "trailing text";
	}
	return "unknown parse error";
}

}  // namespace kinetum::algo
