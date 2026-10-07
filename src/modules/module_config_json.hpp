// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_config_json.hpp
 * @brief Allocation-free structural reader for strict module-owned JSON.
 * @author Fleming Patel
 *
 * Built-in module images cannot depend on a process-global generated-schema
 * registry and still be safely unloaded and reloaded. This reader provides the
 * exact runtime mechanism needed by those images: strict JSON tokenization,
 * duplicate/unknown-field enforcement by the schema-specific caller,
 * integer-only numeric fields, UTF-8 validation, and cooperative cancellation.
 * It builds no DOM, performs no recursive descent, and allocates no storage of
 * its own; each module compiler owns a fixed schema-depth traversal.
 */

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <string>

namespace kinetum::modules::config
{

/** @brief Terminal result of one module configuration compilation. */
enum class compile_result : uint8_t {
	OK = 0,	    ///< Complete valid input.
	INVALID,    ///< Syntax, schema, range, or ownership failure.
	CANCELLED,  ///< Cooperative cancellation observed.
};

/** @brief Non-owning cancellation hook polled during bounded JSON work. */
struct cancellation_probe {
	/** @brief Callback returning true after cancellation is published. */
	bool (*is_cancelled)(const void *context) noexcept {nullptr};
	/** @brief Opaque callback context. */
	const void *context{nullptr};

	/** @return true when the installed callback reports cancellation; false when absent. */
	[[nodiscard]] bool cancelled() const noexcept
	{
		return is_cancelled != nullptr && is_cancelled(context);
	}
};

/**
 * @brief Forward-only strict JSON reader over one immutable byte span.
 *
 * The reader accepts RFC-8259 whitespace, strings, booleans, and integer
 * numbers needed by the built-in module schemas. Strings are decoded into a
 * caller-owned fixed buffer or PMR string. Object and array traversal is
 * explicit so schema-specific code can reject unknown and duplicate fields.
 * Floating-point/exponent numbers are intentionally outside this contract.
 */
class json_reader {
    public:
	/**
	 * @brief Construct a reader over exact, non-NUL-terminated bytes.
	 *
	 * @param data Input bytes; null is valid only when @p size is zero.
	 * @param size Exact input byte count.
	 * @param cancellation Cooperative cancellation authority.
	 */
	json_reader(const void *data, std::size_t size, cancellation_probe cancellation = {}) noexcept;

	/** @return true after consuming an object-opening token; false on parse failure or cancellation. */
	[[nodiscard]] bool begin_object() noexcept;
	/** @return true after consuming an array-opening token; false on parse failure or cancellation. */
	[[nodiscard]] bool begin_array() noexcept;

	/**
	 * @brief Advance to the next object member or consume the closing token.
	 *
	 * @param first Caller-owned state initialized to true for this object.
	 * @return true when one member follows; false on closure or failure.
	 */
	[[nodiscard]] bool next_object_member(bool *first) noexcept;

	/**
	 * @brief Advance to the next array element or consume the closing token.
	 *
	 * @param first Caller-owned state initialized to true for this array.
	 * @return true when one element follows; false on closure or failure.
	 */
	[[nodiscard]] bool next_array_element(bool *first) noexcept;

	/** @return true after consuming a key/value colon; false on parse failure or cancellation. */
	[[nodiscard]] bool consume_colon() noexcept;

	/**
	 * @brief Decode one JSON string into fixed caller-owned storage.
	 *
	 * @param output Writable character storage.
	 * @param capacity Total capacity including room for a trailing NUL.
	 * @param out_size Decoded byte count excluding the trailing NUL.
	 * @return true after exact decoding; false on syntax, UTF-8, or capacity
	 *         failure.
	 */
	[[nodiscard]] bool read_string(char *output, std::size_t capacity, std::size_t *out_size) noexcept;

	/**
	 * @brief Decode one JSON string into caller-owned PMR storage.
	 *
	 * @param output Destination whose allocator determines ownership.
	 * @return true after exact decoding; false on syntax or UTF-8 failure.
	 * @throws std::bad_alloc when the supplied resource is exhausted.
	 */
	[[nodiscard]] bool read_string(std::pmr::string *output);

	/** @return true after validating and discarding one string without allocation; false on failure. */
	[[nodiscard]] bool discard_string() noexcept;
	/**
	 * @brief Read one signed integer with overflow and grammar checks.
	 * @param output Destination written only after successful conversion.
	 * @return true for one valid int64_t value; false on invalid input or cancellation.
	 */
	[[nodiscard]] bool read_int64(int64_t *output) noexcept;
	/**
	 * @brief Read one unsigned integer with overflow and grammar checks.
	 * @param output Destination written only after successful conversion.
	 * @return true for one nonnegative uint64_t value; false on invalid input or cancellation.
	 */
	[[nodiscard]] bool read_uint64(uint64_t *output) noexcept;
	/**
	 * @brief Read one exact JSON boolean.
	 * @param output Destination for the parsed value, which may be written before cancellation is observed.
	 * @return true for a complete boolean with no cancellation; false otherwise.
	 */
	[[nodiscard]] bool read_bool(bool *output) noexcept;

	/**
	 * @brief Require only trailing whitespace after the root value.
	 *
	 * @return OK, INVALID, or CANCELLED for the complete parse.
	 */
	[[nodiscard]] compile_result finish() noexcept;

	/** @return Current parse status, without consuming input or checking trailing bytes. */
	[[nodiscard]] compile_result result() const noexcept;

    private:
	/** Number of consumed bytes between cooperative cancellation probes. */
	static constexpr std::size_t CANCELLATION_POLL_BYTES = 1024;

	/** @return true while no syntax failure or cancellation has been recorded. */
	[[nodiscard]] bool healthy_() const noexcept;
	/** @brief Preserve the first terminal failure as INVALID. */
	void invalidate_() noexcept;
	/** @return true while parsing remains healthy, probing cancellation when its byte interval is due. */
	[[nodiscard]] bool poll_cancellation_() noexcept;
	/** @brief Consume RFC-8259 whitespace and poll cancellation. */
	void skip_whitespace_() noexcept;
	/**
	 * @brief Consume one expected structural token after whitespace.
	 * @param expected Required ASCII token.
	 * @return true after consuming it with no cancellation; false on mismatch, exhaustion, or cancellation.
	 */
	[[nodiscard]] bool consume_(char expected) noexcept;
	/**
	 * @brief Decode four hexadecimal digits into one UTF-16 code unit.
	 * @param code_point Destination for the decoded unit, which may be written before cancellation is observed.
	 * @return true after four valid digits with no cancellation; false otherwise.
	 */
	[[nodiscard]] bool consume_hex_quad_(uint32_t *code_point) noexcept;
	/**
	 * @brief Validate and copy one raw multibyte UTF-8 sequence.
	 * @param first Leading byte already consumed from the input.
	 * @param bytes Writable storage for up to four bytes; may be partially written on failure.
	 * @param count Destination for the validated sequence length, written before the final cancellation check.
	 * @return true for one valid Unicode scalar with no cancellation; false otherwise.
	 */
	[[nodiscard]] bool consume_utf8_sequence_(uint8_t first, uint8_t *bytes, std::size_t *count) noexcept;

	/**
	 * @brief Decode one string by invoking a caller-supplied byte appender.
	 * @tparam append_type Callable accepting a decoded byte and returning whether it was accepted.
	 * @param append Borrowed appender; prior accepted bytes remain written if parsing later fails.
	 * @return true after the closing quote with no cancellation; false on parse or appender rejection.
	 * @throws Any exception raised by the appender.
	 */
	template <typename append_type>
	[[nodiscard]] bool read_string_impl_(append_type &&append);

	/**
	 * @brief Parse sign and unsigned magnitude under the integer-only grammar.
	 * @param negative Receives the sign before magnitude validation completes.
	 * @param magnitude Receives the bounded magnitude only after successful parsing.
	 * @return true after parsing the magnitude; false on syntax, overflow, or cancellation.
	 *         The caller validates the following structural delimiter.
	 */
	[[nodiscard]] bool read_integer_magnitude_(bool *negative, uint64_t *magnitude) noexcept;

	const uint8_t *data_{nullptr};		     ///< Exact immutable input bytes.
	std::size_t size_{0};			     ///< Exact input extent.
	std::size_t position_{0};		     ///< Next unread byte offset.
	std::size_t next_cancellation_poll_{0};	     ///< Offset that triggers the next probe.
	cancellation_probe cancellation_{};	     ///< Borrowed cooperative cancellation authority.
	compile_result result_{compile_result::OK};  ///< First terminal parser result.
};

}  // namespace kinetum::modules::config
