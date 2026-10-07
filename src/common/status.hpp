// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file status.hpp
 * @brief Status type for error handling.
 * @author Fleming Patel
 *
 * Provides an explicit error handling mechanism that:
 * - Avoids exceptions in the hot path
 * - Is compatible with gRPC status codes
 *
 * Usage:
 *   status ok_status = status::ok();
 *   status err = status(status_code::NOT_FOUND,
 *                       static_status_text("item not found"));
 *   if (!err.is_ok()) { handle_error(err); }
 *
 * Thread-safety: Fully constructed status objects are safe to read from
 * multiple threads. Mutation while another thread reads the same instance is
 * forbidden.
 */

#include <cstddef>
#include <cstdint>
#include <exception>
#include <ostream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace kinetum::common
{

// =============================================================================
// Status Codes (aligned with gRPC canonical codes)
// =============================================================================

/**
 * @brief Error codes aligned with gRPC canonical status codes.
 *
 * These provide consistent error semantics across the platform and retain the
 * canonical gRPC integer mapping for transport translation.
 */
enum class status_code : int32_t {
	OK = 0,			  ///< Success
	CANCELLED = 1,		  ///< Operation was cancelled
	UNKNOWN = 2,		  ///< Unknown error
	INVALID_ARGUMENT = 3,	  ///< Client specified an invalid argument
	DEADLINE_EXCEEDED = 4,	  ///< Deadline expired before completion
	NOT_FOUND = 5,		  ///< Requested entity was not found
	ALREADY_EXISTS = 6,	  ///< Entity already exists
	PERMISSION_DENIED = 7,	  ///< Caller lacks permission
	RESOURCE_EXHAUSTED = 8,	  ///< Resource has been exhausted
	FAILED_PRECONDITION = 9,  ///< System not in required state
	ABORTED = 10,		  ///< Operation was aborted
	OUT_OF_RANGE = 11,	  ///< Value is out of valid range
	UNIMPLEMENTED = 12,	  ///< Operation is not implemented
	INTERNAL_ERROR = 13,	  ///< Internal error
	UNAVAILABLE = 14,	  ///< Service is unavailable
	DATA_LOSS = 15,		  ///< Unrecoverable data loss
	UNAUTHENTICATED = 16,	  ///< Request lacks valid authentication

	// Kinetum-specific extended codes (100+)
	POOL_EXHAUSTED = 102,  ///< Resource pool exhausted (e.g., NAT ports)
	MODULE_ERROR = 104,    ///< Module loading or execution error
};

/**
 * @brief Convert status code to string representation.
 * @param code Declared platform status code.
 * @return Stable uppercase name, or `UNKNOWN` for an undeclared value.
 */
[[nodiscard]] constexpr const char *status_code_name(status_code code) noexcept
{
	switch (code) {
	case status_code::OK:
		return "OK";
	case status_code::CANCELLED:
		return "CANCELLED";
	case status_code::UNKNOWN:
		return "UNKNOWN";
	case status_code::INVALID_ARGUMENT:
		return "INVALID_ARGUMENT";
	case status_code::DEADLINE_EXCEEDED:
		return "DEADLINE_EXCEEDED";
	case status_code::NOT_FOUND:
		return "NOT_FOUND";
	case status_code::ALREADY_EXISTS:
		return "ALREADY_EXISTS";
	case status_code::PERMISSION_DENIED:
		return "PERMISSION_DENIED";
	case status_code::RESOURCE_EXHAUSTED:
		return "RESOURCE_EXHAUSTED";
	case status_code::FAILED_PRECONDITION:
		return "FAILED_PRECONDITION";
	case status_code::ABORTED:
		return "ABORTED";
	case status_code::OUT_OF_RANGE:
		return "OUT_OF_RANGE";
	case status_code::UNIMPLEMENTED:
		return "UNIMPLEMENTED";
	case status_code::INTERNAL_ERROR:
		return "INTERNAL_ERROR";
	case status_code::UNAVAILABLE:
		return "UNAVAILABLE";
	case status_code::DATA_LOSS:
		return "DATA_LOSS";
	case status_code::UNAUTHENTICATED:
		return "UNAUTHENTICATED";
	case status_code::POOL_EXHAUSTED:
		return "POOL_EXHAUSTED";
	case status_code::MODULE_ERROR:
		return "MODULE_ERROR";
	}
	return "UNKNOWN";
}

// =============================================================================
// Status Class
// =============================================================================

/**
 * @brief Prove static lifetime for one allocation-free status diagnostic.
 *
 * Construction is immediate: only text whose address is a constant expression
 * can initialize this type. A string literal or static character array is
 * therefore admissible, while an automatic array is rejected at compile time.
 * Runtime text must enter `status` through an owning `std::string` overload.
 */
class static_status_text final {
    public:
	/**
	 * @brief Bind one statically stored character array.
	 * @tparam extent Complete array extent.
	 * @param value Static diagnostic bytes.
	 */
	template <std::size_t extent>
	consteval explicit static_status_text(const char (&value)[extent]) noexcept
		: value_(value, literal_length_(value))
	{
	}

	/** @return Borrowed static diagnostic bytes before the first null or array end. */
	[[nodiscard]] constexpr std::string_view view() const noexcept
	{
		return value_;
	}

    private:
	/**
	 * @brief Return the prior C-string length without invoking a runtime library.
	 * @tparam extent Complete static array extent.
	 * @param value Static diagnostic bytes.
	 * @return Byte count before the first null or the complete array extent.
	 */
	template <std::size_t extent>
	[[nodiscard]] static consteval std::size_t literal_length_(const char (&value)[extent]) noexcept
	{
		std::size_t length = 0;
		while (length < extent && value[length] != '\0') {
			++length;
		}
		return length;
	}

	std::string_view value_;  ///< Static-lifetime text view.
};

/**
 * @brief Represents the outcome of an operation.
 *
 * Status is the primary error handling mechanism in Kinetum. It provides:
 * - Rich error codes aligned with gRPC
 * - Human-readable error messages
 * - Optional supplemental diagnostic text
 *
 * Typed status and response fields select behavior. Callers may display or
 * retain diagnostic text but must never parse it as retry or policy authority.
 * Default construction is the sole OK representation; diagnostic constructors
 * and detail mutation require a non-OK code.
 *
 * Thread-safety: Fully constructed objects are safe for concurrent reads.
 * Callers attach details before publication and never mutate a shared status.
 */
class status {
    private:
	/** Allocation-free diagnostic pair backed only by static storage. */
	struct static_diagnostics {
		std::string_view message;  ///< Static human-readable diagnostic.
		std::string_view details;  ///< Static supplemental context.
	};

	/** Owned diagnostic pair for runtime-composed text. */
	struct owned_diagnostics {
		std::string message;  ///< Owned human-readable diagnostic.
		std::string details;  ///< Owned supplemental context.

		/**
		 * @brief Construct by nonthrowing ownership transfer from complete strings.
		 * @param message_value Complete message ownership.
		 * @param details_value Complete details ownership.
		 */
		owned_diagnostics(std::string message_value, std::string details_value) noexcept
			: message(std::move(message_value))
			, details(std::move(details_value))
		{
		}
	};

	/** @brief Sole static-or-owned representation for one complete diagnostic pair. */
	using diagnostic_storage = std::variant<static_diagnostics, owned_diagnostics>;

    public:
	// ---------------------------------------------------------------------------
	// Constructors
	// ---------------------------------------------------------------------------

	/** Construct an OK status. */
	status() noexcept
		: code_(status_code::OK)
		, diagnostics_(std::in_place_type<static_diagnostics>, std::string_view{}, std::string_view{})
	{
	}

	/**
	 * @brief Construct a status with allocation-free static diagnostic text.
	 * @param code Non-OK outcome category.
	 * @param message Compile-time-proven static diagnostic.
	 */
	status(status_code code, static_status_text message) noexcept
		: code_(code)
		, diagnostics_(std::in_place_type<static_diagnostics>, message.view(), std::string_view{})
	{
		if (code_ == status_code::OK) {
			std::terminate();
		}
	}

	/**
	 * @brief Construct a status with allocation-free static message and details.
	 * @param code Non-OK outcome category.
	 * @param message Compile-time-proven static diagnostic.
	 * @param details Compile-time-proven static supplemental context.
	 */
	status(status_code code, static_status_text message, static_status_text details) noexcept
		: code_(code)
		, diagnostics_(std::in_place_type<static_diagnostics>, message.view(), details.view())
	{
		if (code_ == status_code::OK) {
			std::terminate();
		}
	}

	/**
	 * @brief Construct a status with code and message.
	 * @param code Non-OK outcome category.
	 * @param message Human-readable diagnostic.
	 */
	status(status_code code, std::string message) noexcept
		: code_(code)
		, diagnostics_(std::in_place_type<owned_diagnostics>, std::move(message), std::string{})
	{
		if (code_ == status_code::OK) {
			std::terminate();
		}
	}

	/**
	 * @brief Construct a status with code, message, and details.
	 * @param code Non-OK outcome category.
	 * @param message Human-readable diagnostic.
	 * @param details Supplemental human-readable operation context.
	 */
	status(status_code code, std::string message, std::string details) noexcept
		: code_(code)
		, diagnostics_(std::in_place_type<owned_diagnostics>, std::move(message), std::move(details))
	{
		if (code_ == status_code::OK) {
			std::terminate();
		}
	}

	/** @brief Copy one complete status; owned diagnostics may allocate. */
	status(const status &) = default;

	/** @brief Move one complete status without allocation. */
	status(status &&) noexcept = default;

	/**
	 * @brief Replace this status transactionally.
	 *
	 * Copy construction of @p other completes before entry. The body then swaps
	 * complete states without throwing, so allocation failure cannot partially
	 * replace code, message, or details.
	 *
	 * @param other Complete replacement status.
	 * @return This replaced status.
	 */
	status &operator=(status other) noexcept
	{
		swap(other);
		return *this;
	}

	/**
	 * @brief Exchange two complete statuses without allocation.
	 * @param other Status receiving this complete state.
	 */
	void swap(status &other) noexcept
	{
		using std::swap;
		swap(code_, other.code_);
		diagnostics_.swap(other.diagnostics_);
	}

	// ---------------------------------------------------------------------------
	// Factory Methods
	// ---------------------------------------------------------------------------

	/** @return One empty OK status. */
	[[nodiscard]] static status ok() noexcept
	{
		return status();
	}

	/**
	 * @return CANCELLED status carrying the fixed `cancelled` diagnostic.
	 */
	[[nodiscard]] static status cancelled() noexcept
	{
		return status(status_code::CANCELLED, static_status_text("cancelled"));
	}

	/**
	 * @param message Static cancellation diagnostic.
	 * @return CANCELLED status borrowing @p message.
	 */
	[[nodiscard]] static status cancelled(static_status_text message) noexcept
	{
		return status(status_code::CANCELLED, message);
	}

	/**
	 * @param message Human-readable cancellation diagnostic.
	 * @return CANCELLED status owning @p message.
	 */
	[[nodiscard]] static status cancelled(std::string message)
	{
		return status(status_code::CANCELLED, std::move(message));
	}

	/**
	 * @param message Human-readable input diagnostic.
	 * @return INVALID_ARGUMENT status carrying @p message.
	 */
	[[nodiscard]] static status invalid_argument(std::string message)
	{
		return status(status_code::INVALID_ARGUMENT, std::move(message));
	}

	/**
	 * @param message Static input diagnostic.
	 * @return INVALID_ARGUMENT status borrowing @p message.
	 */
	[[nodiscard]] static status invalid_argument(static_status_text message) noexcept
	{
		return status(status_code::INVALID_ARGUMENT, message);
	}

	/**
	 * @param message Human-readable lookup diagnostic.
	 * @return NOT_FOUND status carrying @p message.
	 */
	[[nodiscard]] static status not_found(std::string message)
	{
		return status(status_code::NOT_FOUND, std::move(message));
	}

	/**
	 * @param message Static lookup diagnostic.
	 * @return NOT_FOUND status borrowing @p message.
	 */
	[[nodiscard]] static status not_found(static_status_text message) noexcept
	{
		return status(status_code::NOT_FOUND, message);
	}

	/**
	 * @param message Human-readable conflict diagnostic.
	 * @return ALREADY_EXISTS status carrying @p message.
	 */
	[[nodiscard]] static status already_exists(std::string message)
	{
		return status(status_code::ALREADY_EXISTS, std::move(message));
	}

	/**
	 * @param message Static conflict diagnostic.
	 * @return ALREADY_EXISTS status borrowing @p message.
	 */
	[[nodiscard]] static status already_exists(static_status_text message) noexcept
	{
		return status(status_code::ALREADY_EXISTS, message);
	}

	/**
	 * @param message Human-readable permission diagnostic.
	 * @return PERMISSION_DENIED status carrying @p message.
	 */
	[[nodiscard]] static status permission_denied(std::string message)
	{
		return status(status_code::PERMISSION_DENIED, std::move(message));
	}

	/**
	 * @param message Static permission diagnostic.
	 * @return PERMISSION_DENIED status borrowing @p message.
	 */
	[[nodiscard]] static status permission_denied(static_status_text message) noexcept
	{
		return status(status_code::PERMISSION_DENIED, message);
	}

	/**
	 * @param message Human-readable resource diagnostic.
	 * @return RESOURCE_EXHAUSTED status carrying @p message.
	 */
	[[nodiscard]] static status resource_exhausted(std::string message)
	{
		return status(status_code::RESOURCE_EXHAUSTED, std::move(message));
	}

	/**
	 * @param message Static resource diagnostic.
	 * @return RESOURCE_EXHAUSTED status borrowing @p message.
	 */
	[[nodiscard]] static status resource_exhausted(static_status_text message) noexcept
	{
		return status(status_code::RESOURCE_EXHAUSTED, message);
	}

	/**
	 * @param message Human-readable state diagnostic.
	 * @return FAILED_PRECONDITION status carrying @p message.
	 */
	[[nodiscard]] static status failed_precondition(std::string message)
	{
		return status(status_code::FAILED_PRECONDITION, std::move(message));
	}

	/**
	 * @param message Static state diagnostic.
	 * @return FAILED_PRECONDITION status borrowing @p message.
	 */
	[[nodiscard]] static status failed_precondition(static_status_text message) noexcept
	{
		return status(status_code::FAILED_PRECONDITION, message);
	}

	/**
	 * @param message Human-readable internal diagnostic.
	 * @return INTERNAL_ERROR status carrying @p message.
	 */
	[[nodiscard]] static status internal_error(std::string message)
	{
		return status(status_code::INTERNAL_ERROR, std::move(message));
	}

	/**
	 * @param message Static internal diagnostic.
	 * @return INTERNAL_ERROR status borrowing @p message.
	 */
	[[nodiscard]] static status internal_error(static_status_text message) noexcept
	{
		return status(status_code::INTERNAL_ERROR, message);
	}

	/**
	 * @param message Human-readable availability diagnostic.
	 * @return UNAVAILABLE status carrying @p message.
	 */
	[[nodiscard]] static status unavailable(std::string message)
	{
		return status(status_code::UNAVAILABLE, std::move(message));
	}

	/**
	 * @param message Static availability diagnostic.
	 * @return UNAVAILABLE status borrowing @p message.
	 */
	[[nodiscard]] static status unavailable(static_status_text message) noexcept
	{
		return status(status_code::UNAVAILABLE, message);
	}

	/**
	 * @return UNIMPLEMENTED status carrying the fixed `not implemented` diagnostic.
	 */
	[[nodiscard]] static status unimplemented() noexcept
	{
		return status(status_code::UNIMPLEMENTED, static_status_text("not implemented"));
	}

	/**
	 * @param message Static capability diagnostic.
	 * @return UNIMPLEMENTED status borrowing @p message.
	 */
	[[nodiscard]] static status unimplemented(static_status_text message) noexcept
	{
		return status(status_code::UNIMPLEMENTED, message);
	}

	/**
	 * @param message Human-readable capability diagnostic.
	 * @return UNIMPLEMENTED status owning @p message.
	 */
	[[nodiscard]] static status unimplemented(std::string message)
	{
		return status(status_code::UNIMPLEMENTED, std::move(message));
	}

	/**
	 * @param message Human-readable integrity diagnostic.
	 * @return DATA_LOSS status carrying @p message.
	 */
	[[nodiscard]] static status data_loss(std::string message)
	{
		return status(status_code::DATA_LOSS, std::move(message));
	}

	/**
	 * @param message Static integrity diagnostic.
	 * @return DATA_LOSS status borrowing @p message.
	 */
	[[nodiscard]] static status data_loss(static_status_text message) noexcept
	{
		return status(status_code::DATA_LOSS, message);
	}

	/**
	 * @param message Human-readable authentication diagnostic.
	 * @return UNAUTHENTICATED status carrying @p message.
	 */
	[[nodiscard]] static status unauthenticated(std::string message)
	{
		return status(status_code::UNAUTHENTICATED, std::move(message));
	}

	/**
	 * @param message Static authentication diagnostic.
	 * @return UNAUTHENTICATED status borrowing @p message.
	 */
	[[nodiscard]] static status unauthenticated(static_status_text message) noexcept
	{
		return status(status_code::UNAUTHENTICATED, message);
	}

	/**
	 * @param message Human-readable abort diagnostic.
	 * @return ABORTED status carrying @p message.
	 */
	[[nodiscard]] static status aborted(std::string message)
	{
		return status(status_code::ABORTED, std::move(message));
	}

	/**
	 * @param message Static abort diagnostic.
	 * @return ABORTED status borrowing @p message.
	 */
	[[nodiscard]] static status aborted(static_status_text message) noexcept
	{
		return status(status_code::ABORTED, message);
	}

	/**
	 * @param message Human-readable deadline diagnostic.
	 * @return DEADLINE_EXCEEDED status carrying @p message.
	 */
	[[nodiscard]] static status deadline_exceeded(std::string message)
	{
		return status(status_code::DEADLINE_EXCEEDED, std::move(message));
	}

	/**
	 * @param message Static deadline diagnostic.
	 * @return DEADLINE_EXCEEDED status borrowing @p message.
	 */
	[[nodiscard]] static status deadline_exceeded(static_status_text message) noexcept
	{
		return status(status_code::DEADLINE_EXCEEDED, message);
	}

	// ---------------------------------------------------------------------------
	// Accessors
	// ---------------------------------------------------------------------------

	/** @return true exactly when the status code is OK. */
	[[nodiscard]] bool is_ok() const noexcept
	{
		return code_ == status_code::OK;
	}

	/** @return true exactly when the status code is non-OK. */
	[[nodiscard]] bool is_error() const noexcept
	{
		return code_ != status_code::OK;
	}

	/** @return Exact outcome category. */
	[[nodiscard]] status_code code() const noexcept
	{
		return code_;
	}

	/** @return Human-readable diagnostic borrowed for this status's lifetime. */
	[[nodiscard]] std::string_view message() const noexcept
	{
		if (const auto *diagnostics = std::get_if<static_diagnostics>(&diagnostics_); diagnostics != nullptr) {
			return diagnostics->message;
		}
		const auto *diagnostics = std::get_if<owned_diagnostics>(&diagnostics_);
		if (diagnostics == nullptr) {
			std::terminate();
		}
		return diagnostics->message;
	}

	/** @return Supplemental details borrowed for this status's lifetime. */
	[[nodiscard]] std::string_view details() const noexcept
	{
		if (const auto *diagnostics = std::get_if<static_diagnostics>(&diagnostics_); diagnostics != nullptr) {
			return diagnostics->details;
		}
		const auto *diagnostics = std::get_if<owned_diagnostics>(&diagnostics_);
		if (diagnostics == nullptr) {
			std::terminate();
		}
		return diagnostics->details;
	}

	// ---------------------------------------------------------------------------
	// Mutation (for building errors)
	// ---------------------------------------------------------------------------

	/**
	 * @brief Attach supplemental diagnostics to one non-OK status before publication.
	 * @param details Human-readable operation context.
	 * @return This updated status.
	 */
	status &set_details(std::string details)
	{
		if (is_ok()) {
			std::terminate();
		}
		status replacement(code_, std::string(message()), std::move(details));
		swap(replacement);
		return *this;
	}

	/**
	 * @brief Move this failure under another non-OK code without copying text.
	 *
	 * This is the allocation-free boundary for a caller that must preserve exact
	 * owned diagnostics while mapping one typed failure category to another.
	 * Successful input or an OK replacement code is a contract violation.
	 *
	 * @param code Replacement non-OK category.
	 * @return This complete status by move with diagnostics unchanged.
	 */
	[[nodiscard]] status reclassified(status_code code) && noexcept
	{
		if (is_ok() || code == status_code::OK) {
			std::terminate();
		}
		code_ = code;
		return std::move(*this);
	}

	// ---------------------------------------------------------------------------
	// String Conversion
	// ---------------------------------------------------------------------------

	/** @return Human-readable code, message, and optional details. */
	[[nodiscard]] std::string to_string() const
	{
		if (is_ok())
			return "OK";
		std::string result = status_code_name(code_);
		result += ": ";
		result.append(message());
		if (!details().empty()) {
			result += " [";
			result.append(details());
			result += "]";
		}
		return result;
	}

	/** Stream output operator. */
	friend std::ostream &operator<<(std::ostream &os, const status &s)
	{
		return os << s.to_string();
	}

    private:
	status_code code_;		  ///< Exact outcome category.
	diagnostic_storage diagnostics_;  ///< Sole complete diagnostic representation.
};

static_assert(std::is_nothrow_move_constructible_v<status>);
static_assert(std::is_nothrow_move_assignable_v<status>);
static_assert(std::is_nothrow_swappable_v<status>);

}  // namespace kinetum::common
