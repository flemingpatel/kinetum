// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file status_or.hpp
 * @brief Exact value-or-error result for C++20.
 * @author Fleming Patel
 *
 * `status_or<T>` stores either one `T` or one non-OK `status`. The variant
 * alternative is the sole state authority and is fixed at construction;
 * assignment is unavailable so a live result cannot become valueless by an
 * exception while replacing that alternative. Constructing an error
 * alternative from OK or accessing the wrong alternative terminates in every
 * build.
 */

#include <exception>
#include <type_traits>
#include <utility>
#include <variant>

#include "src/common/status.hpp"

namespace kinetum::common
{

/**
 * @brief Hold exactly one value or one non-OK status.
 *
 * The result owns its stored `T` object. Pointer and view payloads retain
 * `T`'s ownership and lifetime rules for the referenced data.
 *
 * @tparam T Move-constructible object type distinct from `status`.
 */
template <typename T>
class status_or {
	static_assert(!std::is_same_v<T, status>, "T cannot be status");
	static_assert(std::is_move_constructible_v<T>, "T must be move-constructible");

    public:
	using value_type = T;  ///< Stored success type.

	/**
	 * @brief Construct the error alternative.
	 * @param error Non-OK status to own.
	 */
	status_or(status error) noexcept(std::is_nothrow_move_constructible_v<status>)
		: value_(std::move(error))
	{
		const status *stored_error = std::get_if<status>(&value_);
		if (stored_error == nullptr || stored_error->is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Copy a borrowed value directly into the success alternative.
	 * @param value Source object borrowed for this call.
	 * @par Exceptions
	 * Propagates exceptions from `T`'s copy constructor.
	 */
	status_or(const T &value) noexcept(std::is_nothrow_copy_constructible_v<T>)
		requires std::is_copy_constructible_v<T>
		: value_(std::in_place_type<T>, value)
	{
	}

	/**
	 * @brief Move a value directly into the success alternative.
	 * @param value Source whose value is moved into this result.
	 * @par Exceptions
	 * Propagates exceptions from `T`'s move constructor.
	 */
	status_or(T &&value) noexcept(std::is_nothrow_move_constructible_v<T>)
		: value_(std::in_place_type<T>, std::move(value))
	{
	}

	/**
	 * @brief Construct the success alternative in place.
	 * @tparam Args Constructor argument types for `T`.
	 * @param args Arguments forwarded to `T`.
	 */
	template <typename... Args>
	explicit status_or(std::in_place_t, Args &&...args)
		: value_(std::in_place_type<T>, std::forward<Args>(args)...)
	{
	}

	/**
	 * @brief Copy one complete result.
	 * @param other Result to copy.
	 */
	status_or(const status_or &other) = default;

	/**
	 * @brief Move one complete result.
	 * @param other Result to move.
	 */
	status_or(status_or &&other) noexcept(std::is_nothrow_move_constructible_v<T> &&
					      std::is_nothrow_move_constructible_v<status>) = default;

	/** @brief Result alternatives are fixed and cannot be copy-assigned. */
	status_or &operator=(const status_or &) = delete;

	/** @brief Result alternatives are fixed and cannot be move-assigned. */
	status_or &operator=(status_or &&) = delete;

	/** @return true exactly when the success alternative is active. */
	[[nodiscard]] bool is_ok() const noexcept
	{
		return std::holds_alternative<T>(value_);
	}

	/** @return Borrowed error status; terminates when this result is successful. */
	[[nodiscard]] const status &error() const & noexcept
	{
		const status *error = std::get_if<status>(&value_);
		if (error == nullptr) {
			std::terminate();
		}
		return *error;
	}

	/** @return Moved error status; terminates when this result is successful. */
	[[nodiscard]] status &&error() && noexcept
	{
		status *error = std::get_if<status>(&value_);
		if (error == nullptr) {
			std::terminate();
		}
		return std::move(*error);
	}

	/** @return Borrowed value; terminates when this result contains an error. */
	[[nodiscard]] T &value() & noexcept
	{
		T *value = std::get_if<T>(&value_);
		if (value == nullptr) {
			std::terminate();
		}
		return *value;
	}

	/** @return Const borrowed value; terminates when this result contains an error. */
	[[nodiscard]] const T &value() const & noexcept
	{
		const T *value = std::get_if<T>(&value_);
		if (value == nullptr) {
			std::terminate();
		}
		return *value;
	}

	/** @return Moved value; terminates when this result contains an error. */
	[[nodiscard]] T &&value() && noexcept
	{
		T *value = std::get_if<T>(&value_);
		if (value == nullptr) {
			std::terminate();
		}
		return std::move(*value);
	}

	/** @return Pointer to the value; terminates when this result contains an error. */
	[[nodiscard]] T *operator->() noexcept
	{
		return &value();
	}

	/** @return Const pointer to the value; terminates when this result contains an error. */
	[[nodiscard]] const T *operator->() const noexcept
	{
		return &value();
	}

	/** @return Borrowed value; terminates when this result contains an error. */
	[[nodiscard]] T &operator*() & noexcept
	{
		return value();
	}

	/** @return Const borrowed value; terminates when this result contains an error. */
	[[nodiscard]] const T &operator*() const & noexcept
	{
		return value();
	}

    private:
	std::variant<status, T> value_;	 ///< Sole success/error state and payload.
};

}  // namespace kinetum::common
