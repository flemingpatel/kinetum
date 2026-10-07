// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_status.cpp
 * @brief Exact common status and status-or invariant tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

#include <cstdint>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace kinetum::common
{
namespace
{

static_assert(static_cast<int32_t>(status_code::POOL_EXHAUSTED) == 102);
static_assert(static_cast<int32_t>(status_code::MODULE_ERROR) == 104);
static_assert(!std::is_copy_assignable_v<status_or<int>>);
static_assert(!std::is_move_assignable_v<status_or<int>>);
static_assert(std::is_nothrow_constructible_v<status, status_code, static_status_text>);
static_assert(std::is_nothrow_move_constructible_v<status>);
static_assert(std::is_nothrow_move_assignable_v<status>);

/** @brief Observe successful value transfers and live instances. */
struct result_value_counts {
	uint32_t copies{0};	  ///< Completed copy constructions.
	uint32_t moves{0};	  ///< Completed move constructions.
	uint32_t live{0};	  ///< Currently owned value instances.
	bool reject_copy{false};  ///< Make the value's copy constructor throw before ownership.
};

/** @brief Aligned value with observable copy, move, and destruction effects. */
struct alignas(64) observed_result_value {
	result_value_counts &counts;  ///< Observations outliving every value instance.
	int number;		      ///< Independently copied or transferred payload.

	/**
	 * @brief Construct one source value owned by the test.
	 * @param observations Borrowed counters retained through every copy/move/destruction.
	 * @param value Observable payload for the new instance.
	 */
	observed_result_value(result_value_counts &observations, int value) noexcept
		: counts(observations)
		, number(value)
	{
		++counts.live;
	}

	/**
	 * @brief Copy one value or throw before a new instance becomes live.
	 * @param other Source supplying the shared counters and copied payload.
	 */
	observed_result_value(const observed_result_value &other)
		: counts(other.counts)
		, number(other.number)
	{
		if (counts.reject_copy) {
			throw std::bad_alloc();
		}
		++counts.copies;
		++counts.live;
	}

	/**
	 * @brief Transfer the payload and leave one observable moved-from source.
	 * @param other Source whose payload is transferred and replaced by the moved-from sentinel.
	 */
	observed_result_value(observed_result_value &&other) noexcept
		: counts(other.counts)
		, number(std::exchange(other.number, -1))
	{
		++counts.moves;
		++counts.live;
	}

	/** @brief Retire exactly one successfully constructed value. */
	~observed_result_value()
	{
		--counts.live;
	}
};

static_assert(!std::is_nothrow_constructible_v<status_or<observed_result_value>, const observed_result_value &>);
static_assert(std::is_nothrow_constructible_v<status_or<observed_result_value>, observed_result_value &&>);

/** @brief Prove direct value ownership, alignment, and copy-failure cleanup. */
TEST(status_or, value_construction_copies_or_moves_directly_into_owned_storage)
{
	result_value_counts counts;
	{
		observed_result_value source(counts, 17);
		status_or<observed_result_value> copied(source);
		ASSERT_TRUE(copied.is_ok());
		EXPECT_EQ(counts.copies, 1u);
		EXPECT_EQ(counts.moves, 0u);
		EXPECT_EQ(counts.live, 2u);
		EXPECT_EQ(copied->number, 17);
		EXPECT_EQ(reinterpret_cast<uintptr_t>(&copied.value()) % alignof(observed_result_value), 0u);

		source.number = 29;
		EXPECT_EQ(copied->number, 17);
		counts.reject_copy = true;
		EXPECT_THROW((void)status_or<observed_result_value>(source), std::bad_alloc);
		EXPECT_EQ(source.number, 29);
		EXPECT_EQ(counts.copies, 1u);
		EXPECT_EQ(counts.moves, 0u);
		EXPECT_EQ(counts.live, 2u);

		status_or<observed_result_value> moved(std::move(source));
		ASSERT_TRUE(moved.is_ok());
		EXPECT_EQ(source.number, -1);
		EXPECT_EQ(moved->number, 29);
		EXPECT_EQ(counts.copies, 1u);
		EXPECT_EQ(counts.moves, 1u);
		EXPECT_EQ(counts.live, 3u);
		EXPECT_EQ(reinterpret_cast<uintptr_t>(&moved.value()) % alignof(observed_result_value), 0u);
	}
	EXPECT_EQ(counts.live, 0u);

	auto pointer = std::make_unique<int>(41);
	const int *identity = pointer.get();
	status_or<std::unique_ptr<int>> owned(std::move(pointer));
	ASSERT_TRUE(owned.is_ok());
	EXPECT_EQ(pointer, nullptr);
	EXPECT_EQ(owned.value().get(), identity);
	EXPECT_EQ(*owned.value(), 41);
}

/** @brief Prove static and owned diagnostics retain one exact observable contract. */
TEST(status, static_and_owned_diagnostics_copy_move_and_replace_exactly)
{
	status static_value(status_code::FAILED_PRECONDITION, static_status_text("static message"),
			    static_status_text("static details"));
	EXPECT_EQ(static_value.message(), "static message");
	EXPECT_EQ(static_value.details(), "static details");

	status static_copy(static_value);
	EXPECT_EQ(static_copy.code(), status_code::FAILED_PRECONDITION);
	EXPECT_EQ(static_copy.message(), "static message");
	EXPECT_EQ(static_copy.details(), "static details");

	status owned_value(status_code::DATA_LOSS, std::string("owned message"), std::string("owned details"));
	status assigned = status::ok();
	assigned = owned_value;
	EXPECT_EQ(assigned.code(), status_code::DATA_LOSS);
	EXPECT_EQ(assigned.message(), "owned message");
	EXPECT_EQ(assigned.details(), "owned details");

	status moved(std::move(assigned));
	EXPECT_EQ(moved.message(), "owned message");
	EXPECT_EQ(moved.details(), "owned details");
	moved.set_details("replacement details");
	EXPECT_EQ(moved.message(), "owned message");
	EXPECT_EQ(moved.details(), "replacement details");

	status reclassified = std::move(moved).reclassified(status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(reclassified.code(), status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(reclassified.message(), "owned message");
	EXPECT_EQ(reclassified.details(), "replacement details");
}

/** @brief Prove contradictory construction and alternative access fail stop. */
TEST(status_or, contradictory_construction_and_access_fail_stop)
{
	EXPECT_DEATH(
		{
			status invalid(status_code::OK, static_status_text("success residue"));
			static_cast<void>(invalid);
		},
		"");
	EXPECT_DEATH(
		{
			status invalid = status::ok();
			invalid.set_details("success residue");
		},
		"");
	EXPECT_DEATH(
		{
			status_or<int> invalid(status::ok());
			static_cast<void>(invalid);
		},
		"");
	EXPECT_DEATH(
		{
			status_or<int> failure(status::invalid_argument("expected failure"));
			static_cast<void>(failure.value());
		},
		"");
	EXPECT_DEATH(
		{
			status_or<int> success(7);
			static_cast<void>(success.error());
		},
		"");
	EXPECT_DEATH(
		{
			status success = status::ok();
			static_cast<void>(std::move(success).reclassified(status_code::DATA_LOSS));
		},
		"");
	EXPECT_DEATH(
		{
			status failure(status_code::DATA_LOSS, static_status_text("failure"));
			static_cast<void>(std::move(failure).reclassified(status_code::OK));
		},
		"");
}

}  // namespace
}  // namespace kinetum::common
