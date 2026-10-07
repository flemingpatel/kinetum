// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_common_schema.cpp
 * @brief Exact common application-status wire-schema tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <utility>

#include "gen/kinetum/common/v1/common.pb.h"
#include "src/common/protobuf_contract.hpp"

namespace kinetum::common
{
namespace
{

/** @brief Status carries only its four consumed outcome fields. */
TEST(common_schema, status_fields_are_compact_and_complete)
{
	const auto *status = kinetum::common::v1::Status::descriptor();
	ASSERT_NE(status, nullptr);
	ASSERT_EQ(status->field_count(), 4);
	constexpr std::array<std::pair<const char *, int>, 4> EXPECTED{{
		{"code", 1},
		{"error_code", 2},
		{"message", 3},
		{"details", 4},
	}};
	for (const auto &[name, number] : EXPECTED) {
		const auto *field = status->FindFieldByName(name);
		ASSERT_NE(field, nullptr) << name;
		EXPECT_EQ(field->number(), number) << name;
	}
	EXPECT_EQ(status->reserved_range_count(), 0);
	EXPECT_EQ(status->reserved_name_count(), 0);
}

/** @brief Removed common utility messages and old status residue stay absent. */
TEST(common_schema, removed_generic_surface_reaches_the_unknown_field_wall)
{
	const auto *file = kinetum::common::v1::Status::descriptor()->file();
	ASSERT_NE(file, nullptr);
	for (const char *name : {"ErrorCause", "Empty", "Timestamp", "Duration", "SemanticVersion",
				 "ResourceIdentifier", "PageToken", "PageInfo"}) {
		EXPECT_EQ(file->FindMessageTypeByName(name), nullptr) << name;
	}

	kinetum::common::v1::Status status;
	ASSERT_TRUE(status.ParseFromString(std::string("\x2a\x01x\x32\x00", 5u)));
	EXPECT_FALSE(reject_unknown_protobuf_fields_recursive(status, "Status").is_ok());
}

}  // namespace
}  // namespace kinetum::common
