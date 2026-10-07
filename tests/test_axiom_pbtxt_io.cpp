// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_axiom_pbtxt_io.cpp
 * @brief Exact protobuf-text admission tests for Axiom pipelines.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>

#include <unistd.h>

#include "src/axiom/axiom_pbtxt_io.hpp"
#include "src/common/status.hpp"

namespace kinetum::axiom
{
namespace
{

/** @brief One temporary protobuf-text source with scope-bound removal. */
class pbtxt_source_file {
    public:
	/**
	 * @brief Write one complete source document.
	 * @param contents Exact protobuf-text bytes.
	 */
	explicit pbtxt_source_file(std::string_view contents)
	{
		std::string pattern = (std::filesystem::temp_directory_path() / "kinetum_axiom_pbtxt.XXXXXX").string();
		const int descriptor = ::mkstemp(pattern.data());
		if (descriptor < 0) {
			return;
		}
		path_ = pattern;
		const char *next = contents.data();
		std::size_t remaining = contents.size();
		while (remaining != 0u) {
			const ssize_t written = ::write(descriptor, next, remaining);
			if (written < 0 && errno == EINTR) {
				continue;
			}
			if (written <= 0) {
				break;
			}
			const auto count = static_cast<std::size_t>(written);
			next += count;
			remaining -= count;
		}
		const int close_result = ::close(descriptor);
		valid_ = remaining == 0u && close_result == 0;
	}

	/** @brief Remove the exact temporary source path. */
	~pbtxt_source_file()
	{
		std::error_code error;
		(void)std::filesystem::remove(path_, error);
	}

	pbtxt_source_file(const pbtxt_source_file &) = delete;
	pbtxt_source_file &operator=(const pbtxt_source_file &) = delete;

	/** @return Exact temporary source path. */
	[[nodiscard]] const std::filesystem::path &path() const noexcept
	{
		return path_;
	}

	/** @return true when every source byte was written. */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_;
	}

    private:
	std::filesystem::path path_;  ///< Exact temporary source identity.
	bool valid_{};		      ///< Whether source publication completed.
};

/** @return One exact current two-stage Axiom source. */
constexpr std::string_view exact_pipeline_text() noexcept
{
	return R"pbtxt(
pipeline_id: "pbtxt_exact"
stages {
  stage_id: "rx"
  kind: STAGE_KIND_RX
  execution_mode: EXECUTION_MODE_PASSIVE
  io { interface: "wan0" }
}
stages {
  stage_id: "tx"
  kind: STAGE_KIND_TX
  execution_mode: EXECUTION_MODE_PASSIVE
  io { interface: "lan0" }
}
edges { from_stage_id: "rx" to_stage_id: "tx" mode: EDGE_MODE_PUSH }
)pbtxt";
}

/** @brief Exact typed source parses and validates without normalization. */
TEST(axiom_pbtxt_io, exact_typed_source_is_admitted_without_defaulting)
{
	pbtxt_source_file source(exact_pipeline_text());
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_pbtxt(source.path().string(), contract_options{});
	ASSERT_TRUE(pipeline_or.is_ok()) << pipeline_or.error().message();
	EXPECT_EQ(pipeline_or->SerializeAsString(), [&] {
		kinetum::axiom::v1::Pipeline expected;
		auto *rx = expected.add_stages();
		expected.set_pipeline_id("pbtxt_exact");
		rx->set_stage_id("rx");
		rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
		rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		rx->mutable_io()->set_interface("wan0");
		auto *tx = expected.add_stages();
		tx->set_stage_id("tx");
		tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
		tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		tx->mutable_io()->set_interface("lan0");
		auto *edge = expected.add_edges();
		edge->set_from_stage_id("rx");
		edge->set_to_stage_id("tx");
		edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
		return expected.SerializeAsString();
	}());
}

/** @brief Missing required execution mode fails instead of acquiring a default. */
TEST(axiom_pbtxt_io, missing_execution_mode_fails_exact_admission)
{
	std::string source_text(exact_pipeline_text());
	const std::string mode_line = "  execution_mode: EXECUTION_MODE_PASSIVE\n";
	const auto position = source_text.find(mode_line);
	ASSERT_NE(position, std::string::npos);
	source_text.erase(position, mode_line.size());
	pbtxt_source_file source(source_text);
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_pbtxt(source.path().string(), contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(pipeline_or.error().message().find("execution_mode"), std::string::npos);
}

/** @brief Removed free-form stage parameters fail during strict text parsing. */
TEST(axiom_pbtxt_io, removed_parameter_surface_is_not_a_compatibility_reader)
{
	std::string source_text(exact_pipeline_text());
	const auto insertion = source_text.find("  io { interface: \"wan0\" }");
	ASSERT_NE(insertion, std::string::npos);
	source_text.insert(insertion, "  params { key: \"interface\" value: \"wan0\" }\n");
	pbtxt_source_file source(source_text);
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_pbtxt(source.path().string(), contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief Removed enum names fail text parsing rather than acquiring new meaning. */
TEST(axiom_pbtxt_io, removed_stage_kind_name_fails_before_semantic_admission)
{
	std::string source_text(exact_pipeline_text());
	const std::string current_kind = "STAGE_KIND_RX";
	const auto position = source_text.find(current_kind);
	ASSERT_NE(position, std::string::npos);
	source_text.replace(position, current_kind.size(), "STAGE_KIND_PARSE_IPV6");
	pbtxt_source_file source(source_text);
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_pbtxt(source.path().string(), contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

}  // namespace
}  // namespace kinetum::axiom
