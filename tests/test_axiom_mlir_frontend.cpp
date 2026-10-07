// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_axiom_mlir_frontend.cpp
 * @brief Exact enabled and disabled Axiom MLIR frontend tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>

#include <unistd.h>

#include "src/axiom/axiom_mlir_frontend.hpp"
#include "src/common/status.hpp"

namespace kinetum::axiom
{
namespace
{

/** @brief Exact temporary MLIR source with scope-bound removal. */
class mlir_source_file {
    public:
	/**
	 * @brief Write one source document to a unique temporary path.
	 * @param contents Complete MLIR source bytes.
	 */
	explicit mlir_source_file(std::string_view contents)
	{
		std::string pattern = (std::filesystem::temp_directory_path() / "kinetum_axiom_mlir.XXXXXX").string();
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
	~mlir_source_file()
	{
		std::error_code error;
		(void)std::filesystem::remove(path_, error);
	}

	mlir_source_file(const mlir_source_file &) = delete;
	mlir_source_file &operator=(const mlir_source_file &) = delete;

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

#if KINETUM_ENABLE_MLIR

/** @brief The enabled frontend lowers exactly the declared passive subset. */
TEST(axiom_mlir_frontend, enabled_build_lowers_exact_supported_subset)
{
	constexpr std::string_view SOURCE = R"mlir(
module attributes {pipeline_id = "mlir_exact", allow_dag = false} {
  "axiom.core.stage"() {stage_id = "rx", kind = "RX", execution_mode = "PASSIVE", interface = "wan0"} : () -> ()
  "axiom.core.stage"() {stage_id = "parse", kind = "PARSE_IPV4", execution_mode = "PASSIVE"} : () -> ()
  "axiom.core.stage"() {stage_id = "acl", kind = "MODULE", execution_mode = "PASSIVE", module_id = "kinetum.acl", context_selection = "SAME_LANE"} : () -> ()
  "axiom.core.stage"() {stage_id = "tx", kind = "TX", execution_mode = "PASSIVE", interface = "lan0"} : () -> ()
  "axiom.core.edge"() {from = "rx", to = "parse", mode = "PUSH"} : () -> ()
  "axiom.core.edge"() {from = "parse", to = "acl", mode = "PUSH"} : () -> ()
  "axiom.core.edge"() {from = "acl", to = "tx", mode = "PUSH"} : () -> ()
}
)mlir";
	mlir_source_file source(SOURCE);
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_mlir(source.path().string(), contract_options{});
	ASSERT_TRUE(pipeline_or.is_ok()) << pipeline_or.error().message();
	EXPECT_EQ(pipeline_or->pipeline_id(), "mlir_exact");
	ASSERT_EQ(pipeline_or->stages_size(), 4);
	const auto find_stage = [&](std::string_view stage_id) -> const kinetum::axiom::v1::Stage * {
		for (const auto &stage : pipeline_or->stages()) {
			if (stage.stage_id() == stage_id) {
				return &stage;
			}
		}
		return nullptr;
	};
	const auto *rx = find_stage("rx");
	const auto *parse = find_stage("parse");
	const auto *acl = find_stage("acl");
	const auto *tx = find_stage("tx");
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(parse, nullptr);
	ASSERT_NE(acl, nullptr);
	ASSERT_NE(tx, nullptr);
	EXPECT_TRUE(rx->has_io());
	EXPECT_EQ(parse->kind(), kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	EXPECT_EQ(acl->module().context_selection(), kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	EXPECT_TRUE(tx->has_io());
	ASSERT_EQ(pipeline_or->edges_size(), 3);
	EXPECT_EQ(pipeline_or->edges(0).mode(), kinetum::axiom::v1::EDGE_MODE_PUSH);
}

/** @brief The enabled frontend enforces the shared exact source-byte ceiling. */
TEST(axiom_mlir_frontend, enabled_build_reads_only_bounded_complete_source)
{
	constexpr std::string_view SOURCE = R"mlir(
module attributes {pipeline_id = "mlir_bound", allow_dag = false} {
  "axiom.core.stage"() {stage_id = "rx", kind = "RX", execution_mode = "PASSIVE", interface = "wan0"} : () -> ()
  "axiom.core.stage"() {stage_id = "tx", kind = "TX", execution_mode = "PASSIVE", interface = "lan0"} : () -> ()
  "axiom.core.edge"() {from = "rx", to = "tx", mode = "PUSH"} : () -> ()
}
)mlir";
	std::string exact_source(SOURCE);
	ASSERT_LT(exact_source.size(), MAX_PIPELINE_SOURCE_BYTES);
	exact_source.resize(MAX_PIPELINE_SOURCE_BYTES, ' ');
	{
		mlir_source_file exact(exact_source);
		ASSERT_TRUE(exact.valid());
		auto pipeline_or = load_pipeline_mlir(exact.path().string(), contract_options{});
		ASSERT_TRUE(pipeline_or.is_ok()) << pipeline_or.error().message();
	}

	exact_source.push_back(' ');
	mlir_source_file oversized(exact_source);
	ASSERT_TRUE(oversized.valid());
	auto pipeline_or = load_pipeline_mlir(oversized.path().string(), contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
}

/** @brief The enabled frontend rejects every foreign stage attribute. */
TEST(axiom_mlir_frontend, enabled_build_rejects_unknown_attributes)
{
	constexpr std::string_view SOURCE = R"mlir(
module attributes {pipeline_id = "mlir_unknown_attr", allow_dag = false} {
  "axiom.core.stage"() {stage_id = "rx", kind = "RX", execution_mode = "PASSIVE", interface = "wan0", queue_count = "1"} : () -> ()
}
)mlir";
	mlir_source_file source(SOURCE);
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_mlir(source.path().string(), contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief The enabled frontend rejects operations outside the exact Axiom subset. */
TEST(axiom_mlir_frontend, enabled_build_rejects_unknown_operations)
{
	constexpr std::string_view SOURCE = R"mlir(
module attributes {pipeline_id = "mlir_unknown_op", allow_dag = false} {
  "axiom.core.unknown"() : () -> ()
}
)mlir";
	mlir_source_file source(SOURCE);
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_mlir(source.path().string(), contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief The enabled frontend cannot lower a removed stage-kind spelling. */
TEST(axiom_mlir_frontend, enabled_build_rejects_removed_stage_kind)
{
	constexpr std::string_view SOURCE = R"mlir(
module attributes {pipeline_id = "mlir_removed_kind", allow_dag = false} {
  "axiom.core.stage"() {stage_id = "parse", kind = "PARSE_IPV6", execution_mode = "PASSIVE"} : () -> ()
}
)mlir";
	mlir_source_file source(SOURCE);
	ASSERT_TRUE(source.valid());

	auto pipeline_or = load_pipeline_mlir(source.path().string(), contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(pipeline_or.error().message().find("unknown stage kind"), std::string::npos);
}

#else

/** @brief A build without MLIR returns one explicit capability failure. */
TEST(axiom_mlir_frontend, disabled_build_rejects_before_source_discovery)
{
	auto pipeline_or = load_pipeline_mlir("/path/is/not/consulted.mlir", contract_options{});
	ASSERT_FALSE(pipeline_or.is_ok());
	EXPECT_EQ(pipeline_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_NE(pipeline_or.error().message().find("MLIR support not enabled"), std::string::npos);
}

#endif

}  // namespace
}  // namespace kinetum::axiom
