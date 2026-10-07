// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_cp_bootstrap_startup.cpp
 * @brief Admission tests for CP's exact bootstrap startup authority.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/file_io.hpp"
#include "src/common/held_file.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/cp/bootstrap_startup.hpp"

namespace kinetum::cp
{
namespace
{

namespace fs = std::filesystem;

using kinetum::common::status_code;

/** @brief Process-local sequence for collision-free bootstrap test roots. */
std::atomic<uint64_t> TEST_ROOT_SEQUENCE{0u};

/** @brief Canonical terminal snapshot and its repository text representation. */
struct bootstrap_snapshot_source {
	kinetum::common::canonical_config_snapshot canonical;  ///< Exact terminal binary authority.
	std::string text;				       ///< Exact protobuf-text source consumed at startup.
};

/**
 * @brief Construct one module-free terminal ConfigSnapshot source.
 *
 * @return Canonical terminal bytes plus protobuf text, or the shared identity
 *         or text-serialization failure.
 */
kinetum::common::status_or<bootstrap_snapshot_source> make_bootstrap_snapshot_source()
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	snapshot.set_snapshot_id("bootstrap.source");
	snapshot.set_revision(17);
	snapshot.set_created_unix_ms(1'000);
	snapshot.set_description("canonical bootstrap source");
	kinetum::gluon::v1::DeploymentPlan module_free_plan;
	auto canonical_or = kinetum::common::canonicalize_config_snapshot(snapshot, module_free_plan);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}

	kinetum::control::v1::ConfigSnapshot terminal;
	const auto terminal_status = kinetum::common::admit_terminal_config_snapshot(canonical_or.value(), &terminal);
	if (!terminal_status.is_ok()) {
		return terminal_status;
	}
	auto text_or = kinetum::common::print_pbtxt_text(terminal);
	if (!text_or.is_ok()) {
		return text_or.error();
	}
	return bootstrap_snapshot_source{
		.canonical = std::move(canonical_or).value(),
		.text = std::move(text_or).value(),
	};
}

/**
 * @brief Replace bytes through the existing inode without pathname replacement.
 *
 * @param path Exact regular-file path.
 * @param bytes Complete replacement bytes.
 * @return true only after exact write, fsync, and close.
 */
bool overwrite_existing_inode(const fs::path &path, std::string_view bytes)
{
	const int descriptor = ::open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0) {
		return false;
	}

	std::size_t offset = 0;
	while (offset < bytes.size()) {
		const ssize_t count = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
		if (count < 0) {
			if (errno == EINTR) {
				continue;
			}
			(void)::close(descriptor);
			return false;
		}
		if (count == 0) {
			(void)::close(descriptor);
			return false;
		}
		offset += static_cast<std::size_t>(count);
	}
	if (::fsync(descriptor) != 0) {
		(void)::close(descriptor);
		return false;
	}
	return ::close(descriptor) == 0;
}

/**
 * @brief Own one canonical temporary directory for bootstrap path tests.
 */
class bootstrap_path_fixture final {
    public:
	/** @brief Create one empty canonical temporary directory. */
	bootstrap_path_fixture()
	{
		const uint64_t sequence = TEST_ROOT_SEQUENCE.fetch_add(1u, std::memory_order_relaxed) + 1u;
		root_ = fs::canonical(fs::temp_directory_path()) /
			("kinetum_cp_bootstrap_startup_" + std::to_string(static_cast<uint64_t>(::getpid())) + "_" +
			 std::to_string(sequence));
		std::error_code ec;
		fs::remove_all(root_, ec);
		ec.clear();
		fs::create_directory(root_, ec);
		if (ec || ::chmod(root_.c_str(), static_cast<mode_t>(0700)) != 0) {
			construction_error_ = ec.message();
			if (construction_error_.empty()) {
				construction_error_ = "failed to apply owner-only test-directory mode";
			}
		}
	}

	/** @brief Remove every fixture artifact without throwing. */
	~bootstrap_path_fixture()
	{
		std::error_code ec;
		fs::remove_all(root_, ec);
	}

	/**
	 * @brief Return the canonical temporary directory.
	 *
	 * @return Fixture-owned canonical directory path.
	 */
	[[nodiscard]] const fs::path &root() const noexcept
	{
		return root_;
	}

	/**
	 * @brief Return setup failure details, or an empty string on success.
	 *
	 * @return Construction diagnostic retained by the fixture.
	 */
	[[nodiscard]] const std::string &construction_error() const noexcept
	{
		return construction_error_;
	}

    private:
	fs::path root_;			  ///< Canonical temporary directory.
	std::string construction_error_;  ///< Nonthrowing setup diagnostic.
};

}  // namespace

/**
 * @brief Verify absence of both values selects the explicit control-only posture.
 */
TEST(cp_bootstrap_startup, absent_pair_admits_control_only_process)
{
	auto result = admit_bootstrap_startup_authority("", "");
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_FALSE(result->has_value());
}

/**
 * @brief Verify neither half of bootstrap authority is sufficient by itself.
 */
TEST(cp_bootstrap_startup, partial_authority_pair_is_rejected)
{
	auto missing_hash = admit_bootstrap_startup_authority("/snapshot.pbtxt", "");
	ASSERT_FALSE(missing_hash.is_ok());
	EXPECT_EQ(missing_hash.error().code(), status_code::INVALID_ARGUMENT);

	auto missing_path = admit_bootstrap_startup_authority("", std::string(64, 'a'));
	ASSERT_FALSE(missing_path.is_ok());
	EXPECT_EQ(missing_path.error().code(), status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify CP consumes the shared exact lowercase SHA-256 claim contract.
 */
TEST(cp_bootstrap_startup, malformed_plan_hash_claim_is_rejected)
{
	auto uppercase = admit_bootstrap_startup_authority("/snapshot.pbtxt", std::string(64, 'A'));
	ASSERT_FALSE(uppercase.is_ok());
	EXPECT_EQ(uppercase.error().code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(uppercase.error().message().find("lowercase hexadecimal"), std::string::npos);
}

/**
 * @brief Verify only the exact canonical regular-file path is admitted.
 */
TEST(cp_bootstrap_startup, canonical_file_admits_and_path_indirection_rejects)
{
	bootstrap_path_fixture fixture;
	ASSERT_TRUE(fixture.construction_error().empty()) << fixture.construction_error();
	auto source_or = make_bootstrap_snapshot_source();
	ASSERT_TRUE(source_or.is_ok()) << source_or.error().message();
	auto source = std::move(source_or).value();
	const fs::path snapshot = fixture.root() / "config_snapshot.pbtxt";
	auto missing = admit_bootstrap_startup_authority(snapshot.string(), std::string(64, 'b'));
	ASSERT_FALSE(missing.is_ok());
	EXPECT_EQ(missing.error().code(), status_code::NOT_FOUND);

	const fs::path oversized = fixture.root() / "oversized_snapshot.pbtxt";
	const int oversized_descriptor =
		::open(oversized.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, static_cast<mode_t>(0644));
	ASSERT_GE(oversized_descriptor, 0);
	constexpr off_t OVERSIZED_SOURCE_SIZE = static_cast<off_t>(64u * 1024u * 1024u + 1u);
	const int truncate_result = ::ftruncate(oversized_descriptor, OVERSIZED_SOURCE_SIZE);
	const int close_result = ::close(oversized_descriptor);
	ASSERT_EQ(truncate_result, 0);
	ASSERT_EQ(close_result, 0);
	auto too_large = admit_bootstrap_startup_authority(oversized.string(), std::string(64, 'b'));
	ASSERT_FALSE(too_large.is_ok());
	EXPECT_EQ(too_large.error().code(), status_code::RESOURCE_EXHAUSTED);

	const fs::path fifo = fixture.root() / "snapshot_fifo.pbtxt";
	ASSERT_EQ(::mkfifo(fifo.c_str(), static_cast<mode_t>(0644)), 0);
	auto named_pipe = admit_bootstrap_startup_authority(fifo.string(), std::string(64, 'b'));
	ASSERT_FALSE(named_pipe.is_ok());
	EXPECT_EQ(named_pipe.error().code(), status_code::FAILED_PRECONDITION);

	const auto write_status = kinetum::common::write_string_to_file(snapshot, source.text);
	ASSERT_TRUE(write_status.is_ok()) << write_status.message();
	ASSERT_EQ(::chmod(snapshot.c_str(), static_cast<mode_t>(0644)), 0);

	auto admitted = admit_bootstrap_startup_authority(snapshot.string(), std::string(64, 'b'));
	ASSERT_TRUE(admitted.is_ok()) << admitted.error().message();
	ASSERT_TRUE(admitted->has_value());
	EXPECT_EQ(admitted->value().snapshot_source.path(), snapshot);
	EXPECT_EQ(admitted->value().snapshot.serialized_bytes, source.canonical.serialized_bytes);
	EXPECT_EQ(admitted->value().snapshot.validation_hash, source.canonical.validation_hash);
	EXPECT_EQ(admitted->value().plan_content_hash, std::string(64, 'b'));
	for (const uint8_t byte : admitted->value().plan_content_hash_bytes) {
		EXPECT_EQ(byte, 0xbbu);
	}

	const fs::path symlink = fixture.root() / "snapshot_link.pbtxt";
	std::error_code ec;
	fs::create_symlink(snapshot, symlink, ec);
	ASSERT_FALSE(ec) << ec.message();
	auto linked = admit_bootstrap_startup_authority(symlink.string(), std::string(64, 'b'));
	ASSERT_FALSE(linked.is_ok());
	EXPECT_EQ(linked.error().code(), status_code::FAILED_PRECONDITION);

	const fs::path component_link = fixture.root() / "component_link";
	ec.clear();
	fs::create_directory_symlink(fixture.root(), component_link, ec);
	ASSERT_FALSE(ec) << ec.message();
	auto linked_component = admit_bootstrap_startup_authority((component_link / snapshot.filename()).string(),
								  std::string(64, 'b'));
	ASSERT_FALSE(linked_component.is_ok());
	EXPECT_EQ(linked_component.error().code(), status_code::FAILED_PRECONDITION);

	const fs::path non_normal = fixture.root() / "." / "config_snapshot.pbtxt";
	auto noncanonical = admit_bootstrap_startup_authority(non_normal.string(), std::string(64, 'b'));
	ASSERT_FALSE(noncanonical.is_ok());
	EXPECT_EQ(noncanonical.error().code(), status_code::INVALID_ARGUMENT);

	ASSERT_EQ(::chmod(snapshot.c_str(), static_cast<mode_t>(0664)), 0);
	auto writable = admit_bootstrap_startup_authority(snapshot.string(), std::string(64, 'b'));
	ASSERT_FALSE(writable.is_ok());
	EXPECT_EQ(writable.error().code(), status_code::PERMISSION_DENIED);
	ASSERT_EQ(::chmod(snapshot.c_str(), static_cast<mode_t>(0644)), 0);

	std::string mutated = source.text;
	ASSERT_FALSE(mutated.empty());
	mutated.front() = mutated.front() == 'x' ? 'y' : 'x';
	ASSERT_TRUE(overwrite_existing_inode(snapshot, mutated));
	auto reread = kinetum::common::read_held_file(admitted->value().snapshot_source, source.text.size());
	ASSERT_FALSE(reread.is_ok());
	EXPECT_EQ(reread.error().code(), status_code::DATA_LOSS);
}

}  // namespace kinetum::cp
