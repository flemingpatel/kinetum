// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_bundle_manifest.cpp
 * @brief Bundle-manifest generation and verification tests.
 * @author Fleming Patel
 *
 * Each bundle contains a manifest that binds the admitted manifest bytes to:
 * - Bundle metadata (name and exact product version)
 * - File inventory (paths, sizes, SHA-256 hashes)
 * - Pipeline configuration references
 *
 * Content-identity properties:
 * ----------------------------
 * 1. Integrity: SHA-256 verifies file content against the admitted manifest
 * 2. Completeness: Manifest lists all files, detecting missing artifacts
 * 3. Version truth: required product identity is never inferred or defaulted
 *
 * @see src/pack/bundle_manifest.hpp
 * @see src/pack/kinetum_pack_main.cpp (bundle creation)
 * @see src/pack/kinetum_bundle_verify_main.cpp (bundle verification)
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "src/common/sha256.hpp"
#include "src/common/version.hpp"
#include "src/pack/bundle_manifest.hpp"

namespace
{

/** @brief Canonical test digest used by grammar-only manifest rows. */
constexpr std::string_view TEST_SHA256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/**
 * @brief Build the exact required metadata prefix for one test manifest.
 *
 * @param name Canonical bundle name.
 * @return Two canonical LF-terminated metadata rows.
 */
[[nodiscard]] std::string canonical_manifest_header(std::string_view name = "test")
{
	return "bundle_name=" + std::string(name) + "\nbundle_version=" + kinetum::common::KINETUM_VERSION_STRING +
	       "\n";
}

/**
 * @brief Return a valid version triplet different from the compiled product.
 *
 * @return Foreign version suitable for exact mismatch evidence.
 */
[[nodiscard]] std::string foreign_product_version()
{
	constexpr std::string_view candidate = "999.999.999";
	constexpr std::string_view alternate = "998.998.998";
	if (std::string_view(kinetum::common::KINETUM_VERSION_STRING) == candidate) {
		return std::string(alternate);
	}
	return std::string(candidate);
}

}  // namespace

//==============================================================================
// Manifest Serialization Tests
//==============================================================================

/**
 * @brief Verify manifest roundtrip serialization preserves all data.
 *
 * A manifest serialized to text and parsed back must produce an identical
 * manifest. This ensures:
 * - Bundle verification works after file transfer
 * - Text format is unambiguous
 * - No information loss in serialization
 *
 * Test Methodology:
 * 1. Create manifest with file entry (path, size, hash)
 * 2. Serialize to text format
 * 3. Parse text back to manifest
 * 4. Verify all fields match original
 *
 * @note SHA-256 hash is 64 hex characters (256 bits = 32 bytes = 64 hex chars)
 */
TEST(bundle_manifest, parse_roundtrip)
{
	// Create manifest with test data
	kinetum::pack::bundle_manifest m;
	m.bundle_name = "x";
	m.bundle_version = kinetum::common::KINETUM_VERSION_STRING;

	// Add file entry with valid SHA-256 hash (64 hex characters)
	kinetum::pack::bundle_file_entry e;
	e.rel_path = "bin/a";
	e.size_bytes = 10;
	e.sha256_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
	m.files.push_back(e);

	// Serialize to text
	auto txt_or = m.to_text();
	ASSERT_TRUE(txt_or.is_ok()) << txt_or.error().message();

	// Parse back from text
	auto m2 = kinetum::pack::bundle_manifest::from_text(txt_or.value());
	ASSERT_TRUE(m2.is_ok()) << "Manifest parsing failed: " << m2.error().message();
	auto second_text_or = m2.value().to_text();
	ASSERT_TRUE(second_text_or.is_ok()) << second_text_or.error().message();
	EXPECT_EQ(second_text_or.value(), txt_or.value()) << "Canonical roundtrip must preserve exact bytes";

	// Verify roundtrip integrity
	EXPECT_EQ(m2.value().bundle_name, m.bundle_name) << "bundle_name must survive roundtrip";
	EXPECT_EQ(m2.value().bundle_version, m.bundle_version) << "bundle_version must survive roundtrip";
	ASSERT_EQ(m2.value().files.size(), 1u) << "File count must match";
	EXPECT_EQ(m2.value().files[0].rel_path, "bin/a") << "File path must survive roundtrip";
	EXPECT_EQ(m2.value().files[0].size_bytes, 10u) << "File size must survive roundtrip";
	EXPECT_EQ(m2.value().files[0].sha256_hex, e.sha256_hex) << "SHA-256 hash must survive roundtrip";
}

//==============================================================================
// Parser Rejection Tests (from_text fail-closed)
//==============================================================================

/**
 * @brief Malformed file line with missing fields is rejected.
 *
 * A file line with only 2 fields (missing hash) must produce
 * invalid_argument, not a partial entry or silent skip.
 */
TEST(bundle_manifest, parser_rejects_malformed_file_line)
{
	const std::string txt = canonical_manifest_header() + "file bin/a 100\n";  // Missing SHA-256 hash

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Malformed file line (missing hash) must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief File line with non-numeric size is rejected.
 *
 * Size field must be a valid uint64. "abc" must not silently parse to 0.
 */
TEST(bundle_manifest, parser_rejects_non_numeric_size)
{
	const std::string txt = canonical_manifest_header() + "file bin/a abc " + std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Non-numeric size must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify parser rejects size with trailing junk.
 */
TEST(bundle_manifest, parser_rejects_size_with_trailing_junk)
{
	const std::string txt = canonical_manifest_header() + "file bin/a 12abc " + std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Size token with trailing junk must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify parser rejects signed size.
 */
TEST(bundle_manifest, parser_rejects_signed_size)
{
	const std::string txt = canonical_manifest_header() + "file bin/a -1 " + std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Signed size token must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief SHA-256 hash with wrong length (63 chars) is rejected.
 *
 * SHA-256 produces exactly 64 hex characters. A truncated hash must not
 * pass validation; this catches corrupted manifests.
 */
TEST(bundle_manifest, parser_rejects_truncated_hash)
{
	const std::string txt = canonical_manifest_header() +
				"file bin/a 100 "
				"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee\n";  // 63 chars

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Truncated SHA-256 hash (63 chars) must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief SHA-256 hash with non-hex character is rejected.
 *
 * A hash containing 'g' (not a hex digit) must be rejected even if
 * the length is correct. Catches subtle corruption.
 */
TEST(bundle_manifest, parser_rejects_non_hex_hash)
{
	// 'g' at the end is not a valid hex character.
	const std::string bad_hash =
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeeg";  // 64 chars, 'g' at end

	// Verify length is indeed 64 to confirm we're testing the hex-char check, not length
	ASSERT_EQ(bad_hash.size(), 64u);

	const std::string txt = canonical_manifest_header() + "file bin/a 100 " + bad_hash + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);

	ASSERT_FALSE(result.is_ok()) << "Non-hex character in SHA-256 hash must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Directory traversal path (../) in file entry is rejected.
 *
 * A manifest containing a path with parent directory references must be
 * rejected to prevent directory traversal during verification.
 */
TEST(bundle_manifest, parser_rejects_directory_traversal)
{
	const std::string txt =
		canonical_manifest_header() + "file ../etc/passwd 100 " + std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Directory traversal path must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Absolute path in file entry is rejected.
 *
 * Only relative paths are valid in a bundle manifest. Absolute paths
 * could reference files outside the bundle directory.
 */
TEST(bundle_manifest, parser_rejects_absolute_path)
{
	const std::string txt = canonical_manifest_header() + "file /etc/shadow 100 " + std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Absolute path must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify parser rejects backslash path separator.
 */
TEST(bundle_manifest, parser_rejects_backslash_path_separator)
{
	const std::string txt = canonical_manifest_header() + "file bin\\tool 100 " + std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Backslash path separator must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Verify parser rejects tab in path.
 */
TEST(bundle_manifest, parser_rejects_tab_in_path)
{
	const std::string txt = canonical_manifest_header() + "file bin/a\tb 100 " + std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Control or whitespace characters in paths must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Completely empty input cannot fabricate required bundle metadata.
 */
TEST(bundle_manifest, parser_rejects_missing_required_metadata)
{
	auto result = kinetum::pack::bundle_manifest::from_text("");
	ASSERT_FALSE(result.is_ok()) << "Empty input must not manufacture bundle identity";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Manifest exceeding maximum size is rejected (DoS protection).
 *
 * The parser enforces MAX_MANIFEST_SIZE (1MB) to prevent denial of service
 * from processing extremely large manifests.
 */
TEST(bundle_manifest, parser_rejects_oversized_manifest)
{
	// Create a manifest just over the 1MB limit
	std::string huge(kinetum::pack::MAX_MANIFEST_SIZE + 1, 'x');
	auto result = kinetum::pack::bundle_manifest::from_text(huge);
	ASSERT_FALSE(result.is_ok()) << "Oversized manifest must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Duplicate file entries are rejected by the parser.
 *
 * Each rel_path must appear exactly once in a valid manifest. Duplicate
 * entries create an ambiguous manifest surface, a security risk on
 * a integrity-critical path. The parser rejects structurally.
 */
TEST(bundle_manifest, parser_rejects_duplicate_entries)
{
	const std::string txt = canonical_manifest_header() + "file bin/a 100 " + std::string(TEST_SHA256) +
				"\n"
				"file bin/a 100 " +
				std::string(TEST_SHA256) + "\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Duplicate rel_path entries must be rejected";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Unknown directive in manifest is rejected (fail-closed).
 *
 * A line that is not bundle_name=, bundle_version=, or file must be
 * rejected. On a security-critical path, silent acceptance of unknown
 * directives creates an ambiguous grammar surface. A format change requires
 * one explicit in-place product-contract replacement, not silent acceptance.
 */
TEST(bundle_manifest, parser_rejects_unknown_directive)
{
	const std::string txt = canonical_manifest_header() +
				"priority=high\n"
				"file bin/a 100 "
				"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n";

	auto result = kinetum::pack::bundle_manifest::from_text(txt);
	ASSERT_FALSE(result.is_ok()) << "Unknown directive must be rejected (fail-closed)";
	EXPECT_EQ(result.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief Verify required metadata has one position, spelling, and version authority. */
TEST(bundle_manifest, parser_requires_exact_metadata_and_product_version)
{
	const std::vector<std::string> malformed = {
		"bundle_version=" + std::string(kinetum::common::KINETUM_VERSION_STRING) + "\n",
		"bundle_name=test\n",
		"bundle_name=\nbundle_version=" + std::string(kinetum::common::KINETUM_VERSION_STRING) + "\n",
		"bundle_name=test\nbundle_version=\n",
		canonical_manifest_header() + "bundle_name=other\n",
		canonical_manifest_header() + "bundle_version=" + std::string(kinetum::common::KINETUM_VERSION_STRING) +
			"\n",
		"bundle_version=" + std::string(kinetum::common::KINETUM_VERSION_STRING) + "\nbundle_name=test\n",
		"bundle_name=bad name\nbundle_version=" + std::string(kinetum::common::KINETUM_VERSION_STRING) + "\n",
		"bundle_name=test\nbundle_version=one.two\n",
	};
	for (const auto &text : malformed) {
		SCOPED_TRACE(text);
		const auto parsed_or = kinetum::pack::bundle_manifest::from_text(text);
		ASSERT_FALSE(parsed_or.is_ok());
		EXPECT_EQ(parsed_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	}

	const std::string foreign = "bundle_name=test\nbundle_version=" + foreign_product_version() + "\n";
	const auto foreign_or = kinetum::pack::bundle_manifest::from_text(foreign);
	ASSERT_FALSE(foreign_or.is_ok());
	EXPECT_EQ(foreign_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
}

/** @brief Verify the one shared bundle-name grammar at both exact length edges. */
TEST(bundle_manifest, canonical_bundle_name_grammar_is_exact)
{
	EXPECT_TRUE(kinetum::pack::is_canonical_bundle_name("A-z_0.1"));
	EXPECT_TRUE(kinetum::pack::is_canonical_bundle_name(std::string(kinetum::pack::MAX_BUNDLE_NAME_LENGTH, 'a')));
	EXPECT_FALSE(kinetum::pack::is_canonical_bundle_name(""));
	EXPECT_FALSE(kinetum::pack::is_canonical_bundle_name("."));
	EXPECT_FALSE(kinetum::pack::is_canonical_bundle_name(".."));
	EXPECT_FALSE(kinetum::pack::is_canonical_bundle_name("bad name"));
	EXPECT_FALSE(
		kinetum::pack::is_canonical_bundle_name(std::string(kinetum::pack::MAX_BUNDLE_NAME_LENGTH + 1, 'a')));
}

/** @brief Verify equivalent-looking noncanonical byte representations all reject. */
TEST(bundle_manifest, parser_rejects_every_noncanonical_representation)
{
	const std::string canonical_row = "file bin/a 1 " + std::string(TEST_SHA256) + "\n";
	std::string uppercase_hash(TEST_SHA256);
	uppercase_hash.front() = 'D';
	const std::vector<std::string> malformed = {
		" " + canonical_manifest_header() + canonical_row,
		canonical_manifest_header() + "\n" + canonical_row,
		"bundle_name=test\r\nbundle_version=" + std::string(kinetum::common::KINETUM_VERSION_STRING) + "\r\n",
		canonical_manifest_header().substr(0, canonical_manifest_header().size() - 1),
		canonical_manifest_header() + "file bin/a 1 " + uppercase_hash + "\n",
		canonical_manifest_header() + "file bin/a 01 " + std::string(TEST_SHA256) + "\n",
		canonical_manifest_header() + "file bin/b 1 " + std::string(TEST_SHA256) + "\nfile bin/a 1 " +
			std::string(TEST_SHA256) + "\n",
		canonical_manifest_header() + "file bin//a 1 " + std::string(TEST_SHA256) + "\n",
		canonical_manifest_header() + "file bin/\xC3\xA9 1 " + std::string(TEST_SHA256) + "\n",
		canonical_manifest_header() + "file BUNDLE_MANIFEST.txt 1 " + std::string(TEST_SHA256) + "\n",
		canonical_manifest_header() + "file  bin/a 1 " + std::string(TEST_SHA256) + "\n",
	};
	for (const auto &text : malformed) {
		SCOPED_TRACE(text.substr(0, 160));
		const auto parsed_or = kinetum::pack::bundle_manifest::from_text(text);
		ASSERT_FALSE(parsed_or.is_ok());
		EXPECT_EQ(parsed_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	}
}

/** @brief Verify structured serialization rejects every invalid authority before output. */
TEST(bundle_manifest, serializer_validates_name_version_order_and_digest)
{
	kinetum::pack::bundle_manifest manifest;
	manifest.bundle_name = "bad name";
	manifest.bundle_version = kinetum::common::KINETUM_VERSION_STRING;
	EXPECT_FALSE(manifest.to_text().is_ok());

	manifest.bundle_name = "valid_name";
	manifest.bundle_version = foreign_product_version();
	auto foreign_or = manifest.to_text();
	ASSERT_FALSE(foreign_or.is_ok());
	EXPECT_EQ(foreign_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);

	manifest.bundle_version = kinetum::common::KINETUM_VERSION_STRING;
	manifest.files = {
		{.rel_path = "bin/b", .size_bytes = 1, .sha256_hex = std::string(TEST_SHA256)},
		{.rel_path = "bin/a", .size_bytes = 1, .sha256_hex = std::string(TEST_SHA256)},
	};
	EXPECT_FALSE(manifest.to_text().is_ok());

	manifest.files.resize(1);
	manifest.files.front().sha256_hex.front() = 'D';
	EXPECT_FALSE(manifest.to_text().is_ok());
}

/** @brief Verify producer and parser agree at the exact file-count and byte ceilings. */
TEST(bundle_manifest, serializer_and_parser_share_exact_count_and_byte_bounds)
{
	kinetum::pack::bundle_manifest count_bound;
	count_bound.bundle_name = "count_bound";
	count_bound.bundle_version = kinetum::common::KINETUM_VERSION_STRING;
	count_bound.files.reserve(kinetum::pack::MAX_BUNDLE_FILES + 1);
	constexpr std::size_t COUNT_ORDINAL_WIDTH = 5;
	for (std::size_t index = 0; index < kinetum::pack::MAX_BUNDLE_FILES; ++index) {
		const std::string ordinal = std::to_string(index);
		ASSERT_LE(ordinal.size(), COUNT_ORDINAL_WIDTH);
		const std::string path = "files/" + std::string(COUNT_ORDINAL_WIDTH - ordinal.size(), '0') + ordinal;
		count_bound.files.push_back(
			{.rel_path = path, .size_bytes = 0, .sha256_hex = std::string(TEST_SHA256)});
	}
	auto count_text_or = count_bound.to_text();
	ASSERT_TRUE(count_text_or.is_ok()) << count_text_or.error().message();
	auto count_parsed_or = kinetum::pack::bundle_manifest::from_text(count_text_or.value());
	ASSERT_TRUE(count_parsed_or.is_ok()) << count_parsed_or.error().message();
	EXPECT_EQ(count_parsed_or->files.size(), kinetum::pack::MAX_BUNDLE_FILES);
	count_bound.files.push_back(
		{.rel_path = "files/10000", .size_bytes = 0, .sha256_hex = std::string(TEST_SHA256)});
	EXPECT_FALSE(count_bound.to_text().is_ok());

	kinetum::pack::bundle_manifest byte_bound;
	byte_bound.bundle_name = "byte_bound";
	byte_bound.bundle_version = kinetum::common::KINETUM_VERSION_STRING;
	std::size_t extent = canonical_manifest_header(byte_bound.bundle_name).size();
	constexpr std::size_t ROW_WITHOUT_PATH_BYTES =
		std::string_view("file ").size() + 1 + 1 + 1 + TEST_SHA256.size() + 1;
	constexpr std::size_t ORDINAL_WIDTH = 6;
	constexpr std::size_t MIN_PATH_BYTES = std::string_view("files/").size() + ORDINAL_WIDTH + 1;
	constexpr std::size_t MIN_ROW_BYTES = ROW_WITHOUT_PATH_BYTES + MIN_PATH_BYTES;
	constexpr std::size_t MAX_ROW_BYTES = ROW_WITHOUT_PATH_BYTES + kinetum::pack::MAX_REL_PATH_LENGTH;
	std::size_t index = 0;
	while (extent < kinetum::pack::MAX_MANIFEST_SIZE) {
		const std::size_t remaining = kinetum::pack::MAX_MANIFEST_SIZE - extent;
		std::size_t row_bytes = std::min(remaining, MAX_ROW_BYTES);
		if (remaining > MAX_ROW_BYTES && remaining - MAX_ROW_BYTES < MIN_ROW_BYTES) {
			row_bytes = remaining - MIN_ROW_BYTES;
		}
		ASSERT_GE(row_bytes, MIN_ROW_BYTES);
		const std::size_t path_bytes = row_bytes - ROW_WITHOUT_PATH_BYTES;
		const std::string ordinal = std::to_string(index++);
		ASSERT_LE(ordinal.size(), ORDINAL_WIDTH);
		std::string path = "files/" + std::string(ORDINAL_WIDTH - ordinal.size(), '0') + ordinal + "_";
		ASSERT_LE(path.size(), path_bytes);
		path.append(path_bytes - path.size(), 'x');
		byte_bound.files.push_back(
			{.rel_path = std::move(path), .size_bytes = 0, .sha256_hex = std::string(TEST_SHA256)});
		extent += row_bytes;
	}
	auto byte_text_or = byte_bound.to_text();
	ASSERT_TRUE(byte_text_or.is_ok()) << byte_text_or.error().message();
	ASSERT_EQ(byte_text_or->size(), kinetum::pack::MAX_MANIFEST_SIZE);
	const auto byte_parsed_or = kinetum::pack::bundle_manifest::from_text(byte_text_or.value());
	EXPECT_TRUE(byte_parsed_or.is_ok()) << byte_parsed_or.error().message();
}

//==============================================================================
// Verification Tests (verify_manifest fail-closed)
//==============================================================================
// These tests exercise the production verifier directly with controlled
// bundle directories. Each test creates a temp dir, populates files,
// constructs a manifest, and asserts fail-closed rejection.

namespace
{

/** @brief Own one kernel-created test bundle tree and remove it at scope exit. */
class bundle_dir_guard final {
    public:
	/** @brief Create one private bundle root with a canonical generated name. */
	bundle_dir_guard()
	{
		std::string pattern =
			(std::filesystem::temp_directory_path() / "kinetum_bundle_manifest.XXXXXX").string();
		if (char *created = ::mkdtemp(pattern.data()); created != nullptr) {
			cleanup_root_ = created;
			path_ = cleanup_root_;
		}
	}

	/**
	 * @brief Create one private parent and exact child bundle name.
	 * @param leaf Exact child name needed by the test.
	 */
	explicit bundle_dir_guard(std::string_view leaf)
		: bundle_dir_guard()
	{
		if (path_.empty()) {
			return;
		}
		const auto child = std::filesystem::path(cleanup_root_) / leaf;
		std::error_code error;
		if (!std::filesystem::create_directory(child, error) || error) {
			path_.clear();
			return;
		}
		path_ = child.string();
	}

	bundle_dir_guard(const bundle_dir_guard &) = delete;
	bundle_dir_guard &operator=(const bundle_dir_guard &) = delete;
	bundle_dir_guard(bundle_dir_guard &&) = delete;
	bundle_dir_guard &operator=(bundle_dir_guard &&) = delete;

	/** @brief Remove the complete private test tree. */
	~bundle_dir_guard()
	{
		if (!cleanup_root_.empty()) {
			std::error_code error;
			std::filesystem::remove_all(cleanup_root_, error);
		}
	}

	/** @return true when the exact test bundle root was created. */
	[[nodiscard]] bool valid() const noexcept
	{
		return !path_.empty();
	}

	/** @return Exact test bundle root. */
	[[nodiscard]] const std::string &path() const noexcept
	{
		return path_;
	}

    private:
	std::string cleanup_root_;  ///< Private kernel-created parent owned by this guard.
	std::string path_;	    ///< Exact bundle root consumed by the test.
};

/**
 * @brief Write one complete fixture file after creating its parent directories.
 * @param path Destination path.
 * @param content Exact fixture bytes.
 * @return true after creating the parent and writing the complete file; false on filesystem/output failure.
 */
[[nodiscard]] bool write_file(const std::string &path, const std::string &content)
{
	namespace fs = std::filesystem;
	std::error_code error;
	fs::create_directories(fs::path(path).parent_path(), error);
	if (error) {
		return false;
	}
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	output.write(content.data(), static_cast<std::streamsize>(content.size()));
	output.flush();
	output.close();
	return output.good();
}

/**
 * @brief Build one valid manifest from independently hashed fixture files.
 * @param bundle_dir Exact fixture bundle root.
 * @param files Relative paths and bytes expected beneath @p bundle_dir.
 * @return Canonical manifest text carrying independently computed SHA-256 rows.
 */
std::string build_valid_manifest(const std::string &bundle_dir,
				 const std::vector<std::pair<std::string, std::string>> &files)
{
	namespace fs = std::filesystem;
	kinetum::pack::bundle_manifest manifest;
	manifest.bundle_name = "test_bundle";
	manifest.bundle_version = kinetum::common::KINETUM_VERSION_STRING;

	for (const auto &[rel_path, content] : files) {
		const auto full_path = (fs::path(bundle_dir) / rel_path).string();
		if (!write_file(full_path, content)) {
			ADD_FAILURE() << "failed to publish bundle fixture " << rel_path;
			return {};
		}

		auto hash_or = kinetum::common::sha256_hex(content);
		EXPECT_TRUE(hash_or.is_ok()) << "SHA-256 computation failed for test setup";
		if (!hash_or.is_ok()) {
			return {};
		}
		const auto size = static_cast<uint64_t>(content.size());
		manifest.files.push_back({.rel_path = rel_path, .size_bytes = size, .sha256_hex = hash_or.value()});
	}

	auto text_or = manifest.to_text();
	EXPECT_TRUE(text_or.is_ok()) << "Valid manifest fixture serialization failed";
	return text_or.is_ok() ? std::move(text_or).value() : std::string{};
}

}  // namespace

/**
 * @brief Valid bundle verifies successfully (baseline).
 *
 * Establishes the positive case: a bundle with correct hashes, sizes,
 * and no extra files must pass verification. All subsequent tests
 * mutate from this baseline.
 */
TEST(bundle_verify, valid_bundle_passes)
{
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	auto manifest = build_valid_manifest(dir, {
							  {"bin/kinetum_cp", "binary content here"},
							  {"configs/pipeline.pbtxt", "stage { name: \"rx\" }"},
						  });

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	EXPECT_TRUE(status.is_ok()) << "Valid bundle must pass verification: " << status.message();
}

/**
 * @brief Verify generator rejects unrepresentable relative path.
 */
TEST(bundle_manifest, generator_rejects_unrepresentable_relative_path)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	ASSERT_TRUE(write_file((fs::path(dir) / "configs/has space.pbtxt").string(), "pipeline config"));

	auto manifest_or = kinetum::pack::generate_manifest_text(dir);
	ASSERT_FALSE(manifest_or.is_ok()) << "Generator must not emit an unparseable manifest path";
	EXPECT_EQ(manifest_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(manifest_or.error().message().find("cannot be represented"), std::string::npos);
}

/** @brief Verify generation rejects a noncanonical root identity before scanning files. */
TEST(bundle_manifest, generator_rejects_noncanonical_bundle_name)
{
	bundle_dir_guard guard("kinetum invalid bundle name");
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	const auto manifest_or = kinetum::pack::generate_manifest_text(dir);
	ASSERT_FALSE(manifest_or.is_ok());
	EXPECT_EQ(manifest_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(manifest_or.error().message().find("canonical bundle name"), std::string::npos);
}

/**
 * @brief Verify generator emits parseable manifest with observed size.
 */
TEST(bundle_manifest, generator_emits_parseable_manifest_with_observed_size)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	const std::string content = "pipeline config";
	ASSERT_TRUE(write_file((fs::path(dir) / "configs/pipeline.pbtxt").string(), content));

	auto manifest_or = kinetum::pack::generate_manifest_text(dir);
	ASSERT_TRUE(manifest_or.is_ok()) << manifest_or.error().message();

	auto parsed_or = kinetum::pack::bundle_manifest::from_text(manifest_or.value());
	ASSERT_TRUE(parsed_or.is_ok()) << parsed_or.error().message();
	ASSERT_EQ(parsed_or.value().files.size(), 1u);
	EXPECT_EQ(parsed_or.value().files[0].rel_path, "configs/pipeline.pbtxt");
	EXPECT_EQ(parsed_or.value().files[0].size_bytes, static_cast<uint64_t>(content.size()));
}

/** @brief Verification rejects an implicit or NUL-truncated bundle root. */
TEST(bundle_verify, rejects_unrepresentable_bundle_root)
{
	const std::string manifest = canonical_manifest_header();
	auto status = kinetum::pack::verify_manifest("", manifest);
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);

	std::string nul_path = "/tmp/kinetum_bundle_root";
	nul_path.push_back('\0');
	nul_path.append("ignored");
	status = kinetum::pack::verify_manifest(nul_path, manifest);
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Corrupted file content (hash mismatch) is rejected.
 *
 * After generating a valid manifest, corrupt one file's content. The
 * SHA-256 hash will no longer match. The verifier must reject with
 * failed_precondition and identify the corrupted file.
 */
TEST(bundle_verify, rejects_corrupted_file_hash_mismatch)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	auto manifest = build_valid_manifest(dir, {
							  {"bin/kinetum_cp", "original binary content"},
							  {"configs/pipeline.pbtxt", "stage { name: \"rx\" }"},
						  });

	// Corrupt the binary file AFTER manifest was generated with original hash
	ASSERT_TRUE(write_file((fs::path(dir) / "bin/kinetum_cp").string(), "changed content"));

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	ASSERT_TRUE(status.is_error()) << "Corrupted file must be rejected (hash mismatch)";
	EXPECT_EQ(status.code(), kinetum::common::status_code::FAILED_PRECONDITION)
		<< "Hash mismatch must produce failed_precondition";
	EXPECT_NE(status.details().find("bin/kinetum_cp"), std::string::npos)
		<< "Error must identify the corrupted file path";
}

/**
 * @brief Missing file (declared in manifest, absent from disk) is rejected.
 *
 * If a manifest lists a file that doesn't exist in the bundle directory,
 * verification must fail with not_found. This catches incomplete bundles
 * or files deleted after manifest generation.
 */
TEST(bundle_verify, rejects_missing_file)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	auto manifest = build_valid_manifest(dir, {
							  {"bin/kinetum_cp", "binary content"},
							  {"configs/pipeline.pbtxt", "pipeline config"},
						  });

	// Delete one file after manifest was generated
	fs::remove(fs::path(dir) / "configs/pipeline.pbtxt");

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	ASSERT_TRUE(status.is_error()) << "Missing file must be rejected";
	EXPECT_EQ(status.code(), kinetum::common::status_code::NOT_FOUND) << "Missing file must produce not_found";
	EXPECT_NE(status.details().find("pipeline.pbtxt"), std::string::npos) << "Error must identify the missing file";
}

/**
 * @brief Extra undeclared file (on disk, not in manifest) is rejected.
 *
 * If the bundle directory contains files not listed in the manifest,
 * verification must fail. This rejects undeclared content injection;
 * an unauthorized writer cannot add files without detection.
 */
TEST(bundle_verify, rejects_extra_undeclared_file)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	auto manifest = build_valid_manifest(dir, {
							  {"bin/kinetum_cp", "binary content"},
						  });

	// Plant an extra file not declared in the manifest
	ASSERT_TRUE(write_file((fs::path(dir) / "bin/undeclared.so").string(), "undeclared payload"));

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	ASSERT_TRUE(status.is_error()) << "Extra undeclared file must be rejected";
	EXPECT_EQ(status.code(), kinetum::common::status_code::FAILED_PRECONDITION)
		<< "Extra files must produce failed_precondition";
	EXPECT_NE(status.message().find("extra file"), std::string::npos) << "Error message must mention extra files";
}

/**
 * @brief Malformed manifest text is rejected by the verifier.
 *
 * verify_manifest() delegates parsing to from_text(). A malformed manifest
 * must propagate the parser's invalid_argument through to the caller.
 */
TEST(bundle_verify, rejects_malformed_manifest)
{
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	// Malformed: file line with only 2 fields
	const std::string bad_manifest = canonical_manifest_header() + "file bin/a 100\n";

	auto status = kinetum::pack::verify_manifest(dir, bad_manifest);
	ASSERT_TRUE(status.is_error()) << "Malformed manifest must be rejected by verifier";
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Size mismatch (correct hash, wrong declared size) is rejected.
 *
 * Even when the hash matches (file content is correct), a size mismatch
 * in the manifest indicates tampering with the manifest itself.
 * The verifier must reject to maintain strict integrity.
 */
TEST(bundle_verify, rejects_size_mismatch)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	const std::string content = "known file content";
	const auto full_path = (fs::path(dir) / "bin/kinetum_cp").string();
	ASSERT_TRUE(write_file(full_path, content));

	auto hash_or = kinetum::common::sha256_hex(content);
	ASSERT_TRUE(hash_or.is_ok());

	// Build manifest with correct hash but WRONG size
	const uint64_t wrong_size = content.size() + 999;
	const std::string manifest = canonical_manifest_header() + "file bin/kinetum_cp " + std::to_string(wrong_size) +
				     " " + hash_or.value() + "\n";

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	ASSERT_TRUE(status.is_error()) << "Size mismatch must be rejected even when hash is correct";
	EXPECT_EQ(status.code(), kinetum::common::status_code::FAILED_PRECONDITION)
		<< "Size mismatch must produce failed_precondition";
}

/**
 * @brief Duplicate entries are rejected through the verifier path.
 *
 * verify_manifest() delegates to from_text() which now rejects duplicate
 * rel_path entries structurally. The parser's invalid_argument must
 * propagate through the verifier.
 */
TEST(bundle_verify, rejects_duplicate_entries_through_verifier)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	const std::string content = "real file content";
	ASSERT_TRUE(write_file((fs::path(dir) / "bin/kinetum_cp").string(), content));

	auto hash_or = kinetum::common::sha256_hex(content);
	ASSERT_TRUE(hash_or.is_ok());
	const auto good_hash = hash_or.value();
	const auto size_str = std::to_string(content.size());

	// Same path twice, even with identical hash, is structurally invalid.
	const std::string manifest = canonical_manifest_header() + "file bin/kinetum_cp " + size_str + " " + good_hash +
				     "\n"
				     "file bin/kinetum_cp " +
				     size_str + " " + good_hash + "\n";

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	ASSERT_TRUE(status.is_error()) << "Duplicate entries must be rejected through verifier path";
	EXPECT_EQ(status.code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/**
 * @brief Multi-file bundle: corruption in second file is caught.
 *
 * Verifier must not stop after first file succeeds. It must verify
 * all entries and fail on any mismatch.
 */
TEST(bundle_verify, multi_file_corruption_in_second_file)
{
	namespace fs = std::filesystem;
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	auto manifest = build_valid_manifest(dir, {
							  {"bin/kinetum_cp", "binary one"},
							  {"bin/kinetum_dp", "binary two"},
							  {"configs/hw.pbtxt", "hardware config"},
						  });

	// Corrupt only the second binary
	ASSERT_TRUE(write_file((fs::path(dir) / "bin/kinetum_dp").string(), "changed content"));

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	ASSERT_TRUE(status.is_error()) << "Corruption in any file must be detected";
	EXPECT_EQ(status.code(), kinetum::common::status_code::FAILED_PRECONDITION);
	EXPECT_NE(status.details().find("kinetum_dp"), std::string::npos) << "Error must identify the corrupted file";
}

/**
 * @brief Completely empty bundle directory with non-empty manifest is rejected.
 *
 * If the manifest declares files but the directory is empty, the verifier
 * must fail with not_found on the first missing file.
 */
TEST(bundle_verify, empty_dir_with_manifest_entries_rejected)
{
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	const std::string manifest =
		canonical_manifest_header() + "file bin/missing 42 " + std::string(TEST_SHA256) + "\n";

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	ASSERT_TRUE(status.is_error()) << "Missing file in empty dir must be rejected";
	EXPECT_EQ(status.code(), kinetum::common::status_code::NOT_FOUND);
}

/**
 * @brief Empty manifest against empty bundle directory passes.
 *
 * A manifest with no file entries against an empty directory is
 * structurally valid: nothing to verify, nothing extra.
 */
TEST(bundle_verify, empty_manifest_empty_dir_passes)
{
	bundle_dir_guard guard;
	ASSERT_TRUE(guard.valid());
	const auto &dir = guard.path();

	const std::string manifest = canonical_manifest_header();

	auto status = kinetum::pack::verify_manifest(dir, manifest);
	EXPECT_TRUE(status.is_ok()) << "Empty manifest + empty dir must pass: " << status.message();
}
