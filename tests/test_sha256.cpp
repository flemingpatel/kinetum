// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_sha256.cpp
 * @brief SHA-256 hashing and file-admission tests.
 * @author Fleming Patel
 *
 * This test suite validates the SHA-256 implementation used for:
 * - Bundle content-integrity verification
 * - Content-addressable storage
 * - Deterministic ID generation
 *
 * Test Categories:
 * ----------------
 * 1. Hex Conversion: bytes_to_hex / hex_to_bytes roundtrip
 * 2. SHA-256 Core: Known test vectors from NIST FIPS 180-4
 * 3. Incremental Hasher: Streaming hash computation
 * 4. Provider Failures: invalid binary ranges fail explicitly
 *
 * Test Vector Sources:
 * --------------------
 * - NIST FIPS 180-4 (Secure Hash Standard)
 *
 * OpenSSL::Crypto is mandatory for every build. Known-vector assertions are
 * unconditional so a build-dependent substitute cannot masquerade as SHA-256.
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <unistd.h>

#include "src/common/sha256.hpp"

namespace kinetum::common
{

namespace
{

/** @brief Own one kernel-created file containing complete fixture bytes. */
class scoped_hash_file final {
    public:
	/**
	 * @brief Create and write one private temporary file.
	 * @param contents Exact fixture bytes.
	 */
	explicit scoped_hash_file(std::string_view contents)
	{
		std::string pattern = (std::filesystem::temp_directory_path() / "kinetum_sha256.XXXXXX").string();
		const int descriptor = ::mkstemp(pattern.data());
		if (descriptor < 0) {
			return;
		}
		path_ = pattern;
		owns_path_ = true;
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

	scoped_hash_file(const scoped_hash_file &) = delete;
	scoped_hash_file &operator=(const scoped_hash_file &) = delete;
	scoped_hash_file(scoped_hash_file &&) = delete;
	scoped_hash_file &operator=(scoped_hash_file &&) = delete;

	/** @brief Remove the exact owned path if it remains present. */
	~scoped_hash_file()
	{
		if (owns_path_) {
			(void)::unlink(path_.c_str());
		}
	}

	/** @return true when creation, writing, and close completed. */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_;
	}

	/** @return Exact private path retained for this fixture. */
	[[nodiscard]] const std::string &path() const noexcept
	{
		return path_;
	}

	/** @return true after removing the file while retaining its absent path. */
	[[nodiscard]] bool remove_now() noexcept
	{
		if (!owns_path_ || ::unlink(path_.c_str()) != 0) {
			return false;
		}
		owns_path_ = false;
		return true;
	}

    private:
	std::string path_;	 ///< Exact kernel-created path.
	bool valid_{false};	 ///< Complete fixture-publication result.
	bool owns_path_{false};	 ///< Whether destruction must unlink the path.
};

}  // namespace

//==============================================================================
// Hex Conversion Tests
//==============================================================================

/**
 * @brief Verify bytes_to_hex handles empty input correctly.
 *
 * Empty input should produce empty output without crashing.
 * This is a boundary condition that must be handled gracefully.
 */
TEST(sha256, bytes_to_hex_empty)
{
	std::vector<uint8_t> empty;
	EXPECT_EQ(bytes_to_hex(empty.data(), 0), "");
}

/**
 * @brief Verify bytes_to_hex converts a single byte correctly.
 *
 * Each byte should produce exactly 2 hex characters.
 * Output should be lowercase per platform convention.
 */
TEST(sha256, bytes_to_hex_single_byte)
{
	uint8_t byte = 0xAB;
	EXPECT_EQ(bytes_to_hex(&byte, 1), "ab");
}

/**
 * @brief Verify bytes_to_hex handles multiple bytes including edge cases.
 *
 * Tests:
 * - 0x00: Minimum value, leading zeros must be preserved
 * - 0xFF: Maximum value
 * - 0x12, 0x34: Typical values
 */
TEST(sha256, bytes_to_hex_multiple_bytes)
{
	uint8_t bytes[] = {0x00, 0xFF, 0x12, 0x34};
	EXPECT_EQ(bytes_to_hex(bytes, 4), "00ff1234");
}

/**
 * @brief Verify hex_to_bytes handles empty input correctly.
 *
 * Empty hex string should produce empty byte vector.
 * This is a valid input and must not fail.
 */
TEST(sha256, hex_to_bytes_empty)
{
	auto result = hex_to_bytes("");
	ASSERT_TRUE(result.is_ok());
	EXPECT_TRUE(result.value().empty());
}

/**
 * @brief Verify hex_to_bytes converts valid lowercase hex correctly.
 *
 * Standard case: lowercase hex input produces correct byte output.
 */
TEST(sha256, hex_to_bytes_valid)
{
	auto result = hex_to_bytes("00ff1234");
	ASSERT_TRUE(result.is_ok());
	ASSERT_EQ(result.value().size(), 4);
	EXPECT_EQ(result.value()[0], 0x00);
	EXPECT_EQ(result.value()[1], 0xFF);
	EXPECT_EQ(result.value()[2], 0x12);
	EXPECT_EQ(result.value()[3], 0x34);
}

/**
 * @brief Verify hex_to_bytes accepts uppercase hex characters.
 *
 * Hex parsing must be case-insensitive per convention.
 */
TEST(sha256, hex_to_bytes_uppercase)
{
	auto result = hex_to_bytes("ABCD");
	ASSERT_TRUE(result.is_ok());
	ASSERT_EQ(result.value().size(), 2);
	EXPECT_EQ(result.value()[0], 0xAB);
	EXPECT_EQ(result.value()[1], 0xCD);
}

/**
 * @brief Verify hex_to_bytes handles mixed-case input.
 *
 * Real-world hex strings often have mixed case (e.g., from different tools).
 */
TEST(sha256, hex_to_bytes_mixed_case)
{
	auto result = hex_to_bytes("aB1C");
	ASSERT_TRUE(result.is_ok());
	ASSERT_EQ(result.value().size(), 2);
	EXPECT_EQ(result.value()[0], 0xAB);
	EXPECT_EQ(result.value()[1], 0x1C);
}

/**
 * @brief Verify hex_to_bytes rejects odd-length strings.
 *
 * Hex strings must have even length (2 chars per byte).
 * Odd-length strings are malformed and must be rejected.
 */
TEST(sha256, hex_to_bytes_odd_length_fails)
{
	auto result = hex_to_bytes("abc");
	EXPECT_FALSE(result.is_ok());
}

/**
 * @brief Verify hex_to_bytes rejects invalid hex characters.
 *
 * Only 0-9, a-f, A-F are valid hex characters.
 * Invalid characters must cause parsing to fail.
 */
TEST(sha256, hex_to_bytes_invalid_char_fails)
{
	auto result = hex_to_bytes("ghij");
	EXPECT_FALSE(result.is_ok());
}

/**
 * @brief Verify bytes_to_hex and hex_to_bytes are perfect inverses.
 *
 * This is a critical property for bundle verification:
 * hash -> hex -> bytes -> hex must produce original.
 */
TEST(sha256, roundtrip_hex_conversion)
{
	uint8_t original[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
	std::string hex = bytes_to_hex(original, 6);
	auto result = hex_to_bytes(hex);
	ASSERT_TRUE(result.is_ok());
	ASSERT_EQ(result.value().size(), 6);
	for (size_t i = 0; i < 6; ++i) {
		EXPECT_EQ(result.value()[i], original[i]) << "Mismatch at byte " << i;
	}
}

//==============================================================================
// SHA-256 Hash Tests (Known Test Vectors from NIST FIPS 180-4)
//==============================================================================

/**
 * @brief Verify SHA-256 of empty string matches NIST test vector.
 *
 * NIST FIPS 180-4 Test Vector:
 * Message: "" (empty)
 * Digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 *
 * This is a critical baseline test.
 */
TEST(sha256, hash_empty_string)
{
	auto result = sha256_hex(std::string_view(""));
	ASSERT_TRUE(result.is_ok());

	EXPECT_EQ(result.value(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		<< "SHA-256 of empty string does not match NIST test vector";
	EXPECT_EQ(result.value().size(), SHA256_HEX_LENGTH);
}

/**
 * @brief Verify SHA-256 of "abc" matches NIST test vector.
 *
 * NIST FIPS 180-4 Test Vector:
 * Message: "abc"
 * Digest: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
TEST(sha256, hash_abc)
{
	auto result = sha256_hex(std::string_view("abc"));
	ASSERT_TRUE(result.is_ok());

	EXPECT_EQ(result.value(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
		<< "SHA-256 of 'abc' does not match NIST test vector";
	EXPECT_EQ(result.value().size(), SHA256_HEX_LENGTH);
}

/**
 * @brief Verify SHA-256 of the 112-byte FIPS message matches its test vector.
 *
 * The input crosses the 64-byte compression-block boundary and therefore
 * exercises incremental processing inside the one-shot provider call.
 */
TEST(sha256, hash_longer_string)
{
	constexpr std::string_view INPUT = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
					   "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	static_assert(INPUT.size() == 112u);
	auto result = sha256_hex(INPUT);
	ASSERT_TRUE(result.is_ok());

	EXPECT_EQ(result.value(), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
		<< "SHA-256 of the 112-byte FIPS message does not match its test vector";
	EXPECT_EQ(result.value().size(), SHA256_HEX_LENGTH);
}

/**
 * @brief Verify SHA-256 produces deterministic output.
 *
 * The same input must always produce the same output.
 * Non-deterministic hashing would break content-addressable storage.
 */
TEST(sha256, deterministic_output)
{
	auto result1 = sha256_hex(std::string_view("test data"));
	auto result2 = sha256_hex(std::string_view("test data"));
	ASSERT_TRUE(result1.is_ok());
	ASSERT_TRUE(result2.is_ok());
	EXPECT_EQ(result1.value(), result2.value()) << "SHA-256 must be deterministic";
}

/**
 * @brief Verify file hash matches buffer hash.
 */
TEST(sha256, file_hash_matches_buffer_hash)
{
	const std::string content = "file hash test payload";
	scoped_hash_file file(content);
	ASSERT_TRUE(file.valid());

	auto file_hash = sha256_file_hex(file.path());
	auto buffer_hash = sha256_hex(content);

	ASSERT_TRUE(file_hash.is_ok()) << file_hash.error().message();
	ASSERT_TRUE(buffer_hash.is_ok()) << buffer_hash.error().message();
	EXPECT_EQ(file_hash.value(), buffer_hash.value());
}

/**
 * @brief Verify file hash and size matches buffer hash and size.
 */
TEST(sha256, file_hash_and_size_matches_buffer_hash_and_size)
{
	const std::string content = "file hash and size payload";
	scoped_hash_file file(content);
	ASSERT_TRUE(file.valid());

	auto file_hash = sha256_file_hex_and_size(file.path());
	auto buffer_hash = sha256_hex(content);

	ASSERT_TRUE(file_hash.is_ok()) << file_hash.error().message();
	ASSERT_TRUE(buffer_hash.is_ok()) << buffer_hash.error().message();
	EXPECT_EQ(file_hash.value().sha256_hex, buffer_hash.value());
	EXPECT_EQ(file_hash.value().size_bytes, static_cast<uint64_t>(content.size()));
}

/**
 * @brief Verify file hash and size missing file returns not found.
 */
TEST(sha256, file_hash_and_size_missing_file_returns_not_found)
{
	scoped_hash_file file("");
	ASSERT_TRUE(file.valid());
	ASSERT_TRUE(file.remove_now());

	auto file_hash = sha256_file_hex_and_size(file.path());
	ASSERT_FALSE(file_hash.is_ok());
	EXPECT_EQ(file_hash.error().code(), status_code::NOT_FOUND);
}

/**
 * @brief Verify file hashing rejects an embedded null before opening a path.
 */
TEST(sha256, file_hash_rejects_embedded_null_path)
{
	std::string path = "/tmp/kinetum_sha256_embedded_null";
	path.push_back('\0');
	path.append("ignored_suffix");

	auto file_hash = sha256_file_hex_and_size(path);
	ASSERT_FALSE(file_hash.is_ok());
	EXPECT_EQ(file_hash.error().code(), status_code::INVALID_ARGUMENT);
}

/** @brief Prove two distinct fixtures do not expose a constant-output defect. */
TEST(sha256, different_inputs_different_hashes)
{
	auto result1 = sha256_hex(std::string_view("input1"));
	auto result2 = sha256_hex(std::string_view("input2"));
	ASSERT_TRUE(result1.is_ok());
	ASSERT_TRUE(result2.is_ok());
	EXPECT_NE(result1.value(), result2.value()) << "Different inputs should produce different hashes";
}

//==============================================================================
// Raw Digest Tests
//==============================================================================

/**
 * @brief Verify raw digest has correct length (32 bytes for SHA-256).
 */
TEST(sha256, raw_digest_length)
{
	auto result = sha256_raw("test");
	ASSERT_TRUE(result.is_ok());
	EXPECT_EQ(result.value().size(), SHA256_DIGEST_SIZE)
		<< "SHA-256 raw digest must be " << SHA256_DIGEST_SIZE << " bytes";
}

/**
 * @brief Verify raw and hex outputs are consistent.
 *
 * sha256_raw and sha256_hex must produce equivalent results
 * (raw bytes converted to hex should match hex output).
 */
TEST(sha256, raw_and_hex_match)
{
	std::string input = "test data for verification";
	auto hex_result = sha256_hex(input);
	auto raw_result = sha256_raw(input);
	ASSERT_TRUE(hex_result.is_ok());
	ASSERT_TRUE(raw_result.is_ok());

	std::string raw_as_hex = bytes_to_hex(raw_result.value().data(), raw_result.value().size());
	EXPECT_EQ(hex_result.value(), raw_as_hex) << "Raw and hex outputs must be consistent";
}

//==============================================================================
// Incremental Hasher Tests
//==============================================================================

/**
 * @brief Verify hasher with single update matches direct hash.
 *
 * Baseline: single-update hasher must match sha256_hex.
 */
TEST(sha256, hasher_single_update)
{
	sha256_hasher hasher;
	hasher.update("test data");
	auto result = hasher.finalize_hex();

	auto direct_result = sha256_hex(std::string_view("test data"));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_TRUE(direct_result.is_ok());
	EXPECT_EQ(result.value(), direct_result.value()) << "Single-update hasher must match direct hash";
}

/**
 * @brief Verify hasher with multiple updates matches concatenated input.
 *
 * Critical for streaming hash computation:
 * update("a") + update("b") must equal hash("ab").
 */
TEST(sha256, hasher_multiple_updates)
{
	sha256_hasher hasher;
	hasher.update("test ");
	hasher.update("data");
	auto result = hasher.finalize_hex();

	auto direct_result = sha256_hex(std::string("test data"));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_TRUE(direct_result.is_ok());
	EXPECT_EQ(result.value(), direct_result.value()) << "Multiple updates must equal concatenated input hash";
}

/**
 * @brief Verify hasher auto-resets after finalize.
 *
 * Hasher must be reusable after finalize without explicit reset.
 * This avoids reconstructing provider state across repeated cold-path hashes.
 */
TEST(sha256, hasher_reset_and_reuse)
{
	sha256_hasher hasher;
	hasher.update("first input");
	auto first_result = hasher.finalize_hex();
	ASSERT_TRUE(first_result.is_ok()) << first_result.error().message();

	hasher.update("second input");
	auto result = hasher.finalize_hex();

	auto direct_result = sha256_hex(std::string("second input"));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_TRUE(direct_result.is_ok());
	EXPECT_EQ(result.value(), direct_result.value()) << "Hasher must be reusable after finalize";
}

/**
 * @brief Verify explicit reset discards accumulated state.
 *
 * Reset must discard all previous update() calls.
 */
TEST(sha256, hasher_explicit_reset)
{
	sha256_hasher hasher;
	hasher.update("partial data");
	hasher.reset();	 // Discard previous updates.
	hasher.update("fresh start");
	auto result = hasher.finalize_hex();

	auto direct_result = sha256_hex(std::string("fresh start"));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_TRUE(direct_result.is_ok());
	EXPECT_EQ(result.value(), direct_result.value()) << "Reset must discard accumulated state";
}

/**
 * @brief Verify finalize_raw returns correct length.
 */
TEST(sha256, hasher_finalize_raw)
{
	sha256_hasher hasher;
	hasher.update("test");
	auto raw = hasher.finalize_raw();

	ASSERT_TRUE(raw.is_ok()) << raw.error().message();
	EXPECT_EQ(raw.value().size(), SHA256_DIGEST_SIZE)
		<< "finalize_raw must return " << SHA256_DIGEST_SIZE << " bytes";
}

/**
 * @brief Verify move operations transfer exact stream ownership and permit reset.
 *
 * Move construction and assignment must preserve the source's accumulated
 * bytes in the destination. A moved-from stream fails finalization explicitly
 * until reset creates a new provider context, after which it is reusable.
 */
TEST(sha256, hasher_move_transfers_state_and_moved_from_reset_recovers)
{
	sha256_hasher constructor_source;
	constructor_source.update("move-constructed content");
	sha256_hasher move_constructed(std::move(constructor_source));

	auto constructed_result = move_constructed.finalize_hex();
	auto constructed_expected = sha256_hex(std::string_view("move-constructed content"));
	ASSERT_TRUE(constructed_result.is_ok()) << constructed_result.error().message();
	ASSERT_TRUE(constructed_expected.is_ok()) << constructed_expected.error().message();
	EXPECT_EQ(constructed_result.value(), constructed_expected.value());

	constructor_source.update("must not enter a moved-from stream");
	auto moved_from_result = constructor_source.finalize_raw();
	ASSERT_FALSE(moved_from_result.is_ok());
	EXPECT_EQ(moved_from_result.error().code(), status_code::FAILED_PRECONDITION);
	constructor_source.reset();
	constructor_source.update("constructor source recovered");
	auto constructor_recovered = constructor_source.finalize_hex();
	auto constructor_recovered_expected = sha256_hex(std::string_view("constructor source recovered"));
	ASSERT_TRUE(constructor_recovered.is_ok()) << constructor_recovered.error().message();
	ASSERT_TRUE(constructor_recovered_expected.is_ok()) << constructor_recovered_expected.error().message();
	EXPECT_EQ(constructor_recovered.value(), constructor_recovered_expected.value());

	sha256_hasher assignment_source;
	assignment_source.update("move-assigned content");
	sha256_hasher move_assigned;
	move_assigned.update("discarded destination content");
	move_assigned = std::move(assignment_source);

	auto assigned_result = move_assigned.finalize_hex();
	auto assigned_expected = sha256_hex(std::string_view("move-assigned content"));
	ASSERT_TRUE(assigned_result.is_ok()) << assigned_result.error().message();
	ASSERT_TRUE(assigned_expected.is_ok()) << assigned_expected.error().message();
	EXPECT_EQ(assigned_result.value(), assigned_expected.value());

	auto assigned_source_result = assignment_source.finalize_raw();
	ASSERT_FALSE(assigned_source_result.is_ok());
	EXPECT_EQ(assigned_source_result.error().code(), status_code::FAILED_PRECONDITION);
	assignment_source.reset();
	assignment_source.update("assignment source recovered");
	auto assignment_recovered = assignment_source.finalize_hex();
	auto assignment_recovered_expected = sha256_hex(std::string_view("assignment source recovered"));
	ASSERT_TRUE(assignment_recovered.is_ok()) << assignment_recovered.error().message();
	ASSERT_TRUE(assignment_recovered_expected.is_ok()) << assignment_recovered_expected.error().message();
	EXPECT_EQ(assignment_recovered.value(), assignment_recovered_expected.value());
}

//==============================================================================
// Provider Failure Test
//==============================================================================

/**
 * @brief Verify an invalid binary range fails instead of reaching OpenSSL.
 */
TEST(sha256, null_nonzero_input_fails_explicitly)
{
	EXPECT_DEATH(static_cast<void>(bytes_to_hex(nullptr, 1)), "");

	auto result = sha256_raw(nullptr, 1);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);

	sha256_hasher hasher;
	hasher.update(nullptr, 1);
	auto streamed_result = hasher.finalize_raw();
	ASSERT_FALSE(streamed_result.is_ok());
	EXPECT_EQ(streamed_result.error().code(), status_code::INVALID_ARGUMENT);

	// Finalization resets a failed stream so the object remains reusable.
	hasher.update("recovered");
	auto recovered_result = hasher.finalize_raw();
	EXPECT_TRUE(recovered_result.is_ok());
}

/**
 * @brief Verify hexadecimal output rejects unrepresentable size arithmetic.
 */
TEST(sha256, bytes_to_hex_rejects_unrepresentable_output_size)
{
	const uint8_t byte = 0;
	EXPECT_THROW(static_cast<void>(bytes_to_hex(&byte, std::numeric_limits<std::size_t>::max())),
		     std::length_error);
}

}  // namespace kinetum::common
