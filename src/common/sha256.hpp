// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file sha256.hpp
 * @brief SHA-256 hashing utilities.
 * @author Fleming Patel
 *
 * Provides exact SHA-256 content identity for:
 * - Bundle integrity verification
 * - Content-addressable storage
 * - Deterministic ID generation
 *
 * @section security_notes Security Notes
 *
 * OpenSSL::Crypto is a mandatory build dependency. Every function in this
 * module therefore computes genuine SHA-256; there is no build-dependent hash
 * fallback or capability-probe path.
 *
 * @par Thread Safety
 * One-shot functions are thread-safe. A `sha256_hasher` has one owner and must
 * not be updated, finalized, or reset concurrently.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/sha256_digest.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Hash result for a file read through one stream.
 *
 * `size_bytes` is the number of bytes that were read and fed to the
 * hasher. Callers that verify file integrity should use this value instead
 * of performing a separate size query after hashing.
 */
struct file_hash_result {
	std::string sha256_hex;	 ///< Exact 64-character lowercase SHA-256 digest.
	uint64_t size_bytes{0};	 ///< Bytes read through the same hashing stream.
};

// =============================================================================
// Core Functions
// =============================================================================

/**
 * @brief Compute SHA-256 hash of data and return as lowercase hex string.
 *
 * @param data Input data to hash.
 * @return A 64-character lowercase hexadecimal digest, or an explicit
 *         allocation or provider failure.
 */
[[nodiscard]] status_or<std::string> sha256_hex(std::string_view data);

/**
 * @brief Compute SHA-256 hash of data and return as lowercase hex string.
 *
 * @param data Input data to hash.
 * @return A 64-character lowercase hexadecimal digest, or an explicit
 *         allocation or provider failure.
 */
[[nodiscard]] status_or<std::string> sha256_hex(const std::string &data);

/**
 * @brief Compute SHA-256 hash of binary data and return as lowercase hex string.
 *
 * @param data Pointer to the first byte. May be null only when @p len is zero.
 * @param len Length of data in bytes.
 * @return A 64-character lowercase hexadecimal digest, or INVALID_ARGUMENT for
 *         an invalid range, RESOURCE_EXHAUSTED or OUT_OF_RANGE when hexadecimal
 *         output cannot be represented, and an explicit provider failure
 *         otherwise.
 */
[[nodiscard]] status_or<std::string> sha256_hex(const void *data, std::size_t len);

/**
 * @brief Compute SHA-256 hash of a file and return as lowercase hex string.
 *
 * @param path Path to the file; embedded null bytes are invalid.
 * @return A 64-character lowercase hexadecimal digest, or an explicit path,
 *         open, read, size, allocation, representation, or provider failure.
 */
[[nodiscard]] status_or<std::string> sha256_file_hex(const std::string &path);

/**
 * @brief Compute SHA-256 hash of a file and return the bytes read.
 *
 * Opens the file once, streams its content through the hasher, and reports the
 * byte count observed by that same read. This is the preferred primitive for
 * bundle verification because hash and size describe the same file stream.
 *
 * @param path Path to the file; embedded null bytes are invalid.
 * @return Hexadecimal digest plus byte count, or an explicit path, open, read,
 *         size, allocation, representation, or provider failure.
 */
[[nodiscard]] status_or<file_hash_result> sha256_file_hex_and_size(const std::string &path);

// =============================================================================
// Raw Digest Functions
// =============================================================================

/**
 * @brief Compute SHA-256 hash and return raw bytes.
 *
 * @param data Input data to hash.
 * @return Exact 32-byte digest, or an explicit provider failure.
 */
[[nodiscard]] status_or<sha256_digest> sha256_raw(std::string_view data);

/**
 * @brief Compute SHA-256 hash of binary data and return raw bytes.
 *
 * @param data Pointer to the first byte. May be null only when @p len is zero.
 * @param len Length of data in bytes.
 * @return Exact 32-byte digest, or INVALID_ARGUMENT for an invalid range and
 *         an explicit provider failure otherwise.
 */
[[nodiscard]] status_or<sha256_digest> sha256_raw(const void *data, std::size_t len);

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * @brief Convert raw bytes to lowercase hex string.
 *
 * Preserves every leading zero byte and emits exactly two characters per input
 * byte.
 *
 * @param bytes Raw byte data. May be null only when @p len is zero.
 * @param len Length of data.
 * @return Lowercase hexadecimal string containing two characters per byte.
 * @throws std::bad_alloc when output storage cannot be allocated.
 * @throws std::length_error when twice @p len cannot be represented by the
 *         output string.
 * @pre A null pointer is valid only when @p len is zero. Violation terminates.
 */
[[nodiscard]] std::string bytes_to_hex(const uint8_t *bytes, std::size_t len);

/**
 * @brief Convert hex string to raw bytes.
 *
 * Both uppercase and lowercase hexadecimal digits are accepted. Identity-claim
 * validators apply their stricter lowercase-only contract before comparison.
 *
 * @param hex Hexadecimal string with an even character count.
 * @return Decoded bytes, INVALID_ARGUMENT for malformed input,
 *         RESOURCE_EXHAUSTED for allocation failure, or OUT_OF_RANGE when the
 *         decoded representation exceeds host limits.
 */
[[nodiscard]] status_or<std::vector<uint8_t>> hex_to_bytes(std::string_view hex);

// =============================================================================
// Incremental Hashing
// =============================================================================

/**
 * @brief Incremental SHA-256 hasher for streaming data.
 *
 * Usage:
 *   sha256_hasher hasher;
 *   hasher.update("chunk1");
 *   hasher.update("chunk2");
 *   auto hash_or = hasher.finalize_hex();
 *
 * @par Thread Safety
 * One owner may update, finalize, or reset an instance. Concurrent operations
 * on the same instance are not permitted.
 */
class sha256_hasher {
    public:
	/**
	 * @brief Construct a uniquely owned incremental SHA-256 stream.
	 *
	 * OpenSSL allocation or initialization failure is retained inside the
	 * stream and returned by the first finalization. Construction never selects
	 * another hash implementation.
	 *
	 * @throws std::bad_alloc If storage for the private stream owner cannot be
	 *         allocated.
	 */
	sha256_hasher();

	/**
	 * @brief Release the uniquely owned OpenSSL digest context.
	 *
	 * Destruction does not finalize buffered input and transfers no digest or
	 * provider ownership to another object.
	 */
	~sha256_hasher();

	/**
	 * @brief Prevent two owners from mutating one logical digest stream.
	 *
	 * Copy construction is deleted because duplicating an opaque provider
	 * context would make stream ownership and finalization ambiguous.
	 */
	sha256_hasher(const sha256_hasher &) = delete;

	/**
	 * @brief Prevent copy assignment of mutable digest state.
	 *
	 * Use move assignment when ownership of a stream must change.
	 */
	sha256_hasher &operator=(const sha256_hasher &) = delete;

	/**
	 * @brief Transfer ownership of another stream's digest context.
	 *
	 * The moved-from stream remains destructible and may be reinitialized with
	 * reset(), but finalization before reset returns FAILED_PRECONDITION.
	 *
	 * @param other Stream whose context is transferred.
	 */
	sha256_hasher(sha256_hasher &&other) noexcept;

	/**
	 * @brief Replace this stream with another stream's digest context.
	 *
	 * Any unfinalized input currently owned by this stream is discarded when its
	 * provider context is released. The moved-from stream has the same contract
	 * as after move construction.
	 *
	 * @param other Stream whose context is transferred.
	 * @return This stream after ownership transfer.
	 */
	sha256_hasher &operator=(sha256_hasher &&other) noexcept;

	/**
	 * @brief Add a byte view to the current digest stream.
	 *
	 * A provider failure is retained and returned by the next finalization.
	 * An update on a moved-from stream is ignored; reset that stream first.
	 *
	 * @param data Bytes to append to the digest stream.
	 */
	void update(std::string_view data);

	/**
	 * @brief Add a binary byte range to the current digest stream.
	 *
	 * A provider failure is retained and returned by the next finalization.
	 * An update on a moved-from stream is ignored; reset that stream first.
	 *
	 * @param data Pointer to the first byte. May be null only when @p len is zero.
	 * @param len Number of bytes to append.
	 */
	void update(const void *data, std::size_t len);

	/**
	 * @brief Finalize and return the hash as lowercase hexadecimal.
	 *
	 * Successful finalization resets the stream for reuse.
	 *
	 * @return A 64-character lowercase digest, or an error when OpenSSL could
	 *         not complete or reset the stream or when output storage cannot be
	 *         represented.
	 */
	[[nodiscard]] status_or<std::string> finalize_hex();

	/**
	 * @brief Finalize and return the fixed-width binary digest.
	 *
	 * Successful finalization resets the stream for reuse.
	 *
	 * @return Exact 32-byte digest, or an error when OpenSSL could not complete
	 *         or reset the stream.
	 */
	[[nodiscard]] status_or<sha256_digest> finalize_raw();

	/**
	 * @brief Discard accumulated bytes and reinitialize the stream.
	 *
	 * A provider reset failure is retained and returned by the next
	 * finalization.
	 *
	 * @throws std::bad_alloc If a moved-from stream cannot allocate a new private
	 *         owner.
	 */
	void reset();

    private:
	/**
	 * @brief OpenSSL provider state hidden from public headers.
	 *
	 * The implementation retains the first update/provider failure until
	 * finalization or explicit reset and owns the EVP context exclusively.
	 */
	struct impl;
	std::unique_ptr<impl> impl_;  ///< Uniquely owned incremental digest context.
};

}  // namespace kinetum::common
