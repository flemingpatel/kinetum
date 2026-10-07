// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file sha256.cpp
 * @brief Mandatory OpenSSL-backed SHA-256 implementation.
 * @author Fleming Patel
 *
 * Cryptographic content identity is a platform invariant rather than a TLS
 * capability. Every build links OpenSSL::Crypto and every hashing entry point
 * returns an explicit failure if OpenSSL cannot produce the requested digest.
 * Incremental streams retain the first input or provider failure and expose it
 * at finalization; no failure selects another hash algorithm or an empty digest.
 *
 * @par Thread Safety
 * One-shot operations have no shared mutable platform state and may run
 * concurrently. Each `sha256_hasher` and its OpenSSL context have one owner;
 * update, finalization, reset, move, and destruction must not race on the same
 * instance.
 *
 * @par Performance
 * Hashing, hexadecimal conversion, file I/O, provider allocation, and status
 * construction are cold-path operations. This implementation is not permitted
 * on a packet worker or module packet callback.
 */

#include "src/common/sha256.hpp"

#include <array>
#include <exception>
#include <fstream>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "src/common/status.hpp"

namespace kinetum::common
{

namespace
{

/** Canonical lowercase hexadecimal alphabet for digest serialization. */
constexpr char HEX_CHARS[] = "0123456789abcdef";

/**
 * @brief Return a non-null byte pointer for an empty OpenSSL input.
 *
 * OpenSSL accepts a zero-length input, but using a stable byte address keeps
 * the contract explicit when an empty string_view exposes a null data pointer.
 *
 * @param data Caller-provided binary input pointer.
 * @param len Caller-provided input length.
 * @return @p data for non-empty input, otherwise a stable empty-input address.
 */
[[nodiscard]] const unsigned char *openssl_input(const void *data, std::size_t len) noexcept
{
	static constexpr unsigned char EMPTY_INPUT = 0;
	if (len == 0) {
		return &EMPTY_INPUT;
	}
	return static_cast<const unsigned char *>(data);
}

}  // namespace

std::string bytes_to_hex(const uint8_t *bytes, std::size_t len)
{
	if (bytes == nullptr && len != 0u) {
		std::terminate();
	}
	std::string result;
	if (len > result.max_size() / 2u) {
		throw std::length_error("hexadecimal output exceeds string size limits");
	}
	result.reserve(len * 2);
	for (std::size_t i = 0; i < len; ++i) {
		result.push_back(HEX_CHARS[bytes[i] >> 4]);
		result.push_back(HEX_CHARS[bytes[i] & 0x0fu]);
	}
	return result;
}

status_or<std::vector<uint8_t>> hex_to_bytes(std::string_view hex)
{
	try {
		if (hex.size() % 2 != 0) {
			return status::invalid_argument("hex string must have even length");
		}

		std::vector<uint8_t> result;
		result.reserve(hex.size() / 2);

		const auto hex_value = [](char value) -> int {
			if (value >= '0' && value <= '9') {
				return value - '0';
			}
			if (value >= 'a' && value <= 'f') {
				return value - 'a' + 10;
			}
			if (value >= 'A' && value <= 'F') {
				return value - 'A' + 10;
			}
			return -1;
		};

		for (std::size_t i = 0; i < hex.size(); i += 2) {
			const int high = hex_value(hex[i]);
			const int low = hex_value(hex[i + 1]);
			if (high < 0 || low < 0) {
				return status::invalid_argument("invalid hex character");
			}
			result.push_back(static_cast<uint8_t>((high << 4) | low));
		}

		return result;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("hexadecimal decoding exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("hexadecimal decoding exceeded host size limits"));
	}
}

status_or<sha256_digest> sha256_raw(const void *data, std::size_t len)
{
	if (data == nullptr && len != 0) {
		return status::invalid_argument("SHA-256 input pointer is null for nonzero length");
	}

	sha256_digest digest{};
	if (SHA256(openssl_input(data, len), len, digest.data()) == nullptr) {
		return status::internal_error("OpenSSL failed to compute SHA-256 digest");
	}
	return digest;
}

status_or<sha256_digest> sha256_raw(std::string_view data)
{
	return sha256_raw(data.data(), data.size());
}

status_or<std::string> sha256_hex(const void *data, std::size_t len)
{
	try {
		auto digest_or = sha256_raw(data, len);
		if (!digest_or.is_ok()) {
			return std::move(digest_or).error();
		}
		const auto &digest = digest_or.value();
		return bytes_to_hex(digest.data(), digest.size());
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("SHA-256 hexadecimal encoding exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("SHA-256 hexadecimal encoding exceeded host size limits"));
	}
}

status_or<std::string> sha256_hex(std::string_view data)
{
	return sha256_hex(data.data(), data.size());
}

status_or<std::string> sha256_hex(const std::string &data)
{
	return sha256_hex(data.data(), data.size());
}

status_or<file_hash_result> sha256_file_hex_and_size(const std::string &path)
{
	try {
		if (path.find('\0') != std::string::npos) {
			return status::invalid_argument("SHA-256 file path contains a null byte");
		}
		std::ifstream input(path, std::ios::binary);
		if (!input) {
			return status(status_code::NOT_FOUND, "failed to open file", path);
		}

		sha256_hasher hasher;
		std::array<char, std::size_t{64} * 1024u> buffer{};
		uint64_t bytes_read = 0;
		while (input) {
			input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
			const std::streamsize count = input.gcount();
			if (count > 0) {
				hasher.update(buffer.data(), static_cast<std::size_t>(count));
				const auto chunk_size = static_cast<uint64_t>(count);
				if (bytes_read > std::numeric_limits<uint64_t>::max() - chunk_size) {
					return status(status_code::RESOURCE_EXHAUSTED, "file too large to hash", path);
				}
				bytes_read += chunk_size;
			}
		}

		if (input.bad()) {
			return status(status_code::INTERNAL_ERROR, "failed to read file", path);
		}

		auto hex_or = hasher.finalize_hex();
		if (!hex_or.is_ok()) {
			return status(hex_or.error().code(), "SHA-256 file hash failed",
				      path + ": " + std::string(hex_or.error().message()));
		}
		return file_hash_result{std::move(hex_or).value(), bytes_read};
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("SHA-256 file hashing exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("SHA-256 file hashing exceeded host size limits"));
	}
}

status_or<std::string> sha256_file_hex(const std::string &path)
{
	auto result_or = sha256_file_hex_and_size(path);
	if (!result_or.is_ok()) {
		return std::move(result_or).error();
	}
	return std::move(result_or).value().sha256_hex;
}

/**
 * @brief Unique OpenSSL state owned by one incremental hasher.
 *
 * The implementation owns exactly one EVP context and one retained failure.
 * No state is shared across hasher instances, and provider errors remain
 * observable until finalization or explicit reset.
 * The owning `sha256_hasher` is the only thread permitted to mutate this state.
 */
struct sha256_hasher::impl {
	EVP_MD_CTX *context{nullptr};  ///< Uniquely owned OpenSSL digest context.
	status failure{};	       ///< First retained input/provider failure.

	/**
	 * @brief Allocate and initialize one SHA-256 provider context.
	 *
	 * Allocation or provider initialization failure is retained for explicit
	 * return by finalize(); construction does not throw a platform status away
	 * or substitute another digest algorithm.
	 */
	impl()
	{
		reset();
	}

	/**
	 * @brief Release the OpenSSL provider context owned by this stream.
	 *
	 * Buffered input is intentionally not finalized during destruction.
	 */
	~impl()
	{
		if (context != nullptr) {
			EVP_MD_CTX_free(context);
		}
	}

	/**
	 * @brief Retain the first stream failure until reset or finalization.
	 *
	 * @param error Failure to retain.
	 */
	void retain_failure(status error)
	{
		if (failure.is_ok()) {
			failure = std::move(error);
		}
	}

	/**
	 * @brief Add one binary range to the OpenSSL stream.
	 *
	 * The first invalid-input or provider failure is retained. Later updates do
	 * not overwrite that diagnostic and finalization returns it before resetting
	 * the stream.
	 *
	 * @param data Pointer to the first byte.
	 * @param len Number of bytes to add.
	 */
	void update(const void *data, std::size_t len)
	{
		if (!failure.is_ok()) {
			return;
		}
		if (data == nullptr && len != 0) {
			retain_failure(status::invalid_argument("SHA-256 input pointer is null for nonzero length"));
			return;
		}
		if (len == 0) {
			return;
		}
		if (EVP_DigestUpdate(context, data, len) != 1) {
			retain_failure(status::internal_error("OpenSSL failed to update SHA-256 digest"));
		}
	}

	/**
	 * @brief Finalize the exact digest and reinitialize the stream for reuse.
	 *
	 * @return Fixed SHA-256 digest, or the retained provider/input failure.
	 */
	status_or<sha256_digest> finalize()
	{
		if (!failure.is_ok()) {
			status retained = failure;
			reset();
			return retained;
		}

		sha256_digest digest{};
		unsigned int digest_size = 0;
		if (EVP_DigestFinal_ex(context, digest.data(), &digest_size) != 1) {
			const auto error = status::internal_error("OpenSSL failed to finalize SHA-256 digest");
			reset();
			return error;
		}
		if (digest_size != SHA256_DIGEST_SIZE) {
			const auto error = status::internal_error("OpenSSL returned an invalid SHA-256 digest width");
			reset();
			return error;
		}

		reset();
		if (!failure.is_ok()) {
			return failure;
		}
		return digest;
	}

	/**
	 * @brief Discard accumulated input and initialize a clean SHA-256 stream.
	 *
	 * The method retries context allocation when initial allocation failed. Any
	 * failure encountered while reinitializing becomes the stream's retained
	 * failure and is returned by the next finalization.
	 */
	void reset()
	{
		failure = status::ok();
		if (context == nullptr) {
			context = EVP_MD_CTX_new();
			if (context == nullptr) {
				failure = status::resource_exhausted("OpenSSL could not allocate a SHA-256 context");
				return;
			}
		}
		if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
			failure = status::internal_error("OpenSSL could not initialize a SHA-256 context");
		}
	}
};

sha256_hasher::sha256_hasher()
	: impl_(std::make_unique<impl>())
{
}

sha256_hasher::~sha256_hasher() = default;

sha256_hasher::sha256_hasher(sha256_hasher &&other) noexcept = default;

sha256_hasher &sha256_hasher::operator=(sha256_hasher &&other) noexcept = default;

void sha256_hasher::update(std::string_view data)
{
	if (impl_ != nullptr) {
		impl_->update(data.data(), data.size());
	}
}

void sha256_hasher::update(const void *data, std::size_t len)
{
	if (impl_ != nullptr) {
		impl_->update(data, len);
	}
}

status_or<std::string> sha256_hasher::finalize_hex()
{
	try {
		auto digest_or = finalize_raw();
		if (!digest_or.is_ok()) {
			return std::move(digest_or).error();
		}
		const auto &digest = digest_or.value();
		return bytes_to_hex(digest.data(), digest.size());
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("SHA-256 hexadecimal encoding exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("SHA-256 hexadecimal encoding exceeded host size limits"));
	}
}

status_or<sha256_digest> sha256_hasher::finalize_raw()
{
	if (impl_ == nullptr) {
		return status::failed_precondition("cannot finalize a moved-from SHA-256 stream");
	}
	return impl_->finalize();
}

void sha256_hasher::reset()
{
	if (impl_ == nullptr) {
		impl_ = std::make_unique<impl>();
		return;
	}
	impl_->reset();
}

}  // namespace kinetum::common
