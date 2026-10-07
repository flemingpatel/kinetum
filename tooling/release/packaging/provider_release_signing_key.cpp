// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_release_signing_key.cpp
 * @brief Private release-seed generation, admission, and cleansing.
 * @author Fleming Patel
 */

#include "tooling/release/packaging/provider_release_signing_key.hpp"

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/common/status.hpp"

namespace kinetum::release
{
namespace
{

/**
 * @brief Compare key-file metadata that must remain immutable while reading.
 *
 * @param before Metadata sampled before the read.
 * @param after Metadata sampled after the read.
 * @return true only when identity and all relevant metadata agree exactly.
 */
bool stable_key_metadata(const struct stat &before, const struct stat &after) noexcept
{
	return before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
	       before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_nlink == after.st_nlink &&
	       before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
	       before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
	       before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

/**
 * @brief Cleanse one raw private seed.
 *
 * @param key Seed storage to erase.
 */
void cleanse(common::ed25519_private_key &key) noexcept
{
	OPENSSL_cleanse(key.data(), key.size());
}

/** Private entropy storage is never copied and is cleansed on every return. */
struct secret_seed {
	/** @brief Begin with fixed-width private storage. */
	secret_seed() = default;
	/** @brief Prevent unowned secret copies. */
	secret_seed(const secret_seed &) = delete;
	/** @brief Prevent unowned secret copies. */
	secret_seed &operator=(const secret_seed &) = delete;
	/** @brief Cleanse all generated private bytes. */
	~secret_seed()
	{
		cleanse(bytes);
	}
	common::ed25519_private_key bytes{};  ///< Exact seed, owned only in this scope.
};

}  // namespace

provider_release_signing_key::provider_release_signing_key(common::ed25519_private_key &key,
							   const common::ed25519_public_key &public_key) noexcept
	: key_(key)
	, public_key_(public_key)
{
	cleanse(key);
}

provider_release_signing_key::provider_release_signing_key(provider_release_signing_key &&other) noexcept
	: key_(other.key_)
	, public_key_(other.public_key_)
{
	cleanse(other.key_);
	other.public_key_.fill(0);
}

provider_release_signing_key &provider_release_signing_key::operator=(provider_release_signing_key &&other) noexcept
{
	if (this != &other) {
		cleanse(key_);
		key_ = other.key_;
		public_key_ = other.public_key_;
		cleanse(other.key_);
		other.public_key_.fill(0);
	}
	return *this;
}

provider_release_signing_key::~provider_release_signing_key()
{
	cleanse(key_);
}

const common::ed25519_private_key &provider_release_signing_key::key() const noexcept
{
	return key_;
}

const common::ed25519_public_key &provider_release_signing_key::public_key() const noexcept
{
	return public_key_;
}

common::status_or<provider_release_signing_key>
admit_provider_release_signing_key(int descriptor, uint32_t required_owner_uid,
				   const common::ed25519_public_key &expected_anchor)
{
	if (descriptor < 3) {
		return common::status::invalid_argument(
			common::static_status_text("release signing-key descriptor must not alias a standard stream"));
	}
	const int descriptor_flags = ::fcntl(descriptor, F_GETFL);
	if (descriptor_flags < 0) {
		return common::status(common::status_code::INVALID_ARGUMENT,
				      "failed to inspect release signing-key descriptor", std::strerror(errno));
	}
	if ((descriptor_flags & O_ACCMODE) != O_RDONLY) {
		return common::status::permission_denied(
			common::static_status_text("release signing-key descriptor must be read-only"));
	}

	struct stat before{};
	if (::fstat(descriptor, &before) != 0) {
		return common::status(common::status_code::INVALID_ARGUMENT,
				      "failed to inspect release signing-key metadata", std::strerror(errno));
	}
	if (!S_ISREG(before.st_mode)) {
		return common::status::failed_precondition(
			common::static_status_text("release signing key must be a regular file"));
	}
	if (static_cast<uint64_t>(before.st_uid) != static_cast<uint64_t>(required_owner_uid)) {
		return common::status::permission_denied(
			common::static_status_text("release signing-key owner does not match the release process"));
	}
	if ((static_cast<uint32_t>(before.st_mode) & 07777u) != 0400u) {
		return common::status::permission_denied(
			common::static_status_text("release signing-key mode must be exactly 0400"));
	}
	if (before.st_nlink != 1) {
		return common::status::permission_denied(
			common::static_status_text("release signing key must have exactly one hard link"));
	}
	if (before.st_size != static_cast<off_t>(common::ED25519_PRIVATE_KEY_SIZE)) {
		return common::status::invalid_argument(
			common::static_status_text("release signing key must contain exactly 32 raw bytes"));
	}

	secret_seed seed;
	auto &key = seed.bytes;
	std::size_t offset = 0;
	while (offset < key.size()) {
		const ssize_t count =
			::pread(descriptor, key.data() + offset, key.size() - offset, static_cast<off_t>(offset));
		if (count < 0) {
			if (errno == EINTR) {
				continue;
			}
			const int saved_errno = errno;
			return common::status(common::status_code::INTERNAL_ERROR, "failed to read release signing key",
					      std::strerror(saved_errno));
		}
		if (count == 0) {
			return common::status::invalid_argument(
				common::static_status_text("release signing key ended before its exact width"));
		}
		offset += static_cast<std::size_t>(count);
	}

	struct stat after{};
	if (::fstat(descriptor, &after) != 0) {
		const int saved_errno = errno;
		return common::status(common::status_code::INTERNAL_ERROR,
				      "failed to re-inspect release signing-key metadata", std::strerror(saved_errno));
	}
	if (!stable_key_metadata(before, after)) {
		return common::status::failed_precondition(
			common::static_status_text("release signing key changed while it was being read"));
	}

	auto public_key_or = common::ed25519_derive_public_key(key);
	if (!public_key_or.is_ok()) {
		return public_key_or.error();
	}
	if (CRYPTO_memcmp(public_key_or->data(), expected_anchor.data(), expected_anchor.size()) != 0) {
		return common::status::permission_denied(common::static_status_text(
			"release signing key does not derive the configured production trust anchor"));
	}
	return provider_release_signing_key(key, expected_anchor);
}

common::status protect_provider_release_key_process()
{
	const struct rlimit limit{0, 0};
	if (::setrlimit(RLIMIT_CORE, &limit) != 0 || ::prctl(PR_SET_DUMPABLE, 0) != 0) {
		return common::status(common::status_code::PERMISSION_DENIED, "cannot disable release-key core dumps",
				      std::strerror(errno));
	}
	return common::status::ok();
}

common::status_or<common::ed25519_public_key> stage_provider_release_signing_key(int descriptor)
{
	struct stat metadata{};
	const int flags = ::fcntl(descriptor, F_GETFL);
	if (flags < 0 || ::fstat(descriptor, &metadata) != 0) {
		return common::status(common::status_code::INVALID_ARGUMENT, "cannot inspect private seed output",
				      std::strerror(errno));
	}
	if (descriptor < 3 || (flags & O_ACCMODE) == O_RDONLY || !S_ISREG(metadata.st_mode) ||
	    metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 || metadata.st_size != 0 ||
	    (metadata.st_mode & 07777) != 0600) {
		return common::status::failed_precondition(common::static_status_text(
			"seed output must be one empty writable mode-0600 owner-held regular file"));
	}
	secret_seed seed;
	if (RAND_priv_bytes(seed.bytes.data(), static_cast<int>(seed.bytes.size())) != 1) {
		return common::status::internal_error(
			common::static_status_text("OpenSSL could not generate a private release seed"));
	}
	auto public_or = common::ed25519_derive_public_key(seed.bytes);
	if (!public_or.is_ok()) {
		return public_or.error();
	}
	std::size_t offset = 0;
	while (offset < seed.bytes.size()) {
		const ssize_t written = ::pwrite(descriptor, seed.bytes.data() + offset, seed.bytes.size() - offset,
						 static_cast<off_t>(offset));
		if (written < 0 && errno == EINTR) {
			continue;
		}
		if (written <= 0) {
			return common::status::internal_error(
				common::static_status_text("cannot write complete private release seed"));
		}
		offset += static_cast<std::size_t>(written);
	}
	if (::fchmod(descriptor, 0400) != 0 || ::fsync(descriptor) != 0) {
		return common::status(common::status_code::INTERNAL_ERROR, "cannot finish private release seed",
				      std::strerror(errno));
	}
	return public_or.value();
}

}  // namespace kinetum::release
