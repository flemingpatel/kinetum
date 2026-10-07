// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file ed25519.cpp
 * @brief Exact OpenSSL-backed Ed25519 signature implementation.
 * @author Fleming Patel
 */

#include "src/common/ed25519.hpp"

#include <memory>

#include <openssl/evp.h>

namespace kinetum::common
{
namespace
{

/** @brief EVP key deleter for unique ownership. */
struct evp_pkey_deleter {
	/**
	 * @brief Release one OpenSSL key object.
	 * @param key Sole key handle transferred for release, or nullptr.
	 */
	void operator()(EVP_PKEY *key) const noexcept
	{
		EVP_PKEY_free(key);
	}
};

/** @brief EVP message-digest context deleter for unique ownership. */
struct evp_md_context_deleter {
	/**
	 * @brief Release one OpenSSL message-digest context.
	 * @param context Sole context handle transferred for release, or nullptr.
	 */
	void operator()(EVP_MD_CTX *context) const noexcept
	{
		EVP_MD_CTX_free(context);
	}
};

/** Sole OpenSSL key ownership with matching EVP reclamation. */
using unique_evp_pkey = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
/** Sole signing/verification context ownership with matching EVP reclamation. */
using unique_evp_md_context = std::unique_ptr<EVP_MD_CTX, evp_md_context_deleter>;

/** Stable non-null address supplied to OpenSSL for an empty message. */
constexpr uint8_t EMPTY_MESSAGE_BYTE = 0;

/**
 * @brief Return a stable message pointer, including for an empty span.
 *
 * OpenSSL accepts a zero byte count, but keeping the pointer non-null avoids
 * making its provider implementation responsible for interpreting a null
 * address whose length is zero.
 *
 * @param message Exact caller-owned message span.
 * @return First message byte, or a stable dummy address for an empty span.
 */
const uint8_t *message_data(std::span<const uint8_t> message) noexcept
{
	return message.empty() ? &EMPTY_MESSAGE_BYTE : message.data();
}

/**
 * @brief Construct one OpenSSL Ed25519 key from a raw private seed.
 *
 * @param private_key Exact private seed.
 * @return Unique key object, or an explicit OpenSSL failure.
 */
status_or<unique_evp_pkey> make_private_key(const ed25519_private_key &private_key)
{
	unique_evp_pkey key(
		EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size()));
	if (!key) {
		return status::internal_error("OpenSSL could not construct an Ed25519 private key");
	}
	return key;
}

/**
 * @brief Construct one OpenSSL Ed25519 key from raw public bytes.
 *
 * @param public_key Exact public key.
 * @return Unique key object, or an explicit OpenSSL failure.
 */
status_or<unique_evp_pkey> make_public_key(const ed25519_public_key &public_key)
{
	unique_evp_pkey key(
		EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size()));
	if (!key) {
		return status::internal_error("OpenSSL could not construct an Ed25519 public key");
	}
	return key;
}

}  // namespace

status_or<ed25519_public_key> ed25519_derive_public_key(const ed25519_private_key &private_key)
{
	auto key_or = make_private_key(private_key);
	if (!key_or.is_ok()) {
		return key_or.error();
	}

	ed25519_public_key public_key{};
	std::size_t size = public_key.size();
	if (EVP_PKEY_get_raw_public_key(key_or->get(), public_key.data(), &size) != 1 || size != public_key.size()) {
		return status::internal_error("OpenSSL could not derive an exact Ed25519 public key");
	}
	return public_key;
}

status_or<ed25519_signature> ed25519_sign(const ed25519_private_key &private_key, std::span<const uint8_t> message)
{
	auto key_or = make_private_key(private_key);
	if (!key_or.is_ok()) {
		return key_or.error();
	}

	unique_evp_md_context context(EVP_MD_CTX_new());
	if (!context) {
		return status::resource_exhausted("OpenSSL could not allocate an Ed25519 signing context");
	}
	if (EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key_or->get()) != 1) {
		return status::internal_error("OpenSSL could not initialize Ed25519 signing");
	}

	ed25519_signature signature{};
	std::size_t size = signature.size();
	if (EVP_DigestSign(context.get(), signature.data(), &size, message_data(message), message.size()) != 1 ||
	    size != signature.size()) {
		return status::internal_error("OpenSSL could not produce an exact Ed25519 signature");
	}
	return signature;
}

status ed25519_verify(const ed25519_public_key &public_key, std::span<const uint8_t> message,
		      const ed25519_signature &signature)
{
	auto key_or = make_public_key(public_key);
	if (!key_or.is_ok()) {
		return key_or.error();
	}

	unique_evp_md_context context(EVP_MD_CTX_new());
	if (!context) {
		return status::resource_exhausted("OpenSSL could not allocate an Ed25519 verification context");
	}
	if (EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key_or->get()) != 1) {
		return status::internal_error("OpenSSL could not initialize Ed25519 verification");
	}

	const int result = EVP_DigestVerify(context.get(), signature.data(), signature.size(), message_data(message),
					    message.size());
	if (result == 1) {
		return status::ok();
	}
	if (result == 0) {
		return status::unauthenticated("Ed25519 signature verification failed");
	}
	return status::internal_error("OpenSSL failed while verifying an Ed25519 signature");
}

}  // namespace kinetum::common
