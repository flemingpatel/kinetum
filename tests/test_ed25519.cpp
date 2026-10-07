// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_ed25519.cpp
 * @brief Exact Ed25519 primitive and RFC 8032 vector tests.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <span>

#include <gtest/gtest.h>

#include "src/common/ed25519.hpp"
#include "src/common/status.hpp"
#include "tests/provider_test_signing_key.hpp"

namespace kinetum::common
{
namespace
{

/** RFC 8032 empty-message signature for the fixed test seed. */
constexpr ed25519_signature RFC8032_EMPTY_SIGNATURE{
	0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
	0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
	0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
	0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
};

}  // namespace

/** @brief Prove the RFC 8032 seed derives its exact public key. */
TEST(ed25519, derives_rfc8032_public_key_from_raw_seed)
{
	auto public_or = ed25519_derive_public_key(test::PROVIDER_TEST_PRIVATE_KEY);
	ASSERT_TRUE(public_or.is_ok()) << public_or.error().to_string();
	EXPECT_EQ(public_or.value(), test::PROVIDER_TEST_PUBLIC_KEY);
}

/** @brief Prove signing the empty RFC 8032 message yields the exact vector. */
TEST(ed25519, signs_empty_message_to_rfc8032_signature)
{
	auto signature_or = ed25519_sign(test::PROVIDER_TEST_PRIVATE_KEY, std::span<const uint8_t>{});
	ASSERT_TRUE(signature_or.is_ok()) << signature_or.error().to_string();
	EXPECT_EQ(signature_or.value(), RFC8032_EMPTY_SIGNATURE);
}

/** @brief Prove the RFC 8032 empty-message signature verifies successfully. */
TEST(ed25519, verifies_rfc8032_empty_message_vector)
{
	const auto status =
		ed25519_verify(test::PROVIDER_TEST_PUBLIC_KEY, std::span<const uint8_t>{}, RFC8032_EMPTY_SIGNATURE);
	EXPECT_TRUE(status.is_ok()) << status.to_string();
}

/** @brief Prove changing authenticated message bytes fails authentication. */
TEST(ed25519, rejects_message_mutation_as_unauthenticated)
{
	const std::array<uint8_t, 1> message{0};
	const auto status = ed25519_verify(test::PROVIDER_TEST_PUBLIC_KEY, message, RFC8032_EMPTY_SIGNATURE);
	EXPECT_EQ(status.code(), status_code::UNAUTHENTICATED);
}

/** @brief Prove changing signature bytes fails authentication. */
TEST(ed25519, rejects_signature_mutation_as_unauthenticated)
{
	auto signature = RFC8032_EMPTY_SIGNATURE;
	signature.back() ^= UINT8_C(1);
	const auto status = ed25519_verify(test::PROVIDER_TEST_PUBLIC_KEY, std::span<const uint8_t>{}, signature);
	EXPECT_EQ(status.code(), status_code::UNAUTHENTICATED);
}

/** @brief Prove a valid nonempty signature is bound to its exact public key. */
TEST(ed25519, nonempty_round_trip_rejects_a_different_public_key)
{
	const std::array<uint8_t, 7> message{'k', 'i', 'n', 'e', 't', 'u', 'm'};
	auto signature_or = ed25519_sign(test::PROVIDER_TEST_PRIVATE_KEY, message);
	ASSERT_TRUE(signature_or.is_ok()) << signature_or.error().to_string();
	EXPECT_TRUE(ed25519_verify(test::PROVIDER_TEST_PUBLIC_KEY, message, signature_or.value()).is_ok());

	auto different_seed = test::PROVIDER_TEST_PRIVATE_KEY;
	different_seed.front() ^= UINT8_C(1);
	auto different_public_or = ed25519_derive_public_key(different_seed);
	ASSERT_TRUE(different_public_or.is_ok()) << different_public_or.error().to_string();
	const auto status = ed25519_verify(different_public_or.value(), message, signature_or.value());
	EXPECT_EQ(status.code(), status_code::UNAUTHENTICATED);
}

}  // namespace kinetum::common
