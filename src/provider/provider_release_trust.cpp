// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_release_trust.cpp
 * @brief Sole production provider-release trust-anchor definition.
 * @author Fleming Patel
 */

#include "src/provider/provider_release_trust.hpp"

namespace kinetum::provider
{
namespace
{

/** Exact owner-generated provider-inventory release public key. */
constexpr common::ed25519_public_key PROVIDER_RELEASE_TRUST_ANCHOR{
	0x00, 0x03, 0xd2, 0x0e, 0xbb, 0x7b, 0x43, 0x85, 0x24, 0xd9, 0xd1, 0xcb, 0x4d, 0xc5, 0x66, 0x76,
	0xe3, 0x20, 0x41, 0xd5, 0x72, 0x12, 0xf8, 0x5d, 0x0e, 0x8e, 0x30, 0x25, 0x32, 0xe6, 0x60, 0x73,
};

}  // namespace

const common::ed25519_public_key &provider_release_trust_anchor() noexcept
{
	return PROVIDER_RELEASE_TRUST_ANCHOR;
}

}  // namespace kinetum::provider
