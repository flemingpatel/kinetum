// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_inventory_internal.hpp
 * @brief Private installed-provider inventory mechanisms shared by signing and authentication.
 * @author Fleming Patel
 *
 * This header is private to the provider-inventory library. It keeps the exact
 * signature preimage under one implementation authority while allowing the
 * signing implementation to occupy a distinct static-archive member from
 * runtime authentication.
 */

#include <string>
#include <string_view>

namespace kinetum::provider
{

/**
 * @brief Build the exact domain-separated provider-inventory signature preimage.
 *
 * @param bytes Canonical inventory bytes.
 * @return Signature-domain prefix followed by the exact input bytes.
 */
[[nodiscard]] std::string provider_inventory_signature_preimage(std::string_view bytes);

}  // namespace kinetum::provider
