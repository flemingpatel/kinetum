// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_inventory_signing.cpp
 * @brief Release-only installed-provider inventory signing implementation.
 * @author Fleming Patel
 *
 * Signing occupies a distinct static-archive member from runtime inventory
 * authentication. A runtime consumer that authenticates inventories therefore
 * cannot acquire the secret-key operation merely by resolving its verifier.
 */

#include "src/provider/provider_inventory.hpp"

#include <span>
#include <string>
#include <utility>

#include "src/provider/provider_inventory_internal.hpp"

namespace kinetum::provider
{

common::status_or<signed_provider_inventory>
sign_provider_inventory(kinetum::provider::v1::InstalledProviderInventory inventory,
			const common::ed25519_private_key &private_key)
{
	auto bytes_or = canonicalize_provider_inventory(std::move(inventory));
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	if (bytes_or->size() > MAX_PROVIDER_INVENTORY_BYTES) {
		return common::status::resource_exhausted("canonical provider inventory exceeds its byte bound");
	}
	const std::string preimage = provider_inventory_signature_preimage(bytes_or.value());
	auto signature_or = common::ed25519_sign(
		private_key,
		std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(preimage.data()), preimage.size()));
	if (!signature_or.is_ok()) {
		return signature_or.error();
	}
	return signed_provider_inventory{std::move(bytes_or).value(), std::move(signature_or).value()};
}

}  // namespace kinetum::provider
