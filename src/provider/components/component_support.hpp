// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file component_support.hpp
 * @brief Header-owned cold helpers shared by exact provider components.
 * @author Fleming Patel
 *
 * These helpers validate borrowed ABI views and write bounded diagnostics
 * without introducing a provider runtime library or another descriptor
 * authority. They contain no native-provider declaration.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::component_support
{

/**
 * @brief Build one exact process-lifetime text view from static storage.
 *
 * @tparam size Static array extent including the terminating NUL.
 * @param text Static NUL-terminated text.
 * @return Exact zero-padded view excluding the terminating NUL.
 */
template <std::size_t size>
[[nodiscard]] constexpr kinetum_provider_text_view static_text_view(const char (&text)[size]) noexcept
{
	static_assert(size > 0);
	return kinetum_provider_text_view{
		.data = text,
		.size = static_cast<uint32_t>(size - 1u),
		.padding = 0,
	};
}

/**
 * @brief Compare one borrowed ABI text view with exact trusted text.
 *
 * @param candidate Borrowed candidate view.
 * @param expected Trusted exact text.
 * @return true only for byte-exact equality.
 */
[[nodiscard]] inline bool text_equals(kinetum_provider_text_view candidate, std::string_view expected) noexcept
{
	return kinetum_provider_text_view_is_valid(candidate) != 0 && candidate.size == expected.size() &&
	       (candidate.size == 0 || std::memcmp(candidate.data, expected.data(), candidate.size) == 0);
}

/**
 * @brief Replace an optional diagnostic with one bounded trusted literal.
 *
 * @param diagnostic Optional caller-owned output.
 * @param message Trusted diagnostic text.
 */
inline void write_diagnostic(kinetum_provider_diagnostic *diagnostic, std::string_view message) noexcept
{
	if (diagnostic == nullptr) {
		return;
	}
	diagnostic->size = 0;
	if (diagnostic->capacity == 0 || diagnostic->data == nullptr) {
		return;
	}
	const auto count = std::min<std::size_t>(diagnostic->capacity, message.size());
	if (count == 0) {
		return;
	}
	std::memcpy(diagnostic->data, message.data(), count);
	diagnostic->size = static_cast<uint32_t>(count);
}

/**
 * @brief Return one provider failure after writing a bounded trusted diagnostic.
 *
 * @param status Exact failure status.
 * @param diagnostic Optional caller-owned output.
 * @param message Trusted diagnostic text.
 * @return @p status unchanged.
 */
[[nodiscard]] inline kinetum_provider_status
fail(kinetum_provider_status status, kinetum_provider_diagnostic *diagnostic, std::string_view message) noexcept
{
	write_diagnostic(diagnostic, message);
	return status;
}

/**
 * @brief Validate one role- and contract-exact factory invocation.
 *
 * This helper deliberately does not interpret canonical configuration bytes.
 * The pure catalog has already validated and canonicalized those bytes, and
 * the shared compiler has projected every component-consumed semantic into
 * the role-specific C fact record. Empty-contract factories additionally use
 * empty_factory_request_is_exact to pin their canonical empty payload. A
 * component must not introduce a second protobuf parser or reconstruct facts
 * from the retained canonical-identity bytes.
 *
 * @param request Candidate borrowed request.
 * @param result Caller-owned zero-initialized result.
 * @param role Exact expected role.
 * @param type_url Exact expected contract identity.
 * @return true only for complete ABI, row, and empty-result agreement.
 */
[[nodiscard]] inline bool factory_request_matches(const kinetum_provider_factory_request *request,
						  const kinetum_provider_factory_result *result,
						  kinetum_provider_role role, std::string_view type_url) noexcept
{
	return request != nullptr && result != nullptr && result->instance == nullptr &&
	       result->operations == nullptr && result->destroy == nullptr &&
	       kinetum_provider_factory_request_is_valid(request) != 0 && request->role == role &&
	       text_equals(request->type_url, type_url);
}

/**
 * @brief Validate one exact factory invocation for a declared empty contract.
 *
 * @param request Candidate borrowed request.
 * @param result Caller-owned zero-initialized result.
 * @param role Exact expected role.
 * @param type_url Exact expected contract identity.
 * @return true only when the general request law holds and the canonical
 *         payload is the exact empty byte string.
 */
[[nodiscard]] inline bool empty_factory_request_is_exact(const kinetum_provider_factory_request *request,
							 const kinetum_provider_factory_result *result,
							 kinetum_provider_role role, std::string_view type_url) noexcept
{
	return factory_request_matches(request, result, role, type_url) && request->canonical_configuration.size == 0;
}

}  // namespace kinetum::provider::component_support
