// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_target_tuple.cpp
 * @brief Exact provider target-tuple identity implementation.
 * @author Fleming Patel
 */

#include "src/provider/provider_target_tuple.hpp"

#include <cstdlib>

#include "src/common/status.hpp"

namespace kinetum::provider
{

common::status_or<provider_target_tuple> parse_provider_target_tuple(std::string_view value)
{
	if (value == LINUX_GNU_AARCH64_TARGET_TUPLE) {
		return provider_target_tuple::LINUX_GNU_AARCH64;
	}
	if (value == LINUX_GNU_X86_64_TARGET_TUPLE) {
		return provider_target_tuple::LINUX_GNU_X86_64;
	}
	return common::status::invalid_argument("release target tuple is not one exact supported identity");
}

std::string_view provider_target_tuple_name(provider_target_tuple target) noexcept
{
	switch (target) {
	case provider_target_tuple::LINUX_GNU_AARCH64:
		return LINUX_GNU_AARCH64_TARGET_TUPLE;
	case provider_target_tuple::LINUX_GNU_X86_64:
		return LINUX_GNU_X86_64_TARGET_TUPLE;
	}
	std::abort();
}

provider_target_tuple native_provider_target_tuple() noexcept
{
#if defined(__aarch64__)
	return provider_target_tuple::LINUX_GNU_AARCH64;
#elif defined(__x86_64__)
	return provider_target_tuple::LINUX_GNU_X86_64;
#else
#error "Provider artifacts support only aarch64 and x86_64 target tuples"
#endif
}

std::string_view provider_runtime_loader_soname(provider_target_tuple target) noexcept
{
	switch (target) {
	case provider_target_tuple::LINUX_GNU_AARCH64:
		return LINUX_GNU_AARCH64_RUNTIME_LOADER_SONAME;
	case provider_target_tuple::LINUX_GNU_X86_64:
		return LINUX_GNU_X86_64_RUNTIME_LOADER_SONAME;
	}
	std::abort();
}

}  // namespace kinetum::provider
