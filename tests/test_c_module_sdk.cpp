// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_c_module_sdk.cpp
 * @brief Production-admission and symbol-closure proofs for a plain-C module.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <dlfcn.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "src/dp/packet.hpp"
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"

#ifndef KINETUM_TEST_C_MODULE_PATH
#error "KINETUM_TEST_C_MODULE_PATH must be defined by CMake"
#endif

namespace
{

/** Explicit context and epoch memory authority supplied to the genuine C11 module fixture. */
constexpr kinetum::test::module_test_resource_contract TEST_MODULE_RESOURCES{
	64u * 1024u * 1024u,
	2u * 1024u * 1024u,
};

/** @brief Verify a genuine C11 image crosses the complete production ABI. */
TEST(c_module_sdk, plain_c_image_admits_prepares_executes_and_retires)
{
	auto module_or = kinetum::test::exact_module_test_context::create(
		"kinetum.test.c", std::filesystem::path(KINETUM_TEST_C_MODULE_PATH), TEST_MODULE_RESOURCES,
		"c_module@lane_0", 3u);
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	const char threshold = 32;
	ASSERT_TRUE(module->prepare_and_activate(7u, std::string_view(&threshold, 1u)).is_ok());
	kinetum::test::packet_record_test_owner forwarded(std::vector<uint8_t>(64, 0), 7);
	kinetum::test::packet_record_test_owner dropped(std::vector<uint8_t>(64, 0), 7);
	ASSERT_TRUE(forwarded.valid()) << forwarded.error();
	ASSERT_TRUE(dropped.valid()) << dropped.error();
	forwarded.metadata().platform_flags |= kinetum::dp::packet_platform_flags::L3_IPV4;
	forwarded.metadata().dscp = 31;
	dropped.metadata().platform_flags |= kinetum::dp::packet_platform_flags::L3_IPV4;
	dropped.metadata().dscp = 32;
	EXPECT_TRUE(module->process(*forwarded.get()));
	EXPECT_FALSE(module->process(*dropped.get()));
	EXPECT_TRUE(module->retire().is_ok());
}

/** @brief Verify immediate local loading exposes only the registration ABI. */
TEST(c_module_sdk, rtld_now_local_image_has_no_host_sdk_runtime_symbols)
{
	void *handle = dlopen(KINETUM_TEST_C_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
	const char *load_error = handle == nullptr ? dlerror() : nullptr;
	ASSERT_NE(handle, nullptr) << (load_error != nullptr ? load_error : "unknown dlopen error");

	dlerror();
	void *registration = dlsym(handle, "kinetum_module_register");
	const char *registration_error = dlerror();
	ASSERT_EQ(registration_error, nullptr) << registration_error;
	ASSERT_NE(registration, nullptr);

	constexpr std::array<const char *, 9> forbidden_runtime_symbols{
		"kinetum_strerror",	   "kinetum_histogram_percentiles", "kinetum_simd_cmp_u8_ge",
		"kinetum_simd_cmp_u8_gt",  "kinetum_simd_cmp_u8_lt",	    "kinetum_simd_cmp_u8_eq",
		"kinetum_simd_cmp_u16_eq", "kinetum_simd_cmp_u16_range",    "kinetum_module_validate",
	};
	for (const char *symbol : forbidden_runtime_symbols) {
		dlerror();
		void *resolved = dlsym(handle, symbol);
		const char *symbol_error = dlerror();
		EXPECT_EQ(resolved, nullptr) << symbol;
		EXPECT_NE(symbol_error, nullptr) << symbol;
	}

	EXPECT_EQ(dlclose(handle), 0);
}

}  // namespace
