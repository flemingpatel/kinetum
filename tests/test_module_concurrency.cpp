// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_module_concurrency.cpp
 * @brief Exact module-capability and descriptor-admission tests.
 * @author Fleming Patel
 *
 * Module concurrency is no longer expressed through a generic concurrent-
 * configuration flag or an SDK-owned current/previous selector. The exact ABI
 * declares only independently testable properties: context replication, live
 * epoch-transition lifecycle, tracked asynchronous epoch work, and stateless
 * module-context selection.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

#include "src/dp/module/module_descriptor_admission.hpp"
#include <kinetum/kinetum_sdk.h>

namespace
{

/**
 * @param batch Borrowed valid callback batch, or nullptr.
 * @return Full occupied-prefix forwarding mask, or zero for a null batch.
 */
uint64_t test_process(kinetum_batch_t *batch) noexcept
{
	return batch != nullptr ? KINETUM_FORWARD_MASK(batch->count) : 0;
}

/** @return Zero admission mask for this descriptor-only selector fixture. */
uint64_t test_select_contexts(const kinetum_context_selection_batch *, const kinetum_context_selection_targets *,
			      uint32_t *) noexcept
{
	return 0u;
}

/**
 * @brief Build one exact valid passive descriptor.
 *
 * @param flags KINETUM_MOD_F_* capabilities to publish.
 * @return Complete descriptor accepted by the exact ABI.
 */
kinetum_module valid_passive_descriptor(uint32_t flags = 0)
{
	return kinetum_module{
		.module_id = "kinetum.test.capability",
		.module_version = "1.0.0",
		.abi_version = KINETUM_MODULE_ABI_VERSION,
		.flags = flags,
		.mode = KINETUM_MODULE_PASSIVE,
		.prepare_config = kinetum_noop_prepare_config,
		.activate_config = kinetum_noop_activate_config,
		.retire_config = kinetum_noop_retire_config,
		.process = test_process,
		.ingest = nullptr,
		.run = nullptr,
		.on_control = nullptr,
		.init = kinetum_noop_init,
		.fini = kinetum_noop_fini,
		.health_check = nullptr,
		.select_contexts = (flags & KINETUM_MOD_F_CONTEXT_SELECTION) != 0u ? test_select_contexts : nullptr,
	};
}

/** @brief Verify replicated contexts occupy the first independent capability bit. */
TEST(module_concurrency, replicated_contexts_is_exact_bit_zero)
{
	EXPECT_EQ(KINETUM_MOD_F_REPLICABLE_CONTEXTS, uint32_t{1} << 0);
}

/** @brief Verify live transition support occupies the second capability bit. */
TEST(module_concurrency, live_epoch_transition_is_exact_bit_one)
{
	EXPECT_EQ(KINETUM_MOD_F_LIVE_EPOCH_TRANSITION, uint32_t{1} << 1);
}

/** @brief Verify tracked asynchronous work is declared in this ABI revision. */
TEST(module_concurrency, tracked_async_epoch_work_is_exact_bit_two)
{
	EXPECT_EQ(KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK, uint32_t{1} << 2);
}

/** @brief Verify the known mask contains exactly the four designed capabilities. */
TEST(module_concurrency, known_mask_is_complete_and_compact)
{
	constexpr uint32_t expected = (uint32_t{1} << 0) | (uint32_t{1} << 1) | (uint32_t{1} << 2) | (uint32_t{1} << 3);
	EXPECT_EQ(KINETUM_MOD_F_KNOWN_MASK, expected);
}

/** @brief Verify every capability can be admitted independently. */
TEST(module_concurrency, capabilities_are_independent_descriptor_claims)
{
	constexpr std::array<uint32_t, 4> flags{
		KINETUM_MOD_F_REPLICABLE_CONTEXTS,
		KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
		KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK,
		KINETUM_MOD_F_CONTEXT_SELECTION,
	};
	for (const uint32_t flag : flags) {
		const auto descriptor = valid_passive_descriptor(flag);
		EXPECT_TRUE(kinetum::dp::module::validate_module_descriptor(&descriptor).is_ok());
	}
}

/** @brief Verify all designed capabilities compose without changing callback shape. */
TEST(module_concurrency, capabilities_compose_under_one_exact_descriptor)
{
	const auto descriptor = valid_passive_descriptor(KINETUM_MOD_F_KNOWN_MASK);
	EXPECT_TRUE(kinetum::dp::module::validate_module_descriptor(&descriptor).is_ok());
}

/** @brief Verify an undeclared capability bit fails exact descriptor admission. */
TEST(module_concurrency, unknown_capability_bit_fails_closed)
{
	auto descriptor = valid_passive_descriptor();
	descriptor.flags = uint32_t{1} << 31;
	EXPECT_FALSE(kinetum::dp::module::validate_module_descriptor(&descriptor).is_ok());
}

}  // namespace
