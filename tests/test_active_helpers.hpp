// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file test_active_helpers.hpp
 * @brief Reusable exact-ABI helpers for active-module component tests.
 * @author Fleming Patel
 *
 * Provides:
 * - RAII harness that admits the exact module image and context
 * - Exact context-local state inspection through one shared test-only type
 *
 * Pattern: follows test_grpc_helpers.hpp (RAII harness) and
 * test_dp_helpers.hpp (packet construction).
 */

#include <cstdint>
#include <memory>
#include <string>

#include <kinetum/kinetum_sdk.h>
#include "tests/module_abi_test_harness.hpp"
#include "tests/test_modules/test_active_module_state.hpp"

#ifndef KINETUM_TEST_ACTIVE_MODULE_PATH
#error "KINETUM_TEST_ACTIVE_MODULE_PATH must be defined by CMake"
#endif

namespace kinetum::test
{

/**
 * @brief RAII harness for exact active-module callback tests.
 *
 * The harness admits the module image/context through the production manager
 * and activates its exact no-op artifact through the production epoch store.
 * Tests invoke callbacks as the sole owner worker; separate runtime tests own
 * authored-plan scheduling and dispatch coverage.
 */
struct active_test_harness {
	std::unique_ptr<exact_module_test_context> module;  ///< Exact admitted image/context owner.
	test_active_state *state{nullptr};		    ///< Borrowed context-local observation state.
	std::string error;				    ///< Cold construction failure diagnostic.

	/**
	 * @brief Create one exact active-module component harness.
	 *
	 * @param resources Explicit test-owned context and epoch-arena capacities.
	 * @return Valid harness on success, or invalid harness with error populated.
	 */
	static active_test_harness create(module_test_resource_contract resources)
	{
		active_test_harness h;
		const std::string so_path = KINETUM_TEST_ACTIVE_MODULE_PATH;
		if (so_path.empty()) {
			h.error = "KINETUM_TEST_ACTIVE_MODULE_PATH is empty";
			return h;
		}

		auto module_or =
			exact_module_test_context::create("kinetum.test_active", so_path, resources, "active0@lane_0");
		if (!module_or.is_ok()) {
			h.error = "active module admission failed: " + std::string(module_or.error().message());
			return h;
		}
		h.module = std::move(module_or).value();
		const auto activation = h.module->prepare_and_activate(1, {});
		if (!activation.is_ok()) {
			h.error = "active module activation failed: " + std::string(activation.message());
			h.module.reset();
			return h;
		}

		h.state = static_cast<test_active_state *>(h.module->context().packet_context.state);
		if (h.state == nullptr) {
			h.error = "active module context-local state is null";
			h.module.reset();
			return h;
		}
		return h;
	}

	/**
	 * @brief Check whether exact module ownership and observation state exist.
	 *
	 * @return true when the harness is ready for assertions.
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		return module != nullptr && state != nullptr;
	}

	/**
	 * @brief Invoke one active ingest callback as the sole owner worker.
	 *
	 * @param active_ctx Exact callback-only active services.
	 * @param batch Exact borrowed packet batch.
	 * @return Sole module disposition mask.
	 */
	[[nodiscard]] uint64_t ingest(kinetum_active_ctx &active_ctx, kinetum_batch_t &batch) const noexcept
	{
		return module->descriptor().ingest(&module->context().packet_context, &active_ctx, &batch);
	}

	/**
	 * @brief Invoke one active run callback as the sole owner worker.
	 *
	 * @param active_ctx Exact active callback services.
	 * @param triggers KINETUM_TRIGGER_* reasons for this turn.
	 */
	void run(kinetum_active_ctx &active_ctx, uint32_t triggers) const noexcept
	{
		module->descriptor().run(&module->context().packet_context, &active_ctx, triggers);
	}

	/**
	 * @brief Deliver one owner-worker control callback.
	 *
	 * @param active_ctx Exact callback-only active services.
	 * @param message Exact borrowed control message.
	 */
	void deliver_control(kinetum_active_ctx &active_ctx, const kinetum_control_msg &message) const noexcept
	{
		module->descriptor().on_control(&module->context().packet_context, &active_ctx, &message);
	}

	/** @brief Construct an empty harness before exact admission. */
	active_test_harness() = default;
	/** @brief Release exact module ownership through member RAII. */
	~active_test_harness() = default;
	/** @brief Reject copying because module/context ownership is linear. @param other Rejected source. */
	active_test_harness(const active_test_harness &other) = delete;
	/**
	 * @brief Reject copy assignment because module/context ownership is linear.
	 * @param other Rejected source.
	 * @return No value; this operation is deleted.
	 */
	active_test_harness &operator=(const active_test_harness &other) = delete;
	/** @brief Transfer exact harness ownership. @param other Source invalidated by transfer. */
	active_test_harness(active_test_harness &&other) = default;
	/**
	 * @brief Replace this harness with transferred exact ownership.
	 * @param other Source invalidated by transfer.
	 * @return This harness after transfer.
	 */
	active_test_harness &operator=(active_test_harness &&other) = default;
};

}  // namespace kinetum::test
