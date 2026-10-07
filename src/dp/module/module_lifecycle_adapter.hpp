// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_lifecycle_adapter.hpp
 * @brief Production bridge from lifecycle executors to the exact module ABI.
 * @author Fleming Patel
 *
 * The adapter validates the borrowed lifecycle identity, obtains the owning
 * image's logical serialization turn, and invokes exactly one descriptor
 * callback. It never owns a packet context, guesses an epoch, interprets
 * configuration bytes, or translates failure into a successful empty record.
 *
 * @par Thread Safety
 * Adapters for different contexts may execute concurrently. Adapters backed by
 * one loaded image serialize PREPARE and RETIRE through the shared image gate;
 * the gate's wait mutex is released before foreign code executes.
 */

#include <cstdint>

#include "src/dp/lifecycle/config_lifecycle_executor.hpp"

namespace kinetum::dp::module
{

struct loaded_module_image;

/** @brief Exact production lifecycle adapter for one admitted context. */
class module_lifecycle_adapter final : public kinetum::dp::lifecycle::config_lifecycle_adapter {
    public:
	/**
	 * @brief Bind one adapter to a stable image and context identity.
	 *
	 * @param image Admitted image that must outlive this adapter.
	 * @param identity Complete compiled context identity accepted by this adapter.
	 */
	module_lifecycle_adapter(loaded_module_image &image,
				 const kinetum::dp::lifecycle::lifecycle_context_identity &identity) noexcept;

	module_lifecycle_adapter(const module_lifecycle_adapter &) = delete;
	module_lifecycle_adapter &operator=(const module_lifecycle_adapter &) = delete;
	module_lifecycle_adapter(module_lifecycle_adapter &&) = delete;
	module_lifecycle_adapter &operator=(module_lifecycle_adapter &&) = delete;
	/** @brief Destroy an idle adapter; callback ownership remains with the image. */
	~module_lifecycle_adapter() override = default;

	/**
	 * @brief Invoke exact ABI PREPARE under image-wide logical serialization.
	 *
	 * @param context Active PREPARE lifecycle context for this image/context.
	 * @param payload Opaque borrowed configuration bytes; null exactly when
	 *        @p payload_size is zero.
	 * @param payload_size Exact byte count.
	 * @return Explicit success, cancellation, or module failure result.
	 */
	[[nodiscard]] kinetum::dp::lifecycle::lifecycle_prepare_callback_result
	prepare(const ::kinetum_lifecycle_ctx &context, const void *payload,
		std::size_t payload_size) noexcept override;

	/**
	 * @brief Invoke exact ABI RETIRE under image-wide logical serialization.
	 *
	 * RETIRE is infallible after ownership transfer. A callback exception or
	 * identity violation is a fatal module-contract breach.
	 *
	 * @param context Active RETIRE lifecycle context for this image/context.
	 * @param prepared Exact record transferred to the module once.
	 */
	void retire(const ::kinetum_lifecycle_ctx &context,
		    kinetum::dp::lifecycle::prepared_config_record prepared) noexcept override;

    private:
	/**
	 * @brief Validate a borrowed context against this adapter's complete identity.
	 *
	 * @param context Active lifecycle context supplied by an executor.
	 * @return true only when every image, context, worker, CPU, and NUMA fact matches.
	 */
	[[nodiscard]] bool matches_(const ::kinetum_lifecycle_ctx &context) const noexcept;

	loaded_module_image &image_;  ///< Stable image and serialization authority.
	const kinetum::dp::lifecycle::lifecycle_context_identity &identity_;  ///< Complete accepted identity.
};

}  // namespace kinetum::dp::module
