// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file acl_module.hpp
 * @brief Exact-lifecycle ACL policy module.
 * @author Fleming Patel
 *
 * Each admitted stage instance owns one ACL module object, one decision cache,
 * and plain owner-local telemetry. PREPARE compiles immutable policy off the
 * packet worker; packet execution receives the exact immutable view through
 * `kinetum_batch_t::epoch_config`. Mutable policy state is context-local and
 * owner-worker confined.
 */

#include <cstddef>
#include <cstdint>

#include "acl_impl.hpp"
#include <kinetum/kinetum_sdk.hpp>

namespace kinetum::modules
{

/** @brief Immutable ACL packet-execution view owned by one prepared artifact. */
struct acl_packet_config {
	/** @brief Exact compiled rule set. */
	const acl::acl_compiled *acl{nullptr};
	/** @brief Preselected evaluation strategy. */
	acl::acl_eval_strategy strategy{acl::acl_eval_strategy::LINEAR};
};

/**
 * @brief Context-local ACL implementation exported through the exact SDK ABI.
 */
class acl_module : public sdk::module_base<acl_module> {
    public:
	/**
	 * @brief Return the exact semantic module identity.
	 *
	 * @return Image-lifetime NUL-terminated descriptor identity.
	 */
	[[nodiscard]] static constexpr const char *module_id() noexcept
	{
		return "kinetum.acl";
	}

	/**
	 * @brief Return the exact module release identity.
	 *
	 * @return Image-lifetime NUL-terminated release string.
	 */
	[[nodiscard]] static constexpr const char *module_version() noexcept
	{
		return KINETUM_VERSION_STR;
	}

	/**
	 * @brief Return declared replication and live-transition capabilities.
	 *
	 * @return Exact KINETUM_MOD_F_* descriptor mask.
	 */
	[[nodiscard]] static constexpr uint32_t flags() noexcept
	{
		return KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION;
	}

	/**
	 * @brief Construct one context-local cache from exact INIT storage.
	 *
	 * @param lifecycle Borrowed INIT allocation authority.
	 * @throws std::bad_alloc when bounded context storage is exhausted.
	 */
	explicit acl_module(const kinetum_lifecycle_ctx *lifecycle)
		: sdk::module_base<acl_module>(lifecycle)
		, cache_(4096, *context_memory_resource())
	{
	}
	/** @brief Destroy context-local state after FINI and owner-worker join. */
	~acl_module() = default;
	acl_module(const acl_module &) = delete;
	acl_module &operator=(const acl_module &) = delete;
	acl_module(acl_module &&) = delete;
	acl_module &operator=(acl_module &&) = delete;

	/**
	 * @brief Initialize context-local cache and telemetry before worker launch.
	 *
	 * @param lifecycle Borrowed exact INIT lifecycle context.
	 * @return KINETUM_OK or the first exact registration failure.
	 */
	[[nodiscard]] kinetum_error do_init(const kinetum_lifecycle_ctx *lifecycle) noexcept;

	/**
	 * @brief Finalize context-local state after owner-worker join.
	 *
	 * @param lifecycle Borrowed exact FINI lifecycle context.
	 */
	void do_fini(const kinetum_lifecycle_ctx *lifecycle) noexcept;

	/**
	 * @brief Compile one immutable ACL artifact.
	 *
	 * Input must contain one strict JSON object with an explicitly authored
	 * nonzero default action. Invalid input returns no ownership transfer.
	 *
	 * @param lifecycle Borrowed exact PREPARE lifecycle context.
	 * @param epoch Exact nonzero prepared epoch.
	 * @param config Non-null opaque ACL ruleset bytes.
	 * @param config_len Exact positive input byte count.
	 * @param out_prepared Output ownership and packet view written on success.
	 * @return KINETUM_OK or an exact argument, configuration, cancellation,
	 *         allocation, or internal failure.
	 */
	[[nodiscard]] static kinetum_error do_prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
							     const void *config, std::size_t config_len,
							     kinetum_prepared_config *out_prepared) noexcept;

	/**
	 * @brief Complete bounded owner-worker activation.
	 *
	 * The platform publishes the exact packet view in its tagged slot; ACL has
	 * no second module-local active pointer to update.
	 *
	 * @param epoch Exact nonzero activated epoch.
	 * @param prepared Borrowed exact prepared artifact.
	 */
	void do_activate_config(uint64_t epoch, const kinetum_prepared_config *prepared) noexcept;

	/**
	 * @brief Reclaim one exact ACL prepared artifact.
	 *
	 * @param lifecycle Borrowed exact RETIRE lifecycle context.
	 * @param epoch Exact nonzero retired epoch.
	 * @param retired Exact prepared ownership transferred once.
	 */
	static void do_retire_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
				     kinetum_prepared_config retired) noexcept;

	/**
	 * @brief Evaluate one exact-config packet batch.
	 *
	 * @param batch Owner-worker batch carrying `acl_packet_config`.
	 * @return Sole forward mask for the occupied batch lanes.
	 */
	[[nodiscard]] uint64_t do_process(kinetum_batch_t *batch) noexcept;

	/**
	 * @brief Produce owner-worker health against one exact active policy.
	 *
	 * @param active_epoch Exact active epoch represented by @p active_config.
	 * @param active_config Borrowed immutable `acl_packet_config`.
	 * @return Fixed bounded module-owned health assessment.
	 */
	[[nodiscard]] kinetum_health_assessment do_health_check(uint64_t active_epoch,
								const void *active_config) noexcept;

    private:
	/** @brief Context-local packet evaluation counter. */
	sdk::counter packets_evaluated_;
	/** @brief Context-local permitted-packet counter. */
	sdk::counter packets_permitted_;
	/** @brief Context-local denied-packet counter. */
	sdk::counter packets_denied_;
	/** @brief Context-local decision-cache hit counter. */
	sdk::counter cache_hits_;
	/** @brief Context-local decision-cache miss counter. */
	sdk::counter cache_misses_;
	/** @brief Mutable decision cache owned by this context's sole worker. */
	acl::acl_cache cache_;
};

}  // namespace kinetum::modules
