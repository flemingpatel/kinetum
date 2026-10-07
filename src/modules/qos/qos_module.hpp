// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file qos_module.hpp
 * @brief Exact-lifecycle stateful QoS policer module.
 * @author Fleming Patel
 *
 * One admitted context owns one preallocated flow policer and its telemetry.
 * Immutable compiled profiles are prepared off-worker and supplied through the
 * exact packet configuration pointer. Mutable flow buckets remain
 * context-local and owner-worker confined.
 */

#include <cstddef>
#include <cstdint>

#include "qos_impl.hpp"
#include <kinetum/kinetum_sdk.hpp>

namespace kinetum::modules
{

/** @brief Number of representable six-bit DSCP values. */
inline constexpr std::size_t MAX_DSCP = 64;

/** @brief Immutable QoS packet-execution view for one exact epoch. */
struct qos_packet_config {
	/** @brief Exact compiled profile collection. */
	const qos::qos_profiles_compiled *profiles{nullptr};
	/** @brief Pre-resolved default profile. */
	const qos::qos_profile_compiled *default_profile{nullptr};
	/** @brief Pre-resolved DSCP-to-profile table; null selects the default. */
	const qos::qos_profile_compiled *dscp_profiles[MAX_DSCP]{};
};

/**
 * @brief Context-local QoS token-bucket policy module.
 *
 * The context and its mutable flow table have one owner worker. Profile policy
 * is immutable and exact-epoch scoped, so preparation and retirement can run
 * on lifecycle executors without sharing writable packet state.
 */
class qos_module : public sdk::module_base<qos_module> {
    public:
	/**
	 * @brief Return the exact semantic module identity.
	 *
	 * @return Image-lifetime NUL-terminated descriptor identity.
	 */
	[[nodiscard]] static constexpr const char *module_id() noexcept
	{
		return "kinetum.qos";
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
	 * @brief Construct one context-local flow policer from exact INIT storage.
	 *
	 * @param lifecycle Borrowed INIT allocation authority.
	 * @throws std::bad_alloc when bounded context storage is exhausted.
	 */
	explicit qos_module(const kinetum_lifecycle_ctx *lifecycle)
		: sdk::module_base<qos_module>(lifecycle)
		, policer_(qos::QOS_DEFAULT_MAX_FLOWS, *context_memory_resource())
	{
	}
	/** @brief Destroy context-local state after FINI and owner-worker join. */
	~qos_module() = default;
	qos_module(const qos_module &) = delete;
	qos_module &operator=(const qos_module &) = delete;
	qos_module(qos_module &&) = delete;
	qos_module &operator=(qos_module &&) = delete;

	/**
	 * @brief Register owner-local telemetry before worker launch.
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
	 * @brief Compile one immutable QoS profile artifact.
	 *
	 * @param lifecycle Borrowed exact PREPARE lifecycle context.
	 * @param epoch Exact nonzero prepared epoch.
	 * @param config Opaque mandatory QoS profile bytes.
	 * @param config_len Exact positive input byte count.
	 * @param out_prepared Output ownership and packet view written on success.
	 * @return KINETUM_OK, CONFIG_INVALID, CANCELLED, or NO_MEMORY.
	 */
	[[nodiscard]] static kinetum_error do_prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
							     const void *config, std::size_t config_len,
							     kinetum_prepared_config *out_prepared) noexcept;

	/**
	 * @brief Complete bounded owner-worker activation.
	 *
	 * @param epoch Exact nonzero activated epoch.
	 * @param prepared Borrowed exact prepared artifact.
	 */
	void do_activate_config(uint64_t epoch, const kinetum_prepared_config *prepared) noexcept;

	/**
	 * @brief Reclaim one exact prepared QoS artifact.
	 *
	 * @param lifecycle Borrowed exact RETIRE lifecycle context.
	 * @param epoch Exact nonzero retired epoch.
	 * @param retired Exact prepared ownership transferred once.
	 */
	static void do_retire_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
				     kinetum_prepared_config retired) noexcept;

	/**
	 * @brief Police one exact-config packet batch.
	 *
	 * @param batch Owner-worker batch carrying `qos_packet_config`.
	 * @return Sole forward mask for the occupied batch lanes.
	 */
	[[nodiscard]] uint64_t do_process(kinetum_batch_t *batch) noexcept;

	/**
	 * @brief Produce owner-worker health against one exact QoS policy.
	 *
	 * @param active_epoch Exact active epoch represented by @p active_config.
	 * @param active_config Borrowed immutable `qos_packet_config`.
	 * @return Fixed bounded module-owned health assessment.
	 */
	[[nodiscard]] kinetum_health_assessment do_health_check(uint64_t active_epoch,
								const void *active_config) noexcept;

    private:
	/** @brief Context-local allowed-packet counter. */
	sdk::counter packets_allowed_;
	/** @brief Context-local dropped-packet counter. */
	sdk::counter packets_dropped_;
	/** @brief Context-local allowed-byte counter. */
	sdk::counter bytes_allowed_;
	/** @brief Context-local dropped-byte counter. */
	sdk::counter bytes_dropped_;
	/** @brief Context-local active-flow gauge. */
	sdk::counter active_flows_;
	/** @brief Preallocated mutable flow policer owned by the sole worker. */
	qos::qos_policer policer_;
};

}  // namespace kinetum::modules
