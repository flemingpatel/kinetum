// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file nat44_module.hpp
 * @brief Exact-lifecycle stateful NAT44 module.
 * @author Fleming Patel
 *
 * One admitted context owns one preallocated session table, telemetry, and
 * counter baseline. Stateless context selection keeps both directions on that
 * sole owner worker. Immutable NAT pool policy is prepared off-worker and
 * supplied through the exact batch configuration pointer. Mutable sessions
 * remain context-local and owner-worker confined.
 */

#include <cstddef>
#include <cstdint>

#include "nat44_impl.hpp"
#include <kinetum/kinetum_sdk.hpp>

namespace kinetum::modules
{

/** @brief Immutable NAT44 packet-execution view for one exact epoch. */
struct nat44_packet_config {
	/** @brief Exact compiled public-address pools. */
	const nat44::nat_pools_compiled *pools{nullptr};
};

/** @brief Context-local stateful NAT44 policy module. */
class nat44_module : public sdk::module_base<nat44_module> {
    public:
	/**
	 * @brief Return the exact semantic module identity.
	 *
	 * @return Image-lifetime NUL-terminated descriptor identity.
	 */
	[[nodiscard]] static constexpr const char *module_id() noexcept
	{
		return "kinetum.nat44";
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
		return KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION |
		       KINETUM_MOD_F_CONTEXT_SELECTION;
	}

	/**
	 * @brief Construct one context-local session table from exact INIT storage.
	 *
	 * @param lifecycle Borrowed INIT allocation authority.
	 * @throws std::bad_alloc when bounded context storage is exhausted.
	 */
	explicit nat44_module(const kinetum_lifecycle_ctx *lifecycle)
		: sdk::module_base<nat44_module>(lifecycle)
		, sessions_(nat44::NAT_DEFAULT_MAX_SESSIONS, *context_memory_resource(), read_partition_(lifecycle))
	{
	}
	/** @brief Destroy context-local state after FINI and owner-worker join. */
	~nat44_module() = default;
	nat44_module(const nat44_module &) = delete;
	nat44_module &operator=(const nat44_module &) = delete;
	nat44_module(nat44_module &&) = delete;
	nat44_module &operator=(nat44_module &&) = delete;

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
	 * @brief Compile one immutable NAT44 pool artifact.
	 *
	 * @param lifecycle Borrowed exact PREPARE lifecycle context.
	 * @param epoch Exact nonzero prepared epoch.
	 * @param config Opaque mandatory NAT pool bytes.
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
	 * @brief Reclaim one exact prepared NAT44 artifact.
	 *
	 * @param lifecycle Borrowed exact RETIRE lifecycle context.
	 * @param epoch Exact nonzero retired epoch.
	 * @param retired Exact prepared ownership transferred once.
	 */
	static void do_retire_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
				     kinetum_prepared_config retired) noexcept;

	/**
	 * @brief Translate one exact-config packet batch.
	 *
	 * @param batch Owner-worker batch carrying `nat44_packet_config`.
	 * @return Sole forward mask for the occupied batch lanes.
	 */
	[[nodiscard]] uint64_t do_process(kinetum_batch_t *batch) noexcept;

	/**
	 * @brief Select each flow's exact context without reading mutable session state.
	 * @param batch Borrowed immutable flow facts.
	 * @param targets Exact generation population and permitted logical-edge destinations.
	 * @param selected_contexts Caller-owned output ordinals for admitted lanes.
	 * @return Admission mask; inapplicable targets reject without an alternate owner.
	 */
	[[nodiscard]] static uint64_t select_contexts(const kinetum_context_selection_batch *batch,
						      const kinetum_context_selection_targets *targets,
						      uint32_t *selected_contexts) noexcept;

	/**
	 * @brief Produce owner-worker health against one exact NAT policy.
	 *
	 * @param active_epoch Exact active epoch represented by @p active_config.
	 * @param active_config Borrowed immutable `nat44_packet_config`.
	 * @return Fixed bounded module-owned health assessment.
	 */
	[[nodiscard]] kinetum_health_assessment do_health_check(uint64_t active_epoch,
								const void *active_config) noexcept;

    private:
	/**
	 * @brief Read the already admitted immutable INIT identity before table construction.
	 * @param lifecycle Exact active INIT shell.
	 * @return Exact NAT context partition; contradictory lifecycle authority terminates.
	 */
	[[nodiscard]] static nat44::context_partition read_partition_(const kinetum_lifecycle_ctx *lifecycle) noexcept;
	/** @brief Snapshot baseline for delta-exported session counters. */
	struct counter_baseline {
		/** @brief Previously exported session creations. */
		uint64_t total_created{0};
		/** @brief Previously exported session expirations. */
		uint64_t total_expired{0};
		/** @brief Previously exported inbound misses. */
		uint64_t inbound_misses{0};
		/** @brief Previously exported allocation failures. */
		uint64_t allocation_failures{0};
	};

	/** @brief Context-local translated-packet counter. */
	sdk::counter packets_translated_;
	/** @brief Context-local dropped-packet counter. */
	sdk::counter packets_dropped_;
	/** @brief Context-local session-creation counter. */
	sdk::counter sessions_created_;
	/** @brief Context-local session-expiration counter. */
	sdk::counter sessions_expired_;
	/** @brief Context-local unsolicited-inbound miss counter. */
	sdk::counter inbound_misses_;
	/** @brief Context-local session-allocation failure counter. */
	sdk::counter allocation_failures_;
	/** @brief Preallocated mutable session table owned by the sole worker. */
	nat44::nat44_table sessions_;
	/** @brief Owner-local baseline for cumulative table statistics. */
	counter_baseline baseline_;
};

}  // namespace kinetum::modules
