// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_runtime_generation.hpp
 * @brief Complete move-only input for one packet-runtime generation.
 * @author Fleming Patel
 *
 * The input binds one canonical plan, the sole compiled artifact derived from
 * that exact plan, the requested-only admitted provider runtime, and the exact
 * main-module image set, and a plan-sized unbound coordinator mailbox before
 * any materialization side effect. It has no default or partial constructor and
 * cannot represent an old backend selector, inferred bundle root, runtime
 * capacity default, or provider-specific startup override.
 *
 * @par Thread Safety
 * Construction is single-owner startup work. After transfer to the runtime,
 * the contained plan and compiled topology are immutable generation truth.
 *
 * @par Performance
 * Validation allocates and compares cold identity sets. The type is never
 * reachable from packet execution.
 */

#include <cstdint>
#include <memory>
#include <vector>

#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_transition_command_mailbox.hpp"
#include "src/dp/module/module_manager.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_runtime_admission.hpp"

namespace kinetum::dp
{

class partitioned_runtime;

/** @brief Exact complete authority transferred into one runtime generation. */
class packet_runtime_generation_input final {
    public:
	/** @brief Complete generation inputs cannot be copied. */
	packet_runtime_generation_input(const packet_runtime_generation_input &) = delete;
	/** @brief Complete generation inputs cannot be copy-assigned. */
	packet_runtime_generation_input &operator=(const packet_runtime_generation_input &) = delete;

	/** @brief Transfer one not-yet-consumed complete generation input. */
	packet_runtime_generation_input(packet_runtime_generation_input &&) noexcept = default;

	/** @brief Disable replacement of linear provider-admission ownership. */
	packet_runtime_generation_input &operator=(packet_runtime_generation_input &&) = delete;

	/** @brief Destroy an unconsumed input and its admitted component authority. */
	~packet_runtime_generation_input() = default;

	/**
	 * @brief Validate and bind every cold authority before materialization.
	 *
	 * @param plan Canonical plan with a verified nonempty content identity.
	 * @param topology Sole compiler output derived from @p plan.
	 * @param command_mailbox Pre-materialization mailbox derived from @p topology.
	 * @param admitted Requested-only provider runtime admitted from @p topology.
	 * @param module_images Strictly sorted exact main-image authority.
	 * @param runtime_generation Nonzero generation representable by provider ABI.
	 * @return Complete move-only input, or a status after consuming the supplied
	 *         linear authorities without starting materialization.
	 */
	[[nodiscard]] static common::status_or<packet_runtime_generation_input>
	create(kinetum::gluon::v1::DeploymentPlan plan, provider::compiled_provider_topology topology,
	       std::unique_ptr<epoch_transition_command_mailbox> command_mailbox,
	       provider::admitted_provider_runtime admitted, std::vector<module::module_image_spec> module_images,
	       uint64_t runtime_generation);

    private:
	friend class partitioned_runtime;

	/**
	 * @brief Adopt already validated exact generation authorities.
	 *
	 * @param plan Canonical deployment-plan authority.
	 * @param topology Sole compiled artifact derived from @p plan.
	 * @param command_mailbox Exact unbound coordinator mailbox.
	 * @param admitted Requested-only admitted provider runtime.
	 * @param module_images Strictly sorted exact main-module images.
	 * @param runtime_generation Exact nonzero generation identity.
	 */
	packet_runtime_generation_input(kinetum::gluon::v1::DeploymentPlan plan,
					provider::compiled_provider_topology topology,
					std::unique_ptr<epoch_transition_command_mailbox> command_mailbox,
					provider::admitted_provider_runtime admitted,
					std::vector<module::module_image_spec> module_images,
					uint64_t runtime_generation) noexcept;

	kinetum::gluon::v1::DeploymentPlan plan_;			     ///< Exact canonical plan authority.
	provider::compiled_provider_topology topology_;			     ///< Sole compiled semantic artifact.
	std::unique_ptr<epoch_transition_command_mailbox> command_mailbox_;  ///< Exact unbound command owner.
	provider::admitted_provider_runtime admitted_;			     ///< Requested-only component authority.
	std::vector<module::module_image_spec> module_images_;		     ///< Sorted exact module image set.
	uint64_t runtime_generation_{0};				     ///< Exact nonzero generation identity.
};

}  // namespace kinetum::dp
