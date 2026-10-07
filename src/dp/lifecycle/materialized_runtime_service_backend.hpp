// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file materialized_runtime_service_backend.hpp
 * @brief Pre-resolved lifecycle-service dispatch over materialized facilities.
 * @author Fleming Patel
 *
 * The adapter derives one exact backend owner for every compiled runtime
 * service from process-facility CPU assignments. A service with no facility
 * dependency uses the native mechanism. A service claimed by more than one
 * facility is unrepresentable and rejects before coordinator binding or
 * executor launch. Provider-native identities remain behind the exact C ABI.
 * A facility callback may return only a valid status and the unchanged,
 * bounded caller-owned diagnostic. Violating that contract fails stop because
 * successful launch or join may already have changed linear entry ownership.
 *
 * @par Thread Safety
 * Creation and all backend calls belong to the single lifecycle coordinator.
 * Provider callbacks and the native backend retain their own exact launch and
 * join ownership contracts.
 *
 * @par Performance
 * This is cold startup and shutdown machinery. Dispatch is one bounds check
 * and one pre-resolved pointer test; no provider lookup or string comparison
 * occurs after construction.
 */

#include <memory>
#include <vector>

#include "src/common/status_or.hpp"
#include "src/dp/lifecycle/runtime_service_launcher.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_runtime_materialization.hpp"

namespace kinetum::dp::lifecycle
{

/**
 * @brief Exact lifecycle backend composed from one materialized generation.
 */
class materialized_runtime_service_backend final : public runtime_service_backend {
    public:
	/**
	 * @brief Pre-resolve every service to one facility or the native backend.
	 *
	 * @param topology Sole compiled provider-topology authority.
	 * @param materialized Complete materialized provider generation that must
	 *        outlive the returned backend and every launched service.
	 * @return Unique backend, or an exact ownership/allocation failure before
	 *         any service side effect.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<materialized_runtime_service_backend>>
	create(const kinetum::provider::compiled_provider_topology &topology,
	       const kinetum::provider::materialized_provider_runtime &materialized);

	/** @brief Materialized service backends cannot be copied. */
	materialized_runtime_service_backend(const materialized_runtime_service_backend &) = delete;
	/** @brief Materialized service backends cannot be copy-assigned. */
	materialized_runtime_service_backend &operator=(const materialized_runtime_service_backend &) = delete;
	/** @brief Materialized service backends cannot be moved. */
	materialized_runtime_service_backend(materialized_runtime_service_backend &&) = delete;
	/** @brief Materialized service backends cannot be move-assigned. */
	materialized_runtime_service_backend &operator=(materialized_runtime_service_backend &&) = delete;
	/** @brief Destroy after every native or facility-owned service has joined. */
	~materialized_runtime_service_backend() override = default;

	/** @copydoc runtime_service_backend::bind_coordinator */
	[[nodiscard]] kinetum::common::status
	bind_coordinator(const kinetum::common::compiled_runtime_service &coordinator) noexcept override;

	/** @copydoc runtime_service_backend::launch_executor */
	[[nodiscard]] kinetum::common::status launch_executor(const kinetum::common::compiled_runtime_service &service,
							      runtime_service_entry_fn entry,
							      void *argument) noexcept override;

	/** @copydoc runtime_service_backend::join_executor */
	[[nodiscard]] kinetum::common::status
	join_executor(const kinetum::common::compiled_runtime_service &service) noexcept override;

    private:
	/**
	 * @brief Adopt an already validated service-to-facility table.
	 *
	 * @param service_facilities Exact facility operation by service index; null
	 *        selects the native mechanism.
	 * @param native_backend Sole native runtime-service backend.
	 */
	materialized_runtime_service_backend(
		std::vector<const kinetum_provider_process_facility_operations *> service_facilities,
		std::unique_ptr<native_runtime_service_backend> native_backend) noexcept;

	/**
	 * @brief Resolve one exact service owner.
	 *
	 * @param service_index Exact compact runtime-service index.
	 * @return Facility operation owner, or null for native execution.
	 */
	[[nodiscard]] const kinetum_provider_process_facility_operations *
	service_facility_(uint32_t service_index) const noexcept;

	std::vector<const kinetum_provider_process_facility_operations *>
		service_facilities_;  ///< Exact facility operation by service index; null means native.
	std::unique_ptr<native_runtime_service_backend> native_backend_;  ///< Sole native service owner.
};

}  // namespace kinetum::dp::lifecycle
