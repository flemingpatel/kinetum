// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_input_scheduler.hpp
 * @brief Generation-owned fair input service in exact worker NUMA storage.
 * @author Fleming Patel
 *
 * Immutable endpoints name pre-resolved RX streams and inbound boundaries.
 * The shared service-order primitive owns only bounded allowances and order;
 * packet, staging, and epoch ownership remain with the worker kernel.
 */

#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>

#include <kinetum/algo/bounded_service_order.hpp>

#include "src/common/status_or.hpp"
#include "src/dp/numa_memory.hpp"

namespace kinetum::dp
{

/** @brief Closed namespaces of pre-resolved packet-worker inputs. */
enum class worker_input_kind : uint8_t {
	RX_STREAM = 1,	///< Provider RX operation stamped with the current source epoch.
	BOUNDARY = 2,	///< DATA channel admitted only at the current active epoch.
};

/** @brief Stable endpoint identity within one worker generation. */
struct worker_input_endpoint {
	worker_input_kind kind{worker_input_kind::RX_STREAM};  ///< Owning kernel table.
	uint32_t ordinal{0};				       ///< Exact index within that table.
};

/** @brief Cold construction input consumed before any packet admission. */
struct worker_input_binding {
	worker_input_endpoint endpoint{};  ///< Pre-resolved input identity.
	uint16_t quantum{0};		   ///< Exact positive provider/worker burst ceiling.
};

/**
 * @brief Own one complete input schedule without owning any packets.
 *
 * @par Thread Safety
 * Construction and destruction are cold and externally serialized. Only the
 * exact packet worker invokes service(); callbacks cannot retain schedule
 * references. Destruction follows worker join and discards all allowances.
 *
 * @par Performance
 * Endpoints, links, allowances, and mutable order controls share one prefaulted
 * worker-NUMA allocation. Per-turn service is bounded by input count and burst
 * ceilings, independent of queue depth; no allocation or synchronization occurs.
 */
class worker_input_scheduler final {
    public:
	/**
	 * @brief Materialize one exact sorted input population on its owner's node.
	 * @param bindings Unique entries sorted by kind and then ordinal; may be empty.
	 * @param numa_node Exact nonnegative worker NUMA node.
	 * @return Complete scheduler, or an explicit shape/allocation error.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_input_scheduler>>
	create(std::span<const worker_input_binding> bindings, int32_t numa_node);

	/** @brief Reject copying a mapping and its mutable service authority. */
	worker_input_scheduler(const worker_input_scheduler &) = delete;
	/** @brief Reject copy assignment of a generation-owned scheduler. */
	worker_input_scheduler &operator=(const worker_input_scheduler &) = delete;
	/** @brief Keep the complete scheduler stable until its worker joins. */
	worker_input_scheduler(worker_input_scheduler &&) = delete;
	/** @brief Reject replacement of a scheduler with a different owner. */
	worker_input_scheduler &operator=(worker_input_scheduler &&) = delete;
	/** @brief Retire the order before reclaiming its borrowed NUMA storage. */
	~worker_input_scheduler();

	/**
	 * @brief Admit one fair bounded turn through the sole worker kernel.
	 * @tparam admit_type Nonthrowing endpoint-service callable.
	 * @param admit Receives an immutable endpoint and positive allowance; returns
	 *        actual transferred/rejected work and its continuation disposition.
	 */
	template <typename admit_type>
	void service(admit_type &&admit) noexcept
	{
		static_assert(std::is_nothrow_invocable_r_v<algo::service_result, admit_type &,
							    const worker_input_endpoint &, uint16_t>);
		if (order_ == nullptr) {
			return;
		}
		order_->service([this, &admit](uint32_t index, uint16_t allowance) noexcept {
			return admit(endpoints_[index], allowance);
		});
	}

    private:
	/**
	 * @brief Adopt the complete cold materialization, including an empty schedule.
	 * @param storage Sole mapping containing all nonempty schedule state.
	 * @param order Placement-constructed ordering owner, null only for no inputs.
	 * @param endpoints Exact immutable endpoint projection borrowed from storage.
	 */
	worker_input_scheduler(numa_memory_region storage, algo::bounded_service_order *order,
			       std::span<const worker_input_endpoint> endpoints) noexcept;

	numa_memory_region storage_;			    ///< Sole mapping; destroyed after every borrowed object.
	algo::bounded_service_order *order_{nullptr};	    ///< Mutable controls placed on the worker's NUMA node.
	std::span<const worker_input_endpoint> endpoints_;  ///< Immutable compact input identities.
};

}  // namespace kinetum::dp
