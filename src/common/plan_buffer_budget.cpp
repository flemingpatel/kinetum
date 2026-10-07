// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file plan_buffer_budget.cpp
 * @brief Provider-neutral packet-storage credit budget implementation.
 * @author Fleming Patel
 */

#include "src/common/plan_buffer_budget.hpp"

#include <cstdint>
#include <limits>
#include <string>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"

namespace kinetum::common
{

namespace
{

/**
 * @brief Add one named nonnegative budget term with exact overflow detection.
 *
 * @param[in,out] total Running total, unchanged on failure.
 * @param term Term to add.
 * @param name Stable diagnostic identity.
 * @return OK after addition, or OUT_OF_RANGE on overflow.
 */
[[nodiscard]] status add_checked(uint64_t &total, uint64_t term, const char *name)
{
	if (term > std::numeric_limits<uint64_t>::max() - total) {
		return status(status_code::OUT_OF_RANGE,
			      std::string("packet-storage budget overflows uint64 while adding ") + name);
	}
	total += term;
	return status::ok();
}

/**
 * @brief Multiply one named nonnegative budget term exactly.
 *
 * @param left Left factor.
 * @param right Right factor.
 * @param name Stable diagnostic identity.
 * @return Exact product, or OUT_OF_RANGE on overflow.
 */
[[nodiscard]] status_or<uint64_t> multiply_checked(uint64_t left, uint64_t right, const char *name)
{
	if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left) {
		return status(status_code::OUT_OF_RANGE,
			      std::string("packet-storage budget overflows uint64 while computing ") + name);
	}
	return left * right;
}

}  // namespace

status_or<compiled_storage_domain_buffer_budget>
compile_storage_domain_buffer_budget(const storage_domain_buffer_budget_inputs &inputs)
{
	if (inputs.storage_domain_id.empty()) {
		return status::invalid_argument("packet-storage budget requires a nonempty storage_domain_id");
	}
	if (inputs.declared_buffer_count == 0) {
		return status(status_code::INVALID_ARGUMENT, "packet storage domain has zero declared buffer_count",
			      inputs.storage_domain_id);
	}
	if (inputs.worker_count == 0) {
		return status(status_code::INVALID_ARGUMENT,
			      "packet-storage budget requires at least one proven owner worker",
			      inputs.storage_domain_id);
	}
	if (inputs.worker_staging_capacity == 0u) {
		return status(status_code::INVALID_ARGUMENT,
			      "packet-storage budget requires nonzero exact worker staging", inputs.storage_domain_id);
	}
	const auto burst_slack_or = multiply_checked(static_cast<uint64_t>(runtime_sizing::PACKET_MAX_BURST_SIZE),
						     inputs.worker_count, "worker burst slack");
	if (!burst_slack_or.is_ok()) {
		return burst_slack_or.error();
	}
	const auto worker_cache_or =
		multiply_checked(inputs.cache_size_per_worker, inputs.worker_count, "worker cache reservation");
	if (!worker_cache_or.is_ok()) {
		return worker_cache_or.error();
	}

	uint64_t required = 0;
	constexpr uint64_t SAFETY_MARGIN = runtime_sizing::PACKET_MAX_BURST_SIZE;
	for (const auto term :
	     {inputs.rx_descriptor_count, inputs.tx_descriptor_count, inputs.worker_staging_capacity,
	      inputs.handoff_staging_capacity, inputs.source_future_staging_capacity, inputs.future_output_capacity,
	      inputs.active_retained_capacity, burst_slack_or.value(), worker_cache_or.value(), SAFETY_MARGIN}) {
		if (const auto term_status = add_checked(required, term, "complete storage-domain total");
		    !term_status.is_ok()) {
			return term_status;
		}
	}

	if (inputs.declared_buffer_count < required) {
		return status(status_code::INVALID_ARGUMENT,
			      "packet storage domain '" + inputs.storage_domain_id +
				      "' buffer_count below computed minimum: " +
				      std::to_string(inputs.declared_buffer_count) + " < " + std::to_string(required),
			      inputs.storage_domain_id);
	}

	return compiled_storage_domain_buffer_budget{inputs.storage_domain_id, required,
						     runtime_sizing::PACKET_MAX_BURST_SIZE};
}

}  // namespace kinetum::common
