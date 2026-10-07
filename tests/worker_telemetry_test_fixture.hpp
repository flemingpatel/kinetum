// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_telemetry_test_fixture.hpp
 * @brief Production-shaped telemetry channel and bank ownership for component tests.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <memory>
#include <span>

#include "src/common/status_or.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::test
{

/** @brief Own one exact channel and worker telemetry bank set. */
struct worker_telemetry_test_owner {
	std::unique_ptr<dp::worker_telemetry_channel> channel;	  ///< Exact poller-local token transport.
	std::unique_ptr<dp::worker_runtime_telemetry> telemetry;  ///< Exact owner-worker banks.

	/** @brief Reclaim a simple active-only worker telemetry lifetime. */
	~worker_telemetry_test_owner()
	{
		if (telemetry == nullptr || channel == nullptr || telemetry->active_epoch() == 0u) {
			return;
		}
		const uint64_t epoch = telemetry->active_epoch();
		if (!telemetry->preflight_shutdown(epoch)) {
			std::terminate();
		}
		telemetry->publish_shutdown(epoch, 2u);
		dp::runtime_telemetry_bank_token token{};
		while (channel->take_completed(token)) {
			if (token.owner_kind != dp::runtime_telemetry_bank_owner_kind::WORKER ||
			    !telemetry->completed_bank(token).is_ok()) {
				std::terminate();
			}
			telemetry->complete_aggregation(token);
			if (token.companion_bank_index != UINT8_MAX) {
				telemetry->mark_epoch_aggregated(epoch);
			}
		}
		if (!telemetry->epoch_aggregated(epoch)) {
			std::terminate();
		}
		if (telemetry->retire_epoch(epoch, 0u).has_value()) {
			std::terminate();
		}
	}

	/**
	 * @brief Create one production-shaped owner over one synthetic stage.
	 * @param worker_index Exact compact worker identity.
	 * @param runtime_generation Exact runtime generation.
	 * @param io_stream_indices Exact owned stream identities; empty for an I/O-free fixture.
	 * @param module_context_count Module owners sharing the channel.
	 * @return Complete owner or exact host/allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_telemetry_test_owner>>
	create(uint32_t worker_index, uint64_t runtime_generation, std::span<const uint32_t> io_stream_indices,
	       std::size_t module_context_count = 0u)
	{
		const auto host = quark::probe_host();
		if (!host.valid || host.memory_numa_nodes.empty()) {
			return common::status::unavailable("test host has no exact memory NUMA node");
		}
		auto owner = std::make_unique<worker_telemetry_test_owner>();
		auto channel_or = dp::worker_telemetry_channel::create(worker_index, module_context_count,
								       host.memory_numa_nodes.front(),
								       host.memory_numa_nodes.front());
		if (!channel_or.is_ok()) {
			return channel_or.error();
		}
		owner->channel = std::move(channel_or).value();
		const std::array<uint32_t, 1> stages{0u};
		auto telemetry_or = dp::worker_runtime_telemetry::create(runtime_generation, worker_index,
									 host.memory_numa_nodes.front(), stages,
									 io_stream_indices, 1000u, *owner->channel);
		if (!telemetry_or.is_ok()) {
			return telemetry_or.error();
		}
		owner->telemetry = std::move(telemetry_or).value();
		return owner;
	}
};

}  // namespace kinetum::test
