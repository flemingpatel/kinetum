// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_numa_placement.cpp
 * @brief Native root, nested-array and poller placement under cross-node construction.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <thread>
#include <vector>

#include <kinetum/algo/quiescence.hpp>

#include "src/dp/epoch/boundary_epoch_storage.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "src/dp/epoch/worker_epoch_activation.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/fixed_packet_pool.hpp"
#include "src/dp/module/module_manager.hpp"
#include "src/dp/packet_worker_kernel.hpp"
#include "src/dp/thread_affinity.hpp"
#include "src/dp/worker_lifecycle.hpp"
#include "src/dp/worker_runtime_command.hpp"
#include "src/dp/worker_input_scheduler.hpp"
#include "src/dp/worker_packet_staging.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/provider/provider_runtime_materialization.hpp"
#include "tests/numa_placement_test_support.hpp"
#include "tests/packet_runtime_test_fixture.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Inspect factory-owned ranges on two genuinely distinct native nodes. */
class WorkerNumaPlacementTest : public kinetum::test::NumaPlacementTest {};

/**
 * @brief Query the complete actual region without substituting its recorded node.
 * @param region Live mapping containing the object's nested storage.
 * @param expected_node Independently selected compiled placement.
 * @return Every resident page agrees, or an explicit observation failure.
 */
[[nodiscard]] ::testing::AssertionResult inspect_region(const numa_memory_region &region, int32_t expected_node)
{
	return kinetum::test::resident_on_node({static_cast<const std::byte *>(region.data()), region.size()},
					       expected_node);
}

}  // namespace

/** @brief Construction on one node places roots and complete nested storage on each selected worker's node. */
TEST_F(WorkerNumaPlacementTest, worker_owners_ignore_the_construction_threads_node)
{
	std::jthread construction([&] {
		ASSERT_EQ(bind_current_thread_to_cpu_raw(cpus_[0].core_id), 0);
		std::array<numa_owner<worker_epoch_ledger>, 2> ledgers;
		for (uint32_t index = 0u; index < cpus_.size(); ++index) {
			SCOPED_TRACE(index);
			const auto node = cpus_[index].numa_node;
			auto pool_or = fixed_packet_pool::create({
				.record_count = 5u,
				.data_room_bytes = 193u,
				.headroom_bytes = 128u,
				.alignment_bytes = 256u,
				.domain_index = 3u,
				.generation = 17u,
				.host_numa_node = node,
			});
			ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
			auto pool = std::move(pool_or).value();
			const auto &pool_storage = pool->storage_region();
			EXPECT_TRUE(inspect_region(pool_storage, node));
			std::array<packet_record *, 8> records{};
			const uint16_t acquired = pool->acquire_burst(records.data(), records.size());
			EXPECT_EQ(acquired, 5u);
			for (uint16_t ordinal = 0u; ordinal < acquired; ++ordinal) {
				EXPECT_TRUE(numa_layout::contains(pool_storage, records[ordinal]));
				EXPECT_TRUE(numa_layout::contains_extent(
					pool_storage,
					{reinterpret_cast<const std::byte *>(records[ordinal]->storage.data), 65u}));
			}
			if (acquired != 0u) {
				pool->operations().release_burst(pool->operations().state, records.data(), acquired);
			}
			EXPECT_EQ(pool->available_approx(), 5u);
			auto ledger_or = worker_epoch_ledger::create(index, 17u, 1024u, node);
			ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
			ledgers[index] = std::move(ledger_or).value();
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(ledgers[index], node));

			constexpr std::array<worker_input_binding, 2> INPUTS{{
				{{worker_input_kind::RX_STREAM, 3u}, 64u},
				{{worker_input_kind::BOUNDARY, 19u}, 64u},
			}};
			auto input = worker_input_scheduler::create(INPUTS, node);
			ASSERT_TRUE(input.is_ok()) << input.error().message();
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(input.value(), node));

			constexpr std::array<packet_work_key, 2> KEYS{{
				{2u, packet_work_phase::RX_DELIVER, {}},
				{97u, packet_work_phase::EXECUTE, {}},
			}};
			const std::array<worker_packet_staging_domain, 2> DOMAINS{{
				{3u, 1024u, 1024u, KEYS},
				{11u, 1024u, std::nullopt, KEYS},
			}};
			auto staging = worker_packet_staging::create(DOMAINS, node);
			ASSERT_TRUE(staging.is_ok()) << staging.error().message();
			const auto &storage = staging.value()->storage_region();
			EXPECT_TRUE(inspect_region(storage, node));
			for (const auto &domain : staging.value()->domains()) {
				EXPECT_TRUE(numa_layout::contains(storage, &domain));
			}

			auto channel = worker_telemetry_channel::create(index, 0u, node, cpus_[1u - index].numa_node);
			ASSERT_TRUE(channel.is_ok()) << channel.error().message();
			EXPECT_TRUE(inspect_region(channel.value()->returned_storage_region(), node));
			EXPECT_TRUE(inspect_region(channel.value()->completed_storage_region(),
						   cpus_[1u - index].numa_node));
			constexpr std::array<uint32_t, 2> STAGES{2u, 97u};
			constexpr std::array<uint32_t, 2> STREAMS{3u, 19u};
			auto telemetry = worker_runtime_telemetry::create(17u, index, node, STAGES, STREAMS, 1000u,
									  *channel.value());
			ASSERT_TRUE(telemetry.is_ok()) << telemetry.error().message();
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(telemetry.value(), node));

			auto sender = worker_boundary_sender::create(index, 17u, {}, {}, node);
			auto receiver = worker_boundary_receiver::create(index, 17u, {}, node);
			ASSERT_TRUE(sender.is_ok()) << sender.error().message();
			ASSERT_TRUE(receiver.is_ok()) << receiver.error().message();
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(sender.value(), node));
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(receiver.value(), node));
			auto activation = worker_epoch_activation::create(index, 17u, {}, {}, *ledgers[index], nullptr,
									  nullptr, *telemetry.value());
			ASSERT_TRUE(activation.is_ok()) << activation.error().message();
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(activation.value(), node));

			auto slab = boundary_epoch_worker_slab::create(index, node, 2u, 2u);
			ASSERT_TRUE(slab.is_ok()) << slab.error().message();
			EXPECT_TRUE(inspect_region(slab.value()->storage_region(), node));
			common::compiled_transition_boundary boundary{};
			boundary.sender_worker_index = index;
			boundary.receiver_worker_index = 1u - index;
			boundary.future_output_hold_capacity = 1024u;
			auto hold = boundary_future_output_hold::create(boundary, node);
			ASSERT_TRUE(hold.is_ok()) << hold.error().message();
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(hold.value(), node));
		}
		EXPECT_TRUE(kinetum::test::resident_owner_on_node(ledgers[0], cpus_[0].numa_node));
		EXPECT_TRUE(kinetum::test::resident_owner_on_node(ledgers[1], cpus_[1].numa_node));
	});
}

/** @brief A real compiled kernel places its root, private tables, scratch and launcher records across node boundaries. */
TEST_F(WorkerNumaPlacementTest, compiled_kernel_layout_is_resident_on_its_worker_node)
{
	namespace fixture = kinetum::test::packet_runtime_fixture_detail;
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	fixture::host_selection selection;
	selection.numa_node = cpus_[1].numa_node;
	for (const auto &cpu : host.cpus) {
		if (cpu.numa_node == selection.numa_node) {
			selection.cpu_cores.push_back(cpu.core_id);
		}
	}
	if (selection.cpu_cores.size() < fixture::TEST_RUNTIME_CORE_COUNT) {
		GTEST_SKIP() << "cross-node kernel qualification requires the complete fixture CPU population";
	}
	selection.cpu_cores.resize(fixture::TEST_RUNTIME_CORE_COUNT);
	for (std::size_t attempt = 0u; attempt < fixture::MAX_UDP_RX_HANDOFF_ATTEMPTS; ++attempt) {
		auto rx_or = fixture::udp_port_reservation::create();
		auto tx_or = fixture::udp_port_reservation::create();
		ASSERT_TRUE(rx_or.is_ok()) << rx_or.error().message();
		ASSERT_TRUE(tx_or.is_ok()) << tx_or.error().message();
		auto rx = std::move(rx_or).value();
		auto tx = std::move(tx_or).value();
		auto compiled_or = fixture::compile_runtime_fixture(fixture::make_pipeline(std::nullopt), selection,
								    rx.port(), tx.port(), 0u, 0u);
		ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
		auto compiled = std::move(compiled_or).value();
		const auto &topology = compiled.topology;
		ASSERT_EQ(topology.worker_schedules.size(), 1u);
		ASSERT_TRUE(topology.transition_topology.boundaries.empty());
		ASSERT_TRUE(topology.module_contexts.empty());

		kinetum::test::provider_component_test_fixture installation;
		const auto staged = fixture::stage_provider_inventory(installation);
		ASSERT_TRUE(staged.is_ok()) << staged.message();
		auto admitted_or = provider::admit_installed_provider_runtime(topology, installation.root(),
									      installation.runtime_image(),
									      kinetum::test::PROVIDER_TEST_PUBLIC_KEY,
									      installation.file_policy());
		ASSERT_TRUE(admitted_or.is_ok()) << admitted_or.error().message();
		ASSERT_TRUE(rx.release().is_ok());
		bool handoff_collision = false;
		std::jthread construction([&] {
			ASSERT_EQ(bind_current_thread_to_cpu_raw(cpus_[0].core_id), 0);
			auto providers_or = provider::materialized_provider_runtime::create(
				std::move(admitted_or).value(), topology, 17u);
			if (!providers_or.is_ok() && fixture::is_udp_rx_handoff_collision(providers_or.error())) {
				handoff_collision = true;
				return;
			}
			ASSERT_TRUE(providers_or.is_ok()) << providers_or.error().message();
			auto providers = std::move(providers_or).value();
			module::module_manager modules;
			auto commands = worker_runtime_command_publication::create(17u);
			ASSERT_TRUE(commands.is_ok()) << commands.error().message();
			auto channel =
				worker_telemetry_channel::create(0u, 0u, selection.numa_node, cpus_[0].numa_node);
			ASSERT_TRUE(channel.is_ok()) << channel.error().message();
			const auto &schedule = topology.worker_schedules.front();
			std::vector<uint32_t> streams = schedule.rx_stream_indices;
			streams.insert(streams.end(), schedule.tx_stream_indices.begin(),
				       schedule.tx_stream_indices.end());
			std::sort(streams.begin(), streams.end());
			auto telemetry = worker_runtime_telemetry::create(17u, 0u, selection.numa_node,
									  schedule.stage_instance_indices, streams,
									  1000u, *channel.value());
			ASSERT_TRUE(telemetry.is_ok()) << telemetry.error().message();
			auto sender = worker_boundary_sender::create(0u, 17u, {}, {}, selection.numa_node);
			auto receiver = worker_boundary_receiver::create(0u, 17u, {}, selection.numa_node);
			ASSERT_TRUE(sender.is_ok()) << sender.error().message();
			ASSERT_TRUE(receiver.is_ok()) << receiver.error().message();
			epoch_protocol_fault_latch faults;
			auto kernel = packet_worker_kernel::create(0u, topology, *providers, modules, *commands.value(),
								   {}, std::move(sender).value(),
								   std::move(receiver).value(), *telemetry.value(),
								   faults, {});
			ASSERT_TRUE(kernel.is_ok()) << kernel.error().message();
			EXPECT_TRUE(kinetum::test::resident_owner_on_node(kernel.value(), selection.numa_node));
			const auto &region = kernel.value().get_deleter().region;
			EXPECT_TRUE(numa_layout::contains(region, &kernel.value()->lifecycle_record()));
			EXPECT_TRUE(numa_layout::contains(region, &kernel.value()->quiescence_reader_registration()));
		});
		construction.join();
		if (!handoff_collision) {
			return;
		}
	}
	FAIL() << "kernel placement qualification could not hand off an unoccupied UDP endpoint";
}

}  // namespace kinetum::dp
