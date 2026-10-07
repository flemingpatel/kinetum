// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file gluon_test_deployment.hpp
 * @brief Explicit provider-graph fixtures shared by Gluon unit tests.
 * @author Fleming Patel
 *
 * These helpers author explicit test deployment intent. They are not planner
 * defaults and are never linked into production. The base fixture spells out
 * the UDP driver, host storage, CPU execution, logical ports, queues, and stage
 * execution ownership required by its pipeline, but deliberately does not
 * manufacture module lifecycle-memory capacity. Module resources and storage
 * transitions remain explicit caller-authored intent because pipeline shape
 * alone cannot prove either contract.
 */

#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>
#include <utility>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/execution/cpu/v1/cpu_execution.pb.h"
#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "gen/kinetum/storage/host/v1/host_storage.pb.h"
#include "gen/kinetum/transition/core/v1/core_transition.pb.h"
#include "src/axiom/stage_configuration.hpp"

namespace kinetum::test
{

namespace detail
{

/** @brief Required pipeline directions for one logical test interface. */
struct test_interface_directions {
	bool rx{false};	 ///< Pipeline contains an RX stage for the interface.
	bool tx{false};	 ///< Pipeline contains a TX stage for the interface.
};

}  // namespace detail

/**
 * @brief Author one exact lane-local module lifecycle-memory contract.
 *
 * The caller supplies both nonzero capacities. This helper performs no sizing,
 * multiplication, or default selection; it only writes explicit test intent.
 *
 * @param bindings Deployment intent to extend.
 * @param logical_stage_id Exact module-stage identity.
 * @param lane_id Exact execution-lane identity.
 * @param context_memory_capacity_bytes Aggregate context-lifetime byte bound.
 * @param epoch_arena_capacity_bytes Per-epoch arena byte bound.
 */
inline void add_module_context_resource_binding(kinetum::gluon::v1::DeploymentBindings &bindings,
						std::string_view logical_stage_id, std::string_view lane_id,
						uint64_t context_memory_capacity_bytes,
						uint64_t epoch_arena_capacity_bytes)
{
	auto *binding = bindings.add_module_context_resource_bindings();
	binding->set_logical_stage_id(logical_stage_id.data(), logical_stage_id.size());
	binding->set_lane_id(lane_id.data(), lane_id.size());
	binding->set_context_memory_capacity_bytes(context_memory_capacity_bytes);
	binding->set_epoch_arena_capacity_bytes(epoch_arena_capacity_bytes);
}

/**
 * @brief Build single-queue UDP/host/CPU intent for one test pipeline.
 *
 * Each logical interface receives one exact numeric loopback endpoint and
 * queue zero with an explicit descriptor count. All stages bind to one
 * explicit CPU execution instance and all streams bind to one host-storage
 * domain. The helper deliberately emits no storage transition: callers that
 * place adjacent stage instances on different workers or execution providers
 * must author the exact transition separately. Module-bearing callers must
 * likewise author every lane-local lifecycle-memory contract separately.
 *
 * @param pipeline Pipeline whose I/O and stage identities are bound.
 * @return Provider bindings suitable for platform-only planner fixtures, or
 *         for explicit extension by module-bearing callers.
 */
[[nodiscard]] inline kinetum::gluon::v1::DeploymentBindings
make_udp_test_deployment_bindings(const kinetum::axiom::v1::Pipeline &pipeline)
{
	constexpr uint32_t TEST_UDP_PORT_BASE = 20'000;
	constexpr uint32_t TEST_DESCRIPTOR_COUNT = 1024;
	constexpr uint32_t TEST_BUFFER_COUNT = 131'071;
	constexpr uint32_t TEST_DATA_ROOM_BYTES = 2048;
	constexpr uint32_t TEST_HEADROOM_BYTES = 128;
	constexpr uint32_t TEST_ALIGNMENT_BYTES = 64;
	constexpr const char *IO_DRIVER_INSTANCE_ID = "io_udp_0";
	constexpr const char *STORAGE_DOMAIN_ID = "storage_host_0";
	constexpr const char *EXECUTION_PROVIDER_INSTANCE_ID = "execution_cpu_0";

	kinetum::gluon::v1::DeploymentBindings bindings;

	std::map<std::string, detail::test_interface_directions> interfaces;
	for (const auto &stage : pipeline.stages()) {
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_RX) {
			interfaces[std::string(kinetum::axiom::stage_interface(stage))].rx = true;
		} else if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_TX) {
			interfaces[std::string(kinetum::axiom::stage_interface(stage))].tx = true;
		}
	}

	kinetum::io::udp::v1::UdpDriverConfig driver_configuration;
	uint32_t port_offset = 0;
	for (const auto &[logical_name, directions] : interfaces) {
		auto *driver_port = driver_configuration.add_ports();
		driver_port->set_driver_port_id(logical_name);
		driver_port->set_ipv4_address("127.0.0.1");
		driver_port->set_port(TEST_UDP_PORT_BASE + port_offset);
		++port_offset;

		auto *logical_port = bindings.add_logical_port_bindings();
		logical_port->set_logical_name(logical_name);
		logical_port->set_io_driver_instance_id(IO_DRIVER_INSTANCE_ID);
		logical_port->set_driver_port_id(logical_name);
		logical_port->set_mtu(1500);
		if (directions.rx && directions.tx) {
			logical_port->set_direction(kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL);
		} else if (directions.rx) {
			logical_port->set_direction(kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY);
		} else {
			logical_port->set_direction(kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY);
		}

		for (const auto &[required, direction] :
		     {std::pair{directions.rx, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX},
		      std::pair{directions.tx, kinetum::gluon::v1::IO_STREAM_DIRECTION_TX}}) {
			if (!required) {
				continue;
			}
			auto *stream = bindings.add_io_stream_bindings();
			stream->set_logical_name(logical_name);
			stream->set_direction(direction);
			auto *queue = stream->add_queues();
			queue->set_driver_queue_id(0);
			queue->set_descriptor_count(TEST_DESCRIPTOR_COUNT);
			if (direction == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				queue->set_rx_storage_domain_id(STORAGE_DOMAIN_ID);
			} else {
				queue->mutable_tx_storage()->add_storage_domain_ids(STORAGE_DOMAIN_ID);
			}
			stream->mutable_steering()->set_kind(kinetum::gluon::v1::TRAFFIC_STEERING_KIND_NONE);
		}
	}

	auto *driver = bindings.add_io_driver_instances();
	driver->set_io_driver_instance_id(IO_DRIVER_INSTANCE_ID);
	driver->mutable_configuration()->PackFrom(driver_configuration);

	kinetum::storage::host::v1::HostStorageConfig storage_configuration;
	auto *storage = bindings.add_packet_storage_domains();
	storage->set_storage_domain_id(STORAGE_DOMAIN_ID);
	storage->mutable_configuration()->PackFrom(storage_configuration);
	storage->set_buffer_count(TEST_BUFFER_COUNT);
	storage->set_data_room_bytes(TEST_DATA_ROOM_BYTES);
	storage->set_headroom_bytes(TEST_HEADROOM_BYTES);
	storage->set_alignment_bytes(TEST_ALIGNMENT_BYTES);
	storage->set_host_numa_node(0);

	kinetum::execution::cpu::v1::CpuExecutionConfig execution_configuration;
	auto *execution = bindings.add_execution_provider_instances();
	execution->set_execution_provider_instance_id(EXECUTION_PROVIDER_INSTANCE_ID);
	execution->mutable_configuration()->PackFrom(execution_configuration);

	for (const auto &stage : pipeline.stages()) {
		auto *stage_binding = bindings.add_stage_execution_bindings();
		stage_binding->set_logical_stage_id(stage.stage_id());
		stage_binding->set_execution_provider_instance_id(EXECUTION_PROVIDER_INSTANCE_ID);
		if (stage.execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
			auto *origin = bindings.add_active_origin_bindings();
			origin->set_logical_stage_id(stage.stage_id());
			origin->set_lane_id("lane_0");
			origin->set_storage_domain_id(STORAGE_DOMAIN_ID);
		}
	}

	return bindings;
}

/**
 * @brief Build test deployment intent with one explicit module-resource contract per module stage.
 *
 * The caller selects both capacities. This overload neither derives values
 * from module configuration nor supplies a fallback; it applies the exact
 * caller-authored contract to lane zero of every module stage in the fixture.
 * Callers with replicated lanes must author each additional lane separately.
 *
 * @param pipeline Pipeline whose I/O, stage, and module-resource identities are bound.
 * @param context_memory_capacity_bytes Aggregate context-lifetime byte bound for each module context.
 * @param epoch_arena_capacity_bytes Per-epoch arena byte bound for each module context.
 * @return DeploymentBindings carrying the exact caller-supplied module capacities.
 */
[[nodiscard]] inline kinetum::gluon::v1::DeploymentBindings
make_udp_test_deployment_bindings(const kinetum::axiom::v1::Pipeline &pipeline, uint64_t context_memory_capacity_bytes,
				  uint64_t epoch_arena_capacity_bytes)
{
	auto bindings = make_udp_test_deployment_bindings(pipeline);
	for (const auto &stage : pipeline.stages()) {
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
			add_module_context_resource_binding(bindings, stage.stage_id(), "lane_0",
							    context_memory_capacity_bytes, epoch_arena_capacity_bytes);
		}
	}
	return bindings;
}

/**
 * @brief Add one explicit same-domain zero-copy transition between stage endpoints.
 *
 * This test-only authoring helper does not infer an edge, lane, storage domain,
 * or owner relation. The caller supplies every identity from its fixture.
 *
 * @param bindings Deployment intent to extend.
 * @param transition_id Exact transition identity.
 * @param from_stage_id Source logical-stage identity.
 * @param from_lane_id Source execution-lane identity.
 * @param to_stage_id Destination logical-stage identity.
 * @param to_lane_id Destination execution-lane identity.
 * @param storage_domain_id Exact domain retained across the stage-owner handoff.
 */
inline void add_zero_copy_stage_transition_binding(kinetum::gluon::v1::DeploymentBindings &bindings,
						   std::string_view transition_id, std::string_view from_stage_id,
						   std::string_view from_lane_id, std::string_view to_stage_id,
						   std::string_view to_lane_id, std::string_view storage_domain_id)
{
	kinetum::transition::core::v1::ZeroCopyShareConfig configuration;
	auto *transition = bindings.add_storage_transition_bindings();
	transition->set_transition_id(transition_id.data(), transition_id.size());
	auto *from = transition->mutable_from_endpoint()->mutable_stage();
	from->set_logical_stage_id(from_stage_id.data(), from_stage_id.size());
	from->set_lane_id(from_lane_id.data(), from_lane_id.size());
	auto *to = transition->mutable_to_endpoint()->mutable_stage();
	to->set_logical_stage_id(to_stage_id.data(), to_stage_id.size());
	to->set_lane_id(to_lane_id.data(), to_lane_id.size());
	transition->set_from_storage_domain_id(storage_domain_id.data(), storage_domain_id.size());
	transition->set_to_storage_domain_id(storage_domain_id.data(), storage_domain_id.size());
	transition->mutable_configuration()->PackFrom(configuration);
}

}  // namespace kinetum::test
