// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_compiled_provider_topology.cpp
 * @brief Shared provider-topology compiler exactness tests.
 * @author Fleming Patel
 *
 * These tests restore semantic plan-compilation coverage at the one final
 * compiler authority. They begin with a complete Gluon-authored provider graph,
 * mutate one structural fact at a time, and prove that no consumer can infer a
 * facility, queue, storage domain, execution owner, transition, or host-proof
 * phase.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/facility/dpdk/v1/dpdk_facility.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "gen/kinetum/io/dpdk/v1/dpdk_driver.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "gen/kinetum/storage/dpdk/v1/dpdk_storage.pb.h"
#include "gen/kinetum/storage/host/v1/host_storage.pb.h"
#include "gen/kinetum/transition/core/v1/core_transition.pb.h"
#include "gen/kinetum/transition/cpu/v1/cpu_transition.pb.h"
#include "src/axiom/axiom_contract.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/plan_buffer_budget.hpp"
#include "src/common/runtime_sizing.hpp"
#include "src/common/status_or.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_component_abi.h"
#include "src/provider/provider_contract_catalog.hpp"
#include "tests/gluon_test_deployment.hpp"

namespace kinetum::provider
{
namespace
{

/** Context-memory authority supplied to compiler fixture modules. */
constexpr uint64_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = uint64_t{2} * 1024u * 1024u;
/** Epoch-arena authority supplied to compiler fixture modules. */
constexpr uint64_t TEST_EPOCH_ARENA_CAPACITY_BYTES = uint64_t{2} * 1024u * 1024u;

/**
 * @brief Build the minimal complete RX-to-TX pipeline used by compiler tests.
 * @return Minimal complete fixture pipeline.
 */
[[nodiscard]] kinetum::axiom::v1::Pipeline make_compiler_pipeline()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("provider_compiler_pipeline");

	auto *rx = pipeline.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("wan0");

	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("lan0");

	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id("rx");
	edge->set_to_stage_id("tx");
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Build one RX-to-active-module-to-TX compiler fixture.
 * @return Fixture pipeline with an admitted active module between RX and TX.
 */
[[nodiscard]] kinetum::axiom::v1::Pipeline make_active_compiler_pipeline()
{
	auto pipeline = make_compiler_pipeline();
	pipeline.set_pipeline_id("provider_active_compiler_pipeline");
	pipeline.mutable_edges(0)->set_to_stage_id("active0");

	auto *active = pipeline.add_stages();
	active->set_stage_id("active0");
	active->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	active->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	active->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
	active->mutable_active_stage_limits()->set_retained_packet_capacity(7u);
	active->mutable_active_stage_limits()->set_retained_byte_capacity(7000u);
	active->mutable_module()->set_module_id("kinetum.test_active");
	active->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	auto *active_to_tx = pipeline.add_edges();
	active_to_tx->set_from_stage_id("active0");
	active_to_tx->set_to_stage_id("tx");
	active_to_tx->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Build one cross-worker RX-to-module-to-TX compiler fixture.
 *
 * @return Three-stage pipeline with an exact region-zero to region-one edge.
 */
[[nodiscard]] kinetum::axiom::v1::Pipeline make_transition_compiler_pipeline()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("provider_transition_compiler_pipeline");

	auto *rx = pipeline.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->set_preferred_region(0);
	rx->mutable_io()->set_interface("wan0");

	auto *module = pipeline.add_stages();
	module->set_stage_id("module0");
	module->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	module->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	module->set_preferred_region(1);
	module->mutable_module()->set_module_id("kinetum.test_module");
	module->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->set_preferred_region(1);
	tx->mutable_io()->set_interface("lan0");

	auto *rx_to_module = pipeline.add_edges();
	rx_to_module->set_from_stage_id("rx");
	rx_to_module->set_to_stage_id("module0");
	rx_to_module->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	auto *module_to_tx = pipeline.add_edges();
	module_to_tx->set_from_stage_id("module0");
	module_to_tx->set_to_stage_id("tx");
	module_to_tx->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Build two source domains converging through one cross-worker edge.
 *
 * @return Five-stage fan-in pipeline with one exact region boundary.
 */
[[nodiscard]] kinetum::axiom::v1::Pipeline make_converging_transition_pipeline()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("provider_converging_transition_pipeline");
	pipeline.set_allow_dag(true);

	auto add_rx = [&](std::string_view stage_id, std::string_view interface_name) {
		auto *stage = pipeline.add_stages();
		stage->set_stage_id(stage_id.data(), stage_id.size());
		stage->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		stage->set_preferred_region(0);
		stage->mutable_io()->set_interface(interface_name.data(), interface_name.size());
	};
	add_rx("rx0", "wan0");
	add_rx("rx1", "wan1");

	auto add_module = [&](std::string_view stage_id, int32_t region) {
		auto *stage = pipeline.add_stages();
		stage->set_stage_id(stage_id.data(), stage_id.size());
		stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		stage->set_preferred_region(region);
		stage->mutable_module()->set_module_id("kinetum.test_module");
		stage->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	};
	add_module("merge", 0);
	add_module("downstream", 1);

	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->set_preferred_region(1);
	tx->mutable_io()->set_interface("lan0");

	auto add_edge = [&](std::string_view from, std::string_view to) {
		auto *edge = pipeline.add_edges();
		edge->set_from_stage_id(from.data(), from.size());
		edge->set_to_stage_id(to.data(), to.size());
		edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	};
	add_edge("rx0", "merge");
	add_edge("rx1", "merge");
	add_edge("merge", "downstream");
	add_edge("downstream", "tx");
	return pipeline;
}

/**
 * @brief Build one single-region RX-to-module-to-TX compiler fixture.
 *
 * @return Three-stage pipeline suitable for lane replication.
 */
[[nodiscard]] kinetum::axiom::v1::Pipeline make_module_compiler_pipeline()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("provider_module_compiler_pipeline");

	auto *rx = pipeline.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("wan0");

	auto *module = pipeline.add_stages();
	module->set_stage_id("module0");
	module->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	module->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	module->mutable_module()->set_module_id("kinetum.test_module");
	module->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("lan0");

	auto *rx_to_module = pipeline.add_edges();
	rx_to_module->set_from_stage_id("rx");
	rx_to_module->set_to_stage_id("module0");
	rx_to_module->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	auto *module_to_tx = pipeline.add_edges();
	module_to_tx->set_from_stage_id("module0");
	module_to_tx->set_to_stage_id("tx");
	module_to_tx->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Build one priority-routed RX stage with two exact TX destinations.
 *
 * @return Valid conditional packet-routing pipeline.
 */
[[nodiscard]] kinetum::axiom::v1::Pipeline make_priority_route_pipeline()
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("provider_priority_route_pipeline");
	pipeline.set_allow_dag(true);

	auto add_io_stage = [&](std::string_view stage_id, std::string_view interface_name,
				kinetum::axiom::v1::StageKind kind) {
		auto *stage = pipeline.add_stages();
		stage->set_stage_id(stage_id.data(), stage_id.size());
		stage->set_kind(kind);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		stage->mutable_io()->set_interface(interface_name.data(), interface_name.size());
	};
	add_io_stage("rx", "wan0", kinetum::axiom::v1::STAGE_KIND_RX);
	add_io_stage("tx0", "lan0", kinetum::axiom::v1::STAGE_KIND_TX);
	add_io_stage("tx1", "lan1", kinetum::axiom::v1::STAGE_KIND_TX);

	auto *priority = pipeline.add_edges();
	priority->set_from_stage_id("rx");
	priority->set_to_stage_id("tx0");
	priority->set_condition("dscp >= 46");
	priority->set_priority(100);
	priority->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	auto *fallback = pipeline.add_edges();
	fallback->set_from_stage_id("rx");
	fallback->set_to_stage_id("tx1");
	fallback->set_priority(0);
	fallback->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Build exact single-node CPU inventory for workers and runtime services.
 * @return Fixed single-NUMA inventory covering eight explicit CPU identities.
 */
[[nodiscard]] kinetum::hw::v1::HardwareInventory make_compiler_hardware()
{
	kinetum::hw::v1::HardwareInventory hardware;
	auto *node = hardware.mutable_node();
	auto *cpu = node->mutable_cpu();
	for (int32_t core_id = 0; core_id < 8; ++core_id) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(core_id);
		core->set_numa_node(0);
		core->set_is_hyperthread(false);
	}
	return hardware;
}

/**
 * @brief Build exact DPDK NIC facts on the shared compiler host.
 *
 * @return Eight-core single-node hardware with two canonical DPDK PCI ports.
 */
[[nodiscard]] kinetum::hw::v1::HardwareInventory make_dpdk_compiler_hardware()
{
	auto hardware = make_compiler_hardware();
	auto *node = hardware.mutable_node();
	for (uint8_t index = 0; index < 2; ++index) {
		auto *nic = node->add_nics();
		nic->set_pci_address(index == 0 ? "0000:03:00.0" : "0000:03:00.1");
		nic->set_numa_node(0);
		nic->set_mac_address(index == 0u ? "02:00:00:00:00:01" : "02:00:00:00:00:02");
		nic->set_max_mtu(9000);
		nic->set_driver(kinetum::hw::v1::NIC_DRIVER_DPDK);
	}
	return hardware;
}

/**
 * @brief Produce one canonical complete plan through Gluon's real lowering.
 *
 * @param pipeline Complete pipeline to lower.
 * @param bindings Exact deployment intent, including any module-resource facts.
 * @param region_count Exact number of logical regions to lower.
 * @return Valid plan or the exact planner/compiler rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan>
make_provider_plan(const kinetum::axiom::v1::Pipeline &pipeline, kinetum::gluon::v1::DeploymentBindings bindings,
		   int32_t region_count = 1)
{
	kinetum::gluon::planner_options options;
	options.regions = region_count;
	options.reserved_cores = 1;
	options.deployment_bindings = std::move(bindings);
	auto planned_or = kinetum::gluon::plan(pipeline, make_compiler_hardware(), options);
	if (!planned_or.is_ok()) {
		return planned_or.error();
	}
	return std::move(planned_or).value();
}

/**
 * @brief Find one mutable authored I/O-stream binding.
 *
 * @param bindings Complete mutable deployment intent.
 * @param logical_name Exact logical-port identity.
 * @param direction Exact stream direction.
 * @return Matching binding, or nullptr.
 */
[[nodiscard]] kinetum::gluon::v1::IoStreamBinding *find_stream_binding(kinetum::gluon::v1::DeploymentBindings &bindings,
								       std::string_view logical_name,
								       kinetum::gluon::v1::IoStreamDirection direction)
{
	for (auto &binding : *bindings.mutable_io_stream_bindings()) {
		if (binding.logical_name() == logical_name && binding.direction() == direction) {
			return &binding;
		}
	}
	return nullptr;
}

/**
 * @brief Replace one authored stream with a dense exact queue set.
 *
 * @param binding Stream binding to mutate.
 * @param queue_count Number of sequential queues beginning at zero.
 */
void set_queue_count(kinetum::gluon::v1::IoStreamBinding &binding, uint32_t queue_count)
{
	ASSERT_FALSE(binding.queues().empty());
	const auto prototype = binding.queues(0);
	binding.clear_queues();
	for (uint32_t queue_id = 0; queue_id < queue_count; ++queue_id) {
		auto *queue = binding.add_queues();
		queue->CopyFrom(prototype);
		queue->set_driver_queue_id(queue_id);
		queue->set_descriptor_count(1024u + queue_id);
	}
}

/**
 * @brief Plan two ingress queues feeding one same-worker TX queue.
 * @param distinct_storage Select a separately authored domain for the second RX queue.
 * @return Complete plan with shared storage or two original domains admitted by TX.
 * @throws std::runtime_error If the base fixture loses a required queue binding.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_fan_in_storage_plan(bool distinct_storage)
{
	auto pipeline = make_compiler_pipeline();
	pipeline.set_allow_dag(true);
	auto *second_rx = pipeline.add_stages();
	second_rx->set_stage_id("rx1");
	second_rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	second_rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	second_rx->mutable_io()->set_interface("wan1");
	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id("rx1");
	edge->set_to_stage_id("tx");
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	if (distinct_storage) {
		const auto original = bindings.packet_storage_domains(0);
		auto *second = bindings.add_packet_storage_domains();
		second->CopyFrom(original);
		second->set_storage_domain_id("storage_host_1");
		auto *rx = find_stream_binding(bindings, "wan1", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
		auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
		if (rx == nullptr || tx == nullptr) {
			throw std::runtime_error("fan-in storage fixture lost a required stream");
		}
		rx->mutable_queues(0)->set_rx_storage_domain_id("storage_host_1");
		tx->mutable_queues(0)->mutable_tx_storage()->add_storage_domain_ids("storage_host_1");
	}
	return make_provider_plan(pipeline, std::move(bindings));
}

/**
 * @brief Build exact host-storage intent for two domains converging into one.
 *
 * @param pipeline Complete converging packet graph.
 * @return Deployment intent with two bounded-copy transitions on one boundary.
 * @throws std::runtime_error If the canonical base fixture loses an expected owner.
 */
[[nodiscard]] kinetum::gluon::v1::DeploymentBindings
make_converging_transition_bindings(const kinetum::axiom::v1::Pipeline &pipeline)
{
	constexpr uint32_t COPY_STAGING_CAPACITY = 128;
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	if (bindings.packet_storage_domains_size() != 1) {
		throw std::runtime_error("converging-transition fixture requires one canonical host storage domain");
	}
	const auto original_storage = bindings.packet_storage_domains(0);
	for (const std::string_view storage_id :
	     {std::string_view{"storage_host_1"}, std::string_view{"storage_host_2"}}) {
		auto *storage = bindings.add_packet_storage_domains();
		storage->CopyFrom(original_storage);
		storage->set_storage_domain_id(storage_id.data(), storage_id.size());
	}
	auto *second_rx = find_stream_binding(bindings, "wan1", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	if (second_rx == nullptr || tx == nullptr) {
		throw std::runtime_error("converging-transition fixture lost an expected RX or TX stream binding");
	}
	second_rx->mutable_queues(0)->set_rx_storage_domain_id("storage_host_1");
	tx->mutable_queues(0)->mutable_tx_storage()->set_storage_domain_ids(0, "storage_host_2");

	kinetum::transition::cpu::v1::BoundedCopyConfig configuration;
	for (const std::string_view source_domain :
	     {std::string_view{"storage_host_0"}, std::string_view{"storage_host_1"}}) {
		auto *transition = bindings.add_storage_transition_bindings();
		transition->set_transition_id(source_domain == "storage_host_0" ? "merge_to_downstream_copy_0" :
										  "merge_to_downstream_copy_1");
		transition->mutable_from_endpoint()->mutable_stage()->set_logical_stage_id("merge");
		transition->mutable_from_endpoint()->mutable_stage()->set_lane_id("lane_0");
		transition->mutable_to_endpoint()->mutable_stage()->set_logical_stage_id("downstream");
		transition->mutable_to_endpoint()->mutable_stage()->set_lane_id("lane_0");
		transition->set_from_storage_domain_id(source_domain.data(), source_domain.size());
		transition->set_to_storage_domain_id("storage_host_2");
		transition->mutable_configuration()->PackFrom(configuration);
		transition->set_staging_capacity(COPY_STAGING_CAPACITY);
		transition->set_staging_numa_node(0);
	}
	return bindings;
}

/**
 * @brief Build exact DPDK facility, driver, storage, and RSS authoring intent.
 *
 * @param pipeline Pipeline whose complete stage and I/O coverage is required.
 * @return Complete two-queue DPDK deployment bindings.
 * @throws std::runtime_error If the canonical base fixture loses an expected stream owner.
 */
[[nodiscard]] kinetum::gluon::v1::DeploymentBindings
make_dpdk_rss_bindings(const kinetum::axiom::v1::Pipeline &pipeline)
{
	constexpr char RSS_KEY[] = "0123456789abcdef0123456789abcdef01234567";
	constexpr char FACILITY_ID[] = "facility_dpdk_0";
	constexpr char DRIVER_ID[] = "io_dpdk_0";
	constexpr char STORAGE_ID[] = "storage_dpdk_0";

	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	bindings.clear_process_facility_instances();
	kinetum::facility::dpdk::v1::DpdkFacilityConfig facility_configuration;
	auto *facility = bindings.add_process_facility_instances();
	facility->set_facility_instance_id(FACILITY_ID);
	facility->mutable_configuration()->PackFrom(facility_configuration);

	kinetum::io::dpdk::v1::DpdkDriverConfig driver_configuration;
	for (const auto &[driver_port_id, pci_address] :
	     {std::pair{"wan0", "0000:03:00.0"}, std::pair{"lan0", "0000:03:00.1"}}) {
		auto *port = driver_configuration.add_ports();
		port->set_driver_port_id(driver_port_id);
		port->mutable_pci()->set_pci_address(pci_address);
	}
	auto *driver = bindings.mutable_io_driver_instances(0);
	driver->set_io_driver_instance_id(DRIVER_ID);
	driver->clear_facility_instance_ids();
	driver->add_facility_instance_ids(FACILITY_ID);
	driver->mutable_configuration()->PackFrom(driver_configuration);
	for (auto &port : *bindings.mutable_logical_port_bindings()) {
		port.set_io_driver_instance_id(DRIVER_ID);
		port.set_driver_port_id(port.logical_name());
	}

	kinetum::storage::dpdk::v1::DpdkStorageConfig storage_configuration;
	storage_configuration.set_cache_size(256);
	auto *storage = bindings.mutable_packet_storage_domains(0);
	storage->set_storage_domain_id(STORAGE_ID);
	storage->clear_facility_instance_ids();
	storage->add_facility_instance_ids(FACILITY_ID);
	storage->mutable_configuration()->PackFrom(storage_configuration);
	for (auto &stream : *bindings.mutable_io_stream_bindings()) {
		for (auto &queue : *stream.mutable_queues()) {
			if (stream.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				queue.set_rx_storage_domain_id(STORAGE_ID);
			} else {
				queue.mutable_tx_storage()->set_storage_domain_ids(0, STORAGE_ID);
			}
		}
	}

	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	if (rx == nullptr || tx == nullptr) {
		throw std::runtime_error("DPDK RSS fixture lost an expected RX or TX stream binding");
	}
	set_queue_count(*rx, 2);
	rx->mutable_steering()->set_kind(kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS);
	rx->mutable_steering()->set_symmetric(true);
	rx->mutable_steering()->add_hash_fields("ipv4");
	rx->mutable_steering()->add_hash_fields("udp");
	rx->mutable_steering()->set_hash_key(RSS_KEY, sizeof(RSS_KEY) - 1u);
	set_queue_count(*tx, 2);
	for (const auto &stage : pipeline.stages()) {
		if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
			kinetum::test::add_module_context_resource_binding(bindings, stage.stage_id(), "lane_1",
									   TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									   TEST_EPOCH_ARENA_CAPACITY_BYTES);
		}
	}
	return bindings;
}

/**
 * @brief Produce one canonical complete passive plan through real lowering.
 * @return Canonical passive fixture plan, or the planner rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_valid_provider_plan()
{
	const auto pipeline = make_compiler_pipeline();
	return make_provider_plan(pipeline, kinetum::test::make_udp_test_deployment_bindings(pipeline));
}

/**
 * @brief Produce one canonical active-origin plan through real lowering.
 * @return Canonical active fixture plan, or the planner rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_valid_active_provider_plan()
{
	const auto pipeline = make_active_compiler_pipeline();
	return make_provider_plan(
		pipeline, kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									   TEST_EPOCH_ARENA_CAPACITY_BYTES));
}

/**
 * @brief Produce one complete cross-worker transition plan through real lowering.
 *
 * @return Valid plan, or the exact planner/compiler rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_valid_transition_provider_plan()
{
	const auto pipeline = make_transition_compiler_pipeline();
	kinetum::gluon::planner_options options;
	options.regions = 2;
	options.reserved_cores = 1;
	options.deployment_bindings = kinetum::test::make_udp_test_deployment_bindings(
		pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES, TEST_EPOCH_ARENA_CAPACITY_BYTES);
	kinetum::test::add_zero_copy_stage_transition_binding(options.deployment_bindings, "rx_to_module0_share", "rx",
							      "lane_0", "module0", "lane_0", "storage_host_0");
	auto planned_or = kinetum::gluon::plan(pipeline, make_compiler_hardware(), options);
	if (!planned_or.is_ok()) {
		return planned_or.error();
	}
	return std::move(planned_or).value();
}

/**
 * @brief Build one two-worker graph whose ingress alone depends on DPDK.
 *
 * @return Exact DPDK-to-host bounded-copy plan, or fixture-construction failure.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_mixed_dpdk_udp_provider_plan()
{
	auto plan_or = make_valid_transition_provider_plan();
	if (!plan_or.is_ok()) {
		return plan_or.error();
	}
	auto plan = std::move(plan_or).value();
	if (plan.io_driver_instances_size() != 1 || plan.packet_storage_domains_size() != 1) {
		return common::status::internal_error(
			"mixed-provider fixture lost its sole UDP driver or host storage domain");
	}

	kinetum::io::udp::v1::UdpDriverConfig udp_configuration;
	if (!plan.io_driver_instances(0).configuration().UnpackTo(&udp_configuration)) {
		return common::status::internal_error(
			"mixed-provider fixture cannot decode canonical UDP configuration");
	}
	kinetum::io::udp::v1::UdpDriverConfig udp_tx_configuration;
	for (const auto &configured_port : udp_configuration.ports()) {
		if (configured_port.driver_port_id() == "lan0") {
			udp_tx_configuration.add_ports()->CopyFrom(configured_port);
		}
	}
	if (udp_tx_configuration.ports_size() != 1) {
		return common::status::internal_error("mixed-provider fixture lost its UDP TX attachment");
	}
	plan.mutable_io_driver_instances(0)->mutable_configuration()->PackFrom(udp_tx_configuration);

	kinetum::facility::dpdk::v1::DpdkFacilityConfig facility_configuration;
	auto *facility = plan.add_process_facility_instances();
	facility->set_facility_instance_id("facility_dpdk_0");
	facility->mutable_configuration()->PackFrom(facility_configuration);

	kinetum::io::dpdk::v1::DpdkDriverConfig driver_configuration;
	auto *configured_dpdk_port = driver_configuration.add_ports();
	configured_dpdk_port->set_driver_port_id("wan0");
	configured_dpdk_port->mutable_pci()->set_pci_address("0000:03:00.0");
	auto *driver = plan.add_io_driver_instances();
	driver->set_io_driver_instance_id("io_dpdk_0");
	driver->add_facility_instance_ids("facility_dpdk_0");
	driver->mutable_configuration()->PackFrom(driver_configuration);
	plan.mutable_io_driver_instances()->SwapElements(0, 1);

	kinetum::storage::dpdk::v1::DpdkStorageConfig storage_configuration;
	storage_configuration.set_cache_size(256);
	auto *dpdk_storage = plan.add_packet_storage_domains();
	dpdk_storage->CopyFrom(plan.packet_storage_domains(0));
	dpdk_storage->set_storage_domain_id("storage_dpdk_0");
	dpdk_storage->clear_facility_instance_ids();
	dpdk_storage->add_facility_instance_ids("facility_dpdk_0");
	dpdk_storage->mutable_configuration()->PackFrom(storage_configuration);
	plan.mutable_packet_storage_domains()->SwapElements(0, 1);

	kinetum::gluon::v1::PortConfig *wan = nullptr;
	for (auto &port : *plan.mutable_ports()) {
		if (port.logical_name() == "wan0") {
			wan = &port;
		}
	}
	kinetum::gluon::v1::IoStream *rx = nullptr;
	for (auto &stream : *plan.mutable_io_streams()) {
		if (stream.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
			rx = &stream;
		}
	}
	if (wan == nullptr || rx == nullptr) {
		return common::status::internal_error("mixed-provider fixture lost its ingress port or stream");
	}
	wan->set_io_driver_instance_id("io_dpdk_0");
	wan->set_driver_port_id("wan0");
	wan->set_host_numa_node(0);
	const std::string mac_address{"\x02\x00\x00\x00\x00\x01", 6};
	wan->set_resolved_mac_address(mac_address);
	rx->set_rx_storage_domain_id("storage_dpdk_0");

	if (plan.storage_transitions_size() != 1) {
		return common::status::internal_error("mixed-provider fixture lost its exact cross-worker transition");
	}
	kinetum::transition::cpu::v1::BoundedCopyConfig transition_configuration;
	auto *transition = plan.mutable_storage_transitions(0);
	transition->set_transition_id("rx_to_module_host_copy");
	transition->mutable_from_endpoint()->set_stage_instance_id("rx@lane_0");
	transition->mutable_to_endpoint()->set_stage_instance_id("module0@lane_0");
	transition->set_from_storage_domain_id("storage_dpdk_0");
	transition->set_to_storage_domain_id("storage_host_0");
	transition->mutable_configuration()->PackFrom(transition_configuration);
	transition->set_staging_capacity(1024);
	transition->set_staging_numa_node(0);
	return common::status_or<kinetum::gluon::v1::DeploymentPlan>(std::in_place, std::move(plan));
}

/**
 * @brief Produce one complete converging-domain cross-worker plan.
 *
 * @return Valid plan, or the exact planner/compiler rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_valid_converging_transition_plan()
{
	const auto pipeline = make_converging_transition_pipeline();
	kinetum::gluon::planner_options options;
	options.regions = 2;
	options.reserved_cores = 1;
	options.deployment_bindings = make_converging_transition_bindings(pipeline);
	auto planned_or = kinetum::gluon::plan(pipeline, make_compiler_hardware(), options);
	if (!planned_or.is_ok()) {
		return planned_or.error();
	}
	return std::move(planned_or).value();
}

/**
 * @brief Produce one complete two-lane DPDK/RSS plan through real lowering.
 *
 * @param pipeline Complete pipeline whose stages are replicated by RSS lanes.
 * @return Valid plan, or the exact planner/compiler rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan>
make_rss_provider_plan(const kinetum::axiom::v1::Pipeline &pipeline)
{
	kinetum::gluon::planner_options options;
	options.regions = 1;
	options.reserved_cores = 1;
	options.deployment_bindings = make_dpdk_rss_bindings(pipeline);
	auto planned_or = kinetum::gluon::plan(pipeline, make_dpdk_compiler_hardware(), options);
	if (!planned_or.is_ok()) {
		return planned_or.error();
	}
	return std::move(planned_or).value();
}

/**
 * @brief Produce the canonical two-stage DPDK/RSS compiler fixture.
 * @return Canonical RX/TX RSS fixture plan, or the planner rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_valid_rss_provider_plan()
{
	return make_rss_provider_plan(make_compiler_pipeline());
}

/**
 * @brief Produce the canonical replicated-module DPDK/RSS compiler fixture.
 * @return Canonical replicated-module RSS fixture plan, or the planner rejection.
 */
[[nodiscard]] common::status_or<kinetum::gluon::v1::DeploymentPlan> make_valid_rss_module_provider_plan()
{
	return make_rss_provider_plan(make_module_compiler_pipeline());
}

/**
 * @brief Require one mutated plan to fail at the shared compiler.
 *
 * @param plan Mutated plan.
 * @param diagnostic Exact diagnostic fragment expected from the owning phase.
 */
void expect_compiler_reject(const kinetum::gluon::v1::DeploymentPlan &plan, const std::string &diagnostic)
{
	const auto result = compile_provider_topology(plan);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find(diagnostic), std::string::npos) << result.error().message();
}

/**
 * @brief Find one mutable I/O stream by direction.
 *
 * @param plan Mutable exact plan.
 * @param direction Direction to find.
 * @return Matching stream, or nullptr.
 */
[[nodiscard]] kinetum::gluon::v1::IoStream *find_stream(kinetum::gluon::v1::DeploymentPlan &plan,
							kinetum::gluon::v1::IoStreamDirection direction)
{
	for (auto &stream : *plan.mutable_io_streams()) {
		if (stream.direction() == direction) {
			return &stream;
		}
	}
	return nullptr;
}

/**
 * @brief Find one mutable logical port by stable name.
 *
 * @param plan Mutable exact plan.
 * @param logical_name Stable logical-port identity.
 * @return Matching port, or nullptr.
 */
[[nodiscard]] kinetum::gluon::v1::PortConfig *find_port(kinetum::gluon::v1::DeploymentPlan &plan,
							std::string_view logical_name)
{
	for (auto &port : *plan.mutable_ports()) {
		if (port.logical_name() == logical_name) {
			return &port;
		}
	}
	return nullptr;
}

/**
 * @brief Add a second exact host-storage domain and route TX through it.
 *
 * @param plan Mutable valid single-domain plan.
 */
void add_second_host_storage_domain(kinetum::gluon::v1::DeploymentPlan &plan)
{
	ASSERT_EQ(plan.packet_storage_domains_size(), 1);
	const auto source = plan.packet_storage_domains(0);
	auto *destination = plan.add_packet_storage_domains();
	destination->CopyFrom(source);
	destination->set_storage_domain_id("storage_host_1");
	auto *tx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx, nullptr);
	tx->mutable_tx_storage()->set_storage_domain_ids(0, "storage_host_1");
}

/**
 * @brief Add the exact bounded-copy transition needed by the two-domain fixture.
 *
 * @param plan Mutable two-domain plan.
 */
void add_bounded_copy_transition(kinetum::gluon::v1::DeploymentPlan &plan)
{
	kinetum::transition::cpu::v1::BoundedCopyConfig configuration;
	auto *transition = plan.add_storage_transitions();
	transition->set_transition_id("rx_to_tx_copy");
	transition->mutable_from_endpoint()->set_stage_instance_id("rx@lane_0");
	transition->mutable_to_endpoint()->set_stage_instance_id("tx@lane_0");
	transition->set_from_storage_domain_id("storage_host_0");
	transition->set_to_storage_domain_id("storage_host_1");
	transition->mutable_configuration()->PackFrom(configuration);
	transition->set_staging_capacity(1024);
	transition->set_staging_numa_node(0);
}

/** @brief Verify complete exact provider facts compile into stable compact indices. */
TEST(runtime_plan_compiler, compiles_io_streams_from_plan_topology)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.io_drivers.size(), 1u);
	ASSERT_EQ(compiled.storage_domains.size(), 1u);
	ASSERT_EQ(compiled.execution_providers.size(), 1u);
	ASSERT_EQ(compiled.ports.size(), 2u);
	ASSERT_EQ(compiled.stage_instances.size(), 2u);
	ASSERT_EQ(compiled.io_streams.size(), 2u);
	ASSERT_EQ(compiled.worker_schedules.size(), 1u);
	EXPECT_EQ(compiled.io_streams[0].io_stream_index, 0u);
	EXPECT_EQ(compiled.io_streams[1].io_stream_index, 1u);
	EXPECT_EQ(compiled.worker_schedules[0].rx_stream_indices.size(), 1u);
	EXPECT_EQ(compiled.worker_schedules[0].tx_stream_indices.size(), 1u);
	EXPECT_EQ(compiled.worker_schedules[0].stage_instance_indices.size(), 2u);
	EXPECT_EQ(compiled.worker_schedules[0].storage_domain_indices, std::vector<uint32_t>{0u});
	EXPECT_EQ(compiled.worker_schedules[0].source_storage_domain_indices, std::vector<uint32_t>{0u});
}

/** @brief Verify provider compilation rejects unknown plan bytes before any phase output. */
TEST(runtime_plan_compiler, exact_plan_wire_rejects_before_provider_compilation)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.GetReflection()->MutableUnknownFields(&plan)->AddVarint(99, 1u);

	const auto compiled_or = compile_provider_topology(plan);

	ASSERT_FALSE(compiled_or.is_ok());
	EXPECT_EQ(compiled_or.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(compiled_or.error().message().find("unknown protobuf field"), std::string::npos);
}

/** @brief Verify every worker receives exact queue owners and one direct TX table. */
TEST(runtime_plan_compiler, compiles_exact_queue_owners_and_dense_tx_maps)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.worker_schedules.size(), 2u);
	for (const auto &schedule : compiled.worker_schedules) {
		ASSERT_EQ(schedule.rx_stream_indices.size(), 1u);
		ASSERT_EQ(schedule.tx_stream_indices.size(), 1u);
		ASSERT_EQ(schedule.tx_stream_index_by_logical_port.size(), compiled.ports.size());
		const uint32_t rx_index = schedule.rx_stream_indices.front();
		const uint32_t tx_index = schedule.tx_stream_indices.front();
		ASSERT_LT(rx_index, compiled.io_streams.size());
		ASSERT_LT(tx_index, compiled.io_streams.size());
		const auto &rx = compiled.io_streams[rx_index];
		const auto &tx = compiled.io_streams[tx_index];
		EXPECT_EQ(rx.worker_index, schedule.worker_index);
		EXPECT_EQ(tx.worker_index, schedule.worker_index);
		EXPECT_EQ(rx.driver_queue_id, schedule.worker_index);
		EXPECT_EQ(tx.driver_queue_id, schedule.worker_index);
		EXPECT_EQ(schedule.source_storage_domain_indices, (std::vector<uint32_t>{rx.rx_storage_domain_index}));
		const uint32_t tx_logical_port_id = compiled.ports[tx.port_index].logical_port_id;
		ASSERT_LT(tx_logical_port_id, schedule.tx_stream_index_by_logical_port.size());
		EXPECT_EQ(schedule.tx_stream_index_by_logical_port[tx_logical_port_id], tx_index);
		for (std::size_t logical_port_id = 0; logical_port_id < schedule.tx_stream_index_by_logical_port.size();
		     ++logical_port_id) {
			if (logical_port_id != tx_logical_port_id) {
				EXPECT_EQ(schedule.tx_stream_index_by_logical_port[logical_port_id],
					  INVALID_COMPILED_PROVIDER_INDEX);
			}
		}
	}
}

/** @brief Verify logical, regional, and direct successor indices have one compact owner. */
TEST(runtime_plan_compiler, compiles_stage_indices_successors_and_regions)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.logical_stages.size(), 2u);
	EXPECT_EQ(compiled.logical_stages[0].logical_stage_id, "rx");
	EXPECT_EQ(compiled.logical_stages[0].logical_stage_index, 0u);
	EXPECT_EQ(compiled.logical_stages[1].logical_stage_id, "tx");
	EXPECT_EQ(compiled.logical_stages[1].logical_stage_index, 1u);
	ASSERT_EQ(compiled.execution_regions.size(), 1u);
	EXPECT_EQ(compiled.execution_regions[0].logical_stage_indices, (std::vector<uint16_t>{0u, 1u}));
	EXPECT_EQ(compiled.execution_regions[0].stage_instance_indices, (std::vector<uint32_t>{0u, 1u}));
	ASSERT_EQ(compiled.stage_instances.size(), 2u);
	EXPECT_EQ(compiled.stage_instances[0].dispatch_mode, compiled_stage_dispatch_mode::UNCONDITIONAL_FANOUT);
	ASSERT_EQ(compiled.stage_instances[0].packet_routes.size(), 1u);
	EXPECT_EQ(compiled.stage_instances[0].packet_routes[0].destination_stage_instance_indices,
		  (std::vector<uint16_t>{1u}));
	EXPECT_TRUE(compiled.stage_instances[0].packet_routes[0].condition.is_unconditional());
	EXPECT_EQ(compiled.stage_instances[1].dispatch_mode, compiled_stage_dispatch_mode::TERMINAL);
}

/** @brief Prove successor lookup is one direct compact lane-local table. */
TEST(routing_logic, successor_lookup)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	const auto rx = std::find_if(compiled.stage_instances.begin(), compiled.stage_instances.end(),
				     [](const auto &stage) { return stage.stage_instance_id == "rx@lane_0"; });
	const auto tx = std::find_if(compiled.stage_instances.begin(), compiled.stage_instances.end(),
				     [](const auto &stage) { return stage.stage_instance_id == "tx@lane_0"; });
	ASSERT_NE(rx, compiled.stage_instances.end());
	ASSERT_NE(tx, compiled.stage_instances.end());
	ASSERT_EQ(rx->dispatch_mode, compiled_stage_dispatch_mode::UNCONDITIONAL_FANOUT);
	ASSERT_EQ(rx->packet_routes.size(), 1u);
	ASSERT_EQ(rx->packet_routes[0].destination_stage_instance_indices.size(), 1u);
	EXPECT_EQ(rx->packet_routes[0].destination_stage_instance_indices.front(), tx->stage_instance_index);
	EXPECT_TRUE(rx->packet_routes[0].condition.is_unconditional());
	EXPECT_EQ(tx->dispatch_mode, compiled_stage_dispatch_mode::TERMINAL);
}

/** @brief Prove every executable stage has one exact dense worker assignment. */
TEST(routing_logic, stage_instance_worker_assignment)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	std::vector<uint8_t> ownership(compiled.stage_instances.size(), uint8_t{0});
	for (const auto &schedule : compiled.worker_schedules) {
		ASSERT_LT(schedule.worker_index, compiled.worker_schedules.size());
		for (const uint32_t stage_index : schedule.stage_instance_indices) {
			ASSERT_LT(stage_index, compiled.stage_instances.size());
			EXPECT_EQ(compiled.stage_instances[stage_index].worker_index, schedule.worker_index);
			ASSERT_EQ(ownership[stage_index], 0u);
			ownership[stage_index] = 1u;
		}
	}
	EXPECT_TRUE(std::all_of(ownership.begin(), ownership.end(), [](uint8_t owned) { return owned == 1u; }));
}

/** @brief Prove a cross-worker route names one exact executable DATA boundary. */
TEST(routing_logic, executable_boundary_identity)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();
	const auto &transition = compiled.transition_topology;

	ASSERT_EQ(transition.boundaries.size(), 1u);
	const auto &boundary = transition.boundaries.front();
	ASSERT_LT(boundary.from_stage_instance_index, compiled.stage_instances.size());
	ASSERT_LT(boundary.to_stage_instance_index, compiled.stage_instances.size());
	const auto &source = compiled.stage_instances[boundary.from_stage_instance_index];
	const auto &destination = compiled.stage_instances[boundary.to_stage_instance_index];
	EXPECT_NE(source.worker_index, destination.worker_index);
	EXPECT_EQ(boundary.sender_worker_index, source.worker_index);
	EXPECT_EQ(boundary.receiver_worker_index, destination.worker_index);
	EXPECT_TRUE(std::any_of(source.packet_routes.begin(), source.packet_routes.end(), [&](const auto &route) {
		return std::binary_search(route.destination_stage_instance_indices.begin(),
					  route.destination_stage_instance_indices.end(),
					  destination.stage_instance_index);
	}));
	ASSERT_LT(boundary.from_stage_instance_index, transition.boundaries_by_source_stage_instance.size());
	const auto &source_boundaries =
		transition.boundaries_by_source_stage_instance[boundary.from_stage_instance_index];
	ASSERT_EQ(source_boundaries.size(), 1u);
	EXPECT_EQ(source_boundaries.front().boundary_index, boundary.boundary_index);
}

/** @brief Verify one real cross-worker edge compiles one exact boundary placement. */
TEST(runtime_plan_compiler, admits_exact_boundary_placements)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &topology = compiled_or.value().transition_topology;

	ASSERT_EQ(topology.boundaries.size(), 1u);
	const auto &boundary = topology.boundaries[0];
	EXPECT_NE(boundary.sender_worker_index, boundary.receiver_worker_index);
	ASSERT_LT(boundary.from_stage_instance_index, topology.boundaries_by_source_stage_instance.size());
	ASSERT_EQ(topology.boundaries_by_source_stage_instance[boundary.from_stage_instance_index].size(), 1u);
	EXPECT_EQ(topology.boundaries_by_source_stage_instance[boundary.from_stage_instance_index][0].boundary_index,
		  boundary.boundary_index);
}

/** @brief Verify a non-staging transition cannot carry an unowned NUMA fact. */
TEST(runtime_plan_compiler, rejects_zero_copy_transition_with_staging_numa)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.storage_transitions_size(), 1);
	plan.mutable_storage_transitions(0)->set_staging_numa_node(0);

	expect_compiler_reject(
		plan, "storage transition staging_numa_node presence must exactly match its provider contract");
}

/** @brief Verify complete live-transition policy survives shared compilation unchanged. */
TEST(runtime_plan_compiler, admits_complete_epoch_transition_plan)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	ASSERT_TRUE(plan_or.value().has_epoch_transition_plan());
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &policy = compiled_or.value().transition_topology.policy;

	EXPECT_TRUE(policy.enabled);
	EXPECT_GT(policy.prepare_timeout.count(), 0);
	EXPECT_GT(policy.prepare_cancel_grace.count(), 0);
	EXPECT_GT(policy.prepared_lease_timeout.count(), 0);
	EXPECT_GT(policy.commit_timeout.count(), 0);
	EXPECT_GT(policy.retirement_timeout.count(), 0);
	EXPECT_EQ(policy.result_history_capacity, plan_or.value().epoch_transition_plan().result_history_capacity());
}

/** @brief Verify runtime-service roles and lifecycle coverage remain canonical. */
TEST(runtime_plan_compiler, admits_canonical_runtime_service_placements)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &topology = compiled_or.value().transition_topology;

	ASSERT_EQ(topology.runtime_services.size(), 2u);
	EXPECT_EQ(topology.runtime_services[0].role,
		  common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR);
	EXPECT_EQ(topology.runtime_services[1].role, common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR);
	EXPECT_NE(topology.runtime_services[0].cpu_core_id, topology.runtime_services[1].cpu_core_id);
	EXPECT_EQ(topology.runtime_services[0].command_mailbox_capacity,
		  common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY);
	EXPECT_EQ(topology.runtime_services[1].command_mailbox_capacity, 0u);
	ASSERT_TRUE(topology.lifecycle_services.has_value());
	EXPECT_EQ(topology.lifecycle_services->coordinator_service_index, 0u);
	EXPECT_EQ(topology.lifecycle_services->lifecycle_executor_service_indices, (std::vector<uint32_t>{1u}));
}

/** @brief Verify an unspecified runtime-service role cannot reach host proof. */
TEST(runtime_plan_compiler, rejects_unspecified_runtime_service_kind)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_runtime_service_placements(0)->set_service_kind(
		kinetum::gluon::v1::RUNTIME_SERVICE_KIND_UNSPECIFIED);

	expect_compiler_reject(plan, "unsupported service_kind");
}

/** @brief Verify only the coordinator owns one bounded power-of-two command mailbox. */
TEST(runtime_plan_compiler, rejects_invalid_runtime_service_command_mailbox_ownership)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	for (const uint32_t invalid_capacity : {0u, 1u, 3u, 65u, 128u}) {
		auto malformed = plan_or.value();
		malformed.mutable_runtime_service_placements(0)->set_command_mailbox_capacity(invalid_capacity);
		expect_compiler_reject(malformed, "command-mailbox capacity");
	}
	auto minimum_capacity = plan_or.value();
	minimum_capacity.mutable_runtime_service_placements(0)->set_command_mailbox_capacity(
		common::MIN_COORDINATOR_COMMAND_MAILBOX_CAPACITY);
	const auto minimum_or = compile_provider_topology(minimum_capacity);
	EXPECT_TRUE(minimum_or.is_ok()) << minimum_or.error().message();

	auto executor_owned = plan_or.value();
	executor_owned.mutable_runtime_service_placements(1)->set_command_mailbox_capacity(2u);
	expect_compiler_reject(executor_owned, "mailbox ownership");
}

/** @brief Verify the transition coordinator has one canonical identity and order. */
TEST(runtime_plan_compiler, rejects_noncanonical_coordinator_identity)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_runtime_service_placements(0)->set_service_id("coordinator_wrong");

	expect_compiler_reject(plan, "coordinator identity or order is invalid");
}

/** @brief Verify lifecycle-executor identity cannot disagree with its NUMA owner. */
TEST(runtime_plan_compiler, rejects_lifecycle_executor_identity_numa_mismatch)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_GE(plan.runtime_service_placements_size(), 2);
	plan.mutable_runtime_service_placements(1)->set_numa_node(1);

	expect_compiler_reject(plan, "lifecycle executors have invalid identity");
}

/** @brief Verify one CPU cannot be owned by a packet worker and runtime service. */
TEST(runtime_plan_compiler, rejects_worker_service_core_overlap)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_GT(plan.worker_placements_size(), 0);
	ASSERT_GT(plan.runtime_service_placements_size(), 0);
	ASSERT_EQ(plan.worker_placements(0).cpu_core_ids_size(), 1);
	plan.mutable_runtime_service_placements(0)->set_cpu_core_id(plan.worker_placements(0).cpu_core_ids(0));

	expect_compiler_reject(plan, "runtime services require unique identity, CPU");
}

/** @brief Verify two runtime services cannot claim one dedicated CPU. */
TEST(runtime_plan_compiler, rejects_service_service_core_overlap)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_GE(plan.runtime_service_placements_size(), 2);
	plan.mutable_runtime_service_placements(1)->set_cpu_core_id(plan.runtime_service_placements(0).cpu_core_id());

	expect_compiler_reject(plan, "runtime services require unique identity, CPU");
}

/** @brief Verify fixed-epoch plans cannot retain source epoch-staging capacity. */
TEST(runtime_plan_compiler, rejects_source_epoch_staging_capacity_without_transition_policy)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_epoch_transition_plan();

	expect_compiler_reject(plan, "fixed-epoch worker carries source_epoch_staging_capacity");
}

/** @brief Verify fixed-epoch plans require the policy-independent observation cadence. */
TEST(runtime_plan_compiler, fixed_epoch_requires_health_poll_interval)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_epoch_transition_plan();
	for (auto &worker : *plan.mutable_worker_placements()) {
		worker.set_source_epoch_staging_capacity(0);
	}
	const auto admitted = compile_provider_topology(plan);
	ASSERT_TRUE(admitted.is_ok()) << admitted.error().message();
	for (auto &worker : *plan.mutable_worker_placements()) {
		worker.set_module_health_poll_interval_ms(0);
	}

	expect_compiler_reject(plan, "module_health_poll_interval_ms");
	for (auto &worker : *plan.mutable_worker_placements()) {
		worker.set_module_health_poll_interval_ms(UINT64_MAX);
	}
	expect_compiler_reject(plan, "module_health_poll_interval_ms");
}

/** @brief Verify fixed-epoch plans require the policy-independent callback budget. */
TEST(runtime_plan_compiler, fixed_epoch_requires_health_callback_budget)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_epoch_transition_plan();
	for (auto &worker : *plan.mutable_worker_placements()) {
		worker.set_source_epoch_staging_capacity(0);
	}
	const auto admitted = compile_provider_topology(plan);
	ASSERT_TRUE(admitted.is_ok()) << admitted.error().message();
	for (auto &worker : *plan.mutable_worker_placements()) {
		worker.set_module_health_callback_budget_ns(0);
	}

	expect_compiler_reject(plan, "module_health_callback_budget_ns");
	for (auto &worker : *plan.mutable_worker_placements()) {
		worker.set_module_health_callback_budget_ns(UINT64_MAX);
	}
	expect_compiler_reject(plan, "module_health_callback_budget_ns");
}

/** @brief Verify incoherent live-transition policy rejects without a partial artifact. */
TEST(runtime_plan_compiler, rejects_incoherent_transition_policy_before_output_mutation)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *policy = plan.mutable_epoch_transition_plan();
	policy->set_prepare_cancel_grace_ms(policy->prepare_timeout_ms() + 1u);

	const auto result = compile_provider_topology(plan);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("prepare_cancel_grace_ms"), std::string::npos)
		<< result.error().message();
}

/** @brief Verify conditional routes compile into one stable priority order. */
TEST(runtime_plan_compiler, compiles_prioritized_edge_matchers)
{
	const auto pipeline = make_priority_route_pipeline();
	auto plan_or = make_provider_plan(pipeline, kinetum::test::make_udp_test_deployment_bindings(pipeline));
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &stages = compiled_or.value().stage_instances;
	const auto rx = std::find_if(stages.begin(), stages.end(),
				     [](const auto &stage) { return stage.logical_stage_id == "rx"; });
	ASSERT_NE(rx, stages.end());
	EXPECT_EQ(rx->dispatch_mode, compiled_stage_dispatch_mode::PRIORITY_ROUTE);
	ASSERT_EQ(rx->packet_routes.size(), 2u);
	EXPECT_EQ(rx->packet_routes[0].priority, 100);
	EXPECT_FALSE(rx->packet_routes[0].condition.is_unconditional());
	EXPECT_EQ(rx->packet_routes[1].priority, 0);
	EXPECT_TRUE(rx->packet_routes[1].condition.is_unconditional());
}

/** @brief Verify malformed edge conditions reject at the composed compiler entry. */
TEST(runtime_plan_compiler, rejects_invalid_edge_condition)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_pipeline()->mutable_edges(0)->set_condition("invalid_field == 1");

	expect_compiler_reject(plan, "Invalid edge condition");
}

/** @brief Verify duplicate logical-stage identity rejects before compact indexing. */
TEST(runtime_plan_compiler, rejects_duplicate_stage_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_pipeline()->mutable_stages(1)->set_stage_id("rx");

	expect_compiler_reject(plan, "duplicate stage_id");
}

/** @brief Verify an empty logical-stage identity cannot become index zero. */
TEST(runtime_plan_compiler, rejects_empty_stage_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_pipeline()->mutable_stages(0)->clear_stage_id();

	expect_compiler_reject(plan, "stage_id must match [A-Za-z_][A-Za-z0-9_]* within 128 bytes");
}

/** @brief Verify an edge cannot name an absent destination stage. */
TEST(runtime_plan_compiler, rejects_unknown_edge_destination_stage)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_pipeline()->mutable_edges(0)->set_to_stage_id("missing");

	expect_compiler_reject(plan, "unknown to_stage_id");
}

/** @brief Verify an edge cannot name an absent source stage. */
TEST(runtime_plan_compiler, rejects_unknown_edge_source_stage)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_pipeline()->mutable_edges(0)->set_from_stage_id("missing");

	expect_compiler_reject(plan, "unknown from_stage_id");
}

/** @brief Verify region provenance cannot name a nonexistent logical stage. */
TEST(runtime_plan_compiler, rejects_unknown_region_stage)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_regions(0)->set_logical_stage_ids(0, "missing");

	expect_compiler_reject(plan, "region logical_stage_ids[] must be exact");
}

/** @brief Verify one logical stage cannot be owned by two regions. */
TEST(runtime_plan_compiler, rejects_duplicate_region_ownership)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.regions_size(), 2);
	plan.mutable_regions(1)->add_logical_stage_ids("rx");

	expect_compiler_reject(plan, "region logical_stage_ids[] must be exact");
}

/** @brief Verify region identities remain unique in the compact namespace. */
TEST(runtime_plan_compiler, rejects_duplicate_region_id)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.regions_size(), 2);
	plan.mutable_regions(1)->set_region_id(0);

	expect_compiler_reject(plan, "duplicate region_id");
}

/** @brief Verify region identity cannot exceed the compact region range. */
TEST(runtime_plan_compiler, rejects_region_id_outside_runtime_range)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_regions(0)->set_region_id(1);

	expect_compiler_reject(plan, "outside the compact region range");
}

/** @brief Verify graph-unsafe logical identities reject before generated IDs exist. */
TEST(runtime_plan_compiler, rejects_stage_id_unsafe_for_generated_instance_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *pipeline = plan.mutable_pipeline();
	auto unsafe = std::find_if(pipeline->mutable_stages()->begin(), pipeline->mutable_stages()->end(),
				   [](const auto &stage) { return stage.stage_id() == "rx"; });
	ASSERT_NE(unsafe, pipeline->mutable_stages()->end());
	unsafe->set_stage_id("unsafe@stage");
	for (auto &edge : *pipeline->mutable_edges()) {
		if (edge.from_stage_id() == "rx") {
			edge.set_from_stage_id("unsafe@stage");
		}
	}

	expect_compiler_reject(plan, "stage_id must match [A-Za-z_][A-Za-z0-9_]* within 128 bytes");
}

/** @brief Verify authored stage cardinality cannot exceed the platform runtime bound. */
TEST(runtime_plan_compiler, rejects_stage_count_above_runtime_index_capacity)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto target = static_cast<std::size_t>(kinetum::axiom::MAX_PIPELINE_STAGES) + 1u;
	for (std::size_t index = static_cast<std::size_t>(plan.pipeline().stages_size()); index < target; ++index) {
		auto *stage = plan.mutable_pipeline()->add_stages();
		stage->set_stage_id("stage_" + std::to_string(index));
		stage->set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
		stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	}

	const auto result = compile_provider_topology(plan);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.error().message().find("too many stages"), std::string::npos) << result.error().message();
}

/** @brief Verify storage-domain cardinality fits the packet-record index namespace. */
TEST(runtime_plan_compiler, rejects_storage_count_above_packet_record_index_capacity)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const int target = static_cast<int>(KINETUM_INVALID_STORAGE_DOMAIN) + 1;
	plan.mutable_packet_storage_domains()->Reserve(target);
	while (plan.packet_storage_domains_size() < target) {
		plan.add_packet_storage_domains();
	}

	const auto result = compile_provider_topology(plan);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::OUT_OF_RANGE);
	EXPECT_NE(result.error().message().find("packet-record index namespace"), std::string::npos)
		<< result.error().message();
}

/** @brief Verify every logical stage has one concrete instance per lane. */
TEST(runtime_plan_compiler, rejects_logical_stage_missing_stage_instance)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_stage_instances()->DeleteSubrange(0, 1);

	expect_compiler_reject(plan, "has no executable stage_instance");
}

/** @brief Verify RSS replication creates one context and owner per module instance. */
TEST(runtime_plan_compiler, compiles_replicated_per_stage_instance_contexts)
{
	auto plan_or = make_valid_rss_module_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &contexts = compiled_or.value().module_contexts;

	ASSERT_EQ(contexts.size(), 2u);
	EXPECT_NE(contexts[0].context_instance_id, contexts[1].context_instance_id);
	EXPECT_NE(contexts[0].stage_instance_index, contexts[1].stage_instance_index);
	EXPECT_NE(contexts[0].worker_index, contexts[1].worker_index);
	for (const auto &context : contexts) {
		EXPECT_EQ(context.context_instance_id,
			  compiled_or->stage_instances[context.stage_instance_index].stage_instance_id);
		EXPECT_EQ(context.context_memory_capacity_bytes, TEST_CONTEXT_MEMORY_CAPACITY_BYTES);
		EXPECT_EQ(context.epoch_arena_capacity_bytes, TEST_EPOCH_ARENA_CAPACITY_BYTES);
	}
	ASSERT_EQ(compiled_or.value().module_memory_budgets.size(), 1u);
	const auto &budget = compiled_or.value().module_memory_budgets[0];
	EXPECT_EQ(budget.numa_node, 0);
	EXPECT_EQ(budget.context_count, 2u);
	EXPECT_EQ(budget.context_memory_capacity_bytes, 2u * TEST_CONTEXT_MEMORY_CAPACITY_BYTES);
	EXPECT_EQ(budget.epoch_arena_capacity_bytes, 2u * TEST_EPOCH_ARENA_CAPACITY_BYTES);
	EXPECT_EQ(budget.complete_memory_capacity_bytes,
		  2u * TEST_CONTEXT_MEMORY_CAPACITY_BYTES +
			  2u * TEST_EPOCH_ARENA_CAPACITY_BYTES * common::EXACT_EPOCH_SLOT_COUNT);
}

/** @brief Verify every module instance carries two explicit nonzero capacities. */
TEST(runtime_plan_compiler, rejects_missing_or_zero_module_context_resource_capacity)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto module = std::find_if(plan.mutable_stage_instances()->begin(), plan.mutable_stage_instances()->end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "module0"; });
	ASSERT_NE(module, plan.mutable_stage_instances()->end());

	module->clear_context_memory_capacity_bytes();
	expect_compiler_reject(plan, "lacks exact per-instance context ownership or memory capacity");
	module->set_context_memory_capacity_bytes(TEST_CONTEXT_MEMORY_CAPACITY_BYTES);
	module->clear_epoch_arena_capacity_bytes();
	expect_compiler_reject(plan, "lacks exact per-instance context ownership or memory capacity");
}

/** @brief Verify platform stages cannot claim module lifecycle-memory capacity. */
TEST(runtime_plan_compiler, rejects_module_context_resource_capacity_on_platform_stage)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_GT(plan.stage_instances_size(), 0);
	plan.mutable_stage_instances(0)->set_context_memory_capacity_bytes(TEST_CONTEXT_MEMORY_CAPACITY_BYTES);

	expect_compiler_reject(plan, "must not declare mutable module context ownership or memory capacity");
}

/** @brief Verify aggregate and exact-slot multiplication reject uint64 overflow. */
TEST(runtime_plan_compiler, rejects_module_lifecycle_memory_budget_overflow)
{
	auto plan_or = make_valid_rss_module_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	std::vector<kinetum::gluon::v1::StageInstance *> modules;
	for (auto &stage : *plan.mutable_stage_instances()) {
		if (stage.logical_stage_id() == "module0") {
			modules.push_back(&stage);
		}
	}
	ASSERT_EQ(modules.size(), 2u);
	modules[0]->set_context_memory_capacity_bytes(std::numeric_limits<uint64_t>::max());
	modules[1]->set_context_memory_capacity_bytes(std::numeric_limits<uint64_t>::max());
	expect_compiler_reject(plan, "overflows while accumulating module context-lifetime memory");

	auto transition_plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(transition_plan_or.is_ok()) << transition_plan_or.error().message();
	plan = std::move(transition_plan_or).value();
	const auto module = std::find_if(plan.mutable_stage_instances()->begin(), plan.mutable_stage_instances()->end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "module0"; });
	ASSERT_NE(module, plan.mutable_stage_instances()->end());
	module->set_epoch_arena_capacity_bytes(std::numeric_limits<uint64_t>::max());
	expect_compiler_reject(plan, "overflows while multiplying module epoch-slot memory");
}

/** @brief Verify a module instance cannot omit its derived context identity. */
TEST(runtime_plan_compiler, rejects_unmaterialized_module_context_identity)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto module = std::find_if(plan.mutable_stage_instances()->begin(), plan.mutable_stage_instances()->end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "module0"; });
	ASSERT_NE(module, plan.mutable_stage_instances()->end());
	module->clear_context_instance_id();

	expect_compiler_reject(plan,
			       "module stage instance 'module0@lane_0' lacks exact per-instance context ownership");
}

/** @brief Verify active origination becomes exact compact storage and schedule truth. */
TEST(runtime_plan_compiler, compiles_active_origin_storage_source_and_schedule)
{
	auto plan_or = make_valid_active_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	const auto active = std::find_if(compiled.stage_instances.begin(), compiled.stage_instances.end(),
					 [](const auto &stage) { return stage.logical_stage_id == "active0"; });
	ASSERT_NE(active, compiled.stage_instances.end());
	ASSERT_TRUE(active->active_origin_storage_domain_index.has_value());
	EXPECT_EQ(active->active_origin_storage_domain_index.value(), 0u);
	EXPECT_EQ(active->reachable_storage_domain_indices, std::vector<uint32_t>{0u});
	ASSERT_LT(active->logical_stage_index, compiled.logical_stages.size());
	const auto &active_logical = compiled.logical_stages[active->logical_stage_index];
	EXPECT_EQ(active_logical.retained_packet_capacity, 7u);
	EXPECT_EQ(active_logical.retained_byte_capacity, 7000u);
	ASSERT_EQ(compiled.storage_domains.size(), 1u);
	EXPECT_EQ(compiled.storage_domains[0].budget.required_min_buffers, 4231u);

	ASSERT_LT(active->worker_index, compiled.worker_schedules.size());
	const auto &schedule = compiled.worker_schedules[active->worker_index];
	EXPECT_EQ(schedule.active_stage_instance_indices, std::vector<uint32_t>{active->stage_instance_index});
	EXPECT_EQ(schedule.loop_trigger_stage_instance_indices, std::vector<uint32_t>{active->stage_instance_index});
	EXPECT_EQ(schedule.source_storage_domain_indices,
		  (std::vector<uint32_t>{active->active_origin_storage_domain_index.value()}));
	ASSERT_LT(active->worker_index, compiled.transition_topology.workers.size());
	EXPECT_TRUE(compiled.transition_topology.workers[active->worker_index].is_source);
}

/** @brief Verify tracked-async resources compile into one exact worker projection and grace. */
TEST(runtime_plan_compiler, compiles_and_rejects_tracked_async_resources_independently)
{
	auto plan_or = make_valid_active_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto active = std::find_if(plan.mutable_pipeline()->mutable_stages()->begin(),
				   plan.mutable_pipeline()->mutable_stages()->end(), [](const auto &stage) {
					   return stage.execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE;
				   });
	ASSERT_NE(active, plan.mutable_pipeline()->mutable_stages()->end());
	active->mutable_active_stage_limits()->set_async_work_capacity(4u);
	active->mutable_active_stage_limits()->set_async_cancel_grace_ms(1000u);
	const auto compiled_or = compile_provider_topology(plan);
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();
	const auto logical =
		std::find_if(compiled.logical_stages.begin(), compiled.logical_stages.end(), [](const auto &candidate) {
			return candidate.execution_mode == provider::compiled_stage_execution_mode::ACTIVE;
		});
	ASSERT_NE(logical, compiled.logical_stages.end());
	EXPECT_EQ(logical->async_work_capacity, 4u);
	EXPECT_EQ(logical->async_cancel_grace, std::chrono::milliseconds(1000u));
	ASSERT_EQ(logical->stage_instance_indices.size(), 1u);
	const uint32_t stage_index = logical->stage_instance_indices.front();
	ASSERT_LT(stage_index, compiled.stage_instances.size());
	const uint32_t worker_index = compiled.stage_instances[stage_index].worker_index;
	ASSERT_LT(worker_index, compiled.worker_schedules.size());
	EXPECT_EQ(compiled.worker_schedules[worker_index].async_stage_instance_indices,
		  std::vector<uint32_t>{stage_index});

	active->mutable_active_stage_limits()->clear_async_cancel_grace_ms();
	expect_compiler_reject(plan, "async capacity and cancellation grace must be present together");
	active->mutable_active_stage_limits()->set_async_cancel_grace_ms(
		plan.epoch_transition_plan().commit_timeout_ms());
	expect_compiler_reject(plan, "strictly shorter than commit_timeout_ms");
}

/** @brief Reject malformed nonzero control resources when CONTROL is absent. */
TEST(runtime_plan_compiler, rejects_active_control_resource_residue_without_trigger)
{
	auto plan_or = make_valid_active_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto active = std::find_if(plan.mutable_pipeline()->mutable_stages()->begin(),
				   plan.mutable_pipeline()->mutable_stages()->end(), [](const auto &stage) {
					   return stage.execution_mode() == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE;
				   });
	ASSERT_NE(active, plan.mutable_pipeline()->mutable_stages()->end());
	active->mutable_active_stage_limits()->set_control_mailbox_capacity(1u);
	expect_compiler_reject(plan, "CONTROL trigger, mailbox/payload capacity, and inbound edge must be exact");

	active->mutable_active_stage_limits()->set_control_mailbox_capacity(0u);
	active->mutable_active_stage_limits()->set_control_message_capacity_bytes(16u);
	expect_compiler_reject(plan, "CONTROL trigger, mailbox/payload capacity, and inbound edge must be exact");
}

/** @brief Verify a direct plan consumer cannot infer active-origin storage. */
TEST(runtime_plan_compiler, rejects_active_stage_without_origin_storage_domain)
{
	auto plan_or = make_valid_active_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto active = std::find_if(plan.mutable_stage_instances()->begin(), plan.mutable_stage_instances()->end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "active0"; });
	ASSERT_NE(active, plan.mutable_stage_instances()->end());
	active->clear_active_origin_storage_domain_id();

	expect_compiler_reject(plan, "active stage instance requires one exact origin storage domain");
}

/** @brief Verify passive execution cannot claim an active packet-origin owner. */
TEST(runtime_plan_compiler, rejects_passive_stage_with_origin_storage_domain)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_stage_instances(0)->set_active_origin_storage_domain_id("storage_host_0");

	expect_compiler_reject(plan, "passive stage instance must not carry an origin storage domain");
}

/** @brief Verify an active origin cannot name storage outside plan truth. */
TEST(runtime_plan_compiler, rejects_active_origin_with_unknown_storage_domain)
{
	auto plan_or = make_valid_active_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto active = std::find_if(plan.mutable_stage_instances()->begin(), plan.mutable_stage_instances()->end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "active0"; });
	ASSERT_NE(active, plan.mutable_stage_instances()->end());
	active->set_active_origin_storage_domain_id("storage_missing");

	expect_compiler_reject(plan, "active stage instance references an unknown origin storage domain");
}

/** @brief Verify active-origin storage placement agrees with its sole owner worker. */
TEST(runtime_plan_compiler, rejects_active_origin_on_foreign_host_numa_node)
{
	auto plan_or = make_valid_active_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.packet_storage_domains_size(), 1);
	plan.mutable_packet_storage_domains(0)->set_host_numa_node(1);

	expect_compiler_reject(plan, "active-origin storage domain disagrees with the owner worker's host NUMA node");
}

/** @brief Verify one queue emits and compiles one exact NONE steering profile. */
TEST(runtime_plan_compiler, compiles_single_stream_none_traffic_steering_profile)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.steering_profiles.size(), 1u);
	EXPECT_EQ(compiled.steering_profiles[0].kind, compiled_steering_kind::NONE);
	EXPECT_FALSE(compiled.steering_profiles[0].symmetric);
	EXPECT_TRUE(compiled.steering_profiles[0].hash_fields.empty());
	EXPECT_TRUE(compiled.steering_profiles[0].hash_key.empty());
	ASSERT_EQ(compiled.steering_profiles[0].io_stream_indices.size(), 1u);
}

/** @brief A module population derives its ordinals from exact context identities. */
TEST(runtime_plan_compiler, compiles_module_context_domain)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.module_context_domains.size(), 1u);
	const auto &domain = compiled.module_context_domains[0];
	EXPECT_EQ(domain.module_id, "kinetum.test_module");
	ASSERT_EQ(domain.module_context_indices.size(), 1u);
	const auto &context = compiled.module_contexts[domain.module_context_indices[0]];
	EXPECT_EQ(context.context_instance_id, "module0@lane_0");
	EXPECT_EQ(context.module_context_ordinal, 0u);
	EXPECT_EQ(context.module_context_count, 1u);
}

/** @brief A module-free RSS graph has hardware steering and no context population. */
TEST(runtime_plan_compiler, compiles_multiple_rx_streams_with_rss_traffic_steering_profile)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.execution_lanes.size(), 2u);
	ASSERT_EQ(compiled.io_streams.size(), 4u);
	ASSERT_EQ(compiled.steering_profiles.size(), 1u);
	const auto &profile = compiled.steering_profiles[0];
	EXPECT_EQ(profile.kind, compiled_steering_kind::RSS);
	EXPECT_TRUE(profile.symmetric);
	EXPECT_EQ(profile.hash_fields, (std::vector<std::string>{"ipv4", "udp"}));
	EXPECT_EQ(profile.hash_key, "0123456789abcdef0123456789abcdef01234567");
	EXPECT_EQ(profile.io_stream_indices.size(), 2u);
	EXPECT_TRUE(compiled.module_context_domains.empty());
}

/** @brief Verify RSS cannot decorate a one-queue receive topology. */
TEST(runtime_plan_compiler, rejects_single_stream_rss_profile)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.traffic_steering_profiles_size(), 1);
	auto *profile = plan.mutable_traffic_steering_profiles(0);
	profile->set_kind(kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS);
	profile->set_symmetric(true);
	profile->add_hash_fields("ipv4");
	profile->set_hash_key("0123456789abcdef0123456789abcdef01234567");

	expect_compiler_reject(plan, "RSS steering requires fields, deterministic key, and multiple streams");
}

/** @brief Verify multi-queue RX never infers an omitted steering profile. */
TEST(runtime_plan_compiler, rejects_multiple_rx_streams_without_traffic_steering_profile)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	for (auto &stream : *plan.mutable_io_streams()) {
		if (stream.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
			stream.clear_steering_profile_id();
		}
	}
	plan.clear_traffic_steering_profiles();

	expect_compiler_reject(plan, "every RX stream requires one exact steering profile");
}

/** @brief Verify RSS always carries exact deterministic key bytes. */
TEST(runtime_plan_compiler, rejects_symmetric_rss_profile_without_exact_key)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.traffic_steering_profiles_size(), 1);
	plan.mutable_traffic_steering_profiles(0)->clear_hash_key();

	expect_compiler_reject(plan, "RSS steering requires fields, deterministic key");
}

/** @brief Required module populations cannot be omitted from a plan. */
TEST(runtime_plan_compiler, rejects_missing_module_context_domain)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_module_context_domains();

	expect_compiler_reject(plan, "module context domains do not cover the exact configured module set");
}

/** @brief A module domain must include its complete context population. */
TEST(runtime_plan_compiler, rejects_module_context_domain_without_contexts)
{
	auto plan_or = make_valid_transition_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.module_context_domains_size(), 1);
	plan.mutable_module_context_domains(0)->clear_context_instance_ids();

	expect_compiler_reject(plan, "module context domains require exact sorted module and context membership");
}

/** @brief Hardware symmetry is independent of a module's context population. */
TEST(runtime_plan_compiler, context_domain_does_not_require_symmetric_rss)
{
	auto plan_or = make_valid_rss_module_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.traffic_steering_profiles_size(), 1);
	plan.mutable_traffic_steering_profiles(0)->set_symmetric(false);

	const auto compiled = compile_provider_topology(plan);
	ASSERT_TRUE(compiled.is_ok()) << compiled.error().message();
	ASSERT_EQ(compiled->module_context_domains.size(), 1u);
	const auto &indices = compiled->module_context_domains[0].module_context_indices;
	ASSERT_EQ(indices.size(), 2u);
	for (uint32_t ordinal = 0u; ordinal < indices.size(); ++ordinal) {
		EXPECT_EQ(compiled->module_contexts[indices[ordinal]].module_context_ordinal, ordinal);
		EXPECT_EQ(compiled->module_contexts[indices[ordinal]].module_context_count, 2u);
	}
}

/** @brief Verify contract requirements are exact, sorted, and duplicate-free. */
TEST(runtime_plan_compiler, derives_exact_required_provider_contract_set)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();

	const std::vector<std::string> expected{
		std::string(CPU_EXECUTION_TYPE_URL),
		std::string(UDP_DRIVER_TYPE_URL),
		std::string(HOST_STORAGE_TYPE_URL),
	};
	EXPECT_EQ(compiled_or.value().required_contract_type_urls, expected);
	EXPECT_TRUE(std::ranges::is_sorted(compiled_or.value().required_contract_type_urls));
}

/** @brief Verify one shared ten-term budget and one burst safety policy are consumed. */
TEST(runtime_plan_compiler, compiles_storage_budget_through_shared_formula_authority)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	ASSERT_EQ(compiled_or.value().storage_domains.size(), 1u);
	const auto &budget = compiled_or.value().storage_domains[0].budget;

	EXPECT_EQ(budget.storage_domain_id, "storage_host_0");
	EXPECT_EQ(budget.required_min_buffers, 4224u);
	EXPECT_EQ(budget.safety_margin, common::runtime_sizing::PACKET_MAX_BURST_SIZE);
}

/** @brief Shared ingress storage counts both RX queues and the sole TX queue once. */
TEST(runtime_plan_compiler, shared_fan_in_storage_budget_counts_each_physical_queue_once)
{
	auto plan_or = make_fan_in_storage_plan(false);
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled.is_ok()) << compiled.error().message();
	ASSERT_EQ(compiled->storage_domains.size(), 1u);
	EXPECT_EQ(compiled->storage_domains[0].budget.required_min_buffers, 5248u);
	ASSERT_EQ(compiled->worker_schedules.size(), 1u);
	EXPECT_EQ(compiled->worker_schedules[0].rx_stream_indices.size(), 2u);
	EXPECT_EQ(compiled->worker_schedules[0].tx_stream_indices.size(), 1u);
}

/** @brief Each admitted domain covers the entire shared TX queue without duplicating that queue. */
TEST(runtime_plan_compiler, distinct_fan_in_storage_budgets_charge_complete_shared_tx_capacity)
{
	auto plan_or = make_fan_in_storage_plan(true);
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto compiled = compile_provider_topology(plan);
	ASSERT_TRUE(compiled.is_ok()) << compiled.error().message();
	ASSERT_EQ(compiled->storage_domains.size(), 2u);
	EXPECT_EQ(compiled->storage_domains[0].budget.required_min_buffers, 4224u);
	EXPECT_EQ(compiled->storage_domains[1].budget.required_min_buffers, 4224u);
	ASSERT_EQ(compiled->worker_schedules.size(), 1u);
	EXPECT_EQ(compiled->worker_schedules[0].tx_stream_indices.size(), 1u);
	const auto &tx = compiled->io_streams[compiled->worker_schedules[0].tx_stream_indices[0]];
	EXPECT_EQ(tx.tx_storage_domain_indices, (std::vector<uint32_t>{0u, 1u}));
	EXPECT_TRUE(compiled->storage_transitions.empty());

	auto *tx_plan = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx_plan, nullptr);
	tx_plan->set_descriptor_count(2048u);
	const auto larger_tx = compile_provider_topology(plan);
	ASSERT_TRUE(larger_tx.is_ok()) << larger_tx.error().message();
	EXPECT_EQ(larger_tx->storage_domains[0].budget.required_min_buffers, 5248u);
	EXPECT_EQ(larger_tx->storage_domains[1].budget.required_min_buffers, 5248u);

	tx_plan->set_descriptor_count(1024u);
	auto *rx_plan = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx_plan, nullptr);
	ASSERT_EQ(rx_plan->rx_storage_domain_id(), "storage_host_0");
	rx_plan->set_descriptor_count(2048u);
	const auto larger_rx = compile_provider_topology(plan);
	ASSERT_TRUE(larger_rx.is_ok()) << larger_rx.error().message();
	EXPECT_EQ(larger_rx->storage_domains[0].budget.required_min_buffers, 5248u);
	EXPECT_EQ(larger_rx->storage_domains[1].budget.required_min_buffers, 4224u);
	plan.mutable_packet_storage_domains(0)->set_buffer_count(5248u);
	plan.mutable_packet_storage_domains(1)->set_buffer_count(4224u);
	EXPECT_TRUE(compile_provider_topology(plan).is_ok());
	for (const int domain_index : {0, 1}) {
		SCOPED_TRACE(domain_index);
		auto insufficient = plan;
		auto *domain = insufficient.mutable_packet_storage_domains(domain_index);
		domain->set_buffer_count(domain->buffer_count() - 1u);
		expect_compiler_reject(insufficient, "buffer_count below computed minimum");
	}
}

/** @brief A declared TX set must cover both original domains on its bound fan-in path. */
TEST(runtime_plan_compiler, rejects_missing_domain_in_tx_fan_in_admission)
{
	auto plan_or = make_fan_in_storage_plan(true);
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *tx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx, nullptr);
	tx->mutable_tx_storage()->mutable_storage_domain_ids()->RemoveLast();
	expect_compiler_reject(plan, "missing storage transition before TX");
}

/** @brief A TX admission declaration cannot keep an otherwise unreachable domain alive. */
TEST(runtime_plan_compiler, rejects_tx_domain_without_bound_or_explicit_egress_use)
{
	auto plan_or = make_fan_in_storage_plan(true);
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto original = plan.packet_storage_domains(0);
	auto *unused = plan.add_packet_storage_domains();
	unused->CopyFrom(original);
	unused->set_storage_domain_id("storage_unused");
	auto *tx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx, nullptr);
	tx->mutable_tx_storage()->add_storage_domain_ids("storage_unused");
	expect_compiler_reject(plan, "no bound or same-worker egress path");
}

/** @brief Pin the exact active-retention term independently from every other credit. */
TEST(runtime_plan_compiler, active_retained_capacity_is_one_exact_budget_term)
{
	const common::storage_domain_buffer_budget_inputs single{
		.storage_domain_id = "storage.active.single",
		.declared_buffer_count = 1000u,
		.rx_descriptor_count = 10u,
		.tx_descriptor_count = 20u,
		.worker_count = 1u,
		.worker_staging_capacity = 30u,
		.handoff_staging_capacity = 40u,
		.source_future_staging_capacity = 50u,
		.future_output_capacity = 60u,
		.active_retained_capacity = 70u,
		.cache_size_per_worker = 5u,
	};
	auto single_budget_or = common::compile_storage_domain_buffer_budget(single);
	ASSERT_TRUE(single_budget_or.is_ok()) << single_budget_or.error().message();
	EXPECT_EQ(single_budget_or->required_min_buffers, 413u);

	auto zero_retention = single;
	zero_retention.active_retained_capacity = 0u;
	auto zero_budget_or = common::compile_storage_domain_buffer_budget(zero_retention);
	ASSERT_TRUE(zero_budget_or.is_ok()) << zero_budget_or.error().message();
	EXPECT_EQ(zero_budget_or->required_min_buffers, 343u);

	auto replicated = single;
	replicated.active_retained_capacity = 140u;
	auto replicated_budget_or = common::compile_storage_domain_buffer_budget(replicated);
	ASSERT_TRUE(replicated_budget_or.is_ok()) << replicated_budget_or.error().message();
	EXPECT_EQ(replicated_budget_or->required_min_buffers, 483u);

	const common::storage_domain_buffer_budget_inputs second_domain{
		.storage_domain_id = "storage.active.second",
		.declared_buffer_count = 1000u,
		.rx_descriptor_count = 0u,
		.tx_descriptor_count = 5u,
		.worker_count = 2u,
		.worker_staging_capacity = 16u,
		.handoff_staging_capacity = 8u,
		.source_future_staging_capacity = 0u,
		.future_output_capacity = 4u,
		.active_retained_capacity = 12u,
		.cache_size_per_worker = 3u,
	};
	auto second_budget_or = common::compile_storage_domain_buffer_budget(second_domain);
	ASSERT_TRUE(second_budget_or.is_ok()) << second_budget_or.error().message();
	EXPECT_EQ(second_budget_or->required_min_buffers, 243u);

	auto undersized = single;
	undersized.declared_buffer_count = 412u;
	const auto rejected = common::compile_storage_domain_buffer_budget(undersized);
	EXPECT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), common::status_code::INVALID_ARGUMENT);
}

/** @brief Prove one source capacity sizes both active and future queue terms exactly. */
TEST(runtime_plan_compiler, source_epoch_staging_capacity_sizes_both_queue_roles)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.worker_placements_size(), 1);
	ASSERT_EQ(plan.packet_storage_domains_size(), 1);
	plan.mutable_packet_storage_domains(0)->set_buffer_count(10'000u);

	plan.mutable_worker_placements(0)->set_source_epoch_staging_capacity(512u);
	const auto smaller_or = compile_provider_topology(plan);
	ASSERT_TRUE(smaller_or.is_ok()) << smaller_or.error().message();
	ASSERT_EQ(smaller_or.value().storage_domains.size(), 1u);
	EXPECT_EQ(smaller_or.value().storage_domains[0].budget.required_min_buffers, 3200u);

	plan.mutable_worker_placements(0)->set_source_epoch_staging_capacity(2048u);
	const auto larger_or = compile_provider_topology(plan);
	ASSERT_TRUE(larger_or.is_ok()) << larger_or.error().message();
	ASSERT_EQ(larger_or.value().storage_domains.size(), 1u);
	EXPECT_EQ(larger_or.value().storage_domains[0].budget.required_min_buffers, 6272u);
}

/** @brief Verify every external fact has one exact proof phase and owner. */
TEST(runtime_plan_compiler, compiles_host_requirements_with_one_proof_phase)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &requirements = compiled_or.value().host_requirements;

	ASSERT_EQ(requirements.size(), 3u);
	EXPECT_EQ(requirements[0].phase, provider_host_proof_phase::QUARK_LIVE_HOST);
	EXPECT_EQ(requirements[0].fact, provider_host_fact::HOST_NUMA_MEMORY);
	EXPECT_EQ(requirements[0].role, provider_contract_role::PACKET_STORAGE);
	EXPECT_EQ(requirements[1].phase, provider_host_proof_phase::QUARK_LIVE_HOST);
	EXPECT_EQ(requirements[1].fact, provider_host_fact::CPU_WORKER_SET);
	EXPECT_EQ(requirements[1].role, provider_contract_role::EXECUTION);
	EXPECT_EQ(requirements[2].phase, provider_host_proof_phase::COMPONENT_HOST_PROOF);
	EXPECT_EQ(requirements[2].fact, provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET);
	EXPECT_EQ(requirements[2].role, provider_contract_role::IO_DRIVER);
}

/** @brief Verify DPDK host facts are partitioned across Quark, component, and materialization. */
TEST(runtime_plan_compiler, compiles_dpdk_host_requirements_at_exact_proof_phases)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &requirements = compiled_or.value().host_requirements;

	ASSERT_EQ(requirements.size(), 5u);
	auto count = [&](provider_host_proof_phase phase, provider_host_fact fact, provider_contract_role role) {
		return std::count_if(requirements.begin(), requirements.end(), [&](const auto &requirement) {
			return requirement.phase == phase && requirement.fact == fact && requirement.role == role;
		});
	};
	EXPECT_EQ(count(provider_host_proof_phase::QUARK_LIVE_HOST, provider_host_fact::HOST_NUMA_MEMORY,
			provider_contract_role::PACKET_STORAGE),
		  1);
	EXPECT_EQ(count(provider_host_proof_phase::QUARK_LIVE_HOST, provider_host_fact::CPU_WORKER_SET,
			provider_contract_role::EXECUTION),
		  1);
	EXPECT_EQ(count(provider_host_proof_phase::COMPONENT_HOST_PROOF, provider_host_fact::DPDK_EAL_RUNTIME,
			provider_contract_role::PROCESS_FACILITY),
		  1);
	EXPECT_EQ(count(provider_host_proof_phase::COMPONENT_HOST_PROOF,
			provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR, provider_contract_role::PROCESS_FACILITY),
		  1);
	EXPECT_EQ(count(provider_host_proof_phase::MATERIALIZATION_PROOF, provider_host_fact::DPDK_ETHDEV_PORT,
			provider_contract_role::IO_DRIVER),
		  1);
}

/** @brief Verify the DPDK main-core fact comes only from the exact coordinator. */
TEST(runtime_plan_compiler, compiles_dpdk_main_core_from_exact_coordinator_service)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.process_facilities.size(), 1u);
	ASSERT_TRUE(compiled.transition_topology.lifecycle_services.has_value());
	const uint32_t coordinator_index = compiled.transition_topology.lifecycle_services->coordinator_service_index;
	ASSERT_LT(coordinator_index, compiled.transition_topology.runtime_services.size());
	ASSERT_TRUE(compiled.process_facilities[0].main_core_id.has_value());
	EXPECT_EQ(compiled.process_facilities[0].main_core_id.value(),
		  compiled.transition_topology.runtime_services[coordinator_index].cpu_core_id);
	ASSERT_EQ(compiled.process_facilities[0].cpu_assignments.size(), 4u);
	const auto coordinator =
		std::find_if(compiled.process_facilities[0].cpu_assignments.begin(),
			     compiled.process_facilities[0].cpu_assignments.end(), [](const auto &assignment) {
				     return assignment.kind == compiled_facility_cpu_owner_kind::TRANSITION_COORDINATOR;
			     });
	ASSERT_NE(coordinator, compiled.process_facilities[0].cpu_assignments.end());
	EXPECT_EQ(coordinator->cpu_core_id, compiled.process_facilities[0].main_core_id.value());
}

/** @brief Verify a process facility claims only workers that invoke its exact mechanisms. */
TEST(runtime_plan_compiler, compiles_dpdk_facility_with_only_dependent_packet_workers)
{
	auto plan_or = make_mixed_dpdk_udp_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.process_facilities.size(), 1u);
	const auto rx_stream =
		std::find_if(compiled.io_streams.begin(), compiled.io_streams.end(),
			     [](const auto &stream) { return stream.direction == compiled_io_stream_direction::RX; });
	ASSERT_NE(rx_stream, compiled.io_streams.end());
	std::vector<uint32_t> packet_worker_indices;
	for (const auto &assignment : compiled.process_facilities[0].cpu_assignments) {
		if (assignment.kind == compiled_facility_cpu_owner_kind::PACKET_WORKER) {
			packet_worker_indices.push_back(assignment.owner_index);
		}
	}
	EXPECT_EQ(packet_worker_indices, (std::vector<uint32_t>{rx_stream->worker_index}));
	ASSERT_EQ(compiled.worker_schedules.size(), 2u);
	EXPECT_NE(compiled.worker_schedules[0].storage_domain_indices,
		  compiled.worker_schedules[1].storage_domain_indices);
}

/** @brief Verify a real cross-domain copy compiles once and contributes destination credits. */
TEST(runtime_plan_compiler, compiles_exact_bounded_copy_transition_and_staging_budget)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	add_second_host_storage_domain(plan);
	add_bounded_copy_transition(plan);

	const auto compiled_or = compile_provider_topology(plan);
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();
	ASSERT_EQ(compiled.storage_transitions.size(), 1u);
	EXPECT_EQ(compiled.storage_transitions[0].capabilities.mode, storage_transition_mode::BOUNDED_COPY);
	EXPECT_EQ(compiled.storage_transitions[0].from_storage_domain_index, 0u);
	EXPECT_EQ(compiled.storage_transitions[0].to_storage_domain_index, 1u);
	EXPECT_EQ(compiled.storage_transitions[0].staging_capacity, 1024u);
	ASSERT_EQ(compiled.storage_domains.size(), 2u);
	EXPECT_EQ(compiled.storage_domains[1].budget.required_min_buffers, 3200u);
	ASSERT_EQ(compiled.worker_schedules.size(), 1u);
	EXPECT_EQ(compiled.worker_schedules[0].storage_transition_indices, (std::vector<uint32_t>{0u}));
	EXPECT_EQ(compiled.worker_schedules[0].storage_domain_indices, (std::vector<uint32_t>{0u, 1u}));
}

/** @brief Charge one physical boundary ring once after source-domain convergence. */
TEST(runtime_plan_compiler, deduplicates_converged_boundary_credits_by_carried_domain)
{
	auto plan_or = make_valid_converging_transition_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	const auto compiled_or = compile_provider_topology(plan_or.value());
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	const auto &compiled = compiled_or.value();

	ASSERT_EQ(compiled.transition_topology.boundaries.size(), 1u);
	ASSERT_EQ(compiled.storage_transitions.size(), 2u);
	for (const std::string_view source_id :
	     {std::string_view{"storage_host_0"}, std::string_view{"storage_host_1"}}) {
		const auto source =
			std::find_if(compiled.storage_domains.begin(), compiled.storage_domains.end(),
				     [source_id](const auto &domain) { return domain.storage_domain_id == source_id; });
		ASSERT_NE(source, compiled.storage_domains.end());
		EXPECT_EQ(source->budget.required_min_buffers, 3200u);
	}
	const auto destination =
		std::find_if(compiled.storage_domains.begin(), compiled.storage_domains.end(),
			     [](const auto &domain) { return domain.storage_domain_id == "storage_host_2"; });
	ASSERT_NE(destination, compiled.storage_domains.end());

	uint64_t transition_staging = 0;
	for (const auto &transition : compiled.storage_transitions) {
		EXPECT_EQ(transition.capabilities.mode, storage_transition_mode::BOUNDED_COPY);
		EXPECT_EQ(transition.to_storage_domain_index, destination->storage_domain_index);
		transition_staging += transition.staging_capacity;
	}
	uint64_t tx_descriptors = 0;
	for (const auto &stream : compiled.io_streams) {
		if (stream.direction == compiled_io_stream_direction::TX &&
		    std::binary_search(stream.tx_storage_domain_indices.begin(), stream.tx_storage_domain_indices.end(),
				       destination->storage_domain_index)) {
			tx_descriptors += stream.descriptor_count;
		}
	}
	uint64_t worker_count = 0;
	const compiled_provider_worker_schedule *transition_owner = nullptr;
	for (const auto &schedule : compiled.worker_schedules) {
		if (std::find(schedule.storage_domain_indices.begin(), schedule.storage_domain_indices.end(),
			      destination->storage_domain_index) != schedule.storage_domain_indices.end()) {
			++worker_count;
		}
		if (schedule.storage_transition_indices.size() == 2u) {
			transition_owner = &schedule;
		}
	}
	ASSERT_NE(transition_owner, nullptr);
	EXPECT_EQ(transition_staging, 256u);
	EXPECT_EQ(tx_descriptors, 1024u);
	EXPECT_EQ(worker_count, 2u);
	EXPECT_EQ(transition_owner->storage_transition_indices, (std::vector<uint32_t>{0u, 1u}));
	EXPECT_EQ(transition_owner->source_storage_domain_indices, (std::vector<uint32_t>{0u, 1u}));
	EXPECT_NE(std::find(transition_owner->storage_domain_indices.begin(),
			    transition_owner->storage_domain_indices.end(), destination->storage_domain_index),
		  transition_owner->storage_domain_indices.end());

	const uint64_t boundary_credits = compiled.transition_topology.boundaries[0].data_ring_capacity;
	const auto expected_or =
		common::compile_storage_domain_buffer_budget(common::storage_domain_buffer_budget_inputs{
			.storage_domain_id = destination->storage_domain_id,
			.declared_buffer_count = destination->buffer_count,
			.rx_descriptor_count = 0,
			.tx_descriptor_count = tx_descriptors,
			.worker_count = worker_count,
			.worker_staging_capacity =
				worker_count * common::runtime_sizing::INTER_REGION_DATA_RING_CAPACITY,
			.handoff_staging_capacity = boundary_credits + transition_staging,
			.source_future_staging_capacity = 0,
			.future_output_capacity =
				compiled.transition_topology.boundaries[0].future_output_hold_capacity,
			.active_retained_capacity = 0u,
			.cache_size_per_worker = destination->cache_size_per_worker,
		});
	ASSERT_TRUE(expected_or.is_ok()) << expected_or.error().message();
	EXPECT_EQ(expected_or.value().required_min_buffers, 5568u);
	EXPECT_EQ(destination->budget.required_min_buffers, expected_or.value().required_min_buffers);
}

/** @brief Verify an unimplemented cross-domain edge never preserves the source domain implicitly. */
TEST(runtime_plan_compiler, rejects_cross_domain_edge_without_exact_transition)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	add_second_host_storage_domain(plan);

	expect_compiler_reject(plan, "missing storage transition before TX");
}

/** @brief Verify bounded-copy staging carries the NUMA fact required by its exact contract. */
TEST(runtime_plan_compiler, rejects_bounded_copy_transition_without_staging_numa)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	add_second_host_storage_domain(plan);
	add_bounded_copy_transition(plan);
	ASSERT_EQ(plan.storage_transitions_size(), 1);
	plan.mutable_storage_transitions(0)->clear_staging_numa_node();

	expect_compiler_reject(
		plan, "storage transition staging_numa_node presence must exactly match its provider contract");
}

/** @brief Verify bounded-copy capacity presence is owned by the exact catalog projection. */
TEST(runtime_plan_compiler, rejects_bounded_copy_transition_without_staging_capacity)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	add_second_host_storage_domain(plan);
	add_bounded_copy_transition(plan);
	ASSERT_EQ(plan.storage_transitions_size(), 1);
	plan.mutable_storage_transitions(0)->set_staging_capacity(0);

	expect_compiler_reject(plan,
			       "storage transition staging_capacity presence must exactly match its provider contract");
}

/** @brief Verify a same-domain stream-adjacent transition cannot duplicate the native RX transfer. */
TEST(runtime_plan_compiler, rejects_duplicate_stream_adjacent_storage_transition)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	kinetum::transition::core::v1::ZeroCopyShareConfig configuration;
	auto *transition = plan.add_storage_transitions();
	transition->set_transition_id("duplicate_rx_transfer");
	transition->mutable_from_endpoint()->set_io_stream_id("wan0.rx.lane_0");
	transition->mutable_to_endpoint()->set_stage_instance_id("rx@lane_0");
	transition->set_from_storage_domain_id("storage_host_0");
	transition->set_to_storage_domain_id("storage_host_0");
	transition->mutable_configuration()->PackFrom(configuration);

	expect_compiler_reject(plan, "zero-copy transition requires one domain and zero staging");
}

/** @brief Verify incomplete worker CPU ownership rejects at the composed structural authority. */
TEST(runtime_plan_compiler, rejects_worker_without_cpu_ownership)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_worker_placements(0)->clear_cpu_core_ids();

	expect_compiler_reject(plan, "requires exactly one dedicated CPU core");
}

/** @brief Verify regions cannot survive without exact worker placements. */
TEST(runtime_plan_compiler, rejects_missing_worker_placements)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_worker_placements();

	expect_compiler_reject(plan, "regions[] require explicit worker_placements[]");
}

/** @brief Verify duplicate compact worker indices reject before later ownership checks. */
TEST(runtime_plan_compiler, rejects_duplicate_worker_index)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto first = plan.worker_placements(0);
	plan.add_worker_placements()->CopyFrom(first);

	expect_compiler_reject(plan, "duplicate or noncompact worker_index");
}

/** @brief Verify worker identity is derived rather than trusted as free text. */
TEST(runtime_plan_compiler, rejects_noncanonical_worker_identity)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_worker_placements(0)->set_worker_id("wrong_worker");

	expect_compiler_reject(plan, "does not match deterministic ID");
}

/** @brief Verify worker ownership cannot name an absent execution lane. */
TEST(runtime_plan_compiler, rejects_unknown_worker_lane)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_worker_placements(0)->set_lane_id("missing_lane");

	expect_compiler_reject(plan, "references invalid lane_id");
}

/** @brief Verify one packet worker cannot own multiple CPU cores. */
TEST(runtime_plan_compiler, rejects_worker_with_multiple_cpu_cores)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *worker = plan.mutable_worker_placements(0);
	ASSERT_EQ(worker->cpu_core_ids_size(), 1);
	worker->add_cpu_core_ids(worker->cpu_core_ids(0) + 1);

	expect_compiler_reject(plan, "requires exactly one dedicated CPU core");
}

/** @brief Verify executable plans cannot omit their lane authority. */
TEST(runtime_plan_compiler, rejects_missing_execution_lanes)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_execution_lanes();

	expect_compiler_reject(plan, "missing execution_lanes[]");
}

/** @brief Verify executable plans cannot omit their stage-instance authority. */
TEST(runtime_plan_compiler, rejects_missing_stage_instances)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_stage_instances();

	expect_compiler_reject(plan, "missing stage_instances[]");
}

/** @brief Verify a stage instance cannot infer an execution provider. */
TEST(runtime_plan_compiler, rejects_unassigned_stage_instance_owner)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_stage_instances(0)->clear_execution_provider_instance_id();

	expect_compiler_reject(plan, "lacks exact region, execution-provider, or worker ownership");
}

/** @brief Verify an unused execution instance cannot enter compiled truth. */
TEST(runtime_plan_compiler, rejects_unused_execution_provider_instance)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto existing = plan.execution_provider_instances(0);
	auto *unused = plan.add_execution_provider_instances();
	unused->CopyFrom(existing);
	unused->set_execution_provider_instance_id("execution_cpu_unused");

	expect_compiler_reject(plan, "owns no stage");
}

/** @brief Verify a provider cannot claim a facility absent from plan truth. */
TEST(runtime_plan_compiler, rejects_unknown_facility_reference)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_io_driver_instances(0)->add_facility_instance_ids("facility_missing");

	expect_compiler_reject(plan, "references unknown facility");
}

/** @brief Verify a provider with no dependencies cannot absorb an extra facility. */
TEST(runtime_plan_compiler, rejects_extra_facility_dependency)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	kinetum::facility::dpdk::v1::DpdkFacilityConfig configuration;
	auto *facility = plan.add_process_facility_instances();
	facility->set_facility_instance_id("facility_dpdk_0");
	facility->mutable_configuration()->PackFrom(configuration);
	plan.mutable_execution_provider_instances(0)->add_facility_instance_ids("facility_dpdk_0");

	expect_compiler_reject(plan, "extra or missing facility dependency");
}

/** @brief Verify two storage records cannot own one stable identity. */
TEST(runtime_plan_compiler, rejects_duplicate_packet_storage_domain_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto existing = plan.packet_storage_domains(0);
	plan.add_packet_storage_domains()->CopyFrom(existing);

	expect_compiler_reject(plan, "duplicate packet-storage domain");
}

/** @brief Verify storage placement is present whenever its exact contract requires host NUMA. */
TEST(runtime_plan_compiler, rejects_storage_domain_without_contract_required_host_numa)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.packet_storage_domains_size(), 1);
	plan.mutable_packet_storage_domains(0)->clear_host_numa_node();

	expect_compiler_reject(plan, "host_numa_node presence must exactly match its provider contract");
}

/** @brief Verify every configured native driver port is consumed exactly once. */
TEST(runtime_plan_compiler, rejects_unused_driver_port_configuration)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	kinetum::io::udp::v1::UdpDriverConfig configuration;
	ASSERT_TRUE(plan.io_driver_instances(0).configuration().UnpackTo(&configuration));
	auto *unused = configuration.add_ports();
	unused->set_driver_port_id("unused0");
	unused->set_ipv4_address("127.0.0.1");
	unused->set_port(29999);
	plan.mutable_io_driver_instances(0)->mutable_configuration()->PackFrom(configuration);

	expect_compiler_reject(plan, "contains an unused driver port");
}

/** @brief Verify a logical port cannot name an undeclared I/O-driver instance. */
TEST(runtime_plan_compiler, rejects_logical_port_with_unknown_io_driver_instance)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->set_io_driver_instance_id("io_missing");

	expect_compiler_reject(plan, "references unknown I/O-driver instance");
}

/** @brief Verify a logical port cannot name an undeclared driver-local endpoint. */
TEST(runtime_plan_compiler, rejects_logical_port_with_unknown_driver_port_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->set_driver_port_id("port_missing");

	expect_compiler_reject(plan, "driver_port_id absent from canonical driver configuration");
}

/** @brief Verify module-visible logical-port IDs stay inside the fixed namespace. */
TEST(runtime_plan_compiler, rejects_logical_port_id_out_of_runtime_range)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->set_logical_port_id(KINETUM_MAX_PORTS);

	expect_compiler_reject(plan, "has invalid ID, MTU, NUMA, or MAC facts");
}

/** @brief Preserve exact MAC bytes and presence, and reject malformed lengths. */
TEST(runtime_plan_compiler, resolved_mac_is_absent_or_exactly_six_bytes)
{
	constexpr std::array<uint8_t, 6> ZERO_MAC{};
	constexpr std::array<uint8_t, 6> EXPECTED_MAC{0x02u, 0x00u, 0x7fu, 0x80u, 0xfeu, 0xffu};
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	const uint32_t port_index = port->logical_port_id();

	port->clear_resolved_mac_address();
	const auto absent = compile_provider_topology(plan);
	ASSERT_TRUE(absent.is_ok()) << absent.error().message();
	ASSERT_LT(port_index, absent->ports.size());
	EXPECT_EQ(absent->ports[port_index].logical_name, "wan0");
	EXPECT_FALSE(absent->ports[port_index].has_resolved_mac_address);
	EXPECT_EQ(absent->ports[port_index].resolved_mac_address, ZERO_MAC);

	port->set_resolved_mac_address(std::string("\x02\x00\x7f\x80\xfe\xff", 6u));
	const auto present = compile_provider_topology(plan);
	ASSERT_TRUE(present.is_ok()) << present.error().message();
	ASSERT_LT(port_index, present->ports.size());
	EXPECT_TRUE(present->ports[port_index].has_resolved_mac_address);
	EXPECT_EQ(present->ports[port_index].resolved_mac_address, EXPECTED_MAC);

	port->set_resolved_mac_address(std::string(6u, '\0'));
	const auto zero = compile_provider_topology(plan);
	ASSERT_TRUE(zero.is_ok()) << zero.error().message();
	ASSERT_LT(port_index, zero->ports.size());
	EXPECT_TRUE(zero->ports[port_index].has_resolved_mac_address);
	EXPECT_EQ(zero->ports[port_index].resolved_mac_address, ZERO_MAC);

	for (const std::size_t length : std::array<std::size_t, 7>{1u, 5u, 7u, 31u, 32u, 33u, 64u}) {
		SCOPED_TRACE(length);
		port->set_resolved_mac_address(std::string(length, 'x'));
		const auto rejected = compile_provider_topology(plan);
		ASSERT_FALSE(rejected.is_ok());
		EXPECT_EQ(rejected.error().code(), common::status_code::INVALID_ARGUMENT);
		EXPECT_NE(rejected.error().message().find("has invalid ID, MTU, NUMA, or MAC facts"),
			  std::string_view::npos);
	}
}

/** @brief Verify two logical ports cannot publish one module-visible ID. */
TEST(runtime_plan_compiler, rejects_duplicate_logical_port_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.ports_size(), 2);
	plan.mutable_ports(1)->set_logical_port_id(plan.ports(0).logical_port_id());

	expect_compiler_reject(plan, "duplicate logical name or logical_port_id");
}

/** @brief Verify two logical ports cannot publish one stable name. */
TEST(runtime_plan_compiler, rejects_duplicate_logical_name)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.ports_size(), 2);
	plan.mutable_ports(1)->set_logical_name(plan.ports(0).logical_name());

	expect_compiler_reject(plan, "duplicate logical name or logical_port_id");
}

/** @brief Verify every logical port carries one exact admitted direction. */
TEST(runtime_plan_compiler, rejects_unspecified_plan_port_direction)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_GT(plan.ports_size(), 0);
	plan.mutable_ports(0)->set_direction(kinetum::gluon::v1::PORT_DIRECTION_UNSPECIFIED);

	expect_compiler_reject(plan, "logical port has unspecified direction");
}

/** @brief Verify an executable provider graph cannot omit every logical port. */
TEST(runtime_plan_compiler, rejects_empty_plan_ports)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_ports();

	expect_compiler_reject(plan, "requires at least one logical port");
}

/** @brief Verify logical-port names are safe inputs to executable stream identity. */
TEST(runtime_plan_compiler, rejects_port_name_unsafe_for_generated_stream_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->set_logical_name("wan@invalid");

	expect_compiler_reject(plan, "logical port name must match");
}

/** @brief Verify an empty native interface alias cannot become a logical port. */
TEST(runtime_plan_compiler, rejects_empty_logical_port_name)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->clear_logical_name();

	expect_compiler_reject(plan, "logical port name must match");
}

/** @brief Verify receive execution cannot bind a transmit-only logical port. */
TEST(runtime_plan_compiler, rejects_rx_stage_bound_to_tx_only_port)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->set_direction(kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY);

	expect_compiler_reject(plan, "RX stream is bound to a TX-only logical port");
}

/** @brief Verify every enabled logical-port direction has exact stream ownership. */
TEST(runtime_plan_compiler, rejects_unowned_enabled_port_direction)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->set_direction(kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL);

	expect_compiler_reject(plan, "stream coverage disagrees with its exact direction");
}

/** @brief Verify logical ports cannot survive without executable streams. */
TEST(runtime_plan_compiler, rejects_plan_ports_without_io_streams)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.clear_io_streams();

	expect_compiler_reject(plan, "stream coverage disagrees with its exact direction");
}

/** @brief Verify an I/O stream cannot name an absent logical port. */
TEST(runtime_plan_compiler, rejects_io_stream_with_unknown_plan_port)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_io_streams(0)->set_logical_port_id(63);

	expect_compiler_reject(plan, "has an unknown port, stage, or worker reference");
}

/** @brief Verify a stream cannot substitute another valid logical-port identity. */
TEST(runtime_plan_compiler, rejects_io_stream_logical_port_mismatch)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *rx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx_port = find_port(plan, "lan0");
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx_port, nullptr);
	tx_port->set_direction(kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL);
	rx->set_logical_port_id(tx_port->logical_port_id());

	expect_compiler_reject(plan, "port disagrees with its logical stage interface binding");
}

/** @brief Verify an I/O stream cannot name storage absent from plan truth. */
TEST(runtime_plan_compiler, rejects_io_stream_with_unknown_storage_domain)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *stream = plan.mutable_io_streams(0);
	if (stream->direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
		stream->set_rx_storage_domain_id("storage_missing");
	} else {
		stream->mutable_tx_storage()->set_storage_domain_ids(0, "storage_missing");
	}

	expect_compiler_reject(plan, "references an unknown storage domain");
}

/** @brief Verify an I/O stream cannot omit its direction-specific storage binding. */
TEST(runtime_plan_compiler, rejects_io_stream_without_storage_binding)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const bool receiving = plan.io_streams(0).direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX;
	plan.mutable_io_streams(0)->clear_storage();

	expect_compiler_reject(plan, receiving ? "RX stream requires its exact allocation domain" :
						 "TX stream requires a nonempty storage admission set");
}

/** @brief Verify a stream identity must equal its canonical port/direction/lane derivation. */
TEST(runtime_plan_compiler, rejects_noncanonical_io_stream_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_io_streams(0)->set_io_stream_id("stream_alias");

	expect_compiler_reject(plan, "noncanonical executable identity");
}

/** @brief Verify duplicate generated stream identity rejects before ownership compilation. */
TEST(runtime_plan_compiler, rejects_duplicate_generated_io_stream_id)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	const auto duplicate = plan.io_streams(0);
	plan.add_io_streams()->CopyFrom(duplicate);

	expect_compiler_reject(plan, "io_streams[] contains duplicate io_stream_id");
}

/** @brief Verify two streams cannot claim one native queue/direction owner. */
TEST(runtime_plan_compiler, rejects_aliased_driver_queue_ownership)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	std::vector<kinetum::gluon::v1::IoStream *> rx_streams;
	for (auto &stream : *plan.mutable_io_streams()) {
		if (stream.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
			rx_streams.push_back(&stream);
		}
	}
	ASSERT_EQ(rx_streams.size(), 2u);
	rx_streams[1]->set_driver_queue_id(rx_streams[0]->driver_queue_id());

	expect_compiler_reject(plan, "same driver queue and direction");
}

/** @brief Verify a native queue identity cannot exceed its selected driver contract. */
TEST(runtime_plan_compiler, rejects_io_stream_driver_queue_above_contract_range)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *rx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx, nullptr);
	rx->set_driver_queue_id(std::numeric_limits<uint16_t>::max());

	expect_compiler_reject(plan, "exceeds its driver contract's queue or descriptor range");
}

/** @brief Verify dense-zero-based native queue ownership cannot contain a gap. */
TEST(runtime_plan_compiler, rejects_non_dense_driver_queue_ownership)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	uint32_t rx_count = 0;
	for (auto &stream : *plan.mutable_io_streams()) {
		if (stream.direction() != kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
			continue;
		}
		if (rx_count == 1u) {
			stream.set_driver_queue_id(2u);
		}
		++rx_count;
	}
	ASSERT_EQ(rx_count, 2u);

	expect_compiler_reject(plan, "dense zero-based range");
}

/** @brief Verify a driver cannot consume storage lacking its exact access agents. */
TEST(runtime_plan_compiler, rejects_io_stream_storage_access_contract_mismatch)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.packet_storage_domains_size(), 1);
	kinetum::storage::host::v1::HostStorageConfig configuration;
	auto *storage = plan.mutable_packet_storage_domains(0);
	storage->clear_facility_instance_ids();
	storage->mutable_configuration()->PackFrom(configuration);

	expect_compiler_reject(plan, "storage domain lacks the exact driver's access agents");
}

/** @brief Verify packet storage payload room covers the bound logical-port MTU. */
TEST(runtime_plan_compiler, rejects_io_stream_storage_data_room_below_port_mtu)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.packet_storage_domains_size(), 1);
	plan.mutable_packet_storage_domains(0)->set_data_room_bytes(1500u);

	expect_compiler_reject(plan, "storage data room cannot hold its exact port MTU");
}

/** @brief Verify stream direction cannot disagree with its executable stage. */
TEST(runtime_plan_compiler, rejects_io_stream_direction_mismatch)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *rx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx, nullptr);
	auto *port = find_port(plan, "wan0");
	ASSERT_NE(port, nullptr);
	port->set_direction(kinetum::gluon::v1::PORT_DIRECTION_BIDIRECTIONAL);
	rx->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	rx->set_io_stream_id(kinetum::common::execution_topology::make_io_stream_id("wan0", "tx", rx->lane_id()));

	expect_compiler_reject(plan, "direction disagrees with its attached stage kind");
}

/** @brief Verify descriptor counts must fit the selected driver contract. */
TEST(runtime_plan_compiler, rejects_io_stream_descriptor_count_contract_mismatch)
{
	auto plan_or = make_valid_rss_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *rx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx, nullptr);
	rx->set_descriptor_count(static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) + 1u);

	expect_compiler_reject(plan, "exceeds its driver contract's queue or descriptor range");
}

/** @brief Verify every receive stream names one exact steering authority. */
TEST(runtime_plan_compiler, rejects_unknown_traffic_steering_profile_reference)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *rx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx, nullptr);
	rx->set_steering_profile_id("steering_missing");

	expect_compiler_reject(plan, "references unknown traffic-steering profile");
}

/** @brief Verify an undeclared steering number cannot become a runtime fallback. */
TEST(runtime_plan_compiler, rejects_unknown_traffic_steering_profile_kind)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	ASSERT_EQ(plan.traffic_steering_profiles_size(), 1);
	plan.mutable_traffic_steering_profiles(0)->set_kind(static_cast<kinetum::gluon::v1::TrafficSteeringKind>(3));

	expect_compiler_reject(plan, "unknown enum number");
}

/** @brief Verify even one receive stream cannot omit its exact steering profile. */
TEST(runtime_plan_compiler, rejects_rx_stream_without_traffic_steering_profile)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	auto *rx = find_stream(plan, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx, nullptr);
	rx->clear_steering_profile_id();
	plan.clear_traffic_steering_profiles();

	expect_compiler_reject(plan, "every RX stream requires one exact steering profile");
}

/** @brief Verify authored storage capacity cannot undercut the compiled credit floor. */
TEST(runtime_plan_compiler, rejects_packet_storage_below_computed_budget)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	plan.mutable_packet_storage_domains(0)->set_buffer_count(3199);

	expect_compiler_reject(plan, "buffer_count below computed minimum");
}

/** @brief Verify descriptor-plus-burst sizing cannot replace the shared ten-term floor. */
TEST(runtime_plan_compiler, rejects_packet_storage_sized_only_for_current_streams)
{
	auto plan_or = make_valid_provider_plan();
	ASSERT_TRUE(plan_or.is_ok()) << plan_or.error().message();
	auto plan = std::move(plan_or).value();
	uint64_t descriptor_only_capacity = common::runtime_sizing::PACKET_MAX_BURST_SIZE;
	for (const auto &stream : plan.io_streams()) {
		descriptor_only_capacity += stream.descriptor_count();
	}
	ASSERT_LE(descriptor_only_capacity, std::numeric_limits<uint32_t>::max());
	plan.mutable_packet_storage_domains(0)->set_buffer_count(static_cast<uint32_t>(descriptor_only_capacity));

	expect_compiler_reject(plan, "buffer_count below computed minimum");
}

}  // namespace
}  // namespace kinetum::provider
