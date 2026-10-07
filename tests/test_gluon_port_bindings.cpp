// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_gluon_port_bindings.cpp
 * @brief Exact DeploymentBindings validation and deterministic-lowering tests.
 * @author Fleming Patel
 *
 * Gluon consumes one complete provider-neutral deployment-intent message.
 * These tests prove that typed provider configuration, logical interfaces,
 * explicit queues, storage ownership, execution ownership, and logical
 * transition endpoints lower into one deterministic DeploymentPlan without a
 * backend selector, target-string inference, queue default, or EAL override.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <google/protobuf/unknown_field_set.h>

#include "gen/kinetum/axiom/v1/axiom.pb.h"
#include "gen/kinetum/execution/cpu/v1/cpu_execution.pb.h"
#include "gen/kinetum/facility/dpdk/v1/dpdk_facility.pb.h"
#include "gen/kinetum/gluon/v1/bindings.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "gen/kinetum/io/dpdk/v1/dpdk_driver.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "gen/kinetum/storage/dpdk/v1/dpdk_storage.pb.h"
#include "gen/kinetum/storage/host/v1/host_storage.pb.h"
#include "gen/kinetum/transition/core/v1/core_transition.pb.h"
#include "gen/kinetum/transition/cpu/v1/cpu_transition.pb.h"
#include "src/common/execution_topology_ids.hpp"
#include "src/gluon/deployment_bindings_lowering.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "src/gluon/transition_plan_lowering.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "tests/gluon_test_deployment.hpp"

namespace kinetum::gluon
{
namespace
{

/** Compiled EAL facility identity shared by binding fixtures. */
constexpr const char *DPDK_FACILITY_ID = "facility_dpdk_0";
/** Compiled native I/O-driver identity shared by binding fixtures. */
constexpr const char *DPDK_DRIVER_ID = "io_dpdk_0";
/** Compiled storage-domain identity shared by binding fixtures. */
constexpr const char *DPDK_STORAGE_ID = "storage_dpdk_0";
/** Exact native queue capacity authored by the fixtures. */
constexpr uint32_t TEST_DESCRIPTOR_COUNT = 1024;
/** Context-memory authority for admitted module stages. */
constexpr uint64_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = uint64_t{2} * 1024u * 1024u;
/** Epoch-arena authority for admitted module stages. */
constexpr uint64_t TEST_EPOCH_ARENA_CAPACITY_BYTES = uint64_t{2} * 1024u * 1024u;
/** Fixed Toeplitz key bytes supplied by every RSS fixture. */
constexpr char TEST_RSS_KEY_BYTES[] = "\x6d\x5a\x56\xda\x25\x5b\x0e\xc2\x41\x67\x25\x3d\x43\xa3\x8f\xb0"
				      "\xd0\xca\x2b\xcb\xae\x7b\x30\xb4\x77\xcb\x2d\xa3\x80\x30\xf2\x0c"
				      "\x6a\x42\xb7\x3b\xbe\xac\x01\xfa";
/** Complete RSS key view excluding the C string terminator. */
constexpr std::string_view TEST_RSS_KEY{TEST_RSS_KEY_BYTES, sizeof(TEST_RSS_KEY_BYTES) - 1u};

/** @brief Typed DPDK attachment used by test deployment construction. */
struct test_dpdk_attachment {
	std::string logical_name;    ///< Pipeline logical-interface identity.
	std::string driver_port_id;  ///< Driver-local identity.
	std::string native_name;     ///< Exact PCI BDF or TAP interface.
	bool pci{true};		     ///< True for PCI, false for TAP.
};

/**
 * @brief Return a deterministic inventory MAC spelling.
 * @param index Fixture port ordinal in the one-byte suffix domain.
 * @return Canonical colon-separated fixture MAC text.
 */
[[nodiscard]] static std::string test_mac_address(int index)
{
	std::ostringstream output;
	output << "02:00:00:00:00:" << std::hex << std::setw(2) << std::setfill('0') << index;
	return output.str();
}

/**
 * @brief Return the exact six-byte MAC corresponding to test_mac_address().
 * @param index Fixture port ordinal in the one-byte suffix domain.
 * @return Six raw MAC bytes matching the textual fixture representation.
 */
[[nodiscard]] static std::string test_mac_bytes(int index)
{
	std::string bytes(6u, '\0');
	bytes[0] = static_cast<char>(0x02);
	bytes[5] = static_cast<char>(index);
	return bytes;
}

/**
 * @brief Create a simple RX-to-TX pipeline with exact interface parameters.
 *
 * @param rx_interface RX logical interface.
 * @param tx_interface TX logical interface.
 * @return Complete two-stage pipeline.
 */
[[nodiscard]] static kinetum::axiom::v1::Pipeline make_rx_tx_pipeline(std::string_view rx_interface,
								      std::string_view tx_interface)
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("test_pipeline");

	auto *rx = pipeline.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface(rx_interface.data(), rx_interface.size());

	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface(tx_interface.data(), tx_interface.size());

	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id("rx");
	edge->set_to_stage_id("tx");
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Create an RX-to-active-module-to-TX pipeline.
 *
 * @param rx_interface RX logical interface.
 * @param tx_interface TX logical interface.
 * @return Pipeline containing one active module stage.
 */
[[nodiscard]] static kinetum::axiom::v1::Pipeline make_rx_active_tx_pipeline(std::string_view rx_interface,
									     std::string_view tx_interface)
{
	auto pipeline = make_rx_tx_pipeline(rx_interface, tx_interface);
	pipeline.mutable_edges(0)->set_to_stage_id("active0");

	auto *active = pipeline.add_stages();
	active->set_stage_id("active0");
	active->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	active->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	active->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
	active->mutable_module()->set_module_id("kinetum.test_active");
	active->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);

	auto *active_to_tx = pipeline.add_edges();
	active_to_tx->set_from_stage_id("active0");
	active_to_tx->set_to_stage_id("tx");
	active_to_tx->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	return pipeline;
}

/**
 * @brief Create a two-RX fan-in pipeline with one TX stage.
 *
 * @param rx0_interface First RX logical interface.
 * @param rx1_interface Second RX logical interface.
 * @param tx_interface TX logical interface.
 * @return Fan-in pipeline.
 */
[[nodiscard]] static kinetum::axiom::v1::Pipeline make_two_rx_one_tx_pipeline(std::string_view rx0_interface,
									      std::string_view rx1_interface,
									      std::string_view tx_interface)
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("test_fan_in_pipeline");
	pipeline.set_allow_dag(true);

	for (const auto &[stage_id, interface_name] :
	     {std::pair{"rx0", rx0_interface}, std::pair{"rx1", rx1_interface}}) {
		auto *rx = pipeline.add_stages();
		rx->set_stage_id(stage_id);
		rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
		rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		rx->mutable_io()->set_interface(interface_name.data(), interface_name.size());
	}

	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface(tx_interface.data(), tx_interface.size());

	for (const auto *rx_id : {"rx0", "rx1"}) {
		auto *edge = pipeline.add_edges();
		edge->set_from_stage_id(rx_id);
		edge->set_to_stage_id("tx");
		edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	}
	return pipeline;
}

/**
 * @brief Create exact CPU and DPDK NIC inventory facts.
 *
 * @param pci_addresses Canonical PCI identities in deterministic MAC order.
 * @return Synthetic single-node hardware inventory.
 */
[[nodiscard]] static kinetum::hw::v1::HardwareInventory make_hw_inventory(const std::vector<std::string> &pci_addresses)
{
	kinetum::hw::v1::HardwareInventory hardware;
	auto *node = hardware.mutable_node();

	auto *cpu = node->mutable_cpu();
	for (int core_id = 0; core_id < 8; ++core_id) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(core_id);
		core->set_numa_node(0);
		core->set_is_hyperthread(false);
	}

	int nic_index = 0;
	for (const auto &pci_address : pci_addresses) {
		auto *nic = node->add_nics();
		nic->set_pci_address(pci_address);
		nic->set_numa_node(0);
		nic->set_mac_address(test_mac_address(nic_index++));
		nic->set_max_mtu(9000);
		nic->set_driver(kinetum::hw::v1::NIC_DRIVER_DPDK);
	}
	return hardware;
}

/**
 * @brief Replace the test UDP/host graph with an explicit DPDK graph.
 *
 * @param pipeline Pipeline whose complete logical coverage is required.
 * @param attachments Exact driver-port attachment set.
 * @return Complete DPDK/DPDK-storage/CPU deployment intent.
 */
[[nodiscard]] static kinetum::gluon::v1::DeploymentBindings
make_dpdk_bindings(const kinetum::axiom::v1::Pipeline &pipeline, const std::vector<test_dpdk_attachment> &attachments)
{
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);

	bindings.clear_process_facility_instances();
	kinetum::facility::dpdk::v1::DpdkFacilityConfig facility_config;
	auto *facility = bindings.add_process_facility_instances();
	facility->set_facility_instance_id(DPDK_FACILITY_ID);
	facility->mutable_configuration()->PackFrom(facility_config);

	kinetum::io::dpdk::v1::DpdkDriverConfig driver_config;
	for (const auto &attachment : attachments) {
		auto *port = driver_config.add_ports();
		port->set_driver_port_id(attachment.driver_port_id);
		if (attachment.pci) {
			port->mutable_pci()->set_pci_address(attachment.native_name);
		} else {
			port->mutable_tap()->set_interface_name(attachment.native_name);
		}
	}
	auto *driver = bindings.mutable_io_driver_instances(0);
	driver->set_io_driver_instance_id(DPDK_DRIVER_ID);
	driver->clear_facility_instance_ids();
	driver->add_facility_instance_ids(DPDK_FACILITY_ID);
	driver->mutable_configuration()->PackFrom(driver_config);

	for (auto &logical_port : *bindings.mutable_logical_port_bindings()) {
		const auto attachment =
			std::find_if(attachments.begin(), attachments.end(), [&](const auto &candidate) {
				return candidate.logical_name == logical_port.logical_name();
			});
		if (attachment != attachments.end()) {
			logical_port.set_io_driver_instance_id(DPDK_DRIVER_ID);
			logical_port.set_driver_port_id(attachment->driver_port_id);
		}
	}

	kinetum::storage::dpdk::v1::DpdkStorageConfig storage_config;
	storage_config.set_cache_size(256);
	auto *storage = bindings.mutable_packet_storage_domains(0);
	storage->set_storage_domain_id(DPDK_STORAGE_ID);
	storage->clear_facility_instance_ids();
	storage->add_facility_instance_ids(DPDK_FACILITY_ID);
	storage->mutable_configuration()->PackFrom(storage_config);
	for (auto &stream : *bindings.mutable_io_stream_bindings()) {
		for (auto &queue : *stream.mutable_queues()) {
			if (stream.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				queue.set_rx_storage_domain_id(DPDK_STORAGE_ID);
			} else {
				queue.mutable_tx_storage()->set_storage_domain_ids(0, DPDK_STORAGE_ID);
			}
		}
	}
	for (auto &origin : *bindings.mutable_active_origin_bindings()) {
		origin.set_storage_domain_id(DPDK_STORAGE_ID);
	}
	return bindings;
}

/**
 * @brief Build planner options from complete deployment intent.
 *
 * @param bindings Exact bindings to consume.
 * @param regions Requested logical-region count.
 * @return Planner options.
 */
[[nodiscard]] static planner_options make_options(const kinetum::gluon::v1::DeploymentBindings &bindings,
						  int32_t regions = 1)
{
	planner_options options;
	options.regions = regions;
	options.deployment_bindings = bindings;
	return options;
}

/**
 * @brief Find one mutable stream binding by logical name and direction.
 *
 * @param bindings Mutable deployment intent.
 * @param logical_name Exact logical interface.
 * @param direction Exact executable direction.
 * @return Mutable binding, or nullptr.
 */
[[nodiscard]] static kinetum::gluon::v1::IoStreamBinding *
find_stream_binding(kinetum::gluon::v1::DeploymentBindings &bindings, std::string_view logical_name,
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
 * @brief Replace one stream binding's explicit queue set.
 *
 * @param binding Stream binding to mutate.
 * @param queue_count Number of sequential queues beginning at zero.
 */
static void set_queue_count(kinetum::gluon::v1::IoStreamBinding &binding, uint32_t queue_count)
{
	ASSERT_FALSE(binding.queues().empty());
	const auto prototype = binding.queues(0);
	binding.clear_queues();
	for (uint32_t queue_id = 0; queue_id < queue_count; ++queue_id) {
		auto *queue = binding.add_queues();
		queue->CopyFrom(prototype);
		queue->set_driver_queue_id(queue_id);
		queue->set_descriptor_count(TEST_DESCRIPTOR_COUNT + queue_id);
	}
}

/**
 * @brief Configure one exact deterministic RSS contract.
 *
 * @param binding RX binding to mutate.
 * @param queue_count Number of explicit queues.
 * @param key Exact deterministic key bytes.
 * @param symmetric Hardware symmetry for an unchanged tuple.
 */
static void set_rss(kinetum::gluon::v1::IoStreamBinding &binding, uint32_t queue_count,
		    std::string_view key = TEST_RSS_KEY, bool symmetric = true)
{
	set_queue_count(binding, queue_count);
	auto *steering = binding.mutable_steering();
	steering->set_kind(kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS);
	steering->set_symmetric(symmetric);
	steering->clear_hash_fields();
	steering->add_hash_fields("ipv4");
	steering->add_hash_fields("udp");
	steering->set_hash_key(key.data(), key.size());
}

/**
 * @brief Find a plan port by logical name.
 *
 * @param plan Exact emitted plan.
 * @param logical_name Port identity.
 * @return Matching port, or nullptr.
 */
[[nodiscard]] static const kinetum::gluon::v1::PortConfig *find_port(const kinetum::gluon::v1::DeploymentPlan &plan,
								     std::string_view logical_name)
{
	for (const auto &port : plan.ports()) {
		if (port.logical_name() == logical_name) {
			return &port;
		}
	}
	return nullptr;
}

/**
 * @brief Find a plan stream by exact ID.
 *
 * @param plan Exact emitted plan.
 * @param stream_id Stream identity.
 * @return Matching stream, or nullptr.
 */
[[nodiscard]] static const kinetum::gluon::v1::IoStream *find_stream(const kinetum::gluon::v1::DeploymentPlan &plan,
								     std::string_view stream_id)
{
	for (const auto &stream : plan.io_streams()) {
		if (stream.io_stream_id() == stream_id) {
			return &stream;
		}
	}
	return nullptr;
}

/**
 * @brief Verify typed PCI bindings resolve exact final port facts.
 */
TEST(gluon_port_bindings, valid_pci_bindings_resolve_exact_plan_ports)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	const auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
							    {"lan0", "lan_port", "0000:03:00.1", true}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();

	const auto &emitted = result.value();
	ASSERT_EQ(emitted.ports_size(), 2);
	const auto *lan = find_port(emitted, "lan0");
	const auto *wan = find_port(emitted, "wan0");
	ASSERT_NE(lan, nullptr);
	ASSERT_NE(wan, nullptr);
	EXPECT_EQ(lan->logical_port_id(), 0u);
	EXPECT_EQ(wan->logical_port_id(), 1u);
	EXPECT_EQ(lan->io_driver_instance_id(), DPDK_DRIVER_ID);
	EXPECT_EQ(lan->driver_port_id(), "lan_port");
	EXPECT_EQ(wan->driver_port_id(), "wan_port");
	EXPECT_EQ(lan->direction(), kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY);
	EXPECT_EQ(wan->direction(), kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY);
	ASSERT_TRUE(lan->has_host_numa_node());
	ASSERT_TRUE(wan->has_host_numa_node());
	EXPECT_EQ(lan->host_numa_node(), 0);
	EXPECT_EQ(wan->host_numa_node(), 0);
	EXPECT_EQ(lan->resolved_mac_address(), test_mac_bytes(1));
	EXPECT_EQ(wan->resolved_mac_address(), test_mac_bytes(0));
}

/**
 * @brief Verify complete bindings emit every provider-graph role explicitly.
 */
TEST(gluon_port_bindings, complete_bindings_emit_exact_provider_graph)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	const auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
							    {"lan0", "lan_port", "0000:03:00.1", true}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto &emitted = result.value();

	ASSERT_EQ(emitted.process_facility_instances_size(), 1);
	EXPECT_EQ(emitted.process_facility_instances(0).facility_instance_id(), DPDK_FACILITY_ID);
	EXPECT_EQ(emitted.process_facility_instances(0).configuration().type_url(),
		  kinetum::provider::DPDK_FACILITY_TYPE_URL);
	ASSERT_EQ(emitted.io_driver_instances_size(), 1);
	EXPECT_EQ(emitted.io_driver_instances(0).io_driver_instance_id(), DPDK_DRIVER_ID);
	EXPECT_EQ(emitted.io_driver_instances(0).configuration().type_url(), kinetum::provider::DPDK_DRIVER_TYPE_URL);
	ASSERT_EQ(emitted.packet_storage_domains_size(), 1);
	EXPECT_EQ(emitted.packet_storage_domains(0).storage_domain_id(), DPDK_STORAGE_ID);
	EXPECT_EQ(emitted.packet_storage_domains(0).configuration().type_url(),
		  kinetum::provider::DPDK_STORAGE_TYPE_URL);
	ASSERT_EQ(emitted.execution_provider_instances_size(), 1);
	EXPECT_EQ(emitted.execution_provider_instances(0).configuration().type_url(),
		  kinetum::provider::CPU_EXECUTION_TYPE_URL);
	EXPECT_EQ(emitted.storage_transitions_size(), 0);
	ASSERT_EQ(emitted.runtime_service_placements_size(), 2);
	for (const auto &instance : emitted.stage_instances()) {
		EXPECT_EQ(instance.execution_provider_instance_id(), "execution_cpu_0");
	}
}

/**
 * @brief Verify one explicit queue lowers into one exact executable topology.
 */
TEST(gluon_port_bindings, single_queue_bindings_lower_exact_execution_topology)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	const auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto &emitted = result.value();

	ASSERT_EQ(emitted.execution_lanes_size(), 1);
	ASSERT_EQ(emitted.worker_placements_size(), 1);
	EXPECT_EQ(emitted.execution_lanes(0).lane_id(), "lane_0");
	EXPECT_EQ(emitted.worker_placements(0).worker_id(), "worker_r0_lane_0");
	EXPECT_EQ(emitted.worker_placements(0).lane_id(), "lane_0");
	ASSERT_EQ(emitted.stage_instances_size(), 2);
	for (const auto &instance : emitted.stage_instances()) {
		EXPECT_EQ(instance.execution_provider_instance_id(), "execution_cpu_0");
	}

	const auto *rx = find_stream(emitted, "wan0.rx.lane_0");
	const auto *tx = find_stream(emitted, "lan0.tx.lane_0");
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx, nullptr);
	EXPECT_EQ(rx->driver_queue_id(), 0u);
	EXPECT_EQ(tx->driver_queue_id(), 0u);
	EXPECT_EQ(rx->owning_worker_id(), "worker_r0_lane_0");
	EXPECT_EQ(tx->owning_worker_id(), "worker_r0_lane_0");
	EXPECT_EQ(rx->rx_storage_domain_id(), "storage_host_0");
	ASSERT_EQ(tx->tx_storage().storage_domain_ids_size(), 1);
	EXPECT_EQ(tx->tx_storage().storage_domain_ids(0), "storage_host_0");
	EXPECT_EQ(rx->descriptor_count(), TEST_DESCRIPTOR_COUNT);
	EXPECT_EQ(tx->descriptor_count(), TEST_DESCRIPTOR_COUNT);
}

/**
 * @brief Verify explicit multi-queue RX and TX lower one deterministic RSS graph.
 */
TEST(gluon_port_bindings, explicit_rss_queues_lower_deterministic_topology)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx, nullptr);
	set_rss(*rx, 2);
	set_queue_count(*tx, 2);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto &emitted = result.value();

	ASSERT_EQ(emitted.execution_lanes_size(), 2);
	ASSERT_EQ(emitted.worker_placements_size(), 2);
	ASSERT_EQ(emitted.traffic_steering_profiles_size(), 1);
	const auto &profile = emitted.traffic_steering_profiles(0);
	EXPECT_EQ(profile.kind(), kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS);
	EXPECT_TRUE(profile.symmetric());
	EXPECT_EQ(profile.hash_key(), TEST_RSS_KEY);
	ASSERT_EQ(profile.hash_fields_size(), 2);
	EXPECT_EQ(profile.hash_fields(0), "ipv4");
	EXPECT_EQ(profile.hash_fields(1), "udp");
	ASSERT_EQ(profile.stream_ids_size(), 2);
	EXPECT_EQ(profile.stream_ids(0), "wan0.rx.lane_0");
	EXPECT_EQ(profile.stream_ids(1), "wan0.rx.lane_1");
	const auto *lane0 = find_stream(emitted, "wan0.rx.lane_0");
	const auto *lane1 = find_stream(emitted, "wan0.rx.lane_1");
	ASSERT_NE(lane0, nullptr);
	ASSERT_NE(lane1, nullptr);
	EXPECT_EQ(lane0->driver_queue_id(), 0u);
	EXPECT_EQ(lane1->driver_queue_id(), 1u);
	EXPECT_TRUE(emitted.module_context_domains().empty());
}

/** @brief RSS queue storage stays attached to its authored queue through lane lowering. */
TEST(gluon_port_bindings, rss_queues_lower_independent_rx_allocation_and_tx_admission)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	const auto original = bindings.packet_storage_domains(0);
	auto *second = bindings.add_packet_storage_domains();
	second->CopyFrom(original);
	second->set_storage_domain_id("storage_dpdk_1");
	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx, nullptr);
	set_rss(*rx, 2);
	set_queue_count(*tx, 2);
	rx->mutable_queues(1)->set_rx_storage_domain_id("storage_dpdk_1");
	tx->mutable_queues(1)->mutable_tx_storage()->set_storage_domain_ids(0, "storage_dpdk_1");
	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto *rx_zero = find_stream(result.value(), "wan0.rx.lane_0");
	const auto *rx_one = find_stream(result.value(), "wan0.rx.lane_1");
	const auto *tx_zero = find_stream(result.value(), "lan0.tx.lane_0");
	const auto *tx_one = find_stream(result.value(), "lan0.tx.lane_1");
	ASSERT_NE(rx_zero, nullptr);
	ASSERT_NE(rx_one, nullptr);
	ASSERT_NE(tx_zero, nullptr);
	ASSERT_NE(tx_one, nullptr);
	EXPECT_EQ(rx_zero->rx_storage_domain_id(), DPDK_STORAGE_ID);
	EXPECT_EQ(rx_one->rx_storage_domain_id(), "storage_dpdk_1");
	ASSERT_EQ(tx_zero->tx_storage().storage_domain_ids_size(), 1);
	ASSERT_EQ(tx_one->tx_storage().storage_domain_ids_size(), 1);
	EXPECT_EQ(tx_zero->tx_storage().storage_domain_ids(0), DPDK_STORAGE_ID);
	EXPECT_EQ(tx_one->tx_storage().storage_domain_ids(0), "storage_dpdk_1");
	EXPECT_EQ(result->storage_transitions_size(), 0);
}

/** @brief RX and TX queues reject a storage arm belonging to the opposite direction. */
TEST(gluon_port_bindings, queue_storage_arm_must_match_direction)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	for (const bool receiving : {true, false}) {
		auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
		auto *stream = find_stream_binding(bindings, receiving ? "wan0" : "lan0",
						   receiving ? kinetum::gluon::v1::IO_STREAM_DIRECTION_RX :
							       kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
		ASSERT_NE(stream, nullptr);
		if (receiving) {
			stream->mutable_queues(0)->mutable_tx_storage()->add_storage_domain_ids("storage_host_0");
		} else {
			stream->mutable_queues(0)->set_rx_storage_domain_id("storage_host_0");
		}
		const auto result = plan(pipeline, hardware, make_options(bindings));
		ASSERT_FALSE(result.is_ok());
		EXPECT_NE(result.error().message().find(receiving ? "RX queue requires" : "TX queue requires"),
			  std::string::npos);
	}
}

/**
 * @brief Verify multi-ingress streams retain exact port-local steering membership.
 */
TEST(gluon_port_bindings, fan_in_rss_lowers_exact_stream_and_steering_membership)
{
	const auto pipeline = make_two_rx_one_tx_pipeline("wan0", "wan1", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1", "0000:03:00.2"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan0_port", "0000:03:00.0", true},
						      {"wan1", "wan1_port", "0000:03:00.1", true},
						      {"lan0", "lan_port", "0000:03:00.2", true}});
	for (const auto *logical_name : {"wan0", "wan1"}) {
		auto *rx = find_stream_binding(bindings, logical_name, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
		ASSERT_NE(rx, nullptr);
		set_rss(*rx, 2);
	}
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx, nullptr);
	set_queue_count(*tx, 2);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto &emitted = result.value();
	ASSERT_EQ(emitted.traffic_steering_profiles_size(), 2);
	EXPECT_TRUE(emitted.module_context_domains().empty());
	for (const auto &lane : emitted.execution_lanes()) {
		EXPECT_TRUE(std::is_sorted(lane.stage_instance_ids().begin(), lane.stage_instance_ids().end()));
		EXPECT_TRUE(std::is_sorted(lane.io_stream_ids().begin(), lane.io_stream_ids().end()));
	}
	for (const auto &profile : emitted.traffic_steering_profiles()) {
		EXPECT_TRUE(std::is_sorted(profile.stream_ids().begin(), profile.stream_ids().end()));
	}
}

/**
 * @brief Verify multi-lane lowering gives every active instance exact ownership.
 */
TEST(gluon_port_bindings, multi_queue_topology_lowers_exact_active_instance_ownership)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	kinetum::test::add_module_context_resource_binding(
		bindings, "active0", "lane_0", TEST_CONTEXT_MEMORY_CAPACITY_BYTES, TEST_EPOCH_ARENA_CAPACITY_BYTES);
	kinetum::test::add_module_context_resource_binding(
		bindings, "active0", "lane_1", TEST_CONTEXT_MEMORY_CAPACITY_BYTES, TEST_EPOCH_ARENA_CAPACITY_BYTES);
	auto *lane_one_origin = bindings.add_active_origin_bindings();
	lane_one_origin->set_logical_stage_id("active0");
	lane_one_origin->set_lane_id("lane_1");
	lane_one_origin->set_storage_domain_id(DPDK_STORAGE_ID);
	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx, nullptr);
	set_rss(*rx, 2);
	set_queue_count(*tx, 2);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	std::vector<std::string> active_instances;
	for (const auto &stage : result->stage_instances()) {
		if (stage.logical_stage_id() == "active0") {
			active_instances.push_back(stage.stage_instance_id());
			EXPECT_EQ(stage.active_origin_storage_domain_id(), DPDK_STORAGE_ID);
			EXPECT_EQ(stage.context_instance_id(), stage.stage_instance_id());
		}
	}
	EXPECT_EQ(active_instances, (std::vector<std::string>{"active0@lane_0", "active0@lane_1"}));
}

/**
 * @brief Verify active origination lowers one exact lane-local storage owner.
 */
TEST(gluon_port_bindings, active_origin_binding_lowers_exact_stage_storage_owner)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	const auto bindings = kinetum::test::make_udp_test_deployment_bindings(
		pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES, TEST_EPOCH_ARENA_CAPACITY_BYTES);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto &stages = result.value().stage_instances();
	const auto active = std::find_if(stages.begin(), stages.end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "active0"; });
	ASSERT_NE(active, stages.end());
	EXPECT_EQ(active->lane_id(), "lane_0");
	EXPECT_EQ(active->active_origin_storage_domain_id(), "storage_host_0");
	for (const auto &stage : stages) {
		if (stage.logical_stage_id() != "active0") {
			EXPECT_TRUE(stage.active_origin_storage_domain_id().empty());
		}
	}
}

/** @brief Verify Gluon independently subordinates async cancellation to commit. */
TEST(gluon_port_bindings, tracked_async_grace_is_strictly_below_emitted_commit_timeout)
{
	auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	auto *active = pipeline.mutable_stages(2);
	ASSERT_EQ(active->stage_id(), "active0");
	active->mutable_module()->set_module_id("kinetum.test_active_async");
	active->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	auto *limits = active->mutable_active_stage_limits();
	limits->set_async_work_capacity(4u);
	limits->set_async_cancel_grace_ms(TRANSITION_COMMIT_TIMEOUT_MS);
	const auto hardware = make_hw_inventory({});
	const auto bindings = kinetum::test::make_udp_test_deployment_bindings(
		pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES, TEST_EPOCH_ARENA_CAPACITY_BYTES);

	const auto rejected = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_NE(rejected.error().message().find("shorter than commit timeout"), std::string::npos);

	limits->set_async_cancel_grace_ms(TRANSITION_COMMIT_TIMEOUT_MS - 1u);
	const auto admitted = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(admitted.is_ok()) << admitted.error().message();
	const auto &emitted = admitted->pipeline().stages(2).active_stage_limits();
	EXPECT_EQ(emitted.async_work_capacity(), 4u);
	EXPECT_EQ(emitted.async_cancel_grace_ms(), TRANSITION_COMMIT_TIMEOUT_MS - 1u);
}

/**
 * @brief Verify every active stage/lane requires an explicit origin owner.
 */
TEST(gluon_port_bindings, missing_active_origin_binding_rejects)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	bindings.clear_active_origin_bindings();

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("requires one exact active-origin storage binding"), std::string::npos);
}

/**
 * @brief Verify a passive stage cannot claim packet-origination storage.
 */
TEST(gluon_port_bindings, passive_stage_active_origin_binding_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	auto *origin = bindings.add_active_origin_bindings();
	origin->set_logical_stage_id("rx");
	origin->set_lane_id("lane_0");
	origin->set_storage_domain_id("storage_host_0");

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("must not carry an active-origin binding"), std::string::npos);
}

/**
 * @brief Verify active-origin ownership cannot name an unmaterialized lane.
 */
TEST(gluon_port_bindings, active_origin_unknown_lane_rejects)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	ASSERT_EQ(bindings.active_origin_bindings_size(), 1);
	bindings.mutable_active_origin_bindings(0)->set_lane_id("lane_1");

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("references unknown lane"), std::string::npos);
}

/**
 * @brief Verify active-origin ownership cannot name an unknown logical stage.
 */
TEST(gluon_port_bindings, active_origin_unknown_logical_stage_rejects)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	ASSERT_EQ(bindings.active_origin_bindings_size(), 1);
	bindings.mutable_active_origin_bindings(0)->set_logical_stage_id("active_missing");

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("references unknown logical stage"), std::string::npos);
}

/**
 * @brief Verify active-origin ownership cannot name an unknown storage domain.
 */
TEST(gluon_port_bindings, active_origin_unknown_storage_domain_rejects)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	ASSERT_EQ(bindings.active_origin_bindings_size(), 1);
	bindings.mutable_active_origin_bindings(0)->set_storage_domain_id("storage_missing");

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("references unknown storage_domain_id"), std::string::npos);
}

/**
 * @brief Verify one active stage/lane cannot carry competing origin owners.
 */
TEST(gluon_port_bindings, duplicate_active_origin_binding_rejects)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	ASSERT_EQ(bindings.active_origin_bindings_size(), 1);
	bindings.add_active_origin_bindings()->CopyFrom(bindings.active_origin_bindings(0));

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("duplicate active-origin binding"), std::string::npos);
}

/**
 * @brief Verify multi-queue RX cannot omit exact RSS steering.
 */
TEST(gluon_port_bindings, multi_queue_rx_without_rss_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx, nullptr);
	set_queue_count(*rx, 2);
	set_queue_count(*tx, 2);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("requires exact RSS steering"), std::string::npos);
}

/**
 * @brief Verify every I/O direction declares the same explicit lane count.
 */
TEST(gluon_port_bindings, mismatched_direction_queue_counts_reject)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx, nullptr);
	set_queue_count(*tx, 2);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("same explicit queue count"), std::string::npos);
}

/**
 * @brief Verify an unused stream binding cannot enter executable topology.
 */
TEST(gluon_port_bindings, unused_stream_binding_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	auto *unused = bindings.add_io_stream_bindings();
	unused->set_logical_name("unused0");
	unused->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	unused->mutable_steering()->set_kind(kinetum::gluon::v1::TRAFFIC_STEERING_KIND_NONE);
	auto *queue = unused->add_queues();
	queue->set_rx_storage_domain_id("storage_host_0");
	queue->set_driver_queue_id(0);
	queue->set_descriptor_count(TEST_DESCRIPTOR_COUNT);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("unused by the pipeline"), std::string::npos);
}

/**
 * @brief Verify RSS requires nonempty hash fields and an exact key.
 */
TEST(gluon_port_bindings, incomplete_rss_contract_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx, nullptr);
	set_rss(*rx, 2);
	rx->mutable_steering()->clear_hash_fields();
	set_queue_count(*tx, 2);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("nonempty fields, and an exact key"), std::string::npos);
}

/**
 * @brief Verify fan-in queue cardinality is one shared RSS contract fact.
 */
TEST(gluon_port_bindings, fan_in_rss_queue_count_mismatch_rejects)
{
	const auto pipeline = make_two_rx_one_tx_pipeline("wan0", "wan1", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1", "0000:03:00.2"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan0_port", "0000:03:00.0", true},
						      {"wan1", "wan1_port", "0000:03:00.1", true},
						      {"lan0", "lan_port", "0000:03:00.2", true}});
	auto *rx0 = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *rx1 = find_stream_binding(bindings, "wan1", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx0, nullptr);
	ASSERT_NE(rx1, nullptr);
	set_rss(*rx0, 2);
	set_rss(*rx1, 3);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("same explicit queue count"), std::string::npos);
}

/**
 * @brief Different ingress RSS keys remain exact independent hardware facts.
 */
TEST(gluon_port_bindings, fan_in_rss_preserves_distinct_port_keys)
{
	const auto pipeline = make_two_rx_one_tx_pipeline("wan0", "wan1", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1", "0000:03:00.2"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan0_port", "0000:03:00.0", true},
						      {"wan1", "wan1_port", "0000:03:00.1", true},
						      {"lan0", "lan_port", "0000:03:00.2", true}});
	auto *rx0 = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *rx1 = find_stream_binding(bindings, "wan1", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx0, nullptr);
	ASSERT_NE(rx1, nullptr);
	set_rss(*rx0, 2, "rss-key-a");
	set_rss(*rx1, 2, "rss-key-b");
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx, nullptr);
	set_queue_count(*tx, 2);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_EQ(result->traffic_steering_profiles_size(), 2);
	EXPECT_EQ(result->traffic_steering_profiles(0).hash_key(), "rss-key-a");
	EXPECT_EQ(result->traffic_steering_profiles(1).hash_key(), "rss-key-b");
}

/**
 * @brief Verify missing DeploymentBindings never acquires provider defaults.
 */
TEST(gluon_port_bindings, missing_deployment_bindings_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	planner_options options;
	options.regions = 1;

	const auto result = plan(pipeline, hardware, options);
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("logical_port_bindings[]"), std::string::npos);
}

/**
 * @brief Verify logical-port bindings cover every pipeline interface exactly.
 */
TEST(gluon_port_bindings, missing_logical_interface_binding_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings()->DeleteSubrange(0, 1);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("cover every pipeline interface exactly once"), std::string::npos);
}

/**
 * @brief Verify duplicate logical names reject rather than normalize away.
 */
TEST(gluon_port_bindings, duplicate_logical_interface_binding_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings(1)->set_logical_name(bindings.logical_port_bindings(0).logical_name());

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("duplicate logical-port binding"), std::string::npos);
}

/**
 * @brief Verify a logical port cannot name an absent driver-local port.
 */
TEST(gluon_port_bindings, unknown_driver_port_reference_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings(0)->set_driver_port_id("missing_port");

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("unknown driver-local port"), std::string::npos);
}

/**
 * @brief Verify an empty logical name fails the shared identifier grammar.
 */
TEST(gluon_port_bindings, empty_logical_name_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings(0)->clear_logical_name();

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("not a valid topology identifier"), std::string::npos);
}

/**
 * @brief Verify the exact provider-identity length bound is admitted.
 */
TEST(gluon_port_bindings, provider_identity_at_exact_bound_is_admitted)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	const std::string identity = "e" + std::string(kinetum::provider::MAX_PROVIDER_ID_BYTES - 1u, 'x');
	bindings.mutable_execution_provider_instances(0)->set_execution_provider_instance_id(identity);
	for (auto &stage_binding : *bindings.mutable_stage_execution_bindings()) {
		stage_binding.set_execution_provider_instance_id(identity);
	}

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_EQ(result.value().execution_provider_instances(0).execution_provider_instance_id(), identity);
}

/**
 * @brief Verify a provider identity one byte beyond the exact bound rejects.
 */
TEST(gluon_port_bindings, provider_identity_beyond_exact_bound_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	const std::string identity = "e" + std::string(kinetum::provider::MAX_PROVIDER_ID_BYTES, 'x');
	bindings.mutable_execution_provider_instances(0)->set_execution_provider_instance_id(identity);
	for (auto &stage_binding : *bindings.mutable_stage_execution_bindings()) {
		stage_binding.set_execution_provider_instance_id(identity);
	}

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("128-byte identity bound"), std::string::npos);
}

/**
 * @brief Verify a configuration cannot cross its provider-role boundary.
 */
TEST(gluon_port_bindings, wrong_role_provider_configuration_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_io_driver_instances(0)->mutable_configuration()->CopyFrom(
		bindings.packet_storage_domains(0).configuration());

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("contract role does not match"), std::string::npos);
}

/**
 * @brief Verify whole-message scalar validation precedes catalog lookup.
 */
TEST(gluon_port_bindings, scalar_validation_precedes_provider_catalog_validation)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_io_driver_instances(0)->mutable_configuration()->CopyFrom(
		bindings.packet_storage_domains(0).configuration());
	bindings.mutable_logical_port_bindings(0)->set_mtu(0);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("invalid exact MTU"), std::string::npos);
}

/**
 * @brief Verify complete catalog validation precedes local-reference checks.
 */
TEST(gluon_port_bindings, provider_catalog_validation_precedes_local_reference_validation)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_io_driver_instances(0)->mutable_configuration()->CopyFrom(
		bindings.packet_storage_domains(0).configuration());
	bindings.mutable_logical_port_bindings(0)->set_io_driver_instance_id("io_missing");

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("contract role does not match"), std::string::npos);
}

/**
 * @brief Verify local-reference checks precede pipeline coverage.
 */
TEST(gluon_port_bindings, local_reference_validation_precedes_pipeline_coverage)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings(0)->set_io_driver_instance_id("io_missing");
	bindings.mutable_logical_port_bindings()->DeleteSubrange(1, 1);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("unknown io_driver_instance_id"), std::string::npos);
}

/**
 * @brief Verify pipeline coverage precedes physical hardware resolution.
 */
TEST(gluon_port_bindings, pipeline_coverage_precedes_hardware_resolution)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	bindings.mutable_logical_port_bindings()->DeleteSubrange(1, 1);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("must cover every pipeline interface"), std::string::npos);
}

/**
 * @brief Verify hardware resolution precedes logical transition resolution.
 */
TEST(gluon_port_bindings, hardware_resolution_precedes_transition_endpoint_resolution)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	kinetum::transition::core::v1::ZeroCopyShareConfig transition_config;
	auto *transition = bindings.add_storage_transition_bindings();
	transition->set_transition_id("bad_transition");
	transition->mutable_from_endpoint()->mutable_io()->set_logical_name("missing0");
	transition->mutable_from_endpoint()->mutable_io()->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	transition->mutable_to_endpoint()->mutable_stage()->set_logical_stage_id("rx");
	transition->mutable_to_endpoint()->mutable_stage()->set_lane_id("lane_0");
	transition->set_from_storage_domain_id(DPDK_STORAGE_ID);
	transition->set_to_storage_domain_id(DPDK_STORAGE_ID);
	transition->mutable_configuration()->PackFrom(transition_config);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("is absent from hardware inventory"), std::string::npos);
}

/**
 * @brief Verify an unspecified logical-port direction cannot become implicit.
 */
TEST(gluon_port_bindings, unspecified_logical_port_direction_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings(0)->set_direction(kinetum::gluon::v1::PORT_DIRECTION_UNSPECIFIED);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("has an unspecified direction"), std::string::npos);
}

/**
 * @brief Verify typed DPDK TAP attachments require no physical NIC record.
 */
TEST(gluon_port_bindings, typed_dpdk_tap_attachments_need_no_nic_inventory)
{
	const auto pipeline = make_rx_tx_pipeline("tap_rx", "tap_tx");
	const auto hardware = make_hw_inventory({});
	const auto bindings = make_dpdk_bindings(pipeline, {{"tap_rx", "rx_port", "kin_rx", false},
							    {"tap_tx", "tx_port", "kin_tx", false}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_EQ(result.value().ports_size(), 2);
	for (const auto &port : result.value().ports()) {
		EXPECT_FALSE(port.has_host_numa_node());
		EXPECT_TRUE(port.resolved_mac_address().empty());
		EXPECT_EQ(port.io_driver_instance_id(), DPDK_DRIVER_ID);
	}
}

/**
 * @brief Verify a TAP binding cannot invent NUMA ownership absent typed truth.
 */
TEST(gluon_port_bindings, typed_dpdk_tap_attachment_rejects_unproven_numa_constraint)
{
	const auto pipeline = make_rx_tx_pipeline("tap_rx", "tap_tx");
	const auto hardware = make_hw_inventory({});
	auto bindings = make_dpdk_bindings(pipeline, {{"tap_rx", "rx_port", "kin_rx", false},
						      {"tap_tx", "tx_port", "kin_tx", false}});
	bindings.mutable_logical_port_bindings(0)->set_host_numa_node(0);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("typed attachment supplies no NUMA fact"), std::string::npos);
}

/**
 * @brief Verify a UDP binding cannot invent NUMA ownership absent typed truth.
 */
TEST(gluon_port_bindings, typed_udp_attachment_rejects_unproven_numa_constraint)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings(0)->set_host_numa_node(0);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("typed attachment supplies no NUMA fact"), std::string::npos);
}

/**
 * @brief Verify PCI attachment identity is resolved only through typed config.
 */
TEST(gluon_port_bindings, typed_pci_attachment_resolves_inventory_facts)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	const auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
							    {"lan0", "lan_port", "0000:03:00.1", true}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto *wan = find_port(result.value(), "wan0");
	ASSERT_NE(wan, nullptr);
	EXPECT_EQ(wan->driver_port_id(), "wan_port");
	EXPECT_EQ(wan->resolved_mac_address(), test_mac_bytes(0));
}

/** @brief Every compact hardware NIC fact is validated before plan publication. */
TEST(gluon_port_bindings, malformed_compact_hardware_nic_rows_reject)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
							    {"lan0", "lan_port", "0000:03:00.1", true}});
	const auto make_hardware = [] { return make_hw_inventory({"0000:03:00.0", "0000:03:00.1"}); };

	auto hardware = make_hardware();
	hardware.mutable_node()->mutable_nics(0)->clear_pci_address();
	const auto missing_pci_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(missing_pci_result.is_ok());
	EXPECT_NE(missing_pci_result.error().message().find("hardware NIC rows require"), std::string::npos);

	hardware = make_hardware();
	hardware.mutable_node()->mutable_nics(0)->set_driver(kinetum::hw::v1::NIC_DRIVER_UNSPECIFIED);
	const auto unspecified_driver_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(unspecified_driver_result.is_ok());
	EXPECT_NE(unspecified_driver_result.error().message().find("hardware NIC rows require"), std::string::npos);

	hardware = make_hardware();
	hardware.mutable_node()->mutable_nics(0)->set_max_mtu(0u);
	const auto zero_mtu_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(zero_mtu_result.is_ok());
	EXPECT_NE(zero_mtu_result.error().message().find("hardware NIC rows require"), std::string::npos);

	hardware = make_hardware();
	hardware.mutable_node()->mutable_nics(0)->set_numa_node(-1);
	const auto negative_numa_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(negative_numa_result.is_ok());
	EXPECT_NE(negative_numa_result.error().message().find("hardware NIC rows require"), std::string::npos);

	hardware = make_hardware();
	hardware.mutable_node()->mutable_nics(1)->set_pci_address("0000:03:00.0");
	const auto duplicate_pci_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(duplicate_pci_result.is_ok());
	EXPECT_NE(duplicate_pci_result.error().message().find("duplicate PCI identity"), std::string::npos);

	hardware = make_hardware();
	hardware.mutable_node()->mutable_nics(0)->set_pci_address("0000:03:00.A");
	const auto noncanonical_pci_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(noncanonical_pci_result.is_ok());
	EXPECT_NE(noncanonical_pci_result.error().message().find("lowercase"), std::string::npos);

	hardware = make_hardware();
	hardware.mutable_node()->mutable_nics(0)->set_mac_address("not-a-mac");
	const auto malformed_mac_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(malformed_mac_result.is_ok());
	EXPECT_NE(malformed_mac_result.error().message().find("hardware MAC is malformed"), std::string::npos);

	hardware = make_hardware();
	auto *unused = hardware.mutable_node()->add_nics();
	unused->CopyFrom(hardware.node().nics(0));
	unused->set_pci_address("0000:03:00.2");
	unused->set_mac_address("not-a-mac");
	const auto unused_malformed_mac_result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(unused_malformed_mac_result.is_ok());
	EXPECT_NE(unused_malformed_mac_result.error().message().find("hardware MAC is malformed"), std::string::npos);
}

/**
 * @brief Verify canonical DPDK PCI configuration remains the sole attachment.
 */
TEST(gluon_port_bindings, pci_attachment_remains_in_typed_driver_configuration)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	const auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "z_wan", "0000:03:00.0", true},
							    {"lan0", "a_lan", "0000:03:00.1", true}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	kinetum::io::dpdk::v1::DpdkDriverConfig configuration;
	ASSERT_TRUE(result.value().io_driver_instances(0).configuration().UnpackTo(&configuration));
	ASSERT_EQ(configuration.ports_size(), 2);
	EXPECT_EQ(configuration.ports(0).driver_port_id(), "a_lan");
	EXPECT_EQ(configuration.ports(0).pci().pci_address(), "0000:03:00.1");
	EXPECT_EQ(configuration.ports(1).driver_port_id(), "z_wan");
	EXPECT_EQ(configuration.ports(1).pci().pci_address(), "0000:03:00.0");
}

/**
 * @brief Verify canonical TAP configuration carries only typed interface names.
 */
TEST(gluon_port_bindings, tap_attachment_remains_in_typed_driver_configuration)
{
	const auto pipeline = make_rx_tx_pipeline("tap_rx", "tap_tx");
	const auto hardware = make_hw_inventory({});
	const auto bindings = make_dpdk_bindings(pipeline, {{"tap_rx", "z_rx", "kin_rx", false},
							    {"tap_tx", "a_tx", "kin_tx", false}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	kinetum::io::dpdk::v1::DpdkDriverConfig configuration;
	ASSERT_TRUE(result.value().io_driver_instances(0).configuration().UnpackTo(&configuration));
	ASSERT_EQ(configuration.ports_size(), 2);
	EXPECT_EQ(configuration.ports(0).driver_port_id(), "a_tx");
	EXPECT_EQ(configuration.ports(0).tap().interface_name(), "kin_tx");
	EXPECT_EQ(configuration.ports(1).driver_port_id(), "z_rx");
	EXPECT_EQ(configuration.ports(1).tap().interface_name(), "kin_rx");
}

/**
 * @brief Verify TAP token-boundary injection is rejected by the catalog.
 */
TEST(gluon_port_bindings, invalid_tap_attachment_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("tap_rx", "tap_tx");
	const auto hardware = make_hw_inventory({});
	const auto bindings = make_dpdk_bindings(pipeline, {{"tap_rx", "rx_port", "kin,rx", false},
							    {"tap_tx", "tx_port", "kin_tx", false}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("TAP interface_name"), std::string::npos);
}

/**
 * @brief Verify noncanonical PCI spelling is rejected rather than normalized.
 */
TEST(gluon_port_bindings, noncanonical_pci_attachment_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	const auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
							    {"lan0", "lan_port", "0000:03:00.A", true}});

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("lowercase"), std::string::npos);
}

/**
 * @brief Verify one driver-local port cannot bind two logical ports.
 */
TEST(gluon_port_bindings, duplicate_driver_port_claim_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_logical_port_bindings(1)->set_driver_port_id(
		bindings.logical_port_bindings(0).driver_port_id());

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("bound to more than one logical port"), std::string::npos);
}

/**
 * @brief Verify authored set permutations normalize to one plan identity.
 */
TEST(gluon_port_bindings, authoring_order_permutations_emit_one_plan_identity)
{
	const auto pipeline = make_rx_tx_pipeline("z_last", "a_first");
	const auto hardware = make_hw_inventory({});
	auto first = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
								      TEST_EPOCH_ARENA_CAPACITY_BYTES);
	auto second = first;
	second.mutable_logical_port_bindings()->SwapElements(0, 1);
	second.mutable_io_stream_bindings()->SwapElements(0, 1);
	second.mutable_stage_execution_bindings()->SwapElements(0, 1);

	const auto first_result = plan(pipeline, hardware, make_options(first));
	const auto second_result = plan(pipeline, hardware, make_options(second));
	ASSERT_TRUE(first_result.is_ok()) << first_result.error().message();
	ASSERT_TRUE(second_result.is_ok()) << second_result.error().message();
	EXPECT_EQ(first_result.value().content_hash(), second_result.value().content_hash());
	auto first_plan = first_result.value();
	auto second_plan = second_result.value();
	first_plan.mutable_metadata()->clear_planned_unix_ms();
	first_plan.mutable_metadata()->clear_planning_duration_ms();
	second_plan.mutable_metadata()->clear_planned_unix_ms();
	second_plan.mutable_metadata()->clear_planning_duration_ms();
	EXPECT_EQ(first_plan.SerializeAsString(), second_plan.SerializeAsString());
	const auto *a_first = find_port(first_result.value(), "a_first");
	const auto *z_last = find_port(first_result.value(), "z_last");
	ASSERT_NE(a_first, nullptr);
	ASSERT_NE(z_last, nullptr);
	EXPECT_LT(a_first->logical_port_id(), z_last->logical_port_id());
}

/** @brief Verify active-origin authoring order is a normalized set. */
TEST(gluon_port_bindings, active_origin_order_permutations_emit_one_plan_identity)
{
	auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	pipeline.mutable_edges(1)->set_to_stage_id("active1");
	auto *active = pipeline.add_stages();
	active->set_stage_id("active1");
	active->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
	active->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_ACTIVE);
	active->set_trigger_mask(static_cast<uint32_t>(kinetum::axiom::v1::TRIGGER_MODE_LOOP));
	active->mutable_module()->set_module_id("kinetum.test_active");
	active->mutable_module()->set_context_selection(kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	auto *edge = pipeline.add_edges();
	edge->set_from_stage_id("active1");
	edge->set_to_stage_id("tx");
	edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);

	const auto hardware = make_hw_inventory({});
	auto first = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
								      TEST_EPOCH_ARENA_CAPACITY_BYTES);
	ASSERT_EQ(first.active_origin_bindings_size(), 2);
	auto second = first;
	second.mutable_active_origin_bindings()->SwapElements(0, 1);

	const auto first_result = plan(pipeline, hardware, make_options(first));
	const auto second_result = plan(pipeline, hardware, make_options(second));
	ASSERT_TRUE(first_result.is_ok()) << first_result.error().message();
	ASSERT_TRUE(second_result.is_ok()) << second_result.error().message();
	EXPECT_EQ(first_result.value().content_hash(), second_result.value().content_hash());
}

/**
 * @brief Verify an unused logical-port binding cannot disappear in lowering.
 */
TEST(gluon_port_bindings, unused_logical_port_binding_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	// Give the extra binding a real unique driver-local endpoint so scalar and
	// local-reference validation pass and exact pipeline coverage rejects first.
	kinetum::io::udp::v1::UdpDriverConfig driver_configuration;
	ASSERT_TRUE(bindings.io_driver_instances(0).configuration().UnpackTo(&driver_configuration));
	auto *driver_port = driver_configuration.add_ports();
	driver_port->set_driver_port_id("mgmt0");
	driver_port->set_ipv4_address("127.0.0.1");
	driver_port->set_port(20'002);
	bindings.mutable_io_driver_instances(0)->mutable_configuration()->PackFrom(driver_configuration);

	auto *extra = bindings.add_logical_port_bindings();
	extra->set_logical_name("mgmt0");
	extra->set_io_driver_instance_id("io_udp_0");
	extra->set_driver_port_id("mgmt0");
	extra->set_direction(kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY);
	extra->set_mtu(1500);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("cover every pipeline interface exactly once"), std::string::npos);
}

/**
 * @brief Verify duplicate I/O stages cannot claim one explicit queue binding.
 */
TEST(gluon_port_bindings, duplicate_io_stage_queue_claim_rejects)
{
	auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	pipeline.set_allow_dag(true);
	auto *duplicate_rx = pipeline.add_stages();
	duplicate_rx->set_stage_id("rx_alt");
	duplicate_rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	duplicate_rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	duplicate_rx->mutable_io()->set_interface("wan0");
	auto *duplicate_edge = pipeline.add_edges();
	duplicate_edge->set_from_stage_id("rx_alt");
	duplicate_edge->set_to_stage_id("tx");
	duplicate_edge->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	const auto hardware = make_hw_inventory({});
	const auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("multiple I/O stages claim one logical port/direction binding"),
		  std::string::npos);
}

/**
 * @brief Verify duplicate explicit queue IDs reject before topology emission.
 */
TEST(gluon_port_bindings, duplicate_driver_queue_id_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	ASSERT_NE(rx, nullptr);
	auto *duplicate = rx->add_queues();
	duplicate->CopyFrom(rx->queues(0));
	duplicate->set_driver_queue_id(0);
	duplicate->set_descriptor_count(TEST_DESCRIPTOR_COUNT);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("duplicate driver_queue_id"), std::string::npos);
}

/**
 * @brief Verify stage-execution coverage is exact in both directions.
 */
TEST(gluon_port_bindings, missing_stage_execution_binding_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_stage_execution_bindings()->DeleteSubrange(0, 1);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("cover every logical pipeline stage exactly once"), std::string::npos);
}

/**
 * @brief Verify duplicate stage-execution ownership rejects.
 */
TEST(gluon_port_bindings, duplicate_stage_execution_binding_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.mutable_stage_execution_bindings(1)->set_logical_stage_id(
		bindings.stage_execution_bindings(0).logical_stage_id());

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("duplicate stage-execution binding"), std::string::npos);
}

/** @brief Verify explicit module lifecycle-memory intent lowers byte-exactly. */
TEST(gluon_port_bindings, module_context_resource_binding_lowers_exact_capacities)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	const auto bindings = kinetum::test::make_udp_test_deployment_bindings(
		pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES, TEST_EPOCH_ARENA_CAPACITY_BYTES);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	const auto module = std::find_if(result.value().stage_instances().begin(),
					 result.value().stage_instances().end(),
					 [](const auto &stage) { return stage.logical_stage_id() == "active0"; });
	ASSERT_NE(module, result.value().stage_instances().end());
	EXPECT_EQ(module->context_memory_capacity_bytes(), TEST_CONTEXT_MEMORY_CAPACITY_BYTES);
	EXPECT_EQ(module->epoch_arena_capacity_bytes(), TEST_EPOCH_ARENA_CAPACITY_BYTES);
	for (const auto &stage : result.value().stage_instances()) {
		if (stage.logical_stage_id() != "active0") {
			EXPECT_EQ(stage.context_memory_capacity_bytes(), 0u);
			EXPECT_EQ(stage.epoch_arena_capacity_bytes(), 0u);
		}
	}
}

/** @brief Verify absent or zero module resource authoring never selects a default. */
TEST(gluon_port_bindings, missing_or_zero_module_context_resource_binding_rejects)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	ASSERT_EQ(bindings.module_context_resource_bindings_size(), 0);
	const auto missing = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(missing.is_ok());
	EXPECT_NE(missing.error().message().find("requires one exact module-context resource binding"),
		  std::string::npos);

	bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	kinetum::test::add_module_context_resource_binding(bindings, "active0", "lane_0", 0,
							   TEST_EPOCH_ARENA_CAPACITY_BYTES);
	const auto zero_context = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(zero_context.is_ok());
	EXPECT_NE(zero_context.error().message().find("requires nonzero context and epoch capacities"),
		  std::string::npos);

	bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	kinetum::test::add_module_context_resource_binding(bindings, "active0", "lane_0",
							   TEST_CONTEXT_MEMORY_CAPACITY_BYTES, 0);
	const auto zero_epoch = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(zero_epoch.is_ok());
	EXPECT_NE(zero_epoch.error().message().find("requires nonzero context and epoch capacities"),
		  std::string::npos);
}

/** @brief Verify duplicate or platform-stage resource claims reject before lowering. */
TEST(gluon_port_bindings, duplicate_or_platform_module_context_resource_binding_rejects)
{
	const auto pipeline = make_rx_active_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
									 TEST_EPOCH_ARENA_CAPACITY_BYTES);
	ASSERT_EQ(bindings.module_context_resource_bindings_size(), 1);
	bindings.add_module_context_resource_bindings()->CopyFrom(bindings.module_context_resource_bindings(0));
	const auto duplicate = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(duplicate.is_ok());
	EXPECT_NE(duplicate.error().message().find("duplicate module-context resource binding"), std::string::npos);

	bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline, TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
								    TEST_EPOCH_ARENA_CAPACITY_BYTES);
	kinetum::test::add_module_context_resource_binding(bindings, "rx", "lane_0", TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
							   TEST_EPOCH_ARENA_CAPACITY_BYTES);
	const auto platform = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(platform.is_ok());
	EXPECT_NE(platform.error().message().find("must not carry a module-context resource binding"),
		  std::string::npos);
}

/**
 * @brief Verify one real cross-domain transition resolves to exact final endpoints.
 */
TEST(gluon_port_bindings, logical_storage_transition_lowers_exact_endpoints)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);

	kinetum::storage::host::v1::HostStorageConfig storage_config;
	auto *destination_storage = bindings.add_packet_storage_domains();
	destination_storage->set_storage_domain_id("storage_host_1");
	destination_storage->mutable_configuration()->PackFrom(storage_config);
	destination_storage->set_buffer_count(131'071);
	destination_storage->set_data_room_bytes(2048);
	destination_storage->set_headroom_bytes(128);
	destination_storage->set_alignment_bytes(64);
	destination_storage->set_host_numa_node(0);
	auto *tx_stream = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(tx_stream, nullptr);
	tx_stream->mutable_queues(0)->mutable_tx_storage()->set_storage_domain_ids(0, "storage_host_1");

	kinetum::transition::cpu::v1::BoundedCopyConfig transition_config;
	auto *transition = bindings.add_storage_transition_bindings();
	transition->set_transition_id("rx_to_tx_copy");
	transition->mutable_from_endpoint()->mutable_stage()->set_logical_stage_id("rx");
	transition->mutable_from_endpoint()->mutable_stage()->set_lane_id("lane_0");
	transition->mutable_to_endpoint()->mutable_stage()->set_logical_stage_id("tx");
	transition->mutable_to_endpoint()->mutable_stage()->set_lane_id("lane_0");
	transition->set_from_storage_domain_id("storage_host_0");
	transition->set_to_storage_domain_id("storage_host_1");
	transition->mutable_configuration()->PackFrom(transition_config);
	transition->set_staging_capacity(1024);
	transition->set_staging_numa_node(0);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	ASSERT_EQ(result.value().storage_transitions_size(), 1);
	const auto &lowered = result.value().storage_transitions(0);
	EXPECT_EQ(lowered.transition_id(), "rx_to_tx_copy");
	ASSERT_EQ(lowered.from_endpoint().endpoint_case(), kinetum::gluon::v1::PacketPathEndpoint::kStageInstanceId);
	ASSERT_EQ(lowered.to_endpoint().endpoint_case(), kinetum::gluon::v1::PacketPathEndpoint::kStageInstanceId);
	EXPECT_EQ(lowered.from_endpoint().stage_instance_id(), "rx@lane_0");
	EXPECT_EQ(lowered.to_endpoint().stage_instance_id(), "tx@lane_0");
	EXPECT_EQ(lowered.from_storage_domain_id(), "storage_host_0");
	EXPECT_EQ(lowered.to_storage_domain_id(), "storage_host_1");
	EXPECT_EQ(lowered.staging_capacity(), 1024u);
	EXPECT_EQ(lowered.staging_numa_node(), 0);
	EXPECT_EQ(lowered.configuration().type_url(), kinetum::provider::BOUNDED_COPY_TYPE_URL);
}

/**
 * @brief Verify an unknown logical transition endpoint fails before emission.
 */
TEST(gluon_port_bindings, unknown_storage_transition_endpoint_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	kinetum::transition::core::v1::ZeroCopyShareConfig transition_config;
	auto *transition = bindings.add_storage_transition_bindings();
	transition->set_transition_id("bad_transition");
	transition->mutable_from_endpoint()->mutable_io()->set_logical_name("missing0");
	transition->mutable_from_endpoint()->mutable_io()->set_direction(kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	transition->mutable_to_endpoint()->mutable_stage()->set_logical_stage_id("rx");
	transition->mutable_to_endpoint()->mutable_stage()->set_lane_id("lane_0");
	transition->set_from_storage_domain_id("storage_host_0");
	transition->set_to_storage_domain_id("storage_host_0");
	transition->mutable_configuration()->PackFrom(transition_config);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("unknown I/O stream"), std::string::npos);
}

/**
 * @brief Verify recursive unknown authoring fields reject at ladder entry.
 */
TEST(gluon_port_bindings, unknown_deployment_binding_field_rejects)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({});
	auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	bindings.GetReflection()->MutableUnknownFields(&bindings)->AddVarint(99, 1);

	const auto result = plan(pipeline, hardware, make_options(bindings));
	ASSERT_FALSE(result.is_ok());
	EXPECT_NE(result.error().message().find("unknown protobuf field"), std::string::npos);
}

/** @brief Verify binding lowering rejects malformed hardware before plan mutation. */
TEST(gluon_port_bindings, malformed_hardware_wire_rejects_before_binding_lowering)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	auto hardware = make_hw_inventory({});
	const auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	kinetum::gluon::v1::DeploymentPlan candidate;
	candidate.mutable_pipeline()->CopyFrom(pipeline);
	const std::string original = candidate.SerializeAsString();
	hardware.GetReflection()->MutableUnknownFields(&hardware)->AddVarint(99, 1u);

	const auto unknown_field_status = lower_deployment_bindings(bindings, hardware, candidate);
	EXPECT_FALSE(unknown_field_status.is_ok());
	EXPECT_NE(unknown_field_status.message().find("unknown protobuf field"), std::string::npos);
	EXPECT_EQ(candidate.SerializeAsString(), original);

	hardware = make_hw_inventory({});
	hardware.mutable_node()->add_nics()->set_driver(static_cast<kinetum::hw::v1::NicDriver>(99));
	const auto invalid_enum_status = lower_deployment_bindings(bindings, hardware, candidate);
	EXPECT_FALSE(invalid_enum_status.is_ok());
	EXPECT_NE(invalid_enum_status.message().find("unknown enum number"), std::string::npos);
	EXPECT_EQ(candidate.SerializeAsString(), original);
}

/**
 * @brief Verify an exact authored RSS key is stable and never entropy-filled.
 */
TEST(gluon_port_bindings, authored_rss_key_is_byte_exact_and_identity_stable)
{
	const auto pipeline = make_rx_tx_pipeline("wan0", "lan0");
	const auto hardware = make_hw_inventory({"0000:03:00.0", "0000:03:00.1"});
	auto bindings = make_dpdk_bindings(pipeline, {{"wan0", "wan_port", "0000:03:00.0", true},
						      {"lan0", "lan_port", "0000:03:00.1", true}});
	auto *rx = find_stream_binding(bindings, "wan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	auto *tx = find_stream_binding(bindings, "lan0", kinetum::gluon::v1::IO_STREAM_DIRECTION_TX);
	ASSERT_NE(rx, nullptr);
	ASSERT_NE(tx, nullptr);
	const std::string exact_key{"\x6b\x69\x6e\x65\x74\x75\x6d\x00\x72\x73\x73", 11};
	set_rss(*rx, 2, exact_key);
	set_queue_count(*tx, 2);

	const auto first = plan(pipeline, hardware, make_options(bindings));
	const auto second = plan(pipeline, hardware, make_options(bindings));
	ASSERT_TRUE(first.is_ok()) << first.error().message();
	ASSERT_TRUE(second.is_ok()) << second.error().message();
	ASSERT_EQ(first.value().traffic_steering_profiles_size(), 1);
	EXPECT_EQ(first.value().traffic_steering_profiles(0).hash_key(), exact_key);
	EXPECT_EQ(first.value().content_hash(), second.value().content_hash());
}

}  // namespace
}  // namespace kinetum::gluon
