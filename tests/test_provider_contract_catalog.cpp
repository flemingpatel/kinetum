// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_contract_catalog.cpp
 * @brief Tests for strict typed provider contracts and canonical catalog rows.
 * @author Fleming Patel
 *
 * The suites pin exact schema identity, the ten-step reject ladder, declared
 * set normalization, spelling rejection, empty-contract rigor, capability and
 * facility projections, bounded diagnostics, map/nested-Any absence, and the
 * closed current access and storage-transition vocabularies.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include <google/protobuf/any.pb.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include <google/protobuf/unknown_field_set.h>

#include "gen/kinetum/execution/cpu/v1/cpu_execution.pb.h"
#include "gen/kinetum/facility/dpdk/v1/dpdk_facility.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "gen/kinetum/io/dpdk/v1/dpdk_driver.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "gen/kinetum/storage/dpdk/v1/dpdk_storage.pb.h"
#include "gen/kinetum/storage/host/v1/host_storage.pb.h"
#include "gen/kinetum/transition/core/v1/core_transition.pb.h"
#include "gen/kinetum/transition/cpu/v1/cpu_transition.pb.h"
#include "src/common/protobuf_contract.hpp"
#include "src/provider/provider_contract_catalog.hpp"

namespace kinetum::provider
{

namespace
{

using common::status;
using common::status_code;
using google::protobuf::Any;
using google::protobuf::Descriptor;

/**
 * @brief Serialize one generated message under a caller-selected exact URL.
 *
 * @tparam message_type Generated protobuf message type.
 * @param type_url Exact Any type URL to write.
 * @param message Message whose current bytes become the payload.
 * @return Populated Any suitable for catalog admission tests.
 */
template <typename message_type>
Any make_any(std::string_view type_url, const message_type &message)
{
	Any value;
	value.set_type_url(type_url.data(), type_url.size());
	EXPECT_TRUE(message.SerializeToString(value.mutable_value()));
	return value;
}

/**
 * @brief Construct one valid DPDK driver configuration with a PCI attachment.
 *
 * @param driver_port_id Stable provider-local port identity.
 * @param pci_address Exact canonical PCI BDF.
 * @return Valid generated DPDK driver message.
 */
kinetum::io::dpdk::v1::DpdkDriverConfig make_dpdk_pci_config(std::string_view driver_port_id,
							     std::string_view pci_address)
{
	kinetum::io::dpdk::v1::DpdkDriverConfig configuration;
	auto *port = configuration.add_ports();
	port->set_driver_port_id(driver_port_id.data(), driver_port_id.size());
	port->mutable_pci()->set_pci_address(pci_address.data(), pci_address.size());
	return configuration;
}

/**
 * @brief Construct one valid UDP driver configuration.
 *
 * @param driver_port_id Stable provider-local port identity.
 * @param ipv4_address Exact canonical numeric IPv4 address.
 * @param port UDP port represented without narrowing.
 * @return Valid generated UDP driver message.
 */
kinetum::io::udp::v1::UdpDriverConfig make_udp_config(std::string_view driver_port_id, std::string_view ipv4_address,
						      uint32_t port)
{
	kinetum::io::udp::v1::UdpDriverConfig configuration;
	auto *endpoint = configuration.add_ports();
	endpoint->set_driver_port_id(driver_port_id.data(), driver_port_id.size());
	endpoint->set_ipv4_address(ipv4_address.data(), ipv4_address.size());
	endpoint->set_port(port);
	return configuration;
}

/**
 * @brief Require one status to identify the exact first failed ladder step.
 *
 * @param result Failure status under test.
 * @param step Expected canonicalization step.
 */
void expect_step(const status &result, provider_configuration_step step)
{
	ASSERT_FALSE(result.is_ok());
	const std::string marker = "step " + std::to_string(static_cast<uint8_t>(step)) + " (" +
				   std::string(provider_configuration_step_name(step)) + ")";
	EXPECT_NE(result.message().find(marker), std::string::npos) << result.message();
}

/**
 * @brief Prove one generated graph contains no map or nested dynamic envelope.
 *
 * @param root Root descriptor to traverse.
 */
void expect_closed_concrete_contract_graph(const Descriptor *root)
{
	ASSERT_NE(root, nullptr);
	std::vector<const Descriptor *> pending{root};
	std::set<const Descriptor *> visited;
	while (!pending.empty()) {
		const Descriptor *descriptor = pending.back();
		pending.pop_back();
		if (!visited.insert(descriptor).second) {
			continue;
		}
		for (int index = 0; index < descriptor->field_count(); ++index) {
			const auto *field = descriptor->field(index);
			EXPECT_FALSE(field->is_map()) << descriptor->full_name() << "." << field->name();
			if (field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE) {
				EXPECT_NE(field->message_type()->full_name(), "google.protobuf.Any")
					<< descriptor->full_name() << "." << field->name();
				pending.push_back(field->message_type());
			}
		}
	}
}

/**
 * @brief Return whether one compact agent mask contains a selected agent.
 *
 * @param mask Compact access-agent set.
 * @param agent Candidate set member.
 * @return true only when the corresponding bit is present.
 */
constexpr bool has_agent(packet_access_agent_mask mask, packet_access_agent agent) noexcept
{
	return (mask & access_agent_bit(agent)) != 0u;
}

}  // namespace

/** @brief Pin the exact eight URLs, roles, generated names, and lexical order. */
TEST(provider_contract_schema, exact_rows_match_generated_contract_identity)
{
	struct expected_row {
		std::string_view type_url;
		std::string_view full_name;
		provider_contract_role role;
	};
	constexpr std::array<expected_row, 8> EXPECTED{
		expected_row{CPU_EXECUTION_TYPE_URL, "kinetum.execution.cpu.v1.CpuExecutionConfig",
			     provider_contract_role::EXECUTION},
		expected_row{DPDK_FACILITY_TYPE_URL, "kinetum.facility.dpdk.v1.DpdkFacilityConfig",
			     provider_contract_role::PROCESS_FACILITY},
		expected_row{DPDK_DRIVER_TYPE_URL, "kinetum.io.dpdk.v1.DpdkDriverConfig",
			     provider_contract_role::IO_DRIVER},
		expected_row{UDP_DRIVER_TYPE_URL, "kinetum.io.udp.v1.UdpDriverConfig",
			     provider_contract_role::IO_DRIVER},
		expected_row{DPDK_STORAGE_TYPE_URL, "kinetum.storage.dpdk.v1.DpdkStorageConfig",
			     provider_contract_role::PACKET_STORAGE},
		expected_row{HOST_STORAGE_TYPE_URL, "kinetum.storage.host.v1.HostStorageConfig",
			     provider_contract_role::PACKET_STORAGE},
		expected_row{ZERO_COPY_SHARE_TYPE_URL, "kinetum.transition.core.v1.ZeroCopyShareConfig",
			     provider_contract_role::STORAGE_TRANSITION},
		expected_row{BOUNDED_COPY_TYPE_URL, "kinetum.transition.cpu.v1.BoundedCopyConfig",
			     provider_contract_role::STORAGE_TRANSITION},
	};

	ASSERT_EQ(provider_contract_count(), EXPECTED.size());
	for (std::size_t index = 0; index < EXPECTED.size(); ++index) {
		const auto *row = provider_contract_at(index);
		ASSERT_NE(row, nullptr);
		EXPECT_EQ(row->type_url, EXPECTED[index].type_url);
		EXPECT_EQ(row->role, EXPECTED[index].role);
		const auto *descriptor = provider_configuration_message_descriptor(row->type_url);
		ASSERT_NE(descriptor, nullptr);
		EXPECT_EQ(descriptor->full_name(), EXPECTED[index].full_name);
		EXPECT_EQ(row->type_url, std::string(PROVIDER_TYPE_URL_PREFIX) + descriptor->full_name());
		if (index != 0) {
			ASSERT_NE(provider_contract_at(index - 1), nullptr);
			EXPECT_LT(provider_contract_at(index - 1)->type_url, row->type_url);
		}
	}
	EXPECT_EQ(provider_contract_at(EXPECTED.size()), nullptr);
	EXPECT_EQ(find_provider_contract("DpdkDriverConfig"), nullptr);
	EXPECT_EQ(provider_configuration_message_descriptor("DpdkDriverConfig"), nullptr);
}

/** @brief Pin compact field numbers and the deliberately empty contracts. */
TEST(provider_contract_schema, message_fields_are_compact_and_deliberate)
{
	EXPECT_EQ(kinetum::facility::dpdk::v1::DpdkFacilityConfig::descriptor()->field_count(), 0);
	EXPECT_EQ(kinetum::storage::host::v1::HostStorageConfig::descriptor()->field_count(), 0);
	EXPECT_EQ(kinetum::execution::cpu::v1::CpuExecutionConfig::descriptor()->field_count(), 0);
	EXPECT_EQ(kinetum::transition::core::v1::ZeroCopyShareConfig::descriptor()->field_count(), 0);
	EXPECT_EQ(kinetum::transition::cpu::v1::BoundedCopyConfig::descriptor()->field_count(), 0);

	const auto *dpdk_driver = kinetum::io::dpdk::v1::DpdkDriverConfig::descriptor();
	ASSERT_EQ(dpdk_driver->field_count(), 1);
	EXPECT_EQ(dpdk_driver->field(0)->name(), "ports");
	EXPECT_EQ(dpdk_driver->field(0)->number(), 1);
	EXPECT_EQ(dpdk_driver->field(0)->type(), google::protobuf::FieldDescriptor::TYPE_MESSAGE);
	EXPECT_EQ(dpdk_driver->field(0)->message_type(), kinetum::io::dpdk::v1::DpdkDriverPort::descriptor());
	EXPECT_TRUE(dpdk_driver->field(0)->is_repeated());

	const auto *dpdk_port = kinetum::io::dpdk::v1::DpdkDriverPort::descriptor();
	ASSERT_EQ(dpdk_port->field_count(), 3);
	const auto *driver_port_id = dpdk_port->FindFieldByName("driver_port_id");
	const auto *pci = dpdk_port->FindFieldByName("pci");
	const auto *tap = dpdk_port->FindFieldByName("tap");
	ASSERT_NE(driver_port_id, nullptr);
	ASSERT_NE(pci, nullptr);
	ASSERT_NE(tap, nullptr);
	EXPECT_EQ(driver_port_id->number(), 1);
	EXPECT_EQ(driver_port_id->type(), google::protobuf::FieldDescriptor::TYPE_STRING);
	EXPECT_EQ(pci->number(), 2);
	EXPECT_EQ(pci->type(), google::protobuf::FieldDescriptor::TYPE_MESSAGE);
	EXPECT_EQ(pci->message_type(), kinetum::io::dpdk::v1::PciAttachment::descriptor());
	EXPECT_EQ(tap->number(), 3);
	EXPECT_EQ(tap->type(), google::protobuf::FieldDescriptor::TYPE_MESSAGE);
	EXPECT_EQ(tap->message_type(), kinetum::io::dpdk::v1::TapAttachment::descriptor());
	ASSERT_EQ(dpdk_port->oneof_decl_count(), 1);
	EXPECT_EQ(dpdk_port->oneof_decl(0)->name(), "attachment");
	EXPECT_EQ(driver_port_id->containing_oneof(), nullptr);
	EXPECT_EQ(pci->containing_oneof(), dpdk_port->oneof_decl(0));
	EXPECT_EQ(tap->containing_oneof(), dpdk_port->oneof_decl(0));

	const auto *pci_attachment = kinetum::io::dpdk::v1::PciAttachment::descriptor();
	ASSERT_EQ(pci_attachment->field_count(), 1);
	EXPECT_EQ(pci_attachment->field(0)->name(), "pci_address");
	EXPECT_EQ(pci_attachment->field(0)->number(), 1);
	EXPECT_EQ(pci_attachment->field(0)->type(), google::protobuf::FieldDescriptor::TYPE_STRING);

	const auto *tap_attachment = kinetum::io::dpdk::v1::TapAttachment::descriptor();
	ASSERT_EQ(tap_attachment->field_count(), 1);
	EXPECT_EQ(tap_attachment->field(0)->name(), "interface_name");
	EXPECT_EQ(tap_attachment->field(0)->number(), 1);
	EXPECT_EQ(tap_attachment->field(0)->type(), google::protobuf::FieldDescriptor::TYPE_STRING);

	const auto *udp_driver = kinetum::io::udp::v1::UdpDriverConfig::descriptor();
	ASSERT_EQ(udp_driver->field_count(), 1);
	EXPECT_EQ(udp_driver->field(0)->name(), "ports");
	EXPECT_EQ(udp_driver->field(0)->number(), 1);
	EXPECT_EQ(udp_driver->field(0)->type(), google::protobuf::FieldDescriptor::TYPE_MESSAGE);
	EXPECT_EQ(udp_driver->field(0)->message_type(), kinetum::io::udp::v1::UdpDriverPort::descriptor());
	EXPECT_TRUE(udp_driver->field(0)->is_repeated());

	const auto *udp_port = kinetum::io::udp::v1::UdpDriverPort::descriptor();
	ASSERT_EQ(udp_port->field_count(), 3);
	const auto *udp_driver_port_id = udp_port->FindFieldByName("driver_port_id");
	const auto *ipv4_address = udp_port->FindFieldByName("ipv4_address");
	const auto *udp_port_number = udp_port->FindFieldByName("port");
	ASSERT_NE(udp_driver_port_id, nullptr);
	ASSERT_NE(ipv4_address, nullptr);
	ASSERT_NE(udp_port_number, nullptr);
	EXPECT_EQ(udp_driver_port_id->number(), 1);
	EXPECT_EQ(udp_driver_port_id->type(), google::protobuf::FieldDescriptor::TYPE_STRING);
	EXPECT_EQ(ipv4_address->number(), 2);
	EXPECT_EQ(ipv4_address->type(), google::protobuf::FieldDescriptor::TYPE_STRING);
	EXPECT_EQ(udp_port_number->number(), 3);
	EXPECT_EQ(udp_port_number->type(), google::protobuf::FieldDescriptor::TYPE_UINT32);

	const auto *dpdk_storage = kinetum::storage::dpdk::v1::DpdkStorageConfig::descriptor();
	ASSERT_EQ(dpdk_storage->field_count(), 1);
	EXPECT_EQ(dpdk_storage->field(0)->name(), "cache_size");
	EXPECT_EQ(dpdk_storage->field(0)->number(), 1);
	EXPECT_EQ(dpdk_storage->field(0)->type(), google::protobuf::FieldDescriptor::TYPE_UINT32);
}

/** @brief Every row graph is map-free and cannot nest another dynamic Any. */
TEST(provider_contract_schema, reachable_contract_graphs_are_closed_and_map_free)
{
	for (std::size_t index = 0; index < provider_contract_count(); ++index) {
		const auto *row = provider_contract_at(index);
		ASSERT_NE(row, nullptr);
		expect_closed_concrete_contract_graph(provider_configuration_message_descriptor(row->type_url));
	}
}

/** @brief Shared protobuf validation rejects forward enum values without guessing. */
TEST(protobuf_contract, invalid_enum_numbers_fail_closed)
{
	kinetum::gluon::v1::DeploymentPlan plan;
	auto *port = plan.add_ports();
	const auto *field = port->GetDescriptor()->FindFieldByName("direction");
	ASSERT_NE(field, nullptr);
	port->GetReflection()->SetEnumValue(port, field, 1'000'003);

	const auto result = common::reject_invalid_protobuf_enum_values_recursive(plan, "DeploymentPlan");
	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.message().find("unknown enum number"), std::string::npos);
	EXPECT_EQ(result.message().find("1000003"), std::string::npos);
}

/** @brief Shared deterministic serialization has one exact generated-wire answer. */
TEST(protobuf_contract, deterministic_serialization_matches_known_wire_bytes)
{
	kinetum::storage::dpdk::v1::DpdkStorageConfig configuration;
	configuration.set_cache_size(512);
	auto serialized_or = common::serialize_protobuf_deterministically(configuration);
	ASSERT_TRUE(serialized_or.is_ok()) << serialized_or.error().message();
	EXPECT_EQ(serialized_or.value(), std::string("\x08\x80\x04", 3));
}

/** @brief Capability rows carry exact roles, dependencies, and host authorities. */
TEST(provider_contract_catalog, role_specific_projections_are_exact)
{
	const auto *facility = find_provider_contract(DPDK_FACILITY_TYPE_URL);
	ASSERT_NE(facility, nullptr);
	ASSERT_TRUE(std::holds_alternative<process_facility_projection>(facility->capabilities));
	const auto &facility_projection = std::get<process_facility_projection>(facility->capabilities);
	EXPECT_TRUE(facility_projection.exactly_one_per_process_generation);
	EXPECT_TRUE(facility_projection.identical_configuration_required);
	EXPECT_TRUE(facility_projection.generation_safe_lease_required);
	EXPECT_TRUE(facility->facility_dependencies.empty());
	ASSERT_EQ(facility->host_requirements.size(), 2u);
	EXPECT_EQ(facility->host_requirements[0].fact, provider_host_fact::DPDK_EAL_RUNTIME);
	EXPECT_EQ(facility->host_requirements[0].phase, provider_host_proof_phase::COMPONENT_HOST_PROOF);
	EXPECT_EQ(facility->host_requirements[1].fact, provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR);
	EXPECT_EQ(facility->host_requirements[1].phase, provider_host_proof_phase::COMPONENT_HOST_PROOF);

	const auto *driver = find_provider_contract(DPDK_DRIVER_TYPE_URL);
	ASSERT_NE(driver, nullptr);
	ASSERT_TRUE(std::holds_alternative<io_driver_projection>(driver->capabilities));
	const auto &driver_projection = std::get<io_driver_projection>(driver->capabilities);
	EXPECT_TRUE(has_agent(driver_projection.packet_access_agents, packet_access_agent::NIC_DMA));
	EXPECT_FALSE(has_agent(driver_projection.packet_access_agents, packet_access_agent::CPU));
	EXPECT_EQ(driver_projection.directions,
		  static_cast<io_direction_mask>(static_cast<io_direction_mask>(io_direction::RX) |
						 static_cast<io_direction_mask>(io_direction::TX)));
	EXPECT_EQ(driver_projection.steering, static_cast<steering_capability_mask>(
						      static_cast<steering_capability_mask>(steering_capability::NONE) |
						      static_cast<steering_capability_mask>(steering_capability::RSS)));
	ASSERT_EQ(driver_projection.rss_hash_fields.size(), 2u);
	EXPECT_EQ(driver_projection.rss_hash_fields[0], "ipv4");
	EXPECT_EQ(driver_projection.rss_hash_fields[1], "udp");
	EXPECT_EQ(driver_projection.maximum_rss_key_bytes, 128u);
	EXPECT_TRUE(driver_projection.supports_symmetric_rss);
	EXPECT_EQ(driver_projection.maximum_driver_queue_id,
		  static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) - 1u);
	EXPECT_EQ(driver_projection.maximum_descriptor_count, std::numeric_limits<uint16_t>::max());
	EXPECT_TRUE(driver_projection.dense_zero_based_queues);
	EXPECT_NE(driver_projection.validate_storage, nullptr);
	ASSERT_EQ(driver->facility_dependencies.size(), 1u);
	EXPECT_EQ(driver->facility_dependencies[0].type_url, DPDK_FACILITY_TYPE_URL);
	EXPECT_EQ(driver->facility_dependencies[0].exact_instance_count, 1u);
	ASSERT_EQ(driver->host_requirements.size(), 1u);
	EXPECT_EQ(driver->host_requirements[0].fact, provider_host_fact::DPDK_ETHDEV_PORT);
	EXPECT_EQ(driver->host_requirements[0].phase, provider_host_proof_phase::MATERIALIZATION_PROOF);

	const auto *udp_driver = find_provider_contract(UDP_DRIVER_TYPE_URL);
	ASSERT_NE(udp_driver, nullptr);
	ASSERT_TRUE(std::holds_alternative<io_driver_projection>(udp_driver->capabilities));
	const auto &udp_projection = std::get<io_driver_projection>(udp_driver->capabilities);
	EXPECT_TRUE(has_agent(udp_projection.packet_access_agents, packet_access_agent::CPU));
	EXPECT_FALSE(has_agent(udp_projection.packet_access_agents, packet_access_agent::NIC_DMA));
	EXPECT_EQ(udp_projection.directions,
		  static_cast<io_direction_mask>(static_cast<io_direction_mask>(io_direction::RX) |
						 static_cast<io_direction_mask>(io_direction::TX)));
	EXPECT_EQ(udp_projection.steering, static_cast<steering_capability_mask>(steering_capability::NONE));
	EXPECT_TRUE(udp_projection.rss_hash_fields.empty());
	EXPECT_EQ(udp_projection.maximum_rss_key_bytes, 0u);
	EXPECT_FALSE(udp_projection.supports_symmetric_rss);
	EXPECT_EQ(udp_projection.maximum_driver_queue_id, 0u);
	EXPECT_EQ(udp_projection.maximum_descriptor_count, std::numeric_limits<uint32_t>::max());
	EXPECT_TRUE(udp_projection.dense_zero_based_queues);
	EXPECT_NE(udp_projection.validate_storage, nullptr);
	EXPECT_TRUE(udp_driver->facility_dependencies.empty());
	ASSERT_EQ(udp_driver->host_requirements.size(), 1u);
	EXPECT_EQ(udp_driver->host_requirements[0].fact, provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET);
	EXPECT_EQ(udp_driver->host_requirements[0].phase, provider_host_proof_phase::COMPONENT_HOST_PROOF);

	const auto *storage = find_provider_contract(DPDK_STORAGE_TYPE_URL);
	ASSERT_NE(storage, nullptr);
	ASSERT_TRUE(std::holds_alternative<packet_storage_projection>(storage->capabilities));
	const auto &storage_projection = std::get<packet_storage_projection>(storage->capabilities);
	EXPECT_TRUE(has_agent(storage_projection.access_agents, packet_access_agent::CPU));
	EXPECT_TRUE(has_agent(storage_projection.access_agents, packet_access_agent::NIC_DMA));
	EXPECT_TRUE(storage_projection.cpu_contiguous_read);
	EXPECT_TRUE(storage_projection.cpu_contiguous_write);
	EXPECT_TRUE(storage_projection.writable_clone);
	EXPECT_EQ(storage_projection.maximum_data_room_bytes, std::numeric_limits<uint16_t>::max());
	ASSERT_EQ(storage->facility_dependencies.size(), 1u);
	EXPECT_EQ(storage->facility_dependencies[0].type_url, DPDK_FACILITY_TYPE_URL);
	EXPECT_EQ(storage->facility_dependencies[0].exact_instance_count, 1u);
	ASSERT_EQ(storage->host_requirements.size(), 1u);
	EXPECT_EQ(storage->host_requirements[0].fact, provider_host_fact::HOST_NUMA_MEMORY);
	EXPECT_EQ(storage->host_requirements[0].phase, provider_host_proof_phase::QUARK_LIVE_HOST);

	const auto *host_storage = find_provider_contract(HOST_STORAGE_TYPE_URL);
	ASSERT_NE(host_storage, nullptr);
	ASSERT_TRUE(std::holds_alternative<packet_storage_projection>(host_storage->capabilities));
	const auto &host_storage_projection = std::get<packet_storage_projection>(host_storage->capabilities);
	EXPECT_TRUE(has_agent(host_storage_projection.access_agents, packet_access_agent::CPU));
	EXPECT_FALSE(has_agent(host_storage_projection.access_agents, packet_access_agent::NIC_DMA));
	EXPECT_TRUE(host_storage_projection.cpu_contiguous_read);
	EXPECT_TRUE(host_storage_projection.cpu_contiguous_write);
	EXPECT_TRUE(host_storage_projection.writable_clone);
	EXPECT_EQ(host_storage_projection.maximum_data_room_bytes, std::numeric_limits<uint32_t>::max());
	EXPECT_TRUE(host_storage->facility_dependencies.empty());
	ASSERT_EQ(host_storage->host_requirements.size(), 1u);
	EXPECT_EQ(host_storage->host_requirements[0].fact, provider_host_fact::HOST_NUMA_MEMORY);
	EXPECT_EQ(host_storage->host_requirements[0].phase, provider_host_proof_phase::QUARK_LIVE_HOST);

	const auto *execution = find_provider_contract(CPU_EXECUTION_TYPE_URL);
	ASSERT_NE(execution, nullptr);
	ASSERT_TRUE(std::holds_alternative<execution_projection>(execution->capabilities));
	const auto &cpu_execution_projection = std::get<execution_projection>(execution->capabilities);
	EXPECT_EQ(cpu_execution_projection.required_access_agents, access_agent_bit(packet_access_agent::CPU));
	EXPECT_TRUE(cpu_execution_projection.requires_cpu_contiguous_read);
	EXPECT_TRUE(cpu_execution_projection.requires_cpu_contiguous_write);
	EXPECT_TRUE(packet_storage_supports_execution(storage_projection, cpu_execution_projection));
	auto missing_cpu_agent = storage_projection;
	missing_cpu_agent.access_agents &=
		static_cast<packet_access_agent_mask>(~access_agent_bit(packet_access_agent::CPU));
	EXPECT_FALSE(packet_storage_supports_execution(missing_cpu_agent, cpu_execution_projection));
	auto missing_read = storage_projection;
	missing_read.cpu_contiguous_read = false;
	EXPECT_FALSE(packet_storage_supports_execution(missing_read, cpu_execution_projection));
	auto missing_write = storage_projection;
	missing_write.cpu_contiguous_write = false;
	EXPECT_FALSE(packet_storage_supports_execution(missing_write, cpu_execution_projection));
	auto missing_clone = storage_projection;
	missing_clone.writable_clone = false;
	EXPECT_TRUE(packet_storage_supports_fanout(missing_clone, 1u));
	EXPECT_FALSE(packet_storage_supports_fanout(missing_clone, 2u));
	EXPECT_TRUE(execution->facility_dependencies.empty());
	ASSERT_EQ(execution->host_requirements.size(), 1u);
	EXPECT_EQ(execution->host_requirements[0].fact, provider_host_fact::CPU_WORKER_SET);
	EXPECT_EQ(execution->host_requirements[0].phase, provider_host_proof_phase::QUARK_LIVE_HOST);

	const auto *zero_copy = find_provider_contract(ZERO_COPY_SHARE_TYPE_URL);
	ASSERT_NE(zero_copy, nullptr);
	ASSERT_TRUE(std::holds_alternative<storage_transition_projection>(zero_copy->capabilities));
	const auto &zero_copy_projection = std::get<storage_transition_projection>(zero_copy->capabilities);
	EXPECT_EQ(zero_copy_projection.mode, storage_transition_mode::ZERO_COPY_SHARE);
	EXPECT_EQ(zero_copy_projection.required_source_access_agents, 0u);
	EXPECT_EQ(zero_copy_projection.required_destination_access_agents, 0u);
	EXPECT_FALSE(zero_copy_projection.requires_nonzero_staging_capacity);
	EXPECT_FALSE(zero_copy_projection.requires_host_staging_numa);
	EXPECT_TRUE(zero_copy->facility_dependencies.empty());
	EXPECT_TRUE(zero_copy->host_requirements.empty());

	const auto *bounded_copy = find_provider_contract(BOUNDED_COPY_TYPE_URL);
	ASSERT_NE(bounded_copy, nullptr);
	ASSERT_TRUE(std::holds_alternative<storage_transition_projection>(bounded_copy->capabilities));
	const auto &bounded_copy_projection = std::get<storage_transition_projection>(bounded_copy->capabilities);
	EXPECT_EQ(bounded_copy_projection.mode, storage_transition_mode::BOUNDED_COPY);
	EXPECT_EQ(bounded_copy_projection.required_source_access_agents, access_agent_bit(packet_access_agent::CPU));
	EXPECT_EQ(bounded_copy_projection.required_destination_access_agents,
		  access_agent_bit(packet_access_agent::CPU));
	EXPECT_TRUE(bounded_copy_projection.requires_nonzero_staging_capacity);
	EXPECT_TRUE(bounded_copy_projection.requires_host_staging_numa);
	EXPECT_TRUE(bounded_copy->facility_dependencies.empty());
	ASSERT_EQ(bounded_copy->host_requirements.size(), 1u);
	EXPECT_EQ(bounded_copy->host_requirements[0].fact, provider_host_fact::HOST_NUMA_MEMORY);
	EXPECT_EQ(bounded_copy->host_requirements[0].phase, provider_host_proof_phase::QUARK_LIVE_HOST);
}

/** @brief Capability rows use only the closed current vocabulary. */
TEST(provider_contract_catalog, capability_vocabulary_is_closed_and_exact)
{
	EXPECT_DEATH({ (void)access_agent_bit(static_cast<packet_access_agent>(255u)); }, "");
	EXPECT_DEATH({ (void)provider_configuration_step_name(static_cast<provider_configuration_step>(255u)); }, "");
	constexpr packet_access_agent_mask KNOWN_ACCESS_AGENTS = access_agent_bit(packet_access_agent::CPU) |
								 access_agent_bit(packet_access_agent::NIC_DMA);
	const auto expect_known_agents = [](packet_access_agent_mask agents) {
		EXPECT_EQ(static_cast<packet_access_agent_mask>(agents & ~KNOWN_ACCESS_AGENTS), 0u);
	};
	for (std::size_t index = 0; index < provider_contract_count(); ++index) {
		const auto *row = provider_contract_at(index);
		ASSERT_NE(row, nullptr);
		std::visit(
			[&](const auto &projection) {
				using projection_type = std::decay_t<decltype(projection)>;
				if constexpr (std::is_same_v<projection_type, io_driver_projection>) {
					expect_known_agents(projection.packet_access_agents);
				} else if constexpr (std::is_same_v<projection_type, packet_storage_projection>) {
					expect_known_agents(projection.access_agents);
				} else if constexpr (std::is_same_v<projection_type, execution_projection>) {
					expect_known_agents(projection.required_access_agents);
				} else if constexpr (std::is_same_v<projection_type, storage_transition_projection>) {
					expect_known_agents(projection.required_source_access_agents);
					expect_known_agents(projection.required_destination_access_agents);
					EXPECT_TRUE(projection.mode == storage_transition_mode::ZERO_COPY_SHARE ||
						    projection.mode == storage_transition_mode::BOUNDED_COPY);
				}
			},
			row->capabilities);
	}
}

/** @brief URL bound is first even when every later property is malformed. */
TEST(provider_configuration, step_1_type_url_bound_has_precedence)
{
	Any input;
	input.set_type_url(std::string(MAX_PROVIDER_TYPE_URL_BYTES + 1u, 'x'));
	input.set_value(std::string(MAX_PROVIDER_CONFIGURATION_BYTES + 1u, '\0'));
	auto result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, input);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::RESOURCE_EXHAUSTED);
	expect_step(result.error(), provider_configuration_step::TYPE_URL_BOUND);
}

/** @brief Canonical URL grammar rejects alternate prefixes before lookup. */
TEST(provider_configuration, step_2_canonical_type_url_has_precedence)
{
	const std::array<std::string_view, 7> NONCANONICAL_URLS{
		"",
		"kinetum.io.dpdk.v1.DpdkDriverConfig",
		"/type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig",
		"https://type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig",
		"type.googleapis.com//kinetum.io.dpdk.v1.DpdkDriverConfig",
		"type.googleapis.com/kinetum..io.dpdk.v1.DpdkDriverConfig",
		"type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig.",
	};
	for (const std::string_view type_url : NONCANONICAL_URLS) {
		Any input;
		input.set_type_url(type_url.data(), type_url.size());
		input.set_value(std::string(MAX_PROVIDER_CONFIGURATION_BYTES + 1u, '\0'));
		auto result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, input);
		ASSERT_FALSE(result.is_ok());
		EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
		expect_step(result.error(), provider_configuration_step::TYPE_URL_CANONICAL_FORM);
	}
}

/** @brief Exact full-URL lookup rejects unknown contracts before payload work. */
TEST(provider_configuration, step_3_catalog_lookup_has_precedence)
{
	Any input;
	input.set_type_url("type.googleapis.com/kinetum.io.unknown.v1.UnknownConfig");
	input.set_value(std::string(MAX_PROVIDER_CONFIGURATION_BYTES + 1u, '\0'));
	auto result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, input);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::NOT_FOUND);
	expect_step(result.error(), provider_configuration_step::CATALOG_LOOKUP);
}

/** @brief Owning-role agreement rejects before payload size or parsing. */
TEST(provider_configuration, step_4_role_agreement_has_precedence)
{
	Any input;
	input.set_type_url(DPDK_DRIVER_TYPE_URL.data(), DPDK_DRIVER_TYPE_URL.size());
	input.set_value(std::string(MAX_PROVIDER_CONFIGURATION_BYTES + 1u, '\0'));
	auto result = canonicalize_provider_configuration(provider_contract_role::PACKET_STORAGE, input);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
	expect_step(result.error(), provider_configuration_step::ROLE_AGREEMENT);
}

/** @brief Payload bound rejects before concrete protobuf decoding. */
TEST(provider_configuration, step_5_payload_bound_has_precedence)
{
	Any input;
	input.set_type_url(DPDK_DRIVER_TYPE_URL.data(), DPDK_DRIVER_TYPE_URL.size());
	input.set_value(std::string(MAX_PROVIDER_CONFIGURATION_BYTES + 1u, '\0'));
	auto result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, input);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::RESOURCE_EXHAUSTED);
	expect_step(result.error(), provider_configuration_step::PAYLOAD_BOUND);
}

/** @brief Truncated wire data fails decode before provider validation. */
TEST(provider_configuration, step_6_concrete_decode_has_precedence)
{
	Any input;
	input.set_type_url(DPDK_DRIVER_TYPE_URL.data(), DPDK_DRIVER_TYPE_URL.size());
	input.set_value(std::string("\x0a", 1));
	auto result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, input);
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
	expect_step(result.error(), provider_configuration_step::CONCRETE_DECODE);
}

/** @brief Recursive unknown fields fail wire validation before provider policy. */
TEST(provider_configuration, step_7_wire_tree_validation_has_precedence)
{
	auto configuration = make_dpdk_pci_config("", "invalid-bdf");
	configuration.mutable_ports(0)
		->GetReflection()
		->MutableUnknownFields(configuration.mutable_ports(0))
		->AddVarint(1'001, 1);
	auto result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
							  make_any(DPDK_DRIVER_TYPE_URL, configuration));
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
	expect_step(result.error(), provider_configuration_step::WIRE_TREE_VALIDATION);

	Any outer_unknown = make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("", "invalid-bdf"));
	outer_unknown.GetReflection()->MutableUnknownFields(&outer_unknown)->AddVarint(1'002, 1);
	auto outer_result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, outer_unknown);
	ASSERT_FALSE(outer_result.is_ok());
	EXPECT_EQ(outer_result.error().code(), status_code::INVALID_ARGUMENT);
	expect_step(outer_result.error(), provider_configuration_step::WIRE_TREE_VALIDATION);
}

/** @brief Decoded known wire with invalid policy fails the provider step. */
TEST(provider_configuration, step_8_provider_validation_has_precedence)
{
	kinetum::io::dpdk::v1::DpdkDriverConfig empty;
	auto result = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
							  make_any(DPDK_DRIVER_TYPE_URL, empty));
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), status_code::INVALID_ARGUMENT);
	expect_step(result.error(), provider_configuration_step::PROVIDER_VALIDATION);
}

/** @brief Deterministic serialization and exact repack are the terminal operations. */
TEST(provider_configuration, steps_9_and_10_produce_exact_fixed_point_without_hashing)
{
	EXPECT_EQ(provider_configuration_step_name(provider_configuration_step::NORMALIZED_SERIALIZATION),
		  "normalized-serialization");
	EXPECT_EQ(provider_configuration_step_name(provider_configuration_step::EXACT_REPACK), "exact-repack");

	const auto input = make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("port_a", "0000:03:00.0"));
	auto first_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, input);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	EXPECT_EQ(first_or.value().contract.get().type_url, DPDK_DRIVER_TYPE_URL);
	EXPECT_EQ(first_or.value().configuration.type_url(), DPDK_DRIVER_TYPE_URL);

	auto second_or =
		canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, first_or.value().configuration);
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	EXPECT_EQ(second_or.value().configuration.SerializeAsString(),
		  first_or.value().configuration.SerializeAsString());
}

/** @brief Exact URL and payload bounds admit the edge and reject edge plus one. */
TEST(provider_configuration, named_bounds_are_exact)
{
	std::string exact_url(PROVIDER_TYPE_URL_PREFIX);
	exact_url.append(MAX_PROVIDER_TYPE_URL_BYTES - exact_url.size(), 'x');
	ASSERT_EQ(exact_url.size(), MAX_PROVIDER_TYPE_URL_BYTES);
	Any url_edge;
	url_edge.set_type_url(exact_url);
	auto url_edge_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, url_edge);
	ASSERT_FALSE(url_edge_or.is_ok());
	expect_step(url_edge_or.error(), provider_configuration_step::CATALOG_LOOKUP);

	url_edge.mutable_type_url()->push_back('x');
	auto url_over_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, url_edge);
	ASSERT_FALSE(url_over_or.is_ok());
	expect_step(url_over_or.error(), provider_configuration_step::TYPE_URL_BOUND);

	Any payload_edge;
	payload_edge.set_type_url(DPDK_DRIVER_TYPE_URL.data(), DPDK_DRIVER_TYPE_URL.size());
	payload_edge.set_value(std::string(MAX_PROVIDER_CONFIGURATION_BYTES, '\0'));
	auto payload_edge_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, payload_edge);
	ASSERT_FALSE(payload_edge_or.is_ok());
	expect_step(payload_edge_or.error(), provider_configuration_step::CONCRETE_DECODE);

	payload_edge.mutable_value()->push_back('\0');
	auto payload_over_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, payload_edge);
	ASSERT_FALSE(payload_over_or.is_ok());
	expect_step(payload_over_or.error(), provider_configuration_step::PAYLOAD_BOUND);
}

/** @brief Diagnostics include length and omit untrusted tails and full payloads. */
TEST(provider_configuration, diagnostics_render_only_bounded_noncomplete_prefixes)
{
	constexpr std::string_view SECRET_TAIL = "secret_tail_must_not_be_echoed";
	Any empty_url;
	auto empty_url_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, empty_url);
	ASSERT_FALSE(empty_url_or.is_ok());
	EXPECT_NE(empty_url_or.error().message().find("length=0"), std::string::npos);
	EXPECT_NE(empty_url_or.error().message().find("truncated=false"), std::string::npos);

	Any unknown;
	unknown.set_type_url("type.googleapis.com/kinetum.io.unknown.v1." +
			     std::string(MAX_PROVIDER_DIAGNOSTIC_PREFIX_BYTES, 'x') + std::string(SECRET_TAIL));
	auto unknown_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, unknown);
	ASSERT_FALSE(unknown_or.is_ok());
	EXPECT_NE(unknown_or.error().message().find("length="), std::string::npos);
	EXPECT_NE(unknown_or.error().message().find("truncated=true"), std::string::npos);
	EXPECT_EQ(unknown_or.error().message().find(SECRET_TAIL), std::string::npos);

	Any oversized;
	oversized.set_type_url(DPDK_DRIVER_TYPE_URL.data(), DPDK_DRIVER_TYPE_URL.size());
	oversized.set_value(std::string(MAX_PROVIDER_CONFIGURATION_BYTES + 1u, 'p') + std::string(SECRET_TAIL));
	auto oversized_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, oversized);
	ASSERT_FALSE(oversized_or.is_ok());
	EXPECT_NE(oversized_or.error().message().find("length="), std::string::npos);
	EXPECT_EQ(oversized_or.error().message().find(SECRET_TAIL), std::string::npos);

	const std::string malformed_bdf(MAX_PROVIDER_DIAGNOSTIC_PREFIX_BYTES, 'a');
	auto malformed_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL,
			 make_dpdk_pci_config("port_a", malformed_bdf + std::string(SECRET_TAIL))));
	ASSERT_FALSE(malformed_or.is_ok());
	EXPECT_NE(malformed_or.error().message().find("length="), std::string::npos);
	EXPECT_EQ(malformed_or.error().message().find(SECRET_TAIL), std::string::npos);

	Any escaped;
	escaped.set_type_url("type.googleapis.com/kinetum.io.'\\\nBad");
	auto escaped_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, escaped);
	ASSERT_FALSE(escaped_or.is_ok());
	EXPECT_NE(escaped_or.error().message().find("\\x27"), std::string::npos);
	EXPECT_NE(escaped_or.error().message().find("\\x5c"), std::string::npos);
	EXPECT_NE(escaped_or.error().message().find("\\x0a"), std::string::npos);
	EXPECT_EQ(escaped_or.error().message().find('\n'), std::string::npos);
}

/** @brief Every empty policy canonicalizes to exact empty bytes. */
TEST(provider_configuration, empty_contracts_have_exact_empty_canonical_payload)
{
	struct empty_case {
		std::string_view type_url;
		provider_contract_role role;
	};
	constexpr std::array<empty_case, 5> EMPTY_CASES{
		empty_case{DPDK_FACILITY_TYPE_URL, provider_contract_role::PROCESS_FACILITY},
		empty_case{HOST_STORAGE_TYPE_URL, provider_contract_role::PACKET_STORAGE},
		empty_case{CPU_EXECUTION_TYPE_URL, provider_contract_role::EXECUTION},
		empty_case{ZERO_COPY_SHARE_TYPE_URL, provider_contract_role::STORAGE_TRANSITION},
		empty_case{BOUNDED_COPY_TYPE_URL, provider_contract_role::STORAGE_TRANSITION},
	};

	for (const auto &test_case : EMPTY_CASES) {
		Any input;
		input.set_type_url(test_case.type_url.data(), test_case.type_url.size());
		auto result = canonicalize_provider_configuration(test_case.role, input);
		ASSERT_TRUE(result.is_ok()) << result.error().message();
		EXPECT_TRUE(result.value().configuration.value().empty());
	}
}

/** @brief Unknown wire fields reject for every otherwise-empty policy message. */
TEST(provider_configuration, empty_contracts_reject_unknown_wire_fields)
{
	struct empty_case {
		std::string_view type_url;
		provider_contract_role role;
	};
	constexpr std::array<empty_case, 5> EMPTY_CASES{
		empty_case{DPDK_FACILITY_TYPE_URL, provider_contract_role::PROCESS_FACILITY},
		empty_case{HOST_STORAGE_TYPE_URL, provider_contract_role::PACKET_STORAGE},
		empty_case{CPU_EXECUTION_TYPE_URL, provider_contract_role::EXECUTION},
		empty_case{ZERO_COPY_SHARE_TYPE_URL, provider_contract_role::STORAGE_TRANSITION},
		empty_case{BOUNDED_COPY_TYPE_URL, provider_contract_role::STORAGE_TRANSITION},
	};

	for (const auto &test_case : EMPTY_CASES) {
		Any input;
		input.set_type_url(test_case.type_url.data(), test_case.type_url.size());
		input.set_value(std::string("\x08\x01", 2));
		auto result = canonicalize_provider_configuration(test_case.role, input);
		ASSERT_FALSE(result.is_ok());
		expect_step(result.error(), provider_configuration_step::WIRE_TREE_VALIDATION);
	}
}

/** @brief DPDK and UDP port sets normalize ordering and reject duplicates. */
TEST(provider_configuration, declared_port_sets_sort_and_reject_duplicates)
{
	kinetum::io::dpdk::v1::DpdkDriverConfig dpdk_first;
	*dpdk_first.add_ports() = make_dpdk_pci_config("port_b", "0000:04:00.0").ports(0);
	*dpdk_first.add_ports() = make_dpdk_pci_config("port_a", "0000:03:00.0").ports(0);
	auto dpdk_second = dpdk_first;
	dpdk_second.mutable_ports()->SwapElements(0, 1);
	auto dpdk_first_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								 make_any(DPDK_DRIVER_TYPE_URL, dpdk_first));
	auto dpdk_second_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								  make_any(DPDK_DRIVER_TYPE_URL, dpdk_second));
	ASSERT_TRUE(dpdk_first_or.is_ok()) << dpdk_first_or.error().message();
	ASSERT_TRUE(dpdk_second_or.is_ok()) << dpdk_second_or.error().message();
	EXPECT_EQ(dpdk_first_or.value().configuration.value(), dpdk_second_or.value().configuration.value());
	kinetum::io::dpdk::v1::DpdkDriverConfig canonical_dpdk;
	ASSERT_TRUE(canonical_dpdk.ParseFromString(dpdk_first_or.value().configuration.value()));
	ASSERT_EQ(canonical_dpdk.ports_size(), 2);
	EXPECT_EQ(canonical_dpdk.ports(0).driver_port_id(), "port_a");
	EXPECT_EQ(canonical_dpdk.ports(1).driver_port_id(), "port_b");

	kinetum::io::udp::v1::UdpDriverConfig udp_first;
	*udp_first.add_ports() = make_udp_config("udp_b", "127.0.0.2", 1001).ports(0);
	*udp_first.add_ports() = make_udp_config("udp_a", "127.0.0.1", 1000).ports(0);
	auto udp_second = udp_first;
	udp_second.mutable_ports()->SwapElements(0, 1);
	auto udp_first_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								make_any(UDP_DRIVER_TYPE_URL, udp_first));
	auto udp_second_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								 make_any(UDP_DRIVER_TYPE_URL, udp_second));
	ASSERT_TRUE(udp_first_or.is_ok()) << udp_first_or.error().message();
	ASSERT_TRUE(udp_second_or.is_ok()) << udp_second_or.error().message();
	EXPECT_EQ(udp_first_or.value().configuration.value(), udp_second_or.value().configuration.value());
	kinetum::io::udp::v1::UdpDriverConfig canonical_udp;
	ASSERT_TRUE(canonical_udp.ParseFromString(udp_first_or.value().configuration.value()));
	ASSERT_EQ(canonical_udp.ports_size(), 2);
	EXPECT_EQ(canonical_udp.ports(0).driver_port_id(), "udp_a");
	EXPECT_EQ(canonical_udp.ports(1).driver_port_id(), "udp_b");

	kinetum::io::dpdk::v1::DpdkDriverConfig duplicate_dpdk;
	*duplicate_dpdk.add_ports() = make_dpdk_pci_config("port_a", "0000:03:00.0").ports(0);
	*duplicate_dpdk.add_ports() = make_dpdk_pci_config("port_a", "0000:04:00.0").ports(0);
	auto duplicate_dpdk_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								     make_any(DPDK_DRIVER_TYPE_URL, duplicate_dpdk));
	ASSERT_FALSE(duplicate_dpdk_or.is_ok());
	expect_step(duplicate_dpdk_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	kinetum::io::udp::v1::UdpDriverConfig duplicate;
	*duplicate.add_ports() = make_udp_config("udp_a", "127.0.0.1", 1000).ports(0);
	*duplicate.add_ports() = make_udp_config("udp_a", "127.0.0.2", 1001).ports(0);
	auto duplicate_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								make_any(UDP_DRIVER_TYPE_URL, duplicate));
	ASSERT_FALSE(duplicate_or.is_ok());
	expect_step(duplicate_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
}

/** @brief PCI and TAP contracts accept one spelling and reject variants. */
TEST(provider_configuration, dpdk_attachment_spelling_is_exact)
{
	auto canonical_pci_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("port_a", "0000:03:00.0")));
	EXPECT_TRUE(canonical_pci_or.is_ok()) << canonical_pci_or.error().message();

	auto uppercase_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("port_a", "0000:0A:00.0")));
	ASSERT_FALSE(uppercase_or.is_ok());
	expect_step(uppercase_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	auto out_of_range_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("port_a", "0000:03:20.0")));
	ASSERT_FALSE(out_of_range_or.is_ok());
	expect_step(out_of_range_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
	auto function_out_of_range_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("port_a", "0000:03:00.8")));
	ASSERT_FALSE(function_out_of_range_or.is_ok());
	expect_step(function_out_of_range_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
	auto malformed_shape_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("port_a", "0000:3:00.0")));
	ASSERT_FALSE(malformed_shape_or.is_ok());
	expect_step(malformed_shape_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
	auto malformed_id_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config("port-a", "0000:03:00.0")));
	ASSERT_FALSE(malformed_id_or.is_ok());
	expect_step(malformed_id_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	kinetum::io::dpdk::v1::DpdkDriverConfig attachment_missing;
	attachment_missing.add_ports()->set_driver_port_id("port_a");
	auto attachment_missing_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER, make_any(DPDK_DRIVER_TYPE_URL, attachment_missing));
	ASSERT_FALSE(attachment_missing_or.is_ok());
	expect_step(attachment_missing_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	kinetum::io::dpdk::v1::DpdkDriverConfig tap;
	auto *tap_port = tap.add_ports();
	tap_port->set_driver_port_id("tap_a");
	tap_port->mutable_tap()->set_interface_name("tap-test.0");
	auto tap_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
							  make_any(DPDK_DRIVER_TYPE_URL, tap));
	EXPECT_TRUE(tap_or.is_ok()) << tap_or.error().message();
	tap.mutable_ports(0)->mutable_tap()->set_interface_name("tap/test");
	auto invalid_tap_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								  make_any(DPDK_DRIVER_TYPE_URL, tap));
	ASSERT_FALSE(invalid_tap_or.is_ok());
	expect_step(invalid_tap_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
	tap.mutable_ports(0)->mutable_tap()->set_interface_name("1tap");
	auto invalid_tap_first_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
									make_any(DPDK_DRIVER_TYPE_URL, tap));
	ASSERT_FALSE(invalid_tap_first_or.is_ok());
	expect_step(invalid_tap_first_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	const std::string maximum_tap_name = "t" + std::string(MAX_TAP_INTERFACE_NAME_BYTES - 1u, 'x');
	tap.mutable_ports(0)->mutable_tap()->set_interface_name(maximum_tap_name);
	auto maximum_tap_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								  make_any(DPDK_DRIVER_TYPE_URL, tap));
	EXPECT_TRUE(maximum_tap_or.is_ok()) << maximum_tap_or.error().message();
	tap.mutable_ports(0)->mutable_tap()->set_interface_name(maximum_tap_name + "x");
	auto oversized_tap_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								    make_any(DPDK_DRIVER_TYPE_URL, tap));
	ASSERT_FALSE(oversized_tap_or.is_ok());
	expect_step(oversized_tap_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	const std::string maximum_provider_id = "p" + std::string(MAX_PROVIDER_ID_BYTES - 1u, 'x');
	auto maximum_id_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config(maximum_provider_id, "0000:03:00.0")));
	EXPECT_TRUE(maximum_id_or.is_ok()) << maximum_id_or.error().message();
	auto oversized_id_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(DPDK_DRIVER_TYPE_URL, make_dpdk_pci_config(maximum_provider_id + "x", "0000:03:00.0")));
	ASSERT_FALSE(oversized_id_or.is_ok());
	expect_step(oversized_id_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
}

/** @brief UDP accepts canonical inet_pton IPv4 and exact uint16 port range only. */
TEST(provider_configuration, udp_address_and_port_spelling_is_exact)
{
	kinetum::io::udp::v1::UdpDriverConfig empty;
	auto empty_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
							    make_any(UDP_DRIVER_TYPE_URL, empty));
	ASSERT_FALSE(empty_or.is_ok());
	expect_step(empty_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	auto zero_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
							   make_any(UDP_DRIVER_TYPE_URL,
								    make_udp_config("udp_a", "127.0.0.1", 0)));
	EXPECT_TRUE(zero_or.is_ok()) << zero_or.error().message();

	auto edge_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
							   make_any(UDP_DRIVER_TYPE_URL,
								    make_udp_config("udp_a", "127.0.0.1", 65'535)));
	EXPECT_TRUE(edge_or.is_ok()) << edge_or.error().message();

	auto abbreviated_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
								  make_any(UDP_DRIVER_TYPE_URL,
									   make_udp_config("udp_a", "127.1", 1000)));
	ASSERT_FALSE(abbreviated_or.is_ok());
	expect_step(abbreviated_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	auto leading_zero_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(UDP_DRIVER_TYPE_URL, make_udp_config("udp_a", "127.000.000.001", 1000)));
	ASSERT_FALSE(leading_zero_or.is_ok());
	expect_step(leading_zero_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
	auto dns_or = canonicalize_provider_configuration(provider_contract_role::IO_DRIVER,
							  make_any(UDP_DRIVER_TYPE_URL,
								   make_udp_config("udp_a", "localhost", 1000)));
	ASSERT_FALSE(dns_or.is_ok());
	expect_step(dns_or.error(), provider_configuration_step::PROVIDER_VALIDATION);

	auto oversized_port_or = canonicalize_provider_configuration(
		provider_contract_role::IO_DRIVER,
		make_any(UDP_DRIVER_TYPE_URL, make_udp_config("udp_a", "127.0.0.1", 65'536)));
	ASSERT_FALSE(oversized_port_or.is_ok());
	expect_step(oversized_port_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
}

/** @brief DPDK cache policy admits its exact edge and rejects edge plus one. */
TEST(provider_configuration, dpdk_cache_bound_is_exact)
{
	kinetum::storage::dpdk::v1::DpdkStorageConfig configuration;
	auto zero_or = canonicalize_provider_configuration(provider_contract_role::PACKET_STORAGE,
							   make_any(DPDK_STORAGE_TYPE_URL, configuration));
	EXPECT_TRUE(zero_or.is_ok()) << zero_or.error().message();

	configuration.set_cache_size(MAX_DPDK_MEMPOOL_CACHE_SIZE);
	auto edge_or = canonicalize_provider_configuration(provider_contract_role::PACKET_STORAGE,
							   make_any(DPDK_STORAGE_TYPE_URL, configuration));
	EXPECT_TRUE(edge_or.is_ok()) << edge_or.error().message();

	configuration.set_cache_size(MAX_DPDK_MEMPOOL_CACHE_SIZE + 1u);
	auto over_or = canonicalize_provider_configuration(provider_contract_role::PACKET_STORAGE,
							   make_any(DPDK_STORAGE_TYPE_URL, configuration));
	ASSERT_FALSE(over_or.is_ok());
	expect_step(over_or.error(), provider_configuration_step::PROVIDER_VALIDATION);
}

/** @brief DPDK admits complete compatible pool sets only under its exact facility identity. */
TEST(provider_contract_catalog, dpdk_storage_admission_requires_native_contract_and_matching_facility)
{
	const auto *driver = find_provider_contract(DPDK_DRIVER_TYPE_URL);
	const auto *storage = find_provider_contract(DPDK_STORAGE_TYPE_URL);
	ASSERT_NE(driver, nullptr);
	ASSERT_NE(storage, nullptr);
	const auto &driver_projection = std::get<io_driver_projection>(driver->capabilities);
	const auto &storage_projection = std::get<packet_storage_projection>(storage->capabilities);
	constexpr std::array<uint32_t, 1> FACILITY{3u};
	constexpr std::array<uint32_t, 1> OTHER_FACILITY{7u};
	std::array<io_storage_candidate, 2> domains{{
		{DPDK_STORAGE_TYPE_URL, storage_projection, FACILITY},
		{DPDK_STORAGE_TYPE_URL, storage_projection, FACILITY},
	}};
	EXPECT_TRUE(validate_io_storage_binding(driver_projection, {io_direction::TX, FACILITY, domains}).is_ok());
	EXPECT_FALSE(validate_io_storage_binding(driver_projection, {io_direction::RX, FACILITY, domains}).is_ok());
	domains[1].facility_indices = OTHER_FACILITY;
	EXPECT_FALSE(validate_io_storage_binding(driver_projection, {io_direction::TX, FACILITY, domains}).is_ok());
	domains[1].facility_indices = FACILITY;
	domains[1].type_url = HOST_STORAGE_TYPE_URL;
	EXPECT_FALSE(validate_io_storage_binding(driver_projection, {io_direction::TX, FACILITY, domains}).is_ok());
	EXPECT_FALSE(validate_io_storage_binding(driver_projection, {io_direction::TX, FACILITY, {}}).is_ok());
}

/** @brief UDP admits readable records from distinct storage implementations without requiring RX write access on TX. */
TEST(provider_contract_catalog, udp_storage_admission_separates_receive_write_from_transmit_read)
{
	const auto *driver = find_provider_contract(UDP_DRIVER_TYPE_URL);
	const auto *host = find_provider_contract(HOST_STORAGE_TYPE_URL);
	const auto *dpdk = find_provider_contract(DPDK_STORAGE_TYPE_URL);
	ASSERT_NE(driver, nullptr);
	ASSERT_NE(host, nullptr);
	ASSERT_NE(dpdk, nullptr);
	const auto &projection = std::get<io_driver_projection>(driver->capabilities);
	constexpr std::array<uint32_t, 1> FACILITY{3u};
	std::array<io_storage_candidate, 2> domains{{
		{HOST_STORAGE_TYPE_URL, std::get<packet_storage_projection>(host->capabilities), {}},
		{DPDK_STORAGE_TYPE_URL, std::get<packet_storage_projection>(dpdk->capabilities), FACILITY},
	}};
	EXPECT_TRUE(validate_io_storage_binding(projection, {io_direction::TX, {}, domains}).is_ok());
	domains[0].capabilities.cpu_contiguous_write = false;
	EXPECT_TRUE(validate_io_storage_binding(projection, {io_direction::TX, {}, domains}).is_ok());
	EXPECT_FALSE(validate_io_storage_binding(projection, {io_direction::RX, {}, {domains.data(), 1u}}).is_ok());
	domains[0].capabilities.cpu_contiguous_write = true;
	EXPECT_TRUE(validate_io_storage_binding(projection, {io_direction::RX, {}, {domains.data(), 1u}}).is_ok());
	domains[1].capabilities.cpu_contiguous_read = false;
	EXPECT_FALSE(validate_io_storage_binding(projection, {io_direction::TX, {}, domains}).is_ok());
}

}  // namespace kinetum::provider
