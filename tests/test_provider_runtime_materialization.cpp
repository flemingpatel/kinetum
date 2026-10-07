// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_runtime_materialization.cpp
 * @brief Complete transaction proofs for provider graph materialization.
 * @author Fleming Patel
 *
 * These tests compile one facility-free graph for recoverable rollback, one
 * exact five-role graph for process-facility dependency and fail-stop proofs,
 * and one facility-only worker topology. One hardened seven-contract/five-role
 * component is admitted through the signed installed-provider path before the
 * production materializer is invoked. Exact event bytes prove recoverable
 * factory failure, reverse dependency rollback, cold publication, explicit
 * packet-I/O activation, reverse successful retirement, post-facility
 * fail-stop, and unclassifiable foreign worker-registration fail-stop.
 */

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gen/kinetum/facility/dpdk/v1/dpdk_facility.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "gen/kinetum/io/dpdk/v1/dpdk_driver.pb.h"
#include "gen/kinetum/storage/dpdk/v1/dpdk_storage.pb.h"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/lifecycle/materialized_runtime_service_backend.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_runtime_admission.hpp"
#include "src/provider/provider_runtime_materialization.hpp"
#include "tests/gluon_test_deployment.hpp"
#include "tests/packet_runtime_test_fixture.hpp"
#include "tests/provider_component_test_fixture.hpp"
#include "tests/provider_test_signing_key.hpp"

#if !defined(KINETUM_TEST_PROVIDER_MATERIALIZATION_COMPONENT_PATH)
#error "The exact seven-contract materialization test component path is required"
#endif

namespace kinetum::provider
{
namespace
{

using common::status;
using common::status_or;

/** Environment key carrying the fixture-owned event descriptor. */
constexpr char TRACE_FD_ENVIRONMENT[] = "KINETUM_TEST_MATERIALIZER_TRACE_FD";
/** Environment key selecting a factory-role failure. */
constexpr char FAIL_ROLE_ENVIRONMENT[] = "KINETUM_TEST_MATERIALIZER_FAIL_ROLE";
/** Environment key injecting diagnostic residue into a successful callback. */
constexpr char SUCCESS_DIAGNOSTIC_ENVIRONMENT[] = "KINETUM_TEST_MATERIALIZER_SUCCESS_DIAGNOSTIC";
/** Signed conformance component identity used by materialization tests. */
constexpr char MATERIALIZATION_COMPONENT_ID[] = "kinetum.test.provider.materialization";
/** Compiled process-facility identity in the complete graph. */
constexpr char DPDK_FACILITY_ID[] = "facility_dpdk_0";
/** Compiled native I/O-driver identity in the complete graph. */
constexpr char DPDK_DRIVER_ID[] = "io_dpdk_0";
/** Compiled native storage-domain identity in the complete graph. */
constexpr char DPDK_STORAGE_ID[] = "storage_dpdk_0";
/** Runtime generation shared by every materialized fixture instance. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 17u;
/** @brief Exact storage population for the two-worker boundary-bearing fixture. */
constexpr uint32_t RECOVERABLE_MATERIALIZATION_BUFFER_COUNT = 8'192u;

/**
 * @brief Scope-bound process environment and nonblocking event channel.
 *
 * Google Test runs this executable's test bodies serially. The component reads
 * these variables only inside a factory or lifecycle callback and writes one
 * byte per linear event. Prior process values are restored exactly.
 */
class scoped_materializer_injection final {
    public:
	/**
	 * @brief Install one event descriptor and optional exact failing role.
	 *
	 * @param failing_role Empty for success, otherwise one of S, I, E, or T.
	 * @param success_diagnostic Empty for the ordinary contract, otherwise one
	 *        exact callback identity selected to return forbidden residue.
	 */
	explicit scoped_materializer_injection(std::string_view failing_role, std::string_view success_diagnostic = {})
	{
		if (!failing_role.empty() && failing_role != "S" && failing_role != "I" && failing_role != "E" &&
		    failing_role != "T") {
			throw std::invalid_argument("materializer injection role is outside the exact test set");
		}
		if (!success_diagnostic.empty() && success_diagnostic != "host-proof" &&
		    success_diagnostic != "factory" && success_diagnostic != "worker-registration" &&
		    success_diagnostic != "io-activation" && success_diagnostic != "lifecycle-bind") {
			throw std::invalid_argument(
				"materializer success-diagnostic injection is outside the exact test set");
		}
		remember_environment_(TRACE_FD_ENVIRONMENT, prior_trace_fd_);
		remember_environment_(FAIL_ROLE_ENVIRONMENT, prior_fail_role_);
		remember_environment_(SUCCESS_DIAGNOSTIC_ENVIRONMENT, prior_success_diagnostic_);

		std::array<int, 2> descriptors{-1, -1};
		if (::pipe2(descriptors.data(), O_CLOEXEC | O_NONBLOCK) != 0) {
			throw std::runtime_error("materializer trace pipe creation failed");
		}
		read_descriptor_ = descriptors[0];
		write_descriptor_ = descriptors[1];
		const std::string descriptor_text = std::to_string(write_descriptor_);
		if (::setenv(TRACE_FD_ENVIRONMENT, descriptor_text.c_str(), 1) != 0 ||
		    (failing_role.empty() ?
			     ::unsetenv(FAIL_ROLE_ENVIRONMENT) :
			     ::setenv(FAIL_ROLE_ENVIRONMENT, std::string(failing_role).c_str(), 1)) != 0 ||
		    (success_diagnostic.empty() ? ::unsetenv(SUCCESS_DIAGNOSTIC_ENVIRONMENT) :
						  ::setenv(SUCCESS_DIAGNOSTIC_ENVIRONMENT,
							   std::string(success_diagnostic).c_str(), 1)) != 0) {
			restore_environment_();
			close_descriptors_();
			throw std::runtime_error("materializer injection environment setup failed");
		}
	}

	/** @brief Restore process environment and close both event descriptors. */
	~scoped_materializer_injection()
	{
		restore_environment_();
		close_descriptors_();
	}

	scoped_materializer_injection(const scoped_materializer_injection &) = delete;
	scoped_materializer_injection &operator=(const scoped_materializer_injection &) = delete;
	scoped_materializer_injection(scoped_materializer_injection &&) = delete;
	scoped_materializer_injection &operator=(scoped_materializer_injection &&) = delete;

	/**
	 * @brief Drain every currently published event without waiting.
	 *
	 * @return Exact ordered event bytes or an I/O failure.
	 */
	[[nodiscard]] status_or<std::string> drain() const
	{
		std::string events;
		std::array<char, 64> bytes{};
		for (;;) {
			const ssize_t count = ::read(read_descriptor_, bytes.data(), bytes.size());
			if (count > 0) {
				events.append(bytes.data(), static_cast<std::size_t>(count));
				continue;
			}
			if (count == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
				return events;
			}
			if (errno == EINTR) {
				continue;
			}
			return status::internal_error("materializer trace read failed with errno " +
						      std::to_string(errno));
		}
	}

    private:
	/**
	 * @brief Snapshot one optional process environment value.
	 * @param name NUL-terminated environment key.
	 * @param destination Initially empty optional populated only when the variable exists.
	 */
	static void remember_environment_(const char *name, std::optional<std::string> &destination)
	{
		const char *value = ::getenv(name);
		if (value != nullptr) {
			destination.emplace(value);
		}
	}

	/** @brief Restore both exact prior process environment values. */
	void restore_environment_() const noexcept
	{
		const auto restore = [](const char *name, const std::optional<std::string> &value) {
			if (value.has_value()) {
				(void)::setenv(name, value->c_str(), 1);
			} else {
				(void)::unsetenv(name);
			}
		};
		restore(TRACE_FD_ENVIRONMENT, prior_trace_fd_);
		restore(FAIL_ROLE_ENVIRONMENT, prior_fail_role_);
		restore(SUCCESS_DIAGNOSTIC_ENVIRONMENT, prior_success_diagnostic_);
	}

	/** @brief Close the test channel exactly once. */
	void close_descriptors_() noexcept
	{
		if (read_descriptor_ >= 0) {
			(void)::close(std::exchange(read_descriptor_, -1));
		}
		if (write_descriptor_ >= 0) {
			(void)::close(std::exchange(write_descriptor_, -1));
		}
	}

	int read_descriptor_{-1};			       ///< Nonblocking event consumer.
	int write_descriptor_{-1};			       ///< Descriptor inherited by component callbacks.
	std::optional<std::string> prior_trace_fd_;	       ///< Exact prior descriptor environment value.
	std::optional<std::string> prior_fail_role_;	       ///< Exact prior failure environment value.
	std::optional<std::string> prior_success_diagnostic_;  ///< Exact prior residue selector.
};

/** @brief Canonical plan and compiled topology used by every transaction row. */
struct materialization_compiled_fixture {
	gluon::v1::DeploymentPlan plan;	      ///< Canonical plan retained for identity ownership.
	compiled_provider_topology topology;  ///< Sole provider compiler result.
};

/**
 * @brief Build exact CPU truth for two workers and both lifecycle services.
 *
 * @param numa_node Exact NUMA owner for all four logical CPUs.
 * @return Four disjoint single-NUMA logical CPUs with complete topology.
 */
[[nodiscard]] kinetum::hw::v1::HardwareInventory make_recoverable_materialization_hardware(int32_t numa_node)
{
	kinetum::hw::v1::HardwareInventory hardware;
	auto *node = hardware.mutable_node();
	auto *cpu = node->mutable_cpu();
	for (int32_t core_id = 0; core_id < 4; ++core_id) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(core_id);
		core->set_numa_node(numa_node);
		core->set_is_hyperthread(false);
	}
	return hardware;
}

/**
 * @brief Compile one explicit facility-free graph for recoverable rollback.
 *
 * @return Canonical plan and topology, or the exact planner/compiler failure.
 */
[[nodiscard]] status_or<materialization_compiled_fixture> compile_recoverable_materialization_fixture()
{
	constexpr int32_t TEST_NUMA_NODE = 0;
	auto pipeline = test::packet_runtime_fixture_detail::make_pipeline(std::nullopt);
	if (pipeline.stages_size() != 3) {
		return status::internal_error("materializer test pipeline lost its exact three-stage shape");
	}
	pipeline.mutable_stages(0)->set_preferred_region(0);
	pipeline.mutable_stages(1)->set_preferred_region(1);
	pipeline.mutable_stages(2)->set_preferred_region(1);
	auto bindings_or = test::packet_runtime_fixture_detail::make_bindings(
		pipeline, TEST_NUMA_NODE, 31'001, 31'002, RECOVERABLE_MATERIALIZATION_BUFFER_COUNT, 0, 0);
	if (!bindings_or.is_ok()) {
		return bindings_or.error();
	}
	auto bindings = std::move(bindings_or).value();
	test::add_zero_copy_stage_transition_binding(bindings, "rx_to_parse", "rx", "lane_0", "parse", "lane_0",
						     "storage_host_0");

	gluon::planner_options options;
	options.regions = 2;
	options.reserved_cores = 1;
	options.numa_aware = false;
	options.allowed_numa_nodes = {TEST_NUMA_NODE};
	options.deployment_bindings = std::move(bindings);
	auto planned_or = gluon::plan(pipeline, make_recoverable_materialization_hardware(TEST_NUMA_NODE), options);
	if (!planned_or.is_ok()) {
		return planned_or.error();
	}
	auto plan = std::move(planned_or).value();
	auto topology_or = compile_provider_topology(plan);
	if (!topology_or.is_ok()) {
		return topology_or.error();
	}
	return materialization_compiled_fixture{
		.plan = std::move(plan),
		.topology = std::move(topology_or).value(),
	};
}

/**
 * @brief Build exact synthetic host truth for one two-worker DPDK graph.
 *
 * The two PCI rows are authoring facts only. The admitted test component is
 * inert and invokes no native DPDK mechanism.
 *
 * @return Eight-core single-node hardware with two canonical DPDK ports.
 */
[[nodiscard]] kinetum::hw::v1::HardwareInventory make_dpdk_materialization_hardware()
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
	for (uint8_t index = 0; index < 2; ++index) {
		auto *nic = node->add_nics();
		nic->set_pci_address(index == 0 ? "0000:03:00.0" : "0000:03:00.1");
		nic->set_numa_node(0);
		nic->set_mac_address(index == 0 ? "02:00:00:00:00:01" : "02:00:00:00:00:02");
		nic->set_max_mtu(9000);
		nic->set_driver(kinetum::hw::v1::NIC_DRIVER_DPDK);
	}
	return hardware;
}

/**
 * @brief Author one catalog-valid DPDK facility/driver/storage graph.
 *
 * The base helper supplies complete CPU execution, logical-port, stream, and
 * queue intent. This function replaces only the I/O and storage contracts with
 * exact DPDK records and adds the required cross-worker storage transition.
 *
 * @param pipeline Exact three-stage materializer pipeline.
 * @return Complete five-role deployment intent, or a malformed-fixture status.
 */
[[nodiscard]] status_or<gluon::v1::DeploymentBindings>
make_dpdk_materialization_bindings(const kinetum::axiom::v1::Pipeline &pipeline)
{
	auto bindings = test::make_udp_test_deployment_bindings(pipeline);
	if (bindings.io_driver_instances_size() != 1 || bindings.packet_storage_domains_size() != 1 ||
	    bindings.logical_port_bindings_size() != 2) {
		return status::internal_error("materializer DPDK fixture lost its exact base graph");
	}

	bindings.clear_process_facility_instances();
	kinetum::facility::dpdk::v1::DpdkFacilityConfig facility_configuration;
	auto *facility = bindings.add_process_facility_instances();
	facility->set_facility_instance_id(DPDK_FACILITY_ID);
	facility->mutable_configuration()->PackFrom(facility_configuration);

	kinetum::io::dpdk::v1::DpdkDriverConfig driver_configuration;
	for (const auto &[driver_port_id, pci_address] :
	     {std::pair{"wan0", "0000:03:00.0"}, std::pair{"lan0", "0000:03:00.1"}}) {
		auto *port = driver_configuration.add_ports();
		port->set_driver_port_id(driver_port_id);
		port->mutable_pci()->set_pci_address(pci_address);
	}
	auto *driver = bindings.mutable_io_driver_instances(0);
	driver->set_io_driver_instance_id(DPDK_DRIVER_ID);
	driver->clear_facility_instance_ids();
	driver->add_facility_instance_ids(DPDK_FACILITY_ID);
	driver->mutable_configuration()->PackFrom(driver_configuration);
	for (auto &port : *bindings.mutable_logical_port_bindings()) {
		if (port.logical_name() != "wan0" && port.logical_name() != "lan0") {
			return status::internal_error("materializer DPDK fixture contains an unknown logical port");
		}
		port.set_io_driver_instance_id(DPDK_DRIVER_ID);
		port.set_driver_port_id(port.logical_name());
	}

	kinetum::storage::dpdk::v1::DpdkStorageConfig storage_configuration;
	storage_configuration.set_cache_size(256);
	auto *storage = bindings.mutable_packet_storage_domains(0);
	storage->set_storage_domain_id(DPDK_STORAGE_ID);
	storage->clear_facility_instance_ids();
	storage->add_facility_instance_ids(DPDK_FACILITY_ID);
	storage->mutable_configuration()->PackFrom(storage_configuration);
	for (auto &stream : *bindings.mutable_io_stream_bindings()) {
		for (auto &queue : *stream.mutable_queues()) {
			if (stream.direction() == kinetum::gluon::v1::IO_STREAM_DIRECTION_RX) {
				queue.set_rx_storage_domain_id(DPDK_STORAGE_ID);
			} else {
				queue.mutable_tx_storage()->set_storage_domain_ids(0, DPDK_STORAGE_ID);
			}
		}
	}
	test::add_zero_copy_stage_transition_binding(bindings, "rx_to_parse", "rx", "lane_0", "parse", "lane_0",
						     DPDK_STORAGE_ID);
	return bindings;
}

/**
 * @brief Compile one genuine process-facility plus four-dependent-role graph.
 *
 * @return Canonical plan and topology, or the exact planner/compiler failure.
 */
[[nodiscard]] status_or<materialization_compiled_fixture> compile_complete_materialization_fixture()
{
	auto pipeline = test::packet_runtime_fixture_detail::make_pipeline(std::nullopt);
	if (pipeline.stages_size() != 3) {
		return status::internal_error("materializer DPDK pipeline lost its exact three-stage shape");
	}
	pipeline.mutable_stages(0)->set_preferred_region(0);
	pipeline.mutable_stages(1)->set_preferred_region(1);
	pipeline.mutable_stages(2)->set_preferred_region(1);
	auto bindings_or = make_dpdk_materialization_bindings(pipeline);
	if (!bindings_or.is_ok()) {
		return bindings_or.error();
	}

	gluon::planner_options options;
	options.regions = 2;
	options.reserved_cores = 1;
	options.numa_aware = false;
	options.allowed_numa_nodes = {0};
	options.deployment_bindings = std::move(bindings_or).value();
	auto planned_or = gluon::plan(pipeline, make_dpdk_materialization_hardware(), options);
	if (!planned_or.is_ok()) {
		return planned_or.error();
	}
	auto plan = std::move(planned_or).value();
	auto topology_or = compile_provider_topology(plan);
	if (!topology_or.is_ok()) {
		return topology_or.error();
	}
	return materialization_compiled_fixture{
		.plan = std::move(plan),
		.topology = std::move(topology_or).value(),
	};
}

/**
 * @brief Build one exact worker-owned DPDK process-facility topology.
 *
 * The topology carries only facts consumed by installed-provider admission,
 * process-facility materialization, and compact worker registration. It does
 * not construct a packet graph or invoke a native provider.
 *
 * @return Self-contained facility topology with one compact worker owner.
 */
[[nodiscard]] compiled_provider_topology make_worker_facility_topology()
{
	compiled_provider_topology topology;
	common::compiled_transition_worker worker;
	worker.worker_id = "worker_0";
	worker.worker_index = 0;
	worker.worker_placement_index = 0;
	worker.region_id = 0;
	worker.lane_id = "lane_0";
	worker.lane_index = 0;
	worker.numa_node = 0;
	worker.cpu_core_ids = {0};
	topology.transition_topology.workers.push_back(std::move(worker));

	common::compiled_runtime_service coordinator;
	coordinator.service_id = "transition_coordinator";
	coordinator.service_index = 0;
	coordinator.role = common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR;
	coordinator.cpu_core_id = 1;
	coordinator.numa_node = 0;
	coordinator.command_mailbox_capacity = common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY;
	topology.transition_topology.runtime_services.push_back(std::move(coordinator));

	common::compiled_runtime_service executor;
	executor.service_id = "lifecycle_executor_0";
	executor.service_index = 1;
	executor.role = common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR;
	executor.cpu_core_id = 2;
	executor.numa_node = 0;
	executor.command_mailbox_capacity = 0u;
	topology.transition_topology.runtime_services.push_back(std::move(executor));
	common::compiled_lifecycle_service_topology lifecycle_services;
	lifecycle_services.coordinator_service_index = 0;
	lifecycle_services.lifecycle_executor_service_indices = {1};
	topology.transition_topology.lifecycle_services = std::move(lifecycle_services);

	compiled_process_facility_instance facility;
	facility.facility_instance_id = "dpdk_facility_0";
	facility.facility_index = 0;
	facility.configuration.type_url = std::string(DPDK_FACILITY_TYPE_URL);
	facility.capabilities = process_facility_projection{true, true, true};
	facility.main_core_id = 1;
	facility.cpu_assignments = {
		compiled_facility_cpu_assignment{
			.owner_index = 0,
			.cpu_core_id = 0,
			.numa_node = 0,
			.kind = compiled_facility_cpu_owner_kind::PACKET_WORKER,
		},
		compiled_facility_cpu_assignment{
			.owner_index = 0,
			.cpu_core_id = 1,
			.numa_node = 0,
			.kind = compiled_facility_cpu_owner_kind::TRANSITION_COORDINATOR,
		},
		compiled_facility_cpu_assignment{
			.owner_index = 1,
			.cpu_core_id = 2,
			.numa_node = 0,
			.kind = compiled_facility_cpu_owner_kind::LIFECYCLE_EXECUTOR,
		},
	};
	topology.process_facilities.push_back(std::move(facility));

	topology.host_requirements = {
		compiled_provider_host_requirement{
			.phase = provider_host_proof_phase::COMPONENT_HOST_PROOF,
			.fact = provider_host_fact::DPDK_EAL_RUNTIME,
			.role = provider_contract_role::PROCESS_FACILITY,
			.instance_index = 0,
		},
		compiled_provider_host_requirement{
			.phase = provider_host_proof_phase::COMPONENT_HOST_PROOF,
			.fact = provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR,
			.role = provider_contract_role::PROCESS_FACILITY,
			.instance_index = 0,
		},
	};
	topology.required_contract_type_urls.emplace_back(DPDK_FACILITY_TYPE_URL);
	return topology;
}

/** @brief Installed-component fixture for recoverable and five-role materializer proofs. */
class provider_runtime_materialization_test : public ::testing::Test {
    protected:
	/** @brief Compile both graph shapes and stage one exact seven-contract component. */
	void SetUp() override
	{
		auto recoverable_or = compile_recoverable_materialization_fixture();
		ASSERT_TRUE(recoverable_or.is_ok()) << recoverable_or.error().message();
		recoverable_compiled_.emplace(std::move(recoverable_or).value());
		ASSERT_EQ(recoverable_compiled_->topology.process_facilities.size(), 0u);
		ASSERT_EQ(recoverable_compiled_->topology.storage_domains.size(), 1u);
		ASSERT_EQ(recoverable_compiled_->topology.io_drivers.size(), 1u);
		ASSERT_EQ(recoverable_compiled_->topology.execution_providers.size(), 1u);
		ASSERT_EQ(recoverable_compiled_->topology.storage_transitions.size(), 1u);

		auto complete_or = compile_complete_materialization_fixture();
		ASSERT_TRUE(complete_or.is_ok()) << complete_or.error().message();
		complete_compiled_.emplace(std::move(complete_or).value());
		ASSERT_EQ(complete_compiled_->topology.process_facilities.size(), 1u);
		ASSERT_EQ(complete_compiled_->topology.storage_domains.size(), 1u);
		ASSERT_EQ(complete_compiled_->topology.io_drivers.size(), 1u);
		ASSERT_EQ(complete_compiled_->topology.execution_providers.size(), 1u);
		ASSERT_EQ(complete_compiled_->topology.storage_transitions.size(), 1u);

		const std::filesystem::path source(KINETUM_TEST_PROVIDER_MATERIALIZATION_COMPONENT_PATH);
		const auto staged = provider_fixture_.stage_artifact(source, source.filename().string());
		auto component = provider_fixture_.component_record(
			staged, MATERIALIZATION_COMPONENT_ID,
			{std::string(CPU_EXECUTION_TYPE_URL), std::string(DPDK_FACILITY_TYPE_URL),
			 std::string(DPDK_DRIVER_TYPE_URL), std::string(UDP_DRIVER_TYPE_URL),
			 std::string(DPDK_STORAGE_TYPE_URL), std::string(HOST_STORAGE_TYPE_URL),
			 std::string(ZERO_COPY_SHARE_TYPE_URL)});
		(void)provider_fixture_.write_signed_inventory(provider_fixture_.inventory({component}, {}));
	}

	/**
	 * @brief Admit and materialize the facility-free recoverable graph once.
	 * @return Owned materialized runtime, or the exact admission/materialization failure.
	 */
	[[nodiscard]] status_or<std::unique_ptr<materialized_provider_runtime>> materialize_recoverable_graph()
	{
		if (!recoverable_compiled_.has_value()) {
			return status::failed_precondition("recoverable materializer test fixture was not compiled");
		}
		auto admitted_or = admit_installed_provider_runtime(
			recoverable_compiled_->topology, provider_fixture_.root(), provider_fixture_.runtime_image(),
			test::PROVIDER_TEST_PUBLIC_KEY, provider_fixture_.file_policy());
		if (!admitted_or.is_ok()) {
			return admitted_or.error();
		}
		return materialized_provider_runtime::create(std::move(admitted_or).value(),
							     recoverable_compiled_->topology, TEST_RUNTIME_GENERATION);
	}

	/**
	 * @brief Admit and materialize the complete five-role graph once.
	 * @return Owned materialized runtime, or the exact admission/materialization failure.
	 */
	[[nodiscard]] status_or<std::unique_ptr<materialized_provider_runtime>> materialize_complete_graph()
	{
		if (!complete_compiled_.has_value()) {
			return status::failed_precondition("complete materializer test fixture was not compiled");
		}
		auto admitted_or = admit_installed_provider_runtime(
			complete_compiled_->topology, provider_fixture_.root(), provider_fixture_.runtime_image(),
			test::PROVIDER_TEST_PUBLIC_KEY, provider_fixture_.file_policy());
		if (!admitted_or.is_ok()) {
			return admitted_or.error();
		}
		return materialized_provider_runtime::create(std::move(admitted_or).value(),
							     complete_compiled_->topology, TEST_RUNTIME_GENERATION);
	}

	/**
	 * @brief Admit and materialize the exact worker-owned process facility.
	 * @return Owned materialized runtime, or the exact admission/materialization failure.
	 */
	[[nodiscard]] status_or<std::unique_ptr<materialized_provider_runtime>> materialize_worker_facility()
	{
		auto topology = make_worker_facility_topology();
		auto admitted_or = admit_installed_provider_runtime(topology, provider_fixture_.root(),
								    provider_fixture_.runtime_image(),
								    test::PROVIDER_TEST_PUBLIC_KEY,
								    provider_fixture_.file_policy());
		if (!admitted_or.is_ok()) {
			return admitted_or.error();
		}
		return materialized_provider_runtime::create(std::move(admitted_or).value(), topology,
							     TEST_RUNTIME_GENERATION);
	}

	test::provider_component_test_fixture provider_fixture_;  ///< Signed fixed installation authority.
	std::optional<materialization_compiled_fixture> recoverable_compiled_;	///< Facility-free graph authority.
	std::optional<materialization_compiled_fixture> complete_compiled_;	///< Exact five-role graph authority.
};

/** @brief A first-role failure publishes no owner and needs no rollback. */
TEST_F(provider_runtime_materialization_test, storage_failure_returns_without_partial_ownership)
{
	scoped_materializer_injection injection("S");
	auto runtime_or = materialize_recoverable_graph();
	ASSERT_FALSE(runtime_or.is_ok());
	EXPECT_EQ(runtime_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto events_or = injection.drain();
	ASSERT_TRUE(events_or.is_ok()) << events_or.error().message();
	EXPECT_EQ(events_or.value(), "S");
}

/** @brief An I/O failure destroys the already-published storage owner. */
TEST_F(provider_runtime_materialization_test, io_failure_rolls_back_storage_in_reverse_order)
{
	scoped_materializer_injection injection("I");
	auto runtime_or = materialize_recoverable_graph();
	ASSERT_FALSE(runtime_or.is_ok());
	EXPECT_EQ(runtime_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto events_or = injection.drain();
	ASSERT_TRUE(events_or.is_ok()) << events_or.error().message();
	EXPECT_EQ(events_or.value(), "SIs");
}

/** @brief An execution failure retires the I/O and storage prefix exactly. */
TEST_F(provider_runtime_materialization_test, execution_failure_rolls_back_complete_prefix)
{
	scoped_materializer_injection injection("E");
	auto runtime_or = materialize_recoverable_graph();
	ASSERT_FALSE(runtime_or.is_ok());
	EXPECT_EQ(runtime_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto events_or = injection.drain();
	ASSERT_TRUE(events_or.is_ok()) << events_or.error().message();
	EXPECT_EQ(events_or.value(), "SIEis");
}

/** @brief A final-role failure retires every earlier role and never activates I/O. */
TEST_F(provider_runtime_materialization_test, transition_failure_rolls_back_every_dependency_without_activation)
{
	scoped_materializer_injection injection("T");
	auto runtime_or = materialize_recoverable_graph();
	ASSERT_FALSE(runtime_or.is_ok());
	EXPECT_EQ(runtime_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto events_or = injection.drain();
	ASSERT_TRUE(events_or.is_ok()) << events_or.error().message();
	EXPECT_EQ(events_or.value(), "SIETeis");
}

/** @brief A successful host proof with diagnostic residue fails stop after component loading. */
TEST_F(provider_runtime_materialization_test, host_proof_success_rejects_diagnostic_residue)
{
	scoped_materializer_injection injection("", "host-proof");
	EXPECT_DEATH(
		{
			auto runtime_or = materialize_recoverable_graph();
			(void)runtime_or;
		},
		"");
	auto events_or = injection.drain();
	ASSERT_TRUE(events_or.is_ok()) << events_or.error().message();
	EXPECT_EQ(events_or.value(), "H");
}

/** @brief A successful factory with diagnostic residue reclaims its unpublished instance. */
TEST_F(provider_runtime_materialization_test, factory_success_rejects_residue_without_leaking_ownership)
{
	scoped_materializer_injection injection("", "factory");
	auto runtime_or = materialize_recoverable_graph();
	ASSERT_FALSE(runtime_or.is_ok());
	EXPECT_EQ(runtime_or.error().code(), common::status_code::INTERNAL_ERROR);
	auto events_or = injection.drain();
	ASSERT_TRUE(events_or.is_ok()) << events_or.error().message();
	EXPECT_EQ(events_or.value(), "Ss");
}

/** @brief Five-role publication validates dependencies, stays cold, and retires in reverse. */
TEST_F(provider_runtime_materialization_test, complete_five_role_graph_activates_once_and_retires_in_reverse_order)
{
	scoped_materializer_injection injection("");
	auto runtime_or = materialize_complete_graph();
	ASSERT_TRUE(runtime_or.is_ok()) << runtime_or.error().message();
	auto runtime = std::move(runtime_or).value();
	ASSERT_NE(runtime->process_facility(0), nullptr);
	ASSERT_NE(runtime->storage_domain(0), nullptr);
	ASSERT_NE(runtime->io_driver(0), nullptr);
	ASSERT_NE(runtime->execution_provider(0), nullptr);
	ASSERT_NE(runtime->storage_transition(0), nullptr);

	auto materialized_events_or = injection.drain();
	ASSERT_TRUE(materialized_events_or.is_ok()) << materialized_events_or.error().message();
	EXPECT_EQ(materialized_events_or.value(), "FSIET");
	ASSERT_TRUE(runtime->activate_packet_io().is_ok());
	ASSERT_TRUE(runtime->deactivate_packet_io().is_ok());
	runtime.reset();
	auto retired_events_or = injection.drain();
	ASSERT_TRUE(retired_events_or.is_ok()) << retired_events_or.error().message();
	EXPECT_EQ(retired_events_or.value(), "ADteisf");
}

/** @brief Successful I/O activation with diagnostic residue cannot be reclassified as recoverable. */
TEST_F(provider_runtime_materialization_test, io_activation_success_rejects_diagnostic_residue)
{
	scoped_materializer_injection injection("", "io-activation");
	auto runtime_or = materialize_complete_graph();
	ASSERT_TRUE(runtime_or.is_ok()) << runtime_or.error().message();
	auto runtime = std::move(runtime_or).value();
	auto materialized_events_or = injection.drain();
	ASSERT_TRUE(materialized_events_or.is_ok()) << materialized_events_or.error().message();
	EXPECT_EQ(materialized_events_or.value(), "FSIET");

	EXPECT_DEATH((void)runtime->activate_packet_io(), "");
	auto activation_events_or = injection.drain();
	ASSERT_TRUE(activation_events_or.is_ok()) << activation_events_or.error().message();
	EXPECT_EQ(activation_events_or.value(), "A");

	runtime.reset();
	auto retired_events_or = injection.drain();
	ASSERT_TRUE(retired_events_or.is_ok()) << retired_events_or.error().message();
	EXPECT_EQ(retired_events_or.value(), "teisf");
}

/** @brief Successful lifecycle binding with diagnostic residue fails stop at its ownership edge. */
TEST_F(provider_runtime_materialization_test, lifecycle_bind_success_rejects_diagnostic_residue)
{
	scoped_materializer_injection injection("", "lifecycle-bind");
	auto runtime_or = materialize_complete_graph();
	ASSERT_TRUE(runtime_or.is_ok()) << runtime_or.error().message();
	auto runtime = std::move(runtime_or).value();
	auto backend_or = kinetum::dp::lifecycle::materialized_runtime_service_backend::create(
		complete_compiled_->topology, *runtime);
	ASSERT_TRUE(backend_or.is_ok()) << backend_or.error().message();
	auto backend = std::move(backend_or).value();
	ASSERT_TRUE(complete_compiled_->topology.transition_topology.lifecycle_services.has_value());
	const uint32_t coordinator_index =
		complete_compiled_->topology.transition_topology.lifecycle_services->coordinator_service_index;
	ASSERT_LT(coordinator_index, complete_compiled_->topology.transition_topology.runtime_services.size());
	const auto &coordinator = complete_compiled_->topology.transition_topology.runtime_services[coordinator_index];
	auto materialized_events_or = injection.drain();
	ASSERT_TRUE(materialized_events_or.is_ok()) << materialized_events_or.error().message();
	EXPECT_EQ(materialized_events_or.value(), "FSIET");

	EXPECT_DEATH((void)backend->bind_coordinator(coordinator), "");
	auto callback_events_or = injection.drain();
	ASSERT_TRUE(callback_events_or.is_ok()) << callback_events_or.error().message();
	EXPECT_EQ(callback_events_or.value(), "B");

	backend.reset();
	runtime.reset();
	auto retired_events_or = injection.drain();
	ASSERT_TRUE(retired_events_or.is_ok()) << retired_events_or.error().message();
	EXPECT_EQ(retired_events_or.value(), "teisf");
}

/** @brief A downstream failure after facility ownership destroys the exact prefix and fails stop. */
TEST_F(provider_runtime_materialization_test, post_facility_storage_failure_retires_exact_owner_and_fails_stop)
{
	scoped_materializer_injection injection("S");
	EXPECT_DEATH(
		{
			auto runtime_or = materialize_complete_graph();
			(void)runtime_or;
		},
		"");
	auto events_or = injection.drain();
	ASSERT_TRUE(events_or.is_ok()) << events_or.error().message();
	EXPECT_EQ(events_or.value(), "FSf");
}

/** @brief An out-of-domain registration result cannot return an uncertain process. */
TEST_F(provider_runtime_materialization_test, invalid_worker_registration_status_fails_stop_without_rollback)
{
	scoped_materializer_injection injection("");
	auto runtime_or = materialize_worker_facility();
	ASSERT_TRUE(runtime_or.is_ok()) << runtime_or.error().message();
	auto runtime = std::move(runtime_or).value();
	ASSERT_NE(runtime->process_facility(0), nullptr);

	auto materialized_events_or = injection.drain();
	ASSERT_TRUE(materialized_events_or.is_ok()) << materialized_events_or.error().message();
	EXPECT_EQ(materialized_events_or.value(), "F");
	EXPECT_DEATH((void)runtime->register_worker_thread(0), "");
	auto registration_events_or = injection.drain();
	ASSERT_TRUE(registration_events_or.is_ok()) << registration_events_or.error().message();
	EXPECT_EQ(registration_events_or.value(), "R");

	runtime.reset();
	auto retired_events_or = injection.drain();
	ASSERT_TRUE(retired_events_or.is_ok()) << retired_events_or.error().message();
	EXPECT_EQ(retired_events_or.value(), "f");
}

/** @brief Successful worker registration with residue is unregistered and returned as failure. */
TEST_F(provider_runtime_materialization_test, worker_registration_success_rejects_diagnostic_residue)
{
	scoped_materializer_injection injection("", "worker-registration");
	auto runtime_or = materialize_worker_facility();
	ASSERT_TRUE(runtime_or.is_ok()) << runtime_or.error().message();
	auto runtime = std::move(runtime_or).value();
	auto materialized_events_or = injection.drain();
	ASSERT_TRUE(materialized_events_or.is_ok()) << materialized_events_or.error().message();
	EXPECT_EQ(materialized_events_or.value(), "F");

	const auto registered = runtime->register_worker_thread(0);
	EXPECT_EQ(registered.code(), common::status_code::INTERNAL_ERROR);
	auto registration_events_or = injection.drain();
	ASSERT_TRUE(registration_events_or.is_ok()) << registration_events_or.error().message();
	EXPECT_EQ(registration_events_or.value(), "RU");

	runtime.reset();
	auto retired_events_or = injection.drain();
	ASSERT_TRUE(retired_events_or.is_ok()) << retired_events_or.error().message();
	EXPECT_EQ(retired_events_or.value(), "f");
}

}  // namespace
}  // namespace kinetum::provider
