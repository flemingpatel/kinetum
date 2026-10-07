// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_runtime_test_fixture.hpp
 * @brief Production-shaped packet-runtime and coordinator test ownership.
 * @author Fleming Patel
 *
 * The fixture authors one explicit UDP/host/CPU provider graph against live
 * process-available CPU and NUMA facts, compiles it through Gluon and the sole
 * provider compiler, admits the real host and UDP components through a
 * test-signed fixed installation, and constructs one complete CONTROL_READY
 * generation. It also owns the canonical six-field bootstrap request for the
 * exact emitted plan. No production default, provider inference, or test-only
 * runtime constructor is introduced.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/gluon/gluon_planner.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/deployment_plan_identity.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/provider/provider_runtime_admission.hpp"
#include "src/quark/host_probe.hpp"
#include "src/quark/runtime_compat.hpp"
#include "src/dp/packet_runtime_generation.hpp"
#include "src/dp/epoch/epoch_transition_command_mailbox.hpp"
#include "src/dp/partitioned_runtime.hpp"
#include "tests/gluon_test_deployment.hpp"
#include "tests/provider_component_test_fixture.hpp"
#include "tests/provider_test_signing_key.hpp"
#include "tests/thread_affinity_test_guard.hpp"

#if !defined(KINETUM_PROVIDER_HOST_COMPONENT_PATH) || !defined(KINETUM_PROVIDER_UDP_COMPONENT_PATH)
#error "Exact host and UDP provider-component paths are required"
#endif

namespace kinetum::test
{

/** @brief Exact test-authored transition timing used before plan re-finalization. */
struct packet_runtime_test_transition_timing {
	uint64_t prepare_timeout_ms{0};		///< Abortable PREPARE timeout.
	uint64_t prepare_cancel_grace_ms{0};	///< Cooperative callback-return grace.
	uint64_t prepared_lease_timeout_ms{0};	///< PREPARED pre-commit lease.
	uint64_t commit_timeout_ms{0};		///< Completion-only commit budget.
	uint64_t retirement_timeout_ms{0};	///< Reader/callback retirement budget.
};

/** @brief Exact test-authored same-domain execution-owner handoff. */
struct packet_runtime_test_zero_copy_transition {
	std::string_view transition_id{};      ///< Exact transition identity.
	std::string_view from_stage_id{};      ///< Source logical-stage identity.
	std::string_view from_lane_id{};       ///< Source execution-lane identity.
	std::string_view to_stage_id{};	       ///< Destination logical-stage identity.
	std::string_view to_lane_id{};	       ///< Destination execution-lane identity.
	std::string_view storage_domain_id{};  ///< Exact domain retained across the handoff.

	/** @return true only when every borrowed authoring identity is nonempty. */
	[[nodiscard]] constexpr bool valid() const noexcept
	{
		return !transition_id.empty() && !from_stage_id.empty() && !from_lane_id.empty() &&
		       !to_stage_id.empty() && !to_lane_id.empty() && !storage_domain_id.empty();
	}
};

namespace packet_runtime_fixture_detail
{

/** @brief Coordinator, lifecycle-executor, and one packet-worker fixture core count. */
constexpr std::size_t TEST_RUNTIME_CORE_COUNT = 3u;
/** @brief Exact nonzero runtime generation used by fixture construction. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 1u;
/** @brief Exact nonzero deterministic bootstrap request identity. */
constexpr uint64_t TEST_BOOTSTRAP_IDENTITY = 1u;
/** @brief Exact RX and TX descriptor population authored by the fixture. */
constexpr uint32_t TEST_RUNTIME_DESCRIPTOR_COUNT = 64u;
/** @brief Exact host-storage population authored by the fixture. */
constexpr uint32_t TEST_RUNTIME_BUFFER_COUNT = 4096u;
/** @brief Maximum UDP payload representable by one IPv4 datagram. */
constexpr std::size_t MAX_UDP_DATAGRAM_BYTES = 65507u;
/** @brief Bounded fresh-port attempts for the non-atomic test-only RX handoff. */
constexpr std::size_t MAX_UDP_RX_HANDOFF_ATTEMPTS = 8u;
/** @brief Exact provider diagnostic identifying only an RX bind collision. */
constexpr char UDP_RX_HANDOFF_COLLISION_DIAGNOSTIC[] = "UDP RX endpoint is already reserved";

/**
 * @brief Classify the sole retryable UDP reservation handoff race.
 *
 * @param failure Exact failed runtime-construction status.
 * @return true only for the provider's typed EADDRINUSE projection.
 */
[[nodiscard]] inline bool is_udp_rx_handoff_collision(const common::status &failure) noexcept
{
	return failure.code() == common::status_code::FAILED_PRECONDITION &&
	       failure.message().ends_with(UDP_RX_HANDOFF_COLLISION_DIAGNOSTIC);
}

/** @brief One exact same-NUMA CPU subset selected from live host truth. */
struct host_selection {
	int32_t numa_node{-1};		 ///< Exact host-memory and CPU NUMA identity.
	std::vector<int32_t> cpu_cores;	 ///< Coordinator, executor, and worker candidates.
};

/**
 * @brief Select the lowest usable same-NUMA process-core subset.
 *
 * @param host Immutable process-available host topology.
 * @param required_core_count Exact same-NUMA process core population.
 * @return Exact selection, or UNAVAILABLE when the test host cannot run a
 *         production-shaped packet-runtime generation.
 */
[[nodiscard]] inline common::status_or<host_selection>
select_host(const quark::host_topology &host, std::size_t required_core_count = TEST_RUNTIME_CORE_COUNT)
{
	if (!host.valid || !host.has_complete_numa_topology() || required_core_count == 0u ||
	    required_core_count > static_cast<std::size_t>(std::numeric_limits<int32_t>::max())) {
		return common::status::unavailable(
			"packet-runtime test requires complete process-available CPU/NUMA topology and a valid core count");
	}
	for (const int32_t numa_node : host.memory_numa_nodes) {
		host_selection selection;
		selection.numa_node = numa_node;
		selection.cpu_cores.reserve(required_core_count);
		for (const auto &cpu : host.cpus) {
			if (cpu.numa_node != numa_node) {
				continue;
			}
			selection.cpu_cores.push_back(cpu.core_id);
			if (selection.cpu_cores.size() == required_core_count) {
				return selection;
			}
		}
	}
	return common::status::unavailable(
		"packet-runtime test requires the requested process CPUs on one allocatable NUMA node");
}

/**
 * @brief Project one live CPU selection into deterministic planner inventory.
 *
 * @param selection Exact same-NUMA host selection.
 * @return Hardware inventory containing only the selected authorized test cores.
 */
[[nodiscard]] inline kinetum::hw::v1::HardwareInventory make_hardware_inventory(const host_selection &selection)
{
	kinetum::hw::v1::HardwareInventory hardware;
	auto *node = hardware.mutable_node();
	auto *cpu = node->mutable_cpu();
	for (const int32_t cpu_core : selection.cpu_cores) {
		auto *core = cpu->add_core_topology();
		core->set_core_id(cpu_core);
		core->set_numa_node(selection.numa_node);
		core->set_is_hyperthread(false);
	}
	return hardware;
}

/**
 * @brief Build the exact passive fixture pipeline.
 *
 * @param module Optional exact module identity inserted between parse and TX.
 * @return RX-to-parse-to-TX pipeline, with the authored module when present.
 */
[[nodiscard]] inline kinetum::axiom::v1::Pipeline make_pipeline(const std::optional<std::string> &module)
{
	kinetum::axiom::v1::Pipeline pipeline;
	pipeline.set_pipeline_id("packet_runtime_fixture");
	auto *rx = pipeline.add_stages();
	rx->set_stage_id("rx");
	rx->set_kind(kinetum::axiom::v1::STAGE_KIND_RX);
	rx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	rx->mutable_io()->set_interface("wan0");
	auto *parse = pipeline.add_stages();
	parse->set_stage_id("parse");
	parse->set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	parse->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	if (module.has_value()) {
		auto *module_stage = pipeline.add_stages();
		module_stage->set_stage_id("module");
		module_stage->set_kind(kinetum::axiom::v1::STAGE_KIND_MODULE);
		module_stage->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
		module_stage->mutable_module()->set_module_id(module.value());
		module_stage->mutable_module()->set_context_selection(
			kinetum::axiom::v1::MODULE_CONTEXT_SELECTION_SAME_LANE);
	}
	auto *tx = pipeline.add_stages();
	tx->set_stage_id("tx");
	tx->set_kind(kinetum::axiom::v1::STAGE_KIND_TX);
	tx->set_execution_mode(kinetum::axiom::v1::EXECUTION_MODE_PASSIVE);
	tx->mutable_io()->set_interface("lan0");
	auto *rx_to_parse = pipeline.add_edges();
	rx_to_parse->set_from_stage_id("rx");
	rx_to_parse->set_to_stage_id("parse");
	rx_to_parse->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	auto *parse_to_tx = pipeline.add_edges();
	parse_to_tx->set_from_stage_id("parse");
	parse_to_tx->set_to_stage_id(module.has_value() ? "module" : "tx");
	parse_to_tx->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	if (module.has_value()) {
		auto *module_to_tx = pipeline.add_edges();
		module_to_tx->set_from_stage_id("module");
		module_to_tx->set_to_stage_id("tx");
		module_to_tx->set_mode(kinetum::axiom::v1::EDGE_MODE_PUSH);
	}
	return pipeline;
}

/** @brief Linear owner for one temporarily reserved loopback UDP port. */
class udp_port_reservation final {
    public:
	/** @brief Live UDP reservations cannot be copied. */
	udp_port_reservation(const udp_port_reservation &) = delete;
	/** @brief Live UDP reservations cannot be copy-assigned. */
	udp_port_reservation &operator=(const udp_port_reservation &) = delete;

	/**
	 * @brief Transfer an exact live reservation.
	 *
	 * @param other Sole source reservation, left empty after transfer.
	 */
	udp_port_reservation(udp_port_reservation &&other) noexcept
		: descriptor_(std::exchange(other.descriptor_, -1))
		, port_(std::exchange(other.port_, 0))
	{
	}

	/** @brief Live UDP reservations cannot be replaced after construction. */
	udp_port_reservation &operator=(udp_port_reservation &&) = delete;

	/** @brief Release a reservation left live by an earlier fixture failure. */
	~udp_port_reservation()
	{
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
	}

	/**
	 * @brief Reserve one kernel-selected IPv4 loopback datagram port.
	 *
	 * @return Live reservation or the exact socket/bind/identity failure.
	 */
	[[nodiscard]] static common::status_or<udp_port_reservation> create()
	{
		const int descriptor = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (descriptor < 0) {
			return common::status::resource_exhausted(
				"packet-runtime fixture could not create a UDP reservation socket");
		}
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		address.sin_port = htons(0);
		if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
			const int saved_errno = errno;
			(void)::close(descriptor);
			return common::status::resource_exhausted(
				"packet-runtime fixture UDP reservation bind failed with errno " +
				std::to_string(saved_errno));
		}
		socklen_t length = static_cast<socklen_t>(sizeof(address));
		if (::getsockname(descriptor, reinterpret_cast<sockaddr *>(&address), &length) != 0 ||
		    length != static_cast<socklen_t>(sizeof(address)) || address.sin_port == 0) {
			const int saved_errno = errno;
			(void)::close(descriptor);
			return common::status::internal_error(
				"packet-runtime fixture UDP reservation identity failed with errno " +
				std::to_string(saved_errno));
		}
		return udp_port_reservation(descriptor, ntohs(address.sin_port));
	}

	/** @return Exact reserved host-order port. */
	[[nodiscard]] uint16_t port() const noexcept
	{
		return port_;
	}

	/**
	 * @brief Receive one bounded datagram from a retained destination endpoint.
	 *
	 * @param maximum_bytes Nonzero receive bound no larger than one IPv4 UDP datagram.
	 * @param timeout_ms Nonnegative bounded poll timeout.
	 * @return Exact received bytes, or a bounded socket/poll status.
	 */
	[[nodiscard]] common::status_or<std::vector<uint8_t>> receive_datagram(std::size_t maximum_bytes,
									       int timeout_ms) const
	{
		if (descriptor_ < 0 || maximum_bytes == 0u || maximum_bytes > MAX_UDP_DATAGRAM_BYTES ||
		    timeout_ms < 0) {
			return common::status::invalid_argument(
				"packet-runtime fixture receive contract is incomplete");
		}
		pollfd descriptor_event{
			.fd = descriptor_,
			.events = POLLIN,
			.revents = 0,
		};
		const int poll_result = ::poll(&descriptor_event, 1, timeout_ms);
		const int poll_errno = errno;
		if (poll_result == 0) {
			return common::status::unavailable(
				"packet-runtime fixture timed out waiting for exact TX output");
		}
		if (poll_result < 0) {
			return common::status::internal_error("packet-runtime fixture TX sink poll failed with errno " +
							      std::to_string(poll_errno));
		}
		if ((descriptor_event.revents & POLLIN) == 0 ||
		    (descriptor_event.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			return common::status::internal_error(
				"packet-runtime fixture TX sink returned invalid poll events " +
				std::to_string(static_cast<unsigned int>(descriptor_event.revents)));
		}
		try {
			std::vector<uint8_t> bytes(maximum_bytes);
			const ssize_t received = ::recv(descriptor_, bytes.data(), bytes.size(), MSG_DONTWAIT);
			if (received < 0) {
				return common::status::internal_error(
					"packet-runtime fixture TX sink receive failed with errno " +
					std::to_string(errno));
			}
			bytes.resize(static_cast<std::size_t>(received));
			return bytes;
		} catch (const std::bad_alloc &) {
			return common::status::resource_exhausted(
				"packet-runtime fixture TX receive allocation failed");
		}
	}

	/**
	 * @brief Release the reservation immediately before provider materialization.
	 *
	 * @return OK after exact close, or a failed-precondition/close status.
	 */
	[[nodiscard]] common::status release() noexcept
	{
		if (descriptor_ < 0) {
			return common::status::failed_precondition(common::static_status_text(
				"packet-runtime fixture UDP reservation was already released"));
		}
		const int descriptor = std::exchange(descriptor_, -1);
		port_ = 0;
		if (::close(descriptor) != 0) {
			return common::status::internal_error(
				common::static_status_text("packet-runtime fixture UDP reservation close failed"));
		}
		return common::status::ok();
	}

    private:
	/**
	 * @brief Adopt one bound reservation descriptor and port.
	 *
	 * @param descriptor Sole bound socket descriptor.
	 * @param port Exact reserved host-order port.
	 */
	udp_port_reservation(int descriptor, uint16_t port) noexcept
		: descriptor_(descriptor)
		, port_(port)
	{
	}

	int descriptor_{-1};  ///< Exact bound socket descriptor.
	uint16_t port_{0};    ///< Exact reserved host-order port.
};

/**
 * @brief Author exact host NUMA and collision-free UDP attachment facts.
 *
 * @param pipeline Exact fixture pipeline.
 * @param host_numa_node Exact host-memory NUMA identity.
 * @param rx_port Reserved RX endpoint port.
 * @param tx_port Reserved TX destination port.
 * @param buffer_count Exact nonzero packet-storage population.
 * @param context_memory_capacity_bytes Explicit module context-lifetime bound,
 *        or zero only when the pipeline contains no module stage.
 * @param epoch_arena_capacity_bytes Explicit module per-epoch arena bound, or
 *        zero only when the pipeline contains no module stage.
 * @param authored_bindings Optional complete provider intent before host/endpoint placement.
 * @return Complete deployment bindings, or a malformed-fixture status.
 */
[[nodiscard]] inline common::status_or<kinetum::gluon::v1::DeploymentBindings>
make_bindings(const kinetum::axiom::v1::Pipeline &pipeline, int32_t host_numa_node, uint16_t rx_port, uint16_t tx_port,
	      uint32_t buffer_count, uint64_t context_memory_capacity_bytes, uint64_t epoch_arena_capacity_bytes,
	      const kinetum::gluon::v1::DeploymentBindings *authored_bindings = nullptr)
{
	const auto module_count =
		std::count_if(pipeline.stages().begin(), pipeline.stages().end(),
			      [](const auto &stage) { return stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE; });
	if (host_numa_node < 0) {
		return common::status::invalid_argument(
			"packet-runtime fixture host NUMA identity must be nonnegative");
	}
	if (buffer_count == 0u) {
		return common::status::invalid_argument(
			"packet-runtime fixture packet-storage population must be nonzero");
	}
	if ((module_count == 0 && (context_memory_capacity_bytes != 0u || epoch_arena_capacity_bytes != 0u)) ||
	    (module_count != 0 && (context_memory_capacity_bytes == 0u || epoch_arena_capacity_bytes == 0u))) {
		return common::status::invalid_argument(
			"packet-runtime fixture module stage and explicit memory contract disagree");
	}
	auto bindings = authored_bindings != nullptr ? *authored_bindings : make_udp_test_deployment_bindings(pipeline);
	if (bindings.packet_storage_domains_size() == 0 || bindings.io_driver_instances_size() != 1) {
		return common::status::internal_error(
			"packet-runtime fixture base bindings lost exact storage or driver ownership");
	}
	for (auto &storage : *bindings.mutable_packet_storage_domains()) {
		storage.set_host_numa_node(host_numa_node);
		storage.set_buffer_count(buffer_count);
	}
	for (auto &transition : *bindings.mutable_storage_transition_bindings()) {
		if (transition.has_staging_numa_node()) {
			transition.set_staging_numa_node(host_numa_node);
		}
	}
	for (auto &stream : *bindings.mutable_io_stream_bindings()) {
		for (auto &queue : *stream.mutable_queues()) {
			queue.set_descriptor_count(TEST_RUNTIME_DESCRIPTOR_COUNT);
		}
	}
	if (context_memory_capacity_bytes != 0u || epoch_arena_capacity_bytes != 0u) {
		for (const auto &stage : pipeline.stages()) {
			if (stage.kind() == kinetum::axiom::v1::STAGE_KIND_MODULE) {
				add_module_context_resource_binding(bindings, stage.stage_id(), "lane_0",
								    context_memory_capacity_bytes,
								    epoch_arena_capacity_bytes);
			}
		}
	}

	kinetum::io::udp::v1::UdpDriverConfig driver;
	if (!bindings.io_driver_instances(0).configuration().UnpackTo(&driver) || driver.ports_size() < 2) {
		return common::status::internal_error("packet-runtime fixture base UDP configuration is malformed");
	}
	bool found_rx = false;
	bool found_tx = false;
	for (auto &port : *driver.mutable_ports()) {
		const auto binding = std::find_if(bindings.logical_port_bindings().begin(),
						  bindings.logical_port_bindings().end(), [&](const auto &candidate) {
							  return candidate.driver_port_id() == port.driver_port_id();
						  });
		if (binding == bindings.logical_port_bindings().end()) {
			return common::status::invalid_argument("fixture UDP port has no logical binding");
		}
		if (binding->direction() == kinetum::gluon::v1::PORT_DIRECTION_RX_ONLY &&
		    port.driver_port_id() == "wan0" && !found_rx) {
			port.set_port(rx_port);
			found_rx = true;
		} else if (binding->direction() == kinetum::gluon::v1::PORT_DIRECTION_TX_ONLY) {
			port.set_port(tx_port);
			found_tx = true;
		} else {
			return common::status::invalid_argument("fixture requires one wan0 RX and explicit TX ports");
		}
	}
	if (!found_rx || !found_tx || rx_port == 0 || tx_port == 0 || rx_port == tx_port) {
		return common::status::internal_error(
			"packet-runtime fixture lacks distinct exact UDP endpoint ownership");
	}
	bindings.mutable_io_driver_instances(0)->mutable_configuration()->PackFrom(driver);
	return bindings;
}

/** @brief Canonical plan and sole compiled artifact for one fixture graph. */
struct compiled_runtime_fixture {
	kinetum::gluon::v1::DeploymentPlan plan;	///< Canonical plan with final content identity.
	provider::compiled_provider_topology topology;	///< Sole compiler output derived from plan.
};

/**
 * @brief Lower and compile one explicit logical fixture graph.
 *
 * The caller owns endpoint reservation lifetime. This helper performs no
 * provider admission or materialization and therefore remains suitable for
 * exact pre-side-effect compiler and module-generation tests.
 *
 * @param pipeline Complete logical packet graph.
 * @param selection Exact live same-NUMA CPU selection.
 * @param rx_port Reserved nonzero RX endpoint.
 * @param tx_port Reserved distinct nonzero TX endpoint.
 * @param context_memory_capacity_bytes Exact module context-lifetime bound, or
 *        zero for a module-free graph.
 * @param epoch_arena_capacity_bytes Exact per-epoch module arena bound, or zero
 *        for a module-free graph.
 * @param transition_timing Optional exact test-authored timing re-finalized
 *        into plan identity before the sole runtime compiler consumes it.
 * @param region_count Exact positive logical region count requested from Gluon.
 * @param buffer_count Exact packet-storage population authored into bindings.
 * @param zero_copy_transitions Exact caller-authored same-domain owner
 *        handoffs; borrowed strings must remain live for this call.
 * @param authored_bindings Optional complete provider intent, consumed by the real planner.
 * @return Canonical plan and its sole compiled provider topology.
 */
[[nodiscard]] inline common::status_or<compiled_runtime_fixture>
compile_runtime_fixture(const kinetum::axiom::v1::Pipeline &pipeline, const host_selection &selection, uint16_t rx_port,
			uint16_t tx_port, uint64_t context_memory_capacity_bytes, uint64_t epoch_arena_capacity_bytes,
			const std::optional<packet_runtime_test_transition_timing> &transition_timing = std::nullopt,
			std::size_t region_count = 1u, uint32_t buffer_count = TEST_RUNTIME_BUFFER_COUNT,
			std::span<const packet_runtime_test_zero_copy_transition> zero_copy_transitions = {},
			const kinetum::gluon::v1::DeploymentBindings *authored_bindings = nullptr)
{
	if (region_count == 0u || region_count > static_cast<std::size_t>(std::numeric_limits<int32_t>::max())) {
		return common::status::invalid_argument("packet-runtime fixture region count is outside int32");
	}
	auto bindings_or = make_bindings(pipeline, selection.numa_node, rx_port, tx_port, buffer_count,
					 context_memory_capacity_bytes, epoch_arena_capacity_bytes, authored_bindings);
	if (!bindings_or.is_ok()) {
		return bindings_or.error();
	}
	auto bindings = std::move(bindings_or).value();
	for (const auto &transition : zero_copy_transitions) {
		if (!transition.valid()) {
			return common::status::invalid_argument(
				"packet-runtime fixture zero-copy transition identity is incomplete");
		}
		add_zero_copy_stage_transition_binding(bindings, transition.transition_id, transition.from_stage_id,
						       transition.from_lane_id, transition.to_stage_id,
						       transition.to_lane_id, transition.storage_domain_id);
	}

	gluon::planner_options options;
	options.regions = static_cast<int>(region_count);
	options.reserved_cores = 1;
	options.numa_aware = false;
	options.allowed_numa_nodes = {selection.numa_node};
	options.deployment_bindings = std::move(bindings);
	auto planned_or = gluon::plan(pipeline, make_hardware_inventory(selection), options);
	if (!planned_or.is_ok()) {
		return planned_or.error();
	}
	auto plan = std::move(planned_or).value();
	if (transition_timing.has_value()) {
		auto *policy = plan.mutable_epoch_transition_plan();
		policy->set_prepare_timeout_ms(transition_timing->prepare_timeout_ms);
		policy->set_prepare_cancel_grace_ms(transition_timing->prepare_cancel_grace_ms);
		policy->set_prepared_lease_timeout_ms(transition_timing->prepared_lease_timeout_ms);
		policy->set_commit_timeout_ms(transition_timing->commit_timeout_ms);
		policy->set_retirement_timeout_ms(transition_timing->retirement_timeout_ms);
		plan.clear_content_hash();
		const auto finalized = provider::finalize_deployment_plan_identity(&plan);
		if (!finalized.is_ok()) {
			return finalized;
		}
	}
	auto topology_or = provider::compile_provider_topology(plan);
	if (!topology_or.is_ok()) {
		return topology_or.error();
	}
	return compiled_runtime_fixture{
		.plan = std::move(plan),
		.topology = std::move(topology_or).value(),
	};
}

/**
 * @brief Stage and sign the two real components required by the fixture plan.
 *
 * @param fixture Fixed installed-provider test root.
 * @return OK after canonical inventory publication.
 */
[[nodiscard]] inline common::status stage_provider_inventory(provider_component_test_fixture &fixture)
{
	try {
		std::vector<provider::v1::ProviderComponentArtifact> components;
		components.reserve(2);
		const std::filesystem::path host_source(KINETUM_PROVIDER_HOST_COMPONENT_PATH);
		const auto host_staged = fixture.stage_artifact(host_source, host_source.filename().string());
		components.push_back(fixture.component_record(host_staged, "kinetum.provider.host",
							      {std::string(provider::CPU_EXECUTION_TYPE_URL),
							       std::string(provider::HOST_STORAGE_TYPE_URL),
							       std::string(provider::ZERO_COPY_SHARE_TYPE_URL),
							       std::string(provider::BOUNDED_COPY_TYPE_URL)}));

		const std::filesystem::path udp_source(KINETUM_PROVIDER_UDP_COMPONENT_PATH);
		const auto udp_staged = fixture.stage_artifact(udp_source, udp_source.filename().string());
		components.push_back(fixture.component_record(udp_staged, "kinetum.provider.udp",
							      {std::string(provider::UDP_DRIVER_TYPE_URL)}));

		(void)fixture.write_signed_inventory(fixture.inventory(components, {}));
		return common::status::ok();
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted(
			"packet-runtime fixture provider inventory allocation failed");
	} catch (const std::exception &error) {
		return common::status::internal_error("packet-runtime fixture provider inventory failed: " +
						      std::string(error.what()));
	}
}

/**
 * @brief Construct the exact canonical bootstrap request for one plan.
 *
 * @param plan Canonical emitted deployment plan.
 * @param module_configuration Optional exact module identity and opaque bytes.
 * @return Validated six-field bootstrap authority.
 */
[[nodiscard]] inline common::status_or<kinetum::dataplane::v1::BootstrapConfigSnapshotRequest>
make_bootstrap_request(const kinetum::gluon::v1::DeploymentPlan &plan,
		       const std::optional<std::pair<std::string, std::string>> &module_configuration)
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	snapshot.set_snapshot_id("packet-runtime-bootstrap");
	snapshot.set_revision(1);
	snapshot.set_created_unix_ms(1);
	snapshot.set_description("exact fixed-epoch runtime fixture");
	if (module_configuration.has_value()) {
		auto *module = snapshot.add_modules();
		module->set_module_id(module_configuration->first);
		module->set_config_blob(module_configuration->second);
	}
	auto canonical_or = common::canonicalize_config_snapshot(snapshot, plan);
	if (!canonical_or.is_ok()) {
		return canonical_or.error();
	}

	kinetum::dataplane::v1::BootstrapConfigSnapshotRequest request;
	const auto terminal_status =
		common::admit_terminal_config_snapshot(canonical_or.value(), request.mutable_snapshot());
	if (!terminal_status.is_ok()) {
		return terminal_status;
	}
	request.set_active_epoch(TEST_BOOTSTRAP_IDENTITY);
	request.set_allocated_epoch_high_watermark(TEST_BOOTSTRAP_IDENTITY);
	request.set_mutation_sequence_high_watermark(TEST_BOOTSTRAP_IDENTITY);
	request.set_plan_content_hash(plan.content_hash());
	auto plan_hash_or = common::decode_sha256_digest_claim(plan.content_hash(), "plan_content_hash");
	if (!plan_hash_or.is_ok()) {
		return plan_hash_or.error();
	}
	auto key_or = common::derive_bootstrap_config_snapshot_idempotency_key(
		canonical_or->validation_hash, plan_hash_or.value(), TEST_BOOTSTRAP_IDENTITY, TEST_BOOTSTRAP_IDENTITY,
		TEST_BOOTSTRAP_IDENTITY);
	if (!key_or.is_ok()) {
		return key_or.error();
	}
	request.set_idempotency_key(std::move(key_or).value());
	auto validated_or = common::validate_bootstrap_config_snapshot_request(request);
	if (!validated_or.is_ok()) {
		return validated_or.error();
	}
	return request;
}

}  // namespace packet_runtime_fixture_detail

/**
 * @brief Explicit module image, configuration, and lifecycle-memory test intent.
 *
 * Every field is caller-authored. The fixture neither sizes module memory nor
 * derives a capacity from the image or configuration payload.
 */
struct packet_runtime_test_module_intent {
	std::string module_id;			 ///< Exact plan, snapshot, and image identity.
	std::filesystem::path canonical_path;	 ///< Canonical absolute main-image path.
	std::string config_blob;		 ///< Opaque module-owned bootstrap configuration.
	uint64_t context_memory_capacity_bytes;	 ///< Exact context-lifetime bound.
	uint64_t epoch_arena_capacity_bytes;	 ///< Exact capacity of each epoch arena.
	kinetum::axiom::v1::ExecutionMode execution_mode{
		kinetum::axiom::v1::EXECUTION_MODE_PASSIVE};  ///< Exact authored scheduling mode.
	uint32_t trigger_mask{0};			      ///< Exact authored active trigger mask.
	uint32_t retained_packet_capacity{0};		      ///< Exact active retained-record capacity.
	uint64_t retained_byte_capacity{0};		      ///< Exact active retained-byte capacity.
	uint32_t timer_capacity{0};			      ///< Exact active timer capacity.
	uint32_t control_mailbox_capacity{0};		      ///< Exact active control-message count.
	uint32_t control_message_capacity_bytes{0};	      ///< Exact active control payload bound.
	uint32_t async_work_capacity{0};		      ///< Exact tracked foreign-work tokens.
	uint64_t async_cancel_grace_ms{0};		      ///< Exact cancellation fail-stop grace.
};

/**
 * @brief Own one complete real-component fixed-epoch runtime test generation.
 *
 * The runtime is destroyed before provider fixture artifacts and component
 * code, and the calling thread's original affinity is restored last.
 */
class packet_runtime_test_owner final {
    public:
	/** @brief Complete test generations cannot be copied. */
	packet_runtime_test_owner(const packet_runtime_test_owner &) = delete;
	/** @brief Complete test generations cannot be copy-assigned. */
	packet_runtime_test_owner &operator=(const packet_runtime_test_owner &) = delete;
	/** @brief Complete test generations cannot be moved after construction. */
	packet_runtime_test_owner(packet_runtime_test_owner &&) = delete;
	/** @brief Complete test generations cannot be move-assigned. */
	packet_runtime_test_owner &operator=(packet_runtime_test_owner &&) = delete;

	/** @brief Retire the runtime before its installed component authority. */
	~packet_runtime_test_owner() = default;

	/**
	 * @brief Construct one module-free production-shaped CONTROL_READY runtime.
	 *
	 * @return Complete owner; UNAVAILABLE only for insufficient live CPU/NUMA
	 *         capacity, otherwise the exact failed admission status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_runtime_test_owner>> create()
	{
		return create_impl_(std::nullopt, std::nullopt, std::nullopt, 1u);
	}

	/**
	 * @brief Construct one module-free runtime from an explicit test pipeline.
	 *
	 * The caller supplies only logical packet policy. Provider, placement,
	 * capacity, compilation, admission, and materialization still traverse the
	 * same production-shaped fixture authorities as create(). A pipeline with a
	 * module stage is rejected because this overload carries no image or memory
	 * authority.
	 *
	 * @param pipeline Complete module-free logical pipeline.
	 * @return Complete owner; UNAVAILABLE only for insufficient live CPU/NUMA
	 *         capacity, otherwise the exact failed admission status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_runtime_test_owner>>
	create_with_pipeline(kinetum::axiom::v1::Pipeline pipeline)
	{
		return create_impl_(std::nullopt, std::move(pipeline), std::nullopt, 1u);
	}

	/**
	 * @brief Construct one module-free runtime over multiple logical regions.
	 * @param pipeline Complete module-free logical pipeline.
	 * @param region_count Exact positive region count; the host must supply two
	 *        additional same-NUMA runtime-service cores.
	 * @param zero_copy_transitions Exact caller-authored same-domain owner
	 *        handoffs; borrowed strings must remain live until return.
	 * @return Complete production-shaped owner or exact host/planner/runtime failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_runtime_test_owner>>
	create_with_pipeline(kinetum::axiom::v1::Pipeline pipeline, std::size_t region_count,
			     std::span<const packet_runtime_test_zero_copy_transition> zero_copy_transitions = {})
	{
		return create_impl_(std::nullopt, std::move(pipeline), std::nullopt, region_count,
				    zero_copy_transitions);
	}

	/**
	 * @brief Construct one production-shaped runtime with exact module intent.
	 *
	 * @param module Caller-authored image, configuration, and memory contract.
	 * @return Complete owner; UNAVAILABLE only for insufficient live CPU/NUMA
	 *         capacity, otherwise the exact failed admission status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_runtime_test_owner>>
	create(packet_runtime_test_module_intent module)
	{
		return create_impl_(std::move(module), std::nullopt, std::nullopt, 1u);
	}

	/**
	 * @brief Construct one module runtime from complete caller-authored deployment intent.
	 * @param module Exact image, configuration, and lifecycle-memory authority.
	 * @param pipeline Logical graph whose module stages share that exact image/configuration identity.
	 * @param bindings Provider bindings before fixture-owned host and UDP endpoint placement.
	 * @return Complete owner after the ordinary planner and runtime admission path.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_runtime_test_owner>>
	create(packet_runtime_test_module_intent module, kinetum::axiom::v1::Pipeline pipeline,
	       const kinetum::gluon::v1::DeploymentBindings &bindings)
	{
		return create_impl_(std::move(module), std::move(pipeline), std::nullopt, 1u, {}, &bindings);
	}

	/**
	 * @brief Construct one module runtime with explicit plan-authored test timing.
	 * @param module Exact module/image/resource intent.
	 * @param timing Exact transition policy values finalized into plan identity.
	 * @return Complete CONTROL_READY owner or exact admission failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_runtime_test_owner>>
	create(packet_runtime_test_module_intent module, packet_runtime_test_transition_timing timing)
	{
		return create_impl_(std::move(module), std::nullopt, timing, 1u);
	}

	/** @return Sole complete runtime generation. */
	[[nodiscard]] dp::partitioned_runtime &runtime() noexcept
	{
		return *runtime_;
	}

	/** @return Exact canonical bootstrap request. */
	[[nodiscard]] const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &bootstrap_request() const noexcept
	{
		return bootstrap_request_;
	}

	/**
	 * @brief Run one foreign producer while this thread services the real mailbox.
	 *
	 * @tparam operation_type Nullary producer callable.
	 * @param operation Operation invoked on one foreign thread.
	 * @return Exact operation result after unconditional producer completion.
	 */
	template <typename operation_type>
	[[nodiscard]] auto run_control_producer(operation_type &&operation) -> std::invoke_result_t<operation_type>
	{
		using result_type = std::invoke_result_t<operation_type>;
		static_assert(!std::is_reference_v<result_type>, "control producers must return owned test results");
		std::optional<result_type> result;
		std::atomic<bool> completed{false};
		std::thread producer([&]() noexcept {
			try {
				result.emplace(operation());
				completed.store(true, std::memory_order_release);
			} catch (...) {
				std::terminate();
			}
		});
		while (!completed.load(std::memory_order_acquire)) {
			const auto lifecycle_descriptor = runtime_->lifecycle_notification_descriptor();
			if (!lifecycle_descriptor.has_value()) {
				break;
			}
			pollfd descriptors[2]{
				pollfd{.fd = runtime_->command_notification_descriptor(),
				       .events = POLLIN,
				       .revents = 0},
				pollfd{.fd = *lifecycle_descriptor, .events = POLLIN, .revents = 0},
			};
			const int poll_result = ::poll(descriptors, 2, 10);
			if (poll_result < 0 && errno == EINTR) {
				continue;
			}
			if (poll_result < 0 || (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
			    (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
				std::terminate();
			}
			if ((descriptors[0].revents & POLLIN) != 0 &&
			    !runtime_->service_command_notifications().is_ok()) {
				std::terminate();
			}
			if ((descriptors[1].revents & POLLIN) != 0 &&
			    !runtime_->service_lifecycle_notifications().is_ok()) {
				std::terminate();
			}
			if (!runtime_->service_control_deadline().is_ok()) {
				std::terminate();
			}
		}
		producer.join();
		if (!result.has_value()) {
			std::terminate();
		}
		return std::move(result).value();
	}

	/**
	 * @brief Submit the fixture's exact Bootstrap through the production mailbox.
	 *
	 * @param request Exact request, defaulting to the fixture authority.
	 * @return Runtime Bootstrap result after owner-thread command service.
	 */
	[[nodiscard]] common::status_or<dp::fixed_epoch_bootstrap_result>
	bootstrap(const kinetum::dataplane::v1::BootstrapConfigSnapshotRequest &request)
	{
		return run_control_producer([this, &request]() { return runtime_->bootstrap(request); });
	}

	/** @return Bootstrap result for the fixture's exact canonical request. */
	[[nodiscard]] common::status_or<dp::fixed_epoch_bootstrap_result> bootstrap()
	{
		return bootstrap(bootstrap_request_);
	}

	/**
	 * @brief Send one exact packet image to the authored RX endpoint.
	 *
	 * @param packet Nonempty Ethernet packet bytes within one IPv4 UDP datagram.
	 * @return OK after one complete datagram send, otherwise a bounded socket status.
	 */
	[[nodiscard]] common::status send_packet_to_rx(std::span<const uint8_t> packet) const
	{
		if (rx_port_ == 0 || packet.empty() ||
		    packet.size() > packet_runtime_fixture_detail::MAX_UDP_DATAGRAM_BYTES) {
			return common::status::invalid_argument(
				"packet-runtime fixture RX packet contract is incomplete");
		}
		const int descriptor = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (descriptor < 0) {
			return common::status::resource_exhausted(
				"packet-runtime fixture could not create a UDP sender socket");
		}
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		address.sin_port = htons(rx_port_);
		const ssize_t sent = ::sendto(descriptor, packet.data(), packet.size(), 0,
					      reinterpret_cast<const sockaddr *>(&address), sizeof(address));
		const int send_errno = errno;
		const int close_result = ::close(descriptor);
		if (sent < 0 || static_cast<std::size_t>(sent) != packet.size()) {
			return common::status::internal_error(
				"packet-runtime fixture RX datagram send failed with errno " +
				std::to_string(send_errno));
		}
		if (close_result != 0) {
			return common::status::internal_error("packet-runtime fixture UDP sender close failed");
		}
		return common::status::ok();
	}

	/**
	 * @brief Receive one packet emitted through the authored TX endpoint.
	 *
	 * @param maximum_bytes Exact caller-selected receive bound.
	 * @param timeout_ms Nonnegative bounded poll timeout.
	 * @return Exact emitted packet bytes, or a bounded receive status.
	 */
	[[nodiscard]] common::status_or<std::vector<uint8_t>> receive_packet_from_tx(std::size_t maximum_bytes,
										     int timeout_ms) const
	{
		if (!tx_sink_.has_value()) {
			return common::status::failed_precondition(
				"packet-runtime fixture lacks its exact TX sink authority");
		}
		return tx_sink_->receive_datagram(maximum_bytes, timeout_ms);
	}

    private:
	/**
	 * @brief Construct an explicit logical policy over one production-shaped runtime.
	 *
	 * @param module Optional exact module image, configuration, and memory intent.
	 * @param authored_pipeline Optional complete logical pipeline matching the module intent.
	 * @param timing Optional exact transition policy finalized into the plan.
	 * @param region_count Exact positive Gluon region count.
	 * @param zero_copy_transitions Exact explicit same-domain owner handoffs.
	 * @param authored_bindings Optional complete provider intent before planning.
	 * @return Complete owner; UNAVAILABLE only for insufficient live CPU/NUMA
	 *         capacity, otherwise the exact failed admission status.
	 *
	 * A kernel-selected port cannot be transferred atomically into the
	 * plan-authored production provider. If another process claims that exact
	 * port after reservation release, construction retries from a fresh explicit
	 * endpoint under one fixed bound. No other provider failure is retried.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<packet_runtime_test_owner>>
	create_impl_(std::optional<packet_runtime_test_module_intent> module,
		     std::optional<kinetum::axiom::v1::Pipeline> authored_pipeline,
		     std::optional<packet_runtime_test_transition_timing> timing, std::size_t region_count,
		     std::span<const packet_runtime_test_zero_copy_transition> zero_copy_transitions = {},
		     const kinetum::gluon::v1::DeploymentBindings *authored_bindings = nullptr)
	{
		try {
			if (module.has_value() && authored_pipeline.has_value() && authored_bindings == nullptr) {
				return common::status::invalid_argument(
					"packet-runtime fixture accepts one logical-pipeline authority");
			}
			if (timing.has_value() &&
			    (timing->prepare_timeout_ms == 0u || timing->prepare_cancel_grace_ms == 0u ||
			     timing->prepared_lease_timeout_ms == 0u || timing->commit_timeout_ms == 0u ||
			     timing->retirement_timeout_ms == 0u)) {
				return common::status::invalid_argument(
					"packet-runtime fixture timing requires five nonzero authored values");
			}
			if (module.has_value() &&
			    (module->module_id.empty() || module->canonical_path.empty() ||
			     !module->canonical_path.is_absolute() ||
			     module->canonical_path != module->canonical_path.lexically_normal() ||
			     module->context_memory_capacity_bytes == 0u || module->epoch_arena_capacity_bytes == 0u)) {
				return common::status::invalid_argument(
					"packet-runtime fixture requires complete explicit module intent");
			}
			auto owner = std::unique_ptr<packet_runtime_test_owner>(new packet_runtime_test_owner());
			const auto host = quark::probe_host();
			if (region_count == 0u || region_count > std::numeric_limits<std::size_t>::max() - 2u) {
				return common::status::invalid_argument(
					"packet-runtime fixture region count is malformed");
			}
			auto selection_or = packet_runtime_fixture_detail::select_host(host, region_count + 2u);
			if (!selection_or.is_ok()) {
				return selection_or.error();
			}
			const std::optional<std::string> module_id =
				module.has_value() ? std::optional<std::string>(module->module_id) : std::nullopt;
			kinetum::axiom::v1::Pipeline pipeline =
				authored_pipeline.has_value() ? std::move(*authored_pipeline) :
								packet_runtime_fixture_detail::make_pipeline(module_id);
			if (module.has_value() && module->execution_mode == kinetum::axiom::v1::EXECUTION_MODE_ACTIVE) {
				auto stage = std::find_if(pipeline.mutable_stages()->begin(),
							  pipeline.mutable_stages()->end(), [](const auto &candidate) {
								  return candidate.stage_id() == "module";
							  });
				if (stage == pipeline.mutable_stages()->end()) {
					return common::status::internal_error(
						"active packet-runtime fixture lost its exact module stage");
				}
				stage->set_execution_mode(module->execution_mode);
				stage->set_trigger_mask(module->trigger_mask);
				auto *limits = stage->mutable_active_stage_limits();
				limits->set_retained_packet_capacity(module->retained_packet_capacity);
				limits->set_retained_byte_capacity(module->retained_byte_capacity);
				limits->set_timer_capacity(module->timer_capacity);
				limits->set_control_mailbox_capacity(module->control_mailbox_capacity);
				limits->set_control_message_capacity_bytes(module->control_message_capacity_bytes);
				limits->set_async_work_capacity(module->async_work_capacity);
				limits->set_async_cancel_grace_ms(module->async_cancel_grace_ms);
			}
			const auto inventory_status =
				packet_runtime_fixture_detail::stage_provider_inventory(owner->provider_fixture_);
			if (!inventory_status.is_ok()) {
				return inventory_status;
			}
			const std::optional<std::pair<std::string, std::string>> module_configuration =
				module.has_value() ? std::optional<std::pair<std::string, std::string>>(
							     std::in_place, module->module_id, module->config_blob) :
						     std::nullopt;
			for (std::size_t attempt = 0u;
			     attempt < packet_runtime_fixture_detail::MAX_UDP_RX_HANDOFF_ATTEMPTS; ++attempt) {
				auto rx_reservation_or = packet_runtime_fixture_detail::udp_port_reservation::create();
				if (!rx_reservation_or.is_ok()) {
					return rx_reservation_or.error();
				}
				auto rx_reservation = std::move(rx_reservation_or).value();
				auto tx_reservation_or = packet_runtime_fixture_detail::udp_port_reservation::create();
				if (!tx_reservation_or.is_ok()) {
					return tx_reservation_or.error();
				}
				auto tx_reservation = std::move(tx_reservation_or).value();
				const uint16_t rx_port = rx_reservation.port();
				auto compiled_or = packet_runtime_fixture_detail::compile_runtime_fixture(
					pipeline, selection_or.value(), rx_port, tx_reservation.port(),
					module.has_value() ? module->context_memory_capacity_bytes : 0u,
					module.has_value() ? module->epoch_arena_capacity_bytes : 0u, timing,
					region_count,
					region_count == 1u ? packet_runtime_fixture_detail::TEST_RUNTIME_BUFFER_COUNT :
							     UINT32_C(16384),
					zero_copy_transitions, authored_bindings);
				if (!compiled_or.is_ok()) {
					return compiled_or.error();
				}
				auto compiled = std::move(compiled_or).value();
				auto plan = std::move(compiled.plan);
				auto topology = std::move(compiled.topology);
				const auto compatibility = quark::validate_runtime_compat(topology, host);
				if (!compatibility.compatible) {
					return common::status::failed_precondition(
						"packet-runtime fixture live-host compatibility failed: " +
						compatibility.summary);
				}
				auto command_mailbox_or =
					dp::epoch_transition_command_mailbox::create(topology.transition_topology);
				if (!command_mailbox_or.is_ok()) {
					return command_mailbox_or.error();
				}
				auto admitted_or = provider::admit_installed_provider_runtime(
					topology, owner->provider_fixture_.root(),
					owner->provider_fixture_.runtime_image(), PROVIDER_TEST_PUBLIC_KEY,
					owner->provider_fixture_.file_policy());
				if (!admitted_or.is_ok()) {
					return admitted_or.error();
				}
				auto bootstrap_or = packet_runtime_fixture_detail::make_bootstrap_request(
					plan, module_configuration);
				if (!bootstrap_or.is_ok()) {
					return bootstrap_or.error();
				}

				std::vector<dp::module::module_image_spec> module_images;
				if (module.has_value()) {
					module_images.push_back({module->module_id, module->canonical_path});
				}
				auto input_or = dp::packet_runtime_generation_input::create(
					std::move(plan), std::move(topology), std::move(command_mailbox_or).value(),
					std::move(admitted_or).value(), std::move(module_images),
					packet_runtime_fixture_detail::TEST_RUNTIME_GENERATION);
				if (!input_or.is_ok()) {
					return input_or.error();
				}
				const auto rx_release = rx_reservation.release();
				if (!rx_release.is_ok()) {
					return rx_release;
				}
				auto runtime_or = dp::partitioned_runtime::create(std::move(input_or).value());
				if (!runtime_or.is_ok()) {
					if (attempt + 1u < packet_runtime_fixture_detail::MAX_UDP_RX_HANDOFF_ATTEMPTS &&
					    packet_runtime_fixture_detail::is_udp_rx_handoff_collision(
						    runtime_or.error())) {
						// The linear input has unwound. Rebuild plan identity and every
						// provider owner around a newly reserved explicit endpoint.
						continue;
					}
					return runtime_or.error();
				}
				owner->bootstrap_request_ = std::move(bootstrap_or).value();
				owner->rx_port_ = rx_port;
				owner->tx_sink_.emplace(std::move(tx_reservation));
				owner->runtime_ = std::move(runtime_or).value();
				return owner;
			}
			return common::status::internal_error(
				"packet-runtime fixture exhausted a nonzero UDP handoff-attempt bound");
		} catch (const std::bad_alloc &) {
			return common::status::resource_exhausted(
				"packet-runtime fixture construction exhausted memory");
		} catch (const std::exception &error) {
			return common::status::internal_error("packet-runtime fixture construction failed: " +
							      std::string(error.what()));
		}
	}

	/** @brief Construct an empty owner populated only by create_impl_(). */
	packet_runtime_test_owner() = default;

	thread_affinity_restore_guard affinity_;	    ///< Original calling-thread affinity, restored last.
	provider_component_test_fixture provider_fixture_;  ///< Installed component/code lifetime authority.
	std::optional<packet_runtime_fixture_detail::udp_port_reservation> tx_sink_;  ///< Exact TX destination.
	uint16_t rx_port_{0};  ///< Exact released RX endpoint used by the materialized driver.
	kinetum::dataplane::v1::BootstrapConfigSnapshotRequest bootstrap_request_;  ///< Exact request authority.
	std::unique_ptr<dp::partitioned_runtime> runtime_;  ///< Retired before component artifacts and affinity.
};

}  // namespace kinetum::test
