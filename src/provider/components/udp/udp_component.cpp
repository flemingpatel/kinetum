// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file udp_component.cpp
 * @brief Exact Linux UDP development I/O-driver component.
 * @author Fleming Patel
 *
 * The component consumes only canonical compiled C facts and exact storage
 * dependencies. It constructs bounded nonblocking recvmmsg/sendmmsg queues
 * and publishes immutable queue operation arrays; it never parses a plan,
 * protobuf payload, provider name, or target-string discriminator.
 */

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iterator>
#include <memory>
#include <new>
#include <string_view>
#include <utility>

#include "gen/kinetum/provider/provider_build_identity.h"
#include "src/dp/backends/udp/udp_io.hpp"
#include "src/provider/components/component_support.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::udp_component
{
namespace
{

using component_support::factory_request_matches;
using component_support::fail;
using component_support::static_text_view;

/** Stable identity exported by the UDP component descriptor. */
constexpr char COMPONENT_ID[] = "kinetum.provider.udp";
/** Exact contract identity admitted by the UDP driver factory. */
constexpr char UDP_DRIVER_TYPE_URL[] = "type.googleapis.com/kinetum.io.udp.v1.UdpDriverConfig";

/** @brief Complete exact UDP driver ownership returned by one factory call. */
struct udp_driver_instance {
	kinetum_provider_io_driver_operations operations{};  ///< Immutable role operation record.
	uint32_t port_count{0};				     ///< Number of canonical driver ports.
	uint32_t rx_count{0};				     ///< Number of constructed receive queues.
	uint32_t tx_count{0};				     ///< Number of constructed transmit queues.
	std::unique_ptr<uint32_t[]> port_indices;	     ///< Canonical global port identities.
	std::unique_ptr<dp::udp_rx_port *[]> rx_ports;	     ///< Individually owned receive queues.
	std::unique_ptr<dp::udp_tx_port *[]> tx_ports;	     ///< Individually owned transmit queues.
	std::unique_ptr<kinetum_packet_rx_burst_operations[]> rx_operations;  ///< Stable published RX rows.
	std::unique_ptr<kinetum_packet_tx_burst_operations[]> tx_operations;  ///< Stable published TX rows.
	bool active{false};  ///< Whether the complete driver has crossed its cold activation edge.

	/**
	 * @brief Activate every receive endpoint or roll all completed activations back.
	 * @param diagnostic Optional caller-owned bounded failure diagnostic.
	 * @return OK with every endpoint active. A failed cold-driver activation rolls back completed endpoints;
	 *         an already-active driver is rejected without changing it. Rollback failure terminates.
	 */
	kinetum_provider_status activate_packet_io(kinetum_provider_diagnostic *diagnostic) noexcept;

	/**
	 * @brief Deactivate every receive endpoint in reverse order.
	 * @param diagnostic Optional caller-owned bounded failure diagnostic.
	 * @return OK when every endpoint is cold; failure retains unresolved driver ownership.
	 */
	kinetum_provider_status deactivate_packet_io(kinetum_provider_diagnostic *diagnostic) noexcept;

	/** @brief Close and retire every queue before releasing operation arrays. */
	~udp_driver_instance()
	{
		if (active) {
			std::terminate();
		}
		if (tx_ports != nullptr) {
			for (uint32_t index = 0; index < tx_count; ++index) {
				delete tx_ports[index];
			}
		}
		if (rx_ports != nullptr) {
			for (uint32_t index = 0; index < rx_count; ++index) {
				delete rx_ports[index];
			}
		}
	}
};

/**
 * @brief Destroy one exact UDP driver instance.
 * @param instance Sole quiescent instance returned by this component, or nullptr.
 */
void destroy_udp_driver(void *instance) noexcept
{
	delete static_cast<udp_driver_instance *>(instance);
}

/**
 * @brief Resolve one exact driver-local compiled port row.
 *
 * @param facts Complete I/O-driver facts.
 * @param port_index Compact global port identity.
 * @return Unique matching row, or null.
 */
[[nodiscard]] const kinetum_provider_io_port_fact *find_port(const kinetum_provider_io_driver_facts &facts,
							     uint32_t port_index) noexcept
{
	const kinetum_provider_io_port_fact *match = nullptr;
	for (uint32_t index = 0; index < facts.port_count; ++index) {
		if (facts.ports[index].port_index != port_index) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = &facts.ports[index];
	}
	return match;
}

/**
 * @brief Resolve one exact driver-local steering profile.
 *
 * @param facts Complete I/O-driver facts.
 * @param steering_profile_index Compact global steering-profile identity.
 * @return Unique matching row, or null.
 */
[[nodiscard]] const kinetum_provider_steering_fact *find_steering_profile(const kinetum_provider_io_driver_facts &facts,
									  uint32_t steering_profile_index) noexcept
{
	const kinetum_provider_steering_fact *match = nullptr;
	for (uint32_t index = 0; index < facts.steering_profile_count; ++index) {
		if (facts.steering_profiles[index].steering_profile_index != steering_profile_index) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = &facts.steering_profiles[index];
	}
	return match;
}

/**
 * @brief Prove UDP receives use only the explicit one-queue NONE contract.
 *
 * Every RX stream owns one distinct NONE profile that names only that stream;
 * TX streams own no profile. Profile cardinality closes the fact set against
 * unreferenced or multiply referenced rows.
 *
 * @param facts Complete I/O-driver facts.
 * @return true only for the exact UDP steering projection.
 */
[[nodiscard]] bool udp_steering_is_exact(const kinetum_provider_io_driver_facts &facts) noexcept
{
	uint32_t rx_count = 0;
	for (uint32_t index = 0; index < facts.stream_count; ++index) {
		const auto &stream = facts.streams[index];
		if (stream.direction == KINETUM_PROVIDER_IO_DIRECTION_TX) {
			if (stream.has_steering_profile != 0) {
				return false;
			}
			continue;
		}
		if (stream.direction != KINETUM_PROVIDER_IO_DIRECTION_RX || stream.has_steering_profile != 1) {
			return false;
		}
		++rx_count;
		const auto *steering = find_steering_profile(facts, stream.steering_profile_index);
		if (steering == nullptr || steering->kind != KINETUM_PROVIDER_STEERING_NONE ||
		    steering->symmetric != 0 || steering->hash_field_count != 0 || steering->hash_key.size != 0 ||
		    steering->io_stream_count != 1 || steering->io_stream_indices[0] != stream.io_stream_index) {
			return false;
		}
	}
	return facts.steering_profile_count == rx_count;
}

/**
 * @brief Resolve one exact packet-storage dependency by domain index.
 *
 * @param request Exact factory request.
 * @param storage_domain_index Required compact domain identity.
 * @return Unique matching immutable operation record, or null.
 */
[[nodiscard]] const kinetum_packet_storage_domain_operations *
find_storage(const kinetum_provider_factory_request &request, uint32_t storage_domain_index) noexcept
{
	if (storage_domain_index >= KINETUM_INVALID_STORAGE_DOMAIN) {
		return nullptr;
	}
	const kinetum_packet_storage_domain_operations *match = nullptr;
	for (uint32_t index = 0; index < request.dependency_count; ++index) {
		const auto &dependency = request.dependencies[index];
		if (dependency.role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE) {
			continue;
		}
		const auto *operations =
			static_cast<const kinetum_packet_storage_domain_operations *>(dependency.operations);
		if (operations->domain_index != storage_domain_index) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = operations;
	}
	return match;
}

/**
 * @brief Prove every dependency is one unique storage domain used by a stream.
 *
 * @param request Exact factory request.
 * @param facts Complete I/O-driver facts.
 * @return true only for one exact, generation-matching storage dependency set.
 */
[[nodiscard]] bool storage_dependencies_are_exact(const kinetum_provider_factory_request &request,
						  const kinetum_provider_io_driver_facts &facts) noexcept
{
	if (request.runtime_generation > UINT32_MAX) {
		return false;
	}
	const auto generation = static_cast<uint32_t>(request.runtime_generation);
	for (uint32_t dependency_index = 0; dependency_index < request.dependency_count; ++dependency_index) {
		const auto &dependency = request.dependencies[dependency_index];
		if (dependency.role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE) {
			return false;
		}
		const auto *storage =
			static_cast<const kinetum_packet_storage_domain_operations *>(dependency.operations);
		if (storage->generation != generation) {
			return false;
		}
		for (uint32_t earlier = 0; earlier < dependency_index; ++earlier) {
			const auto *other = static_cast<const kinetum_packet_storage_domain_operations *>(
				request.dependencies[earlier].operations);
			if (other->domain_index == storage->domain_index) {
				return false;
			}
		}
		bool used = false;
		for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
			used = used || kinetum_provider_io_stream_uses_storage(&facts.streams[stream_index],
									       storage->domain_index) != 0;
		}
		if (!used) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Parse one already canonical numeric IPv4 attachment without allocation.
 *
 * @param attachment Exact compiled UDP attachment.
 * @param[out] endpoint Network-order socket endpoint.
 * @return true only for current UDP attachment shape and canonical byte bound.
 */
[[nodiscard]] bool parse_endpoint(const kinetum_provider_driver_attachment_fact &attachment,
				  dp::udp_ipv4_endpoint &endpoint) noexcept
{
	if (attachment.kind != KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4 ||
	    !kinetum_provider_text_view_is_valid(attachment.attachment_identity) ||
	    attachment.attachment_identity.size == 0) {
		return false;
	}
	return dp::parse_udp_ipv4_endpoint(std::string_view(attachment.attachment_identity.data,
							    attachment.attachment_identity.size),
					   attachment.endpoint_port, endpoint);
}

/**
 * @brief Check a stream direction against its owning port.
 * @param port_direction Compiled RX, TX, or bidirectional port direction.
 * @param stream_direction Candidate RX or TX stream direction.
 * @return true only for a stream direction admitted by that port.
 */
[[nodiscard]] bool direction_matches(kinetum_provider_io_direction port_direction,
				     kinetum_provider_io_direction stream_direction) noexcept
{
	return stream_direction == KINETUM_PROVIDER_IO_DIRECTION_RX ?
		       (port_direction == KINETUM_PROVIDER_IO_DIRECTION_RX ||
			port_direction == KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL) :
		       stream_direction == KINETUM_PROVIDER_IO_DIRECTION_TX &&
			       (port_direction == KINETUM_PROVIDER_IO_DIRECTION_TX ||
				port_direction == KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL);
}

/**
 * @brief Map one cold UDP socket status into the closed component status set.
 * @param status Non-OK socket or lifecycle result.
 * @return Matching provider failure code; unclassified errors become IMPLEMENTATION_ERROR.
 */
[[nodiscard]] kinetum_provider_status udp_status(const common::status &status) noexcept
{
	switch (status.code()) {
	case common::status_code::INVALID_ARGUMENT:
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	case common::status_code::ALREADY_EXISTS:
	case common::status_code::FAILED_PRECONDITION:
		return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
	case common::status_code::RESOURCE_EXHAUSTED:
		return KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
	default:
		return KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
	}
}

kinetum_provider_status udp_driver_instance::activate_packet_io(kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (active) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "UDP driver is already packet-active");
	}
	uint32_t activated_count = 0;
	for (; activated_count < rx_count; ++activated_count) {
		const auto activation = rx_ports[activated_count]->activate();
		if (activation.is_ok()) {
			continue;
		}
		for (uint32_t rollback = activated_count; rollback > 0; --rollback) {
			if (!rx_ports[rollback - 1u]->deactivate().is_ok()) {
				std::terminate();
			}
		}
		return fail(udp_status(activation), diagnostic, "UDP RX activation failed");
	}
	active = true;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

kinetum_provider_status udp_driver_instance::deactivate_packet_io(kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!active) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic, "UDP driver is not packet-active");
	}
	for (uint32_t remaining = rx_count; remaining > 0; --remaining) {
		const auto deactivation = rx_ports[remaining - 1u]->deactivate();
		if (!deactivation.is_ok()) {
			return fail(udp_status(deactivation), diagnostic, "UDP RX deactivation failed");
		}
	}
	active = false;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief C-ABI adapter for complete UDP packet-I/O activation.
 * @param state Borrowed UDP driver instance.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return Exact activation result; an already-active driver is rejected without changing it.
 */
kinetum_provider_status activate_udp_packet_io(void *state, kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *instance = static_cast<udp_driver_instance *>(state);
	if (instance == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "UDP activation received a null driver");
	}
	return instance->activate_packet_io(diagnostic);
}

/**
 * @brief C-ABI adapter for complete UDP packet-I/O deactivation.
 * @param state Borrowed UDP driver instance.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK after every endpoint is cold, or a failure retaining unresolved ownership.
 */
kinetum_provider_status deactivate_udp_packet_io(void *state, kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *instance = static_cast<udp_driver_instance *>(state);
	if (instance == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "UDP deactivation received a null driver");
	}
	return instance->deactivate_packet_io(diagnostic);
}

/**
 * @brief Publish explicit unsupported native UDP port rows.
 * @param state Borrowed UDP driver instance.
 * @param observations Caller-owned complete port-row storage; identities are populated from the driver.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK with every row marked UNSUPPORTED, or INVALID_ARGUMENT for malformed input.
 */
kinetum_provider_status observe_udp_statistics(void *state, kinetum_provider_io_observation_batch *observations,
					       kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *instance = static_cast<udp_driver_instance *>(state);
	if (instance == nullptr || observations == nullptr || observations->port_count != instance->port_count ||
	    (instance->port_count != 0u && (observations->ports == nullptr || instance->port_indices == nullptr)) ||
	    observations->port_padding != 0u ||
	    !std::all_of(std::begin(observations->padding), std::end(observations->padding),
			 [](uint8_t byte) { return byte == 0u; })) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "UDP statistics received a malformed caller-owned observation batch");
	}
	for (uint32_t index = 0u; index < instance->port_count; ++index) {
		observations->ports[index] = {};
		observations->ports[index].port_index = instance->port_indices[index];
		observations->ports[index].state = KINETUM_PROVIDER_OBSERVATION_UNSUPPORTED;
	}
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Prove Linux can create and cold-gate the exact UDP receive class.
 *
 * The descriptor is closed before return; no endpoint is bound or reserved.
 * @param request Borrowed request identifying the exact UDP driver role and contract.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK when the socket lifecycle proof succeeds, or an explicit admission or host failure.
 */
kinetum_provider_status prove_udp_host(const kinetum_provider_host_proof_request *request,
				       kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (kinetum_provider_host_proof_request_is_valid(request) == 0 ||
	    request->role != KINETUM_PROVIDER_ROLE_IO_DRIVER ||
	    !component_support::text_equals(request->type_url, UDP_DRIVER_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "UDP host proof received a malformed request");
	}
	const auto proof = dp::prove_udp_rx_lifecycle_support();
	if (!proof.is_ok()) {
		return fail(udp_status(proof), diagnostic, "Linux UDP cold lifecycle is unavailable");
	}
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Materialize one complete exact UDP I/O-driver instance.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_udp_driver_impl(const kinetum_provider_factory_request *request,
					       kinetum_provider_factory_result *result,
					       kinetum_provider_diagnostic *diagnostic)
{
	if (!factory_request_matches(request, result, KINETUM_PROVIDER_ROLE_IO_DRIVER, UDP_DRIVER_TYPE_URL)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "UDP driver factory received a malformed request");
	}
	const auto &facts = *request->compiled_facts.io_driver;
	if (facts.attachment_count == 0 || facts.attachments == nullptr || facts.port_count == 0 ||
	    facts.ports == nullptr || facts.stream_count == 0 || facts.streams == nullptr ||
	    request->dependency_count == 0 || !storage_dependencies_are_exact(*request, facts) ||
	    !udp_steering_is_exact(facts)) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "UDP driver facts, dependencies, or NONE steering are incomplete");
	}

	uint32_t rx_count = 0;
	uint32_t tx_count = 0;
	for (uint32_t index = 0; index < facts.stream_count; ++index) {
		const auto direction = facts.streams[index].direction;
		if (direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
			++rx_count;
		} else if (direction == KINETUM_PROVIDER_IO_DIRECTION_TX) {
			++tx_count;
		} else {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "UDP stream direction is not exact RX or TX");
		}
	}

	auto instance = std::unique_ptr<udp_driver_instance>(new (std::nothrow) udp_driver_instance);
	if (instance == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic, "UDP driver allocation failed");
	}
	instance->rx_count = rx_count;
	instance->tx_count = tx_count;
	instance->port_count = facts.port_count;
	instance->port_indices.reset(new (std::nothrow) uint32_t[facts.port_count]{});
	if (rx_count != 0) {
		instance->rx_ports.reset(new (std::nothrow) dp::udp_rx_port *[rx_count] {});
		instance->rx_operations.reset(new (std::nothrow) kinetum_packet_rx_burst_operations[rx_count]{});
	}
	if (tx_count != 0) {
		instance->tx_ports.reset(new (std::nothrow) dp::udp_tx_port *[tx_count] {});
		instance->tx_operations.reset(new (std::nothrow) kinetum_packet_tx_burst_operations[tx_count]{});
	}
	if (!instance->port_indices || (rx_count != 0 && (!instance->rx_ports || !instance->rx_operations)) ||
	    (tx_count != 0 && (!instance->tx_ports || !instance->tx_operations))) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "UDP queue-table allocation failed");
	}

	uint32_t rx_index = 0;
	uint32_t tx_index = 0;
	for (uint32_t port_index = 0u; port_index < facts.port_count; ++port_index) {
		instance->port_indices[port_index] = facts.ports[port_index].port_index;
	}
	for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
		const auto &stream = facts.streams[stream_index];
		const auto *port = find_port(facts, stream.port_index);
		if (port == nullptr || port->driver_port_index >= facts.attachment_count ||
		    port->logical_port_id >= KINETUM_INVALID_PORT ||
		    !direction_matches(port->direction, stream.direction) || stream.driver_queue_id != 0 ||
		    stream.descriptor_count == 0) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "UDP stream does not match one exact port and queue-zero contract");
		}
		const auto &attachment = facts.attachments[port->driver_port_index];
		if (attachment.io_driver_index != facts.io_driver_index) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "UDP attachment belongs to a different driver instance");
		}
		dp::udp_ipv4_endpoint endpoint{};
		if (!parse_endpoint(attachment, endpoint)) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "UDP attachment is not one canonical numeric endpoint");
		}
		auto storage = std::unique_ptr<const kinetum_packet_storage_domain_operations *[]>{new (
			std::nothrow) const kinetum_packet_storage_domain_operations *[stream.storage_domain_count] {}};
		if (storage == nullptr) {
			return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
				    "UDP stream storage admission allocation failed");
		}
		const uint32_t required_access = KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ |
						 (stream.direction == KINETUM_PROVIDER_IO_DIRECTION_RX ?
							  KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE :
							  0u);
		for (uint32_t domain_index = 0; domain_index < stream.storage_domain_count; ++domain_index) {
			storage[domain_index] = find_storage(*request, stream.storage_domain_indices[domain_index]);
			if (storage[domain_index] == nullptr ||
			    (storage[domain_index]->capabilities & required_access) != required_access) {
				return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
					    "UDP stream storage dependency is absent or incompatible");
			}
		}

		if (stream.direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
			auto queue_or = dp::udp_rx_port::create(
				*storage[0], static_cast<uint16_t>(port->logical_port_id), stream.descriptor_count);
			if (!queue_or.is_ok()) {
				return fail(udp_status(queue_or.error()), diagnostic,
					    "UDP RX queue descriptor construction failed");
			}
			auto queue = std::move(queue_or).value();
			const auto queue_status = queue->reserve(endpoint);
			if (!queue_status.is_ok()) {
				return fail(udp_status(queue_status), diagnostic, queue_status.message());
			}
			instance->rx_operations[rx_index] = queue->burst_operations();
			instance->rx_ports[rx_index] = queue.release();
			++rx_index;
		} else {
			if (attachment.endpoint_port == 0) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "UDP TX endpoint port must be nonzero");
			}
			auto queue_or = dp::udp_tx_port::create({storage.get(), stream.storage_domain_count},
								static_cast<uint16_t>(port->logical_port_id),
								stream.descriptor_count);
			if (!queue_or.is_ok()) {
				return fail(udp_status(queue_or.error()), diagnostic,
					    "UDP TX queue descriptor construction failed");
			}
			auto queue = std::move(queue_or).value();
			const auto queue_status = queue->connect(endpoint);
			if (!queue_status.is_ok()) {
				return fail(udp_status(queue_status), diagnostic, "UDP TX queue connect failed");
			}
			instance->tx_operations[tx_index] = queue->burst_operations();
			instance->tx_ports[tx_index] = queue.release();
			++tx_index;
		}
	}

	instance->operations.state = instance.get();
	instance->operations.activate_packet_io = activate_udp_packet_io;
	instance->operations.deactivate_packet_io = deactivate_udp_packet_io;
	instance->operations.rx_queues = instance->rx_operations.get();
	instance->operations.tx_queues = instance->tx_operations.get();
	instance->operations.observe_statistics = observe_udp_statistics;
	instance->operations.rx_queue_count = instance->rx_count;
	instance->operations.tx_queue_count = instance->tx_count;
	instance->operations.io_driver_index = facts.io_driver_index;
	if (!kinetum_provider_io_driver_operations_are_valid(&instance->operations)) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "UDP driver produced an invalid operation record");
	}
	result->operations = &instance->operations;
	result->instance = instance.release();
	result->destroy = destroy_udp_driver;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Enforce the no-exception C boundary around UDP queue construction.
 * @param request Borrowed compiled facts and dependency handles for this exact factory role.
 * @param result Initially empty output receiving the instance, operations, and destroy callback on success.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK transfers complete instance ownership; failure transfers none.
 */
kinetum_provider_status create_udp_driver(const kinetum_provider_factory_request *request,
					  kinetum_provider_factory_result *result,
					  kinetum_provider_diagnostic *diagnostic) noexcept
{
	try {
		return create_udp_driver_impl(request, result, diagnostic);
	} catch (const std::bad_alloc &) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "UDP driver construction exhausted process memory");
	} catch (...) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "UDP driver construction raised an unexpected failure");
	}
}

/** UDP factory and host-proof inventory exported by this component. */
constexpr kinetum_provider_contract_implementation CONTRACTS[]{
	{
		.type_url = static_text_view(UDP_DRIVER_TYPE_URL),
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = create_udp_driver,
				.packet_storage = nullptr,
				.execution = nullptr,
				.storage_transition = nullptr,
			},
		.host_proof = prove_udp_host,
		.role = KINETUM_PROVIDER_ROLE_IO_DRIVER,
		.padding = {0},
	},
};

/** Immutable product, ABI, and contract identity returned by the component query. */
constexpr kinetum_provider_component_descriptor DESCRIPTOR{
	.product_version_major = KINETUM_PROVIDER_PRODUCT_VERSION_MAJOR,
	.product_version_minor = KINETUM_PROVIDER_PRODUCT_VERSION_MINOR,
	.product_version_patch = KINETUM_PROVIDER_PRODUCT_VERSION_PATCH,
	.version_padding = {0},
	.abi_identity = KINETUM_PROVIDER_ABI_IDENTITY_INITIALIZER,
	.component_id = static_text_view(COMPONENT_ID),
	.contracts = CONTRACTS,
	.contract_count = 1,
	.tail_padding = {0},
};

}  // namespace
}  // namespace kinetum::provider::udp_component

extern "C" const kinetum_provider_component_descriptor *kinetum_provider_component_query(void) noexcept
{
	return &kinetum::provider::udp_component::DESCRIPTOR;
}
