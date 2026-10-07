// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_contract_catalog.cpp
 * @brief Pure typed provider-configuration and capability contract catalog.
 * @author Fleming Patel
 *
 * The implementation is one immutable, lexicographically ordered row table.
 * Each row binds an exact type URL to a generated-message canonicalizer and a
 * role-specific provider-neutral projection. No descriptor scanning, dynamic
 * registration, native provider dependency, or runtime selection occurs here.
 */

#include "src/provider/provider_contract_catalog.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "gen/kinetum/execution/cpu/v1/cpu_execution.pb.h"
#include "gen/kinetum/facility/dpdk/v1/dpdk_facility.pb.h"
#include "gen/kinetum/io/dpdk/v1/dpdk_driver.pb.h"
#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "gen/kinetum/storage/dpdk/v1/dpdk_storage.pb.h"
#include "gen/kinetum/storage/host/v1/host_storage.pb.h"
#include "gen/kinetum/transition/core/v1/core_transition.pb.h"
#include "gen/kinetum/transition/cpu/v1/cpu_transition.pb.h"
#include "src/common/execution_topology_ids.hpp"
#include "src/common/protobuf_contract.hpp"

namespace kinetum::provider
{

namespace
{

using common::status;
using common::status_code;
using common::status_or;
using google::protobuf::Descriptor;

/** @brief Private generated-payload canonicalizer signature. */
using canonicalize_payload_fn = status_or<std::string> (*)(const google::protobuf::Any &configuration);

/** @brief Private generated-message descriptor accessor signature. */
using message_descriptor_fn = const Descriptor *(*)();

/** @brief One private row joining public facts to generated-type operations. */
struct provider_contract_row {
	provider_contract_descriptor descriptor;       ///< Immutable provider-neutral contract facts.
	canonicalize_payload_fn canonicalize_payload;  ///< Exact generated-message canonicalizer.
	message_descriptor_fn message_descriptor;      ///< Generated descriptor inspection operation.
};

/** Direction mask for contracts admitting both RX and TX streams. */
constexpr io_direction_mask RX_TX_DIRECTIONS = static_cast<io_direction_mask>(
	static_cast<io_direction_mask>(io_direction::RX) | static_cast<io_direction_mask>(io_direction::TX));
/** Capability mask admitting only the explicit NONE steering mode. */
constexpr steering_capability_mask NO_STEERING = static_cast<steering_capability_mask>(steering_capability::NONE);
/** Capability mask admitting explicit NONE and RSS steering modes. */
constexpr steering_capability_mask NONE_AND_RSS_STEERING =
	static_cast<steering_capability_mask>(static_cast<steering_capability_mask>(steering_capability::NONE) |
					      static_cast<steering_capability_mask>(steering_capability::RSS));

/** Exact order-contractual RSS field sequence implemented by the DPDK contract. */
constexpr std::array<std::string_view, 2> DPDK_RSS_HASH_FIELDS{"ipv4", "udp"};

/** Maximum bounded exact RSS key accepted before native device proof. */
constexpr uint32_t MAX_DPDK_RSS_KEY_BYTES = 128;
/** CPU access-agent bit used by host storage and execution contracts. */
constexpr packet_access_agent_mask CPU_ACCESS = access_agent_bit(packet_access_agent::CPU);
/** NIC DMA access-agent bit used by native I/O contracts. */
constexpr packet_access_agent_mask NIC_DMA_ACCESS = access_agent_bit(packet_access_agent::NIC_DMA);

static_assert(MAX_PROVIDER_CONFIGURATION_BYTES <= static_cast<std::size_t>(std::numeric_limits<int>::max()),
	      "provider payload bound must fit protobuf ParseFromArray's int size");

/** Exactly one EAL process-facility dependency for native DPDK roles. */
constexpr std::array<provider_facility_dependency, 1> DPDK_FACILITY_DEPENDENCY{
	provider_facility_dependency{DPDK_FACILITY_TYPE_URL, 1},
};

/** Non-materializing DPDK runtime and hugepage proofs. */
constexpr std::array<provider_host_requirement, 2> DPDK_FACILITY_HOST_REQUIREMENTS{
	provider_host_requirement{provider_host_fact::DPDK_EAL_RUNTIME,
				  provider_host_proof_phase::COMPONENT_HOST_PROOF},
	provider_host_requirement{provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR,
				  provider_host_proof_phase::COMPONENT_HOST_PROOF},
};
/** Native ethdev proof owned by driver materialization. */
constexpr std::array<provider_host_requirement, 1> DPDK_DRIVER_HOST_REQUIREMENTS{
	provider_host_requirement{provider_host_fact::DPDK_ETHDEV_PORT,
				  provider_host_proof_phase::MATERIALIZATION_PROOF},
};
/** Non-materializing Linux UDP socket lifecycle proof. */
constexpr std::array<provider_host_requirement, 1> UDP_DRIVER_HOST_REQUIREMENTS{
	provider_host_requirement{provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET,
				  provider_host_proof_phase::COMPONENT_HOST_PROOF},
};
/** Live-host memory placement proof required before provider admission. */
constexpr std::array<provider_host_requirement, 1> HOST_NUMA_MEMORY_REQUIREMENTS{
	provider_host_requirement{provider_host_fact::HOST_NUMA_MEMORY, provider_host_proof_phase::QUARK_LIVE_HOST},
};
/** Live-host worker CPU proof required before provider admission. */
constexpr std::array<provider_host_requirement, 1> CPU_EXECUTION_HOST_REQUIREMENTS{
	provider_host_requirement{provider_host_fact::CPU_WORKER_SET, provider_host_proof_phase::QUARK_LIVE_HOST},
};

/**
 * @brief Build the trusted diagnostic prefix for one ladder step.
 *
 * @param step Exact failed canonicalization step.
 * @return Stable human-readable step prefix.
 */
[[nodiscard]] std::string step_prefix(provider_configuration_step step)
{
	return "provider configuration step " + std::to_string(static_cast<uint8_t>(step)) + " (" +
	       std::string(provider_configuration_step_name(step)) + "): ";
}

/**
 * @brief Construct one status owned by an exact ladder step.
 *
 * @param step Exact failed canonicalization step.
 * @param code Stable failure category.
 * @param message Trusted or already-bounded diagnostic detail.
 * @return Failure status carrying the stable step identity.
 */
[[nodiscard]] status step_error(provider_configuration_step step, status_code code, std::string message)
{
	return status(code, step_prefix(step) + std::move(message));
}

/**
 * @brief Preserve a cause's code while assigning its owning ladder step.
 *
 * @param step Exact failed canonicalization step.
 * @param cause Failure produced by a shared or provider-specific validator.
 * @return Step-qualified failure status.
 */
[[nodiscard]] status wrap_step_error(provider_configuration_step step, const status &cause)
{
	return step_error(step, cause.code(), std::string(cause.message()));
}

/**
 * @brief Encode one nibble as canonical lowercase hexadecimal.
 *
 * @param value Nibble in the range `[0, 15]`.
 * @return Corresponding lowercase ASCII digit.
 */
[[nodiscard]] constexpr char hexadecimal_digit(uint8_t value) noexcept
{
	return value < 10u ? static_cast<char>('0' + value) : static_cast<char>('a' + (value - 10u));
}

/**
 * @brief Render a bounded escaped prefix without reproducing full input.
 *
 * Every nonempty value omits at least its last byte, even when shorter than the
 * configured diagnostic cap. The caller supplies only a trusted field label.
 *
 * @param label Trusted field label.
 * @param value Untrusted bytes to summarize.
 * @return Declared length plus escaped, non-complete prefix.
 */
[[nodiscard]] std::string bounded_untrusted_summary(std::string_view label, std::string_view value)
{
	const std::size_t prefix_size =
		value.empty() ? 0u : std::min(MAX_PROVIDER_DIAGNOSTIC_PREFIX_BYTES, value.size() - 1u);
	std::string summary;
	summary.reserve(label.size() + 48u + (prefix_size * 4u));
	summary.append(label);
	summary.append("[length=");
	summary.append(std::to_string(value.size()));
	summary.append(",prefix='");
	for (std::size_t index = 0; index < prefix_size; ++index) {
		const uint8_t byte = static_cast<uint8_t>(value[index]);
		if (byte >= 0x20u && byte <= 0x7eu && byte != static_cast<uint8_t>('\'') &&
		    byte != static_cast<uint8_t>('\\')) {
			summary.push_back(static_cast<char>(byte));
			continue;
		}
		summary.append("\\x");
		summary.push_back(hexadecimal_digit(static_cast<uint8_t>(byte >> 4u)));
		summary.push_back(hexadecimal_digit(static_cast<uint8_t>(byte & 0x0fu)));
	}
	summary.append(value.empty() ? "',truncated=false]" : "',truncated=true]");
	return summary;
}

/**
 * @brief Validate the complete canonical provider type-URL grammar.
 *
 * @param type_url Candidate complete URL.
 * @return true only for the exact prefix followed by protobuf identifier atoms.
 */
[[nodiscard]] constexpr bool is_canonical_type_url(std::string_view type_url) noexcept
{
	if (!type_url.starts_with(PROVIDER_TYPE_URL_PREFIX)) {
		return false;
	}
	type_url.remove_prefix(PROVIDER_TYPE_URL_PREFIX.size());
	if (type_url.empty()) {
		return false;
	}

	bool at_segment_start = true;
	for (const char value : type_url) {
		if (value == '.') {
			if (at_segment_start) {
				return false;
			}
			at_segment_start = true;
			continue;
		}
		if (at_segment_start) {
			if (!common::execution_topology::is_identifier_first_char(value)) {
				return false;
			}
			at_segment_start = false;
			continue;
		}
		if (!common::execution_topology::is_identifier_char(value)) {
			return false;
		}
	}
	return !at_segment_start;
}

/**
 * @brief Validate one stable provider-local identity.
 *
 * @param value Candidate identity.
 * @param field_name Trusted field name used in diagnostics.
 * @return OK for a bounded topology identifier; INVALID_ARGUMENT otherwise.
 */
[[nodiscard]] status validate_provider_id(std::string_view value, std::string_view field_name)
{
	if (value.size() > MAX_PROVIDER_ID_BYTES || !common::execution_topology::is_topology_identifier(value)) {
		return status::invalid_argument(std::string(field_name) + " must match [A-Za-z_][A-Za-z0-9_]* within " +
						std::to_string(MAX_PROVIDER_ID_BYTES) +
						" bytes: " + bounded_untrusted_summary("value", value));
	}
	return status::ok();
}

/**
 * @brief Check one canonical lowercase hexadecimal byte.
 *
 * @param value Candidate ASCII byte.
 * @return true for `0-9` or `a-f`.
 */
[[nodiscard]] constexpr bool is_lower_hex(char value) noexcept
{
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

/**
 * @brief Convert one already-validated lowercase hexadecimal byte.
 *
 * @param value Canonical hexadecimal byte.
 * @return Numeric nibble value.
 */
[[nodiscard]] constexpr uint8_t hex_value(char value) noexcept
{
	return value <= '9' ? static_cast<uint8_t>(value - '0') : static_cast<uint8_t>(10 + (value - 'a'));
}

/**
 * @brief Validate one exact lowercase PCI domain/bus/device/function address.
 *
 * @param address Candidate `dddd:bb:ss.f` text.
 * @return OK for canonical bounded BDF text; INVALID_ARGUMENT otherwise.
 */
[[nodiscard]] status validate_pci_address_impl(std::string_view address)
{
	constexpr std::size_t PCI_ADDRESS_SIZE = 12;
	if (address.size() != PCI_ADDRESS_SIZE || address[4] != ':' || address[7] != ':' || address[10] != '.') {
		return status::invalid_argument("pci_address must use exact lowercase dddd:bb:ss.f form: " +
						bounded_untrusted_summary("pci_address", address));
	}
	constexpr std::array<std::size_t, 9> HEX_POSITIONS{0, 1, 2, 3, 5, 6, 8, 9, 11};
	for (const std::size_t position : HEX_POSITIONS) {
		if (!is_lower_hex(address[position])) {
			return status::invalid_argument("pci_address must use exact lowercase hexadecimal digits: " +
							bounded_untrusted_summary("pci_address", address));
		}
	}
	const uint8_t device = static_cast<uint8_t>((hex_value(address[8]) << 4u) | hex_value(address[9]));
	const uint8_t function = hex_value(address[11]);
	if (device > 0x1fu || function > 0x07u) {
		return status::invalid_argument("pci_address device/function is outside PCI BDF range: " +
						bounded_untrusted_summary("pci_address", address));
	}
	return status::ok();
}

/**
 * @brief Check the first byte of the admitted TAP interface grammar.
 *
 * @param value Candidate ASCII byte.
 * @return true for an ASCII letter or underscore.
 */
[[nodiscard]] constexpr bool is_tap_first_char(char value) noexcept
{
	return common::execution_topology::is_identifier_first_char(value);
}

/**
 * @brief Check a noninitial byte of the admitted TAP interface grammar.
 *
 * @param value Candidate ASCII byte.
 * @return true for an admitted identifier, dot, or hyphen byte.
 */
[[nodiscard]] constexpr bool is_tap_char(char value) noexcept
{
	return common::execution_topology::is_identifier_char(value) || value == '-' || value == '.';
}

/**
 * @brief Validate one bounded canonical Linux TAP interface name.
 *
 * @param name Candidate interface name.
 * @return OK for the exact catalog grammar; INVALID_ARGUMENT otherwise.
 */
[[nodiscard]] status validate_tap_interface_name(std::string_view name)
{
	if (name.empty() || name.size() > MAX_TAP_INTERFACE_NAME_BYTES || !is_tap_first_char(name.front()) ||
	    !std::all_of(name.begin() + 1, name.end(), is_tap_char)) {
		return status::invalid_argument("TAP interface_name must match [A-Za-z_][A-Za-z0-9_.-]{0,14}: " +
						bounded_untrusted_summary("interface_name", name));
	}
	return status::ok();
}

/**
 * @brief Validate Linux canonical numeric IPv4 text without DNS or repair.
 *
 * The input must both parse through `inet_pton(AF_INET)` and equal the matching
 * `inet_ntop` rendering.
 *
 * @param address Candidate IPv4 text.
 * @return OK for canonical numeric text; INVALID_ARGUMENT for input errors;
 *         INTERNAL_ERROR if libc cannot render a successfully parsed address.
 */
[[nodiscard]] status validate_canonical_ipv4(std::string_view address)
{
	in_addr parsed{};
	const std::string owned(address);
	if (inet_pton(AF_INET, owned.c_str(), &parsed) != 1) {
		return status::invalid_argument("ipv4_address must be numeric IPv4 accepted by inet_pton(AF_INET): " +
						bounded_untrusted_summary("ipv4_address", address));
	}

	std::array<char, INET_ADDRSTRLEN> canonical{};
	if (inet_ntop(AF_INET, &parsed, canonical.data(), static_cast<socklen_t>(canonical.size())) == nullptr) {
		return status::internal_error("inet_ntop(AF_INET) failed after successful provider IPv4 validation");
	}
	if (address != std::string_view(canonical.data())) {
		return status::invalid_argument("ipv4_address uses a noncanonical numeric spelling: " +
						bounded_untrusted_summary("ipv4_address", address));
	}
	return status::ok();
}

/**
 * @brief Accept one generated empty message as a complete current policy.
 *
 * Wire-tree validation runs before this normalizer, so empty means no known or
 * unknown state rather than ignored input.
 *
 * @tparam message_type Generated empty contract type.
 * @param configuration Non-null decoded empty policy.
 * @return Always OK.
 */
template <typename message_type>
[[nodiscard]] status normalize_empty_contract(message_type *configuration)
{
	(void)configuration;
	return status::ok();
}

/**
 * @brief Validate and sort one DPDK driver's exact port set.
 *
 * @param configuration Mutable generated message to normalize in place.
 * @return OK after sorting; INVALID_ARGUMENT for empty, duplicate, malformed,
 *         or attachment-less ports.
 */
[[nodiscard]] status normalize_dpdk_driver(kinetum::io::dpdk::v1::DpdkDriverConfig *configuration)
{
	if (configuration->ports_size() == 0) {
		return status::invalid_argument("DpdkDriverConfig.ports[] must not be empty");
	}

	std::vector<kinetum::io::dpdk::v1::DpdkDriverPort> ports;
	ports.reserve(static_cast<std::size_t>(configuration->ports_size()));
	for (const auto &port : configuration->ports()) {
		auto id_status = validate_provider_id(port.driver_port_id(), "DpdkDriverPort.driver_port_id");
		if (!id_status.is_ok()) {
			return id_status;
		}
		switch (port.attachment_case()) {
		case kinetum::io::dpdk::v1::DpdkDriverPort::kPci: {
			auto pci_status = validate_pci_address(port.pci().pci_address());
			if (!pci_status.is_ok()) {
				return pci_status;
			}
			break;
		}
		case kinetum::io::dpdk::v1::DpdkDriverPort::kTap: {
			auto tap_status = validate_tap_interface_name(port.tap().interface_name());
			if (!tap_status.is_ok()) {
				return tap_status;
			}
			break;
		}
		case kinetum::io::dpdk::v1::DpdkDriverPort::ATTACHMENT_NOT_SET:
			return status::invalid_argument("DpdkDriverPort.attachment must select exactly PCI or TAP");
		}
		ports.push_back(port);
	}

	std::sort(ports.begin(), ports.end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.driver_port_id() < rhs.driver_port_id(); });
	for (std::size_t index = 1; index < ports.size(); ++index) {
		if (ports[index - 1].driver_port_id() == ports[index].driver_port_id()) {
			return status::invalid_argument(
				"DpdkDriverConfig.ports[] contains duplicate driver_port_id: " +
				bounded_untrusted_summary("driver_port_id", ports[index].driver_port_id()));
		}
	}

	configuration->clear_ports();
	for (const auto &port : ports) {
		configuration->add_ports()->CopyFrom(port);
	}
	return status::ok();
}

/**
 * @brief Require every queue domain to belong to the exact DPDK facility.
 * @param binding Complete common-validated queue storage request.
 * @return OK for DPDK storage sharing the driver's sole facility.
 */
[[nodiscard]] status validate_dpdk_io_storage(const io_storage_binding &binding)
{
	if (binding.facility_indices.size() != 1u) {
		return status::invalid_argument("DPDK queue storage requires one exact driver facility");
	}
	for (const auto &domain : binding.domains) {
		if (domain.type_url != DPDK_STORAGE_TYPE_URL || domain.facility_indices.size() != 1u ||
		    domain.facility_indices.front() != binding.facility_indices.front()) {
			return status::invalid_argument(
				"DPDK queue storage must use its exact native storage contract and facility");
		}
	}
	return status::ok();
}

/**
 * @brief Prove the CPU span shape consumed by a UDP queue.
 * @param binding Complete common-validated queue storage request.
 * @return OK for readable contiguous storage, also writable when receiving.
 */
[[nodiscard]] status validate_udp_io_storage(const io_storage_binding &binding)
{
	for (const auto &domain : binding.domains) {
		if (!domain.capabilities.cpu_contiguous_read ||
		    (binding.direction == io_direction::RX && !domain.capabilities.cpu_contiguous_write)) {
			return status::invalid_argument("UDP queue storage lacks its required contiguous CPU span");
		}
	}
	return status::ok();
}

/**
 * @brief Validate the sole current DPDK packet-storage tuning value.
 *
 * @param configuration Mutable generated storage policy.
 * @return OK through the exact cache bound; INVALID_ARGUMENT above it.
 */
[[nodiscard]] status normalize_dpdk_storage(kinetum::storage::dpdk::v1::DpdkStorageConfig *configuration)
{
	if (configuration->cache_size() > MAX_DPDK_MEMPOOL_CACHE_SIZE) {
		return status::invalid_argument("DpdkStorageConfig.cache_size exceeds the " +
						std::to_string(MAX_DPDK_MEMPOOL_CACHE_SIZE) + "-entry contract bound");
	}
	return status::ok();
}

/**
 * @brief Validate and sort one UDP driver's exact endpoint set.
 *
 * @param configuration Mutable generated message to normalize in place.
 * @return OK after sorting; INVALID_ARGUMENT for empty, duplicate, malformed,
 *         noncanonical-address, or nonrepresentable-port input.
 */
[[nodiscard]] status normalize_udp_driver(kinetum::io::udp::v1::UdpDriverConfig *configuration)
{
	if (configuration->ports_size() == 0) {
		return status::invalid_argument("UdpDriverConfig.ports[] must not be empty");
	}

	std::vector<kinetum::io::udp::v1::UdpDriverPort> ports;
	ports.reserve(static_cast<std::size_t>(configuration->ports_size()));
	for (const auto &port : configuration->ports()) {
		auto id_status = validate_provider_id(port.driver_port_id(), "UdpDriverPort.driver_port_id");
		if (!id_status.is_ok()) {
			return id_status;
		}
		auto address_status = validate_canonical_ipv4(port.ipv4_address());
		if (!address_status.is_ok()) {
			return address_status;
		}
		if (port.port() > std::numeric_limits<uint16_t>::max()) {
			return status::invalid_argument("UdpDriverPort.port exceeds the uint16_t socket-port range");
		}
		ports.push_back(port);
	}

	std::sort(ports.begin(), ports.end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.driver_port_id() < rhs.driver_port_id(); });
	for (std::size_t index = 1; index < ports.size(); ++index) {
		if (ports[index - 1].driver_port_id() == ports[index].driver_port_id()) {
			return status::invalid_argument(
				"UdpDriverConfig.ports[] contains duplicate driver_port_id: " +
				bounded_untrusted_summary("driver_port_id", ports[index].driver_port_id()));
		}
	}

	configuration->clear_ports();
	for (const auto &port : ports) {
		configuration->add_ports()->CopyFrom(port);
	}
	return status::ok();
}

/**
 * @brief Execute generated decode through normalized deterministic bytes.
 *
 * @tparam message_type Exact generated contract type selected by the row.
 * @tparam normalizer Provider-policy validator and declared set normalizer.
 * @param configuration Bounded outer envelope and serialized payload.
 * @return Canonical deterministic payload or a step-qualified failure.
 */
template <typename message_type, status (*normalizer)(message_type *)>
[[nodiscard]] status_or<std::string> canonicalize_typed_payload(const google::protobuf::Any &configuration)
{
	const std::string_view payload = configuration.value();
	message_type message;
	const char *payload_data = payload.empty() ? "" : payload.data();
	if (!message.ParseFromArray(payload_data, static_cast<int>(payload.size()))) {
		return step_error(provider_configuration_step::CONCRETE_DECODE, status_code::INVALID_ARGUMENT,
				  "payload is not a complete " + message.GetDescriptor()->full_name());
	}

	const auto envelope_unknown_status =
		common::reject_unknown_protobuf_fields_recursive(configuration, "provider configuration Any");
	if (!envelope_unknown_status.is_ok()) {
		return wrap_step_error(provider_configuration_step::WIRE_TREE_VALIDATION, envelope_unknown_status);
	}
	const auto unknown_status =
		common::reject_unknown_protobuf_fields_recursive(message, message.GetDescriptor()->full_name());
	if (!unknown_status.is_ok()) {
		return wrap_step_error(provider_configuration_step::WIRE_TREE_VALIDATION, unknown_status);
	}
	const auto enum_status =
		common::reject_invalid_protobuf_enum_values_recursive(message, message.GetDescriptor()->full_name());
	if (!enum_status.is_ok()) {
		return wrap_step_error(provider_configuration_step::WIRE_TREE_VALIDATION, enum_status);
	}

	const auto validation_status = normalizer(&message);
	if (!validation_status.is_ok()) {
		return wrap_step_error(provider_configuration_step::PROVIDER_VALIDATION, validation_status);
	}

	auto serialized_or = common::serialize_protobuf_deterministically(message);
	if (!serialized_or.is_ok()) {
		return wrap_step_error(provider_configuration_step::NORMALIZED_SERIALIZATION, serialized_or.error());
	}
	if (serialized_or.value().size() > MAX_PROVIDER_CONFIGURATION_BYTES) {
		return step_error(provider_configuration_step::NORMALIZED_SERIALIZATION,
				  status_code::RESOURCE_EXHAUSTED,
				  "normalized payload exceeds the provider configuration bound");
	}
	return std::move(serialized_or).value();
}

/**
 * @brief Return one generated type's process-lifetime descriptor.
 *
 * @tparam message_type Generated provider contract type.
 * @return Stable generated descriptor pointer.
 */
template <typename message_type>
[[nodiscard]] const Descriptor *message_descriptor()
{
	return message_type::descriptor();
}

/** Closed pure contract catalog owning capability and dependency semantics. */
constexpr std::array<provider_contract_row, 8> CONTRACT_ROWS{
	provider_contract_row{
		provider_contract_descriptor{
			CPU_EXECUTION_TYPE_URL,
			provider_contract_role::EXECUTION,
			provider_capability_projection{execution_projection{CPU_ACCESS, true, true}},
			{},
			CPU_EXECUTION_HOST_REQUIREMENTS,
		},
		&canonicalize_typed_payload<kinetum::execution::cpu::v1::CpuExecutionConfig,
					    normalize_empty_contract<kinetum::execution::cpu::v1::CpuExecutionConfig>>,
		&message_descriptor<kinetum::execution::cpu::v1::CpuExecutionConfig>,
	},
	provider_contract_row{
		provider_contract_descriptor{
			DPDK_FACILITY_TYPE_URL,
			provider_contract_role::PROCESS_FACILITY,
			provider_capability_projection{process_facility_projection{true, true, true}},
			{},
			DPDK_FACILITY_HOST_REQUIREMENTS,
		},
		&canonicalize_typed_payload<kinetum::facility::dpdk::v1::DpdkFacilityConfig,
					    normalize_empty_contract<kinetum::facility::dpdk::v1::DpdkFacilityConfig>>,
		&message_descriptor<kinetum::facility::dpdk::v1::DpdkFacilityConfig>,
	},
	provider_contract_row{
		provider_contract_descriptor{
			DPDK_DRIVER_TYPE_URL,
			provider_contract_role::IO_DRIVER,
			provider_capability_projection{io_driver_projection{
				NIC_DMA_ACCESS,
				RX_TX_DIRECTIONS,
				NONE_AND_RSS_STEERING,
				DPDK_RSS_HASH_FIELDS,
				MAX_DPDK_RSS_KEY_BYTES,
				true,
				static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) - 1u,
				std::numeric_limits<uint16_t>::max(),
				true,
				&validate_dpdk_io_storage,
			}},
			DPDK_FACILITY_DEPENDENCY,
			DPDK_DRIVER_HOST_REQUIREMENTS,
		},
		&canonicalize_typed_payload<kinetum::io::dpdk::v1::DpdkDriverConfig, normalize_dpdk_driver>,
		&message_descriptor<kinetum::io::dpdk::v1::DpdkDriverConfig>,
	},
	provider_contract_row{
		provider_contract_descriptor{
			UDP_DRIVER_TYPE_URL,
			provider_contract_role::IO_DRIVER,
			provider_capability_projection{io_driver_projection{
				CPU_ACCESS,
				RX_TX_DIRECTIONS,
				NO_STEERING,
				{},
				0u,
				false,
				0u,
				std::numeric_limits<uint32_t>::max(),
				true,
				&validate_udp_io_storage,
			}},
			{},
			UDP_DRIVER_HOST_REQUIREMENTS,
		},
		&canonicalize_typed_payload<kinetum::io::udp::v1::UdpDriverConfig, normalize_udp_driver>,
		&message_descriptor<kinetum::io::udp::v1::UdpDriverConfig>,
	},
	provider_contract_row{
		provider_contract_descriptor{
			DPDK_STORAGE_TYPE_URL,
			provider_contract_role::PACKET_STORAGE,
			provider_capability_projection{packet_storage_projection{
				static_cast<packet_access_agent_mask>(CPU_ACCESS | NIC_DMA_ACCESS), true, true, true,
				std::numeric_limits<uint16_t>::max()}},
			DPDK_FACILITY_DEPENDENCY,
			HOST_NUMA_MEMORY_REQUIREMENTS,
		},
		&canonicalize_typed_payload<kinetum::storage::dpdk::v1::DpdkStorageConfig, normalize_dpdk_storage>,
		&message_descriptor<kinetum::storage::dpdk::v1::DpdkStorageConfig>,
	},
	provider_contract_row{
		provider_contract_descriptor{
			HOST_STORAGE_TYPE_URL,
			provider_contract_role::PACKET_STORAGE,
			provider_capability_projection{packet_storage_projection{CPU_ACCESS, true, true, true,
										 std::numeric_limits<uint32_t>::max()}},
			{},
			HOST_NUMA_MEMORY_REQUIREMENTS,
		},
		&canonicalize_typed_payload<kinetum::storage::host::v1::HostStorageConfig,
					    normalize_empty_contract<kinetum::storage::host::v1::HostStorageConfig>>,
		&message_descriptor<kinetum::storage::host::v1::HostStorageConfig>,
	},
	provider_contract_row{
		provider_contract_descriptor{
			ZERO_COPY_SHARE_TYPE_URL,
			provider_contract_role::STORAGE_TRANSITION,
			provider_capability_projection{storage_transition_projection{
				storage_transition_mode::ZERO_COPY_SHARE, 0, 0, false, false}},
			{},
			{},
		},
		&canonicalize_typed_payload<kinetum::transition::core::v1::ZeroCopyShareConfig,
					    normalize_empty_contract<kinetum::transition::core::v1::ZeroCopyShareConfig>>,
		&message_descriptor<kinetum::transition::core::v1::ZeroCopyShareConfig>,
	},
	provider_contract_row{
		provider_contract_descriptor{
			BOUNDED_COPY_TYPE_URL,
			provider_contract_role::STORAGE_TRANSITION,
			provider_capability_projection{storage_transition_projection{
				storage_transition_mode::BOUNDED_COPY, CPU_ACCESS, CPU_ACCESS, true, true}},
			{},
			HOST_NUMA_MEMORY_REQUIREMENTS,
		},
		&canonicalize_typed_payload<kinetum::transition::cpu::v1::BoundedCopyConfig,
					    normalize_empty_contract<kinetum::transition::cpu::v1::BoundedCopyConfig>>,
		&message_descriptor<kinetum::transition::cpu::v1::BoundedCopyConfig>,
	},
};

/**
 * @brief Prove compile-time nondecreasing lexical row order.
 *
 * @return true when every adjacent type URL is lexically ordered.
 */
[[nodiscard]] consteval bool catalog_is_lexicographically_sorted()
{
	for (std::size_t index = 1; index < CONTRACT_ROWS.size(); ++index) {
		if (CONTRACT_ROWS[index].descriptor.type_url < CONTRACT_ROWS[index - 1].descriptor.type_url) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Prove compile-time pairwise type-URL uniqueness.
 *
 * @return true when no two rows carry the same complete type URL.
 */
[[nodiscard]] consteval bool catalog_has_unique_type_urls()
{
	for (std::size_t first = 0; first < CONTRACT_ROWS.size(); ++first) {
		for (std::size_t second = first + 1u; second < CONTRACT_ROWS.size(); ++second) {
			if (CONTRACT_ROWS[first].descriptor.type_url == CONTRACT_ROWS[second].descriptor.type_url) {
				return false;
			}
		}
	}
	return true;
}

/**
 * @brief Prove every authored row identity satisfies its own admission rule.
 *
 * @return true when all row URLs are canonical and within the public bound.
 */
[[nodiscard]] consteval bool catalog_type_urls_are_canonical_and_bounded()
{
	for (const auto &row : CONTRACT_ROWS) {
		if (row.descriptor.type_url.size() > MAX_PROVIDER_TYPE_URL_BYTES ||
		    !is_canonical_type_url(row.descriptor.type_url)) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Prove each structural role owns the matching projection alternative.
 *
 * @return true when no row can publish a role/projection disagreement.
 */
[[nodiscard]] consteval bool catalog_roles_match_capability_projections()
{
	for (const auto &row : CONTRACT_ROWS) {
		switch (row.descriptor.role) {
		case provider_contract_role::PROCESS_FACILITY:
			if (!std::holds_alternative<process_facility_projection>(row.descriptor.capabilities)) {
				return false;
			}
			break;
		case provider_contract_role::IO_DRIVER:
			if (!std::holds_alternative<io_driver_projection>(row.descriptor.capabilities)) {
				return false;
			}
			break;
		case provider_contract_role::PACKET_STORAGE:
			if (!std::holds_alternative<packet_storage_projection>(row.descriptor.capabilities)) {
				return false;
			}
			break;
		case provider_contract_role::EXECUTION:
			if (!std::holds_alternative<execution_projection>(row.descriptor.capabilities)) {
				return false;
			}
			break;
		case provider_contract_role::STORAGE_TRANSITION:
			if (!std::holds_alternative<storage_transition_projection>(row.descriptor.capabilities)) {
				return false;
			}
			break;
		default:
			return false;
		}
	}
	return true;
}

/**
 * @brief Prove CPU span projections cannot exist without CPU agent access.
 *
 * Agent identity and byte-shape permissions are separate facts, but a CPU
 * contiguous-read/write claim is coherent only when the same row names CPU as
 * an available or required access agent.
 *
 * @return true when every storage and execution CPU shape is agent-backed.
 */
[[nodiscard]] consteval bool catalog_cpu_shape_projections_are_coherent()
{
	for (const auto &row : CONTRACT_ROWS) {
		if (const auto *storage = std::get_if<packet_storage_projection>(&row.descriptor.capabilities);
		    storage != nullptr) {
			if ((storage->cpu_contiguous_read || storage->cpu_contiguous_write) &&
			    !packet_access_agents_include(storage->access_agents, CPU_ACCESS)) {
				return false;
			}
		}
		if (const auto *execution = std::get_if<execution_projection>(&row.descriptor.capabilities);
		    execution != nullptr) {
			if ((execution->requires_cpu_contiguous_read || execution->requires_cpu_contiguous_write) &&
			    !packet_access_agents_include(execution->required_access_agents, CPU_ACCESS)) {
				return false;
			}
		}
	}
	return true;
}

/**
 * @brief Prove every facility dependency is canonical, nonzero, and resolvable.
 *
 * Dependency spans must be strictly sorted so one row cannot request the same
 * facility contract twice under separate cardinality records.
 *
 * @return true when every dependency resolves to one process-facility row.
 */
[[nodiscard]] consteval bool catalog_facility_dependencies_are_exact()
{
	for (const auto &row : CONTRACT_ROWS) {
		for (std::size_t index = 0; index < row.descriptor.facility_dependencies.size(); ++index) {
			const auto &dependency = row.descriptor.facility_dependencies[index];
			if (dependency.exact_instance_count == 0u || !is_canonical_type_url(dependency.type_url) ||
			    (index != 0u &&
			     !(row.descriptor.facility_dependencies[index - 1u].type_url < dependency.type_url))) {
				return false;
			}

			bool matched_facility = false;
			for (const auto &candidate : CONTRACT_ROWS) {
				if (candidate.descriptor.type_url == dependency.type_url &&
				    candidate.descriptor.role == provider_contract_role::PROCESS_FACILITY) {
					matched_facility = true;
					break;
				}
			}
			if (!matched_facility) {
				return false;
			}
		}
	}
	return true;
}

/**
 * @brief Prove every host requirement is known, sorted, and unique per row.
 *
 * Strict fact order prevents one row from assigning two proof phases
 * to the same host requirement.
 *
 * @return true when every requirement is a known exact fact/authority pair.
 */
[[nodiscard]] consteval bool catalog_host_requirements_are_exact()
{
	for (const auto &row : CONTRACT_ROWS) {
		for (std::size_t index = 0; index < row.descriptor.host_requirements.size(); ++index) {
			const auto &requirement = row.descriptor.host_requirements[index];
			if (index != 0u && !(row.descriptor.host_requirements[index - 1u].fact < requirement.fact)) {
				return false;
			}
			switch (requirement.fact) {
			case provider_host_fact::DPDK_EAL_RUNTIME:
			case provider_host_fact::DPDK_HUGEPAGE_PAYLOAD_FLOOR:
			case provider_host_fact::DPDK_ETHDEV_PORT:
			case provider_host_fact::LINUX_IPV4_DATAGRAM_SOCKET:
			case provider_host_fact::HOST_NUMA_MEMORY:
			case provider_host_fact::CPU_WORKER_SET:
				break;
			default:
				return false;
			}
			switch (requirement.phase) {
			case provider_host_proof_phase::QUARK_LIVE_HOST:
			case provider_host_proof_phase::COMPONENT_HOST_PROOF:
			case provider_host_proof_phase::MATERIALIZATION_PROOF:
				break;
			default:
				return false;
			}
		}
	}
	return true;
}

/**
 * @brief Prove every row owns complete generated-type operations.
 *
 * @return true when no canonicalizer or descriptor accessor is absent.
 */
[[nodiscard]] consteval bool catalog_operations_are_complete()
{
	for (const auto &row : CONTRACT_ROWS) {
		if (row.canonicalize_payload == nullptr || row.message_descriptor == nullptr) {
			return false;
		}
		if (const auto *driver = std::get_if<io_driver_projection>(&row.descriptor.capabilities);
		    driver != nullptr && driver->validate_storage == nullptr) {
			return false;
		}
	}
	return true;
}

static_assert(catalog_is_lexicographically_sorted(), "provider contract catalog must be lexicographically sorted");
static_assert(catalog_has_unique_type_urls(), "provider contract catalog type URLs must be unique");
static_assert(catalog_type_urls_are_canonical_and_bounded(),
	      "provider contract catalog type URLs must satisfy the admitted identity contract");
static_assert(catalog_roles_match_capability_projections(),
	      "provider contract roles must agree with their capability projection alternatives");
static_assert(catalog_cpu_shape_projections_are_coherent(),
	      "provider CPU span projections must name CPU as an access agent");
static_assert(catalog_facility_dependencies_are_exact(),
	      "provider facility dependencies must be sorted, unique, nonzero, and catalog-resolvable");
static_assert(catalog_host_requirements_are_exact(),
	      "provider host requirements must be known, sorted, unique, and single-authority");
static_assert(catalog_operations_are_complete(), "provider contract rows must own complete generated-type operations");

/**
 * @brief Resolve one private row by exact complete type URL.
 *
 * @param type_url Complete candidate URL.
 * @return Stable row pointer, or nullptr when absent.
 */
[[nodiscard]] const provider_contract_row *find_contract_row(std::string_view type_url) noexcept
{
	std::size_t first = 0;
	std::size_t last = CONTRACT_ROWS.size();
	while (first < last) {
		const std::size_t middle = first + ((last - first) / 2u);
		if (CONTRACT_ROWS[middle].descriptor.type_url < type_url) {
			first = middle + 1u;
		} else {
			last = middle;
		}
	}
	if (first == CONTRACT_ROWS.size() || CONTRACT_ROWS[first].descriptor.type_url != type_url) {
		return nullptr;
	}
	return &CONTRACT_ROWS[first];
}

}  // namespace

status validate_pci_address(std::string_view address)
try {
	return validate_pci_address_impl(address);
} catch (const std::bad_alloc &) {
	return status::resource_exhausted(
		kinetum::common::static_status_text("PCI address validation exhausted host memory"));
} catch (const std::length_error &) {
	return status(status_code::OUT_OF_RANGE,
		      kinetum::common::static_status_text("PCI address diagnostic exceeded the host size domain"));
}

std::size_t provider_contract_count() noexcept
{
	return CONTRACT_ROWS.size();
}

const provider_contract_descriptor *provider_contract_at(std::size_t index) noexcept
{
	return index < CONTRACT_ROWS.size() ? &CONTRACT_ROWS[index].descriptor : nullptr;
}

common::status validate_io_storage_binding(const io_driver_projection &driver, const io_storage_binding &binding)
{
	if ((binding.direction != io_direction::RX && binding.direction != io_direction::TX) ||
	    binding.domains.empty() || (binding.direction == io_direction::RX && binding.domains.size() != 1u) ||
	    driver.validate_storage == nullptr) {
		return common::status::invalid_argument("I/O storage binding has an invalid role or domain population");
	}
	for (const auto &domain : binding.domains) {
		if (!packet_access_agents_include(domain.capabilities.access_agents, driver.packet_access_agents)) {
			return common::status::invalid_argument(
				"I/O storage domain lacks the exact driver's access agents");
		}
	}
	return driver.validate_storage(binding);
}

const provider_contract_descriptor *find_provider_contract(std::string_view type_url) noexcept
{
	const provider_contract_row *row = find_contract_row(type_url);
	return row != nullptr ? &row->descriptor : nullptr;
}

const Descriptor *provider_configuration_message_descriptor(std::string_view type_url)
{
	const provider_contract_row *row = find_contract_row(type_url);
	return row != nullptr ? row->message_descriptor() : nullptr;
}

status_or<canonical_provider_configuration>
canonicalize_provider_configuration(provider_contract_role expected_role, const google::protobuf::Any &configuration)
try {
	const std::string_view type_url = configuration.type_url();
	if (type_url.size() > MAX_PROVIDER_TYPE_URL_BYTES) {
		return step_error(provider_configuration_step::TYPE_URL_BOUND, status_code::RESOURCE_EXHAUSTED,
				  "type URL exceeds the " + std::to_string(MAX_PROVIDER_TYPE_URL_BYTES) +
					  "-byte contract bound: " + bounded_untrusted_summary("type_url", type_url));
	}
	if (!is_canonical_type_url(type_url)) {
		return step_error(provider_configuration_step::TYPE_URL_CANONICAL_FORM, status_code::INVALID_ARGUMENT,
				  "type URL is not exact type.googleapis.com/<fully.qualified.Message>: " +
					  bounded_untrusted_summary("type_url", type_url));
	}

	const provider_contract_row *row = find_contract_row(type_url);
	if (row == nullptr) {
		return step_error(provider_configuration_step::CATALOG_LOOKUP, status_code::NOT_FOUND,
				  "no provider contract matches " + bounded_untrusted_summary("type_url", type_url));
	}
	if (row->descriptor.role != expected_role) {
		return step_error(provider_configuration_step::ROLE_AGREEMENT, status_code::INVALID_ARGUMENT,
				  "catalog contract role does not match the owning plan field for " +
					  bounded_untrusted_summary("type_url", type_url));
	}

	const std::string_view payload = configuration.value();
	if (payload.size() > MAX_PROVIDER_CONFIGURATION_BYTES) {
		return step_error(provider_configuration_step::PAYLOAD_BOUND, status_code::RESOURCE_EXHAUSTED,
				  "payload exceeds the " + std::to_string(MAX_PROVIDER_CONFIGURATION_BYTES) +
					  "-byte contract bound: " + bounded_untrusted_summary("payload", payload));
	}

	auto canonical_payload_or = row->canonicalize_payload(configuration);
	if (!canonical_payload_or.is_ok()) {
		return canonical_payload_or.error();
	}

	google::protobuf::Any canonical_configuration;
	canonical_configuration.set_type_url(row->descriptor.type_url.data(), row->descriptor.type_url.size());
	canonical_configuration.set_value(std::move(canonical_payload_or).value());
	if (std::string_view(canonical_configuration.type_url()) != row->descriptor.type_url) {
		return step_error(provider_configuration_step::EXACT_REPACK, status_code::INTERNAL_ERROR,
				  "canonical type URL changed while repacking");
	}
	return canonical_provider_configuration{std::cref(row->descriptor), std::move(canonical_configuration)};
} catch (const std::bad_alloc &) {
	return status::resource_exhausted(
		kinetum::common::static_status_text("provider configuration canonicalization exhausted host memory"));
} catch (const std::length_error &) {
	return status(status_code::OUT_OF_RANGE,
		      kinetum::common::static_status_text(
			      "provider configuration canonicalization exceeded the host size domain"));
}

}  // namespace kinetum::provider
