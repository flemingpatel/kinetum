// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_contract_catalog.hpp
 * @brief Pure typed provider-configuration and capability contract catalog.
 * @author Fleming Patel
 *
 * The catalog is a closed, immutable cold-path authority. Exact canonical
 * protobuf type URLs select generated configuration contracts; rows project
 * provider-neutral role, access, facility-dependency, transition, and host-
 * evidence requirements. It owns no native provider object, registration,
 * component factory, runtime selection, hashing, or side effect.
 *
 * Canonicalization applies a fixed ten-step reject ladder. It validates an
 * exact type URL and expected role, decodes the generated message, rejects
 * unknown wire state, validates provider policy, normalizes only declared
 * set-like fields, deterministically serializes, and repacks one exact Any.
 * The returned Any is the terminal pure-catalog representation. A consuming
 * identity authority owns hashing of that already-normalized representation.
 *
 * @par Thread Safety
 * Catalog rows and projections have static immutable lifetime. Lookup and
 * canonicalization are stateless and safe for concurrent calls.
 *
 * @par Performance
 * Protobuf parsing, reflection, sorting, diagnostic construction, and repacking
 * are cold-path operations. This component must remain outside every packet-
 * worker call graph.
 */

#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <span>
#include <string_view>
#include <variant>

#include <google/protobuf/any.pb.h>

#include "src/common/status_or.hpp"

namespace google::protobuf
{
class Descriptor;
}  // namespace google::protobuf

namespace kinetum::provider
{

/** @brief Exact required prefix for every canonical provider type URL. */
inline constexpr std::string_view PROVIDER_TYPE_URL_PREFIX = "type.googleapis.com/";

/** @brief Maximum admitted provider type-URL bytes, bounding lookup and diagnostics. */
inline constexpr std::size_t MAX_PROVIDER_TYPE_URL_BYTES = 256;

/** @brief Maximum serialized provider configuration, bounding cold admission work. */
inline constexpr std::size_t MAX_PROVIDER_CONFIGURATION_BYTES = std::size_t{64} * 1024u;

/** @brief Maximum untrusted input bytes rendered into one diagnostic prefix. */
inline constexpr std::size_t MAX_PROVIDER_DIAGNOSTIC_PREFIX_BYTES = 48;

/** @brief Maximum stable provider-local identity under the shared topology grammar. */
inline constexpr std::size_t MAX_PROVIDER_ID_BYTES = 128;

/** @brief Linux interface-name payload bytes excluding the terminating NUL. */
inline constexpr std::size_t MAX_TAP_INTERFACE_NAME_BYTES = 15;

/** @brief Maximum admitted DPDK per-lcore mempool cache size. */
inline constexpr uint32_t MAX_DPDK_MEMPOOL_CACHE_SIZE = 512;

/**
 * @brief Validate one canonical lowercase PCI domain/bus/device/function identity.
 *
 * Provider configuration and Gluon hardware admission consume this one grammar,
 * so physical inventory cannot name an attachment differently from its exact
 * typed provider configuration.
 *
 * @param address Candidate `dddd:bb:ss.f` text.
 * @return OK for canonical bounded BDF text; INVALID_ARGUMENT for malformed
 *         input; RESOURCE_EXHAUSTED or OUT_OF_RANGE if a rejection diagnostic
 *         cannot be represented.
 *
 * @par Thread Safety
 * Stateless and safe for concurrent calls.
 *
 * @par Performance
 * Cold-path fixed-width validation with no protobuf or provider operation.
 */
[[nodiscard]] common::status validate_pci_address(std::string_view address);

/** @brief Exact contract identity for the current DPDK process facility. */
inline constexpr std::string_view DPDK_FACILITY_TYPE_URL =
	"type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";

/** @brief Exact contract identity for DPDK native I/O endpoints. */
inline constexpr std::string_view DPDK_DRIVER_TYPE_URL = "type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig";

/** @brief Exact contract identity for DPDK-backed packet storage. */
inline constexpr std::string_view DPDK_STORAGE_TYPE_URL =
	"type.googleapis.com/kinetum.storage.dpdk.v1.DpdkStorageConfig";

/** @brief Exact contract identity for development UDP I/O endpoints. */
inline constexpr std::string_view UDP_DRIVER_TYPE_URL = "type.googleapis.com/kinetum.io.udp.v1.UdpDriverConfig";

/** @brief Exact contract identity for host-owned packet storage. */
inline constexpr std::string_view HOST_STORAGE_TYPE_URL =
	"type.googleapis.com/kinetum.storage.host.v1.HostStorageConfig";

/** @brief Exact contract identity for CPU stage execution. */
inline constexpr std::string_view CPU_EXECUTION_TYPE_URL =
	"type.googleapis.com/kinetum.execution.cpu.v1.CpuExecutionConfig";

/** @brief Exact contract identity for same-domain zero-copy sharing. */
inline constexpr std::string_view ZERO_COPY_SHARE_TYPE_URL =
	"type.googleapis.com/kinetum.transition.core.v1.ZeroCopyShareConfig";

/** @brief Exact contract identity for bounded CPU-mediated copies. */
inline constexpr std::string_view BOUNDED_COPY_TYPE_URL =
	"type.googleapis.com/kinetum.transition.cpu.v1.BoundedCopyConfig";

/** @brief Structural provider role selected by a plan instance. */
enum class provider_contract_role : uint8_t {
	PROCESS_FACILITY,    ///< Generation-scoped process service.
	IO_DRIVER,	     ///< Native endpoint and queue-transfer owner.
	PACKET_STORAGE,	     ///< Packet byte/record ownership domain.
	EXECUTION,	     ///< Stage execution resource owner.
	STORAGE_TRANSITION,  ///< Explicit storage-domain handoff mechanism.
};

/**
 * @brief Exact ordered step in provider Any canonicalization.
 *
 * Values are stable diagnostic/test identities, not wire values.
 */
enum class provider_configuration_step : uint8_t {
	TYPE_URL_BOUND = 1,	       ///< Bound URL work before grammar inspection.
	TYPE_URL_CANONICAL_FORM = 2,   ///< Require the complete canonical URL spelling.
	CATALOG_LOOKUP = 3,	       ///< Resolve one exact immutable row.
	ROLE_AGREEMENT = 4,	       ///< Match the row to its owning plan role.
	PAYLOAD_BOUND = 5,	       ///< Bound decode and allocation work.
	CONCRETE_DECODE = 6,	       ///< Parse the row's generated message type.
	WIRE_TREE_VALIDATION = 7,      ///< Reject unknown fields and enum numbers.
	PROVIDER_VALIDATION = 8,       ///< Validate policy and normalize declared sets.
	NORMALIZED_SERIALIZATION = 9,  ///< Emit deterministic normalized bytes.
	EXACT_REPACK = 10,	       ///< Publish the terminal canonical Any.
};

/** @brief Agent capable of directly accessing bytes in a storage domain. */
enum class packet_access_agent : uint8_t {
	CPU = 0,      ///< Host CPU load/store access.
	NIC_DMA = 1,  ///< NIC direct-memory-access participation.
};

/** @brief Compact set of packet-access agents. */
using packet_access_agent_mask = uint8_t;

/**
 * @brief Convert one access agent to its compact set bit.
 *
 * @param agent Access agent whose bit is required.
 * @return Single-bit mask for a declared agent.
 *
 * A value outside the closed internal enum is a programmer contract violation
 * and fails stop instead of being reinterpreted as an empty capability set.
 */
[[nodiscard]] constexpr packet_access_agent_mask access_agent_bit(packet_access_agent agent) noexcept
{
	switch (agent) {
	case packet_access_agent::CPU:
		return static_cast<packet_access_agent_mask>(1u << 0u);
	case packet_access_agent::NIC_DMA:
		return static_cast<packet_access_agent_mask>(1u << 1u);
	}
	std::terminate();
}

/** @brief Driver transfer directions supported by an I/O contract. */
enum class io_direction : uint8_t {
	RX = 1u,  ///< Receive transfer into a storage domain.
	TX = 2u,  ///< Transmit transfer from a storage domain.
};

/** @brief Compact set of supported I/O directions. */
using io_direction_mask = uint8_t;

/** @brief Steering mechanisms a driver contract can prove. */
enum class steering_capability : uint8_t {
	NONE = 1u,  ///< Unsteered single-queue operation.
	RSS = 2u,   ///< Receive-side scaling under an exact compiled profile.
};

/** @brief Compact set of traffic-steering capabilities. */
using steering_capability_mask = uint8_t;

/** @brief Storage-domain transition mechanism. */
enum class storage_transition_mode : uint8_t {
	ZERO_COPY_SHARE,  ///< Same domain, expanded proven access and one logical owner.
	BOUNDED_COPY,	  ///< Preallocated destination copy followed by source retirement.
};

/** @brief Host fact a provider contract requires before materialization. */
enum class provider_host_fact : uint8_t {
	DPDK_EAL_RUNTIME,	      ///< Compatible DPDK process facility is available.
	DPDK_HUGEPAGE_PAYLOAD_FLOOR,  ///< Unreserved hugepages cover the compiled payload-byte floor.
	DPDK_ETHDEV_PORT,	      ///< Exact DPDK ethdev attachment can be proven.
	LINUX_IPV4_DATAGRAM_SOCKET,   ///< Linux IPv4 datagram socket facility is available.
	HOST_NUMA_MEMORY,	      ///< Exact host NUMA placement can be satisfied.
	CPU_WORKER_SET,		      ///< Compiled CPU worker placement is host-resolvable.
};

/** @brief Sole phase that must prove one external provider requirement. */
enum class provider_host_proof_phase : uint8_t {
	QUARK_LIVE_HOST,	///< Quark proves CPU, NUMA, and host-memory truth.
	COMPONENT_HOST_PROOF,	///< A non-materializing component probe proves the fact.
	MATERIALIZATION_PROOF,	///< Native construction proves the initialized fact.
};

/** @brief One exact host-fact/evidence relation. */
struct provider_host_requirement {
	provider_host_fact fact;	  ///< Required host capability.
	provider_host_proof_phase phase;  ///< Sole proof phase.
};

/** @brief Exact facility-contract dependency and cardinality. */
struct provider_facility_dependency {
	std::string_view type_url;     ///< Required canonical facility contract.
	uint8_t exact_instance_count;  ///< Required instances of that exact contract.
};

/** @brief Process-facility sharing and generation semantics. */
struct process_facility_projection {
	bool exactly_one_per_process_generation;  ///< Exactly one matching facility instance is required.
	bool identical_configuration_required;	  ///< Sharing requires byte-identical canonical configuration.
	bool generation_safe_lease_required;	  ///< Side-by-side generations require an explicit safe lease.
};

struct io_storage_binding;

/** @brief I/O-driver transfer and steering capabilities. */
struct io_driver_projection {
	packet_access_agent_mask packet_access_agents;	    ///< Agents used by native transfer.
	io_direction_mask directions;			    ///< Supported RX/TX directions.
	steering_capability_mask steering;		    ///< Supported steering mechanisms.
	std::span<const std::string_view> rss_hash_fields;  ///< Exact supported RSS field sequence.
	uint32_t maximum_rss_key_bytes;			    ///< Largest exact RSS key accepted by the contract.
	bool supports_symmetric_rss;			    ///< Contract admits native symmetric RSS proof.
	uint32_t maximum_driver_queue_id;		    ///< Largest representable queue ID per port/direction.
	uint32_t maximum_descriptor_count;		    ///< Largest representable queue descriptor count.
	bool dense_zero_based_queues;			    ///< Queue IDs must form the exact range [0, count).
	/**
	 * @brief Prove native storage-shape and facility compatibility for the complete set.
	 * @param binding Call-borrowed queue facts after common direction/access validation.
	 * @return OK only if every domain satisfies this driver's storage contract.
	 */
	common::status (*validate_storage)(const io_storage_binding &binding);
};

/** @brief Packet-storage access and ownership capabilities. */
struct packet_storage_projection {
	packet_access_agent_mask access_agents;	 ///< Agents allowed to access stored bytes.
	bool cpu_contiguous_read;		 ///< CPU stages may read one coherent contiguous span.
	bool cpu_contiguous_write;		 ///< CPU stages may write that coherent contiguous span.
	bool writable_clone;			 ///< Domain can create an independently writable clone.
	uint32_t maximum_data_room_bytes;	 ///< Largest representable physical data room.
};

/** @brief One storage domain borrowed by a cold I/O compatibility proof. */
struct io_storage_candidate {
	std::string_view type_url;		     ///< Exact canonical storage contract.
	packet_storage_projection capabilities{};    ///< Immutable catalog-owned access and shape facts.
	std::span<const uint32_t> facility_indices;  ///< Exact resolved facility identities.
};

/** @brief Complete direction-specific storage request for one native queue. */
struct io_storage_binding {
	io_direction direction;				///< Exact RX or TX transfer role.
	std::span<const uint32_t> facility_indices;	///< Facilities owned by the I/O driver.
	std::span<const io_storage_candidate> domains;	///< Complete allocation/admission set.
};

/**
 * @brief Prove one complete I/O storage binding through its pure contract.
 *
 * RX requires one domain; TX requires a nonempty set. Common agent checks
 * precede the provider-owned shape and facility relation. Native backing and
 * queue-mode proof remain with materialization. All views are call-borrowed.
 *
 * @param driver Immutable I/O-driver contract projection.
 * @param binding Complete direction, driver facilities, and storage facts.
 * @return OK only when every common and provider-owned requirement is met.
 */
[[nodiscard]] common::status validate_io_storage_binding(const io_driver_projection &driver,
							 const io_storage_binding &binding);

/** @brief Execution-provider byte-access requirement. */
struct execution_projection {
	packet_access_agent_mask required_access_agents;  ///< Agents required by this executor.
	bool requires_cpu_contiguous_read;		  ///< CPU execution reads one coherent span.
	bool requires_cpu_contiguous_write;		  ///< CPU execution may mutate that span.
};

/**
 * @brief Test whether an access-agent set contains every required agent.
 *
 * @param available Access agents supplied by one packet-storage domain.
 * @param required Access agents required by an adjacent provider.
 * @return true only when every required agent is available.
 */
[[nodiscard]] constexpr bool packet_access_agents_include(packet_access_agent_mask available,
							  packet_access_agent_mask required) noexcept
{
	return static_cast<packet_access_agent_mask>(available & required) == required;
}

/**
 * @brief Prove one storage projection satisfies one execution projection.
 *
 * Agent access and CPU span shape are orthogonal. The executor declares the
 * exact CPU read/write shape it consumes; a caller must not infer contiguous
 * access merely because the CPU appears in the domain's agent set.
 *
 * @param storage Candidate packet-storage capabilities.
 * @param execution Exact execution-provider requirements.
 * @return true only when access and every required CPU span operation exist.
 */
[[nodiscard]] constexpr bool packet_storage_supports_execution(const packet_storage_projection &storage,
							       const execution_projection &execution) noexcept
{
	return packet_access_agents_include(storage.access_agents, execution.required_access_agents) &&
	       (!execution.requires_cpu_contiguous_read || storage.cpu_contiguous_read) &&
	       (!execution.requires_cpu_contiguous_write || storage.cpu_contiguous_write);
}

/**
 * @brief Prove one domain can realize an exact unconditional fan-out degree.
 *
 * The original successor keeps the source record. Every additional successor
 * requires an independently writable clone, so a linear path has no clone
 * requirement and no provider operation is over-constrained.
 *
 * @param storage Candidate packet-storage capabilities.
 * @param successor_count Exact authored unconditional successor count.
 * @return true when the domain needs no clone or supplies writable cloning.
 */
[[nodiscard]] constexpr bool packet_storage_supports_fanout(const packet_storage_projection &storage,
							    std::size_t successor_count) noexcept
{
	return successor_count <= 1u || storage.writable_clone;
}

/** @brief Storage-transition compatibility and staging requirements. */
struct storage_transition_projection {
	storage_transition_mode mode;				      ///< Exact transition mechanism.
	packet_access_agent_mask required_source_access_agents;	      ///< Fixed source-agent requirements.
	packet_access_agent_mask required_destination_access_agents;  ///< Fixed destination-agent requirements.
	bool requires_nonzero_staging_capacity;			      ///< Plan must provide bounded staging.
	bool requires_host_staging_numa;			      ///< Plan must place host staging explicitly.
};

/** @brief Role-partitioned generic capability projection. */
using provider_capability_projection =
	std::variant<process_facility_projection, io_driver_projection, packet_storage_projection, execution_projection,
		     storage_transition_projection>;

/**
 * @brief Immutable public facts for one exact provider contract.
 *
 * Every span refers to static catalog storage and remains valid for the process
 * lifetime. `facility_dependencies` is a sorted exact dependency/cardinality
 * set. `host_requirements` is sorted by host fact and contains one exact
 * proof phase per fact. An empty set is explicit no-facility or no-host-
 * evidence policy rather than permission to infer one.
 */
struct provider_contract_descriptor {
	std::string_view type_url;		      ///< Complete canonical protobuf Any type URL.
	provider_contract_role role;		      ///< Exact structural role.
	provider_capability_projection capabilities;  ///< Role-specific capability facts.
	std::span<const provider_facility_dependency> facility_dependencies;  ///< Exact facility requirements.
	std::span<const provider_host_requirement> host_requirements;  ///< Sorted exact host-evidence requirements.
};

/**
 * @brief Canonical terminal representation of one provider configuration.
 *
 * `contract` refers to immutable static catalog storage. `configuration`
 * contains normalized deterministic bytes under that contract's exact type
 * URL. The pure catalog deliberately provides no hashing entry point.
 */
struct canonical_provider_configuration {
	std::reference_wrapper<const provider_contract_descriptor> contract;  ///< Matched immutable catalog row.
	google::protobuf::Any configuration;				      ///< Exact normalized and repacked Any.
};

/**
 * @brief Return the stable diagnostic name for one canonicalization step.
 *
 * A value outside the closed internal enum is a programmer contract violation
 * and fails stop rather than inventing a diagnostic identity.
 *
 * @param step Step whose stable name is required.
 * @return Static lowercase hyphenated step name.
 */
[[nodiscard]] constexpr std::string_view provider_configuration_step_name(provider_configuration_step step) noexcept
{
	switch (step) {
	case provider_configuration_step::TYPE_URL_BOUND:
		return "type-url-bound";
	case provider_configuration_step::TYPE_URL_CANONICAL_FORM:
		return "type-url-canonical-form";
	case provider_configuration_step::CATALOG_LOOKUP:
		return "catalog-lookup";
	case provider_configuration_step::ROLE_AGREEMENT:
		return "role-agreement";
	case provider_configuration_step::PAYLOAD_BOUND:
		return "payload-bound";
	case provider_configuration_step::CONCRETE_DECODE:
		return "concrete-decode";
	case provider_configuration_step::WIRE_TREE_VALIDATION:
		return "wire-tree-validation";
	case provider_configuration_step::PROVIDER_VALIDATION:
		return "provider-validation";
	case provider_configuration_step::NORMALIZED_SERIALIZATION:
		return "normalized-serialization";
	case provider_configuration_step::EXACT_REPACK:
		return "exact-repack";
	}
	std::terminate();
}

/**
 * @brief Return the number of immutable provider-contract rows.
 *
 * @return Exact catalog cardinality.
 */
[[nodiscard]] std::size_t provider_contract_count() noexcept;

/**
 * @brief Read one immutable catalog row by compact index.
 *
 * @param index Catalog index in `[0, provider_contract_count())`.
 * @return Stable row pointer, or nullptr when index is out of range.
 */
[[nodiscard]] const provider_contract_descriptor *provider_contract_at(std::size_t index) noexcept;

/**
 * @brief Find one provider contract by complete exact type URL.
 *
 * This lookup performs no suffix matching, prefix repair, aliasing, or dynamic
 * descriptor discovery.
 *
 * @param type_url Complete candidate URL.
 * @return Stable exact row pointer, or nullptr when no row matches.
 */
[[nodiscard]] const provider_contract_descriptor *find_provider_contract(std::string_view type_url) noexcept;

/**
 * @brief Return the generated message descriptor for one exact catalog row.
 *
 * This inspection surface exists for schema auditing and canonical validation;
 * it does not discover or register contracts dynamically.
 *
 * @param type_url Complete exact catalog type URL.
 * @return Generated descriptor, or nullptr when no row matches.
 */
[[nodiscard]] const google::protobuf::Descriptor *provider_configuration_message_descriptor(std::string_view type_url);

/**
 * @brief Validate, normalize, deterministically serialize, and repack one Any.
 *
 * The fixed step order is: URL bound, canonical URL form, catalog lookup, role
 * agreement, payload bound, concrete decode, outer-envelope and recursive
 * concrete-message wire-tree validation, provider validation/normalization,
 * deterministic serialization, exact repack. Failure diagnostics identify the
 * first failed step and render only a bounded non-complete prefix of untrusted
 * input with its declared length.
 *
 * @param expected_role Role required by the owning plan field.
 * @param configuration Candidate typed provider configuration.
 * @return Canonical terminal representation, the first fail-closed ladder
 *         error, RESOURCE_EXHAUSTED for host allocation failure, or
 *         OUT_OF_RANGE for an unrepresentable extent. No hashing operation is
 *         performed or exposed.
 */
[[nodiscard]] common::status_or<canonical_provider_configuration>
canonicalize_provider_configuration(provider_contract_role expected_role, const google::protobuf::Any &configuration);

}  // namespace kinetum::provider
