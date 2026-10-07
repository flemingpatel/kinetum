// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_components.cpp
 * @brief Conformance tests for the exact host, UDP, and DPDK components.
 * @author Fleming Patel
 *
 * The real component outputs are staged under the fixed test installation
 * layout and admitted through a test-signed inventory. This proves their ELF,
 * descriptor, ABI, catalog, and multi-component behavior. ELF audits check
 * implementation exclusion and static-verification link boundaries. Inventory
 * and loader suites exercise authentication behavior independently of whether
 * LTO retains individual function symbols. The test key never acquires release
 * provenance.
 */

#include <gtest/gtest.h>

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <exception>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "gen/kinetum/io/udp/v1/udp_driver.pb.h"
#include "src/common/status_or.hpp"
#include "src/provider/provider_component_abi.h"
#include "src/provider/provider_component_loader.hpp"
#include "src/provider/provider_contract_catalog.hpp"
#include "src/quark/host_probe.hpp"
#include "tests/provider_component_test_fixture.hpp"
#include "tests/provider_log_capture.hpp"
#include "tests/provider_test_signing_key.hpp"

#if !defined(KINETUM_PROVIDER_HOST_COMPONENT_PATH) || !defined(KINETUM_PROVIDER_UDP_COMPONENT_PATH) || \
	!defined(KINETUM_PROVIDER_DPDK_COMPONENT_PATH) || !defined(KINETUM_PRODUCTION_PACKAGE_PATH) || \
	!defined(KINETUM_PRODUCTION_DP_PATH) || !defined(KINETUM_PRODUCTION_INFO_PATH) ||              \
	!defined(KINETUM_PROVIDER_DPDK_TESTS_PATH)
#error "Exact production provider-component and runtime paths are required"
#endif

namespace kinetum::provider
{
namespace
{

using kinetum::provider::v1::ProviderComponentArtifact;

/** @brief Minimal ELF link facts used by the production firewall audit. */
struct elf_link_facts {
	std::vector<std::string> needed_sonames;  ///< Sorted direct DT_NEEDED identities.
	std::vector<std::string> symbol_names;	  ///< Sorted regular and dynamic symbol names.
};

/** @brief Scope owner for one read-only ELF file descriptor. */
class elf_file_owner {
    public:
	/**
	 * @brief Adopt one open file descriptor.
	 *
	 * @param descriptor File descriptor to close at destruction.
	 */
	explicit elf_file_owner(int descriptor) noexcept
		: descriptor_(descriptor)
	{
	}

	elf_file_owner(const elf_file_owner &) = delete;
	elf_file_owner &operator=(const elf_file_owner &) = delete;
	elf_file_owner(elf_file_owner &&) = delete;
	elf_file_owner &operator=(elf_file_owner &&) = delete;

	/** @brief Close the exact adopted descriptor. */
	~elf_file_owner()
	{
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
	}

	/** @return the borrowed descriptor. */
	[[nodiscard]] int get() const noexcept
	{
		return descriptor_;
	}

    private:
	int descriptor_{-1};  ///< Exact owned descriptor.
};

/** @brief Scope owner for one libelf read session. */
class elf_session_owner {
    public:
	/**
	 * @brief Adopt one libelf session.
	 *
	 * @param session Session to finish at destruction.
	 */
	explicit elf_session_owner(Elf *session) noexcept
		: session_(session)
	{
	}

	elf_session_owner(const elf_session_owner &) = delete;
	elf_session_owner &operator=(const elf_session_owner &) = delete;
	elf_session_owner(elf_session_owner &&) = delete;
	elf_session_owner &operator=(elf_session_owner &&) = delete;

	/** @brief Finish the exact adopted session. */
	~elf_session_owner()
	{
		if (session_ != nullptr) {
			(void)::elf_end(session_);
		}
	}

	/** @return the borrowed libelf session. */
	[[nodiscard]] Elf *get() const noexcept
	{
		return session_;
	}

    private:
	Elf *session_{nullptr};	 ///< Exact owned libelf session.
};

/**
 * @brief Inspect one production ELF image without executing it.
 *
 * Both the dynamic dependency table and regular/dynamic symbol tables are
 * inspected. This is release-link evidence only; provider artifact admission
 * retains its stricter held-descriptor ELF authority.
 *
 * @param path Exact completed executable path.
 * @return Sorted link facts, or a fail-closed inspection status.
 */
[[nodiscard]] common::status_or<elf_link_facts> inspect_runtime_link_facts(const std::filesystem::path &path)
{
	if (::elf_version(EV_CURRENT) == EV_NONE) {
		return common::status::internal_error("libelf initialization failed");
	}
	const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (descriptor < 0) {
		return common::status::internal_error("runtime ELF open failed with errno " + std::to_string(errno));
	}
	elf_file_owner file(descriptor);
	Elf *raw_session = ::elf_begin(file.get(), ELF_C_READ, nullptr);
	if (raw_session == nullptr) {
		return common::status::internal_error("runtime ELF session creation failed");
	}
	elf_session_owner session(raw_session);
	GElf_Ehdr file_header{};
	if (::gelf_getehdr(session.get(), &file_header) == nullptr || file_header.e_machine == EM_NONE) {
		return common::status::internal_error("runtime ELF header is unreadable");
	}

	elf_link_facts facts;
	Elf_Scn *section = nullptr;
	while ((section = ::elf_nextscn(session.get(), section)) != nullptr) {
		GElf_Shdr section_header{};
		if (::gelf_getshdr(section, &section_header) == nullptr) {
			return common::status::internal_error("runtime ELF section header is unreadable");
		}
		if (section_header.sh_type != SHT_DYNAMIC && section_header.sh_type != SHT_DYNSYM &&
		    section_header.sh_type != SHT_SYMTAB) {
			continue;
		}
		if (section_header.sh_entsize == 0u) {
			return common::status::internal_error("runtime ELF table has zero entry size");
		}
		Elf_Data *data = nullptr;
		while ((data = ::elf_getdata(section, data)) != nullptr) {
			if (data->d_size % section_header.sh_entsize != 0u) {
				return common::status::internal_error("runtime ELF table has a partial entry");
			}
			const std::size_t entry_count = data->d_size / section_header.sh_entsize;
			if (entry_count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
				return common::status::internal_error("runtime ELF table exceeds libelf index range");
			}
			for (std::size_t index = 0; index < entry_count; ++index) {
				if (section_header.sh_type == SHT_DYNAMIC) {
					GElf_Dyn entry{};
					if (::gelf_getdyn(data, static_cast<int>(index), &entry) == nullptr) {
						return common::status::internal_error(
							"runtime ELF dynamic entry is unreadable");
					}
					if (entry.d_tag != DT_NEEDED) {
						continue;
					}
					const char *name =
						::elf_strptr(session.get(), section_header.sh_link, entry.d_un.d_val);
					if (name == nullptr || name[0] == '\0') {
						return common::status::internal_error(
							"runtime ELF contains an invalid DT_NEEDED identity");
					}
					facts.needed_sonames.emplace_back(name);
					continue;
				}

				GElf_Sym symbol{};
				if (::gelf_getsym(data, static_cast<int>(index), &symbol) == nullptr) {
					return common::status::internal_error("runtime ELF symbol is unreadable");
				}
				const char *name = ::elf_strptr(session.get(), section_header.sh_link, symbol.st_name);
				if (name != nullptr && name[0] != '\0') {
					facts.symbol_names.emplace_back(name);
				}
			}
		}
	}

	auto normalize = [](std::vector<std::string> &values) {
		std::sort(values.begin(), values.end());
		values.erase(std::unique(values.begin(), values.end()), values.end());
	};
	normalize(facts.needed_sonames);
	normalize(facts.symbol_names);
	return common::status_or<elf_link_facts>(std::in_place, std::move(facts));
}

/**
 * @brief Test whether one symbol would link provider implementation or release production into a runtime.
 *
 * @param symbol Exact ELF symbol identity.
 * @return true for DPDK packet symbols, component query implementations, or inventory signing.
 */
[[nodiscard]] bool is_forbidden_runtime_implementation_symbol(std::string_view symbol) noexcept
{
	return symbol.starts_with("rte_") ||
	       symbol.find("kinetum_provider_component_query") != std::string_view::npos ||
	       symbol.find("sign_provider_inventory") != std::string_view::npos;
}

/** One exact completed component output and its contract ownership. */
struct component_input {
	std::filesystem::path source;	     ///< Exact completed component output.
	std::string_view component_id;	     ///< Exact descriptor identity.
	std::vector<std::string> contracts;  ///< Complete owned contract set.
};

/** @brief Scope owner for one successfully materialized component instance. */
class factory_instance_owner {
    public:
	factory_instance_owner() = default;
	factory_instance_owner(const factory_instance_owner &) = delete;
	factory_instance_owner &operator=(const factory_instance_owner &) = delete;
	factory_instance_owner(factory_instance_owner &&) = delete;
	factory_instance_owner &operator=(factory_instance_owner &&) = delete;

	/** @brief Destroy the exact instance after all later dependents retire. */
	~factory_instance_owner()
	{
		if (result_.destroy != nullptr) {
			result_.destroy(result_.instance);
		}
	}

	/**
	 * @brief Adopt one complete successful factory result.
	 *
	 * @param result Exact role-valid instance result.
	 * @return true only when this owner was empty and the result was complete.
	 */
	[[nodiscard]] bool adopt(kinetum_provider_factory_result result) noexcept
	{
		if (result_.instance != nullptr || result_.operations != nullptr || result_.destroy != nullptr ||
		    result.instance == nullptr || result.operations == nullptr || result.destroy == nullptr) {
			return false;
		}
		result_ = result;
		return true;
	}

	/** @return Cold diagnostics retained through result destruction. */
	[[nodiscard]] kinetum_provider_cold_log logging() noexcept
	{
		return logging_.capability();
	}

	/** @return the exact component-owned instance handle. */
	[[nodiscard]] void *instance() const noexcept
	{
		return result_.instance;
	}

	/** @return the immutable role operation record. */
	[[nodiscard]] const void *operations() const noexcept
	{
		return result_.operations;
	}

    private:
	kinetum_provider_factory_result result_{};	       ///< Exact adopted result.
	kinetum::test_support::provider_log_capture logging_;  ///< Callback ownership outliving result destruction.
};

/** One cold factory invocation result and bounded diagnostic. */
struct factory_call_outcome {
	kinetum_provider_status status{KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR};  ///< Exact callback status.
	std::string diagnostic;	 ///< Bounded callback diagnostic bytes.
};

/**
 * @brief Construct one exact borrowed ABI text view.
 *
 * @param value Stable text for the complete callback.
 * @return Exact zero-padded ABI view.
 */
[[nodiscard]] kinetum_provider_text_view text_view(std::string_view value) noexcept
{
	if (value.size() > std::numeric_limits<uint32_t>::max()) {
		std::terminate();
	}
	return kinetum_provider_text_view{
		.data = value.empty() ? nullptr : value.data(),
		.size = static_cast<uint32_t>(value.size()),
		.padding = 0,
	};
}

/**
 * @brief Construct one exact borrowed ABI byte view.
 *
 * @param value Stable bytes for the complete callback.
 * @return Exact zero-padded ABI view.
 */
[[nodiscard]] kinetum_provider_byte_view byte_view(std::string_view value) noexcept
{
	if (value.size() > std::numeric_limits<uint32_t>::max()) {
		std::terminate();
	}
	return kinetum_provider_byte_view{
		.data = value.empty() ? nullptr : reinterpret_cast<const uint8_t *>(value.data()),
		.size = static_cast<uint32_t>(value.size()),
		.padding = 0,
	};
}

/**
 * @brief Construct one fully initialized, role-exact compiled-fact record.
 *
 * @tparam fact_type One declared provider fact-record type.
 * @param facts Stable fact record borrowed for the callback.
 * @return Record with exactly the matching role pointer populated.
 */
template <typename fact_type>
[[nodiscard]] constexpr kinetum_provider_compiled_fact_record compiled_fact_record(const fact_type &facts) noexcept
{
	static_assert(std::is_same_v<fact_type, kinetum_provider_process_facility_facts> ||
			      std::is_same_v<fact_type, kinetum_provider_io_driver_facts> ||
			      std::is_same_v<fact_type, kinetum_provider_packet_storage_facts> ||
			      std::is_same_v<fact_type, kinetum_provider_execution_facts> ||
			      std::is_same_v<fact_type, kinetum_provider_storage_transition_facts>,
		      "compiled fact helper requires one exact ABI fact type");
	kinetum_provider_compiled_fact_record record{};
	if constexpr (std::is_same_v<fact_type, kinetum_provider_process_facility_facts>) {
		record.process_facility = &facts;
	} else if constexpr (std::is_same_v<fact_type, kinetum_provider_io_driver_facts>) {
		record.io_driver = &facts;
	} else if constexpr (std::is_same_v<fact_type, kinetum_provider_packet_storage_facts>) {
		record.packet_storage = &facts;
	} else if constexpr (std::is_same_v<fact_type, kinetum_provider_execution_facts>) {
		record.execution = &facts;
	} else {
		record.storage_transition = &facts;
	}
	return record;
}

/**
 * @brief Resolve the role-partitioned factory already admitted for one row.
 *
 * @param implementation Exact admitted C ABI row.
 * @return Sole matching factory, or null for an impossible role value.
 */
[[nodiscard]] kinetum_provider_factory_fn
admitted_factory(const kinetum_provider_contract_implementation &implementation) noexcept
{
	switch (implementation.role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		return implementation.factories.process_facility;
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		return implementation.factories.io_driver;
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		return implementation.factories.packet_storage;
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		return implementation.factories.execution;
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		return implementation.factories.storage_transition;
	default:
		return nullptr;
	}
}

/**
 * @brief Invoke one admitted real component factory through the exact C ABI.
 *
 * This helper is test-only conformance machinery. It constructs no production
 * projection adapter and publishes no runtime graph.
 *
 * @param row Exact sealed runtime-catalog row.
 * @param instance_id Stable test instance identity.
 * @param canonical_configuration Canonical payload bytes from the pure catalog.
 * @param compiled_facts Exactly one role-matching compiled fact pointer.
 * @param dependencies Exact borrowed dependency handles.
 * @param runtime_generation Nonzero test materialization generation.
 * @param owner Empty owner that adopts a complete successful result.
 * @return Exact callback status and bounded diagnostic.
 */
[[nodiscard]] factory_call_outcome
invoke_admitted_factory(const runtime_provider_implementation &row, std::string_view instance_id,
			std::string_view canonical_configuration, kinetum_provider_compiled_fact_record compiled_facts,
			std::span<const kinetum_provider_dependency_handle> dependencies, uint64_t runtime_generation,
			factory_instance_owner &owner)
{
	if (row.implementation == nullptr || owner.instance() != nullptr ||
	    dependencies.size() > std::numeric_limits<uint32_t>::max()) {
		return factory_call_outcome{KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT,
					    "test factory invocation has no unique owner"};
	}
	const auto factory = admitted_factory(*row.implementation);
	if (factory == nullptr) {
		return factory_call_outcome{KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT,
					    "admitted row has no role-matching factory"};
	}
	const kinetum_provider_factory_request request{
		.instance_id = text_view(instance_id),
		.type_url = row.implementation->type_url,
		.canonical_configuration = byte_view(canonical_configuration),
		.compiled_facts = compiled_facts,
		.dependencies = dependencies.empty() ? nullptr : dependencies.data(),
		.dependency_count = static_cast<uint32_t>(dependencies.size()),
		.dependency_padding = 0,
		.runtime_generation = runtime_generation,
		.role = row.implementation->role,
		.padding = {0},
		.logging = owner.logging(),
	};
	std::array<char, 256> diagnostic_bytes{};
	kinetum_provider_diagnostic diagnostic{
		.data = diagnostic_bytes.data(),
		.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
		.size = 0,
	};
	kinetum_provider_factory_result result{};
	const auto status = factory(&request, &result, &diagnostic);
	if (diagnostic.size > diagnostic.capacity ||
	    !kinetum_provider_factory_result_matches_status(request.role, status, &result)) {
		if (result.instance != nullptr && result.destroy != nullptr) {
			result.destroy(result.instance);
		}
		return factory_call_outcome{KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR,
					    "component returned an invalid factory result"};
	}
	if (status == KINETUM_PROVIDER_STATUS_OK && !owner.adopt(result)) {
		result.destroy(result.instance);
		return factory_call_outcome{KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR,
					    "test owner rejected a complete factory result"};
	}
	return factory_call_outcome{
		.status = status,
		.diagnostic = std::string(diagnostic.data, diagnostic.size),
	};
}

/**
 * @brief Build one valid exact host-storage fact record.
 *
 * @param storage_domain_index Compact domain identity.
 * @param host_numa_node Exact process-allowed host memory node.
 * @return Facts accepted by the shared ABI and real host component.
 */
[[nodiscard]] kinetum_provider_packet_storage_facts host_storage_facts(uint32_t storage_domain_index,
								       int32_t host_numa_node) noexcept
{
	return kinetum_provider_packet_storage_facts{
		.storage_domain_index = storage_domain_index,
		.buffer_count = 64,
		.data_room_bytes = 2048,
		.headroom_bytes = 128,
		.alignment_bytes = 64,
		.cache_size_per_worker = 0,
		.required_buffer_count = 64,
		.safety_margin = 32,
		.host_numa_node = host_numa_node,
		.maximum_packet_length = 1920,
		.access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.has_host_numa_node = 1,
		.padding = {0},
	};
}

/**
 * @brief Canonicalize the exact two-port UDP component-conformance configuration.
 *
 * The RX port deliberately uses zero so the kernel selects a collision-free
 * ephemeral endpoint inside this isolated factory test. Production plans
 * cannot carry that noncanonical identity: the shared compiler requires an
 * exact nonzero endpoint before materialization.
 *
 * @return Canonical UDP driver configuration or the exact catalog failure.
 */
[[nodiscard]] common::status_or<canonical_provider_configuration> canonical_udp_driver_configuration()
{
	kinetum::io::udp::v1::UdpDriverConfig configuration;
	auto *configured_rx_port = configuration.add_ports();
	configured_rx_port->set_driver_port_id("udp_rx_0");
	configured_rx_port->set_ipv4_address("127.0.0.1");
	configured_rx_port->set_port(0);
	auto *configured_tx_port = configuration.add_ports();
	configured_tx_port->set_driver_port_id("udp_tx_0");
	configured_tx_port->set_ipv4_address("127.0.0.1");
	configured_tx_port->set_port(9);
	google::protobuf::Any candidate;
	candidate.PackFrom(configuration);
	return canonicalize_provider_configuration(provider_contract_role::IO_DRIVER, candidate);
}

/**
 * @brief Own the stable exact facts borrowed by one UDP factory invocation.
 *
 * The second queue ID is parameterized so conformance tests can force a
 * failure only after the first RX queue has reserved and bound its complete
 * descriptor population. The RX stream owns one explicit NONE steering row.
 * Copy and move are forbidden because the ABI fact record borrows the member-
 * array addresses.
 */
class udp_driver_fact_fixture {
    public:
	/**
	 * @brief Build one exact RX/TX graph.
	 *
	 * @param tx_driver_queue_id Queue identity for the second, TX stream.
	 */
	explicit udp_driver_fact_fixture(uint32_t tx_driver_queue_id) noexcept
		: attachments_{
			  kinetum_provider_driver_attachment_fact{
				  .driver_port_id = text_view("udp_rx_0"),
				  .attachment_identity = text_view("127.0.0.1"),
				  .io_driver_index = 0,
				  .endpoint_port = 0,
				  .kind = KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4,
				  .padding = {0},
			  },
			  kinetum_provider_driver_attachment_fact{
				  .driver_port_id = text_view("udp_tx_0"),
				  .attachment_identity = text_view("127.0.0.1"),
				  .io_driver_index = 0,
				  .endpoint_port = 9,
				  .kind = KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4,
				  .padding = {0},
			  },
		  },
		  ports_{
			  kinetum_provider_io_port_fact{
				  .port_index = 0,
				  .driver_port_index = 0,
				  .logical_port_id = 1,
				  .mtu = 1500,
				  .host_numa_node = 0,
				  .direction = KINETUM_PROVIDER_IO_DIRECTION_RX,
				  .has_host_numa_node = 0,
				  .has_resolved_mac_address = 0,
				  .direction_padding = 0,
				  .resolved_mac_address = {0},
				  .padding = {0},
			  },
			  kinetum_provider_io_port_fact{
				  .port_index = 1,
				  .driver_port_index = 1,
				  .logical_port_id = 2,
				  .mtu = 1500,
				  .host_numa_node = 0,
				  .direction = KINETUM_PROVIDER_IO_DIRECTION_TX,
				  .has_host_numa_node = 0,
				  .has_resolved_mac_address = 0,
				  .direction_padding = 0,
				  .resolved_mac_address = {0},
				  .padding = {0},
			  },
		  },
		  streams_{
			  kinetum_provider_io_stream_fact{
				  .io_stream_index = 0,
				  .port_index = 0,
				  .stage_instance_index = 0,
				  .worker_index = 0,
				  .driver_queue_id = 0,
				  .descriptor_count = 64,
				  .steering_profile_index = 0,
				  .direction = KINETUM_PROVIDER_IO_DIRECTION_RX,
				  .has_steering_profile = 1,
				  .padding = {0},
				  .storage_domain_indices = storage_domains_.data(),
				  .storage_domain_count = static_cast<uint32_t>(storage_domains_.size()),
				  .storage_padding = 0,
			  },
			  kinetum_provider_io_stream_fact{
				  .io_stream_index = 1,
				  .port_index = 1,
				  .stage_instance_index = 1,
				  .worker_index = 0,
				  .driver_queue_id = tx_driver_queue_id,
				  .descriptor_count = 64,
				  .steering_profile_index = 0,
				  .direction = KINETUM_PROVIDER_IO_DIRECTION_TX,
				  .has_steering_profile = 0,
				  .padding = {0},
				  .storage_domain_indices = storage_domains_.data(),
				  .storage_domain_count = static_cast<uint32_t>(storage_domains_.size()),
				  .storage_padding = 0,
			  },
		  },
		  steering_stream_indices_{0},
		  steering_profiles_{
			  kinetum_provider_steering_fact{
				  .steering_profile_index = 0,
				  .kind = KINETUM_PROVIDER_STEERING_NONE,
				  .symmetric = 0,
				  .kind_padding = {0},
				  .hash_fields = nullptr,
				  .hash_field_count = 0,
				  .hash_field_padding = 0,
				  .hash_key = {.data = nullptr, .size = 0, .padding = 0},
				  .io_stream_indices = steering_stream_indices_.data(),
				  .io_stream_count = static_cast<uint32_t>(steering_stream_indices_.size()),
				  .padding = {0},
			  },
		  },
		  facts_{
			  .io_driver_index = 0,
			  .index_padding = 0,
			  .attachments = attachments_.data(),
			  .attachment_count = static_cast<uint32_t>(attachments_.size()),
			  .attachment_padding = 0,
			  .ports = ports_.data(),
			  .port_count = static_cast<uint32_t>(ports_.size()),
			  .port_padding = 0,
			  .streams = streams_.data(),
			  .stream_count = static_cast<uint32_t>(streams_.size()),
			  .stream_padding = 0,
			  .steering_profiles = steering_profiles_.data(),
			  .steering_profile_count = static_cast<uint32_t>(steering_profiles_.size()),
			  .steering_padding = 0,
		  }
	{
	}

	udp_driver_fact_fixture(const udp_driver_fact_fixture &) = delete;
	udp_driver_fact_fixture &operator=(const udp_driver_fact_fixture &) = delete;
	udp_driver_fact_fixture(udp_driver_fact_fixture &&) = delete;
	udp_driver_fact_fixture &operator=(udp_driver_fact_fixture &&) = delete;

	/** @brief Remove the mandatory RX NONE profile to form the obsolete invalid shape. */
	void omit_rx_steering_contract() noexcept
	{
		streams_[0].has_steering_profile = 0;
		facts_.steering_profiles = nullptr;
		facts_.steering_profile_count = 0;
	}

	/** @return Stable exact I/O-driver facts for the fixture lifetime. */
	[[nodiscard]] const kinetum_provider_io_driver_facts &facts() const noexcept
	{
		return facts_;
	}

    private:
	std::array<kinetum_provider_driver_attachment_fact, 2> attachments_{};	///< Exact native endpoints.
	std::array<kinetum_provider_io_port_fact, 2> ports_{};			///< Exact logical ports.
	std::array<uint32_t, 1> storage_domains_{0};				///< Exact shared-domain admission.
	std::array<kinetum_provider_io_stream_fact, 2> streams_{};		///< Exact queue ownership.
	std::array<uint32_t, 1> steering_stream_indices_{};			///< Exact NONE-profile membership.
	std::array<kinetum_provider_steering_fact, 1> steering_profiles_{};	///< Exact RX steering row.
	kinetum_provider_io_driver_facts facts_{};				///< Stable borrowed ABI view.
};

/** @return the source-controlled real component inventory. */
[[nodiscard]] std::array<component_input, 3> real_component_inputs()
{
	return std::array<component_input, 3>{
		component_input{
			KINETUM_PROVIDER_HOST_COMPONENT_PATH,
			"kinetum.provider.host",
			{std::string(CPU_EXECUTION_TYPE_URL), std::string(HOST_STORAGE_TYPE_URL),
			 std::string(ZERO_COPY_SHARE_TYPE_URL), std::string(BOUNDED_COPY_TYPE_URL)},
		},
		component_input{
			KINETUM_PROVIDER_UDP_COMPONENT_PATH,
			"kinetum.provider.udp",
			{std::string(UDP_DRIVER_TYPE_URL)},
		},
		component_input{
			KINETUM_PROVIDER_DPDK_COMPONENT_PATH,
			"kinetum.provider.dpdk",
			{std::string(DPDK_FACILITY_TYPE_URL), std::string(DPDK_DRIVER_TYPE_URL),
			 std::string(DPDK_STORAGE_TYPE_URL)},
		},
	};
}

/**
 * @brief Stage every real component and derive its exact authenticated record.
 *
 * @param fixture Fixed test installation owner.
 * @return Complete component records in source-controlled component order.
 */
[[nodiscard]] std::vector<ProviderComponentArtifact>
stage_real_components(kinetum::test::provider_component_test_fixture &fixture)
{
	std::vector<ProviderComponentArtifact> records;
	records.reserve(3);
	for (auto &input : real_component_inputs()) {
		const auto staged = fixture.stage_artifact(input.source, input.source.filename().string());
		records.push_back(fixture.component_record(staged, input.component_id, std::move(input.contracts)));
	}
	return records;
}

/** Exact sorted complete contract set supplied by the three real components. */
constexpr std::array<std::string_view, 8> REQUIRED_CONTRACTS{
	CPU_EXECUTION_TYPE_URL, DPDK_FACILITY_TYPE_URL, DPDK_DRIVER_TYPE_URL,	  UDP_DRIVER_TYPE_URL,
	DPDK_STORAGE_TYPE_URL,	HOST_STORAGE_TYPE_URL,	ZERO_COPY_SHARE_TYPE_URL, BOUNDED_COPY_TYPE_URL,
};

/** Exact sorted host-component contract set. */
constexpr std::array<std::string_view, 4> HOST_REQUIRED_CONTRACTS{
	CPU_EXECUTION_TYPE_URL,
	HOST_STORAGE_TYPE_URL,
	ZERO_COPY_SHARE_TYPE_URL,
	BOUNDED_COPY_TYPE_URL,
};

/** Exact sorted host-storage plus UDP-driver contract set. */
constexpr std::array<std::string_view, 2> UDP_REQUIRED_CONTRACTS{
	UDP_DRIVER_TYPE_URL,
	HOST_STORAGE_TYPE_URL,
};

/** Exact sorted DPDK component contract set. */
constexpr std::array<std::string_view, 3> DPDK_REQUIRED_CONTRACTS{
	DPDK_FACILITY_TYPE_URL,
	DPDK_DRIVER_TYPE_URL,
	DPDK_STORAGE_TYPE_URL,
};

static_assert([]() consteval {
	for (std::size_t index = 1; index < REQUIRED_CONTRACTS.size(); ++index) {
		if (REQUIRED_CONTRACTS[index - 1] >= REQUIRED_CONTRACTS[index]) {
			return false;
		}
	}
	return true;
}());

static_assert([]() consteval {
	for (std::size_t index = 1; index < HOST_REQUIRED_CONTRACTS.size(); ++index) {
		if (HOST_REQUIRED_CONTRACTS[index - 1] >= HOST_REQUIRED_CONTRACTS[index]) {
			return false;
		}
	}
	return true;
}());

static_assert([]() consteval {
	for (std::size_t index = 1; index < UDP_REQUIRED_CONTRACTS.size(); ++index) {
		if (UDP_REQUIRED_CONTRACTS[index - 1] >= UDP_REQUIRED_CONTRACTS[index]) {
			return false;
		}
	}
	return true;
}());

static_assert([]() consteval {
	for (std::size_t index = 1; index < DPDK_REQUIRED_CONTRACTS.size(); ++index) {
		if (DPDK_REQUIRED_CONTRACTS[index - 1] >= DPDK_REQUIRED_CONTRACTS[index]) {
			return false;
		}
	}
	return true;
}());

}  // namespace

/** @brief Production DP excludes provider implementation and inventory-signing code. */
TEST(provider_components, production_runtime_keeps_exact_provider_firewall)
{
	const std::array<std::string, 3> component_filenames{
		std::filesystem::path(KINETUM_PROVIDER_HOST_COMPONENT_PATH).filename().string(),
		std::filesystem::path(KINETUM_PROVIDER_UDP_COMPONENT_PATH).filename().string(),
		std::filesystem::path(KINETUM_PROVIDER_DPDK_COMPONENT_PATH).filename().string(),
	};
	const auto assert_provider_implementation_free = [&component_filenames](const std::filesystem::path &image,
										const elf_link_facts &facts) {
		for (const auto &needed : facts.needed_sonames) {
			EXPECT_FALSE(needed.starts_with("librte_")) << image << ": " << needed;
			EXPECT_EQ(needed.find("dpdk"), std::string::npos) << image << ": " << needed;
			EXPECT_EQ(std::find(component_filenames.begin(), component_filenames.end(), needed),
				  component_filenames.end())
				<< image << ": " << needed;
		}
		for (const auto &symbol : facts.symbol_names) {
			EXPECT_FALSE(is_forbidden_runtime_implementation_symbol(symbol)) << image << ": " << symbol;
		}
	};

	const std::filesystem::path dataplane_image(KINETUM_PRODUCTION_DP_PATH);
	auto dataplane_or = inspect_runtime_link_facts(dataplane_image);
	ASSERT_TRUE(dataplane_or.is_ok()) << dataplane_image << ": " << dataplane_or.error().message();
	assert_provider_implementation_free(dataplane_image, dataplane_or.value());
}

/** @brief The installation information image retains no dynamic provider-loader edge. */
TEST(provider_components, installation_verifier_has_no_dynamic_provider_loader_edge)
{
	const std::array<std::string, 3> component_filenames{
		std::filesystem::path(KINETUM_PROVIDER_HOST_COMPONENT_PATH).filename().string(),
		std::filesystem::path(KINETUM_PROVIDER_UDP_COMPONENT_PATH).filename().string(),
		std::filesystem::path(KINETUM_PROVIDER_DPDK_COMPONENT_PATH).filename().string(),
	};
	constexpr std::array<std::string_view, 7> FORBIDDEN_LOADER_SYMBOLS{
		"dlopen",
		"dlmopen",
		"dlsym",
		"dlclose",
		"load_installed_provider_catalog",
		"admit_preflighted_provider_components",
		"kinetum_provider_component_query",
	};
	const std::filesystem::path image(KINETUM_PRODUCTION_INFO_PATH);
	auto facts_or = inspect_runtime_link_facts(image);
	ASSERT_TRUE(facts_or.is_ok()) << image << ": " << facts_or.error().message();
	for (const auto &needed : facts_or->needed_sonames) {
		EXPECT_FALSE(needed.starts_with("librte_")) << image << ": " << needed;
		EXPECT_EQ(needed.find("dpdk"), std::string::npos) << image << ": " << needed;
		EXPECT_EQ(needed.find("libdl"), std::string::npos) << image << ": " << needed;
		EXPECT_EQ(std::find(component_filenames.begin(), component_filenames.end(), needed),
			  component_filenames.end())
			<< image << ": " << needed;
	}
	for (const auto &symbol : facts_or->symbol_names) {
		for (const auto forbidden : FORBIDDEN_LOADER_SYMBOLS) {
			EXPECT_EQ(std::string_view(symbol).find(forbidden), std::string_view::npos)
				<< image << ": " << symbol;
		}
	}
}

/** @brief Real components retain no undeclared provider-private dependency. */
TEST(provider_components, real_images_are_link_closed_to_the_platform_runtime)
{
	const std::array<std::filesystem::path, 19> codec_free_images{
		std::filesystem::path("/proc/self/exe"),
		KINETUM_PRODUCTION_AXIOM_PATH,
		KINETUM_PRODUCTION_BUNDLE_VERIFY_PATH,
		KINETUM_PRODUCTION_CP_PATH,
		KINETUM_PRODUCTION_DP_PATH,
		KINETUM_PRODUCTION_GLUON_PATH,
		KINETUM_PRODUCTION_INFO_PATH,
		KINETUM_PRODUCTION_PACK_PATH,
		KINETUM_PRODUCTION_PHOTON_PATH,
		KINETUM_PRODUCTION_CTL_PATH,
		KINETUM_ACL_MODULE_PATH,
		KINETUM_NAT44_MODULE_PATH,
		KINETUM_QOS_MODULE_PATH,
		KINETUM_PROVIDER_HOST_COMPONENT_PATH,
		KINETUM_PROVIDER_UDP_COMPONENT_PATH,
		KINETUM_PROVIDER_DPDK_COMPONENT_PATH,
		KINETUM_PROVIDER_DPDK_TESTS_PATH,
		KINETUM_VALIDATION_TAP_SENDER_PATH,
		KINETUM_VALIDATION_TAP_ANALYZER_PATH,
	};
	for (const auto &image : codec_free_images) {
		auto facts_or = inspect_runtime_link_facts(image);
		ASSERT_TRUE(facts_or.is_ok()) << image << ": " << facts_or.error().message();
		for (const auto &soname : facts_or->needed_sonames) {
			EXPECT_FALSE(soname.starts_with("libarchive.so")) << image << ": " << soname;
		}
	}
	auto package_or = inspect_runtime_link_facts(std::filesystem::path(KINETUM_PRODUCTION_PACKAGE_PATH));
	ASSERT_TRUE(package_or.is_ok()) << package_or.error().message();
	EXPECT_TRUE(std::any_of(package_or->needed_sonames.begin(), package_or->needed_sonames.end(),
				[](const std::string &soname) { return soname.starts_with("libarchive.so"); }));

	kinetum::test::provider_component_test_fixture fixture;
	const auto records = stage_real_components(fixture);

	ASSERT_EQ(records.size(), 3u);
	for (const auto &record : records) {
		for (const auto &soname : record.needed_sonames()) {
			EXPECT_TRUE(is_platform_runtime_soname(soname, native_provider_target_tuple()))
				<< record.component_id() << " imports undeclared private dependency " << soname;
		}
	}

	const auto dpdk_component =
		inspect_runtime_link_facts(std::filesystem::path(KINETUM_PROVIDER_DPDK_COMPONENT_PATH));
	ASSERT_TRUE(dpdk_component.is_ok()) << dpdk_component.error().message();
	EXPECT_EQ(std::find(dpdk_component->needed_sonames.begin(), dpdk_component->needed_sonames.end(),
			    "libbsd.so.0"),
		  dpdk_component->needed_sonames.end());
	EXPECT_NE(std::find(dpdk_component->needed_sonames.begin(), dpdk_component->needed_sonames.end(),
			    "libnuma.so.1"),
		  dpdk_component->needed_sonames.end());
	for (const auto &soname : dpdk_component->needed_sonames) {
		EXPECT_FALSE(soname.starts_with("librte_")) << soname;
		EXPECT_EQ(soname.find("archive"), std::string::npos) << soname;
		EXPECT_EQ(soname.find("bsd"), std::string::npos) << soname;
		EXPECT_EQ(soname.find("pcap"), std::string::npos) << soname;
		EXPECT_EQ(soname.find("jansson"), std::string::npos) << soname;
		EXPECT_EQ(soname.find("fdt"), std::string::npos) << soname;
		EXPECT_EQ(soname.find("atomic"), std::string::npos) << soname;
	}
	EXPECT_NE(std::find(dpdk_component->symbol_names.begin(), dpdk_component->symbol_names.end(), "rte_eth_fp_ops"),
		  dpdk_component->symbol_names.end());

	const auto native_tests = inspect_runtime_link_facts(std::filesystem::path(KINETUM_PROVIDER_DPDK_TESTS_PATH));
	ASSERT_TRUE(native_tests.is_ok()) << native_tests.error().message();
	for (const auto &soname : native_tests->needed_sonames) {
		EXPECT_FALSE(soname.starts_with("librte_")) << soname;
		EXPECT_EQ(soname.find("kinetum_provider_dpdk_component"), std::string::npos) << soname;
	}
	EXPECT_NE(std::find(native_tests->symbol_names.begin(), native_tests->symbol_names.end(), "rte_eth_fp_ops"),
		  native_tests->symbol_names.end());
	for (const auto &symbol : native_tests->symbol_names) {
		EXPECT_EQ(symbol.find("load_installed_provider_catalog"), std::string::npos) << symbol;
		EXPECT_EQ(symbol.find("kinetum_provider_component_query"), std::string::npos) << symbol;
	}
}

/** @brief Admitted host factories materialize every exact role and burst contract. */
TEST(provider_components, admitted_host_component_materializes_exact_role_records)
{
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	const int32_t host_numa_node = host.memory_numa_nodes.front();
	kinetum::test::provider_component_test_fixture fixture;
	auto records = stage_real_components(fixture);
	const auto inventory = fixture.inventory(records, {});
	(void)fixture.write_signed_inventory(inventory);

	auto catalog_or =
		load_installed_provider_catalog(fixture.root(), fixture.runtime_image(), HOST_REQUIRED_CONTRACTS,
						kinetum::test::PROVIDER_TEST_PUBLIC_KEY, fixture.file_policy());
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().message();
	const auto *storage_row = catalog_or->find(HOST_STORAGE_TYPE_URL);
	const auto *execution_row = catalog_or->find(CPU_EXECUTION_TYPE_URL);
	const auto *zero_copy_row = catalog_or->find(ZERO_COPY_SHARE_TYPE_URL);
	const auto *bounded_copy_row = catalog_or->find(BOUNDED_COPY_TYPE_URL);
	ASSERT_NE(storage_row, nullptr);
	ASSERT_NE(execution_row, nullptr);
	ASSERT_NE(zero_copy_row, nullptr);
	ASSERT_NE(bounded_copy_row, nullptr);

	factory_instance_owner storage_zero;
	factory_instance_owner storage_one;
	factory_instance_owner execution;
	factory_instance_owner zero_copy;
	factory_instance_owner bounded_copy;
	const auto storage_zero_facts = host_storage_facts(0, host_numa_node);
	const auto storage_one_facts = host_storage_facts(1, host_numa_node);
	const auto storage_zero_outcome = invoke_admitted_factory(
		*storage_row, "storage.0", {}, compiled_fact_record(storage_zero_facts), {}, 7, storage_zero);
	ASSERT_EQ(storage_zero_outcome.status, KINETUM_PROVIDER_STATUS_OK) << storage_zero_outcome.diagnostic;
	const auto storage_one_outcome = invoke_admitted_factory(
		*storage_row, "storage.1", {}, compiled_fact_record(storage_one_facts), {}, 7, storage_one);
	ASSERT_EQ(storage_one_outcome.status, KINETUM_PROVIDER_STATUS_OK) << storage_one_outcome.diagnostic;

	const auto *storage_zero_operations =
		static_cast<const kinetum_packet_storage_domain_operations *>(storage_zero.operations());
	const auto *storage_one_operations =
		static_cast<const kinetum_packet_storage_domain_operations *>(storage_one.operations());
	ASSERT_NE(storage_zero_operations, nullptr);
	ASSERT_NE(storage_one_operations, nullptr);
	EXPECT_EQ(storage_zero_operations->domain_index, 0u);
	EXPECT_EQ(storage_one_operations->domain_index, 1u);
	EXPECT_EQ(storage_zero_operations->generation, 7u);
	EXPECT_EQ(storage_one_operations->generation, 7u);

	const std::array<kinetum_provider_dependency_handle, 1> storage_zero_dependency{
		kinetum_provider_dependency_handle{
			.instance_id = text_view("storage.0"),
			.type_url = storage_row->implementation->type_url,
			.instance = storage_zero.instance(),
			.operations = storage_zero.operations(),
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		},
	};
	const std::array<uint32_t, 1> stage_indices{0};
	const std::array<uint32_t, 1> worker_indices{0};
	const kinetum_provider_execution_facts execution_facts{
		.execution_provider_index = 0,
		.required_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU,
		.index_padding = {0},
		.stage_instance_indices = stage_indices.data(),
		.stage_instance_count = static_cast<uint32_t>(stage_indices.size()),
		.stage_padding = 0,
		.worker_indices = worker_indices.data(),
		.worker_count = static_cast<uint32_t>(worker_indices.size()),
		.worker_padding = 0,
	};
	auto read_only_storage_operations = *storage_zero_operations;
	read_only_storage_operations.capabilities &= ~KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE;
	const std::array<kinetum_provider_dependency_handle, 1> read_only_storage_dependency{
		kinetum_provider_dependency_handle{
			.instance_id = text_view("storage.read_only"),
			.type_url = storage_row->implementation->type_url,
			.instance = storage_zero.instance(),
			.operations = &read_only_storage_operations,
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		},
	};
	factory_instance_owner rejected_execution;
	const auto rejected_execution_outcome = invoke_admitted_factory(*execution_row, "execution.read_only", {},
									compiled_fact_record(execution_facts),
									read_only_storage_dependency, 7,
									rejected_execution);
	EXPECT_EQ(rejected_execution_outcome.status, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_NE(rejected_execution_outcome.diagnostic.find("contiguous read/write"), std::string::npos);

	const auto execution_outcome = invoke_admitted_factory(*execution_row, "execution.0", {},
							       compiled_fact_record(execution_facts),
							       storage_zero_dependency, 7, execution);
	ASSERT_EQ(execution_outcome.status, KINETUM_PROVIDER_STATUS_OK) << execution_outcome.diagnostic;
	const auto *execution_operations =
		static_cast<const kinetum_provider_execution_operations *>(execution.operations());
	ASSERT_NE(execution_operations, nullptr);
	EXPECT_EQ(execution_operations->execution_provider_index, 0u);
	EXPECT_EQ(execution_operations->required_access_agents, KINETUM_PROVIDER_ACCESS_AGENT_CPU);

	const kinetum_provider_storage_transition_facts zero_copy_facts{
		.transition_index = 0,
		.from_endpoint =
			{
				.kind = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE,
				.padding = {0},
				.endpoint_index = 0,
			},
		.to_endpoint =
			{
				.kind = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE,
				.padding = {0},
				.endpoint_index = 1,
			},
		.from_storage_domain_index = 0,
		.to_storage_domain_index = 0,
		.staging_capacity = 0,
		.staging_numa_node = 0,
		.mode = KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE,
		.has_staging_numa_node = 0,
		.padding = {0},
	};
	const auto zero_copy_outcome = invoke_admitted_factory(*zero_copy_row, "transition.zero_copy", {},
							       compiled_fact_record(zero_copy_facts),
							       storage_zero_dependency, 7, zero_copy);
	ASSERT_EQ(zero_copy_outcome.status, KINETUM_PROVIDER_STATUS_OK) << zero_copy_outcome.diagnostic;

	const std::array<kinetum_provider_dependency_handle, 2> bounded_copy_dependencies{
		kinetum_provider_dependency_handle{
			.instance_id = text_view("storage.0"),
			.type_url = storage_row->implementation->type_url,
			.instance = storage_zero.instance(),
			.operations = storage_zero.operations(),
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		},
		kinetum_provider_dependency_handle{
			.instance_id = text_view("storage.1"),
			.type_url = storage_row->implementation->type_url,
			.instance = storage_one.instance(),
			.operations = storage_one.operations(),
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		},
	};
	const kinetum_provider_storage_transition_facts bounded_copy_facts{
		.transition_index = 1,
		.from_endpoint =
			{
				.kind = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE,
				.padding = {0},
				.endpoint_index = 1,
			},
		.to_endpoint =
			{
				.kind = KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE,
				.padding = {0},
				.endpoint_index = 2,
			},
		.from_storage_domain_index = 0,
		.to_storage_domain_index = 1,
		.staging_capacity = 8,
		.staging_numa_node = 0,
		.mode = KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY,
		.has_staging_numa_node = 1,
		.padding = {0},
	};
	const auto bounded_copy_outcome = invoke_admitted_factory(*bounded_copy_row, "transition.bounded_copy", {},
								  compiled_fact_record(bounded_copy_facts),
								  bounded_copy_dependencies, 7, bounded_copy);
	ASSERT_EQ(bounded_copy_outcome.status, KINETUM_PROVIDER_STATUS_OK) << bounded_copy_outcome.diagnostic;

	std::array<uint8_t, 32> payload{};
	for (std::size_t index = 0; index < payload.size(); ++index) {
		payload[index] = static_cast<uint8_t>(index + 1u);
	}
	const kinetum_packet_origin_view origin{
		.data = payload.data(),
		.length = static_cast<uint32_t>(payload.size()),
		.padding = 0,
	};
	const std::array<kinetum_packet_origin_view, 2> zero_copy_origins{origin, origin};
	std::array<kinetum_packet_record *, 3> overlapping_handoff{};
	ASSERT_EQ(storage_zero_operations->copy_origins_burst(storage_zero_operations->state, zero_copy_origins.data(),
							      overlapping_handoff.data(), 2),
		  2u);
	ASSERT_NE(overlapping_handoff[0], nullptr);
	ASSERT_NE(overlapping_handoff[1], nullptr);
	auto *const first_zero_copy_source = overlapping_handoff[0];
	auto *const second_zero_copy_source = overlapping_handoff[1];
	const auto *zero_copy_operations =
		static_cast<const kinetum_provider_storage_transition_operations *>(zero_copy.operations());
	ASSERT_EQ(zero_copy_operations->transfer_burst(zero_copy_operations->state, overlapping_handoff.data(),
						       overlapping_handoff.data() + 1, 2),
		  2u);
	EXPECT_EQ(overlapping_handoff[1], first_zero_copy_source);
	EXPECT_EQ(overlapping_handoff[2], second_zero_copy_source);
	storage_zero_operations->release_burst(storage_zero_operations->state, overlapping_handoff.data() + 1, 2);

	kinetum_packet_record *source = nullptr;
	ASSERT_EQ(storage_zero_operations->copy_origins_burst(storage_zero_operations->state, &origin, &source, 1), 1u);
	ASSERT_NE(source, nullptr);
	source->metadata.user_meta = 0x1122334455667788ULL;
	source->metadata.user_meta_valid = 1;
	const auto *bounded_copy_operations =
		static_cast<const kinetum_provider_storage_transition_operations *>(bounded_copy.operations());
	auto *const bounded_copy_source = source;
	std::array<kinetum_packet_record *, 1> in_place_handoff{source};
	ASSERT_EQ(bounded_copy_operations->transfer_burst(bounded_copy_operations->state, in_place_handoff.data(),
							  in_place_handoff.data(), 1),
		  1u);
	auto *bounded_copy_destination = in_place_handoff[0];
	ASSERT_NE(bounded_copy_destination, nullptr);
	EXPECT_NE(bounded_copy_destination, bounded_copy_source);
	EXPECT_EQ(bounded_copy_destination->storage.operations, storage_one_operations);
	EXPECT_EQ(bounded_copy_destination->metadata.user_meta, 0x1122334455667788ULL);
	EXPECT_EQ(bounded_copy_destination->metadata.user_meta_valid, 1u);
	EXPECT_TRUE(std::equal(payload.begin(), payload.end(), bounded_copy_destination->storage.data));
	storage_one_operations->release_burst(storage_one_operations->state, &bounded_copy_destination, 1);
}

/** @brief Host storage rejects an absent NUMA fact before allocating packet backing. */
TEST(provider_components, admitted_host_storage_requires_exact_numa_presence)
{
	kinetum::test::provider_component_test_fixture fixture;
	auto records = stage_real_components(fixture);
	const auto inventory = fixture.inventory(records, {});
	(void)fixture.write_signed_inventory(inventory);

	auto catalog_or =
		load_installed_provider_catalog(fixture.root(), fixture.runtime_image(), HOST_REQUIRED_CONTRACTS,
						kinetum::test::PROVIDER_TEST_PUBLIC_KEY, fixture.file_policy());
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().message();
	const auto *storage_row = catalog_or->find(HOST_STORAGE_TYPE_URL);
	ASSERT_NE(storage_row, nullptr);

	auto storage_facts = host_storage_facts(0, 0);
	storage_facts.has_host_numa_node = 0;
	storage_facts.host_numa_node = 0;
	factory_instance_owner storage;
	const auto outcome = invoke_admitted_factory(*storage_row, "storage.0", {}, compiled_fact_record(storage_facts),
						     {}, 7, storage);

	EXPECT_EQ(outcome.status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_NE(outcome.diagnostic.find("exact CPU domain"), std::string::npos);
	EXPECT_EQ(storage.instance(), nullptr);
}

/** @brief Admitted UDP factory consumes exact host storage and publishes RX/TX queues. */
TEST(provider_components, admitted_udp_component_materializes_exact_rx_and_tx_queues)
{
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	const int32_t host_numa_node = host.memory_numa_nodes.front();
	kinetum::test::provider_component_test_fixture fixture;
	auto records = stage_real_components(fixture);
	const auto inventory = fixture.inventory(records, {});
	(void)fixture.write_signed_inventory(inventory);

	auto catalog_or =
		load_installed_provider_catalog(fixture.root(), fixture.runtime_image(), UDP_REQUIRED_CONTRACTS,
						kinetum::test::PROVIDER_TEST_PUBLIC_KEY, fixture.file_policy());
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().message();
	const auto *storage_row = catalog_or->find(HOST_STORAGE_TYPE_URL);
	const auto *udp_row = catalog_or->find(UDP_DRIVER_TYPE_URL);
	ASSERT_NE(storage_row, nullptr);
	ASSERT_NE(udp_row, nullptr);
	ASSERT_NE(udp_row->implementation, nullptr);

	factory_instance_owner storage;
	factory_instance_owner udp_driver;
	const auto storage_facts = host_storage_facts(0, host_numa_node);
	const auto storage_outcome = invoke_admitted_factory(*storage_row, "storage.0", {},
							     compiled_fact_record(storage_facts), {}, 11, storage);
	ASSERT_EQ(storage_outcome.status, KINETUM_PROVIDER_STATUS_OK) << storage_outcome.diagnostic;

	auto canonical_or = canonical_udp_driver_configuration();
	ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().message();
	const auto &canonical_payload = canonical_or->configuration.value();
	udp_driver_fact_fixture io_graph(0);
	const auto compiled_facts = compiled_fact_record(io_graph.facts());
	std::array<char, 256> proof_diagnostic_bytes{};
	kinetum_provider_diagnostic proof_diagnostic{
		.data = proof_diagnostic_bytes.data(),
		.capacity = static_cast<uint32_t>(proof_diagnostic_bytes.size()),
		.size = 0,
	};
	const kinetum_provider_host_proof_request proof_request{
		.type_url = udp_row->implementation->type_url,
		.canonical_configuration = byte_view(canonical_payload),
		.compiled_facts = compiled_facts,
		.role = KINETUM_PROVIDER_ROLE_IO_DRIVER,
		.padding = {0},
	};
	ASSERT_NE(udp_row->implementation->host_proof, nullptr);
	EXPECT_EQ(udp_row->implementation->host_proof(&proof_request, &proof_diagnostic), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(proof_diagnostic.size, 0u);

	const std::array<kinetum_provider_dependency_handle, 1> dependencies{
		kinetum_provider_dependency_handle{
			.instance_id = text_view("storage.0"),
			.type_url = storage_row->implementation->type_url,
			.instance = storage.instance(),
			.operations = storage.operations(),
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		},
	};
	udp_driver_fact_fixture missing_steering(0);
	missing_steering.omit_rx_steering_contract();
	factory_instance_owner malformed_udp_driver;
	const auto malformed_outcome = invoke_admitted_factory(*udp_row, "udp.missing_steering", canonical_payload,
							       compiled_fact_record(missing_steering.facts()),
							       dependencies, 11, malformed_udp_driver);
	EXPECT_EQ(malformed_outcome.status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_EQ(malformed_udp_driver.instance(), nullptr);

	const auto udp_outcome = invoke_admitted_factory(*udp_row, "udp.0", canonical_payload, compiled_facts,
							 dependencies, 11, udp_driver);
	ASSERT_EQ(udp_outcome.status, KINETUM_PROVIDER_STATUS_OK) << udp_outcome.diagnostic;
	const auto *operations = static_cast<const kinetum_provider_io_driver_operations *>(udp_driver.operations());
	ASSERT_NE(operations, nullptr);
	EXPECT_EQ(operations->io_driver_index, 0u);
	ASSERT_NE(operations->activate_packet_io, nullptr);
	ASSERT_NE(operations->deactivate_packet_io, nullptr);
	EXPECT_EQ(operations->rx_queue_count, 1u);
	EXPECT_EQ(operations->tx_queue_count, 1u);
	ASSERT_NE(operations->rx_queues, nullptr);
	ASSERT_NE(operations->tx_queues, nullptr);
	EXPECT_EQ(operations->rx_queues[0].logical_port, 1u);
	EXPECT_EQ(operations->tx_queues[0].logical_port, 2u);
	std::array<kinetum_provider_port_observation, 2> port_observations{};
	kinetum_provider_io_observation_batch observation_batch{
		.ports = port_observations.data(),
		.port_count = static_cast<uint32_t>(port_observations.size()),
		.port_padding = 0u,
		.padding = {},
	};
	ASSERT_NE(operations->observe_statistics, nullptr);
	EXPECT_EQ(operations->observe_statistics(operations->state, &observation_batch, nullptr),
		  KINETUM_PROVIDER_STATUS_OK);
	for (std::size_t index = 0u; index < port_observations.size(); ++index) {
		EXPECT_EQ(port_observations[index].port_index, io_graph.facts().ports[index].port_index);
		EXPECT_EQ(port_observations[index].state, KINETUM_PROVIDER_OBSERVATION_UNSUPPORTED);
	}
	kinetum_provider_diagnostic lifecycle_diagnostic{
		.data = proof_diagnostic_bytes.data(),
		.capacity = static_cast<uint32_t>(proof_diagnostic_bytes.size()),
		.size = 0,
	};
	EXPECT_EQ(operations->activate_packet_io(operations->state, &lifecycle_diagnostic), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(lifecycle_diagnostic.size, 0u);
	EXPECT_EQ(operations->deactivate_packet_io(operations->state, &lifecycle_diagnostic),
		  KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(lifecycle_diagnostic.size, 0u);
}

/** @brief A later UDP queue failure returns every earlier reserved storage credit. */
TEST(provider_components, admitted_udp_component_partial_queue_failure_conserves_storage)
{
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	const int32_t host_numa_node = host.memory_numa_nodes.front();
	kinetum::test::provider_component_test_fixture fixture;
	auto records = stage_real_components(fixture);
	const auto inventory = fixture.inventory(records, {});
	(void)fixture.write_signed_inventory(inventory);

	auto catalog_or =
		load_installed_provider_catalog(fixture.root(), fixture.runtime_image(), UDP_REQUIRED_CONTRACTS,
						kinetum::test::PROVIDER_TEST_PUBLIC_KEY, fixture.file_policy());
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().message();
	const auto *storage_row = catalog_or->find(HOST_STORAGE_TYPE_URL);
	const auto *udp_row = catalog_or->find(UDP_DRIVER_TYPE_URL);
	ASSERT_NE(storage_row, nullptr);
	ASSERT_NE(udp_row, nullptr);

	factory_instance_owner storage;
	const auto storage_facts = host_storage_facts(0, host_numa_node);
	const auto storage_outcome = invoke_admitted_factory(*storage_row, "storage.0", {},
							     compiled_fact_record(storage_facts), {}, 11, storage);
	ASSERT_EQ(storage_outcome.status, KINETUM_PROVIDER_STATUS_OK) << storage_outcome.diagnostic;
	const auto *storage_operations =
		static_cast<const kinetum_packet_storage_domain_operations *>(storage.operations());
	ASSERT_NE(storage_operations, nullptr);

	auto canonical_or = canonical_udp_driver_configuration();
	ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().message();
	udp_driver_fact_fixture malformed_graph(1);
	const std::array<kinetum_provider_dependency_handle, 1> dependencies{
		kinetum_provider_dependency_handle{
			.instance_id = text_view("storage.0"),
			.type_url = storage_row->implementation->type_url,
			.instance = storage.instance(),
			.operations = storage.operations(),
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		},
	};
	factory_instance_owner rejected_driver;
	const auto outcome = invoke_admitted_factory(*udp_row, "udp.invalid", canonical_or->configuration.value(),
						     compiled_fact_record(malformed_graph.facts()), dependencies, 11,
						     rejected_driver);
	EXPECT_EQ(outcome.status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_NE(outcome.diagnostic.find("queue-zero contract"), std::string::npos);
	EXPECT_EQ(rejected_driver.instance(), nullptr);

	std::array<kinetum_packet_record *, 64> reclaimed{};
	ASSERT_EQ(storage_operations->acquire_burst(storage_operations->state, reclaimed.data(),
						    static_cast<uint16_t>(reclaimed.size())),
		  reclaimed.size());
	storage_operations->release_burst(storage_operations->state, reclaimed.data(),
					  static_cast<uint16_t>(reclaimed.size()));
}

/** @brief Admitted DPDK callbacks dispatch every exact role before native effects. */
TEST(provider_components, admitted_dpdk_component_dispatches_every_role_factory)
{
	kinetum::test::provider_component_test_fixture fixture;
	auto records = stage_real_components(fixture);
	const auto inventory = fixture.inventory(records, {});
	(void)fixture.write_signed_inventory(inventory);

	auto catalog_or =
		load_installed_provider_catalog(fixture.root(), fixture.runtime_image(), DPDK_REQUIRED_CONTRACTS,
						kinetum::test::PROVIDER_TEST_PUBLIC_KEY, fixture.file_policy());
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().message();
	const auto *facility_row = catalog_or->find(DPDK_FACILITY_TYPE_URL);
	const auto *driver_row = catalog_or->find(DPDK_DRIVER_TYPE_URL);
	const auto *storage_row = catalog_or->find(DPDK_STORAGE_TYPE_URL);
	ASSERT_NE(facility_row, nullptr);
	ASSERT_NE(driver_row, nullptr);
	ASSERT_NE(storage_row, nullptr);
	ASSERT_NE(facility_row->implementation, nullptr);
	ASSERT_NE(driver_row->implementation, nullptr);
	ASSERT_NE(storage_row->implementation, nullptr);

	const kinetum_provider_process_facility_facts facility_facts{};
	std::array<char, 256> proof_diagnostic_bytes{};
	kinetum_provider_diagnostic proof_diagnostic{
		.data = proof_diagnostic_bytes.data(),
		.capacity = static_cast<uint32_t>(proof_diagnostic_bytes.size()),
		.size = 0,
	};
	const kinetum_provider_host_proof_request proof_request{
		.type_url = facility_row->implementation->type_url,
		.canonical_configuration = {},
		.compiled_facts = compiled_fact_record(facility_facts),
		.role = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
		.padding = {0},
	};
	ASSERT_NE(facility_row->implementation->host_proof, nullptr);
	EXPECT_EQ(facility_row->implementation->host_proof(&proof_request, &proof_diagnostic),
		  KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_GT(proof_diagnostic.size, 0u);

	factory_instance_owner facility;
	factory_instance_owner storage;
	factory_instance_owner driver;
	const auto facility_outcome = invoke_admitted_factory(*facility_row, "facility.dpdk", {},
							      compiled_fact_record(facility_facts), {}, 13, facility);
	EXPECT_EQ(facility_outcome.status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT) << facility_outcome.diagnostic;

	const kinetum_provider_packet_storage_facts storage_facts{};
	const auto storage_outcome = invoke_admitted_factory(*storage_row, "storage.dpdk", {},
							     compiled_fact_record(storage_facts), {}, 13, storage);
	EXPECT_EQ(storage_outcome.status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT) << storage_outcome.diagnostic;

	const kinetum_provider_io_driver_facts driver_facts{};
	const auto driver_outcome = invoke_admitted_factory(*driver_row, "driver.dpdk", {},
							    compiled_fact_record(driver_facts), {}, 13, driver);
	EXPECT_EQ(driver_outcome.status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT) << driver_outcome.diagnostic;
	EXPECT_EQ(facility.instance(), nullptr);
	EXPECT_EQ(storage.instance(), nullptr);
	EXPECT_EQ(driver.instance(), nullptr);
}

/** @brief One test-signed inventory admits and seals every exact real row. */
TEST(provider_components, test_signed_inventory_admits_complete_real_component_set)
{
	kinetum::test::provider_component_test_fixture fixture;
	auto records = stage_real_components(fixture);
	const auto inventory = fixture.inventory(records, {});
	(void)fixture.write_signed_inventory(inventory);

	auto catalog_or = load_installed_provider_catalog(fixture.root(), fixture.runtime_image(), REQUIRED_CONTRACTS,
							  kinetum::test::PROVIDER_TEST_PUBLIC_KEY,
							  fixture.file_policy());
	ASSERT_TRUE(catalog_or.is_ok()) << catalog_or.error().message();
	ASSERT_EQ(catalog_or->component_count(), 3u);
	ASSERT_EQ(catalog_or->size(), REQUIRED_CONTRACTS.size());

	for (std::size_t index = 0; index < REQUIRED_CONTRACTS.size(); ++index) {
		const auto *row = catalog_or->at(index);
		ASSERT_NE(row, nullptr);
		EXPECT_EQ(row->type_url, REQUIRED_CONTRACTS[index]);
		ASSERT_NE(row->implementation, nullptr);
		EXPECT_NE(admitted_factory(*row->implementation), nullptr);
	}
}

}  // namespace kinetum::provider
