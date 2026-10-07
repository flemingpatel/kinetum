// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dpdk_component_test_harness.hpp
 * @brief Exact injected DPDK process-facility fixture for native tests.
 * @author Fleming Patel
 *
 * The fixture owns one structurally and semantically complete process-facility
 * request plus a cold injected native API. Host-proof, facility, storage, and
 * I/O tests therefore consume one exact compiled-fact dialect while retaining
 * complete control over native side effects and rollback observations.
 */

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "src/dp/backends/dpdk/dpdk_process_facility.hpp"
#include "src/provider/provider_component_abi.h"
#include "tests/provider_log_capture.hpp"

namespace kinetum::provider::dpdk_component::test_support
{

/** Exact DPDK facility contract identity. */
constexpr std::string_view DPDK_FACILITY_TYPE_URL = "type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";

/** Exact DPDK driver contract identity. */
constexpr std::string_view DPDK_DRIVER_TYPE_URL = "type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig";

/** Exact DPDK storage contract identity. */
constexpr std::string_view DPDK_STORAGE_TYPE_URL = "type.googleapis.com/kinetum.storage.dpdk.v1.DpdkStorageConfig";

/**
 * @brief Construct a zero-padded borrowed ABI text view.
 * @param value Borrowed fixture bytes with an extent representable by uint32_t.
 * @return Text view retaining the supplied backing address and zero ABI padding.
 */
[[nodiscard]] inline kinetum_provider_text_view text_view(std::string_view value) noexcept
{
	return kinetum_provider_text_view{
		.data = value.data(),
		.size = static_cast<uint32_t>(value.size()),
		.padding = 0,
	};
}

/** @brief Complete observable state behind one injected facility API. */
struct facility_api_state {
	FILE *log_stream{nullptr};		 ///< Exact native stream borrowed until explicit detachment.
	int log_level{7};			 ///< DPDK informational severity during injected writes.
	int log_registration_result{0};		 ///< Native stream registration outcome.
	bool emit_lifecycle_logs{false};	 ///< Emit through the real stream during injected EAL init/cleanup.
	std::vector<std::string> eal_arguments;	 ///< Exact argv observed by EAL initialization.
	std::string runtime_version{"DPDK 24.11.7"};  ///< Exact nonempty linked-runtime identity.
	int eal_init_result{0};			      ///< Configured EAL initialization result.
	int eal_cleanup_result{0};		      ///< Configured EAL cleanup result.
	int thread_register_result{0};		      ///< Configured external-thread registration result.
	int remote_launch_result{0};		      ///< Configured remote-launch result.
	int current_cpu{3};			      ///< Calling Linux CPU returned to the facility.
	uint32_t current_lcore{3};		      ///< Calling native lcore returned to the facility.
	uint32_t main_lcore{3};			      ///< Exact EAL main lcore.
	uint32_t launched_lcore{UINT32_MAX};	      ///< Last lifecycle-executor lcore.
	int32_t launched_entry_result{0};	      ///< Result produced by the injected executor entry.
	uint32_t eal_init_calls{0};		      ///< Number of EAL initialization attempts.
	uint32_t eal_cleanup_calls{0};		      ///< Number of owned-generation cleanups.
	uint32_t thread_register_calls{0};	      ///< Number of external-thread registrations.
	uint32_t thread_unregister_calls{0};	      ///< Number of external-thread retirements.
	uint32_t remote_launch_calls{0};	      ///< Number of lifecycle launches.
	uint32_t wait_lcore_calls{0};		      ///< Number of lifecycle joins.
};

/**
 * @brief Capture one deterministic EAL initialization request.
 * @param opaque Borrowed fixture-owned native API state.
 * @param argc Number of supplied argument pointers.
 * @param argv Borrowed argument array copied into the observation state.
 * @return Injected initialization result, or -1 for malformed arguments.
 */
inline int eal_init(void *opaque, int argc, char **argv) noexcept
{
	auto &state = *static_cast<facility_api_state *>(opaque);
	++state.eal_init_calls;
	if (state.emit_lifecycle_logs && state.log_stream != nullptr) {
		(void)std::fprintf(state.log_stream, "EAL initialization\n");
	}
	state.eal_arguments.clear();
	if (argc < 0 || (argc != 0 && argv == nullptr)) {
		return -1;
	}
	state.eal_arguments.reserve(static_cast<std::size_t>(argc));
	for (int index = 0; index < argc; ++index) {
		if (argv[index] == nullptr) {
			return -1;
		}
		state.eal_arguments.emplace_back(argv[index]);
	}
	return state.eal_init_result;
}

/**
 * @brief Observe exact EAL generation retirement.
 * @param opaque Borrowed fixture-owned native API state.
 * @return Injected cleanup result after recording the attempt.
 */
inline int eal_cleanup(void *opaque) noexcept
{
	auto &state = *static_cast<facility_api_state *>(opaque);
	++state.eal_cleanup_calls;
	if (state.emit_lifecycle_logs && state.log_stream != nullptr) {
		(void)std::fprintf(state.log_stream, "EAL cleanup\n");
	}
	return state.eal_cleanup_result;
}

/**
 * @brief Borrow or detach the exact real cookie stream supplied by the facility.
 * @param opaque Fixture-owned native API state.
 * @param stream Borrowed stream, or null for detachment.
 * @return Injected registration result; failure leaves the prior stream unchanged.
 */
inline int open_log_stream(void *opaque, FILE *stream) noexcept
{
	auto &state = *static_cast<facility_api_state *>(opaque);
	if (state.log_registration_result == 0) {
		state.log_stream = stream;
	}
	return state.log_registration_result;
}

/**
 * @param opaque Fixture-owned native API state.
 * @return Injected severity of the current native emission.
 */
inline int current_log_level(void *opaque) noexcept
{
	return static_cast<facility_api_state *>(opaque)->log_level;
}

/**
 * @brief Observe one external packet-thread registration.
 * @param opaque Borrowed fixture-owned native API state.
 * @return Injected registration result after counting the attempt.
 */
inline int thread_register(void *opaque) noexcept
{
	auto &state = *static_cast<facility_api_state *>(opaque);
	++state.thread_register_calls;
	return state.thread_register_result;
}

/**
 * @brief Observe one exact external packet-thread retirement.
 * @param opaque Borrowed fixture-owned native API state.
 */
inline void thread_unregister(void *opaque) noexcept
{
	auto &state = *static_cast<facility_api_state *>(opaque);
	++state.thread_unregister_calls;
}

/**
 * @brief Return the injected calling native lcore.
 * @param opaque Borrowed fixture-owned native API state.
 * @return Fixture's current native lcore identity.
 */
inline uint32_t current_lcore_id(void *opaque) noexcept
{
	return static_cast<facility_api_state *>(opaque)->current_lcore;
}

/**
 * @brief Return the injected EAL main lcore.
 * @param opaque Borrowed fixture-owned native API state.
 * @return Fixture's configured EAL main-lcore identity.
 */
inline uint32_t main_lcore_id(void *opaque) noexcept
{
	return static_cast<facility_api_state *>(opaque)->main_lcore;
}

/**
 * @brief Admit only the exact coordinator and lifecycle executor lcores.
 * @param opaque Unused API context.
 * @param lcore_id Candidate native lcore.
 * @return One for the fixture's coordinator or executor lcore, otherwise zero.
 */
inline int lcore_is_enabled(void *opaque, uint32_t lcore_id) noexcept
{
	(void)opaque;
	return lcore_id == 3u || lcore_id == 5u ? 1 : 0;
}

/**
 * @brief Execute one injected lifecycle callback synchronously for proof.
 * @param opaque Borrowed fixture-owned native API state.
 * @param entry Borrowed callback executed before this fake launch returns.
 * @param argument Borrowed callback state.
 * @param lcore_id Requested executor identity recorded by the fixture.
 * @return Injected launch failure, -1 for absent callback state, or zero after saving the callback result.
 */
inline int remote_launch(void *opaque, int (*entry)(void *), void *argument, uint32_t lcore_id) noexcept
{
	auto &state = *static_cast<facility_api_state *>(opaque);
	++state.remote_launch_calls;
	state.launched_lcore = lcore_id;
	if (state.remote_launch_result != 0 || entry == nullptr || argument == nullptr) {
		return state.remote_launch_result != 0 ? state.remote_launch_result : -1;
	}
	state.launched_entry_result = static_cast<int32_t>(entry(argument));
	return 0;
}

/**
 * @brief Observe one exact lifecycle-executor join.
 * @param opaque Borrowed fixture-owned native API state.
 * @param lcore_id Candidate executor lcore being joined.
 * @return Saved callback result for the last launched lcore, otherwise zero.
 */
inline int wait_lcore(void *opaque, uint32_t lcore_id) noexcept
{
	auto &state = *static_cast<facility_api_state *>(opaque);
	++state.wait_lcore_calls;
	return lcore_id == state.launched_lcore ? state.launched_entry_result : 0;
}

/**
 * @brief Return the injected calling Linux CPU.
 * @param opaque Borrowed fixture-owned native API state.
 * @return Fixture's current Linux CPU identity.
 */
inline int current_cpu(void *opaque) noexcept
{
	return static_cast<facility_api_state *>(opaque)->current_cpu;
}

/**
 * @brief Resolve the fixture's sole exact PCI attachment.
 * @param opaque Unused API context.
 * @param name Candidate NUL-terminated PCI device identity.
 * @param port_id Resolved port output written only on success.
 * @return Zero for the fixture attachment, or -1 for mismatch.
 */
inline int eth_port_by_name(void *opaque, const char *name, uint16_t *port_id) noexcept
{
	(void)opaque;
	if (name == nullptr || port_id == nullptr || std::string_view(name) != "0000:01:00.0") {
		return -1;
	}
	*port_id = 7;
	return 0;
}

/**
 * @brief Return the injected linked-runtime identity.
 * @param opaque Borrowed fixture-owned native API state.
 * @return Borrowed version text retained by the fixture state.
 */
inline const char *runtime_version(void *opaque) noexcept
{
	return static_cast<facility_api_state *>(opaque)->runtime_version.c_str();
}

/**
 * @brief One exact DPDK facility request and its injected native owner.
 *
 * The process facts contain one external packet worker, one EAL-main
 * transition coordinator, one lifecycle executor, one PCI attachment, and
 * one exact packet-storage requirement. All borrowed storage outlives every
 * request and dependency view produced by the fixture.
 */
class facility_fixture {
    public:
	/** @brief Construct the canonical exact facility fact tree. */
	facility_fixture()
	{
		cpu_assignments_[0] = kinetum_provider_cpu_assignment{
			.owner_index = 0,
			.cpu_core_id = 2,
			.numa_node = 0,
			.kind = KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER,
			.padding = {0},
		};
		cpu_assignments_[1] = kinetum_provider_cpu_assignment{
			.owner_index = 0,
			.cpu_core_id = 3,
			.numa_node = 0,
			.kind = KINETUM_PROVIDER_CPU_OWNER_TRANSITION_COORDINATOR,
			.padding = {0},
		};
		cpu_assignments_[2] = kinetum_provider_cpu_assignment{
			.owner_index = 1,
			.cpu_core_id = 5,
			.numa_node = 0,
			.kind = KINETUM_PROVIDER_CPU_OWNER_LIFECYCLE_EXECUTOR,
			.padding = {0},
		};
		attachments_[0] = kinetum_provider_driver_attachment_fact{
			.driver_port_id = text_view(DRIVER_PORT_ID),
			.attachment_identity = text_view(PCI_BDF),
			.io_driver_index = 0,
			.endpoint_port = 0,
			.kind = KINETUM_PROVIDER_ATTACHMENT_PCI,
			.padding = {0},
		};
		memory_domains_[0] = kinetum_provider_memory_domain_fact{
			.storage_domain_index = 0,
			.buffer_count = 128,
			.data_room_bytes = 2176,
			.headroom_bytes = 128,
			.alignment_bytes = 64,
			.cache_size_per_worker = 0,
			.host_numa_node = 0,
			.has_host_numa_node = 1,
			.padding = {0},
		};
		facts_ = kinetum_provider_process_facility_facts{
			.facility_index = 0,
			.main_core_id = 3,
			.cpu_assignments = cpu_assignments_.data(),
			.cpu_assignment_count = 3,
			.cpu_assignment_padding = 0,
			.attachments = attachments_.data(),
			.attachment_count = static_cast<uint32_t>(attachments_.size()),
			.attachment_padding = 0,
			.memory_domains = memory_domains_.data(),
			.memory_domain_count = 1,
			.padding = {0},
		};
		request_ = kinetum_provider_factory_request{
			.instance_id = text_view(FACILITY_INSTANCE_ID),
			.type_url = text_view(DPDK_FACILITY_TYPE_URL),
			.canonical_configuration = {},
			.compiled_facts =
				{
					.process_facility = &facts_,
					.io_driver = nullptr,
					.packet_storage = nullptr,
					.execution = nullptr,
					.storage_transition = nullptr,
				},
			.dependencies = nullptr,
			.dependency_count = 0,
			.dependency_padding = 0,
			.runtime_generation = 1,
			.role = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
			.padding = {0},
			.logging = logging_.capability(),
		};
		api_ = dpdk_process_facility_api{
			.state = &api_state_,
			.eal_init = eal_init,
			.eal_cleanup = eal_cleanup,
			.open_log_stream = open_log_stream,
			.current_log_level = current_log_level,
			.thread_register = thread_register,
			.thread_unregister = thread_unregister,
			.current_lcore_id = current_lcore_id,
			.main_lcore_id = main_lcore_id,
			.lcore_is_enabled = lcore_is_enabled,
			.remote_launch = remote_launch,
			.wait_lcore = wait_lcore,
			.current_cpu = current_cpu,
			.eth_port_by_name = eth_port_by_name,
			.runtime_version = runtime_version,
			.unassigned_lcore_id = UINT32_MAX,
		};
	}

	/** Keep the request's borrowed member addresses under one fixture owner. */
	facility_fixture(const facility_fixture &) = delete;
	/** Prevent replacing a request and its retained native owner by copying. */
	facility_fixture &operator=(const facility_fixture &) = delete;
	/** Prevent moving storage referenced by the request and native API. */
	facility_fixture(facility_fixture &&) = delete;
	/** Prevent relocating or overwriting live borrowed fixture state. */
	facility_fixture &operator=(facility_fixture &&) = delete;

	/**
	 * @brief Create and retain the exact facility once.
	 * @param diagnostic Optional bounded diagnostic storage supplied by the test.
	 * @return Production factory result; successful ownership remains in this fixture.
	 */
	[[nodiscard]] kinetum_provider_status create(kinetum_provider_diagnostic *diagnostic = nullptr) noexcept
	{
		return dpdk_process_facility::create(request_, api_, facility_, diagnostic);
	}

	/** @return Borrowed mutable process-facility request. */
	[[nodiscard]] kinetum_provider_factory_request &request() noexcept
	{
		return request_;
	}

	/** @return Borrowed mutable process-facility fact tree. */
	[[nodiscard]] kinetum_provider_process_facility_facts &facts() noexcept
	{
		return facts_;
	}

	/** @return Borrowed first memory-domain fact. */
	[[nodiscard]] kinetum_provider_memory_domain_fact &memory_domain() noexcept
	{
		return memory_domains_[0];
	}

	/**
	 * @brief Add a second packet-worker assignment with exact ownership.
	 * @param worker_index Compact identity assigned to the added worker.
	 * @param cpu_core_id Linux CPU assigned to that worker on NUMA node zero.
	 */
	void add_packet_worker(uint32_t worker_index, int32_t cpu_core_id) noexcept
	{
		cpu_assignments_[3] = kinetum_provider_cpu_assignment{
			.owner_index = worker_index,
			.cpu_core_id = cpu_core_id,
			.numa_node = 0,
			.kind = KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER,
			.padding = {0},
		};
		facts_.cpu_assignment_count = 4;
	}

	/**
	 * @brief Add a second memory row with caller-selected compact identity.
	 * @param storage_domain_index Domain identity replacing the copied first row's identity.
	 */
	void add_memory_domain(uint32_t storage_domain_index) noexcept
	{
		memory_domains_[1] = memory_domains_[0];
		memory_domains_[1].storage_domain_index = storage_domain_index;
		facts_.memory_domain_count = 2;
	}

	/** @return Borrowed mutable PCI attachment fact. */
	[[nodiscard]] kinetum_provider_driver_attachment_fact &attachment() noexcept
	{
		return attachments_[0];
	}

	/** @return Borrowed mutable native API state and recorded observations. */
	[[nodiscard]] facility_api_state &api_state() noexcept
	{
		return api_state_;
	}

	/** @return Reference to the fixture's retained facility owner. */
	[[nodiscard]] std::unique_ptr<dpdk_process_facility> &facility() noexcept
	{
		return facility_;
	}

	/** @return Borrowed mutable injected native API table. */
	[[nodiscard]] dpdk_process_facility_api &api() noexcept
	{
		return api_;
	}

	/** @return Borrowed dependency view of the live facility, or an empty handle before successful creation. */
	[[nodiscard]] kinetum_provider_dependency_handle dependency() const noexcept
	{
		if (facility_ == nullptr) {
			return {};
		}
		return kinetum_provider_dependency_handle{
			.instance_id = text_view(FACILITY_INSTANCE_ID),
			.type_url = text_view(DPDK_FACILITY_TYPE_URL),
			.instance = facility_.get(),
			.operations = &facility_->operations(),
			.role = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY,
			.padding = {0},
		};
	}

    public:
	/** @return Copied native log evidence whose receiver outlives facility retirement. */
	[[nodiscard]] kinetum::test_support::provider_log_capture::observation logs() const
	{
		return logging_.read();
	}

    private:
	/** Compiled instance identity shared by the request and dependency views. */
	static constexpr std::string_view FACILITY_INSTANCE_ID = "dpdk.facility.0";
	/** Driver-local port identity attached to the fixture PCI function. */
	static constexpr std::string_view DRIVER_PORT_ID = "wan0";
	/** Canonical fixture PCI function resolved by the fake native API. */
	static constexpr std::string_view PCI_BDF = "0000:01:00.0";

	std::array<kinetum_provider_cpu_assignment, 4> cpu_assignments_{};	///< Exact CPU owners.
	std::array<kinetum_provider_driver_attachment_fact, 1> attachments_{};	///< Exact PCI attachment.
	std::array<kinetum_provider_memory_domain_fact, 2> memory_domains_{};	///< Exact storage rows.
	kinetum_provider_process_facility_facts facts_{};			///< Complete borrowed facility facts.
	kinetum_provider_factory_request request_{};				///< Exact empty-contract request.
	facility_api_state api_state_{};					///< Observable injected native state.
	dpdk_process_facility_api api_{};					///< Complete injected API table.
	kinetum::test_support::provider_log_capture logging_;  ///< Cold callback owner, retained through EAL cleanup.
	std::unique_ptr<dpdk_process_facility> facility_;      ///< Retained EAL generation owner.
};

}  // namespace kinetum::provider::dpdk_component::test_support
