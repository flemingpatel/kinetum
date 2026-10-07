// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dpdk_process_facility.cpp
 * @brief Exact DPDK EAL process-facility ownership implementation.
 * @author Fleming Patel
 */

#include "src/dp/backends/dpdk/dpdk_process_facility.hpp"

#include <sched.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_version.h>

#include "src/provider/components/component_support.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

using component_support::fail;

/** Exact contract admitted by the EAL process-facility factory. */
constexpr char DPDK_FACILITY_TYPE_URL[] = "type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";
/** Program-name argument supplied to native EAL initialization. */
constexpr char EAL_PROGRAM_NAME[] = "kinetum_dp";
/** Native virtual-device driver prefix for admitted TAP attachments. */
constexpr char EAL_TAP_PREFIX[] = "net_tap";
/** Registration slot has no native lcore ownership. */
constexpr uint8_t WORKER_UNREGISTERED = 0;
/** One caller owns the in-progress worker registration attempt. */
constexpr uint8_t WORKER_RESERVING = 1;
/** Worker registration and native placement proof are complete. */
constexpr uint8_t WORKER_REGISTERED = 2;
/** Native lcore has no claimed process-facility owner. */
constexpr uint64_t NATIVE_LCORE_UNOWNED = 0;
/** Native lcore is reserved for a compiled runtime service. */
constexpr uint64_t NATIVE_LCORE_SERVICE_OWNER = UINT64_MAX;

/**
 * @brief Encode one compact worker identity without colliding with owner sentinels.
 * @param worker_index Compiled uint32_t worker identity.
 * @return Nonzero ownership token distinct from the runtime-service sentinel.
 */
[[nodiscard]] constexpr uint64_t worker_lcore_owner(uint32_t worker_index) noexcept
{
	return static_cast<uint64_t>(worker_index) + 1u;
}

/**
 * @brief Return true only for one complete injected cold native table.
 * @param api Borrowed candidate EAL operation table.
 * @return true only when every required native operation is present.
 */
[[nodiscard]] bool api_is_complete(const dpdk_process_facility_api &api) noexcept
{
	return api.eal_init != nullptr && api.eal_cleanup != nullptr && api.open_log_stream != nullptr &&
	       api.current_log_level != nullptr && api.thread_register != nullptr && api.thread_unregister != nullptr &&
	       api.current_lcore_id != nullptr && api.main_lcore_id != nullptr && api.lcore_is_enabled != nullptr &&
	       api.remote_launch != nullptr && api.wait_lcore != nullptr && api.current_cpu != nullptr &&
	       api.eth_port_by_name != nullptr && api.runtime_version != nullptr;
}

/**
 * @brief Copy one valid ABI text view into owned cold storage.
 * @param view Previously validated borrowed byte span.
 * @return Owned copy of exactly the view's bytes.
 */
[[nodiscard]] std::string copy_text(kinetum_provider_text_view view)
{
	return std::string(view.data, static_cast<std::size_t>(view.size));
}

/**
 * @brief Render the admitted EAL lcore list in input order.
 * @param lcores Admitted lcore identities in their required output order.
 * @return Comma-separated decimal identities preserving input order.
 */
[[nodiscard]] std::string render_lcore_list(const std::vector<int32_t> &lcores)
{
	std::string rendered;
	for (std::size_t index = 0; index < lcores.size(); ++index) {
		if (index != 0) {
			rendered.push_back(',');
		}
		rendered += std::to_string(lcores[index]);
	}
	return rendered;
}

/**
 * @brief Native production wrapper over rte_eal_init.
 * @param state Opaque API context; unused by this native wrapper.
 * @param argc Number of mutable native arguments.
 * @param argv Caller-owned mutable EAL argument vector.
 * @return Native initialization result: consumed argument count or an error.
 */
int native_eal_init(void *state, int argc, char **argv) noexcept
{
	(void)state;
	return rte_eal_init(argc, argv);
}

/**
 * @brief Native production wrapper over rte_eal_cleanup.
 * @param state Opaque API context; unused by this native wrapper.
 * @return Native EAL cleanup result.
 */
int native_eal_cleanup(void *state) noexcept
{
	(void)state;
	return rte_eal_cleanup();
}

/**
 * @brief Register or detach the caller-owned stream using the required DPDK API.
 * @param stream Borrowed stream retained until detachment; null restores native ownership.
 * @return Zero after registration or the native failure code.
 */
int native_open_log_stream(void *, FILE *stream) noexcept
{
	return ::rte_openlog_stream(stream);
}

/** @return Actual DPDK severity during the synchronous native emission. */
int native_current_log_level(void *) noexcept
{
	return ::rte_log_cur_msg_loglevel();
}

/**
 * @brief Native production wrapper over external thread registration.
 * @param state Opaque API context; unused by this native wrapper.
 * @return Native registration result for the calling thread.
 */
int native_thread_register(void *state) noexcept
{
	(void)state;
	return rte_thread_register();
}

/**
 * @brief Native production wrapper over external thread retirement.
 * @param state Opaque API context; unused by this native wrapper.
 */
void native_thread_unregister(void *state) noexcept
{
	(void)state;
	rte_thread_unregister();
}

/**
 * @brief Native production wrapper returning the current DPDK lcore.
 * @param state Opaque API context; unused by this native wrapper.
 * @return Calling thread's native lcore identity, including the native unregistered sentinel.
 */
uint32_t native_current_lcore_id(void *state) noexcept
{
	(void)state;
	return static_cast<uint32_t>(rte_lcore_id());
}

/**
 * @brief Native production wrapper returning EAL's main lcore.
 * @param state Opaque API context; unused by this native wrapper.
 * @return Configured EAL main-lcore identity.
 */
uint32_t native_main_lcore_id(void *state) noexcept
{
	(void)state;
	return static_cast<uint32_t>(rte_get_main_lcore());
}

/**
 * @brief Native production wrapper testing one EAL lcore.
 * @param state Opaque API context; unused by this native wrapper.
 * @param lcore_id Candidate native lcore identity.
 * @return Nonzero only for an in-range enabled lcore; zero otherwise.
 */
int native_lcore_is_enabled(void *state, uint32_t lcore_id) noexcept
{
	(void)state;
	return lcore_id < RTE_MAX_LCORE ? rte_lcore_is_enabled(lcore_id) : 0;
}

/**
 * @brief Native production wrapper launching one EAL remote callback.
 * @param state Opaque API context; unused by this native wrapper.
 * @param entry Callback borrowed until its matching join.
 * @param argument Callback argument borrowed through that join.
 * @param lcore_id Enabled target EAL lcore.
 * @return Native launch result; zero indicates successful submission.
 */
int native_remote_launch(void *state, int (*entry)(void *), void *argument, uint32_t lcore_id) noexcept
{
	(void)state;
	return rte_eal_remote_launch(entry, argument, lcore_id);
}

/**
 * @brief Native production wrapper joining one EAL lcore.
 * @param state Opaque API context; unused by this native wrapper.
 * @param lcore_id Exact native lcore whose callback is joined.
 * @return Native wait result, including the callback's signed return value; its sign is not join-failure evidence.
 */
int native_wait_lcore(void *state, uint32_t lcore_id) noexcept
{
	(void)state;
	return rte_eal_wait_lcore(lcore_id);
}

/**
 * @brief Native production wrapper returning the calling Linux CPU.
 * @param state Opaque API context; unused by this native wrapper.
 * @return Calling CPU identity, or -1 when sched_getcpu fails.
 */
int native_current_cpu(void *state) noexcept
{
	(void)state;
	return sched_getcpu();
}

/**
 * @brief Native production wrapper resolving one exact ethdev name.
 * @param state Opaque API context; unused by this native wrapper.
 * @param name Borrowed NUL-terminated native device name.
 * @param port_id Caller-owned destination for the resolved ethdev identity.
 * @return Native lookup result; zero indicates successful resolution.
 */
int native_eth_port_by_name(void *state, const char *name, uint16_t *port_id) noexcept
{
	(void)state;
	return rte_eth_dev_get_port_by_name(name, port_id);
}

/**
 * @brief Native production wrapper returning linked DPDK version text.
 * @param state Opaque API context; unused by this native wrapper.
 * @return Borrowed process-lifetime DPDK version string.
 */
const char *native_runtime_version(void *state) noexcept
{
	(void)state;
	return rte_version();
}

}  // namespace

/** @brief Complete process-generation state retained behind the public owner. */
struct dpdk_process_facility::implementation {
	/**
	 * @brief Consume one native stdio write without retaining borrowed DPDK text.
	 *
	 * A write is one diagnostic fragment, not a promise about DPDK's printf
	 * message boundaries. Embedded newlines remain message bytes for the host
	 * encoder; fragments are never fused across threads or buffered past return.
	 * @param opaque Facility owner retained until the stream closes.
	 * @param data Native fragment borrowed through this call.
	 * @param size Complete fragment extent.
	 * @return Consumed byte count, or -1 if it cannot be represented by ssize_t.
	 */
	static ssize_t write_log(void *opaque, const char *data, std::size_t size) noexcept
	{
		auto &state = *static_cast<implementation *>(opaque);
		if (size > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max())) {
			errno = EOVERFLOW;
			return -1;
		}
		const int native_level = state.api.current_log_level(state.api.state);
		const auto level = native_level >= static_cast<int>(RTE_LOG_EMERG) &&
						   native_level <= static_cast<int>(RTE_LOG_DEBUG) ?
					   static_cast<kinetum_provider_log_level>(9 - native_level) :
					   kinetum_provider_log_level{0};
		std::size_t message_size = size;
		if (message_size != 0 && data[message_size - 1] == '\n') {
			--message_size;
		}
		constexpr char EVENT[] = "dpdk.write";
		state.logging.write(
			state.logging.context, level, {EVENT, static_cast<uint32_t>(sizeof(EVENT) - 1), 0}, {},
			{data, static_cast<uint32_t>(std::min(message_size, static_cast<std::size_t>(UINT32_MAX))), 0});
		return static_cast<ssize_t>(size);
	}

	/** @brief One exact packet-worker registration slot. */
	struct worker_slot {
		uint32_t worker_index{0};			    ///< Compact packet-worker identity.
		int32_t cpu_core_id{-1};			    ///< Exact Linux CPU owned by the worker.
		std::atomic<uint8_t> state{WORKER_UNREGISTERED};    ///< Linear registration state.
		std::atomic<uint32_t> native_lcore_id{UINT32_MAX};  ///< Claimed native lcore.
	};

	/** @brief One exact coordinator or lifecycle-executor slot. */
	struct service_slot {
		uint32_t service_index{0};				   ///< Compact runtime-service identity.
		int32_t cpu_core_id{-1};				   ///< Exact EAL lcore/CPU identity.
		kinetum_provider_cpu_owner_kind kind{0};		   ///< Coordinator or executor role.
		kinetum_provider_runtime_service_entry_fn entry{nullptr};  ///< Retained executor entry.
		void *argument{nullptr};				   ///< Retained executor argument.
		bool launched{false};					   ///< True while EAL owns the remote callback.
	};

	/** @brief One immutable resolved native attachment. */
	struct attachment_slot {
		std::string driver_port_id;		   ///< Exact driver-local identity.
		std::string attachment_identity;	   ///< Exact BDF or TAP interface identity.
		std::string native_device_name;		   ///< Exact EAL ethdev name.
		uint32_t io_driver_index{0};		   ///< Owning compact I/O driver.
		kinetum_provider_attachment_kind kind{0};  ///< Exact native attachment kind.
		uint16_t physical_port{0};		   ///< Resolved ethdev port ID.
	};

	dpdk_process_facility_api api{};	   ///< Complete copied cold native API.
	kinetum_provider_cold_log logging{};	   ///< Exact host capability retained through cleanup.
	FILE *log_stream{nullptr};		   ///< Owned unbuffered native capture stream.
	bool log_registered{false};		   ///< Native API still borrows log_stream.
	uint64_t generation{0};			   ///< Exact runtime generation.
	uint32_t facility_index{0};		   ///< Exact compact facility identity.
	std::unique_ptr<worker_slot[]> workers;	   ///< Stable worker slots.
	uint32_t worker_count{0};		   ///< Exact worker slot count.
	std::unique_ptr<service_slot[]> services;  ///< Stable service slots.
	uint32_t service_count{0};		   ///< Exact service slot count.
	std::unique_ptr<std::atomic<uint64_t>[]> native_lcore_owners;	  ///< Native-ID uniqueness authority.
	std::vector<attachment_slot> attachments;			  ///< Immutable resolved attachment set.
	std::vector<kinetum_provider_memory_domain_fact> memory_domains;  ///< Immutable dependent memory rows.
	bool eal_owned{false};	///< True only after successful EAL initialization.
};

dpdk_process_facility_api default_dpdk_process_facility_api() noexcept
{
	return dpdk_process_facility_api{
		.state = nullptr,
		.eal_init = native_eal_init,
		.eal_cleanup = native_eal_cleanup,
		.open_log_stream = native_open_log_stream,
		.current_log_level = native_current_log_level,
		.thread_register = native_thread_register,
		.thread_unregister = native_thread_unregister,
		.current_lcore_id = native_current_lcore_id,
		.main_lcore_id = native_main_lcore_id,
		.lcore_is_enabled = native_lcore_is_enabled,
		.remote_launch = native_remote_launch,
		.wait_lcore = native_wait_lcore,
		.current_cpu = native_current_cpu,
		.eth_port_by_name = native_eth_port_by_name,
		.runtime_version = native_runtime_version,
		.unassigned_lcore_id = static_cast<uint32_t>(LCORE_ID_ANY),
	};
}

dpdk_process_facility::dpdk_process_facility(std::unique_ptr<implementation> state) noexcept
	: state_(std::move(state))
{
	operations_.state = this;
	operations_.register_worker_thread = register_worker_thread_;
	operations_.unregister_worker_thread = unregister_worker_thread_;
	operations_.bind_runtime_service_coordinator = bind_runtime_service_coordinator_;
	operations_.launch_runtime_service = launch_runtime_service_;
	operations_.join_runtime_service = join_runtime_service_;
	operations_.generation = state_->generation;
	operations_.facility_index = state_->facility_index;
}

dpdk_process_facility::~dpdk_process_facility() noexcept
{
	for (uint32_t index = 0; index < state_->worker_count; ++index) {
		if (state_->workers[index].state.load(std::memory_order_acquire) != WORKER_UNREGISTERED) {
			std::terminate();
		}
	}
	for (uint32_t index = 0; index < state_->service_count; ++index) {
		if (state_->services[index].launched) {
			std::terminate();
		}
	}
	if (state_->eal_owned) {
		// Claim retirement before foreign cleanup so re-entry or failure cannot
		// cause a second call against the same process-global generation.
		state_->eal_owned = false;
		if (state_->api.eal_cleanup(state_->api.state) != 0) {
			std::terminate();
		}
	}
	if (state_->log_registered) {
		if (state_->api.open_log_stream(state_->api.state, nullptr) != 0) {
			std::fputs("DPDK log stream detachment failed\n", stderr);
			std::terminate();
		}
		state_->log_registered = false;
	}
	if (state_->log_stream != nullptr) {
		FILE *const stream = std::exchange(state_->log_stream, nullptr);
		if (::fclose(stream) != 0) {
			constexpr char EVENT[] = "dpdk.log.close_failed";
			constexpr char MESSAGE[] = "native diagnostic stream close failed";
			state_->logging.write(state_->logging.context, KINETUM_PROVIDER_LOG_ERROR,
					      {EVENT, sizeof(EVENT) - 1, 0}, {}, {MESSAGE, sizeof(MESSAGE) - 1, 0});
		}
	}
}

void dpdk_process_facility::fail_stop_after_eal_() noexcept
{
	if (state_ == nullptr || !state_->eal_owned) {
		std::terminate();
	}
	// Cleanup cannot prove that DPDK helper state is reusable. Claim the one
	// allowed attempt first, invoke it exactly once, then make process exit the
	// final ownership boundary regardless of the native result.
	state_->eal_owned = false;
	(void)state_->api.eal_cleanup(state_->api.state);
	std::terminate();
}

kinetum_provider_status dpdk_process_facility::create(const kinetum_provider_factory_request &request,
						      const dpdk_process_facility_api &api,
						      std::unique_ptr<dpdk_process_facility> &output,
						      kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (output != nullptr || !api_is_complete(api) || kinetum_provider_factory_request_is_valid(&request) == 0 ||
	    request.role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY ||
	    !component_support::text_equals(request.type_url, DPDK_FACILITY_TYPE_URL) ||
	    request.canonical_configuration.size != 0 || request.dependency_count != 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK facility received a malformed exact request");
	}
	const auto &facts = *request.compiled_facts.process_facility;
	if (facts.main_core_id < 0 || facts.cpu_assignment_count == 0 || facts.attachment_count == 0 ||
	    facts.memory_domain_count == 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic, "DPDK facility facts are incomplete");
	}

	try {
		auto state = std::make_unique<implementation>();
		state->api = api;
		state->logging = request.logging;
		state->generation = request.runtime_generation;
		state->facility_index = facts.facility_index;

		uint32_t worker_count = 0;
		uint32_t service_count = 0;
		uint32_t coordinator_count = 0;
		std::vector<int32_t> eal_lcores;
		eal_lcores.reserve(facts.cpu_assignment_count);
		for (uint32_t index = 0; index < facts.cpu_assignment_count; ++index) {
			const auto &assignment = facts.cpu_assignments[index];
			if (assignment.cpu_core_id < 0 || assignment.numa_node < 0) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK facility CPU facts are not exact");
			}
			for (uint32_t earlier = 0; earlier < index; ++earlier) {
				const auto &previous = facts.cpu_assignments[earlier];
				if (previous.cpu_core_id == assignment.cpu_core_id ||
				    (previous.kind == assignment.kind &&
				     previous.owner_index == assignment.owner_index)) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK facility CPU ownership is not pairwise exact");
				}
			}
			switch (assignment.kind) {
			case KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER:
				++worker_count;
				break;
			case KINETUM_PROVIDER_CPU_OWNER_TRANSITION_COORDINATOR:
				if (assignment.cpu_core_id != facts.main_core_id ||
				    assignment.cpu_core_id >= static_cast<int32_t>(RTE_MAX_LCORE)) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK coordinator does not own the exact main lcore");
				}
				++coordinator_count;
				++service_count;
				eal_lcores.push_back(assignment.cpu_core_id);
				break;
			case KINETUM_PROVIDER_CPU_OWNER_LIFECYCLE_EXECUTOR:
				if (assignment.cpu_core_id >= static_cast<int32_t>(RTE_MAX_LCORE)) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK lifecycle executor exceeds native lcore capacity");
				}
				++service_count;
				eal_lcores.push_back(assignment.cpu_core_id);
				break;
			default:
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK facility has an unknown CPU owner role");
			}
		}
		if (coordinator_count != 1 || eal_lcores.empty() || worker_count == 0) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK facility requires exact worker and coordinator ownership");
		}
		std::sort(eal_lcores.begin(), eal_lcores.end());

		state->worker_count = worker_count;
		state->service_count = service_count;
		state->workers = std::make_unique<implementation::worker_slot[]>(worker_count);
		state->services = std::make_unique<implementation::service_slot[]>(service_count);
		state->native_lcore_owners = std::make_unique<std::atomic<uint64_t>[]>(RTE_MAX_LCORE);
		for (uint32_t index = 0; index < RTE_MAX_LCORE; ++index) {
			state->native_lcore_owners[index].store(NATIVE_LCORE_UNOWNED, std::memory_order_relaxed);
		}
		uint32_t worker_index = 0;
		uint32_t service_index = 0;
		for (uint32_t index = 0; index < facts.cpu_assignment_count; ++index) {
			const auto &assignment = facts.cpu_assignments[index];
			if (assignment.kind == KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER) {
				state->workers[worker_index].worker_index = assignment.owner_index;
				state->workers[worker_index].cpu_core_id = assignment.cpu_core_id;
				++worker_index;
			} else {
				state->services[service_index].service_index = assignment.owner_index;
				state->services[service_index].cpu_core_id = assignment.cpu_core_id;
				state->services[service_index].kind = assignment.kind;
				state->native_lcore_owners[static_cast<uint32_t>(assignment.cpu_core_id)].store(
					NATIVE_LCORE_SERVICE_OWNER, std::memory_order_relaxed);
				++service_index;
			}
		}

		state->memory_domains.assign(facts.memory_domains, facts.memory_domains + facts.memory_domain_count);
		for (std::size_t index = 0; index < state->memory_domains.size(); ++index) {
			const auto &memory = state->memory_domains[index];
			if (memory.buffer_count == 0 || memory.data_room_bytes == 0 ||
			    memory.headroom_bytes >= memory.data_room_bytes || memory.alignment_bytes == 0 ||
			    memory.has_host_numa_node != 1 || memory.host_numa_node < 0) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK facility memory-domain facts are incomplete");
			}
			for (std::size_t earlier = 0; earlier < index; ++earlier) {
				if (state->memory_domains[earlier].storage_domain_index ==
				    memory.storage_domain_index) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK facility memory-domain ownership is duplicated");
				}
			}
		}

		state->attachments.reserve(facts.attachment_count);
		bool has_pci_attachment = false;
		for (uint32_t index = 0; index < facts.attachment_count; ++index) {
			const auto &attachment = facts.attachments[index];
			if (attachment.driver_port_id.size == 0 || attachment.attachment_identity.size == 0 ||
			    attachment.endpoint_port != 0 ||
			    (attachment.kind != KINETUM_PROVIDER_ATTACHMENT_PCI &&
			     attachment.kind != KINETUM_PROVIDER_ATTACHMENT_TAP)) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK facility attachment facts are not PCI or TAP");
			}
			implementation::attachment_slot retained{
				.driver_port_id = copy_text(attachment.driver_port_id),
				.attachment_identity = copy_text(attachment.attachment_identity),
				.native_device_name = {},
				.io_driver_index = attachment.io_driver_index,
				.kind = attachment.kind,
				.physical_port = 0,
			};
			if (attachment.kind == KINETUM_PROVIDER_ATTACHMENT_PCI) {
				has_pci_attachment = true;
				retained.native_device_name = retained.attachment_identity;
			} else {
				retained.native_device_name = EAL_TAP_PREFIX + std::to_string(index);
			}
			for (const auto &previous : state->attachments) {
				if (previous.attachment_identity == retained.attachment_identity ||
				    (previous.io_driver_index == retained.io_driver_index &&
				     previous.driver_port_id == retained.driver_port_id)) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK facility attachment ownership is duplicated");
				}
			}
			state->attachments.push_back(std::move(retained));
		}

		std::vector<std::string> eal_arguments;
		eal_arguments.reserve(7u + state->attachments.size() * 2u);
		eal_arguments.emplace_back(EAL_PROGRAM_NAME);
		eal_arguments.emplace_back("-l");
		eal_arguments.push_back(render_lcore_list(eal_lcores));
		eal_arguments.emplace_back("--main-lcore");
		eal_arguments.push_back(std::to_string(facts.main_core_id));
		eal_arguments.emplace_back("--no-telemetry");
		if (!has_pci_attachment) {
			eal_arguments.emplace_back("--no-pci");
		}
		for (const auto &attachment : state->attachments) {
			if (attachment.kind == KINETUM_PROVIDER_ATTACHMENT_PCI) {
				eal_arguments.emplace_back("-a");
				eal_arguments.push_back(attachment.attachment_identity);
			} else {
				eal_arguments.emplace_back("--vdev");
				eal_arguments.push_back(attachment.native_device_name +
							",iface=" + attachment.attachment_identity);
			}
		}
		if (eal_arguments.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
			return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
				    "DPDK EAL argument count is not representable");
		}
		std::vector<char *> argv;
		argv.reserve(eal_arguments.size());
		for (auto &argument : eal_arguments) {
			argv.push_back(argument.data());
		}

		auto candidate = std::unique_ptr<dpdk_process_facility>(new dpdk_process_facility(std::move(state)));
		const char *runtime_version = candidate->state_->api.runtime_version(candidate->state_->api.state);
		if (runtime_version == nullptr || runtime_version[0] == '\0') {
			return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
				    "DPDK runtime identity is unavailable");
		}
		const cookie_io_functions_t stream_functions{
			.read = nullptr, .write = implementation::write_log, .seek = nullptr, .close = nullptr};
		candidate->state_->log_stream = ::fopencookie(candidate->state_.get(), "w", stream_functions);
		if (candidate->state_->log_stream == nullptr ||
		    ::setvbuf(candidate->state_->log_stream, nullptr, _IONBF, 0) != 0) {
			return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
				    "DPDK native diagnostic stream creation failed");
		}
		if (candidate->state_->api.open_log_stream(candidate->state_->api.state,
							   candidate->state_->log_stream) != 0) {
			return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
				    "DPDK native diagnostic stream registration failed");
		}
		candidate->state_->log_registered = true;
		const int init_result = candidate->state_->api.eal_init(candidate->state_->api.state,
									static_cast<int>(argv.size()), argv.data());
		if (init_result < 0) {
			// A failed EAL call may have changed process-global helper state, but
			// it did not establish cleanup ownership. The native API proves
			// neither safe cleanup nor a reusable process after this return, so
			// the operating system is the only honest reclamation boundary.
			std::terminate();
		}
		candidate->state_->eal_owned = true;
		if (candidate->state_->api.main_lcore_id(candidate->state_->api.state) !=
		    static_cast<uint32_t>(facts.main_core_id)) {
			candidate->fail_stop_after_eal_();
		}
		for (const int32_t lcore : eal_lcores) {
			const auto native_lcore = static_cast<uint32_t>(lcore);
			if (candidate->state_->api.lcore_is_enabled(candidate->state_->api.state, native_lcore) == 0) {
				candidate->fail_stop_after_eal_();
			}
		}
		for (std::size_t index = 0; index < candidate->state_->attachments.size(); ++index) {
			auto &attachment = candidate->state_->attachments[index];
			if (candidate->state_->api.eth_port_by_name(candidate->state_->api.state,
								    attachment.native_device_name.c_str(),
								    &attachment.physical_port) != 0) {
				candidate->fail_stop_after_eal_();
			}
			for (std::size_t earlier = 0; earlier < index; ++earlier) {
				if (candidate->state_->attachments[earlier].physical_port == attachment.physical_port) {
					candidate->fail_stop_after_eal_();
				}
			}
		}
		if (!kinetum_provider_process_facility_operations_are_valid(&candidate->operations_)) {
			candidate->fail_stop_after_eal_();
		}
		output = std::move(candidate);
		component_support::write_diagnostic(diagnostic, std::string_view{});
		return KINETUM_PROVIDER_STATUS_OK;
	} catch (const std::bad_alloc &) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "DPDK facility host-state allocation failed");
	} catch (...) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK facility construction raised an unexpected failure");
	}
}

const kinetum_provider_process_facility_operations &dpdk_process_facility::operations() const noexcept
{
	return operations_;
}

bool dpdk_process_facility::resolve_physical_port(const kinetum_provider_driver_attachment_fact &attachment,
						  uint16_t &physical_port) const noexcept
{
	if (!active() || !kinetum_provider_text_view_is_valid(attachment.driver_port_id) ||
	    !kinetum_provider_text_view_is_valid(attachment.attachment_identity) || attachment.endpoint_port != 0) {
		return false;
	}
	const implementation::attachment_slot *match = nullptr;
	for (const auto &candidate : state_->attachments) {
		if (candidate.io_driver_index != attachment.io_driver_index || candidate.kind != attachment.kind ||
		    !component_support::text_equals(attachment.driver_port_id, candidate.driver_port_id) ||
		    !component_support::text_equals(attachment.attachment_identity, candidate.attachment_identity)) {
			continue;
		}
		if (match != nullptr) {
			return false;
		}
		match = &candidate;
	}
	if (match == nullptr) {
		return false;
	}
	physical_port = match->physical_port;
	return true;
}

bool dpdk_process_facility::contains_memory_domain(const kinetum_provider_packet_storage_facts &facts) const noexcept
{
	if (!active()) {
		return false;
	}
	const kinetum_provider_memory_domain_fact *match = nullptr;
	for (const auto &candidate : state_->memory_domains) {
		if (candidate.storage_domain_index != facts.storage_domain_index) {
			continue;
		}
		if (match != nullptr) {
			return false;
		}
		match = &candidate;
	}
	return match != nullptr && match->buffer_count == facts.buffer_count &&
	       match->data_room_bytes == facts.data_room_bytes && match->headroom_bytes == facts.headroom_bytes &&
	       match->alignment_bytes == facts.alignment_bytes &&
	       match->cache_size_per_worker == facts.cache_size_per_worker &&
	       match->host_numa_node == facts.host_numa_node && match->has_host_numa_node == facts.has_host_numa_node;
}

bool dpdk_process_facility::active() const noexcept
{
	return state_ != nullptr && state_->eal_owned;
}

kinetum_provider_status dpdk_process_facility::register_worker_thread_(void *state, uint32_t worker_index,
								       kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *facility = static_cast<dpdk_process_facility *>(state);
	if (facility == nullptr || !facility->active()) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK worker registration has no active facility");
	}
	implementation::worker_slot *slot = nullptr;
	for (uint32_t index = 0; index < facility->state_->worker_count; ++index) {
		if (facility->state_->workers[index].worker_index == worker_index) {
			if (slot != nullptr) {
				return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
					    "DPDK worker identity is duplicated in facility state");
			}
			slot = &facility->state_->workers[index];
		}
	}
	if (slot == nullptr || facility->state_->api.current_cpu(facility->state_->api.state) != slot->cpu_core_id) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK worker is not running on its exact compiled CPU");
	}
	uint8_t expected_state = WORKER_UNREGISTERED;
	if (!slot->state.compare_exchange_strong(expected_state, WORKER_RESERVING, std::memory_order_acq_rel,
						 std::memory_order_acquire)) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK worker registration is already owned");
	}
	if (facility->state_->api.thread_register(facility->state_->api.state) != 0) {
		slot->state.store(WORKER_UNREGISTERED, std::memory_order_release);
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK rejected external packet-worker registration");
	}
	const uint32_t native_lcore = facility->state_->api.current_lcore_id(facility->state_->api.state);
	if (native_lcore == facility->state_->api.unassigned_lcore_id || native_lcore >= RTE_MAX_LCORE) {
		facility->state_->api.thread_unregister(facility->state_->api.state);
		slot->state.store(WORKER_UNREGISTERED, std::memory_order_release);
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK did not assign a representable native worker lcore");
	}
	uint64_t expected_owner = NATIVE_LCORE_UNOWNED;
	const uint64_t owner = worker_lcore_owner(worker_index);
	if (!facility->state_->native_lcore_owners[native_lcore].compare_exchange_strong(
		    expected_owner, owner, std::memory_order_acq_rel, std::memory_order_acquire)) {
		facility->state_->api.thread_unregister(facility->state_->api.state);
		slot->state.store(WORKER_UNREGISTERED, std::memory_order_release);
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK assigned a reserved or already owned native worker lcore");
	}
	slot->native_lcore_id.store(native_lcore, std::memory_order_relaxed);
	// Release publishes the native identity and successful DPDK registration to
	// the exact unregister operation. No packet callback is admitted before the
	// generic all-or-none launcher observes this successful return.
	slot->state.store(WORKER_REGISTERED, std::memory_order_release);
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

void dpdk_process_facility::unregister_worker_thread_(void *state, uint32_t worker_index) noexcept
{
	auto *facility = static_cast<dpdk_process_facility *>(state);
	if (facility == nullptr || !facility->active()) {
		std::terminate();
	}
	implementation::worker_slot *slot = nullptr;
	for (uint32_t index = 0; index < facility->state_->worker_count; ++index) {
		if (facility->state_->workers[index].worker_index == worker_index) {
			slot = &facility->state_->workers[index];
			break;
		}
	}
	if (slot == nullptr || slot->state.load(std::memory_order_acquire) != WORKER_REGISTERED ||
	    facility->state_->api.current_cpu(facility->state_->api.state) != slot->cpu_core_id) {
		std::terminate();
	}
	const uint32_t native_lcore = slot->native_lcore_id.load(std::memory_order_relaxed);
	if (native_lcore >= RTE_MAX_LCORE ||
	    facility->state_->api.current_lcore_id(facility->state_->api.state) != native_lcore ||
	    facility->state_->native_lcore_owners[native_lcore].load(std::memory_order_acquire) !=
		    worker_lcore_owner(worker_index)) {
		std::terminate();
	}
	facility->state_->api.thread_unregister(facility->state_->api.state);
	facility->state_->native_lcore_owners[native_lcore].store(NATIVE_LCORE_UNOWNED, std::memory_order_release);
	slot->native_lcore_id.store(UINT32_MAX, std::memory_order_relaxed);
	slot->state.store(WORKER_UNREGISTERED, std::memory_order_release);
}

kinetum_provider_status
dpdk_process_facility::bind_runtime_service_coordinator_(void *state, uint32_t service_index, int32_t cpu_core_id,
							 kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *facility = static_cast<dpdk_process_facility *>(state);
	if (facility == nullptr || !facility->active() || cpu_core_id < 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK coordinator binding is malformed");
	}
	const implementation::service_slot *slot = nullptr;
	for (uint32_t index = 0; index < facility->state_->service_count; ++index) {
		const auto &candidate = facility->state_->services[index];
		if (candidate.service_index == service_index &&
		    candidate.kind == KINETUM_PROVIDER_CPU_OWNER_TRANSITION_COORDINATOR) {
			slot = &candidate;
			break;
		}
	}
	if (slot == nullptr || slot->cpu_core_id != cpu_core_id ||
	    facility->state_->api.current_cpu(facility->state_->api.state) != cpu_core_id ||
	    facility->state_->api.current_lcore_id(facility->state_->api.state) != static_cast<uint32_t>(cpu_core_id) ||
	    facility->state_->api.main_lcore_id(facility->state_->api.state) != static_cast<uint32_t>(cpu_core_id) ||
	    facility->state_->api.lcore_is_enabled(facility->state_->api.state, static_cast<uint32_t>(cpu_core_id)) ==
		    0) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK coordinator caller is not the exact EAL main lcore");
	}
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

kinetum_provider_status dpdk_process_facility::launch_runtime_service_(void *state, uint32_t service_index,
								       int32_t cpu_core_id,
								       kinetum_provider_runtime_service_entry_fn entry,
								       void *argument,
								       kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *facility = static_cast<dpdk_process_facility *>(state);
	if (facility == nullptr || !facility->active() || cpu_core_id < 0 || entry == nullptr || argument == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic, "DPDK lifecycle launch is malformed");
	}
	implementation::service_slot *slot = nullptr;
	for (uint32_t index = 0; index < facility->state_->service_count; ++index) {
		auto &candidate = facility->state_->services[index];
		if (candidate.service_index == service_index &&
		    candidate.kind == KINETUM_PROVIDER_CPU_OWNER_LIFECYCLE_EXECUTOR) {
			slot = &candidate;
			break;
		}
	}
	if (slot == nullptr || slot->cpu_core_id != cpu_core_id || slot->launched ||
	    facility->state_->api.lcore_is_enabled(facility->state_->api.state, static_cast<uint32_t>(cpu_core_id)) ==
		    0) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK lifecycle executor is absent, disabled, or already launched");
	}
	slot->entry = entry;
	slot->argument = argument;
	slot->launched = true;
	if (facility->state_->api.remote_launch(facility->state_->api.state, runtime_service_entry_, slot,
						static_cast<uint32_t>(cpu_core_id)) != 0) {
		slot->launched = false;
		slot->entry = nullptr;
		slot->argument = nullptr;
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK rejected lifecycle-executor launch");
	}
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

kinetum_provider_status dpdk_process_facility::join_runtime_service_(void *state, uint32_t service_index,
								     int32_t cpu_core_id,
								     kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *facility = static_cast<dpdk_process_facility *>(state);
	if (facility == nullptr || !facility->active() || cpu_core_id < 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic, "DPDK lifecycle join is malformed");
	}
	implementation::service_slot *slot = nullptr;
	for (uint32_t index = 0; index < facility->state_->service_count; ++index) {
		auto &candidate = facility->state_->services[index];
		if (candidate.service_index == service_index &&
		    candidate.kind == KINETUM_PROVIDER_CPU_OWNER_LIFECYCLE_EXECUTOR) {
			slot = &candidate;
			break;
		}
	}
	if (slot == nullptr || slot->cpu_core_id != cpu_core_id || !slot->launched) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK lifecycle executor is not owned by this join");
	}
	// DPDK's wait operation returns the completed callback's integer result;
	// negative values do not report join failure. Returning from wait is the
	// completion proof that permits releasing the borrowed callback storage.
	(void)facility->state_->api.wait_lcore(facility->state_->api.state, static_cast<uint32_t>(cpu_core_id));
	slot->launched = false;
	slot->entry = nullptr;
	slot->argument = nullptr;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

int dpdk_process_facility::runtime_service_entry_(void *state) noexcept
{
	auto *slot = static_cast<implementation::service_slot *>(state);
	if (slot == nullptr || !slot->launched || slot->entry == nullptr || slot->argument == nullptr) {
		std::terminate();
	}
	static_assert(sizeof(int) == sizeof(int32_t));
	return static_cast<int>(slot->entry(slot->argument));
}

}  // namespace kinetum::provider::dpdk_component
