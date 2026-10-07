// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_runtime_materialization.cpp
 * @brief Transactional ownership of one exact materialized provider graph.
 * @author Fleming Patel
 */

#include "src/provider/provider_runtime_materialization.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "src/common/log.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"
#include "src/provider/provider_contract_catalog.hpp"

namespace kinetum::provider
{
namespace
{

using common::status;
using common::status_code;
using common::status_or;

/** Maximum component diagnostic accepted from one cold factory callback. */
constexpr std::size_t PROVIDER_FACTORY_DIAGNOSTIC_BYTES = 256;

/** Maximum complete fatal diagnostic emitted after facility initialization. */
constexpr std::size_t PROVIDER_MATERIALIZATION_FATAL_BYTES = 512;

/** Maximum worker-registration diagnostic accepted from one facility. */
constexpr std::size_t PROVIDER_WORKER_DIAGNOSTIC_BYTES = 256;

/** Maximum packet-I/O lifecycle diagnostic accepted from one driver. */
constexpr std::size_t PROVIDER_IO_LIFECYCLE_DIAGNOSTIC_BYTES = 256;

/** One role-relative materialized dependency key. */
struct dependency_key {
	provider_contract_role role{provider_contract_role::PROCESS_FACILITY};	///< Exact dependency role.
	uint32_t instance_index{0};  ///< Compact index in that role's vector.
};

/**
 * @brief Map one pure contract role into the exact C ABI.
 * @param role Candidate provider contract role.
 * @param output ABI role written only after successful translation.
 * @return true for a declared role; false otherwise.
 */
[[nodiscard]] bool abi_role(provider_contract_role role, kinetum_provider_role &output) noexcept
{
	switch (role) {
	case provider_contract_role::PROCESS_FACILITY:
		output = KINETUM_PROVIDER_ROLE_PROCESS_FACILITY;
		return true;
	case provider_contract_role::IO_DRIVER:
		output = KINETUM_PROVIDER_ROLE_IO_DRIVER;
		return true;
	case provider_contract_role::PACKET_STORAGE:
		output = KINETUM_PROVIDER_ROLE_PACKET_STORAGE;
		return true;
	case provider_contract_role::EXECUTION:
		output = KINETUM_PROVIDER_ROLE_EXECUTION;
		return true;
	case provider_contract_role::STORAGE_TRANSITION:
		output = KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION;
		return true;
	}
	return false;
}

/**
 * @brief Resolve the sole role-partitioned factory from one admitted row.
 * @param implementation Admitted component contract row.
 * @return Factory for the row's role, or nullptr for an unknown role.
 */
[[nodiscard]] kinetum_provider_factory_fn
factory_for_role(const kinetum_provider_contract_implementation &implementation) noexcept
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
 * @brief Construct one borrowed text view after preflighted width validation.
 * @param value Borrowed bytes with an already-proved uint32_t extent.
 * @return ABI text view whose backing bytes remain caller-owned.
 */
[[nodiscard]] kinetum_provider_text_view abi_text_view(std::string_view value) noexcept
{
	return kinetum_provider_text_view{
		.data = value.empty() ? nullptr : value.data(),
		.size = static_cast<uint32_t>(value.size()),
		.padding = 0,
	};
}

/**
 * @brief Construct one borrowed byte view after preflighted width validation.
 * @param value Borrowed bytes with an already-proved uint32_t extent.
 * @return ABI byte view whose backing bytes remain caller-owned.
 */
[[nodiscard]] kinetum_provider_byte_view abi_byte_view(std::string_view value) noexcept
{
	return kinetum_provider_byte_view{
		.data = value.empty() ? nullptr : reinterpret_cast<const uint8_t *>(value.data()),
		.size = static_cast<uint32_t>(value.size()),
		.padding = 0,
	};
}

/**
 * @brief Return whether a bounded component diagnostic is safe printable ASCII.
 * @param diagnostic Foreign result retaining the caller-owned bounded buffer.
 * @return true only when the extent is valid and every diagnostic byte is printable ASCII.
 */
[[nodiscard]] bool diagnostic_is_valid(const kinetum_provider_diagnostic &diagnostic) noexcept
{
	if (diagnostic.size > diagnostic.capacity || (diagnostic.capacity != 0 && diagnostic.data == nullptr)) {
		return false;
	}
	for (uint32_t index = 0; index < diagnostic.size; ++index) {
		const auto byte = static_cast<unsigned char>(diagnostic.data[index]);
		if (byte < 0x20u || byte > 0x7eu) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Reclaim one unadopted factory result or fail stop on partial ownership.
 *
 * A malformed callback result may still contain a reclaimable instance even
 * though it cannot be published. The exact instance/destroy pair is sufficient
 * to retire that instance. Any other nonempty shape leaves ownership
 * unknowable and therefore cannot return to a process that might unload or
 * retry the component.
 *
 * @param result Caller-owned result returned by the foreign factory callback.
 */
void reclaim_unadopted_factory_result_or_terminate(kinetum_provider_factory_result &result) noexcept
{
	const bool any_result = result.instance != nullptr || result.operations != nullptr || result.destroy != nullptr;
	if (!any_result) {
		return;
	}
	if (result.instance == nullptr || result.destroy == nullptr) {
		std::terminate();
	}

	auto *const instance = result.instance;
	const auto destroy = result.destroy;
	result = {};
	destroy(instance);
}

/**
 * @brief Convert one exact factory callback result to the platform status domain.
 * @param callback_status Foreign factory result code.
 * @param instance_id Compiled instance identity used for failure attribution.
 * @param diagnostic Caller-owned bounded foreign diagnostic.
 * @return Admitted local status, or INTERNAL_ERROR for malformed foreign output.
 */
[[nodiscard]] status factory_callback_status(kinetum_provider_status callback_status, std::string_view instance_id,
					     const kinetum_provider_diagnostic &diagnostic)
{
	if (!kinetum_provider_status_is_valid(callback_status) || !diagnostic_is_valid(diagnostic)) {
		return status::internal_error("provider component returned an invalid factory callback result");
	}
	if (callback_status == KINETUM_PROVIDER_STATUS_OK) {
		if (diagnostic.size != 0u) {
			return status::internal_error("provider factory success carried diagnostic residue");
		}
		return status::ok();
	}
	std::string message = "provider factory failed for instance '" + std::string(instance_id) + "'";
	if (diagnostic.size != 0) {
		message.append(": ");
		message.append(diagnostic.data, diagnostic.size);
	}
	switch (callback_status) {
	case KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT:
		// The shared compiler and ABI preflight already admitted the request;
		// component disagreement is an implementation defect, not user input.
		return status::internal_error(std::move(message));
	case KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION:
		return status::failed_precondition(std::move(message));
	case KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED:
		return status::resource_exhausted(std::move(message));
	case KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR:
		return status::internal_error(std::move(message));
	case KINETUM_PROVIDER_STATUS_OK:
	default:
		break;
	}
	return status::internal_error("provider component returned an unreachable factory status");
}

/**
 * @brief Convert one exact worker-registration callback result.
 * @param callback_status Foreign registration code; an unknown value fails stop because ownership is uncertain.
 * @param worker_index Compiled worker identity used for failure attribution.
 * @param diagnostic Caller-owned bounded foreign diagnostic.
 * @return Admitted local result or diagnostic-format/allocation failure.
 */
[[nodiscard]] status worker_callback_status(kinetum_provider_status callback_status, uint32_t worker_index,
					    const kinetum_provider_diagnostic &diagnostic) noexcept
{
	if (!kinetum_provider_status_is_valid(callback_status)) {
		// An out-of-domain status cannot prove whether the foreign callback
		// retained calling-thread registration. Returning would permit a retry in
		// a process whose facility ownership is no longer knowable.
		std::terminate();
	}
	if (!diagnostic_is_valid(diagnostic)) {
		return status::internal_error(kinetum::common::static_status_text(
			"provider facility returned an invalid worker-registration result"));
	}
	if (callback_status == KINETUM_PROVIDER_STATUS_OK) {
		if (diagnostic.size != 0u) {
			return status::internal_error(kinetum::common::static_status_text(
				"provider worker-registration success carried diagnostic residue"));
		}
		return status::ok();
	}

	status_code code = status_code::INTERNAL_ERROR;
	switch (callback_status) {
	case KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT:
		code = status_code::INTERNAL_ERROR;
		break;
	case KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION:
		code = status_code::FAILED_PRECONDITION;
		break;
	case KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED:
		code = status_code::RESOURCE_EXHAUSTED;
		break;
	case KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR:
		code = status_code::INTERNAL_ERROR;
		break;
	case KINETUM_PROVIDER_STATUS_OK:
	default:
		std::terminate();
	}

	try {
		std::string message = "provider facility rejected compact worker ";
		message.append(std::to_string(worker_index));
		if (diagnostic.size != 0) {
			message.append(": ");
			message.append(diagnostic.data, diagnostic.size);
		}
		return status(code, std::move(message));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(kinetum::common::static_status_text(
			"provider worker-registration diagnostic allocation failed"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "provider worker-registration diagnostic exceeded the host size domain"));
	}
}

/**
 * @brief Convert one exact I/O lifecycle callback result.
 * @param callback_status Foreign lifecycle code; malformed output fails stop.
 * @param io_driver_index Exact compiled I/O-driver identity.
 * @param operation Trusted activation/deactivation label used in diagnostics.
 * @param diagnostic Caller-owned bounded foreign diagnostic.
 * @return Admitted local lifecycle result; unresolved foreign result shape never returns.
 */
[[nodiscard]] status io_lifecycle_callback_status(kinetum_provider_status callback_status, uint32_t io_driver_index,
						  std::string_view operation,
						  const kinetum_provider_diagnostic &diagnostic) noexcept
{
	if (!kinetum_provider_status_is_valid(callback_status) || !diagnostic_is_valid(diagnostic)) {
		std::terminate();
	}
	if (callback_status == KINETUM_PROVIDER_STATUS_OK) {
		if (diagnostic.size != 0u) {
			// The callback has already crossed its live/cold ownership edge.
			// Reclassifying that successful side effect as recoverable is unsafe.
			std::terminate();
		}
		return status::ok();
	}

	status_code code = status_code::INTERNAL_ERROR;
	switch (callback_status) {
	case KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT:
		code = status_code::INTERNAL_ERROR;
		break;
	case KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION:
		code = status_code::FAILED_PRECONDITION;
		break;
	case KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED:
		code = status_code::RESOURCE_EXHAUSTED;
		break;
	case KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR:
		code = status_code::INTERNAL_ERROR;
		break;
	case KINETUM_PROVIDER_STATUS_OK:
	default:
		std::terminate();
	}

	try {
		std::string message = "provider I/O driver ";
		message.append(operation);
		message.append(" failed for compact driver ");
		message.append(std::to_string(io_driver_index));
		if (diagnostic.size != 0) {
			message.append(": ");
			message.append(diagnostic.data, diagnostic.size);
		}
		return status(code, std::move(message));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("provider I/O lifecycle diagnostic allocation failed"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "provider I/O lifecycle diagnostic exceeded the host size domain"));
	}
}

/**
 * @brief Invoke one exact I/O lifecycle callback through bounded caller storage.
 * @param operations Admitted driver operation record retaining the instance state.
 * @param io_driver_index Expected compiled driver identity.
 * @param callback Exact activation or deactivation callback to invoke.
 * @param operation Trusted diagnostic label for the operation.
 * @return Validated lifecycle status; changed buffer ownership or malformed callback identity fails stop.
 */
[[nodiscard]] status invoke_io_lifecycle(const kinetum_provider_io_driver_operations &operations,
					 uint32_t io_driver_index, kinetum_provider_io_lifecycle_fn callback,
					 std::string_view operation) noexcept
{
	if (operations.state == nullptr || callback == nullptr || operations.io_driver_index != io_driver_index) {
		std::terminate();
	}
	std::array<char, PROVIDER_IO_LIFECYCLE_DIAGNOSTIC_BYTES> diagnostic_bytes{};
	kinetum_provider_diagnostic diagnostic{
		.data = diagnostic_bytes.data(),
		.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
		.size = 0,
	};
	char *const diagnostic_data = diagnostic.data;
	const uint32_t diagnostic_capacity = diagnostic.capacity;
	const auto callback_status = callback(operations.state, &diagnostic);
	if (diagnostic.data != diagnostic_data || diagnostic.capacity != diagnostic_capacity) {
		std::terminate();
	}
	return io_lifecycle_callback_status(callback_status, io_driver_index, operation, diagnostic);
}

/**
 * @brief Map one compiled transition mode into the exact current C ABI.
 * @param mode Candidate compiled storage-transition mode.
 * @param output ABI mode written only after successful translation.
 * @return true for a declared mode; false otherwise.
 */
[[nodiscard]] bool abi_transition_mode(storage_transition_mode mode, kinetum_provider_transition_mode &output) noexcept
{
	switch (mode) {
	case storage_transition_mode::ZERO_COPY_SHARE:
		output = KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE;
		return true;
	case storage_transition_mode::BOUNDED_COPY:
		output = KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY;
		return true;
	}
	return false;
}

/**
 * @brief Derive the exact packet-storage operation capability mask.
 * @param projection Catalog-owned storage capabilities and access-agent facts.
 * @return ABI mask for CPU byte access, NIC DMA, and writable cloning.
 */
[[nodiscard]] uint32_t operation_storage_capabilities(const packet_storage_projection &projection) noexcept
{
	uint32_t capabilities = 0;
	if (projection.cpu_contiguous_read) {
		capabilities |= KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ;
	}
	if (projection.cpu_contiguous_write) {
		capabilities |= KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE;
	}
	if ((projection.access_agents & access_agent_bit(packet_access_agent::NIC_DMA)) != 0) {
		capabilities |= KINETUM_PACKET_STORAGE_NIC_RX_DMA | KINETUM_PACKET_STORAGE_NIC_TX_DMA;
	}
	if (projection.writable_clone) {
		capabilities |= KINETUM_PACKET_STORAGE_WRITABLE_CLONE;
	}
	return capabilities;
}

/**
 * @brief Return an indexed pointer or null without narrowing or throwing.
 * @param values Borrowed vector of retained owner pointers.
 * @param index Candidate compact index.
 * @return Stored pointer for an in-range index, otherwise nullptr.
 * @tparam value_type Type owned by the stored pointers.
 */
template <typename value_type>
[[nodiscard]] const value_type *at_or_null(const std::vector<const value_type *> &values, uint32_t index) noexcept
{
	return index < values.size() ? values[index] : nullptr;
}

}  // namespace

/** @brief Stable linear owner shell for one exact provider factory result. */
class materialized_provider_runtime::provider_instance_owner final {
    public:
	/**
	 * @brief Construct one empty stable owner shell over admitted immutable facts.
	 *
	 * @param facts Exact admitted instance facts that outlive this shell.
	 * @param abi_role Exact fixed-width provider role.
	 * @param factory Exact admitted role factory.
	 * @param generation Exact runtime generation retained for cold diagnostics.
	 */
	provider_instance_owner(const provider_component_instance_facts &facts, kinetum_provider_role abi_role,
				kinetum_provider_factory_fn factory, uint64_t generation) noexcept
		: facts_(facts)
		, abi_role_(abi_role)
		, factory_(factory)
		, generation_(generation)
	{
	}

	provider_instance_owner(const provider_instance_owner &) = delete;
	provider_instance_owner &operator=(const provider_instance_owner &) = delete;
	provider_instance_owner(provider_instance_owner &&) = delete;
	provider_instance_owner &operator=(provider_instance_owner &&) = delete;

	/** @brief Retire an adopted result when the transaction still owns it. */
	~provider_instance_owner() noexcept
	{
		reset();
	}

	/**
	 * @brief Adopt one already validated complete successful result.
	 *
	 * @param result Complete instance, operation table, and destroy callback.
	 * @return true when the previously empty shell adopts the complete result.
	 */
	[[nodiscard]] bool adopt(kinetum_provider_factory_result result) noexcept
	{
		if (live() || result.instance == nullptr || result.operations == nullptr || result.destroy == nullptr) {
			return false;
		}
		result_ = result;
		return true;
	}

	/** @brief Destroy the adopted instance exactly once. */
	void reset() noexcept
	{
		if (result_.destroy != nullptr) {
			auto result = result_;
			result_ = {};
			result.destroy(result.instance);
		}
	}

	/** @return true when this shell owns any factory-result authority. */
	[[nodiscard]] bool live() const noexcept
	{
		return result_.instance != nullptr || result_.operations != nullptr || result_.destroy != nullptr;
	}

	/** @return Exact admitted immutable instance facts. */
	[[nodiscard]] const provider_component_instance_facts &facts() const noexcept
	{
		return facts_;
	}

	/** @return Exact fixed-width C ABI role. */
	[[nodiscard]] kinetum_provider_role role() const noexcept
	{
		return abi_role_;
	}

	/** @return Exact admitted role factory. */
	[[nodiscard]] kinetum_provider_factory_fn factory() const noexcept
	{
		return factory_;
	}

	/** @return Cold capability whose exact context survives through instance destruction. */
	[[nodiscard]] kinetum_provider_cold_log logging() noexcept
	{
		return {.context = this, .write = log_};
	}

	/** @return Mutable dependency recipe storage before factory invocation. */
	[[nodiscard]] std::vector<dependency_key> &dependencies() noexcept
	{
		return dependencies_;
	}

	/** @return Adopted opaque component instance, or null while empty. */
	[[nodiscard]] void *instance() const noexcept
	{
		return result_.instance;
	}

	/** @return Adopted immutable role operation record, or null while empty. */
	[[nodiscard]] const void *operations() const noexcept
	{
		return result_.operations;
	}

	/** @return Exact long-lived dependency handle over the adopted result. */
	[[nodiscard]] kinetum_provider_dependency_handle dependency_handle() const noexcept
	{
		return kinetum_provider_dependency_handle{
			.instance_id = abi_text_view(facts_.instance_id),
			.type_url = abi_text_view(facts_.type_url),
			.instance = result_.instance,
			.operations = result_.operations,
			.role = abi_role_,
			.padding = {0},
		};
	}

    private:
	/**
	 * @brief Copy one provider diagnostic before returning to foreign code.
	 * @param context Exact instance owner retained through the provider's destroy callback.
	 * @param level Native severity in the closed provider range.
	 * @param event Stable event identity, validated before publication.
	 * @param function Native source function, or an empty view when unavailable.
	 * @param message Borrowed native bytes, bounded before formatting.
	 */
	static void log_(void *context, kinetum_provider_log_level level, kinetum_provider_text_view event,
			 kinetum_provider_text_view function, kinetum_provider_text_view message) noexcept
	{
		if (common::reject_packet_thread_log()) {
			return;
		}
		if (context == nullptr || level < KINETUM_PROVIDER_LOG_DEBUG ||
		    level > KINETUM_PROVIDER_LOG_EMERGENCY || !kinetum_provider_text_view_is_valid(event) ||
		    !kinetum_provider_text_view_is_valid(function) || !kinetum_provider_text_view_is_valid(message)) {
			common::reject_log_record();
			return;
		}
		const auto &owner = *static_cast<provider_instance_owner *>(context);
		constexpr std::array<common::log_level, 8> LEVELS{common::log_level::DEBUG, common::log_level::INFO,
								  common::log_level::INFO,  common::log_level::WARN,
								  common::log_level::ERROR, common::log_level::FATAL,
								  common::log_level::FATAL, common::log_level::FATAL};
		const auto mapped = LEVELS[level - 1u];
		/** Borrow only validated callback text and preserve explicit empty views. */
		const auto view = [](kinetum_provider_text_view input) -> std::string_view {
			return input.size == 0 ? std::string_view{} : std::string_view(input.data, input.size);
		};
		common::log_foreign_lazy(
			{mapped, "provider", view(event), view(function), static_cast<uint8_t>(8u - level)},
			[&](std::span<char> output) -> std::size_t {
				return static_cast<std::size_t>(
					std::format_to_n(output.data(), static_cast<std::ptrdiff_t>(output.size()),
							 "instance={} generation={}: {}", owner.facts_.instance_id,
							 owner.generation_,
							 view(message).substr(0, common::LOG_MESSAGE_BYTES + 1))
						.size);
			});
	}

	const provider_component_instance_facts &facts_;  ///< Stable admitted fact authority.
	kinetum_provider_role abi_role_{0};		  ///< Exact fixed-width role.
	kinetum_provider_factory_fn factory_{nullptr};	  ///< Exact role-owned callback.
	const uint64_t generation_;			  ///< Diagnostic attribution, never runtime authority.
	std::vector<dependency_key> dependencies_;	  ///< Precompiled dependency schedule.
	kinetum_provider_factory_result result_{};	  ///< Adopted complete component result.
};

materialized_provider_runtime::materialized_provider_runtime(admitted_provider_runtime admitted,
							     uint64_t runtime_generation) noexcept
	: admitted_(std::move(admitted))
	, runtime_generation_(runtime_generation)
{
}

materialized_provider_runtime::~materialized_provider_runtime() noexcept
{
	if (active_io_driver_count_ != 0) {
		std::terminate();
	}
	rollback_instances_();
}

void materialized_provider_runtime::rollback_instances_() noexcept
{
	if (active_io_driver_count_ != 0) {
		std::terminate();
	}
	auto reset_reverse = [](auto &owners) noexcept {
		for (auto iterator = owners.rbegin(); iterator != owners.rend(); ++iterator) {
			if (*iterator != nullptr) {
				(*iterator)->reset();
			}
		}
	};

	// Dependents retire before every borrowed dependency. The admitted catalog
	// is an earlier-declared member and therefore remains alive after this pass.
	reset_reverse(storage_transitions_);
	reset_reverse(execution_providers_);
	reset_reverse(io_drivers_);
	reset_reverse(storage_domains_);
	reset_reverse(process_facilities_);
}

[[noreturn]] void materialized_provider_runtime::fail_stop_after_facility_(const common::status &failure) noexcept
{
	rollback_instances_();
	try {
		std::string diagnostic = "provider materialization failed after process-facility initialization [";
		diagnostic.append(common::status_code_name(failure.code()));
		diagnostic.append("]: ");
		const std::string_view message = failure.message();
		const std::size_t remaining = diagnostic.size() < PROVIDER_MATERIALIZATION_FATAL_BYTES ?
						      PROVIDER_MATERIALIZATION_FATAL_BYTES - diagnostic.size() :
						      0;
		if (message.size() <= remaining) {
			diagnostic.append(message);
		} else if (remaining > 3) {
			std::string_view prefix = message;
			prefix.remove_suffix(prefix.size() - (remaining - 3u));
			diagnostic.append(prefix);
			diagnostic.append("...");
		} else {
			std::string_view prefix = message;
			prefix.remove_suffix(prefix.size() - remaining);
			diagnostic.append(prefix);
		}
		std::fprintf(stderr, "provider: %s\n", diagnostic.c_str());
		(void)std::fflush(stderr);
		common::offer_fatal_log(
			{common::log_level::FATAL, "provider", "provider.materialization.fatal", __func__}, diagnostic);
	} catch (...) {
		std::fputs(
			"provider: materialization failed after process-facility initialization; diagnostic emission failed\n",
			stderr);
	}
	std::terminate();
}

status_or<std::unique_ptr<materialized_provider_runtime>>
materialized_provider_runtime::create(admitted_provider_runtime admitted, const compiled_provider_topology &topology,
				      uint64_t runtime_generation)
{
	if (runtime_generation == 0 || runtime_generation > std::numeric_limits<uint32_t>::max()) {
		return status::invalid_argument("provider runtime generation is outside the exact packet ABI range");
	}
	if (topology.storage_domains.size() > KINETUM_INVALID_STORAGE_DOMAIN) {
		return status::internal_error(
			"compiled storage-domain population exceeds the packet-record index namespace");
	}

	std::unique_ptr<materialized_provider_runtime> runtime;
	try {
		runtime.reset(new materialized_provider_runtime(std::move(admitted), runtime_generation));

		runtime->process_facilities_.reserve(topology.process_facilities.size());
		runtime->storage_domains_.reserve(topology.storage_domains.size());
		runtime->io_drivers_.reserve(topology.io_drivers.size());
		runtime->execution_providers_.reserve(topology.execution_providers.size());
		runtime->storage_transitions_.reserve(topology.storage_transitions.size());
		runtime->facility_operations_.assign(topology.process_facilities.size(), nullptr);
		runtime->storage_operations_.assign(topology.storage_domains.size(), nullptr);
		runtime->driver_operations_.assign(topology.io_drivers.size(), nullptr);
		runtime->execution_operations_.assign(topology.execution_providers.size(), nullptr);
		runtime->transition_operations_.assign(topology.storage_transitions.size(), nullptr);
		runtime->rx_stream_operations_.assign(topology.io_streams.size(), nullptr);
		runtime->tx_stream_operations_.assign(topology.io_streams.size(), nullptr);
		runtime->worker_facility_indices_.resize(topology.transition_topology.workers.size());
		for (const auto &facility : topology.process_facilities) {
			for (const auto &assignment : facility.cpu_assignments) {
				if (assignment.kind != compiled_facility_cpu_owner_kind::PACKET_WORKER) {
					continue;
				}
				if (assignment.owner_index >= runtime->worker_facility_indices_.size()) {
					return status::internal_error(
						"compiled facility references an unknown compact packet worker");
				}
				runtime->worker_facility_indices_[assignment.owner_index].push_back(
					facility.facility_index);
			}
		}
		for (const auto &facility_indices : runtime->worker_facility_indices_) {
			if (!std::is_sorted(facility_indices.begin(), facility_indices.end()) ||
			    std::adjacent_find(facility_indices.begin(), facility_indices.end()) !=
				    facility_indices.end()) {
				return status::internal_error(
					"compiled worker facility ownership is not strictly sorted and unique");
			}
		}
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("provider materialization owner-table allocation failed");
	} catch (...) {
		return status::internal_error("provider materialization owner-table construction failed");
	}

	auto owner_vector =
		[&](provider_contract_role role) -> std::vector<std::unique_ptr<provider_instance_owner>> * {
		switch (role) {
		case provider_contract_role::PROCESS_FACILITY:
			return &runtime->process_facilities_;
		case provider_contract_role::IO_DRIVER:
			return &runtime->io_drivers_;
		case provider_contract_role::PACKET_STORAGE:
			return &runtime->storage_domains_;
		case provider_contract_role::EXECUTION:
			return &runtime->execution_providers_;
		case provider_contract_role::STORAGE_TRANSITION:
			return &runtime->storage_transitions_;
		}
		return nullptr;
	};

	auto owner_at = [&](provider_contract_role role, uint32_t index) -> provider_instance_owner * {
		auto *owners = owner_vector(role);
		return owners != nullptr && index < owners->size() ? (*owners)[index].get() : nullptr;
	};

	auto append_owner = [&](provider_contract_role role, uint32_t index, std::string_view instance_id,
				std::string_view type_url, std::string_view canonical_configuration) -> status {
		const auto *facts = runtime->admitted_.instance_facts(role, index);
		kinetum_provider_role fixed_role = 0;
		if (facts == nullptr || facts->role != role || facts->instance_index != index ||
		    facts->instance_id != instance_id || facts->type_url != type_url ||
		    facts->canonical_configuration != canonical_configuration || !abi_role(role, fixed_role) ||
		    facts->instance_id.size() > std::numeric_limits<uint32_t>::max() ||
		    facts->type_url.size() > std::numeric_limits<uint32_t>::max() ||
		    facts->canonical_configuration.size() > std::numeric_limits<uint32_t>::max()) {
			return status::internal_error(
				"admitted provider facts disagree with compiled topology identity");
		}
		const auto *implementation = runtime->admitted_.catalog().find(type_url);
		if (implementation == nullptr || implementation->implementation == nullptr ||
		    implementation->type_url != type_url || implementation->implementation->role != fixed_role) {
			return status::internal_error("sealed provider catalog lacks one exact compiled factory row");
		}
		const auto factory = factory_for_role(*implementation->implementation);
		if (factory == nullptr) {
			return status::internal_error("sealed provider catalog row lacks its exact role factory");
		}
		auto *owners = owner_vector(role);
		if (owners == nullptr || owners->size() != index) {
			return status::internal_error("provider materialization owner order is not compact and exact");
		}
		try {
			owners->emplace_back(std::make_unique<provider_instance_owner>(*facts, fixed_role, factory,
										       runtime_generation));
		} catch (const std::bad_alloc &) {
			return status::resource_exhausted("provider materialization owner allocation failed");
		} catch (...) {
			return status::internal_error("provider materialization owner construction failed");
		}
		return status::ok();
	};

	for (const auto &instance : topology.process_facilities) {
		auto result = append_owner(provider_contract_role::PROCESS_FACILITY, instance.facility_index,
					   instance.facility_instance_id, instance.configuration.type_url,
					   instance.configuration.canonical_payload);
		if (!result.is_ok()) {
			return result;
		}
	}
	for (const auto &instance : topology.storage_domains) {
		auto result = append_owner(provider_contract_role::PACKET_STORAGE, instance.storage_domain_index,
					   instance.storage_domain_id, instance.configuration.type_url,
					   instance.configuration.canonical_payload);
		if (!result.is_ok()) {
			return result;
		}
	}
	for (const auto &instance : topology.io_drivers) {
		auto result = append_owner(provider_contract_role::IO_DRIVER, instance.io_driver_index,
					   instance.io_driver_instance_id, instance.configuration.type_url,
					   instance.configuration.canonical_payload);
		if (!result.is_ok()) {
			return result;
		}
	}
	for (const auto &instance : topology.execution_providers) {
		auto result = append_owner(provider_contract_role::EXECUTION, instance.execution_provider_index,
					   instance.execution_provider_instance_id, instance.configuration.type_url,
					   instance.configuration.canonical_payload);
		if (!result.is_ok()) {
			return result;
		}
	}
	for (const auto &instance : topology.storage_transitions) {
		auto result = append_owner(provider_contract_role::STORAGE_TRANSITION, instance.transition_index,
					   instance.transition_id, instance.configuration.type_url,
					   instance.configuration.canonical_payload);
		if (!result.is_ok()) {
			return result;
		}
	}
	if (runtime->admitted_.instance_count() !=
	    topology.process_facilities.size() + topology.io_drivers.size() + topology.storage_domains.size() +
		    topology.execution_providers.size() + topology.storage_transitions.size()) {
		return status::internal_error("admitted provider fact set contains an unmaterialized instance");
	}

	auto add_dependency = [&](provider_instance_owner &owner, provider_contract_role role,
				  uint32_t index) -> status {
		if (owner_at(role, index) == nullptr) {
			return status::internal_error(
				"compiled provider dependency index is outside its exact role vector");
		}
		try {
			owner.dependencies().push_back(dependency_key{role, index});
		} catch (const std::bad_alloc &) {
			return status::resource_exhausted("provider dependency-recipe allocation failed");
		} catch (...) {
			return status::internal_error("provider dependency-recipe construction failed");
		}
		return status::ok();
	};

	auto add_indices = [&](provider_instance_owner &owner, provider_contract_role role,
			       const std::vector<uint32_t> &indices) -> status {
		for (uint32_t index : indices) {
			auto result = add_dependency(owner, role, index);
			if (!result.is_ok()) {
				return result;
			}
		}
		return status::ok();
	};

	for (const auto &instance : topology.storage_domains) {
		auto *owner = owner_at(provider_contract_role::PACKET_STORAGE, instance.storage_domain_index);
		if (owner == nullptr) {
			return status::internal_error("packet-storage owner shell is absent");
		}
		auto result = add_indices(*owner, provider_contract_role::PROCESS_FACILITY, instance.facility_indices);
		if (!result.is_ok()) {
			return result;
		}
	}
	for (const auto &instance : topology.io_drivers) {
		auto *owner = owner_at(provider_contract_role::IO_DRIVER, instance.io_driver_index);
		if (owner == nullptr) {
			return status::internal_error("I/O-driver owner shell is absent");
		}
		auto result = add_indices(*owner, provider_contract_role::PROCESS_FACILITY, instance.facility_indices);
		if (result.is_ok()) {
			result = add_indices(*owner, provider_contract_role::PACKET_STORAGE,
					     instance.storage_domain_indices);
		}
		if (!result.is_ok()) {
			return result;
		}
	}
	for (const auto &instance : topology.execution_providers) {
		auto *owner = owner_at(provider_contract_role::EXECUTION, instance.execution_provider_index);
		if (owner == nullptr) {
			return status::internal_error("execution-provider owner shell is absent");
		}
		auto result = add_indices(*owner, provider_contract_role::PROCESS_FACILITY, instance.facility_indices);
		if (result.is_ok()) {
			result = add_indices(*owner, provider_contract_role::PACKET_STORAGE,
					     instance.storage_domain_indices);
		}
		if (!result.is_ok()) {
			return result;
		}
	}
	for (const auto &instance : topology.storage_transitions) {
		auto *owner = owner_at(provider_contract_role::STORAGE_TRANSITION, instance.transition_index);
		if (owner == nullptr) {
			return status::internal_error("storage-transition owner shell is absent");
		}
		auto result = add_indices(*owner, provider_contract_role::PROCESS_FACILITY, instance.facility_indices);
		const uint32_t first_storage_index =
			std::min(instance.from_storage_domain_index, instance.to_storage_domain_index);
		const uint32_t second_storage_index =
			std::max(instance.from_storage_domain_index, instance.to_storage_domain_index);
		if (result.is_ok()) {
			result = add_dependency(*owner, provider_contract_role::PACKET_STORAGE, first_storage_index);
		}
		if (result.is_ok() && second_storage_index != first_storage_index) {
			result = add_dependency(*owner, provider_contract_role::PACKET_STORAGE, second_storage_index);
		}
		if (!result.is_ok()) {
			return result;
		}
	}

	std::size_t maximum_dependencies = 0;
	auto finalize_dependencies = [&](auto &owners) -> status {
		for (auto &owner : owners) {
			auto &dependencies = owner->dependencies();
			for (std::size_t index = 1; index < dependencies.size(); ++index) {
				const auto &previous = dependencies[index - 1];
				const auto &current = dependencies[index];
				kinetum_provider_role previous_role = 0;
				kinetum_provider_role current_role = 0;
				if (!abi_role(previous.role, previous_role) || !abi_role(current.role, current_role) ||
				    previous_role > current_role ||
				    (previous_role == current_role &&
				     previous.instance_index >= current.instance_index)) {
					return status::internal_error(
						"compiled provider dependency set is not strictly canonical");
				}
			}
			maximum_dependencies = std::max(maximum_dependencies, dependencies.size());
		}
		return status::ok();
	};

	auto result = finalize_dependencies(runtime->process_facilities_);
	if (result.is_ok()) {
		result = finalize_dependencies(runtime->storage_domains_);
	}
	if (result.is_ok()) {
		result = finalize_dependencies(runtime->io_drivers_);
	}
	if (result.is_ok()) {
		result = finalize_dependencies(runtime->execution_providers_);
	}
	if (result.is_ok()) {
		result = finalize_dependencies(runtime->storage_transitions_);
	}
	if (!result.is_ok()) {
		return result;
	}
	if (maximum_dependencies > std::numeric_limits<uint32_t>::max()) {
		return status::internal_error("provider dependency schedule exceeds the exact C ABI width");
	}
	try {
		runtime->dependency_scratch_.reserve(maximum_dependencies);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("provider dependency callback-array allocation failed");
	} catch (...) {
		return status::internal_error("provider dependency callback-array construction failed");
	}

	auto invoke_factory = [&](provider_instance_owner &owner) -> status {
		runtime->dependency_scratch_.clear();
		for (const auto &key : owner.dependencies()) {
			auto *dependency = owner_at(key.role, key.instance_index);
			if (dependency == nullptr || !dependency->live()) {
				return status::internal_error(
					"provider factory dependency is not materialized before its dependent");
			}
			runtime->dependency_scratch_.push_back(dependency->dependency_handle());
		}
		const auto &facts = owner.facts();
		const kinetum_provider_factory_request request{
			.instance_id = abi_text_view(facts.instance_id),
			.type_url = abi_text_view(facts.type_url),
			.canonical_configuration = abi_byte_view(facts.canonical_configuration),
			.compiled_facts = facts.compiled_facts,
			.dependencies = runtime->dependency_scratch_.empty() ? nullptr :
									       runtime->dependency_scratch_.data(),
			.dependency_count = static_cast<uint32_t>(runtime->dependency_scratch_.size()),
			.dependency_padding = 0,
			.runtime_generation = runtime_generation,
			.role = owner.role(),
			.padding = {0},
			.logging = owner.logging(),
		};
		if (kinetum_provider_factory_request_is_valid(&request) == 0) {
			return status::internal_error("compiled provider factory request violates the exact C ABI");
		}

		std::array<char, PROVIDER_FACTORY_DIAGNOSTIC_BYTES> diagnostic_bytes{};
		kinetum_provider_diagnostic diagnostic{
			.data = diagnostic_bytes.data(),
			.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
			.size = 0,
		};
		char *const diagnostic_data = diagnostic.data;
		const uint32_t diagnostic_capacity = diagnostic.capacity;
		kinetum_provider_factory_result factory_result{};
		const auto callback_status = owner.factory()(&request, &factory_result, &diagnostic);
		const bool callback_status_valid = kinetum_provider_status_is_valid(callback_status) != 0;
		if (owner.role() == KINETUM_PROVIDER_ROLE_PROCESS_FACILITY &&
		    (callback_status == KINETUM_PROVIDER_STATUS_OK || !callback_status_valid)) {
			// A successful facility callback may have initialized process-global
			// foreign state even if its result is malformed. An undeclared status
			// cannot prove the opposite. Neither case may return to a process that
			// could attempt materialization again.
			runtime->facility_materialized_ = true;
		}
		if (diagnostic.data != diagnostic_data || diagnostic.capacity != diagnostic_capacity) {
			reclaim_unadopted_factory_result_or_terminate(factory_result);
			return status::internal_error(
				"provider component replaced caller-owned factory diagnostic storage");
		}
		if (!kinetum_provider_factory_result_matches_status(request.role, callback_status, &factory_result)) {
			reclaim_unadopted_factory_result_or_terminate(factory_result);
			return status::internal_error("provider component returned an invalid role factory result");
		}
		auto callback_result = factory_callback_status(callback_status, facts.instance_id, diagnostic);
		if (!callback_result.is_ok()) {
			reclaim_unadopted_factory_result_or_terminate(factory_result);
			return callback_result;
		}
		if (!owner.adopt(factory_result)) {
			reclaim_unadopted_factory_result_or_terminate(factory_result);
			return status::internal_error(
				"provider materialization owner rejected a complete factory result");
		}
		return status::ok();
	};

	auto handle_failure = [&](const status &failure) -> status_or<std::unique_ptr<materialized_provider_runtime>> {
		if (runtime->facility_materialized_) {
			runtime->fail_stop_after_facility_(failure);
		}
		return failure;
	};

	auto validate_process_facility = [&](provider_instance_owner &owner) -> status {
		const auto &facts = owner.facts();
		const auto *operations =
			static_cast<const kinetum_provider_process_facility_operations *>(owner.operations());
		if (facts.compiled_facts.process_facility == nullptr ||
		    !kinetum_provider_process_facility_operations_are_valid(operations) ||
		    operations->generation != runtime_generation ||
		    operations->facility_index != facts.compiled_facts.process_facility->facility_index) {
			return status::internal_error(
				"provider process-facility operations disagree with compiled identity");
		}
		runtime->facility_operations_[facts.instance_index] = operations;
		return status::ok();
	};

	auto validate_storage = [&](provider_instance_owner &owner) -> status {
		const auto &facts = owner.facts();
		if (facts.instance_index >= topology.storage_domains.size() ||
		    facts.compiled_facts.packet_storage == nullptr) {
			return status::internal_error("provider packet-storage facts lack their compiled owner");
		}
		const auto &compiled = topology.storage_domains[facts.instance_index];
		const auto *operations =
			static_cast<const kinetum_packet_storage_domain_operations *>(owner.operations());
		if (!kinetum_provider_packet_storage_operations_are_valid(operations) ||
		    operations->generation != runtime_generation ||
		    operations->domain_index != compiled.storage_domain_index ||
		    operations->maximum_packet_length != compiled.maximum_packet_length ||
		    operations->capabilities != operation_storage_capabilities(compiled.capabilities)) {
			return status::internal_error(
				"provider packet-storage operations disagree with compiled identity or shape");
		}
		runtime->storage_operations_[compiled.storage_domain_index] = operations;
		return status::ok();
	};

	auto validate_io_driver = [&](provider_instance_owner &owner) -> status {
		const auto &facts = owner.facts();
		if (facts.instance_index >= topology.io_drivers.size() || facts.compiled_facts.io_driver == nullptr) {
			return status::internal_error("provider I/O-driver facts lack their compiled owner");
		}
		const auto &compiled = topology.io_drivers[facts.instance_index];
		const auto &abi_facts = *facts.compiled_facts.io_driver;
		const auto *operations = static_cast<const kinetum_provider_io_driver_operations *>(owner.operations());
		if (!kinetum_provider_io_driver_operations_are_valid(operations) ||
		    operations->io_driver_index != compiled.io_driver_index ||
		    abi_facts.io_driver_index != compiled.io_driver_index) {
			return status::internal_error("provider I/O-driver operations disagree with compiled identity");
		}
		uint32_t rx_position = 0;
		uint32_t tx_position = 0;
		for (uint32_t index = 0; index < abi_facts.stream_count; ++index) {
			const auto &stream_fact = abi_facts.streams[index];
			if (stream_fact.io_stream_index >= topology.io_streams.size()) {
				return status::internal_error(
					"provider I/O-driver operation references an unknown stream");
			}
			const auto &stream = topology.io_streams[stream_fact.io_stream_index];
			if (stream.port_index >= topology.ports.size() ||
			    stream.io_stream_index != stream_fact.io_stream_index ||
			    topology.ports[stream.port_index].io_driver_index != compiled.io_driver_index ||
			    topology.ports[stream.port_index].logical_port_id >= KINETUM_INVALID_PORT) {
				return status::internal_error(
					"provider I/O-driver stream ownership disagrees with compiled topology");
			}
			const auto logical_port =
				static_cast<uint16_t>(topology.ports[stream.port_index].logical_port_id);
			if (stream_fact.direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
				if (stream.direction != compiled_io_stream_direction::RX ||
				    rx_position >= operations->rx_queue_count ||
				    runtime->rx_stream_operations_[stream.io_stream_index] != nullptr) {
					return status::internal_error(
						"provider RX operation order disagrees with compiled stream order");
				}
				const auto *queue = &operations->rx_queues[rx_position++];
				if (queue->logical_port != logical_port ||
				    queue->maximum_burst > common::runtime_sizing::PACKET_MAX_BURST_SIZE) {
					return status::internal_error(
						"provider RX operation disagrees with exact logical-port or burst bounds");
				}
				runtime->rx_stream_operations_[stream.io_stream_index] = queue;
			} else if (stream_fact.direction == KINETUM_PROVIDER_IO_DIRECTION_TX) {
				if (stream.direction != compiled_io_stream_direction::TX ||
				    tx_position >= operations->tx_queue_count ||
				    runtime->tx_stream_operations_[stream.io_stream_index] != nullptr) {
					return status::internal_error(
						"provider TX operation order disagrees with compiled stream order");
				}
				const auto *queue = &operations->tx_queues[tx_position++];
				if (queue->logical_port != logical_port ||
				    queue->maximum_burst > common::runtime_sizing::PACKET_MAX_BURST_SIZE) {
					return status::internal_error(
						"provider TX operation disagrees with exact logical-port or burst bounds");
				}
				runtime->tx_stream_operations_[stream.io_stream_index] = queue;
			} else {
				return status::internal_error(
					"provider I/O-driver fact contains an invalid stream direction");
			}
		}
		if (rx_position != operations->rx_queue_count || tx_position != operations->tx_queue_count) {
			return status::internal_error(
				"provider I/O-driver operation table contains an uncompiled queue");
		}
		runtime->driver_operations_[compiled.io_driver_index] = operations;
		return status::ok();
	};

	auto validate_execution = [&](provider_instance_owner &owner) -> status {
		const auto &facts = owner.facts();
		if (facts.instance_index >= topology.execution_providers.size() ||
		    facts.compiled_facts.execution == nullptr) {
			return status::internal_error("provider execution facts lack their compiled owner");
		}
		const auto &compiled = topology.execution_providers[facts.instance_index];
		const auto *operations = static_cast<const kinetum_provider_execution_operations *>(owner.operations());
		if (!kinetum_provider_execution_operations_are_valid(operations) ||
		    operations->execution_provider_index != compiled.execution_provider_index ||
		    operations->required_access_agents != facts.compiled_facts.execution->required_access_agents) {
			return status::internal_error(
				"provider execution operations disagree with compiled identity or access");
		}
		runtime->execution_operations_[compiled.execution_provider_index] = operations;
		return status::ok();
	};

	auto validate_transition = [&](provider_instance_owner &owner) -> status {
		const auto &facts = owner.facts();
		if (facts.instance_index >= topology.storage_transitions.size() ||
		    facts.compiled_facts.storage_transition == nullptr) {
			return status::internal_error("provider transition facts lack their compiled owner");
		}
		const auto &compiled = topology.storage_transitions[facts.instance_index];
		const auto *operations =
			static_cast<const kinetum_provider_storage_transition_operations *>(owner.operations());
		kinetum_provider_transition_mode expected_mode = 0;
		if (!abi_transition_mode(compiled.capabilities.mode, expected_mode) ||
		    !kinetum_provider_storage_transition_operations_are_valid(operations) ||
		    operations->generation != runtime_generation ||
		    operations->transition_index != compiled.transition_index ||
		    operations->from_storage_domain_index != compiled.from_storage_domain_index ||
		    operations->to_storage_domain_index != compiled.to_storage_domain_index ||
		    operations->mode != expected_mode) {
			return status::internal_error(
				"provider transition operations disagree with compiled identity or mode");
		}
		runtime->transition_operations_[compiled.transition_index] = operations;
		return status::ok();
	};

	status exceptional_allocation_failure =
		status::resource_exhausted("provider materialization exhausted memory after factory admission");
	status exceptional_internal_failure =
		status::internal_error("provider materialization raised an unexpected internal exception");
	try {
		for (auto &owner : runtime->process_facilities_) {
			result = invoke_factory(*owner);
			if (result.is_ok()) {
				result = validate_process_facility(*owner);
			}
			if (!result.is_ok()) {
				return handle_failure(result);
			}
		}
		for (auto &owner : runtime->storage_domains_) {
			result = invoke_factory(*owner);
			if (result.is_ok()) {
				result = validate_storage(*owner);
			}
			if (!result.is_ok()) {
				return handle_failure(result);
			}
		}
		for (auto &owner : runtime->io_drivers_) {
			result = invoke_factory(*owner);
			if (result.is_ok()) {
				result = validate_io_driver(*owner);
			}
			if (!result.is_ok()) {
				return handle_failure(result);
			}
		}
		for (auto &owner : runtime->execution_providers_) {
			result = invoke_factory(*owner);
			if (result.is_ok()) {
				result = validate_execution(*owner);
			}
			if (!result.is_ok()) {
				return handle_failure(result);
			}
		}
		for (auto &owner : runtime->storage_transitions_) {
			result = invoke_factory(*owner);
			if (result.is_ok()) {
				result = validate_transition(*owner);
			}
			if (!result.is_ok()) {
				return handle_failure(result);
			}
		}

		for (const auto &stream : topology.io_streams) {
			if (stream.io_stream_index >= runtime->rx_stream_operations_.size() ||
			    stream.io_stream_index >= runtime->tx_stream_operations_.size()) {
				return handle_failure(
					status::internal_error("compiled stream index is outside materialized tables"));
			}
			const bool has_rx = runtime->rx_stream_operations_[stream.io_stream_index] != nullptr;
			const bool has_tx = runtime->tx_stream_operations_[stream.io_stream_index] != nullptr;
			if ((stream.direction == compiled_io_stream_direction::RX && (!has_rx || has_tx)) ||
			    (stream.direction == compiled_io_stream_direction::TX && (has_rx || !has_tx))) {
				return handle_failure(status::internal_error(
					"materialized stream table is incomplete or directionally aliased"));
			}
		}

		return runtime;
	} catch (const std::bad_alloc &) {
		if (runtime->facility_materialized_) {
			runtime->fail_stop_after_facility_(exceptional_allocation_failure);
		}
		return exceptional_allocation_failure;
	} catch (...) {
		if (runtime->facility_materialized_) {
			runtime->fail_stop_after_facility_(exceptional_internal_failure);
		}
		return exceptional_internal_failure;
	}
}

uint64_t materialized_provider_runtime::runtime_generation() const noexcept
{
	return runtime_generation_;
}

const kinetum_provider_process_facility_operations *
materialized_provider_runtime::process_facility(uint32_t facility_index) const noexcept
{
	return at_or_null(facility_operations_, facility_index);
}

const kinetum_packet_storage_domain_operations *
materialized_provider_runtime::storage_domain(uint32_t storage_domain_index) const noexcept
{
	return at_or_null(storage_operations_, storage_domain_index);
}

const kinetum_provider_io_driver_operations *
materialized_provider_runtime::io_driver(uint32_t io_driver_index) const noexcept
{
	return at_or_null(driver_operations_, io_driver_index);
}

const kinetum_provider_execution_operations *
materialized_provider_runtime::execution_provider(uint32_t execution_provider_index) const noexcept
{
	return at_or_null(execution_operations_, execution_provider_index);
}

const kinetum_provider_storage_transition_operations *
materialized_provider_runtime::storage_transition(uint32_t transition_index) const noexcept
{
	return at_or_null(transition_operations_, transition_index);
}

const kinetum_packet_rx_burst_operations *
materialized_provider_runtime::rx_stream(uint32_t io_stream_index) const noexcept
{
	return at_or_null(rx_stream_operations_, io_stream_index);
}

const kinetum_packet_tx_burst_operations *
materialized_provider_runtime::tx_stream(uint32_t io_stream_index) const noexcept
{
	return at_or_null(tx_stream_operations_, io_stream_index);
}

std::size_t materialized_provider_runtime::io_stream_count() const noexcept
{
	return rx_stream_operations_.size();
}

status materialized_provider_runtime::activate_packet_io() noexcept
{
	if (active_io_driver_count_ != 0) {
		return status::failed_precondition(
			kinetum::common::static_status_text("provider packet I/O is already active"));
	}
	for (std::size_t index = 0; index < driver_operations_.size(); ++index) {
		const auto *operations = driver_operations_[index];
		if (!kinetum_provider_io_driver_operations_are_valid(operations) ||
		    index > static_cast<std::size_t>(UINT32_MAX)) {
			std::terminate();
		}
		auto result = invoke_io_lifecycle(*operations, static_cast<uint32_t>(index),
						  operations->activate_packet_io, "activation");
		if (result.is_ok()) {
			++active_io_driver_count_;
			continue;
		}
		while (active_io_driver_count_ != 0) {
			const std::size_t rollback_index = active_io_driver_count_ - 1u;
			const auto *rollback_operations = driver_operations_[rollback_index];
			if (rollback_operations == nullptr || rollback_index > static_cast<std::size_t>(UINT32_MAX)) {
				std::terminate();
			}
			const auto rollback_result =
				invoke_io_lifecycle(*rollback_operations, static_cast<uint32_t>(rollback_index),
						    rollback_operations->deactivate_packet_io, "activation rollback");
			if (!rollback_result.is_ok()) {
				std::terminate();
			}
			--active_io_driver_count_;
		}
		return result;
	}
	return status::ok();
}

status materialized_provider_runtime::deactivate_packet_io() noexcept
{
	if (active_io_driver_count_ != driver_operations_.size()) {
		return status::failed_precondition(
			kinetum::common::static_status_text("provider packet I/O is not completely active"));
	}
	while (active_io_driver_count_ != 0) {
		const std::size_t index = active_io_driver_count_ - 1u;
		const auto *operations = driver_operations_[index];
		if (operations == nullptr || index > static_cast<std::size_t>(UINT32_MAX)) {
			std::terminate();
		}
		auto result = invoke_io_lifecycle(*operations, static_cast<uint32_t>(index),
						  operations->deactivate_packet_io, "deactivation");
		if (!result.is_ok()) {
			return result;
		}
		--active_io_driver_count_;
	}
	return status::ok();
}

status materialized_provider_runtime::register_worker_thread(uint32_t worker_index) const noexcept
{
	if (worker_index >= worker_facility_indices_.size()) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"compact worker index is outside the materialized generation"));
	}

	const auto &facility_indices = worker_facility_indices_[worker_index];
	std::size_t registered_count = 0;
	for (uint32_t facility_index : facility_indices) {
		const auto *operations = process_facility(facility_index);
		if (!kinetum_provider_process_facility_operations_are_valid(operations)) {
			for (std::size_t rollback = registered_count; rollback > 0; --rollback) {
				const auto *registered = process_facility(facility_indices[rollback - 1u]);
				registered->unregister_worker_thread(registered->state, worker_index);
			}
			return status::internal_error(kinetum::common::static_status_text(
				"materialized worker facility table contains an invalid operation record"));
		}

		std::array<char, PROVIDER_WORKER_DIAGNOSTIC_BYTES> diagnostic_bytes{};
		kinetum_provider_diagnostic diagnostic{
			.data = diagnostic_bytes.data(),
			.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
			.size = 0,
		};
		char *const diagnostic_data = diagnostic.data;
		const uint32_t diagnostic_capacity = diagnostic.capacity;
		const auto callback_status =
			operations->register_worker_thread(operations->state, worker_index, &diagnostic);
		if (!kinetum_provider_status_is_valid(callback_status)) {
			std::terminate();
		}
		const bool callback_succeeded = callback_status == KINETUM_PROVIDER_STATUS_OK;
		if (diagnostic.data != diagnostic_data || diagnostic.capacity != diagnostic_capacity) {
			if (callback_succeeded) {
				operations->unregister_worker_thread(operations->state, worker_index);
			}
			for (std::size_t rollback = registered_count; rollback > 0; --rollback) {
				const auto *registered = process_facility(facility_indices[rollback - 1u]);
				registered->unregister_worker_thread(registered->state, worker_index);
			}
			return status::internal_error(kinetum::common::static_status_text(
				"provider facility replaced caller-owned worker diagnostic storage"));
		}
		auto callback_result = worker_callback_status(callback_status, worker_index, diagnostic);
		if (!callback_result.is_ok()) {
			if (callback_succeeded) {
				operations->unregister_worker_thread(operations->state, worker_index);
			}
			for (std::size_t rollback = registered_count; rollback > 0; --rollback) {
				const auto *registered = process_facility(facility_indices[rollback - 1u]);
				registered->unregister_worker_thread(registered->state, worker_index);
			}
			return callback_result;
		}
		++registered_count;
	}
	return status::ok();
}

void materialized_provider_runtime::unregister_worker_thread(uint32_t worker_index) const noexcept
{
	if (worker_index >= worker_facility_indices_.size()) {
		std::terminate();
	}
	const auto &facility_indices = worker_facility_indices_[worker_index];
	for (auto iterator = facility_indices.rbegin(); iterator != facility_indices.rend(); ++iterator) {
		const auto *operations = process_facility(*iterator);
		if (!kinetum_provider_process_facility_operations_are_valid(operations)) {
			std::terminate();
		}
		operations->unregister_worker_thread(operations->state, worker_index);
	}
}

bool materialized_provider_runtime::worker_uses_process_facility(uint32_t worker_index) const noexcept
{
	return worker_index < worker_facility_indices_.size() && !worker_facility_indices_[worker_index].empty();
}

}  // namespace kinetum::provider
