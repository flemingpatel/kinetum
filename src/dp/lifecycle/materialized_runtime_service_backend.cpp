// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file materialized_runtime_service_backend.cpp
 * @brief Materialized lifecycle-service backend implementation.
 * @author Fleming Patel
 */

#include "src/dp/lifecycle/materialized_runtime_service_backend.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "src/common/status.hpp"

namespace kinetum::dp::lifecycle
{
namespace
{

using kinetum::common::compiled_runtime_service;
using kinetum::common::compiled_runtime_service_role;
using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::provider::compiled_facility_cpu_owner_kind;

/** Maximum accepted component diagnostic for one lifecycle callback. */
constexpr std::size_t PROVIDER_LIFECYCLE_DIAGNOSTIC_BYTES = 256;

static_assert(std::is_same_v<runtime_service_entry_fn, kinetum_provider_runtime_service_entry_fn>,
	      "provider and platform lifecycle entry callback shapes diverged");

/**
 * @brief Return whether one provider diagnostic is bounded printable ASCII.
 * @param diagnostic Foreign result retaining caller-owned buffer storage.
 * @return true only when extent and printable-ASCII contents are valid.
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
 * @brief Fail stop after a facility callback violates its lifecycle result contract.
 *
 * A successful launch may retain the caller-owned entry context, while a
 * successful join releases it. Once the foreign callback returns a malformed
 * status or diagnostic, the platform cannot distinguish those ownership
 * transitions from a rejected operation and must not unwind or retry.
 *
 * @param operation Bounded lifecycle operation description.
 */
[[noreturn]] void fail_stop_invalid_lifecycle_callback(std::string_view operation) noexcept
{
	std::fprintf(stderr,
		     "lifecycle: process facility violated the lifecycle callback contract while attempting to %.*s\n",
		     static_cast<int>(operation.size() < 8192 ? operation.size() : 8192), operation.data());
	(void)std::fflush(stderr);
	std::terminate();
}

/**
 * @brief Convert one exact facility callback result into platform status.
 * @param callback_status Previously validated foreign lifecycle result code.
 * @param operation Trusted operation label for failure attribution.
 * @param diagnostic Previously validated caller-owned diagnostic.
 * @return Admitted local status; success with diagnostic residue fails stop.
 */
[[nodiscard]] status facility_callback_status(kinetum_provider_status callback_status, std::string_view operation,
					      const kinetum_provider_diagnostic &diagnostic) noexcept
{
	if (callback_status == KINETUM_PROVIDER_STATUS_OK) {
		if (diagnostic.size != 0u) {
			// Bind, launch, and join success each cross a foreign ownership edge.
			// Diagnostic residue cannot turn that edge into a recoverable failure.
			fail_stop_invalid_lifecycle_callback(operation);
		}
		return status::ok();
	}

	status_code code = status_code::INTERNAL_ERROR;
	switch (callback_status) {
	case KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT:
		// Compilation and materialization admitted the exact service record;
		// callback disagreement is an implementation defect.
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
		std::terminate();
	default:
		fail_stop_invalid_lifecycle_callback(operation);
	}

	try {
		std::string message = "process facility failed to ";
		message.append(operation);
		if (diagnostic.size != 0) {
			message.append(": ");
			message.append(diagnostic.data, diagnostic.size);
		}
		return status(code, std::move(message));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("process facility callback diagnostic allocation failed"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "process facility callback diagnostic exceeded the host size domain"));
	}
}

/**
 * @brief Invoke one provider lifecycle callback with caller-owned diagnostics.
 * @param callback Borrowed callable receiving the bounded diagnostic record.
 * @param operation Trusted bind, launch, or join label.
 * @return Validated local result; a changed diagnostic buffer or malformed foreign result fails stop.
 * @tparam callback_type Callable returning one provider status from the supplied diagnostic.
 */
template <typename callback_type>
[[nodiscard]] status invoke_facility_callback(callback_type &&callback, std::string_view operation)
{
	std::array<char, PROVIDER_LIFECYCLE_DIAGNOSTIC_BYTES> storage{};
	kinetum_provider_diagnostic diagnostic{
		.data = storage.data(),
		.capacity = static_cast<uint32_t>(storage.size()),
		.size = 0,
	};
	const char *const expected_data = diagnostic.data;
	const uint32_t expected_capacity = diagnostic.capacity;
	const kinetum_provider_status callback_status = callback(diagnostic);
	if (!kinetum_provider_status_is_valid(callback_status) || diagnostic.data != expected_data ||
	    diagnostic.capacity != expected_capacity || !diagnostic_is_valid(diagnostic)) {
		fail_stop_invalid_lifecycle_callback(operation);
	}
	return facility_callback_status(callback_status, operation, diagnostic);
}

/**
 * @brief Return the exact runtime-service role required by one facility assignment.
 * @param kind Compiled facility CPU owner kind.
 * @param role Runtime-service role written only for a coordinator or executor assignment.
 * @return true for a runtime-service assignment; false for a packet worker or unknown kind.
 */
[[nodiscard]] bool assignment_service_role(compiled_facility_cpu_owner_kind kind,
					   compiled_runtime_service_role &role) noexcept
{
	switch (kind) {
	case compiled_facility_cpu_owner_kind::TRANSITION_COORDINATOR:
		role = compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR;
		return true;
	case compiled_facility_cpu_owner_kind::LIFECYCLE_EXECUTOR:
		role = compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR;
		return true;
	case compiled_facility_cpu_owner_kind::PACKET_WORKER:
		return false;
	}
	return false;
}

}  // namespace

materialized_runtime_service_backend::materialized_runtime_service_backend(
	std::vector<const kinetum_provider_process_facility_operations *> service_facilities,
	std::unique_ptr<native_runtime_service_backend> native_backend) noexcept
	: service_facilities_(std::move(service_facilities))
	, native_backend_(std::move(native_backend))
{
}

kinetum::common::status_or<std::unique_ptr<materialized_runtime_service_backend>>
materialized_runtime_service_backend::create(const kinetum::provider::compiled_provider_topology &topology,
					     const kinetum::provider::materialized_provider_runtime &materialized)
{
	const auto &services = topology.transition_topology.runtime_services;
	std::vector<const kinetum_provider_process_facility_operations *> service_facilities;
	try {
		service_facilities.assign(services.size(), nullptr);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate runtime-service facility ownership table");
	}

	for (std::size_t facility_index = 0; facility_index < topology.process_facilities.size(); ++facility_index) {
		const auto &facility = topology.process_facilities[facility_index];
		if (facility.facility_index != facility_index) {
			return status::internal_error("compiled process-facility indices are not dense");
		}
		const auto *operations = materialized.process_facility(facility.facility_index);
		if (operations == nullptr) {
			return status::failed_precondition(
				"materialized runtime lacks exact process-facility lifecycle operations");
		}

		for (const auto &assignment : facility.cpu_assignments) {
			compiled_runtime_service_role required_role{};
			if (!assignment_service_role(assignment.kind, required_role)) {
				continue;
			}
			if (assignment.owner_index >= services.size()) {
				return status::internal_error(
					"compiled facility references an out-of-range runtime service");
			}
			const auto &service = services[assignment.owner_index];
			if (service.service_index != assignment.owner_index || service.role != required_role ||
			    service.cpu_core_id != assignment.cpu_core_id ||
			    service.numa_node != assignment.numa_node) {
				return status::internal_error(
					"compiled facility runtime-service assignment is internally inconsistent");
			}
			auto *&owner = service_facilities[assignment.owner_index];
			if (owner != nullptr) {
				return status::failed_precondition(
					"runtime service is claimed by more than one process facility");
			}
			owner = operations;
		}
	}

	try {
		auto native_backend = std::make_unique<native_runtime_service_backend>();
		return std::unique_ptr<materialized_runtime_service_backend>(new materialized_runtime_service_backend(
			std::move(service_facilities), std::move(native_backend)));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate materialized runtime-service backend");
	}
}

const kinetum_provider_process_facility_operations *
materialized_runtime_service_backend::service_facility_(uint32_t service_index) const noexcept
{
	return service_index < service_facilities_.size() ? service_facilities_[service_index] : nullptr;
}

status materialized_runtime_service_backend::bind_coordinator(const compiled_runtime_service &coordinator) noexcept
{
	if (coordinator.service_index >= service_facilities_.size() ||
	    coordinator.role != compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "materialized coordinator binding requires an exact compiled coordinator"));
	}
	const auto *facility = service_facility_(coordinator.service_index);
	if (facility == nullptr) {
		return native_backend_->bind_coordinator(coordinator);
	}
	return invoke_facility_callback(
		[facility, &coordinator](kinetum_provider_diagnostic &diagnostic) {
			return facility->bind_runtime_service_coordinator(facility->state, coordinator.service_index,
									  coordinator.cpu_core_id, &diagnostic);
		},
		"bind the lifecycle coordinator");
}

status materialized_runtime_service_backend::launch_executor(const compiled_runtime_service &service,
							     runtime_service_entry_fn entry, void *argument) noexcept
{
	if (service.service_index >= service_facilities_.size() ||
	    service.role != compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR || entry == nullptr ||
	    argument == nullptr) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "materialized lifecycle launch requires one exact executor and entry context"));
	}
	const auto *facility = service_facility_(service.service_index);
	if (facility == nullptr) {
		return native_backend_->launch_executor(service, entry, argument);
	}
	return invoke_facility_callback(
		[facility, &service, entry, argument](kinetum_provider_diagnostic &diagnostic) {
			return facility->launch_runtime_service(facility->state, service.service_index,
								service.cpu_core_id, entry, argument, &diagnostic);
		},
		"launch a lifecycle executor");
}

status materialized_runtime_service_backend::join_executor(const compiled_runtime_service &service) noexcept
{
	if (service.service_index >= service_facilities_.size() ||
	    service.role != compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "materialized lifecycle join requires one exact compiled executor"));
	}
	const auto *facility = service_facility_(service.service_index);
	if (facility == nullptr) {
		return native_backend_->join_executor(service);
	}
	return invoke_facility_callback(
		[facility, &service](kinetum_provider_diagnostic &diagnostic) {
			return facility->join_runtime_service(facility->state, service.service_index,
							      service.cpu_core_id, &diagnostic);
		},
		"join a lifecycle executor");
}

}  // namespace kinetum::dp::lifecycle
