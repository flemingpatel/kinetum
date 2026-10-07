// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_provider_component_cpp.cpp
 * @brief C++ implementation canary behind the exact C provider ABI.
 * @author Fleming Patel
 *
 * The component deliberately uses C++ allocation, noexcept callbacks, and an
 * ODR-used inline variable that GCC would otherwise give GNU-unique binding.
 * The provider component policy must still produce one locally unloadable ELF
 * image whose only public symbol is the C query authority.
 */

#include "src/provider/provider_component_abi.h"

#include <cstdint>
#include <cstring>
#include <new>
#include <type_traits>

#include "gen/kinetum/provider/provider_build_identity.h"
#include "tests/provider_components/test_provider_private.h"

namespace kinetum::test::provider_component_cpp_canary
{

/** Tag giving the GNU-unique canary one exact external specialization identity. */
struct unique_canary_tag {};

/**
 * @brief Externally linked inline storage that must not retain GNU-unique binding.
 *
 * The export map later localizes this implementation symbol. External linkage
 * is deliberate: without `-fno-gnu-unique`, GCC emits the ODR-used
 * specialization with process-unique binding and exact ELF admission rejects
 * the component.
 */
template <typename tag_type>
struct unique_canary {
	/** ODR-used inline canary whose binding must remain local after the component export map. */
	__attribute__((visibility("default"))) static inline const std::uint32_t operations = UINT32_C(0x4b435050);
};

}  // namespace kinetum::test::provider_component_cpp_canary

namespace
{

/** Exact contract implemented by the C++ conformance component. */
constexpr char TEST_CONTRACT_TYPE_URL[] = "type.googleapis.com/kinetum.transition.core.v1.ZeroCopyShareConfig";

/** Exact externally linked inline-storage specialization used by the fixture. */
using cpp_unique_storage = kinetum::test::provider_component_cpp_canary::unique_canary<
	kinetum::test::provider_component_cpp_canary::unique_canary_tag>;

/** Minimal C++-owned provider instance. */
struct cpp_provider_instance {
	std::uint32_t private_marker;				    ///< Value obtained through the private dependency.
	std::uint32_t operation_marker;				    ///< Exact C++ canary marker.
	kinetum_provider_storage_transition_operations operations;  ///< Exact transition operation record.
	kinetum_provider_cold_log logging;			    ///< Host capability valid through destroy.
};

/**
 * @brief Return whether a request names the exact C++ fixture contract.
 *
 * @param request Candidate foreign ABI request.
 * @return true only for the exact type and role.
 */
bool request_is_exact(const kinetum_provider_factory_request *request) noexcept
{
	return kinetum_provider_factory_request_is_valid(request) != 0 &&
	       request->role == KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION && request->runtime_generation != 0 &&
	       request->runtime_generation <= UINT32_MAX && request->compiled_facts.process_facility == nullptr &&
	       request->compiled_facts.io_driver == nullptr && request->compiled_facts.packet_storage == nullptr &&
	       request->compiled_facts.execution == nullptr && request->compiled_facts.storage_transition != nullptr &&
	       request->type_url.data != nullptr &&
	       request->type_url.size == static_cast<std::uint32_t>(sizeof(TEST_CONTRACT_TYPE_URL) - 1u) &&
	       std::memcmp(request->type_url.data, TEST_CONTRACT_TYPE_URL, sizeof(TEST_CONTRACT_TYPE_URL) - 1u) == 0;
}

/**
 * @brief Transfer one exact zero-copy prefix for the C++ ABI canary.
 *
 * @param state Non-null C++ conformance instance.
 * @param sources Exact source-owner array.
 * @param destinations Caller-owned destination array.
 * @param count Exact bounded source count.
 * @return Exact transferred prefix, or zero for malformed input.
 */
std::uint16_t cpp_provider_transfer_burst(void *state, kinetum_packet_record *const *sources,
					  kinetum_packet_record **destinations, std::uint16_t count) noexcept
{
	if (state == nullptr || (count != 0 && (sources == nullptr || destinations == nullptr))) {
		return 0;
	}
	for (std::uint16_t i = 0; i < count; ++i) {
		if (sources[i] == nullptr) {
			return i;
		}
		destinations[i] = sources[i];
	}
	return count;
}

/**
 * @brief Retire one exact C++-owned conformance instance.
 *
 * @param instance Instance returned by cpp_provider_factory().
 */
void cpp_provider_destroy(void *instance) noexcept
{
	auto *owned = static_cast<cpp_provider_instance *>(instance);
	constexpr char EVENT[] = "test.provider.destroyed";
	constexpr char MESSAGE[] = "provider destruction";
	owned->logging.write(owned->logging.context, KINETUM_PROVIDER_LOG_INFO, {EVENT, sizeof(EVENT) - 1, 0}, {},
			     {MESSAGE, sizeof(MESSAGE) - 1, 0});
	delete owned;
}

/**
 * @brief Materialize one C++ instance through the exact C callback contract.
 *
 * @param request Exact role request.
 * @param result Non-null caller-owned result.
 * @param diagnostic Optional bounded diagnostic.
 * @return Exact provider status.
 */
kinetum_provider_status cpp_provider_factory(const kinetum_provider_factory_request *request,
					     kinetum_provider_factory_result *result,
					     kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!request_is_exact(request) || result == nullptr) {
		if (diagnostic != nullptr) {
			diagnostic->size = 0;
		}
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}

	if (diagnostic != nullptr) {
		diagnostic->size = 0;
	}
	auto *instance = new (std::nothrow) cpp_provider_instance{};
	if (instance == nullptr) {
		return KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
	}
	instance->private_marker = kinetum_test_provider_private_marker();
	instance->operation_marker = cpp_unique_storage::operations;
	instance->logging = request->logging;
	instance->operations.state = instance;
	instance->operations.transfer_burst = cpp_provider_transfer_burst;
	instance->operations.generation = static_cast<std::uint32_t>(request->runtime_generation);
	instance->operations.transition_index = request->compiled_facts.storage_transition->transition_index;
	instance->operations.from_storage_domain_index =
		request->compiled_facts.storage_transition->from_storage_domain_index;
	instance->operations.to_storage_domain_index =
		request->compiled_facts.storage_transition->to_storage_domain_index;
	instance->operations.mode = request->compiled_facts.storage_transition->mode;
	std::memset(instance->operations.padding, 0, sizeof(instance->operations.padding));
	result->instance = instance;
	result->operations = &instance->operations;
	result->destroy = cpp_provider_destroy;
	constexpr char EVENT[] = "test.provider.created";
	char message[] = "provider construction";
	instance->logging.write(instance->logging.context, KINETUM_PROVIDER_LOG_INFO, {EVENT, sizeof(EVENT) - 1, 0}, {},
				{message, sizeof(message) - 1, 0});
	std::memset(message, 'x', sizeof(message) - 1);
	return KINETUM_PROVIDER_STATUS_OK;
}

static_assert(std::is_same_v<decltype(&cpp_provider_factory), kinetum_provider_factory_fn>,
	      "C++ factory must exactly match the C ABI noexcept callback");
static_assert(std::is_same_v<decltype(&cpp_provider_destroy), decltype(kinetum_provider_factory_result::destroy)>,
	      "C++ destroy callback must exactly match the C ABI noexcept callback");

/** Exact one-row implementation table exposed through the C ABI. */
const kinetum_provider_contract_implementation TEST_PROVIDER_CONTRACTS[] = {
	{
		.type_url =
			{
				.data = TEST_CONTRACT_TYPE_URL,
				.size = static_cast<std::uint32_t>(sizeof(TEST_CONTRACT_TYPE_URL) - 1u),
				.padding = 0,
			},
		.factories =
			{
				.process_facility = nullptr,
				.io_driver = nullptr,
				.packet_storage = nullptr,
				.execution = nullptr,
				.storage_transition = cpp_provider_factory,
			},
		.host_proof = nullptr,
		.role = KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION,
		.padding = {0},
	},
};

/** Process-lifetime immutable C++ component descriptor. */
const kinetum_provider_component_descriptor TEST_PROVIDER_DESCRIPTOR = {
	.product_version_major = KINETUM_PROVIDER_PRODUCT_VERSION_MAJOR,
	.product_version_minor = KINETUM_PROVIDER_PRODUCT_VERSION_MINOR,
	.product_version_patch = KINETUM_PROVIDER_PRODUCT_VERSION_PATCH,
	.version_padding = {0},
	.abi_identity = KINETUM_PROVIDER_ABI_IDENTITY_INITIALIZER,
	.component_id =
		{
			.data = "kinetum.test.provider.cpp",
			.size = static_cast<std::uint32_t>(sizeof("kinetum.test.provider.cpp") - 1u),
			.padding = 0,
		},
	.contracts = TEST_PROVIDER_CONTRACTS,
	.contract_count =
		static_cast<std::uint32_t>(sizeof(TEST_PROVIDER_CONTRACTS) / sizeof(TEST_PROVIDER_CONTRACTS[0])),
	.tail_padding = {0},
};

}  // namespace

extern "C" const kinetum_provider_component_descriptor *kinetum_provider_component_query(void) noexcept
{
	return &TEST_PROVIDER_DESCRIPTOR;
}

static_assert(std::is_same_v<decltype(&kinetum_provider_component_query), kinetum_provider_component_query_fn>,
	      "C++ query must exactly match the C ABI linkage and noexcept contract");
