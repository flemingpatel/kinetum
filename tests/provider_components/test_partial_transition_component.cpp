// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_partial_transition_component.cpp
 * @brief Admitted host-provider decorator that exercises zero-copy refusal and short prefixes.
 * @author Fleming Patel
 *
 * The test image links the unchanged host implementation under a private query
 * name. Only its zero-copy factory is decorated; storage, execution, copies,
 * request validation and destruction use their real implementations. Counters
 * are owner-local and reported only during cold destruction after worker join.
 */

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <exception>
#include <new>

#include "src/provider/provider_component_abi.h"

/** @return The genuine host descriptor linked privately into this test image. */
extern "C" const kinetum_provider_component_descriptor *kinetum_test_host_component_query(void) noexcept;

namespace
{

/** Exact host contract whose accepted-prefix behavior is controlled by this fixture. */
constexpr char ZERO_COPY_TYPE[] = "type.googleapis.com/kinetum.transition.core.v1.ZeroCopyShareConfig";

/** @brief One decorated transition and its exact underlying factory owner. */
struct partial_transition {
	kinetum_provider_factory_result inner{};  ///< Genuine transition instance and destruction authority.
	kinetum_provider_storage_transition_operations operations{};  ///< Published decorated operation record.
	uint64_t refused{0u};	       ///< Complete refusals before the first successful call.
	uint64_t partial{0u};	       ///< Calls consuming a nonempty strict prefix.
	uint64_t accepted{0u};	       ///< Total exact transferred packet ownership.
	uint16_t maximum_request{0u};  ///< Largest requested prefix, proving batch coverage.
};

/** @param row Complete contract row. @return Whether it names exactly the zero-copy contract. */
[[nodiscard]] bool is_zero_copy(const kinetum_provider_contract_implementation &row) noexcept
{
	return row.type_url.size == sizeof(ZERO_COPY_TYPE) - 1u && row.type_url.data != nullptr &&
	       std::memcmp(row.type_url.data, ZERO_COPY_TYPE, sizeof(ZERO_COPY_TYPE) - 1u) == 0;
}

/**
 * @brief Refuse once, then delegate at most one record while leaving the suffix untouched.
 * @param state Exact decorated transition owned by this worker.
 * @param sources Caller-owned input prefix.
 * @param destinations Caller-owned zeroed output prefix.
 * @param count Requested positive burst.
 * @return Zero on the first call, then the genuine transfer's accepted prefix bounded by one.
 */
uint16_t transfer_partial(void *state, kinetum_packet_record *const *sources, kinetum_packet_record **destinations,
			  uint16_t count) noexcept
{
	if (state == nullptr || (count != 0u && (sources == nullptr || destinations == nullptr))) {
		std::terminate();
	}
	if (count == 0u) {
		return 0u;
	}
	if (!std::all_of(destinations, destinations + count,
			 [](const auto *record) noexcept { return record == nullptr; })) {
		std::terminate();
	}
	auto &owned = *static_cast<partial_transition *>(state);
	owned.maximum_request = std::max(owned.maximum_request, count);
	if (owned.refused == 0u) {
		++owned.refused;
		return 0u;
	}
	const auto *inner = static_cast<const kinetum_provider_storage_transition_operations *>(owned.inner.operations);
	const uint16_t accepted =
		inner->transfer_burst(inner->state, sources, destinations, std::min<uint16_t>(count, 1u));
	if (accepted > 1u || accepted > count) {
		std::terminate();
	}
	owned.accepted += accepted;
	owned.partial += accepted != 0u && accepted < count ? 1u : 0u;
	return accepted;
}

/**
 * @brief Report quiescent prefix evidence, then destroy the genuine owner and decorator.
 * @param instance Exact decorated instance after every worker has joined.
 */
void destroy_partial(void *instance) noexcept
{
	auto *owned = static_cast<partial_transition *>(instance);
	std::fprintf(stderr, "kinetum-test-partial %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %u\n",
		     owned->operations.transition_index, owned->refused, owned->partial, owned->accepted,
		     static_cast<unsigned>(owned->maximum_request));
	owned->inner.destroy(owned->inner.instance);
	delete owned;
}

/**
 * @brief Wrap the real zero-copy factory without changing its admission or dependency rules.
 * @param request Exact materializer-owned factory request.
 * @param[out] result Complete decorated owner on success, empty on failure.
 * @param diagnostic Borrowed cold diagnostic storage passed to the genuine factory.
 * @return The genuine refusal, allocation failure, or complete success.
 */
kinetum_provider_status create_partial(const kinetum_provider_factory_request *request,
				       kinetum_provider_factory_result *result,
				       kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (result != nullptr) {
		*result = {};
	}
	if (diagnostic != nullptr) {
		diagnostic->size = 0u;
	}
	if (request == nullptr || result == nullptr) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	const auto *descriptor = kinetum_test_host_component_query();
	kinetum_provider_factory_fn factory = nullptr;
	for (uint32_t index = 0u; index < descriptor->contract_count; ++index) {
		if (is_zero_copy(descriptor->contracts[index])) {
			factory = descriptor->contracts[index].factories.storage_transition;
		}
	}
	if (factory == nullptr) {
		return KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
	}
	auto *owned = new (std::nothrow) partial_transition{};
	if (owned == nullptr) {
		return KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED;
	}
	const auto status = factory(request, &owned->inner, diagnostic);
	if (!kinetum_provider_factory_result_matches_status(request->role, status, &owned->inner)) {
		std::terminate();
	}
	if (status != KINETUM_PROVIDER_STATUS_OK) {
		delete owned;
		return status;
	}
	owned->operations =
		*static_cast<const kinetum_provider_storage_transition_operations *>(owned->inner.operations);
	owned->operations.state = owned;
	owned->operations.transfer_burst = transfer_partial;
	*result = {owned, &owned->operations, destroy_partial};
	return KINETUM_PROVIDER_STATUS_OK;
}

/** @brief Immutable projection preserving the host component's complete identity and contract membership. */
struct component_projection {
	/** @brief Copy the exact four host rows and replace only the zero-copy factory. */
	component_projection() noexcept
	{
		const auto *original = kinetum_test_host_component_query();
		if (original == nullptr || original->contract_count != contracts.size()) {
			std::terminate();
		}
		descriptor = *original;
		std::copy_n(original->contracts, contracts.size(), contracts.begin());
		std::size_t replaced = 0u;
		for (auto &row : contracts) {
			if (is_zero_copy(row)) {
				row.factories.storage_transition = create_partial;
				++replaced;
			}
		}
		if (replaced != 1u) {
			std::terminate();
		}
		descriptor.contracts = contracts.data();
	}
	std::array<kinetum_provider_contract_implementation, 4> contracts{};  ///< Complete unchanged row membership.
	kinetum_provider_component_descriptor descriptor{};  ///< Exact product, ABI and component identity.
};

}  // namespace

/** @brief Export the exact host descriptor with the controlled accepted-prefix factory. @return Stable descriptor. */
extern "C" const kinetum_provider_component_descriptor *kinetum_provider_component_query(void) noexcept
{
	static const component_projection PROJECTION;
	return &PROJECTION.descriptor;
}
