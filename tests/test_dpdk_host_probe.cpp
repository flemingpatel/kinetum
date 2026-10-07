// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dpdk_host_probe.cpp
 * @brief Non-materializing DPDK component host-proof tests.
 * @author Fleming Patel
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include <gtest/gtest.h>

#include "src/dp/backends/dpdk/dpdk_host_probe.hpp"
#include "tests/dpdk_component_test_harness.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

using test_support::facility_fixture;

/** @brief Complete bounded host state exposed through the probe API. */
struct host_probe_state {
	std::string runtime_version{"DPDK 24.11.7"};  ///< Linked native runtime identity.
	std::string meminfo;			      ///< Exact bounded Linux meminfo bytes.
	uint32_t runtime_queries{0};		      ///< Number of runtime identity reads.
	uint32_t meminfo_reads{0};		      ///< Number of bounded host-file reads.
};

/**
 * @brief Return the injected DPDK runtime identity.
 * @param opaque Borrowed host-probe state whose query count is incremented.
 * @return Borrowed fixture-owned runtime version text.
 */
const char *probe_runtime_version(void *opaque) noexcept
{
	auto &state = *static_cast<host_probe_state *>(opaque);
	++state.runtime_queries;
	return state.runtime_version.c_str();
}

/**
 * @brief Copy exact injected meminfo bytes into caller-owned bounded storage.
 * @param opaque Borrowed host-probe state whose read count is incremented.
 * @param buffer Caller-owned output storage.
 * @param capacity Available output extent.
 * @param size Copied byte count written on success.
 * @return Zero after complete bounded copying, or -1 for malformed/insufficient output.
 */
int read_meminfo(void *opaque, char *buffer, uint32_t capacity, uint32_t *size) noexcept
{
	auto &state = *static_cast<host_probe_state *>(opaque);
	++state.meminfo_reads;
	if (buffer == nullptr || size == nullptr || state.meminfo.size() > capacity) {
		return -1;
	}
	std::memcpy(buffer, state.meminfo.data(), state.meminfo.size());
	*size = static_cast<uint32_t>(state.meminfo.size());
	return 0;
}

/**
 * @brief Construct the exact host-proof view from the shared facility fixture.
 * @param fixture Facility fixture retaining all borrowed request backing.
 * @return Host-proof request borrowing the fixture's exact role, contract, and facts.
 */
kinetum_provider_host_proof_request proof_request(facility_fixture &fixture)
{
	return kinetum_provider_host_proof_request{
		.type_url = fixture.request().type_url,
		.canonical_configuration = fixture.request().canonical_configuration,
		.compiled_facts = fixture.request().compiled_facts,
		.role = fixture.request().role,
		.padding = {0},
	};
}

/**
 * @brief Return a complete injected host-probe API.
 * @param state Fixture state retained through all callback uses.
 * @return Probe API borrowing the supplied state.
 */
dpdk_host_probe_api probe_api(host_probe_state &state)
{
	return dpdk_host_probe_api{
		.state = &state,
		.runtime_version = probe_runtime_version,
		.read_meminfo = read_meminfo,
	};
}

/**
 * @brief Convert one bounded provider diagnostic to owned test text.
 * @param bytes Fixture-owned diagnostic buffer.
 * @param diagnostic Result whose size has been validated within the buffer extent.
 * @return Owned copy of the returned diagnostic prefix.
 */
std::string diagnostic_text(const std::array<char, 256> &bytes, const kinetum_provider_diagnostic &diagnostic)
{
	return std::string(bytes.data(), diagnostic.size);
}

}  // namespace

/** @brief Prove equality at the exact plan-visible hugepage byte floor. */
TEST(dpdk_host_probe, exact_unreserved_hugepage_floor_succeeds_without_materialization)
{
	facility_fixture fixture;
	host_probe_state state{
		.meminfo = "HugePages_Free: 1\nHugePages_Rsvd: 0\nHugepagesize: 272 kB\n",
	};
	const auto request = proof_request(fixture);
	const auto api = probe_api(state);

	const auto status = prove_dpdk_host(request, api, nullptr);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(state.runtime_queries, 1u);
	EXPECT_EQ(state.meminfo_reads, 1u);
}

/** @brief Prove reserved pages are excluded from available capacity. */
TEST(dpdk_host_probe, reserved_hugepages_cannot_satisfy_the_payload_floor)
{
	facility_fixture fixture;
	host_probe_state state{
		.meminfo = "HugePages_Free: 2\nHugePages_Rsvd: 2\nHugepagesize: 2048 kB\n",
	};
	const auto request = proof_request(fixture);
	const auto api = probe_api(state);
	std::array<char, 256> bytes{};
	kinetum_provider_diagnostic diagnostic{bytes.data(), static_cast<uint32_t>(bytes.size()), 0};

	const auto status = prove_dpdk_host(request, api, &diagnostic);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_NE(diagnostic_text(bytes, diagnostic).find("below the compiled payload floor"), std::string::npos);
}

/** @brief Reject duplicate meminfo authorities rather than taking one value. */
TEST(dpdk_host_probe, duplicate_hugepage_inventory_fields_fail_closed)
{
	facility_fixture fixture;
	host_probe_state state{
		.meminfo = "HugePages_Free: 4\nHugePages_Free: 5\nHugePages_Rsvd: 0\n"
			   "Hugepagesize: 2048 kB\n",
	};
	const auto request = proof_request(fixture);
	const auto api = probe_api(state);

	const auto status = prove_dpdk_host(request, api, nullptr);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
}

/** @brief Reject absent linked-runtime identity before inspecting host memory. */
TEST(dpdk_host_probe, missing_runtime_identity_precedes_meminfo_access)
{
	facility_fixture fixture;
	host_probe_state state{
		.runtime_version = {},
		.meminfo = "HugePages_Free: 4\nHugePages_Rsvd: 0\nHugepagesize: 2048 kB\n",
	};
	const auto request = proof_request(fixture);
	const auto api = probe_api(state);

	const auto status = prove_dpdk_host(request, api, nullptr);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(state.runtime_queries, 1u);
	EXPECT_EQ(state.meminfo_reads, 0u);
}

/** @brief Reject an incomplete compiled payload floor before host-file access. */
TEST(dpdk_host_probe, incomplete_memory_facts_precede_meminfo_access)
{
	facility_fixture fixture;
	fixture.memory_domain().buffer_count = 0;
	host_probe_state state{
		.meminfo = "HugePages_Free: 4\nHugePages_Rsvd: 0\nHugepagesize: 2048 kB\n",
	};
	const auto request = proof_request(fixture);
	const auto api = probe_api(state);

	const auto status = prove_dpdk_host(request, api, nullptr);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_EQ(state.runtime_queries, 1u);
	EXPECT_EQ(state.meminfo_reads, 0u);
}

}  // namespace kinetum::provider::dpdk_component
