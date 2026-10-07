// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_verification.cpp
 * @brief Independent runtime membership and static provenance verification.
 * @author Fleming Patel
 */

#include "tooling/release/verification/runtime_verification.hpp"

#include <array>

#include "tooling/release/verification/payload_manifest.hpp"
#include "src/provider/provider_release.hpp"
#include "src/provider/provider_release_trust.hpp"

namespace kinetum::release
{
namespace
{

/**
 * Independent verifier assertion retained from kinetum-info. The producer
 * derives its files from CMake staging; it never uses this list to select
 * what ships. Disagreement must remain a qualification failure.
 */
constexpr std::array<runtime_artifact, 31> EXPECTED_RUNTIME_ARTIFACTS = {
	runtime_artifact{"LICENSE", "Kinetum license"},
	runtime_artifact{"NOTICE", "Kinetum notice"},
	runtime_artifact{"README.md", "Runtime README"},
	runtime_artifact{"THIRD_PARTY_NOTICES.md", "Runtime third-party notices"},
	runtime_artifact{"VERSION", "Version file"},
	runtime_artifact{"bin/kinetum-info", "Installation info tool"},
	runtime_artifact{"bin/kinetum_axiom", "Axiom compiler"},
	runtime_artifact{"bin/kinetum_bundle_verify", "Bundle verifier"},
	runtime_artifact{"bin/kinetum_cp", "Control plane binary"},
	runtime_artifact{"bin/kinetum_dp", "Data plane binary"},
	runtime_artifact{"bin/kinetum_gluon", "Gluon planner"},
	runtime_artifact{"bin/kinetum_pack", "Bundle packer"},
	runtime_artifact{"bin/kinetum_photon", "Photon supervisor"},
	runtime_artifact{"bin/kinetumctl", "CLI tool"},
	runtime_artifact{"lib/kinetum/providers/libkinetum_provider_dpdk_component.so", "DPDK provider component"},
	runtime_artifact{"lib/kinetum/providers/libkinetum_provider_host_component.so", "Host provider component"},
	runtime_artifact{"lib/modules/libkinetum_acl.so", "ACL module"},
	runtime_artifact{"lib/modules/libkinetum_nat44.so", "NAT44 module"},
	runtime_artifact{"lib/modules/libkinetum_qos.so", "QoS module"},
	runtime_artifact{"share/kinetum/providers/installed_provider_inventory.pb", "Installed provider inventory"},
	runtime_artifact{"share/kinetum/providers/installed_provider_inventory.pb.sig",
			 "Installed provider inventory signature"},
	runtime_artifact{"share/kinetum/release/native_provider_admission_receipt.pb",
			 "Native provider admission receipt"},
	runtime_artifact{"share/licenses/KinetumDPDK/DPDK_STATIC_CLOSURE_NOTICE.txt",
			 "DPDK static-closure attribution"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/README", "DPDK license index"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/bsd-2-clause.txt", "DPDK BSD-2-Clause text"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/bsd-3-clause.txt", "DPDK BSD-3-Clause text"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/exceptions.txt", "DPDK license exceptions"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/gpl-2.0.txt", "DPDK GPL-2.0 text"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/isc.txt", "DPDK ISC text"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/lgpl-2.1.txt", "DPDK LGPL-2.1 text"},
	runtime_artifact{"share/licenses/KinetumDPDK/dpdk/mit.txt", "DPDK MIT text"},
};

/** @return Exact manifest paths derived from the one verifier-owned role table. */
consteval auto expected_paths()
{
	std::array<std::string_view, EXPECTED_RUNTIME_ARTIFACTS.size()> paths{};
	for (std::size_t index = 0; index < paths.size(); ++index) {
		paths[index] = EXPECTED_RUNTIME_ARTIFACTS[index].relative_path;
	}
	return paths;
}

/** Exact independent path assertion consumed only by verification. */
constexpr auto EXPECTED_RUNTIME_PAYLOAD = expected_paths();

/** SDK and source-build dependencies are the only independently owned peers. */
constexpr std::array<std::string_view, 2> INSTALLED_RUNTIME_PEERS{"dependencies", "sdk"};

static_assert(
	[]() consteval {
		for (std::size_t index = 1; index < EXPECTED_RUNTIME_PAYLOAD.size(); ++index) {
			if (EXPECTED_RUNTIME_PAYLOAD[index - 1u] >= EXPECTED_RUNTIME_PAYLOAD[index]) {
				return false;
			}
		}
		return true;
	}(),
	"independent runtime membership must remain strictly sorted");

/**
 * @brief Apply one runtime assertion within its caller's exact ownership domain.
 * @param root Private payload or installed runtime root.
 * @param target Exact runtime tuple.
 * @param policy File/directory ownership authority.
 * @param peers Empty for packages; the fixed SDK/dependency peers only for installations.
 * @return Both static verification outcomes without executing target code.
 */
runtime_verification_result verify_runtime_domain(const std::filesystem::path &root,
						  provider::provider_target_tuple target,
						  const common::held_file_policy &policy,
						  std::span<const std::string_view> peers)
{
	const payload_manifest_contract contract{
		.manifest_relative_path = RUNTIME_PAYLOAD_MANIFEST,
		.expected_relative_paths = EXPECTED_RUNTIME_PAYLOAD,
		.excluded_directory_roots = peers,
	};
	auto payload_status = verify_payload_manifest(root, contract, policy);
	auto provider_result = provider::verify_installed_provider_release(
		root, target, provider::provider_release_trust_anchor(), policy);
	return {std::move(payload_status), provider_result.is_ok() ? common::status::ok() : provider_result.error()};
}

}  // namespace

std::span<const runtime_artifact> expected_runtime_artifacts() noexcept
{
	return EXPECTED_RUNTIME_ARTIFACTS;
}

runtime_verification_result verify_runtime_payload(const std::filesystem::path &root,
						   provider::provider_target_tuple target,
						   const common::held_file_policy &policy)
{
	return verify_runtime_domain(root, target, policy, {});
}

runtime_verification_result verify_installed_runtime(const std::filesystem::path &root,
						     provider::provider_target_tuple target,
						     const common::held_file_policy &policy)
{
	return verify_runtime_domain(root, target, policy, INSTALLED_RUNTIME_PEERS);
}

}  // namespace kinetum::release
