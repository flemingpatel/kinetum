// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dpdk_pci_probe.hpp
 * @brief Read-only i40e physical-function ownership admission before EAL.
 * @author Fleming Patel
 *
 * Component host proof and facility construction share one admission function.
 * Native observations distinguish absence from failed reads; they never bind a
 * device or reserve it against later administrative changes. All work is cold.
 */

#include <cstdint>
#include <span>

#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::dpdk_component
{

/** @brief Complete outcome of inspecting one PCI function. */
enum class dpdk_pci_probe_result : uint8_t {
	ABSENT,	      ///< No function exists at the requested address.
	PRESENT,      ///< Every observation was read completely.
	UNAVAILABLE,  ///< A function or one of its observations could not be read.
};

/** @brief Kernel-driver ownership observed through the function's driver link. */
enum class dpdk_pci_binding : uint8_t {
	UNBOUND,  ///< The driver link is absent.
	VFIO,	  ///< The driver link names vfio-pci.
	FOREIGN,  ///< Another kernel driver owns the function.
};

/** @brief One complete immutable sysfs observation; absence has explicit presence bits. */
struct dpdk_pci_function_observation {
	uint16_t vendor{0};				      ///< PCI vendor identifier.
	uint16_t device{0};				      ///< PCI device identifier.
	uint16_t sriov_totalvfs{0};			      ///< Value only when totalvfs_present is true.
	uint16_t sriov_numvfs{0};			      ///< Value only when numvfs_present is true.
	dpdk_pci_binding binding{dpdk_pci_binding::UNBOUND};  ///< Current driver ownership.
	bool totalvfs_present{false};			      ///< Whether sriov_totalvfs exists.
	bool numvfs_present{false};			      ///< Whether sriov_numvfs exists.
	bool physfn_present{false};			      ///< This function is a VF.
	bool virtfn_present{false};			      ///< This function exposes at least one VF link.
};

/** @brief Read-only native mechanism shared by both ownership-admission callers. */
struct dpdk_pci_probe_api {
	void *state;  ///< Borrowed mechanism state retained through each inspection.
	/** Inspect a canonical address without changing device or driver state. */
	dpdk_pci_probe_result (*read_function)(void *state, const char *address,
					       dpdk_pci_function_observation *observation) noexcept;
};

/** @return Native read-only sysfs mechanism; it retains no descriptors. */
[[nodiscard]] dpdk_pci_probe_api default_dpdk_pci_probe_api() noexcept;

/**
 * @brief Inspect one function under a caller-held PCI devices directory.
 * @param devices_directory Borrowed directory descriptor, never closed here.
 * @param address Canonical null-terminated PCI function address.
 * @param observation Written only after complete reads and descriptor retirement.
 * @return PRESENT, exact ABSENT, or UNAVAILABLE without an inferred observation.
 */
[[nodiscard]] dpdk_pci_probe_result read_dpdk_pci_function_at(int devices_directory, const char *address,
							      dpdk_pci_function_observation &observation) noexcept;

/**
 * @brief Prove exclusive ownership of every declared i40e adapter's functions.
 * @param attachments Complete declared attachment set; TAP contributes no PCI requirement.
 * @param api Read-only observation mechanism, with no independent admission policy.
 * @param diagnostic Optional bounded failure output identifying the PCI function.
 * @return OK for complete ownership, or explicit malformed/unavailable/foreign evidence.
 *
 * The generated PMD identity set is the sole vendor/device authority. Work is
 * O(n log n) in declared attachments plus eight bounded inspections per adapter.
 * This cold proof neither reserves hardware nor admits later binding changes.
 */
[[nodiscard]] kinetum_provider_status
prove_dpdk_pci_ownership(std::span<const kinetum_provider_driver_attachment_fact> attachments,
			 const dpdk_pci_probe_api &api, kinetum_provider_diagnostic *diagnostic) noexcept;

}  // namespace kinetum::provider::dpdk_component
