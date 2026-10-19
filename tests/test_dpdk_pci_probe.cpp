// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dpdk_pci_probe.cpp
 * @brief Exact sysfs observations and exclusive PCI ownership admission.
 * @author Fleming Patel
 */

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

#include <gtest/gtest.h>

#include "src/dp/backends/dpdk/dpdk_pci_probe.hpp"
#include "tests/dpdk_component_test_harness.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

using test_support::facility_fixture;

/** Exact function used by both filesystem and injected-observation fixtures. */
constexpr char TEST_PCI_ADDRESS[] = "0000:01:00.0";

/**
 * @brief Invoke the shared proof over one fixture's actual declared set.
 * @param fixture Owner of the borrowed attachments and observation API.
 * @return Production admission outcome without initializing a facility.
 */
kinetum_provider_status prove(facility_fixture &fixture)
{
	const auto &facts = fixture.facts();
	return prove_dpdk_pci_ownership({facts.attachments, facts.attachment_count}, fixture.api().pci, nullptr);
}

/** @brief Caller-owned temporary directory representing kernel PCI files and links. */
class PciSysfsTest : public ::testing::Test {
    protected:
	/** @brief Create complete ordinary-PF files before admitting any observation. */
	void SetUp() override
	{
		std::array<char, 40> pattern{};
		constexpr std::string_view PREFIX = "/tmp/kinetum-pci-probe-XXXXXX";
		std::copy(PREFIX.begin(), PREFIX.end(), pattern.begin());
		const char *created = mkdtemp(pattern.data());
		ASSERT_NE(created, nullptr);
		root_ = created;
		std::filesystem::create_directory(root_ / TEST_PCI_ADDRESS);
		directory_ = open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		ASSERT_GE(directory_, 0);
		ASSERT_TRUE(write_attribute("vendor", "0x8086\n"));
		ASSERT_TRUE(write_attribute("device", "0x1572\n"));
		std::filesystem::create_symlink("../../drivers/vfio-pci", root_ / TEST_PCI_ADDRESS / "driver");
	}

	/** @brief Close the borrowed-root owner and remove only its temporary files. */
	void TearDown() override
	{
		if (directory_ >= 0) {
			EXPECT_EQ(close(directory_), 0);
		}
		if (!root_.empty()) {
			std::error_code error;
			std::filesystem::remove_all(root_, error);
			EXPECT_FALSE(error) << error.message();
		}
	}

	/**
	 * @brief Write one exact kernel-attribute fixture and close it before observation.
	 * @param name Attribute basename inside the fixture function.
	 * @param text Complete expected attribute bytes.
	 * @return True only after successful writing and close.
	 */
	bool write_attribute(const char *name, std::string_view text)
	{
		std::ofstream output(root_ / TEST_PCI_ADDRESS / name, std::ios::binary);
		output << text;
		output.close();
		return output.good();
	}

	/**
	 * @brief Read this fixture through the actual native directory reader.
	 * @param observation Complete output on success.
	 * @return Exact native read outcome.
	 */
	dpdk_pci_probe_result observe(dpdk_pci_function_observation &observation) const noexcept
	{
		return read_dpdk_pci_function_at(directory_, TEST_PCI_ADDRESS, observation);
	}

	std::filesystem::path root_;  ///< Sole temporary filesystem owner.
	int directory_{-1};	      ///< Retained PCI directory descriptor.
};

}  // namespace

/** @brief Missing SR-IOV files remain explicit absence on a completely read PF. */
TEST_F(PciSysfsTest, absent_sriov_attributes_do_not_fabricate_a_read_failure)
{
	dpdk_pci_function_observation observed{};
	ASSERT_EQ(observe(observed), dpdk_pci_probe_result::PRESENT);
	EXPECT_EQ(observed.vendor, 0x8086u);
	EXPECT_EQ(observed.device, 0x1572u);
	EXPECT_EQ(observed.binding, dpdk_pci_binding::VFIO);
	EXPECT_FALSE(observed.totalvfs_present);
	EXPECT_FALSE(observed.numvfs_present);
	EXPECT_FALSE(observed.physfn_present);
	EXPECT_FALSE(observed.virtfn_present);
}

/** @brief A present unreadable or malformed attribute is never reported as absent. */
TEST_F(PciSysfsTest, failed_and_malformed_attribute_reads_are_unavailable)
{
	dpdk_pci_function_observation observed{};
	ASSERT_TRUE(write_attribute("sriov_totalvfs", "64\n"));
	ASSERT_EQ(observe(observed), dpdk_pci_probe_result::PRESENT);
	EXPECT_TRUE(observed.totalvfs_present);
	EXPECT_FALSE(observed.numvfs_present);
	std::filesystem::create_symlink("missing-target", root_ / TEST_PCI_ADDRESS / "sriov_numvfs");
	EXPECT_EQ(observe(observed), dpdk_pci_probe_result::UNAVAILABLE);
	std::filesystem::remove(root_ / TEST_PCI_ADDRESS / "sriov_numvfs");
	for (const auto text : {"", "-1\n", "65536\n", "0 trailing\n"}) {
		ASSERT_TRUE(write_attribute("sriov_numvfs", text));
		EXPECT_EQ(observe(observed), dpdk_pci_probe_result::UNAVAILABLE) << text;
	}
}

/** @brief Dangling VF links are present evidence, while a dangling device is unavailable. */
TEST_F(PciSysfsTest, dangling_links_do_not_turn_present_objects_into_absence)
{
	std::filesystem::create_symlink("missing-pf", root_ / TEST_PCI_ADDRESS / "physfn");
	std::filesystem::create_symlink("missing-vf", root_ / TEST_PCI_ADDRESS / "virtfn0");
	dpdk_pci_function_observation observed{};
	ASSERT_EQ(observe(observed), dpdk_pci_probe_result::PRESENT);
	EXPECT_TRUE(observed.physfn_present);
	EXPECT_TRUE(observed.virtfn_present);
	EXPECT_EQ(read_dpdk_pci_function_at(directory_, "0000:01:00.1", observed), dpdk_pci_probe_result::ABSENT);
	std::filesystem::create_symlink("missing-function", root_ / "0000:01:00.1");
	EXPECT_EQ(read_dpdk_pci_function_at(directory_, "0000:01:00.1", observed), dpdk_pci_probe_result::UNAVAILABLE);
}

/** @brief Unbound unused functions are permitted without assuming SR-IOV capability. */
TEST(dpdk_pci_probe, admits_declared_vfio_and_unbound_unused_functions)
{
	facility_fixture fixture;
	fixture.api_state().pci_functions.emplace("0000:01:00.1", dpdk_pci_function_observation{
									  .vendor = 0x8086,
									  .device = 0x1572,
									  .binding = dpdk_pci_binding::UNBOUND,
								  });
	EXPECT_EQ(prove(fixture), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(fixture.api_state().pci_reads, 8u);
	auto &used = fixture.api_state().pci_functions.at(TEST_PCI_ADDRESS);
	used.totalvfs_present = true;
	used.numvfs_present = true;
	used.sriov_totalvfs = 64;
	EXPECT_EQ(prove(fixture), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(fixture.api_state().eal_init_calls, 0u);
}

/** @brief Every present function must have complete exclusive ownership evidence. */
TEST(dpdk_pci_probe, rejects_foreign_missing_unavailable_and_unsupported_functions)
{
	for (uint32_t failure = 0; failure < 7; ++failure) {
		SCOPED_TRACE(failure);
		facility_fixture fixture;
		auto &state = fixture.api_state();
		if (failure == 0) {
			state.pci_functions.clear();
		} else if (failure == 1) {
			state.unavailable_pci_function = TEST_PCI_ADDRESS;
		} else if (failure == 2) {
			state.pci_functions.at(TEST_PCI_ADDRESS).device = 0xffff;
		} else if (failure == 5) {
			state.pci_functions.at(TEST_PCI_ADDRESS).device = 0x100e;
		} else if (failure == 6) {
			state.pci_functions.at(TEST_PCI_ADDRESS).vendor = 0x1234;
		} else {
			state.pci_functions.emplace("0000:01:00.3",
						    dpdk_pci_function_observation{
							    .vendor = 0x8086,
							    .device = 0x1572,
							    .binding = failure == 3 ? dpdk_pci_binding::FOREIGN :
										      dpdk_pci_binding::VFIO,
						    });
		}
		EXPECT_EQ(prove(fixture), KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
		EXPECT_EQ(state.eal_init_calls, 0u);
	}
}

/** @brief Active, virtual, and inconsistent SR-IOV states reject independently. */
TEST(dpdk_pci_probe, rejects_virtualized_and_inconsistent_sriov_evidence)
{
	for (uint32_t failure = 0; failure < 6; ++failure) {
		SCOPED_TRACE(failure);
		facility_fixture fixture;
		auto &observed = fixture.api_state().pci_functions.at(TEST_PCI_ADDRESS);
		observed.physfn_present = failure == 0;
		observed.virtfn_present = failure == 1;
		observed.totalvfs_present = failure == 2 || failure == 4;
		observed.numvfs_present = failure == 3 || failure == 4;
		observed.sriov_numvfs = failure == 4 ? 1 : 0;
		observed.sriov_totalvfs = failure >= 4 ? 64 : 0;
		EXPECT_EQ(prove(fixture), KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	}
}

/** @brief Several declared PFs share one complete bounded adapter inspection. */
TEST(dpdk_pci_probe, declared_functions_share_one_adapter_inspection)
{
	facility_fixture fixture;
	std::array attachments{fixture.attachment(), fixture.attachment()};
	attachments[1].attachment_identity = test_support::text_view("0000:01:00.1");
	attachments[1].driver_port_id = test_support::text_view("wan1");
	fixture.api_state().pci_functions.emplace("0000:01:00.1", dpdk_pci_function_observation{
									  .vendor = 0x8086,
									  .device = 0x1572,
									  .binding = dpdk_pci_binding::VFIO,
								  });
	EXPECT_EQ(prove_dpdk_pci_ownership(attachments, fixture.api().pci, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(fixture.api_state().pci_reads, 8u);
	attachments[1] = attachments[0];
	EXPECT_EQ(prove_dpdk_pci_ownership(attachments, fixture.api().pci, nullptr),
		  KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_EQ(fixture.api_state().pci_reads, 8u);
}

/** @brief A TAP-only facility performs no PCI observation. */
TEST(dpdk_pci_probe, tap_only_skips_pci_inspection)
{
	facility_fixture fixture;
	fixture.use_tap_attachment();
	EXPECT_EQ(prove(fixture), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(fixture.api_state().pci_reads, 0u);
}

}  // namespace kinetum::provider::dpdk_component
