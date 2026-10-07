// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_hardware_schema.cpp
 * @brief Exact single-node hardware-inventory descriptor tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>

#include <google/protobuf/descriptor.h>

#include "gen/kinetum/hw/v1/hardware.pb.h"
#include "src/common/protobuf_contract.hpp"

namespace kinetum::hw
{
namespace
{

/** Exact generated protobuf field-kind identity used by schema expectations. */
using field_type = google::protobuf::FieldDescriptor::Type;

/** @brief One expected protobuf field. */
struct expected_field {
	const char *name;	///< Exact field spelling.
	int number;		///< Compact field number.
	field_type type;	///< Exact scalar, message, or enum type.
	bool repeated;		///< Whether the field is repeated.
	const char *reference;	///< Full referenced type, or null for a scalar.
};

/**
 * @brief Require one generated message to have exactly the declared fields.
 * @tparam count Number of expected fields.
 * @param descriptor Generated message descriptor.
 * @param expected Exact expected field sequence.
 */
template <std::size_t count>
void expect_message(const google::protobuf::Descriptor *descriptor, const std::array<expected_field, count> &expected)
{
	ASSERT_NE(descriptor, nullptr);
	ASSERT_EQ(descriptor->field_count(), static_cast<int>(expected.size()));
	EXPECT_EQ(descriptor->reserved_range_count(), 0);
	EXPECT_EQ(descriptor->reserved_name_count(), 0);
	for (std::size_t index = 0; index < expected.size(); ++index) {
		const auto *field = descriptor->field(static_cast<int>(index));
		ASSERT_NE(field, nullptr);
		EXPECT_EQ(field->name(), expected[index].name);
		EXPECT_EQ(field->number(), expected[index].number);
		EXPECT_EQ(field->type(), expected[index].type);
		EXPECT_EQ(field->is_repeated(), expected[index].repeated);
		if (field->type() == google::protobuf::FieldDescriptor::TYPE_MESSAGE) {
			ASSERT_NE(field->message_type(), nullptr);
			EXPECT_EQ(field->message_type()->full_name(), expected[index].reference);
		} else if (field->type() == google::protobuf::FieldDescriptor::TYPE_ENUM) {
			ASSERT_NE(field->enum_type(), nullptr);
			EXPECT_EQ(field->enum_type()->full_name(), expected[index].reference);
		} else {
			EXPECT_EQ(expected[index].reference, nullptr);
		}
	}
}

/** @brief Every hardware message carries only current Gluon-consumed facts. */
TEST(hardware_schema, messages_are_compact_and_single_node_exact)
{
	constexpr std::array<expected_field, 1> INVENTORY{{
		{"node", 1, field_type::TYPE_MESSAGE, false, "kinetum.hw.v1.Node"},
	}};
	constexpr std::array<expected_field, 2> NODE{{
		{"cpu", 1, field_type::TYPE_MESSAGE, false, "kinetum.hw.v1.CpuInfo"},
		{"nics", 2, field_type::TYPE_MESSAGE, true, "kinetum.hw.v1.NicPort"},
	}};
	constexpr std::array<expected_field, 1> CPU{{
		{"core_topology", 1, field_type::TYPE_MESSAGE, true, "kinetum.hw.v1.CpuCore"},
	}};
	constexpr std::array<expected_field, 3> CORE{{
		{"core_id", 1, field_type::TYPE_INT32, false, nullptr},
		{"numa_node", 2, field_type::TYPE_INT32, false, nullptr},
		{"is_hyperthread", 3, field_type::TYPE_BOOL, false, nullptr},
	}};
	constexpr std::array<expected_field, 5> NIC{{
		{"pci_address", 1, field_type::TYPE_STRING, false, nullptr},
		{"max_mtu", 2, field_type::TYPE_UINT32, false, nullptr},
		{"mac_address", 3, field_type::TYPE_STRING, false, nullptr},
		{"numa_node", 4, field_type::TYPE_INT32, false, nullptr},
		{"driver", 5, field_type::TYPE_ENUM, false, "kinetum.hw.v1.NicDriver"},
	}};

	expect_message(kinetum::hw::v1::HardwareInventory::descriptor(), INVENTORY);
	expect_message(kinetum::hw::v1::Node::descriptor(), NODE);
	expect_message(kinetum::hw::v1::CpuInfo::descriptor(), CPU);
	expect_message(kinetum::hw::v1::CpuCore::descriptor(), CORE);
	expect_message(kinetum::hw::v1::NicPort::descriptor(), NIC);
}

/** @brief Hardware enums and removed inventory authorities have no descriptor. */
TEST(hardware_schema, driver_and_removed_surface_are_exact)
{
	const auto *file = kinetum::hw::v1::HardwareInventory::descriptor()->file();
	ASSERT_NE(file, nullptr);
	const auto *driver = file->FindEnumTypeByName("NicDriver");
	ASSERT_NE(driver, nullptr);
	ASSERT_EQ(driver->value_count(), 2);
	EXPECT_EQ(driver->value(0)->name(), "NIC_DRIVER_UNSPECIFIED");
	EXPECT_EQ(driver->value(0)->number(), 0);
	EXPECT_EQ(driver->value(1)->name(), "NIC_DRIVER_DPDK");
	EXPECT_EQ(driver->value(1)->number(), 2);
	for (const char *removed : {"NIC_DRIVER_KERNEL", "NIC_DRIVER_XDP", "NIC_DRIVER_AF_XDP"}) {
		EXPECT_EQ(driver->FindValueByName(removed), nullptr) << removed;
	}

	EXPECT_EQ(file->FindEnumTypeByName("NicCapability"), nullptr);
	EXPECT_EQ(file->FindEnumTypeByName("AcceleratorType"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("NumaNode"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("MemoryInfo"), nullptr);
	EXPECT_EQ(file->FindMessageTypeByName("Accelerator"), nullptr);
}

/** @brief Every removed NIC-driver number reaches exact invalid-enum admission. */
TEST(hardware_schema, removed_driver_numbers_reach_the_invalid_enum_wall)
{
	constexpr std::array<int, 3> REMOVED_DRIVER_NUMBERS{1, 3, 4};
	for (const int number : REMOVED_DRIVER_NUMBERS) {
		SCOPED_TRACE(number);
		kinetum::hw::v1::HardwareInventory inventory;
		inventory.mutable_node()->add_nics()->set_driver(static_cast<kinetum::hw::v1::NicDriver>(number));
		const auto status =
			kinetum::common::reject_invalid_protobuf_enum_values_recursive(inventory, "HardwareInventory");
		EXPECT_FALSE(status.is_ok());
		EXPECT_NE(status.message().find("unknown enum number"), std::string::npos);
	}
}

/** @brief A multi-node-era inventory cannot become compact single-node truth. */
TEST(hardware_schema, removed_inventory_wire_reaches_the_recursive_unknown_field_wall)
{
	constexpr std::array<uint8_t, 6> OLD_INVENTORY_WIRE{0x0a, 0x04, 0x1a, 0x02, 0x08, 0x04};
	kinetum::hw::v1::HardwareInventory inventory;
	ASSERT_TRUE(inventory.ParseFromArray(OLD_INVENTORY_WIRE.data(), static_cast<int>(OLD_INVENTORY_WIRE.size())));
	EXPECT_FALSE(kinetum::common::reject_unknown_protobuf_fields_recursive(inventory, "HardwareInventory").is_ok());
}

}  // namespace
}  // namespace kinetum::hw
