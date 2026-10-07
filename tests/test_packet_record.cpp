// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_packet_record.cpp
 * @brief Exact packet-record layout and fixed storage-domain ownership tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

#include "src/dp/fixed_packet_pool.hpp"

namespace kinetum::dp
{

namespace
{

/**
 * @brief Build one complete provider-free fixed-pool test contract.
 *
 * @param record_count Logical packet-credit population.
 * @param data_room_bytes Bytes reserved for each payload slot.
 * @param headroom_bytes Bytes preceding packet data in each slot.
 * @param alignment_bytes Required record and packet-data alignment.
 * @param domain_index Exact storage-domain identity.
 * @param generation Exact nonzero materialization generation.
 * @return Complete options with intentionally absent host NUMA placement.
 */
[[nodiscard]] fixed_packet_pool_options provider_free_pool_options(uint32_t record_count, uint32_t data_room_bytes,
								   uint32_t headroom_bytes, uint32_t alignment_bytes,
								   uint16_t domain_index, uint32_t generation) noexcept
{
	return fixed_packet_pool_options{
		.record_count = record_count,
		.data_room_bytes = data_room_bytes,
		.headroom_bytes = headroom_bytes,
		.alignment_bytes = alignment_bytes,
		.domain_index = domain_index,
		.generation = generation,
		.host_numa_node = std::nullopt,
	};
}

}  // namespace

/** @brief Pin the provider-neutral record and role-partitioned operation tables. */
TEST(packet_record, layout_and_operation_roles_are_exact)
{
	EXPECT_EQ(sizeof(packet_private), 128u);
	EXPECT_EQ(alignof(packet_private), 64u);
	EXPECT_EQ(offsetof(packet_private, timestamp_ns), 0u);
	EXPECT_EQ(offsetof(packet_private, epoch), 8u);
	EXPECT_EQ(offsetof(packet_private, user_meta), 16u);
	EXPECT_EQ(offsetof(packet_private, flow_hash), 24u);
	EXPECT_EQ(offsetof(packet_private, platform_flags), 28u);
	EXPECT_EQ(offsetof(packet_private, user_flags), 32u);
	EXPECT_EQ(offsetof(packet_private, ingress_port), 36u);
	EXPECT_EQ(offsetof(packet_private, egress_port), 38u);
	EXPECT_EQ(offsetof(packet_private, next_stage), 40u);
	EXPECT_EQ(offsetof(packet_private, current_stage), 42u);
	EXPECT_EQ(offsetof(packet_private, next_stage_instance), 44u);
	EXPECT_EQ(offsetof(packet_private, current_stage_instance), 46u);
	EXPECT_EQ(offsetof(packet_private, module_next_stage), 48u);
	EXPECT_EQ(offsetof(packet_private, user_meta_valid), 50u);
	EXPECT_EQ(offsetof(packet_private, padding_hot), 51u);
	EXPECT_EQ(offsetof(packet_private, src_ipv4), 64u);
	EXPECT_EQ(offsetof(packet_private, dst_ipv4), 68u);
	EXPECT_EQ(offsetof(packet_private, src_port), 72u);
	EXPECT_EQ(offsetof(packet_private, dst_port), 74u);
	EXPECT_EQ(offsetof(packet_private, eth_type), 76u);
	EXPECT_EQ(offsetof(packet_private, ip_offset), 78u);
	EXPECT_EQ(offsetof(packet_private, l4_offset), 80u);
	EXPECT_EQ(offsetof(packet_private, ip_header_len), 82u);
	EXPECT_EQ(offsetof(packet_private, ip_total_len), 84u);
	EXPECT_EQ(offsetof(packet_private, l4_proto), 86u);
	EXPECT_EQ(offsetof(packet_private, dscp), 87u);
	EXPECT_EQ(offsetof(packet_private, padding_parsed), 88u);
	EXPECT_EQ(sizeof(packet_storage_descriptor), 64u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, native_handle), 0u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, data), 8u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, operations), 16u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, length), 24u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, contiguous_length), 28u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, generation), 32u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, domain_index), 36u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, segment_count), 38u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, capabilities), 40u);
	EXPECT_EQ(offsetof(packet_storage_descriptor, padding), 44u);
	EXPECT_EQ(sizeof(packet_record), 192u);
	EXPECT_EQ(alignof(packet_record), 64u);
	EXPECT_TRUE(std::is_standard_layout_v<packet_record>);
	EXPECT_TRUE(std::is_trivially_copyable_v<packet_record>);
	EXPECT_EQ(sizeof(packet_storage_domain_operations), 64u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, state), 0u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, acquire_burst), 8u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, clone_writable), 16u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, copy_origins_burst), 24u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, release_burst), 32u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, observe_statistics), 40u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, generation), 48u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, domain_index), 52u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, maximum_packet_length), 54u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, capabilities), 56u);
	EXPECT_EQ(offsetof(packet_storage_domain_operations, padding), 60u);
	EXPECT_EQ(sizeof(packet_rx_burst_operations), 64u);
	EXPECT_EQ(offsetof(packet_rx_burst_operations, state), 0u);
	EXPECT_EQ(offsetof(packet_rx_burst_operations, receive_burst), 8u);
	EXPECT_EQ(offsetof(packet_rx_burst_operations, maximum_burst), 16u);
	EXPECT_EQ(offsetof(packet_rx_burst_operations, logical_port), 18u);
	EXPECT_EQ(offsetof(packet_rx_burst_operations, padding), 20u);
	EXPECT_EQ(sizeof(packet_tx_burst_operations), 64u);
	EXPECT_EQ(offsetof(packet_tx_burst_operations, state), 0u);
	EXPECT_EQ(offsetof(packet_tx_burst_operations, transmit_burst), 8u);
	EXPECT_EQ(offsetof(packet_tx_burst_operations, flush), 16u);
	EXPECT_EQ(offsetof(packet_tx_burst_operations, maybe_flush), 24u);
	EXPECT_EQ(offsetof(packet_tx_burst_operations, maximum_burst), 32u);
	EXPECT_EQ(offsetof(packet_tx_burst_operations, logical_port), 34u);
	EXPECT_EQ(offsetof(packet_tx_burst_operations, padding), 36u);
	EXPECT_FALSE((std::is_same_v<packet_storage_domain_operations, packet_rx_burst_operations>));
	EXPECT_FALSE((std::is_same_v<packet_storage_domain_operations, packet_tx_burst_operations>));
	EXPECT_FALSE((std::is_same_v<packet_rx_burst_operations, packet_tx_burst_operations>));
}

/** @brief Pin every representable relationship among current parser facts. */
TEST(packet_record, platform_fact_coherence_is_exact)
{
	using namespace packet_platform_flags;

	EXPECT_TRUE(packet_platform_facts_are_coherent(0, 0));
	EXPECT_TRUE(packet_platform_facts_are_coherent(L3_IPV4, 1));
	EXPECT_TRUE(packet_platform_facts_are_coherent(L3_IPV4 | L4_TCP, 6));
	EXPECT_TRUE(packet_platform_facts_are_coherent(L3_IPV4 | L4_UDP, 17));
	EXPECT_TRUE(packet_platform_facts_are_coherent(L3_IPV4 | L4_TCP | FRAGMENT, 6));
	EXPECT_FALSE(packet_platform_facts_are_coherent(0, 6));
	EXPECT_FALSE(packet_platform_facts_are_coherent(L4_TCP, 6));
	EXPECT_FALSE(packet_platform_facts_are_coherent(FRAGMENT, 0));
	EXPECT_FALSE(packet_platform_facts_are_coherent(L3_IPV4 | L4_TCP | L4_UDP, 6));
	EXPECT_FALSE(packet_platform_facts_are_coherent(L3_IPV4 | L4_TCP, 17));
	EXPECT_FALSE(packet_platform_facts_are_coherent(L3_IPV4 | L4_UDP, 6));
	EXPECT_FALSE(packet_platform_facts_are_coherent(L3_IPV4, 6));
	EXPECT_FALSE(packet_platform_facts_are_coherent(L3_IPV4, 17));
	EXPECT_FALSE(packet_platform_facts_are_coherent(UINT32_C(1) << 31, 0));
}

/** @brief Verify every invalid fixed-pool identity or shape rejects before allocation. */
TEST(packet_record, fixed_pool_rejects_invalid_construction_contract)
{
	const auto valid = []() { return provider_free_pool_options(1, 64, 0, 64, 1, 1); };
	auto zero_records_options = valid();
	zero_records_options.record_count = 0;
	auto zero_room_options = valid();
	zero_room_options.data_room_bytes = 0;
	auto invalid_headroom_options = valid();
	invalid_headroom_options.headroom_bytes = invalid_headroom_options.data_room_bytes;
	auto invalid_alignment_options = valid();
	invalid_alignment_options.alignment_bytes = 3;
	auto oversized_packet_options = valid();
	oversized_packet_options.data_room_bytes = UINT32_C(65536);
	auto invalid_domain_options = valid();
	invalid_domain_options.domain_index = INVALID_STORAGE_DOMAIN;
	auto zero_generation_options = valid();
	zero_generation_options.generation = 0;
	auto negative_numa_options = valid();
	negative_numa_options.host_numa_node = -1;

	const auto zero_records = fixed_packet_pool::create(zero_records_options);
	const auto zero_room = fixed_packet_pool::create(zero_room_options);
	const auto invalid_headroom = fixed_packet_pool::create(invalid_headroom_options);
	const auto invalid_alignment = fixed_packet_pool::create(invalid_alignment_options);
	const auto oversized_packet = fixed_packet_pool::create(oversized_packet_options);
	const auto invalid_domain = fixed_packet_pool::create(invalid_domain_options);
	const auto zero_generation = fixed_packet_pool::create(zero_generation_options);
	const auto negative_numa = fixed_packet_pool::create(negative_numa_options);

	ASSERT_FALSE(zero_records.is_ok());
	ASSERT_FALSE(zero_room.is_ok());
	ASSERT_FALSE(invalid_headroom.is_ok());
	ASSERT_FALSE(invalid_alignment.is_ok());
	ASSERT_FALSE(oversized_packet.is_ok());
	ASSERT_FALSE(invalid_domain.is_ok());
	ASSERT_FALSE(zero_generation.is_ok());
	ASSERT_FALSE(negative_numa.is_ok());
	EXPECT_NE(zero_records.error().message().find("zero record_count"), std::string::npos);
	EXPECT_NE(zero_room.error().message().find("zero data_room_bytes"), std::string::npos);
	EXPECT_NE(invalid_headroom.error().message().find("headroom_bytes"), std::string::npos);
	EXPECT_NE(invalid_alignment.error().message().find("alignment_bytes"), std::string::npos);
	EXPECT_NE(oversized_packet.error().message().find("packet length"), std::string::npos);
	EXPECT_NE(invalid_domain.error().message().find("invalid domain_index"), std::string::npos);
	EXPECT_NE(zero_generation.error().message().find("zero generation"), std::string::npos);
	EXPECT_NE(negative_numa.error().message().find("NUMA node"), std::string::npos);
}

/** @brief Prove writable fan-out clones have independent payload and metadata. */
TEST(packet_record, fixed_pool_writable_clone_is_independent)
{
	auto pool_or = fixed_packet_pool::create(provider_free_pool_options(2, 64, 0, 64, 7, 11));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	packet_record *original = nullptr;
	ASSERT_EQ(pool->acquire_burst(&original, 1), 1u);
	ASSERT_NE(original, nullptr);
	original->storage.data[0] = 0x01;
	original->storage.data[1] = 0x02;
	original->storage.length = 2;
	original->storage.contiguous_length = 2;
	original->metadata.epoch = 17;
	original->metadata.user_meta = UINT64_C(0x1122334455667788);
	original->metadata.user_meta_valid = 1;
	original->metadata.user_flags = UINT32_C(0xa5a5);

	const auto &operations = pool->operations();
	auto *clone = operations.clone_writable(operations.state, original);
	if (clone == nullptr) {
		operations.release_burst(operations.state, &original, 1);
	}
	ASSERT_NE(clone, nullptr);
	EXPECT_NE(clone, original);
	EXPECT_EQ(clone->storage.data[0], 0x01);
	EXPECT_EQ(clone->metadata.epoch, 17u);
	EXPECT_EQ(clone->metadata.user_meta, UINT64_C(0x1122334455667788));
	EXPECT_EQ(clone->metadata.user_meta_valid, 1u);
	EXPECT_EQ(clone->metadata.user_flags, UINT32_C(0xa5a5));

	clone->storage.data[0] = 0xff;
	clone->metadata.user_meta = UINT64_C(0x8877665544332211);
	clone->metadata.user_flags = UINT32_C(0x5a5a);
	EXPECT_EQ(original->storage.data[0], 0x01);
	EXPECT_EQ(original->metadata.user_meta, UINT64_C(0x1122334455667788));
	EXPECT_EQ(original->metadata.user_flags, UINT32_C(0xa5a5));

	packet_record *records[]{original, clone};
	operations.release_burst(operations.state, records, 2);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 2u);
}

/** @brief Prove clone authority rejects every foreign or stale storage identity. */
TEST(packet_record, fixed_pool_writable_clone_rejects_foreign_domain_or_generation)
{
	auto source_pool_or = fixed_packet_pool::create(provider_free_pool_options(1, 64, 0, 64, 7, 11));
	auto other_pool_or = fixed_packet_pool::create(provider_free_pool_options(1, 64, 0, 64, 8, 11));
	ASSERT_TRUE(source_pool_or.is_ok()) << source_pool_or.error().message();
	ASSERT_TRUE(other_pool_or.is_ok()) << other_pool_or.error().message();
	auto source_pool = std::move(source_pool_or).value();
	auto other_pool = std::move(other_pool_or).value();
	packet_record *source = nullptr;
	ASSERT_EQ(source_pool->acquire_burst(&source, 1), 1u);
	source->storage.length = 1;
	source->storage.contiguous_length = 1;
	source->storage.data[0] = 0x5a;

	const auto &other_operations = other_pool->operations();
	EXPECT_EQ(other_operations.clone_writable(other_operations.state, source), nullptr);
	EXPECT_EQ(other_pool->outstanding(), 0u);

	const auto &source_operations = source_pool->operations();
	const uint32_t exact_generation = source->storage.generation;
	const uint16_t exact_domain = source->storage.domain_index;
	source->storage.generation = exact_generation + 1;
	EXPECT_EQ(source_operations.clone_writable(source_operations.state, source), nullptr);
	source->storage.generation = exact_generation;
	source->storage.domain_index = other_operations.domain_index;
	EXPECT_EQ(source_operations.clone_writable(source_operations.state, source), nullptr);
	source->storage.domain_index = exact_domain;

	packet_record *records[]{source};
	source_operations.release_burst(source_operations.state, records, 1);
	EXPECT_EQ(source_pool->outstanding(), 0u);
}

/** @brief Prove clone-credit exhaustion leaks nothing and never changes storage domain. */
TEST(packet_record, fixed_pool_writable_clone_exhaustion_preserves_exact_owner)
{
	auto pool_or = fixed_packet_pool::create(provider_free_pool_options(1, 64, 0, 64, 7, 11));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	packet_record *source = nullptr;
	ASSERT_EQ(pool->acquire_burst(&source, 1), 1u);
	ASSERT_NE(source, nullptr);
	source->storage.length = 1;
	source->storage.contiguous_length = 1;
	source->storage.data[0] = 0x5a;
	const auto *source_operations = source->storage.operations;
	const void *source_handle = source->storage.native_handle;

	const auto &operations = pool->operations();
	EXPECT_EQ(operations.clone_writable(operations.state, source), nullptr);
	EXPECT_EQ(source->storage.operations, source_operations);
	EXPECT_EQ(source->storage.native_handle, source_handle);
	EXPECT_EQ(source->storage.data[0], 0x5a);
	EXPECT_EQ(pool->outstanding(), 1u);
	EXPECT_EQ(pool->available_approx(), 0u);

	operations.release_burst(operations.state, &source, 1);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 1u);
}

/** @brief Prove cross-owner burst retirement restores reusable fixed-pool credits. */
TEST(packet_record, fixed_pool_cross_owner_burst_release_restores_reusable_credits)
{
	auto pool_or = fixed_packet_pool::create(provider_free_pool_options(4, 193, 128, 256, 3, 5));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	EXPECT_EQ(pool->operations().maximum_packet_length, 65u);
	packet_record *records[4]{};
	ASSERT_EQ(pool->acquire_burst(records, 4), 4u);
	EXPECT_EQ(pool->outstanding(), 4u);
	EXPECT_EQ(pool->available_approx(), 0u);
	for (const auto *record : records) {
		ASSERT_NE(record, nullptr);
		EXPECT_EQ(reinterpret_cast<std::uintptr_t>(record) % 256u, 0u);
		EXPECT_EQ(reinterpret_cast<std::uintptr_t>(record->storage.data) % 256u, 0u);
	}

	const auto &operations = pool->operations();
	kinetum_provider_storage_observation observation{};
	ASSERT_EQ(operations.observe_statistics(operations.state, &observation, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(observation.runtime_generation, 5u);
	EXPECT_EQ(observation.storage_domain_index, 3u);
	EXPECT_EQ(observation.state, KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE);
	EXPECT_EQ(observation.in_use, 4u);
	EXPECT_EQ(observation.available, 0u);
	std::thread return_owner([&operations, &records]() { operations.release_burst(operations.state, records, 4); });
	return_owner.join();
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 4u);
	ASSERT_EQ(operations.observe_statistics(operations.state, &observation, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(observation.in_use, 0u);
	EXPECT_EQ(observation.available, 4u);

	packet_record *reacquired[4]{};
	ASSERT_EQ(pool->acquire_burst(reacquired, 4), 4u);
	EXPECT_EQ(pool->outstanding(), 4u);
	operations.release_burst(operations.state, reacquired, 4);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 4u);
}

/** @brief Prove a second retirement of one fixed-pool credit fails stop. */
TEST(packet_record, fixed_pool_rejects_duplicate_retirement)
{
	EXPECT_DEATH(
		{
			auto pool_or = fixed_packet_pool::create(provider_free_pool_options(2, 64, 0, 64, 3, 5));
			if (!pool_or.is_ok()) {
				std::terminate();
			}
			auto pool = std::move(pool_or).value();
			packet_record *record = nullptr;
			if (pool->acquire_burst(&record, 1) != 1) {
				std::terminate();
			}
			const auto &operations = pool->operations();
			operations.release_burst(operations.state, &record, 1);
			operations.release_burst(operations.state, &record, 1);
		},
		"");
}

/** @brief Prove one retirement burst cannot publish the same credit twice. */
TEST(packet_record, fixed_pool_rejects_duplicate_within_retirement_burst)
{
	EXPECT_DEATH(
		{
			auto pool_or = fixed_packet_pool::create(provider_free_pool_options(2, 64, 0, 64, 3, 5));
			if (!pool_or.is_ok()) {
				std::terminate();
			}
			auto pool = std::move(pool_or).value();
			packet_record *record = nullptr;
			if (pool->acquire_burst(&record, 1) != 1) {
				std::terminate();
			}
			packet_record *records[2]{};
			records[0] = record;
			records[1] = record;
			const auto &operations = pool->operations();
			operations.release_burst(operations.state, records, 2);
		},
		"");
}

/** @brief Prove a counted null retirement fails stop instead of hiding a lost credit. */
TEST(packet_record, fixed_pool_rejects_null_retirement)
{
	EXPECT_DEATH(
		{
			auto pool_or = fixed_packet_pool::create(provider_free_pool_options(1, 64, 0, 64, 3, 5));
			if (!pool_or.is_ok()) {
				std::terminate();
			}
			auto pool = std::move(pool_or).value();
			packet_record *records[]{nullptr};
			const auto &operations = pool->operations();
			operations.release_burst(operations.state, records, 1);
		},
		"");
}

/** @brief Prove an empty retirement call is a caller contract fault. */
TEST(packet_record, fixed_pool_rejects_empty_retirement_burst)
{
	EXPECT_DEATH(
		{
			auto pool_or = fixed_packet_pool::create(provider_free_pool_options(1, 64, 0, 64, 3, 5));
			if (!pool_or.is_ok()) {
				std::terminate();
			}
			auto pool = std::move(pool_or).value();
			const auto &operations = pool->operations();
			operations.release_burst(operations.state, nullptr, 0);
		},
		"");
}

/** @brief Prove malformed origins are transactional and capacity returns an exact prefix. */
TEST(packet_record, fixed_pool_origin_copy_validates_before_storage_credit)
{
	auto pool_or = fixed_packet_pool::create(provider_free_pool_options(2, 8, 0, 64, 2, 7));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	const uint8_t first[]{1, 2, 3};
	const uint8_t second[]{4, 5};
	const uint8_t third[]{6};
	packet_origin_view malformed[]{{first, sizeof(first), 0}, {second, sizeof(second), 0}, {nullptr, 1, 0}};
	packet_record *records[3]{};
	const auto &operations = pool->operations();
	EXPECT_EQ(operations.copy_origins_burst(operations.state, malformed, records, 3), 0u);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 2u);

	packet_origin_view valid[]{{first, sizeof(first), 0}, {second, sizeof(second), 0}, {third, sizeof(third), 0}};
	const uint16_t accepted = operations.copy_origins_burst(operations.state, valid, records, 3);
	ASSERT_EQ(accepted, 2u);
	ASSERT_NE(records[0], nullptr);
	ASSERT_NE(records[1], nullptr);
	EXPECT_EQ(records[2], nullptr);
	EXPECT_EQ(records[0]->storage.length, sizeof(first));
	EXPECT_EQ(records[1]->storage.length, sizeof(second));
	EXPECT_EQ(std::memcmp(records[0]->storage.data, first, sizeof(first)), 0);
	EXPECT_EQ(std::memcmp(records[1]->storage.data, second, sizeof(second)), 0);

	operations.release_burst(operations.state, records, accepted);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 2u);
}

}  // namespace kinetum::dp
