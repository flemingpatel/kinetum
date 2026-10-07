// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_boundary_epoch_channel.cpp
 * @brief Exact DATA sequence, typed control, and endpoint publication tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/boundary_epoch_storage.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::dp
{
namespace
{

/** Runtime identity shared by the channel and endpoint slabs. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 7u;
/** Packet epoch used by DATA and control fixtures. */
constexpr uint64_t TEST_EPOCH = 11u;
/** Compact boundary identity carried by both endpoints. */
constexpr uint32_t TEST_BOUNDARY_INDEX = 3u;
/** Exact sending worker identity. */
constexpr uint32_t TEST_SENDER_WORKER = 1u;
/** Exact receiving worker identity. */
constexpr uint32_t TEST_RECEIVER_WORKER = 2u;

static_assert(!std::is_copy_constructible_v<boundary_epoch_channel>);
static_assert(!std::is_move_constructible_v<boundary_epoch_channel>);
static_assert(!std::is_copy_constructible_v<boundary_epoch_worker_slab>);
static_assert(!std::is_move_constructible_v<boundary_epoch_worker_slab>);

/** @brief Test owner that destroys its borrowing channel before both endpoint slabs. */
struct test_channel_owner {
	std::unique_ptr<boundary_epoch_worker_slab> sender_slab;    ///< Exact sender-worker storage owner.
	std::unique_ptr<boundary_epoch_worker_slab> receiver_slab;  ///< Exact receiver-worker storage owner.
	std::unique_ptr<boundary_epoch_channel> channel;	    ///< Sole semantic transport borrower.
	std::unique_ptr<boundary_future_output_hold> hold;	    ///< Exact sender-NUMA future owner.
	std::unique_ptr<worker_boundary_sender> sender;		    ///< Sole sender-policy claim.
	std::unique_ptr<worker_boundary_receiver> receiver;	    ///< Sole receiver-policy claim.

	/** @brief Test owners cannot be copied because every production owner is linear. */
	test_channel_owner(const test_channel_owner &) = delete;
	/** @brief Test owners cannot be copy-assigned. */
	test_channel_owner &operator=(const test_channel_owner &) = delete;
	/** @brief Transfer one complete test ownership graph. */
	test_channel_owner(test_channel_owner &&) noexcept = default;
	/** @brief Reject replacement because memberwise assignment would retire slabs before a live channel. */
	test_channel_owner &operator=(test_channel_owner &&) = delete;
	/** @brief Construct an empty test owner. */
	test_channel_owner() noexcept = default;
	/** @brief Destroy in reverse order: receiver/sender policies, hold, channel, then slabs. */
	~test_channel_owner() = default;

	/** @return Borrowed exact channel pointer for concise test expressions. */
	[[nodiscard]] boundary_epoch_channel *operator->() const noexcept
	{
		return channel.get();
	}

	/** @return true when the complete owner contains one channel. */
	[[nodiscard]] explicit operator bool() const noexcept
	{
		return channel != nullptr;
	}
};

/**
 * @param owner Candidate complete test owner.
 * @return true when @p owner contains no channel.
 */
[[nodiscard]] bool operator==(const test_channel_owner &owner, std::nullptr_t) noexcept
{
	return !static_cast<bool>(owner);
}

/**
 * @param owner Candidate complete test owner.
 * @return true when @p owner contains one channel.
 */
[[nodiscard]] bool operator!=(const test_channel_owner &owner, std::nullptr_t) noexcept
{
	return static_cast<bool>(owner);
}

/**
 * @brief Return whether one test DATA publication transferred ownership.
 * @tparam channel_owner Pointer-like owner exposing boundary_epoch_channel.
 * @param channel Exact channel owner or pointer.
 * @param record Nonnull record offered to DATA.
 * @return true only for TRANSFERRED; false for any non-transfer result.
 */
template <typename channel_owner>
[[nodiscard]] bool data_transferred(channel_owner &channel, packet_record *record) noexcept
{
	return channel.operator->()->try_send_data(record) == boundary_data_publication_result::TRANSFERRED;
}

/** @return Lowest process-allocatable NUMA node, or -1 when unavailable. */
[[nodiscard]] int32_t test_numa_node()
{
	const auto host = quark::probe_host();
	if (!host.valid || host.memory_numa_nodes.empty()) {
		return -1;
	}
	return host.memory_numa_nodes.front();
}

/**
 * @brief Build one complete compact boundary descriptor.
 *
 * @param numa_node Exact receiver-local DATA NUMA node.
 * @param data_capacity Exact plan-owned DATA capacity.
 * @return Complete boundary facts.
 */
[[nodiscard]] common::compiled_transition_boundary boundary_facts(int32_t numa_node, uint32_t data_capacity = 4u)
{
	return {
		.boundary_id = "boundary_3",
		.boundary_index = TEST_BOUNDARY_INDEX,
		.from_stage_instance_index = 5u,
		.to_stage_instance_index = 8u,
		.sender_worker_index = TEST_SENDER_WORKER,
		.receiver_worker_index = TEST_RECEIVER_WORKER,
		.data_ring_capacity = data_capacity,
		.future_output_hold_capacity = 4u,
		.data_ring_numa_node = numa_node,
	};
}

/**
 * @brief Create one exact channel and its two stable endpoint-storage owners.
 *
 * @param facts Complete compiled boundary facts.
 * @param runtime_generation Exact nonzero generation identity.
 * @param sender_numa Exact sender-worker NUMA node.
 * @param receiver_numa Exact receiver-worker NUMA node.
 * @return Complete owner graph, or an empty owner after recording failure.
 */
[[nodiscard]] test_channel_owner make_channel(const common::compiled_transition_boundary &facts,
					      uint64_t runtime_generation, int32_t sender_numa, int32_t receiver_numa)
{
	test_channel_owner owner;
	auto sender_or = boundary_epoch_worker_slab::create(facts.sender_worker_index, sender_numa, 1u, 0u);
	if (!sender_or.is_ok()) {
		ADD_FAILURE() << sender_or.error().message();
		return owner;
	}
	owner.sender_slab = std::move(sender_or).value();
	auto receiver_or = boundary_epoch_worker_slab::create(facts.receiver_worker_index, receiver_numa, 0u, 1u);
	if (!receiver_or.is_ok()) {
		ADD_FAILURE() << receiver_or.error().message();
		return owner;
	}
	owner.receiver_slab = std::move(receiver_or).value();

	auto channel_or = boundary_epoch_channel::create(facts, runtime_generation, *owner.sender_slab, 0u,
							 *owner.receiver_slab, 0u);
	if (!channel_or.is_ok()) {
		ADD_FAILURE() << channel_or.error().message();
		return owner;
	}
	owner.channel = std::move(channel_or).value();
	auto hold_or = boundary_future_output_hold::create(facts, sender_numa);
	if (!hold_or.is_ok()) {
		ADD_FAILURE() << hold_or.error().message();
		owner.channel.reset();
		return owner;
	}
	owner.hold = std::move(hold_or).value();
	std::array<boundary_epoch_channel *, 1> channels{owner.channel.get()};
	std::array<boundary_future_output_hold *, 1> holds{owner.hold.get()};
	auto policy_or = worker_boundary_sender::create(facts.sender_worker_index, runtime_generation, channels, holds);
	if (!policy_or.is_ok()) {
		ADD_FAILURE() << policy_or.error().message();
		owner.hold.reset();
		owner.channel.reset();
		return owner;
	}
	owner.sender = std::move(policy_or).value();
	auto receiver_policy_or =
		worker_boundary_receiver::create(facts.receiver_worker_index, runtime_generation, channels);
	if (!receiver_policy_or.is_ok()) {
		ADD_FAILURE() << receiver_policy_or.error().message();
		owner.sender.reset();
		owner.hold.reset();
		owner.channel.reset();
		return owner;
	}
	owner.receiver = std::move(receiver_policy_or).value();
	const auto sender_sealed = owner.sender_slab->seal();
	const auto receiver_sealed = owner.receiver_slab->seal();
	if (!sender_sealed.is_ok() || !receiver_sealed.is_ok()) {
		ADD_FAILURE() << (sender_sealed.is_ok() ? receiver_sealed.message() : sender_sealed.message());
		owner.sender.reset();
		owner.hold.reset();
		owner.channel.reset();
		return owner;
	}
	return owner;
}

/**
 * @brief Create one same-node exact channel or report an unexpected failure.
 *
 * @param numa_node Exact sender, receiver, and DATA NUMA node.
 * @param data_capacity Exact plan-owned DATA capacity.
 * @return Complete owner graph, or an empty owner after recording failure.
 */
[[nodiscard]] test_channel_owner make_channel(int32_t numa_node, uint32_t data_capacity = 4u)
{
	return make_channel(boundary_facts(numa_node, data_capacity), TEST_RUNTIME_GENERATION, numa_node, numa_node);
}

/**
 * @brief Require one exact channel-construction rejection.
 *
 * @param facts Candidate compiled boundary facts.
 * @param runtime_generation Candidate runtime generation.
 * @param expected_code Exact required rejection category.
 */
void expect_channel_rejection(const common::compiled_transition_boundary &facts, uint64_t runtime_generation,
			      common::status_code expected_code)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto sender_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, numa_node, 1u, 0u);
	auto receiver_or = boundary_epoch_worker_slab::create(TEST_RECEIVER_WORKER, numa_node, 0u, 1u);
	ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto sender = std::move(sender_or).value();
	auto receiver = std::move(receiver_or).value();
	auto channel_or = boundary_epoch_channel::create(facts, runtime_generation, *sender, 0u, *receiver, 0u);
	ASSERT_FALSE(channel_or.is_ok());
	EXPECT_EQ(channel_or.error().code(), expected_code);
}

/**
 * @brief Attempt a null DATA publication.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void send_null_data(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)data_transferred(channel, nullptr);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Attempt a second DATA receive before completing the first.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void receive_twice_without_completion(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	std::array<packet_record, 2> records{};
	packet_record *received = nullptr;
	if (channel == nullptr || !data_transferred(channel, &records[0]) || !data_transferred(channel, &records[1]) ||
	    channel->try_receive_data(received) != boundary_data_receive_result::RECEIVED) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)channel->try_receive_data(received);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Complete one DATA receive with a foreign pointer.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void complete_foreign_data(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	std::array<packet_record, 2> records{};
	packet_record *received = nullptr;
	if (channel == nullptr || !data_transferred(channel, &records[0]) ||
	    channel->try_receive_data(received) != boundary_data_receive_result::RECEIVED) {
		std::_Exit(EXIT_SUCCESS);
	}
	channel->complete_data_receive(&records[1]);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Publish receiver transport while one dequeue remains unsequenced.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void publish_unsequenced_receive(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	packet_record record{};
	packet_record *received = nullptr;
	if (channel == nullptr || !data_transferred(channel, &record) ||
	    channel->try_receive_data(received) != boundary_data_receive_result::RECEIVED) {
		std::_Exit(EXIT_SUCCESS);
	}
	channel->publish_receiver_transport();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Destroy one channel while dequeue completion remains unresolved.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_unsequenced_receive(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	packet_record record{};
	packet_record *received = nullptr;
	if (channel == nullptr || !data_transferred(channel, &record) ||
	    channel->try_receive_data(received) != boundary_data_receive_result::RECEIVED) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Submit one invalid typed CUT.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void submit_invalid_cut(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)channel->submit_cut({0u, 1u});
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Submit one invalid typed ACK.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void submit_invalid_ack(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)channel->submit_ack({0u, 1u});
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Submit a competing CUT while one exact record is pending.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void submit_competing_pending_cut(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr || channel->submit_cut({11u, 0u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_cut({12u, 1u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_cut({13u, 2u}) != boundary_control_publication_result::PENDING) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)channel->submit_cut({14u, 3u});
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Submit a competing ACK while one exact record is pending.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void submit_competing_pending_ack(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr || channel->submit_ack({11u, 0u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_ack({12u, 1u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_ack({13u, 2u}) != boundary_control_publication_result::PENDING) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)channel->submit_ack({14u, 3u});
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Destroy one channel while DATA remains owned by its ring.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_live_data(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	packet_record record{};
	if (channel == nullptr || !data_transferred(channel, &record)) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Destroy one channel while a published CUT remains owned.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_live_cut(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr || channel->submit_cut({11u, 0u}) != boundary_control_publication_result::PUBLISHED) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Destroy one channel while a published ACK remains owned.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_live_ack(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr || channel->submit_ack({11u, 0u}) != boundary_control_publication_result::PUBLISHED) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Destroy one channel with only an unpublished CUT remaining.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_pending_cut(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr || channel->submit_cut({11u, 0u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_cut({12u, 1u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_cut({13u, 2u}) != boundary_control_publication_result::PENDING) {
		std::_Exit(EXIT_SUCCESS);
	}
	boundary_epoch_cut received{};
	if (!channel->try_receive_cut(received) || !channel->try_receive_cut(received)) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Destroy one channel while a pending ACK remains owner-local.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_pending_ack(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr || channel->submit_ack({11u, 0u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_ack({12u, 1u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_ack({13u, 2u}) != boundary_control_publication_result::PENDING) {
		std::_Exit(EXIT_SUCCESS);
	}
	boundary_epoch_ack received{};
	if (!channel->try_receive_ack(received) || !channel->try_receive_ack(received)) {
		std::_Exit(EXIT_SUCCESS);
	}
}

/**
 * @brief Send DATA after the sole producer closes permanently.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void send_after_close(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	packet_record record{};
	if (channel == nullptr) {
		std::_Exit(EXIT_SUCCESS);
	}
	channel->close_sender();
	(void)data_transferred(channel, &record);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Submit a CUT after the sole producer closes permanently.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void submit_cut_after_close(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr) {
		std::_Exit(EXIT_SUCCESS);
	}
	channel->close_sender();
	(void)channel->submit_cut({11u, 0u});
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Close the sole producer twice.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void close_sender_twice(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr) {
		std::_Exit(EXIT_SUCCESS);
	}
	channel->close_sender();
	channel->close_sender();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Close the producer while one CUT remains endpoint-owned.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void close_with_pending_cut(int32_t numa_node)
{
	auto channel = make_channel(numa_node);
	if (channel == nullptr || channel->submit_cut({11u, 0u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_cut({12u, 1u}) != boundary_control_publication_result::PUBLISHED ||
	    channel->submit_cut({13u, 2u}) != boundary_control_publication_result::PENDING) {
		std::_Exit(EXIT_SUCCESS);
	}
	channel->close_sender();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Destroy one sealed sender slab while its channel still borrows a slot.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_sender_slab_before_channel(int32_t numa_node)
{
	const auto facts = boundary_facts(numa_node);
	auto sender_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, numa_node, 1u, 0u);
	auto receiver_or = boundary_epoch_worker_slab::create(TEST_RECEIVER_WORKER, numa_node, 0u, 1u);
	if (!sender_or.is_ok() || !receiver_or.is_ok()) {
		std::_Exit(EXIT_SUCCESS);
	}
	auto sender = std::move(sender_or).value();
	auto receiver = std::move(receiver_or).value();
	auto channel_or = boundary_epoch_channel::create(facts, TEST_RUNTIME_GENERATION, *sender, 0u, *receiver, 0u);
	if (!channel_or.is_ok()) {
		std::_Exit(EXIT_SUCCESS);
	}
	auto channel = std::move(channel_or).value();
	auto hold_or = boundary_future_output_hold::create(facts, numa_node);
	if (!hold_or.is_ok()) {
		std::_Exit(EXIT_SUCCESS);
	}
	auto hold = std::move(hold_or).value();
	std::array<boundary_epoch_channel *, 1> channels{channel.get()};
	std::array<boundary_future_output_hold *, 1> holds{hold.get()};
	auto policy_or = worker_boundary_sender::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, channels, holds);
	if (!policy_or.is_ok()) {
		std::_Exit(EXIT_SUCCESS);
	}
	auto policy = std::move(policy_or).value();
	auto receiver_policy_or =
		worker_boundary_receiver::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, channels);
	if (!receiver_policy_or.is_ok()) {
		std::_Exit(EXIT_SUCCESS);
	}
	auto receiver_policy = std::move(receiver_policy_or).value();
	if (!sender->seal().is_ok() || !receiver->seal().is_ok()) {
		std::_Exit(EXIT_SUCCESS);
	}
	(void)policy;
	(void)receiver_policy;
	(void)hold;
	(void)channel;
	sender.reset();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Destroy one channel before its sender-policy claim retires.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_channel_before_sender_policy(int32_t numa_node)
{
	auto owner = make_channel(numa_node);
	if (owner == nullptr) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.channel.reset();
	std::_Exit(EXIT_SUCCESS);
}

}  // namespace

/** @brief Prove checked slab layout, exact mapping cardinality, and zero-slot shape. */
TEST(boundary_epoch_worker_slab, checked_layout_uses_one_mapping_per_nonempty_worker)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	EXPECT_EQ(sizeof(boundary_sender_transition_snapshot), 2u * kinetum::algo::CACHE_LINE_SIZE);
	EXPECT_EQ(sizeof(boundary_receiver_transition_snapshot), 2u * kinetum::algo::CACHE_LINE_SIZE);
	auto empty_bytes_or = boundary_epoch_worker_slab::checked_storage_bytes(0u, 0u);
	ASSERT_TRUE(empty_bytes_or.is_ok()) << empty_bytes_or.error().message();
	EXPECT_EQ(empty_bytes_or.value(), 0u);
	auto exact_bytes_or = boundary_epoch_worker_slab::checked_storage_bytes(2u, 3u);
	ASSERT_TRUE(exact_bytes_or.is_ok()) << exact_bytes_or.error().message();
	EXPECT_GT(exact_bytes_or.value(), 0u);
	auto overflow_or =
		boundary_epoch_worker_slab::checked_storage_bytes(std::numeric_limits<std::size_t>::max(), 1u);
	ASSERT_FALSE(overflow_or.is_ok());
	EXPECT_EQ(overflow_or.error().code(), common::status_code::OUT_OF_RANGE);

	auto empty_or = boundary_epoch_worker_slab::create(0u, numa_node, 0u, 0u);
	ASSERT_TRUE(empty_or.is_ok()) << empty_or.error().message();
	auto empty = std::move(empty_or).value();
	EXPECT_EQ(empty->mapping_count(), 0u);
	EXPECT_EQ(empty->storage_bytes(), 0u);
	EXPECT_TRUE(empty->seal().is_ok());
	EXPECT_EQ(empty->seal().code(), common::status_code::FAILED_PRECONDITION);

	auto slab_or = boundary_epoch_worker_slab::create(1u, numa_node, 2u, 3u);
	ASSERT_TRUE(slab_or.is_ok()) << slab_or.error().message();
	auto slab = std::move(slab_or).value();
	EXPECT_EQ(slab->worker_index(), 1u);
	EXPECT_EQ(slab->numa_node(), numa_node);
	EXPECT_EQ(slab->sender_slot_count(), 2u);
	EXPECT_EQ(slab->receiver_slot_count(), 3u);
	EXPECT_EQ(slab->storage_bytes(), exact_bytes_or.value());
	EXPECT_EQ(slab->mapping_count(), 1u);
	EXPECT_FALSE(slab->sealed());

	auto sentinel_or = boundary_epoch_worker_slab::create(std::numeric_limits<uint32_t>::max(), numa_node, 0u, 0u);
	ASSERT_FALSE(sentinel_or.is_ok());
	EXPECT_EQ(sentinel_or.error().code(), common::status_code::INVALID_ARGUMENT);
	auto invalid_node_or = boundary_epoch_worker_slab::create(0u, -1, 0u, 0u);
	ASSERT_FALSE(invalid_node_or.is_ok());
	EXPECT_EQ(invalid_node_or.error().code(), common::status_code::INVALID_ARGUMENT);
}

/** @brief Place every endpoint state and control ring with its exact owner or poller. */
TEST(boundary_epoch_worker_slab, every_slot_and_control_ring_follow_exact_worker_numa_ownership)
{
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	std::vector<int32_t> worker_nodes;
	for (const int32_t numa_node : host.memory_numa_nodes) {
		if (std::any_of(host.cpus.begin(), host.cpus.end(),
				[&](const auto &cpu) { return cpu.numa_node == numa_node; })) {
			worker_nodes.push_back(numa_node);
		}
	}
	ASSERT_FALSE(worker_nodes.empty());
	const int32_t sender_numa = worker_nodes.front();
	const int32_t receiver_numa = worker_nodes.back();
	auto sender_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, sender_numa, 2u, 0u);
	auto receiver_or = boundary_epoch_worker_slab::create(TEST_RECEIVER_WORKER, receiver_numa, 0u, 2u);
	ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto sender = std::move(sender_or).value();
	auto receiver = std::move(receiver_or).value();

	auto first_facts = boundary_facts(receiver_numa);
	first_facts.boundary_index = 0u;
	first_facts.boundary_id = "boundary_0";
	auto first_or =
		boundary_epoch_channel::create(first_facts, TEST_RUNTIME_GENERATION, *sender, 0u, *receiver, 0u);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	auto first = std::move(first_or).value();
	auto second_facts = first_facts;
	second_facts.boundary_index = 1u;
	second_facts.boundary_id = "boundary_1";
	second_facts.from_stage_instance_index = 6u;
	second_facts.to_stage_instance_index = 9u;
	auto partial_claim_or =
		boundary_epoch_channel::create(second_facts, TEST_RUNTIME_GENERATION, *sender, 1u, *receiver, 0u);
	ASSERT_FALSE(partial_claim_or.is_ok());
	EXPECT_EQ(partial_claim_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto second_or =
		boundary_epoch_channel::create(second_facts, TEST_RUNTIME_GENERATION, *sender, 1u, *receiver, 1u);
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto second = std::move(second_or).value();

	auto duplicate_or =
		boundary_epoch_channel::create(first_facts, TEST_RUNTIME_GENERATION, *sender, 0u, *receiver, 0u);
	ASSERT_FALSE(duplicate_or.is_ok());
	EXPECT_EQ(duplicate_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto first_hold_or = boundary_future_output_hold::create(first_facts, sender_numa);
	auto second_hold_or = boundary_future_output_hold::create(second_facts, sender_numa);
	ASSERT_TRUE(first_hold_or.is_ok()) << first_hold_or.error().message();
	ASSERT_TRUE(second_hold_or.is_ok()) << second_hold_or.error().message();
	auto first_hold = std::move(first_hold_or).value();
	auto second_hold = std::move(second_hold_or).value();
	std::array<boundary_epoch_channel *, 2> channels{first.get(), second.get()};
	std::array<boundary_future_output_hold *, 2> holds{first_hold.get(), second_hold.get()};
	auto policy_or = worker_boundary_sender::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, channels, holds);
	ASSERT_TRUE(policy_or.is_ok()) << policy_or.error().message();
	auto policy = std::move(policy_or).value();
	auto receiver_policy_or =
		worker_boundary_receiver::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, channels);
	ASSERT_TRUE(receiver_policy_or.is_ok()) << receiver_policy_or.error().message();
	auto receiver_policy = std::move(receiver_policy_or).value();
	ASSERT_TRUE(sender->seal().is_ok());
	ASSERT_TRUE(receiver->seal().is_ok());
	for (const auto *channel : {first.get(), second.get()}) {
		ASSERT_NE(channel, nullptr);
		EXPECT_EQ(channel->sender_endpoint_numa_node(), sender_numa);
		EXPECT_EQ(channel->ack_ring_numa_node(), sender_numa);
		EXPECT_EQ(channel->receiver_endpoint_numa_node(), receiver_numa);
		EXPECT_EQ(channel->cut_ring_numa_node(), receiver_numa);
		EXPECT_EQ(channel->data_ring_numa_node(), receiver_numa);
		EXPECT_TRUE(channel->endpoint_storage_sealed());
	}
	EXPECT_EQ(policy->size(), 2u);
	EXPECT_EQ(policy->policy_numa_node(0u), sender_numa);
	EXPECT_EQ(policy->policy_numa_node(1u), sender_numa);
	EXPECT_EQ(receiver_policy->policy_numa_node(0u), receiver_numa);
	EXPECT_EQ(receiver_policy->policy_numa_node(1u), receiver_numa);
	receiver_policy.reset();
	policy.reset();
	second_hold.reset();
	first_hold.reset();
	second.reset();
	first.reset();
}

/** @brief Require virgin complete claims and channel-before-slab teardown order. */
TEST(boundary_epoch_worker_slab, sealing_and_destruction_enforce_the_complete_borrow_lifetime)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto incomplete_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, numa_node, 1u, 0u);
	ASSERT_TRUE(incomplete_or.is_ok()) << incomplete_or.error().message();
	auto incomplete = std::move(incomplete_or).value();
	const auto incomplete_seal = incomplete->seal();
	EXPECT_EQ(incomplete_seal.code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_FALSE(incomplete->sealed());
	{
		const auto facts = boundary_facts(numa_node);
		auto sender_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, numa_node, 1u, 0u);
		auto receiver_or = boundary_epoch_worker_slab::create(TEST_RECEIVER_WORKER, numa_node, 0u, 1u);
		ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
		ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
		auto sender = std::move(sender_or).value();
		auto receiver = std::move(receiver_or).value();
		auto channel_or =
			boundary_epoch_channel::create(facts, TEST_RUNTIME_GENERATION, *sender, 0u, *receiver, 0u);
		ASSERT_TRUE(channel_or.is_ok()) << channel_or.error().message();
		auto channel = std::move(channel_or).value();
		const auto channel_only_sender_seal = sender->seal();
		const auto channel_only_receiver_seal = receiver->seal();
		EXPECT_EQ(channel_only_sender_seal.code(), common::status_code::FAILED_PRECONDITION);
		EXPECT_EQ(channel_only_receiver_seal.code(), common::status_code::FAILED_PRECONDITION);
		EXPECT_FALSE(sender->sealed());
		channel.reset();
	}
	{
		const auto facts = boundary_facts(numa_node);
		auto sender_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, numa_node, 1u, 0u);
		auto receiver_or = boundary_epoch_worker_slab::create(TEST_RECEIVER_WORKER, numa_node, 0u, 1u);
		ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
		ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
		auto sender = std::move(sender_or).value();
		auto receiver = std::move(receiver_or).value();
		auto channel_or =
			boundary_epoch_channel::create(facts, TEST_RUNTIME_GENERATION, *sender, 0u, *receiver, 0u);
		ASSERT_TRUE(channel_or.is_ok()) << channel_or.error().message();
		auto channel = std::move(channel_or).value();
		packet_record record{};
		ASSERT_TRUE(data_transferred(channel, &record));
		packet_record *received = nullptr;
		ASSERT_EQ(channel->try_receive_data(received), boundary_data_receive_result::RECEIVED);
		ASSERT_EQ(received, &record);
		channel->complete_data_receive(received);
		auto hold_or = boundary_future_output_hold::create(facts, numa_node);
		ASSERT_TRUE(hold_or.is_ok()) << hold_or.error().message();
		auto hold = std::move(hold_or).value();
		std::array<boundary_epoch_channel *, 1> channels{channel.get()};
		std::array<boundary_future_output_hold *, 1> holds{hold.get()};
		auto policy_or =
			worker_boundary_sender::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, channels, holds);
		ASSERT_FALSE(policy_or.is_ok());
		EXPECT_EQ(policy_or.error().code(), common::status_code::FAILED_PRECONDITION);
	}
	EXPECT_DEATH(destroy_sender_slab_before_channel(numa_node), "");
	EXPECT_DEATH(destroy_channel_before_sender_policy(numa_node), "");

	auto owner = make_channel(numa_node);
	ASSERT_NE(owner, nullptr);
	EXPECT_TRUE(owner.sender_slab->sealed());
	EXPECT_TRUE(owner.receiver_slab->sealed());
}

/** @brief Prove exact cold identity, capacities, layout, and unpublished startup. */
TEST(boundary_epoch_channel, exact_identity_layout_and_typed_capacities_are_final)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	EXPECT_EQ(channel->runtime_generation(), TEST_RUNTIME_GENERATION);
	EXPECT_EQ(channel->boundary_index(), TEST_BOUNDARY_INDEX);
	EXPECT_EQ(channel->sender_worker_index(), TEST_SENDER_WORKER);
	EXPECT_EQ(channel->receiver_worker_index(), TEST_RECEIVER_WORKER);
	EXPECT_EQ(channel->from_stage_instance_index(), 5u);
	EXPECT_EQ(channel->to_stage_instance_index(), 8u);
	EXPECT_EQ(channel->data_ring_numa_node(), numa_node);
	EXPECT_EQ(channel->sender_endpoint_numa_node(), numa_node);
	EXPECT_EQ(channel->receiver_endpoint_numa_node(), numa_node);
	EXPECT_EQ(channel->cut_ring_numa_node(), numa_node);
	EXPECT_EQ(channel->ack_ring_numa_node(), numa_node);
	EXPECT_TRUE(channel->endpoint_storage_sealed());
	EXPECT_EQ(channel->data_capacity(), 4u);
	EXPECT_EQ(common::runtime_sizing::BOUNDARY_CUT_RING_CAPACITY, 2u);
	EXPECT_EQ(common::runtime_sizing::BOUNDARY_ACK_RING_CAPACITY, 2u);
	EXPECT_TRUE(channel->empty());
	boundary_sender_transport_snapshot sender{};
	boundary_receiver_transport_snapshot receiver{};
	EXPECT_EQ(channel->try_read_sender_transport(sender), publication_read_result::UNAVAILABLE);
	EXPECT_EQ(channel->try_read_receiver_transport(receiver), publication_read_result::UNAVAILABLE);
}

/** @brief Reject malformed generation, endpoint, NUMA, and DATA-capacity facts. */
TEST(boundary_epoch_channel, malformed_generation_endpoint_numa_or_capacity_rejects_before_allocation)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto facts = boundary_facts(numa_node);
	expect_channel_rejection(facts, 0u, common::status_code::INVALID_ARGUMENT);
	expect_channel_rejection(facts, uint64_t{1} << 32u, common::status_code::INVALID_ARGUMENT);
	facts.receiver_worker_index = facts.sender_worker_index;
	expect_channel_rejection(facts, TEST_RUNTIME_GENERATION, common::status_code::FAILED_PRECONDITION);
	facts = boundary_facts(numa_node);
	facts.sender_worker_index = TEST_SENDER_WORKER + 10u;
	expect_channel_rejection(facts, TEST_RUNTIME_GENERATION, common::status_code::FAILED_PRECONDITION);
	facts = boundary_facts(numa_node);
	facts.receiver_worker_index = TEST_RECEIVER_WORKER + 10u;
	expect_channel_rejection(facts, TEST_RUNTIME_GENERATION, common::status_code::FAILED_PRECONDITION);
	facts = boundary_facts(-1);
	expect_channel_rejection(facts, TEST_RUNTIME_GENERATION, common::status_code::FAILED_PRECONDITION);
	facts = boundary_facts(numa_node == 0 ? 1 : 0);
	expect_channel_rejection(facts, TEST_RUNTIME_GENERATION, common::status_code::FAILED_PRECONDITION);
	for (const uint32_t capacity : {0u, 1u, 3u}) {
		facts = boundary_facts(numa_node, capacity);
		expect_channel_rejection(facts, TEST_RUNTIME_GENERATION, common::status_code::FAILED_PRECONDITION);
	}
}

/** @brief Preserve FIFO ownership and advance only successful DATA operations. */
TEST(boundary_epoch_channel, data_fifo_backpressure_and_sequences_conserve_every_record)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	std::array<packet_record, 5> records{};
	for (std::size_t index = 0; index < 4u; ++index) {
		records[index].metadata.epoch = index + 1u;
		ASSERT_TRUE(data_transferred(channel, &records[index]));
		EXPECT_EQ(channel->data_enqueued_sequence(), index + 1u);
	}
	EXPECT_FALSE(data_transferred(channel, &records[4]));
	EXPECT_EQ(channel->data_enqueued_sequence(), 4u);
	EXPECT_EQ(channel->peek_data(), &records[0]);
	channel->publish_sender_transport();
	boundary_sender_transport_snapshot sender_observation{};
	ASSERT_EQ(channel->try_read_sender_transport(sender_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(sender_observation.data_enqueued_sequence, 4u);
	EXPECT_EQ(sender_observation.data_backpressure_events, 1u);

	for (std::size_t index = 0; index < 4u; ++index) {
		packet_record *received = nullptr;
		ASSERT_EQ(channel->try_receive_data(received), boundary_data_receive_result::RECEIVED);
		EXPECT_EQ(received, &records[index]);
		EXPECT_EQ(channel->data_dequeued_sequence(), index);
		channel->complete_data_receive(received);
		EXPECT_EQ(channel->data_dequeued_sequence(), index + 1u);
	}
	channel->publish_receiver_transport();
	boundary_receiver_transport_snapshot receiver_observation{};
	ASSERT_EQ(channel->try_read_receiver_transport(receiver_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(receiver_observation.data_dequeued_sequence, 4u);
	EXPECT_TRUE(channel->data_empty());
}

/** @brief Pin sender/receiver sequence ordering around exact worker credits. */
TEST(boundary_epoch_channel, worker_credit_transfer_brackets_successful_sequences_exactly)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	auto sender_or = worker_epoch_ledger::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, 1u);
	auto receiver_or = worker_epoch_ledger::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, 1u);
	ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto sender = std::move(sender_or).value();
	auto receiver = std::move(receiver_or).value();
	sender->bind_bootstrap_epoch(TEST_EPOCH);
	receiver->bind_bootstrap_epoch(TEST_EPOCH);

	packet_record record{};
	record.metadata.epoch = TEST_EPOCH;
	sender->acquire(TEST_EPOCH);
	ASSERT_TRUE(data_transferred(channel, &record));
	EXPECT_EQ(channel->data_enqueued_sequence(), 1u);
	worker_epoch_ledger_snapshot sender_observation{};
	sender->publish();
	ASSERT_EQ(sender->try_read(sender_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(sender_observation.active_unretired, 1u);
	sender->retire(TEST_EPOCH);

	packet_record *received = nullptr;
	ASSERT_EQ(channel->try_receive_data(received), boundary_data_receive_result::RECEIVED);
	EXPECT_EQ(channel->data_dequeued_sequence(), 0u);
	receiver->acquire(TEST_EPOCH);
	channel->complete_data_receive(received);
	EXPECT_EQ(channel->data_dequeued_sequence(), 1u);
	worker_epoch_ledger_snapshot receiver_observation{};
	receiver->publish();
	ASSERT_EQ(receiver->try_read(receiver_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(receiver_observation.active_unretired, 1u);
	receiver->retire(TEST_EPOCH);
}

/** @brief Preserve duplicate CUT values and retain one exact record under pressure. */
TEST(boundary_epoch_channel, cut_publication_is_nonblocking_and_retains_one_exact_pending_record)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	EXPECT_EQ(channel->service_pending_cut(), boundary_control_publication_result::ABSENT);
	EXPECT_EQ(channel->submit_cut({11u, 7u}), boundary_control_publication_result::PUBLISHED);
	EXPECT_EQ(channel->submit_cut({11u, 7u}), boundary_control_publication_result::PUBLISHED);
	EXPECT_EQ(channel->submit_cut({13u, 0u}), boundary_control_publication_result::PENDING);
	EXPECT_TRUE(channel->has_pending_cut());
	channel->publish_sender_transport();
	boundary_sender_transport_snapshot observation{};
	ASSERT_EQ(channel->try_read_sender_transport(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.pending_cut_epoch, 13u);
	EXPECT_EQ(observation.pending_cut_sequence, 0u);

	boundary_epoch_cut received{};
	ASSERT_TRUE(channel->try_receive_cut(received));
	EXPECT_EQ(received, (boundary_epoch_cut{11u, 7u}));
	EXPECT_EQ(channel->service_pending_cut(), boundary_control_publication_result::PUBLISHED);
	EXPECT_FALSE(channel->has_pending_cut());
	ASSERT_TRUE(channel->try_receive_cut(received));
	EXPECT_EQ(received, (boundary_epoch_cut{11u, 7u}));
	ASSERT_TRUE(channel->try_receive_cut(received));
	EXPECT_EQ(received, (boundary_epoch_cut{13u, 0u}));
	EXPECT_FALSE(channel->try_receive_cut(received));
	EXPECT_TRUE(channel->control_empty());
}

/** @brief Preserve duplicate ACK values and retain one exact record under pressure. */
TEST(boundary_epoch_channel, ack_publication_is_nonblocking_and_retains_one_exact_pending_record)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	EXPECT_EQ(channel->service_pending_ack(), boundary_control_publication_result::ABSENT);
	EXPECT_EQ(channel->submit_ack({11u, 7u}), boundary_control_publication_result::PUBLISHED);
	EXPECT_EQ(channel->submit_ack({11u, 7u}), boundary_control_publication_result::PUBLISHED);
	EXPECT_EQ(channel->submit_ack({13u, 0u}), boundary_control_publication_result::PENDING);
	EXPECT_TRUE(channel->has_pending_ack());
	channel->publish_receiver_transport();
	boundary_receiver_transport_snapshot observation{};
	ASSERT_EQ(channel->try_read_receiver_transport(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.pending_ack_epoch, 13u);
	EXPECT_EQ(observation.pending_ack_sequence, 0u);

	boundary_epoch_ack received{};
	ASSERT_TRUE(channel->try_receive_ack(received));
	EXPECT_EQ(received, (boundary_epoch_ack{11u, 7u}));
	EXPECT_EQ(channel->service_pending_ack(), boundary_control_publication_result::PUBLISHED);
	EXPECT_FALSE(channel->has_pending_ack());
	ASSERT_TRUE(channel->try_receive_ack(received));
	EXPECT_EQ(received, (boundary_epoch_ack{11u, 7u}));
	ASSERT_TRUE(channel->try_receive_ack(received));
	EXPECT_EQ(received, (boundary_epoch_ack{13u, 0u}));
	EXPECT_FALSE(channel->try_receive_ack(received));
	EXPECT_TRUE(channel->control_empty());
}

/** @brief Publish exact cache-line sender and receiver transport observations. */
TEST(boundary_epoch_channel, sender_and_receiver_publications_are_coherent_and_cacheline_exact)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	channel->publish_sender_transport();
	channel->publish_receiver_transport();
	boundary_sender_transport_snapshot sender{};
	boundary_receiver_transport_snapshot receiver{};
	ASSERT_EQ(channel->try_read_sender_transport(sender), publication_read_result::AVAILABLE);
	ASSERT_EQ(channel->try_read_receiver_transport(receiver), publication_read_result::AVAILABLE);
	EXPECT_EQ(sender.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(receiver.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(sender.boundary_index, TEST_BOUNDARY_INDEX);
	EXPECT_EQ(receiver.boundary_index, TEST_BOUNDARY_INDEX);
	EXPECT_EQ(sender.data_enqueued_sequence, 0u);
	EXPECT_EQ(receiver.data_dequeued_sequence, 0u);
	EXPECT_NE(sender.publication_generation, 0u);
	EXPECT_NE(receiver.publication_generation, 0u);
}

/** @brief Coherent invalid transport data is terminal, distinct from an unavailable publication. */
TEST(boundary_epoch_channel, decoded_transport_validation_preserves_identity_and_state_failures)
{
	const boundary_sender_transport_snapshot sender{.publication_generation = 1u,
							.runtime_generation = TEST_RUNTIME_GENERATION,
							.boundary_index = TEST_BOUNDARY_INDEX};
	const boundary_receiver_transport_snapshot receiver{.publication_generation = 1u,
							    .runtime_generation = TEST_RUNTIME_GENERATION,
							    .boundary_index = TEST_BOUNDARY_INDEX};
	EXPECT_EQ(validate_boundary_sender_transport(sender, TEST_RUNTIME_GENERATION, TEST_BOUNDARY_INDEX),
		  publication_read_result::AVAILABLE);
	EXPECT_EQ(validate_boundary_receiver_transport(receiver, TEST_RUNTIME_GENERATION, TEST_BOUNDARY_INDEX),
		  publication_read_result::AVAILABLE);
	EXPECT_EQ(validate_boundary_sender_transport(sender, TEST_RUNTIME_GENERATION + 1u, TEST_BOUNDARY_INDEX),
		  publication_read_result::INVALID_IDENTITY);
	EXPECT_EQ(validate_boundary_receiver_transport(receiver, TEST_RUNTIME_GENERATION, TEST_BOUNDARY_INDEX + 1u),
		  publication_read_result::INVALID_IDENTITY);
	for (std::size_t fault = 0u; fault < 4u; ++fault) {
		auto bad_sender = sender;
		auto bad_receiver = receiver;
		switch (fault) {
		case 0u:
			bad_sender.publication_generation = 0u;
			bad_receiver.publication_generation = 0u;
			break;
		case 1u:
			bad_sender.data_enqueued_sequence = UINT64_MAX;
			bad_receiver.data_dequeued_sequence = UINT64_MAX;
			break;
		case 2u:
			bad_sender.pending_cut_sequence = 1u;
			bad_receiver.pending_ack_sequence = 1u;
			break;
		case 3u:
			bad_sender.pending_cut_epoch = UINT64_MAX;
			bad_receiver.pending_ack_epoch = UINT64_MAX;
			break;
		}
		EXPECT_EQ(validate_boundary_sender_transport(bad_sender, TEST_RUNTIME_GENERATION, TEST_BOUNDARY_INDEX),
			  publication_read_result::INVALID_STATE);
		EXPECT_EQ(validate_boundary_receiver_transport(bad_receiver, TEST_RUNTIME_GENERATION,
							       TEST_BOUNDARY_INDEX),
			  publication_read_result::INVALID_STATE);
	}
	auto empty_cut = sender;
	auto empty_ack = receiver;
	empty_cut.pending_cut_epoch = TEST_EPOCH;
	empty_ack.pending_ack_epoch = TEST_EPOCH;
	EXPECT_EQ(validate_boundary_sender_transport(empty_cut, TEST_RUNTIME_GENERATION, TEST_BOUNDARY_INDEX),
		  publication_read_result::AVAILABLE);
	EXPECT_EQ(validate_boundary_receiver_transport(empty_ack, TEST_RUNTIME_GENERATION, TEST_BOUNDARY_INDEX),
		  publication_read_result::AVAILABLE);
}

/** @brief Preserve exact sequence coherence under concurrent DATA transfer and observation. */
TEST(boundary_epoch_channel, concurrent_data_transfer_and_observation_preserve_exact_sequences)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node, 64u);
	ASSERT_NE(channel, nullptr);
	constexpr std::size_t RECORD_COUNT = 1000u;
	std::vector<packet_record> records(RECORD_COUNT);
	std::atomic<bool> sender_done{false};
	std::atomic<bool> receiver_done{false};
	std::atomic<bool> receiver_observed_close{false};
	std::atomic<bool> observation_failed{false};

	std::thread sender([&]() {
		for (auto &record : records) {
			while (!data_transferred(channel, &record)) {
				std::this_thread::yield();
			}
			channel->publish_sender_transport();
		}
		channel->close_sender();
		sender_done.store(true, std::memory_order_release);
	});
	std::thread receiver([&]() {
		std::size_t count = 0u;
		while (count < records.size()) {
			packet_record *record = nullptr;
			if (channel->try_receive_data(record) == boundary_data_receive_result::EMPTY) {
				std::this_thread::yield();
				continue;
			}
			if (record == nullptr) {
				std::terminate();
			}
			channel->complete_data_receive(record);
			channel->publish_receiver_transport();
			++count;
		}
		while (!channel->sender_closed()) {
			std::this_thread::yield();
		}
		receiver_observed_close.store(true, std::memory_order_release);
		receiver_done.store(true, std::memory_order_release);
	});
	std::thread observer([&]() {
		uint64_t sender_sequence = 0u;
		uint64_t receiver_sequence = 0u;
		while (!sender_done.load(std::memory_order_acquire) || !receiver_done.load(std::memory_order_acquire)) {
			boundary_sender_transport_snapshot sender_observation{};
			const auto sender_read = channel->try_read_sender_transport(sender_observation);
			if (sender_read == publication_read_result::AVAILABLE) {
				if (sender_observation.data_enqueued_sequence < sender_sequence) {
					observation_failed.store(true, std::memory_order_release);
				}
				sender_sequence = sender_observation.data_enqueued_sequence;
			} else if (sender_read != publication_read_result::UNAVAILABLE) {
				observation_failed.store(true, std::memory_order_release);
			}
			boundary_receiver_transport_snapshot receiver_observation{};
			const auto receiver_read = channel->try_read_receiver_transport(receiver_observation);
			if (receiver_read == publication_read_result::AVAILABLE) {
				if (receiver_observation.data_dequeued_sequence < receiver_sequence) {
					observation_failed.store(true, std::memory_order_release);
				}
				receiver_sequence = receiver_observation.data_dequeued_sequence;
			} else if (receiver_read != publication_read_result::UNAVAILABLE) {
				observation_failed.store(true, std::memory_order_release);
			}
		}
	});
	sender.join();
	receiver.join();
	observer.join();
	EXPECT_FALSE(observation_failed.load(std::memory_order_acquire));
	EXPECT_TRUE(receiver_observed_close.load(std::memory_order_acquire));
	boundary_sender_transport_snapshot sender_observation{};
	boundary_receiver_transport_snapshot receiver_observation{};
	ASSERT_EQ(channel->try_read_sender_transport(sender_observation), publication_read_result::AVAILABLE);
	ASSERT_EQ(channel->try_read_receiver_transport(receiver_observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(sender_observation.data_enqueued_sequence, RECORD_COUNT);
	EXPECT_EQ(receiver_observation.data_dequeued_sequence, RECORD_COUNT);
	EXPECT_EQ(channel->data_enqueued_sequence(), RECORD_COUNT);
	EXPECT_EQ(channel->data_dequeued_sequence(), RECORD_COUNT);
	EXPECT_TRUE(channel->empty());
}

/** @brief Keep every fan-in channel's sequences and pending control independent. */
TEST(boundary_epoch_channel, fan_in_channels_keep_independent_sequence_and_control_ownership)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto left = make_channel(numa_node);
	auto right_facts = boundary_facts(numa_node);
	right_facts.boundary_id = "boundary_4";
	right_facts.boundary_index = 4u;
	right_facts.sender_worker_index = 3u;
	auto right = make_channel(right_facts, TEST_RUNTIME_GENERATION, numa_node, numa_node);
	ASSERT_NE(left, nullptr);
	ASSERT_NE(right, nullptr);
	packet_record left_record{};
	packet_record right_record{};
	ASSERT_TRUE(data_transferred(left, &left_record));
	ASSERT_TRUE(data_transferred(right, &right_record));
	EXPECT_EQ(left->submit_cut({11u, 1u}), boundary_control_publication_result::PUBLISHED);
	EXPECT_TRUE(right->control_empty());
	EXPECT_EQ(left->data_enqueued_sequence(), 1u);
	EXPECT_EQ(right->data_enqueued_sequence(), 1u);
	boundary_epoch_cut cut{};
	ASSERT_TRUE(left->try_receive_cut(cut));
	EXPECT_EQ(cut, (boundary_epoch_cut{11u, 1u}));
	packet_record *received = nullptr;
	ASSERT_EQ(left->try_receive_data(received), boundary_data_receive_result::RECEIVED);
	left->complete_data_receive(received);
	ASSERT_EQ(right->try_receive_data(received), boundary_data_receive_result::RECEIVED);
	right->complete_data_receive(received);
}

/** @brief Preserve packet metadata bytes without a DATA envelope or epoch mirror. */
TEST(boundary_epoch_channel, transfer_preserves_exact_packet_epoch_without_derivation)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	packet_record record{};
	record.metadata.epoch = TEST_EPOCH;
	record.metadata.user_meta = UINT64_C(0x1122334455667788);
	record.metadata.user_meta_valid = 1u;
	ASSERT_TRUE(data_transferred(channel, &record));
	packet_record *received = nullptr;
	ASSERT_EQ(channel->try_receive_data(received), boundary_data_receive_result::RECEIVED);
	channel->complete_data_receive(received);
	EXPECT_EQ(received, &record);
	EXPECT_EQ(received->metadata.epoch, TEST_EPOCH);
	EXPECT_EQ(received->metadata.user_meta, UINT64_C(0x1122334455667788));
	EXPECT_EQ(received->metadata.user_meta_valid, 1u);
}

/** @brief Preserve queued DATA order through exact process-shutdown closure. */
TEST(boundary_epoch_channel, sender_close_preserves_queued_data_order)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto channel = make_channel(numa_node);
	ASSERT_NE(channel, nullptr);
	std::array<packet_record, 2> records{};
	ASSERT_TRUE(data_transferred(channel, &records[0]));
	ASSERT_TRUE(data_transferred(channel, &records[1]));
	channel->close_sender();
	EXPECT_TRUE(channel->sender_closed());
	for (auto &expected : records) {
		packet_record *received = nullptr;
		ASSERT_EQ(channel->try_receive_data(received), boundary_data_receive_result::RECEIVED);
		EXPECT_EQ(received, &expected);
		channel->complete_data_receive(received);
	}
	EXPECT_TRUE(channel->empty());
	EXPECT_DEATH(send_after_close(numa_node), "");
}

/** @brief Fail stop on malformed, competing, or closed transport operations. */
TEST(boundary_epoch_channel, malformed_or_competing_transport_operations_fail_stop)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	EXPECT_DEATH(send_null_data(numa_node), "");
	EXPECT_DEATH(receive_twice_without_completion(numa_node), "");
	EXPECT_DEATH(complete_foreign_data(numa_node), "");
	EXPECT_DEATH(publish_unsequenced_receive(numa_node), "");
	EXPECT_DEATH(submit_invalid_cut(numa_node), "");
	EXPECT_DEATH(submit_invalid_ack(numa_node), "");
	EXPECT_DEATH(submit_competing_pending_cut(numa_node), "");
	EXPECT_DEATH(submit_competing_pending_ack(numa_node), "");
	EXPECT_DEATH(submit_cut_after_close(numa_node), "");
	EXPECT_DEATH(close_sender_twice(numa_node), "");
	EXPECT_DEATH(close_with_pending_cut(numa_node), "");
}

/** @brief Fail stop when any DATA, control, pending, or completion owner survives. */
TEST(boundary_epoch_channel, live_data_control_pending_or_completion_ownership_fails_stop_at_destruction)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	EXPECT_DEATH(destroy_live_data(numa_node), "");
	EXPECT_DEATH(destroy_unsequenced_receive(numa_node), "");
	EXPECT_DEATH(destroy_live_cut(numa_node), "");
	EXPECT_DEATH(destroy_live_ack(numa_node), "");
	EXPECT_DEATH(destroy_pending_cut(numa_node), "");
	EXPECT_DEATH(destroy_pending_ack(numa_node), "");
}

}  // namespace kinetum::dp
