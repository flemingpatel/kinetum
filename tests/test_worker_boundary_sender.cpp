// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_boundary_sender.cpp
 * @brief Exact sender sealing, ACK gating, and held-output ownership tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status.hpp"
#include "src/common/time.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/boundary_epoch_storage.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/quark/host_probe.hpp"
#include "tests/worker_telemetry_test_fixture.hpp"

namespace kinetum::dp
{
namespace
{

/** Compact worker owning the sending endpoint. */
constexpr uint32_t TEST_SENDER_WORKER = 1u;
/** Compact worker owning the receiving endpoint. */
constexpr uint32_t TEST_RECEIVER_WORKER = 2u;
/** Runtime identity shared by both boundary owners. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 7u;
/** Initial packet epoch before the ordered cut. */
constexpr uint64_t TEST_ACTIVE_EPOCH = 11u;
/** Target packet epoch after the ordered cut. */
constexpr uint64_t TEST_FUTURE_EPOCH = 13u;
/** Exact transition-command identity used by the endpoint fixtures. */
constexpr uint64_t TEST_TRANSITION_GENERATION = 5u;

static_assert(!std::is_copy_constructible_v<worker_boundary_sender>);
static_assert(!std::is_move_constructible_v<worker_boundary_sender>);

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
 * @brief Construct one exact compiled boundary.
 *
 * @param boundary_index Exact compact boundary identity.
 * @param numa_node Exact endpoint and DATA NUMA node.
 * @param data_capacity Exact DATA capacity.
 * @param hold_capacity Exact future-output capacity.
 * @return Complete compiled facts.
 */
[[nodiscard]] common::compiled_transition_boundary
boundary_facts(uint32_t boundary_index, int32_t numa_node, uint32_t data_capacity = 4u, uint32_t hold_capacity = 4u)
{
	return {
		.boundary_id = "boundary_" + std::to_string(boundary_index),
		.boundary_index = boundary_index,
		.from_stage_instance_index = static_cast<uint32_t>(5u + boundary_index * 2u),
		.to_stage_instance_index = static_cast<uint32_t>(6u + boundary_index * 2u),
		.sender_worker_index = TEST_SENDER_WORKER,
		.receiver_worker_index = TEST_RECEIVER_WORKER,
		.data_ring_capacity = data_capacity,
		.future_output_hold_capacity = hold_capacity,
		.data_ring_numa_node = numa_node,
	};
}

/** @brief Complete one-boundary ownership graph in reverse-safe member order. */
struct sender_test_owner {
	std::unique_ptr<boundary_epoch_worker_slab> sender_slab;       ///< Exact sender storage.
	std::unique_ptr<boundary_epoch_worker_slab> receiver_slab;     ///< Exact receiver storage.
	std::unique_ptr<boundary_epoch_channel> channel;	       ///< Exact transport.
	std::unique_ptr<boundary_future_output_hold> hold;	       ///< Exact held-output queue.
	std::unique_ptr<test::worker_telemetry_test_owner> telemetry;  ///< Production-shaped worker banks.
	std::unique_ptr<epoch_protocol_fault_latch> faults;	       ///< Process-generation first-fault authority.
	std::unique_ptr<worker_epoch_ledger> ledger;		       ///< Exact worker credit owner.
	std::unique_ptr<worker_boundary_sender> sender;		       ///< Sole sender policy.
	std::unique_ptr<worker_boundary_receiver> receiver;	       ///< Mirrored receiver claim owner.

	sender_test_owner() noexcept = default;
	sender_test_owner(const sender_test_owner &) = delete;
	sender_test_owner &operator=(const sender_test_owner &) = delete;
	/** Transfer complete fixture resource ownership. */
	sender_test_owner(sender_test_owner &&) noexcept = default;
	sender_test_owner &operator=(sender_test_owner &&) = delete;
	~sender_test_owner() = default;

	/** @return true when every exact owner is present. */
	[[nodiscard]] explicit operator bool() const noexcept
	{
		return sender_slab != nullptr && receiver_slab != nullptr && channel != nullptr && hold != nullptr &&
		       telemetry != nullptr && faults != nullptr && ledger != nullptr && sender != nullptr &&
		       receiver != nullptr;
	}
};

/**
 * @brief Construct one completely bound fixed-epoch sender.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 * @param data_capacity Exact DATA capacity.
 * @param hold_capacity Exact future-output capacity.
 * @return Complete owner or an empty/partial owner after recording failure.
 */
[[nodiscard]] sender_test_owner make_sender(int32_t numa_node, uint32_t data_capacity = 4u, uint32_t hold_capacity = 4u)
{
	sender_test_owner owner;
	const auto facts = boundary_facts(0u, numa_node, data_capacity, hold_capacity);
	auto sender_slab_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, numa_node, 1u, 0u);
	auto receiver_slab_or = boundary_epoch_worker_slab::create(TEST_RECEIVER_WORKER, numa_node, 0u, 1u);
	if (!sender_slab_or.is_ok() || !receiver_slab_or.is_ok()) {
		ADD_FAILURE() << (sender_slab_or.is_ok() ? receiver_slab_or.error().message() :
							   sender_slab_or.error().message());
		return owner;
	}
	owner.sender_slab = std::move(sender_slab_or).value();
	owner.receiver_slab = std::move(receiver_slab_or).value();
	auto channel_or = boundary_epoch_channel::create(facts, TEST_RUNTIME_GENERATION, *owner.sender_slab, 0u,
							 *owner.receiver_slab, 0u);
	if (!channel_or.is_ok()) {
		ADD_FAILURE() << channel_or.error().message();
		return owner;
	}
	owner.channel = std::move(channel_or).value();
	auto hold_or = boundary_future_output_hold::create(facts, numa_node);
	if (!hold_or.is_ok()) {
		ADD_FAILURE() << hold_or.error().message();
		return owner;
	}
	owner.hold = std::move(hold_or).value();
	std::array<boundary_epoch_channel *, 1> channels{owner.channel.get()};
	std::array<boundary_future_output_hold *, 1> holds{owner.hold.get()};
	auto sender_or = worker_boundary_sender::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, channels, holds);
	if (!sender_or.is_ok()) {
		ADD_FAILURE() << sender_or.error().message();
		return owner;
	}
	owner.sender = std::move(sender_or).value();
	auto receiver_or = worker_boundary_receiver::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, channels);
	if (!receiver_or.is_ok()) {
		ADD_FAILURE() << receiver_or.error().message();
		return owner;
	}
	owner.receiver = std::move(receiver_or).value();
	const auto sender_sealed = owner.sender_slab->seal();
	const auto receiver_sealed = owner.receiver_slab->seal();
	if (!sender_sealed.is_ok() || !receiver_sealed.is_ok()) {
		ADD_FAILURE() << (sender_sealed.is_ok() ? receiver_sealed.message() : sender_sealed.message());
		return owner;
	}
	auto ledger_or = worker_epoch_ledger::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, 32u);
	if (!ledger_or.is_ok()) {
		ADD_FAILURE() << ledger_or.error().message();
		return owner;
	}
	owner.ledger = std::move(ledger_or).value();
	auto telemetry_or = test::worker_telemetry_test_owner::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, {});
	if (!telemetry_or.is_ok()) {
		ADD_FAILURE() << telemetry_or.error().message();
		return owner;
	}
	owner.telemetry = std::move(telemetry_or).value();
	owner.faults = std::make_unique<epoch_protocol_fault_latch>();
	const auto bound = owner.sender->bind_ledger(*owner.ledger);
	const auto ledger_faults = owner.ledger->bind_protocol_faults(*owner.telemetry->telemetry, *owner.faults);
	const auto sender_faults = owner.sender->bind_protocol_faults(*owner.telemetry->telemetry, *owner.faults);
	if (!bound.is_ok() || !ledger_faults.is_ok() || !sender_faults.is_ok()) {
		ADD_FAILURE() << (!bound.is_ok()	 ? bound.message() :
				  !ledger_faults.is_ok() ? ledger_faults.message() :
							   sender_faults.message());
		return owner;
	}
	const uint64_t cached_time = common::update_cached_ns();
	if (cached_time == 0u) {
		ADD_FAILURE() << "test worker monotonic authority returned zero";
		return owner;
	}
	owner.telemetry->telemetry->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH, cached_time);
	owner.ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	owner.sender->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	return owner;
}

/**
 * @brief Drain an exact DATA population and complete every sequence.
 *
 * @param channel Exact channel to drain.
 * @param expected_count Exact number of records expected.
 */
void drain_data(boundary_epoch_channel &channel, std::size_t expected_count)
{
	for (std::size_t index = 0u; index < expected_count; ++index) {
		packet_record *record = nullptr;
		ASSERT_EQ(channel.try_receive_data(record), boundary_data_receive_result::RECEIVED);
		ASSERT_NE(record, nullptr);
		channel.complete_data_receive(record);
	}
	packet_record *extra = nullptr;
	EXPECT_EQ(channel.try_receive_data(extra), boundary_data_receive_result::EMPTY);
}

/**
 * @brief Bind one future slot, begin exact sender policy, and close old source admission.
 *
 * @param owner Complete one-boundary owner.
 */
void begin_transition(sender_test_owner &owner)
{
	ASSERT_TRUE(owner.ledger->preflight_begin_transition(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	ASSERT_TRUE(owner.sender->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							     TEST_FUTURE_EPOCH));
	owner.ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(owner.sender->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							     TEST_FUTURE_EPOCH));
	ASSERT_TRUE(owner.sender->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	EXPECT_FALSE(owner.sender->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	owner.ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
}

/**
 * @brief Consume one exact CUT and return it.
 *
 * @param channel Exact boundary channel.
 * @return Exact consumed CUT.
 */
[[nodiscard]] boundary_epoch_cut consume_cut(boundary_epoch_channel &channel)
{
	boundary_epoch_cut cut{};
	EXPECT_TRUE(channel.try_receive_cut(cut));
	return cut;
}

/**
 * @brief Publish and consume one matching ACK, opening the sender gate.
 *
 * @param owner Complete active-transition owner.
 * @param cut Exact already consumed CUT.
 */
void acknowledge(sender_test_owner &owner, const boundary_epoch_cut &cut)
{
	ASSERT_TRUE(owner.ledger->preflight_promote_future_epoch(TEST_FUTURE_EPOCH).is_ok());
	owner.ledger->promote_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_EQ(owner.channel->submit_ack({cut.next_epoch, cut.data_cut_sequence}),
		  boundary_control_publication_result::PUBLISHED);
	owner.sender->service_control();
	EXPECT_EQ(owner.sender->phase(0u), boundary_epoch_sender_phase::OPEN);
	EXPECT_EQ(owner.sender->open_epoch(0u), TEST_FUTURE_EPOCH);
}

/**
 * @brief Fail stop when old DATA reaches a sender after exact sealing.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void send_old_after_seal(int32_t numa_node)
{
	auto owner = make_sender(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition(owner);
	if (!owner.sender->try_seal_after_old_work_drained()) {
		std::_Exit(EXIT_SUCCESS);
	}
	packet_record record{};
	record.metadata.epoch = TEST_ACTIVE_EPOCH;
	owner.ledger->acquire(TEST_ACTIVE_EPOCH);
	(void)owner.sender->try_send(0u, &record);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Fail stop when an unrelated epoch reaches one active sender generation.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void send_unrelated_epoch(int32_t numa_node)
{
	auto owner = make_sender(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition(owner);
	packet_record record{};
	record.metadata.epoch = TEST_FUTURE_EPOCH + 1u;
	(void)owner.sender->try_send(0u, &record);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Fail stop when ACK identity is not byte-exact.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void consume_mismatched_ack(int32_t numa_node)
{
	auto owner = make_sender(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition(owner);
	if (!owner.sender->try_seal_after_old_work_drained()) {
		std::_Exit(EXIT_SUCCESS);
	}
	const auto cut = consume_cut(*owner.channel);
	if (owner.channel->submit_ack({cut.next_epoch, cut.data_cut_sequence + 1u}) !=
	    boundary_control_publication_result::PUBLISHED) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.sender->service_control();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Fail stop when a competing sender generation overlaps.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void begin_overlapping_transition(int32_t numa_node)
{
	auto owner = make_sender(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition(owner);
	(void)owner.sender->begin_transition(TEST_TRANSITION_GENERATION + 1u, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Fail stop when sender policy is destroyed during an active generation.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_active_sender(int32_t numa_node)
{
	auto owner = make_sender(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition(owner);
}

/**
 * @brief Fail stop when a caller exceeds the permanent owner-turn work bound.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void service_oversized_hold_budget(int32_t numa_node)
{
	auto owner = make_sender(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition(owner);
	(void)owner.sender->service_held_output(
		static_cast<std::size_t>(common::runtime_sizing::PACKET_MAX_BURST_SIZE) + 1u);
	std::_Exit(EXIT_SUCCESS);
}

/** @brief Prove exact layout, binding, identity, and sender-NUMA placement. */
TEST(worker_boundary_sender, policy_state_is_cacheline_exact_and_sender_numa_local)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node);
	ASSERT_TRUE(owner);
	auto foreign_owner = make_sender(numa_node);
	ASSERT_TRUE(foreign_owner);
	EXPECT_TRUE(owner.sender->owns_ledger(*owner.ledger));
	EXPECT_TRUE(owner.sender->owns_boundary_channel(0u, *owner.channel));
	EXPECT_FALSE(owner.sender->owns_boundary_channel(0u, *foreign_owner.channel));
	EXPECT_EQ(owner.sender->size(), 1u);
	EXPECT_EQ(owner.sender->worker_index(), TEST_SENDER_WORKER);
	EXPECT_EQ(owner.sender->runtime_generation(), TEST_RUNTIME_GENERATION);
	EXPECT_EQ(owner.sender->boundary_index(0u), 0u);
	EXPECT_EQ(owner.sender->policy_numa_node(0u), numa_node);
	EXPECT_EQ(owner.sender->phase(0u), boundary_epoch_sender_phase::OPEN);
	EXPECT_EQ(owner.sender->open_epoch(0u), TEST_ACTIVE_EPOCH);
	EXPECT_FALSE(owner.sender->transition_active());
	EXPECT_TRUE(owner.sender->packet_ownership_empty());
	EXPECT_TRUE(owner.channel->control_empty());
	const boundary_epoch_ack stale_ack{TEST_FUTURE_EPOCH, 0u};
	ASSERT_EQ(owner.channel->submit_ack(stale_ack), boundary_control_publication_result::PUBLISHED);
	EXPECT_FALSE(owner.sender->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							      TEST_FUTURE_EPOCH));
	boundary_epoch_ack retained_ack{};
	ASSERT_TRUE(owner.channel->try_receive_ack(retained_ack));
	EXPECT_EQ(retained_ack, stale_ack);
	boundary_sender_transition_snapshot baseline{};
	ASSERT_EQ(owner.sender->try_read_transition(0u, baseline), publication_read_result::AVAILABLE);
	EXPECT_EQ(baseline.publication_generation, 1u);
	EXPECT_EQ(baseline.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(baseline.boundary_index, 0u);
	EXPECT_EQ(baseline.transition_generation, 0u);
	EXPECT_EQ(baseline.from_epoch, 0u);
	EXPECT_EQ(baseline.to_epoch, TEST_ACTIVE_EPOCH);
	EXPECT_EQ(baseline.cut_sequence, 0u);
	EXPECT_EQ(baseline.ack_observed, 0u);
}

/** @brief Preserve fixed OPEN transfer and sequence-before-credit retirement. */
TEST(worker_boundary_sender, fixed_open_path_preserves_sequence_before_credit_retirement)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node, 2u);
	ASSERT_TRUE(owner);
	std::array<packet_record, 3> records{};
	for (auto &record : records) {
		record.metadata.epoch = TEST_ACTIVE_EPOCH;
		owner.ledger->acquire(TEST_ACTIVE_EPOCH);
	}
	EXPECT_EQ(owner.sender->try_send(0u, &records[0]), boundary_epoch_send_result::TRANSFERRED);
	EXPECT_EQ(owner.sender->try_send(0u, &records[1]), boundary_epoch_send_result::TRANSFERRED);
	EXPECT_EQ(owner.sender->try_send(0u, &records[2]), boundary_epoch_send_result::BACKPRESSURED);
	EXPECT_EQ(owner.channel->data_enqueued_sequence(), 2u);
	owner.ledger->publish();
	worker_epoch_ledger_snapshot observation{};
	ASSERT_EQ(owner.ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_unretired, 1u);
	drain_data(*owner.channel, 2u);
	EXPECT_EQ(owner.sender->try_send(0u, &records[2]), boundary_epoch_send_result::TRANSFERRED);
	EXPECT_EQ(owner.channel->data_enqueued_sequence(), 3u);
	owner.ledger->publish();
	ASSERT_EQ(owner.ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.active_unretired, 0u);
	drain_data(*owner.channel, 1u);
}

/** @brief Hold future output until one byte-exact ACK and retire only on release. */
TEST(worker_boundary_sender, future_output_is_held_until_exact_ack)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node);
	ASSERT_TRUE(owner);
	begin_transition(owner);
	packet_record record{};
	record.metadata.epoch = TEST_FUTURE_EPOCH;
	owner.ledger->acquire(TEST_FUTURE_EPOCH);
	EXPECT_EQ(owner.sender->try_send(0u, &record), boundary_epoch_send_result::HELD);
	EXPECT_EQ(owner.sender->held_size(0u), 1u);
	EXPECT_EQ(owner.channel->data_enqueued_sequence(), 0u);
	ASSERT_TRUE(owner.sender->try_seal_after_old_work_drained());
	EXPECT_TRUE(owner.sender->outbound_sealed());
	EXPECT_TRUE(owner.sender->all_cuts_published());
	const auto cut = consume_cut(*owner.channel);
	EXPECT_EQ(cut, (boundary_epoch_cut{TEST_FUTURE_EPOCH, 0u}));
	acknowledge(owner, cut);
	boundary_sender_transition_snapshot completed{};
	ASSERT_EQ(owner.sender->try_read_transition(0u, completed), publication_read_result::AVAILABLE);
	EXPECT_EQ(completed.publication_generation, 4u);
	EXPECT_EQ(completed.transition_generation, TEST_TRANSITION_GENERATION);
	EXPECT_EQ(completed.from_epoch, TEST_ACTIVE_EPOCH);
	EXPECT_EQ(completed.to_epoch, TEST_FUTURE_EPOCH);
	EXPECT_EQ(completed.cut_sequence, cut.data_cut_sequence);
	EXPECT_EQ(completed.ack_observed, 1u);
	EXPECT_NE(completed.cut_published_monotonic_ns, 0u);
	EXPECT_GE(completed.ack_observed_monotonic_ns, completed.cut_published_monotonic_ns);
	EXPECT_EQ(owner.sender->service_held_output(1u), 1u);
	EXPECT_EQ(owner.sender->held_size(0u), 0u);
	EXPECT_EQ(owner.channel->data_enqueued_sequence(), 1u);
	owner.ledger->publish();
	worker_epoch_ledger_snapshot observation{};
	ASSERT_EQ(owner.ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.future_unretired, 0u);
	owner.sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
	drain_data(*owner.channel, 1u);
}

/** @brief Preserve full-hold ownership and spend the complete release budget. */
TEST(worker_boundary_sender, full_hold_preserves_pointer_reservation_and_credit)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node, 4u, 2u);
	ASSERT_TRUE(owner);
	begin_transition(owner);
	std::array<packet_record, 3> records{};
	for (auto &record : records) {
		record.metadata.epoch = TEST_FUTURE_EPOCH;
		owner.ledger->acquire(TEST_FUTURE_EPOCH);
	}
	EXPECT_EQ(owner.sender->try_send(0u, &records[0]), boundary_epoch_send_result::HELD);
	EXPECT_EQ(owner.sender->try_send(0u, &records[1]), boundary_epoch_send_result::HELD);
	EXPECT_EQ(owner.sender->try_send(0u, &records[2]), boundary_epoch_send_result::BACKPRESSURED);
	EXPECT_EQ(owner.sender->held_size(0u), 2u);
	owner.ledger->publish();
	worker_epoch_ledger_snapshot observation{};
	ASSERT_EQ(owner.ledger->try_read(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.future_unretired, 3u);
	ASSERT_TRUE(owner.sender->try_seal_after_old_work_drained());
	const auto cut = consume_cut(*owner.channel);
	acknowledge(owner, cut);
	EXPECT_EQ(owner.sender->service_held_output(1u), 1u);
	EXPECT_EQ(owner.sender->try_send(0u, &records[2]), boundary_epoch_send_result::BACKPRESSURED);
	EXPECT_EQ(owner.sender->service_held_output(2u), 1u);
	EXPECT_EQ(owner.sender->try_send(0u, &records[2]), boundary_epoch_send_result::TRANSFERRED);
	EXPECT_EQ(owner.sender->service_held_output(2u), 0u);
	EXPECT_TRUE(owner.sender->packet_ownership_empty());
	owner.sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
	drain_data(*owner.channel, 3u);
}

/** @brief Require target source admission and zero old credit before exact cut capture. */
TEST(worker_boundary_sender, old_credit_prevents_cut_and_zero_captures_every_exact_sequence)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node);
	ASSERT_TRUE(owner);
	owner.ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(owner.sender->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	EXPECT_FALSE(owner.sender->try_seal_after_old_work_drained());
	EXPECT_EQ(owner.sender->phase(0u), boundary_epoch_sender_phase::DRAINING);
	owner.ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
	packet_record old_record{};
	old_record.metadata.epoch = TEST_ACTIVE_EPOCH;
	owner.ledger->acquire(TEST_ACTIVE_EPOCH);
	EXPECT_FALSE(owner.sender->try_seal_after_old_work_drained());
	EXPECT_EQ(owner.sender->phase(0u), boundary_epoch_sender_phase::DRAINING);
	EXPECT_EQ(owner.sender->cut_sequence(0u), 0u);
	EXPECT_EQ(owner.sender->try_send(0u, &old_record), boundary_epoch_send_result::TRANSFERRED);
	EXPECT_TRUE(owner.sender->try_seal_after_old_work_drained());
	EXPECT_EQ(owner.sender->cut_sequence(0u), 1u);
	EXPECT_EQ(owner.sender->phase(0u), boundary_epoch_sender_phase::WAITING_ACK);
	const auto cut = consume_cut(*owner.channel);
	EXPECT_EQ(cut, (boundary_epoch_cut{TEST_FUTURE_EPOCH, 1u}));
	acknowledge(owner, cut);
	owner.sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
	drain_data(*owner.channel, 1u);
}

/** @brief Accept exact duplicate ACK only and count it without monotonic inference. */
TEST(worker_boundary_sender, exact_duplicate_ack_is_idempotent_and_counted)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node);
	ASSERT_TRUE(owner);
	begin_transition(owner);
	ASSERT_TRUE(owner.sender->try_seal_after_old_work_drained());
	const auto cut = consume_cut(*owner.channel);
	ASSERT_TRUE(owner.ledger->preflight_promote_future_epoch(TEST_FUTURE_EPOCH).is_ok());
	owner.ledger->promote_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_EQ(owner.channel->submit_ack({cut.next_epoch, cut.data_cut_sequence}),
		  boundary_control_publication_result::PUBLISHED);
	ASSERT_EQ(owner.channel->submit_ack({cut.next_epoch, cut.data_cut_sequence}),
		  boundary_control_publication_result::PUBLISHED);
	owner.sender->service_control();
	owner.sender->service_control();
	EXPECT_EQ(owner.sender->duplicate_ack_count(0u), 1u);
	EXPECT_TRUE(owner.sender->all_gates_open());
	boundary_sender_transition_snapshot publication{};
	ASSERT_EQ(owner.sender->try_read_transition(0u, publication), publication_read_result::AVAILABLE);
	EXPECT_EQ(publication.publication_generation, 5u);
	EXPECT_EQ(publication.ack_observed, 1u);
	owner.sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
}

/** @brief Retain and publish one exact pending CUT under full control pressure. */
TEST(worker_boundary_sender, cut_pressure_retains_one_exact_pending_publication_without_spin)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node);
	ASSERT_TRUE(owner);
	begin_transition(owner);

	const boundary_epoch_cut first_filler{TEST_FUTURE_EPOCH + 2u, 1u};
	const boundary_epoch_cut second_filler{TEST_FUTURE_EPOCH + 4u, 2u};
	ASSERT_EQ(owner.channel->submit_cut(first_filler), boundary_control_publication_result::PUBLISHED);
	ASSERT_EQ(owner.channel->submit_cut(second_filler), boundary_control_publication_result::PUBLISHED);

	ASSERT_TRUE(owner.sender->try_seal_after_old_work_drained());
	EXPECT_EQ(owner.sender->phase(0u), boundary_epoch_sender_phase::CUT_PENDING);
	EXPECT_TRUE(owner.sender->outbound_sealed());
	EXPECT_FALSE(owner.sender->all_cuts_published());
	EXPECT_TRUE(owner.channel->has_pending_cut());
	owner.sender->publish_transport();
	boundary_sender_transport_snapshot observation{};
	ASSERT_EQ(owner.channel->try_read_sender_transport(observation), publication_read_result::AVAILABLE);
	EXPECT_EQ(observation.pending_cut_epoch, TEST_FUTURE_EPOCH);
	EXPECT_EQ(observation.pending_cut_sequence, 0u);

	EXPECT_EQ(consume_cut(*owner.channel), first_filler);
	owner.sender->service_control();
	EXPECT_EQ(owner.sender->phase(0u), boundary_epoch_sender_phase::WAITING_ACK);
	EXPECT_TRUE(owner.sender->all_cuts_published());
	EXPECT_FALSE(owner.channel->has_pending_cut());
	EXPECT_EQ(consume_cut(*owner.channel), second_filler);
	const auto exact_cut = consume_cut(*owner.channel);
	EXPECT_EQ(exact_cut, (boundary_epoch_cut{TEST_FUTURE_EPOCH, 0u}));
	acknowledge(owner, exact_cut);
	owner.sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
	EXPECT_TRUE(owner.channel->control_empty());
}

/** @brief Continue ACK progress while full DATA retains held future ownership. */
TEST(worker_boundary_sender, data_pressure_preserves_held_ownership_and_control_progress)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_sender(numa_node, 2u, 4u);
	ASSERT_TRUE(owner);
	begin_transition(owner);
	std::array<packet_record, 3> records{};
	for (auto &record : records) {
		record.metadata.epoch = TEST_FUTURE_EPOCH;
		owner.ledger->acquire(TEST_FUTURE_EPOCH);
		ASSERT_EQ(owner.sender->try_send(0u, &record), boundary_epoch_send_result::HELD);
	}
	ASSERT_TRUE(owner.sender->try_seal_after_old_work_drained());
	const auto cut = consume_cut(*owner.channel);
	acknowledge(owner, cut);
	EXPECT_EQ(owner.sender->service_held_output(1u), 1u);
	EXPECT_EQ(owner.sender->service_held_output(1u), 1u);
	EXPECT_EQ(owner.sender->service_held_output(1u), 0u);
	EXPECT_EQ(owner.sender->held_size(0u), 1u);
	ASSERT_EQ(owner.channel->submit_ack({cut.next_epoch, cut.data_cut_sequence}),
		  boundary_control_publication_result::PUBLISHED);
	owner.sender->service_control();
	EXPECT_EQ(owner.sender->duplicate_ack_count(0u), 1u);
	drain_data(*owner.channel, 2u);
	EXPECT_EQ(owner.sender->service_held_output(1u), 1u);
	owner.sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
	drain_data(*owner.channel, 1u);
}

/** @brief Seal every edge atomically and release held work in bounded round-robin order. */
TEST(worker_boundary_sender, multiboundary_seal_and_hold_service_are_all_or_none_and_round_robin)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	const auto first_facts = boundary_facts(0u, numa_node);
	const auto second_facts = boundary_facts(1u, numa_node);
	auto sender_slab_or = boundary_epoch_worker_slab::create(TEST_SENDER_WORKER, numa_node, 2u, 0u);
	auto receiver_slab_or = boundary_epoch_worker_slab::create(TEST_RECEIVER_WORKER, numa_node, 0u, 2u);
	ASSERT_TRUE(sender_slab_or.is_ok()) << sender_slab_or.error().message();
	ASSERT_TRUE(receiver_slab_or.is_ok()) << receiver_slab_or.error().message();
	auto sender_slab = std::move(sender_slab_or).value();
	auto receiver_slab = std::move(receiver_slab_or).value();

	std::vector<std::unique_ptr<boundary_epoch_channel>> channel_owners;
	std::vector<std::unique_ptr<boundary_future_output_hold>> hold_owners;
	std::vector<boundary_epoch_channel *> channels;
	std::vector<boundary_future_output_hold *> holds;
	for (std::size_t index = 0u; index < 2u; ++index) {
		const auto &facts = index == 0u ? first_facts : second_facts;
		auto channel_or = boundary_epoch_channel::create(facts, TEST_RUNTIME_GENERATION, *sender_slab, index,
								 *receiver_slab, index);
		auto hold_or = boundary_future_output_hold::create(facts, numa_node);
		ASSERT_TRUE(channel_or.is_ok()) << channel_or.error().message();
		ASSERT_TRUE(hold_or.is_ok()) << hold_or.error().message();
		channels.push_back(channel_or->get());
		holds.push_back(hold_or->get());
		channel_owners.push_back(std::move(channel_or).value());
		hold_owners.push_back(std::move(hold_or).value());
	}
	auto ledger_or = worker_epoch_ledger::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, 32u);
	ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
	auto ledger = std::move(ledger_or).value();
	auto sender_or = worker_boundary_sender::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, channels, holds);
	ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
	auto sender = std::move(sender_or).value();
	auto receiver_or = worker_boundary_receiver::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, channels);
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto receiver = std::move(receiver_or).value();
	ASSERT_TRUE(sender_slab->seal().is_ok());
	ASSERT_TRUE(receiver_slab->seal().is_ok());
	ASSERT_TRUE(sender->bind_ledger(*ledger).is_ok());
	ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	sender->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(sender->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	ledger->advance_source_epoch(TEST_FUTURE_EPOCH);

	packet_record old_record{};
	old_record.metadata.epoch = TEST_ACTIVE_EPOCH;
	ledger->acquire(TEST_ACTIVE_EPOCH);
	ASSERT_EQ(sender->try_send(0u, &old_record), boundary_epoch_send_result::TRANSFERRED);
	ledger->acquire(TEST_ACTIVE_EPOCH);
	EXPECT_FALSE(sender->try_seal_after_old_work_drained());
	EXPECT_EQ(sender->phase(0u), boundary_epoch_sender_phase::DRAINING);
	EXPECT_EQ(sender->phase(1u), boundary_epoch_sender_phase::DRAINING);
	EXPECT_EQ(sender->cut_sequence(0u), 0u);
	EXPECT_EQ(sender->cut_sequence(1u), 0u);
	ledger->retire(TEST_ACTIVE_EPOCH);

	std::array<packet_record, 2> future_records{};
	for (std::size_t index = 0u; index < future_records.size(); ++index) {
		future_records[index].metadata.epoch = TEST_FUTURE_EPOCH;
		ledger->acquire(TEST_FUTURE_EPOCH);
		ASSERT_EQ(sender->try_send(static_cast<uint32_t>(index), &future_records[index]),
			  boundary_epoch_send_result::HELD);
	}
	ASSERT_TRUE(sender->try_seal_after_old_work_drained());
	EXPECT_EQ(sender->cut_sequence(0u), 1u);
	EXPECT_EQ(sender->cut_sequence(1u), 0u);
	for (std::size_t index = 0u; index < channels.size(); ++index) {
		const auto cut = consume_cut(*channels[index]);
		EXPECT_EQ(cut.data_cut_sequence, index == 0u ? 1u : 0u);
		ASSERT_EQ(channels[index]->submit_ack({cut.next_epoch, cut.data_cut_sequence}),
			  boundary_control_publication_result::PUBLISHED);
	}
	ASSERT_TRUE(ledger->preflight_promote_future_epoch(TEST_FUTURE_EPOCH).is_ok());
	ledger->promote_future_epoch(TEST_FUTURE_EPOCH);
	sender->service_control();
	EXPECT_TRUE(sender->all_gates_open());
	EXPECT_EQ(sender->service_held_output(1u), 1u);
	EXPECT_EQ(channels[0]->data_enqueued_sequence(), 2u);
	EXPECT_EQ(channels[1]->data_enqueued_sequence(), 0u);
	EXPECT_EQ(sender->service_held_output(1u), 1u);
	EXPECT_EQ(channels[1]->data_enqueued_sequence(), 1u);
	sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
	drain_data(*channels[0], 2u);
	drain_data(*channels[1], 1u);
}

/** @brief Fail stop on wrong epochs, ACK mismatch, overlap, and active teardown. */
TEST(worker_boundary_sender, exactness_and_live_lifetime_violations_fail_stop)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	EXPECT_DEATH(send_old_after_seal(numa_node), "");
	EXPECT_DEATH(send_unrelated_epoch(numa_node), "");
	EXPECT_DEATH(consume_mismatched_ack(numa_node), "");
	EXPECT_DEATH(begin_overlapping_transition(numa_node), "");
	EXPECT_DEATH(destroy_active_sender(numa_node), "");
	EXPECT_DEATH(service_oversized_hold_budget(numa_node), "");
}

}  // namespace
}  // namespace kinetum::dp
