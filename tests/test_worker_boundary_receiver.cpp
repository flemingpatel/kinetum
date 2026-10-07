// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_boundary_receiver.cpp
 * @brief Exact CUT drain, fan-in, activation ACK, and receiver-lifetime tests.
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

#include "src/common/status.hpp"
#include "src/common/time.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/boundary_epoch_storage.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "src/dp/epoch/worker_epoch_activation.hpp"
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

static_assert(!std::is_copy_constructible_v<worker_boundary_receiver>);
static_assert(!std::is_move_constructible_v<worker_boundary_receiver>);

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
 * @return Complete compiled facts.
 */
[[nodiscard]] common::compiled_transition_boundary boundary_facts(uint32_t boundary_index, int32_t numa_node)
{
	return {
		.boundary_id = "boundary_" + std::to_string(boundary_index),
		.boundary_index = boundary_index,
		.from_stage_instance_index = static_cast<uint32_t>(5u + boundary_index * 2u),
		.to_stage_instance_index = static_cast<uint32_t>(6u + boundary_index * 2u),
		.sender_worker_index = TEST_SENDER_WORKER,
		.receiver_worker_index = TEST_RECEIVER_WORKER,
		.data_ring_capacity = 4u,
		.future_output_hold_capacity = 4u,
		.data_ring_numa_node = numa_node,
	};
}

/** @brief Complete one-boundary receiver ownership graph in reverse-safe order. */
struct receiver_test_owner {
	std::unique_ptr<boundary_epoch_worker_slab> sender_slab;       ///< Exact sender storage.
	std::unique_ptr<boundary_epoch_worker_slab> receiver_slab;     ///< Exact receiver storage.
	std::unique_ptr<boundary_epoch_channel> channel;	       ///< Exact transport owner.
	std::unique_ptr<boundary_future_output_hold> hold;	       ///< Required sender hold owner.
	std::unique_ptr<test::worker_telemetry_test_owner> telemetry;  ///< Production-shaped telemetry banks.
	std::unique_ptr<epoch_protocol_fault_latch> faults;	       ///< Process-generation first-fault authority.
	std::unique_ptr<worker_epoch_ledger> sender_ledger;	       ///< Exact sender credit owner.
	std::unique_ptr<worker_epoch_ledger> ledger;		       ///< Exact receiver credit owner.
	std::unique_ptr<worker_boundary_sender> sender_claim;	       ///< Mirrored sender-policy claim.
	std::unique_ptr<worker_boundary_receiver> receiver;	       ///< Sole receiver policy.
	std::unique_ptr<worker_epoch_activation> activation;	       ///< Exact local activation order.

	receiver_test_owner() noexcept = default;
	receiver_test_owner(const receiver_test_owner &) = delete;
	receiver_test_owner &operator=(const receiver_test_owner &) = delete;
	/** Transfer complete fixture resource ownership. */
	receiver_test_owner(receiver_test_owner &&) noexcept = default;
	receiver_test_owner &operator=(receiver_test_owner &&) = delete;
	~receiver_test_owner() = default;

	/** @return true when every exact owner is present. */
	[[nodiscard]] explicit operator bool() const noexcept
	{
		return sender_slab != nullptr && receiver_slab != nullptr && channel != nullptr && hold != nullptr &&
		       telemetry != nullptr && faults != nullptr && sender_claim != nullptr &&
		       sender_ledger != nullptr && ledger != nullptr && receiver != nullptr && activation != nullptr;
	}
};

/**
 * @brief Construct one completely bound fixed-epoch receiver.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 * @return Complete owner or a partial owner after recording failure.
 */
[[nodiscard]] receiver_test_owner make_receiver(int32_t numa_node)
{
	receiver_test_owner owner;
	const auto facts = boundary_facts(0u, numa_node);
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
	auto receiver_or = worker_boundary_receiver::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, channels);
	if (!sender_or.is_ok() || !receiver_or.is_ok()) {
		ADD_FAILURE() << (sender_or.is_ok() ? receiver_or.error().message() : sender_or.error().message());
		return owner;
	}
	owner.sender_claim = std::move(sender_or).value();
	owner.receiver = std::move(receiver_or).value();
	const auto sender_sealed = owner.sender_slab->seal();
	const auto receiver_sealed = owner.receiver_slab->seal();
	if (!sender_sealed.is_ok() || !receiver_sealed.is_ok()) {
		ADD_FAILURE() << (sender_sealed.is_ok() ? receiver_sealed.message() : sender_sealed.message());
		return owner;
	}
	auto sender_ledger_or = worker_epoch_ledger::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, 32u);
	auto ledger_or = worker_epoch_ledger::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, 32u);
	if (!sender_ledger_or.is_ok() || !ledger_or.is_ok()) {
		ADD_FAILURE() << (sender_ledger_or.is_ok() ? ledger_or.error().message() :
							     sender_ledger_or.error().message());
		return owner;
	}
	owner.sender_ledger = std::move(sender_ledger_or).value();
	owner.ledger = std::move(ledger_or).value();
	auto telemetry_or =
		test::worker_telemetry_test_owner::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, {});
	if (!telemetry_or.is_ok()) {
		ADD_FAILURE() << telemetry_or.error().message();
		return owner;
	}
	owner.telemetry = std::move(telemetry_or).value();
	owner.faults = std::make_unique<epoch_protocol_fault_latch>();
	const auto sender_bound = owner.sender_claim->bind_ledger(*owner.sender_ledger);
	const auto bound = owner.receiver->bind_ledger(*owner.ledger);
	const auto ledger_faults = owner.ledger->bind_protocol_faults(*owner.telemetry->telemetry, *owner.faults);
	const auto receiver_faults = owner.receiver->bind_protocol_faults(*owner.telemetry->telemetry, *owner.faults);
	if (!sender_bound.is_ok() || !bound.is_ok() || !ledger_faults.is_ok() || !receiver_faults.is_ok()) {
		ADD_FAILURE() << (!sender_bound.is_ok()	 ? sender_bound.message() :
				  !bound.is_ok()	 ? bound.message() :
				  !ledger_faults.is_ok() ? ledger_faults.message() :
							   receiver_faults.message());
		return owner;
	}
	if (common::update_cached_ns() == 0u) {
		ADD_FAILURE() << "test worker monotonic authority returned zero";
		return owner;
	}
	owner.sender_ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	owner.ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	owner.sender_claim->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	owner.receiver->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	std::array<module::module_epoch_store *, 0> no_modules{};
	std::array<packet_epoch_input_staging *, 0> no_staging{};
	auto activation_or = worker_epoch_activation::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, no_modules,
							     no_staging, *owner.ledger, nullptr, nullptr,
							     *owner.telemetry->telemetry);
	if (!activation_or.is_ok()) {
		ADD_FAILURE() << activation_or.error().message();
		return owner;
	}
	owner.activation = std::move(activation_or).value();
	owner.telemetry->telemetry->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH, 1u);
	owner.activation->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	return owner;
}

/**
 * @brief Bind one exact future slot and close old source admission.
 *
 * @param owner Complete receiver owner.
 */
void begin_transition(receiver_test_owner &owner)
{
	ASSERT_TRUE(owner.telemetry->telemetry->reserve_target_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).is_ok());
	ASSERT_TRUE(owner.ledger->preflight_begin_transition(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	ASSERT_TRUE(owner.receiver->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							       TEST_FUTURE_EPOCH));
	owner.ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(owner.receiver->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							       TEST_FUTURE_EPOCH));
	ASSERT_TRUE(owner.receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	EXPECT_FALSE(
		owner.receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	owner.ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
}

/**
 * @brief Merge and reclaim the component test's exact old worker banks.
 * @param owner Fixture retaining the receiver's telemetry bank and return channel.
 */
void complete_telemetry_transition(receiver_test_owner &owner)
{
	runtime_telemetry_bank_token token{};
	while (owner.telemetry->channel->take_completed(token)) {
		ASSERT_EQ(token.owner_kind, runtime_telemetry_bank_owner_kind::WORKER);
		ASSERT_TRUE(owner.telemetry->telemetry->completed_bank(token).is_ok());
		owner.telemetry->telemetry->complete_aggregation(token);
	}
	owner.telemetry->telemetry->mark_epoch_aggregated(TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(owner.telemetry->telemetry->epoch_aggregated(TEST_ACTIVE_EPOCH));
	ASSERT_TRUE(owner.telemetry->telemetry->retire_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).has_value());
	while (owner.telemetry->channel->take_returned(token)) {
		owner.telemetry->telemetry->accept_returned(token);
	}
}

/**
 * @brief Begin one death-test generation without a nonfatal assertion escape.
 *
 * @param owner Complete receiver owner.
 */
void begin_transition_for_death(receiver_test_owner &owner)
{
	owner.ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	if (!owner.receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH)) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
}

/**
 * @brief Drain one exact DATA pointer through the production completion order.
 *
 * @param owner Complete receiver owner.
 * @param record Exact record already channel-owned.
 * @param retire Whether to retire local work immediately.
 */
void receive_data(receiver_test_owner &owner, packet_record &record, bool retire)
{
	packet_record *received = nullptr;
	ASSERT_EQ(owner.channel->try_receive_data(received), boundary_data_receive_result::RECEIVED);
	ASSERT_EQ(received, &record);
	owner.ledger->acquire(record.metadata.epoch);
	owner.channel->complete_data_receive(received);
	if (retire) {
		owner.ledger->retire(record.metadata.epoch);
	}
}

/**
 * @brief Complete one exact activation/ACK exchange and clean control storage.
 *
 * @param owner Complete active-transition receiver owner.
 */
void activate_and_acknowledge(receiver_test_owner &owner)
{
	owner.receiver->refresh_cut_progress();
	ASSERT_TRUE(owner.activation->activate(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH, 1u)
			    .is_ok());
	complete_telemetry_transition(owner);
	owner.receiver->acknowledge_activation(TEST_TRANSITION_GENERATION, TEST_FUTURE_EPOCH);
	ASSERT_TRUE(owner.receiver->all_acks_published());
	boundary_epoch_ack ack{};
	ASSERT_TRUE(owner.channel->try_receive_ack(ack));
	EXPECT_EQ(ack, (boundary_epoch_ack{TEST_FUTURE_EPOCH, owner.receiver->accepted_cut(0u).data_cut_sequence}));
	owner.receiver->complete_receiver_transition(TEST_TRANSITION_GENERATION);
}

/**
 * @brief Observe one duplicate-different CUT and require fail-stop.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void receive_conflicting_cut(int32_t numa_node)
{
	auto owner = make_receiver(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition_for_death(owner);
	if (owner.channel->submit_cut({TEST_FUTURE_EPOCH, 0u}) != boundary_control_publication_result::PUBLISHED) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.receiver->service_control();
	if (owner.channel->submit_cut({TEST_FUTURE_EPOCH, 1u}) != boundary_control_publication_result::PUBLISHED) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.receiver->service_control();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Observe one stale, skipped, or unrelated target CUT and require fail-stop.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 * @param next_epoch Wrong but individually valid CUT epoch.
 */
void receive_wrong_epoch_cut(int32_t numa_node, uint64_t next_epoch)
{
	auto owner = make_receiver(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition_for_death(owner);
	if (owner.channel->submit_cut({next_epoch, 0u}) != boundary_control_publication_result::PUBLISHED) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.receiver->service_control();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Bind behind one already queued wrong-epoch CUT and require fail-stop.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 * @param next_epoch Wrong but individually valid CUT epoch.
 */
void receive_prearrived_wrong_epoch_cut(int32_t numa_node, uint64_t next_epoch)
{
	auto owner = make_receiver(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	if (owner.channel->submit_cut({next_epoch, 0u}) != boundary_control_publication_result::PUBLISHED) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	if (!owner.receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH)) {
		std::_Exit(EXIT_SUCCESS);
	}
	owner.ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
	owner.receiver->service_control();
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Attempt ACK publication before CUT drain and activation.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void acknowledge_before_activation(int32_t numa_node)
{
	auto owner = make_receiver(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition_for_death(owner);
	owner.receiver->acknowledge_activation(TEST_TRANSITION_GENERATION, TEST_FUTURE_EPOCH);
	std::_Exit(EXIT_SUCCESS);
}

/**
 * @brief Destroy one receiver while a generation remains active.
 *
 * @param numa_node Exact endpoint and DATA NUMA node.
 */
void destroy_active_receiver(int32_t numa_node)
{
	auto owner = make_receiver(numa_node);
	if (!owner) {
		std::_Exit(EXIT_SUCCESS);
	}
	begin_transition_for_death(owner);
}

/** @brief Prove fixed binding, receiver-NUMA placement, and untrusted early CUT admission. */
TEST(worker_boundary_receiver, policy_state_is_cacheline_exact_and_receiver_numa_local)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_receiver(numa_node);
	ASSERT_TRUE(owner);
	auto foreign_owner = make_receiver(numa_node);
	ASSERT_TRUE(foreign_owner);
	EXPECT_TRUE(owner.receiver->owns_ledger(*owner.ledger));
	EXPECT_TRUE(owner.receiver->owns_boundary_channel(0u, *owner.channel));
	EXPECT_FALSE(owner.receiver->owns_boundary_channel(0u, *foreign_owner.channel));
	EXPECT_EQ(owner.receiver->size(), 1u);
	EXPECT_EQ(owner.receiver->worker_index(), TEST_RECEIVER_WORKER);
	EXPECT_EQ(owner.receiver->runtime_generation(), TEST_RUNTIME_GENERATION);
	EXPECT_EQ(owner.receiver->boundary_index(0u), 0u);
	EXPECT_EQ(owner.receiver->policy_numa_node(0u), numa_node);
	EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::OPEN);
	EXPECT_EQ(owner.receiver->active_epoch(0u), TEST_ACTIVE_EPOCH);
	EXPECT_FALSE(owner.receiver->transition_active());
	EXPECT_TRUE(owner.channel->control_empty());
	boundary_receiver_transition_snapshot baseline{};
	ASSERT_EQ(owner.receiver->try_read_transition(0u, baseline), publication_read_result::AVAILABLE);
	EXPECT_EQ(baseline.publication_generation, 1u);
	EXPECT_EQ(baseline.runtime_generation, TEST_RUNTIME_GENERATION);
	EXPECT_EQ(baseline.boundary_index, 0u);
	EXPECT_EQ(baseline.transition_generation, 0u);
	EXPECT_EQ(baseline.from_epoch, 0u);
	EXPECT_EQ(baseline.to_epoch, TEST_ACTIVE_EPOCH);
	EXPECT_EQ(baseline.cut_sequence, 0u);
	EXPECT_EQ(baseline.ack_published, 0u);

	ASSERT_TRUE(owner.telemetry->telemetry->reserve_target_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).is_ok());
	const boundary_epoch_cut early_cut{TEST_FUTURE_EPOCH, 0u};
	ASSERT_EQ(owner.channel->submit_cut(early_cut), boundary_control_publication_result::PUBLISHED);
	EXPECT_FALSE(owner.channel->control_empty());
	EXPECT_TRUE(owner.receiver->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							       TEST_FUTURE_EPOCH));
	EXPECT_FALSE(owner.channel->control_empty());
	owner.ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	EXPECT_TRUE(owner.receiver->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							       TEST_FUTURE_EPOCH));
	EXPECT_FALSE(owner.channel->control_empty());
	ASSERT_TRUE(owner.receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::WAITING_CUT);
	EXPECT_EQ(owner.receiver->accepted_cut(0u), boundary_epoch_cut{});
	EXPECT_FALSE(owner.channel->control_empty());
	owner.ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
	owner.receiver->service_control();
	EXPECT_TRUE(owner.channel->control_empty());
	EXPECT_EQ(owner.receiver->accepted_cut(0u), early_cut);
	EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::CUT_DRAINED);
	EXPECT_TRUE(owner.receiver->activation_ready());
	activate_and_acknowledge(owner);
}

/** @brief Classify pending, reached, duplicate, and contradictory cuts exactly. */
TEST(worker_boundary_receiver, exact_cut_progress_duplicate_and_contradiction_are_sequence_defined)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	{
		auto owner = make_receiver(numa_node);
		ASSERT_TRUE(owner);
		packet_record record{};
		record.metadata.epoch = TEST_ACTIVE_EPOCH;
		ASSERT_EQ(owner.channel->try_send_data(&record), boundary_data_publication_result::TRANSFERRED);
		begin_transition(owner);
		ASSERT_EQ(owner.channel->submit_cut({TEST_FUTURE_EPOCH, 1u}),
			  boundary_control_publication_result::PUBLISHED);
		owner.receiver->service_control();
		EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::CUT_DRAINING);
		receive_data(owner, record, false);
		owner.receiver->refresh_cut_progress();
		EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::CUT_DRAINED);
		EXPECT_FALSE(owner.receiver->activation_ready());
		owner.ledger->retire(TEST_ACTIVE_EPOCH);
		EXPECT_TRUE(owner.receiver->activation_ready());
		ASSERT_EQ(owner.channel->submit_cut({TEST_FUTURE_EPOCH, 1u}),
			  boundary_control_publication_result::PUBLISHED);
		owner.receiver->service_control();
		EXPECT_EQ(owner.receiver->duplicate_cut_count(0u), 1u);
		activate_and_acknowledge(owner);
	}
	EXPECT_DEATH(
		{
			auto owner = make_receiver(numa_node);
			if (!owner) {
				std::_Exit(EXIT_SUCCESS);
			}
			packet_record record{};
			record.metadata.epoch = TEST_ACTIVE_EPOCH;
			if (owner.channel->try_send_data(&record) != boundary_data_publication_result::TRANSFERRED) {
				std::_Exit(EXIT_SUCCESS);
			}
			packet_record *received = nullptr;
			if (owner.channel->try_receive_data(received) != boundary_data_receive_result::RECEIVED ||
			    received != &record) {
				std::_Exit(EXIT_SUCCESS);
			}
			owner.ledger->acquire(record.metadata.epoch);
			owner.channel->complete_data_receive(received);
			owner.ledger->retire(record.metadata.epoch);
			begin_transition_for_death(owner);
			if (owner.channel->submit_cut({TEST_FUTURE_EPOCH, 0u}) !=
			    boundary_control_publication_result::PUBLISHED) {
				std::_Exit(EXIT_SUCCESS);
			}
			owner.receiver->service_control();
		},
		"");
}

/** @brief Require all inbound cuts and zero old credit; admit zero-inbound vacuity exactly. */
TEST(worker_boundary_receiver, fan_in_requires_every_cut_zero_old_credit_and_target_source_admission)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto ledger_or = worker_epoch_ledger::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, 8u);
	ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
	auto ledger = std::move(ledger_or).value();
	std::array<boundary_epoch_channel *, 0> no_channels{};
	auto receiver_or = worker_boundary_receiver::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, no_channels);
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto receiver = std::move(receiver_or).value();
	ASSERT_TRUE(receiver->bind_ledger(*ledger).is_ok());
	ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	receiver->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	auto telemetry_or =
		test::worker_telemetry_test_owner::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, {});
	ASSERT_TRUE(telemetry_or.is_ok()) << telemetry_or.error().message();
	auto telemetry = std::move(telemetry_or).value();
	std::array<module::module_epoch_store *, 0> no_modules{};
	std::array<packet_epoch_input_staging *, 0> no_staging{};
	auto activation_or = worker_epoch_activation::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, no_modules,
							     no_staging, *ledger, nullptr, nullptr,
							     *telemetry->telemetry);
	ASSERT_TRUE(activation_or.is_ok()) << activation_or.error().message();
	auto activation = std::move(activation_or).value();
	telemetry->telemetry->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH, 1u);
	activation->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(telemetry->telemetry->reserve_target_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).is_ok());
	ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	EXPECT_FALSE(receiver->activation_ready());
	ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
	EXPECT_TRUE(receiver->activation_ready());
	ASSERT_TRUE(activation->activate(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH, 1u).is_ok());
	runtime_telemetry_bank_token telemetry_token{};
	while (telemetry->channel->take_completed(telemetry_token)) {
		ASSERT_TRUE(telemetry->telemetry->completed_bank(telemetry_token).is_ok());
		telemetry->telemetry->complete_aggregation(telemetry_token);
	}
	telemetry->telemetry->mark_epoch_aggregated(TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(telemetry->telemetry->epoch_aggregated(TEST_ACTIVE_EPOCH));
	ASSERT_TRUE(telemetry->telemetry->retire_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).has_value());
	while (telemetry->channel->take_returned(telemetry_token)) {
		telemetry->telemetry->accept_returned(telemetry_token);
	}
	receiver->acknowledge_activation(TEST_TRANSITION_GENERATION, TEST_FUTURE_EPOCH);
	EXPECT_TRUE(receiver->all_acks_published());
	receiver->complete_receiver_transition(TEST_TRANSITION_GENERATION);
}

/** @brief Require every exact inbound boundary before multi-edge fan-in becomes ready. */
TEST(worker_boundary_receiver, multiboundary_fan_in_is_exact_and_region_aggregate_independent)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
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
		const auto facts = boundary_facts(static_cast<uint32_t>(index), numa_node);
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
	auto ledger_or = worker_epoch_ledger::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, 8u);
	ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
	auto ledger = std::move(ledger_or).value();
	auto sender_or = worker_boundary_sender::create(TEST_SENDER_WORKER, TEST_RUNTIME_GENERATION, channels, holds);
	auto receiver_or = worker_boundary_receiver::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, channels);
	ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto sender = std::move(sender_or).value();
	auto receiver = std::move(receiver_or).value();
	EXPECT_EQ(sender->size(), 2u);
	ASSERT_TRUE(sender_slab->seal().is_ok());
	ASSERT_TRUE(receiver_slab->seal().is_ok());
	ASSERT_TRUE(receiver->bind_ledger(*ledger).is_ok());
	ledger->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	receiver->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	auto telemetry_or =
		test::worker_telemetry_test_owner::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, {});
	ASSERT_TRUE(telemetry_or.is_ok()) << telemetry_or.error().message();
	auto telemetry = std::move(telemetry_or).value();
	std::array<module::module_epoch_store *, 0> no_modules{};
	std::array<packet_epoch_input_staging *, 0> no_staging{};
	auto activation_or = worker_epoch_activation::create(TEST_RECEIVER_WORKER, TEST_RUNTIME_GENERATION, no_modules,
							     no_staging, *ledger, nullptr, nullptr,
							     *telemetry->telemetry);
	ASSERT_TRUE(activation_or.is_ok()) << activation_or.error().message();
	auto activation = std::move(activation_or).value();
	telemetry->telemetry->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH, 1u);
	activation->bind_bootstrap_epoch(TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(telemetry->telemetry->reserve_target_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).is_ok());
	ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	ledger->advance_source_epoch(TEST_FUTURE_EPOCH);

	ASSERT_EQ(channels[0]->submit_cut({TEST_FUTURE_EPOCH, 0u}), boundary_control_publication_result::PUBLISHED);
	receiver->service_control();
	EXPECT_EQ(receiver->phase(0u), boundary_epoch_receiver_phase::CUT_DRAINED);
	EXPECT_EQ(receiver->phase(1u), boundary_epoch_receiver_phase::WAITING_CUT);
	EXPECT_FALSE(receiver->activation_ready());
	ASSERT_EQ(channels[1]->submit_cut({TEST_FUTURE_EPOCH, 0u}), boundary_control_publication_result::PUBLISHED);
	receiver->service_control();
	receiver->refresh_cut_progress();
	EXPECT_TRUE(receiver->activation_ready());
	ASSERT_TRUE(activation->activate(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH, 1u).is_ok());
	runtime_telemetry_bank_token telemetry_token{};
	while (telemetry->channel->take_completed(telemetry_token)) {
		ASSERT_TRUE(telemetry->telemetry->completed_bank(telemetry_token).is_ok());
		telemetry->telemetry->complete_aggregation(telemetry_token);
	}
	telemetry->telemetry->mark_epoch_aggregated(TEST_ACTIVE_EPOCH);
	ASSERT_TRUE(telemetry->telemetry->epoch_aggregated(TEST_ACTIVE_EPOCH));
	ASSERT_TRUE(telemetry->telemetry->retire_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).has_value());
	while (telemetry->channel->take_returned(telemetry_token)) {
		telemetry->telemetry->accept_returned(telemetry_token);
	}
	receiver->acknowledge_activation(TEST_TRANSITION_GENERATION, TEST_FUTURE_EPOCH);
	EXPECT_TRUE(receiver->all_acks_published());
	for (auto *channel : channels) {
		boundary_epoch_ack ack{};
		ASSERT_TRUE(channel->try_receive_ack(ack));
		EXPECT_EQ(ack, (boundary_epoch_ack{TEST_FUTURE_EPOCH, 0u}));
	}
	receiver->complete_receiver_transition(TEST_TRANSITION_GENERATION);
}

/** @brief Compose exact outbound publication, local activation, ACK, and gate opening once. */
TEST(worker_boundary_receiver, local_switch_waits_for_published_cut_and_acks_only_after_activation)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_receiver(numa_node);
	ASSERT_TRUE(owner);
	ASSERT_TRUE(owner.telemetry->telemetry->reserve_target_epoch(TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH).is_ok());
	owner.sender_ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	owner.ledger->bind_future_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(
		owner.sender_claim->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	owner.sender_ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
	ASSERT_TRUE(owner.sender_claim->try_seal_after_old_work_drained());
	ASSERT_TRUE(owner.sender_claim->outbound_sealed());
	ASSERT_TRUE(owner.sender_claim->all_cuts_published());
	ASSERT_FALSE(owner.channel->control_empty());
	ASSERT_TRUE(owner.receiver->preflight_begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH,
							       TEST_FUTURE_EPOCH));
	ASSERT_TRUE(owner.receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH));
	EXPECT_FALSE(owner.channel->control_empty());
	owner.ledger->advance_source_epoch(TEST_FUTURE_EPOCH);
	EXPECT_FALSE(owner.receiver->activation_ready());
	ASSERT_TRUE(owner.sender_ledger->preflight_promote_future_epoch(TEST_FUTURE_EPOCH).is_ok());
	owner.sender_ledger->promote_future_epoch(TEST_FUTURE_EPOCH);
	owner.receiver->service_control();
	owner.receiver->refresh_cut_progress();
	EXPECT_TRUE(owner.channel->control_empty());
	ASSERT_TRUE(owner.receiver->activation_ready());
	EXPECT_EQ(owner.sender_claim->phase(0u), boundary_epoch_sender_phase::WAITING_ACK);
	boundary_epoch_ack early_ack{};
	EXPECT_FALSE(owner.channel->try_receive_ack(early_ack));
	ASSERT_TRUE(owner.activation->activate(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH, 1u)
			    .is_ok());
	complete_telemetry_transition(owner);
	EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::CUT_DRAINED);
	owner.receiver->acknowledge_activation(TEST_TRANSITION_GENERATION, TEST_FUTURE_EPOCH);
	EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::ACK_PUBLISHED);
	boundary_receiver_transition_snapshot completed{};
	ASSERT_EQ(owner.receiver->try_read_transition(0u, completed), publication_read_result::AVAILABLE);
	EXPECT_EQ(completed.publication_generation, 5u);
	EXPECT_EQ(completed.transition_generation, TEST_TRANSITION_GENERATION);
	EXPECT_EQ(completed.from_epoch, TEST_ACTIVE_EPOCH);
	EXPECT_EQ(completed.to_epoch, TEST_FUTURE_EPOCH);
	EXPECT_EQ(completed.cut_sequence, 0u);
	EXPECT_EQ(completed.ack_published, 1u);
	EXPECT_NE(completed.cut_observed_monotonic_ns, 0u);
	EXPECT_GE(completed.cut_drained_monotonic_ns, completed.cut_observed_monotonic_ns);
	EXPECT_GE(completed.activation_monotonic_ns, completed.cut_drained_monotonic_ns);
	EXPECT_GE(completed.ack_published_monotonic_ns, completed.activation_monotonic_ns);
	owner.sender_claim->service_control();
	EXPECT_TRUE(owner.sender_claim->all_gates_open());
	EXPECT_EQ(owner.sender_claim->open_epoch(0u), TEST_FUTURE_EPOCH);
	owner.receiver->complete_receiver_transition(TEST_TRANSITION_GENERATION);
	owner.sender_claim->complete_sender_transition(TEST_TRANSITION_GENERATION);
	EXPECT_FALSE(owner.receiver->transition_active());
	EXPECT_FALSE(owner.sender_claim->transition_active());
}

/** @brief Retain one pending ACK under pressure and never resubmit after publication. */
TEST(worker_boundary_receiver, activation_marks_all_before_exact_pending_ack_publication)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	auto owner = make_receiver(numa_node);
	ASSERT_TRUE(owner);
	begin_transition(owner);
	ASSERT_EQ(owner.channel->submit_cut({TEST_FUTURE_EPOCH, 0u}), boundary_control_publication_result::PUBLISHED);
	owner.receiver->service_control();
	owner.receiver->refresh_cut_progress();
	ASSERT_TRUE(owner.receiver->activation_ready());
	ASSERT_EQ(owner.channel->submit_ack({TEST_FUTURE_EPOCH + 2u, 1u}),
		  boundary_control_publication_result::PUBLISHED);
	ASSERT_EQ(owner.channel->submit_ack({TEST_FUTURE_EPOCH + 4u, 2u}),
		  boundary_control_publication_result::PUBLISHED);
	ASSERT_TRUE(owner.activation->activate(TEST_TRANSITION_GENERATION, TEST_ACTIVE_EPOCH, TEST_FUTURE_EPOCH, 1u)
			    .is_ok());
	complete_telemetry_transition(owner);
	owner.receiver->acknowledge_activation(TEST_TRANSITION_GENERATION, TEST_FUTURE_EPOCH);
	EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::ACK_PENDING);
	EXPECT_TRUE(owner.channel->has_pending_ack());
	boundary_receiver_transition_snapshot before_publication{};
	ASSERT_EQ(owner.receiver->try_read_transition(0u, before_publication), publication_read_result::AVAILABLE);
	EXPECT_EQ(before_publication.publication_generation, 4u);
	EXPECT_EQ(before_publication.transition_generation, TEST_TRANSITION_GENERATION);
	EXPECT_EQ(before_publication.ack_published, 0u);
	ASSERT_EQ(owner.channel->submit_cut({TEST_FUTURE_EPOCH, 0u}), boundary_control_publication_result::PUBLISHED);
	ASSERT_EQ(owner.channel->submit_cut({TEST_FUTURE_EPOCH, 0u}), boundary_control_publication_result::PUBLISHED);
	boundary_epoch_ack observed{};
	ASSERT_TRUE(owner.channel->try_receive_ack(observed));
	owner.receiver->service_control();
	EXPECT_EQ(owner.receiver->phase(0u), boundary_epoch_receiver_phase::ACK_PUBLISHED);
	EXPECT_FALSE(owner.channel->has_pending_ack());
	boundary_receiver_transition_snapshot after_publication{};
	ASSERT_EQ(owner.receiver->try_read_transition(0u, after_publication), publication_read_result::AVAILABLE);
	EXPECT_EQ(after_publication.publication_generation, 6u);
	EXPECT_EQ(after_publication.transition_generation, TEST_TRANSITION_GENERATION);
	EXPECT_EQ(after_publication.ack_published, 1u);
	EXPECT_FALSE(owner.receiver->all_acks_published());
	owner.receiver->service_control();
	EXPECT_EQ(owner.receiver->duplicate_cut_count(0u), 2u);
	boundary_receiver_transition_snapshot duplicate_publication{};
	ASSERT_EQ(owner.receiver->try_read_transition(0u, duplicate_publication), publication_read_result::AVAILABLE);
	EXPECT_EQ(duplicate_publication.publication_generation, 7u);
	EXPECT_EQ(duplicate_publication.ack_published, 1u);
	EXPECT_TRUE(owner.receiver->all_acks_published());
	ASSERT_TRUE(owner.channel->try_receive_ack(observed));
	ASSERT_TRUE(owner.channel->try_receive_ack(observed));
	EXPECT_EQ(observed, (boundary_epoch_ack{TEST_FUTURE_EPOCH, 0u}));
	owner.receiver->service_control();
	EXPECT_FALSE(owner.channel->try_receive_ack(observed));
	owner.receiver->complete_receiver_transition(TEST_TRANSITION_GENERATION);
}

/** @brief Fail stop on conflicting/stale CUT, early ACK, and live receiver teardown. */
TEST(worker_boundary_receiver, exactness_activation_order_and_lifetime_violations_fail_stop)
{
	const int32_t numa_node = test_numa_node();
	ASSERT_GE(numa_node, 0);
	EXPECT_DEATH(receive_conflicting_cut(numa_node), "");
	EXPECT_DEATH(receive_wrong_epoch_cut(numa_node, TEST_ACTIVE_EPOCH), "");
	EXPECT_DEATH(receive_wrong_epoch_cut(numa_node, TEST_FUTURE_EPOCH + 1u), "");
	EXPECT_DEATH(receive_prearrived_wrong_epoch_cut(numa_node, TEST_FUTURE_EPOCH + 1u), "");
	EXPECT_DEATH(acknowledge_before_activation(numa_node), "");
	EXPECT_DEATH(destroy_active_receiver(numa_node), "");
}

}  // namespace
}  // namespace kinetum::dp
