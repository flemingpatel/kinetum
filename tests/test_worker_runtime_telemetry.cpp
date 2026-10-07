// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_runtime_telemetry.cpp
 * @brief Exact bank, placement, cadence, activation, and shutdown telemetry tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <numeric>

#include "src/dp/runtime_telemetry_bank.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::dp
{
namespace
{

/** Runtime identity carried by worker bank tokens. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 17u;
/** Old epoch whose bank is published and retired. */
constexpr uint64_t TEST_FROM_EPOCH = 41u;
/** Activated target epoch receiving the replacement bank. */
constexpr uint64_t TEST_TO_EPOCH = 47u;
/** Compact owner-worker identity carried by each observation. */
constexpr uint32_t TEST_WORKER_INDEX = 3u;
/** Authored telemetry publication interval in nanoseconds. */
constexpr uint64_t TEST_CADENCE_NS = 1000u;
/** @brief Final fixture timestamp beyond every authored cadence publication. */
constexpr uint64_t TEST_SHUTDOWN_NS = 100u * TEST_CADENCE_NS;
/** @brief Nonadjacent compiled stream identities exercising local ordinal lookup. */
constexpr std::array<uint32_t, 2> TEST_STREAMS{3u, 19u};
/** @brief Exact stage identities shared by the worker-bank fixtures. */
constexpr std::array<uint32_t, 2> TEST_STAGES{2u, 5u};

/** @brief Create one exact worker channel and bank owner on an available NUMA node. */
struct worker_bank_fixture {
	std::unique_ptr<worker_telemetry_channel> channel;  ///< Exact bidirectional SPSC transport.
	std::unique_ptr<worker_runtime_telemetry> owner;    ///< Exact worker-local three-bank owner.

	/**
	 * @param stages Exact owned stage identities for this fixture.
	 * @param streams Exact owned stream identities for this fixture.
	 * @return Complete fixture or an exact host/allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_bank_fixture>>
	create(std::span<const uint32_t> stages, std::span<const uint32_t> streams)
	{
		const auto host = quark::probe_host();
		if (!host.valid || host.memory_numa_nodes.empty()) {
			return common::status::unavailable("telemetry test host has no exact memory NUMA node");
		}
		const int32_t node = host.memory_numa_nodes.front();
		auto fixture = std::make_unique<worker_bank_fixture>();
		auto channel_or = worker_telemetry_channel::create(TEST_WORKER_INDEX, 0u, node, node);
		if (!channel_or.is_ok()) {
			return channel_or.error();
		}
		fixture->channel = std::move(channel_or).value();
		auto owner_or = worker_runtime_telemetry::create(TEST_RUNTIME_GENERATION, TEST_WORKER_INDEX, node,
								 stages, streams, TEST_CADENCE_NS, *fixture->channel);
		if (!owner_or.is_ok()) {
			return owner_or.error();
		}
		fixture->owner = std::move(owner_or).value();
		return fixture;
	}

	/** @brief Publish, aggregate, and retire a simple active-only final epoch. */
	~worker_bank_fixture()
	{
		if (owner == nullptr || channel == nullptr || owner->active_epoch() == 0u) {
			return;
		}
		const uint64_t epoch = owner->active_epoch();
		if (!owner->preflight_shutdown(epoch)) {
			std::terminate();
		}
		owner->publish_shutdown(epoch, TEST_SHUTDOWN_NS);
		runtime_telemetry_bank_token token{};
		if (!channel->take_completed(token) || token.reason != runtime_telemetry_publication_reason::SHUTDOWN ||
		    token.companion_bank_index == UINT8_MAX || !owner->completed_bank(token).is_ok()) {
			std::terminate();
		}
		owner->complete_aggregation(token);
		owner->mark_epoch_aggregated(epoch);
		if (owner->retire_epoch(epoch, 0u).has_value()) {
			std::terminate();
		}
	}
};

/** @brief Prove derived capacity and both ring placements use their exact poller nodes. */
TEST(worker_runtime_telemetry, channel_capacity_and_poller_numa_are_exact)
{
	EXPECT_EQ(worker_telemetry_channel::capacity_for(0u).value(), 2u);
	EXPECT_EQ(worker_telemetry_channel::capacity_for(1u).value(), 4u);
	EXPECT_EQ(worker_telemetry_channel::capacity_for(2u).value(), 8u);
	EXPECT_EQ(worker_telemetry_channel::capacity_for(3u).value(), 8u);
	EXPECT_FALSE(worker_telemetry_channel::capacity_for(std::numeric_limits<std::size_t>::max()).is_ok());

	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	const int32_t worker_node = host.memory_numa_nodes.front();
	const int32_t coordinator_node = host.memory_numa_nodes.back();
	auto channel_or = worker_telemetry_channel::create(TEST_WORKER_INDEX, 2u, worker_node, coordinator_node);
	ASSERT_TRUE(channel_or.is_ok()) << channel_or.error().message();
	auto channel = std::move(channel_or).value();
	EXPECT_EQ(channel->capacity(), 8u);
	EXPECT_EQ(channel->returned_numa_node(), worker_node);
	EXPECT_EQ(channel->completed_numa_node(), coordinator_node);
}

/** @brief Prove ordinary banks carry exact interval counters and visible skips. */
TEST(worker_runtime_telemetry, cadence_swap_is_nonblocking_and_skip_is_visible)
{
	auto fixture_or = worker_bank_fixture::create(TEST_STAGES, TEST_STREAMS);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_TRUE(fixture->owner->owns_channel(*fixture->channel));
	auto foreign_channel_or = worker_telemetry_channel::create(TEST_WORKER_INDEX, 0u, fixture->owner->numa_node(),
								   fixture->owner->numa_node());
	ASSERT_TRUE(foreign_channel_or.is_ok()) << foreign_channel_or.error().message();
	EXPECT_FALSE(fixture->owner->owns_channel(*foreign_channel_or.value()));
	fixture->owner->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	const uint32_t stage = fixture->owner->stage_ordinal(2u);
	ASSERT_NE(stage, UINT32_MAX);
	const uint32_t rx_stream = fixture->owner->stream_ordinal(TEST_STREAMS[0]);
	const uint32_t tx_stream = fixture->owner->stream_ordinal(TEST_STREAMS[1]);
	ASSERT_NE(rx_stream, UINT32_MAX);
	ASSERT_NE(tx_stream, UINT32_MAX);
	fixture->owner->record_stream(rx_stream, 1u, 64u, 0u);
	fixture->owner->record_stream(tx_stream, 1u, 60u, 0u);
	fixture->owner->record_drop();
	fixture->owner->record_fanout_overflow();
	fixture->owner->record_protocol_fault(epoch_protocol_fault_code::OLD_DATA_AFTER_SEAL);
	fixture->owner->record_stage_input(stage, 1u, 64u);
	fixture->owner->record_stage_output(stage, 60u);
	fixture->owner->record_stage_drop(stage);
	const runtime_telemetry_bank_token pressure{};
	ASSERT_TRUE(fixture->channel->publish_completed(pressure));
	ASSERT_TRUE(fixture->channel->publish_completed(pressure));
	const auto pressure_service = fixture->owner->service_turn(1u);
	EXPECT_TRUE(pressure_service.cadence_due);
	EXPECT_EQ(pressure_service.return_need, runtime_telemetry_return_need::POLL_REQUIRED);
	runtime_telemetry_bank_token discarded{};
	ASSERT_TRUE(fixture->channel->take_completed(discarded));
	ASSERT_TRUE(fixture->channel->take_completed(discarded));
	EXPECT_TRUE(fixture->owner->preflight_completed_publications(2u));

	const auto first_service = fixture->owner->service_turn(1u + TEST_CADENCE_NS);
	EXPECT_TRUE(first_service.cadence_due);
	EXPECT_EQ(first_service.return_need, runtime_telemetry_return_need::EXPECTED);
	EXPECT_FALSE(fixture->owner->preflight_completed_publications(2u));
	const auto skipped_service = fixture->owner->service_turn(1u + 2u * TEST_CADENCE_NS);
	EXPECT_TRUE(skipped_service.cadence_due);
	EXPECT_EQ(skipped_service.return_need, runtime_telemetry_return_need::POLL_REQUIRED);

	runtime_telemetry_bank_token first{};
	ASSERT_TRUE(fixture->channel->take_completed(first));
	EXPECT_TRUE(fixture->owner->preflight_completed_publications(2u));
	ASSERT_EQ(first.kind, runtime_telemetry_bank_token_kind::BANK);
	ASSERT_EQ(first.reason, runtime_telemetry_publication_reason::CADENCE);
	ASSERT_EQ(first.companion_bank_index, UINT8_MAX);
	auto first_bank_or = fixture->owner->completed_bank(first);
	ASSERT_TRUE(first_bank_or.is_ok()) << first_bank_or.error().message();
	const auto first_bank = first_bank_or.value();
	ASSERT_EQ(first_bank.streams.size(), TEST_STREAMS.size());
	EXPECT_EQ(first_bank.streams[rx_stream].packets, 1u);
	EXPECT_EQ(first_bank.streams[tx_stream].packets, 1u);
	EXPECT_EQ(first_bank.engine.dropped_packets, 1u);
	EXPECT_EQ(first_bank.streams[rx_stream].bytes, 64u);
	EXPECT_EQ(first_bank.streams[tx_stream].bytes, 60u);
	EXPECT_EQ(first_bank.streams[rx_stream].rejected_packets, 0u);
	EXPECT_EQ(first_bank.streams[tx_stream].rejected_packets, 0u);
	EXPECT_EQ(first_bank.engine.fanout_overflow, 1u);
	EXPECT_EQ(
		first_bank.protocol_faults[epoch_protocol_fault_ordinal(epoch_protocol_fault_code::OLD_DATA_AFTER_SEAL)],
		1u);
	EXPECT_EQ(first_bank.skipped_publications, 1u);
	ASSERT_EQ(first_bank.stages.size(), 2u);
	EXPECT_EQ(first_bank.stages[stage].in_packets, 1u);
	EXPECT_EQ(first_bank.stages[stage].out_packets, 1u);
	EXPECT_EQ(first_bank.stages[stage].dropped_packets, 1u);
	const auto first_stage_address = reinterpret_cast<std::uintptr_t>(first_bank.stages.data());
	EXPECT_EQ(first_stage_address % kinetum::algo::CACHE_LINE_SIZE, 0u);
	fixture->owner->complete_aggregation(first);

	runtime_telemetry_bank_token returned{};
	ASSERT_TRUE(fixture->channel->take_returned(returned));
	fixture->owner->accept_returned(returned);
	const auto second_service = fixture->owner->service_turn(1u + 3u * TEST_CADENCE_NS);
	EXPECT_EQ(second_service.return_need, runtime_telemetry_return_need::EXPECTED);
	runtime_telemetry_bank_token second{};
	ASSERT_TRUE(fixture->channel->take_completed(second));
	auto second_bank_or = fixture->owner->completed_bank(second);
	ASSERT_TRUE(second_bank_or.is_ok()) << second_bank_or.error().message();
	EXPECT_EQ(second_bank_or->skipped_publications, 1u);
	const auto second_stage_address = reinterpret_cast<std::uintptr_t>(second_bank_or->stages.data());
	EXPECT_EQ(second_stage_address % kinetum::algo::CACHE_LINE_SIZE, 0u);
	EXPECT_GE(first_stage_address > second_stage_address ? first_stage_address - second_stage_address :
							       second_stage_address - first_stage_address,
		  kinetum::algo::CACHE_LINE_SIZE);
	fixture->owner->complete_aggregation(second);
	ASSERT_TRUE(fixture->channel->take_returned(returned));
	fixture->owner->accept_returned(returned);
}

/** @brief Prove activation publishes one dirty bank and retains its clean companion. */
TEST(worker_runtime_telemetry, activation_reserve_is_exact_and_reopens_one_target_standby)
{
	auto fixture_or = worker_bank_fixture::create(TEST_STAGES, TEST_STREAMS);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->owner->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	fixture->owner->record_stream(fixture->owner->stream_ordinal(TEST_STREAMS[0]), 1u, 128u, 2u);
	ASSERT_TRUE(fixture->owner->reserve_target_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH).is_ok());
	ASSERT_TRUE(fixture->owner->preflight_activate(TEST_FROM_EPOCH, TEST_TO_EPOCH));
	EXPECT_FALSE(fixture->owner->activation_timestamp_representable(UINT64_MAX));
	EXPECT_TRUE(fixture->owner->activation_timestamp_representable(2u));
	fixture->owner->activate_target_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH, 2u);

	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(fixture->channel->take_completed(token));
	EXPECT_EQ(token.reason, runtime_telemetry_publication_reason::ACTIVATION);
	EXPECT_NE(token.companion_bank_index, UINT8_MAX);
	const auto old_bank = fixture->owner->completed_bank(token);
	ASSERT_TRUE(old_bank.is_ok());
	ASSERT_EQ(old_bank->streams.size(), TEST_STREAMS.size());
	EXPECT_EQ(old_bank->streams[0].packets, 1u);
	EXPECT_EQ(old_bank->streams[0].bytes, 128u);
	EXPECT_EQ(old_bank->streams[0].rejected_packets, 2u);
	fixture->owner->complete_aggregation(token);
	fixture->owner->mark_epoch_aggregated(TEST_FROM_EPOCH);
	ASSERT_TRUE(fixture->owner->epoch_aggregated(TEST_FROM_EPOCH));
	const auto transfer = fixture->owner->retire_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH);
	ASSERT_TRUE(transfer.has_value());
	ASSERT_EQ(transfer->kind, runtime_telemetry_bank_token_kind::BANK);
	ASSERT_TRUE(fixture->channel->take_returned(token));
	fixture->owner->accept_returned(token);
	EXPECT_EQ(fixture->owner->active_epoch(), TEST_TO_EPOCH);
}

/** @brief Prove a cadence return crossing activation is acknowledged exactly once. */
TEST(worker_runtime_telemetry, late_cadence_return_after_activation_becomes_exact_retained_ack)
{
	auto fixture_or = worker_bank_fixture::create(TEST_STAGES, TEST_STREAMS);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->owner->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	EXPECT_EQ(fixture->owner->service_turn(1u).return_need, runtime_telemetry_return_need::EXPECTED);
	ASSERT_TRUE(fixture->owner->reserve_target_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH).is_ok());
	fixture->owner->activate_target_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH, 2u);

	runtime_telemetry_bank_token cadence{};
	runtime_telemetry_bank_token activation{};
	ASSERT_TRUE(fixture->channel->take_completed(cadence));
	ASSERT_TRUE(fixture->channel->take_completed(activation));
	ASSERT_EQ(cadence.reason, runtime_telemetry_publication_reason::CADENCE);
	ASSERT_EQ(activation.reason, runtime_telemetry_publication_reason::ACTIVATION);
	ASSERT_EQ(activation.companion_bank_index, UINT8_MAX);
	fixture->owner->complete_aggregation(cadence);
	fixture->owner->complete_aggregation(activation);

	runtime_telemetry_bank_token returned{};
	ASSERT_TRUE(fixture->channel->take_returned(returned));
	fixture->owner->accept_returned(returned);
	runtime_telemetry_bank_token acknowledgment{};
	ASSERT_TRUE(fixture->channel->take_completed(acknowledgment));
	EXPECT_EQ(acknowledgment.kind, runtime_telemetry_bank_token_kind::RETURN_RETAINED);
	EXPECT_EQ(acknowledgment.bank_index, returned.bank_index);
	EXPECT_EQ(acknowledgment.bank_generation, returned.bank_generation);
	fixture->owner->mark_epoch_aggregated(TEST_FROM_EPOCH);
	ASSERT_TRUE(fixture->owner->epoch_aggregated(TEST_FROM_EPOCH));
	ASSERT_TRUE(fixture->owner->retire_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH).has_value());
	ASSERT_TRUE(fixture->channel->take_returned(returned));
	fixture->owner->accept_returned(returned);
}

/** @brief Prove shutdown waits for cadence return and publishes one final bank. */
TEST(worker_runtime_telemetry, shutdown_cannot_strand_an_unreturned_cadence_bank)
{
	auto fixture_or = worker_bank_fixture::create(TEST_STAGES, TEST_STREAMS);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->owner->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	EXPECT_EQ(fixture->owner->service_turn(1u).return_need, runtime_telemetry_return_need::EXPECTED);
	EXPECT_FALSE(fixture->owner->preflight_shutdown(TEST_FROM_EPOCH));

	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(fixture->channel->take_completed(token));
	fixture->owner->complete_aggregation(token);
	ASSERT_TRUE(fixture->channel->take_returned(token));
	fixture->owner->accept_returned(token);
	ASSERT_TRUE(fixture->owner->preflight_shutdown(TEST_FROM_EPOCH));
	fixture->owner->publish_shutdown(TEST_FROM_EPOCH, 2u);
	ASSERT_TRUE(fixture->channel->take_completed(token));
	EXPECT_EQ(token.reason, runtime_telemetry_publication_reason::SHUTDOWN);
	EXPECT_NE(token.companion_bank_index, UINT8_MAX);
	fixture->owner->complete_aggregation(token);
	fixture->owner->mark_epoch_aggregated(TEST_FROM_EPOCH);
	ASSERT_TRUE(fixture->owner->epoch_aggregated(TEST_FROM_EPOCH));
	EXPECT_FALSE(fixture->owner->retire_epoch(TEST_FROM_EPOCH, 0u).has_value());
}

/** @brief Rejection-only work survives publication without adding transfers or terminal runtime drops. */
TEST(worker_runtime_telemetry, rejected_only_burst_is_not_empty_accounting)
{
	auto fixture_or = worker_bank_fixture::create(TEST_STAGES, TEST_STREAMS);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->owner->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	fixture->owner->record_stream(fixture->owner->stream_ordinal(TEST_STREAMS[0]), 0u, 0u, 7u);
	ASSERT_EQ(fixture->owner->service_turn(1u).return_need, runtime_telemetry_return_need::EXPECTED);
	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(fixture->channel->take_completed(token));
	const auto bank = fixture->owner->completed_bank(token);
	ASSERT_TRUE(bank.is_ok()) << bank.error().message();
	const auto counters = bank->streams[0];
	const auto drops = bank->engine.dropped_packets;
	const auto address = reinterpret_cast<std::uintptr_t>(bank->streams.data());
	fixture->owner->complete_aggregation(token);
	ASSERT_TRUE(fixture->channel->take_returned(token));
	fixture->owner->accept_returned(token);
	EXPECT_EQ(counters.packets, 0u);
	EXPECT_EQ(counters.bytes, 0u);
	EXPECT_EQ(counters.rejected_packets, 7u);
	EXPECT_EQ(drops, 0u);
	EXPECT_EQ(address % kinetum::algo::CACHE_LINE_SIZE, 0u);
}

/** @brief A stream-free worker still publishes and retires its stage/engine banks. */
TEST(worker_runtime_telemetry, empty_stream_membership_has_no_counter_extent)
{
	auto fixture_or = worker_bank_fixture::create(TEST_STAGES, {});
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_TRUE(fixture->owner->io_stream_indices().empty());
	EXPECT_EQ(fixture->owner->stream_ordinal(0u), UINT32_MAX);
	fixture->owner->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	fixture->owner->record_drop();
	ASSERT_EQ(fixture->owner->service_turn(1u).return_need, runtime_telemetry_return_need::EXPECTED);
	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(fixture->channel->take_completed(token));
	const auto bank = fixture->owner->completed_bank(token);
	ASSERT_TRUE(bank.is_ok()) << bank.error().message();
	const bool streams_empty = bank->streams.empty();
	const auto drops = bank->engine.dropped_packets;
	fixture->owner->complete_aggregation(token);
	ASSERT_TRUE(fixture->channel->take_returned(token));
	fixture->owner->accept_returned(token);
	EXPECT_TRUE(streams_empty);
	EXPECT_EQ(drops, 1u);
}

/** @brief Software stream populations are independent of native queue-counter array limits. */
TEST(worker_runtime_telemetry, many_streams_retain_distinct_rows_and_detect_exhaustion)
{
	std::array<uint32_t, 20> identities{};
	std::iota(identities.begin(), identities.end(), 0u);
	auto fixture_or = worker_bank_fixture::create(identities, identities);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->owner->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	for (const auto identity : identities) {
		fixture->owner->record_stream(fixture->owner->stream_ordinal(identity), 1u, 64u + identity, 0u);
	}
	const uint32_t last = fixture->owner->stream_ordinal(identities.back());
	fixture->owner->record_stream(last, 1u, UINT64_MAX - 1u, 0u);
	ASSERT_EQ(fixture->owner->service_turn(1u).return_need, runtime_telemetry_return_need::EXPECTED);
	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(fixture->channel->take_completed(token));
	const auto bank = fixture->owner->completed_bank(token);
	ASSERT_TRUE(bank.is_ok()) << bank.error().message();
	std::array<worker_stream_telemetry_counters, 20> counters{};
	const bool complete = bank->streams.size() == counters.size();
	if (complete) {
		std::copy(bank->streams.begin(), bank->streams.end(), counters.begin());
	}
	fixture->owner->complete_aggregation(token);
	ASSERT_TRUE(fixture->channel->take_returned(token));
	fixture->owner->accept_returned(token);
	ASSERT_TRUE(complete);
	for (std::size_t index = 0u; index + 1u < counters.size(); ++index) {
		EXPECT_EQ(counters[index].packets, 1u);
		EXPECT_EQ(counters[index].bytes, 64u + identities[index]);
		EXPECT_EQ(counters[index].rejected_packets, 0u);
	}
	EXPECT_EQ(counters.back().packets, 2u);
	EXPECT_EQ(counters.back().bytes, UINT64_MAX);
}

}  // namespace
}  // namespace kinetum::dp
