// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_native_handoff.cpp
 * @brief Verify local receipt, FIFO, epoch and reclamation ownership with the real worker roles.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <sys/mman.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/worker_native_handoff.hpp"
#include "tests/numa_test_support.hpp"
#include "tests/worker_telemetry_test_fixture.hpp"

namespace kinetum::dp
{
namespace
{
static_assert(!std::is_convertible_v<native_packet_slot *, packet_record *>);
static_assert(!std::is_invocable_v<decltype(&packet_epoch_input_staging::commit_active), packet_epoch_input_staging &,
				   uint32_t, native_packet_slot *>);
constexpr int EXPECTED_HANDOFF_FAULT = 86;  ///< Identifies termination at the specific injected transfer.

/** @brief Give only a deliberately malformed callback return the expected child exit status. */
void arm_transfer_fault() noexcept
{
	std::set_terminate([] { std::_Exit(EXPECTED_HANDOFF_FAULT); });
}

/** @brief Native buffer witnesses and explicit accepted-prefix behavior for a single worker. */
struct test_queues {
	/** @brief Map one independently protectable page for each received buffer. */
	test_queues()
	{
		const auto page = ::sysconf(_SC_PAGESIZE);
		if (page <= 0) {
			throw std::runtime_error("test requires the system page size");
		}
		page_size = static_cast<std::size_t>(page);
		void *mapping =
			::mmap(nullptr, 3u * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mapping == MAP_FAILED) {
			throw std::runtime_error("native receipt test mapping failed");
		}
		pages = static_cast<uint8_t *>(mapping);
	}
	test_queues(const test_queues &) = delete;
	test_queues &operator=(const test_queues &) = delete;
	/** @brief Reclaim the mapping, including any pages already made inaccessible at TX. */
	~test_queues()
	{
		(void)::munmap(pages, 3u * page_size);
	}
	/** @param index Original packet ordinal. @return Its independently protected range. */
	[[nodiscard]] uint8_t *page(uint16_t index) const noexcept
	{
		return pages + index * page_size;
	}

	uint8_t *pages{nullptr};    ///< Three native buffers in independent virtual pages.
	std::size_t page_size{0u};  ///< Length and stride of each mapping.
	uint16_t accepted{0u};	    ///< TX prefix consumed by the queue.
	uint16_t checked{0u};	    ///< Suffix population verified by storage.
	uint16_t released{0u};	    ///< Suffix population retired by storage.
	bool change_start{false};   ///< Change the first refused view at constant length.
	bool move_storage{false};   ///< Shift the provider's live range without changing the submitted receipt.
	std::array<uint16_t, 3> offsets{1u, 1u, 1u};  ///< Current data offset of each provider buffer.
	bool suffix_dirty{false};		      ///< Publish an ownership witness beyond the returned RX prefix.

	/**
	 * @param state Test queue owner.
	 * @param[out] out Requested output slots, already clear on entry.
	 * @param capacity Four for the populated poll, one for its empty successor.
	 * @return Transfers and rejections for this request.
	 */
	static kinetum_packet_rx_burst_result receive(void *state, kinetum_packet_native_view *out,
						      uint16_t capacity) noexcept
	{
		auto &owner = *static_cast<test_queues *>(state);
		if (capacity == 1u) {
			EXPECT_EQ(out[0].handle, nullptr);
			EXPECT_EQ(out[0].data_start, nullptr);
			EXPECT_EQ(out[0].length, 0u);
			return {};
		}
		EXPECT_EQ(capacity, 4u);
		for (uint16_t i = 0u; i < 3u; ++i) {
			out[i] = {owner.page(i), owner.page(i) + 1u, 60u, 0u};
		}
		if (owner.suffix_dirty) {
			out[3].length = 1u;
			arm_transfer_fault();
		}
		return {3u, 1u};
	}
	/**
	 * @param state Queue specifying the acceptance boundary.
	 * @param views Borrowed FIFO offer. Each accepted buffer page becomes inaccessible before return.
	 * @param count Number of offered views.
	 * @return Configured accepted prefix.
	 */
	static uint16_t transmit(void *state, const kinetum_packet_native_view *views, uint16_t count) noexcept
	{
		auto &owner = *static_cast<test_queues *>(state);
		EXPECT_EQ(count, 3u);
		for (uint16_t i = 0u; i < count; ++i) {
			EXPECT_EQ(views[i].handle, owner.page(i));
			EXPECT_EQ(views[i].data_start, owner.page(i) + 1u);
			if (i < owner.accepted) {
				EXPECT_EQ(::mprotect(owner.page(i), owner.page_size, PROT_NONE), 0);
			}
		}
		if (owner.change_start || owner.move_storage) {
			owner.offsets[owner.accepted] = 2u;
		}
		if (owner.change_start) {
			// Deliberately violate the provider's borrowed-array contract in this death test.
			const_cast<kinetum_packet_native_view &>(views[owner.accepted]).data_start =
				owner.page(owner.accepted) + 2u;
			arm_transfer_fault();
		}
		return owner.accepted;
	}
	/**
	 * @param state Original storage owner.
	 * @param views Retained suffix.
	 * @param count Number of views still owned by storage.
	 * @return One if each original data start and length agrees.
	 */
	static uint8_t verify(void *state, const kinetum_packet_native_view *views, uint16_t count) noexcept
	{
		auto &owner = *static_cast<test_queues *>(state);
		owner.checked = count;
		if (owner.change_start) {
			// A changed receipt must fail before the worker consults storage.
			std::_Exit(EXIT_SUCCESS);
		}
		for (uint16_t i = 0u; i < count; ++i) {
			const auto *original = owner.page(static_cast<uint16_t>(owner.accepted + i));
			if (views[i].handle != original ||
			    views[i].data_start != original + owner.offsets[owner.accepted + i] ||
			    views[i].length != 60u) {
				if (owner.move_storage) {
					arm_transfer_fault();
				}
				return 0u;
			}
		}
		return 1u;
	}
	/** @param state Original storage owner. @param count Number of verified buffers being reclaimed. */
	static void release(void *state, const kinetum_packet_native_view *, uint16_t count) noexcept
	{
		auto &owner = *static_cast<test_queues *>(state);
		if (owner.move_storage) {
			std::_Exit(EXIT_SUCCESS);  // A failed verification cannot authorize release.
		}
		EXPECT_EQ(owner.checked, count);
		EXPECT_EQ(owner.released, 0u);
		owner.released = count;
	}
};

/** @param queues Provider with the specified acceptance and corruption behavior.
 * @param future Admit into the inert role and promote it before service.
 */
void run_handoff(test_queues &queues, bool future)
{
	const auto node = test::required_memory_numa_node();
	constexpr std::array<packet_work_key, 2> KEYS{{
		{0u, packet_work_phase::RX_DELIVER, {}},
		{1u, packet_work_phase::EXECUTE, {}},
	}};
	const std::array<worker_packet_staging_domain, 1> domains{{{2u, 4u, 4u, KEYS}}};
	auto staging = worker_packet_staging::create(domains, node, true);
	ASSERT_TRUE(staging.is_ok());
	auto ledger = worker_epoch_ledger::create(0u, 1u, 8u, node);
	ASSERT_TRUE(ledger.is_ok());
	test::worker_telemetry_test_owner counters;
	auto channel = worker_telemetry_channel::create(0u, 0u, node, node);
	ASSERT_TRUE(channel.is_ok());
	counters.channel = std::move(channel).value();
	constexpr std::array<uint32_t, 2> INDICES{0u, 1u};
	auto telemetry = worker_runtime_telemetry::create(1u, 0u, node, INDICES, INDICES, 1000u, *counters.channel);
	ASSERT_TRUE(telemetry.is_ok());
	counters.telemetry = std::move(telemetry).value();
	counters.telemetry->bind_bootstrap_epoch(1u, 1u);
	auto &credits = *ledger.value();
	credits.bind_bootstrap_epoch(1u);
	auto &role = staging.value()->domains().front();
	kinetum_packet_storage_domain_operations storage{};
	storage.state = &queues;
	storage.acquire_burst = [](void *, packet_record **, uint16_t) noexcept -> uint16_t { return 0u; };
	storage.clone_writable = [](void *, const packet_record *) noexcept -> packet_record * { return nullptr; };
	storage.copy_origins_burst = [](void *, const kinetum_packet_origin_view *, packet_record **,
					uint16_t) noexcept -> uint16_t { return 0u; };
	storage.release_burst = [](void *, packet_record *const *, uint16_t) noexcept { std::terminate(); };
	storage.observe_statistics = [](void *, kinetum_provider_storage_observation *,
					kinetum_provider_diagnostic *) noexcept {
		return KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION;
	};
	storage.capabilities = packet_storage_capabilities::CURRENT_CPU_RECORD_REQUIRED;
	storage.maximum_packet_length = 1500u;
	storage.domain_index = 2u;
	storage.generation = 1u;
	const kinetum_packet_native_storage_operations owner{&storage, test_queues::verify, test_queues::release};
	kinetum_packet_rx_burst_operations rx{};
	rx.state = &queues;
	rx.logical_port = 1u;
	rx.receive_burst = [](void *, packet_record **, uint16_t) noexcept { return kinetum_packet_rx_burst_result{}; };
	rx.receive_native = test_queues::receive;
	rx.native_storage = &owner;
	rx.maximum_burst = 4u;
	kinetum_packet_tx_burst_operations tx{};
	tx.state = &queues;
	tx.transmit_burst = [](void *, packet_record *const *, uint16_t) noexcept -> uint16_t { return 0u; };
	tx.flush = [](void *) noexcept {};
	tx.maybe_flush = [](void *) noexcept -> uint8_t { return 0u; };
	tx.transmit_native = test_queues::transmit;
	tx.native_storage = &owner;
	tx.maximum_burst = 4u;
	ASSERT_TRUE(kinetum_provider_packet_storage_operations_are_valid(&storage));
	ASSERT_TRUE(kinetum_provider_rx_operations_are_valid(&rx));
	ASSERT_TRUE(kinetum_provider_tx_operations_are_valid(&tx));
	std::array<native_packet_slot, 8> slots{};
	std::array<native_packet_slot *, 8> free{};
	const native_packet_binding binding{
		.rx = &rx,
		.tx = &tx,
		.storage = &owner,
		.rx_stream = 0u,
		.tx_stream = 1u,
		.domain = 2u,
		.rx_stage = 0u,
		.tx_stage = 1u,
		.rx_stage_counter = 0u,
		.tx_stage_counter = 1u,
		.tx_stream_counter = 1u,
	};
	worker_native_handoff handoff(binding, 1u, role, credits, *counters.telemetry, slots, free);
	if (future) {
		ASSERT_TRUE(counters.telemetry->reserve_target_epoch(1u, 2u).is_ok());
		credits.bind_future_epoch(2u);
		credits.advance_source_epoch(2u);
	}
	const auto epoch = credits.source_epoch();
	ASSERT_TRUE(future ? role.reserve_future(4u) : role.reserve_active(4u));
	uint64_t bytes = 0u;
	const auto result =
		handoff.receive({.epoch = epoch, .timestamp = 10u, .key = 0u, .capacity = 4u, .future = future}, bytes);
	EXPECT_EQ(result.transferred_count, 3u);
	if (queues.suffix_dirty) {
		std::_Exit(EXIT_SUCCESS);
	}
	EXPECT_EQ(result.rejected_count, 1u);
	EXPECT_EQ(bytes, 180u);
	if (future) {
		role.release_future_reservation(1u);
		handoff.service(1u);
		EXPECT_TRUE(role.active_empty());
		role.rotate_after_activation();
		credits.promote_future_epoch(epoch);
		counters.telemetry->activate_target_epoch(1u, epoch, 2u);
		runtime_telemetry_bank_token token{};
		ASSERT_TRUE(counters.channel->take_completed(token));
		counters.telemetry->complete_aggregation(token);
		counters.telemetry->mark_epoch_aggregated(1u);
		ASSERT_TRUE(counters.telemetry->retire_epoch(1u, epoch).has_value());
		ASSERT_TRUE(counters.channel->take_returned(token));
		counters.telemetry->accept_returned(token);
	} else {
		role.release_active_reservation(1u);
	}
	handoff.service(epoch);
	handoff.service(epoch);
	handoff.flush();
	if (queues.change_start || queues.move_storage) {
		std::_Exit(EXIT_SUCCESS);
	}
	EXPECT_TRUE(handoff.empty());
	EXPECT_TRUE(credits.empty());
	EXPECT_TRUE(role.empty());
	EXPECT_EQ(queues.checked, 3u - queues.accepted);
	EXPECT_EQ(queues.released, 3u - queues.accepted);
	ASSERT_TRUE(role.reserve_active());
	const auto empty =
		handoff.receive({.epoch = epoch, .timestamp = 11u, .key = 0u, .capacity = 1u, .future = false}, bytes);
	EXPECT_EQ(empty.transferred_count, 0u);
	EXPECT_EQ(empty.rejected_count, 0u);
	EXPECT_EQ(bytes, 0u);
	role.release_active_reservation();
	ASSERT_TRUE(counters.telemetry->preflight_shutdown(epoch));
	counters.telemetry->publish_shutdown(epoch, 12u);
	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(counters.channel->take_completed(token));
	auto bank = counters.telemetry->completed_bank(token);
	if (bank.is_ok() && bank->stages.size() == 2u && bank->streams.size() == 2u) {
		EXPECT_EQ(bank->stages[0].in_packets, 3u);
		EXPECT_EQ(bank->stages[0].out_packets, 3u);
		EXPECT_EQ(bank->stages[1].in_packets, 3u);
		EXPECT_EQ(bank->stages[1].out_packets, queues.accepted);
		EXPECT_EQ(bank->stages[1].dropped_packets, 3u - queues.accepted);
		EXPECT_EQ(bank->streams[1].packets, queues.accepted);
		EXPECT_EQ(bank->streams[1].bytes, queues.accepted * 60u);
		EXPECT_EQ(bank->streams[1].rejected_packets, 3u - queues.accepted);
		EXPECT_EQ(bank->engine.dropped_packets, 3u - queues.accepted);
	} else {
		ADD_FAILURE() << "native forwarding did not publish the expected stage and stream populations";
	}
	counters.telemetry->complete_aggregation(token);
	counters.telemetry->mark_epoch_aggregated(epoch);
	EXPECT_FALSE(counters.telemetry->retire_epoch(epoch, 0u).has_value());
}
}  // namespace

/** @brief Every accepted prefix and both source roles conserve receipts, reservations and credits. */
TEST(worker_native_handoff, complete_and_partial_transfers_preserve_original_storage)
{
	for (const bool future : {false, true}) {
		for (uint16_t accepted = 0u; accepted <= 3u; ++accepted) {
			test_queues queues;
			queues.accepted = accepted;
			run_handoff(queues, future);
		}
	}
}

/** @brief Reject a changed refused range and a populated unused RX slot before normal teardown. */
TEST(worker_native_handoff, malformed_foreign_results_fail_at_the_transfer)
{
	test_queues changed;
	changed.accepted = 1u;
	changed.change_start = true;
	EXPECT_EXIT(run_handoff(changed, false), ::testing::ExitedWithCode(EXPECTED_HANDOFF_FAULT), "");
	test_queues moved;
	moved.accepted = 1u;
	moved.move_storage = true;
	EXPECT_EXIT(run_handoff(moved, false), ::testing::ExitedWithCode(EXPECTED_HANDOFF_FAULT), "");
	test_queues dirty;
	dirty.suffix_dirty = true;
	EXPECT_EXIT(run_handoff(dirty, false), ::testing::ExitedWithCode(EXPECTED_HANDOFF_FAULT), "");
}
}  // namespace kinetum::dp
