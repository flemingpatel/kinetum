// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_packet_thread_log_guard.cpp
 * @brief Packet-context diagnostic exclusion and exact live/retired rejection counts.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <thread>

#include "src/common/log.hpp"
#include "src/common/log_service.hpp"
#include "src/common/packet_thread_log_guard.hpp"

namespace kinetum::common
{

/** @brief A packet hook counts once without invoking its formatter or requiring a logger. */
TEST(packet_thread_log_guard, foreign_calls_reject_before_any_cold_work)
{
	const auto before = packet_thread_log_rejections();
	uint32_t formatted = 0;
	{
		packet_thread_log_guard scope;
		for (const auto level : {log_level::INFO, log_level::ERROR, log_level::FATAL}) {
			log_foreign_lazy({level, "grpc", "test.packet", {}}, [&](std::span<char>) {
				++formatted;
				return std::size_t{0};
			});
		}
	}
	EXPECT_EQ(formatted, 0u);
	EXPECT_EQ(packet_thread_log_rejections(), before + 3);
	EXPECT_EQ(process_log_health().packet_thread_rejections, before + 3);
	EXPECT_FALSE(reject_packet_thread_log());
}

/** @brief Cold snapshots conserve concurrent single-writer counts across scope retirement. */
TEST(packet_thread_log_guard, concurrent_scope_retirement_preserves_every_rejection)
{
	const auto before = packet_thread_log_rejections();
	std::atomic<bool> unexpected{false};
	std::array<std::jthread, 8> workers;
	for (auto &worker : workers) {
		worker = std::jthread([&] {
			packet_thread_log_guard scope;
			for (uint32_t index = 0; index < 1000; ++index) {
				if (!reject_packet_thread_log()) {
					unexpected.store(true, std::memory_order_relaxed);
				}
			}
		});
	}
	uint64_t previous = before;
	for (auto &worker : workers) {
		worker.join();
		const auto current = packet_thread_log_rejections();
		EXPECT_GE(current, previous);
		previous = current;
	}
	EXPECT_FALSE(unexpected.load(std::memory_order_relaxed));
	EXPECT_EQ(previous, before + 8000);
}

/** @brief A nested scope cannot replace another packet owner's thread identity. */
TEST(packet_thread_log_guard, nested_ownership_fails_stop)
{
	EXPECT_DEATH(
		{
			packet_thread_log_guard first;
			packet_thread_log_guard second;
		},
		"");
}

}  // namespace kinetum::common
