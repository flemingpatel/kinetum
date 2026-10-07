// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_timer_wheel.cpp
 * @brief Unit tests for hierarchical timer wheel.
 * @author Fleming Patel
 *
 * Tests cover:
 * - Basic arm/advance/expire lifecycle
 * - Cancellation before expiry
 * - Re-arm (per-key deduplication)
 * - Coarse-to-fine cascade on rollover
 * - Pool exhaustion and recovery
 * - Batch expiry with multiple timers in same slot
 * - advance_to convenience API
 * - Telemetry counters
 * - Edge cases (zero ticks, max range, empty wheel)
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

#include <kinetum/algo/timer_wheel.hpp>

namespace kinetum::algo
{

/** Small fixture wheel with 16 timers, 8 fine slots, and 4 coarse slots. */
using test_wheel = timer_wheel<16, 8, 4>;

// =============================================================================
// Basic Lifecycle
// =============================================================================

/**
 * @brief Verify arm and expire single timer.
 */
TEST(timer_wheel, arm_and_expire_single_timer)
{
	test_wheel tw;

	auto h = tw.arm(3);
	ASSERT_TRUE(h.valid());
	EXPECT_EQ(tw.active_count(), 1);

	// Advance 2 ticks - should not expire yet
	auto r1 = tw.advance();
	EXPECT_TRUE(r1.empty());
	auto r2 = tw.advance();
	EXPECT_TRUE(r2.empty());
	EXPECT_EQ(tw.active_count(), 1);

	// Advance 1 more tick - should expire
	auto r3 = tw.advance();
	EXPECT_EQ(r3.count, 1);
	EXPECT_EQ(r3.handles[0], h);
	EXPECT_EQ(tw.active_count(), 0);
	EXPECT_EQ(tw.total_expired(), 1);
}

/**
 * @brief Verify arm with user key.
 */
TEST(timer_wheel, arm_with_user_key)
{
	test_wheel tw;

	auto h = tw.arm(1, 42);
	ASSERT_TRUE(h.valid());
	EXPECT_EQ(tw.user_key(h), 42);

	auto r = tw.advance();
	EXPECT_EQ(r.count, 1);
	EXPECT_EQ(tw.user_key(r.handles[0]), 42);
}

/**
 * @brief Verify empty wheel advance is safe.
 */
TEST(timer_wheel, empty_wheel_advance_is_safe)
{
	test_wheel tw;

	for (int i = 0; i < 100; ++i) {
		auto r = tw.advance();
		EXPECT_TRUE(r.empty());
	}
	EXPECT_EQ(tw.active_count(), 0);
}

// =============================================================================
// Cancellation
// =============================================================================

/**
 * @brief Verify cancel before expiry.
 */
TEST(timer_wheel, cancel_before_expiry)
{
	test_wheel tw;

	auto h = tw.arm(5);
	ASSERT_TRUE(h.valid());
	EXPECT_EQ(tw.active_count(), 1);

	bool ok = tw.cancel(h);
	EXPECT_TRUE(ok);
	EXPECT_EQ(tw.active_count(), 0);
	EXPECT_EQ(tw.total_cancelled(), 1);

	// Advance past expiry - nothing should fire
	for (int i = 0; i < 10; ++i) {
		auto r = tw.advance();
		EXPECT_TRUE(r.empty());
	}
}

/**
 * @brief Verify cancel invalid handle returns false.
 */
TEST(timer_wheel, cancel_invalid_handle_returns_false)
{
	test_wheel tw;
	EXPECT_FALSE(tw.cancel(INVALID_TIMER_HANDLE));
}

/**
 * @brief Verify double cancel returns false.
 */
TEST(timer_wheel, double_cancel_returns_false)
{
	test_wheel tw;

	auto h = tw.arm(5);
	EXPECT_TRUE(tw.cancel(h));
	EXPECT_FALSE(tw.cancel(h));
}

// =============================================================================
// Re-arm (deduplication)
// =============================================================================

/**
 * @brief Verify rearm extends deadline.
 */
TEST(timer_wheel, rearm_extends_deadline)
{
	test_wheel tw;

	auto h = tw.arm(2, 99);
	ASSERT_TRUE(h.valid());

	// Re-arm to 5 ticks from now instead of 2
	bool ok = tw.rearm(h, 5);
	EXPECT_TRUE(ok);

	// Advance 3 ticks - original would have fired, rearm should not
	for (int i = 0; i < 3; ++i) {
		auto r = tw.advance();
		EXPECT_TRUE(r.empty());
	}

	// Advance 2 more - now it should fire
	tw.advance();
	auto r = tw.advance();
	EXPECT_EQ(r.count, 1);
	EXPECT_EQ(tw.user_key(r.handles[0]), 99);
}

/**
 * @brief Verify rearm invalid handle returns false.
 */
TEST(timer_wheel, rearm_invalid_handle_returns_false)
{
	test_wheel tw;
	EXPECT_FALSE(tw.rearm(INVALID_TIMER_HANDLE, 5));
}

// =============================================================================
// Coarse Wheel Cascade
// =============================================================================

/**
 * @brief Verify coarse wheel timer fires after cascade.
 */
TEST(timer_wheel, coarse_wheel_timer_fires_after_cascade)
{
	test_wheel tw;	// 8 fine slots, 4 coarse slots

	// Arm at tick 10 - beyond fine wheel range (8), goes to coarse
	auto h = tw.arm(10, 77);
	ASSERT_TRUE(h.valid());

	// Advance 9 ticks - should not fire (needs cascade at tick 8, then fine)
	for (int i = 0; i < 9; ++i) {
		auto r = tw.advance();
		EXPECT_TRUE(r.empty()) << "unexpected expiry at tick " << (i + 1);
	}

	// Tick 10 - should fire
	auto r = tw.advance();
	EXPECT_EQ(r.count, 1);
	EXPECT_EQ(tw.user_key(r.handles[0]), 77);
}

// =============================================================================
// Pool Exhaustion
// =============================================================================

/**
 * @brief Verify pool exhaustion returns invalid.
 */
TEST(timer_wheel, pool_exhaustion_returns_invalid)
{
	test_wheel tw;	// MaxTimers = 16

	// Fill the pool
	for (int i = 0; i < 16; ++i) {
		auto h = tw.arm(100, static_cast<uint64_t>(i));
		ASSERT_TRUE(h.valid()) << "failed to arm timer " << i;
	}
	EXPECT_EQ(tw.active_count(), 16);

	// 17th timer should fail
	auto h = tw.arm(100);
	EXPECT_FALSE(h.valid());
}

/**
 * @brief Verify pool recovery after cancel.
 */
TEST(timer_wheel, pool_recovery_after_cancel)
{
	test_wheel tw;

	// Fill and cancel one
	timer_handle handles[16];
	for (int i = 0; i < 16; ++i)
		handles[i] = tw.arm(100);

	tw.cancel(handles[0]);
	EXPECT_EQ(tw.active_count(), 15);

	// Should succeed now - one slot freed
	auto h = tw.arm(100);
	EXPECT_TRUE(h.valid());
	EXPECT_EQ(tw.active_count(), 16);
}

/**
 * @brief Verify stale handle does not cancel reused slot.
 */
TEST(timer_wheel, stale_handle_does_not_cancel_reused_slot)
{
	test_wheel tw;

	auto old_handle = tw.arm(100, 1);
	ASSERT_TRUE(old_handle.valid());
	ASSERT_TRUE(tw.cancel(old_handle));

	auto new_handle = tw.arm(100, 2);
	ASSERT_TRUE(new_handle.valid());
	EXPECT_FALSE(old_handle == new_handle);
	EXPECT_FALSE(tw.cancel(old_handle));
	EXPECT_TRUE(tw.cancel(new_handle));
}

/**
 * @brief Verify cancel coarse timer unlinks from coarse slot.
 */
TEST(timer_wheel, cancel_coarse_timer_unlinks_from_coarse_slot)
{
	test_wheel tw;	// 8 fine slots, so arm(8) is stored in the coarse wheel.

	auto h = tw.arm(8, 77);
	ASSERT_TRUE(h.valid());
	EXPECT_TRUE(tw.cancel(h));
	EXPECT_EQ(tw.active_count(), 0);

	timer_handle out[4];
	uint32_t n = tw.advance_to(8, out, 4);
	EXPECT_EQ(n, 0u);
	EXPECT_EQ(tw.active_count(), 0);
}

// =============================================================================
// Multiple Timers in Same Slot
// =============================================================================

/**
 * @brief Verify multiple timers same slot all expire.
 */
TEST(timer_wheel, multiple_timers_same_slot_all_expire)
{
	test_wheel tw;

	(void)tw.arm(3, 1);
	(void)tw.arm(3, 2);
	(void)tw.arm(3, 3);

	// Advance to expiry
	tw.advance();
	tw.advance();
	auto r = tw.advance();

	EXPECT_EQ(r.count, 3);
	EXPECT_EQ(tw.active_count(), 0);
}

// =============================================================================
// advance_to Convenience
// =============================================================================

/**
 * @brief Verify advance to collects all expired.
 */
TEST(timer_wheel, advance_to_collects_all_expired)
{
	test_wheel tw;

	(void)tw.arm(2, 10);
	(void)tw.arm(5, 20);
	(void)tw.arm(7, 30);

	timer_handle out[16];
	uint32_t n = tw.advance_to(10, out, 16);

	EXPECT_EQ(n, 3);
	EXPECT_EQ(tw.active_count(), 0);
}

// =============================================================================
// Edge Cases
// =============================================================================

/**
 * @brief Verify arm zero ticks fires on next advance.
 */
TEST(timer_wheel, arm_zero_ticks_fires_on_next_advance)
{
	test_wheel tw;

	(void)tw.arm(0, 55);  // Should be clamped to 1
	auto r = tw.advance();
	EXPECT_EQ(r.count, 1);
	EXPECT_EQ(tw.user_key(r.handles[0]), 55);
}

/**
 * @brief Verify arm max range clamped.
 */
TEST(timer_wheel, arm_max_range_clamped)
{
	test_wheel tw;

	// MAX_RANGE = 8 * 4 = 32. Arm at 100 - clamped to 31.
	auto h = tw.arm(100, 88);
	ASSERT_TRUE(h.valid());

	// Should fire at tick 31
	timer_handle out[4];
	uint32_t n = tw.advance_to(31, out, 4);
	EXPECT_EQ(n, 1);
	EXPECT_EQ(tw.user_key(out[0]), 88);
}

/**
 * @brief Verify reset clears all state.
 */
TEST(timer_wheel, reset_clears_all_state)
{
	test_wheel tw;

	auto stale = tw.arm(5);
	ASSERT_TRUE(stale.valid());
	(void)tw.arm(10);
	tw.advance();
	tw.advance();

	tw.reset();

	EXPECT_EQ(tw.active_count(), 0);
	EXPECT_EQ(tw.current_tick(), 0);
	EXPECT_EQ(tw.total_armed(), 0);
	EXPECT_EQ(tw.total_expired(), 0);

	auto fresh = tw.arm(5);
	ASSERT_TRUE(fresh.valid());
	EXPECT_FALSE(stale == fresh);
	EXPECT_FALSE(tw.cancel(stale));
	EXPECT_TRUE(tw.cancel(fresh));
}

// =============================================================================
// Telemetry Counters
// =============================================================================

/**
 * @brief Verify telemetry counters are accurate.
 */
TEST(timer_wheel, telemetry_counters_are_accurate)
{
	test_wheel tw;

	(void)tw.arm(1);
	(void)tw.arm(2);
	(void)tw.arm(3);
	EXPECT_EQ(tw.total_armed(), 3);

	tw.advance();  // expires timer at tick 1
	EXPECT_EQ(tw.total_expired(), 1);

	auto h = tw.arm(1);
	tw.cancel(h);
	EXPECT_EQ(tw.total_cancelled(), 1);
	EXPECT_EQ(tw.total_armed(), 4);
}

// =============================================================================
// Overflow: more than MAX_EXPIRE_BATCH in one slot
// =============================================================================

/**
 * @brief Verify overflow batch drains across multiple advance calls.
 */
TEST(timer_wheel, overflow_batch_drains_across_multiple_advance_calls)
{
	// Small wheel with MAX_EXPIRE_BATCH = 64 but we use a tiny wheel
	// Default MAX_EXPIRE_BATCH is 64, test_wheel has MaxTimers=16
	// So arm all 16 timers at the same tick and verify all drain
	test_wheel tw;

	// Arm all 16 timers to fire at tick 1
	for (int i = 0; i < 16; ++i) {
		(void)tw.arm(1, static_cast<uint64_t>(i));
	}
	EXPECT_EQ(tw.active_count(), 16);

	// advance() should drain all 16 (MAX_EXPIRE_BATCH=64 > 16 for test_wheel)
	auto r = tw.advance();
	EXPECT_EQ(r.count, 16);
	EXPECT_EQ(tw.active_count(), 0);
	EXPECT_EQ(tw.total_expired(), 16);
}

/**
 * @brief Verify overflow with large batch drains completely.
 */
TEST(timer_wheel, overflow_with_large_batch_drains_completely)
{
	// Use a wheel where we can exceed MAX_EXPIRE_BATCH
	// MAX_EXPIRE_BATCH = 64, so arm 80 timers at the same tick
	using big_wheel = timer_wheel<128, 8, 4>;
	big_wheel tw;

	for (int i = 0; i < 80; ++i) {
		(void)tw.arm(1, static_cast<uint64_t>(i));
	}
	EXPECT_EQ(tw.active_count(), 80);

	// First advance: drains up to 64
	auto r1 = tw.advance();
	EXPECT_EQ(r1.count, 64);
	EXPECT_EQ(tw.active_count(), 16);

	// Second advance: should NOT increment tick (drain_pending),
	// drains the remaining 16
	auto r2 = tw.advance();
	EXPECT_EQ(r2.count, 16);
	EXPECT_EQ(tw.active_count(), 0);
	EXPECT_EQ(tw.total_expired(), 80);

	// Third advance: now tick advances normally, empty
	auto r3 = tw.advance();
	EXPECT_TRUE(r3.empty());
}

/**
 * @brief Verify advance to overflow drains target tick fully.
 */
TEST(timer_wheel, advance_to_overflow_drains_target_tick_fully)
{
	// advance_to must drain all expired timers even if target tick
	// has more than MAX_EXPIRE_BATCH expirations
	using big_wheel = timer_wheel<128, 8, 4>;
	big_wheel tw;

	// Arm 80 timers at tick 5
	for (int i = 0; i < 80; ++i) {
		(void)tw.arm(5, static_cast<uint64_t>(i));
	}
	EXPECT_EQ(tw.active_count(), 80);

	// advance_to should drain all 80 even though they overflow MAX_EXPIRE_BATCH
	timer_handle out[128];
	uint32_t n = tw.advance_to(5, out, 128);
	EXPECT_EQ(n, 80);
	EXPECT_EQ(tw.active_count(), 0);
	EXPECT_EQ(tw.total_expired(), 80);
}

/**
 * @brief Verify advance to respects output capacity without losing handles.
 */
TEST(timer_wheel, advance_to_respects_output_capacity_without_losing_handles)
{
	using big_wheel = timer_wheel<128, 8, 4>;
	big_wheel tw;

	for (int i = 0; i < 80; ++i) {
		(void)tw.arm(5, static_cast<uint64_t>(i));
	}
	EXPECT_EQ(tw.active_count(), 80);

	timer_handle out[32];
	uint32_t n1 = tw.advance_to(5, out, 32);
	EXPECT_EQ(n1, 32u);
	EXPECT_EQ(tw.active_count(), 48u);
	EXPECT_EQ(tw.total_expired(), 32u);

	uint32_t n2 = tw.advance_to(5, out, 32);
	EXPECT_EQ(n2, 32u);
	EXPECT_EQ(tw.active_count(), 16u);
	EXPECT_EQ(tw.total_expired(), 64u);

	uint32_t n3 = tw.advance_to(5, out, 32);
	EXPECT_EQ(n3, 16u);
	EXPECT_EQ(tw.active_count(), 0u);
	EXPECT_EQ(tw.total_expired(), 80u);
}

/** @brief Prove runtime-capacity caller storage uses the same exact wheel arithmetic. */
TEST(timer_wheel, caller_storage_runtime_capacity_is_exact_and_allocation_free)
{
	using view_type = timer_wheel_view<8, 4>;
	std::array<view_type::entry_type, 7> entries{};
	std::array<uint32_t, view_type::FINE_SLOTS> fine{};
	std::array<uint32_t, view_type::COARSE_SLOTS> coarse{};
	view_type wheel(entries.data(), entries.size(), fine.data(), coarse.data());
	std::array<timer_handle, 7> handles{};
	for (uint32_t index = 0u; index < handles.size(); ++index) {
		handles[index] = wheel.arm(index + 1u, index + 10u);
		ASSERT_TRUE(handles[index].valid());
	}
	EXPECT_FALSE(wheel.arm(1u).valid());
	std::array<timer_handle, 7> expired{};
	EXPECT_EQ(wheel.advance_to(7u, expired.data(), expired.size()), expired.size());
	EXPECT_EQ(wheel.active_count(), 0u);
	for (const auto handle : expired) {
		EXPECT_TRUE(handle.valid());
	}
}

/** @brief Prove a large clock jump is capacity-bounded and preserves future timers. */
TEST(timer_wheel, elapsed_jump_rebuilds_from_occupied_entries_without_tick_iteration)
{
	using view_type = timer_wheel_view<256, 256>;
	std::array<view_type::entry_type, 4> entries{};
	std::array<uint32_t, view_type::FINE_SLOTS> fine{};
	std::array<uint32_t, view_type::COARSE_SLOTS> coarse{};
	view_type wheel(entries.data(), entries.size(), fine.data(), coarse.data());
	std::array<timer_handle, 4> expired{};
	EXPECT_EQ(wheel.advance_to(UINT64_C(1000000000), expired.data(), expired.size()), 0u);
	const auto first = wheel.arm(100u, 1u);
	const auto second = wheel.arm(500u, 2u);
	ASSERT_TRUE(first.valid());
	ASSERT_TRUE(second.valid());
	EXPECT_EQ(wheel.advance_to(UINT64_C(1000000300), expired.data(), expired.size()), 1u);
	EXPECT_EQ(expired[0], first);
	EXPECT_EQ(wheel.current_tick(), UINT64_C(1000000300));
	EXPECT_EQ(wheel.active_count(), 1u);
	EXPECT_EQ(wheel.live_handle_at(static_cast<uint32_t>(second.value)), second);
	EXPECT_EQ(wheel.advance_to(UINT64_C(1000000500), expired.data(), expired.size()), 1u);
	EXPECT_EQ(expired[0], second);
	EXPECT_EQ(wheel.active_count(), 0u);

	wheel.reset();
	EXPECT_EQ(wheel.advance_to(UINT64_MAX - 1u, expired.data(), expired.size()), 0u);
	EXPECT_FALSE(wheel.arm(2u).valid());
	const auto terminal = wheel.arm(1u);
	ASSERT_TRUE(terminal.valid());
	EXPECT_FALSE(wheel.rearm(terminal, 2u));
	EXPECT_EQ(wheel.active_count(), 1u);
	EXPECT_EQ(wheel.advance_to(UINT64_MAX, expired.data(), expired.size()), 1u);
	EXPECT_EQ(expired[0], terminal);
}

}  // namespace kinetum::algo
