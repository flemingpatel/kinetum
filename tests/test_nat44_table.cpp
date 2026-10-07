// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_nat44_table.cpp
 * @brief Unit tests for nat44_table session table.
 * @author Fleming Patel
 *
 * Tests verify behavioral properties of the pre-allocated session table:
 * - Unified timestamp: both traffic directions share a single canonical
 *   last_seen_ns per session, preventing one-sided GC eviction
 * - Max sessions enforcement: both policy limit (from config) and slab
 *   capacity hard cap prevent unbounded growth
 * - GC correctness with cursor-based slab walk and unified timestamps
 * - Config validation: max_total_sessions rejected if exceeds slab capacity (fail-closed)
 *
 * Note: zero hot-path allocation is a structural property of the design
 * (pre-allocated cuckoo_map + contiguous slab + freelist). These tests
 * validate the capacity and behavioral contracts that follow from that
 * design, not allocation instrumentation.
 */

#include <gtest/gtest.h>

#include <memory_resource>

#include "src/modules/nat44/nat44_impl.hpp"

// Host authoring model for the strict JSON compiler test.
#include "src/modules/nat44/nat44.pb.h"
#include "tests/module_config_test_helpers.hpp"

using namespace kinetum::modules::nat44;

namespace
{

/** Number of translate() calls between periodic garbage-collection triggers. */
constexpr uint64_t GC_TRIGGER_COUNT = NAT_GC_TRIGGER_MASK + 1;

/** Nanoseconds per second used by explicit fixture timestamps. */
constexpr uint64_t SEC_TO_NS = 1000000000ull;

/**
 * @brief Build a minimal single-context NAT pool using the default PMR resource.
 * @param max_sessions Admitted session population.
 * @param timeout_s Idle session lifetime in seconds.
 * @return Pool configuration with one fixed TEST-NET-3 public address range.
 */
nat_pools_compiled make_test_pools(uint32_t max_sessions = 256, uint32_t timeout_s = 300)
{
	auto &memory = *std::pmr::get_default_resource();
	nat_pools_compiled pools(memory, {0u, 1u});
	pools.session_timeout_s = timeout_s;
	pools.max_sessions = max_sessions;

	nat_pool_compiled pool(memory);
	// 203.0.113.1 - 203.0.113.100 (TEST-NET-3 per RFC5737, 100 IPs)
	pool.public_ranges.push_back({0xCB007101, 0xCB007164, 100});
	pool.total_public_ips = 100;
	pool.port_min = 1024;
	pool.port_max = 65535;
	pool.first_owned_port = 1024;
	pool.owned_port_count = 65535u - 1024u + 1u;
	pools.pools.push_back(std::move(pool));

	return pools;
}

/**
 * @brief Advance periodic GC accounting with one repeated outbound flow.
 *
 * The first call creates a session if absent; later calls refresh that same session.
 * @param table NAT table whose GC call counter is advanced.
 * @param pools Admitted immutable pool configuration.
 * @param now_ns Monotonic timestamp supplied to every translation.
 * @param count Number of translation attempts.
 * @param src_ip Source IPv4 address in host order.
 * @param src_port Source transport port.
 * @param dst_ip Destination IPv4 address in host order.
 * @param dst_port Destination transport port.
 */
void pump_gc_counter(nat44_table &table, const nat_pools_compiled &pools, uint64_t now_ns, uint64_t count,
		     uint32_t src_ip = 0x0aFF0001, uint16_t src_port = 9999, uint32_t dst_ip = 0x01010101,
		     uint16_t dst_port = 80)
{
	uint32_t out_ip;
	uint16_t out_port;
	for (uint64_t i = 0; i < count; ++i) {
		(void)table.translate(now_ns, pools, true, 17, src_ip, src_port, dst_ip, dst_port, &out_ip, &out_port);
	}
}

}  // namespace

// =============================================================================
// Unified Timestamp Tests (single canonical last_seen_ns per session)
// =============================================================================

/**
 * @brief Both outbound and inbound traffic share a single session entry.
 *
 * Verify that creating a session via outbound, then looking it up via inbound,
 * both succeed and resolve to the same canonical session.
 */
TEST(nat44_table_test, unified_timestamp_both_directions)
{
	nat44_table table(256, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(256, 300);

	uint32_t out_ip = 0, rev_ip = 0;
	uint16_t out_port = 0, rev_port = 0;

	// Outbound: create session (10.0.0.1:1234 -> 8.8.8.8:53)
	ASSERT_TRUE(
		table.translate(1 * SEC_TO_NS, pools, true, 17, 0x0a000001, 1234, 0x08080808, 53, &out_ip, &out_port));
	EXPECT_NE(out_ip, 0u);
	EXPECT_NE(out_port, 0u);

	// Inbound: reverse lookup (8.8.8.8:53 -> public_ip:public_port)
	ASSERT_TRUE(
		table.translate(2 * SEC_TO_NS, pools, false, 17, 0x08080808, 53, out_ip, out_port, &rev_ip, &rev_port));

	// Must resolve back to original internal endpoint
	EXPECT_EQ(rev_ip, 0x0a000001u);
	EXPECT_EQ(rev_port, 1234);

	// Both directions share one session - not two copies
	EXPECT_EQ(table.get_stats().active_sessions, 1u);
}

/**
 * @brief Inbound-only traffic prevents GC eviction (unified timestamp proof).
 *
 * Both directions update the same slab-owned last_seen_ns. GC must therefore
 * retain an inbound-active session even when its outbound direction is idle.
 */
TEST(nat44_table_test, inbound_traffic_prevents_gc_eviction)
{
	// Small table with 5-second timeout
	nat44_table table(256, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(256, 5);

	uint32_t pub_ip = 0;
	uint16_t pub_port = 0;

	// T=0s: Create session via outbound
	ASSERT_TRUE(table.translate(0, pools, true, 17, 0x0a000001, 1234, 0x08080808, 53, &pub_ip, &pub_port));
	EXPECT_EQ(table.get_stats().active_sessions, 1u);

	// T=4s: Inbound hit refreshes the canonical timestamp to 4s.
	uint32_t rev_ip = 0;
	uint16_t rev_port = 0;
	ASSERT_TRUE(
		table.translate(4 * SEC_TO_NS, pools, false, 17, 0x08080808, 53, pub_ip, pub_port, &rev_ip, &rev_port));
	EXPECT_EQ(rev_ip, 0x0a000001u);

	// A delayed packet carries an older arrival timestamp. It must not move the
	// canonical session clock backward and make active state appear expired.
	ASSERT_TRUE(table.translate(0, pools, false, 17, 0x08080808, 53, pub_ip, pub_port, &rev_ip, &rev_port));

	// T=6s: Pump translate calls (different flow) to trigger GC.
	// Session A last_seen=4s, timeout=5s. At T=6s: 6-4=2 < 5, so it survives.
	pump_gc_counter(table, pools, 6 * SEC_TO_NS, GC_TRIGGER_COUNT - 3);

	// Session A must still be alive (inbound traffic kept it fresh)
	EXPECT_EQ(table.get_stats().active_sessions, 2u);  // session A + pump session

	// Verify session A is still functional (inbound lookup succeeds)
	rev_ip = 0;
	rev_port = 0;
	ASSERT_TRUE(
		table.translate(6 * SEC_TO_NS, pools, false, 17, 0x08080808, 53, pub_ip, pub_port, &rev_ip, &rev_port))
		<< "Session should survive GC - inbound traffic refreshed the timestamp";
	EXPECT_EQ(rev_ip, 0x0a000001u);
	EXPECT_EQ(rev_port, 1234);
}

// =============================================================================
// Max Sessions Enforcement Tests (bounded growth)
// =============================================================================

/**
 * @brief Policy limit from configuration prevents over-allocation.
 *
 * The pools.max_sessions field (from proto max_total_sessions) is enforced
 * at allocation time. Even when slab has physical capacity remaining, the
 * policy limit caps the number of active sessions.
 */
TEST(nat44_table_test, max_sessions_policy_enforced)
{
	// Slab has 256 physical slots, but policy limits to 10 sessions
	nat44_table table(256, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(10, 300);

	uint32_t out_ip = 0;
	uint16_t out_port = 0;
	const uint64_t now = 1 * SEC_TO_NS;

	// Create 10 sessions (should all succeed)
	for (uint32_t i = 0; i < 10; ++i) {
		ASSERT_TRUE(table.translate(now, pools, true, 17, 0x0a000001, static_cast<uint16_t>(1000 + i),
					    0x08080808, 53, &out_ip, &out_port))
			<< "Session " << i << " should succeed (within policy limit)";
	}
	EXPECT_EQ(table.get_stats().active_sessions, 10u);

	// 11th session must fail (policy limit reached, slab still has room)
	EXPECT_FALSE(table.translate(now, pools, true, 17, 0x0a000001, 2000, 0x08080808, 53, &out_ip, &out_port));
	EXPECT_EQ(table.get_stats().active_sessions, 10u);
	EXPECT_GT(table.get_stats().allocation_failures, 0u);
}

/**
 * @brief Slab capacity is the absolute hard cap (no malloc on hot path).
 *
 * Even if policy allows more sessions than the slab can hold, the freelist
 * exhaustion prevents any allocation beyond slab capacity. This guarantees
 * zero heap allocation on the translate() hot path.
 */
TEST(nat44_table_test, slab_exhaustion_hard_cap)
{
	// Small slab: 32 slots. Policy allows 1000 (larger than slab).
	nat44_table table(32, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(1000, 300);

	uint32_t out_ip = 0;
	uint16_t out_port = 0;
	const uint64_t now = 1 * SEC_TO_NS;

	// Fill all 32 slab slots
	for (uint32_t i = 0; i < 32; ++i) {
		ASSERT_TRUE(table.translate(now, pools, true, 17, 0x0a000001, static_cast<uint16_t>(1000 + i),
					    0x08080808, 53, &out_ip, &out_port))
			<< "Session " << i << " should succeed (slab has capacity)";
	}
	EXPECT_EQ(table.get_stats().active_sessions, 32u);

	// 33rd session must fail (slab exhausted - no malloc, no crash)
	EXPECT_FALSE(table.translate(now, pools, true, 17, 0x0a000001, 2000, 0x08080808, 53, &out_ip, &out_port));
	EXPECT_EQ(table.get_stats().active_sessions, 32u);
}

/**
 * @brief Zero-capacity tables fail closed without touching an empty slab.
 */
TEST(nat44_table_test, zero_capacity_is_safe)
{
	nat44_table table(0, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(1, 300);

	uint32_t out_ip = 0;
	uint16_t out_port = 0;
	EXPECT_FALSE(
		table.translate(1 * SEC_TO_NS, pools, true, 17, 0x0a000001, 1234, 0x08080808, 53, &out_ip, &out_port));
	EXPECT_EQ(table.get_stats().active_sessions, 0u);
	EXPECT_EQ(table.get_stats().allocation_failures, 1u);
}

// =============================================================================
// GC Tests (cursor-based slab walk with unified timestamps)
// =============================================================================

/**
 * @brief GC reclaims expired sessions from the contiguous slab.
 *
 * Create sessions at T=0, advance time past timeout, trigger GC, verify
 * sessions are reclaimed and stats updated correctly.
 */
TEST(nat44_table_test, gc_reclaims_expired_sessions)
{
	nat44_table table(256, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(256, 5);  // 5-second timeout

	uint32_t out_ip = 0;
	uint16_t out_port = 0;

	// T=0: Create 8 sessions
	for (uint32_t i = 0; i < 8; ++i) {
		ASSERT_TRUE(table.translate(0, pools, true, 17, 0x0a000001, static_cast<uint16_t>(1000 + i), 0x08080808,
					    53, &out_ip, &out_port));
	}
	EXPECT_EQ(table.get_stats().active_sessions, 8u);

	// T=10s: All 8 sessions expired (10 - 0 = 10 > 5). Trigger GC.
	// Pump creates 1 fresh session at T=10s which survives.
	pump_gc_counter(table, pools, 10 * SEC_TO_NS, GC_TRIGGER_COUNT - 8);

	auto stats = table.get_stats();
	EXPECT_EQ(stats.total_expired, 8u);
	EXPECT_EQ(stats.active_sessions, 1u);  // Only the pump session remains
}

/**
 * @brief Freed slab slots are reusable after GC.
 *
 * After GC reclaims sessions, the freed slab indices return to the freelist
 * and new sessions can be allocated without any heap allocation.
 */
TEST(nat44_table_test, freed_slots_reusable_after_gc)
{
	nat44_table table(32, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(32, 5);

	uint32_t out_ip = 0;
	uint16_t out_port = 0;

	// T=0: Fill all 32 slots
	for (uint32_t i = 0; i < 32; ++i) {
		ASSERT_TRUE(table.translate(0, pools, true, 17, 0x0a000001, static_cast<uint16_t>(1000 + i), 0x08080808,
					    53, &out_ip, &out_port));
	}
	EXPECT_EQ(table.get_stats().active_sessions, 32u);

	// Slab full - verify allocation fails
	EXPECT_FALSE(table.translate(0, pools, true, 17, 0x0a000001, 5000, 0x08080808, 53, &out_ip, &out_port));

	// T=10s: Trigger GC using an existing session (cache hit, no new allocation).
	// Session 0 (port 1000) gets timestamp updated to T=10s and survives GC.
	// Sessions 1-31 (ports 1001-1031) remain at T=0 -> expired -> evicted.
	pump_gc_counter(table, pools, 10 * SEC_TO_NS, GC_TRIGGER_COUNT - 33, 0x0a000001, 1000, 0x08080808, 53);

	auto stats = table.get_stats();
	EXPECT_EQ(stats.total_expired, 31u);
	EXPECT_EQ(stats.active_sessions, 1u);  // Only session 0 remains

	// Now create 31 new sessions in the freed slab slots
	uint32_t created = 0;
	for (uint32_t i = 0; i < 31; ++i) {
		if (table.translate(10 * SEC_TO_NS, pools, true, 17, 0x0a000001, static_cast<uint16_t>(3000 + i),
				    0x08080808, 53, &out_ip, &out_port)) {
			++created;
		}
	}
	EXPECT_EQ(created, 31u) << "All freed slab slots should be reusable after GC";
	EXPECT_EQ(table.get_stats().active_sessions, 32u);
}

// =============================================================================
// Fail-Closed Behavior
// =============================================================================

/**
 * @brief Unsolicited inbound traffic is rejected (fail-closed).
 *
 * Inbound packets for which no outbound session exists must be dropped.
 */
TEST(nat44_table_test, unsolicited_inbound_rejected)
{
	nat44_table table(256, *std::pmr::get_default_resource(), {0u, 1u});
	auto pools = make_test_pools(256, 300);

	uint32_t out_ip = 0;
	uint16_t out_port = 0;

	// Inbound without prior outbound must fail
	EXPECT_FALSE(
		table.translate(1 * SEC_TO_NS, pools, false, 17, 0x08080808, 53, 0xCB007101, 1024, &out_ip, &out_port));

	auto stats = table.get_stats();
	EXPECT_EQ(stats.inbound_misses, 1u);
	EXPECT_EQ(stats.active_sessions, 0u);
}

// =============================================================================
// Context Ownership
// =============================================================================

/** @brief Separate contexts cannot alias one public endpoint and each reply returns to its own session. */
TEST(nat44_table_test, context_residues_preserve_independent_return_ownership)
{
	constexpr std::string_view CONFIG =
		R"json({"pools":[{"public_ip_ranges":["203.0.113.1"],"port_min":10000,"port_max":10003}],"max_total_sessions":4})json";
	const auto first_policy = kinetum::test::compile_nat_for_test(CONFIG, {0u, 2u});
	const auto second_policy = kinetum::test::compile_nat_for_test(CONFIG, {1u, 2u});
	ASSERT_NE(first_policy, nullptr);
	ASSERT_NE(second_policy, nullptr);
	nat44_table first(4, *std::pmr::get_default_resource(), {0u, 2u});
	nat44_table second(4, *std::pmr::get_default_resource(), {1u, 2u});
	uint32_t first_ip = 0u;
	uint32_t second_ip = 0u;
	uint16_t first_port = 0u;
	uint16_t second_port = 0u;
	ASSERT_TRUE(first.translate(SEC_TO_NS, *first_policy, true, 17, 0x0a000001, 1234, 0x08080808, 9999, &first_ip,
				    &first_port));
	ASSERT_TRUE(second.translate(SEC_TO_NS, *second_policy, true, 17, 0x0a000002, 1234, 0x08080808, 9999,
				     &second_ip, &second_port));
	EXPECT_EQ(first_ip, second_ip);
	EXPECT_EQ(first_port % 2u, 0u);
	EXPECT_EQ(second_port % 2u, 1u);
	EXPECT_NE(first_port, second_port);
	uint32_t restored_ip = 0u;
	uint16_t restored_port = 0u;
	ASSERT_TRUE(first.translate(2 * SEC_TO_NS, *first_policy, false, 17, 0x08080808, 9999, first_ip, first_port,
				    &restored_ip, &restored_port));
	EXPECT_EQ(restored_ip, 0x0a000001u);
	EXPECT_EQ(restored_port, 1234u);
	ASSERT_TRUE(second.translate(2 * SEC_TO_NS, *second_policy, false, 17, 0x08080808, 9999, second_ip, second_port,
				     &restored_ip, &restored_port));
	EXPECT_EQ(restored_ip, 0x0a000002u);
	EXPECT_EQ(restored_port, 1234u);
	EXPECT_FALSE(first.translate(3 * SEC_TO_NS, *first_policy, false, 17, 0x08080808, 9999, second_ip, second_port,
				     &restored_ip, &restored_port));
}

/** @brief Pool updates preserve live endpoints, then expired sessions reuse only the same owner's ports. */
TEST(nat44_table_test, pool_update_preserves_live_endpoints_and_residue_after_expiration)
{
	const auto original = kinetum::test::compile_nat_for_test(
		R"({"pools":[{"public_ip_ranges":["203.0.113.1"],"port_min":10000,"port_max":10003}],"session_timeout_s":1})",
		{1u, 2u});
	const auto replacement = kinetum::test::compile_nat_for_test(
		R"({"pools":[{"public_ip_ranges":["203.0.113.2"],"port_min":20000,"port_max":20003}],"session_timeout_s":1})",
		{1u, 2u});
	ASSERT_NE(original, nullptr);
	ASSERT_NE(replacement, nullptr);
	nat44_table table(4u, *std::pmr::get_default_resource(), {1u, 2u});
	uint32_t old_ip = 0u;
	uint16_t old_port = 0u;
	ASSERT_TRUE(
		table.translate(0u, *original, true, 17u, 0x0a000001u, 1234u, 0x08080808u, 9999u, &old_ip, &old_port));
	uint32_t address = 0u;
	uint16_t port = 0u;
	ASSERT_TRUE(table.translate(SEC_TO_NS, *replacement, true, 17u, 0x0a000001u, 1234u, 0x08080808u, 9999u,
				    &address, &port));
	EXPECT_EQ(address, old_ip);
	EXPECT_EQ(port, old_port);
	EXPECT_EQ(port % 2u, 1u);
	ASSERT_TRUE(table.translate(SEC_TO_NS, *replacement, false, 17u, 0x08080808u, 9999u, old_ip, old_port, &address,
				    &port));
	EXPECT_EQ(address, 0x0a000001u);
	EXPECT_EQ(port, 1234u);
	ASSERT_TRUE(table.translate(SEC_TO_NS, *replacement, true, 17u, 0x0a000002u, 1234u, 0x08080808u, 9999u,
				    &address, &port));
	EXPECT_EQ(address, 0xcb007102u);
	EXPECT_GE(port, 20000u);
	EXPECT_EQ(port % 2u, 1u);
	pump_gc_counter(table, *replacement, 10u * SEC_TO_NS, GC_TRIGGER_COUNT - 4u);
	EXPECT_EQ(table.get_stats().total_expired, 2u);
	EXPECT_FALSE(table.translate(10u * SEC_TO_NS, *replacement, false, 17u, 0x08080808u, 9999u, old_ip, old_port,
				     &address, &port));
	ASSERT_TRUE(table.translate(10u * SEC_TO_NS, *replacement, true, 17u, 0x0a000001u, 1234u, 0x08080808u, 9999u,
				    &address, &port));
	EXPECT_EQ(address, 0xcb007102u);
	EXPECT_EQ(port % 2u, 1u);
}

/** @brief Inclusive odd-width ranges compile exact residue populations without borrowing another owner's ports. */
TEST(nat44_table_test, context_port_capacity_is_exact_at_range_boundaries)
{
	constexpr std::string_view CONFIG =
		R"json({"pools":[{"public_ip_ranges":["203.0.113.1"],"port_min":10000,"port_max":10004}]})json";
	const auto first = kinetum::test::compile_nat_for_test(CONFIG, {0u, 2u});
	const auto second = kinetum::test::compile_nat_for_test(CONFIG, {1u, 2u});
	ASSERT_NE(first, nullptr);
	ASSERT_NE(second, nullptr);
	ASSERT_EQ(first->pools.size(), 1u);
	ASSERT_EQ(second->pools.size(), 1u);
	EXPECT_EQ(first->pools.front().first_owned_port, 10000u);
	EXPECT_EQ(first->pools.front().owned_port_count, 3u);
	EXPECT_EQ(second->pools.front().first_owned_port, 10001u);
	EXPECT_EQ(second->pools.front().owned_port_count, 2u);
	EXPECT_EQ(kinetum::test::compile_nat_for_test(CONFIG, {0u, 0u}), nullptr);
	EXPECT_EQ(kinetum::test::compile_nat_for_test(CONFIG, {2u, 2u}), nullptr);
	EXPECT_EQ(
		kinetum::test::compile_nat_for_test(
			R"json({"pools":[{"public_ip_ranges":["203.0.113.1"],"port_min":65535,"port_max":65535}]})json",
			{0u, 2u}),
		nullptr);
}

// =============================================================================
// Configuration Parsing
// =============================================================================

/**
 * @brief compile_nat_from_json consumes max_total_sessions from JSON.
 *
 * The compiled policy must carry the authored value into runtime admission.
 */
TEST(nat44_table_test, compile_blob_consumes_max_total_sessions)
{
	kinetum::module::nat44::v1::NatPools config;
	config.set_session_timeout_s(60);
	config.set_max_total_sessions(4096);

	auto *pool = config.add_pools();
	pool->add_public_ip_ranges("203.0.113.1");
	pool->set_port_min(1024);
	pool->set_port_max(65535);

	std::string blob = kinetum::test::module_config_json(config);
	auto compiled = kinetum::test::compile_nat_for_test(blob, {0u, 1u});
	ASSERT_NE(compiled, nullptr);
	EXPECT_EQ(compiled->max_sessions, 4096u);
}

/**
 * @brief Configs requesting more than slab capacity are rejected (fail-closed).
 *
 * The per-lcore slab is pre-allocated to NAT_DEFAULT_MAX_SESSIONS. Requesting
 * more than the slab can hold would be under-delivered at runtime, violating
 * the operator's intent. Fail-closed: reject the config entirely.
 */
TEST(nat44_table_test, compile_blob_rejects_excess_max_sessions)
{
	kinetum::module::nat44::v1::NatPools config;
	config.set_session_timeout_s(60);
	config.set_max_total_sessions(200000);	// Far exceeds slab capacity

	auto *pool = config.add_pools();
	pool->add_public_ip_ranges("203.0.113.1");
	pool->set_port_min(1024);
	pool->set_port_max(65535);

	std::string blob = kinetum::test::module_config_json(config);
	auto compiled = kinetum::test::compile_nat_for_test(blob, {0u, 1u});
	EXPECT_EQ(compiled, nullptr) << "Config exceeding slab capacity must be rejected (fail-closed)";
}

/**
 * @brief compile_nat_from_json defaults max_sessions when the field is absent.
 */
TEST(nat44_table_test, compile_blob_defaults_max_sessions_when_unset)
{
	kinetum::module::nat44::v1::NatPools config;
	config.set_session_timeout_s(60);
	// max_total_sessions omitted: compiler selects the bounded default.

	auto *pool = config.add_pools();
	pool->add_public_ip_ranges("203.0.113.1");
	pool->set_port_min(1024);
	pool->set_port_max(65535);

	std::string blob = kinetum::test::module_config_json(config);
	auto compiled = kinetum::test::compile_nat_for_test(blob, {0u, 1u});
	ASSERT_NE(compiled, nullptr);
	EXPECT_EQ(compiled->max_sessions, NAT_DEFAULT_MAX_SESSIONS);
}
