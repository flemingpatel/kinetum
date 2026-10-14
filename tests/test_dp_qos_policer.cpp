// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_qos_policer.cpp
 * @brief QoS policer behavior and admission tests.
 * @author Fleming Patel
 *
 * The QoS policer implements per-flow rate limiting using a token bucket
 * algorithm. This is the mechanism behind Quality of Service enforcement
 * in the Edge Gateway pipeline.
 *
 * Token Bucket Algorithm:
 * -----------------------
 * - Each flow has a virtual bucket that fills at CIR (Committed Information Rate)
 * - Bucket has maximum capacity = burst_bytes
 * - Each packet consumes tokens equal to its size
 * - If insufficient tokens, packet is marked/dropped
 *
 * Exact Credit:
 * -------------
 * The policer retains fractional bytes in an unsigned 128-bit numerator
 * over one billion. Repeated short intervals earn the same credit as their
 * combined duration, without floating-point arithmetic or rounding loss.
 *
 * Owner-Local Design:
 * -------------------
 * Each executable context has owner-worker-local policer state. The packet
 * path takes no locks; the deployment routes each flow to one context owner.
 *
 * Wire-Format Testing:
 * --------------------
 * QoS module is read-only for packet buffer (only modifies DSCP for remarking).
 * Tests verify packet buffer integrity after processing.
 *
 * @see src/modules/qos/qos_impl.hpp
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <memory_resource>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "src/modules/qos/qos_impl.hpp"
#include "src/modules/qos/qos_module.hpp"
#include "src/dp/dp_engine.hpp"
#include "src/modules/qos/qos.pb.h"
#include "tests/module_config_test_helpers.hpp"
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/test_dp_helpers.hpp"

// KINETUM_QOS_MODULE_PATH is defined by CMake at compile time.
#ifndef KINETUM_QOS_MODULE_PATH
#error "KINETUM_QOS_MODULE_PATH must be defined by CMake"
#endif

/** @brief Explicit lifecycle-memory contract for each QoS module fixture. */
constexpr kinetum::test::module_test_resource_contract TEST_MODULE_RESOURCES{
	std::size_t{16} * 1024u * 1024u,
	std::size_t{2} * 1024u * 1024u,
};

//==============================================================================
// Token Bucket Tests
//==============================================================================

using kinetum::modules::qos::policer_result;

namespace
{

/**
 * @brief Construct a valid directional key for one source address.
 * @param source Source IPv4 value in host byte order.
 * @return UDP identity with fixed destination and ports.
 */
[[nodiscard]] kinetum::modules::qos::flow_key test_flow(uint32_t source) noexcept
{
	return {source, 0xcb007101u, 12345u, 9999u, 17u, kinetum::modules::qos::flow_kind::TRANSPORT};
}

/**
 * @brief Build one exact 512-byte packet so a 1-KiB allowance admits two packets.
 * @param destination Destination IPv4 value in host byte order.
 * @param port Destination UDP port.
 * @return Complete Ethernet/IPv4/UDP frame with a valid IPv4 checksum.
 */
[[nodiscard]] std::vector<uint8_t> qos_packet(uint32_t destination = 0xcb00710au, uint16_t port = 9999u)
{
	return build_eth_ipv4_udp(0x0a000001u, destination, 12345u, port, 0u, std::vector<uint8_t>(470u, 0u));
}

/** @brief Own a real admitted QoS image, exact policy, parser, and bounded lifecycle storage. */
class QosModuleTest : public ::testing::Test {
    protected:
	/** @brief Admit a 1-Kbit/s, 1-KiB profile under the deployed 16-MiB context budget. */
	void SetUp() override
	{
		auto admitted = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
										 TEST_MODULE_RESOURCES, "qos0@lane_0");
		ASSERT_TRUE(admitted.is_ok()) << admitted.error().message();
		module_ = std::move(admitted).value();
		ASSERT_TRUE(module_->prepare_and_activate(1u, R"({"default_profile":"default","profiles":[)"
							      R"({"name":"default","cir_kbps":1,"cbs_kb":1}]})")
				    .is_ok());
		parse_.set_stage_id("parse");
		parse_.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	}

	/**
	 * @param name Exact registered counter name.
	 * @return Owner-local value; a missing registration records a test failure.
	 */
	[[nodiscard]] uint64_t counter(std::string_view name) const
	{
		const auto &owner = *module_->context().lifecycle_owner;
		for (std::size_t index = 1u; index <= owner.telemetry_handle_count(); ++index) {
			const auto *row = owner.telemetry_descriptor(
				static_cast<kinetum::dp::lifecycle::lifecycle_telemetry_handle>(index));
			if (row != nullptr && row->kind == kinetum::dp::lifecycle::lifecycle_telemetry_kind::COUNTER &&
			    name == row->counter.name) {
				return row->counter.value;
			}
		}
		ADD_FAILURE() << "Missing QoS counter: " << name;
		return UINT64_MAX;
	}

	/** @brief Check the four mutually exclusive causes against the aggregate in this context. */
	void expect_drop_accounting() const
	{
		EXPECT_EQ(counter("qos.packets_dropped"),
			  counter("qos.unconfigured_drops") + counter("qos.rate_limit_drops") +
				  counter("qos.flow_capacity_drops") + counter("qos.invalid_input_drops"));
	}

	std::unique_ptr<kinetum::test::exact_module_test_context> module_;  ///< Exact image/configuration owner.
	kinetum::dp::dp_engine engine_;	   ///< Serialized component-test execution owner.
	kinetum::axiom::v1::Stage parse_;  ///< Production IPv4 parser configuration.
};

}  // namespace

/**
 * @brief Verify token bucket correctly enforces rate limiting.
 *
 * Test Scenario:
 * - Profile: 1KB/s CIR, 1KB burst
 * - At t=0: bucket is full (1000 bytes)
 * - Send 500 + 500 bytes: should be allowed (consumes full bucket)
 * - Send 1 more byte: should be denied (bucket empty)
 * - Wait 1 second: bucket refills 1000 bytes
 * - Send 1000 bytes: should be allowed (full refill)
 * - Send 1 more byte: should be denied (bucket empty again)
 *
 * Time Units:
 * - Policer uses nanoseconds internally
 * - 1 second = 1,000,000,000 nanoseconds
 *
 */
TEST(qos_policer, exact_token_bucket)
{
	// One context owner supplies every processing-time observation.
	kinetum::modules::qos::qos_policer p(kinetum::modules::qos::QOS_DEFAULT_MAX_FLOWS,
					     *std::pmr::get_default_resource());

	// Create rate-limiting profile
	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000;  // 1KB/s committed information rate
	prof.burst_bytes = 1000;      // 1KB burst (bucket capacity)
	kinetum::modules::qos::qos_runtime_tuning runtime;

	const auto flow = test_flow(123);

	// At t=0, bucket full (burst), allow up to burst bytes
	uint64_t t0 = 1000000000ull;  // 1 second in nanoseconds

	// First 500 bytes: allowed
	EXPECT_EQ(p.police(t0, prof, runtime, flow, 500), policer_result::ALLOWED)
		<< "First 500 bytes should be allowed (bucket has 1000)";

	// Second 500 bytes: allowed (now bucket empty)
	EXPECT_EQ(p.police(t0, prof, runtime, flow, 500), policer_result::ALLOWED)
		<< "Second 500 bytes should be allowed (bucket had 500 remaining)";

	// One more byte: denied (bucket exhausted)
	EXPECT_EQ(p.police(t0, prof, runtime, flow, 1), policer_result::RATE_LIMIT)
		<< "Bucket is empty, 1 byte should be denied";

	// Regressed platform time is a contradiction, before any credit mutation.
	EXPECT_DEATH((void)p.police(t0 - 1000000000ull, prof, runtime, flow, 1), "");
	const uint64_t t_half = t0 + 500000000ull;
	EXPECT_EQ(p.police(t_half, prof, runtime, flow, 750), policer_result::RATE_LIMIT)
		<< "Only 500 bytes may refill after half a second";

	// After 1 second, refill 1000 bytes (CIR = 1000 bytes/s)
	uint64_t t1 = t0 + 1000000000ull;  // +1 second

	// 1000 bytes: allowed (full refill)
	EXPECT_EQ(p.police(t1, prof, runtime, flow, 1000), policer_result::ALLOWED)
		<< "After 1s, bucket should have 1000 bytes from refill";

	// One more byte: denied (bucket empty again)
	EXPECT_EQ(p.police(t1, prof, runtime, flow, 1), policer_result::RATE_LIMIT)
		<< "Bucket exhausted again after consuming refill";

	// Existing flow state survives exact configuration activation, but credit
	// above the replacement profile's smaller burst must not. Without the
	// clamp, this flow would incorrectly retain 900 bytes of old-policy credit.
	const auto reconfigured_flow = test_flow(456);
	ASSERT_EQ(p.police(t1, prof, runtime, reconfigured_flow, 100), policer_result::ALLOWED);
	kinetum::modules::qos::qos_profile_compiled smaller_burst(*std::pmr::get_default_resource());
	smaller_burst.name = prof.name;
	smaller_burst.cir_bytes_per_s = prof.cir_bytes_per_s;
	smaller_burst.conform_dscp = prof.conform_dscp;
	smaller_burst.burst_bytes = 100;
	EXPECT_EQ(p.police(t1, smaller_burst, runtime, reconfigured_flow, 101), policer_result::RATE_LIMIT);
	EXPECT_EQ(p.police(t1, smaller_burst, runtime, reconfigured_flow, 100), policer_result::ALLOWED);

	// Maximal representable rate and elapsed time must saturate at the burst
	// ceiling without overflowing the wide refill intermediate.
	kinetum::modules::qos::qos_policer extreme_gap_policer(kinetum::modules::qos::QOS_DEFAULT_MAX_FLOWS,
							       *std::pmr::get_default_resource());
	kinetum::modules::qos::qos_profile_compiled extreme_rate(*std::pmr::get_default_resource());
	extreme_rate.name = prof.name;
	extreme_rate.burst_bytes = prof.burst_bytes;
	extreme_rate.conform_dscp = prof.conform_dscp;
	extreme_rate.cir_bytes_per_s = std::numeric_limits<uint64_t>::max();
	const auto extreme_flow = test_flow(789);
	ASSERT_EQ(extreme_gap_policer.police(0, extreme_rate, runtime, extreme_flow, 1000), policer_result::ALLOWED);
	EXPECT_EQ(extreme_gap_policer.police(std::numeric_limits<uint64_t>::max(), extreme_rate, runtime, extreme_flow,
					     1000),
		  policer_result::ALLOWED);
}

//==============================================================================
// Pre-Allocated Capacity Tests
//==============================================================================

/**
 * @brief Verify fail-closed behavior when flow table is exhausted.
 *
 * With max_flows=4, the fifth distinct flow must be dropped while the four
 * admitted flows remain owned. No unpoliced passthrough is permitted.
 */
TEST(qos_policer, capacity_exhaustion_drops_new_flows)
{
	// Small capacity to test boundary
	kinetum::modules::qos::qos_policer p(4, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	// Disable GC so flows are not evicted during this test
	runtime.gc_trigger_mask = ~0ull;

	const uint64_t t = 1000000000ull;

	// Fill all 4 slots with distinct flows
	for (uint32_t f = 1; f <= 4; ++f) {
		EXPECT_EQ(p.police(t, prof, runtime, test_flow(f), 100), policer_result::ALLOWED)
			<< "Flow " << f << " must be allowed (capacity not yet full)";
	}

	EXPECT_EQ(p.active_flows(), 4u);

	// 5th flow must be dropped (fail-closed)
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(5), 100), policer_result::FLOW_CAPACITY)
		<< "5th flow must be dropped - table full, fail-closed";

	EXPECT_EQ(p.active_flows(), 4u);
}

/**
 * @brief Verify that existing flows still work after capacity is reached.
 *
 * When the table is full, packets for already-tracked flows must still
 * be processed normally. Only NEW flows are rejected.
 */
TEST(qos_policer, existing_flows_work_at_capacity)
{
	kinetum::modules::qos::qos_policer p(4, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	runtime.gc_trigger_mask = ~0ull;

	const uint64_t t = 1000000000ull;

	// Fill all 4 slots
	for (uint32_t f = 1; f <= 4; ++f) {
		EXPECT_EQ(p.police(t, prof, runtime, test_flow(f), 100), policer_result::ALLOWED);
	}

	// Existing flow 1 at t+1s: tokens refilled, should allow
	const uint64_t t1 = t + 1000000000ull;
	EXPECT_EQ(p.police(t1, prof, runtime, test_flow(1), 100), policer_result::ALLOWED)
		<< "Existing flow must still be policed normally at capacity";
}

/**
 * @brief Verify flow slot reuse after GC reclaims expired flows.
 *
 * 1. Fill to capacity (4 flows)
 * 2. Advance time past idle timeout
 * 3. Trigger GC to reclaim expired slots
 * 4. New flow must now be accepted (reused slot from freelist)
 */
TEST(qos_policer, flow_reuse_after_gc)
{
	kinetum::modules::qos::qos_policer p(4, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	// Trigger GC every packet (mask=0 means every packet triggers)
	runtime.gc_trigger_mask = 0;
	runtime.gc_max_evictions = 256;
	runtime.idle_timeout_ns = 5000000000ull;  // 5s idle timeout

	const uint64_t t0 = 1000000000ull;

	// Fill all 4 slots
	for (uint32_t f = 1; f <= 4; ++f) {
		EXPECT_EQ(p.police(t0, prof, runtime, test_flow(f), 100), policer_result::ALLOWED);
	}
	EXPECT_EQ(p.active_flows(), 4u);

	// 5th flow rejected at capacity
	EXPECT_EQ(p.police(t0, prof, runtime, test_flow(5), 100), policer_result::FLOW_CAPACITY);

	// Advance time past idle timeout (t0 + 6s > 5s timeout)
	const uint64_t t1 = t0 + 6000000000ull;

	// An unlimited replacement still drives retirement of stale bounded-policy
	// state without allocating a bucket for the unlimited flow.
	kinetum::modules::qos::qos_profile_compiled unlimited(*std::pmr::get_default_resource());
	unlimited.name = "unlimited";
	unlimited.cir_bytes_per_s = 0u;
	unlimited.burst_bytes = 0u;
	EXPECT_EQ(p.police(t1, unlimited, runtime, test_flow(99), 100), policer_result::ALLOWED);
	EXPECT_EQ(p.active_flows(), 0u);

	// Returning to a bounded profile can consume one reclaimed slot.
	EXPECT_EQ(p.police(t1, prof, runtime, test_flow(99), 100), policer_result::ALLOWED);
	EXPECT_EQ(p.active_flows(), 1u);
}

/**
 * @brief Verify repeated capacity rejection preserves all admitted flow state.
 *
 * Rejected new flows must not displace an admitted flow or change occupancy.
 */
TEST(qos_policer, repeated_capacity_rejection_preserves_admitted_flows)
{
	kinetum::modules::qos::qos_policer p(2, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	runtime.gc_trigger_mask = ~0ull;

	const uint64_t t = 1000000000ull;

	// Fill both slots
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(1), 100), policer_result::ALLOWED);
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(2), 100), policer_result::ALLOWED);

	// 3 rejected attempts
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(10), 100), policer_result::FLOW_CAPACITY);
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(11), 100), policer_result::FLOW_CAPACITY);
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(12), 100), policer_result::FLOW_CAPACITY);

	EXPECT_EQ(p.active_flows(), 2u);
	EXPECT_EQ(p.police(t + 1'000'000'000ull, prof, runtime, test_flow(1), 100), policer_result::ALLOWED);
	EXPECT_EQ(p.police(t + 1'000'000'000ull, prof, runtime, test_flow(2), 100), policer_result::ALLOWED);
}

/**
 * @brief Verify zero-capacity policer is safe (no crash, fail-closed).
 *
 * qos_policer(0) creates an empty slab. All packets must be dropped
 * fail-closed, and GC must not access an absent slab entry.
 */
TEST(qos_policer, zero_capacity_is_safe)
{
	kinetum::modules::qos::qos_policer p(0, *std::pmr::get_default_resource());

	kinetum::modules::qos::qos_profile_compiled prof(*std::pmr::get_default_resource());
	prof.name = "default";
	prof.cir_bytes_per_s = 1000000;
	prof.burst_bytes = 10000;
	kinetum::modules::qos::qos_runtime_tuning runtime;
	// Trigger GC every packet to exercise the GC guard path
	runtime.gc_trigger_mask = 0;

	const uint64_t t = 1000000000ull;

	// All packets must be dropped (no slab capacity)
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(1), 100), policer_result::FLOW_CAPACITY)
		<< "Zero-capacity policer must drop all packets (fail-closed)";
	EXPECT_EQ(p.police(t, prof, runtime, test_flow(2), 100), policer_result::FLOW_CAPACITY)
		<< "Zero-capacity policer must drop all packets (fail-closed)";

	EXPECT_EQ(p.active_flows(), 0u);
}

/** @brief Failed cuckoo insertion returns its slab index and preserves every prior bucket. */
TEST(qos_policer, cuckoo_collision_failure_releases_claimed_capacity)
{
	using namespace kinetum::modules::qos;
	qos_policer policer(16u, *std::pmr::get_default_resource());
	qos_profile_compiled profile(*std::pmr::get_default_resource());
	profile.cir_bytes_per_s = 125u;
	profile.burst_bytes = 64u;
	qos_runtime_tuning runtime;
	// These semantic keys share one candidate in each four-bucket table.
	constexpr std::array<uint32_t, 9> SOURCES{36u, 54u, 70u, 75u, 90u, 134u, 137u, 158u, 168u};
	for (std::size_t index = 0u; index < 8u; ++index) {
		ASSERT_EQ(policer.police(0u, profile, runtime, test_flow(SOURCES[index]), 64u),
			  policer_result::ALLOWED);
	}
	for (uint32_t attempt = 0u; attempt < 3u; ++attempt) {
		EXPECT_EQ(policer.police(0u, profile, runtime, test_flow(SOURCES.back()), 64u),
			  policer_result::FLOW_CAPACITY);
	}
	EXPECT_EQ(policer.active_flows(), 8u);
	for (std::size_t index = 0u; index < 8u; ++index) {
		EXPECT_EQ(policer.police(0u, profile, runtime, test_flow(SOURCES[index]), 1u),
			  policer_result::RATE_LIMIT);
	}
	EXPECT_EQ(policer.police(0u, profile, runtime, test_flow(1u), 64u), policer_result::ALLOWED);
	EXPECT_EQ(policer.active_flows(), 9u);
}

/** @brief Fractions survive profile replacement, while clock history survives unlimited policy and GC. */
TEST(qos_policer, exact_fractions_and_context_clock_survive_policy_changes)
{
	using namespace kinetum::modules::qos;
	qos_policer policer(4u, *std::pmr::get_default_resource());
	qos_profile_compiled profile(*std::pmr::get_default_resource());
	profile.cir_bytes_per_s = 125u;
	profile.burst_bytes = 64u;
	qos_runtime_tuning runtime;
	const auto key = test_flow(1u);
	ASSERT_EQ(policer.police(0u, profile, runtime, key, 64u), policer_result::ALLOWED);
	for (uint64_t step = 1u; step < 512000u; ++step) {
		ASSERT_EQ(policer.police(step * 1000u, profile, runtime, key, 64u), policer_result::RATE_LIMIT);
	}
	EXPECT_EQ(policer.police(512000000u, profile, runtime, key, 64u), policer_result::ALLOWED);
	EXPECT_EQ(policer.police(516000000u, profile, runtime, key, 1u), policer_result::RATE_LIMIT);
	// Retained half-byte plus 2 ms at the replacement 250-byte/s rate is one byte.
	profile.cir_bytes_per_s = 250u;
	EXPECT_EQ(policer.police(518000000u, profile, runtime, key, 1u), policer_result::ALLOWED);
	profile.cir_bytes_per_s = 0u;
	runtime.gc_trigger_mask = 0u;
	runtime.idle_timeout_ns = 1u;
	EXPECT_EQ(policer.police(600000000u, profile, runtime, {}, 100u), policer_result::ALLOWED);
	EXPECT_EQ(policer.active_flows(), 0u);
	EXPECT_DEATH((void)policer.police(599999999u, profile, runtime, {}, 0u), "");
	profile.cir_bytes_per_s = 125u;
	EXPECT_DEATH((void)policer.police(599999999u, profile, runtime, test_flow(2u), 0u), "");
	EXPECT_EQ(policer.police(600000000u, profile, runtime, key, 64u), policer_result::ALLOWED);
}

/** @brief Malformed keys reject before GC or allocation; equality ignores implicit key padding. */
TEST(qos_policer, semantic_keys_reject_missing_identity_without_mutating_flow_state)
{
	using namespace kinetum::modules::qos;
	qos_policer policer(4u, *std::pmr::get_default_resource());
	qos_profile_compiled profile(*std::pmr::get_default_resource());
	profile.cir_bytes_per_s = 125u;
	profile.burst_bytes = 64u;
	qos_runtime_tuning runtime;
	runtime.gc_trigger_mask = 0u;
	runtime.idle_timeout_ns = 1u;
	ASSERT_EQ(policer.police(0u, profile, runtime, test_flow(1u), 64u), policer_result::ALLOWED);
	EXPECT_EQ(policer.police(100u, profile, runtime, {}, 64u), policer_result::INVALID_INPUT);
	EXPECT_EQ(policer.active_flows(), 1u);
	flow_key first = test_flow(1u);
	flow_key second = first;
	auto *padding = reinterpret_cast<unsigned char *>(&second);
	padding[sizeof(second) - 1u] = 0xffu;
	EXPECT_EQ(first, second);
	EXPECT_EQ(flow_identity_hash{}(first), flow_identity_hash{}(second));
}

/** @brief Distinct tuples with the same parser hash have separate allowances; rehashing cannot renew credit. */
TEST_F(QosModuleTest, tuple_identity_survives_parser_hash_collisions_and_rehashing)
{
	kinetum::test::packet_record_test_owner first(qos_packet());
	kinetum::test::packet_record_test_owner second(qos_packet(0xcb00710bu, 9997u));
	ASSERT_TRUE(first.valid()) << first.error();
	ASSERT_TRUE(second.valid()) << second.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, first.get()));
	ASSERT_TRUE(engine_.execute_stage(&parse_, second.get()));
	ASSERT_EQ(first.metadata().flow_hash, 4199874031u);
	ASSERT_EQ(first.metadata().flow_hash, second.metadata().flow_hash);
	EXPECT_TRUE(module_->process(*first.get(), 0u));
	EXPECT_TRUE(module_->process(*first.get(), 0u));
	++first.metadata().flow_hash;
	EXPECT_FALSE(module_->process(*first.get(), 0u));
	EXPECT_TRUE(module_->process(*second.get(), 0u));
	EXPECT_TRUE(module_->process(*second.get(), 0u));
	EXPECT_FALSE(module_->process(*second.get(), 0u));
	EXPECT_EQ(counter("qos.active_flows"), 2u);
	EXPECT_EQ(counter("qos.rate_limit_drops"), 2u);
	EXPECT_EQ(counter("qos.packets_allowed"), 4u);
	expect_drop_accounting();
}

/** @brief Post-rewrite SoA fields own identity, zero ports are real values, and l4_off is not presence evidence. */
TEST_F(QosModuleTest, post_rewrite_lanes_and_zero_ports_define_transport_identity)
{
	kinetum::test::packet_record_test_owner packet(qos_packet());
	ASSERT_TRUE(packet.valid()) << packet.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, packet.get()));
	EXPECT_TRUE(module_->process(*packet.get(), 0u));
	EXPECT_TRUE(module_->process(*packet.get(), 0u));
	// Rewrite both wire and lanes, preserving the packet coherence contract.
	kinetum::algo::net::write_be32(packet.get()->storage.data + 26u, 0xcb00710cu);
	kinetum::algo::net::write_be16(packet.get()->storage.data + 34u, 0u);
	kinetum::algo::net::write_be16(packet.get()->storage.data + 36u, 0u);
	kinetum::algo::net::write_be16(packet.get()->storage.data + 24u,
				       compute_ipv4_checksum(packet.get()->storage.data + 14u, 20u));
	packet.metadata().src_ipv4 = 0xcb00710cu;
	packet.metadata().src_port = 0u;
	packet.metadata().dst_port = 0u;
	// A callback lane is not the proof of transport extent; bytes and IHL are.
	packet.metadata().l4_offset = 0u;
	EXPECT_TRUE(module_->process(*packet.get(), 0u));
	EXPECT_TRUE(module_->process(*packet.get(), 0u));
	EXPECT_FALSE(module_->process(*packet.get(), 0u));
	EXPECT_EQ(counter("qos.active_flows"), 2u);
	expect_drop_accounting();
}

/** @brief Declared IPv4 extent bounds transport eligibility even when Ethernet padding contains apparent ports. */
TEST_F(QosModuleTest, truncated_transport_and_ip_options_use_declared_extent)
{
	for (uint8_t protocol : {uint8_t{6}, uint8_t{17}}) {
		for (uint8_t ihl : {uint8_t{20}, uint8_t{24}}) {
			for (uint16_t extent = ihl; extent < ihl + 4u; ++extent) {
				auto bytes = qos_packet();
				bytes[14u] = static_cast<uint8_t>(0x40u | (ihl / 4u));
				bytes[23u] = protocol;
				kinetum::algo::net::write_be16(bytes.data() + 16u, extent);
				kinetum::test::packet_record_test_owner packet(bytes);
				ASSERT_TRUE(packet.valid()) << packet.error();
				ASSERT_TRUE(engine_.execute_stage(&parse_, packet.get()));
				// Even plausible lane values do not supply missing on-wire bytes.
				packet.metadata().src_port = 12345u;
				packet.metadata().dst_port = 9999u;
				EXPECT_FALSE(module_->process(*packet.get(), 0u));
			}
		}
	}
	EXPECT_EQ(counter("qos.active_flows"), 0u);
	EXPECT_EQ(counter("qos.invalid_input_drops"), 16u);
	// The exact four-byte edge with a 24-byte header is eligible, including zero ports.
	auto bytes = qos_packet();
	bytes[14u] = 0x46u;
	kinetum::algo::net::write_be16(bytes.data() + 16u, 28u);
	std::fill(bytes.begin() + 38u, bytes.begin() + 42u, uint8_t{0});
	kinetum::test::packet_record_test_owner complete(bytes);
	ASSERT_TRUE(complete.valid()) << complete.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, complete.get()));
	EXPECT_TRUE(module_->process(*complete.get(), 0u));
	EXPECT_EQ(counter("qos.active_flows"), 1u);
	expect_drop_accounting();
}

/** @brief First and later fragments share the explicit aggregate; another protocol has its own aggregate. */
TEST_F(QosModuleTest, fragment_and_non_transport_aggregates_have_canonical_ports)
{
	for (uint16_t fragment : {uint16_t{0x2000}, uint16_t{1}, uint16_t{2}}) {
		auto bytes = qos_packet();
		kinetum::algo::net::write_be16(bytes.data() + 20u, fragment);
		kinetum::test::packet_record_test_owner packet(bytes);
		ASSERT_TRUE(packet.valid()) << packet.error();
		ASSERT_TRUE(engine_.execute_stage(&parse_, packet.get()));
		EXPECT_EQ(module_->process(*packet.get(), 0u), fragment != 2u);
	}
	kinetum::test::packet_record_test_owner zero_ports(
		build_eth_ipv4_udp(0x0a000001u, 0xcb00710au, 0u, 0u, 0u, std::vector<uint8_t>(470u, 0u)));
	ASSERT_TRUE(zero_ports.valid()) << zero_ports.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, zero_ports.get()));
	EXPECT_TRUE(module_->process(*zero_ports.get(), 0u));
	auto bytes = qos_packet();
	bytes[23u] = 1u;
	kinetum::test::packet_record_test_owner icmp(bytes);
	ASSERT_TRUE(icmp.valid()) << icmp.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, icmp.get()));
	EXPECT_TRUE(module_->process(*icmp.get(), 0u));
	EXPECT_EQ(counter("qos.active_flows"), 3u);
	expect_drop_accounting();
}

/** @brief Only processing time refills credit; the same-time excessive burst still drops. */
TEST_F(QosModuleTest, processing_time_is_independent_of_reordered_origin_timestamps)
{
	kinetum::test::packet_record_test_owner packet(qos_packet());
	ASSERT_TRUE(packet.valid()) << packet.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, packet.get()));
	packet.metadata().timestamp_ns = 9000000000u;
	EXPECT_TRUE(module_->process(*packet.get(), 0u));
	EXPECT_TRUE(module_->process(*packet.get(), 0u));
	packet.metadata().timestamp_ns = 1u;
	EXPECT_FALSE(module_->process(*packet.get(), 0u));
	// 512 bytes / 125 bytes/s = 4.096 seconds, independent of the old RX timestamp.
	EXPECT_TRUE(module_->process(*packet.get(), 4096000000u));
	EXPECT_FALSE(module_->process(*packet.get(), 4096000000u));
	EXPECT_DEATH((void)module_->process(*packet.get(), 4095999999u), "");
	EXPECT_EQ(counter("qos.rate_limit_drops"), 2u);
	expect_drop_accounting();
}

/** @brief Exact epoch activation retains both consumed flow credit and the context clock. */
TEST_F(QosModuleTest, activation_does_not_reset_the_policer)
{
	kinetum::test::packet_record_test_owner packet(qos_packet());
	ASSERT_TRUE(packet.valid()) << packet.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, packet.get()));
	EXPECT_TRUE(module_->process(*packet.get(), 100u));
	EXPECT_TRUE(module_->process(*packet.get(), 100u));
	ASSERT_TRUE(module_->prepare_and_activate(2u, R"({"default_profile":"default","profiles":[)"
						      R"({"name":"default","cir_kbps":2,"cbs_kb":1}]})")
			    .is_ok());
	packet.metadata().epoch = 2u;
	EXPECT_FALSE(module_->process(*packet.get(), 100u));
	EXPECT_DEATH((void)module_->process(*packet.get(), 99u), "");
	// Replacement rate is 250 bytes/s: one 512-byte refill takes 2.048 seconds.
	EXPECT_TRUE(module_->process(*packet.get(), 2048000100u));
	EXPECT_EQ(counter("qos.active_flows"), 1u);
	expect_drop_accounting();
}

/** @brief An unlimited replacement needs no packet key but still enforces time and remarking prerequisites. */
TEST_F(QosModuleTest, unlimited_profile_keeps_clock_and_remarking_validation)
{
	kinetum::test::packet_record_test_owner packet(qos_packet());
	ASSERT_TRUE(packet.valid()) << packet.error();
	// Unparsed input cannot establish a bounded flow identity.
	EXPECT_FALSE(module_->process(*packet.get(), 100u));
	ASSERT_TRUE(module_->prepare_and_activate(2u,
						  R"({"default_profile":"unlimited","profiles":[)"
						  R"({"name":"unlimited","cir_kbps":0,"cbs_kb":0},)"
						  R"({"name":"dscp_10","cir_kbps":0,"cbs_kb":0,"conform_dscp":20}]})")
			    .is_ok());
	packet.metadata().epoch = 2u;
	EXPECT_TRUE(module_->process(*packet.get(), 100u));
	packet.metadata().dscp = 10u;
	packet.get()->storage.data[15u] = 40u;
	EXPECT_FALSE(module_->process(*packet.get(), 100u));
	EXPECT_EQ(counter("qos.active_flows"), 0u);
	EXPECT_EQ(counter("qos.invalid_input_drops"), 2u);
	EXPECT_DEATH((void)module_->process(*packet.get(), 99u), "");
	expect_drop_accounting();
}

/** @brief Exhaustion of the deployed flow budget counts a capacity refusal, not a rate rejection. */
TEST_F(QosModuleTest, flow_admission_refusal_is_classified_without_losing_existing_state)
{
	kinetum::test::packet_record_test_owner packet(qos_packet());
	ASSERT_TRUE(packet.valid()) << packet.error();
	ASSERT_TRUE(engine_.execute_stage(&parse_, packet.get()));
	uint32_t admitted = 0u;
	for (uint32_t source = 1u; source <= kinetum::modules::qos::QOS_DEFAULT_MAX_FLOWS + 1u; ++source) {
		kinetum::algo::net::write_be32(packet.get()->storage.data + 26u, source);
		kinetum::algo::net::write_be16(packet.get()->storage.data + 24u,
					       compute_ipv4_checksum(packet.get()->storage.data + 14u, 20u));
		packet.metadata().src_ipv4 = source;
		if (!module_->process(*packet.get(), 0u)) {
			break;
		}
		++admitted;
	}
	ASSERT_GT(admitted, 0u);
	EXPECT_EQ(counter("qos.active_flows"), admitted);
	EXPECT_EQ(counter("qos.flow_capacity_drops"), 1u);
	EXPECT_EQ(counter("qos.rate_limit_drops"), 0u);
	kinetum::algo::net::write_be32(packet.get()->storage.data + 26u, 1u);
	kinetum::algo::net::write_be16(packet.get()->storage.data + 24u,
				       compute_ipv4_checksum(packet.get()->storage.data + 14u, 20u));
	packet.metadata().src_ipv4 = 1u;
	EXPECT_TRUE(module_->process(*packet.get(), 0u));
	EXPECT_FALSE(module_->process(*packet.get(), 0u));
	EXPECT_EQ(counter("qos.rate_limit_drops"), 1u);
	expect_drop_accounting();
}

/** @brief Missing policy is counted, while corrupt prepared pointers fail stop in packets and health. */
TEST_F(QosModuleTest, absent_and_contradictory_configuration_have_distinct_fates)
{
	std::array<uint8_t, 512> first{};
	std::array<uint8_t, 64> second{};
	kinetum_batch_t batch{};
	batch.ctx = &module_->context().packet_context;
	batch.epoch = 1u;
	batch.count = 2u;
	batch.data[0] = first.data();
	batch.data[1] = second.data();
	batch.len[0] = 512u;
	batch.len[1] = 64u;
	batch.now_ns = 123u;
	EXPECT_EQ(module_->descriptor().process(&batch), 0u);
	EXPECT_EQ(counter("qos.unconfigured_drops"), 2u);
	EXPECT_EQ(counter("qos.bytes_dropped"), 576u);
	expect_drop_accounting();
	batch.now_ns = 122u;
	EXPECT_DEATH((void)module_->descriptor().process(&batch), "");
	batch.now_ns = 123u;
	const auto *exact = static_cast<const kinetum::modules::qos_packet_config *>(module_->active_packet_config());
	ASSERT_NE(exact, nullptr);
	for (bool missing_default : {false, true}) {
		auto malformed = *exact;
		if (missing_default) {
			malformed.default_profile = nullptr;
		} else {
			malformed.profiles = nullptr;
		}
		batch.epoch_config = &malformed;
		EXPECT_DEATH((void)module_->descriptor().process(&batch), "");
		EXPECT_DEATH((void)module_->descriptor().health_check(batch.ctx, 1u, &malformed), "");
	}
}

//==============================================================================
// QoS Module Wire-Format Verification Tests
//==============================================================================

/**
 * @brief Verify QoS module does not corrupt packet buffer on PERMIT.
 *
 * This catches offset defects in the otherwise read-only path and in optional
 * DSCP remarking.
 *
 * Test verifies:
 * 1. Ethernet header is NOT corrupted after QoS permit
 * 2. IP src/dst addresses are unchanged
 * 3. UDP ports are unchanged
 * 4. IP checksum is valid (may be updated for DSCP change)
 */
TEST(qos_policer, wire_format_permit_unchanged)
{
	kinetum::dp::dp_engine eng;

	// Build test packet with high burst profile (will permit)
	auto bytes = build_eth_ipv4_udp(0xC0A80101,  // src: 192.168.1.1
					0xC0A80201,  // dst: 192.168.2.1
					12345,	     // src_port
					8080,	     // dst_port
					0,	     // dscp (will use default)
					{0x01, 0x02, 0x03, 0x04});

	// Save original Ethernet header before processing
	uint8_t orig_eth[14];
	save_ethernet_header(bytes.data(), orig_eth);

	// Verify original packet structure
	auto pre_verify = verify_wire_format(bytes.data(), bytes.size(), 0xC0A80101, 0xC0A80201, 12345, 8080);
	ASSERT_TRUE(pre_verify.ok) << "Pre-QoS: " << pre_verify.failure_reason;

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Setup pipeline
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// QoS config: high-rate profile (will permit small packets)
	kinetum::module::qos::v1::QosProfiles qos_config;
	qos_config.set_default_profile("default");

	auto *profile = qos_config.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(1000000);	 // 1 Gbps (very high, will permit)
	profile->set_cbs_kb(1024);	 // 1MB burst

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(qos_config)).is_ok());

	// Execute parse and QoS
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get(), 0u)) << "QoS should PERMIT packet with high-rate profile";

	// Verify that QoS changed no packet field outside its declared DSCP byte.

	const uint8_t *pkt_data = packet.data();
	const std::size_t pkt_len = packet.size();

	// 1. Ethernet header must be unchanged
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth)) << "Ethernet header corrupted during QoS processing";

	EXPECT_TRUE(verify_ethernet_intact(pkt_data, pkt_len)) << "Ethernet header integrity check failed";

	// 2. IP src/dst and UDP ports should be unchanged (QoS only touches DSCP)
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_hdr = pkt_data + wire_offsets::UDP_HDR_START;

	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);
	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	uint16_t wire_src_port = kinetum::algo::net::read_be16(udp_hdr + 0);
	uint16_t wire_dst_port = kinetum::algo::net::read_be16(udp_hdr + 2);

	EXPECT_EQ(wire_src_ip, 0xC0A80101u) << "QoS should not modify src_ip";
	EXPECT_EQ(wire_dst_ip, 0xC0A80201u) << "QoS should not modify dst_ip";
	EXPECT_EQ(wire_src_port, 12345) << "QoS should not modify src_port";
	EXPECT_EQ(wire_dst_port, 8080) << "QoS should not modify dst_port";

	// 3. Verify IP checksum is valid
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_hdr + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_hdr, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum invalid after QoS";

	// 4. Verify metadata-wire consistency
	const auto &metadata = packet.metadata();
	auto consistency = verify_metadata_wire_consistency(pkt_data, pkt_len, metadata.src_ipv4, metadata.dst_ipv4,
							    metadata.src_port, metadata.dst_port);
	EXPECT_TRUE(consistency.ok) << consistency.failure_reason;
}

// =============================================================================
// QoS DSCP Remarking (conform_dscp)
// =============================================================================

/**
 * @brief Verify DSCP remark validates bytes before policing and updates wire truth.
 */
TEST(qos_policer, conform_dscp_remark_writes_on_wire)
{
	// Configure QoS with conform_dscp=10 - every conforming packet
	// should have its on-wire DSCP set to 10 and checksum recomputed.
	kinetum::dp::dp_engine eng;

	auto bytes = build_eth_ipv4_udp(0xC0A80101,  // src: 192.168.1.1
					0xC0A80201,  // dst: 192.168.2.1
					12345,	     // src_port
					8080,	     // dst_port
					0,	     // dscp=0 (will be remarked to 10)
					{0x01, 0x02, 0x03, 0x04});

	// Record original DSCP (should be 0)
	const uint8_t orig_dscp = bytes[wire_offsets::IP_HDR_START + 1] >> 2;
	ASSERT_EQ(orig_dscp, 0) << "Test packet should start with DSCP=0";

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Parse stage
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("parse0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	kinetum::module::qos::v1::QosProfiles qos_config;
	qos_config.set_default_profile("default");

	auto *profile = qos_config.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(1000000);	 // 1 Gbps (will permit)
	profile->set_cbs_kb(1);
	profile->set_conform_dscp(10);	// Remark conforming packets to DSCP=10

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos_dscp@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(qos_config)).is_ok());

	// Malformed same-flow packets must not consume tokens or allocate flow state
	// before the remarking precondition rejects them.
	for (std::size_t attempt = 0u; attempt < 32u; ++attempt) {
		kinetum::test::packet_record_test_owner malformed(bytes);
		ASSERT_TRUE(malformed.valid()) << malformed.error();
		ASSERT_TRUE(eng.execute_stage(&parse, malformed.get()));
		malformed.get()->storage.data[wire_offsets::IP_HDR_START] = 0x65u;
		EXPECT_FALSE(module->process(*malformed.get(), 0u));
	}

	// Execute
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get(), 0u)) << "QoS should PERMIT packet";

	// Verify on-wire DSCP was remarked
	const uint8_t *pkt_data = packet.data();
	const uint8_t *ip_hdr = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t wire_dscp = ip_hdr[1] >> 2;
	const uint8_t wire_ecn = ip_hdr[1] & 0x03;

	EXPECT_EQ(wire_dscp, 10) << "On-wire DSCP should be remarked to 10";
	EXPECT_EQ(wire_ecn, 0) << "ECN bits should be preserved (was 0)";

	// Verify IP checksum is still valid after remark
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_hdr + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_hdr, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum must be valid after DSCP remark";

	// Verify IP src/dst and UDP ports are untouched
	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_hdr + 12);
	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_hdr + 16);
	EXPECT_EQ(wire_src_ip, 0xC0A80101u) << "DSCP remark should not modify src_ip";
	EXPECT_EQ(wire_dst_ip, 0xC0A80201u) << "DSCP remark should not modify dst_ip";
}

/**
 * @brief Verify empty config is rejected by exact module preparation.
 */
TEST(qos_policer, empty_config_rejected_by_module_prepare)
{
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.qos", KINETUM_QOS_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "qos_empty@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();

	const auto status = module->prepare_and_activate(1, {});
	EXPECT_FALSE(status.is_ok()) << "QoS must reject empty config instead of installing an implicit fallback";
}
