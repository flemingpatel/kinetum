// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dp_nat44.cpp
 * @brief NAT44 module behavior and admission tests.
 * @author Fleming Patel
 *
 * The NAT44 module implements Network Address Port Translation (NAPT) for
 * IPv4 traffic. It is an ordinary SDK module using the same APIs and image
 * lifecycle as customer modules.
 *
 * NAT44 Session Lifecycle:
 * ------------------------
 * 1. Outbound packet arrives (private src -> public dst)
 * 2. NAT creates session: maps (private_ip:private_port) -> (public_ip:public_port)
 * 3. Packet rewritten: src_ip = public_ip, src_port = public_port
 * 4. Inbound reply arrives (public dst -> NAT public_ip:public_port)
 * 5. NAT looks up session, rewrites: dst_ip = private_ip, dst_port = private_port
 *
 * Checksum Handling:
 * ------------------
 * - IPv4 and TCP/UDP checksums: adjusted from valid input after endpoint changes
 * - IPv4 UDP checksum absence is preserved; Ethernet padding is unchanged
 * - Uses one's complement arithmetic
 *
 * Session Timeout:
 * ----------------
 * - Sessions expire after configurable timeout (default 300s)
 * - Garbage collection runs periodically with bounded work per iteration
 *
 * @see src/modules/nat44/nat44_module.cpp
 * @see src/modules/nat44/nat44.proto
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <set>
#include <thread>
#include <vector>

#include "src/dp/dp_engine.hpp"
#include <kinetum/algo/net.hpp>
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_record_test_harness.hpp"
#include "tests/packet_runtime_test_fixture.hpp"
#include "tests/test_dp_helpers.hpp"

// Module-owned NAT44 proto (generated from src/modules/nat44/nat44.proto)
#include "src/modules/nat44/nat44.pb.h"
#include "tests/module_config_test_helpers.hpp"

// KINETUM_NAT44_MODULE_PATH is defined by CMake at compile time.
#ifndef KINETUM_NAT44_MODULE_PATH
#error "KINETUM_NAT44_MODULE_PATH must be defined by CMake"
#endif

/** @brief Explicit lifecycle-memory contract for each NAT44 module fixture. */
constexpr kinetum::test::module_test_resource_contract TEST_MODULE_RESOURCES{
	64u * 1024u * 1024u,
	2u * 1024u * 1024u,
};

/**
 * @brief Install a valid checksum on one complete fixed-header UDP fixture.
 * @param bytes Mutable Ethernet/IPv4/UDP frame created by the packet builder.
 * @return true after independent full checksum generation; false for incomplete bounds.
 */
static bool prepare_udp_checksum(std::vector<uint8_t> &bytes)
{
	if (bytes.size() < wire_offsets::MIN_UDP_PACKET) {
		return false;
	}
	auto *ip = bytes.data() + wire_offsets::IP_HDR_START;
	auto *udp = bytes.data() + wire_offsets::UDP_HDR_START;
	const std::size_t length = kinetum::algo::net::read_be16(udp + 4u);
	if (length < 8u || length > bytes.size() - wire_offsets::UDP_HDR_START) {
		return false;
	}
	kinetum::algo::net::write_be16(udp + 6u, 0u);
	uint16_t checksum = compute_ipv4_l4_checksum({17u, ip, udp, length});
	if (checksum == 0u) {
		checksum = UINT16_MAX;
	}
	kinetum::algo::net::write_be16(udp + 6u, checksum);
	return true;
}

/** @brief Return a complete TCP fixture with an independent valid transport checksum. */
static std::vector<uint8_t> make_tcp_checksum_packet()
{
	auto bytes = build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234u, 80u, 0u, {});
	bytes.resize(wire_offsets::ETH_HDR_LEN + 20u + 22u, 0u);
	auto *ip = bytes.data() + wire_offsets::IP_HDR_START;
	auto *tcp = bytes.data() + wire_offsets::UDP_HDR_START;
	std::memset(tcp + 4u, 0, 18u);
	tcp[12] = 0x50u;
	ip[9] = 6u;
	kinetum::algo::net::write_be16(ip + 2u, 42u);
	kinetum::algo::net::write_be16(ip + 10u, compute_ipv4_checksum(ip, 20u));
	kinetum::algo::net::write_be16(tcp + 16u, compute_ipv4_l4_checksum({6u, ip, tcp, 22u}));
	return bytes;
}

/** @brief Return steering is derived from the translated port and rejects an unavailable owner. */
TEST(dp_nat44, selector_uses_port_residues_with_exact_permitted_membership)
{
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	const auto select = module->descriptor().select_contexts;
	ASSERT_NE(select, nullptr);
	kinetum_context_selection_batch batch{};
	batch.count = KINETUM_MAX_BURST;
	std::array<uint32_t, KINETUM_MAX_BURST> selected{};
	const std::array<uint32_t, 2u> permitted{0u, 2u};
	const uint64_t bitmap = 5u;
	const kinetum_context_selection_targets targets{3u, 2u, permitted.data(), &bitmap};
	uint64_t expected = 0u;
	for (uint16_t lane = 0u; lane < batch.count; ++lane) {
		batch.src_ip[lane] = UINT32_C(0x08080808);
		batch.dst_ip[lane] = UINT32_C(0xcb00710a);
		batch.src_port[lane] = 53u;
		batch.dst_port[lane] = static_cast<uint16_t>(40000u + lane);
		batch.proto[lane] = 17u;
		batch.platform_flags[lane] = KINETUM_PKT_F_L3_IPV4 | KINETUM_PKT_F_L4_UDP;
		if (batch.dst_port[lane] % targets.context_count != 1u) {
			expected |= UINT64_C(1) << lane;
		}
	}
	EXPECT_EQ(select(&batch, &targets, selected.data()), expected);
	for (uint16_t lane = 0u; lane < batch.count; ++lane) {
		if ((expected & (UINT64_C(1) << lane)) != 0u) {
			EXPECT_EQ(selected[lane], batch.dst_port[lane] % targets.context_count);
		}
	}
}

/** @brief Original tuples select consistently across ingress queues, while fragments ignore ports. */
TEST(dp_nat44, selector_is_independent_of_rss_and_classifies_portless_input)
{
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	const auto select = module->descriptor().select_contexts;
	ASSERT_NE(select, nullptr);
	kinetum_context_selection_batch batch{};
	batch.count = KINETUM_MAX_BURST;
	std::array<uint32_t, KINETUM_MAX_BURST> first{};
	std::array<uint32_t, KINETUM_MAX_BURST> second{};
	const std::array<uint32_t, 2u> permitted{1u, 3u};
	const uint64_t bitmap = 10u;
	const kinetum_context_selection_targets targets{4u, 2u, permitted.data(), &bitmap};
	for (uint16_t lane = 0u; lane < batch.count; ++lane) {
		batch.src_ip[lane] = UINT32_C(0x0a000001);
		batch.dst_ip[lane] = UINT32_C(0x08080808);
		batch.src_port[lane] = static_cast<uint16_t>(20000u + lane);
		batch.dst_port[lane] = 53u;
		batch.proto[lane] = 17u;
		batch.platform_flags[lane] = KINETUM_PKT_F_L3_IPV4 | KINETUM_PKT_F_L4_UDP;
	}
	EXPECT_EQ(select(&batch, &targets, first.data()), UINT64_MAX);
	for (uint16_t lane = 0u; lane < batch.count; ++lane) {
		batch.input_port[lane] = 1u;
		batch.flow_hash[lane] = UINT32_MAX - lane;
		EXPECT_TRUE(first[lane] == 1u || first[lane] == 3u);
	}
	EXPECT_EQ(select(&batch, &targets, second.data()), UINT64_MAX);
	EXPECT_EQ(first, second);
	EXPECT_NE(std::find(first.begin(), first.end(), 1u), first.end());
	EXPECT_NE(std::find(first.begin(), first.end(), 3u), first.end());
	for (uint16_t lane = 0u; lane < batch.count; ++lane) {
		batch.src_ip[lane] = UINT32_C(0x08080808);
		batch.platform_flags[lane] = KINETUM_PKT_F_L3_IPV4 | KINETUM_PKT_F_FRAGMENT;
	}
	EXPECT_EQ(select(&batch, &targets, first.data()), UINT64_MAX);
	for (uint16_t lane = 0u; lane < batch.count; ++lane) {
		batch.src_port[lane] = UINT16_MAX;
		batch.dst_port[lane] = 0u;
	}
	EXPECT_EQ(select(&batch, &targets, second.data()), UINT64_MAX);
	EXPECT_EQ(first, second);
}

/** @brief Incremental endpoint updates preserve TCP zero and encode a computed UDP zero as all ones. */
TEST(dp_nat44, translated_checksum_zero_obeys_transport_semantics)
{
	for (const bool udp : {false, true}) {
		SCOPED_TRACE(udp);
		auto module_or = kinetum::test::exact_module_test_context::create(
			"kinetum.nat44", KINETUM_NAT44_MODULE_PATH, TEST_MODULE_RESOURCES, "nat0@lane_0");
		ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
		auto module = std::move(module_or).value();
		ASSERT_TRUE(
			module->prepare_and_activate(
				      1u,
				      R"({"pools":[{"public_ip_ranges":["203.0.113.10-203.0.113.10"],"port_min":40000,"port_max":40010}]})")
				.is_ok());
		const std::size_t checksum_offset = udp ? 6u : 16u;
		const std::size_t header_size = udp ? 8u : 20u;
		const std::size_t packet_size = wire_offsets::UDP_HDR_START + header_size + 2u;
		const uint8_t protocol = udp ? 17u : 6u;
		auto original =
			udp ? build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234u, 80u, 0u, {0u, 0u}) :
			      make_tcp_checksum_packet();
		if (original.size() != packet_size) {
			FAIL() << "checksum fixture requires " << packet_size << " bytes, got " << original.size();
		}
		if (udp) {
			ASSERT_TRUE(prepare_udp_checksum(original));
		}
		kinetum::test::packet_record_test_owner probe(original);
		ASSERT_TRUE(probe.valid()) << probe.error();
		kinetum::dp::dp_engine engine;
		kinetum::axiom::v1::Stage parse;
		parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
		ASSERT_TRUE(engine.execute_stage(&parse, probe.get()));
		ASSERT_TRUE(module->process(*probe.get()));
		auto *const probe_bytes = probe.data();
		if (probe_bytes == nullptr || probe.size() != packet_size) {
			FAIL() << "translated probe lost its complete payload backing";
		}
		// The probe is fixture-owned and will not be submitted again.
		auto *translated_ip = probe_bytes + wire_offsets::IP_HDR_START;
		auto *translated_l4 = probe_bytes + wire_offsets::UDP_HDR_START;
		kinetum::algo::net::write_be16(translated_l4 + checksum_offset, 0u);
		const uint16_t payload =
			compute_ipv4_l4_checksum({protocol, translated_ip, translated_l4, header_size + 2u});
		auto *ip = original.data() + wire_offsets::IP_HDR_START;
		auto *l4 = original.data() + wire_offsets::UDP_HDR_START;
		kinetum::algo::net::write_be16(l4 + header_size, payload);
		kinetum::algo::net::write_be16(l4 + checksum_offset, 0u);
		uint16_t before = compute_ipv4_l4_checksum({protocol, ip, l4, header_size + 2u});
		if (udp && before == 0u) {
			before = UINT16_MAX;
		}
		kinetum::algo::net::write_be16(l4 + checksum_offset, before);
		kinetum::test::packet_record_test_owner packet(original);
		ASSERT_TRUE(packet.valid()) << packet.error();
		ASSERT_TRUE(engine.execute_stage(&parse, packet.get()));
		ASSERT_TRUE(module->process(*packet.get()));
		const auto *const packet_bytes = packet.data();
		if (packet_bytes == nullptr || packet.size() != packet_size) {
			FAIL() << "translated packet lost its complete payload backing";
		}
		const auto *after = packet_bytes + wire_offsets::UDP_HDR_START;
		EXPECT_EQ(kinetum::algo::net::read_be16(after + checksum_offset), udp ? UINT16_MAX : 0u);
		EXPECT_EQ(compute_ipv4_l4_checksum(
				  {protocol, packet_bytes + wire_offsets::IP_HDR_START, after, header_size + 2u}),
			  0u);
	}
}

/** @brief Endpoint adjustment preserves input checksum corruption instead of silently repairing it. */
TEST(dp_nat44, incremental_translation_does_not_repair_invalid_payload_checksum)
{
	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(
		module->prepare_and_activate(
			      1u,
			      R"({"pools":[{"public_ip_ranges":["192.0.2.1-192.0.2.1"],"port_min":40000,"port_max":40010}]})")
			.is_ok());
	auto bytes = build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234u, 53u, 0u, {1u, 2u});
	ASSERT_TRUE(prepare_udp_checksum(bytes));
	bytes.back() ^= 1u;
	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();
	kinetum::dp::dp_engine engine;
	kinetum::axiom::v1::Stage parse;
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);
	ASSERT_TRUE(engine.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get()));
	const uint8_t *ip = packet.data() + wire_offsets::IP_HDR_START;
	const uint8_t *udp = packet.data() + wire_offsets::UDP_HDR_START;
	EXPECT_NE(compute_ipv4_l4_checksum({17u, ip, udp, 10u}), 0u);
	EXPECT_EQ(kinetum::algo::net::read_be16(ip + 10u), compute_ipv4_checksum(ip, 20u));
}

/** @brief Real runtime routing filters return ownership before either context's stateful callback. */
TEST(dp_nat44, runtime_selects_exact_return_context_before_module_execution)
{
	using namespace kinetum::axiom::v1;
	Pipeline pipeline;
	pipeline.set_pipeline_id("nat_parallel_contexts");
	pipeline.set_allow_dag(true);
	const auto add_platform = [&](const char *id, StageKind kind, const char *interface) {
		auto *stage = pipeline.add_stages();
		stage->set_stage_id(id);
		stage->set_kind(kind);
		stage->set_execution_mode(EXECUTION_MODE_PASSIVE);
		if (interface != nullptr) {
			stage->mutable_io()->set_interface(interface);
		}
	};
	add_platform("rx", STAGE_KIND_RX, "wan0");
	add_platform("parse", STAGE_KIND_PARSE_IPV4, nullptr);
	for (const auto *id : {"nat_a", "nat_b"}) {
		auto *stage = pipeline.add_stages();
		stage->set_stage_id(id);
		stage->set_kind(STAGE_KIND_MODULE);
		stage->set_execution_mode(EXECUTION_MODE_PASSIVE);
		stage->mutable_module()->set_module_id("kinetum.nat44");
		stage->mutable_module()->set_context_selection(MODULE_CONTEXT_SELECTION_MODULE);
	}
	add_platform("tx", STAGE_KIND_TX, "lan0");
	for (const auto &[from, to] : std::array<std::pair<const char *, const char *>, 5>{
		     {{"rx", "parse"}, {"parse", "nat_a"}, {"parse", "nat_b"}, {"nat_a", "tx"}, {"nat_b", "tx"}}}) {
		auto *edge = pipeline.add_edges();
		edge->set_from_stage_id(from);
		edge->set_to_stage_id(to);
		edge->set_mode(EDGE_MODE_PUSH);
	}
	const auto bindings = kinetum::test::make_udp_test_deployment_bindings(pipeline);
	const kinetum::test::packet_runtime_test_module_intent intent{
		.module_id = "kinetum.nat44",
		.canonical_path = KINETUM_NAT44_MODULE_PATH,
		.config_blob =
			R"({"pools":[{"public_ip_ranges":["192.0.2.1-192.0.2.1"],"port_min":40000,"port_max":40010}]})",
		.context_memory_capacity_bytes = TEST_MODULE_RESOURCES.context_memory_capacity_bytes,
		.epoch_arena_capacity_bytes = TEST_MODULE_RESOURCES.epoch_arena_capacity_bytes,
	};
	auto owner_or = kinetum::test::packet_runtime_test_owner::create(intent, std::move(pipeline), bindings);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	const auto bootstrap = owner->bootstrap();
	ASSERT_TRUE(bootstrap.is_ok()) << bootstrap.error().message();
	auto outgoing = build_eth_ipv4_udp(UINT32_C(0x0a000001), UINT32_C(0x08080808), 1234u, 53u, 0u, {1u, 2u});
	ASSERT_TRUE(prepare_udp_checksum(outgoing));
	ASSERT_TRUE(owner->send_packet_to_rx(outgoing).is_ok());
	std::set<uint16_t> public_ports;
	for (std::size_t index = 0u; index < 2u; ++index) {
		auto observed = owner->receive_packet_from_tx(2048u, 2000);
		ASSERT_TRUE(observed.is_ok()) << observed.error().message();
		ASSERT_GE(observed->size(), wire_offsets::MIN_UDP_PACKET);
		EXPECT_EQ(kinetum::algo::net::read_be32(observed->data() + wire_offsets::IP_HDR_START + 12u),
			  UINT32_C(0xc0000201));
		EXPECT_TRUE(
			public_ports
				.insert(kinetum::algo::net::read_be16(observed->data() + wire_offsets::UDP_HDR_START))
				.second);
	}
	ASSERT_EQ(public_ports.size(), 2u);
	EXPECT_NE(*public_ports.begin() % 2u, *public_ports.rbegin() % 2u);
	for (const uint16_t port : public_ports) {
		auto reply = build_eth_ipv4_udp(UINT32_C(0x08080808), UINT32_C(0xc0000201), 53u, port, 0u, {3u, 4u});
		ASSERT_TRUE(prepare_udp_checksum(reply));
		ASSERT_TRUE(owner->send_packet_to_rx(reply).is_ok());
		auto observed = owner->receive_packet_from_tx(2048u, 2000);
		ASSERT_TRUE(observed.is_ok()) << observed.error().message();
		const auto verified = verify_wire_format(observed->data(), observed->size(), UINT32_C(0x08080808),
							 UINT32_C(0x0a000001), 53u, 1234u);
		EXPECT_TRUE(verified.ok) << verified.failure_reason;
	}
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
	bool complete = false;
	while (std::chrono::steady_clock::now() < deadline) {
		const auto serviced = owner->runtime().service_control_deadline();
		ASSERT_TRUE(serviced.is_ok()) << serviced.message();
		auto snapshot = owner->runtime().collect_runtime_telemetry({
			.include_stage_stats = true,
			.include_module_metrics = true,
			.include_topology_stats = true,
		});
		if (!snapshot.is_ok()) {
			ASSERT_EQ(snapshot.error().code(), kinetum::common::status_code::UNAVAILABLE)
				<< snapshot.error().message();
		}
		if (snapshot.is_ok() && snapshot->engine.rx_packets == 3u && snapshot->engine.tx_packets == 4u) {
			std::size_t admitted_contexts = 0u;
			uint64_t misses = 0u;
			uint64_t translated = 0u;
			for (const auto &counter : snapshot->module_counters) {
				if (counter.name == "nat44.inbound_misses") {
					++admitted_contexts;
					misses += counter.value;
				} else if (counter.name == "nat44.packets_translated") {
					translated += counter.value;
				}
			}
			if (admitted_contexts == 2u && translated == 4u) {
				EXPECT_EQ(misses, 0u);
				EXPECT_EQ(snapshot->engine.dropped_packets, 2u);
				std::size_t nat_stages = 0u;
				for (const auto &stage : snapshot->stages) {
					if (stage.stage_id == "nat_a" || stage.stage_id == "nat_b") {
						++nat_stages;
						EXPECT_EQ(stage.in_packets, 2u);
						EXPECT_EQ(stage.dropped_packets, 0u);
					}
				}
				EXPECT_EQ(nat_stages, 2u);
				complete = true;
				break;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	owner->runtime().shutdown();
	EXPECT_TRUE(complete);
}

//==============================================================================
// NAT44 Translation Tests
//==============================================================================

/**
 * @brief Verify NAT44 correctly performs SNAT and DNAT roundtrip.
 *
 * Test Scenario:
 * 1. Outbound: 10.0.0.1:1234 -> 8.8.8.8:53 (DNS query)
 *    - NAT translates src to 203.0.113.10:40000-40010 (public IP:port)
 * 2. Inbound reply: 8.8.8.8:53 -> 203.0.113.10:allocated_port
 *    - NAT translates dst back to 10.0.0.1:1234 (original private IP:port)
 *
 * NAT Pool Configuration:
 * - Public IP: 203.0.113.10 (TEST-NET-3 per RFC5737)
 * - Port range: 40000-40010 (11 ports available)
 * - Mode: NAPT (port address translation)
 *
 * Expected Results:
 * - After outbound NAT: src_ip = 203.0.113.10, src_port in [40000, 40010]
 * - After inbound NAT: dst_ip = 10.0.0.1, dst_port = 1234
 *
 * @note This test validates bidirectional NAT session handling.
 *       For stateful NAT, both directions must use the same session.
 */
TEST(dp_nat44, snat_and_dnat_roundtrip)
{
	kinetum::dp::dp_engine eng;

	// Build outbound UDP packet: 10.0.0.1:1234 -> 8.8.8.8:53
	auto bytes = build_eth_ipv4_udp(0x0a000001,    // src: 10.0.0.1 (private)
					0x08080808,    // dst: 8.8.8.8 (Google DNS)
					1234,	       // src_port
					53,	       // dst_port (DNS)
					0,	       // dscp
					{1, 2, 3, 4},  // payload
					0	       // checksum installed below
	);
	ASSERT_TRUE(prepare_udp_checksum(bytes));
	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Parse stage (platform mechanism)
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// Create NAT configuration using MODULE-OWNED proto
	kinetum::module::nat44::v1::NatPools nat_config;
	nat_config.set_session_timeout_s(60);

	// Configure NAT pool with public IP and port range
	auto *pool = nat_config.add_pools();
	pool->add_public_ip_ranges("203.0.113.10-203.0.113.10");  // Single public IP
	pool->set_port_min(40000);
	pool->set_port_max(40010);

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << "Module admission failed: " << module_or.error().message();
	auto module = std::move(module_or).value();
	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(nat_config));
	ASSERT_TRUE(status.is_ok()) << "Module preparation failed: " << status.message();

	// Outbound NAT (SNAT)
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get())) << "Parse stage should succeed for outbound packet";
	ASSERT_TRUE(module->process(*packet.get())) << "NAT stage should succeed for outbound packet";

	// Verify SNAT translation
	EXPECT_EQ(packet.metadata().src_ipv4, 0xcb00710au)  // 203.0.113.10 in network byte order
		<< "After SNAT, src_ip should be public IP (203.0.113.10)";
	EXPECT_GE(packet.metadata().src_port, 40000) << "After SNAT, src_port should be >= pool minimum";
	EXPECT_LE(packet.metadata().src_port, 40010) << "After SNAT, src_port should be <= pool maximum";

	// Save allocated port for inbound test
	uint16_t allocated_port = packet.metadata().src_port;

	// Inbound NAT (DNAT) - craft reply packet
	auto reply_bytes = build_eth_ipv4_udp(0x08080808,		   // src: 8.8.8.8 (DNS server)
					      packet.metadata().src_ipv4,  // dst: NAT public IP
					      53,			   // src_port: DNS
					      allocated_port,		   // dst_port: NAT allocated port
					      0,			   // dscp
					      {9, 9, 9},		   // payload (DNS response)
					      0				   // checksum installed below
	);
	ASSERT_TRUE(prepare_udp_checksum(reply_bytes));
	kinetum::test::packet_record_test_owner reply(reply_bytes);
	ASSERT_TRUE(reply.valid()) << reply.error();

	// Parse and NAT the reply
	ASSERT_TRUE(eng.execute_stage(&parse, reply.get())) << "Parse stage should succeed for inbound reply";
	ASSERT_TRUE(module->process(*reply.get())) << "NAT stage should succeed for inbound reply";

	// Verify DNAT translation
	EXPECT_EQ(reply.metadata().dst_ipv4, 0x0a000001u)  // 10.0.0.1
		<< "After DNAT, dst_ip should be original private IP";
	EXPECT_EQ(reply.metadata().dst_port, 1234) << "After DNAT, dst_port should be original private port";

	// When multiple health conditions coexist, the score and reason must
	// describe the most severe condition rather than a later, weaker check.
	ASSERT_TRUE(module->set_counter_value("nat44.packets_translated", 1001).is_ok());
	ASSERT_TRUE(module->set_counter_value("nat44.allocation_failures", 200).is_ok());
	ASSERT_TRUE(module->set_counter_value("nat44.packets_dropped", 1001).is_ok());
	auto health_or = module->health_assessment();
	ASSERT_TRUE(health_or.is_ok()) << health_or.error().message();
	const auto health = health_or.value();
	EXPECT_EQ(health.health_score, 50u);
	EXPECT_NE(health.flags & KINETUM_HEALTH_F_CONFIG_ISSUE, 0u);
	EXPECT_STREQ(health.reason, "Alloc fail >10% - pool exhausted");
}

/**
 * @brief Verify NAT44 modifies packet bytes and metadata coherently.
 *
 * This verifies that NAT applies parsed L3/L4 offsets to the exact wire
 * locations it mutates. A packet-base mutation violates link-layer integrity.
 *
 * Test verifies:
 * 1. IP header src_ip bytes at offset 14+12 = 26 (after Ethernet)
 * 2. UDP header src_port bytes at offset 14+20 = 34
 * 3. IP header checksum is valid after modification
 * 4. Ethernet header remains unchanged
 *
 * Wire format layout:
 *   [0-13]   Ethernet header (dst MAC, src MAC, EtherType)
 *   [14-33]  IPv4 header (src_ip at 26-29, dst_ip at 30-33)
 *   [34-41]  UDP header (src_port at 34-35, dst_port at 36-37)
 *   [42+]    Payload
 */
TEST(dp_nat44, wire_format_snat_verification)
{
	kinetum::dp::dp_engine eng;

	// Build outbound UDP packet: 10.0.0.1:5000 -> 1.1.1.1:80
	auto bytes = build_eth_ipv4_udp(0x0a000001,		   // src: 10.0.0.1 (private)
					0x01010101,		   // dst: 1.1.1.1
					5000,			   // src_port
					80,			   // dst_port
					0,			   // dscp
					{0xAA, 0xBB, 0xCC, 0xDD},  // payload
					0			   // no UDP checksum
	);

	// Save original Ethernet header before processing
	uint8_t orig_eth[14];
	save_ethernet_header(bytes.data(), orig_eth);

	// Verify packet structure before NAT
	ASSERT_EQ(bytes.size(), wire_offsets::MIN_UDP_PACKET + 4);

	// Verify original wire format
	auto pre_verify = verify_wire_format(bytes.data(), bytes.size(),
					     0x0a000001,  // src: 10.0.0.1
					     0x01010101,  // dst: 1.1.1.1
					     5000, 80);
	ASSERT_TRUE(pre_verify.ok) << "Pre-NAT: " << pre_verify.failure_reason;

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	// Setup NAT pipeline
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// NAT config: public IP 198.51.100.1 (0xC6336401)
	kinetum::module::nat44::v1::NatPools nat_config;
	nat_config.set_session_timeout_s(60);
	auto *pool = nat_config.add_pools();
	pool->add_public_ip_ranges("198.51.100.1-198.51.100.1");
	pool->set_port_min(50000);
	pool->set_port_max(50100);

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	const auto status = module->prepare_and_activate(1, kinetum::test::module_config_json(nat_config));
	ASSERT_TRUE(status.is_ok()) << status.message();

	// Execute parse and NAT
	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get()));

	// Verify the packet buffer through the independent test-side wire helpers.

	const uint8_t *pkt_data = packet.data();
	const std::size_t pkt_len = packet.size();

	// 1. L3/L4 mutation must not overwrite link-layer bytes.
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth))
		<< "module overwrote Ethernet bytes while mutating L3/L4 fields";

	// 2. Verify Ethernet header details
	EXPECT_TRUE(verify_ethernet_intact(pkt_data, pkt_len)) << "Ethernet header integrity check failed";

	// 3. Read wire-format values after NAT
	const uint8_t *ip_after = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_after = pkt_data + wire_offsets::UDP_HDR_START;

	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_after + 12);
	uint16_t wire_src_port = kinetum::algo::net::read_be16(udp_after + 0);

	// 4. Verify SNAT translation in wire format
	EXPECT_EQ(wire_src_ip, 0xC6336401u)  // 198.51.100.1
		<< "Wire-format src_ip should be NAT public IP (198.51.100.1)";
	EXPECT_TRUE(verify_port_in_range(wire_src_port, 50000, 50100))
		<< "Wire-format src_port should be in NAT pool range [50000, 50100]";

	// 5. Verify destination unchanged (SNAT only modifies source)
	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_after + 16);
	uint16_t wire_dst_port = kinetum::algo::net::read_be16(udp_after + 2);
	EXPECT_EQ(wire_dst_ip, 0x01010101u) << "SNAT should not modify dst_ip";
	EXPECT_EQ(wire_dst_port, 80) << "SNAT should not modify dst_port";

	EXPECT_EQ(kinetum::algo::net::read_be16(udp_after + 6u), 0u);
	// 6. Verify IP checksum is valid using helper
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_after + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_after, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum invalid after NAT";

	// 7. Verify metadata matches wire format (consistency check)
	const auto &metadata = packet.metadata();
	auto consistency = verify_metadata_wire_consistency(pkt_data, pkt_len, metadata.src_ipv4, metadata.dst_ipv4,
							    metadata.src_port, metadata.dst_port);
	EXPECT_TRUE(consistency.ok) << "Metadata-wire consistency failed: " << consistency.failure_reason;
}

/**
 * @brief Verify SNAT L4 checksum ignores Ethernet padding beyond IPv4 length.
 *
 * Ethernet frames can carry padding bytes after the IPv4 packet. NAT checksum
 * adjustment must preserve a valid protocol checksum without inspecting the packet-buffer tail.
 */
TEST(dp_nat44, snat_l4_checksum_uses_protocol_length_not_padding)
{
	kinetum::dp::dp_engine eng;

	auto bytes = build_eth_ipv4_udp(0x0a000001,		   // src: 10.0.0.1 (private)
					0x01010101,		   // dst: 1.1.1.1
					5000,			   // src_port
					80,			   // dst_port
					0,			   // dscp
					{0xAA, 0xBB, 0xCC, 0xDD},  // payload
					0			   // no UDP checksum
	);
	const std::size_t ip_total_len =
		static_cast<std::size_t>(kinetum::algo::net::read_be16(bytes.data() + wire_offsets::IP_HDR_START + 2));
	const std::size_t udp_len =
		static_cast<std::size_t>(kinetum::algo::net::read_be16(bytes.data() + wire_offsets::UDP_HDR_START + 4));
	ASSERT_EQ(bytes.size(), wire_offsets::ETH_HDR_LEN + ip_total_len);
	ASSERT_TRUE(prepare_udp_checksum(bytes));

	bytes.insert(bytes.end(), 18, 0xEE);

	kinetum::test::packet_record_test_owner packet(bytes);
	ASSERT_TRUE(packet.valid()) << packet.error();

	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	kinetum::module::nat44::v1::NatPools nat_config;
	nat_config.set_session_timeout_s(60);
	auto *pool = nat_config.add_pools();
	pool->add_public_ip_ranges("198.51.100.1-198.51.100.1");
	pool->set_port_min(50000);
	pool->set_port_max(50100);

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(nat_config)).is_ok());

	ASSERT_TRUE(eng.execute_stage(&parse, packet.get()));
	ASSERT_TRUE(module->process(*packet.get()));

	const uint8_t *pkt_data = packet.data();
	const uint8_t *ip_after = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_after = pkt_data + wire_offsets::UDP_HDR_START;

	ASSERT_EQ(static_cast<std::size_t>(kinetum::algo::net::read_be16(ip_after + 2)), ip_total_len);
	ASSERT_EQ(static_cast<std::size_t>(kinetum::algo::net::read_be16(udp_after + 4)), udp_len);

	std::vector<uint8_t> udp_segment(udp_after, udp_after + udp_len);
	udp_segment[6] = 0;
	udp_segment[7] = 0;
	uint16_t expected_udp_checksum = compute_ipv4_l4_checksum(test_ipv4_l4_checksum_input{
		.ip_protocol = static_cast<uint8_t>(17),
		.ipv4_header = ip_after,
		.l4_segment = udp_segment.data(),
		.l4_length = udp_segment.size(),
	});
	if (expected_udp_checksum == 0) {
		expected_udp_checksum = 0xffff;
	}

	const uint16_t wire_udp_checksum = kinetum::algo::net::read_be16(udp_after + 6);
	EXPECT_EQ(wire_udp_checksum, expected_udp_checksum)
		<< "UDP checksum adjustment must agree with the independent full checksum";
}

/**
 * @brief Verify DNAT (inbound) translation modifies actual packet buffer.
 *
 * This tests the reverse direction of NAT: inbound packets destined to the
 * NAT public IP are translated back to the original private IP.
 */
TEST(dp_nat44, wire_format_dnat_verification)
{
	kinetum::dp::dp_engine eng;

	// First, establish a session with outbound packet
	auto outbound = build_eth_ipv4_udp(0x0a000001,	  // src: 10.0.0.1 (private)
					   0x08080808,	  // dst: 8.8.8.8
					   12345,	  // src_port
					   53,		  // dst_port (DNS)
					   0,		  // dscp
					   {0x01, 0x02},  // payload
					   0);

	kinetum::test::packet_record_test_owner outbound_packet(outbound);
	ASSERT_TRUE(outbound_packet.valid()) << outbound_packet.error();

	// Setup pipeline
	kinetum::axiom::v1::Stage parse;
	parse.set_stage_id("p0");
	parse.set_kind(kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4);

	// NAT config: public IP 192.0.2.1 (TEST-NET-1)
	kinetum::module::nat44::v1::NatPools nat_config;
	nat_config.set_session_timeout_s(60);
	auto *pool = nat_config.add_pools();
	pool->add_public_ip_ranges("192.0.2.1-192.0.2.1");
	pool->set_port_min(60000);
	pool->set_port_max(60100);

	auto module_or = kinetum::test::exact_module_test_context::create("kinetum.nat44", KINETUM_NAT44_MODULE_PATH,
									  TEST_MODULE_RESOURCES, "nat0@lane_0");
	ASSERT_TRUE(module_or.is_ok()) << module_or.error().message();
	auto module = std::move(module_or).value();
	ASSERT_TRUE(module->prepare_and_activate(1, kinetum::test::module_config_json(nat_config)).is_ok());

	// Process outbound to create session
	ASSERT_TRUE(eng.execute_stage(&parse, outbound_packet.get()));
	ASSERT_TRUE(module->process(*outbound_packet.get()));

	// Capture allocated port from outbound
	uint16_t nat_port = outbound_packet.metadata().src_port;
	ASSERT_TRUE(verify_port_in_range(nat_port, 60000, 60100));

	// Now create inbound reply packet
	auto inbound = build_eth_ipv4_udp(0x08080808,	 // src: 8.8.8.8 (DNS server)
					  0xC0000201,	 // dst: 192.0.2.1 (NAT public IP)
					  53,		 // src_port (DNS)
					  nat_port,	 // dst_port (NAT allocated port)
					  0,		 // dscp
					  {0x03, 0x04},	 // payload (reply)
					  0);

	// Save original Ethernet header
	uint8_t orig_eth[14];
	save_ethernet_header(inbound.data(), orig_eth);

	kinetum::test::packet_record_test_owner inbound_packet(inbound);
	ASSERT_TRUE(inbound_packet.valid()) << inbound_packet.error();

	// Process inbound
	ASSERT_TRUE(eng.execute_stage(&parse, inbound_packet.get()));
	ASSERT_TRUE(module->process(*inbound_packet.get()));

	// Verify the DNAT mutation in the packet bytes.

	const uint8_t *pkt_data = inbound_packet.data();
	const std::size_t pkt_len = inbound_packet.size();

	// 1. Ethernet header must NOT be corrupted
	EXPECT_TRUE(compare_ethernet_headers(pkt_data, orig_eth)) << "Ethernet header corrupted during DNAT";

	// 2. Read wire-format values after DNAT
	const uint8_t *ip_after = pkt_data + wire_offsets::IP_HDR_START;
	const uint8_t *udp_after = pkt_data + wire_offsets::UDP_HDR_START;

	uint32_t wire_dst_ip = kinetum::algo::net::read_be32(ip_after + 16);
	uint16_t wire_dst_port = kinetum::algo::net::read_be16(udp_after + 2);

	// 3. Verify DNAT translation restored original private IP/port
	EXPECT_EQ(wire_dst_ip, 0x0a000001u)  // 10.0.0.1
		<< "Wire-format dst_ip should be original private IP after DNAT";
	EXPECT_EQ(wire_dst_port, 12345) << "Wire-format dst_port should be original private port after DNAT";

	// 4. Verify source unchanged (DNAT only modifies destination)
	uint32_t wire_src_ip = kinetum::algo::net::read_be32(ip_after + 12);
	uint16_t wire_src_port = kinetum::algo::net::read_be16(udp_after + 0);
	EXPECT_EQ(wire_src_ip, 0x08080808u) << "DNAT should not modify src_ip";
	EXPECT_EQ(wire_src_port, 53) << "DNAT should not modify src_port";

	// 5. Verify IP checksum valid
	uint16_t wire_cksum = kinetum::algo::net::read_be16(ip_after + 10);
	uint16_t computed_cksum = compute_ipv4_checksum(ip_after, 20);
	EXPECT_EQ(wire_cksum, computed_cksum) << "IP header checksum invalid after DNAT";

	// 6. Verify metadata-wire consistency
	const auto &metadata = inbound_packet.metadata();
	auto consistency = verify_metadata_wire_consistency(pkt_data, pkt_len, metadata.src_ipv4, metadata.dst_ipv4,
							    metadata.src_port, metadata.dst_port);
	EXPECT_TRUE(consistency.ok) << consistency.failure_reason;
}
