// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_module_config_parsing.cpp
 * @brief Fail-closed module config parsing tests for malformed input.
 * @author Fleming Patel
 *
 * These tests validate fail-closed behavior for module-owned config schemas.
 * They exercise malformed/truncated inputs to ensure modules never accept
 * ambiguous or corrupted configuration blobs.
 */

#include <gtest/gtest.h>

#include <limits>
#include <memory_resource>
#include <string>
#include <type_traits>

#include "src/modules/acl/acl_impl.hpp"
#include "src/modules/nat44/nat44_impl.hpp"
#include "src/modules/qos/qos_impl.hpp"
#include "src/modules/acl/acl.pb.h"
#include "src/modules/nat44/nat44.pb.h"
#include "src/modules/qos/qos.pb.h"
#include "tests/module_config_test_helpers.hpp"

namespace
{

using kinetum::test::compile_acl_for_test;
using kinetum::test::compile_nat_for_test;
using kinetum::test::compile_qos_for_test;
using kinetum::test::module_config_json;

static_assert(!std::is_copy_assignable_v<kinetum::modules::acl::acl_compiled>);
static_assert(!std::is_move_assignable_v<kinetum::modules::acl::acl_compiled>);
static_assert(std::is_nothrow_move_constructible_v<kinetum::modules::acl::acl_compiled>);
static_assert(!std::is_copy_assignable_v<kinetum::modules::nat44::nat_pool_compiled>);
static_assert(!std::is_move_assignable_v<kinetum::modules::nat44::nat_pool_compiled>);
static_assert(std::is_nothrow_move_constructible_v<kinetum::modules::nat44::nat_pool_compiled>);
static_assert(!std::is_copy_assignable_v<kinetum::modules::nat44::nat_pools_compiled>);
static_assert(!std::is_move_assignable_v<kinetum::modules::nat44::nat_pools_compiled>);
static_assert(std::is_nothrow_move_constructible_v<kinetum::modules::nat44::nat_pools_compiled>);
static_assert(!std::is_copy_assignable_v<kinetum::modules::qos::qos_profile_compiled>);
static_assert(!std::is_move_assignable_v<kinetum::modules::qos::qos_profile_compiled>);
static_assert(std::is_nothrow_move_constructible_v<kinetum::modules::qos::qos_profile_compiled>);
static_assert(!std::is_copy_assignable_v<kinetum::modules::qos::qos_profiles_compiled>);
static_assert(!std::is_move_assignable_v<kinetum::modules::qos::qos_profiles_compiled>);
static_assert(std::is_nothrow_move_constructible_v<kinetum::modules::qos::qos_profiles_compiled>);

/**
 * @brief Verify arbitrary non-JSON bytes are rejected.
 */
TEST(module_config_parsing, non_json_bytes_rejected)
{
	const std::string malformed("\x01\xff\x00\xab\xcd\xef", 6);

	EXPECT_EQ(compile_acl_for_test(malformed), nullptr);
	EXPECT_EQ(compile_nat_for_test(malformed, {0u, 1u}), nullptr);
	EXPECT_EQ(compile_qos_for_test(malformed), nullptr);
}

/**
 * @brief Verify a truncated JSON object is rejected.
 */
TEST(module_config_parsing, truncated_json_rejected)
{
	kinetum::module::nat44::v1::NatPools nat_cfg;
	auto *pool = nat_cfg.add_pools();
	pool->add_public_ip_ranges("203.0.113.10-203.0.113.20");
	pool->set_port_min(1024);
	pool->set_port_max(65535);
	nat_cfg.set_session_timeout_s(300);

	std::string valid = module_config_json(nat_cfg);
	ASSERT_GT(valid.size(), 8u);
	valid.resize(valid.size() - 5);	 // Intentionally truncate payload

	EXPECT_EQ(compile_nat_for_test(valid, {0u, 1u}), nullptr);
}

/**
 * @brief Verify protobuf text is not a runtime fallback format.
 */
TEST(module_config_parsing, protobuf_text_rejected)
{
	const std::string bad_text = R"pb(
    rules {
      src_cidr: "10.0.0.0/99"
      action: ACL_ACTION_PERMIT
      enabled: true
    }
  )pb";

	EXPECT_EQ(compile_acl_for_test(bad_text), nullptr);
}

/**
 * @brief Verify valid configs accepted.
 */
TEST(module_config_parsing, valid_configs_accepted)
{
	kinetum::module::acl::v1::AclRuleset acl_cfg;
	acl_cfg.set_default_action(kinetum::module::acl::v1::ACL_ACTION_DENY);
	auto *acl_rule = acl_cfg.add_rules();
	acl_rule->set_priority(10);
	acl_rule->set_src_cidr("0.0.0.0/0");
	acl_rule->set_dst_cidr("0.0.0.0/0");
	acl_rule->set_protocol(17);
	acl_rule->set_dst_port_min(53);
	acl_rule->set_dst_port_max(53);
	acl_rule->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);
	acl_rule->set_enabled(true);
	const std::string acl_blob = module_config_json(acl_cfg);
	EXPECT_NE(compile_acl_for_test(acl_blob), nullptr);

	kinetum::module::acl::v1::AclRuleset tied_acl_cfg;
	tied_acl_cfg.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);
	auto *first_tied_rule = tied_acl_cfg.add_rules();
	first_tied_rule->set_priority(10);
	first_tied_rule->set_action(kinetum::module::acl::v1::ACL_ACTION_DENY);
	first_tied_rule->set_enabled(true);
	auto *second_tied_rule = tied_acl_cfg.add_rules();
	second_tied_rule->set_priority(10);
	second_tied_rule->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);
	second_tied_rule->set_enabled(true);
	const auto tied_acl = compile_acl_for_test(module_config_json(tied_acl_cfg));
	ASSERT_NE(tied_acl, nullptr);
	EXPECT_EQ(kinetum::modules::acl::eval_acl_5tuple(*tied_acl, 0, 0, 6, 1, 1),
		  kinetum::modules::acl::acl_action::DENY);

	kinetum::module::nat44::v1::NatPools nat_cfg;
	nat_cfg.set_session_timeout_s(120);
	auto *nat_pool = nat_cfg.add_pools();
	// Author out of address order: PREPARE canonicalizes the disjoint set
	// before building cumulative hot-path ordinals.
	nat_pool->add_public_ip_ranges("198.51.100.20");
	nat_pool->add_public_ip_ranges("198.51.100.10-198.51.100.19");
	nat_pool->set_port_min(1024);
	nat_pool->set_port_max(65535);
	const std::string nat_blob = module_config_json(nat_cfg);
	const auto compiled_nat = compile_nat_for_test(nat_blob, {0u, 1u});
	ASSERT_NE(compiled_nat, nullptr);
	ASSERT_EQ(compiled_nat->pools.size(), 1u);
	EXPECT_EQ(compiled_nat->pools[0].total_public_ips, 11u);
	ASSERT_EQ(compiled_nat->pools[0].public_ranges.size(), 2u);
	EXPECT_EQ(compiled_nat->pools[0].public_ranges[0].start, 0xc633640au);
	EXPECT_EQ(compiled_nat->pools[0].public_ranges[0].cumulative_end, 10u);
	EXPECT_EQ(compiled_nat->pools[0].public_ranges[1].start, 0xc6336414u);
	EXPECT_EQ(compiled_nat->pools[0].public_ranges[1].cumulative_end, 11u);

	kinetum::module::qos::v1::QosProfiles qos_cfg;
	qos_cfg.set_default_profile("default");
	auto *qos_profile = qos_cfg.add_profiles();
	qos_profile->set_name("default");
	qos_profile->set_cir_kbps(1000);
	qos_profile->set_cbs_kb(64);
	const std::string qos_blob = module_config_json(qos_cfg);
	EXPECT_NE(compile_qos_for_test(qos_blob), nullptr);
}

/**
 * @brief Verify JSON unknown fields rejected.
 */
TEST(module_config_parsing, json_unknown_fields_rejected)
{
	const std::string acl_json = R"json({
    "default_action": 1,
    "unexpected_acl_field": true,
    "rules": [
      {
        "priority": 1,
        "src_cidr": "0.0.0.0/0",
        "dst_cidr": "0.0.0.0/0",
        "action": 1,
        "enabled": true
      }
    ]
  })json";

	const std::string nat_json = R"json({
    "session_timeout_s": 60,
    "unexpected_nat_field": 7,
    "pools": [
      {
        "public_ip_ranges": ["203.0.113.10"],
        "port_min": 1024,
        "port_max": 65535
      }
    ]
  })json";

	const std::string qos_json = R"json({
    "default_profile": "default",
    "unexpected_qos_field": "typo",
    "profiles": [
      {
        "name": "default",
        "cir_kbps": 1000,
        "cbs_kb": 64
      }
    ]
  })json";

	EXPECT_EQ(compile_acl_for_test(acl_json), nullptr);
	EXPECT_EQ(compile_nat_for_test(nat_json, {0u, 1u}), nullptr);
	EXPECT_EQ(compile_qos_for_test(qos_json), nullptr);
}

/** @brief Verify removed advertised-but-unimplemented policy surfaces stay absent. */
TEST(module_config_parsing, removed_policy_surfaces_are_unknown)
{
	EXPECT_EQ(compile_acl_for_test(
			  R"json({"rules":[{"rule_id":"legacy","action":1,"enabled":true}],"default_action":2})json"),
		  nullptr);
	EXPECT_EQ(
		compile_nat_for_test(
			R"json({"pools":[{"public_ip_ranges":["203.0.113.1"],"port_min":1024,"port_max":65535}],"mode":1})json",
			{0u, 1u}),
		nullptr);
	EXPECT_EQ(
		compile_qos_for_test(
			R"json({"profiles":[{"name":"default","cir_kbps":1000,"cbs_kb":64}],"default_profile":"default","scheduler":1})json"),
		nullptr);
	EXPECT_EQ(compile_acl_for_test(R"json({"rules":[{"action":4,"enabled":true}],"default_action":2})json"),
		  nullptr);
}

/** @brief Verify strict JSON rejects duplicate, aliased, fractional, and invalid UTF-8 input. */
TEST(module_config_parsing, strict_json_grammar_rejects_ambiguous_input)
{
	EXPECT_EQ(compile_acl_for_test(R"json({"rules":[],"rules":[],"default_action":2})json"), nullptr);
	EXPECT_EQ(compile_nat_for_test(
			  R"json({"pools":[{"publicIpRanges":["203.0.113.1"],"port_min":1024,"port_max":65535}]})json",
			  {0u, 1u}),
		  nullptr);
	EXPECT_EQ(
		compile_qos_for_test(
			R"json({"profiles":[{"name":"default","cir_kbps":1.5,"cbs_kb":64}],"default_profile":"default"})json"),
		nullptr);
	std::string invalid_utf8 = R"json({"rules":[{"src_cidr":"0.0.0.0/0","dst_cidr":")json";
	invalid_utf8.push_back(static_cast<char>(0xc0));
	invalid_utf8.append(R"json(","action":1,"enabled":true}],"default_action":2})json");
	EXPECT_EQ(compile_acl_for_test(invalid_utf8), nullptr);
}

/** @brief Verify long cold-path parsing observes cooperative cancellation. */
TEST(module_config_parsing, compilation_observes_cancellation)
{
	std::string json(2048u, ' ');
	json.append(R"json({"rules":[],"default_action":2})json");
	bool cancelled = true;
	std::pmr::monotonic_buffer_resource memory;
	kinetum::modules::acl::acl_compiled compiled(memory);
	const auto result = kinetum::modules::acl::compile_acl_from_json(
		json.data(), json.size(), &memory, &compiled,
		kinetum::modules::config::cancellation_probe{
			.is_cancelled = [](const void *context) noexcept { return *static_cast<const bool *>(context); },
			.context = &cancelled,
		});
	EXPECT_EQ(result, kinetum::modules::config::compile_result::CANCELLED);
}

/**
 * @brief Verify ACL numeric validation rejects invalid values.
 */
TEST(module_config_parsing, acl_numeric_validation_rejects_invalid_values)
{
	kinetum::module::acl::v1::AclRuleset acl_cfg;
	acl_cfg.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);

	auto *rule = acl_cfg.add_rules();
	rule->set_priority(10);
	rule->set_src_cidr("0.0.0.0/0");
	rule->set_dst_cidr("0.0.0.0/0");
	rule->set_protocol(256);
	rule->set_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);
	rule->set_enabled(true);
	std::string blob = module_config_json(acl_cfg);
	EXPECT_EQ(compile_acl_for_test(blob), nullptr);

	rule->set_protocol(6);
	rule->set_src_port_min(-1);
	rule->set_src_port_max(0);
	blob = module_config_json(acl_cfg);
	EXPECT_EQ(compile_acl_for_test(blob), nullptr);

	rule->set_src_port_min(1024);
	rule->set_src_port_max(1000);
	blob = module_config_json(acl_cfg);
	EXPECT_EQ(compile_acl_for_test(blob), nullptr);

	rule->set_src_port_min(0);
	rule->set_src_port_max(0);
	acl_cfg.set_max_rules(-1);
	blob = module_config_json(acl_cfg);
	EXPECT_EQ(compile_acl_for_test(blob), nullptr);
}

/**
 * @brief Verify NAT validation rejects invalid ranges and limits.
 */
TEST(module_config_parsing, nat_validation_rejects_invalid_ranges_and_limits)
{
	kinetum::module::nat44::v1::NatPools nat_cfg;
	nat_cfg.set_session_timeout_s(60);
	auto *pool = nat_cfg.add_pools();
	pool->add_public_ip_ranges("203.0.113.20-203.0.113.10");
	pool->set_port_min(1024);
	pool->set_port_max(65535);

	std::string blob = module_config_json(nat_cfg);
	EXPECT_EQ(compile_nat_for_test(blob, {0u, 1u}), nullptr);

	pool->clear_public_ip_ranges();
	pool->add_public_ip_ranges("203.0.113.10-");
	blob = module_config_json(nat_cfg);
	EXPECT_EQ(compile_nat_for_test(blob, {0u, 1u}), nullptr);

	pool->clear_public_ip_ranges();
	pool->add_public_ip_ranges("203.0.113.10-203.0.113.20");
	pool->add_public_ip_ranges("203.0.113.20-203.0.113.30");
	blob = module_config_json(nat_cfg);
	EXPECT_EQ(compile_nat_for_test(blob, {0u, 1u}), nullptr);

	pool->clear_public_ip_ranges();
	pool->add_public_ip_ranges("203.0.113.10");
	pool->set_port_min(70000);
	pool->set_port_max(65535);
	blob = module_config_json(nat_cfg);
	EXPECT_EQ(compile_nat_for_test(blob, {0u, 1u}), nullptr);

	pool->set_port_min(2000);
	pool->set_port_max(1000);
	blob = module_config_json(nat_cfg);
	EXPECT_EQ(compile_nat_for_test(blob, {0u, 1u}), nullptr);

	pool->set_port_min(1024);
	pool->set_port_max(65535);
	nat_cfg.set_session_timeout_s(-1);
	blob = module_config_json(nat_cfg);
	EXPECT_EQ(compile_nat_for_test(blob, {0u, 1u}), nullptr);

	nat_cfg.set_session_timeout_s(60);
	nat_cfg.set_max_total_sessions(-1);
	blob = module_config_json(nat_cfg);
	EXPECT_EQ(compile_nat_for_test(blob, {0u, 1u}), nullptr);
}

/**
 * @brief Verify NAT zero timeout uses default timeout.
 */
TEST(module_config_parsing, nat_zero_timeout_uses_default_timeout)
{
	kinetum::module::nat44::v1::NatPools nat_cfg;
	auto *pool = nat_cfg.add_pools();
	pool->add_public_ip_ranges("203.0.113.10");
	pool->set_port_min(1024);
	pool->set_port_max(65535);

	const std::string blob = module_config_json(nat_cfg);
	const auto compiled = compile_nat_for_test(blob, {0u, 1u});
	ASSERT_NE(compiled, nullptr);
	EXPECT_EQ(compiled->session_timeout_s, kinetum::modules::nat44::NAT_DEFAULT_TIMEOUT_S);
}

/**
 * @brief Verify QoS validation rejects ambiguous profiles.
 */
TEST(module_config_parsing, qos_validation_rejects_ambiguous_profiles)
{
	kinetum::module::qos::v1::QosProfiles qos_cfg;
	qos_cfg.set_default_profile("missing");
	auto *profile = qos_cfg.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(1000);
	profile->set_cbs_kb(64);

	std::string blob = module_config_json(qos_cfg);
	EXPECT_EQ(compile_qos_for_test(blob), nullptr);

	qos_cfg.set_default_profile("default");
	auto *duplicate = qos_cfg.add_profiles();
	duplicate->set_name("default");
	duplicate->set_cir_kbps(1000);
	duplicate->set_cbs_kb(64);
	blob = module_config_json(qos_cfg);
	EXPECT_EQ(compile_qos_for_test(blob), nullptr);
}

/**
 * @brief Verify QoS validation rejects invalid numeric values.
 */
TEST(module_config_parsing, qos_validation_rejects_invalid_numeric_values)
{
	kinetum::module::qos::v1::QosProfiles qos_cfg;
	qos_cfg.set_default_profile("default");
	auto *profile = qos_cfg.add_profiles();
	profile->set_name("default");
	profile->set_cir_kbps(-1);
	profile->set_cbs_kb(64);

	std::string blob = module_config_json(qos_cfg);
	EXPECT_EQ(compile_qos_for_test(blob), nullptr);

	profile->set_cir_kbps(1000);
	profile->set_cbs_kb(-1);
	blob = module_config_json(qos_cfg);
	EXPECT_EQ(compile_qos_for_test(blob), nullptr);

	profile->set_cbs_kb(64);
	profile->set_conform_dscp(64);
	blob = module_config_json(qos_cfg);
	EXPECT_EQ(compile_qos_for_test(blob), nullptr);

	profile->set_conform_dscp(0);
	profile->set_cbs_kb(kinetum::modules::qos::QOS_MAX_CBS_KB + 1);
	blob = module_config_json(qos_cfg);
	EXPECT_EQ(compile_qos_for_test(blob), nullptr);

	profile->set_cbs_kb(64);
	qos_cfg.set_gc_max_evictions(kinetum::modules::qos::DEFAULT_QOS_GC_SCAN_LIMIT);
	blob = module_config_json(qos_cfg);
	EXPECT_NE(compile_qos_for_test(blob), nullptr);
	qos_cfg.set_gc_max_evictions(kinetum::modules::qos::DEFAULT_QOS_GC_SCAN_LIMIT + 1u);
	blob = module_config_json(qos_cfg);
	EXPECT_EQ(compile_qos_for_test(blob), nullptr);

	constexpr std::string_view OVERSIZED_IDLE_TIMEOUT =
		R"({"profiles":[{"name":"default","cir_kbps":1000,"cbs_kb":64}],)"
		R"("default_profile":"default","idle_timeout_s":4294967296})";
	EXPECT_EQ(compile_qos_for_test(OVERSIZED_IDLE_TIMEOUT), nullptr);
}

}  // namespace
