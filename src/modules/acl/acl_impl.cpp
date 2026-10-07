// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file acl_impl.cpp
 * @brief ACL Module Implementation
 * @author Fleming Patel
 *
 * Self-contained ACL evaluation logic using strict module-owned JSON.
 * Hot execution uses bounded dual-loop batching, SIMD, and cache prefetch.
 */

#include "acl_impl.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>

// Canonical algo/ headers for hot-path optimization macros
#include <kinetum/algo/platform.hpp>  // KINETUM_LIKELY/UNLIKELY
#include <kinetum/algo/prefetch.hpp>  // KINETUM_PREFETCH_L1

namespace kinetum::modules::acl
{

// =============================================================================
// Utility Functions
// =============================================================================

namespace
{

/**
 * @brief Compile an exact IP protocol byte into the internal fast-path tag.
 * @param proto_num Validated schema protocol value; zero denotes the wildcard.
 * @return ANY for zero, the supported ICMP/TCP/UDP tag, or OTHER for the remaining values.
 */
[[nodiscard]] l4_protocol parse_protocol(int32_t proto_num) noexcept
{
	switch (proto_num) {
	case 0:
		return l4_protocol::ANY;
	case 1:
		return l4_protocol::ICMP;
	case 6:
		return l4_protocol::TCP;
	case 17:
		return l4_protocol::UDP;
	default:
		return l4_protocol::OTHER;
	}
}

/**
 * @brief Validate and compile one optional inclusive transport-port range.
 * @param min_port Lower port bound; zero with a zero upper bound selects the wildcard.
 * @param max_port Upper bound, or zero to select only the nonzero lower port.
 * @param out Destination range; may be populated before a reversed interval is rejected.
 * @return true for a representable valid interval or wildcard; false otherwise.
 */
[[nodiscard]] bool compile_port_range(int32_t min_port, int32_t max_port, port_range *out) noexcept
{
	if (out == nullptr || min_port < 0 || max_port < 0 || min_port > 65535 || max_port > 65535) {
		return false;
	}

	if (min_port == 0 && max_port == 0) {
		*out = port_range{};
		return true;
	}

	out->min = static_cast<uint16_t>(min_port);
	out->max = max_port > 0 ? static_cast<uint16_t>(max_port) : out->min;
	return out->is_valid();
}

}  // namespace

// CIDR parsing is the canonical header-owned SDK mechanism in algo/cidr.hpp.

// =============================================================================
// ACL Cache Implementation
// =============================================================================

void acl_cache::stats::reset() noexcept
{
	*this = {};
}

acl_cache::acl_cache(std::size_t max_entries, std::pmr::memory_resource &memory_resource)
	: entries_(&memory_resource)
{
	if (max_entries == 0u || (max_entries & (max_entries - 1u)) != 0u) {
		throw std::invalid_argument("ACL cache capacity must be a positive power of two");
	}
	mask_ = max_entries - 1u;
	entries_.resize(max_entries);
}

bool acl_cache::lookup(const flow_key &key, uint64_t config_epoch, acl_action &out_action) noexcept
{
	if (KINETUM_UNLIKELY(config_epoch == 0)) {
		++stats_.misses;
		return false;
	}
	if (KINETUM_UNLIKELY(config_epoch != cache_epoch_)) {
		cache_epoch_ = config_epoch;
		++stats_.misses;
		return false;
	}

	flow_key_hash hasher;
	const std::size_t idx = hasher(key) & mask_;

	KINETUM_PREFETCH_L1(&entries_[idx]);

	const auto &entry = entries_[idx];
	if (KINETUM_LIKELY(entry.valid && entry.config_epoch == config_epoch && entry.key == key)) {
		out_action = entry.action;
		++stats_.hits;
		return true;
	}

	++stats_.misses;
	return false;
}

void acl_cache::insert(const flow_key &key, uint64_t config_epoch, acl_action action) noexcept
{
	if (KINETUM_UNLIKELY(config_epoch == 0)) {
		return;
	}
	if (KINETUM_UNLIKELY(config_epoch != cache_epoch_)) {
		cache_epoch_ = config_epoch;
	}

	flow_key_hash hasher;
	const std::size_t idx = hasher(key) & mask_;

	auto &entry = entries_[idx];

	entry.key = key;
	entry.action = action;
	entry.config_epoch = config_epoch;
	entry.valid = true;
}

acl_cache::stats acl_cache::get_stats() const noexcept
{
	return stats_;
}

void acl_cache::reset_stats() noexcept
{
	stats_.reset();
}

// =============================================================================
// ACL Compilation from Strict Module-Owned JSON
// =============================================================================

namespace
{

/**
 * @brief Claim one schema field exactly once.
 * @param seen Mutable field-presence mask for the current object.
 * @param bit Schema-assigned field bit below 64.
 * @return true after claiming a new bit; false for a duplicate or absent mask.
 */
[[nodiscard]] bool claim_field(uint64_t *seen, uint8_t bit) noexcept
{
	const uint64_t mask = uint64_t{1} << bit;
	if (seen == nullptr || (*seen & mask) != 0) {
		return false;
	}
	*seen |= mask;
	return true;
}

/**
 * @brief Decode one JSON integer into the exact signed 32-bit domain.
 * @param reader Reader positioned before the candidate integer.
 * @param output Destination written only after successful parsing and narrowing.
 * @return true for an int32_t value; false on parse, range, or output failure.
 */
[[nodiscard]] bool read_int32(config::json_reader &reader, int32_t *output) noexcept
{
	int64_t value = 0;
	if (output == nullptr || !reader.read_int64(&value) || value < std::numeric_limits<int32_t>::min() ||
	    value > std::numeric_limits<int32_t>::max()) {
		return false;
	}
	*output = static_cast<int32_t>(value);
	return true;
}

/**
 * @brief Preserve parser cancellation while mapping every other failure to INVALID.
 * @param reader Reader whose first terminal state is inspected.
 * @return CANCELLED when already observed; INVALID for every other state.
 */
[[nodiscard]] config::compile_result invalid_or_cancelled(const config::json_reader &reader) noexcept
{
	return reader.result() == config::compile_result::CANCELLED ? config::compile_result::CANCELLED :
								      config::compile_result::INVALID;
}

/**
 * @brief Decode the complete implemented ACL action set.
 * @param encoded Numeric schema action.
 * @param output Destination written only for an admitted action.
 * @return true after decoding a supported action; false for an unknown value or absent output.
 */
[[nodiscard]] bool parse_action(int32_t encoded, acl_action *output) noexcept
{
	if (output == nullptr) {
		return false;
	}
	switch (encoded) {
	case 1:
		*output = acl_action::PERMIT;
		return true;
	case 2:
		*output = acl_action::DENY;
		return true;
	default:
		return false;
	}
}

/**
 * @brief Parse and validate one strict ACL rule object.
 * @param reader Exact bounded JSON reader.
 * @param memory_resource Exact temporary string-storage authority.
 * @param output Compiled rule replaced only on success.
 * @param enabled_out Whether the authored rule participates in evaluation.
 * @return true after one complete rule object is parsed and validated.
 */
[[nodiscard]] bool parse_acl_rule(config::json_reader &reader, std::pmr::memory_resource *memory_resource,
				  acl_rule_compiled *output, bool *enabled_out)
{
	if (output == nullptr || enabled_out == nullptr || !reader.begin_object()) {
		return false;
	}
	acl_rule_compiled candidate;
	std::pmr::string source_cidr(memory_resource);
	std::pmr::string destination_cidr(memory_resource);
	int32_t action = 0;
	int32_t protocol = 0;
	int32_t source_port_min = 0;
	int32_t source_port_max = 0;
	int32_t destination_port_min = 0;
	int32_t destination_port_max = 0;
	bool enabled = false;
	uint64_t seen = 0;
	bool first = true;
	while (reader.next_object_member(&first)) {
		char key[48]{};
		std::size_t key_size = 0;
		if (!reader.read_string(key, sizeof(key), &key_size) || !reader.consume_colon()) {
			return false;
		}
		const std::string_view field(key, key_size);
		if (field == "priority") {
			if (!claim_field(&seen, 0) || !read_int32(reader, &candidate.priority))
				return false;
		} else if (field == "src_cidr") {
			if (!claim_field(&seen, 1) || !reader.read_string(&source_cidr))
				return false;
		} else if (field == "dst_cidr") {
			if (!claim_field(&seen, 2) || !reader.read_string(&destination_cidr))
				return false;
		} else if (field == "action") {
			if (!claim_field(&seen, 3) || !read_int32(reader, &action))
				return false;
		} else if (field == "protocol") {
			if (!claim_field(&seen, 4) || !read_int32(reader, &protocol))
				return false;
		} else if (field == "src_port_min") {
			if (!claim_field(&seen, 5) || !read_int32(reader, &source_port_min))
				return false;
		} else if (field == "src_port_max") {
			if (!claim_field(&seen, 6) || !read_int32(reader, &source_port_max))
				return false;
		} else if (field == "dst_port_min") {
			if (!claim_field(&seen, 7) || !read_int32(reader, &destination_port_min))
				return false;
		} else if (field == "dst_port_max") {
			if (!claim_field(&seen, 8) || !read_int32(reader, &destination_port_max))
				return false;
		} else if (field == "enabled") {
			if (!claim_field(&seen, 9) || !reader.read_bool(&enabled))
				return false;
		} else {
			return false;
		}
	}
	if (reader.result() != config::compile_result::OK || protocol < 0 || protocol > 255 ||
	    !compile_port_range(source_port_min, source_port_max, &candidate.src_port) ||
	    !compile_port_range(destination_port_min, destination_port_max, &candidate.dst_port)) {
		return false;
	}
	if (!parse_action(action, &candidate.action)) {
		return false;
	}
	candidate.protocol = parse_protocol(protocol);
	candidate.protocol_num = static_cast<uint8_t>(protocol);
	candidate.src = source_cidr.empty() ? parse_cidr("0.0.0.0/0") : parse_cidr(std::string_view(source_cidr));
	candidate.dst = destination_cidr.empty() ? parse_cidr("0.0.0.0/0") :
						   parse_cidr(std::string_view(destination_cidr));
	if (!candidate.src.valid || candidate.src.prefix_len > 32 || !candidate.dst.valid ||
	    candidate.dst.prefix_len > 32) {
		return false;
	}
	*output = candidate;
	*enabled_out = enabled;
	return true;
}

}  // namespace

config::compile_result compile_acl_from_json(const void *data, std::size_t len,
					     std::pmr::memory_resource *memory_resource, acl_compiled *out,
					     config::cancellation_probe cancellation)
{
	if (memory_resource == nullptr || out == nullptr || data == nullptr || len == 0 ||
	    out->rules.get_allocator().resource() != memory_resource ||
	    out->simd_rules.get_allocator().resource() != memory_resource) {
		return config::compile_result::INVALID;
	}
	config::json_reader reader(data, len, cancellation);
	if (!reader.begin_object()) {
		return invalid_or_cancelled(reader);
	}
	acl_compiled candidate(*memory_resource);
	std::size_t authored_rule_count = 0;
	int32_t max_rules = 0;
	uint64_t seen = 0;
	bool first = true;
	while (reader.next_object_member(&first)) {
		char key[48]{};
		std::size_t key_size = 0;
		if (!reader.read_string(key, sizeof(key), &key_size) || !reader.consume_colon()) {
			return invalid_or_cancelled(reader);
		}
		const std::string_view field(key, key_size);
		if (field == "rules") {
			if (!claim_field(&seen, 0) || !reader.begin_array())
				return invalid_or_cancelled(reader);
			bool first_rule = true;
			while (reader.next_array_element(&first_rule)) {
				acl_rule_compiled rule;
				bool enabled = false;
				if (!parse_acl_rule(reader, memory_resource, &rule, &enabled)) {
					return invalid_or_cancelled(reader);
				}
				if (authored_rule_count >
				    static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
					return config::compile_result::INVALID;
				}
				rule.authored_order = static_cast<uint32_t>(authored_rule_count);
				++authored_rule_count;
				if (enabled) {
					candidate.rules.push_back(rule);
				}
			}
			if (reader.result() != config::compile_result::OK)
				return reader.result();
		} else if (field == "default_action") {
			int32_t action = 0;
			if (!claim_field(&seen, 1) || !read_int32(reader, &action) ||
			    !parse_action(action, &candidate.default_action))
				return invalid_or_cancelled(reader);
		} else if (field == "max_rules") {
			if (!claim_field(&seen, 2) || !read_int32(reader, &max_rules))
				return invalid_or_cancelled(reader);
		} else {
			return config::compile_result::INVALID;
		}
	}
	const auto parse_result = reader.finish();
	if (parse_result != config::compile_result::OK) {
		return parse_result;
	}
	if ((seen & (uint64_t{1} << 1u)) == 0u || max_rules < 0 ||
	    (max_rules > 0 && authored_rule_count > static_cast<std::size_t>(max_rules))) {
		return config::compile_result::INVALID;
	}

	std::sort(candidate.rules.begin(), candidate.rules.end(),
		  [](const acl_rule_compiled &a, const acl_rule_compiled &b) noexcept {
			  return a.priority != b.priority ? a.priority > b.priority :
							    a.authored_order < b.authored_order;
		  });

	candidate.simd_rules.reserve(candidate.rules.size());
	for (const auto &rule : candidate.rules) {
		kinetum::algo::acl_rule_simd simd_rule{};
		simd_rule.src_network = rule.src.network;
		simd_rule.src_mask = rule.src.mask;
		simd_rule.dst_network = rule.dst.network;
		simd_rule.dst_mask = rule.dst.mask;
		simd_rule.src_port_min = rule.src_port.min;
		simd_rule.src_port_max = rule.src_port.max;
		simd_rule.dst_port_min = rule.dst_port.min;
		simd_rule.dst_port_max = rule.dst_port.max;
		simd_rule.protocol = rule.protocol == l4_protocol::OTHER ? rule.protocol_num :
									   static_cast<uint8_t>(rule.protocol);
		simd_rule.action = static_cast<uint8_t>(rule.action);
		candidate.simd_rules.push_back(simd_rule);
	}

	out->rules.swap(candidate.rules);
	out->simd_rules.swap(candidate.simd_rules);
	out->default_action = candidate.default_action;
	return config::compile_result::OK;
}

// =============================================================================
// ACL Evaluation
// =============================================================================

acl_action eval_acl_5tuple(const acl_compiled &acl, uint32_t src_ipv4, uint32_t dst_ipv4, uint8_t protocol,
			   uint16_t src_port, uint16_t dst_port) noexcept
{
	for (const auto &r : acl.rules) {
		if (r.matches(src_ipv4, dst_ipv4, protocol, src_port, dst_port)) {
			return r.action;
		}
	}
	return acl.default_action;
}

acl_action eval_acl_cached(const acl_compiled &acl, acl_cache &cache, uint64_t config_epoch, uint32_t src_ipv4,
			   uint32_t dst_ipv4, uint8_t protocol, uint16_t src_port, uint16_t dst_port) noexcept
{
	flow_key key{};
	key.src_ip = src_ipv4;
	key.dst_ip = dst_ipv4;
	key.src_port = src_port;
	key.dst_port = dst_port;
	key.protocol = protocol;

	acl_action cached_action;
	if (KINETUM_LIKELY(cache.lookup(key, config_epoch, cached_action))) {
		return cached_action;
	}

	acl_action result = eval_acl_5tuple(acl, src_ipv4, dst_ipv4, protocol, src_port, dst_port);
	cache.insert(key, config_epoch, result);

	return result;
}

}  // namespace kinetum::modules::acl
