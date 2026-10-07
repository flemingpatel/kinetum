// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file acl_impl.hpp
 * @brief ACL Module Implementation (Module-Owned, Self-Contained)
 * @author Fleming Patel
 *
 * This file contains the ACL evaluation logic for the ACL module.
 * Its strict JSON contract corresponds to the module-owned
 * kinetum.module.acl.v1 schema and remains self-contained in the image.
 *
 * Design Philosophy:
 * - Module is the SOURCE OF TRUTH for ACL configuration schema
 * - Platform routes opaque config_blob without interpretation
 * - Module deserializes and applies its own config format
 *
 * CIDR utilities are shared from <kinetum/algo/cidr.hpp>.
 */

#include <cstdint>
#include <memory_resource>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <kinetum/algo/cidr.hpp>  // Canonical CIDR utilities
#include <kinetum/algo/hash.hpp>  // FNV1A_OFFSET_BASIS, FNV1A_PRIME
#include <kinetum/algo/net.hpp>
#include <kinetum/algo/simd_classify.hpp>  // SIMD batch classification primitives
#include "src/modules/module_config_json.hpp"

namespace kinetum::modules::acl
{

// Import CIDR types from algo namespace for module use
using kinetum::algo::cidr;
using kinetum::algo::parse_cidr;
using kinetum::algo::parse_ipv4;
using kinetum::algo::match_cidr;

// =============================================================================
// ACL Types
// =============================================================================

/** @brief Terminal action selected by one compiled ACL rule. */
enum class acl_action : uint8_t {
	PERMIT = 0,  ///< Forward the matching packet.
	DENY = 1,    ///< Retire the matching packet.
};

/** @brief Compiled IP-protocol selector for one ACL rule. */
enum class l4_protocol : uint8_t {
	ANY = 0,     ///< Match every protocol without applying transport ports.
	TCP = 6,     ///< Match TCP and apply any authored port ranges.
	UDP = 17,    ///< Match UDP and apply any authored port ranges.
	ICMP = 1,    ///< Match ICMP without applying transport ports.
	OTHER = 255  ///< Match the separately compiled protocol number.
};

/** @brief Inclusive transport-port interval. */
struct port_range {
	uint16_t min{0};      ///< Inclusive minimum port.
	uint16_t max{65535};  ///< Inclusive maximum port.

	/** @param port Candidate transport port. @return True when @p port is inside this interval. */
	[[nodiscard]] constexpr bool matches(uint16_t port) const noexcept
	{
		return port >= min && port <= max;
	}

	/** @return True when this interval accepts every uint16 port. */
	[[nodiscard]] constexpr bool is_any() const noexcept
	{
		return min == 0 && max == 65535;
	}

	/** @return True when the inclusive endpoints are ordered. */
	[[nodiscard]] constexpr bool is_valid() const noexcept
	{
		return min <= max;
	}
};

/**
 * @brief Compiled ACL rule
 */
struct acl_rule_compiled {
	int32_t priority{0};			 ///< Higher values are evaluated first.
	uint32_t authored_order{0};		 ///< Stable tie-breaker for equal priorities.
	cidr src{};				 ///< Source IPv4 prefix.
	cidr dst{};				 ///< Destination IPv4 prefix.
	acl_action action{acl_action::DENY};	 ///< Terminal action on a match.
	l4_protocol protocol{l4_protocol::ANY};	 ///< Compiled protocol selector.
	uint8_t protocol_num{0};		 ///< Exact protocol selected by @ref l4_protocol::OTHER.
	port_range src_port{};			 ///< Source range applied only to TCP or UDP.
	port_range dst_port{};			 ///< Destination range applied only to TCP or UDP.

	/**
	 * @brief Match one complete packet tuple against this rule.
	 * @param src_ip Source IPv4 address in host representation.
	 * @param dst_ip Destination IPv4 address in host representation.
	 * @param proto IP protocol number.
	 * @param sport Source transport port.
	 * @param dport Destination transport port.
	 * @return True when every applicable rule predicate matches.
	 */
	[[nodiscard]] bool matches(uint32_t src_ip, uint32_t dst_ip, uint8_t proto, uint16_t sport,
				   uint16_t dport) const noexcept
	{
		if (!match_cidr(src_ip, src))
			return false;
		if (!match_cidr(dst_ip, dst))
			return false;

		if (protocol != l4_protocol::ANY) {
			if (protocol == l4_protocol::OTHER) {
				if (proto != protocol_num)
					return false;
			} else {
				if (proto != static_cast<uint8_t>(protocol))
					return false;
			}
		}

		if (proto == kinetum::algo::net::protocol::TCP || proto == kinetum::algo::net::protocol::UDP) {
			if (!src_port.is_any() && !src_port.matches(sport))
				return false;
			if (!dst_port.is_any() && !dst_port.matches(dport))
				return false;
		}

		return true;
	}
};

/**
 * @brief Compiled ACL ruleset
 */
struct acl_compiled {
	/** @brief Construct one immutable policy. @param resource Exact policy-storage authority. */
	explicit acl_compiled(std::pmr::memory_resource &resource)
		: rules(&resource)
		, simd_rules(&resource)
	{
	}
	/** @brief Reject copying because one PMR arena owns the complete policy. */
	acl_compiled(const acl_compiled &) = delete;
	/** @brief Reject copy assignment because policy publication is construction-fixed. */
	acl_compiled &operator=(const acl_compiled &) = delete;
	/** @brief Move-construct one unpublished policy with its exact allocator. */
	acl_compiled(acl_compiled &&) noexcept = default;
	/** @brief Reject move assignment because policy publication uses same-resource exchange. */
	acl_compiled &operator=(acl_compiled &&) = delete;

	std::pmr::vector<acl_rule_compiled> rules;		    ///< Priority-ordered scalar rules.
	std::pmr::vector<kinetum::algo::acl_rule_simd> simd_rules;  ///< Scalar-equivalent SIMD projections.
	acl_action default_action{acl_action::DENY};		    ///< Action when no rule matches.
};

static_assert(std::is_nothrow_move_constructible_v<acl_compiled>,
	      "ACL compiled policy transfer must remain nonthrowing");

// =============================================================================
// ACL Hash Cache (Flow Memoization)
// =============================================================================

/** @brief Semantic five-tuple key used by the owner-local decision cache. */
struct alignas(16) flow_key {
	uint32_t src_ip;     ///< Source IPv4 address.
	uint32_t dst_ip;     ///< Destination IPv4 address.
	uint16_t src_port;   ///< Source transport port.
	uint16_t dst_port;   ///< Destination transport port.
	uint8_t protocol;    ///< IP protocol number.
	uint8_t padding{0};  ///< Explicit layout byte excluded from equality and hashing.

	/** @param other Candidate semantic key. @return True when all five tuple fields match. */
	[[nodiscard]] bool operator==(const flow_key &other) const noexcept
	{
		return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port &&
		       dst_port == other.dst_port && protocol == other.protocol;
	}
};

/** @brief Nonthrowing field-wise hasher for @ref flow_key. */
struct flow_key_hash {
	/** @param k Semantic key to hash. @return Field-wise FNV-1a hash excluding padding. */
	[[nodiscard]] std::size_t operator()(const flow_key &k) const noexcept
	{
		// FNV-1a variant optimized for 32-bit field hashing
		// Uses canonical constants from algo/hash.hpp
		std::size_t h = kinetum::algo::FNV1A_OFFSET_BASIS;
		h ^= k.src_ip;
		h *= kinetum::algo::FNV1A_PRIME;
		h ^= k.dst_ip;
		h *= kinetum::algo::FNV1A_PRIME;
		h ^= (static_cast<std::size_t>(k.src_port) << 16) | k.dst_port;
		h *= kinetum::algo::FNV1A_PRIME;
		h ^= k.protocol;
		return h;
	}
};

/**
 * @brief Context-owned ACL cache for memoized lookups.
 *
 * One packet worker owns the enclosing module context and is the sole reader
 * and writer of this cache and its statistics.
 */
class acl_cache {
    public:
	/** @brief Owner-local cache telemetry accumulated between publications. */
	struct stats {
		uint64_t hits{0};    ///< Exact key-and-epoch cache hits.
		uint64_t misses{0};  ///< Cache misses requiring rule evaluation.

		/** @brief Reset every cache telemetry counter to zero. */
		void reset() noexcept;
	};

	/**
	 * @brief Construct a fixed-capacity direct-mapped ACL cache.
	 *
	 * @param max_entries Exact positive power-of-two entry capacity.
	 * @param memory_resource Exact context-lifetime storage authority.
	 * @throws std::invalid_argument If @p max_entries is zero or not a power of two.
	 */
	explicit acl_cache(std::size_t max_entries, std::pmr::memory_resource &memory_resource);

	/**
	 * @brief Look up one flow under an exact platform configuration epoch.
	 *
	 * Epoch changes are O(1): stale entries remain physically resident but
	 * cannot match because every entry carries its exact nonzero epoch tag.
	 *
	 * @param key Flow key to query.
	 * @param config_epoch Exact nonzero platform packet epoch.
	 * @param out_action Output action, written only on a cache hit.
	 * @return true on an exact key-and-epoch hit; false otherwise.
	 */
	[[nodiscard]] bool lookup(const flow_key &key, uint64_t config_epoch, acl_action &out_action) noexcept;

	/**
	 * @brief Insert one evaluated action under an exact platform epoch.
	 *
	 * A zero epoch is rejected by leaving the cache unchanged.
	 *
	 * @param key Evaluated flow key.
	 * @param config_epoch Exact nonzero platform packet epoch.
	 * @param action Evaluated action to cache.
	 */
	void insert(const flow_key &key, uint64_t config_epoch, acl_action action) noexcept;

	/** @return Copy of current owner-local cache telemetry. */
	[[nodiscard]] stats get_stats() const noexcept;

	/** @brief Reset telemetry without invalidating cached decisions. */
	void reset_stats() noexcept;

    private:
	/** @brief One cache-line-isolated decision with an exact epoch tag. */
	struct alignas(64) cache_entry {
		flow_key key{};			      ///< Exact five-tuple cache key.
		acl_action action{acl_action::DENY};  ///< Evaluated action for the exact key.
		uint64_t config_epoch{0};	      ///< Exact nonzero platform packet epoch.
		bool valid{false};		      ///< Whether this slot may match.
		uint8_t padding[6]{};		      ///< Explicit cache-line layout padding.
	};

	std::pmr::vector<cache_entry> entries_;	 ///< Fixed direct-mapped entry storage.
	std::size_t mask_{0};			 ///< Index mask equal to the exact capacity minus one.
	uint64_t cache_epoch_{0};		 ///< Exact owner-local generation admitted for cache inserts.
	stats stats_;				 ///< Owner-local cumulative cache counters.
};

// =============================================================================
// ACL Compilation and Evaluation API
// =============================================================================

/**
 * @brief Compile one strict module-owned JSON ACL ruleset.
 *
 * Unknown or duplicate fields, alternate protobuf encodings, malformed UTF-8,
 * fractional numbers, invalid policy values, and trailing content reject.
 *
 * @param data Exact JSON bytes corresponding to AclRuleset field names.
 * @param len Exact byte count.
 * @param memory_resource Exact storage authority for the compiled policy.
 * @param out Output replaced only after complete successful compilation.
 * @param cancellation Cooperative cold-path cancellation probe.
 * @return OK, INVALID, or CANCELLED.
 */
[[nodiscard]] config::compile_result compile_acl_from_json(const void *data, std::size_t len,
							   std::pmr::memory_resource *memory_resource,
							   acl_compiled *out,
							   config::cancellation_probe cancellation = {});

/**
 * @brief Evaluate one complete five-tuple without cache lookup.
 *
 * @param acl Exact immutable compiled ACL policy.
 * @param src_ipv4 Source IPv4 address in host integer representation.
 * @param dst_ipv4 Destination IPv4 address in host integer representation.
 * @param protocol IP protocol number.
 * @param src_port Source transport port.
 * @param dst_port Destination transport port.
 * @return First matching action, or the exact compiled default action.
 */
[[nodiscard]] acl_action eval_acl_5tuple(const acl_compiled &acl, uint32_t src_ipv4, uint32_t dst_ipv4,
					 uint8_t protocol, uint16_t src_port, uint16_t dst_port) noexcept;

/**
 * @brief Evaluate one five-tuple through the exact-epoch ACL cache.
 *
 * @param acl Exact immutable compiled ACL policy.
 * @param cache Context-owned decision cache.
 * @param config_epoch Exact nonzero platform packet epoch.
 * @param src_ipv4 Source IPv4 address in host integer representation.
 * @param dst_ipv4 Destination IPv4 address in host integer representation.
 * @param protocol IP protocol number.
 * @param src_port Source transport port.
 * @param dst_port Destination transport port.
 * @return Cached or freshly evaluated ACL action.
 */
[[nodiscard]] acl_action eval_acl_cached(const acl_compiled &acl, acl_cache &cache, uint64_t config_epoch,
					 uint32_t src_ipv4, uint32_t dst_ipv4, uint8_t protocol, uint16_t src_port,
					 uint16_t dst_port) noexcept;

// =============================================================================
// Evaluation Strategy
// =============================================================================

/** @brief Exact admitted packet-evaluation implementation. */
enum class acl_eval_strategy : uint8_t {
	LINEAR,	     ///< Scalar ordered rule walk.
	HASH_CACHE,  ///< Exact-epoch cache followed by scalar evaluation on miss.
	SIMD_BATCH,  ///< Scalar-equivalent batched SIMD evaluation.
};

}  // namespace kinetum::modules::acl
