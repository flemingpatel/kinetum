// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file nat44_impl.cpp
 * @brief NAT44 Module Implementation (Single-Owner, Pre-Allocated)
 * @author Fleming Patel
 *
 * Self-contained NAT44 translation logic using strict module-owned JSON.
 *
 * Hot-Path Optimizations:
 * - Lock-free design (no mutex in translate() function)
 * - One context-local session table per admitted module context
 * - Pre-allocated cuckoo_map + contiguous session slab: zero hot-path allocation
 *   (Platform Engineering Guide: "No malloc/free on hot path")
 * - Cursor-based incremental GC with bounded work per cycle
 * - Single canonical last_seen_ns per session (both directions share one slab entry)
 *
 * Session Storage:
 * - Contiguous PMR slab pre-sized from the exact INIT arena
 * - out_map / in_map: cuckoo_map with explicit field-wise key hashers
 * - Bounded index pool for O(1) slab slot allocation/release
 *
 * Module selection delivers both directions to the exact context owner.
 * Context-local port residues keep return ownership independent of RSS.
 */

#include "nat44_impl.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <string_view>

// Canonical algo/ headers for hot-path optimization macros
#include <kinetum/algo/platform.hpp>  // KINETUM_LIKELY/UNLIKELY
#include <kinetum/algo/prefetch.hpp>  // KINETUM_PREFETCH_L1

namespace kinetum::modules::nat44
{

// =============================================================================
// IP Parsing
// =============================================================================

namespace
{

/**
 * @brief Parse one exact address or ascending inclusive address range.
 * @param s One IPv4 address or two addresses separated by a single hyphen.
 * @param out Destination written only after both endpoints are valid and ordered.
 * @return true for a complete ascending range; false otherwise.
 */
[[nodiscard]] bool parse_ip_range(std::string_view s, ip_range *out) noexcept
{
	if (out == nullptr || s.empty())
		return false;

	const auto dash = s.find('-');
	std::string_view a = s;
	std::string_view b{};

	if (dash != std::string_view::npos) {
		const char *const begin = s.data();
		a = std::string_view(begin, dash);
		b = std::string_view(begin + dash + 1u, s.size() - dash - 1u);
		if (a.empty() || b.empty() || b.find('-') != std::string_view::npos) {
			return false;
		}
	}

	uint32_t start = 0, end = 0;
	if (!kinetum::algo::parse_ipv4(a, &start))
		return false;

	if (dash == std::string_view::npos) {
		end = start;
	} else {
		if (!kinetum::algo::parse_ipv4(b, &end))
			return false;
	}

	if (end < start)
		return false;

	out->start = start;
	out->end = end;
	return true;
}

/**
 * @brief Validate and compile one mandatory inclusive NAPT port range.
 * @param min_port Positive inclusive lower bound.
 * @param max_port Inclusive upper bound at least as large as the lower bound.
 * @param pool Destination whose port bounds are written on success.
 * @return true for an ordered interval within 1..65535; false otherwise.
 */
[[nodiscard]] bool compile_nat_port_range(int32_t min_port, int32_t max_port, nat_pool_compiled *pool) noexcept
{
	if (pool == nullptr || min_port <= 0 || max_port <= 0 || min_port > 65535 || max_port > 65535 ||
	    min_port > max_port) {
		return false;
	}

	pool->port_min = static_cast<uint16_t>(min_port);
	pool->port_max = static_cast<uint16_t>(max_port);
	return true;
}

}  // namespace

// =============================================================================
// NAT Compilation from Strict Module-Owned JSON
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
 * @brief Parse every public address range in one NAT pool.
 * @param reader Reader positioned before the public-range JSON array.
 * @param pool Unpublished pool receiving parsed ranges; earlier entries remain on failure.
 * @return true after consuming the array with no parser failure or cancellation; false otherwise.
 */
[[nodiscard]] bool parse_public_ranges(config::json_reader &reader, nat_pool_compiled *pool)
{
	if (pool == nullptr || !reader.begin_array()) {
		return false;
	}
	bool first = true;
	while (reader.next_array_element(&first)) {
		char encoded_range[64]{};
		std::size_t encoded_size = 0;
		ip_range range{};
		if (!reader.read_string(encoded_range, sizeof(encoded_range), &encoded_size) ||
		    !parse_ip_range(std::string_view(encoded_range, encoded_size), &range)) {
			return false;
		}
		pool->public_ranges.push_back(range);
	}
	return reader.result() == config::compile_result::OK;
}

/**
 * @brief Canonicalize disjoint ranges and build the hot-path ordinal index.
 * @param pool Unpublished pool whose ranges are sorted and assigned cumulative ends.
 * @return true for a nonempty disjoint overflow-free address population; false otherwise.
 */
[[nodiscard]] bool finalize_public_ranges(nat_pool_compiled *pool) noexcept
{
	if (pool == nullptr || pool->public_ranges.empty()) {
		return false;
	}
	std::sort(pool->public_ranges.begin(), pool->public_ranges.end(),
		  [](const ip_range &left, const ip_range &right) noexcept {
			  return left.start != right.start ? left.start < right.start : left.end < right.end;
		  });

	uint64_t cumulative_end = 0;
	uint32_t previous_end = 0;
	bool first = true;
	for (auto &range : pool->public_ranges) {
		// Duplicate or overlapping authority would overstate pool capacity and
		// make the bounded packet-path candidate walk revisit addresses.
		if (!first && range.start <= previous_end) {
			return false;
		}
		const uint64_t range_size = static_cast<uint64_t>(range.end) - static_cast<uint64_t>(range.start) + 1u;
		if (cumulative_end > std::numeric_limits<uint64_t>::max() - range_size) {
			return false;
		}
		cumulative_end += range_size;
		range.cumulative_end = cumulative_end;
		previous_end = range.end;
		first = false;
	}
	pool->total_public_ips = cumulative_end;
	return true;
}

/**
 * @brief Parse and validate one strict NAT pool object.
 * @param reader Reader positioned before the pool object.
 * @param memory_resource PREPARE resource shared by the candidate and destination.
 * @param output Destination receiving the validated candidate only after complete parsing.
 * @return true for a complete valid pool with matching allocator ownership; false otherwise.
 */
[[nodiscard]] bool parse_nat_pool(config::json_reader &reader, std::pmr::memory_resource *memory_resource,
				  nat_pool_compiled *output)
{
	if (output == nullptr || output->public_ranges.get_allocator().resource() != memory_resource ||
	    !reader.begin_object()) {
		return false;
	}
	nat_pool_compiled candidate(*memory_resource);
	int32_t port_min = 0;
	int32_t port_max = 0;
	uint64_t seen = 0;
	bool first = true;
	while (reader.next_object_member(&first)) {
		char key[48]{};
		std::size_t key_size = 0;
		if (!reader.read_string(key, sizeof(key), &key_size) || !reader.consume_colon()) {
			return false;
		}
		const std::string_view field(key, key_size);
		if (field == "public_ip_ranges") {
			if (!claim_field(&seen, 0) || !parse_public_ranges(reader, &candidate))
				return false;
		} else if (field == "port_min") {
			if (!claim_field(&seen, 1) || !read_int32(reader, &port_min))
				return false;
		} else if (field == "port_max") {
			if (!claim_field(&seen, 2) || !read_int32(reader, &port_max))
				return false;
		} else {
			return false;
		}
	}
	if (reader.result() != config::compile_result::OK || !finalize_public_ranges(&candidate) ||
	    !compile_nat_port_range(port_min, port_max, &candidate)) {
		return false;
	}
	output->public_ranges.swap(candidate.public_ranges);
	output->total_public_ips = candidate.total_public_ips;
	output->port_min = candidate.port_min;
	output->port_max = candidate.port_max;
	return true;
}

}  // namespace

config::compile_result compile_nat_from_json(const void *data, std::size_t len,
					     std::pmr::memory_resource *memory_resource, nat_pools_compiled *out,
					     config::cancellation_probe cancellation)
{
	if (memory_resource == nullptr || out == nullptr || data == nullptr || len == 0 || !out->partition.valid() ||
	    out->pools.get_allocator().resource() != memory_resource) {
		return config::compile_result::INVALID;
	}
	config::json_reader reader(data, len, cancellation);
	if (!reader.begin_object()) {
		return invalid_or_cancelled(reader);
	}
	nat_pools_compiled candidate(*memory_resource, out->partition);
	int32_t session_timeout_s = 0;
	int32_t max_total_sessions = 0;
	uint64_t seen = 0;
	bool first = true;
	while (reader.next_object_member(&first)) {
		char key[48]{};
		std::size_t key_size = 0;
		if (!reader.read_string(key, sizeof(key), &key_size) || !reader.consume_colon()) {
			return invalid_or_cancelled(reader);
		}
		const std::string_view field(key, key_size);
		if (field == "pools") {
			if (!claim_field(&seen, 0) || !reader.begin_array())
				return invalid_or_cancelled(reader);
			bool first_pool = true;
			while (reader.next_array_element(&first_pool)) {
				nat_pool_compiled pool(*memory_resource);
				if (!parse_nat_pool(reader, memory_resource, &pool)) {
					return invalid_or_cancelled(reader);
				}
				const uint32_t stride = candidate.partition.count;
				const uint32_t first_owned = static_cast<uint32_t>(pool.port_min) +
							     (candidate.partition.ordinal + stride -
							      static_cast<uint32_t>(pool.port_min) % stride) %
								     stride;
				if (first_owned > pool.port_max) {
					continue;
				}
				pool.first_owned_port = static_cast<uint16_t>(first_owned);
				pool.owned_port_count =
					(static_cast<uint32_t>(pool.port_max) - first_owned) / stride + 1u;
				candidate.pools.push_back(std::move(pool));
			}
			if (reader.result() != config::compile_result::OK)
				return reader.result();
		} else if (field == "session_timeout_s") {
			if (!claim_field(&seen, 1) || !read_int32(reader, &session_timeout_s))
				return invalid_or_cancelled(reader);
		} else if (field == "max_total_sessions") {
			if (!claim_field(&seen, 2) || !read_int32(reader, &max_total_sessions))
				return invalid_or_cancelled(reader);
		} else {
			return config::compile_result::INVALID;
		}
	}
	const auto parse_result = reader.finish();
	if (parse_result != config::compile_result::OK) {
		return parse_result;
	}
	if (candidate.pools.empty() || session_timeout_s < 0 || max_total_sessions < 0 ||
	    max_total_sessions > static_cast<int32_t>(NAT_DEFAULT_MAX_SESSIONS)) {
		return config::compile_result::INVALID;
	}
	candidate.session_timeout_s = session_timeout_s > 0 ? static_cast<uint32_t>(session_timeout_s) :
							      NAT_DEFAULT_TIMEOUT_S;
	candidate.max_sessions = max_total_sessions > 0 ? static_cast<uint32_t>(max_total_sessions) :
							  NAT_DEFAULT_MAX_SESSIONS;

	out->pools.swap(candidate.pools);
	out->session_timeout_s = candidate.session_timeout_s;
	out->max_sessions = candidate.max_sessions;
	return config::compile_result::OK;
}

// =============================================================================
// NAT44 Table Implementation (Single-Owner, Pre-Allocated)
// =============================================================================

nat44_table::nat44_table(uint32_t max_sessions, std::pmr::memory_resource &memory_resource, context_partition owner)
	: partition_(owner)
	, slab_(max_sessions, &memory_resource)
	, free_indices_(max_sessions, &memory_resource)
	, out_map_(std::max<std::size_t>(1u, max_sessions / kinetum::algo::CUCKOO_BUCKET_SIZE), &memory_resource)
	, in_map_(std::max<std::size_t>(1u, max_sessions / kinetum::algo::CUCKOO_BUCKET_SIZE), &memory_resource)
	, max_sessions_(max_sessions)
{
	if (!partition_.valid()) {
		std::terminate();
	}
}

nat_stats_snapshot nat44_table::get_stats() const noexcept
{
	return stats_.snapshot();
}

bool nat44_table::allocate_and_insert_(const nat_pools_compiled &pools, uint64_t now_ns, uint8_t proto,
				       uint32_t internal_ip, uint16_t internal_port, uint32_t remote_ip,
				       uint16_t remote_port, nat_session *out) noexcept
{
	// The admitted module context gives this table one packet-worker owner.
	if (!out || pools.pools.empty())
		return false;

	// Capacity enforcement: slab exhaustion = hard cap (no malloc on hot path)
	if (KINETUM_UNLIKELY(free_indices_.available() == 0u)) {
		++stats_.allocation_failures;
		return false;
	}

	// Policy enforcement: max_sessions from configuration
	const uint32_t active = free_indices_.in_use();
	if (KINETUM_UNLIKELY(active >= pools.max_sessions)) {
		++stats_.allocation_failures;
		return false;
	}

	const std::size_t pool_idx = static_cast<std::size_t>(alloc_counter_++ % pools.pools.size());
	const auto &pool = pools.pools[pool_idx];

	if (pool.public_ranges.empty() || pool.total_public_ips == 0 || pool.owned_port_count == 0u)
		return false;

	const uint32_t port_span = pool.owned_port_count;
	const uint64_t start_ctr = alloc_counter_;
	const uint64_t candidate_count = pool.total_public_ips > std::numeric_limits<uint64_t>::max() / port_span ?
						 std::numeric_limits<uint64_t>::max() :
						 pool.total_public_ips * port_span;
	const uint32_t max_attempts =
		static_cast<uint32_t>(std::min<uint64_t>(NAT_MAX_ALLOC_ATTEMPTS, candidate_count));

	for (uint32_t attempt = 0; attempt < max_attempts; ++attempt) {
		const uint64_t ctr = start_ctr + attempt;
		const uint16_t cand_port = static_cast<uint16_t>(static_cast<uint64_t>(pool.first_owned_port) +
								 (ctr % port_span) * partition_.count);

		const uint64_t address_ordinal = (ctr / port_span) % pool.total_public_ips;
		const auto range = std::lower_bound(pool.public_ranges.begin(), pool.public_ranges.end(),
						    address_ordinal,
						    [](const ip_range &candidate, uint64_t ordinal) noexcept {
							    return candidate.cumulative_end <= ordinal;
						    });
		if (KINETUM_UNLIKELY(range == pool.public_ranges.end())) {
			++stats_.allocation_failures;
			return false;
		}
		const uint64_t prior_end = range == pool.public_ranges.begin() ? 0u : (range - 1)->cumulative_end;
		const uint32_t cand_ip =
			static_cast<uint32_t>(static_cast<uint64_t>(range->start) + address_ordinal - prior_end);

		const in_key ik{proto, cand_ip, cand_port, remote_ip, remote_port};

		// Check for public-side collision (inbound key already in use)
		if (in_map_.contains(ik)) {
			continue;
		}

		// Acquire one preallocated slab index without changing physical storage.
		uint32_t idx = 0u;
		if (!free_indices_.try_acquire(idx)) {
			std::terminate();
		}

		// Fill slab entry (single canonical session - both maps point here)
		nat_session &s = slab_[idx];
		if (s.occupied) {
			std::terminate();
		}
		s.last_seen_ns = now_ns;
		s.internal_ip = internal_ip;
		s.remote_ip = remote_ip;
		s.public_ip = cand_ip;
		s.internal_port = internal_port;
		s.remote_port = remote_port;
		s.public_port = cand_port;
		s.proto = proto;
		s.occupied = true;

		// Insert into both cuckoo maps with slab index as value (zero heap alloc)
		const out_key ok{proto, internal_ip, internal_port, remote_ip, remote_port};

		if (KINETUM_UNLIKELY(!out_map_.insert(ok, idx))) {
			// Cuckoo table full after max displacement kicks - rollback
			s.occupied = false;
			free_indices_.release(idx);
			++stats_.allocation_failures;
			return false;
		}

		if (KINETUM_UNLIKELY(!in_map_.insert(ik, idx))) {
			// Rollback: erase from out_map, release slab slot
			if (!out_map_.erase(ok)) {
				std::terminate();
			}
			s.occupied = false;
			free_indices_.release(idx);
			++stats_.allocation_failures;
			return false;
		}

		++stats_.active_sessions;
		++stats_.total_created;

		*out = s;
		return true;
	}

	++stats_.allocation_failures;
	return false;
}

void nat44_table::maybe_gc_(uint64_t now_ns, uint64_t timeout_ns) noexcept
{
	// Sole-owner GC needs no synchronization. The cursor scans one bounded
	// contiguous slab window per invocation.
	if (KINETUM_UNLIKELY(max_sessions_ == 0))
		return;

	++gc_counter_;

	if ((gc_counter_ & NAT_GC_TRIGGER_MASK) != 0)
		return;

	uint32_t scanned = 0;
	std::size_t evicted = 0;
	uint32_t cursor = gc_cursor_;

	while (scanned < NAT_GC_SCAN_LIMIT && evicted < NAT_GC_MAX_EVICTIONS) {
		if (cursor >= max_sessions_)
			cursor = 0;

		// Prefetch next slab entry for cache-friendly iteration
		if (KINETUM_LIKELY(scanned + 1 < NAT_GC_SCAN_LIMIT && cursor + 1 < max_sessions_)) {
			KINETUM_PREFETCH_L1(&slab_[cursor + 1]);
		}

		const nat_session &entry = slab_[cursor];
		if (entry.occupied && now_ns > entry.last_seen_ns && now_ns - entry.last_seen_ns > timeout_ns) {
			// Construct both keys from the single canonical slab entry
			const out_key ok{entry.proto, entry.internal_ip, entry.internal_port, entry.remote_ip,
					 entry.remote_port};
			const in_key ik{entry.proto, entry.public_ip, entry.public_port, entry.remote_ip,
					entry.remote_port};

			// Erase from both maps (O(1) each)
			if (!out_map_.erase(ok) || !in_map_.erase(ik)) {
				std::terminate();
			}

			// Return the retired slab index without changing physical storage.
			slab_[cursor].occupied = false;
			free_indices_.release(cursor);

			++evicted;
		}

		++cursor;
		++scanned;
	}

	gc_cursor_ = (cursor >= max_sessions_) ? 0 : cursor;

	if (evicted > 0) {
		const auto reclaimed = static_cast<uint64_t>(evicted);
		if (reclaimed > stats_.active_sessions ||
		    reclaimed > std::numeric_limits<uint64_t>::max() - stats_.total_expired) {
			std::terminate();
		}
		stats_.active_sessions -= reclaimed;
		stats_.total_expired += reclaimed;
	}
}

bool nat44_table::translate(uint64_t now_ns, const nat_pools_compiled &pools, bool outbound, uint8_t proto,
			    uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint32_t *out_ip,
			    uint16_t *out_port)
{
	// LOCK-FREE HOT PATH
	// - No mutex, no shared_mutex
	// - Sole context-owner access; admitted selection preserves session ownership
	// - Follows Platform Engineering Guide: "No locks on hot path"
	// - Zero allocation: cuckoo_map find -> slab dereference

	if (KINETUM_UNLIKELY(!out_ip || !out_port))
		return false;

	const uint64_t timeout_ns = static_cast<uint64_t>(pools.session_timeout_s) * 1000000000ull;

	// Opportunistic bounded GC on the same owner worker.
	maybe_gc_(now_ns, timeout_ns);

	if (KINETUM_LIKELY(outbound)) {
		// Outbound: lookup existing session or create new
		const out_key ok{proto, src_ip, src_port, dst_ip, dst_port};

		// O(1) cuckoo lookup -> slab dereference (single canonical session)
		const uint32_t *idx = out_map_.find(ok);
		if (KINETUM_LIKELY(idx != nullptr)) {
			nat_session &s = slab_[*idx];
			if (now_ns > s.last_seen_ns) {
				s.last_seen_ns = now_ns;
			}
			*out_ip = s.public_ip;
			*out_port = s.public_port;
			return true;
		}

		// Create new session (lock-free)
		nat_session ns{};
		if (!allocate_and_insert_(pools, now_ns, proto, src_ip, src_port, dst_ip, dst_port, &ns)) {
			return false;
		}

		*out_ip = ns.public_ip;
		*out_port = ns.public_port;
		return true;
	}

	// Inbound: lookup existing session (must exist - fail-closed)
	const in_key ik{proto, dst_ip, dst_port, src_ip, src_port};

	// O(1) cuckoo lookup -> slab dereference (same canonical session as outbound)
	const uint32_t *idx = in_map_.find(ik);
	if (KINETUM_UNLIKELY(idx == nullptr)) {
		++stats_.inbound_misses;
		return false;
	}

	nat_session &s = slab_[*idx];
	if (now_ns > s.last_seen_ns) {
		s.last_seen_ns = now_ns;
	}
	*out_ip = s.internal_ip;
	*out_port = s.internal_port;
	return true;
}

}  // namespace kinetum::modules::nat44
