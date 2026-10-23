// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file qos_impl.cpp
 * @brief Strict QoS policy compilation and sole-worker flow policing.
 * @author Fleming Patel
 *
 * Flow state uses exact byte-credit arithmetic, a compact mutable slab and
 * separate reclamation keys. GC and policing mutate each index only on its
 * context's worker.
 */

#include "qos_impl.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <string_view>

#include <kinetum/algo/platform.hpp>

namespace kinetum::modules::qos
{

// =============================================================================
// QoS Compilation from Strict Module-Owned JSON
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
 * @brief Parse and validate one strict QoS profile object.
 * @param reader Reader positioned before the profile object.
 * @param memory_resource PREPARE resource shared by the candidate and destination.
 * @param output Destination receiving the validated candidate only after complete parsing.
 * @return true for a complete valid profile with matching allocator ownership; false otherwise.
 */
[[nodiscard]] bool parse_qos_profile(config::json_reader &reader, std::pmr::memory_resource *memory_resource,
				     qos_profile_compiled *output)
{
	if (output == nullptr || output->name.get_allocator().resource() != memory_resource || !reader.begin_object()) {
		return false;
	}
	qos_profile_compiled candidate(*memory_resource);
	int64_t cir_kbps = 0;
	int64_t cbs_kb = 0;
	int32_t conform_dscp = 0;
	uint64_t seen = 0;
	bool first = true;
	while (reader.next_object_member(&first)) {
		char key[48]{};
		std::size_t key_size = 0;
		if (!reader.read_string(key, sizeof(key), &key_size) || !reader.consume_colon()) {
			return false;
		}
		const std::string_view field(key, key_size);
		if (field == "name") {
			if (!claim_field(&seen, 0) || !reader.read_string(&candidate.name))
				return false;
		} else if (field == "cir_kbps") {
			if (!claim_field(&seen, 1) || !reader.read_int64(&cir_kbps))
				return false;
		} else if (field == "cbs_kb") {
			if (!claim_field(&seen, 2) || !reader.read_int64(&cbs_kb))
				return false;
		} else if (field == "conform_dscp") {
			if (!claim_field(&seen, 3) || !read_int32(reader, &conform_dscp))
				return false;
		} else {
			return false;
		}
	}
	if (reader.result() != config::compile_result::OK || candidate.name.empty() || cir_kbps < 0 ||
	    cir_kbps > QOS_MAX_CIR_KBPS || cbs_kb < 0 || cbs_kb > QOS_MAX_CBS_KB || conform_dscp < 0 ||
	    conform_dscp >= 64) {
		return false;
	}
	candidate.cir_bytes_per_s = static_cast<uint64_t>(cir_kbps) * 125u;
	candidate.burst_bytes = static_cast<uint64_t>(cbs_kb) * 1024u;
	candidate.conform_dscp = static_cast<uint8_t>(conform_dscp);
	output->name.swap(candidate.name);
	output->cir_bytes_per_s = candidate.cir_bytes_per_s;
	output->burst_bytes = candidate.burst_bytes;
	output->conform_dscp = candidate.conform_dscp;
	return true;
}

}  // namespace

const qos_profile_compiled *qos_profiles_compiled::find_profile(std::string_view name) const noexcept
{
	const auto it = std::find_if(profiles.begin(), profiles.end(), [name](const qos_profile_compiled &profile) {
		return std::string_view(profile.name.data(), profile.name.size()) == name;
	});
	return it != profiles.end() ? &*it : nullptr;
}

config::compile_result compile_qos_from_json(const void *data, std::size_t len,
					     std::pmr::memory_resource *memory_resource, qos_profiles_compiled *out,
					     config::cancellation_probe cancellation)
{
	if (memory_resource == nullptr || out == nullptr || data == nullptr || len == 0 ||
	    out->default_profile.get_allocator().resource() != memory_resource ||
	    out->profiles.get_allocator().resource() != memory_resource) {
		return config::compile_result::INVALID;
	}
	config::json_reader reader(data, len, cancellation);
	if (!reader.begin_object()) {
		return invalid_or_cancelled(reader);
	}
	qos_profiles_compiled candidate(*memory_resource);
	uint64_t gc_trigger_mask = 0;
	uint64_t gc_max_evictions = 0;
	uint64_t idle_timeout_s = 0;
	uint64_t seen = 0;
	bool first = true;
	while (reader.next_object_member(&first)) {
		char key[48]{};
		std::size_t key_size = 0;
		if (!reader.read_string(key, sizeof(key), &key_size) || !reader.consume_colon()) {
			return invalid_or_cancelled(reader);
		}
		const std::string_view field(key, key_size);
		if (field == "profiles") {
			if (!claim_field(&seen, 0) || !reader.begin_array())
				return invalid_or_cancelled(reader);
			bool first_profile = true;
			while (reader.next_array_element(&first_profile)) {
				qos_profile_compiled profile(*memory_resource);
				if (!parse_qos_profile(reader, memory_resource, &profile) ||
				    candidate.find_profile(
					    std::string_view(profile.name.data(), profile.name.size())) != nullptr) {
					return invalid_or_cancelled(reader);
				}
				candidate.profiles.push_back(std::move(profile));
			}
			if (reader.result() != config::compile_result::OK)
				return reader.result();
		} else if (field == "default_profile") {
			if (!claim_field(&seen, 1) || !reader.read_string(&candidate.default_profile))
				return invalid_or_cancelled(reader);
		} else if (field == "gc_trigger_mask") {
			if (!claim_field(&seen, 2) || !reader.read_uint64(&gc_trigger_mask))
				return invalid_or_cancelled(reader);
		} else if (field == "gc_max_evictions") {
			if (!claim_field(&seen, 3) || !reader.read_uint64(&gc_max_evictions))
				return invalid_or_cancelled(reader);
		} else if (field == "idle_timeout_s") {
			if (!claim_field(&seen, 4) || !reader.read_uint64(&idle_timeout_s))
				return invalid_or_cancelled(reader);
		} else {
			return config::compile_result::INVALID;
		}
	}
	const auto parse_result = reader.finish();
	if (parse_result != config::compile_result::OK) {
		return parse_result;
	}
	constexpr uint64_t NS_PER_SECOND = 1000000000ull;
	if (candidate.default_profile.empty() || candidate.profiles.empty() ||
	    gc_max_evictions > static_cast<uint64_t>(std::numeric_limits<std::size_t>::max()) ||
	    gc_max_evictions > DEFAULT_QOS_GC_SCAN_LIMIT || idle_timeout_s > std::numeric_limits<uint32_t>::max() ||
	    candidate.find_profile(
		    std::string_view(candidate.default_profile.data(), candidate.default_profile.size())) == nullptr) {
		return config::compile_result::INVALID;
	}
	candidate.runtime.gc_trigger_mask = gc_trigger_mask != 0 ? gc_trigger_mask : DEFAULT_QOS_GC_TRIGGER_MASK;
	candidate.runtime.gc_max_evictions = gc_max_evictions != 0 ? static_cast<std::size_t>(gc_max_evictions) :
								     DEFAULT_QOS_GC_MAX_EVICTIONS;
	const uint64_t effective_idle_timeout_s = idle_timeout_s != 0 ? idle_timeout_s :
									DEFAULT_QOS_IDLE_TIMEOUT_NS / NS_PER_SECOND;
	candidate.runtime.idle_timeout_ns = effective_idle_timeout_s * NS_PER_SECOND;

	out->default_profile.swap(candidate.default_profile);
	out->profiles.swap(candidate.profiles);
	out->runtime = candidate.runtime;
	return config::compile_result::OK;
}

// =============================================================================
// QoS Policer Implementation (Single-Owner, Pre-Allocated)
// =============================================================================

qos_policer::qos_policer(uint32_t max_flows, std::pmr::memory_resource &memory_resource)
	: slab_(max_flows, &memory_resource)
	, keys_(max_flows, &memory_resource)
	, free_indices_(max_flows, &memory_resource)
	, map_(std::max<std::size_t>(1u, max_flows / kinetum::algo::CUCKOO_BUCKET_SIZE), &memory_resource)
	, max_flows_(max_flows)
{
}

uint64_t qos_policer::active_flows() const noexcept
{
	return free_indices_.in_use();
}

void qos_policer::observe_time(uint64_t now_ns) noexcept
{
	if (now_ns < last_observed_ns_) {
		std::terminate();
	}
	last_observed_ns_ = now_ns;
}

void qos_policer::maybe_gc_(uint64_t now_ns, const qos_runtime_tuning &runtime) noexcept
{
	// Sole-owner GC needs no synchronization. The cursor scans one bounded
	// contiguous slab window per invocation.

	// Guard: zero-capacity policer has no slab entries to scan.
	// Without this, cursor wraps to 0 and slab_[0] is UB on empty vector.
	if (KINETUM_UNLIKELY(max_flows_ == 0))
		return;

	++gc_counter_;

	if ((gc_counter_ & runtime.gc_trigger_mask) != 0)
		return;

	uint32_t scanned = 0;
	std::size_t evicted = 0;
	uint32_t cursor = gc_cursor_;

	while (scanned < DEFAULT_QOS_GC_SCAN_LIMIT && evicted < runtime.gc_max_evictions) {
		if (cursor >= max_flows_)
			cursor = 0;

		// Prefetch next slab entry for cache-friendly iteration
		if (KINETUM_LIKELY(scanned + 1 < DEFAULT_QOS_GC_SCAN_LIMIT && cursor + 1 < max_flows_)) {
			KINETUM_PREFETCH_L1(&slab_[cursor + 1]);
		}

		const bucket &entry = slab_[cursor];
		if (entry.occupied && now_ns > entry.last_ns && now_ns - entry.last_ns > runtime.idle_timeout_ns) {
			if (!map_.erase(keys_[cursor])) {
				std::terminate();
			}
			slab_[cursor].occupied = false;
			free_indices_.release(cursor);
			++evicted;
		}

		++cursor;
		++scanned;
	}

	gc_cursor_ = (cursor >= max_flows_) ? 0 : cursor;
}

policer_result qos_policer::police(uint64_t now_ns, const qos_profile_compiled &profile,
				   const qos_runtime_tuning &runtime, const prepared_query *query,
				   std::size_t bytes) noexcept
{
	observe_time(now_ns);
	if (profile.cir_bytes_per_s != 0u) {
		if (query == nullptr) {
			std::terminate();
		}
		if (!query->key().valid()) {
			return policer_result::INVALID_INPUT;
		}
	}

	// Even an unlimited replacement policy must retire stale state retained from
	// an earlier bounded profile.
	maybe_gc_(now_ns, runtime);

	// Unlimited rate: allow all.
	if (KINETUM_UNLIKELY(profile.cir_bytes_per_s == 0)) {
		return policer_result::ALLOWED;
	}

	// O(1) cuckoo lookup -> slab dereference (zero heap allocation)
	uint32_t *idx_ptr = map_.find(*query);

	bucket *b;

	if (KINETUM_LIKELY(idx_ptr != nullptr)) {
		// Existing flow: direct slab access
		b = &slab_[*idx_ptr];
	} else {
		// New flow: acquire one fixed slab index (fail-closed on exhaustion).
		if (KINETUM_UNLIKELY(free_indices_.available() == 0u)) {
			return policer_result::FLOW_CAPACITY;
		}

		uint32_t idx = 0u;
		if (!free_indices_.try_acquire(idx)) {
			std::terminate();
		}
		bucket *const acquired = &slab_[idx];
		if (acquired->occupied) {
			std::terminate();
		}

		if (KINETUM_UNLIKELY(!map_.insert(query->key(), idx))) {
			// Cuckoo table full after max displacement - rollback
			free_indices_.release(idx);
			return policer_result::FLOW_CAPACITY;
		}

		b = acquired;
		b->credit.reset(profile.burst_bytes);
		b->last_ns = now_ns;
		keys_[idx] = query->key();
		b->occupied = true;
	}

	// The active profile governs this observation. Shared arithmetic caps retained
	// credit before refill, including when configuration lowers the burst limit.
	const uint64_t elapsed_ns = now_ns - b->last_ns;
	b->last_ns = now_ns;
	static_assert(sizeof(std::size_t) <= sizeof(uint64_t));
	return b->credit.consume(elapsed_ns, profile.cir_bytes_per_s, profile.burst_bytes,
				 static_cast<uint64_t>(bytes)) ?
		       policer_result::ALLOWED :
		       policer_result::RATE_LIMIT;
}

}  // namespace kinetum::modules::qos
