// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file acl_module.cpp
 * @brief SDK-based ACL module implementation.
 * @author Fleming Patel
 *
 * Built-in platform policies use the same SDK and image contract as customer
 * modules, making this image an end-to-end conformance implementation.
 *
 * Hot-Path Optimizations:
 * - Uses KINETUM_COUNTER_ADD for cached owner-local counter updates
 * - Uses KINETUM_LIKELY/UNLIKELY for branch prediction hints
 * - Uses bounded dual-loop batching with packet prefetching
 * - Uses one context-local cache owned by the sole packet worker
 *
 * Configuration Flow:
 * 1. config_blob arrives as strict module-owned JSON
 * 2. compile_acl_from_json() validates into the exact PREPARE arena
 * 3. The platform owns the resulting exact tagged configuration slot
 * 4. process() consumes only batch.epoch_config
 *
 * @see docs/PLATFORM_ENGINEERING_GUIDE.md for optimization patterns
 */

#include "acl_module.hpp"

#include <cstring>  // std::memcpy for SIMD batch SoA population
#include <exception>
#include <new>

namespace kinetum::modules
{

using namespace acl;

namespace
{

/** @brief Own one immutable compiled ACL artifact and its packet view. */
struct acl_prepared_artifact {
	/**
	 * @brief Bind all variable storage to the exact PREPARE arena.
	 * @param lifecycle Borrowed PREPARE context backing the artifact's epoch memory resource.
	 */
	explicit acl_prepared_artifact(const kinetum_lifecycle_ctx *lifecycle)
		: memory(lifecycle)
		, compiled(memory)
	{
	}

	/** @brief PMR adapter whose lifetime covers every compiled member. */
	sdk::epoch_memory_resource memory;
	/** @brief Immutable compiled ACL policy. */
	acl::acl_compiled compiled;
	/** @brief Pointer-only hot-path view published by the platform. */
	acl_packet_config packet;
};

/**
 * @brief Adapt lifecycle cancellation to the strict JSON compiler probe.
 * @param context Borrowed lifecycle context supplied by the active PREPARE operation.
 * @return Current lifecycle cancellation state.
 */
[[nodiscard]] bool lifecycle_cancelled(const void *context) noexcept
{
	return kinetum_lifecycle_cancellation_requested(static_cast<const kinetum_lifecycle_ctx *>(context));
}

/**
 * @brief Map one strict compiler result to the exact module ABI error.
 * @param result Compiler success, invalid-input, or cancellation result.
 * @return Corresponding module error; unknown compiler values map to INTERNAL.
 */
[[nodiscard]] kinetum_error compile_error(config::compile_result result) noexcept
{
	switch (result) {
	case config::compile_result::OK:
		return KINETUM_OK;
	case config::compile_result::INVALID:
		return KINETUM_ERR_CONFIG_INVALID;
	case config::compile_result::CANCELLED:
		return KINETUM_ERR_CANCELLED;
	}
	return KINETUM_ERR_INTERNAL;
}

}  // namespace

kinetum_error acl_module::do_init(const kinetum_lifecycle_ctx *lifecycle) noexcept
{
	packets_evaluated_ = sdk::counter::create(lifecycle, "acl.packets_evaluated");
	packets_permitted_ = sdk::counter::create(lifecycle, "acl.packets_permitted");
	packets_denied_ = sdk::counter::create(lifecycle, "acl.packets_denied");
	cache_hits_ = sdk::counter::create(lifecycle, "acl.cache_hits");
	cache_misses_ = sdk::counter::create(lifecycle, "acl.cache_misses");

	if (!packets_evaluated_ || !packets_permitted_ || !packets_denied_ || !cache_hits_ || !cache_misses_) {
		return KINETUM_ERR_LIMIT_EXCEEDED;
	}
	return KINETUM_OK;
}

void acl_module::do_fini([[maybe_unused]] const kinetum_lifecycle_ctx *lifecycle) noexcept
{
}

kinetum_error acl_module::do_prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, const void *config,
					    std::size_t config_len, kinetum_prepared_config *out_prepared) noexcept
{
	if (!lifecycle || epoch == 0 || !config || config_len == 0 || !out_prepared) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_prepared = {};
	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		return KINETUM_ERR_CANCELLED;
	}

	void *storage = nullptr;
	constexpr uint32_t ALLOCATION_FLAGS = alignof(acl_prepared_artifact) >= KINETUM_CACHE_LINE ?
						      static_cast<uint32_t>(KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) :
						      uint32_t{0};
	const auto allocation_error = kinetum_lifecycle_allocate_epoch(
		lifecycle, sizeof(acl_prepared_artifact), alignof(acl_prepared_artifact), ALLOCATION_FLAGS, &storage);
	if (allocation_error != KINETUM_OK) {
		return allocation_error;
	}

	acl_prepared_artifact *artifact = nullptr;
	try {
		artifact = new (storage) acl_prepared_artifact(lifecycle);
		const auto result = compile_acl_from_json(
			config, config_len, &artifact->memory, &artifact->compiled,
			config::cancellation_probe{.is_cancelled = lifecycle_cancelled, .context = lifecycle});
		if (result != config::compile_result::OK) {
			artifact->~acl_prepared_artifact();
			return compile_error(result);
		}
	} catch (const std::bad_alloc &) {
		if (artifact != nullptr) {
			artifact->~acl_prepared_artifact();
		}
		return KINETUM_ERR_NO_MEMORY;
	} catch (...) {
		if (artifact != nullptr) {
			artifact->~acl_prepared_artifact();
		}
		return KINETUM_ERR_INTERNAL;
	}
	artifact->packet.acl = &artifact->compiled;

	const std::size_t rule_count = artifact->compiled.rules.size();
	if (rule_count <= 16) {
		artifact->packet.strategy = acl_eval_strategy::LINEAR;
	} else if (rule_count <= 256) {
		artifact->packet.strategy = acl_eval_strategy::HASH_CACHE;
	} else {
		artifact->packet.strategy = acl_eval_strategy::SIMD_BATCH;
	}

	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		artifact->~acl_prepared_artifact();
		return KINETUM_ERR_CANCELLED;
	}
	artifact->memory.seal();
	out_prepared->owner_handle = artifact;
	out_prepared->packet_config = &artifact->packet;
	return KINETUM_OK;
}

void acl_module::do_activate_config(uint64_t epoch, const kinetum_prepared_config *prepared) noexcept
{
	if (epoch == 0 || !prepared || !prepared->owner_handle) {
		std::terminate();
	}
	const auto *artifact = static_cast<const acl_prepared_artifact *>(prepared->owner_handle);
	if (prepared->packet_config != &artifact->packet) {
		std::terminate();
	}
}

void acl_module::do_retire_config([[maybe_unused]] const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
				  kinetum_prepared_config retired) noexcept
{
	if (!lifecycle || epoch == 0 || !retired.owner_handle) {
		std::terminate();
	}
	auto *artifact = static_cast<acl_prepared_artifact *>(retired.owner_handle);
	if (retired.packet_config != &artifact->packet) {
		std::terminate();
	}
	artifact->~acl_prepared_artifact();
}

uint64_t acl_module::do_process(kinetum_batch_t *batch) noexcept
{
	const uint16_t count = batch->count;

	// Fast path: early exit on empty batch
	if (KINETUM_UNLIKELY(count == 0)) {
		return 0;
	}
	uint64_t forward_mask = KINETUM_FORWARD_MASK(count);

	const auto *cfg = sdk::exact_config<acl_packet_config>(batch);

	// Fail-closed: deny all if no ACL configured
	if (KINETUM_UNLIKELY(!cfg || !cfg->acl)) {
		KINETUM_COUNTER_ADD(packets_evaluated_.native(), count);
		KINETUM_COUNTER_ADD(packets_denied_.native(), count);
		return 0;
	}

	const auto &acl_rules = *cfg->acl;

	// Batch-local accumulators reduce owner-local telemetry writes.
	uint32_t local_permitted = 0;
	uint32_t local_denied = 0;
	uint32_t local_cache_hits = 0;
	uint32_t local_cache_misses = 0;

	// Evaluate based on configured strategy
	switch (cfg->strategy) {
	case acl_eval_strategy::HASH_CACHE: {
		// Dual-loop prefetching overlaps the next lane's memory latency while
		// preserving one context-owned cache.
		acl::acl_cache &cache = cache_;
		uint16_t i = 0;

		// Main loop: process 2 packets per iteration (SoA access)
		while (i + 2 <= count) {
			// Prefetch next cache lines for SoA arrays (data-oriented prefetch)
			if (KINETUM_LIKELY(i + 4 < count)) {
				__builtin_prefetch(&batch->src_ip[i + 4], 0, 3);
				__builtin_prefetch(&batch->dst_ip[i + 4], 0, 3);
			}

			// Evaluate with cache using SoA accessor macros
			const auto action0 =
				eval_acl_cached(acl_rules, cache, batch->epoch, KINETUM_PKT_SRC_IP(batch, i),
						KINETUM_PKT_DST_IP(batch, i), KINETUM_PKT_PROTO(batch, i),
						KINETUM_PKT_SRC_PORT(batch, i), KINETUM_PKT_DST_PORT(batch, i));

			const auto action1 =
				eval_acl_cached(acl_rules, cache, batch->epoch, KINETUM_PKT_SRC_IP(batch, i + 1),
						KINETUM_PKT_DST_IP(batch, i + 1), KINETUM_PKT_PROTO(batch, i + 1),
						KINETUM_PKT_SRC_PORT(batch, i + 1), KINETUM_PKT_DST_PORT(batch, i + 1));

			if (KINETUM_LIKELY(action0 == acl_action::PERMIT)) {
				// Permit: retain this lane in the forward mask.
				local_permitted++;
			} else {
				KINETUM_DROP(forward_mask, i);
				local_denied++;
			}

			if (KINETUM_LIKELY(action1 == acl_action::PERMIT)) {
				local_permitted++;
			} else {
				KINETUM_DROP(forward_mask, i + 1);
				local_denied++;
			}

			i += 2;
		}

		// Tail: handle remaining packet
		for (; i < count; i++) {
			const auto action = eval_acl_cached(acl_rules, cache, batch->epoch,
							    KINETUM_PKT_SRC_IP(batch, i), KINETUM_PKT_DST_IP(batch, i),
							    KINETUM_PKT_PROTO(batch, i), KINETUM_PKT_SRC_PORT(batch, i),
							    KINETUM_PKT_DST_PORT(batch, i));

			if (KINETUM_LIKELY(action == acl_action::PERMIT)) {
				local_permitted++;
			} else {
				KINETUM_DROP(forward_mask, i);
				local_denied++;
			}
		}

		// Extract context-local cache deltas and reset for the next batch.
		// Without reset, cumulative stats are re-added each batch - quadratic inflation.
		const auto stats = cache.get_stats();
		local_cache_hits = static_cast<uint32_t>(stats.hits);
		local_cache_misses = static_cast<uint32_t>(stats.misses);
		cache.reset_stats();
		break;
	}

	case acl_eval_strategy::SIMD_BATCH: {
		// SIMD batch classification using algo-layer vectorized primitives.
		// Populates packet_batch_soa from kinetum_batch_t SoA arrays, then
		// calls classify_batch_acl() with precomputed simd_rules.
		kinetum::algo::packet_batch_soa soa_batch{.count = count};

		// Direct memcpy from kinetum_batch_t SoA arrays (both alignas(64), same layout)
		std::memcpy(soa_batch.src_ips.data(), batch->src_ip, count * sizeof(uint32_t));
		std::memcpy(soa_batch.dst_ips.data(), batch->dst_ip, count * sizeof(uint32_t));
		std::memcpy(soa_batch.src_ports.data(), batch->src_port, count * sizeof(uint16_t));
		std::memcpy(soa_batch.dst_ports.data(), batch->dst_port, count * sizeof(uint16_t));
		std::memcpy(soa_batch.protocols.data(), batch->proto, count * sizeof(uint8_t));

		// Classify entire batch against all rules in one vectorized pass
		alignas(64) uint8_t actions[kinetum::algo::MAX_BATCH_SIZE];
		kinetum::algo::classify_batch_acl(soa_batch, acl_rules.simd_rules.data(), acl_rules.simd_rules.size(),
						  actions, static_cast<uint8_t>(acl_rules.default_action));

		// Map SIMD actions to the sole per-lane forward mask.
		for (std::size_t i = 0; i < soa_batch.count; ++i) {
			const auto action = static_cast<acl_action>(actions[i]);
			if (KINETUM_LIKELY(action == acl_action::PERMIT)) {
				local_permitted++;
			} else {
				KINETUM_DROP(forward_mask, i);
				local_denied++;
			}
		}
		break;
	}

	case acl_eval_strategy::LINEAR: {
		// Evaluate canonical priority order independently for each lane.
		for (uint16_t i = 0; i < count; i++) {
			// Prefetch next SoA elements
			if (KINETUM_LIKELY(i + 2 < count)) {
				__builtin_prefetch(&batch->src_ip[i + 2], 0, 3);
			}

			const auto action = eval_acl_5tuple(acl_rules, KINETUM_PKT_SRC_IP(batch, i),
							    KINETUM_PKT_DST_IP(batch, i), KINETUM_PKT_PROTO(batch, i),
							    KINETUM_PKT_SRC_PORT(batch, i),
							    KINETUM_PKT_DST_PORT(batch, i));

			if (KINETUM_LIKELY(action == acl_action::PERMIT)) {
				local_permitted++;
			} else {
				KINETUM_DROP(forward_mask, i);
				local_denied++;
			}
		}
		break;
	}
	}

	// One plain owner-local update per counter and batch avoids callback dispatch
	// and metric-name lookup without introducing cross-worker cache contention.
	KINETUM_COUNTER_ADD(packets_evaluated_.native(), count);
	KINETUM_COUNTER_ADD(packets_permitted_.native(), local_permitted);
	KINETUM_COUNTER_ADD(packets_denied_.native(), local_denied);

	if (cfg->strategy == acl_eval_strategy::HASH_CACHE) {
		KINETUM_COUNTER_ADD(cache_hits_.native(), local_cache_hits);
		KINETUM_COUNTER_ADD(cache_misses_.native(), local_cache_misses);
	}

	return forward_mask;
}

// =============================================================================
// Owner-Worker Health Assessment
// =============================================================================

kinetum_health_assessment acl_module::do_health_check(uint64_t, const void *active_config) noexcept
{
	kinetum_health_assessment assessment{};
	assessment.health_score = 100;
	const auto *cfg = static_cast<const acl_packet_config *>(active_config);

	// Check 1: ACL configuration exists and contains an explicit rule set.
	if (!cfg || !cfg->acl) {
		assessment.health_score = 80;
		assessment.flags |= KINETUM_HEALTH_F_CONFIG_ISSUE;
		sdk::set_health_reason_literal(assessment, "ACL configuration unavailable");
	} else if (cfg->acl->rules.empty()) {
		assessment.health_score = 80;
		assessment.flags |= KINETUM_HEALTH_F_CONFIG_ISSUE;
		if (cfg->acl->default_action == acl_action::DENY) {
			sdk::set_health_reason_literal(assessment, "No ACL rules - default deny-all");
		} else {
			sdk::set_health_reason_literal(assessment, "No ACL rules - default permit-all");
		}
	}

	// Check 2: High deny ratio might indicate misconfiguration
	// Health runs on the owner worker and reads the same owner-local counters.
	const uint64_t evaluated = packets_evaluated_.get();
	const uint64_t denied = packets_denied_.get();

	if (evaluated > 1000) {	 // Only check after sufficient samples
		const double deny_ratio = static_cast<double>(denied) / static_cast<double>(evaluated);
		if (deny_ratio > 0.95) {
			// Almost all packets denied - likely config issue
			assessment.health_score = std::min(assessment.health_score, static_cast<uint8_t>(60));
			assessment.flags |= KINETUM_HEALTH_F_CONFIG_ISSUE;
			sdk::set_health_reason_literal(assessment, "Deny ratio > 95% - check rules");
		} else if (deny_ratio > 0.80) {
			// High deny ratio - worth noting
			assessment.health_score = std::min(assessment.health_score, static_cast<uint8_t>(75));
			sdk::set_health_reason_literal(assessment, "Deny ratio > 80% - review config");
		}
	}

	return assessment;
}

// Module registration exports the exact descriptor entry point consumed by
// canonical generation admission through dlopen/dlsym.
/** @brief Export the sole ACL module registration entry. */
KINETUM_MODULE_REGISTER(acl_module);

}  // namespace kinetum::modules
