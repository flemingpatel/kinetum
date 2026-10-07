// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file qos_module.cpp
 * @brief SDK-based QoS policer module implementation.
 * @author Fleming Patel
 *
 * Hot-Path Optimizations:
 * - Uses KINETUM_COUNTER_ADD for O(1) counter updates
 * - Uses fixed-point arithmetic (Q20) for precision without FP overhead
 * - One preallocated context-local policer with sole-worker ownership
 * - Lazy token refill minimizes per-packet work
 * - Precomputed DSCP->profile array for O(1) lookup
 */

#include "qos_module.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <exception>
#include <new>
#include <string_view>

#include <kinetum/algo/net.hpp>

namespace kinetum::modules
{

using namespace qos;

namespace
{

/** @brief Own one immutable compiled QoS artifact and its packet view. */
struct qos_prepared_artifact {
	/**
	 * @brief Bind all variable storage to the exact PREPARE arena.
	 * @param lifecycle Borrowed PREPARE context backing the artifact's epoch memory resource.
	 */
	explicit qos_prepared_artifact(const kinetum_lifecycle_ctx *lifecycle)
		: memory(lifecycle)
		, compiled(memory)
	{
	}

	/** @brief PMR adapter whose lifetime covers every compiled member. */
	sdk::epoch_memory_resource memory;
	/** @brief Immutable compiled QoS policy. */
	qos_profiles_compiled compiled;
	/** @brief Pointer-only hot-path view published by the platform. */
	qos_packet_config packet;
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

/**
 * @brief Resolve one exact writable IPv4 header before policing for remark.
 * @param batch Exact owner-worker packet batch.
 * @param index Occupied packet lane.
 * @param[out] header Writable IPv4 header start.
 * @param[out] header_length Exact validated IPv4 header length.
 * @return true only when parser facts and packet bytes prove a complete header.
 */
[[nodiscard]] bool remarkable_ipv4_header(kinetum_batch_t *batch, uint16_t index, uint8_t **header,
					  uint8_t *header_length) noexcept
{
	if (batch == nullptr || header == nullptr || header_length == nullptr ||
	    (KINETUM_PKT_PLATFORM_FLAGS(batch, index) & KINETUM_PKT_F_L3_IPV4) == 0u) {
		return false;
	}
	auto *packet = static_cast<uint8_t *>(KINETUM_PKT_DATA(batch, index));
	const std::size_t packet_length = KINETUM_PKT_LEN(batch, index);
	const std::size_t l3_offset = KINETUM_PKT_L3_OFF(batch, index);
	if (packet == nullptr || l3_offset > packet_length || packet_length - l3_offset < 20u) {
		return false;
	}
	auto *candidate = packet + l3_offset;
	const uint8_t candidate_length = static_cast<uint8_t>((candidate[0] & 0x0fu) * 4u);
	const std::size_t total_length = kinetum::algo::net::read_be16(candidate + 2u);
	if ((candidate[0] >> 4u) != 4u || candidate_length < 20u || candidate_length > packet_length - l3_offset ||
	    total_length < candidate_length || total_length > packet_length - l3_offset) {
		return false;
	}
	*header = candidate;
	*header_length = candidate_length;
	return true;
}

}  // namespace

kinetum_error qos_module::do_init(const kinetum_lifecycle_ctx *lifecycle) noexcept
{
	packets_allowed_ = sdk::counter::create(lifecycle, "qos.packets_allowed");
	packets_dropped_ = sdk::counter::create(lifecycle, "qos.packets_dropped");
	bytes_allowed_ = sdk::counter::create(lifecycle, "qos.bytes_allowed");
	bytes_dropped_ = sdk::counter::create(lifecycle, "qos.bytes_dropped");
	active_flows_ = sdk::counter::create(lifecycle, "qos.active_flows");

	if (!packets_allowed_ || !packets_dropped_ || !bytes_allowed_ || !bytes_dropped_ || !active_flows_) {
		return KINETUM_ERR_LIMIT_EXCEEDED;
	}
	return KINETUM_OK;
}

void qos_module::do_fini([[maybe_unused]] const kinetum_lifecycle_ctx *lifecycle) noexcept
{
}

kinetum_error qos_module::do_prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, const void *config,
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
	constexpr uint32_t ALLOCATION_FLAGS = alignof(qos_prepared_artifact) >= KINETUM_CACHE_LINE ?
						      static_cast<uint32_t>(KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) :
						      uint32_t{0};
	const auto allocation_error = kinetum_lifecycle_allocate_epoch(
		lifecycle, sizeof(qos_prepared_artifact), alignof(qos_prepared_artifact), ALLOCATION_FLAGS, &storage);
	if (allocation_error != KINETUM_OK) {
		return allocation_error;
	}

	qos_prepared_artifact *artifact = nullptr;
	try {
		artifact = new (storage) qos_prepared_artifact(lifecycle);
		const auto result = compile_qos_from_json(
			config, config_len, &artifact->memory, &artifact->compiled,
			config::cancellation_probe{.is_cancelled = lifecycle_cancelled, .context = lifecycle});
		if (result != config::compile_result::OK) {
			artifact->~qos_prepared_artifact();
			return compile_error(result);
		}
	} catch (const std::bad_alloc &) {
		if (artifact != nullptr) {
			artifact->~qos_prepared_artifact();
		}
		return KINETUM_ERR_NO_MEMORY;
	} catch (...) {
		if (artifact != nullptr) {
			artifact->~qos_prepared_artifact();
		}
		return KINETUM_ERR_INTERNAL;
	}
	artifact->packet.profiles = &artifact->compiled;
	artifact->packet.default_profile = artifact->compiled.find_profile(
		std::string_view(artifact->compiled.default_profile.data(), artifact->compiled.default_profile.size()));
	if (artifact->packet.default_profile == nullptr) {
		artifact->~qos_prepared_artifact();
		return KINETUM_ERR_CONFIG_INVALID;
	}

	// Resolve the string-keyed policy once so packet execution performs only
	// fixed-array pointer selection.
	for (std::size_t dscp = 0; dscp < MAX_DSCP; ++dscp) {
		char dscp_profile_name[16]{};
		constexpr char PREFIX[] = "dscp_";
		constexpr std::size_t PREFIX_SIZE = sizeof(PREFIX) - 1u;
		std::memcpy(dscp_profile_name, PREFIX, PREFIX_SIZE);
		const auto conversion = std::to_chars(dscp_profile_name + PREFIX_SIZE,
						      dscp_profile_name + sizeof(dscp_profile_name), dscp);
		if (conversion.ec != std::errc{}) {
			artifact->~qos_prepared_artifact();
			return KINETUM_ERR_INTERNAL;
		}
		artifact->packet.dscp_profiles[dscp] = artifact->compiled.find_profile(std::string_view(
			dscp_profile_name, static_cast<std::size_t>(conversion.ptr - dscp_profile_name)));
	}

	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		artifact->~qos_prepared_artifact();
		return KINETUM_ERR_CANCELLED;
	}
	artifact->memory.seal();
	out_prepared->owner_handle = artifact;
	out_prepared->packet_config = &artifact->packet;
	return KINETUM_OK;
}

void qos_module::do_activate_config(uint64_t epoch, const kinetum_prepared_config *prepared) noexcept
{
	if (epoch == 0 || !prepared || !prepared->owner_handle) {
		std::terminate();
	}
	const auto *artifact = static_cast<const qos_prepared_artifact *>(prepared->owner_handle);
	if (prepared->packet_config != &artifact->packet) {
		std::terminate();
	}
}

void qos_module::do_retire_config([[maybe_unused]] const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
				  kinetum_prepared_config retired) noexcept
{
	if (!lifecycle || epoch == 0 || !retired.owner_handle) {
		std::terminate();
	}
	auto *artifact = static_cast<qos_prepared_artifact *>(retired.owner_handle);
	if (retired.packet_config != &artifact->packet) {
		std::terminate();
	}
	artifact->~qos_prepared_artifact();
}

uint64_t qos_module::do_process(kinetum_batch_t *batch) noexcept
{
	// One worker owns the context-local policer and its precomputed DSCP table.

	const uint16_t count = batch->count;
	if (KINETUM_UNLIKELY(count == 0)) {
		return 0;
	}
	uint64_t forward_mask = KINETUM_FORWARD_MASK(count);

	const auto *cfg_ptr = sdk::exact_config<qos_packet_config>(batch);

	if (KINETUM_UNLIKELY(!cfg_ptr || !cfg_ptr->profiles)) {
		uint64_t dropped_bytes = 0;
		for (uint16_t i = 0; i < count; i++) {
			dropped_bytes += KINETUM_PKT_LEN(batch, i);
			KINETUM_DROP(forward_mask, i);
		}
		KINETUM_COUNTER_ADD(packets_dropped_.native(), count);
		KINETUM_COUNTER_ADD(bytes_dropped_.native(), dropped_bytes);
		return 0;
	}
	const qos_packet_config &cfg = *cfg_ptr;

	const auto &profiles = *cfg.profiles;
	uint32_t local_allowed = 0;
	uint32_t local_dropped = 0;
	uint64_t local_bytes_allowed = 0;
	uint64_t local_bytes_dropped = 0;

	const qos_profile_compiled *default_profile = cfg.default_profile;
	if (KINETUM_UNLIKELY(default_profile == nullptr)) {
		uint64_t dropped_bytes = 0;
		for (uint16_t i = 0; i < count; i++) {
			dropped_bytes += KINETUM_PKT_LEN(batch, i);
			KINETUM_DROP(forward_mask, i);
		}
		KINETUM_COUNTER_ADD(packets_dropped_.native(), count);
		KINETUM_COUNTER_ADD(bytes_dropped_.native(), dropped_bytes);
		return 0;
	}

	qos_policer &policer = policer_;

	for (uint16_t i = 0; i < count; i++) {
		// Prefetch next SoA elements
		if (KINETUM_LIKELY(i + 2 < count)) {
			__builtin_prefetch(&batch->flow_hash[i + 2], 0, 3);
			__builtin_prefetch(&batch->dscp[i + 2], 0, 3);
		}

		// Use flow_hash as flow key (5-tuple hash computed by the shared parser).
		const uint32_t flow_key = KINETUM_PKT_HASH(batch, i);
		const std::size_t pkt_bytes = KINETUM_PKT_LEN(batch, i);
		const uint8_t dscp = KINETUM_PKT_DSCP(batch, i);

		// Determine which profile to use
		// O(1) DSCP lookup via precomputed array (no snprintf in hot path!)
		const qos_profile_compiled *profile = default_profile;
		if (dscp < MAX_DSCP && cfg.dscp_profiles[dscp] != nullptr) {
			profile = cfg.dscp_profiles[dscp];
		}
		uint8_t *remark_header = nullptr;
		uint8_t remark_header_length = 0u;
		if (profile->conform_dscp != 0u &&
		    !remarkable_ipv4_header(batch, i, &remark_header, &remark_header_length)) {
			KINETUM_DROP(forward_mask, i);
			local_dropped++;
			local_bytes_dropped += pkt_bytes;
			continue;
		}

		// RX owns monotonic packet time. The policer consumes that exact value
		// without issuing a clock read on the packet worker.
		const uint64_t packet_time_ns = KINETUM_PKT_TS(batch, i);
		const bool allowed = policer.allow(packet_time_ns, *profile, profiles.runtime, flow_key, pkt_bytes);

		if (KINETUM_LIKELY(allowed)) {
			// DSCP remarking for conforming packets (IPv4 only)
			if (KINETUM_UNLIKELY(remark_header != nullptr)) {
				const uint8_t new_dscp = profile->conform_dscp;
				batch->dscp[i] = new_dscp;
				const uint8_t ecn = remark_header[1] & 0x03u;
				remark_header[1] = static_cast<uint8_t>((new_dscp << 2u) | ecn);
				remark_header[10] = 0u;
				remark_header[11] = 0u;
				uint32_t sum = 0u;
				for (uint8_t j = 0u; j + 1u < remark_header_length; j += 2u) {
					sum += static_cast<uint32_t>((static_cast<uint16_t>(remark_header[j]) << 8u) |
								     remark_header[j + 1u]);
				}
				while ((sum >> 16u) != 0u) {
					sum = (sum & 0xffffu) + (sum >> 16u);
				}
				const uint16_t checksum = static_cast<uint16_t>(~sum);
				remark_header[10] = static_cast<uint8_t>(checksum >> 8u);
				remark_header[11] = static_cast<uint8_t>(checksum & 0xffu);
			}

			// Retain the lane in the forward mask.
			local_allowed++;
			local_bytes_allowed += pkt_bytes;
		} else {
			KINETUM_DROP(forward_mask, i);
			local_dropped++;
			local_bytes_dropped += pkt_bytes;
		}
	}

	// Update telemetry
	KINETUM_COUNTER_ADD(packets_allowed_.native(), local_allowed);
	KINETUM_COUNTER_ADD(packets_dropped_.native(), local_dropped);
	KINETUM_COUNTER_ADD(bytes_allowed_.native(), local_bytes_allowed);
	KINETUM_COUNTER_ADD(bytes_dropped_.native(), local_bytes_dropped);

	// Update active flows gauge
	KINETUM_COUNTER_SET(active_flows_.native(), policer.active_flows());

	return forward_mask;
}

kinetum_health_assessment qos_module::do_health_check(uint64_t, const void *active_config) noexcept
{
	kinetum_health_assessment assessment{};
	assessment.health_score = 100;

	// Health executes on the owner worker against the same exact immutable
	// policy pointer used by packet execution.
	const auto *cfg_ptr = static_cast<const qos_packet_config *>(active_config);
	if (!cfg_ptr || !cfg_ptr->profiles) {
		assessment.health_score = 70;
		assessment.flags |= KINETUM_HEALTH_F_CONFIG_ISSUE;
		sdk::set_health_reason_literal(assessment, "No QoS profiles configured");
		return assessment;
	}

	// Check 2: High drop ratio might indicate misconfiguration or overload
	const uint64_t allowed = packets_allowed_.get();
	const uint64_t dropped = packets_dropped_.get();
	const auto total = static_cast<unsigned __int128>(allowed) + dropped;

	if (total > 1000) {
		const auto scaled_drops = static_cast<unsigned __int128>(dropped) * 100u;
		if (scaled_drops > total * 50u) {
			// More than half dropped - severe overload or misconfiguration
			assessment.health_score = std::min(assessment.health_score, static_cast<uint8_t>(50));
			assessment.flags |= KINETUM_HEALTH_F_CONFIG_ISSUE;
			sdk::set_health_reason_literal(assessment, "Drop >50% - check rate limits");
		} else if (scaled_drops > total * 25u) {
			// Significant drops - worth noting
			assessment.health_score = std::min(assessment.health_score, static_cast<uint8_t>(75));
			sdk::set_health_reason_literal(assessment, "Drop >25% - review QoS config");
		}
	}

	return assessment;
}

/** @brief Export the sole QoS module registration entry. */
KINETUM_MODULE_REGISTER(qos_module);

}  // namespace kinetum::modules
