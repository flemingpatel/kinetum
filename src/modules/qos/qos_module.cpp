// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file qos_module.cpp
 * @brief SDK-based QoS policer module implementation.
 * @author Fleming Patel
 *
 * Prepared profiles and copied query facts feed one context-local policer.
 * GC, credit mutation and remarking follow packet order; telemetry is
 * accumulated over the occupied batch prefix.
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
 * @brief Borrow one bounded IPv4 header for identity eligibility and remarking.
 */
struct ipv4_header_view {
	uint8_t *data{nullptr};	   ///< Borrowed header within the packet's backing.
	uint16_t total_length{0};  ///< Declared IPv4 extent, excluding Ethernet padding.
	uint8_t header_length{0};  ///< Header length derived from the on-wire IHL.
};

/**
 * @brief Validate the IPv4 bytes needed by classification and DSCP remarking.
 * @param batch Exact owner-worker packet batch.
 * @param index Occupied packet lane.
 * @param[out] header Borrowed validated header and declared extent.
 * @return true only when parser facts and packet bytes prove a complete header.
 */
[[nodiscard]] bool read_ipv4_header(const kinetum_batch_t &batch, uint16_t index, ipv4_header_view &header) noexcept
{
	if ((batch.platform_flags[index] & KINETUM_PKT_F_L3_IPV4) == 0u) {
		return false;
	}
	auto *packet = static_cast<uint8_t *>(batch.data[index]);
	const std::size_t packet_length = batch.len[index];
	const std::size_t l3_offset = batch.l3_off[index];
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
	header = {candidate, static_cast<uint16_t>(total_length), candidate_length};
	return true;
}

/**
 * @brief Classify present packet facts without using zero port values as absence.
 * @param batch Exact post-rewrite SoA lanes.
 * @param index Occupied packet lane.
 * @param header Validated on-wire IPv4 extent.
 * @param[out] key Semantic tuple or explicit address/protocol aggregate.
 * @return false when an unfragmented TCP/UDP packet lacks its port bytes.
 */
[[nodiscard]] bool make_flow_key(const kinetum_batch_t &batch, uint16_t index, const ipv4_header_view &header,
				 flow_key &key) noexcept
{
	const uint8_t protocol = batch.proto[index];
	const bool transport = (batch.platform_flags[index] & KINETUM_PKT_F_FRAGMENT) == 0u &&
			       (protocol == 6u || protocol == 17u);
	if (transport && header.total_length < header.header_length + 4u) {
		return false;
	}
	key = {
		.src_ip = batch.src_ip[index],
		.dst_ip = batch.dst_ip[index],
		.src_port = transport ? batch.src_port[index] : uint16_t{0},
		.dst_port = transport ? batch.dst_port[index] : uint16_t{0},
		.protocol = protocol,
		.kind = transport ? flow_kind::TRANSPORT : flow_kind::IP_AGGREGATE,
	};
	return true;
}

/**
 * @brief Distinguish absent policy from a broken immutable prepared artifact.
 * @param packet_config Exact configuration pointer supplied by the runtime.
 * @return Null for absent policy; a complete typed view otherwise.
 * @note A present view with missing prepared internals terminates.
 */
[[nodiscard]] const qos_packet_config *configured_policy(const void *packet_config) noexcept
{
	const auto *config = static_cast<const qos_packet_config *>(packet_config);
	if (config != nullptr && (config->profiles == nullptr || config->default_profile == nullptr)) {
		std::terminate();
	}
	return config;
}

/**
 * @brief Select the exact prepared DSCP profile, or its mandatory default.
 * @param config Completely validated prepared packet view.
 * @param dscp Current packet classification lane.
 * @return Borrowed profile for this callback only.
 */
[[nodiscard]] const qos_profile_compiled &select_profile(const qos_packet_config &config, uint8_t dscp) noexcept
{
	return *(dscp < MAX_DSCP && config.dscp_profiles[dscp] != nullptr ? config.dscp_profiles[dscp] :
									    config.default_profile);
}

}  // namespace

kinetum_error qos_module::do_init(const kinetum_lifecycle_ctx *lifecycle) noexcept
{
	packets_allowed_ = sdk::counter::create(lifecycle, "qos.packets_allowed");
	packets_dropped_ = sdk::counter::create(lifecycle, "qos.packets_dropped");
	bytes_allowed_ = sdk::counter::create(lifecycle, "qos.bytes_allowed");
	bytes_dropped_ = sdk::counter::create(lifecycle, "qos.bytes_dropped");
	active_flows_ = sdk::counter::create(lifecycle, "qos.active_flows");
	unconfigured_drops_ = sdk::counter::create(lifecycle, "qos.unconfigured_drops");
	rate_limit_drops_ = sdk::counter::create(lifecycle, "qos.rate_limit_drops");
	flow_capacity_drops_ = sdk::counter::create(lifecycle, "qos.flow_capacity_drops");
	invalid_input_drops_ = sdk::counter::create(lifecycle, "qos.invalid_input_drops");

	if (!packets_allowed_ || !packets_dropped_ || !bytes_allowed_ || !bytes_dropped_ || !active_flows_ ||
	    !unconfigured_drops_ || !rate_limit_drops_ || !flow_capacity_drops_ || !invalid_input_drops_) {
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
	policer_.observe_time(batch->now_ns);

	const auto *cfg_ptr = configured_policy(batch->epoch_config);

	if (KINETUM_UNLIKELY(cfg_ptr == nullptr)) {
		uint64_t dropped_bytes = 0;
		for (uint16_t i = 0; i < count; i++) {
			dropped_bytes += KINETUM_PKT_LEN(batch, i);
		}
		KINETUM_COUNTER_ADD(packets_dropped_.native(), count);
		KINETUM_COUNTER_ADD(bytes_dropped_.native(), dropped_bytes);
		KINETUM_COUNTER_ADD(unconfigured_drops_.native(), count);
		return 0;
	}
	const qos_packet_config &cfg = *cfg_ptr;

	const auto &profiles = *cfg.profiles;
	uint32_t local_allowed = 0;
	uint32_t local_rate_drops = 0;
	uint32_t local_capacity_drops = 0;
	uint32_t local_invalid_drops = 0;
	uint64_t local_bytes_allowed = 0;
	uint64_t local_bytes_dropped = 0;

	qos_policer &policer = policer_;

	// Prepare only immutable lookup facts; GC and mutations stay in packet order.
	for (uint16_t i = 0; i < count; ++i) {
		const auto &profile = select_profile(cfg, KINETUM_PKT_DSCP(batch, i));
		auto &facts = queries_[i];
		ipv4_header_view header;
		flow_key key;
		const bool bounded = profile.cir_bytes_per_s != 0u;
		facts.valid = !((bounded || profile.conform_dscp != 0u) && !read_ipv4_header(*batch, i, header)) &&
			      !(bounded && !make_flow_key(*batch, i, header, key));
		facts.header_length = header.header_length;
		if (facts.valid && bounded) {
			facts.query.emplace(policer.prepare(key));
		}
	}

	for (uint16_t i = 0; i < count; i++) {
		const std::size_t pkt_bytes = KINETUM_PKT_LEN(batch, i);
		const auto &profile = select_profile(cfg, KINETUM_PKT_DSCP(batch, i));
		const auto &facts = queries_[i];
		if (!facts.valid) {
			KINETUM_DROP(forward_mask, i);
			++local_invalid_drops;
			local_bytes_dropped += pkt_bytes;
			continue;
		}

		const auto *query = profile.cir_bytes_per_s != 0u ? &*facts.query : nullptr;
		const auto result = policer.police(batch->now_ns, profile, profiles.runtime, query, pkt_bytes);

		if (KINETUM_LIKELY(result == policer_result::ALLOWED)) {
			// DSCP remarking for conforming packets (IPv4 only)
			if (KINETUM_UNLIKELY(profile.conform_dscp != 0u)) {
				auto *remark_header = static_cast<uint8_t *>(batch->data[i]) + batch->l3_off[i];
				const uint8_t new_dscp = profile.conform_dscp;
				batch->dscp[i] = new_dscp;
				const uint8_t ecn = remark_header[1] & 0x03u;
				remark_header[1] = static_cast<uint8_t>((new_dscp << 2u) | ecn);
				remark_header[10] = 0u;
				remark_header[11] = 0u;
				algo::net::write_be16(remark_header + 10u,
						      algo::net::internet_checksum(remark_header, facts.header_length));
			}

			// Retain the lane in the forward mask.
			local_allowed++;
			local_bytes_allowed += pkt_bytes;
		} else {
			KINETUM_DROP(forward_mask, i);
			switch (result) {
			case policer_result::RATE_LIMIT:
				++local_rate_drops;
				break;
			case policer_result::FLOW_CAPACITY:
				++local_capacity_drops;
				break;
			case policer_result::INVALID_INPUT:
				++local_invalid_drops;
				break;
			case policer_result::ALLOWED:
				std::terminate();
			}
			local_bytes_dropped += pkt_bytes;
		}
	}

	// Update telemetry
	KINETUM_COUNTER_ADD(packets_allowed_.native(), local_allowed);
	KINETUM_COUNTER_ADD(packets_dropped_.native(), local_rate_drops + local_capacity_drops + local_invalid_drops);
	KINETUM_COUNTER_ADD(rate_limit_drops_.native(), local_rate_drops);
	KINETUM_COUNTER_ADD(flow_capacity_drops_.native(), local_capacity_drops);
	KINETUM_COUNTER_ADD(invalid_input_drops_.native(), local_invalid_drops);
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
	const auto *cfg_ptr = configured_policy(active_config);
	if (cfg_ptr == nullptr) {
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
