// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file nat44_module.cpp
 * @brief SDK-based NAT44 module implementation.
 * @author Fleming Patel
 *
 * Hot-path shape:
 * - Uses KINETUM_COUNTER_ADD for plain owner-local counter updates
 * - Uses KINETUM_LIKELY/UNLIKELY for branch prediction hints
 * - Uses one preallocated context-local session table
 * - Processes bounded SoA batches with packet prefetching
 * - Selects exact context ownership independently of hardware RSS
 */

#include "nat44_module.hpp"

#include <algorithm>
#include <exception>
#include <new>

#include <kinetum/algo/net.hpp>	 // Canonical byte order functions

namespace kinetum::modules
{

namespace
{

using kinetum::algo::net::is_private_ip;
using kinetum::algo::net::read_be16;
using kinetum::algo::net::update_internet_checksum;
using kinetum::algo::net::write_be16;
using kinetum::algo::net::write_be32;

/** @brief Borrowed writable headers whose complete bounds have been proved. */
struct nat_packet_view {
	uint8_t *ip_header{nullptr};	     ///< Exact IPv4 header.
	uint8_t *transport_header{nullptr};  ///< Exact TCP or UDP header.
};

/**
 * @brief Rewrite one endpoint and adjust only the affected checksum words.
 * @param packet Borrowed validated packet headers.
 * @param outbound True selects source translation; false selects destination.
 * @param proto Exact TCP or UDP protocol.
 * @param address Translated host-order IPv4 value.
 * @param port Translated host-order transport port.
 */
void rewrite_nat_endpoint(nat_packet_view packet, bool outbound, uint8_t proto, uint32_t address,
			  uint16_t port) noexcept
{
	auto *address_bytes = packet.ip_header + (outbound ? 12u : 16u);
	auto *port_bytes = packet.transport_header + (outbound ? 0u : 2u);
	const uint16_t previous_high = read_be16(address_bytes);
	const uint16_t previous_low = read_be16(address_bytes + 2u);
	const uint16_t replacement_high = static_cast<uint16_t>(address >> 16u);
	const uint16_t replacement_low = static_cast<uint16_t>(address & UINT16_MAX);
	uint16_t ip_checksum = read_be16(packet.ip_header + 10u);
	ip_checksum = update_internet_checksum(ip_checksum, previous_high, replacement_high);
	ip_checksum = update_internet_checksum(ip_checksum, previous_low, replacement_low);
	write_be16(packet.ip_header + 10u, ip_checksum);

	auto *checksum_bytes = packet.transport_header + (proto == 6u ? 16u : 6u);
	uint16_t transport_checksum = read_be16(checksum_bytes);
	if (proto != 17u || transport_checksum != 0u) {
		transport_checksum = update_internet_checksum(transport_checksum, previous_high, replacement_high);
		transport_checksum = update_internet_checksum(transport_checksum, previous_low, replacement_low);
		transport_checksum = update_internet_checksum(transport_checksum, read_be16(port_bytes), port);
		if (proto == 17u && transport_checksum == 0u) {
			transport_checksum = UINT16_MAX;
		}
		write_be16(checksum_bytes, transport_checksum);
	}
	write_be32(address_bytes, address);
	write_be16(port_bytes, port);
}

/**
 * @brief Validate packet buffer bounds before NAT rewrites packet bytes.
 *
 * The parse stage should provide sane L3/L4 offsets, but NAT is the stage that
 * mutates packet memory. It must fail closed if metadata and buffer length do
 * not prove the IPv4 and TCP/UDP headers are present.
 *
 * @param batch Packet batch carrying data and parser metadata.
 * @param index Packet index within @p batch.
 * @param proto Validated IP protocol number: TCP (6) or UDP (17).
 * @param output Header pointers written only after complete bounds validation.
 * @return true when every output is valid for in-place rewrite; false on any
 *         null input, malformed length, or out-of-bounds metadata.
 */
[[nodiscard]] bool nat_packet_headers(const kinetum_batch_t *batch, uint16_t index, uint8_t proto,
				      nat_packet_view *output) noexcept
{
	if (batch == nullptr || output == nullptr) {
		return false;
	}

	uint8_t *pkt_data = static_cast<uint8_t *>(KINETUM_PKT_DATA(batch, index));
	const std::size_t pkt_len = KINETUM_PKT_LEN(batch, index);
	const std::size_t l3_off = KINETUM_PKT_L3_OFF(batch, index);
	const std::size_t l4_off = KINETUM_PKT_L4_OFF(batch, index);
	const std::size_t min_l4_len = (proto == 6) ? std::size_t{20} : std::size_t{8};

	if (pkt_data == nullptr || l3_off + 20u > pkt_len || l4_off + min_l4_len > pkt_len) {
		return false;
	}

	uint8_t *candidate_ip = pkt_data + l3_off;
	const uint8_t version = static_cast<uint8_t>(candidate_ip[0] >> 4);
	const uint8_t candidate_ip_len = static_cast<uint8_t>((candidate_ip[0] & 0x0F) * 4);
	const std::size_t ip_total_len = static_cast<std::size_t>(read_be16(candidate_ip + 2));
	if (version != 4 || candidate_ip_len < 20 || l3_off + candidate_ip_len > pkt_len ||
	    ip_total_len < candidate_ip_len || l3_off + ip_total_len > pkt_len || l4_off != l3_off + candidate_ip_len) {
		return false;
	}

	const std::size_t l4_relative_off = l4_off - l3_off;
	if (l4_relative_off + min_l4_len > ip_total_len) {
		return false;
	}

	const std::size_t remaining_l4_len = ip_total_len - l4_relative_off;
	if (proto == 17) {
		const std::size_t udp_len = static_cast<std::size_t>(read_be16(pkt_data + l4_off + 4));
		if (udp_len < min_l4_len || udp_len > remaining_l4_len) {
			return false;
		}
	} else {
		const uint8_t tcp_hdr_len = static_cast<uint8_t>(((pkt_data[l4_off + 12] >> 4) & 0x0F) * 4);
		if (tcp_hdr_len < min_l4_len || tcp_hdr_len > remaining_l4_len) {
			return false;
		}
	}
	*output = {candidate_ip, pkt_data + l4_off};
	return true;
}

}  // anonymous namespace

using namespace nat44;

namespace
{

/** @brief Own one immutable compiled NAT44 artifact and its packet view. */
struct nat44_prepared_artifact {
	/**
	 * @brief Bind all variable storage to the exact PREPARE arena.
	 * @param lifecycle Borrowed PREPARE context backing the artifact's epoch memory resource.
	 * @param owner Exact generation-fixed context partition.
	 */
	nat44_prepared_artifact(const kinetum_lifecycle_ctx *lifecycle, nat44::context_partition owner)
		: memory(lifecycle)
		, compiled(memory, owner)
	{
	}

	/** @brief PMR adapter whose lifetime covers every compiled member. */
	sdk::epoch_memory_resource memory;
	/** @brief Immutable compiled NAT44 policy. */
	nat44::nat_pools_compiled compiled;
	/** @brief Pointer-only hot-path view published by the platform. */
	nat44_packet_config packet;
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
 * @brief Convert a cumulative owner-local counter into a publication delta.
 *
 * @param current Current cumulative counter value.
 * @param previous Previous value, updated to @p current before return.
 * @return Increment since the prior publication.
 */
uint64_t counter_delta(uint64_t current, uint64_t &previous) noexcept
{
	if (current < previous) {
		std::terminate();
	}
	const uint64_t delta = current - previous;
	previous = current;
	return delta;
}

}  // namespace

nat44::context_partition nat44_module::read_partition_(const kinetum_lifecycle_ctx *lifecycle) noexcept
{
	kinetum_lifecycle_identity identity{};
	if (kinetum_lifecycle_get_identity(lifecycle, &identity) != KINETUM_OK) {
		std::terminate();
	}
	const nat44::context_partition owner{identity.module_context_ordinal, identity.module_context_count};
	if (!owner.valid()) {
		std::terminate();
	}
	return owner;
}

uint64_t nat44_module::select_contexts(const kinetum_context_selection_batch *batch,
				       const kinetum_context_selection_targets *targets,
				       uint32_t *selected_contexts) noexcept
{
	if (batch == nullptr || targets == nullptr || selected_contexts == nullptr || batch->count == 0u ||
	    batch->count > KINETUM_MAX_BURST || targets->context_count == 0u || targets->context_count > UINT16_MAX ||
	    targets->permitted_count == 0u || targets->permitted_count > targets->context_count ||
	    targets->permitted_ordinals == nullptr || targets->permitted_bitmap == nullptr) {
		return 0u;
	}
	uint64_t accepted = 0u;
	if (targets->context_count == 1u) {
		const uint32_t ordinal = targets->permitted_ordinals[0];
		if (!kinetum_context_is_permitted(targets, ordinal)) {
			return 0u;
		}
		std::fill_n(selected_contexts, batch->count, ordinal);
		return KINETUM_FORWARD_MASK(batch->count);
	}
	for (uint16_t index = 0u; index < batch->count; ++index) {
		const uint32_t flags = batch->platform_flags[index];
		const uint8_t protocol = batch->proto[index];
		const bool has_transport = (flags & KINETUM_PKT_F_L3_IPV4) != 0u &&
					   (flags & KINETUM_PKT_F_FRAGMENT) == 0u &&
					   (protocol == 6u || protocol == 17u);
		uint32_t ordinal;
		if (has_transport && !is_private_ip(batch->src_ip[index])) {
			ordinal = static_cast<uint32_t>(batch->dst_port[index]) % targets->context_count;
		} else {
			// Portless traffic follows stateless selection; process owns its pass/drop policy.
			const uint64_t addresses = (static_cast<uint64_t>(batch->src_ip[index]) << 32u) |
						   static_cast<uint64_t>(batch->dst_ip[index]);
			const uint32_t ports = has_transport ? (static_cast<uint32_t>(batch->src_port[index]) << 16u) |
								       batch->dst_port[index] :
							       0u;
			const uint64_t hash =
				kinetum::algo::splitmix64(kinetum::algo::splitmix64(addresses ^ protocol) ^ ports);
			ordinal = targets->permitted_ordinals[hash % targets->permitted_count];
		}
		if (!kinetum_context_is_permitted(targets, ordinal)) {
			continue;
		}
		selected_contexts[index] = ordinal;
		accepted |= UINT64_C(1) << index;
	}
	return accepted;
}

kinetum_error nat44_module::do_init(const kinetum_lifecycle_ctx *lifecycle) noexcept
{
	packets_translated_ = sdk::counter::create(lifecycle, "nat44.packets_translated");
	packets_dropped_ = sdk::counter::create(lifecycle, "nat44.packets_dropped");
	sessions_created_ = sdk::counter::create(lifecycle, "nat44.sessions_created");
	sessions_expired_ = sdk::counter::create(lifecycle, "nat44.sessions_expired");
	inbound_misses_ = sdk::counter::create(lifecycle, "nat44.inbound_misses");
	allocation_failures_ = sdk::counter::create(lifecycle, "nat44.allocation_failures");

	if (!packets_translated_ || !packets_dropped_ || !sessions_created_ || !sessions_expired_ || !inbound_misses_ ||
	    !allocation_failures_) {
		return KINETUM_ERR_LIMIT_EXCEEDED;
	}
	return KINETUM_OK;
}

void nat44_module::do_fini([[maybe_unused]] const kinetum_lifecycle_ctx *lifecycle) noexcept
{
}

kinetum_error nat44_module::do_prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
					      const void *config, std::size_t config_len,
					      kinetum_prepared_config *out_prepared) noexcept
{
	if (!lifecycle || epoch == 0 || !config || config_len == 0 || !out_prepared) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_prepared = {};
	kinetum_lifecycle_identity identity{};
	const auto identity_error = kinetum_lifecycle_get_identity(lifecycle, &identity);
	if (identity_error != KINETUM_OK) {
		return identity_error;
	}
	const nat44::context_partition owner{identity.module_context_ordinal, identity.module_context_count};
	if (!owner.valid()) {
		return KINETUM_ERR_INVALID_ARG;
	}
	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		return KINETUM_ERR_CANCELLED;
	}

	void *storage = nullptr;
	constexpr uint32_t ALLOCATION_FLAGS = alignof(nat44_prepared_artifact) >= KINETUM_CACHE_LINE ?
						      static_cast<uint32_t>(KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) :
						      uint32_t{0};
	const auto allocation_error = kinetum_lifecycle_allocate_epoch(lifecycle, sizeof(nat44_prepared_artifact),
								       alignof(nat44_prepared_artifact),
								       ALLOCATION_FLAGS, &storage);
	if (allocation_error != KINETUM_OK) {
		return allocation_error;
	}

	nat44_prepared_artifact *artifact = nullptr;
	try {
		artifact = new (storage) nat44_prepared_artifact(lifecycle, owner);
		const auto result = compile_nat_from_json(
			config, config_len, &artifact->memory, &artifact->compiled,
			config::cancellation_probe{.is_cancelled = lifecycle_cancelled, .context = lifecycle});
		if (result != config::compile_result::OK) {
			artifact->~nat44_prepared_artifact();
			return compile_error(result);
		}
	} catch (const std::bad_alloc &) {
		if (artifact != nullptr) {
			artifact->~nat44_prepared_artifact();
		}
		return KINETUM_ERR_NO_MEMORY;
	} catch (...) {
		if (artifact != nullptr) {
			artifact->~nat44_prepared_artifact();
		}
		return KINETUM_ERR_INTERNAL;
	}
	artifact->packet.pools = &artifact->compiled;
	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		artifact->~nat44_prepared_artifact();
		return KINETUM_ERR_CANCELLED;
	}
	artifact->memory.seal();
	out_prepared->owner_handle = artifact;
	out_prepared->packet_config = &artifact->packet;
	return KINETUM_OK;
}

void nat44_module::do_activate_config(uint64_t epoch, const kinetum_prepared_config *prepared) noexcept
{
	if (epoch == 0 || !prepared || !prepared->owner_handle) {
		std::terminate();
	}
	const auto *artifact = static_cast<const nat44_prepared_artifact *>(prepared->owner_handle);
	if (prepared->packet_config != &artifact->packet || artifact->compiled.partition != sessions_.partition()) {
		std::terminate();
	}
}

void nat44_module::do_retire_config([[maybe_unused]] const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
				    kinetum_prepared_config retired) noexcept
{
	if (!lifecycle || epoch == 0 || !retired.owner_handle) {
		std::terminate();
	}
	auto *artifact = static_cast<nat44_prepared_artifact *>(retired.owner_handle);
	if (retired.packet_config != &artifact->packet) {
		std::terminate();
	}
	artifact->~nat44_prepared_artifact();
}

uint64_t nat44_module::do_process(kinetum_batch_t *batch) noexcept
{
	// The compiled selector delivers each flow to its sole session-table owner.

	const uint16_t count = batch->count;
	if (KINETUM_UNLIKELY(count == 0)) {
		return 0;
	}
	uint64_t forward_mask = KINETUM_FORWARD_MASK(count);

	const auto *cfg = sdk::exact_config<nat44_packet_config>(batch);

	if (KINETUM_UNLIKELY(!cfg || !cfg->pools)) {
		KINETUM_COUNTER_ADD(packets_dropped_.native(), count);
		return 0;
	}

	const auto &pools = *cfg->pools;
	uint32_t local_translated = 0;
	uint32_t local_dropped = 0;

	nat44_table &sessions = sessions_;

	for (uint16_t i = 0; i < count; i++) {
		// Prefetch next SoA elements
		if (KINETUM_LIKELY(i + 2 < count)) {
			__builtin_prefetch(&batch->src_ip[i + 2], 0, 3);
			__builtin_prefetch(&batch->dst_ip[i + 2], 0, 3);
		}

		// Only process TCP/UDP IPv4 packets using SoA flags
		const uint32_t flags = KINETUM_PKT_PLATFORM_FLAGS(batch, i);
		const uint8_t proto = KINETUM_PKT_PROTO(batch, i);

		if ((flags & KINETUM_PKT_F_L3_IPV4) == 0 || (proto != 6 && proto != 17)) {
			// Non-NAT-able packet: forward as-is by retaining its mask bit.
			continue;
		}

		// Skip fragments (NAT requires L4 ports)
		if (flags & KINETUM_PKT_F_FRAGMENT) {
			KINETUM_DROP(forward_mask, i);
			local_dropped++;
			continue;
		}

		// Extract 5-tuple from SoA arrays
		const uint32_t src_ip = KINETUM_PKT_SRC_IP(batch, i);
		const uint32_t dst_ip = KINETUM_PKT_DST_IP(batch, i);
		const uint16_t src_port = KINETUM_PKT_SRC_PORT(batch, i);
		const uint16_t dst_port = KINETUM_PKT_DST_PORT(batch, i);

		// Determine direction based on source IP
		const bool outbound = is_private_ip(src_ip);

		nat_packet_view packet;
		if (KINETUM_UNLIKELY(!nat_packet_headers(batch, i, proto, &packet))) {
			KINETUM_DROP(forward_mask, i);
			local_dropped++;
			continue;
		}

		uint32_t new_ip = 0;
		uint16_t new_port = 0;

		// RX stamps the monotonic packet time once. Reusing that authority avoids
		// a clock read in module code and preserves arrival-time ordering.
		const uint64_t packet_time_ns = KINETUM_PKT_TS(batch, i);
		const bool translated = sessions.translate(packet_time_ns, pools, outbound, proto, src_ip, src_port,
							   dst_ip, dst_port, &new_ip, &new_port);

		if (KINETUM_LIKELY(translated)) {
			// Preserve metadata/wire coherence: downstream stages consume the SoA
			// projection, while transmission consumes the packet bytes.

			if (outbound) {
				batch->src_ip[i] = new_ip;
				batch->src_port[i] = new_port;
			} else {
				batch->dst_ip[i] = new_ip;
				batch->dst_port[i] = new_port;
			}
			rewrite_nat_endpoint(packet, outbound, proto, new_ip, new_port);

			// Retain the lane in the forward mask.
			local_translated++;
		} else {
			KINETUM_DROP(forward_mask, i);
			local_dropped++;
		}
	}

	// Update telemetry
	KINETUM_COUNTER_ADD(packets_translated_.native(), local_translated);
	KINETUM_COUNTER_ADD(packets_dropped_.native(), local_dropped);

	// Publish deltas from the same context-local session table.
	const auto stats = sessions.get_stats();
	auto &baseline = baseline_;
	KINETUM_COUNTER_ADD(sessions_created_.native(), counter_delta(stats.total_created, baseline.total_created));
	KINETUM_COUNTER_ADD(sessions_expired_.native(), counter_delta(stats.total_expired, baseline.total_expired));
	KINETUM_COUNTER_ADD(inbound_misses_.native(), counter_delta(stats.inbound_misses, baseline.inbound_misses));
	KINETUM_COUNTER_ADD(allocation_failures_.native(),
			    counter_delta(stats.allocation_failures, baseline.allocation_failures));

	return forward_mask;
}

kinetum_health_assessment nat44_module::do_health_check(uint64_t, const void *active_config) noexcept
{
	kinetum_health_assessment assessment{};
	assessment.health_score = 100;

	// Health executes on the owner worker against the same exact immutable
	// policy pointer used by packet execution.
	const auto *cfg_ptr = static_cast<const nat44_packet_config *>(active_config);
	if (!cfg_ptr || !cfg_ptr->pools || cfg_ptr->pools->pools.empty()) {
		assessment.health_score = 60;
		assessment.flags |= KINETUM_HEALTH_F_CONFIG_ISSUE;
		sdk::set_health_reason_literal(assessment, "No NAT pools - traffic dropped");
		return assessment;
	}

	// Check 2: High allocation failure ratio indicates pool exhaustion
	const uint64_t translated = packets_translated_.get();
	const uint64_t alloc_failures = allocation_failures_.get();
	const auto total = static_cast<unsigned __int128>(translated) + alloc_failures;

	if (total > 1000 && alloc_failures > 0) {
		const auto scaled_failures = static_cast<unsigned __int128>(alloc_failures) * 100u;
		if (scaled_failures > total * 10u) {
			// > 10% allocation failures - pool exhaustion
			assessment.health_score = std::min(assessment.health_score, static_cast<uint8_t>(50));
			assessment.flags |= KINETUM_HEALTH_F_CONFIG_ISSUE;
			sdk::set_health_reason_literal(assessment, "Alloc fail >10% - pool exhausted");
		} else if (scaled_failures > total) {
			// > 1% failures - worth noting
			assessment.health_score = std::min(assessment.health_score, static_cast<uint8_t>(80));
			sdk::set_health_reason_literal(assessment, "Alloc fail >1% - monitor pool");
		}
	}

	// Check 3: High drop ratio
	const uint64_t dropped = packets_dropped_.get();
	const auto total_pkts = static_cast<unsigned __int128>(translated) + dropped;
	if (total_pkts > 1000) {
		if (static_cast<unsigned __int128>(dropped) * 100u > total_pkts * 30u &&
		    assessment.health_score > 60u) {
			// A later, weaker condition must not detach the diagnostic
			// reason from the score and flags that made health worse.
			assessment.health_score = 60;
			sdk::set_health_reason_literal(assessment, "Drop >30% - check NAT config");
		}
	}

	return assessment;
}

/** @brief Export the sole NAT44 module registration entry. */
KINETUM_MODULE_REGISTER(nat44_module);

}  // namespace kinetum::modules
