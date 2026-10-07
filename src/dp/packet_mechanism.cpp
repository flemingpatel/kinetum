// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file packet_mechanism.cpp
 * @brief Sole provider-neutral packet mechanism implementation.
 * @author Fleming Patel
 */

#include "src/dp/packet_mechanism.hpp"

#include <cstddef>
#include <cstring>
#include <limits>

#include "src/dp/io_contract.hpp"
#include "src/dp/net/ipv4.hpp"

namespace kinetum::dp
{
namespace
{

static_assert(packet_platform_flags::L3_IPV4 == KINETUM_PKT_F_L3_IPV4);
static_assert(packet_platform_flags::L4_TCP == KINETUM_PKT_F_L4_TCP);
static_assert(packet_platform_flags::L4_UDP == KINETUM_PKT_F_L4_UDP);
static_assert(packet_platform_flags::FRAGMENT == KINETUM_PKT_F_FRAGMENT);
static_assert(packet_platform_flags::PARSED_MASK == KINETUM_PKT_F_PLATFORM_MASK);

/**
 * @brief Derive the stable 32-bit flow hash from parsed tuple authority.
 *
 * @param metadata Current parsed packet metadata.
 * @return Deterministic hash of protocol, addresses, and ports.
 */
[[nodiscard]] uint32_t flow_hash32(const packet_private &metadata) noexcept
{
	uint64_t value = (static_cast<uint64_t>(metadata.l4_proto) << 56u) ^
			 (static_cast<uint64_t>(metadata.src_ipv4) << 24u) ^
			 (static_cast<uint64_t>(metadata.dst_ipv4) << 1u) ^
			 (static_cast<uint64_t>(metadata.src_port) << 16u) ^ static_cast<uint64_t>(metadata.dst_port);
	value += UINT64_C(0x9e3779b97f4a7c15);
	value = (value ^ (value >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
	value = (value ^ (value >> 27u)) * UINT64_C(0x94d049bb133111eb);
	return static_cast<uint32_t>((value ^ (value >> 31u)) & UINT32_MAX);
}

/**
 * @brief Invoke one exact passive or active-ingest packet callback.
 *
 * @tparam active true only for the scheduler-owned ACTIVE entry.
 * @param view Prevalidated owner-local executable view.
 * @param active_ctx Exact ACTIVE services; null in the passive instantiation.
 * @param batch Transient occupied SoA prefix.
 * @return Module disposition mask; an exception is a fatal C-ABI violation.
 */
template <bool active>
[[nodiscard]] KINETUM_ALWAYS_INLINE uint64_t invoke_module_packet(const module::module_executable_view &view,
								  kinetum_active_ctx *active_ctx,
								  kinetum_batch_t &batch) noexcept
{
	if constexpr (active) {
		if (view.mode != KINETUM_MODULE_ACTIVE || active_ctx == nullptr) {
			std::terminate();
		}
		return view.ingest != nullptr ? view.ingest(view.context, active_ctx, &batch) : 0u;
	} else {
		if (view.mode != KINETUM_MODULE_PASSIVE) {
			std::terminate();
		}
		return view.process(&batch);
	}
}

/**
 * @brief Project one exact record into an occupied SoA lane.
 * @param packet Exact provider-neutral packet authority.
 * @param index Occupied lane selected by the batch owner.
 * @param batch Worker-owned scratch whose lane is completely overwritten.
 */
KINETUM_ALWAYS_INLINE void project_record_to_batch(const packet_record &packet, uint16_t index,
						   kinetum_batch_t &batch) noexcept
{
	const auto &metadata = packet.metadata;
	batch.data[index] = packet.storage.data;
	batch.len[index] = packet.storage.length;
	batch.l3_off[index] = metadata.ip_offset;
	batch.l4_off[index] = metadata.l4_offset;
	batch.src_ip[index] = metadata.src_ipv4;
	batch.dst_ip[index] = metadata.dst_ipv4;
	batch.src_port[index] = metadata.src_port;
	batch.dst_port[index] = metadata.dst_port;
	batch.proto[index] = metadata.l4_proto;
	batch.dscp[index] = metadata.dscp;
	batch.platform_flags[index] = metadata.platform_flags;
	batch.user_flags[index] = metadata.user_flags;
	batch.flow_hash[index] = metadata.flow_hash;
	batch.input_port[index] = metadata.ingress_port;
	batch.output_port[index] = metadata.egress_port;
	batch.next_stage[index] = KINETUM_NEXT_STAGE_UNSET;
	batch.ts_ns[index] = metadata.timestamp_ns;
	batch.user_meta[index] = metadata.user_meta;
	batch.user_meta_valid[index] = metadata.user_meta_valid != 0 ? 1 : 0;
}

/**
 * @brief Prove the callback preserved every occupied lane's immutable authority.
 *
 * The callback may update bytes and documented metadata, but cannot replace
 * storage, resize records, rewrite provenance, or change the executable view.
 *
 * @param batch Batch returned by the foreign callback.
 * @param packets Exact input records, in the original occupied-lane order.
 * @param region_id Immutable owner-worker region.
 * @param view Executable view that supplied this callback.
 * @return true only when the header and complete occupied prefix remain valid.
 */
[[nodiscard]] bool validate_module_batch_after_callback(const kinetum_batch_t &batch,
							std::span<packet_record *const> packets, uint16_t region_id,
							const module::module_executable_view &view) noexcept
{
	if (batch.count != packets.size() || batch.region_id != region_id || batch.padding != 0u ||
	    batch.epoch != view.epoch || batch.epoch_config != view.packet_config || batch.ctx != view.context) {
		return false;
	}
	for (std::size_t index = 0u; index < packets.size(); ++index) {
		const auto &packet = *packets[index];
		const auto &metadata = packet.metadata;
		if (batch.data[index] != packet.storage.data || batch.len[index] != packet.storage.length ||
		    batch.input_port[index] != metadata.ingress_port || batch.ts_ns[index] != metadata.timestamp_ns ||
		    batch.l3_off[index] > batch.len[index] || batch.l4_off[index] > batch.len[index] ||
		    batch.dscp[index] > 63u ||
		    !packet_platform_facts_are_coherent(batch.platform_flags[index], batch.proto[index]) ||
		    batch.user_meta_valid[index] > 1u) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Publish one validated occupied lane's callback-mutable metadata.
 *
 * Storage, length, ingress, timestamp, region, epoch, configuration, and context
 * authority are never copied back from foreign memory.
 *
 * @param batch Completely validated callback output.
 * @param index Occupied lane associated with the exact record.
 * @param packet Sole record whose mutable metadata receives this lane.
 */
KINETUM_ALWAYS_INLINE void publish_batch_to_record(const kinetum_batch_t &batch, uint16_t index,
						   packet_record &packet) noexcept
{
	auto &metadata = packet.metadata;
	metadata.ip_offset = batch.l3_off[index];
	metadata.l4_offset = batch.l4_off[index];
	metadata.src_ipv4 = batch.src_ip[index];
	metadata.dst_ipv4 = batch.dst_ip[index];
	metadata.src_port = batch.src_port[index];
	metadata.dst_port = batch.dst_port[index];
	metadata.l4_proto = batch.proto[index];
	metadata.dscp = batch.dscp[index];
	metadata.platform_flags = batch.platform_flags[index];
	metadata.user_flags = batch.user_flags[index];
	metadata.flow_hash = batch.flow_hash[index];
	metadata.egress_port = batch.output_port[index];
	metadata.module_next_stage = batch.next_stage[index];
	metadata.user_meta = batch.user_meta[index];
	metadata.user_meta_valid = batch.user_meta_valid[index] != 0 ? 1 : 0;
}

/**
 * @brief Validate one exact ingress record.
 *
 * @param packet Sole mutable record owned by the caller.
 * @return FORWARDED_RX when the record satisfies fixed ingress admission;
 *         otherwise REJECTED.
 */
[[nodiscard]] packet_mechanism_outcome execute_rx(packet_record &packet) noexcept
{
	const uint16_t ingress = packet.metadata.ingress_port;
	// Materialization proves that an executable RX operation is enabled, has RX
	// direction, and stamps its compiled logical port. This surviving check is
	// only the final fixed-namespace proof before immutable ingress identity is
	// exposed through the module ABI; it is not a second packet-time admission
	// or native-link gate.
	if (KINETUM_UNLIKELY(static_cast<std::size_t>(ingress) >= MAX_LOGICAL_PORTS)) {
		return packet_mechanism_outcome::REJECTED;
	}
	return packet_mechanism_outcome::FORWARDED_RX;
}

/**
 * @brief Parse one contiguous Ethernet/IPv4 record into sole metadata.
 *
 * @param packet Sole mutable, shape-admitted packet record.
 * @return FORWARDED for one complete supported packet; otherwise REJECTED.
 */
[[nodiscard]] packet_mechanism_outcome execute_parse_ipv4(packet_record &packet) noexcept
{
	if (KINETUM_UNLIKELY(!packet_record_has_current_cpu_shape(&packet))) {
		return packet_mechanism_outcome::REJECTED;
	}
	const auto *data = packet.storage.data;
	const auto length = packet.storage.length;
	__builtin_prefetch(data, 0, 3);

	auto &metadata = packet.metadata;
	std::memset(&metadata.src_ipv4, 0, sizeof(packet_private) - offsetof(packet_private, src_ipv4));
	metadata.platform_flags &= ~packet_platform_flags::PARSED_MASK;

	const auto ethernet = net::parse_ethernet(data, length);
	metadata.eth_type = ethernet.eth_type;
	if (KINETUM_UNLIKELY(!ethernet.ok || ethernet.eth_type != 0x0800)) {
		return packet_mechanism_outcome::REJECTED;
	}

	const auto ipv4 = net::parse_ipv4(data, length, ethernet.l3_offset);
	if (KINETUM_UNLIKELY(!ipv4.ok)) {
		return packet_mechanism_outcome::REJECTED;
	}

	metadata.platform_flags |= packet_platform_flags::L3_IPV4;
	if (ipv4.proto == 6) {
		metadata.platform_flags |= packet_platform_flags::L4_TCP;
	} else if (ipv4.proto == 17) {
		metadata.platform_flags |= packet_platform_flags::L4_UDP;
	}
	if (ipv4.is_fragment) {
		metadata.platform_flags |= packet_platform_flags::FRAGMENT;
	}
	metadata.ip_offset = ipv4.ip_offset;
	metadata.l4_offset = ipv4.l4_offset;
	metadata.ip_header_len = ipv4.ip_header_len;
	metadata.ip_total_len = ipv4.ip_total_len;
	metadata.src_ipv4 = ipv4.src_ipv4;
	metadata.dst_ipv4 = ipv4.dst_ipv4;
	metadata.src_port = ipv4.src_port;
	metadata.dst_port = ipv4.dst_port;
	metadata.l4_proto = ipv4.proto;
	metadata.dscp = ipv4.dscp;
	metadata.flow_hash = flow_hash32(metadata);
	return packet_mechanism_outcome::FORWARDED;
}

/**
 * @brief Validate one exact egress disposition.
 *
 * @param packet Sole mutable record owned by the caller.
 * @return FORWARDED_TX when exact egress metadata is representable; otherwise
 *         REJECTED.
 */
[[nodiscard]] packet_mechanism_outcome execute_tx(packet_record &packet) noexcept
{
	const uint16_t egress = packet.metadata.egress_port;
	if (egress == KINETUM_PORT_DROP) {
		return packet_mechanism_outcome::REJECTED;
	}
	// Cold worker-I/O compilation proves every executable TX stage/direction and
	// builds the owner-local dense logical-port table. Packet execution only
	// proves representability here; the dispatcher performs the exact dense
	// lookup, and the selected provider reports native availability by its
	// accepted-prefix result.
	if (egress != KINETUM_PORT_UNSET && static_cast<std::size_t>(egress) >= MAX_LOGICAL_PORTS) {
		return packet_mechanism_outcome::REJECTED;
	}
	return packet_mechanism_outcome::FORWARDED_TX;
}

}  // namespace

packet_mechanism_outcome execute_packet_mechanism(packet_mechanism_kind kind, packet_record *packet) noexcept
{
	if (KINETUM_UNLIKELY(packet == nullptr)) {
		return packet_mechanism_outcome::REJECTED;
	}
	switch (kind) {
	case packet_mechanism_kind::RX:
		return execute_rx(*packet);
	case packet_mechanism_kind::PARSE_IPV4:
		return execute_parse_ipv4(*packet);
	case packet_mechanism_kind::TX:
		return execute_tx(*packet);
	}
	return packet_mechanism_outcome::REJECTED;
}

bool validate_active_origin_batch(const kinetum_emit_batch_t *batch, uint16_t maximum_packet_length,
				  std::size_t logical_stage_count) noexcept
{
	if (batch == nullptr || batch->count == 0u || batch->count > KINETUM_MAX_BURST || maximum_packet_length == 0u ||
	    logical_stage_count == 0u || logical_stage_count > UINT16_MAX) {
		return false;
	}
	for (uint16_t index = 0u; index < batch->count; ++index) {
		if (batch->data[index] == nullptr || batch->len[index] == 0u ||
		    batch->len[index] > maximum_packet_length || batch->l3_off[index] > batch->len[index] ||
		    batch->l4_off[index] > batch->len[index] || batch->dscp[index] > 63u ||
		    batch->user_meta_valid[index] > 1u ||
		    !packet_platform_facts_are_coherent(batch->platform_flags[index], batch->proto[index]) ||
		    (batch->next_stage[index] != KINETUM_NEXT_STAGE_UNSET &&
		     batch->next_stage[index] >= logical_stage_count)) {
			return false;
		}
	}
	return true;
}

namespace
{

/**
 * @brief Shared exact-view batch projection with compile-time callback mode.
 * @tparam active True only for scheduler-owned ACTIVE INGEST.
 * @param store Exact context-local executable-view authority.
 * @param stage_instance_index Exact executable stage-instance index.
 * @param region_id Sole-owner runtime region.
 * @param packets Borrowed occupied prefix of caller-owned records.
 * @param active_ctx Exact active services, or null in the passive instantiation.
 * @param scratch Owner-worker reusable ABI batch.
 * @return Sole forward mask; invalid input rejects before foreign effects.
 */
template <bool active>
[[nodiscard]] KINETUM_ALWAYS_INLINE uint64_t execute_module_batch_mechanism_impl(
	module::module_epoch_store &store, uint16_t stage_instance_index, int32_t region_id,
	std::span<packet_record *const> packets, kinetum_active_ctx *active_ctx, module_batch_scratch &scratch) noexcept
{
	if (KINETUM_UNLIKELY(packets.empty() || packets.size() > KINETUM_MAX_BURST || region_id < 0 ||
			     region_id > std::numeric_limits<uint16_t>::max())) {
		return 0u;
	}
	const auto &view = store.owner_executable_view();
	bool valid = true;
	for (const auto *packet : packets) {
		if (KINETUM_UNLIKELY(packet == nullptr || packet->metadata.epoch != view.epoch)) {
			store.record_epoch_mismatch(packet != nullptr ? packet->metadata.epoch : 0,
						    stage_instance_index, region_id);
			valid = false;
		} else if (KINETUM_UNLIKELY(!packet_record_has_current_cpu_shape(packet))) {
			valid = false;
		}
	}
	if (KINETUM_UNLIKELY(!valid)) {
		return 0u;
	}

	auto &batch = scratch.batch;
	const auto count = static_cast<uint16_t>(packets.size());
	for (uint16_t index = 0u; index < count; ++index) {
		project_record_to_batch(*packets[index], index, batch);
	}
	batch.count = count;
	batch.region_id = static_cast<uint16_t>(region_id);
	batch.padding = 0u;
	batch.epoch = view.epoch;
	batch.epoch_config = view.packet_config;
	batch.ctx = view.context;
	const uint64_t forward_mask = invoke_module_packet<active>(view, active_ctx, batch);
	if (KINETUM_UNLIKELY((forward_mask & ~KINETUM_FORWARD_MASK(count)) != 0u)) {
		// An out-of-prefix bit is a foreign ABI violation, not another disposition.
		std::terminate();
	}
	if (KINETUM_UNLIKELY(
		    !validate_module_batch_after_callback(batch, packets, static_cast<uint16_t>(region_id), view))) {
		// Validate the complete prefix before publishing any foreign metadata.
		// Storage, provenance, and executable identity cannot be reconstructed
		// after a callback replaces their authority.
		std::terminate();
	}
	for (uint16_t index = 0u; index < count; ++index) {
		publish_batch_to_record(batch, index, *packets[index]);
	}
	return forward_mask;
}

}  // namespace

uint64_t execute_module_batch_mechanism(module::module_epoch_store &store, uint16_t stage_instance_index,
					int32_t region_id, std::span<packet_record *const> packets,
					module_batch_scratch &scratch) noexcept
{
	return execute_module_batch_mechanism_impl<false>(store, stage_instance_index, region_id, packets, nullptr,
							  scratch);
}

uint64_t execute_active_module_batch_mechanism(module::module_epoch_store &store, uint16_t stage_instance_index,
					       int32_t region_id, std::span<packet_record *const> packets,
					       kinetum_active_ctx &active_ctx, module_batch_scratch &scratch) noexcept
{
	return execute_module_batch_mechanism_impl<true>(store, stage_instance_index, region_id, packets, &active_ctx,
							 scratch);
}

}  // namespace kinetum::dp
