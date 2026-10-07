// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet.hpp
 * @brief Exact provider-neutral packet record and packet operation contracts.
 * @author Fleming Patel
 *
 * Every packet-path owner carries exactly one packet_record pointer. Native
 * provider handles remain opaque inside packet_storage_descriptor; core
 * routing, modules, boundaries, and epoch logic never include or branch on a
 * provider type.
 *
 * The record separates three roles deliberately:
 *
 * - packet_rx_burst_operations admits records from an I/O driver;
 * - packet_tx_burst_operations transfers records to an I/O driver; and
 * - packet_storage_domain_operations clones, originates, and retires storage.
 *
 * The current DPDK implementation may implement all three roles, but the
 * contracts remain distinct: an I/O driver and a storage domain need not share
 * one implementation object.
 *
 * @par Performance
 * The metadata occupies two cache lines and the storage descriptor one cache
 * line. Operation tables are immutable after startup. Packet processing uses
 * no allocation, shared ownership, RTTI, virtual dispatch, strings, or native
 * provider headers.
 *
 * @par Thread Safety
 * One owner worker mutates a record at a time. Operation tables are immutable
 * after materialization and may be shared. Each operation documents whether
 * its provider state admits concurrent owners.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include <kinetum/algo/platform.hpp>

#include "src/provider/provider_component_abi.h"

namespace kinetum::dp
{

inline constexpr std::size_t PACKET_PRIVATE_SIZE = KINETUM_PACKET_PRIVATE_SIZE;	 ///< Exact metadata bytes.
inline constexpr std::size_t PACKET_RECORD_SIZE = KINETUM_PACKET_RECORD_SIZE;	 ///< Exact complete record bytes.
inline constexpr uint16_t INVALID_STAGE_ID = KINETUM_INVALID_STAGE_ID;		 ///< Invalid compact stage identity.
inline constexpr uint16_t INVALID_PORT = KINETUM_INVALID_PORT;			 ///< Invalid logical port identity.
inline constexpr uint16_t INVALID_STORAGE_DOMAIN =
	KINETUM_INVALID_STORAGE_DOMAIN;	 ///< Invalid storage-domain identity.

/** Provider ABI metadata shared with the worker and module adapters. */
using packet_private = ::kinetum_packet_private;
/** Borrowed payload span copied when an active stage originates a packet. */
using packet_origin_view = ::kinetum_packet_origin_view;
/** Immutable callbacks through which one storage domain owns its records. */
using packet_storage_domain_operations = ::kinetum_packet_storage_domain_operations;
/** Storage identity and byte-access facts retained by each packet record. */
using packet_storage_descriptor = ::kinetum_packet_storage_descriptor;
/** Provider-neutral owned record combining metadata and storage identity. */
using packet_record = ::kinetum_packet_record;
/** @brief Provider-neutral RX ownership-transfer and rejection result. */
using packet_rx_burst_result = ::kinetum_packet_rx_burst_result;
/** Queue-bound receive callbacks transferring records into worker ownership. */
using packet_rx_burst_operations = ::kinetum_packet_rx_burst_operations;
/** Queue-bound transmit callbacks accepting records from worker ownership. */
using packet_tx_burst_operations = ::kinetum_packet_tx_burst_operations;

namespace packet_platform_flags
{
inline constexpr uint32_t L3_IPV4 = KINETUM_PACKET_PLATFORM_L3_IPV4;	///< Parser proved an IPv4 header.
inline constexpr uint32_t L4_TCP = KINETUM_PACKET_PLATFORM_L4_TCP;	///< IPv4 protocol field identifies TCP.
inline constexpr uint32_t L4_UDP = KINETUM_PACKET_PLATFORM_L4_UDP;	///< IPv4 protocol field identifies UDP.
inline constexpr uint32_t FRAGMENT = KINETUM_PACKET_PLATFORM_FRAGMENT;	///< IPv4 fragmentation is present.
/** Exact set of parser-owned packet facts currently materialized. */
inline constexpr uint32_t PARSED_MASK = L3_IPV4 | L4_TCP | L4_UDP | FRAGMENT;
}  // namespace packet_platform_flags

/**
 * @brief Validate relationships among current parser facts and IP protocol.
 *
 * This check cannot prove byte/metadata coherence after foreign code mutates a
 * packet, but it prevents internally contradictory metadata from being
 * published as platform truth. TCP and UDP are exclusive, each L4 fact agrees
 * with the protocol number in both directions, and L4/fragment facts require
 * IPv4. An unparsed packet carries no protocol fact.
 *
 * @param flags Candidate packet_platform_flags mask.
 * @param protocol Candidate IP protocol number.
 * @return true only for one representable current parser-fact combination.
 */
[[nodiscard]] inline constexpr bool packet_platform_facts_are_coherent(uint32_t flags, uint8_t protocol) noexcept
{
	if ((flags & ~packet_platform_flags::PARSED_MASK) != 0) {
		return false;
	}
	const bool ipv4 = (flags & packet_platform_flags::L3_IPV4) != 0;
	const bool tcp = (flags & packet_platform_flags::L4_TCP) != 0;
	const bool udp = (flags & packet_platform_flags::L4_UDP) != 0;
	const bool fragment = (flags & packet_platform_flags::FRAGMENT) != 0;
	if (!ipv4) {
		return !tcp && !udp && !fragment && protocol == 0;
	}
	if (tcp && udp) {
		return false;
	}
	return tcp == (protocol == 6) && udp == (protocol == 17);
}

namespace packet_storage_capabilities
{
inline constexpr uint32_t CPU_CONTIGUOUS_READ =
	KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ;  ///< CPU-readable contiguous span.
inline constexpr uint32_t CPU_CONTIGUOUS_WRITE =
	KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE;			   ///< CPU-writable contiguous span.
inline constexpr uint32_t NIC_RX_DMA = KINETUM_PACKET_STORAGE_NIC_RX_DMA;  ///< Storage admits NIC RX DMA.
inline constexpr uint32_t NIC_TX_DMA = KINETUM_PACKET_STORAGE_NIC_TX_DMA;  ///< Storage admits NIC TX DMA.
inline constexpr uint32_t WRITABLE_CLONE =
	KINETUM_PACKET_STORAGE_WRITABLE_CLONE;	///< Deep writable clone is available.
/** Exact set of storage capability bits understood by this runtime. */
inline constexpr uint32_t KNOWN_MASK = CPU_CONTIGUOUS_READ | CPU_CONTIGUOUS_WRITE | NIC_RX_DMA | NIC_TX_DMA |
				       WRITABLE_CLONE;
/** Byte-access capabilities required before the current CPU execution core admits a record. */
inline constexpr uint32_t CURRENT_CPU_RECORD_REQUIRED = CPU_CONTIGUOUS_READ | CPU_CONTIGUOUS_WRITE;
}  // namespace packet_storage_capabilities

/**
 * @brief Reset metadata while preserving no prior packet authority.
 * @param metadata Exclusively owned metadata to clear and mark with invalid routing identities.
 */
inline void reset_packet_private(packet_private &metadata) noexcept
{
	std::memset(&metadata, 0, sizeof(metadata));
	metadata.ingress_port = INVALID_PORT;
	metadata.egress_port = INVALID_PORT;
	metadata.next_stage = INVALID_STAGE_ID;
	metadata.current_stage = INVALID_STAGE_ID;
	metadata.next_stage_instance = INVALID_STAGE_ID;
	metadata.current_stage_instance = INVALID_STAGE_ID;
	metadata.module_next_stage = INVALID_STAGE_ID;
}

/**
 * @brief Initialize a newly acquired record while preserving storage identity.
 * @param record Exclusively owned record whose metadata is reset; storage fields remain intact.
 */
inline void initialize_packet_record(packet_record &record) noexcept
{
	reset_packet_private(record.metadata);
}

/**
 * @param record Borrowed record, or nullptr.
 * @return Mutable storage byte pointer, or nullptr when the record or its data is absent.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE uint8_t *packet_data(packet_record *record) noexcept
{
	return record != nullptr ? record->storage.data : nullptr;
}

/**
 * @param record Borrowed record, or nullptr.
 * @return Immutable storage byte pointer, or nullptr when the record or its data is absent.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE const uint8_t *packet_data(const packet_record *record) noexcept
{
	return record != nullptr ? record->storage.data : nullptr;
}

/**
 * @brief Prove one record has the exact storage shape current CPU stages consume.
 *
 * Current parser and module mechanisms require one nonempty contiguous,
 * CPU-readable/writable record. Unknown capability bits are rejected rather
 * than interpreted as an implicit extension. Writable cloning is a separate
 * compiled fan-out requirement and is not charged to a linear packet path.
 *
 * @param record Candidate provider-neutral record.
 * @return true only when every current CPU-execution shape fact is present.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE bool packet_record_has_current_cpu_shape(const packet_record *record) noexcept
{
	if (record == nullptr) {
		return false;
	}
	const auto &storage = record->storage;
	return storage.data != nullptr && storage.length != 0 && storage.segment_count == 1 &&
	       storage.contiguous_length >= storage.length &&
	       (storage.capabilities & ~packet_storage_capabilities::KNOWN_MASK) == 0 &&
	       (storage.capabilities & packet_storage_capabilities::CURRENT_CPU_RECORD_REQUIRED) ==
		       packet_storage_capabilities::CURRENT_CPU_RECORD_REQUIRED;
}

/**
 * @brief Prefetch the record and first payload cache line for imminent use.
 *
 * @param record Non-null record already owned by the calling worker.
 * @pre record is non-null.
 */
KINETUM_ALWAYS_INLINE void packet_prefetch(const packet_record *record) noexcept
{
	__builtin_prefetch(record, 0, 3);
	if (record->storage.data != nullptr) {
		__builtin_prefetch(record->storage.data, 0, 3);
	}
}

static_assert(sizeof(packet_private) == PACKET_PRIVATE_SIZE, "packet_private must occupy exactly two cache lines");
static_assert(alignof(packet_private) == 64, "packet_private must be cache-line aligned");
static_assert(offsetof(packet_private, timestamp_ns) == 0, "packet timestamp offset changed");
static_assert(offsetof(packet_private, epoch) == 8, "packet epoch offset changed");
static_assert(offsetof(packet_private, user_meta) == 16, "packet user metadata offset changed");
static_assert(offsetof(packet_private, flow_hash) == 24, "packet flow-hash offset changed");
static_assert(offsetof(packet_private, platform_flags) == 28, "packet platform-flags offset changed");
static_assert(offsetof(packet_private, user_flags) == 32, "packet user-flags offset changed");
static_assert(offsetof(packet_private, ingress_port) == 36, "packet ingress-port offset changed");
static_assert(offsetof(packet_private, egress_port) == 38, "packet egress-port offset changed");
static_assert(offsetof(packet_private, next_stage) == 40, "packet next-stage offset changed");
static_assert(offsetof(packet_private, current_stage) == 42, "packet current-stage offset changed");
static_assert(offsetof(packet_private, next_stage_instance) == 44, "packet next-stage-instance offset changed");
static_assert(offsetof(packet_private, current_stage_instance) == 46, "packet current-stage-instance offset changed");
static_assert(offsetof(packet_private, module_next_stage) == 48, "packet module-next-stage offset changed");
static_assert(offsetof(packet_private, user_meta_valid) == 50, "packet user-metadata-presence offset changed");
static_assert(offsetof(packet_private, padding_hot) == 51, "packet hot-padding offset changed");
static_assert(offsetof(packet_private, src_ipv4) == 64, "packet source-IPv4 offset changed");
static_assert(offsetof(packet_private, dst_ipv4) == 68, "packet destination-IPv4 offset changed");
static_assert(offsetof(packet_private, src_port) == 72, "packet source-port offset changed");
static_assert(offsetof(packet_private, dst_port) == 74, "packet destination-port offset changed");
static_assert(offsetof(packet_private, eth_type) == 76, "packet Ethernet-type offset changed");
static_assert(offsetof(packet_private, ip_offset) == 78, "packet IP-offset field changed");
static_assert(offsetof(packet_private, l4_offset) == 80, "packet L4-offset field changed");
static_assert(offsetof(packet_private, ip_header_len) == 82, "packet IP-header-length offset changed");
static_assert(offsetof(packet_private, ip_total_len) == 84, "packet IP-total-length offset changed");
static_assert(offsetof(packet_private, l4_proto) == 86, "packet L4-protocol offset changed");
static_assert(offsetof(packet_private, dscp) == 87, "packet DSCP offset changed");
static_assert(offsetof(packet_private, padding_parsed) == 88, "packet parsed-padding offset changed");
static_assert(std::is_standard_layout_v<packet_private>, "packet_private must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_private>, "packet_private must remain trivially copyable");
static_assert(sizeof(packet_origin_view) == 16, "packet_origin_view ABI changed");
static_assert(offsetof(packet_origin_view, data) == 0, "packet origin data offset changed");
static_assert(offsetof(packet_origin_view, length) == 8, "packet origin length offset changed");
static_assert(offsetof(packet_origin_view, padding) == 12, "packet origin padding offset changed");
static_assert(std::is_standard_layout_v<packet_origin_view>, "packet_origin_view must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_origin_view>, "packet_origin_view must remain trivially copyable");
static_assert(sizeof(packet_storage_domain_operations) == 64, "storage operation table must be one cache line");
static_assert(alignof(packet_storage_domain_operations) == 64, "storage operation table alignment changed");
static_assert(offsetof(packet_storage_domain_operations, state) == 0, "storage state offset changed");
static_assert(offsetof(packet_storage_domain_operations, acquire_burst) == 8,
	      "storage acquire operation offset changed");
static_assert(offsetof(packet_storage_domain_operations, clone_writable) == 16,
	      "storage clone operation offset changed");
static_assert(offsetof(packet_storage_domain_operations, copy_origins_burst) == 24,
	      "storage origin-copy operation offset changed");
static_assert(offsetof(packet_storage_domain_operations, release_burst) == 32,
	      "storage release operation offset changed");
static_assert(offsetof(packet_storage_domain_operations, observe_statistics) == 40,
	      "storage observation operation offset changed");
static_assert(offsetof(packet_storage_domain_operations, generation) == 48, "storage generation offset changed");
static_assert(offsetof(packet_storage_domain_operations, domain_index) == 52, "storage domain-index offset changed");
static_assert(offsetof(packet_storage_domain_operations, maximum_packet_length) == 54,
	      "storage maximum-packet-length offset changed");
static_assert(offsetof(packet_storage_domain_operations, capabilities) == 56, "storage capabilities offset changed");
static_assert(offsetof(packet_storage_domain_operations, padding) == 60,
	      "storage operation-table padding offset changed");
static_assert(std::is_standard_layout_v<packet_storage_domain_operations>,
	      "storage operation table must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_storage_domain_operations>,
	      "storage operation table must remain trivially copyable");
static_assert(sizeof(packet_storage_descriptor) == 64, "storage descriptor must be one cache line");
static_assert(alignof(packet_storage_descriptor) == 64, "storage descriptor alignment changed");
static_assert(offsetof(packet_storage_descriptor, native_handle) == 0, "storage native-handle offset changed");
static_assert(offsetof(packet_storage_descriptor, data) == 8, "storage data offset changed");
static_assert(offsetof(packet_storage_descriptor, operations) == 16, "storage operations offset changed");
static_assert(offsetof(packet_storage_descriptor, length) == 24, "storage length offset changed");
static_assert(offsetof(packet_storage_descriptor, contiguous_length) == 28, "storage contiguous-length offset changed");
static_assert(offsetof(packet_storage_descriptor, generation) == 32, "storage descriptor generation offset changed");
static_assert(offsetof(packet_storage_descriptor, domain_index) == 36,
	      "storage descriptor domain-index offset changed");
static_assert(offsetof(packet_storage_descriptor, segment_count) == 38, "storage segment-count offset changed");
static_assert(offsetof(packet_storage_descriptor, capabilities) == 40,
	      "storage descriptor capabilities offset changed");
static_assert(offsetof(packet_storage_descriptor, padding) == 44, "storage descriptor padding offset changed");
static_assert(std::is_standard_layout_v<packet_storage_descriptor>, "storage descriptor must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_storage_descriptor>,
	      "storage descriptor must remain trivially copyable");
static_assert(sizeof(packet_record) == PACKET_RECORD_SIZE, "packet_record must occupy exactly three cache lines");
static_assert(alignof(packet_record) == 64, "packet_record must be cache-line aligned");
static_assert(offsetof(packet_record, metadata) == 0, "packet metadata must begin at record offset zero");
static_assert(offsetof(packet_record, storage) == PACKET_PRIVATE_SIZE,
	      "packet storage descriptor must begin after exact metadata");
static_assert(std::is_standard_layout_v<packet_record>, "packet_record must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_record>, "packet_record must remain trivially copyable");
static_assert(sizeof(packet_rx_burst_result) == 4, "RX result size changed");
static_assert(alignof(packet_rx_burst_result) == 2, "RX result alignment changed");
static_assert(offsetof(packet_rx_burst_result, transferred_count) == 0, "RX transferred-count offset changed");
static_assert(offsetof(packet_rx_burst_result, rejected_count) == 2, "RX rejected-count offset changed");
static_assert(std::is_standard_layout_v<packet_rx_burst_result>, "RX result must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_rx_burst_result>, "RX result must remain trivially copyable");
static_assert(sizeof(packet_rx_burst_operations) == 64, "RX operation table must be one cache line");
static_assert(alignof(packet_rx_burst_operations) == 64, "RX operation table alignment changed");
static_assert(offsetof(packet_rx_burst_operations, state) == 0, "RX state offset changed");
static_assert(offsetof(packet_rx_burst_operations, receive_burst) == 8, "RX burst operation offset changed");
static_assert(offsetof(packet_rx_burst_operations, maximum_burst) == 16, "RX maximum-burst offset changed");
static_assert(offsetof(packet_rx_burst_operations, logical_port) == 18, "RX logical-port offset changed");
static_assert(offsetof(packet_rx_burst_operations, padding) == 20, "RX operation-table padding offset changed");
static_assert(std::is_standard_layout_v<packet_rx_burst_operations>, "RX operation table must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_rx_burst_operations>,
	      "RX operation table must remain trivially copyable");
static_assert(sizeof(packet_tx_burst_operations) == 64, "TX operation table must be one cache line");
static_assert(alignof(packet_tx_burst_operations) == 64, "TX operation table alignment changed");
static_assert(offsetof(packet_tx_burst_operations, state) == 0, "TX state offset changed");
static_assert(offsetof(packet_tx_burst_operations, transmit_burst) == 8, "TX burst operation offset changed");
static_assert(offsetof(packet_tx_burst_operations, flush) == 16, "TX flush operation offset changed");
static_assert(offsetof(packet_tx_burst_operations, maybe_flush) == 24, "TX conditional-flush operation offset changed");
static_assert(offsetof(packet_tx_burst_operations, maximum_burst) == 32, "TX maximum-burst offset changed");
static_assert(offsetof(packet_tx_burst_operations, logical_port) == 34, "TX logical-port offset changed");
static_assert(offsetof(packet_tx_burst_operations, padding) == 36, "TX operation-table padding offset changed");
static_assert(std::is_standard_layout_v<packet_tx_burst_operations>, "TX operation table must retain standard layout");
static_assert(std::is_trivially_copyable_v<packet_tx_burst_operations>,
	      "TX operation table must remain trivially copyable");

}  // namespace kinetum::dp
