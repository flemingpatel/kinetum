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
 * The complete record occupies two cache lines. Operation tables are immutable after startup. Packet processing uses
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

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/prefetch.hpp>

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
 * @brief Match one record against the already admitted storage expectation.
 * @param record Live candidate record, or null.
 * @param operations Immutable materialized operation table, or null when unscheduled.
 * @param expected_domain Exact compiled domain selected by the caller.
 * @param runtime_generation Exact admitted provider generation.
 * @return True only when every record identity and intrinsic length/capability fact agrees.
 */
[[nodiscard]] KINETUM_ALWAYS_INLINE bool
packet_record_matches_storage(const packet_record *record, const packet_storage_domain_operations *operations,
			      uint32_t expected_domain, uint64_t runtime_generation) noexcept
{
	if (record == nullptr || operations == nullptr) {
		return false;
	}
	const auto &storage = record->storage;
	return storage.operations == operations && storage.generation == runtime_generation &&
	       storage.generation == operations->generation && storage.domain_index == expected_domain &&
	       storage.domain_index == operations->domain_index && storage.length != 0 &&
	       storage.length <= operations->maximum_packet_length && storage.segment_count != 0 &&
	       storage.capabilities == operations->capabilities &&
	       (storage.capabilities & ~packet_storage_capabilities::KNOWN_MASK) == 0;
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
 * @brief Prefetch the complete live record without reading a payload address.
 *
 * @param record Nonnull record whose lifetime is retained by the current ownership prefix.
 */
KINETUM_ALWAYS_INLINE void packet_prefetch_record(const packet_record *record) noexcept
{
	KINETUM_PREFETCH_L1(record);
	KINETUM_PREFETCH_L1(&record->metadata.src_ipv4);
}

/**
 * @brief Prefetch the first payload line after exact CPU-access admission.
 * @param record Live record already accepted by packet_record_has_current_cpu_shape().
 */
KINETUM_ALWAYS_INLINE void packet_prefetch_payload(const packet_record &record) noexcept
{
	KINETUM_PREFETCH_L1(record.storage.data);
}

}  // namespace kinetum::dp
