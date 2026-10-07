// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dpdk_packet_record.hpp
 * @brief Provider-private mapping between rte_mbuf and packet_record.
 * @author Fleming Patel
 *
 * This header is private to the DPDK provider implementation. Core packet,
 * engine, boundary, SDK, and runtime interfaces carry packet_record pointers
 * and never include native DPDK declarations.
 */

#include <cstddef>
#include <cstdint>
#include <new>

#include <rte_mbuf.h>

#include "src/common/status.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

static_assert(sizeof(packet_record) <= UINT16_MAX, "packet_record must fit DPDK's uint16_t private-area size argument");
inline constexpr uint16_t DPDK_PACKET_RECORD_PRIVATE_SIZE =
	static_cast<uint16_t>(sizeof(packet_record));  ///< Exact requested mbuf private-area bytes.

/**
 * @param private_area Candidate mbuf private-area address, or nullptr.
 * @return true only for a non-null address aligned for a packet_record.
 */
[[nodiscard]] inline bool dpdk_packet_record_private_area_is_aligned(const void *private_area) noexcept
{
	return private_area != nullptr &&
	       (reinterpret_cast<std::uintptr_t>(private_area) % alignof(packet_record)) == 0;
}

/**
 * @brief Validate one materialized mbuf private area for packet_record.
 *
 * DPDK guarantees only RTE_MBUF_PRIV_ALIGN for private bytes. The actual pool
 * must therefore prove both the requested size and Kinetum's stronger cache-
 * line alignment before any record lifetime begins.
 *
 * @param private_size Actual private-area bytes reported by the mempool.
 * @param private_area Address returned by rte_mbuf_to_priv() for a pool mbuf.
 * @return OK when packet_record placement is legal; FAILED_PRECONDITION with
 *         a distinct size, null-address, or alignment diagnostic otherwise.
 */
[[nodiscard]] inline kinetum::common::status validate_dpdk_packet_record_private_area(std::size_t private_size,
										      const void *private_area) noexcept
{
	using kinetum::common::status;
	using kinetum::common::status_code;

	if (private_size < sizeof(packet_record)) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("DPDK mempool private area is smaller than packet_record"));
	}
	if (private_area == nullptr) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("DPDK mempool returned a null packet_record private area"));
	}
	if (!dpdk_packet_record_private_area_is_aligned(private_area)) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text(
				      "DPDK mempool cannot provide cache-aligned packet_record private areas"));
	}
	return status::ok();
}

/**
 * @param mbuf Borrowed mbuf from a pool with an admitted packet-record private area.
 * @return Mutable record in the mbuf's private area, or nullptr for a null mbuf.
 */
[[nodiscard]] inline packet_record *dpdk_packet_record(rte_mbuf *mbuf) noexcept
{
	return mbuf != nullptr ? static_cast<packet_record *>(rte_mbuf_to_priv(mbuf)) : nullptr;
}

/**
 * @param mbuf Borrowed mbuf from a pool with an admitted packet-record private area.
 * @return Immutable record in the mbuf's private area, or nullptr for a null mbuf.
 */
[[nodiscard]] inline const packet_record *dpdk_packet_record(const rte_mbuf *mbuf) noexcept
{
	if (mbuf == nullptr) {
		return nullptr;
	}

	// rte_mbuf_to_priv() only derives an address but has no const-qualified
	// overload in supported DPDK releases. Cast solely for that accessor; this
	// overload performs no mutation and returns an immutable record.
	return static_cast<const packet_record *>(rte_mbuf_to_priv(const_cast<rte_mbuf *>(mbuf)));
}

/**
 * @brief Begin a fresh packet_record lifetime over one received/allocated mbuf.
 *
 * @param mbuf Exact native owner.
 * @param operations Immutable storage-domain operations.
 * @return Initialized record, or nullptr for a null mbuf.
 */
[[nodiscard]] inline packet_record *
initialize_dpdk_packet_record(rte_mbuf *mbuf, const packet_storage_domain_operations &operations) noexcept
{
	if (mbuf == nullptr) {
		return nullptr;
	}
	auto *record = new (rte_mbuf_to_priv(mbuf)) packet_record{};
	initialize_packet_record(*record);
	record->storage.native_handle = mbuf;
	record->storage.data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	record->storage.operations = &operations;
	record->storage.length = rte_pktmbuf_pkt_len(mbuf);
	record->storage.contiguous_length = rte_pktmbuf_data_len(mbuf);
	record->storage.generation = operations.generation;
	record->storage.domain_index = operations.domain_index;
	record->storage.segment_count = mbuf->nb_segs;
	record->storage.capabilities = operations.capabilities;
	return record;
}

/**
 * @param mbuf Borrowed native packet descriptor.
 * @return true when one unchained segment holds the complete native packet length.
 */
[[nodiscard]] inline bool dpdk_packet_is_contiguous(const rte_mbuf &mbuf) noexcept
{
	return mbuf.nb_segs == 1 && mbuf.next == nullptr && rte_pktmbuf_pkt_len(&mbuf) == rte_pktmbuf_data_len(&mbuf);
}

/**
 * @brief Prove one record is the exact current view of its native DPDK owner.
 *
 * @param record Provider-neutral record to validate.
 * @param operations Exact storage-domain table expected by the caller.
 * @return true when native identity, storage facts, and domain authority agree.
 */
[[nodiscard]] inline bool
dpdk_packet_record_matches_storage(const packet_record *record,
				   const packet_storage_domain_operations &operations) noexcept
{
	if (record == nullptr || record->storage.operations != &operations ||
	    record->storage.native_handle == nullptr || record->storage.generation != operations.generation ||
	    record->storage.domain_index != operations.domain_index ||
	    record->storage.capabilities != operations.capabilities) {
		return false;
	}
	auto *mbuf = static_cast<rte_mbuf *>(record->storage.native_handle);
	return dpdk_packet_record(mbuf) == record && dpdk_packet_is_contiguous(*mbuf) &&
	       record->storage.data == rte_pktmbuf_mtod(mbuf, uint8_t *) &&
	       record->storage.length == rte_pktmbuf_pkt_len(mbuf) &&
	       record->storage.contiguous_length == rte_pktmbuf_data_len(mbuf) &&
	       record->storage.segment_count == mbuf->nb_segs;
}

static_assert(sizeof(packet_record) == DPDK_PACKET_RECORD_PRIVATE_SIZE,
	      "DPDK private-area size argument must represent the complete packet_record");
static_assert((alignof(packet_record) % RTE_MBUF_PRIV_ALIGN) == 0,
	      "packet_record alignment must be compatible with DPDK private-area alignment");

}  // namespace kinetum::dp
