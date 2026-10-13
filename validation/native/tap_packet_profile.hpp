// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file tap_packet_profile.hpp
 * @brief Shared native TAP packet layout and input-stream identity.
 * @author Fleming Patel
 */

#include <cstddef>
#include <cstdint>

namespace kinetum::validation::tap
{

inline constexpr uint8_t MAGIC[]{'K', 'I', 'N', 'E', 'T', 'U', 'M'};  ///< Exact payload discriminator.
inline constexpr std::size_t MAGIC_LEN = sizeof(MAGIC);		      ///< Discriminator bytes.
inline constexpr std::size_t HEADER_SIZE = 21;	///< Magic, packet ID, tag, and binary64 timestamp.
inline constexpr std::size_t ETH_HDR_LEN = 14;	///< Ethernet-II header bytes.
inline constexpr std::size_t IP_HDR_LEN = 20;	///< Option-free IPv4 header bytes.
inline constexpr std::size_t UDP_HDR_LEN = 8;	///< UDP header bytes.
inline constexpr uint32_t MAX_STREAMS = 64;	///< Maximum authored ingress population.

/**
 * @brief Recover one input's ordinal from the sender's successful-packet ID.
 * @param sequence Dense packet ID shared across all inputs.
 * @param stream_count Admitted nonzero input count, at most MAX_STREAMS.
 * @return Index in the sender's ordered interface list.
 *
 * IDs advance only after complete sends. Each input therefore owns one residue
 * class, including after a failed send; different inputs have no common FIFO.
 */
[[nodiscard]] constexpr uint32_t stream_index(uint32_t sequence, uint32_t stream_count) noexcept
{
	return sequence % stream_count;
}

}  // namespace kinetum::validation::tap
