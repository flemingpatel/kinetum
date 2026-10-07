// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dp_engine.cpp
 * @brief Provider-neutral owner-worker packet mechanism implementation.
 * @author Fleming Patel
 */

#include "src/dp/dp_engine.hpp"

#include <bit>
#include <exception>

namespace kinetum::dp
{

bool dp_engine::execute_stage(const kinetum::axiom::v1::Stage *stage, packet_record *packet)
{
	if (KINETUM_UNLIKELY(stage == nullptr || packet == nullptr)) {
		return false;
	}
	switch (stage->kind()) {
	case kinetum::axiom::v1::STAGE_KIND_RX:
		return account_outcome_(execute_packet_mechanism(packet_mechanism_kind::RX, packet));
	case kinetum::axiom::v1::STAGE_KIND_PARSE_IPV4:
		return account_outcome_(execute_packet_mechanism(packet_mechanism_kind::PARSE_IPV4, packet));
	case kinetum::axiom::v1::STAGE_KIND_TX:
		return account_outcome_(execute_packet_mechanism(packet_mechanism_kind::TX, packet));
	case kinetum::axiom::v1::STAGE_KIND_MODULE:
	case kinetum::axiom::v1::STAGE_KIND_UNSPECIFIED:
	case kinetum::axiom::v1::StageKind_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::axiom::v1::StageKind_INT_MAX_SENTINEL_DO_NOT_USE_:
		return account_outcome_(packet_mechanism_outcome::REJECTED);
	}
	return account_outcome_(packet_mechanism_outcome::REJECTED);
}

uint64_t dp_engine::execute_module_stage(module::module_epoch_store &store, uint16_t stage_instance_index,
					 int32_t region_id, std::span<packet_record *const> packets,
					 module_batch_scratch &scratch) noexcept
{
	const uint64_t forwarded =
		execute_module_batch_mechanism(store, stage_instance_index, region_id, packets, scratch);
	counters_.dropped_packets +=
		static_cast<uint64_t>(packets.size()) - static_cast<uint64_t>(std::popcount(forwarded));
	return forwarded;
}

bool dp_engine::account_outcome_(packet_mechanism_outcome outcome) noexcept
{
	switch (outcome) {
	case packet_mechanism_outcome::FORWARDED:
		return true;
	case packet_mechanism_outcome::FORWARDED_RX:
		++counters_.rx_packets;
		return true;
	case packet_mechanism_outcome::FORWARDED_TX:
		++counters_.tx_packets;
		return true;
	case packet_mechanism_outcome::REJECTED:
		++counters_.dropped_packets;
		return false;
	}
	std::terminate();
}

engine_stats dp_engine::stats() const noexcept
{
	return counters_;
}

}  // namespace kinetum::dp
