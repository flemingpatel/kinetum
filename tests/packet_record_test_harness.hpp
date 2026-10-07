// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file packet_record_test_harness.hpp
 * @brief Exact provider-neutral packet ownership for dataplane unit tests.
 * @author Fleming Patel
 *
 * Tests exercise the production fixed packet-storage domain and carry the same
 * packet_record pointer consumed by platform stages and modules. The helper
 * owns no alternate metadata representation and deliberately terminates if a
 * transferred record is not returned to its pool before fixture destruction.
 */

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "src/dp/fixed_packet_pool.hpp"

namespace kinetum::test
{

/** @brief RAII owner for one exact test packet and its bounded storage domain. */
class packet_record_test_owner final {
    public:
	/**
	 * @brief Construct one packet in a real fixed storage domain.
	 *
	 * @param bytes Initial packet bytes copied into the acquired record.
	 * @param epoch Exact initial packet epoch.
	 * @param record_capacity Pool credits available for writable fan-out clones.
	 */
	explicit packet_record_test_owner(std::vector<uint8_t> bytes, uint64_t epoch = 1, uint32_t record_capacity = 8)
	{
		if (bytes.size() > std::numeric_limits<uint16_t>::max() || record_capacity == 0) {
			error_ = "test packet shape exceeds fixed storage bounds";
			return;
		}
		const auto data_room_bytes =
			static_cast<uint32_t>(std::max<std::size_t>(bytes.size(), static_cast<std::size_t>(64)));
		auto pool_or = dp::fixed_packet_pool::create(dp::fixed_packet_pool_options{
			.record_count = record_capacity,
			.data_room_bytes = data_room_bytes,
			.headroom_bytes = 0,
			.alignment_bytes = alignof(dp::packet_record),
			.domain_index = 0,
			.generation = 1,
			.host_numa_node = std::nullopt,
		});
		if (!pool_or.is_ok()) {
			error_ = pool_or.error().to_string();
			return;
		}
		pool_ = std::move(pool_or).value();
		if (pool_->acquire_burst(&record_, 1) != 1 || record_ == nullptr) {
			error_ = "test packet storage did not return its reserved record";
			return;
		}
		if (!bytes.empty()) {
			std::memcpy(record_->storage.data, bytes.data(), bytes.size());
		}
		record_->storage.length = static_cast<uint32_t>(bytes.size());
		record_->storage.contiguous_length = static_cast<uint32_t>(bytes.size());
		record_->metadata.epoch = epoch;
	}

	/** @brief Disable copying because the fixture owns one linear packet token. */
	packet_record_test_owner(const packet_record_test_owner &) = delete;
	/** @brief Disable copy assignment because packet ownership cannot be duplicated. */
	packet_record_test_owner &operator=(const packet_record_test_owner &) = delete;
	/** @brief Disable moving so the pool-backed record address remains fixture-stable. */
	packet_record_test_owner(packet_record_test_owner &&) = delete;
	/** @brief Disable move assignment so fixture ownership cannot be replaced implicitly. */
	packet_record_test_owner &operator=(packet_record_test_owner &&) = delete;

	/** @return Borrowed mutable record, or nullptr after transfer or failed construction. */
	[[nodiscard]] dp::packet_record *get() noexcept
	{
		return record_;
	}

	/** @return Borrowed immutable record, or nullptr after transfer or failed construction. */
	[[nodiscard]] const dp::packet_record *get() const noexcept
	{
		return record_;
	}

	/** @return true while the fixture retains a successfully acquired record. */
	[[nodiscard]] bool valid() const noexcept
	{
		return record_ != nullptr;
	}

	/** @return Borrowed bounded construction diagnostic retained by the fixture. */
	[[nodiscard]] const std::string &error() const noexcept
	{
		return error_;
	}

	/** @return Borrowed mutable metadata; an absent fixture-owned record fails stop. */
	[[nodiscard]] dp::packet_private &metadata() noexcept
	{
		if (record_ == nullptr) {
			std::terminate();
		}
		return record_->metadata;
	}

	/** @return Borrowed mutable packet bytes, or nullptr when no record is retained. */
	[[nodiscard]] uint8_t *data() noexcept
	{
		return record_ != nullptr ? record_->storage.data : nullptr;
	}

	/** @return Retained record's packet length, or zero when no record is retained. */
	[[nodiscard]] uint32_t size() const noexcept
	{
		return record_ != nullptr ? record_->storage.length : 0;
	}

	/**
	 * @brief Transfer sole packet ownership to production code.
	 *
	 * The fixed pool remains alive so the production storage operation can
	 * retire the record. Fixture destruction proves no transferred credit is
	 * left outstanding.
	 *
	 * @return Exact record pointer, or nullptr after an earlier transfer.
	 */
	[[nodiscard]] dp::packet_record *take() noexcept
	{
		auto *record = record_;
		record_ = nullptr;
		return record;
	}

	/** @return Pool's approximate externally owned record count, or zero before pool creation. */
	[[nodiscard]] uint32_t outstanding() const noexcept
	{
		return pool_ != nullptr ? pool_->outstanding() : 0;
	}

	/** @brief Retire a still fixture-owned packet before destroying its pool. */
	~packet_record_test_owner()
	{
		if (record_ != nullptr) {
			const auto *operations = record_->storage.operations;
			if (operations == nullptr || operations->release_burst == nullptr) {
				std::terminate();
			}
			operations->release_burst(operations->state, &record_, 1);
			record_ = nullptr;
		}
		if (pool_ != nullptr && pool_->outstanding() != 0) {
			std::terminate();
		}
	}

    private:
	std::unique_ptr<dp::fixed_packet_pool> pool_;  ///< Exact bounded storage owner.
	dp::packet_record *record_{nullptr};	       ///< Sole fixture-owned packet token.
	std::string error_;			       ///< Bounded cold construction diagnostic.
};

}  // namespace kinetum::test
