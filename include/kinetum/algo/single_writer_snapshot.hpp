// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file single_writer_snapshot.hpp
 * @brief Coherent bounded publication from one owner to foreign observers.
 * @author Fleming Patel
 *
 * `single_writer_snapshot` lets one owner publish a small fixed set of integer
 * fields without exposing unrelated owner-local state to foreign readers.
 * Payload fields remain atomic to satisfy the C++ memory model; an odd/even
 * publication sequence lets readers reject an observation that overlapped a
 * write.
 *
 * @par Thread Safety
 * Exactly one thread may call publish(). Any number of foreign threads may call
 * try_read() or completed_generation(). The writer role must not be transferred
 * without external synchronization.
 *
 * @par Performance
 * Storage is fixed at compile time. Publication and observation do not allocate,
 * lock, sleep, log, or retry without a caller-supplied bound. This primitive is
 * intended for loop/batch-boundary telemetry, not per-packet publication.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

/**
 * @brief Publish a fixed-width snapshot from one writer to foreign observers.
 *
 * The sequence is zero until the first complete publication. Each successful
 * publication advances the externally visible generation by one. A reader
 * accepts values only when the sequence observed before and after the payload
 * is the same nonzero even value.
 *
 * @tparam field_count Number of uint64_t fields in one publication.
 *
 * @par Ownership
 * The sole writer owns publish(). Readers own only local `snapshot` values
 * returned by try_read(). No reader accesses writer-local state directly.
 */
template <std::size_t field_count>
class alignas(CACHE_LINE_SIZE) single_writer_snapshot {
	static_assert(field_count > 0, "single_writer_snapshot requires at least one field");
	static_assert(std::atomic<uint64_t>::is_always_lock_free,
		      "single_writer_snapshot requires lock-free uint64_t atomics");

    public:
	/**
	 * @brief One coherent observer-owned snapshot.
	 */
	struct snapshot {
		uint64_t generation{0};			     ///< Successful publication generation.
		std::array<uint64_t, field_count> fields{};  ///< Coherent published fields.
	};

	/**
	 * @brief Construct an unpublished snapshot channel.
	 */
	single_writer_snapshot() noexcept = default;

	single_writer_snapshot(const single_writer_snapshot &) = delete;
	single_writer_snapshot &operator=(const single_writer_snapshot &) = delete;
	single_writer_snapshot(single_writer_snapshot &&) = delete;
	single_writer_snapshot &operator=(single_writer_snapshot &&) = delete;

	/**
	 * @brief Determine whether an even publication sequence can advance safely.
	 *
	 * The internal sequence consumes two values per publication. Refusing the
	 * final increment prevents wrap from making an old generation appear new.
	 *
	 * @param sequence Current internal odd/even publication sequence.
	 * @return true when another complete publication can be represented.
	 */
	[[nodiscard]] static constexpr bool can_advance_sequence(uint64_t sequence) noexcept
	{
		return (sequence & 1u) == 0u && sequence <= MAX_SEQUENCE_BEFORE_PUBLISH;
	}

	/**
	 * @brief Publish one complete field set.
	 *
	 * Only the designated writer may call this function. A failed call performs
	 * no writes. An odd sequence indicates reentrant or violated writer
	 * ownership; an exhausted sequence is terminal for this channel.
	 *
	 * @param fields Values to publish as one coherent observation.
	 * @return true on publication; false if the sequence is odd or exhausted.
	 *
	 * @par Hot-Path Constraints
	 * Fixed work proportional to field_count; no allocation, locks, logging, or
	 * unbounded retries.
	 */
	[[nodiscard]] bool publish(const std::array<uint64_t, field_count> &fields) noexcept
	{
		const uint64_t sequence = sequence_.load(std::memory_order_relaxed);
		if (KINETUM_UNLIKELY(!can_advance_sequence(sequence))) {
			return false;
		}

		// Publish the odd marker before any payload write. If a reader observes a
		// concurrent payload store, the paired acquire fence forces its final
		// sequence read to observe this odd marker or a later publication.
		sequence_.store(sequence + 1u, std::memory_order_relaxed);
		std::atomic_thread_fence(std::memory_order_release);
		for (std::size_t i = 0; i < field_count; ++i) {
			fields_[i].store(fields[i], std::memory_order_relaxed);
		}
		sequence_.store(sequence + 2u, std::memory_order_release);
		return true;
	}

	/**
	 * @brief Attempt to read one coherent completed publication.
	 *
	 * The output remains unchanged when no coherent publication is observed
	 * within the caller's retry bound.
	 *
	 * @param out Observer-owned destination updated only on success.
	 * @param max_attempts Maximum read attempts; zero performs no work.
	 * @return true when one complete nonzero generation was read coherently.
	 */
	[[nodiscard]] bool try_read(snapshot &out, std::size_t max_attempts) const noexcept
	{
		for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
			const uint64_t begin = sequence_.load(std::memory_order_acquire);
			if (begin == 0u || (begin & 1u) != 0u) {
				continue;
			}

			std::array<uint64_t, field_count> observed{};
			for (std::size_t i = 0; i < field_count; ++i) {
				observed[i] = fields_[i].load(std::memory_order_relaxed);
			}

			// If any payload load observed a concurrent writer store, this fence
			// pairs with that writer's pre-payload release fence.
			std::atomic_thread_fence(std::memory_order_acquire);
			const uint64_t end = sequence_.load(std::memory_order_acquire);
			if (begin == end && (end & 1u) == 0u) {
				out.generation = end / 2u;
				out.fields = observed;
				return true;
			}
		}

		return false;
	}

	/**
	 * @brief Return the last completed publication generation.
	 *
	 * This diagnostic accessor does not return payload fields. Call try_read()
	 * when a coherent field set is required.
	 *
	 * @return Completed generation, or zero before the first publication. If a
	 * publication is in progress, returns the preceding completed generation.
	 */
	[[nodiscard]] uint64_t completed_generation() const noexcept
	{
		const uint64_t sequence = sequence_.load(std::memory_order_acquire);
		return sequence / 2u;
	}

    private:
	/** @brief Greatest even sequence that can begin one final publication. */
	static constexpr uint64_t MAX_SEQUENCE_BEFORE_PUBLISH = std::numeric_limits<uint64_t>::max() - 3u;

	std::atomic<uint64_t> sequence_{0};			   ///< Odd while publication is in progress.
	std::array<std::atomic<uint64_t>, field_count> fields_{};  ///< Atomically observable payload fields.
};

static_assert(alignof(single_writer_snapshot<1>) == CACHE_LINE_SIZE,
	      "single_writer_snapshot must begin on its own cache line");
static_assert(sizeof(single_writer_snapshot<1>) == CACHE_LINE_SIZE,
	      "one-field single_writer_snapshot must occupy exactly one cache line");

}  // namespace kinetum::algo
