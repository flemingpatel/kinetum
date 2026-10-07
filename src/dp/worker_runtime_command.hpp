// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_runtime_command.hpp
 * @brief One-load packet-worker transition and shutdown command publication.
 * @author Fleming Patel
 *
 * One coordinator publishes immutable process-generation commands through a
 * release-stored pointer. Every packet worker acquire-loads that pointer once
 * per turn. Two alternating transition records prevent the writer from
 * modifying the currently published record.
 * Global transition completion explicitly retires one published generation
 * before the other record may be reused.
 *
 * @par Thread Safety
 * The runtime coordinator is the sole publisher and completion writer. Any
 * number of packet workers may call observe() concurrently. Returned records
 * remain immutable for at least the complete globally serialized transition.
 *
 * @par Performance
 * observe() is exactly one acquire pointer load. Fixed execution performs no
 * allocation, lock, system call, clock read, retry, or payload copy.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>

#include <kinetum/algo/cache.hpp>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::dp
{

/** @brief Exact process-generation command selected by one published record. */
enum class worker_runtime_command_kind : uint8_t {
	RUN = 0,     ///< Fixed execution or an already consumed transition command.
	TRANSITION,  ///< Begin one exact committed epoch transition.
	STOP,	     ///< Permanently close source admission and drain for shutdown.
};

/** @brief Immutable fixed-width packet-worker command payload. */
struct worker_runtime_command_record {
	uint64_t runtime_generation{0};	    ///< Exact materialized runtime generation.
	uint64_t transition_generation{0};  ///< Exact mutation sequence, or zero outside TRANSITION.
	uint64_t from_epoch{0};		    ///< Exact old epoch, or zero outside TRANSITION.
	uint64_t to_epoch{0};		    ///< Exact target epoch, or zero outside TRANSITION.
	worker_runtime_command_kind kind{worker_runtime_command_kind::RUN};  ///< Command discriminator.
	std::array<uint8_t, 7> padding{};				     ///< Explicit natural-alignment completion.

	/** @return true only for one exact RUN, TRANSITION, or STOP representation. */
	[[nodiscard]] bool valid() const noexcept;
};

static_assert(sizeof(worker_runtime_command_record) == 40u,
	      "worker runtime command records must remain exactly 40 bytes");
static_assert(alignof(worker_runtime_command_record) == alignof(uint64_t),
	      "worker runtime command records must retain natural uint64_t alignment");
static_assert(std::is_trivially_copyable_v<worker_runtime_command_record>,
	      "worker runtime command records must remain trivially copyable");
static_assert(std::is_standard_layout_v<worker_runtime_command_record>,
	      "worker runtime command records must retain standard layout");
static_assert(std::atomic<const worker_runtime_command_record *>::is_always_lock_free,
	      "worker command publication requires one lock-free pointer load");

/** @brief Sole transition/stop publication shared by one packet-worker set. */
class worker_runtime_command_publication final {
    public:
	/**
	 * @brief Allocate one stable RUN publication for a runtime generation.
	 * @param runtime_generation Exact nonzero representable runtime generation.
	 * @return Stable publication owner or exact identity/allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_runtime_command_publication>>
	create(uint64_t runtime_generation) noexcept;

	worker_runtime_command_publication(const worker_runtime_command_publication &) = delete;
	worker_runtime_command_publication &operator=(const worker_runtime_command_publication &) = delete;
	worker_runtime_command_publication(worker_runtime_command_publication &&) = delete;
	worker_runtime_command_publication &operator=(worker_runtime_command_publication &&) = delete;

	/** @brief Destroy one baseline or exactly completed publication, optionally after STOP. */
	~worker_runtime_command_publication();

	/**
	 * @brief Prove one transition command can be published without mutation.
	 * @param transition_generation Exact new mutation sequence.
	 * @param from_epoch Exact currently globally active epoch.
	 * @param to_epoch Exact greater target epoch.
	 * @return OK only after the prior publication is globally complete and one
	 *         inactive immutable slot is available.
	 */
	[[nodiscard]] common::status preflight_transition(uint64_t transition_generation, uint64_t from_epoch,
							  uint64_t to_epoch) const noexcept;

	/**
	 * @brief Release-publish one preflighted immutable transition command.
	 * @param transition_generation Exact preflighted mutation sequence.
	 * @param from_epoch Exact preflighted old epoch.
	 * @param to_epoch Exact preflighted target epoch.
	 */
	void publish_transition_or_terminate(uint64_t transition_generation, uint64_t from_epoch,
					     uint64_t to_epoch) noexcept;

	/**
	 * @brief Retire one globally completed transition publication.
	 * @param transition_generation Exact published generation now proved COMPLETE.
	 *
	 * A RETIRING shutdown may publish STOP before exact old-object reclamation
	 * completes. STOP forbids another transition but does not erase the live
	 * generation; its exact completion must still resolve this ownership.
	 */
	void complete_transition_or_terminate(uint64_t transition_generation) noexcept;

	/** @brief Permanently release-publish STOP; repeated calls are idempotent. */
	void request_stop() noexcept;

	/**
	 * @brief Acquire-observe the current immutable command.
	 * @return Stable non-null record owned by this publication.
	 */
	[[nodiscard]] KINETUM_HOT KINETUM_ALWAYS_INLINE const worker_runtime_command_record *observe() const noexcept
	{
		return publication_.active.load(std::memory_order_acquire);
	}

	/** @return Exact materialized runtime generation. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;

    private:
	/** @brief One cache line containing only the recurring shared load. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) publication_line {
		std::atomic<const worker_runtime_command_record *> active{nullptr};  ///< Release/acquire command.
		std::array<std::byte,
			   kinetum::algo::CACHE_LINE_SIZE - sizeof(std::atomic<const worker_runtime_command_record *>)>
			padding{};  ///< Isolation.
	};

	static_assert(sizeof(publication_line) == kinetum::algo::CACHE_LINE_SIZE,
		      "worker command pointer must occupy one complete cache line");
	static_assert(alignof(publication_line) == kinetum::algo::CACHE_LINE_SIZE,
		      "worker command pointer must be cache-line aligned");

	/**
	 * @brief Construct one stable baseline publication.
	 * @param runtime_generation Exact validated nonzero runtime generation.
	 */
	explicit worker_runtime_command_publication(uint64_t runtime_generation) noexcept;

	publication_line publication_{};			      ///< Sole recurring reader line.
	worker_runtime_command_record run_record_{};		      ///< Immutable baseline record.
	worker_runtime_command_record stop_record_{};		      ///< Immutable terminal stop record.
	std::array<worker_runtime_command_record, 2> transitions_{};  ///< Alternating immutable transition records.
	uint64_t runtime_generation_{0};			      ///< Exact process generation.
	uint64_t published_transition_generation_{0};		      ///< Latest trigger publication.
	uint64_t completed_transition_generation_{0};		      ///< Latest globally COMPLETE trigger.
	std::size_t next_transition_slot_{0};			      ///< Inactive record selected next.
	bool stop_published_{false};				      ///< Irreversible writer-side STOP state.
};

}  // namespace kinetum::dp
