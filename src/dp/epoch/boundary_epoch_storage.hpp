// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file boundary_epoch_storage.hpp
 * @brief Exact per-worker NUMA storage for boundary endpoint transport state.
 * @author Fleming Patel
 *
 * One slab owns every sender-poller and receiver-poller endpoint slot assigned
 * to one compiled packet worker. The complete slot set occupies one checked,
 * prefaulted mapping on that worker's exact NUMA node. Slots are stable and
 * borrowed by nonmovable boundary channels and exact worker endpoint policies;
 * the slab owns bytes and lifetime, while those borrowers retain their
 * separate transport and policy authorities.
 *
 * ACK rings live in sender slots because the sender polls ACK. CUT rings and
 * process-shutdown closure publication live in receiver slots because the
 * receiver polls them. DATA retains its existing receiver-NUMA owner.
 *
 * @par Thread Safety
 * Creation, slot claims, sealing, release, and destruction are cold and
 * externally serialized. After sealing, only the borrowing channel and exact
 * endpoint policies access their disjoint lines. Destruction requires every sealed
 * claim to have retired after both endpoint workers are quiescent.
 */

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/queue.hpp>
#include <kinetum/algo/single_writer_snapshot.hpp>

#include "src/common/runtime_sizing.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/boundary_epoch_receiver_types.hpp"
#include "src/dp/epoch/boundary_epoch_sender_types.hpp"
#include "src/dp/epoch/ordered_cut.hpp"
#include "src/dp/numa_memory.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

class boundary_epoch_channel;
class worker_boundary_receiver;
class worker_boundary_sender;

/**
 * @brief Storage-only owner of all boundary endpoint slots for one worker.
 *
 * @par Ownership
 * One slab owns one exact mapping and placement-constructed slots. A channel
 * receives one linear slot claim; each sender slot also receives one linear
 * policy claim. Neither borrower receives a public storage accessor. The slab
 * cannot move and must outlive every claim. Sealing proves complete compiled
 * coverage.
 *
 * @par Thread Safety
 * Construction, claim, seal, and destruction are externally serialized. Once
 * sealed, the exact endpoint workers and foreign snapshot readers obey the
 * channel/sender contracts; the slab itself exposes no mutable semantic
 * operation.
 *
 * @par Performance
 * Checked layout, NUMA binding, prefault, and placement construction are cold.
 * Every hot slot and publication is cache-line aligned, and all slots for one
 * worker share one mapping rather than one page-rounded allocation per edge.
 */
class boundary_epoch_worker_slab final {
    public:
	/**
	 * @brief Compute the exact usable bytes for one worker slab.
	 *
	 * @param sender_slot_count Number of outbound-boundary sender slots.
	 * @param receiver_slot_count Number of inbound-boundary receiver slots.
	 * @return Exact checked usable bytes, including cold claim records, or an
	 *         overflow status. Two zero counts produce zero bytes.
	 */
	[[nodiscard]] static common::status_or<std::size_t> checked_storage_bytes(std::size_t sender_slot_count,
										  std::size_t receiver_slot_count);

	/**
	 * @brief Allocate and construct one exact worker-local endpoint slab.
	 *
	 * @param worker_index Exact non-sentinel compact worker identity.
	 * @param numa_node Exact nonnegative compiled worker NUMA node.
	 * @param sender_slot_count Exact outbound-boundary slot count.
	 * @param receiver_slot_count Exact inbound-boundary slot count.
	 * @return Unique unsealed slab, or a fail-closed validation/allocation status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<boundary_epoch_worker_slab>>
	create(uint32_t worker_index, int32_t numa_node, std::size_t sender_slot_count,
	       std::size_t receiver_slot_count);

	/** @brief Reject copying because one mapping has one lifetime owner. */
	boundary_epoch_worker_slab(const boundary_epoch_worker_slab &) = delete;
	/** @brief Reject copy assignment because slot addresses cannot be duplicated. */
	boundary_epoch_worker_slab &operator=(const boundary_epoch_worker_slab &) = delete;
	/** @brief Reject moving so every borrowed slot address remains stable. */
	boundary_epoch_worker_slab(boundary_epoch_worker_slab &&) = delete;
	/** @brief Reject move assignment so a published slab cannot be replaced. */
	boundary_epoch_worker_slab &operator=(boundary_epoch_worker_slab &&) = delete;

	/** @brief Destroy only after every sealed channel and endpoint-policy claim retires exactly. */
	~boundary_epoch_worker_slab();

	/**
	 * @brief Seal the complete one-claim-per-slot construction result.
	 *
	 * @return OK when every authored slot has one channel claim and one role-
	 *         correct policy claim; otherwise a fail-closed status
	 *         with no state change.
	 */
	[[nodiscard]] common::status seal();

	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;
	/** @return Exact compiled host NUMA node. */
	[[nodiscard]] int32_t numa_node() const noexcept;
	/** @return Exact outbound sender-slot count. */
	[[nodiscard]] std::size_t sender_slot_count() const noexcept;
	/** @return Exact inbound receiver-slot count. */
	[[nodiscard]] std::size_t receiver_slot_count() const noexcept;
	/** @return Exact usable bytes in the sole mapping, or zero for an empty slab. */
	[[nodiscard]] std::size_t storage_bytes() const noexcept;
	/** @return One for a nonempty slab and zero for an empty slab. */
	[[nodiscard]] std::size_t mapping_count() const noexcept;
	/** @return true after complete slot coverage is sealed. */
	[[nodiscard]] bool sealed() const noexcept;

    private:
	friend class boundary_epoch_channel;
	friend class worker_boundary_receiver;
	friend class worker_boundary_sender;

	/** @brief Exact sender-publication payload width. */
	static constexpr std::size_t SENDER_PUBLICATION_FIELD_COUNT = 6u;
	/** @brief Exact receiver-publication payload width. */
	static constexpr std::size_t RECEIVER_PUBLICATION_FIELD_COUNT = 5u;
	/** @brief Exact sender-policy proof payload width. */
	static constexpr std::size_t SENDER_POLICY_PUBLICATION_FIELD_COUNT = 12u;
	/** @brief Exact receiver-policy proof payload width. */
	static constexpr std::size_t RECEIVER_POLICY_PUBLICATION_FIELD_COUNT = 14u;

	/** @brief Sender-only hot state occupying one private cache line. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) sender_owner_state {
		successful_data_sequence data_enqueued;	 ///< Successful DATA publications.
		uint64_t data_backpressure_events{0};	 ///< Full DATA publication attempts.
		boundary_epoch_cut pending_cut{};	 ///< Exact unpublished CUT when present.
		bool cut_pending{false};		 ///< Whether pending_cut is authoritative.
		bool closed{false};			 ///< Sole-producer process-shutdown state.
	};

	/**
	 * @brief Sender-gate policy facts occupying one owner-local cache line.
	 *
	 * The slab owns these bytes but exposes no policy operation. Exactly one
	 * `worker_boundary_sender` claim interprets and mutates the value.
	 */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) sender_policy_state {
		uint64_t transition_generation{0};  ///< Last exact transition generation accepted.
		uint64_t open_epoch{0};		    ///< Exact epoch currently permitted into DATA.
		uint64_t from_epoch{0};		    ///< Exact old epoch for the retained generation.
		uint64_t to_epoch{0};		    ///< Exact target epoch for the retained generation.
		uint64_t cut_sequence{0};	    ///< Exact captured successful-enqueue sequence.
		uint64_t duplicate_ack_count{0};    ///< Exact duplicate ACK observations.
		boundary_epoch_sender_phase phase{boundary_epoch_sender_phase::UNBOUND};  ///< Sole sender-gate phase.
		std::array<uint8_t, 15> padding{};  ///< Explicit cache-line completion.
	};

	/** @brief Sender transition-event timestamps isolated from packet policy. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) sender_timing_state {
		uint64_t cut_published_monotonic_ns{0};	 ///< Pre-publication batch sample.
		uint64_t ack_observed_monotonic_ns{0};	 ///< Post-consumption batch sample.
		std::array<uint8_t, 48> padding{};	 ///< Explicit cache-line completion.
	};

	/** @brief Receiver-only hot state occupying one private cache line. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) receiver_owner_state {
		successful_data_sequence data_dequeued;	     ///< Credit-completed DATA transfers.
		boundary_epoch_ack pending_ack{};	     ///< Exact unpublished ACK when present.
		packet_record *unsequenced_record{nullptr};  ///< Borrowed exact completion identity.
		bool ack_pending{false};		     ///< Whether pending_ack is authoritative.
	};

	/**
	 * @brief Receiver CUT/ACK policy facts occupying one owner-local cache line.
	 *
	 * The exact worker receiver interprets these storage-only bytes. Transition
	 * generation and from/to identity are retained once by that worker owner,
	 * never repeated in each boundary line.
	 */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) receiver_policy_state {
		uint64_t active_epoch{0};	    ///< Exact epoch admitted by DATA receive.
		boundary_epoch_cut accepted_cut{};  ///< First exact CUT for the generation.
		uint64_t duplicate_cut_count{0};    ///< Exact duplicate CUT observations.
		boundary_epoch_receiver_phase phase{
			boundary_epoch_receiver_phase::UNBOUND};  ///< Sole receiver-policy phase.
		std::array<uint8_t, 31> padding{};		  ///< Explicit cache-line completion.
	};

	/** @brief Receiver transition-event timestamps isolated from packet policy. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) receiver_timing_state {
		uint64_t cut_observed_monotonic_ns{0};	 ///< Post-consumption batch sample.
		uint64_t cut_drained_monotonic_ns{0};	 ///< Post-drain-classification batch sample.
		uint64_t activation_monotonic_ns{0};	 ///< Exact local activation sample.
		uint64_t ack_published_monotonic_ns{0};	 ///< Pre-publication batch sample.
		std::array<uint8_t, 32> padding{};	 ///< Explicit cache-line completion.
	};

	/** @brief Sender-local transport, distinct policy, publication, and ACK storage. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) sender_slot {
		sender_owner_state owner;    ///< Sole sender-mutated transport state.
		sender_policy_state policy;  ///< Sole worker-owned sender-gate state.
		sender_timing_state timing;  ///< Transition-only sender timing state.
		kinetum::algo::single_writer_snapshot<SENDER_POLICY_PUBLICATION_FIELD_COUNT>
			policy_publication;  ///< Event-edge coherent sender transition proof.
		kinetum::algo::single_writer_snapshot<SENDER_PUBLICATION_FIELD_COUNT>
			publication;  ///< Coherent sender transport observation only.
		kinetum::algo::spsc_ring_static<boundary_epoch_ack,
						common::runtime_sizing::BOUNDARY_ACK_RING_CAPACITY>
			ack_ring;  ///< Receiver-to-sender transport placed with its poller.

		/** @return true when no sender-side control ownership remains. */
		[[nodiscard]] bool empty() const noexcept;
		/** @return true before the slot has ever served a channel. */
		[[nodiscard]] bool pristine() const noexcept;
	};

	/** @brief Receiver-local state, publication, receiver-polled CUT ring, and closure. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) receiver_slot {
		receiver_owner_state owner;    ///< Sole receiver-mutated transport state.
		receiver_policy_state policy;  ///< Sole worker-owned CUT/ACK policy state.
		receiver_timing_state timing;  ///< Transition-only receiver timing state.
		kinetum::algo::single_writer_snapshot<RECEIVER_POLICY_PUBLICATION_FIELD_COUNT>
			policy_publication;  ///< Event-edge coherent receiver transition proof.
		kinetum::algo::single_writer_snapshot<RECEIVER_PUBLICATION_FIELD_COUNT>
			publication;  ///< Coherent receiver transport observation only.
		kinetum::algo::spsc_ring_static<boundary_epoch_cut,
						common::runtime_sizing::BOUNDARY_CUT_RING_CAPACITY>
			cut_ring;  ///< Sender-to-receiver transport placed with its poller.
		/** Release/acquire process-shutdown closure placed with its poller. */
		alignas(kinetum::algo::CACHE_LINE_SIZE) std::atomic<bool> sender_closed{false};

		/** @return true when no receiver-side control/completion ownership remains. */
		[[nodiscard]] bool empty() const noexcept;
		/** @return true before the slot has ever served a channel. */
		[[nodiscard]] bool pristine() const noexcept;
	};

	/** @brief Cold lifetime state for one stable slot. */
	enum class claim_state : uint8_t {
		UNCLAIMED = 0,	///< No channel has borrowed this slot.
		CLAIMED,	///< One exact channel currently borrows this slot.
		RETIRED,	///< The sole channel claim retired permanently.
	};

	/** @brief Cold exact channel/policy claims stored inside the sole mapping. */
	struct slot_claim {
		uint32_t boundary_index{0};  ///< Exact borrowing boundary while claimed or retired.
		claim_state channel_state{claim_state::UNCLAIMED};  ///< Linear channel lifetime.
		claim_state policy_state{claim_state::UNCLAIMED};   ///< Linear role-correct policy lifetime.
	};

	/** @brief Checked offsets for every array in one mapping. */
	struct storage_layout {
		std::size_t sender_slots_offset{0};	///< First sender-slot byte.
		std::size_t receiver_slots_offset{0};	///< First receiver-slot byte.
		std::size_t sender_claims_offset{0};	///< First sender-claim byte.
		std::size_t receiver_claims_offset{0};	///< First receiver-claim byte.
		std::size_t storage_bytes{0};		///< Complete usable extent.
	};

	static_assert(sizeof(sender_owner_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender owner state must occupy exactly one cache line");
	static_assert(sizeof(receiver_owner_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver owner state must occupy exactly one cache line");
	static_assert(alignof(sender_owner_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender owner state must retain cache-line alignment");
	static_assert(alignof(receiver_owner_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver owner state must retain cache-line alignment");
	static_assert(sizeof(sender_policy_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender policy state must occupy exactly one cache line");
	static_assert(alignof(sender_policy_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender policy state must retain cache-line alignment");
	static_assert(std::is_standard_layout_v<sender_policy_state> &&
			      std::is_trivially_copyable_v<sender_policy_state>,
		      "boundary sender policy state must retain fixed value layout");
	static_assert(sizeof(receiver_policy_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver policy state must occupy exactly one cache line");
	static_assert(alignof(receiver_policy_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver policy state must retain cache-line alignment");
	static_assert(std::is_standard_layout_v<receiver_policy_state> &&
			      std::is_trivially_copyable_v<receiver_policy_state>,
		      "boundary receiver policy state must retain fixed value layout");
	static_assert(sizeof(sender_timing_state) == kinetum::algo::CACHE_LINE_SIZE &&
			      sizeof(receiver_timing_state) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary timing state must remain cache-line exact");
	static_assert(std::is_standard_layout_v<sender_timing_state> &&
			      std::is_trivially_copyable_v<sender_timing_state> &&
			      std::is_standard_layout_v<receiver_timing_state> &&
			      std::is_trivially_copyable_v<receiver_timing_state>,
		      "boundary timing state must retain fixed value layout");
	static_assert(sizeof(kinetum::algo::single_writer_snapshot<SENDER_PUBLICATION_FIELD_COUNT>) ==
			      kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender publication must occupy exactly one cache line");
	static_assert(sizeof(kinetum::algo::single_writer_snapshot<RECEIVER_PUBLICATION_FIELD_COUNT>) ==
			      kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver publication must occupy exactly one cache line");
	static_assert(sizeof(kinetum::algo::single_writer_snapshot<SENDER_POLICY_PUBLICATION_FIELD_COUNT>) ==
			      2u * kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender policy publication must occupy exactly two cache lines");
	static_assert(sizeof(kinetum::algo::single_writer_snapshot<RECEIVER_POLICY_PUBLICATION_FIELD_COUNT>) ==
			      2u * kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver policy publication must occupy exactly two cache lines");
	static_assert(alignof(sender_slot) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender slot must retain cache-line alignment");
	static_assert(alignof(receiver_slot) == kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver slot must retain cache-line alignment");
	static_assert(std::is_standard_layout_v<sender_slot> && std::is_standard_layout_v<receiver_slot>,
		      "boundary endpoint slots must retain inspectable standard layout");
	static_assert(offsetof(sender_slot, owner) == 0u &&
			      offsetof(sender_slot, policy) == kinetum::algo::CACHE_LINE_SIZE &&
			      offsetof(sender_slot, timing) == 2u * kinetum::algo::CACHE_LINE_SIZE &&
			      offsetof(sender_slot, policy_publication) == 3u * kinetum::algo::CACHE_LINE_SIZE &&
			      offsetof(sender_slot, publication) == 5u * kinetum::algo::CACHE_LINE_SIZE,
		      "boundary sender transport, policy, and publications must occupy disjoint cache lines");
	static_assert(offsetof(receiver_slot, owner) == 0u &&
			      offsetof(receiver_slot, policy) == kinetum::algo::CACHE_LINE_SIZE &&
			      offsetof(receiver_slot, timing) == 2u * kinetum::algo::CACHE_LINE_SIZE &&
			      offsetof(receiver_slot, policy_publication) == 3u * kinetum::algo::CACHE_LINE_SIZE &&
			      offsetof(receiver_slot, publication) == 5u * kinetum::algo::CACHE_LINE_SIZE,
		      "boundary receiver transport, policy, and publications must occupy disjoint cache lines");
	static_assert(offsetof(sender_slot, ack_ring) % kinetum::algo::CACHE_LINE_SIZE == 0u,
		      "boundary ACK ring must begin on a sender-local cache line");
	static_assert(offsetof(receiver_slot, cut_ring) % kinetum::algo::CACHE_LINE_SIZE == 0u,
		      "boundary CUT ring must begin on a receiver-local cache line");
	static_assert(offsetof(receiver_slot, sender_closed) % kinetum::algo::CACHE_LINE_SIZE == 0u,
		      "boundary closure publication must begin on a receiver-local cache line");
	static_assert(sizeof(sender_slot) % kinetum::algo::CACHE_LINE_SIZE == 0u,
		      "boundary sender slot stride must preserve cache-line alignment");
	static_assert(sizeof(receiver_slot) % kinetum::algo::CACHE_LINE_SIZE == 0u,
		      "boundary receiver slot stride must preserve cache-line alignment");
	static_assert(std::atomic<bool>::is_always_lock_free,
		      "boundary sender closure requires a lock-free boolean atomic");

	/**
	 * @brief Compute every checked array offset and the complete extent.
	 *
	 * @param sender_slot_count Exact outbound-boundary slot population.
	 * @param receiver_slot_count Exact inbound-boundary slot population.
	 * @return Complete aligned layout or an overflow status without mutation.
	 */
	[[nodiscard]] static common::status_or<storage_layout> compute_layout_(std::size_t sender_slot_count,
									       std::size_t receiver_slot_count);

	/**
	 * @brief Adopt one complete mapping and placement-construct every slot.
	 *
	 * @param worker_index Exact compact worker identity.
	 * @param numa_node Exact compiled worker node.
	 * @param sender_slot_count Exact sender-slot population.
	 * @param receiver_slot_count Exact receiver-slot population.
	 * @param layout Checked mapping layout.
	 * @param region Sole exact mapping owner, empty only for a zero-slot slab.
	 */
	boundary_epoch_worker_slab(uint32_t worker_index, int32_t numa_node, std::size_t sender_slot_count,
				   std::size_t receiver_slot_count, const storage_layout &layout,
				   numa_memory_region region);

	/**
	 * @brief Check one sender slot before the linear claim transaction.
	 *
	 * @param slot_index Candidate outbound ordinal.
	 * @return true when one sender slot can be claimed without mutation.
	 */
	[[nodiscard]] bool sender_slot_claimable_(std::size_t slot_index) const noexcept;
	/**
	 * @brief Check one receiver slot before the linear claim transaction.
	 *
	 * @param slot_index Candidate inbound ordinal.
	 * @return true when one receiver slot can be claimed without mutation.
	 */
	[[nodiscard]] bool receiver_slot_claimable_(std::size_t slot_index) const noexcept;
	/**
	 * @brief Claim one exact sender slot for a channel during construction.
	 *
	 * @param slot_index Exact outbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 * @return Borrowed stable slot or a fail-closed availability status.
	 */
	[[nodiscard]] common::status_or<sender_slot *> claim_sender_slot_(std::size_t slot_index,
									  uint32_t boundary_index);
	/**
	 * @brief Claim one exact receiver slot for a channel during construction.
	 *
	 * @param slot_index Exact inbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 * @return Borrowed stable slot or a fail-closed availability status.
	 */
	[[nodiscard]] common::status_or<receiver_slot *> claim_receiver_slot_(std::size_t slot_index,
									      uint32_t boundary_index);
	/**
	 * @brief Validate one sender claim before channel retirement.
	 *
	 * @param slot_index Exact outbound ordinal.
	 * @param boundary_index Expected borrowing boundary identity.
	 * @return true when one sender claim equals the expected live channel.
	 */
	[[nodiscard]] bool sender_claim_matches_(std::size_t slot_index, uint32_t boundary_index) const noexcept;
	/**
	 * @brief Validate one receiver claim before channel retirement.
	 *
	 * @param slot_index Exact inbound ordinal.
	 * @param boundary_index Expected borrowing boundary identity.
	 * @return true when one receiver claim equals the expected live channel.
	 */
	[[nodiscard]] bool receiver_claim_matches_(std::size_t slot_index, uint32_t boundary_index) const noexcept;
	/**
	 * @brief Claim one exact sender-policy line after channel construction.
	 *
	 * @param slot_index Exact outbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 * @return Stable policy storage from one virgin sender slot, or a
	 *         fail-closed duplicate/identity/state status.
	 */
	[[nodiscard]] common::status_or<sender_policy_state *> claim_sender_policy_(std::size_t slot_index,
										    uint32_t boundary_index);
	/**
	 * @brief Claim one exact receiver-policy line after channel construction.
	 *
	 * @param slot_index Exact inbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 * @return Stable policy storage from one virgin receiver slot, or a
	 *         fail-closed duplicate/identity/state status.
	 */
	[[nodiscard]] common::status_or<receiver_policy_state *> claim_receiver_policy_(std::size_t slot_index,
											uint32_t boundary_index);
	/**
	 * @brief Retire one empty sender-policy claim before channel retirement.
	 *
	 * @param slot_index Exact outbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 */
	void release_sender_policy_(std::size_t slot_index, uint32_t boundary_index) noexcept;
	/**
	 * @brief Retire one empty receiver-policy claim before channel retirement.
	 *
	 * @param slot_index Exact inbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 */
	void release_receiver_policy_(std::size_t slot_index, uint32_t boundary_index) noexcept;
	/**
	 * @brief Retire one already validated sender claim permanently.
	 *
	 * @param slot_index Exact outbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 */
	void release_sender_slot_(std::size_t slot_index, uint32_t boundary_index) noexcept;
	/**
	 * @brief Retire one already validated receiver claim permanently.
	 *
	 * @param slot_index Exact inbound ordinal.
	 * @param boundary_index Exact borrowing boundary identity.
	 */
	void release_receiver_slot_(std::size_t slot_index, uint32_t boundary_index) noexcept;

	uint32_t worker_index_{0};		  ///< Immutable compact worker identity.
	int32_t numa_node_{-1};			  ///< Exact compiled worker NUMA node.
	std::size_t sender_slot_count_{0};	  ///< Exact outbound slot population.
	std::size_t receiver_slot_count_{0};	  ///< Exact inbound slot population.
	std::size_t storage_bytes_{0};		  ///< Exact usable mapping extent.
	numa_memory_region region_;		  ///< Sole prefaulted worker-local mapping.
	sender_slot *sender_slots_{nullptr};	  ///< Placement-constructed sender slots.
	receiver_slot *receiver_slots_{nullptr};  ///< Placement-constructed receiver slots.
	slot_claim *sender_claims_{nullptr};	  ///< Cold sender-slot lifetime records.
	slot_claim *receiver_claims_{nullptr};	  ///< Cold receiver-slot lifetime records.
	bool sealed_{false};			  ///< Complete one-claim-per-slot construction proof.
};

}  // namespace kinetum::dp
