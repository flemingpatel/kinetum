// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file boundary_epoch_channel.hpp
 * @brief Exact DATA sequence and typed CUT/ACK transport for one boundary.
 * @author Fleming Patel
 *
 * One compiled sender and receiver share three bounded SPSC lanes. DATA carries
 * only `packet_record *`; successful sender publication and receiver ownership
 * completion advance independent process-lifetime sequences. CUT and ACK lanes
 * carry their exact fixed-width record types and retain at most one pending
 * publication without spinning.
 *
 * Endpoint mutable state and coherent publication borrow stable slots from
 * the owning workers' exact-NUMA slabs. CUT storage lives with its receiver
 * poller; ACK storage lives with its sender poller. The slabs own only bytes
 * and lifetime, so every operation still passes through this channel.
 *
 * This owner is transport, not transition policy. It does not seal old DATA,
 * interpret duplicates, gate future output, aggregate fan-in, activate a
 * participant, or authorize reclamation. Those operations belong to the
 * sender, receiver, and coordinator policy owners that compose this channel.
 *
 * @par Thread Safety
 * The compiled sender exclusively owns DATA/CUT production, ACK consumption,
 * sender closure, and sender publication. The compiled receiver exclusively
 * owns DATA/CUT consumption, ACK production, receive completion, and receiver
 * publication. Foreign threads may read only the coherent publications and
 * sender-closure flag. Construction and destruction require both endpoints
 * absent or quiescent.
 *
 * @par Performance
 * Every packet operation is allocation-free, lock-free, clock-free O(1) work.
 * Successful DATA transfer adds one plain owner-local sequence increment.
 * Control publication attempts one ring operation and never spins, sleeps, or
 * yields. Endpoint observations publish only at a bounded worker-turn boundary.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>

#include <kinetum/algo/platform.hpp>

#include "src/common/status_or.hpp"
#include "src/common/transition_topology.hpp"
#include "src/dp/epoch/boundary_epoch_storage.hpp"
#include "src/dp/epoch/ordered_cut.hpp"
#include "src/dp/numa_spsc_ring.hpp"
#include "src/dp/packet.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp
{

/** @brief Result of one bounded typed-control publication turn. */
enum class boundary_control_publication_result : uint8_t {
	ABSENT = 0,  ///< No endpoint-local pending record exists.
	PENDING,     ///< One exact record remains endpoint-owned after a full ring.
	PUBLISHED,   ///< One exact record transferred to its SPSC lane.
};

/**
 * @brief Coherent sender-owned transport observation for one boundary.
 *
 * @par Thread Safety
 * Each value belongs to one observer. Concurrent readers use independent values
 * populated from the same channel publication.
 *
 * @par Performance
 * Exactly one cache line, standard-layout, and trivially copyable.
 */
struct alignas(kinetum::algo::CACHE_LINE_SIZE) boundary_sender_transport_snapshot {
	uint64_t publication_generation{0};    ///< Completed coherent-publication generation.
	uint64_t runtime_generation{0};	       ///< Exact materialized runtime generation.
	uint64_t boundary_index{0};	       ///< Exact compact boundary identity.
	uint64_t data_enqueued_sequence{0};    ///< Successful DATA publications.
	uint64_t data_backpressure_events{0};  ///< Full DATA publication attempts.
	uint64_t pending_cut_epoch{0};	       ///< Pending CUT epoch, or zero when absent.
	uint64_t pending_cut_sequence{0};      ///< Pending CUT DATA watermark, or zero when absent.
};

/**
 * @brief Coherent receiver-owned transport observation for one boundary.
 *
 * @par Thread Safety
 * Each value belongs to one observer. Concurrent readers use independent values
 * populated from the same channel publication.
 *
 * @par Performance
 * Exactly one cache line, standard-layout, and trivially copyable.
 */
struct alignas(kinetum::algo::CACHE_LINE_SIZE) boundary_receiver_transport_snapshot {
	uint64_t publication_generation{0};  ///< Completed coherent-publication generation.
	uint64_t runtime_generation{0};	     ///< Exact materialized runtime generation.
	uint64_t boundary_index{0};	     ///< Exact compact boundary identity.
	uint64_t data_dequeued_sequence{0};  ///< DATA transfers completed after receiver credit.
	uint64_t pending_ack_epoch{0};	     ///< Pending ACK epoch, or zero when absent.
	uint64_t pending_ack_sequence{0};    ///< Pending ACK DATA watermark, or zero when absent.
};

static_assert(sizeof(boundary_sender_transport_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "boundary sender transport observation must occupy exactly one cache line");
static_assert(sizeof(boundary_receiver_transport_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "boundary receiver transport observation must occupy exactly one cache line");
static_assert(alignof(boundary_sender_transport_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "boundary sender transport observation must retain cache-line alignment");
static_assert(alignof(boundary_receiver_transport_snapshot) == kinetum::algo::CACHE_LINE_SIZE,
	      "boundary receiver transport observation must retain cache-line alignment");
static_assert(std::is_standard_layout_v<boundary_sender_transport_snapshot> &&
		      std::is_trivially_copyable_v<boundary_sender_transport_snapshot>,
	      "boundary sender transport observation must retain value semantics");
static_assert(std::is_standard_layout_v<boundary_receiver_transport_snapshot> &&
		      std::is_trivially_copyable_v<boundary_receiver_transport_snapshot>,
	      "boundary receiver transport observation must retain value semantics");
static_assert(sizeof(boundary_control_publication_result) == sizeof(uint8_t),
	      "boundary control publication result must remain one byte");

/**
 * @brief Validate one coherently decoded sender transport publication.
 * @param value Complete observer-owned value; no live endpoint state is read.
 * @param runtime_generation Exact channel generation.
 * @param boundary_index Exact compact channel identity.
 * @return AVAILABLE or the intrinsic identity/state failure; never UNAVAILABLE.
 */
[[nodiscard]] publication_read_result
validate_boundary_sender_transport(const boundary_sender_transport_snapshot &value, uint64_t runtime_generation,
				   uint32_t boundary_index) noexcept;

/**
 * @brief Validate one coherently decoded receiver transport publication.
 * @param value Complete observer-owned value; no live endpoint state is read.
 * @param runtime_generation Exact channel generation.
 * @param boundary_index Exact compact channel identity.
 * @return AVAILABLE or the intrinsic identity/state failure; never UNAVAILABLE.
 */
[[nodiscard]] publication_read_result
validate_boundary_receiver_transport(const boundary_receiver_transport_snapshot &value, uint64_t runtime_generation,
				     uint32_t boundary_index) noexcept;

/** @brief Exact result of one sender-owned DATA publication attempt. */
enum class boundary_data_publication_result : uint8_t {
	TRANSFERRED = 0,     ///< DATA owns the pointer and sequence advanced.
	BACKPRESSURED,	     ///< Caller retains ownership because DATA is full.
	SEQUENCE_EXHAUSTED,  ///< No additional successful sequence is representable.
};

static_assert(sizeof(boundary_data_publication_result) == sizeof(uint8_t),
	      "boundary DATA publication result must remain one byte");

/** @brief Exact result of one receiver-owned DATA acquisition attempt. */
enum class boundary_data_receive_result : uint8_t {
	RECEIVED = 0,	     ///< Caller owns one unresolved pointer transfer.
	EMPTY,		     ///< DATA contained no pointer and no state changed.
	SEQUENCE_EXHAUSTED,  ///< Queued DATA cannot receive another successful sequence.
};

static_assert(sizeof(boundary_data_receive_result) == sizeof(uint8_t),
	      "boundary DATA receive result must remain one byte");

/**
 * @brief Nonmovable owner of one exact three-lane boundary transport.
 *
 * The channel owns physical DATA/CUT/ACK transfer, endpoint-local transport
 * progress, and coherent observation only. Sender sealing, ACK gating,
 * receiver fan-in, activation, and reclamation remain external policy.
 *
 * @par Ownership
 * The channel owns its DATA mapping and sole claims on one sender slot and one
 * receiver slot. The corresponding worker slabs retain the physical endpoint
 * bytes and must be destroyed only after this channel releases both claims.
 *
 * @par Thread Safety
 * One compiled sender and one compiled receiver own their respective method
 * families. Foreign threads may use only try_read_*() and sender_closed(). The
 * borrowed endpoint slabs must outlive the channel.
 */
class boundary_epoch_channel final {
    public:
	/**
	 * @brief Materialize one complete empty channel from compiled truth.
	 *
	 * @param facts Exact compact boundary identity, DATA capacity, and receiver NUMA.
	 * @param runtime_generation Exact nonzero materialized generation identity.
	 * @param sender_slab Stable storage owned by the exact sender worker.
	 * @param sender_slot_index Exact outbound ordinal within @p sender_slab.
	 * @param receiver_slab Stable storage owned by the exact receiver worker.
	 * @param receiver_slot_index Exact inbound ordinal within @p receiver_slab.
	 * @return Unique empty channel, or a fail-closed validation/allocation status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<boundary_epoch_channel>>
	create(const common::compiled_transition_boundary &facts, uint64_t runtime_generation,
	       boundary_epoch_worker_slab &sender_slab, std::size_t sender_slot_index,
	       boundary_epoch_worker_slab &receiver_slab, std::size_t receiver_slot_index);

	/** @brief Reject copying because endpoint and packet ownership are linear. */
	boundary_epoch_channel(const boundary_epoch_channel &) = delete;
	/** @brief Reject copy assignment because sequence authority cannot be duplicated. */
	boundary_epoch_channel &operator=(const boundary_epoch_channel &) = delete;
	/** @brief Reject moving so every published channel address remains stable. */
	boundary_epoch_channel(boundary_epoch_channel &&) = delete;
	/** @brief Reject move assignment so endpoint ownership cannot be replaced. */
	boundary_epoch_channel &operator=(boundary_epoch_channel &&) = delete;

	/** @brief Destroy only after every DATA/control/completion owner is empty. */
	~boundary_epoch_channel();

	/**
	 * @brief Transfer one packet into DATA and then advance sender sequence truth.
	 *
	 * @param record Nonnull exact packet ownership offered by the sender.
	 * @return TRANSFERRED after ring transfer and sequence advancement,
	 *         BACKPRESSURED when full with caller ownership unchanged, or
	 *         SEQUENCE_EXHAUSTED before mutation.
	 */
	[[nodiscard]] boundary_data_publication_result try_send_data(packet_record *record) noexcept;

	/**
	 * @brief Transfer one packet out of DATA without yet advancing dequeue truth.
	 *
	 * One successful call creates one exact unresolved completion. The receiver
	 * must acquire its worker credit and call complete_data_receive() before any
	 * second receive or receiver publication.
	 *
	 * @param[out] record Destination changed only after one successful pop.
	 * @return RECEIVED after pointer transfer, EMPTY when DATA has no pointer, or
	 *         SEQUENCE_EXHAUSTED before mutation when queued DATA cannot receive
	 *         another successful sequence.
	 */
	[[nodiscard]] boundary_data_receive_result try_receive_data(packet_record *&record) noexcept;

	/**
	 * @brief Complete one exact dequeue after receiver-credit acquisition.
	 *
	 * @param record Exact pointer returned by the unresolved try_receive_data().
	 */
	void complete_data_receive(packet_record *record) noexcept;

	/** @return Consumer-borrowed next DATA record, or null when empty. */
	[[nodiscard]] const packet_record *peek_data() const noexcept;

	/**
	 * @brief Publish or retain one exact CUT without waiting.
	 *
	 * @param cut Valid sequence-defined CUT transferred on PUBLISHED or retained
	 *        by the sender endpoint on PENDING.
	 * @return PUBLISHED or PENDING.
	 */
	[[nodiscard]] boundary_control_publication_result submit_cut(const boundary_epoch_cut &cut) noexcept;

	/** @return ABSENT, PENDING, or PUBLISHED after one pending-CUT retry. */
	[[nodiscard]] boundary_control_publication_result service_pending_cut() noexcept;

	/**
	 * @brief Consume one typed CUT on the exact receiver.
	 *
	 * @param[out] cut Destination changed only when a valid CUT is available.
	 * @return true after one transfer; false when the CUT lane is empty.
	 */
	[[nodiscard]] bool try_receive_cut(boundary_epoch_cut &cut) noexcept;

	/**
	 * @brief Publish or retain one exact ACK without waiting.
	 *
	 * @param ack Valid exact ACK transferred on PUBLISHED or retained by the
	 *        receiver endpoint on PENDING.
	 * @return PUBLISHED or PENDING.
	 */
	[[nodiscard]] boundary_control_publication_result submit_ack(const boundary_epoch_ack &ack) noexcept;

	/** @return ABSENT, PENDING, or PUBLISHED after one pending-ACK retry. */
	[[nodiscard]] boundary_control_publication_result service_pending_ack() noexcept;

	/**
	 * @brief Consume one typed ACK on the exact sender.
	 *
	 * @param[out] ack Destination changed only when a valid ACK is available.
	 * @return true after one transfer; false when the ACK lane is empty.
	 */
	[[nodiscard]] bool try_receive_ack(boundary_epoch_ack &ack) noexcept;

	/** @return true while the sender owns one unpublished CUT. */
	[[nodiscard]] bool has_pending_cut() const noexcept;
	/** @return true while the receiver owns one unpublished ACK. */
	[[nodiscard]] bool has_pending_ack() const noexcept;

	/** @brief Publish one coherent sender endpoint transport observation. */
	void publish_sender_transport() noexcept;
	/** @brief Publish one coherent receiver endpoint transport observation. */
	void publish_receiver_transport() noexcept;

	/**
	 * @brief Attempt one bounded coherent sender observation.
	 *
	 * @param[out] out Observer value updated only after exact validation.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_sender_transport(boundary_sender_transport_snapshot &out) const noexcept;

	/**
	 * @brief Attempt one bounded coherent receiver observation.
	 *
	 * @param[out] out Observer value updated only after exact validation.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_receiver_transport(boundary_receiver_transport_snapshot &out) const noexcept;

	/** @brief Permanently close the sole process-generation DATA producer. */
	void close_sender() noexcept;
	/** @return true after release/acquire process-shutdown sender closure. */
	[[nodiscard]] bool sender_closed() const noexcept;

	/** @return Exact compact boundary identity. */
	[[nodiscard]] uint32_t boundary_index() const noexcept;
	/** @return Exact executable source stage-instance index. */
	[[nodiscard]] uint32_t from_stage_instance_index() const noexcept;
	/** @return Exact executable destination stage-instance index. */
	[[nodiscard]] uint32_t to_stage_instance_index() const noexcept;
	/** @return Exact sole sender-worker compact index. */
	[[nodiscard]] uint32_t sender_worker_index() const noexcept;
	/** @return Exact sole receiver-worker compact index. */
	[[nodiscard]] uint32_t receiver_worker_index() const noexcept;
	/** @return Exact materialized runtime generation. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;
	/** @return Exact receiver-local DATA NUMA node. */
	[[nodiscard]] int32_t data_ring_numa_node() const noexcept;
	/** @return Exact sender-owner endpoint-state NUMA node. */
	[[nodiscard]] int32_t sender_endpoint_numa_node() const noexcept;
	/** @return Exact receiver-owner endpoint-state NUMA node. */
	[[nodiscard]] int32_t receiver_endpoint_numa_node() const noexcept;
	/** @return Exact receiver-poller CUT-ring NUMA node. */
	[[nodiscard]] int32_t cut_ring_numa_node() const noexcept;
	/** @return Exact sender-poller ACK-ring NUMA node. */
	[[nodiscard]] int32_t ack_ring_numa_node() const noexcept;
	/**
	 * @brief Observe cold endpoint-storage completion before worker launch.
	 *
	 * @return true after both complete worker-slab claim sets are sealed.
	 */
	[[nodiscard]] bool endpoint_storage_sealed() const noexcept;
	/** @return Exact plan-owned usable DATA capacity. */
	[[nodiscard]] std::size_t data_capacity() const noexcept;
	/** @return Owner-local successful DATA enqueue sequence. */
	[[nodiscard]] uint64_t data_enqueued_sequence() const noexcept;
	/** @return Owner-local completed DATA dequeue sequence. */
	[[nodiscard]] uint64_t data_dequeued_sequence() const noexcept;
	/**
	 * @brief Observe complete DATA retirement after endpoint quiescence or sender closure.
	 *
	 * The receiver may call after acquire-observing sender_closed(). Cold code
	 * may call only while both endpoints are absent or externally quiescent.
	 * Foreign observers must use the coherent snapshots instead.
	 *
	 * @return true when DATA and its receive-completion seam are empty and both
	 *         successful sequences agree.
	 */
	[[nodiscard]] bool data_empty() const noexcept;
	/**
	 * @brief Observe control retirement after endpoint quiescence or sender closure.
	 *
	 * The same receiver-or-quiescent calling contract as data_empty() applies.
	 *
	 * @return true when CUT/ACK lanes and pending publications are empty.
	 */
	[[nodiscard]] bool control_empty() const noexcept;
	/**
	 * @brief Observe complete channel retirement under the same quiescent contract.
	 *
	 * Foreign observers must not use this owner-state predicate.
	 *
	 * @return true when every channel-owned transport/completion state is empty.
	 */
	[[nodiscard]] bool empty() const noexcept;

    private:
	friend class worker_boundary_receiver;
	friend class worker_boundary_sender;

	/** @return true when no published CUT remains in receiver-polled transport. */
	[[nodiscard]] bool cut_lane_empty() const noexcept;
	/** @return true when no published ACK remains in sender-polled transport. */
	[[nodiscard]] bool ack_lane_empty() const noexcept;

	/** @brief Fixed sender-publication field order. */
	enum sender_publication_field : std::size_t {
		SENDER_RUNTIME_GENERATION = 0,	///< Exact materialized generation.
		SENDER_BOUNDARY_INDEX,		///< Exact compact boundary identity.
		SENDER_DATA_SEQUENCE,		///< Successful DATA enqueue sequence.
		SENDER_BACKPRESSURE_EVENTS,	///< Full DATA publication attempts.
		SENDER_PENDING_CUT_EPOCH,	///< Pending CUT epoch, or zero.
		SENDER_PENDING_CUT_SEQUENCE,	///< Pending CUT sequence, or zero.
	};

	/** @brief Fixed receiver-publication field order. */
	enum receiver_publication_field : std::size_t {
		RECEIVER_RUNTIME_GENERATION = 0,  ///< Exact materialized generation.
		RECEIVER_BOUNDARY_INDEX,	  ///< Exact compact boundary identity.
		RECEIVER_DATA_SEQUENCE,		  ///< Completed DATA dequeue sequence.
		RECEIVER_PENDING_ACK_EPOCH,	  ///< Pending ACK epoch, or zero.
		RECEIVER_PENDING_ACK_SEQUENCE,	  ///< Pending ACK sequence, or zero.
	};

	static constexpr std::size_t SENDER_PUBLICATION_FIELD_COUNT =
		SENDER_PENDING_CUT_SEQUENCE + 1u;  ///< Exact sender payload width.
	static constexpr std::size_t RECEIVER_PUBLICATION_FIELD_COUNT =
		RECEIVER_PENDING_ACK_SEQUENCE + 1u;		 ///< Exact receiver payload width.
	static constexpr std::size_t OBSERVATION_ATTEMPTS = 8u;	 ///< Bounded coherent-read attempts.
	static_assert(SENDER_PUBLICATION_FIELD_COUNT == boundary_epoch_worker_slab::SENDER_PUBLICATION_FIELD_COUNT,
		      "boundary sender publication field order must equal its worker-local storage");
	static_assert(RECEIVER_PUBLICATION_FIELD_COUNT == boundary_epoch_worker_slab::RECEIVER_PUBLICATION_FIELD_COUNT,
		      "boundary receiver publication field order must equal its worker-local storage");

	/**
	 * @brief Adopt complete empty DATA/control storage and immutable identity.
	 *
	 * @param facts Exact compact boundary descriptor.
	 * @param runtime_generation Exact nonzero materialized generation.
	 * @param data_ring Sole exact receiver-NUMA DATA owner.
	 * @param sender_slab Stable sender-worker storage owner.
	 * @param sender_slot_index Exact claimed outbound ordinal.
	 * @param sender_slot Exact claimed sender slot.
	 * @param receiver_slab Stable receiver-worker storage owner.
	 * @param receiver_slot_index Exact claimed inbound ordinal.
	 * @param receiver_slot Exact claimed receiver slot.
	 */
	boundary_epoch_channel(const common::compiled_transition_boundary &facts, uint64_t runtime_generation,
			       std::unique_ptr<numa_spsc_ring<packet_record *>> data_ring,
			       boundary_epoch_worker_slab &sender_slab, std::size_t sender_slot_index,
			       boundary_epoch_worker_slab::sender_slot &sender_slot,
			       boundary_epoch_worker_slab &receiver_slab, std::size_t receiver_slot_index,
			       boundary_epoch_worker_slab::receiver_slot &receiver_slot) noexcept;

	uint32_t boundary_index_{0};					 ///< Exact compact boundary identity.
	uint32_t from_stage_instance_index_{0};				 ///< Exact executable source endpoint.
	uint32_t to_stage_instance_index_{0};				 ///< Exact executable destination endpoint.
	uint32_t sender_worker_index_{0};				 ///< Sole DATA/CUT producer and ACK consumer.
	uint32_t receiver_worker_index_{0};				 ///< Sole DATA/CUT consumer and ACK producer.
	uint64_t runtime_generation_{0};				 ///< Exact materialized generation identity.
	int32_t data_ring_numa_node_{-1};				 ///< Exact receiver-local DATA placement.
	std::unique_ptr<numa_spsc_ring<packet_record *>> data_ring_;	 ///< Sole plan-sized DATA owner.
	boundary_epoch_worker_slab *sender_slab_{nullptr};		 ///< Stable sender-worker storage lifetime.
	std::size_t sender_slot_index_{0};				 ///< Exact claimed outbound ordinal.
	boundary_epoch_worker_slab::sender_slot *sender_slot_{nullptr};	 ///< Borrowed sender-local state.
	boundary_epoch_worker_slab *receiver_slab_{nullptr};		 ///< Stable receiver-worker storage lifetime.
	std::size_t receiver_slot_index_{0};				 ///< Exact claimed inbound ordinal.
	boundary_epoch_worker_slab::receiver_slot *receiver_slot_{nullptr};  ///< Borrowed receiver-local state.
};

static_assert(sizeof(packet_record *) == sizeof(void *), "boundary DATA must carry one machine-word pointer");
static_assert(std::is_trivially_copyable_v<packet_record *>, "boundary DATA pointers must be trivially copyable");

}  // namespace kinetum::dp
