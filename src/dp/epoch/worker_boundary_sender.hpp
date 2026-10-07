// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_boundary_sender.hpp
 * @brief Exact sender sealing, ACK gating, and future-output ownership.
 * @author Fleming Patel
 *
 * One packet worker owns one complete sorted outbound-boundary set. The owner
 * composes channel transport, sender-NUMA future holds, and the worker epoch
 * ledger without copying any of their state machines. Fixed execution and an
 * exact post-ACK gate use the same OPEN path; no packet-worker caller bypasses
 * this authority to reach sender-side DATA, CUT, ACK-consume, or hold
 * operations directly.
 *
 * @par Thread Safety
 * Construction, policy-slot claims, ledger binding, and destruction are
 * externally serialized. After ledger binding, exactly one packet-worker
 * thread calls every mutable method. Foreign readers consume only coherent
 * transition snapshots and never access the writable policy or timing lines.
 *
 * @par Performance
 * Packet routing is O(1), allocation-free, lock-free, clock-free work over one
 * pre-resolved ordinal and one owner-local policy cache line. Transition
 * control visits each owned endpoint at most once per turn and samples time
 * only for complete CUT-publication or ACK-consumption batches. Held-output
 * service visits at most the caller-supplied bounded work budget and performs
 * no queue scan.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "src/common/status_or.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/boundary_epoch_sender_types.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp
{

class worker_runtime_telemetry;

/**
 * @brief Sole sender-policy owner for one compiled packet worker.
 *
 * @par Ownership
 * The object owns every sender-policy claim and its immutable endpoint
 * projection. It borrows the exact channels, future holds, and bound ledger;
 * those authorities must outlive it. Destruction requires no active sender
 * generation or held/control ownership and retires policy before channel
 * claims may retire.
 */
class worker_boundary_sender final {
    public:
	/**
	 * @brief Claim the complete exact outbound channel/hold set before slab seal.
	 *
	 * Inputs must be strictly sorted by boundary index and contain only the
	 * exact worker's outbound ownership. Construction claims one policy line in
	 * each channel's sender slab but binds no epoch or ledger.
	 *
	 * @param worker_index Exact compact sender-worker identity.
	 * @param runtime_generation Exact nonzero materialized generation.
	 * @param channels Complete exact outbound channel set.
	 * @param holds Complete matching outbound future-hold set.
	 * @return Unique unbound sender owner or a fail-closed identity/claim status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_boundary_sender>>
	create(uint32_t worker_index, uint64_t runtime_generation, std::span<boundary_epoch_channel *const> channels,
	       std::span<boundary_future_output_hold *const> holds);

	/** @brief Reject copying because sender policy and policy-slot claims are linear. */
	worker_boundary_sender(const worker_boundary_sender &) = delete;
	/** @brief Reject copy assignment because endpoint authority cannot be duplicated. */
	worker_boundary_sender &operator=(const worker_boundary_sender &) = delete;
	/** @brief Reject moving so kernel-held sender ordinals remain stable. */
	worker_boundary_sender(worker_boundary_sender &&) = delete;
	/** @brief Reject move assignment so claimed policy storage cannot be replaced. */
	worker_boundary_sender &operator=(worker_boundary_sender &&) = delete;

	/** @brief Release only clean policy claims before the channels retire. */
	~worker_boundary_sender();

	/**
	 * @brief Bind the sole worker ledger after cold kernel construction.
	 *
	 * @param ledger Exact same-worker, same-generation credit authority.
	 * @return OK after the first exact binding; otherwise no state change.
	 */
	[[nodiscard]] common::status bind_ledger(worker_epoch_ledger &ledger);

	/**
	 * @brief Bind the sole same-worker protocol counter and process fault latch.
	 * @param telemetry Exact owner-worker telemetry bank authority.
	 * @param faults Process-generation write-once safety-fault authority.
	 * @return OK after the first exact binding; otherwise no mutation.
	 */
	[[nodiscard]] common::status bind_protocol_faults(worker_runtime_telemetry &telemetry,
							  epoch_protocol_fault_latch &faults) noexcept;

	/**
	 * @brief Bind every outbound sender to one fixed Bootstrap epoch.
	 *
	 * The owner ledger must already be bound to the same exact active/source
	 * epoch. This method allocates, publishes, and transports nothing.
	 *
	 * @param bootstrap_epoch Exact already activated owner-worker epoch.
	 */
	void bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept;

	/**
	 * @brief Prove one exact sender generation before any worker mutation.
	 * @param transition_generation Exact nonzero mutation generation.
	 * @param from_epoch Exact currently open epoch.
	 * @param to_epoch Exact greater target epoch, either not yet ledger-bound or
	 *        already bound by the same owner-side transaction.
	 * @return true only when every sender policy, hold, pending record, and ACK
	 *         lane is clean and the ledger identity is exact.
	 */
	[[nodiscard]] bool preflight_begin_transition(uint64_t transition_generation, uint64_t from_epoch,
						      uint64_t to_epoch) const noexcept;

	/**
	 * @brief Begin one exact sender generation without sealing an outbound edge.
	 *
	 * The ledger must already own @p from_epoch as active and @p to_epoch as its
	 * exact future slot. An exact duplicate active generation is idempotent;
	 * every overlap or nonexact reuse terminates.
	 *
	 * @param transition_generation Exact nonzero mutation-generation identity.
	 * @param from_epoch Exact currently open epoch.
	 * @param to_epoch Exact greater target epoch.
	 * @return true when a new generation was applied; false for an exact active
	 *         retry while the ledger still retains the pre-activation identity.
	 */
	[[nodiscard]] bool begin_transition(uint64_t transition_generation, uint64_t from_epoch,
					    uint64_t to_epoch) noexcept;

	/**
	 * @brief Route one cross-worker packet through exact sender policy.
	 *
	 * TRANSFERRED means channel publication and enqueue-sequence advancement
	 * completed before this method retired the worker credit. HELD means the
	 * hold owns the pointer while the ledger credit remains. BACKPRESSURED
	 * changes neither caller reservation nor ownership.
	 *
	 * @param sender_ordinal Pre-resolved worker-local outbound ordinal.
	 * @param record Nonnull exact packet record carrying one live worker credit.
	 * @return Exact ownership disposition.
	 */
	[[nodiscard]] boundary_epoch_send_result try_send(uint32_t sender_ordinal, packet_record *record) noexcept;

	/**
	 * @brief Seal every outbound edge after exact old worker-credit drain.
	 *
	 * The caller additionally owns the inbound-seal proof. This method first
	 * requires exact target source admission so zero old credit is stable, then
	 * preflights the complete sender set, captures all channel sequences, marks
	 * every edge sealed, and attempts one CUT per edge without interleaved packet
	 * work.
	 *
	 * @return true after every sender sealed; false with no state change while
	 *         old source admission or old worker credits remain.
	 */
	[[nodiscard]] bool try_seal_after_old_work_drained() noexcept;

	/** @brief Attempt each pending CUT and consume at most one ACK per edge. */
	void service_control() noexcept;

	/**
	 * @brief Release a bounded round-robin prefix of exact held output.
	 *
	 * A selected endpoint drains until DATA is full, its hold is empty, or the
	 * complete attempt budget expires. The cursor advances before that drain, so
	 * a budget-ending endpoint cannot monopolize the next turn. Each successful
	 * release publishes DATA and advances its sequence, removes the exact same
	 * FIFO pointer from the hold, then retires the worker credit. Gated/empty
	 * endpoint visits and failed DATA pushes also consume one attempt.
	 *
	 * @param maximum_attempts Owner-turn work budget in the closed range
	 *        1..`PACKET_MAX_BURST_SIZE`.
	 * @return Number of held records transferred in this turn.
	 */
	[[nodiscard]] std::size_t service_held_output(std::size_t maximum_attempts) noexcept;

	/**
	 * @brief Mark the sender-local generation complete after every gate opens.
	 *
	 * This retires no global coordinator state and authorizes no later
	 * transition. It only ends per-turn sender service after all exact ACKs,
	 * controls, and held pointers are gone.
	 *
	 * @param transition_generation Exact active sender generation.
	 */
	void complete_sender_transition(uint64_t transition_generation) noexcept;

	/** @brief Publish every owned channel's coherent sender transport once. */
	void publish_transport() noexcept;

	/** @brief Close every clean fixed/open DATA producer exactly once. */
	void close_for_shutdown() noexcept;

	/** @return true while one sender generation still needs service. */
	[[nodiscard]] bool transition_active() const noexcept;
	/** @return true after the complete outbound set passed one atomic seal. */
	[[nodiscard]] bool outbound_sealed() const noexcept;
	/** @return true when every exact ACK opened its gate for the active target. */
	[[nodiscard]] bool all_gates_open() const noexcept;
	/** @return true when every exact outbound CUT has entered channel ownership. */
	[[nodiscard]] bool all_cuts_published() const noexcept;
	/** @return true when no future hold owns a packet pointer. */
	[[nodiscard]] bool packet_ownership_empty() const noexcept;
	/** @return Number of exact outbound sender endpoints. */
	[[nodiscard]] std::size_t size() const noexcept;
	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;
	/** @return Exact materialized runtime generation. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;
	/**
	 * @brief Verify this owner borrowed one exact worker ledger.
	 *
	 * @param ledger Candidate immutable ledger identity.
	 * @return true only for the exact ledger bound before Bootstrap.
	 */
	[[nodiscard]] bool owns_ledger(const worker_epoch_ledger &ledger) const noexcept;
	/** @return Exact active/last transition generation, or zero before first begin. */
	[[nodiscard]] uint64_t transition_generation() const noexcept;
	/** @return Exact active/last transition-from epoch, or zero before first begin. */
	[[nodiscard]] uint64_t transition_from_epoch() const noexcept;
	/** @return Exact active/last transition-to epoch, or zero before first begin. */
	[[nodiscard]] uint64_t transition_to_epoch() const noexcept;

	/**
	 * @brief Resolve one boundary to its direct worker-local sender ordinal.
	 *
	 * @param boundary_index Exact compact global boundary identity.
	 * @return Direct ordinal, or an out-of-range status when not owned.
	 */
	[[nodiscard]] common::status_or<uint32_t> sender_ordinal(uint32_t boundary_index) const;

	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact boundary identity for @p sender_ordinal.
	 */
	[[nodiscard]] uint32_t boundary_index(uint32_t sender_ordinal) const noexcept;
	/**
	 * @brief Verify one ordinal borrows an exact boundary channel object.
	 *
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @param channel Candidate immutable channel identity.
	 * @return true only when the ordinal owns that exact channel address.
	 */
	[[nodiscard]] bool owns_boundary_channel(uint32_t sender_ordinal,
						 const boundary_epoch_channel &channel) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact owner-local phase for @p sender_ordinal.
	 */
	[[nodiscard]] boundary_epoch_sender_phase phase(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact currently open epoch for @p sender_ordinal.
	 */
	[[nodiscard]] uint64_t open_epoch(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact retained transition-from epoch for @p sender_ordinal.
	 */
	[[nodiscard]] uint64_t from_epoch(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact retained transition-to epoch for @p sender_ordinal.
	 */
	[[nodiscard]] uint64_t to_epoch(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact captured cut sequence for @p sender_ordinal.
	 */
	[[nodiscard]] uint64_t cut_sequence(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact duplicate-ACK count for @p sender_ordinal.
	 */
	[[nodiscard]] uint64_t duplicate_ack_count(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Current held pointer population for @p sender_ordinal.
	 */
	[[nodiscard]] std::size_t held_size(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact plan-owned future-hold capacity for @p sender_ordinal.
	 */
	[[nodiscard]] std::size_t hold_capacity(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact sender-policy storage NUMA node for @p sender_ordinal.
	 */
	[[nodiscard]] int32_t policy_numa_node(uint32_t sender_ordinal) const noexcept;
	/**
	 * @brief Read one coherent Bootstrap baseline or sender transition-edge proof.
	 *
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @param[out] out Observer-owned value updated only on exact publication.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_transition(uint32_t sender_ordinal, boundary_sender_transition_snapshot &out) const noexcept;

    private:
	/** @brief Exact sender-policy proof field order. */
	enum policy_publication_field : std::size_t {
		POLICY_RUNTIME_GENERATION = 0,
		POLICY_BOUNDARY_INDEX,
		POLICY_TRANSITION_GENERATION,
		POLICY_FROM_EPOCH,
		POLICY_TO_EPOCH,
		POLICY_CUT_SEQUENCE,
		POLICY_ACK_OBSERVED,
		POLICY_PHASE,
		POLICY_CUT_PUBLISHED_NS,
		POLICY_ACK_OBSERVED_NS,
		POLICY_DUPLICATE_ACK_COUNT,
		POLICY_OPEN_EPOCH,
		POLICY_PUBLICATION_FIELD_COUNT,
	};
	static_assert(POLICY_PUBLICATION_FIELD_COUNT ==
			      boundary_epoch_worker_slab::SENDER_POLICY_PUBLICATION_FIELD_COUNT,
		      "sender policy publication field count must equal slab storage");
	/** @brief Bounded coherent-reader attempts. */
	static constexpr std::size_t OBSERVATION_ATTEMPTS = 4u;

	/** @brief Exact immutable worker/generation identity adopted together. */
	struct sender_identity {
		uint32_t worker_index{0};	 ///< Exact compact sender-worker identity.
		uint64_t runtime_generation{0};	 ///< Exact materialized generation.
	};

	/** @brief One immutable transport binding plus its borrowed policy line. */
	struct endpoint {
		uint32_t boundary_index{0};					   ///< Exact compact boundary identity.
		boundary_epoch_channel *channel{nullptr};			   ///< Sole transport authority.
		boundary_future_output_hold *hold{nullptr};			   ///< Sole future-pointer owner.
		boundary_epoch_worker_slab::sender_policy_state *policy{nullptr};  ///< Owner-local facts.
		boundary_epoch_worker_slab::sender_timing_state *timing{nullptr};  ///< Transition-only timing facts.
		kinetum::algo::single_writer_snapshot<POLICY_PUBLICATION_FIELD_COUNT> *publication{
			nullptr};  ///< One-shot coherent transition proof.
	};

	/**
	 * @brief Adopt already validated immutable endpoint bindings.
	 *
	 * @param identity Exact compact worker and materialized generation.
	 * @param endpoints Strictly sorted complete outbound endpoint set.
	 */
	worker_boundary_sender(sender_identity identity, std::vector<endpoint> endpoints) noexcept;

	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact mutable endpoint or terminate for a malformed ordinal.
	 */
	[[nodiscard]] endpoint &endpoint_(uint32_t sender_ordinal) noexcept;
	/**
	 * @param sender_ordinal Exact owner-local outbound ordinal.
	 * @return Exact immutable endpoint or terminate for a malformed ordinal.
	 */
	[[nodiscard]] const endpoint &endpoint_(uint32_t sender_ordinal) const noexcept;
	/**
	 * @param entry Candidate exact sender endpoint.
	 * @return true when @p entry is clean and may begin another generation.
	 */
	[[nodiscard]] static bool clean_for_begin_(const endpoint &entry) noexcept;
	/**
	 * @param entry Candidate exact sender endpoint.
	 * @return true when @p entry carries no live policy facts.
	 */
	[[nodiscard]] static bool policy_unbound_(const endpoint &entry) noexcept;
	/**
	 * @brief Publish one Bootstrap baseline or exact ACK-observed edge proof.
	 *
	 * @param entry Exact sender endpoint whose publication line is owned here.
	 */
	void publish_transition_(endpoint &entry) noexcept;
	/**
	 * @brief Record one typed fault before the owning path fails closed.
	 * @param entry Exact sender endpoint involved in the violation.
	 * @param code Violated protocol invariant.
	 * @param disposition Required disposition of the affected ownership.
	 * @param observed_epoch Packet or control epoch observed at the failure.
	 * @param expected_value Expected sequence, count, or identity selected by @p code.
	 * @param observed_value Actual value that violated that expectation.
	 */
	void record_fault_(const endpoint &entry, epoch_protocol_fault_code code,
			   epoch_protocol_fault_disposition disposition, uint64_t observed_epoch,
			   uint64_t expected_value, uint64_t observed_value) noexcept;

	uint32_t worker_index_{0};			///< Exact compact worker identity.
	uint64_t runtime_generation_{0};		///< Exact materialized generation.
	std::vector<endpoint> endpoints_;		///< Stable sorted owner-local endpoint table.
	worker_epoch_ledger *ledger_{nullptr};		///< Bound sole worker credit authority.
	worker_runtime_telemetry *telemetry_{nullptr};	///< Sole owner-local protocol counters.
	epoch_protocol_fault_latch *faults_{nullptr};	///< Process-generation first-fault authority.
	std::size_t round_robin_cursor_{0};		///< Next held-output service ordinal.
	uint64_t bootstrap_epoch_{0};			///< Exact fixed epoch after owner binding.
	uint64_t transition_generation_{0};		///< Current/last exact generation.
	uint64_t transition_from_epoch_{0};		///< Current/last exact old epoch.
	uint64_t transition_to_epoch_{0};		///< Current/last exact target epoch.
	bool transition_active_{false};			///< Whether control/hold service remains required.
	bool outbound_sealed_{false};			///< Complete sender-set seal applied for the generation.
};

}  // namespace kinetum::dp
