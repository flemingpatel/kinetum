// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_boundary_receiver.hpp
 * @brief Exact receiver CUT drain, fan-in, and post-activation ACK policy.
 * @author Fleming Patel
 *
 * One packet worker owns one complete sorted inbound-boundary set. The owner
 * composes typed channel transport and the worker epoch ledger while retaining
 * only receiver policy. It never receives DATA, advances DATA sequences,
 * rotates execution state, or publishes a second progress channel.
 *
 * @par Thread Safety
 * Construction, policy claims, ledger binding, and destruction are externally
 * serialized. After binding, exactly one packet-worker thread calls mutable
 * methods. Foreign readers consume only coherent transition snapshots and
 * never access the owner-local policy or timing lines.
 *
 * @par Performance
 * CUT classification and ACK service are bounded per endpoint per worker turn
 * and run only during a transition. Fixed DATA receive does not call this
 * component and retains its existing packet-path instruction shape. Time is
 * sampled only after a complete CUT/data-drain batch or before a complete ACK
 * publication batch.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "src/common/status_or.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/boundary_epoch_receiver_types.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp
{

class worker_runtime_telemetry;

/**
 * @brief Sole receiver-policy owner for one compiled packet worker.
 *
 * @par Ownership
 * The object owns every receiver-policy claim and its immutable endpoint
 * projection. It borrows the exact channels and bound worker ledger; those
 * authorities must outlive it. Destruction requires no active receiver
 * generation or pending control ownership and retires policy before channel
 * claims may retire.
 */
class worker_boundary_receiver final {
    public:
	/**
	 * @brief Claim the complete exact inbound channel set before slab seal.
	 *
	 * @param worker_index Exact compact receiver-worker identity.
	 * @param runtime_generation Exact nonzero materialized generation.
	 * @param channels Strictly boundary-index-sorted complete inbound set.
	 * @return Unique unbound receiver owner or a fail-closed identity/claim status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_boundary_receiver>>
	create(uint32_t worker_index, uint64_t runtime_generation, std::span<boundary_epoch_channel *const> channels);

	/** @brief Reject copying because receiver policy claims are linear. */
	worker_boundary_receiver(const worker_boundary_receiver &) = delete;
	/** @brief Reject copy assignment because endpoint authority cannot be duplicated. */
	worker_boundary_receiver &operator=(const worker_boundary_receiver &) = delete;
	/** @brief Reject moving so kernel-held receiver ordinals remain stable. */
	worker_boundary_receiver(worker_boundary_receiver &&) = delete;
	/** @brief Reject move assignment so claimed policy storage cannot be replaced. */
	worker_boundary_receiver &operator=(worker_boundary_receiver &&) = delete;

	/** @brief Release only clean receiver-policy claims before channels retire. */
	~worker_boundary_receiver();

	/**
	 * @brief Bind the sole same-worker epoch ledger after cold construction.
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
	 * @brief Bind every inbound receiver to one fixed Bootstrap epoch.
	 *
	 * @param bootstrap_epoch Exact already activated worker epoch.
	 */
	void bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept;

	/**
	 * @brief Prove one exact receiver generation before any worker mutation.
	 * @param transition_generation Exact nonzero mutation generation.
	 * @param from_epoch Exact currently active epoch.
	 * @param to_epoch Exact greater target epoch, either not yet ledger-bound or
	 *        already bound by the same owner-side transaction.
	 * @return true only when every receiver policy and pending ACK owner is clean
	 *         and the ledger identity is exact. A queued CUT remains untrusted
	 *         until bounded service validates it after receiver binding.
	 */
	[[nodiscard]] bool preflight_begin_transition(uint64_t transition_generation, uint64_t from_epoch,
						      uint64_t to_epoch) const noexcept;

	/**
	 * @brief Begin one exact receiver generation without consuming a CUT.
	 *
	 * @param transition_generation Exact nonzero mutation-generation identity.
	 * @param from_epoch Exact currently active epoch.
	 * @param to_epoch Exact greater bound future epoch.
	 * @return true for a new generation; false for an exact active retry while
	 *         the ledger still retains the pre-activation identity.
	 */
	[[nodiscard]] bool begin_transition(uint64_t transition_generation, uint64_t from_epoch,
					    uint64_t to_epoch) noexcept;

	/**
	 * @brief Consume at most one CUT and service at most one pending ACK per edge.
	 *
	 * Exact duplicate CUTs are counted. Every conflicting, stale, skipped,
	 * malformed, or unrelated record terminates. Sequence progress is classified
	 * solely by `classify_sequence_cut()`.
	 */
	void service_control() noexcept;

	/**
	 * @brief Refresh every accepted pending CUT after bounded old-work drain.
	 *
	 * This method consumes no control record and retries no ACK. It applies the
	 * sole sequence classifier to accepted endpoints, takes one post-work clock
	 * sample for the complete endpoint batch, and stamps newly observed and
	 * newly drained CUT edges from that one sample. One worker turn therefore
	 * performs at most one receiver timing sample and one control-lane operation
	 * per edge.
	 */
	void refresh_cut_progress() noexcept;

	/**
	 * @brief Prove exact inbound fan-in and zero old owner credit.
	 *
	 * A zero-inbound participant is vacuously drained only after source admission
	 * names the target epoch. Region aggregate state is not consulted.
	 *
	 * @return true when local activation may be preflighted.
	 */
	[[nodiscard]] bool activation_ready() const noexcept;

	/**
	 * @brief Mark complete local activation, then submit one exact ACK per edge.
	 *
	 * The ledger must already have promoted @p to_epoch. Every receiver line is
	 * marked ACK_PENDING before the first channel submission, so no ACK can make
	 * a partially switched worker externally visible.
	 *
	 * @param transition_generation Exact active receiver generation.
	 * @param to_epoch Exact newly active epoch.
	 */
	void acknowledge_activation(uint64_t transition_generation, uint64_t to_epoch) noexcept;

	/**
	 * @brief End receiver-local service after every exact ACK is published.
	 *
	 * @param transition_generation Exact active receiver generation.
	 */
	void complete_receiver_transition(uint64_t transition_generation) noexcept;

	/** @return true while one receiver generation still needs service. */
	[[nodiscard]] bool transition_active() const noexcept;
	/** @return true when all exact inbound CUTs are fully drained. */
	[[nodiscard]] bool all_cuts_drained() const noexcept;
	/** @return true after all exact ACKs have transferred to channel ownership. */
	[[nodiscard]] bool all_acks_published() const noexcept;
	/** @return Number of exact inbound receiver endpoints. */
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
	/** @return Exact active receiver generation, or zero before first begin. */
	[[nodiscard]] uint64_t transition_generation() const noexcept;
	/** @return Exact retained transition-from epoch, or zero before first begin. */
	[[nodiscard]] uint64_t transition_from_epoch() const noexcept;
	/** @return Exact retained transition-to epoch, or zero before first begin. */
	[[nodiscard]] uint64_t transition_to_epoch() const noexcept;

	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Exact boundary identity for @p receiver_ordinal.
	 */
	[[nodiscard]] uint32_t boundary_index(uint32_t receiver_ordinal) const noexcept;
	/**
	 * @brief Verify one ordinal borrows an exact boundary channel object.
	 *
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @param channel Candidate immutable channel identity.
	 * @return true only when the ordinal owns that exact channel address.
	 */
	[[nodiscard]] bool owns_boundary_channel(uint32_t receiver_ordinal,
						 const boundary_epoch_channel &channel) const noexcept;
	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Exact owner-local receiver phase.
	 */
	[[nodiscard]] boundary_epoch_receiver_phase phase(uint32_t receiver_ordinal) const noexcept;
	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Exact epoch admitted by this receiver line.
	 */
	[[nodiscard]] uint64_t active_epoch(uint32_t receiver_ordinal) const noexcept;
	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Accepted exact CUT, or the zero record while absent.
	 */
	[[nodiscard]] boundary_epoch_cut accepted_cut(uint32_t receiver_ordinal) const noexcept;
	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Exact duplicate-CUT count for the active/last generation.
	 */
	[[nodiscard]] uint64_t duplicate_cut_count(uint32_t receiver_ordinal) const noexcept;
	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Exact receiver-policy storage NUMA node.
	 */
	[[nodiscard]] int32_t policy_numa_node(uint32_t receiver_ordinal) const noexcept;
	/**
	 * @brief Read one coherent Bootstrap baseline or receiver transition-edge proof.
	 *
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @param[out] out Observer-owned value updated only on exact publication.
	 * @return Availability or a coherent identity/state violation; failure leaves @p out unchanged.
	 */
	[[nodiscard]] publication_read_result
	try_read_transition(uint32_t receiver_ordinal, boundary_receiver_transition_snapshot &out) const noexcept;

    private:
	/** @brief Exact receiver-policy proof field order. */
	enum policy_publication_field : std::size_t {
		POLICY_RUNTIME_GENERATION = 0,
		POLICY_BOUNDARY_INDEX,
		POLICY_TRANSITION_GENERATION,
		POLICY_FROM_EPOCH,
		POLICY_TO_EPOCH,
		POLICY_CUT_SEQUENCE,
		POLICY_ACK_PUBLISHED,
		POLICY_PHASE,
		POLICY_CUT_OBSERVED_NS,
		POLICY_CUT_DRAINED_NS,
		POLICY_ACTIVATION_NS,
		POLICY_ACK_PUBLISHED_NS,
		POLICY_DUPLICATE_CUT_COUNT,
		POLICY_ACTIVE_EPOCH,
		POLICY_PUBLICATION_FIELD_COUNT,
	};
	static_assert(POLICY_PUBLICATION_FIELD_COUNT ==
			      boundary_epoch_worker_slab::RECEIVER_POLICY_PUBLICATION_FIELD_COUNT,
		      "receiver policy publication field count must equal slab storage");
	/** @brief Bounded coherent-reader attempts. */
	static constexpr std::size_t OBSERVATION_ATTEMPTS = 4u;

	/** @brief One immutable transport binding plus its borrowed policy line. */
	struct endpoint {
		uint32_t boundary_index{0};		   ///< Exact compact boundary identity.
		boundary_epoch_channel *channel{nullptr};  ///< Sole transport authority.
		boundary_epoch_worker_slab::receiver_policy_state *policy{nullptr};  ///< Owner-local facts.
		boundary_epoch_worker_slab::receiver_timing_state *timing{nullptr};  ///< Transition-only timing facts.
		kinetum::algo::single_writer_snapshot<POLICY_PUBLICATION_FIELD_COUNT> *publication{
			nullptr};  ///< One-shot coherent transition proof.
	};

	/**
	 * @brief Adopt validated immutable identity and endpoint bindings.
	 *
	 * @param worker_index Exact compact receiver-worker identity.
	 * @param runtime_generation Exact materialized generation.
	 * @param endpoints Strictly sorted complete inbound endpoint set.
	 */
	worker_boundary_receiver(uint32_t worker_index, uint64_t runtime_generation,
				 std::vector<endpoint> endpoints) noexcept;
	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Exact mutable endpoint or terminate for a malformed ordinal.
	 */
	[[nodiscard]] endpoint &endpoint_(uint32_t receiver_ordinal) noexcept;
	/**
	 * @param receiver_ordinal Exact owner-local inbound ordinal.
	 * @return Exact immutable endpoint or terminate for a malformed ordinal.
	 */
	[[nodiscard]] const endpoint &endpoint_(uint32_t receiver_ordinal) const noexcept;
	/**
	 * @brief Prove begin cleanliness without consuming an asynchronously arrived CUT.
	 *
	 * @param entry Candidate exact receiver endpoint.
	 * @return true when one line may begin another generation.
	 *
	 * CUT-lane occupancy is deliberately excluded: the remote sender may publish
	 * the exact new-generation CUT before this receiver observes the shared
	 * transition command. The bound receiver validates that record later.
	 */
	[[nodiscard]] static bool clean_for_begin_(const endpoint &entry) noexcept;
	/**
	 * @param entry Candidate exact receiver endpoint.
	 * @return true when one line carries no live policy facts.
	 */
	[[nodiscard]] static bool policy_unbound_(const endpoint &entry) noexcept;
	/**
	 * @brief Apply the sole sequence-cut classifier to one accepted CUT.
	 *
	 * @param entry Exact endpoint whose accepted CUT is authoritative.
	 * @return true only when this call first reaches the accepted CUT.
	 */
	[[nodiscard]] bool refresh_cut_progress_(endpoint &entry) noexcept;
	/**
	 * @brief Publish one Bootstrap baseline or exact ACK-published edge proof.
	 *
	 * @param entry Exact receiver endpoint whose publication line is owned here.
	 */
	void publish_transition_(endpoint &entry) noexcept;
	/**
	 * @brief Record one typed fault before the owning path fails closed.
	 * @param entry Exact receiver endpoint involved in the violation.
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
	std::vector<endpoint> endpoints_;		///< Stable sorted inbound endpoint table.
	worker_epoch_ledger *ledger_{nullptr};		///< Bound sole worker credit authority.
	worker_runtime_telemetry *telemetry_{nullptr};	///< Sole owner-local protocol counters.
	epoch_protocol_fault_latch *faults_{nullptr};	///< Process-generation first-fault authority.
	uint64_t bootstrap_epoch_{0};			///< Exact fixed epoch after owner binding.
	uint64_t transition_generation_{0};		///< Current/last exact generation.
	uint64_t transition_from_epoch_{0};		///< Current/last exact old epoch.
	uint64_t transition_to_epoch_{0};		///< Current/last exact target epoch.
	bool transition_active_{false};			///< Whether CUT/ACK service remains required.
	bool activation_acknowledged_{false};		///< Whether complete local activation was marked.
};

}  // namespace kinetum::dp
