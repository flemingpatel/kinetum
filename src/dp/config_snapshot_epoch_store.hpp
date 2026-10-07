// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file config_snapshot_epoch_store.hpp
 * @brief Exact two-slot ownership for canonical configuration snapshots.
 * @author Fleming Patel
 *
 * The store composes `exact_epoch_slot_table` with immutable canonical
 * ConfigSnapshot artifacts. It owns no epoch allocator or history policy:
 * callers supply exact nonzero epochs, gaps are valid, and an unknown epoch
 * never selects a nearby artifact. One published snapshot and either one
 * prepared or one retained snapshot are the only representable live layouts.
 *
 * Retirement is a linear store-bound protocol. A move-only claim withdraws
 * one exact artifact while its slot remains tagged. The issuing store must
 * either restore that artifact or complete the exact slot retirement;
 * destroying an unresolved claim is process-fatal.
 *
 * @par Thread Safety
 * This store is not internally synchronized. The transition coordinator is
 * its sole reader and writer. A borrowed artifact remains valid only until the
 * next coordinator mutation involving that slot. Packet workers and foreign
 * telemetry readers must consume separately published immutable views rather
 * than reading this store.
 *
 * @par Performance
 * Store lifecycle operations are cold-path and inspect at most two slots.
 * Staging and artifact construction may allocate before slot publication.
 * Publication, exact lookup, claim transfer, restoration, and completion are
 * bounded O(1) operations with no lock, map, shared ownership, or implicit
 * epoch search.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "gen/kinetum/control/v1/control.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/sha256_digest.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/exact_slot_table.hpp"

namespace kinetum::dp
{

/**
 * @brief Immutable canonical snapshot plus its exact raw validation hash.
 *
 * Construction accepts only the shared canonical-content result. The factory
 * delegates to the common plan-independent terminal validator, which parses
 * and reserializes exact bytes, rejects unknown fields and invalid enums,
 * proves module ordering/blob hashes, recomputes the self-hash-free preimage,
 * and binds both embedded and raw identities to that result.
 * Plan-dependent module-set normalization remains exclusively owned by
 * `canonicalize_config_snapshot()` and is not reimplemented here.
 */
class config_snapshot_artifact {
    public:
	/**
	 * @brief Construct one immutable artifact from shared canonical output.
	 *
	 * @param canonical Canonical bytes and validation hash produced by the
	 *        shared content-identity authority.
	 * @return Immutable artifact, or an exact parse, representation, identity,
	 *         size, or allocation failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<const config_snapshot_artifact>>
	create(const kinetum::common::canonical_config_snapshot &canonical);

	config_snapshot_artifact(const config_snapshot_artifact &) = delete;
	config_snapshot_artifact &operator=(const config_snapshot_artifact &) = delete;
	config_snapshot_artifact(config_snapshot_artifact &&) = delete;
	config_snapshot_artifact &operator=(config_snapshot_artifact &&) = delete;

	/**
	 * @brief Borrow the immutable canonical snapshot.
	 *
	 * @return Snapshot owned by this artifact.
	 */
	[[nodiscard]] const kinetum::control::v1::ConfigSnapshot &snapshot() const noexcept;

	/**
	 * @brief Borrow the exact raw canonical validation hash.
	 *
	 * @return Fixed-width SHA-256 digest owned by this artifact.
	 */
	[[nodiscard]] const kinetum::common::sha256_digest &validation_hash() const noexcept;

    private:
	/**
	 * @brief Construct one already validated immutable artifact.
	 *
	 * @param snapshot Canonical snapshot whose ownership transfers into the
	 *        immutable artifact.
	 * @param validation_hash Exact raw identity bound to @p snapshot.
	 */
	config_snapshot_artifact(kinetum::control::v1::ConfigSnapshot snapshot,
				 kinetum::common::sha256_digest validation_hash) noexcept;

	const kinetum::control::v1::ConfigSnapshot snapshot_;	///< Canonical immutable snapshot.
	const kinetum::common::sha256_digest validation_hash_;	///< Exact raw canonical identity.
};

class config_snapshot_epoch_store;

/**
 * @brief Move-only claim over one exact snapshot slot and artifact.
 *
 * A claim remains bound to its issuing store, nonzero nonce, fixed slot,
 * original lifecycle state, and exact epoch. It exposes only a read-only
 * artifact borrow. The issuing coordinator must restore or complete it before
 * destruction.
 */
class config_snapshot_retirement_claim {
    public:
	config_snapshot_retirement_claim(const config_snapshot_retirement_claim &) = delete;
	config_snapshot_retirement_claim &operator=(const config_snapshot_retirement_claim &) = delete;
	/**
	 * @brief Transfer the sole claim and invalidate the moved-from object.
	 *
	 * @param other Live claim whose sole ownership transfers here.
	 */
	config_snapshot_retirement_claim(config_snapshot_retirement_claim &&other) noexcept;
	config_snapshot_retirement_claim &operator=(config_snapshot_retirement_claim &&) = delete;
	/** @brief Destroy a resolved claim; an unresolved claim terminates. */
	~config_snapshot_retirement_claim();

	/** @return Nonzero store-local claim identity, or zero after resolution. */
	[[nodiscard]] uint64_t claim_id() const noexcept;
	/** @return Exact claimed epoch, or zero after resolution. */
	[[nodiscard]] uint64_t epoch() const noexcept;
	/** @return RETAINED or PUBLISHED for a live claim; EMPTY after resolution. */
	[[nodiscard]] epoch_slot_state slot_state() const noexcept;
	/** @return Read-only claimed artifact, or null after move/resolution. */
	[[nodiscard]] const config_snapshot_artifact *artifact() const noexcept;

    private:
	friend class config_snapshot_epoch_store;

	/**
	 * @brief Construct one claim after its issuing store records the nonce.
	 *
	 * @param owner Exact issuing store, which must outlive the claim.
	 * @param claim_id Nonzero store-local claim identity.
	 * @param slot_index Exact claimed slot.
	 * @param slot_state Original RETAINED or PUBLISHED lifecycle state.
	 * @param epoch Exact epoch retained in the claimed slot.
	 * @param artifact Sole immutable artifact ownership withdrawn from the slot.
	 */
	config_snapshot_retirement_claim(const config_snapshot_epoch_store *owner, uint64_t claim_id,
					 std::size_t slot_index, epoch_slot_state slot_state, uint64_t epoch,
					 std::unique_ptr<const config_snapshot_artifact> artifact) noexcept;
	/** @brief Invalidate this claim after exact store resolution. */
	void resolve_() noexcept;

	const config_snapshot_epoch_store *owner_{nullptr};	    ///< Exact issuing store.
	uint64_t claim_id_{0};					    ///< Nonzero store-local nonce.
	std::size_t slot_index_{INVALID_EPOCH_SLOT_INDEX};	    ///< Exact claimed slot.
	epoch_slot_state slot_state_{epoch_slot_state::EMPTY};	    ///< Original exact slot state.
	uint64_t epoch_{0};					    ///< Exact claimed epoch.
	std::unique_ptr<const config_snapshot_artifact> artifact_;  ///< Withdrawn immutable artifact.
};

/**
 * @brief Own exactly two epoch-tagged canonical configuration snapshots.
 *
 * The store delegates all slot lifecycle legality to
 * `exact_epoch_slot_table`. It adds only artifact ownership, one explicit
 * active-slot index, and one linear retirement claimant. No state other than
 * EMPTY, PREPARED, PUBLISHED, and RETAINED is representable.
 */
class config_snapshot_epoch_store {
    public:
	/** @brief Construct the exact EMPTY/EMPTY store. */
	config_snapshot_epoch_store() noexcept = default;
	config_snapshot_epoch_store(const config_snapshot_epoch_store &) = delete;
	config_snapshot_epoch_store &operator=(const config_snapshot_epoch_store &) = delete;
	config_snapshot_epoch_store(config_snapshot_epoch_store &&) = delete;
	config_snapshot_epoch_store &operator=(config_snapshot_epoch_store &&) = delete;
	/** @brief Destroy only after every slot and claim has been resolved. */
	~config_snapshot_epoch_store();

	/**
	 * @brief Stage one exact immutable artifact as PREPARED.
	 *
	 * @param epoch Caller-allocated nonzero epoch. Gaps are valid.
	 * @param artifact Sole artifact ownership; moved only on success.
	 * @return OK after exact slot publication; failure leaves @p artifact owned
	 *         by the caller.
	 */
	[[nodiscard]] kinetum::common::status
	stage_prepared(uint64_t epoch, std::unique_ptr<const config_snapshot_artifact> &artifact) noexcept;

	/**
	 * @brief Preflight future staging/publication/claim before target ownership moves.
	 *
	 * @param from_epoch Exact sole published baseline.
	 * @param to_epoch Exact advancing target that remains caller-owned.
	 * @return OK only when the empty slot and later retained-claim nonce are complete.
	 */
	[[nodiscard]] kinetum::common::status preflight_future_preparation(uint64_t from_epoch,
									   uint64_t to_epoch) const noexcept;

	/**
	 * @brief Discard one exact PREPARED artifact before publication.
	 *
	 * @param epoch Exact prepared epoch to abort.
	 * @return Recovered artifact ownership, or failure without mutation.
	 */
	[[nodiscard]] kinetum::common::status_or<std::unique_ptr<const config_snapshot_artifact>>
	discard_prepared(uint64_t epoch) noexcept;

	/**
	 * @brief Validate exact publication without changing store state.
	 *
	 * @param epoch Exact PREPARED epoch selected for publication.
	 * @return OK only when bounded publication can no longer fail while this
	 *         sole-owner store remains unchanged.
	 */
	[[nodiscard]] kinetum::common::status preflight_publish_prepared(uint64_t epoch) const noexcept;

	/**
	 * @brief Publish one exact PREPARED epoch and retain the prior publication.
	 *
	 * @param epoch Exact PREPARED epoch selected by the coordinator.
	 * @return OK after bounded metadata publication, or a preflight failure.
	 */
	[[nodiscard]] kinetum::common::status publish_prepared(uint64_t epoch) noexcept;

	/**
	 * @brief Preflight the exact post-activation retained-claim shape.
	 *
	 * This check runs before the irreversible commit edge. It proves publishing
	 * @p to_epoch will retain @p from_epoch and that the later claim nonce and
	 * artifact ownership are already representable.
	 *
	 * @param from_epoch Exact currently published epoch.
	 * @param to_epoch Exact currently prepared target epoch.
	 * @return OK only when later retained retirement has no undiscovered store failure.
	 */
	[[nodiscard]] kinetum::common::status preflight_future_retained(uint64_t from_epoch,
									uint64_t to_epoch) const noexcept;

	/** @return Exact published epoch, or zero before/after publication ownership. */
	[[nodiscard]] uint64_t active_epoch() const noexcept;
	/** @return Exact prepared epoch, or zero when no PREPARED slot exists. */
	[[nodiscard]] uint64_t prepared_epoch() const noexcept;
	/** @return Exact retained epoch, or zero when no RETAINED slot exists. */
	[[nodiscard]] uint64_t retained_epoch() const noexcept;

	/**
	 * @brief Borrow an artifact by exact epoch identity.
	 *
	 * @param epoch Exact requested epoch.
	 * @return Matching owned artifact, or null. No nearest/current fallback is
	 *         performed; an artifact withdrawn into a claim is not borrowed.
	 */
	[[nodiscard]] const config_snapshot_artifact *find_exact(uint64_t epoch) const noexcept;

	/** @return Exact active artifact, or null when no publication is owned. */
	[[nodiscard]] const config_snapshot_artifact *active_artifact() const noexcept;

	/**
	 * @brief Claim one RETAINED artifact after transition quiescence.
	 *
	 * @param epoch Exact retained epoch proved safe for retirement.
	 * @return Sole move-only claim, or failure without ownership transfer.
	 */
	[[nodiscard]] kinetum::common::status_or<config_snapshot_retirement_claim>
	claim_retained(uint64_t epoch) noexcept;

	/**
	 * @brief Revalidate one exact retained claim without ownership transfer.
	 *
	 * @param epoch Exact retained epoch proved reader-quiescent.
	 * @return OK only when `claim_retained()` is a bounded non-failing transfer
	 *         while this sole-owner store remains unchanged.
	 */
	[[nodiscard]] kinetum::common::status preflight_claim_retained(uint64_t epoch) const noexcept;

	/**
	 * @brief Claim the sole PUBLISHED artifact for quiescent shutdown.
	 *
	 * @param epoch Exact published epoch selected for final retirement.
	 * @return Sole move-only claim; the active index is withdrawn on success.
	 */
	[[nodiscard]] kinetum::common::status_or<config_snapshot_retirement_claim>
	claim_published_for_shutdown(uint64_t epoch) noexcept;

	/**
	 * @brief Restore an unresolved claim to its exact original slot.
	 *
	 * @param claim Current claim issued by this store.
	 * @return OK after restoration; failure leaves the claim unchanged.
	 */
	[[nodiscard]] kinetum::common::status restore_retirement(config_snapshot_retirement_claim &claim) noexcept;

	/**
	 * @brief Complete exact retirement and release the claimed artifact.
	 *
	 * @param claim Current claim issued by this store after external quiescence
	 *        and retirement obligations have completed.
	 * @return OK after clearing the exact slot; failure leaves the claim live.
	 */
	[[nodiscard]] kinetum::common::status complete_retirement(config_snapshot_retirement_claim &claim) noexcept;

	/**
	 * @brief Inspect one exact slot descriptor on the sole coordinator thread.
	 *
	 * @param slot_index Fixed index in [0, EXACT_EPOCH_SLOT_COUNT).
	 * @return Borrowed descriptor, or null for an invalid index.
	 */
	[[nodiscard]] const epoch_slot_descriptor *slot(std::size_t slot_index) const noexcept;

	/** @return true only when destruction owns no slot, artifact, or claim. */
	[[nodiscard]] bool empty() const noexcept;

    private:
	/**
	 * @brief Find the fixed array index for one exact epoch and state.
	 *
	 * @param epoch Exact epoch to locate.
	 * @param state Required lifecycle state.
	 * @return Matching slot index, or INVALID_EPOCH_SLOT_INDEX.
	 */
	[[nodiscard]] std::size_t find_slot_index_(uint64_t epoch, epoch_slot_state state) const noexcept;
	/**
	 * @brief Return the exact epoch occupying one lifecycle state.
	 *
	 * @param state Lifecycle state to locate.
	 * @return Exact epoch occupying @p state, or zero when absent.
	 */
	[[nodiscard]] uint64_t epoch_in_state_(epoch_slot_state state) const noexcept;
	/**
	 * @brief Claim one exact artifact after lifecycle-state validation.
	 *
	 * @param epoch Exact epoch to withdraw.
	 * @param state Required RETAINED or PUBLISHED state.
	 * @return Sole move-only claim, or failure without ownership transfer.
	 */
	[[nodiscard]] kinetum::common::status_or<config_snapshot_retirement_claim>
	claim_(uint64_t epoch, epoch_slot_state state) noexcept;
	/**
	 * @brief Validate one claim against current store-local ownership.
	 *
	 * @param claim Claim expected to be current and issued by this store.
	 * @return OK only when every nonce, slot, state, epoch, and artifact fact
	 *         still agrees without mutation.
	 */
	[[nodiscard]] kinetum::common::status
	validate_claim_(const config_snapshot_retirement_claim &claim) const noexcept;
	/** @brief Clear claim bookkeeping after one successful resolution. */
	void clear_claim_() noexcept;

	exact_epoch_slot_table slots_;	///< Sole exact lifecycle-state authority.
	/** Immutable artifact owners indexed by the matching exact-epoch lifecycle slots. */
	std::array<std::unique_ptr<const config_snapshot_artifact>, EXACT_EPOCH_SLOT_COUNT> artifacts_{};
	std::size_t active_slot_index_{INVALID_EPOCH_SLOT_INDEX};	///< Exact PUBLISHED owner.
	uint64_t next_claim_id_{1};					///< Nonzero claim source.
	uint64_t active_claim_id_{0};					///< Current claim nonce, or zero.
	std::size_t claimed_slot_index_{INVALID_EPOCH_SLOT_INDEX};	///< Current claimed slot.
	epoch_slot_state claimed_slot_state_{epoch_slot_state::EMPTY};	///< Current claim state.
};

}  // namespace kinetum::dp
