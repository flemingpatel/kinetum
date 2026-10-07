// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_epoch_store.hpp
 * @brief Exact two-slot configuration ownership for one module context.
 * @author Fleming Patel
 *
 * A store composes the platform's exact slot-state primitive with one linear
 * prepared-configuration token per occupied slot. Cold PREPARE publication is
 * transferred to the sole owner worker with release/acquire ordering. The
 * owner invokes ACTIVATE and then publishes one pre-resolved executable view;
 * packet execution reads only that view and performs one exact epoch equality.
 *
 * Null module owner/config pointers are valid successful artifacts. Slot state
 * and explicit token ownership, never pointer non-nullness, define success.
 *
 * @par Thread Safety
 * One lifecycle producer stages a prepared token and release-publishes its
 * epoch. The context's sole owner worker acquire-observes, activates, records
 * mismatches, and performs retirement claims. Staging may overlap ordinary
 * packet reads of the immutable active view, but the transition coordinator
 * must phase-serialize staging/discard with activation and retirement; the
 * release/acquire pair publishes PREPARE state and is not a general concurrent
 * mutation protocol. Other threads must not inspect slot metadata, the active
 * view, or diagnostics while that owner can run.
 * Any foreign diagnostics reader requires a separate coherent publication
 * layer; that layer must not change this owner-local authority.
 *
 * @par Performance
 * The active executable view is exactly one cache line. Reading this store's
 * execution authority and recording mismatch evidence perform no slot search,
 * allocation, lock, string lookup, logging, clock read, manager lookup, or
 * shared-atomic counter update.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/epoch/exact_slot_table.hpp"
#include "src/dp/lifecycle/prepared_config_ownership.hpp"

#include <kinetum/kinetum_sdk.h>

namespace kinetum::dp::lifecycle
{
class lifecycle_context_owner;
}  // namespace kinetum::dp::lifecycle

namespace kinetum::dp::module
{

/**
 * @brief One cache-line owner-local module execution authority.
 *
 * The view contains only values needed by packet and active-stage callbacks.
 * `packet_config` may be null for a valid no-op artifact. A nonzero epoch and
 * non-null context establish validity; mode-specific callback shape is checked
 * before publication.
 */
struct alignas(64) module_executable_view {
	kinetum_ctx *context{nullptr};			   ///< Sole-owner mutable context.
	const void *packet_config{nullptr};		   ///< Exact immutable config; null is valid.
	kinetum_process_batch_fn process{nullptr};	   ///< Passive batch callback.
	kinetum_ingest_fn ingest{nullptr};		   ///< Optional active push callback.
	kinetum_run_fn run{nullptr};			   ///< Active scheduling callback.
	kinetum_on_control_fn on_control{nullptr};	   ///< Optional active control callback.
	uint64_t epoch{0};				   ///< Exact epoch accepted by this view.
	uint32_t context_index{0};			   ///< Exact executable/context index.
	kinetum_module_mode mode{KINETUM_MODULE_PASSIVE};  ///< Exact descriptor mode.

	/**
	 * @brief Check whether this view contains a complete mode-specific authority.
	 *
	 * @return true for an exact passive or active view ready for owner execution.
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		if (epoch == 0 || context == nullptr) {
			return false;
		}
		if (mode == KINETUM_MODULE_PASSIVE) {
			return process != nullptr && ingest == nullptr && run == nullptr && on_control == nullptr;
		}
		return mode == KINETUM_MODULE_ACTIVE && process == nullptr && run != nullptr;
	}
};

static_assert(sizeof(module_executable_view) == 64, "module_executable_view must remain one cache line");
static_assert(alignof(module_executable_view) == 64, "module_executable_view must remain cache-line aligned");
static_assert(std::is_standard_layout_v<module_executable_view>, "module_executable_view must have standard layout");
static_assert(std::is_trivially_copyable_v<module_executable_view>,
	      "module_executable_view must remain trivially copyable");

/** @brief Fixed evidence captured for the first exact-epoch execution mismatch. */
struct module_epoch_mismatch_record {
	uint64_t packet_epoch{0};	   ///< Immutable epoch carried by the rejected packet.
	uint64_t active_epoch{0};	   ///< Exact epoch selected by the owner-local view.
	uint32_t context_index{0};	   ///< Exact module context index.
	uint16_t stage_instance_index{0};  ///< Executable stage-instance index.
	uint16_t reserved{0};		   ///< Explicit alignment padding.
	uint32_t worker_index{0};	   ///< Sole owner-worker index.
	int32_t region_id{-1};		   ///< Runtime region processing the packet.
};

static_assert(sizeof(module_epoch_mismatch_record) == 32, "module_epoch_mismatch_record must remain fixed and bounded");
static_assert(alignof(module_epoch_mismatch_record) == alignof(uint64_t),
	      "module_epoch_mismatch_record must retain natural uint64_t alignment");
static_assert(std::is_standard_layout_v<module_epoch_mismatch_record>,
	      "module_epoch_mismatch_record must have standard layout");
static_assert(std::is_trivially_copyable_v<module_epoch_mismatch_record>,
	      "module_epoch_mismatch_record must remain trivially copyable");

/**
 * @brief Owner-local mismatch counter and bounded first-fault record.
 *
 * No foreign thread may read this structure while the owner worker can update
 * it. The reserved bytes make its cache-line footprint explicit; the owner
 * copies completed evidence into the coherent telemetry publication.
 */
struct alignas(64) module_epoch_diagnostics {
	uint64_t mismatch_count{0};		     ///< Saturating exact-mismatch count.
	module_epoch_mismatch_record first_fault{};  ///< First mismatch only.
	uint8_t first_fault_valid{0};		     ///< One when first_fault is populated.
	uint8_t sticky_fault{0};		     ///< One after any mismatch.
	std::array<uint8_t, 22> reserved{};	     ///< Explicit cache-line padding.
};

static_assert(sizeof(module_epoch_diagnostics) == 64, "module_epoch_diagnostics must remain one cache line");
static_assert(alignof(module_epoch_diagnostics) == 64, "module_epoch_diagnostics must remain cache-line aligned");
static_assert(std::is_standard_layout_v<module_epoch_diagnostics>,
	      "module_epoch_diagnostics must have standard layout");
static_assert(std::is_trivially_copyable_v<module_epoch_diagnostics>,
	      "module_epoch_diagnostics must remain trivially copyable");

/** @brief Exact kind of slot transferred by one retirement claim. */
enum class module_retirement_kind : uint8_t {
	RETAINED = 0,	     ///< Prior epoch retired after transition quiescence.
	PUBLISHED_SHUTDOWN,  ///< Active epoch retired after final worker quiescence.
};

class module_epoch_store;

/**
 * @brief Move-only proof that one exact store slot has one retirement claimant.
 *
 * The claim exposes the embedded ownership token only as a read-only borrow
 * for the matching RETIRE callback. The token cannot escape the claim;
 * successful callback completion is recorded by claim-scoped consumption,
 * after which only the issuing store can clear the exact slot. Destroying an
 * unresolved claim terminates rather than silently leaking or double-retiring
 * module state.
 */
class module_retirement_claim {
    public:
	module_retirement_claim(const module_retirement_claim &) = delete;
	module_retirement_claim &operator=(const module_retirement_claim &) = delete;
	/**
	 * @brief Transfer the sole claim and invalidate the moved-from nonce.
	 * @param other Sole claim whose ownership is transferred.
	 */
	module_retirement_claim(module_retirement_claim &&other) noexcept;
	module_retirement_claim &operator=(module_retirement_claim &&) = delete;
	/** @brief Destroy an already resolved claim; an unresolved claim is fatal. */
	~module_retirement_claim();

	/**
	 * @brief Return the unforgeable store-local claim sequence.
	 *
	 * @return Nonzero sequence while this object carries the exact claim; zero
	 *         after move-from or successful store resolution.
	 */
	[[nodiscard]] uint64_t claim_id() const noexcept;
	/**
	 * @brief Return the exact claimed epoch cached independently of token state.
	 *
	 * @return Claimed epoch, or zero after move-from or store resolution.
	 */
	[[nodiscard]] uint64_t epoch() const noexcept;
	/**
	 * @brief Return the lifecycle kind of the claimed slot.
	 *
	 * @return Exact retained or published-shutdown claim kind.
	 */
	[[nodiscard]] module_retirement_kind kind() const noexcept;
	/**
	 * @brief Borrow the linear token for the matching RETIRE callback.
	 *
	 * The read-only borrow prevents ownership from escaping the store-bound
	 * claim. The callback may inspect the exact prepared record but cannot move
	 * or consume its platform ownership.
	 *
	 * @return Immutable ownership token carried by this claim.
	 */
	[[nodiscard]] const kinetum::dp::lifecycle::prepared_config_ownership &ownership() const noexcept;
	/**
	 * @brief Consume claim ownership after exact RETIRE completed successfully.
	 *
	 * @pre The matching module RETIRE callback has completed successfully for
	 *      `ownership()`, `epoch()`, and this claim's exact context identity.
	 * @return OK after one exact claim-scoped consumption; non-OK leaves the
	 *         unresolved claim unchanged.
	 */
	[[nodiscard]] kinetum::common::status consume_after_retire() noexcept;

    private:
	friend class module_epoch_store;

	/**
	 * @brief Construct one validated claim after the store records its nonce.
	 * @param owner Exact issuing store.
	 * @param claim_id Store-local nonzero claim sequence.
	 * @param slot_index Exact claimed slot index.
	 * @param kind Retained or published-shutdown lifecycle kind.
	 * @param module_image_index Exact module-image identity.
	 * @param context_index Exact module-context identity.
	 * @param epoch Exact claimed epoch.
	 * @param ownership Linear prepared-configuration token to adopt.
	 */
	module_retirement_claim(const module_epoch_store *owner, uint64_t claim_id, std::size_t slot_index,
				module_retirement_kind kind, uint32_t module_image_index, uint32_t context_index,
				uint64_t epoch, kinetum::dp::lifecycle::prepared_config_ownership ownership) noexcept;
	/** @brief Invalidate this claim after its issuing store resolves it. */
	void resolve_() noexcept;

	const module_epoch_store *owner_{nullptr};			 ///< Exact store that issued this claim.
	uint64_t claim_id_{0};						 ///< Store-local nonzero claimant nonce.
	std::size_t slot_index_{INVALID_EPOCH_SLOT_INDEX};		 ///< Exact claimed slot.
	module_retirement_kind kind_{module_retirement_kind::RETAINED};	 ///< Claimed lifecycle state.
	uint32_t module_image_index_{0};  ///< Cached image identity after token consumption.
	uint32_t context_index_{0};	  ///< Cached context identity after token consumption.
	uint64_t epoch_{0};		  ///< Cached epoch after token consumption.
	kinetum::dp::lifecycle::prepared_config_ownership ownership_;  ///< Exact linear artifact.
	bool retirement_completed_{false};  ///< Explicit matching-RETIRE completion evidence.
};

/** @brief Exact two-slot artifact and executable-view owner for one context. */
class module_epoch_store {
    public:
	/**
	 * @brief Create one empty store bound to an admitted descriptor and context.
	 *
	 * @param module_image_index Exact generation-local image index.
	 * @param context_index Exact executable context index.
	 * @param descriptor Immutable admitted image descriptor.
	 * @param context Stable sole-owner packet context.
	 * @param telemetry_owner Exact context-local three-bank telemetry authority.
	 * @return Empty store, or exact structural/allocation failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<module_epoch_store>>
	create(uint32_t module_image_index, uint32_t context_index, const kinetum_module *descriptor,
	       kinetum_ctx *context, kinetum::dp::lifecycle::lifecycle_context_owner *telemetry_owner);

	module_epoch_store(const module_epoch_store &) = delete;
	module_epoch_store &operator=(const module_epoch_store &) = delete;
	module_epoch_store(module_epoch_store &&) = delete;
	module_epoch_store &operator=(module_epoch_store &&) = delete;
	/** @brief Destroy only after every exact artifact has completed retirement. */
	~module_epoch_store();

	/**
	 * @brief Stage and release-publish one exact prepared token.
	 *
	 * @param ownership Live token whose identity must match this store.
	 * @return OK after publication; otherwise ownership remains with the caller.
	 */
	[[nodiscard]] kinetum::common::status
	stage_prepared(kinetum::dp::lifecycle::prepared_config_ownership &ownership) noexcept;

	/**
	 * @brief Abort one staged epoch before owner activation.
	 *
	 * @param epoch Exact prepared epoch to remove.
	 * @return The still-live token for exact RETIRE, or failure without mutation.
	 */
	[[nodiscard]] kinetum::common::status_or<kinetum::dp::lifecycle::prepared_config_ownership>
	discard_prepared(uint64_t epoch) noexcept;

	/**
	 * @brief Prove one exact prepared activation without invoking module code.
	 *
	 * This is the same complete preflight consumed by `activate_prepared()`. The
	 * sole owner worker calls it for every local context with packet work
	 * excluded, so later activation has no undiscovered structural, bank, channel,
	 * or ownership failure. The coordinator uses the narrower immutable-reserve
	 * check below and never reads worker-mutated bank state.
	 *
	 * @param epoch Exact release-published prepared epoch.
	 * @return OK only when the slot, token, callback input, and prospective
	 *         executable view are complete and mutually consistent.
	 */
	[[nodiscard]] kinetum::common::status preflight_activate_prepared(uint64_t epoch) const noexcept;

	/**
	 * @brief Prove exact prepared ownership and its cold telemetry reserve.
	 *
	 * This coordinator-side check intentionally excludes worker-owned bank and
	 * channel state. The owner worker performs the complete activation preflight
	 * through `preflight_activate_prepared()` after it consumes the trigger.
	 *
	 * @param epoch Exact release-published prepared epoch.
	 * @return OK only when the prepared artifact and immutable target reserve
	 *         are complete and mutually consistent.
	 */
	[[nodiscard]] kinetum::common::status preflight_prepared_for_commit(uint64_t epoch) const noexcept;

	/**
	 * @brief Acquire, activate, and publish one exact prepared epoch on its owner.
	 *
	 * All fallible preflight and prospective-view construction precede the
	 * foreign callback. After ACTIVATE begins, callback return is followed only
	 * by bounded non-failing owner-local assignments; a foreign exception or
	 * violated preflight invariant terminates the process.
	 *
	 * @param epoch Exact release-published prepared epoch.
	 * @param now_ns Sole owner-worker cached monotonic publication timestamp.
	 * @return OK after owner-local publication, or pre-callback failure.
	 */
	[[nodiscard]] kinetum::common::status activate_prepared(uint64_t epoch, uint64_t now_ns) noexcept;

	/**
	 * @brief Preflight one eventual retained claim before irreversible commit.
	 *
	 * @param from_epoch Exact currently published execution epoch.
	 * @param to_epoch Exact release-published prepared target epoch.
	 * @return OK only when activation will retain @p from_epoch with complete
	 *         token ownership and a representable later claim nonce.
	 */
	[[nodiscard]] kinetum::common::status preflight_future_retained(uint64_t from_epoch,
									uint64_t to_epoch) const noexcept;

	/**
	 * @brief Return the stable owner-local active-view address for cold admission.
	 *
	 * This validating accessor is used before packet workers launch. Foreign
	 * readers must not call it while the owner can activate or retire a view.
	 *
	 * @return Stable view address when an exact epoch is published; otherwise null.
	 */
	[[nodiscard]] const module_executable_view *active_view() const noexcept;

	/**
	 * @brief Borrow the stable executable view on the sole owner packet path.
	 *
	 * Unlike `active_view()`, this accessor performs no structural validation.
	 * Runtime construction must first prove that `active_view()` is non-null and
	 * exact for the stage, context, placement, mode, and snapshot epoch. The same
	 * owner cannot interleave packet execution with ACTIVATE or shutdown claim,
	 * so the referenced cache line remains complete for the whole callback.
	 *
	 * @return Stable owner-local view reference with no slot lookup or branch.
	 */
	[[nodiscard]] const module_executable_view &owner_executable_view() const noexcept;
	/**
	 * @brief Return the owner-local active epoch.
	 *
	 * @return Exact published epoch, or zero before activation or after a
	 *         published-shutdown claim withdraws the view.
	 */
	[[nodiscard]] uint64_t active_epoch() const noexcept;
	/**
	 * @brief Acquire-observe the lifecycle producer's prepared publication.
	 *
	 * @return Exact release-published prepared epoch, or zero when none exists.
	 */
	[[nodiscard]] uint64_t prepared_epoch() const noexcept;
	/** @return Immutable compact module-context identity. */
	[[nodiscard]] uint32_t context_index() const noexcept;

	/**
	 * @brief Bind the process-generation protocol safety-fault authority.
	 * @param faults Stable authority outliving this store and its owner worker.
	 * @return OK for first or exact repeated binding; failure for another owner.
	 */
	[[nodiscard]] kinetum::common::status bind_protocol_fault_latch(epoch_protocol_fault_latch &faults) noexcept;

	/**
	 * @brief Record one packet/view epoch mismatch on the sole owner worker.
	 *
	 * @param packet_epoch Immutable packet epoch.
	 * @param stage_instance_index Exact executable stage-instance index.
	 * @param region_id Runtime region processing the packet.
	 */
	void record_epoch_mismatch(uint64_t packet_epoch, uint16_t stage_instance_index, int32_t region_id) noexcept;

	/**
	 * @brief Snapshot diagnostics only after the owner is quiescent.
	 *
	 * @return Plain owner-local diagnostic state.
	 */
	[[nodiscard]] module_epoch_diagnostics diagnostics_after_quiescence() const noexcept;

	/**
	 * @brief Claim one retained old epoch exactly once.
	 *
	 * @param epoch Exact RETAINED epoch proven globally quiescent.
	 * @return Move-only claim carrying the live ownership token.
	 */
	[[nodiscard]] kinetum::common::status_or<module_retirement_claim> claim_retained(uint64_t epoch) noexcept;

	/**
	 * @brief Revalidate one retained claim immediately before transfer.
	 *
	 * @param epoch Exact globally quiescent retained epoch.
	 * @return OK only when `claim_retained()` has no undiscovered bounded failure.
	 */
	[[nodiscard]] kinetum::common::status preflight_claim_retained(uint64_t epoch) const noexcept;

	/**
	 * @brief Claim the sole published epoch after final worker quiescence.
	 *
	 * Every RETAINED artifact must already have completed retirement. The idle-
	 * layout requirement is preflighted before the active token or view moves.
	 *
	 * @param epoch Exact active epoch being shut down.
	 * @return Move-only claim and live token; the active view is withdrawn.
	 */
	[[nodiscard]] kinetum::common::status_or<module_retirement_claim>
	claim_published_for_shutdown(uint64_t epoch) noexcept;

	/**
	 * @brief Restore a live token after RETIRE was not dispatched.
	 *
	 * Only the current exact claim nonce may restore its slot. A rejected restore
	 * leaves the claim and token intact.
	 *
	 * @param claim Current store-local retirement claim.
	 * @return OK after exact restoration; non-OK without consuming the token.
	 */
	[[nodiscard]] kinetum::common::status restore_retirement(module_retirement_claim &claim) noexcept;

	/**
	 * @brief Complete one exact claimed retirement after claim-scoped consumption.
	 *
	 * @param claim Current claim whose `consume_after_retire()` completed exactly
	 *        once after the matching RETIRE callback.
	 * @return OK after clearing the exact slot; non-OK without clearing it.
	 */
	[[nodiscard]] kinetum::common::status complete_retirement(module_retirement_claim &claim) noexcept;

	/**
	 * @brief Return one exact slot descriptor for cold diagnostics and tests.
	 *
	 * @param slot_index Fixed slot-table index.
	 * @return Borrowed descriptor, or null when slot_index is out of range.
	 */
	[[nodiscard]] const epoch_slot_descriptor *slot(std::size_t slot_index) const noexcept;
	/**
	 * @brief Check whether no slot, token, active view, or health borrow remains.
	 *
	 * @return true only when destruction is legal.
	 */
	[[nodiscard]] bool empty() const noexcept;
	/**
	 * @brief Check whether the linear health claim is the sole remaining owner.
	 * @return true only when releasing that claim makes @c empty() true.
	 */
	[[nodiscard]] bool health_owner_release_ready() const noexcept;

    private:
	/** @brief Complete non-owning result of one exact ACTIVATE preflight. */
	struct prepared_activation {
		std::size_t slot_index{INVALID_EPOCH_SLOT_INDEX};  ///< Exact PREPARED slot.
		module_executable_view executable_view{};	   ///< Prospective owner-local view.
		kinetum_prepared_config callback_input{};	   ///< Borrowed exact callback input.
	};

	/**
	 * @brief Construct one already validated empty context store.
	 *
	 * @param module_image_index Exact generation-local image index.
	 * @param context_index Exact executable context index.
	 * @param descriptor Stable admitted image descriptor.
	 * @param context Stable sole-owner packet context.
	 * @param telemetry_owner Exact context-local telemetry-bank authority.
	 */
	module_epoch_store(uint32_t module_image_index, uint32_t context_index, const kinetum_module &descriptor,
			   kinetum_ctx &context,
			   kinetum::dp::lifecycle::lifecycle_context_owner &telemetry_owner) noexcept;

	/**
	 * @brief Build a complete one-cache-line view from one exact live token.
	 *
	 * @param ownership Exact still-live token owned by one occupied slot.
	 * @return Complete mode-specific view, or a structural identity failure.
	 */
	[[nodiscard]] kinetum::common::status_or<module_executable_view>
	make_view_(const kinetum::dp::lifecycle::prepared_config_ownership &ownership) const noexcept;
	/**
	 * @brief Build the sole complete ACTIVATE preflight result.
	 *
	 * @param epoch Exact release-published prepared epoch.
	 * @return Borrowed callback/view facts and slot identity, or failure without
	 *         mutation or foreign code execution.
	 */
	[[nodiscard]] kinetum::common::status_or<prepared_activation>
	preflight_activation_(uint64_t epoch) const noexcept;
	/** @return true when no configuration, callback, or telemetry-bank ownership remains. */
	[[nodiscard]] bool ownership_empty_() const noexcept;
	/**
	 * @brief Claim one slot after state and kind preflight.
	 *
	 * @param epoch Exact epoch to claim.
	 * @param kind Required lifecycle state of the claimed slot.
	 * @return Sole move-only claim, or failure without removing ownership.
	 */
	[[nodiscard]] kinetum::common::status_or<module_retirement_claim> claim_(uint64_t epoch,
										 module_retirement_kind kind) noexcept;
	/**
	 * @brief Verify that one claim is the current exact claimant.
	 *
	 * @param claim Claim to compare with store-local nonce and slot identity.
	 * @return OK only for the current claimant; otherwise a non-mutating failure.
	 */
	[[nodiscard]] kinetum::common::status validate_claim_(const module_retirement_claim &claim) const noexcept;
	/** @brief Clear current claim bookkeeping after one successful resolution. */
	void clear_claim_() noexcept;

	uint32_t module_image_index_{0};				    ///< Exact generation-local image identity.
	uint32_t context_index_{0};					    ///< Exact executable/context identity.
	const kinetum_module &descriptor_;				    ///< Stable admitted callback authority.
	kinetum_ctx &context_;						    ///< Stable sole-owner packet context.
	kinetum::dp::lifecycle::lifecycle_context_owner &telemetry_owner_;  ///< Exact telemetry-bank owner.
	exact_epoch_slot_table slots_;	///< Exact metadata state; never read by packets.
	std::array<std::optional<kinetum::dp::lifecycle::prepared_config_ownership>, EXACT_EPOCH_SLOT_COUNT>
		ownership_{};					    ///< Linear artifact ownership aligned with slots_.
	alignas(64) std::atomic<uint64_t> prepared_epoch_{0};	    ///< Release/acquire handoff.
	module_executable_view active_view_{};			    ///< Owner-local packet authority.
	std::size_t active_slot_index_{INVALID_EPOCH_SLOT_INDEX};   ///< Owner-local active slot.
	module_epoch_diagnostics diagnostics_{};		    ///< Owner-local mismatch evidence.
	epoch_protocol_fault_latch *protocol_faults_{nullptr};	    ///< Process-generation safety-fault authority.
	uint64_t next_claim_id_{1};				    ///< Monotonic nonzero claim source.
	uint64_t active_claim_id_{0};				    ///< Current claimant nonce, or zero.
	std::size_t claimed_slot_index_{INVALID_EPOCH_SLOT_INDEX};  ///< Current claimed slot.
	module_retirement_kind claimed_kind_{module_retirement_kind::RETAINED};	 ///< Current claim kind.
};

}  // namespace kinetum::dp::module
