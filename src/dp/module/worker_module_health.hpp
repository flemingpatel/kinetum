// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_module_health.hpp
 * @brief Linear owner-worker module-health invocation and publication.
 * @author Fleming Patel
 *
 * One immutable row binds each worker-owned module stage instance to its exact
 * context store, admitted descriptor, and context-NUMA publication owner. A
 * move-only invocation claim brackets the synchronous foreign callback with one
 * worker-ledger credit and publishes only a validated, platform-stamped result.
 *
 * @par Thread Safety
 * Construction and Bootstrap binding are externally serialized. Thereafter the
 * exact packet worker is the sole caller. Foreign readers use only the coherent
 * lifecycle-owner publication and never access this owner or a live context.
 *
 * @par Performance
 * No operation allocates after construction. Invocation is cadence-only and
 * performs direct indexed access, plain owner-local ledger arithmetic, one
 * pre-resolved callback, bounded validation, and coherent publication.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <kinetum/kinetum_sdk.h>

#include "src/common/status_or.hpp"

namespace kinetum::dp
{
class worker_epoch_ledger;
namespace lifecycle
{
class lifecycle_context_owner;
}  // namespace lifecycle
}  // namespace kinetum::dp

namespace kinetum::dp::module
{

class module_epoch_store;
class worker_module_health;

/** @brief One cold exact stage/context health binding. */
struct worker_module_health_binding {
	uint32_t stage_instance_index{0};			   ///< Exact executable stage instance.
	uint32_t context_index{0};				   ///< Exact module context identity.
	kinetum_ctx *context{nullptr};				   ///< Exact sole-owner live context.
	module_epoch_store *store{nullptr};			   ///< Exact active-view authority.
	const kinetum_module *descriptor{nullptr};		   ///< Immutable admitted callback descriptor.
	lifecycle::lifecycle_context_owner *publication{nullptr};  ///< Exact context-NUMA publication owner.
};

/** @brief Move-only proof of one synchronous owner-worker health callback. */
class module_health_invocation final {
    public:
	/** @brief Reject copying because one invocation owns one ledger credit. */
	module_health_invocation(const module_health_invocation &) = delete;
	/** @brief Reject copy assignment because a claim cannot be duplicated. */
	module_health_invocation &operator=(const module_health_invocation &) = delete;
	/**
	 * @brief Transfer the sole live invocation and invalidate the source.
	 * @param other Sole invocation owner whose claim is transferred.
	 */
	module_health_invocation(module_health_invocation &&other) noexcept;
	/** @brief Reject move assignment so live ownership cannot be overwritten. */
	module_health_invocation &operator=(module_health_invocation &&) = delete;
	/** @brief Destroy only after exact completion; unresolved ownership is fatal. */
	~module_health_invocation();

	/**
	 * @brief Invoke the exact pre-resolved callback once on the owner worker.
	 * @param start_ns Ordinary turn refresh sampled immediately before invocation.
	 */
	void invoke(uint64_t start_ns) noexcept;
	/**
	 * @brief Validate, publish, and resolve one returned callback result.
	 * @param finish_ns Same-clock monotonic sample taken immediately after return.
	 */
	void complete(uint64_t finish_ns) noexcept;

    private:
	friend class worker_module_health;
	/** @brief Exact phase of one live callback claim. */
	enum class state : uint8_t {
		CLAIMED = 0,  ///< Ledger and owner hold one not-yet-invoked callback.
		INVOKED,      ///< Callback returned and awaits duration/publication completion.
	};
	/** @brief Fixed identity transferred together when one invocation is issued. */
	struct claim_identity {
		uint64_t claim_id{0};	     ///< Nonzero never-reused claim identity.
		std::size_t row_ordinal{0};  ///< Exact immutable context ordinal.
		uint64_t epoch{0};	     ///< Exact credited callback epoch.
	};

	/**
	 * @brief Adopt one exact owner-issued invocation claim.
	 * @param owner Sole issuing health scheduler.
	 * @param identity Complete claim, row, and epoch identity.
	 * @param context Exact sole-owner live context borrow.
	 * @param packet_config Exact immutable callback-duration config borrow.
	 */
	module_health_invocation(worker_module_health &owner, claim_identity identity, kinetum_ctx &context,
				 const void *packet_config) noexcept;
	/** @brief Clear this claim after its owner resolves every resource. */
	void resolve_() noexcept;

	worker_module_health *owner_{nullptr};	  ///< Exact issuing owner while unresolved.
	uint64_t claim_id_{0};			  ///< Owner-local nonzero claim sequence.
	std::size_t row_ordinal_{0};		  ///< Exact immutable binding ordinal.
	uint64_t epoch_{0};			  ///< Exact credited callback epoch.
	uint64_t start_ns_{0};			  ///< Cached owner-turn start timestamp.
	kinetum_ctx *context_{nullptr};		  ///< Exact context borrowed for this callback.
	const void *packet_config_{nullptr};	  ///< Exact immutable callback-duration config borrow.
	kinetum_health_assessment assessment_{};  ///< Fixed callback result after invoke().
	state state_{state::CLAIMED};		  ///< Exact claim phase.
};

/** @brief Exact health callback owner for one packet worker. */
class worker_module_health final {
    public:
	/**
	 * @brief Construct one complete immutable worker health projection.
	 * @param worker_index Exact compact worker identity.
	 * @param runtime_generation Exact materialized runtime generation.
	 * @param callback_budget_ns Exact positive compiled callback budget.
	 * @param bindings Complete stage-ordered worker module-context set.
	 * @param ledger Sole unbound worker epoch-credit authority.
	 * @return Complete unbound owner or exact admission/allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_module_health>>
	create(uint32_t worker_index, uint64_t runtime_generation, uint64_t callback_budget_ns,
	       std::span<const worker_module_health_binding> bindings, worker_epoch_ledger &ledger);

	/** @brief Reject copying because each context claim has one owner. */
	worker_module_health(const worker_module_health &) = delete;
	/** @brief Reject copy assignment because context claims cannot be duplicated. */
	worker_module_health &operator=(const worker_module_health &) = delete;
	/** @brief Reject moving so activation and kernel borrows remain stable. */
	worker_module_health(worker_module_health &&) = delete;
	/** @brief Reject move assignment so live worker authority cannot be replaced. */
	worker_module_health &operator=(worker_module_health &&) = delete;
	/** @brief Destroy only after callback quiescence and exact module-store retirement. */
	~worker_module_health();

	/**
	 * @brief Bind the already active fixed Bootstrap epoch without invoking health.
	 * @param bootstrap_epoch Exact active epoch for every bound context and ledger.
	 */
	void bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept;
	/**
	 * @brief Begin one exact callback when the selected context implements health.
	 * @param row_ordinal Immutable stage-ordered context ordinal.
	 * @return One linear invocation, or nullopt for source/active suppression or
	 *         an exact null callback.
	 */
	[[nodiscard]] std::optional<module_health_invocation> begin(std::size_t row_ordinal) noexcept;

	/** @return true only when no callback claim can block transition or teardown. */
	[[nodiscard]] bool quiescent() const noexcept;
	/**
	 * @param ledger Candidate ledger identity.
	 * @return true only for the exact ledger borrowed at construction.
	 */
	[[nodiscard]] bool owns_ledger(const worker_epoch_ledger &ledger) const noexcept;
	/** @return Exact immutable binding population. */
	[[nodiscard]] std::size_t size() const noexcept;
	/** @return Number of rows carrying an admitted non-null callback. */
	[[nodiscard]] std::size_t callback_count() const noexcept;
	/**
	 * @param row_ordinal Immutable stage-ordered context ordinal.
	 * @return Exact context identity for that row, or UINT32_MAX when absent.
	 */
	[[nodiscard]] uint32_t context_index(std::size_t row_ordinal) const noexcept;
	/**
	 * @brief Verify one row's exact module-store borrow.
	 * @param row_ordinal Immutable stage-ordered context ordinal.
	 * @param store Candidate module-store identity.
	 * @return true only when the row borrows @p store as its view authority.
	 */
	[[nodiscard]] bool owns_store(std::size_t row_ordinal, const module_epoch_store &store) const noexcept;
	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;
	/** @return Exact materialized runtime generation. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;

    private:
	friend class module_health_invocation;
	/** @brief Complete immutable identity adopted by the private owner constructor. */
	struct owner_identity {
		uint32_t worker_index{0};	 ///< Exact compact worker identity.
		uint64_t runtime_generation{0};	 ///< Exact materialized generation.
		uint64_t callback_budget_ns{0};	 ///< Plan-authored callback budget.
	};

	/**
	 * @brief Adopt a completely claimed immutable context projection.
	 * @param identity Exact worker, runtime, and callback-budget identity.
	 * @param bindings Complete claimed stage/context rows.
	 * @param ledger Sole worker epoch-credit authority.
	 */
	worker_module_health(owner_identity identity, std::vector<worker_module_health_binding> bindings,
			     worker_epoch_ledger &ledger) noexcept;
	/**
	 * @brief Invoke one exact callback behind a validated live claim.
	 * @param claim Exact unresolved claim issued by this owner.
	 * @param start_ns Ordinary turn refresh sampled immediately before invocation.
	 */
	void invoke_(module_health_invocation &claim, uint64_t start_ns) noexcept;
	/**
	 * @brief Resolve one returned callback and retire its ledger credit last.
	 * @param claim Exact invoked claim issued by this owner.
	 * @param finish_ns Same-clock post-return timestamp.
	 */
	void complete_(module_health_invocation &claim, uint64_t finish_ns) noexcept;
	/**
	 * @param row_ordinal Candidate immutable binding ordinal.
	 * @return Exact row or terminate on a foreign ordinal.
	 */
	[[nodiscard]] const worker_module_health_binding &binding_(std::size_t row_ordinal) const noexcept;

	uint32_t worker_index_{0};			      ///< Exact compact worker identity.
	uint64_t runtime_generation_{0};		      ///< Exact materialized generation.
	uint64_t callback_budget_ns_{0};		      ///< Plan-authored callback budget.
	std::vector<worker_module_health_binding> bindings_;  ///< Immutable stage-ordered rows.
	worker_epoch_ledger *ledger_{nullptr};		      ///< Sole worker credit authority.
	bool bound_{false};				      ///< Whether fixed Bootstrap established ownership.
	uint64_t next_claim_id_{1};			      ///< Never-reused invocation sequence.
	uint64_t live_claim_id_{0};			      ///< Nonzero while one callback is unresolved.
	std::size_t live_row_ordinal_{0};		      ///< Exact live binding ordinal.
};

}  // namespace kinetum::dp::module
