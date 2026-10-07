// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_module_completion.hpp
 * @brief Narrow cold module-generation authority consumed by transition completion.
 * @author Fleming Patel
 *
 * The interface exposes only exact context membership, aggregate activation,
 * retained claims, lifecycle task/result transfer, and final old-slot proof.
 * It owns no coordinator phase, grace, certificate, timeout, or runtime-status
 * policy. Production implements it with the sole module runtime generation.
 *
 * @par Thread Safety
 * Every method except executor task execution belongs to the sole coordinator.
 * Returned claims and result ownership remain linear under their existing
 * store/executor contracts.
 */

#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/lifecycle/config_lifecycle_executor.hpp"
#include "src/dp/module/module_epoch_store.hpp"

namespace kinetum::dp
{

/** @brief Fixed exact identity for one claimed module RETIRE submission. */
struct epoch_transition_retire_submission {
	uint64_t task_sequence{0};    ///< Never-reused lifecycle task identity.
	uint32_t context_ordinal{0};  ///< Dense completion context ordinal.
	uint32_t padding{0};	      ///< Explicit deterministic alignment completion.
};

static_assert(sizeof(epoch_transition_retire_submission) == 16u,
	      "completion RETIRE submission identity must remain exactly 16 bytes");
static_assert(alignof(epoch_transition_retire_submission) == alignof(uint64_t),
	      "completion RETIRE submission identity must retain uint64 alignment");
static_assert(offsetof(epoch_transition_retire_submission, task_sequence) == 0u &&
		      offsetof(epoch_transition_retire_submission, context_ordinal) == 8u &&
		      offsetof(epoch_transition_retire_submission, padding) == 12u,
	      "completion RETIRE submission fields must retain exact offsets");
static_assert(std::is_standard_layout_v<epoch_transition_retire_submission> &&
		      std::is_trivially_copyable_v<epoch_transition_retire_submission>,
	      "completion RETIRE submission identity must retain value semantics");

/** @brief Narrow PREPARED bookkeeping handoff consumed at irreversible commit. */
class epoch_transition_prepared_completion {
    public:
	/** @brief Construct one unbound PREPARED bookkeeping authority. */
	epoch_transition_prepared_completion() noexcept = default;
	/** @brief PREPARED bookkeeping authorities cannot be copied. */
	epoch_transition_prepared_completion(const epoch_transition_prepared_completion &) = delete;
	/** @brief PREPARED bookkeeping authorities cannot be copy-assigned. */
	epoch_transition_prepared_completion &operator=(const epoch_transition_prepared_completion &) = delete;
	/** @brief Stable bookkeeping identity cannot move. */
	epoch_transition_prepared_completion(epoch_transition_prepared_completion &&) = delete;
	/** @brief Stable bookkeeping identity cannot be move-assigned. */
	epoch_transition_prepared_completion &operator=(epoch_transition_prepared_completion &&) = delete;
	/** @brief Destroy only after implementation-owned transient state is resolved. */
	virtual ~epoch_transition_prepared_completion() = default;

	/**
	 * @brief Check whether one exact identity owns completed PREPARE bookkeeping.
	 * @param identity Exact candidate transaction.
	 * @return true only when release at commit is currently legal.
	 */
	[[nodiscard]] virtual bool
	completion_prepared(const common::epoch_transition_identity &identity) const noexcept = 0;
	/**
	 * @brief Release transient bookkeeping after the irreversible coordinator edge.
	 * @param identity Exact transaction now owned by COMMITTING.
	 */
	virtual void release_completion_preparation(const common::epoch_transition_identity &identity) noexcept = 0;
};

/** @brief Exact module/lifecycle operations required by one completion owner. */
class epoch_transition_module_completion {
    public:
	/** @brief Construct one unbound implementation authority. */
	epoch_transition_module_completion() noexcept = default;
	/** @brief Interface authorities cannot be copied. */
	epoch_transition_module_completion(const epoch_transition_module_completion &) = delete;
	/** @brief Interface authorities cannot be copy-assigned. */
	epoch_transition_module_completion &operator=(const epoch_transition_module_completion &) = delete;
	/** @brief Stable implementation identity cannot move. */
	epoch_transition_module_completion(epoch_transition_module_completion &&) = delete;
	/** @brief Stable implementation identity cannot be move-assigned. */
	epoch_transition_module_completion &operator=(epoch_transition_module_completion &&) = delete;
	/** @brief Destroy only after the implementation has resolved its exact ownership. */
	virtual ~epoch_transition_module_completion() = default;

	/** @return Exact dense module-context population. */
	[[nodiscard]] virtual std::size_t completion_context_count() const noexcept = 0;
	/** @return Exact loaded-image serialization-domain population. */
	[[nodiscard]] virtual std::size_t completion_image_count() const noexcept = 0;
	/** @return Exact lifecycle-executor population. */
	[[nodiscard]] virtual std::size_t completion_executor_count() const noexcept = 0;
	/**
	 * @param ordinal Dense completion context ordinal.
	 * @return Exact compiled context index, or UINT32_MAX when absent.
	 */
	[[nodiscard]] virtual uint32_t completion_context_index(std::size_t ordinal) const noexcept = 0;
	/**
	 * @param ordinal Dense completion context ordinal.
	 * @return Exact image index, or image-count when absent.
	 */
	[[nodiscard]] virtual uint32_t completion_image_index(std::size_t ordinal) const noexcept = 0;
	/**
	 * @param ordinal Dense completion context ordinal.
	 * @return Exact executor index, or executor-count when absent.
	 */
	[[nodiscard]] virtual std::size_t completion_executor_index(std::size_t ordinal) const noexcept = 0;
	/** @return Next nonzero never-reused lifecycle task identity. */
	[[nodiscard]] virtual uint64_t next_completion_task_sequence() noexcept = 0;
	/**
	 * @param from_epoch Exact published baseline.
	 * @param to_epoch Exact prepared target.
	 * @return OK only when every eventual retained claim is representable.
	 */
	[[nodiscard]] virtual common::status preflight_future_completion(uint64_t from_epoch,
									 uint64_t to_epoch) const noexcept = 0;
	/**
	 * @param from_epoch Exact retained baseline.
	 * @param to_epoch Exact participant-active target.
	 * @return OK only when every context completed activation exactly.
	 */
	[[nodiscard]] virtual common::status preflight_completion_activation(uint64_t from_epoch,
									     uint64_t to_epoch) const noexcept = 0;
	/**
	 * @param from_epoch Exact old aggregate publication.
	 * @param to_epoch Exact new aggregate publication.
	 */
	virtual void publish_completion_activation(uint64_t from_epoch, uint64_t to_epoch) noexcept = 0;
	/**
	 * @param ordinal Dense context ordinal.
	 * @param epoch Exact retained old epoch.
	 * @return OK only when claim transfer has no undiscovered failure.
	 */
	[[nodiscard]] virtual common::status preflight_completion_retained(std::size_t ordinal,
									   uint64_t epoch) const noexcept = 0;
	/**
	 * @param ordinal Dense context ordinal.
	 * @param epoch Exact retained old epoch.
	 * @return Sole store-bound claim or exact transfer failure.
	 */
	[[nodiscard]] virtual common::status_or<module::module_retirement_claim>
	claim_completion_retained(std::size_t ordinal, uint64_t epoch) noexcept = 0;
	/**
	 * @param submission Exact context and task identity.
	 * @param control Stable completion-owned deadline.
	 * @param claim Exact store-bound claim retained through result delivery.
	 * @return OK after executor task ownership transfer.
	 */
	[[nodiscard]] virtual common::status
	submit_completion_retire(epoch_transition_retire_submission submission,
				 lifecycle::lifecycle_operation_control &control,
				 const module::module_retirement_claim &claim) noexcept = 0;
	/** @return One currently available owning lifecycle result, or nullopt. */
	[[nodiscard]] virtual std::optional<lifecycle::config_lifecycle_result>
	try_take_completion_result() noexcept = 0;
	/**
	 * @param ordinal Dense context ordinal.
	 * @param claim Exact identity-validated successful RETIRE claim.
	 */
	virtual void complete_completion_retirement(std::size_t ordinal,
						    module::module_retirement_claim &claim) noexcept = 0;
	/**
	 * @param active_epoch Exact target that must remain published.
	 * @return true only when no context retains an older slot or claim.
	 */
	[[nodiscard]] virtual bool completion_retirement_complete(uint64_t active_epoch) const noexcept = 0;
};

}  // namespace kinetum::dp
