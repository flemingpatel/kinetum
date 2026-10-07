// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file config_snapshot_epoch_store.cpp
 * @brief Exact canonical-snapshot epoch-store implementation.
 * @author Fleming Patel
 */

#include "src/dp/config_snapshot_epoch_store.hpp"

#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "src/common/epoch_transition_contract.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

namespace
{

/**
 * @brief Convert one shared exact-slot result into a stable snapshot-store status.
 *
 * @param result Exact slot-table outcome.
 * @param operation Stable operation name for diagnostics.
 * @param epoch Exact epoch involved in the rejected operation.
 * @return OK for APPLIED; otherwise the precise public status category.
 */
[[nodiscard]] status slot_status(epoch_slot_result result, const char *operation, uint64_t epoch) noexcept
try {
	const std::string prefix =
		std::string(operation) + " rejected exact configuration epoch " + std::to_string(epoch) + ": ";
	switch (result) {
	case epoch_slot_result::APPLIED:
		return status::ok();
	case epoch_slot_result::INVALID_EPOCH:
		return status::invalid_argument(prefix + "invalid epoch identity");
	case epoch_slot_result::INVALID_STATE:
		return status::failed_precondition(prefix + "slot lifecycle state does not permit the operation");
	case epoch_slot_result::EPOCH_ALREADY_PRESENT:
		return status::failed_precondition(prefix + "epoch already occupies an exact slot");
	case epoch_slot_result::EPOCH_NOT_FOUND:
		return status::not_found(prefix + "epoch does not occupy an exact slot");
	case epoch_slot_result::EPOCH_ORDER_VIOLATION:
		return status::failed_precondition(prefix + "epoch does not advance the published epoch");
	case epoch_slot_result::NO_EMPTY_SLOT:
		return status::resource_exhausted(prefix + "both exact slots remain owned");
	}
	return status::internal_error(prefix + "unknown slot result");
} catch (const std::bad_alloc &) {
	return status::resource_exhausted(
		kinetum::common::static_status_text("configuration slot diagnostic exhausted memory"));
} catch (const std::length_error &) {
	return status(
		status_code::OUT_OF_RANGE,
		kinetum::common::static_status_text("configuration slot diagnostic exceeded a representation bound"));
}

}  // namespace

status_or<std::unique_ptr<const config_snapshot_artifact>>
config_snapshot_artifact::create(const kinetum::common::canonical_config_snapshot &canonical)
{
	if (canonical.serialized_bytes.empty()) {
		return status::invalid_argument("canonical configuration snapshot bytes must be nonempty");
	}
	if (canonical.serialized_bytes.size() > kinetum::common::MAX_CONFIG_SNAPSHOT_BYTES) {
		return status::resource_exhausted("canonical configuration snapshot exceeds the exact size bound");
	}

	try {
		kinetum::control::v1::ConfigSnapshot snapshot;
		const auto terminal_status = kinetum::common::admit_terminal_config_snapshot(canonical, &snapshot);
		if (!terminal_status.is_ok()) {
			return terminal_status;
		}

		return std::unique_ptr<const config_snapshot_artifact>(
			new config_snapshot_artifact(std::move(snapshot), canonical.validation_hash));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate canonical configuration snapshot artifact");
	}
}

config_snapshot_artifact::config_snapshot_artifact(kinetum::control::v1::ConfigSnapshot snapshot,
						   kinetum::common::sha256_digest validation_hash) noexcept
	: snapshot_(std::move(snapshot))
	, validation_hash_(validation_hash)
{
}

const kinetum::control::v1::ConfigSnapshot &config_snapshot_artifact::snapshot() const noexcept
{
	return snapshot_;
}

const kinetum::common::sha256_digest &config_snapshot_artifact::validation_hash() const noexcept
{
	return validation_hash_;
}

config_snapshot_retirement_claim::config_snapshot_retirement_claim(
	const config_snapshot_epoch_store *owner, uint64_t claim_id, std::size_t slot_index,
	epoch_slot_state slot_state, uint64_t epoch, std::unique_ptr<const config_snapshot_artifact> artifact) noexcept
	: owner_(owner)
	, claim_id_(claim_id)
	, slot_index_(slot_index)
	, slot_state_(slot_state)
	, epoch_(epoch)
	, artifact_(std::move(artifact))
{
}

config_snapshot_retirement_claim::config_snapshot_retirement_claim(config_snapshot_retirement_claim &&other) noexcept
	: owner_(std::exchange(other.owner_, nullptr))
	, claim_id_(std::exchange(other.claim_id_, 0))
	, slot_index_(std::exchange(other.slot_index_, INVALID_EPOCH_SLOT_INDEX))
	, slot_state_(std::exchange(other.slot_state_, epoch_slot_state::EMPTY))
	, epoch_(std::exchange(other.epoch_, 0))
	, artifact_(std::move(other.artifact_))
{
}

config_snapshot_retirement_claim::~config_snapshot_retirement_claim()
{
	if (owner_ != nullptr || claim_id_ != 0 || slot_index_ != INVALID_EPOCH_SLOT_INDEX ||
	    slot_state_ != epoch_slot_state::EMPTY || epoch_ != 0 || artifact_ != nullptr) {
		std::terminate();
	}
}

uint64_t config_snapshot_retirement_claim::claim_id() const noexcept
{
	return claim_id_;
}

uint64_t config_snapshot_retirement_claim::epoch() const noexcept
{
	return epoch_;
}

epoch_slot_state config_snapshot_retirement_claim::slot_state() const noexcept
{
	return slot_state_;
}

const config_snapshot_artifact *config_snapshot_retirement_claim::artifact() const noexcept
{
	return artifact_.get();
}

void config_snapshot_retirement_claim::resolve_() noexcept
{
	if (artifact_ != nullptr) {
		std::terminate();
	}
	owner_ = nullptr;
	claim_id_ = 0;
	slot_index_ = INVALID_EPOCH_SLOT_INDEX;
	slot_state_ = epoch_slot_state::EMPTY;
	epoch_ = 0;
}

config_snapshot_epoch_store::~config_snapshot_epoch_store()
{
	if (!empty()) {
		std::terminate();
	}
}

status config_snapshot_epoch_store::preflight_future_preparation(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	if (!common::valid_epoch_id(from_epoch) || !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch ||
	    active_claim_id_ != 0u || active_epoch() != from_epoch || prepared_epoch() != 0u ||
	    retained_epoch() != 0u || next_claim_id_ == 0u || next_claim_id_ == std::numeric_limits<uint64_t>::max()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"configuration store cannot stage one future retained generation"));
	}
	std::size_t empty_count = 0u;
	for (std::size_t index = 0u; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
		const auto *descriptor = slots_.slot(index);
		if (descriptor == nullptr) {
			return status::internal_error(kinetum::common::static_status_text(
				"configuration store lost one exact slot descriptor"));
		}
		if (descriptor->state == epoch_slot_state::EMPTY) {
			if (descriptor->epoch != 0u || artifacts_[index] != nullptr) {
				return status::internal_error(kinetum::common::static_status_text(
					"configuration store empty slot retains hidden ownership"));
			}
			++empty_count;
		}
	}
	return empty_count == 1u ? status::ok() :
				   status::failed_precondition(kinetum::common::static_status_text(
					   "configuration store lacks one exact future slot"));
}

status config_snapshot_epoch_store::stage_prepared(uint64_t epoch,
						   std::unique_ptr<const config_snapshot_artifact> &artifact) noexcept
{
	if (active_claim_id_ != 0) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"configuration epoch store already owns a retirement claim"));
	}
	if (artifact == nullptr) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"PREPARE requires one canonical configuration snapshot artifact"));
	}

	const auto staged = slots_.stage_prepared(epoch);
	if (!staged.applied()) {
		return slot_status(staged.result, "PREPARE", epoch);
	}
	if (staged.slot_index >= artifacts_.size() || artifacts_[staged.slot_index] != nullptr) {
		std::terminate();
	}
	artifacts_[staged.slot_index] = std::move(artifact);
	return status::ok();
}

status_or<std::unique_ptr<const config_snapshot_artifact>>
config_snapshot_epoch_store::discard_prepared(uint64_t epoch) noexcept
{
	if (active_claim_id_ != 0) {
		return status::failed_precondition(
			kinetum::common::static_status_text("discard cannot race an exact retirement claim"));
	}
	const std::size_t slot_index = find_slot_index_(epoch, epoch_slot_state::PREPARED);
	if (slot_index == INVALID_EPOCH_SLOT_INDEX) {
		return status::not_found(
			kinetum::common::static_status_text("discard requires an exact PREPARED configuration slot"));
	}
	if (artifacts_[slot_index] == nullptr) {
		std::terminate();
	}

	const auto discarded = slots_.discard_prepared(epoch);
	if (!discarded.applied() || discarded.slot_index != slot_index) {
		std::terminate();
	}
	auto artifact = std::move(artifacts_[slot_index]);
	return artifact;
}

status config_snapshot_epoch_store::preflight_publish_prepared(uint64_t epoch) const noexcept
{
	if (active_claim_id_ != 0) {
		return status::failed_precondition(
			kinetum::common::static_status_text("publication cannot race an exact retirement claim"));
	}
	const auto preflight = slots_.preflight_publish_prepared(epoch);
	if (!preflight.applied()) {
		return slot_status(preflight.result, "PUBLISH preflight", epoch);
	}
	if (preflight.slot_index >= artifacts_.size() || artifacts_[preflight.slot_index] == nullptr) {
		return status::internal_error(kinetum::common::static_status_text(
			"PUBLISH preflight found no exact prepared snapshot artifact"));
	}

	if (active_slot_index_ == INVALID_EPOCH_SLOT_INDEX) {
		if (epoch_in_state_(epoch_slot_state::PUBLISHED) != 0) {
			return status::internal_error(kinetum::common::static_status_text(
				"configuration epoch store has an unindexed published artifact"));
		}
		return status::ok();
	}
	const auto *active = slots_.slot(active_slot_index_);
	if (active == nullptr || active->state != epoch_slot_state::PUBLISHED || active->epoch == 0 ||
	    artifacts_[active_slot_index_] == nullptr) {
		return status::internal_error(
			kinetum::common::static_status_text("configuration epoch store active index is inconsistent"));
	}
	return status::ok();
}

status config_snapshot_epoch_store::publish_prepared(uint64_t epoch) noexcept
{
	auto preflight_status = preflight_publish_prepared(epoch);
	if (!preflight_status.is_ok()) {
		return preflight_status;
	}
	const auto published = slots_.publish_prepared(epoch);
	if (!published.applied() || published.slot_index >= artifacts_.size() ||
	    artifacts_[published.slot_index] == nullptr) {
		std::terminate();
	}
	active_slot_index_ = published.slot_index;
	return status::ok();
}

status config_snapshot_epoch_store::preflight_future_retained(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	if (!common::valid_epoch_id(from_epoch) || !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch ||
	    active_claim_id_ != 0 || active_epoch() != from_epoch || prepared_epoch() != to_epoch ||
	    retained_epoch() != 0u || next_claim_id_ == 0u || next_claim_id_ == std::numeric_limits<uint64_t>::max()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"configuration store cannot represent the exact future retained claim"));
	}
	auto publish = preflight_publish_prepared(to_epoch);
	if (!publish.is_ok()) {
		return publish;
	}
	const std::size_t from_index = find_slot_index_(from_epoch, epoch_slot_state::PUBLISHED);
	const std::size_t to_index = find_slot_index_(to_epoch, epoch_slot_state::PREPARED);
	if (from_index == INVALID_EPOCH_SLOT_INDEX || to_index == INVALID_EPOCH_SLOT_INDEX || from_index == to_index ||
	    artifacts_[from_index] == nullptr || artifacts_[to_index] == nullptr) {
		return status::internal_error(kinetum::common::static_status_text(
			"configuration store future retained ownership is incomplete"));
	}
	return status::ok();
}

uint64_t config_snapshot_epoch_store::active_epoch() const noexcept
{
	if (active_slot_index_ == INVALID_EPOCH_SLOT_INDEX) {
		return 0;
	}
	const auto *descriptor = slots_.slot(active_slot_index_);
	return descriptor != nullptr && descriptor->state == epoch_slot_state::PUBLISHED ? descriptor->epoch : 0;
}

uint64_t config_snapshot_epoch_store::prepared_epoch() const noexcept
{
	return epoch_in_state_(epoch_slot_state::PREPARED);
}

uint64_t config_snapshot_epoch_store::retained_epoch() const noexcept
{
	return epoch_in_state_(epoch_slot_state::RETAINED);
}

const config_snapshot_artifact *config_snapshot_epoch_store::find_exact(uint64_t epoch) const noexcept
{
	const auto *descriptor = slots_.find_exact(epoch);
	if (descriptor == nullptr) {
		return nullptr;
	}
	const std::size_t slot_index = find_slot_index_(epoch, descriptor->state);
	return slot_index == INVALID_EPOCH_SLOT_INDEX ? nullptr : artifacts_[slot_index].get();
}

const config_snapshot_artifact *config_snapshot_epoch_store::active_artifact() const noexcept
{
	return active_slot_index_ < artifacts_.size() ? artifacts_[active_slot_index_].get() : nullptr;
}

status_or<config_snapshot_retirement_claim> config_snapshot_epoch_store::claim_retained(uint64_t epoch) noexcept
{
	return claim_(epoch, epoch_slot_state::RETAINED);
}

status config_snapshot_epoch_store::preflight_claim_retained(uint64_t epoch) const noexcept
{
	if (!common::valid_epoch_id(epoch) || active_claim_id_ != 0 || prepared_epoch() != 0u || next_claim_id_ == 0u ||
	    next_claim_id_ == std::numeric_limits<uint64_t>::max()) {
		return status::failed_precondition(
			kinetum::common::static_status_text("configuration retained claim lacks exact idle ownership"));
	}
	const std::size_t slot_index = find_slot_index_(epoch, epoch_slot_state::RETAINED);
	if (slot_index == INVALID_EPOCH_SLOT_INDEX || artifacts_[slot_index] == nullptr ||
	    active_slot_index_ == INVALID_EPOCH_SLOT_INDEX || active_slot_index_ == slot_index ||
	    active_epoch() <= epoch || active_artifact() == nullptr) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"configuration retained claim does not match exact active truth"));
	}
	return status::ok();
}

status_or<config_snapshot_retirement_claim>
config_snapshot_epoch_store::claim_published_for_shutdown(uint64_t epoch) noexcept
{
	return claim_(epoch, epoch_slot_state::PUBLISHED);
}

status_or<config_snapshot_retirement_claim> config_snapshot_epoch_store::claim_(uint64_t epoch,
										epoch_slot_state state) noexcept
{
	if (active_claim_id_ != 0) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"configuration epoch store already owns a retirement claim"));
	}
	if (prepared_epoch() != 0) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement cannot begin while a PREPARED snapshot remains"));
	}
	if (state != epoch_slot_state::RETAINED && state != epoch_slot_state::PUBLISHED) {
		return status::invalid_argument(
			kinetum::common::static_status_text("retirement claim requires RETAINED or PUBLISHED state"));
	}
	if (state == epoch_slot_state::RETAINED) {
		auto preflight = preflight_claim_retained(epoch);
		if (!preflight.is_ok()) {
			return preflight;
		}
	}
	if (state == epoch_slot_state::PUBLISHED) {
		const auto preflight = slots_.preflight_retire_published(epoch);
		if (!preflight.applied()) {
			return slot_status(preflight.result, "published shutdown claim", epoch);
		}
	}

	const std::size_t slot_index = find_slot_index_(epoch, state);
	if (slot_index == INVALID_EPOCH_SLOT_INDEX) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement claim does not match the exact required slot state"));
	}
	if (artifacts_[slot_index] == nullptr) {
		return status::internal_error(kinetum::common::static_status_text(
			"retirement claim found no exact snapshot artifact ownership"));
	}
	if (state == epoch_slot_state::PUBLISHED && active_slot_index_ != slot_index) {
		return status::failed_precondition(
			kinetum::common::static_status_text("shutdown claim does not match the exact active slot"));
	}
	if (next_claim_id_ == 0 || next_claim_id_ == std::numeric_limits<uint64_t>::max()) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("configuration retirement claim sequence exhausted"));
	}

	const uint64_t claim_id = next_claim_id_++;
	active_claim_id_ = claim_id;
	claimed_slot_index_ = slot_index;
	claimed_slot_state_ = state;
	auto artifact = std::move(artifacts_[slot_index]);
	if (state == epoch_slot_state::PUBLISHED) {
		active_slot_index_ = INVALID_EPOCH_SLOT_INDEX;
	}
	return config_snapshot_retirement_claim(this, claim_id, slot_index, state, epoch, std::move(artifact));
}

status config_snapshot_epoch_store::validate_claim_(const config_snapshot_retirement_claim &claim) const noexcept
{
	if (claim.owner_ != this || active_claim_id_ == 0 || claim.claim_id_ != active_claim_id_ ||
	    claim.slot_index_ != claimed_slot_index_ || claim.slot_state_ != claimed_slot_state_) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement operation does not own the current exact claim"));
	}
	if (claim.epoch_ == 0 || claim.artifact_ == nullptr) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"retirement claim does not carry one exact snapshot artifact"));
	}
	const auto *descriptor = slots_.slot(claim.slot_index_);
	if (descriptor == nullptr || descriptor->epoch != claim.epoch_ || descriptor->state != claim.slot_state_) {
		return status::failed_precondition(
			kinetum::common::static_status_text("retirement claim no longer matches its exact slot"));
	}
	if (artifacts_[claim.slot_index_] != nullptr) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement claim slot already owns a replacement artifact"));
	}
	return status::ok();
}

void config_snapshot_epoch_store::clear_claim_() noexcept
{
	active_claim_id_ = 0;
	claimed_slot_index_ = INVALID_EPOCH_SLOT_INDEX;
	claimed_slot_state_ = epoch_slot_state::EMPTY;
}

status config_snapshot_epoch_store::restore_retirement(config_snapshot_retirement_claim &claim) noexcept
{
	if (auto claim_status = validate_claim_(claim); !claim_status.is_ok()) {
		return claim_status;
	}
	artifacts_[claim.slot_index_] = std::move(claim.artifact_);
	if (claim.slot_state_ == epoch_slot_state::PUBLISHED) {
		active_slot_index_ = claim.slot_index_;
	}
	clear_claim_();
	claim.resolve_();
	return status::ok();
}

status config_snapshot_epoch_store::complete_retirement(config_snapshot_retirement_claim &claim) noexcept
{
	if (auto claim_status = validate_claim_(claim); !claim_status.is_ok()) {
		return claim_status;
	}
	const auto retired = claim.slot_state_ == epoch_slot_state::RETAINED ? slots_.retire_retained(claim.epoch_) :
									       slots_.retire_published(claim.epoch_);
	if (!retired.applied() || retired.slot_index != claim.slot_index_) {
		std::terminate();
	}
	claim.artifact_.reset();
	clear_claim_();
	claim.resolve_();
	return status::ok();
}

const epoch_slot_descriptor *config_snapshot_epoch_store::slot(std::size_t slot_index) const noexcept
{
	return slots_.slot(slot_index);
}

bool config_snapshot_epoch_store::empty() const noexcept
{
	if (!slots_.empty() || active_slot_index_ != INVALID_EPOCH_SLOT_INDEX || active_claim_id_ != 0 ||
	    claimed_slot_index_ != INVALID_EPOCH_SLOT_INDEX || claimed_slot_state_ != epoch_slot_state::EMPTY) {
		return false;
	}
	for (const auto &artifact : artifacts_) {
		if (artifact != nullptr) {
			return false;
		}
	}
	return true;
}

std::size_t config_snapshot_epoch_store::find_slot_index_(uint64_t epoch, epoch_slot_state state) const noexcept
{
	for (std::size_t slot_index = 0; slot_index < EXACT_EPOCH_SLOT_COUNT; ++slot_index) {
		const auto *descriptor = slots_.slot(slot_index);
		if (descriptor != nullptr && descriptor->epoch == epoch && descriptor->state == state) {
			return slot_index;
		}
	}
	return INVALID_EPOCH_SLOT_INDEX;
}

uint64_t config_snapshot_epoch_store::epoch_in_state_(epoch_slot_state state) const noexcept
{
	for (std::size_t slot_index = 0; slot_index < EXACT_EPOCH_SLOT_COUNT; ++slot_index) {
		const auto *descriptor = slots_.slot(slot_index);
		if (descriptor != nullptr && descriptor->state == state) {
			return descriptor->epoch;
		}
	}
	return 0;
}

}  // namespace kinetum::dp
