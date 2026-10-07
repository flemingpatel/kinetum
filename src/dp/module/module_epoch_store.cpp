// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module_epoch_store.cpp
 * @brief Exact module epoch-store and executable-view implementation.
 * @author Fleming Patel
 */

#include "src/dp/module/module_epoch_store.hpp"

#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "src/common/time.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"

namespace kinetum::dp::module
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;
using kinetum::dp::lifecycle::lifecycle_context_owner;
using kinetum::dp::lifecycle::prepared_config_ownership;

namespace
{

/**
 * @brief Convert one exact-slot rejection into a stable cold-path status.
 *
 * @param result Exact slot-table outcome.
 * @param operation Stable operation name for diagnostics.
 * @param epoch Exact epoch involved in the rejected operation.
 * @return OK for APPLIED; otherwise the precise public status category.
 */
[[nodiscard]] status slot_status(epoch_slot_result result, const char *operation, uint64_t epoch) noexcept
try {
	const std::string prefix =
		std::string(operation) + " rejected exact module epoch " + std::to_string(epoch) + ": ";
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
		kinetum::common::static_status_text("module slot diagnostic exhausted memory"));
} catch (const std::length_error &) {
	return status(status_code::OUT_OF_RANGE,
		      kinetum::common::static_status_text("module slot diagnostic exceeded a representation bound"));
}

}  // namespace

module_retirement_claim::module_retirement_claim(const module_epoch_store *owner, uint64_t claim_id,
						 std::size_t slot_index, module_retirement_kind kind,
						 uint32_t module_image_index, uint32_t context_index, uint64_t epoch,
						 kinetum::dp::lifecycle::prepared_config_ownership ownership) noexcept
	: owner_(owner)
	, claim_id_(claim_id)
	, slot_index_(slot_index)
	, kind_(kind)
	, module_image_index_(module_image_index)
	, context_index_(context_index)
	, epoch_(epoch)
	, ownership_(std::move(ownership))
{
}

module_retirement_claim::module_retirement_claim(module_retirement_claim &&other) noexcept
	: owner_(std::exchange(other.owner_, nullptr))
	, claim_id_(std::exchange(other.claim_id_, 0))
	, slot_index_(std::exchange(other.slot_index_, INVALID_EPOCH_SLOT_INDEX))
	, kind_(std::exchange(other.kind_, module_retirement_kind::RETAINED))
	, module_image_index_(std::exchange(other.module_image_index_, 0))
	, context_index_(std::exchange(other.context_index_, 0))
	, epoch_(std::exchange(other.epoch_, 0))
	, ownership_(std::move(other.ownership_))
	, retirement_completed_(std::exchange(other.retirement_completed_, false))
{
}

module_retirement_claim::~module_retirement_claim()
{
	if (owner_ != nullptr || claim_id_ != 0 || slot_index_ != INVALID_EPOCH_SLOT_INDEX || epoch_ != 0 ||
	    ownership_.owns_state() || retirement_completed_) {
		std::terminate();
	}
}

uint64_t module_retirement_claim::claim_id() const noexcept
{
	return claim_id_;
}

uint64_t module_retirement_claim::epoch() const noexcept
{
	return epoch_;
}

module_retirement_kind module_retirement_claim::kind() const noexcept
{
	return kind_;
}

const prepared_config_ownership &module_retirement_claim::ownership() const noexcept
{
	return ownership_;
}

status module_retirement_claim::consume_after_retire() noexcept
{
	if (owner_ == nullptr || claim_id_ == 0 || slot_index_ == INVALID_EPOCH_SLOT_INDEX || epoch_ == 0 ||
	    retirement_completed_) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement consumption requires one unresolved exact claim"));
	}
	auto retired = ownership_.retire_exact(module_image_index_, context_index_, epoch_);
	if (!retired.is_ok()) {
		return retired;
	}
	retirement_completed_ = true;
	return status::ok();
}

void module_retirement_claim::resolve_() noexcept
{
	if (ownership_.owns_state()) {
		std::terminate();
	}
	owner_ = nullptr;
	claim_id_ = 0;
	slot_index_ = INVALID_EPOCH_SLOT_INDEX;
	kind_ = module_retirement_kind::RETAINED;
	module_image_index_ = 0;
	context_index_ = 0;
	epoch_ = 0;
	retirement_completed_ = false;
}

status_or<std::unique_ptr<module_epoch_store>>
module_epoch_store::create(uint32_t module_image_index, uint32_t context_index, const kinetum_module *descriptor,
			   kinetum_ctx *context, lifecycle_context_owner *telemetry_owner)
{
	if (descriptor == nullptr || context == nullptr || telemetry_owner == nullptr ||
	    descriptor->module_id == nullptr || descriptor->activate_config == nullptr ||
	    telemetry_owner->identity().module_id != descriptor->module_id ||
	    telemetry_owner->identity().module_image_index != module_image_index ||
	    telemetry_owner->identity().context_index != context_index ||
	    telemetry_owner->identity().worker_index != context->worker_index ||
	    telemetry_owner->identity().cpu_core_id != context->cpu_core_id ||
	    telemetry_owner->identity().numa_node != context->numa_node) {
		return status::invalid_argument(
			"module epoch store requires exact descriptor, context, telemetry owner, and ACTIVATE");
	}
	if (descriptor->mode == KINETUM_MODULE_PASSIVE) {
		if (descriptor->process == nullptr || descriptor->ingest != nullptr || descriptor->run != nullptr ||
		    descriptor->on_control != nullptr) {
			return status::invalid_argument(
				"passive module epoch store received an invalid callback shape");
		}
	} else if (descriptor->mode == KINETUM_MODULE_ACTIVE) {
		if (descriptor->process != nullptr || descriptor->run == nullptr) {
			return status::invalid_argument("active module epoch store received an invalid callback shape");
		}
	} else {
		return status::invalid_argument("module epoch store received an unknown execution mode");
	}

	try {
		return std::unique_ptr<module_epoch_store>(new module_epoch_store(
			module_image_index, context_index, *descriptor, *context, *telemetry_owner));
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("failed to allocate exact module epoch store");
	}
}

module_epoch_store::module_epoch_store(uint32_t module_image_index, uint32_t context_index,
				       const kinetum_module &descriptor, kinetum_ctx &context,
				       kinetum::dp::lifecycle::lifecycle_context_owner &telemetry_owner) noexcept
	: module_image_index_(module_image_index)
	, context_index_(context_index)
	, descriptor_(descriptor)
	, context_(context)
	, telemetry_owner_(telemetry_owner)
{
}

module_epoch_store::~module_epoch_store()
{
	if (!empty()) {
		std::terminate();
	}
}

status module_epoch_store::stage_prepared(prepared_config_ownership &ownership) noexcept
{
	if (prepared_epoch_.load(std::memory_order_acquire) != 0 || active_claim_id_ != 0) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module epoch store already owns pending lifecycle work"));
	}
	if (!ownership.owns_state() || ownership.module_image_index() != module_image_index_ ||
	    ownership.context_index() != context_index_) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"prepared token does not match the exact module epoch store identity"));
	}

	const uint64_t epoch = ownership.epoch();
	const auto stage_preflight = slots_.preflight_stage_prepared(epoch);
	if (!stage_preflight.applied()) {
		return slot_status(stage_preflight.result, "PREPARE publication", epoch);
	}
	const uint64_t current_epoch = active_epoch();
	if (current_epoch != 0u && !telemetry_owner_.telemetry_target_reserved(current_epoch, epoch)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module store telemetry target reserve is incomplete"));
	}
	const auto staged = slots_.stage_prepared(epoch);
	if (!staged.applied() || staged.slot_index != stage_preflight.slot_index) {
		std::terminate();
	}
	if (staged.slot_index >= ownership_.size() || ownership_[staged.slot_index].has_value()) {
		std::terminate();
	}
	ownership_[staged.slot_index].emplace(std::move(ownership));

	// The token, immutable module artifact, and exact slot descriptor are fully
	// constructed before this release. ACTIVATE's owner acquire-loads the same
	// epoch before borrowing any of those non-atomic fields.
	prepared_epoch_.store(epoch, std::memory_order_release);
	return status::ok();
}

status_or<prepared_config_ownership> module_epoch_store::discard_prepared(uint64_t epoch) noexcept
{
	if (prepared_epoch_.load(std::memory_order_acquire) != epoch || active_claim_id_ != 0) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"discard requires the exact release-published prepared epoch"));
	}
	const auto *descriptor = slots_.find_exact(epoch);
	if (descriptor == nullptr || descriptor->state != epoch_slot_state::PREPARED) {
		return status::not_found(
			kinetum::common::static_status_text("discard requires an exact PREPARED module slot"));
	}

	std::size_t slot_index = INVALID_EPOCH_SLOT_INDEX;
	for (std::size_t index = 0; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
		const auto *candidate = slots_.slot(index);
		if (candidate != nullptr && candidate->epoch == epoch &&
		    candidate->state == epoch_slot_state::PREPARED) {
			slot_index = index;
			break;
		}
	}
	if (slot_index == INVALID_EPOCH_SLOT_INDEX || !ownership_[slot_index].has_value()) {
		std::terminate();
	}

	const auto discarded = slots_.discard_prepared(epoch);
	if (!discarded.applied() || discarded.slot_index != slot_index) {
		std::terminate();
	}
	auto result = std::move(*ownership_[slot_index]);
	ownership_[slot_index].reset();
	prepared_epoch_.store(0, std::memory_order_release);
	return result;
}

status_or<module_executable_view>
module_epoch_store::make_view_(const prepared_config_ownership &ownership) const noexcept
{
	if (!ownership.owns_state() || ownership.module_image_index() != module_image_index_ ||
	    ownership.context_index() != context_index_) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"module executable view requires the exact live prepared token"));
	}
	auto record_or = ownership.borrow_exact(module_image_index_, context_index_, ownership.epoch());
	if (!record_or.is_ok()) {
		return std::move(record_or).error();
	}
	const auto record = record_or.value();
	module_executable_view view{
		.context = &context_,
		.packet_config = record.packet_config,
		.process = descriptor_.process,
		.ingest = descriptor_.ingest,
		.run = descriptor_.run,
		.on_control = descriptor_.on_control,
		.epoch = ownership.epoch(),
		.context_index = context_index_,
		.mode = descriptor_.mode,
	};
	if (!view.valid()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"prepared module token cannot form a complete executable view"));
	}
	return view;
}

status_or<module_epoch_store::prepared_activation>
module_epoch_store::preflight_activation_(uint64_t epoch) const noexcept
{
	// This acquire pairs with PREPARE publication and makes the complete token,
	// slot descriptor, and immutable artifact visible to the sole owner worker.
	if (prepared_epoch_.load(std::memory_order_acquire) != epoch || active_claim_id_ != 0) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"ACTIVATE requires the exact release-published prepared epoch"));
	}
	const auto preflight = slots_.preflight_publish_prepared(epoch);
	if (!preflight.applied()) {
		return slot_status(preflight.result, "ACTIVATE preflight", epoch);
	}
	if (preflight.slot_index >= ownership_.size()) {
		return status::internal_error(
			kinetum::common::static_status_text("ACTIVATE exact slot index exceeds prepared ownership"));
	}
	auto &slot_ownership = ownership_[preflight.slot_index];
	if (!slot_ownership.has_value()) {
		return status::internal_error(
			kinetum::common::static_status_text("ACTIVATE exact slot has no prepared ownership token"));
	}
	auto view_or = make_view_(*slot_ownership);
	if (!view_or.is_ok()) {
		return std::move(view_or).error();
	}
	const module_executable_view prospective = view_or.value();
	auto record_or = slot_ownership->borrow_exact(module_image_index_, context_index_, epoch);
	if (!record_or.is_ok()) {
		return std::move(record_or).error();
	}
	const auto record = record_or.value();
	return prepared_activation{
		.slot_index = preflight.slot_index,
		.executable_view = prospective,
		.callback_input = {record.owner_handle, record.packet_config},
	};
}

status module_epoch_store::preflight_activate_prepared(uint64_t epoch) const noexcept
{
	auto preflight_or = preflight_activation_(epoch);
	if (!preflight_or.is_ok()) {
		return std::move(preflight_or).error();
	}
	const uint64_t from_epoch = active_epoch();
	if (from_epoch != 0u && !telemetry_owner_.preflight_activate_telemetry(from_epoch, epoch)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module ACTIVATE telemetry reserve is incomplete"));
	}
	return status::ok();
}

status module_epoch_store::preflight_prepared_for_commit(uint64_t epoch) const noexcept
{
	auto preflight_or = preflight_activation_(epoch);
	if (!preflight_or.is_ok()) {
		return std::move(preflight_or).error();
	}
	const uint64_t from_epoch = active_epoch();
	if (from_epoch != 0u && !telemetry_owner_.telemetry_target_reserved(from_epoch, epoch)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module PREPARED telemetry reserve is incomplete"));
	}
	return status::ok();
}

status module_epoch_store::activate_prepared(uint64_t epoch, uint64_t now_ns) noexcept
{
	if (now_ns == 0u) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"module ACTIVATE requires one exact owner-worker timestamp"));
	}
	auto activation_or = preflight_activation_(epoch);
	if (!activation_or.is_ok()) {
		return std::move(activation_or).error();
	}
	const prepared_activation activation = activation_or.value();
	const uint64_t from_epoch = active_epoch();
	if (from_epoch == 0u) {
		if (telemetry_owner_.telemetry_active_epoch() != 0u) {
			std::terminate();
		}
		telemetry_owner_.bind_bootstrap_telemetry(epoch, now_ns);
	} else if (!telemetry_owner_.preflight_activate_telemetry(from_epoch, epoch)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module ACTIVATE telemetry reserve is incomplete"));
	}
	if (from_epoch != 0u) {
		// Final old-epoch telemetry is immutable before target activation can
		// update a context-owned handle. Packet work cannot interleave here.
		telemetry_owner_.activate_telemetry_epoch(from_epoch, epoch, now_ns);
	}

	try {
		descriptor_.activate_config(&context_, epoch, &activation.callback_input);
	} catch (...) {
		std::terminate();
	}

	// ACTIVATE runs on the same sole owner that executes packets. That owner
	// cannot interleave packet callbacks while it is inside this method. The
	// foreign callback is therefore followed only by preflight-proven bounded
	// assignments: exact slot promotion, active-index update, and view commit.
	const auto published = slots_.publish_prepared(epoch);
	if (!published.applied() || published.slot_index != activation.slot_index) {
		std::terminate();
	}
	active_slot_index_ = published.slot_index;
	active_view_ = activation.executable_view;
	prepared_epoch_.store(0, std::memory_order_release);
	return status::ok();
}

status module_epoch_store::preflight_future_retained(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	if (!common::valid_epoch_id(from_epoch) || !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch ||
	    active_epoch() != from_epoch || prepared_epoch_.load(std::memory_order_acquire) != to_epoch ||
	    active_claim_id_ != 0u || next_claim_id_ == 0u || next_claim_id_ == std::numeric_limits<uint64_t>::max()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"module store cannot represent the exact future retained claim"));
	}
	auto activation = preflight_activation_(to_epoch);
	if (!activation.is_ok()) {
		return std::move(activation).error();
	}
	if (!telemetry_owner_.telemetry_target_reserved(from_epoch, to_epoch)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module future telemetry reserve is incomplete"));
	}
	std::size_t from_index = INVALID_EPOCH_SLOT_INDEX;
	for (std::size_t index = 0u; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
		const auto *descriptor = slots_.slot(index);
		if (descriptor != nullptr && descriptor->epoch == from_epoch &&
		    descriptor->state == epoch_slot_state::PUBLISHED) {
			from_index = index;
			break;
		}
	}
	if (from_index == INVALID_EPOCH_SLOT_INDEX || from_index == activation->slot_index ||
	    active_slot_index_ != from_index || !ownership_[from_index].has_value()) {
		return status::internal_error(
			kinetum::common::static_status_text("module store future retained ownership is incomplete"));
	}
	return status::ok();
}

const module_executable_view *module_epoch_store::active_view() const noexcept
{
	return active_view_.valid() ? &active_view_ : nullptr;
}

const module_executable_view &module_epoch_store::owner_executable_view() const noexcept
{
	return active_view_;
}

uint64_t module_epoch_store::active_epoch() const noexcept
{
	return active_view_.valid() ? active_view_.epoch : 0;
}

uint64_t module_epoch_store::prepared_epoch() const noexcept
{
	return prepared_epoch_.load(std::memory_order_acquire);
}

uint32_t module_epoch_store::context_index() const noexcept
{
	return context_index_;
}

status module_epoch_store::bind_protocol_fault_latch(epoch_protocol_fault_latch &faults) noexcept
{
	if (protocol_faults_ == nullptr) {
		protocol_faults_ = &faults;
		return status::ok();
	}
	return protocol_faults_ == &faults ? status::ok() :
					     status::failed_precondition(kinetum::common::static_status_text(
						     "module epoch store protocol-fault authority changed identity"));
}

void module_epoch_store::record_epoch_mismatch(uint64_t packet_epoch, uint16_t stage_instance_index,
					       int32_t region_id) noexcept
{
	const uint64_t execution_epoch = active_epoch();
	if (diagnostics_.mismatch_count != std::numeric_limits<uint64_t>::max()) {
		++diagnostics_.mismatch_count;
	}
	diagnostics_.sticky_fault = 1;
	if (diagnostics_.first_fault_valid == 0) {
		diagnostics_.first_fault = module_epoch_mismatch_record{
			.packet_epoch = packet_epoch,
			.active_epoch = execution_epoch,
			.context_index = context_index_,
			.stage_instance_index = stage_instance_index,
			.reserved = 0,
			.worker_index = context_.worker_index,
			.region_id = region_id,
		};
		diagnostics_.first_fault_valid = 1;
	}
	if (protocol_faults_ != nullptr) {
		(void)protocol_faults_->record(epoch_protocol_first_fault{
			.runtime_generation = telemetry_owner_.telemetry_runtime_generation(),
			.transition_generation = 0u,
			.from_epoch = execution_epoch,
			.to_epoch = 0u,
			.observed_epoch = packet_epoch,
			.expected_value = execution_epoch,
			.observed_value = packet_epoch,
			.observed_monotonic_ns = common::cached_ns(),
			.worker_index = context_.worker_index,
			.boundary_index = UINT32_MAX,
			.context_index = context_index_,
			.stage_instance_index = stage_instance_index,
			.code = epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH,
			.disposition = epoch_protocol_fault_disposition::DROP_AND_RETIRE,
			.padding = {},
		});
	}
	const uint64_t telemetry_epoch = telemetry_owner_.telemetry_active_epoch();
	if (execution_epoch == 0u && telemetry_epoch == 0u) {
		// Before Bootstrap, the store owns bounded local rejection evidence but
		// no epoch-tagged telemetry bank exists to receive a projection.
		return;
	}
	if (execution_epoch != telemetry_epoch) {
		std::terminate();
	}
	telemetry_owner_.record_telemetry_mismatch(lifecycle::lifecycle_telemetry_mismatch_snapshot{
		.mismatch_count = diagnostics_.mismatch_count,
		.packet_epoch = diagnostics_.first_fault.packet_epoch,
		.active_epoch = diagnostics_.first_fault.active_epoch,
		.context_index = diagnostics_.first_fault.context_index,
		.worker_index = diagnostics_.first_fault.worker_index,
		.stage_instance_index = diagnostics_.first_fault.stage_instance_index,
		.reserved = 0u,
		.region_id = diagnostics_.first_fault.region_id,
		.first_fault_valid = diagnostics_.first_fault_valid,
		.sticky_fault = diagnostics_.sticky_fault,
		.padding = {},
	});
}

module_epoch_diagnostics module_epoch_store::diagnostics_after_quiescence() const noexcept
{
	return diagnostics_;
}

status_or<module_retirement_claim> module_epoch_store::claim_(uint64_t epoch, module_retirement_kind kind) noexcept
{
	if (active_claim_id_ != 0 || prepared_epoch_.load(std::memory_order_acquire) != 0) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module epoch store already owns pending lifecycle work"));
	}
	if (kind == module_retirement_kind::RETAINED) {
		auto preflight = preflight_claim_retained(epoch);
		if (!preflight.is_ok()) {
			return preflight;
		}
	}
	if (kind == module_retirement_kind::PUBLISHED_SHUTDOWN) {
		const auto preflight = slots_.preflight_retire_published(epoch);
		if (!preflight.applied()) {
			return slot_status(preflight.result, "published shutdown claim", epoch);
		}
	}
	if (!telemetry_owner_.telemetry_epoch_aggregated(epoch)) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"module retirement requires exact completed telemetry aggregation"));
	}
	const auto *exact = slots_.find_exact(epoch);
	const epoch_slot_state required = kind == module_retirement_kind::RETAINED ? epoch_slot_state::RETAINED :
										     epoch_slot_state::PUBLISHED;
	if (exact == nullptr || exact->state != required) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement claim does not match the exact required slot state"));
	}

	std::size_t slot_index = INVALID_EPOCH_SLOT_INDEX;
	for (std::size_t index = 0; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
		const auto *candidate = slots_.slot(index);
		if (candidate != nullptr && candidate->epoch == epoch && candidate->state == required) {
			slot_index = index;
			break;
		}
	}
	if (slot_index == INVALID_EPOCH_SLOT_INDEX || !ownership_[slot_index].has_value()) {
		return status::internal_error(
			kinetum::common::static_status_text("retirement claim found no exact artifact ownership"));
	}
	if (kind == module_retirement_kind::PUBLISHED_SHUTDOWN &&
	    (active_slot_index_ != slot_index || active_view_.epoch != epoch)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("shutdown claim does not match the exact active view"));
	}
	if (next_claim_id_ == 0 || next_claim_id_ == std::numeric_limits<uint64_t>::max()) {
		return status::resource_exhausted(
			kinetum::common::static_status_text("module retirement claim sequence exhausted"));
	}

	const uint64_t claim_id = next_claim_id_++;
	active_claim_id_ = claim_id;
	claimed_slot_index_ = slot_index;
	claimed_kind_ = kind;
	auto token = std::move(*ownership_[slot_index]);
	ownership_[slot_index].reset();
	if (kind == module_retirement_kind::PUBLISHED_SHUTDOWN) {
		active_view_ = {};
		active_slot_index_ = INVALID_EPOCH_SLOT_INDEX;
	}
	return module_retirement_claim(this, claim_id, slot_index, kind, module_image_index_, context_index_, epoch,
				       std::move(token));
}

status_or<module_retirement_claim> module_epoch_store::claim_retained(uint64_t epoch) noexcept
{
	return claim_(epoch, module_retirement_kind::RETAINED);
}

status module_epoch_store::preflight_claim_retained(uint64_t epoch) const noexcept
{
	if (!common::valid_epoch_id(epoch) || active_claim_id_ != 0u ||
	    prepared_epoch_.load(std::memory_order_acquire) != 0u || next_claim_id_ == 0u ||
	    next_claim_id_ == std::numeric_limits<uint64_t>::max() || active_slot_index_ == INVALID_EPOCH_SLOT_INDEX ||
	    active_view_.epoch <= epoch) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module retained claim lacks exact active ownership"));
	}
	std::size_t retained_index = INVALID_EPOCH_SLOT_INDEX;
	for (std::size_t index = 0u; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
		const auto *descriptor = slots_.slot(index);
		if (descriptor != nullptr && descriptor->epoch == epoch &&
		    descriptor->state == epoch_slot_state::RETAINED) {
			retained_index = index;
			break;
		}
	}
	if (retained_index == INVALID_EPOCH_SLOT_INDEX || retained_index == active_slot_index_ ||
	    !ownership_[retained_index].has_value() || !active_view_.valid()) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module retained claim does not match exact active truth"));
	}
	return status::ok();
}

status_or<module_retirement_claim> module_epoch_store::claim_published_for_shutdown(uint64_t epoch) noexcept
{
	return claim_(epoch, module_retirement_kind::PUBLISHED_SHUTDOWN);
}

status module_epoch_store::validate_claim_(const module_retirement_claim &claim) const noexcept
{
	if (claim.owner_ != this || active_claim_id_ == 0 || claim.claim_id_ != active_claim_id_ ||
	    claim.slot_index_ != claimed_slot_index_ || claim.kind_ != claimed_kind_) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement operation does not own the current exact claim"));
	}
	if (claim.module_image_index_ != module_image_index_ || claim.context_index_ != context_index_ ||
	    claim.epoch_ == 0) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"retirement claim identity does not match the exact module store"));
	}
	const auto *slot_descriptor = slots_.slot(claim.slot_index_);
	if (slot_descriptor == nullptr || slot_descriptor->epoch != claim.epoch_) {
		return status::failed_precondition(
			kinetum::common::static_status_text("retirement claim no longer matches its exact slot"));
	}
	return status::ok();
}

void module_epoch_store::clear_claim_() noexcept
{
	active_claim_id_ = 0;
	claimed_slot_index_ = INVALID_EPOCH_SLOT_INDEX;
	claimed_kind_ = module_retirement_kind::RETAINED;
}

status module_epoch_store::restore_retirement(module_retirement_claim &claim) noexcept
{
	if (auto claim_status = validate_claim_(claim); !claim_status.is_ok()) {
		return claim_status;
	}
	if (claim.retirement_completed_) {
		return status::failed_precondition(
			kinetum::common::static_status_text("completed RETIRE ownership cannot be restored"));
	}
	if (!claim.ownership_.owns_state() || claim.ownership_.module_image_index() != module_image_index_ ||
	    claim.ownership_.context_index() != context_index_ || claim.ownership_.epoch() != claim.epoch_) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"retirement restore requires the exact still-live ownership token"));
	}
	if (ownership_[claim.slot_index_].has_value()) {
		std::terminate();
	}

	module_executable_view restored_view{};
	if (claim.kind_ == module_retirement_kind::PUBLISHED_SHUTDOWN) {
		auto view_or = make_view_(claim.ownership_);
		if (!view_or.is_ok()) {
			return std::move(view_or).error();
		}
		restored_view = view_or.value();
	}
	ownership_[claim.slot_index_].emplace(std::move(claim.ownership_));
	if (claim.kind_ == module_retirement_kind::PUBLISHED_SHUTDOWN) {
		active_slot_index_ = claim.slot_index_;
		active_view_ = restored_view;
		telemetry_owner_.restore_shutdown_telemetry(claim.epoch_);
	}
	clear_claim_();
	claim.resolve_();
	return status::ok();
}

status module_epoch_store::complete_retirement(module_retirement_claim &claim) noexcept
{
	if (auto claim_status = validate_claim_(claim); !claim_status.is_ok()) {
		return claim_status;
	}
	if (!claim.retirement_completed_ || claim.ownership_.owns_state()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"retirement completion requires exact claim-scoped RETIRE consumption"));
	}

	const uint64_t retired_epoch = claim.epoch_;
	const module_retirement_kind retired_kind = claim.kind_;
	const uint64_t successor_epoch = retired_kind == module_retirement_kind::RETAINED ? active_epoch() : 0u;
	const auto retired = retired_kind == module_retirement_kind::RETAINED ? slots_.retire_retained(retired_epoch) :
										slots_.retire_published(retired_epoch);
	if (!retired.applied() || retired.slot_index != claim.slot_index_) {
		std::terminate();
	}
	telemetry_owner_.retire_telemetry_epoch(retired_epoch, successor_epoch);
	clear_claim_();
	claim.resolve_();
	return status::ok();
}

const epoch_slot_descriptor *module_epoch_store::slot(std::size_t slot_index) const noexcept
{
	return slots_.slot(slot_index);
}

bool module_epoch_store::empty() const noexcept
{
	return !telemetry_owner_.module_health_owner_claimed() && ownership_empty_();
}

bool module_epoch_store::health_owner_release_ready() const noexcept
{
	return telemetry_owner_.module_health_owner_claimed() && ownership_empty_();
}

bool module_epoch_store::ownership_empty_() const noexcept
{
	if (!slots_.empty() || prepared_epoch_.load(std::memory_order_acquire) != 0 || active_view_.valid() ||
	    active_slot_index_ != INVALID_EPOCH_SLOT_INDEX || active_claim_id_ != 0 ||
	    claimed_slot_index_ != INVALID_EPOCH_SLOT_INDEX || !telemetry_owner_.telemetry_empty()) {
		return false;
	}
	for (const auto &token : ownership_) {
		if (token.has_value()) {
			return false;
		}
	}
	return true;
}

}  // namespace kinetum::dp::module
