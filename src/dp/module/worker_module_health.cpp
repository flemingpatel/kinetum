// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_module_health.cpp
 * @brief Exact owner-worker module-health invocation implementation.
 * @author Fleming Patel
 */

#include "src/dp/module/worker_module_health.hpp"

#include <algorithm>
#include <exception>
#include <new>
#include <stdexcept>
#include <utility>

#include "src/common/epoch_transition_contract.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/module/module_epoch_store.hpp"

namespace kinetum::dp::module
{

module_health_invocation::module_health_invocation(worker_module_health &owner, claim_identity identity,
						   kinetum_ctx &context, const void *packet_config) noexcept
	: owner_(&owner)
	, claim_id_(identity.claim_id)
	, row_ordinal_(identity.row_ordinal)
	, epoch_(identity.epoch)
	, context_(&context)
	, packet_config_(packet_config)
{
}

module_health_invocation::module_health_invocation(module_health_invocation &&other) noexcept
	: owner_(std::exchange(other.owner_, nullptr))
	, claim_id_(std::exchange(other.claim_id_, 0u))
	, row_ordinal_(std::exchange(other.row_ordinal_, 0u))
	, epoch_(std::exchange(other.epoch_, 0u))
	, start_ns_(std::exchange(other.start_ns_, 0u))
	, context_(std::exchange(other.context_, nullptr))
	, packet_config_(std::exchange(other.packet_config_, nullptr))
	, assessment_(other.assessment_)
	, state_(other.state_)
{
	other.assessment_ = {};
	other.state_ = state::CLAIMED;
}

module_health_invocation::~module_health_invocation()
{
	if (owner_ != nullptr || claim_id_ != 0u || epoch_ != 0u || start_ns_ != 0u || context_ != nullptr ||
	    packet_config_ != nullptr) {
		std::terminate();
	}
}

void module_health_invocation::invoke(uint64_t start_ns) noexcept
{
	if (owner_ == nullptr || claim_id_ == 0u || start_ns == 0u || start_ns_ != 0u || state_ != state::CLAIMED) {
		std::terminate();
	}
	owner_->invoke_(*this, start_ns);
}

void module_health_invocation::complete(uint64_t finish_ns) noexcept
{
	if (owner_ == nullptr || claim_id_ == 0u || state_ != state::INVOKED) {
		std::terminate();
	}
	owner_->complete_(*this, finish_ns);
}

void module_health_invocation::resolve_() noexcept
{
	owner_ = nullptr;
	claim_id_ = 0u;
	row_ordinal_ = 0u;
	epoch_ = 0u;
	start_ns_ = 0u;
	context_ = nullptr;
	packet_config_ = nullptr;
	assessment_ = {};
	state_ = state::CLAIMED;
}

common::status_or<std::unique_ptr<worker_module_health>>
worker_module_health::create(uint32_t worker_index, uint64_t runtime_generation, uint64_t callback_budget_ns,
			     std::span<const worker_module_health_binding> bindings, worker_epoch_ledger &ledger)
{
	if (worker_index == UINT32_MAX || runtime_generation == 0u || callback_budget_ns == 0u || bindings.empty() ||
	    ledger.worker_index() != worker_index || ledger.runtime_generation() != runtime_generation) {
		return common::status::invalid_argument(
			"module health requires exact worker, runtime, budget, and ledger identity");
	}
	if (ledger.active_epoch() != 0u || ledger.source_epoch() != 0u || ledger.future_epoch() != 0u ||
	    !ledger.empty()) {
		return common::status::failed_precondition(
			"module health requires its exact worker ledger before Bootstrap binding");
	}
	uint32_t previous_stage = 0u;
	uint32_t previous_context = 0u;
	bool have_previous = false;
	std::size_t callback_count = 0u;
	for (const auto &binding : bindings) {
		const auto *identity = binding.publication != nullptr ? &binding.publication->identity() : nullptr;
		if (binding.stage_instance_index > UINT16_MAX || binding.context_index == UINT32_MAX ||
		    binding.context == nullptr || binding.store == nullptr || binding.descriptor == nullptr ||
		    binding.descriptor->module_id == nullptr || identity == nullptr ||
		    binding.store->context_index() != binding.context_index ||
		    binding.context->worker_index != worker_index ||
		    binding.context->cpu_core_id != identity->cpu_core_id ||
		    binding.context->numa_node != identity->numa_node ||
		    identity->context_index != binding.context_index || identity->worker_index != worker_index ||
		    identity->module_id != binding.descriptor->module_id ||
		    binding.publication->telemetry_runtime_generation() != runtime_generation ||
		    binding.publication->telemetry_stage_instance_index() != binding.stage_instance_index ||
		    binding.publication->health_callback_available() != (binding.descriptor->health_check != nullptr) ||
		    (have_previous &&
		     (binding.stage_instance_index <= previous_stage || binding.context_index <= previous_context))) {
			return common::status::failed_precondition(
				"module health binding does not match exact stage/context ownership");
		}
		previous_stage = binding.stage_instance_index;
		previous_context = binding.context_index;
		have_previous = true;
		callback_count += binding.descriptor->health_check != nullptr ? 1u : 0u;
	}
	try {
		std::vector<worker_module_health_binding> rows(bindings.begin(), bindings.end());
		std::size_t claimed = 0u;
		for (auto &row : rows) {
			const auto claim = row.publication->claim_module_health_owner(
				runtime_generation, static_cast<uint16_t>(row.stage_instance_index));
			if (!claim.is_ok()) {
				while (claimed != 0u) {
					--claimed;
					rows[claimed].publication->release_module_health_owner();
				}
				return claim;
			}
			++claimed;
		}
		auto owner = std::unique_ptr<worker_module_health>(new (std::nothrow) worker_module_health(
			owner_identity{
				.worker_index = worker_index,
				.runtime_generation = runtime_generation,
				.callback_budget_ns = callback_budget_ns,
			},
			std::move(rows), ledger));
		if (owner == nullptr) {
			for (auto it = bindings.rbegin(); it != bindings.rend(); ++it) {
				it->publication->release_module_health_owner();
			}
			return common::status::resource_exhausted("module health owner allocation failed");
		}
		if (owner->callback_count() != callback_count) {
			std::terminate();
		}
		return owner;
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("module health binding allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "module health binding extent exceeds the host size domain");
	}
}

worker_module_health::worker_module_health(owner_identity identity, std::vector<worker_module_health_binding> bindings,
					   worker_epoch_ledger &ledger) noexcept
	: worker_index_(identity.worker_index)
	, runtime_generation_(identity.runtime_generation)
	, callback_budget_ns_(identity.callback_budget_ns)
	, bindings_(std::move(bindings))
	, ledger_(&ledger)
{
}

worker_module_health::~worker_module_health()
{
	if (!quiescent()) {
		std::terminate();
	}
	for (const auto &binding : bindings_) {
		if (binding.publication == nullptr || binding.store == nullptr ||
		    !binding.publication->module_health_owner_claimed() ||
		    !binding.store->health_owner_release_ready()) {
			std::terminate();
		}
	}
	for (auto it = bindings_.rbegin(); it != bindings_.rend(); ++it) {
		it->publication->release_module_health_owner();
		if (!it->store->empty()) {
			std::terminate();
		}
	}
}

void worker_module_health::bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept
{
	if (bound_ || !common::valid_epoch_id(bootstrap_epoch) || ledger_ == nullptr ||
	    ledger_->active_epoch() != bootstrap_epoch || ledger_->source_epoch() != bootstrap_epoch ||
	    ledger_->future_epoch() != 0u || !quiescent()) {
		std::terminate();
	}
	for (const auto &binding : bindings_) {
		const auto *view = binding.store->active_view();
		if (view == nullptr || view->epoch != bootstrap_epoch || view->context_index != binding.context_index ||
		    view->context != binding.context ||
		    binding.publication->telemetry_active_epoch() != bootstrap_epoch ||
		    !binding.publication->module_health_owner_claimed()) {
			std::terminate();
		}
	}
	bound_ = true;
}

std::optional<module_health_invocation> worker_module_health::begin(std::size_t row_ordinal) noexcept
{
	const auto &binding = binding_(row_ordinal);
	if (!bound_ || ledger_ == nullptr || live_claim_id_ != 0u || next_claim_id_ == 0u ||
	    next_claim_id_ == UINT64_MAX || !binding.publication->module_health_owner_claimed()) {
		std::terminate();
	}
	if (binding.descriptor->health_check == nullptr) {
		return std::nullopt;
	}
	const uint64_t active_epoch = ledger_->active_epoch();
	const uint64_t source_epoch = ledger_->source_epoch();
	if (active_epoch != source_epoch) {
		return std::nullopt;
	}
	const auto &view = binding.store->owner_executable_view();
	if (!view.valid() || view.epoch != active_epoch || view.context_index != binding.context_index ||
	    view.context != binding.context || binding.publication->telemetry_active_epoch() != active_epoch) {
		std::terminate();
	}
	ledger_->acquire(active_epoch);
	const uint64_t claim_id = next_claim_id_++;
	live_claim_id_ = claim_id;
	live_row_ordinal_ = row_ordinal;
	return module_health_invocation(*this,
					module_health_invocation::claim_identity{
						.claim_id = claim_id,
						.row_ordinal = row_ordinal,
						.epoch = active_epoch,
					},
					*view.context, view.packet_config);
}

bool worker_module_health::quiescent() const noexcept
{
	return live_claim_id_ == 0u;
}

bool worker_module_health::owns_ledger(const worker_epoch_ledger &ledger) const noexcept
{
	return ledger_ == &ledger;
}

std::size_t worker_module_health::size() const noexcept
{
	return bindings_.size();
}

std::size_t worker_module_health::callback_count() const noexcept
{
	return static_cast<std::size_t>(std::count_if(bindings_.begin(), bindings_.end(), [](const auto &binding) {
		return binding.descriptor->health_check != nullptr;
	}));
}

uint32_t worker_module_health::context_index(std::size_t row_ordinal) const noexcept
{
	return row_ordinal < bindings_.size() ? bindings_[row_ordinal].context_index : UINT32_MAX;
}

bool worker_module_health::owns_store(std::size_t row_ordinal, const module_epoch_store &store) const noexcept
{
	return row_ordinal < bindings_.size() && bindings_[row_ordinal].store == &store;
}

uint32_t worker_module_health::worker_index() const noexcept
{
	return worker_index_;
}

uint64_t worker_module_health::runtime_generation() const noexcept
{
	return runtime_generation_;
}

void worker_module_health::invoke_(module_health_invocation &claim, uint64_t start_ns) noexcept
{
	if (claim.owner_ != this || claim.claim_id_ == 0u || claim.claim_id_ != live_claim_id_ ||
	    claim.row_ordinal_ != live_row_ordinal_ || claim.state_ != module_health_invocation::state::CLAIMED ||
	    claim.epoch_ != ledger_->active_epoch() || start_ns == 0u || claim.start_ns_ != 0u) {
		std::terminate();
	}
	const auto &binding = binding_(claim.row_ordinal_);
	if (claim.context_ == nullptr || claim.context_ != binding.context ||
	    binding.descriptor->health_check == nullptr) {
		std::terminate();
	}
	claim.start_ns_ = start_ns;
	try {
		claim.assessment_ =
			binding.descriptor->health_check(claim.context_, claim.epoch_, claim.packet_config_);
	} catch (...) {
		// Throwing violates the C ABI and cannot unwind a live ledger claim.
		std::terminate();
	}
	claim.state_ = module_health_invocation::state::INVOKED;
}

void worker_module_health::complete_(module_health_invocation &claim, uint64_t finish_ns) noexcept
{
	if (claim.owner_ != this || claim.claim_id_ == 0u || claim.claim_id_ != live_claim_id_ ||
	    claim.row_ordinal_ != live_row_ordinal_ || claim.state_ != module_health_invocation::state::INVOKED ||
	    claim.epoch_ != ledger_->active_epoch() || finish_ns < claim.start_ns_) {
		std::terminate();
	}
	const auto &binding = binding_(claim.row_ordinal_);
	if (claim.context_ == nullptr || claim.context_ != binding.context ||
	    binding.publication->telemetry_active_epoch() != claim.epoch_) {
		std::terminate();
	}
	binding.publication->publish_module_health_attempt(claim.assessment_,
							   lifecycle::lifecycle_module_health_attempt{
								   .epoch = claim.epoch_,
								   .timestamp_ns = claim.start_ns_,
								   .duration_ns = finish_ns - claim.start_ns_,
								   .callback_budget_ns = callback_budget_ns_,
							   });
	live_claim_id_ = 0u;
	live_row_ordinal_ = 0u;
	const uint64_t epoch = claim.epoch_;
	claim.resolve_();
	ledger_->retire(epoch);
}

const worker_module_health_binding &worker_module_health::binding_(std::size_t row_ordinal) const noexcept
{
	if (row_ordinal >= bindings_.size()) {
		std::terminate();
	}
	return bindings_[row_ordinal];
}

}  // namespace kinetum::dp::module
