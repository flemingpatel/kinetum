// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_epoch_activation.cpp
 * @brief Exact local participant activation implementation.
 * @author Fleming Patel
 */

#include "src/dp/epoch/worker_epoch_activation.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include "src/common/epoch_transition_contract.hpp"
#include "src/common/status.hpp"
#include "src/dp/active/worker_active_stage_scheduler.hpp"
#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/module/worker_module_health.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"

namespace kinetum::dp
{

common::status_or<std::unique_ptr<worker_epoch_activation>>
worker_epoch_activation::create(uint32_t worker_index, uint64_t runtime_generation,
				std::span<module::module_epoch_store *const> module_stores,
				std::span<packet_epoch_input_staging *const> source_staging,
				worker_epoch_ledger &ledger, worker_active_stage_scheduler *active_scheduler,
				module::worker_module_health *module_health, worker_runtime_telemetry &telemetry)
{
	if (worker_index == std::numeric_limits<uint32_t>::max() || runtime_generation == 0u ||
	    runtime_generation > std::numeric_limits<uint32_t>::max() || ledger.worker_index() != worker_index ||
	    ledger.runtime_generation() != runtime_generation || telemetry.worker_index() != worker_index ||
	    telemetry.active_epoch() != 0u) {
		return common::status::invalid_argument(
			"worker activation requires exact representable worker and runtime identities");
	}
	if (module_stores.size() > std::numeric_limits<uint32_t>::max() ||
	    source_staging.size() > std::numeric_limits<uint32_t>::max()) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "worker activation bindings exceed representable participant cardinality");
	}
	uint32_t previous_context_index = 0u;
	bool have_previous_context = false;
	for (const auto *store : module_stores) {
		if (store == nullptr || (have_previous_context && store->context_index() <= previous_context_index)) {
			return common::status::failed_precondition(
				"worker activation module stores must be strictly context-index sorted and unique");
		}
		previous_context_index = store->context_index();
		have_previous_context = true;
	}
	for (const auto *candidate : source_staging) {
		if (candidate == nullptr || !candidate->has_future()) {
			return common::status::failed_precondition(
				"worker activation source staging must be complete and own future roles");
		}
	}
	std::vector<module::module_epoch_store *> stores;
	std::vector<packet_epoch_input_staging *> staging;
	try {
		stores.assign(module_stores.begin(), module_stores.end());
		staging.assign(source_staging.begin(), source_staging.end());
		std::unordered_set<packet_epoch_input_staging *> staging_identities;
		staging_identities.reserve(staging.size());
		for (auto *candidate : staging) {
			if (!staging_identities.insert(candidate).second) {
				return common::status::failed_precondition(
					"worker activation source staging must be unique");
			}
		}
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("worker activation binding allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "worker activation binding exceeds a bounded host container");
	}
	if (active_scheduler != nullptr &&
	    (active_scheduler->worker_index() != worker_index || active_scheduler->active_epoch() != 0u ||
	     !active_scheduler->owns_ledger(ledger))) {
		return common::status::failed_precondition(
			"worker activation active scheduler has foreign, already-bound, or mismatched ledger ownership");
	}
	if ((module_stores.empty() != (module_health == nullptr)) ||
	    (module_health != nullptr &&
	     (module_health->worker_index() != worker_index ||
	      module_health->runtime_generation() != runtime_generation || !module_health->owns_ledger(ledger) ||
	      module_health->size() != module_stores.size() || !module_health->quiescent()))) {
		return common::status::failed_precondition(
			"worker activation health ownership does not match its exact module projection");
	}
	for (std::size_t index = 0u; index < module_stores.size(); ++index) {
		if (module_health == nullptr || module_stores[index] == nullptr ||
		    module_health->context_index(index) != module_stores[index]->context_index() ||
		    !module_health->owns_store(index, *module_stores[index])) {
			return common::status::failed_precondition(
				"worker activation health rows do not match the exact module-store order");
		}
	}
	auto *owner = new (std::nothrow) worker_epoch_activation(
		owner_identity{
			.worker_index = worker_index,
			.runtime_generation = runtime_generation,
		},
		std::move(stores), std::move(staging), ledger, active_scheduler, module_health, telemetry);
	if (owner == nullptr) {
		return common::status::resource_exhausted("worker activation owner allocation failed");
	}
	return std::unique_ptr<worker_epoch_activation>(owner);
}

worker_epoch_activation::worker_epoch_activation(owner_identity identity,
						 std::vector<module::module_epoch_store *> module_stores,
						 std::vector<packet_epoch_input_staging *> source_staging,
						 worker_epoch_ledger &ledger,
						 worker_active_stage_scheduler *active_scheduler,
						 module::worker_module_health *module_health,
						 worker_runtime_telemetry &telemetry) noexcept
	: worker_index_(identity.worker_index)
	, runtime_generation_(identity.runtime_generation)
	, module_stores_(std::move(module_stores))
	, source_staging_(std::move(source_staging))
	, ledger_(&ledger)
	, active_scheduler_(active_scheduler)
	, module_health_(module_health)
	, telemetry_(&telemetry)
{
}

void worker_epoch_activation::bind_bootstrap_epoch(uint64_t bootstrap_epoch) noexcept
{
	if (active_epoch_ != 0u || last_transition_generation_ != 0u || ledger_ == nullptr ||
	    !common::valid_epoch_id(bootstrap_epoch) || ledger_->active_epoch() != bootstrap_epoch ||
	    ledger_->source_epoch() != bootstrap_epoch || ledger_->future_epoch() != 0u || telemetry_ == nullptr ||
	    telemetry_->active_epoch() != bootstrap_epoch) {
		std::terminate();
	}
	for (const auto *store : module_stores_) {
		if (store == nullptr || store->active_epoch() != bootstrap_epoch || store->prepared_epoch() != 0u) {
			std::terminate();
		}
	}
	for (const auto *staging : source_staging_) {
		if (staging == nullptr || !staging->activation_ready() || !staging->future_empty()) {
			std::terminate();
		}
	}
	if (active_scheduler_ != nullptr) {
		active_scheduler_->bind_bootstrap_epoch(bootstrap_epoch);
	}
	if (module_health_ != nullptr) {
		module_health_->bind_bootstrap_epoch(bootstrap_epoch);
	}
	active_epoch_ = bootstrap_epoch;
	last_to_epoch_ = bootstrap_epoch;
	last_activation_monotonic_ns_ = 0u;
	publish_(false);
}

bool worker_epoch_activation::preflight_begin_transition(uint64_t transition_generation, uint64_t from_epoch,
							 uint64_t to_epoch) const noexcept
{
	if (!common::valid_mutation_sequence(transition_generation) || !common::valid_epoch_id(from_epoch) ||
	    !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch || active_epoch_ != from_epoch ||
	    (last_transition_generation_ != 0u && transition_generation <= last_transition_generation_) ||
	    ledger_ == nullptr || ledger_->worker_index() != worker_index_ ||
	    ledger_->runtime_generation() != runtime_generation_ || telemetry_ == nullptr ||
	    !telemetry_->preflight_activate(from_epoch, to_epoch)) {
		return false;
	}
	if (!ledger_->preflight_begin_transition(from_epoch, to_epoch)) {
		return false;
	}
	for (const auto *store : module_stores_) {
		if (store == nullptr || store->active_epoch() != from_epoch || store->prepared_epoch() != to_epoch) {
			return false;
		}
	}
	for (const auto *staging : source_staging_) {
		if (staging == nullptr || !staging->has_future() || !staging->future_empty()) {
			return false;
		}
	}
	if (active_scheduler_ != nullptr &&
	    !active_scheduler_->preflight_begin_transition(transition_generation, from_epoch, to_epoch)) {
		return false;
	}
	if (module_health_ != nullptr && !module_health_->quiescent()) {
		return false;
	}
	return true;
}

common::status worker_epoch_activation::preflight(uint64_t transition_generation, uint64_t from_epoch,
						  uint64_t to_epoch) const noexcept
{
	if (module_stores_.size() == std::numeric_limits<std::size_t>::max() || telemetry_ == nullptr ||
	    !telemetry_->preflight_completed_publications(module_stores_.size() + 1u)) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker activation telemetry publication prefix is not completely available"));
	}
	if (!common::valid_mutation_sequence(transition_generation) || !common::valid_epoch_id(from_epoch) ||
	    !common::valid_epoch_id(to_epoch) || to_epoch <= from_epoch || active_epoch_ != from_epoch ||
	    (last_transition_generation_ != 0u && transition_generation <= last_transition_generation_) ||
	    ledger_ == nullptr || ledger_->worker_index() != worker_index_ ||
	    ledger_->runtime_generation() != runtime_generation_ ||
	    !telemetry_->preflight_activate(from_epoch, to_epoch)) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker activation identity does not name one new local transition"));
	}
	auto ledger_status = ledger_->preflight_promote_future_epoch(to_epoch);
	if (!ledger_status.is_ok()) {
		return ledger_status;
	}
	for (const auto *store : module_stores_) {
		if (store == nullptr || store->active_epoch() != from_epoch) {
			return common::status::failed_precondition(kinetum::common::static_status_text(
				"worker activation module store is not active at the exact old epoch"));
		}
		auto module_status = store->preflight_activate_prepared(to_epoch);
		if (!module_status.is_ok()) {
			return module_status;
		}
	}
	for (const auto *staging : source_staging_) {
		if (staging == nullptr || !staging->activation_ready()) {
			return common::status::failed_precondition(kinetum::common::static_status_text(
				"worker activation source staging has unresolved old work or reservations"));
		}
	}
	if (active_scheduler_ != nullptr &&
	    !active_scheduler_->preflight_activate(transition_generation, from_epoch, to_epoch)) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker activation synchronous active owner is not completely drained"));
	}
	if (module_health_ != nullptr && !module_health_->quiescent()) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker activation health callback ownership is not quiescent"));
	}
	return common::status::ok();
}

common::status worker_epoch_activation::activate(uint64_t transition_generation, uint64_t from_epoch, uint64_t to_epoch,
						 uint64_t now_ns) noexcept
{
	if (now_ns == 0u) {
		return common::status::invalid_argument(
			kinetum::common::static_status_text("worker activation requires one exact cached timestamp"));
	}
	if (telemetry_ == nullptr) {
		return common::status::failed_precondition(
			kinetum::common::static_status_text("worker activation lost its telemetry authority"));
	}
	if (!telemetry_->activation_timestamp_representable(now_ns)) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "worker activation telemetry deadline exceeds the timestamp domain"));
	}
	auto preflight_status = preflight(transition_generation, from_epoch, to_epoch);
	if (!preflight_status.is_ok()) {
		return preflight_status;
	}
	for (auto *store : module_stores_) {
		if (!store->activate_prepared(to_epoch, now_ns).is_ok()) {
			std::terminate();
		}
	}
	telemetry_->activate_target_epoch(from_epoch, to_epoch, now_ns);
	for (auto *staging : source_staging_) {
		staging->rotate_after_activation();
	}
	ledger_->promote_future_epoch(to_epoch);
	if (active_scheduler_ != nullptr) {
		active_scheduler_->activate(transition_generation, from_epoch, to_epoch);
	}
	active_epoch_ = to_epoch;
	last_transition_generation_ = transition_generation;
	last_from_epoch_ = from_epoch;
	last_to_epoch_ = to_epoch;
	last_activation_monotonic_ns_ = now_ns;
	publish_(true);
	return common::status::ok();
}

uint64_t worker_epoch_activation::active_epoch() const noexcept
{
	return active_epoch_;
}

uint64_t worker_epoch_activation::last_transition_generation() const noexcept
{
	return last_transition_generation_;
}

uint32_t worker_epoch_activation::worker_index() const noexcept
{
	return worker_index_;
}

uint64_t worker_epoch_activation::runtime_generation() const noexcept
{
	return runtime_generation_;
}

bool worker_epoch_activation::owns_ledger(const worker_epoch_ledger &ledger) const noexcept
{
	return ledger_ == &ledger;
}

std::size_t worker_epoch_activation::module_store_count() const noexcept
{
	return module_stores_.size();
}

std::size_t worker_epoch_activation::source_staging_count() const noexcept
{
	return source_staging_.size();
}

publication_read_result worker_epoch_activation::try_read(worker_epoch_activation_snapshot &out) const noexcept
{
	kinetum::algo::single_writer_snapshot<PUBLICATION_FIELD_COUNT>::snapshot observed{};
	if (!publication_.try_read(observed, OBSERVATION_ATTEMPTS)) {
		return publication_read_result::UNAVAILABLE;
	}
	const uint64_t runtime_generation = observed.fields[PUBLICATION_RUNTIME_GENERATION];
	const uint64_t worker_index = observed.fields[PUBLICATION_WORKER_INDEX];
	const uint64_t transition_generation = observed.fields[PUBLICATION_TRANSITION_GENERATION];
	const uint64_t from_epoch = observed.fields[PUBLICATION_FROM_EPOCH];
	const uint64_t to_epoch = observed.fields[PUBLICATION_TO_EPOCH];
	const uint64_t active_epoch = observed.fields[PUBLICATION_ACTIVE_EPOCH];
	const uint64_t activation_complete = observed.fields[PUBLICATION_ACTIVATION_COMPLETE];
	const uint64_t activation_ns = observed.fields[PUBLICATION_ACTIVATION_NS];
	const bool bootstrap_shape = transition_generation == 0u && from_epoch == 0u &&
				     common::valid_epoch_id(to_epoch) && active_epoch == to_epoch &&
				     activation_complete == 0u && activation_ns == 0u;
	const bool transition_shape = common::valid_mutation_sequence(transition_generation) &&
				      common::valid_epoch_id(from_epoch) && common::valid_epoch_id(to_epoch) &&
				      to_epoch > from_epoch && active_epoch == to_epoch && activation_complete == 1u &&
				      activation_ns != 0u;
	if (runtime_generation != runtime_generation_ || worker_index != worker_index_) {
		return publication_read_result::INVALID_IDENTITY;
	}
	if (!bootstrap_shape && !transition_shape) {
		return publication_read_result::INVALID_STATE;
	}
	out = worker_epoch_activation_snapshot{
		.publication_generation = observed.generation,
		.runtime_generation = runtime_generation,
		.worker_index = worker_index,
		.transition_generation = transition_generation,
		.from_epoch = from_epoch,
		.to_epoch = to_epoch,
		.active_epoch = active_epoch,
		.activation_complete = activation_complete,
		.activation_monotonic_ns = activation_ns,
		.padding = {},
	};
	return publication_read_result::AVAILABLE;
}

void worker_epoch_activation::publish_(bool activation_complete) noexcept
{
	const bool bootstrap_shape = !activation_complete && last_transition_generation_ == 0u &&
				     last_from_epoch_ == 0u && common::valid_epoch_id(last_to_epoch_) &&
				     active_epoch_ == last_to_epoch_ && last_activation_monotonic_ns_ == 0u;
	const bool transition_shape = activation_complete &&
				      common::valid_mutation_sequence(last_transition_generation_) &&
				      common::valid_epoch_id(last_from_epoch_) &&
				      common::valid_epoch_id(last_to_epoch_) && last_to_epoch_ > last_from_epoch_ &&
				      active_epoch_ == last_to_epoch_ && last_activation_monotonic_ns_ != 0u;
	if (!bootstrap_shape && !transition_shape) {
		std::terminate();
	}
	const std::array<uint64_t, PUBLICATION_FIELD_COUNT> fields{
		runtime_generation_, worker_index_, last_transition_generation_,   last_from_epoch_,
		last_to_epoch_,	     active_epoch_, activation_complete ? 1u : 0u, last_activation_monotonic_ns_,
	};
	if (!publication_.publish(fields)) {
		std::terminate();
	}
}

}  // namespace kinetum::dp
