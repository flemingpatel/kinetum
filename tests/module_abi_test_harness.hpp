// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_abi_test_harness.hpp
 * @brief Exact module-lifecycle fixture for SDK component and policy tests.
 * @author Fleming Patel
 *
 * This fixture is deliberately test-only. It exercises production image and
 * context admission, the public lifecycle shell, exact two-slot ownership,
 * the owner-local executable view, the production exact packet entry point,
 * and the real module descriptor. It does not emulate runtime routing,
 * boundary ownership, or worker scheduling.
 */

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <array>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "src/common/status.hpp"
#include "src/dp/dp_engine.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/lifecycle/prepared_config_ownership.hpp"
#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/module/module_lifecycle_adapter.hpp"
#include "src/dp/module/module_manager.hpp"
#include "src/dp/packet.hpp"
#include "src/dp/worker_telemetry_channel.hpp"

namespace kinetum::test
{

/** @brief Explicit lifecycle-memory authority supplied by each module test. */
struct module_test_resource_contract {
	std::size_t context_memory_capacity_bytes;  ///< Aggregate context-lifetime byte bound.
	std::size_t epoch_arena_capacity_bytes;	    ///< Exact capacity of each epoch arena.
};

/** @brief Exact heap-backed provider for cold module component tests. */
class module_test_memory_provider final : public dp::lifecycle::lifecycle_memory_provider {
    public:
	/** @copydoc dp::lifecycle::lifecycle_memory_provider::allocate */
	[[nodiscard]] common::status_or<dp::lifecycle::lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept override
	{
		const std::size_t effective_alignment = std::max(alignment, sizeof(void *));
		void *pointer = nullptr;
		if (posix_memalign(&pointer, effective_alignment, size) != 0) {
			return common::status(common::status_code::RESOURCE_EXHAUSTED, "module test allocation failed");
		}
		std::memset(pointer, zero_initialize ? 0 : 0xa5, size);
		return dp::lifecycle::lifecycle_memory_block{
			pointer, size, effective_alignment, numa_node, {},
		};
	}

	/** @copydoc dp::lifecycle::lifecycle_memory_provider::release */
	void release(dp::lifecycle::lifecycle_memory_block block) noexcept override
	{
		std::free(block.data);
	}
};

/** @brief Bounded diagnostic sink for module component tests. */
class module_test_log_provider final : public dp::lifecycle::lifecycle_log_provider {
    public:
	/** @copydoc dp::lifecycle::lifecycle_log_provider::write */
	void write(const dp::lifecycle::lifecycle_log_record_view &record) noexcept override
	{
		last_level_ = record.level;
		last_message_.assign(record.message);
		++write_count_;
	}

	/** @return Number of diagnostics copied by this receiver. */
	[[nodiscard]] std::size_t write_count() const noexcept
	{
		return write_count_;
	}

	/** @return Severity retained from the most recent diagnostic. */
	[[nodiscard]] dp::lifecycle::lifecycle_log_level last_level() const noexcept
	{
		return last_level_;
	}

	/** @return Borrowed most recently copied diagnostic text. */
	[[nodiscard]] const std::string &last_message() const noexcept
	{
		return last_message_;
	}

    private:
	std::size_t write_count_{0};  ///< Number of copied diagnostics.
	dp::lifecycle::lifecycle_log_level last_level_{
		dp::lifecycle::lifecycle_log_level::DEBUG};  ///< Latest severity.
	std::string last_message_;			     ///< Latest test-owned diagnostic text.
};

/**
 * @brief One admitted module context with one exact active test artifact.
 *
 * The test thread is the sole owner worker. PREPARE and RETIRE borrow the real
 * cold lifecycle context; ACTIVATE and packet callbacks receive the compact
 * live context. Destruction retires a still-live artifact before manager FINI.
 */
class exact_module_test_context {
    public:
	exact_module_test_context(const exact_module_test_context &) = delete;
	exact_module_test_context &operator=(const exact_module_test_context &) = delete;
	exact_module_test_context(exact_module_test_context &&) = delete;
	exact_module_test_context &operator=(exact_module_test_context &&) = delete;

	/** @brief Retire active prepared ownership, then permit manager FINI. */
	~exact_module_test_context()
	{
		if (context_ == nullptr || context_->epoch_store == nullptr) {
			return;
		}
		const uint64_t prepared_epoch = context_->epoch_store->prepared_epoch();
		if (prepared_epoch != 0u) {
			auto discarded_or = context_->epoch_store->discard_prepared(prepared_epoch);
			if (!discarded_or.is_ok()) {
				std::terminate();
			}
			auto discarded = std::move(discarded_or).value();
			retire_token_exact_(discarded, prepared_epoch);
		}
		for (std::size_t index = 0u; index < dp::EXACT_EPOCH_SLOT_COUNT; ++index) {
			const auto *slot = context_->epoch_store->slot(index);
			if (slot == nullptr || slot->state != dp::epoch_slot_state::RETAINED) {
				continue;
			}
			auto claim_or = context_->epoch_store->claim_retained(slot->epoch);
			if (!claim_or.is_ok()) {
				std::terminate();
			}
			auto claim = std::move(claim_or).value();
			retire_claim_exact_(claim);
			if (!context_->epoch_store->complete_retirement(claim).is_ok()) {
				std::terminate();
			}
			const uint64_t active_epoch = context_->epoch_store->active_epoch();
			if (active_epoch == 0u ||
			    !context_->lifecycle_owner->take_reclaimed_telemetry_transfer(active_epoch).has_value()) {
				std::terminate();
			}
			dispatch_telemetry_returns_();
		}
		if (context_->epoch_store->active_epoch() != 0u && !retire().is_ok()) {
			std::terminate();
		}
		context_->lifecycle_owner->unbind_telemetry();
		telemetry_channel_.reset();
	}

	/**
	 * @brief Admit one canonical module image and context.
	 *
	 * @param module_id Exact expected descriptor identity.
	 * @param module_path Canonical absolute regular-file identity.
	 * @param resources Exact lifecycle-memory bounds authored by the test.
	 * @param context_instance_id Exact executable context identity.
	 * @param context_index Exact executable context index.
	 * @param stage_instance_index Exact telemetry stage identity, or UINT32_MAX
	 *        to use @p context_index for narrow component fixtures.
	 * @return Unique admitted fixture, or the production admission failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<exact_module_test_context>>
	create(std::string module_id, std::filesystem::path module_path, module_test_resource_contract resources,
	       std::string context_instance_id = "module@lane_0", uint32_t context_index = 0,
	       uint32_t stage_instance_index = UINT32_MAX)
	{
		std::unique_ptr<exact_module_test_context> fixture;
		try {
			fixture.reset(new exact_module_test_context());
		} catch (const std::bad_alloc &) {
			return common::status(common::status_code::RESOURCE_EXHAUSTED,
					      "failed to allocate exact module test fixture");
		}

		std::vector<dp::module::module_image_spec> images{
			{module_id, std::move(module_path)},
		};
		std::vector<dp::module::module_context_spec> contexts{{
			.context_instance_id = std::move(context_instance_id),
			.module_id = module_id,
			.context_index = context_index,
			.worker_index = 0,
			.cpu_core_id = 0,
			.numa_node = 0,
			.context_memory_capacity_bytes = resources.context_memory_capacity_bytes,
			.epoch_arena_capacity_bytes = resources.epoch_arena_capacity_bytes,
			.module_context_ordinal = 0u,
			.module_context_count = 1u,
		}};
		const auto admitted = fixture->manager_.admit_generation(
			std::move(images), std::move(contexts), fixture->memory_, fixture->log_, fixture->control_);
		if (!admitted.is_ok()) {
			return admitted;
		}
		fixture->context_ = fixture->manager_.context(context_index);
		if (fixture->context_ == nullptr || fixture->context_->image == nullptr ||
		    fixture->context_->image->descriptor == nullptr) {
			return common::status(common::status_code::INTERNAL_ERROR,
					      "admitted module fixture lacks an exact context descriptor");
		}
		auto channel_or = dp::worker_telemetry_channel::create(0u, 1u, 0, 0);
		if (!channel_or.is_ok()) {
			return channel_or.error();
		}
		fixture->telemetry_channel_ = std::move(channel_or).value();
		const uint32_t telemetry_stage_index = stage_instance_index == UINT32_MAX ? context_index :
											    stage_instance_index;
		if (telemetry_stage_index > UINT16_MAX) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "module test telemetry stage identity exceeds uint16");
		}
		const auto bound = fixture->context_->lifecycle_owner->bind_telemetry(
			1u, static_cast<uint16_t>(telemetry_stage_index), *fixture->telemetry_channel_,
			fixture->context_->image->descriptor->health_check != nullptr);
		if (!bound.is_ok()) {
			return bound;
		}
		return fixture;
	}

	/**
	 * @brief Prepare one exact artifact without changing owner execution.
	 *
	 * @param epoch Exact nonzero advancing epoch.
	 * @param payload Opaque module configuration bytes.
	 * @return OK after exact PREPARED publication, or a fail-closed lifecycle error.
	 */
	[[nodiscard]] common::status prepare(uint64_t epoch, std::string_view payload)
	{
		if (epoch == 0 || context_ == nullptr) {
			return common::status::invalid_argument(
				"module test preparation requires an admitted context and nonzero epoch");
		}
		if (context_->epoch_store == nullptr || context_->epoch_store->prepared_epoch() != 0 ||
		    (context_->epoch_store->active_epoch() != 0 && epoch <= context_->epoch_store->active_epoch())) {
			return common::status::failed_precondition(
				"module test context cannot prepare this exact advancing artifact");
		}
		if (context_->epoch_store->active_epoch() != 0u) {
			const auto reserved = context_->lifecycle_owner->reserve_telemetry_epoch(
				context_->epoch_store->active_epoch(), epoch);
			if (!reserved.is_ok()) {
				return reserved;
			}
		}

		auto arena_or = dp::lifecycle::epoch_arena_ownership::create(
			memory_, context_->context_index, epoch, context_->lifecycle_owner->identity().numa_node,
			context_->lifecycle_owner->epoch_arena_capacity_bytes(), 64);
		if (!arena_or.is_ok()) {
			return arena_or.error();
		}
		auto arena = std::move(arena_or).value();
		auto operation_or = context_->lifecycle_owner->begin_operation(dp::lifecycle::lifecycle_phase::PREPARE,
									       epoch, control_, &arena);
		if (!operation_or.is_ok()) {
			return operation_or.error();
		}
		auto operation = std::move(operation_or).value();

		kinetum_prepared_config record{};
		const void *payload_data = payload.empty() ? nullptr : payload.data();
		const kinetum_error result = context_->image->descriptor->prepare_config(
			&operation.context(), epoch, payload_data, payload.size(), &record);
		operation.release();
		if (result != KINETUM_OK) {
			if (record.owner_handle != nullptr || record.packet_config != nullptr) {
				std::terminate();
			}
			return common::status(common::status_code::MODULE_ERROR,
					      "module PREPARE rejected the exact test configuration",
					      std::to_string(result));
		}

		auto token_or = dp::lifecycle::prepared_config_ownership::create(
			context_->image->module_image_index, context_->context_index, epoch,
			{record.owner_handle, record.packet_config}, std::move(arena));
		if (!token_or.is_ok()) {
			std::terminate();
		}
		auto token = std::move(token_or).value();
		const auto stage_status = context_->epoch_store->stage_prepared(token);
		if (!stage_status.is_ok()) {
			if (context_->epoch_store->active_epoch() != 0u) {
				context_->lifecycle_owner->discard_telemetry_epoch(epoch);
			}
			retire_token_exact_(token, epoch);
			return stage_status;
		}
		return common::status::ok();
	}

	/**
	 * @brief Activate one exact artifact already owned by the production store.
	 * @param epoch Exact PREPARED epoch.
	 * @return OK after bounded owner activation; otherwise PREPARED remains owned.
	 */
	[[nodiscard]] common::status activate_prepared(uint64_t epoch) noexcept
	{
		if (context_ == nullptr || context_->epoch_store == nullptr) {
			return common::status::failed_precondition("module test context has no exact epoch store");
		}
		const auto activated = context_->epoch_store->activate_prepared(epoch, 1u);
		if (activated.is_ok() && context_->epoch_store->active_epoch() == epoch) {
			drain_telemetry_();
		}
		return activated;
	}

	/**
	 * @brief Withdraw and RETIRE one exact PREPARED artifact without activation.
	 * @param epoch Exact PREPARED epoch.
	 * @return OK after callback and arena ownership are completely retired.
	 */
	[[nodiscard]] common::status retire_prepared(uint64_t epoch) noexcept
	{
		if (context_ == nullptr || context_->epoch_store == nullptr) {
			return common::status::failed_precondition("module test context has no exact epoch store");
		}
		auto discarded_or = context_->epoch_store->discard_prepared(epoch);
		if (!discarded_or.is_ok()) {
			return discarded_or.error();
		}
		auto discarded = std::move(discarded_or).value();
		if (context_->epoch_store->active_epoch() != 0u) {
			context_->lifecycle_owner->discard_telemetry_epoch(epoch);
		}
		retire_token_exact_(discarded, epoch);
		return common::status::ok();
	}

	/**
	 * @brief Prepare and activate one exact artifact.
	 *
	 * @param epoch Exact nonzero epoch.
	 * @param payload Opaque module configuration bytes.
	 * @return OK after exact activation, or a fail-closed lifecycle error.
	 */
	[[nodiscard]] common::status prepare_and_activate(uint64_t epoch, std::string_view payload)
	{
		const auto prepared = prepare(epoch, payload);
		if (!prepared.is_ok()) {
			return prepared;
		}
		const auto activate_status = activate_prepared(epoch);
		if (!activate_status.is_ok()) {
			auto discarded_or = context_->epoch_store->discard_prepared(epoch);
			if (!discarded_or.is_ok()) {
				std::terminate();
			}
			auto discarded = std::move(discarded_or).value();
			if (context_->epoch_store->active_epoch() != 0u) {
				context_->lifecycle_owner->discard_telemetry_epoch(epoch);
			}
			retire_token_exact_(discarded, epoch);
			return activate_status;
		}
		return common::status::ok();
	}

	/**
	 * @brief Retire the active prepared artifact exactly once.
	 *
	 * @return OK after module retirement and arena release.
	 */
	[[nodiscard]] common::status retire() noexcept
	{
		if (context_ == nullptr || context_->epoch_store == nullptr ||
		    context_->epoch_store->active_epoch() == 0) {
			return common::status::failed_precondition(
				"module test context has no prepared artifact to retire");
		}
		const uint64_t epoch = context_->epoch_store->active_epoch();
		if (!context_->lifecycle_owner->preflight_publish_shutdown_telemetry(epoch)) {
			return common::status::failed_precondition(
				"module test telemetry cannot publish exact shutdown truth");
		}
		context_->lifecycle_owner->publish_shutdown_telemetry(epoch, 2u);
		drain_telemetry_();
		auto claim_or = context_->epoch_store->claim_published_for_shutdown(epoch);
		if (!claim_or.is_ok()) {
			return claim_or.error();
		}
		auto claim = std::move(claim_or).value();
		retire_claim_exact_(claim);
		return context_->epoch_store->complete_retirement(claim);
	}

	/** @brief Drain every completed module telemetry bank through the exact cold seam. */
	void drain_telemetry_for_test() noexcept
	{
		drain_telemetry_();
	}

	/**
	 * @param epoch Exact module epoch whose bank aggregation is queried.
	 * @return true only when the lifecycle owner reports complete aggregation.
	 */
	[[nodiscard]] bool telemetry_epoch_aggregated(uint64_t epoch) const noexcept
	{
		return context_ != nullptr && context_->lifecycle_owner->telemetry_epoch_aggregated(epoch);
	}

	/**
	 * @brief Consume the cold test stand-in for an aggregator retirement handoff.
	 * @param active_epoch Exact target epoch receiving the reclaimed telemetry bank.
	 */
	void consume_reclaimed_telemetry_transfer(uint64_t active_epoch) noexcept
	{
		if (context_ == nullptr || active_epoch == 0u ||
		    !context_->lifecycle_owner->take_reclaimed_telemetry_transfer(active_epoch).has_value()) {
			std::terminate();
		}
		dispatch_telemetry_returns_();
	}

	/**
	 * @brief Execute one packet through the production exact-module entry point.
	 *
	 * @param packet Exact packet record updated from exact module output.
	 * @return true only when the production engine forwards the packet.
	 */
	[[nodiscard]] bool process(dp::packet_record &packet) noexcept
	{
		return process_batch(std::array{&packet}) == UINT64_C(1);
	}

	/**
	 * @brief Execute a borrowed occupied prefix through the production batch bridge.
	 * @param packets Exact caller-owned records in callback-lane order.
	 * @return Sole forward mask; incomplete fixture ownership rejects before execution.
	 */
	[[nodiscard]] uint64_t process_batch(std::span<dp::packet_record *const> packets) noexcept
	{
		if (context_ == nullptr || context_->epoch_store == nullptr ||
		    context_->epoch_store->active_view() == nullptr ||
		    context_->context_index > std::numeric_limits<uint16_t>::max()) {
			return 0u;
		}
		return packet_engine_.execute_module_stage(*context_->epoch_store,
							   static_cast<uint16_t>(context_->context_index), 0, packets,
							   packet_batch_);
	}

	/** @return Borrowed admitted context; an absent context fails stop. */
	[[nodiscard]] dp::module::module_context_instance &context() const noexcept
	{
		if (context_ == nullptr) {
			std::terminate();
		}
		return *context_;
	}

	/**
	 * @brief Construct the production lifecycle adapter for this exact context.
	 * @return Unique adapter or exact manager/context ownership failure.
	 */
	[[nodiscard]] common::status_or<std::unique_ptr<dp::module::module_lifecycle_adapter>> make_lifecycle_adapter()
	{
		return manager_.make_lifecycle_adapter(context().context_index);
	}

	/** @return Borrowed descriptor retained by the admitted context's image. */
	[[nodiscard]] const kinetum_module &descriptor() const noexcept
	{
		return *context().image->descriptor;
	}

	/** @return Currently activated test epoch, or zero without a context/store. */
	[[nodiscard]] uint64_t active_epoch() const noexcept
	{
		return context_ != nullptr && context_->epoch_store != nullptr ? context_->epoch_store->active_epoch() :
										 0;
	}

	/** @return Borrowed active packet configuration, or nullptr without an active view. */
	[[nodiscard]] const void *active_packet_config() const noexcept
	{
		const auto *view = context().epoch_store != nullptr ? context().epoch_store->active_view() : nullptr;
		return view != nullptr ? view->packet_config : nullptr;
	}

	/**
	 * @brief Replace one owner-local test counter by exact registered name.
	 *
	 * This test-only operation runs while the fixture thread is the sole context
	 * owner. It bypasses no production synchronization and cannot be used by a
	 * runtime observer to mutate module telemetry.
	 *
	 * @param name Exact registered counter identity.
	 * @param value Replacement owner-local value.
	 * @return OK on exact counter match, otherwise NOT_FOUND.
	 */
	[[nodiscard]] common::status set_counter_value(std::string_view name, uint64_t value) noexcept
	{
		if (context_ == nullptr || context_->lifecycle_owner == nullptr) {
			return common::status::failed_precondition("module test context has no lifecycle owner");
		}
		for (std::size_t index = 1; index <= context_->lifecycle_owner->telemetry_handle_count(); ++index) {
			const auto *descriptor = context_->lifecycle_owner->telemetry_descriptor(
				static_cast<dp::lifecycle::lifecycle_telemetry_handle>(index));
			if (descriptor != nullptr &&
			    descriptor->kind == dp::lifecycle::lifecycle_telemetry_kind::COUNTER &&
			    name == descriptor->counter.name) {
				auto *counter = const_cast<kinetum_counter *>(&descriptor->counter);
				counter->value = value;
				return common::status::ok();
			}
		}
		return common::status(common::status_code::NOT_FOUND, "module test counter is not registered",
				      std::string(name));
	}

	/**
	 * @brief Invoke the admitted descriptor's owner-worker health callback.
	 *
	 * @return Exact bounded assessment, or a fail-closed fixture-state error.
	 */
	[[nodiscard]] common::status_or<kinetum_health_assessment> health_assessment() const noexcept
	{
		const auto *view = context_ != nullptr && context_->epoch_store != nullptr ?
					   context_->epoch_store->active_view() :
					   nullptr;
		if (view == nullptr || context_->image == nullptr || context_->image->descriptor == nullptr ||
		    context_->image->descriptor->health_check == nullptr) {
			return common::status::failed_precondition("module test context has no active health callback");
		}
		return context_->image->descriptor->health_check(view->context, view->epoch, view->packet_config);
	}

	/** @return Borrowed production manager retained by this fixture. */
	[[nodiscard]] dp::module::module_manager &manager() noexcept
	{
		return manager_;
	}

    private:
	/**
	 * @brief Invoke the real RETIRE callback with one exact read-only token.
	 *
	 * @param token Exact token borrowed for the callback.
	 * @param epoch Exact token epoch.
	 */
	void invoke_retire_exact_(const dp::lifecycle::prepared_config_ownership &token, uint64_t epoch) noexcept
	{
		auto borrowed_or =
			token.borrow_exact(context_->image->module_image_index, context_->context_index, epoch);
		if (!borrowed_or.is_ok()) {
			std::terminate();
		}
		auto operation_or = context_->lifecycle_owner->begin_operation(dp::lifecycle::lifecycle_phase::RETIRE,
									       epoch, control_);
		if (!operation_or.is_ok()) {
			std::terminate();
		}
		auto operation = std::move(operation_or).value();
		const auto borrowed = borrowed_or.value();
		context_->image->descriptor->retire_config(&operation.context(), epoch,
							   kinetum_prepared_config{borrowed.owner_handle,
										   borrowed.packet_config});
		operation.release();
	}

	/**
	 * @brief Run exact RETIRE and consume one unclaimed fixture-owned token.
	 * @param token Sole prepared-artifact ownership to retire and consume.
	 * @param epoch Exact epoch bound to that token.
	 */
	void retire_token_exact_(dp::lifecycle::prepared_config_ownership &token, uint64_t epoch) noexcept
	{
		invoke_retire_exact_(token, epoch);
		if (!token.retire_exact(context_->image->module_image_index, context_->context_index, epoch).is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Run exact RETIRE and consume one store-bound claim without token escape.
	 * @param claim Sole retirement claim whose callback and final consumption are completed here.
	 */
	void retire_claim_exact_(dp::module::module_retirement_claim &claim) noexcept
	{
		invoke_retire_exact_(claim.ownership(), claim.epoch());
		if (!claim.consume_after_retire().is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Clear all completed histogram buckets through bounded production prefixes.
	 * @param token Exact completed module telemetry bank retained through the clear operation.
	 */
	void clear_completed_histograms_(const dp::runtime_telemetry_bank_token &token) noexcept
	{
		std::size_t histogram_count = 0u;
		for (std::size_t handle = 1u; handle <= context_->lifecycle_owner->telemetry_handle_count(); ++handle) {
			const auto *descriptor = context_->lifecycle_owner->telemetry_descriptor(
				static_cast<dp::lifecycle::lifecycle_telemetry_handle>(handle));
			if (descriptor != nullptr &&
			    descriptor->kind == dp::lifecycle::lifecycle_telemetry_kind::HISTOGRAM) {
				++histogram_count;
			}
		}
		std::size_t observed = 0u;
		for (std::size_t handle = 1u; handle <= context_->lifecycle_owner->telemetry_handle_count(); ++handle) {
			const auto *descriptor = context_->lifecycle_owner->telemetry_descriptor(
				static_cast<dp::lifecycle::lifecycle_telemetry_handle>(handle));
			if (descriptor == nullptr ||
			    descriptor->kind != dp::lifecycle::lifecycle_telemetry_kind::HISTOGRAM) {
				continue;
			}
			if (descriptor->kind_ordinal != observed) {
				std::terminate();
			}
			auto buckets_or = context_->lifecycle_owner->completed_telemetry_histogram(
				token, descriptor->kind_ordinal);
			if (!buckets_or.is_ok()) {
				std::terminate();
			}
			const auto buckets = buckets_or.value();
			for (std::size_t begin = 0u; begin < buckets.size();) {
				const std::size_t count = std::min(dp::lifecycle::LIFECYCLE_TELEMETRY_BUCKET_PREFIX,
								   buckets.size() - begin);
				const bool complete =
					context_->lifecycle_owner->clear_completed_telemetry_histogram_prefix(
						token, descriptor->kind_ordinal, begin, count);
				begin += count;
				if (complete != (observed + 1u == histogram_count && begin == buckets.size())) {
					std::terminate();
				}
			}
			++observed;
		}
	}

	/** @brief Consume every completed module bank through the exact cold surface. */
	void drain_telemetry_() noexcept
	{
		dp::runtime_telemetry_bank_token token{};
		while (telemetry_channel_->take_completed(token)) {
			if (token.kind == dp::runtime_telemetry_bank_token_kind::RETURN_RETAINED) {
				context_->lifecycle_owner->mark_telemetry_epoch_aggregated(token.epoch);
				continue;
			}
			if (!context_->lifecycle_owner->completed_telemetry_bank(token).is_ok()) {
				std::terminate();
			}
			clear_completed_histograms_(token);
			context_->lifecycle_owner->complete_telemetry_aggregation(token);
			if (token.reason != dp::runtime_telemetry_publication_reason::CADENCE &&
			    token.companion_bank_index != UINT8_MAX) {
				context_->lifecycle_owner->mark_telemetry_epoch_aggregated(token.epoch);
			}
		}
		dispatch_telemetry_returns_();
	}

	/** @brief Dispatch every returned bank to the fixture's exact module owner. */
	void dispatch_telemetry_returns_() noexcept
	{
		dp::runtime_telemetry_bank_token token{};
		while (telemetry_channel_->take_returned(token)) {
			if (token.owner_kind != dp::runtime_telemetry_bank_owner_kind::MODULE) {
				std::terminate();
			}
			context_->lifecycle_owner->accept_returned_telemetry(token);
		}
	}

	/** @brief Build an empty fixture before exact generation admission. */
	exact_module_test_context()
		: control_(std::chrono::steady_clock::now() + std::chrono::seconds(30))
	{
	}

	module_test_memory_provider memory_;				   ///< Exact allocation authority.
	module_test_log_provider log_;					   ///< Exact diagnostic authority.
	dp::lifecycle::lifecycle_operation_control control_;		   ///< Stable callback control.
	dp::module::module_manager manager_;				   ///< Production generation owner.
	std::unique_ptr<dp::worker_telemetry_channel> telemetry_channel_;  ///< Exact test bank channel.
	dp::module::module_context_instance *context_{nullptr};		   ///< Stable admitted context.
	dp::dp_engine packet_engine_;					   ///< Production packet entry point.
	dp::module_batch_scratch packet_batch_{};			   ///< Reusable owner-local batch.
};

}  // namespace kinetum::test
