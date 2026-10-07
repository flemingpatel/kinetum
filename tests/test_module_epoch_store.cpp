// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_module_epoch_store.cpp
 * @brief Unit tests for module epoch ownership, views, and local activation order.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

#include "src/dp/epoch/worker_epoch_activation.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/module/worker_module_health.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::dp::module
{

namespace
{

using kinetum::dp::lifecycle::prepared_config_ownership;
using kinetum::dp::lifecycle::prepared_config_record;

/** @brief Exact heap-backed lifecycle memory for the synthetic store fixture. */
class store_memory_provider final : public lifecycle::lifecycle_memory_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::allocate */
	[[nodiscard]] common::status_or<lifecycle::lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept override
	{
		void *storage = nullptr;
		const std::size_t effective_alignment = std::max(alignment, sizeof(void *));
		if (posix_memalign(&storage, effective_alignment, size) != 0) {
			return common::status::resource_exhausted("store fixture allocation failed");
		}
		std::memset(storage, zero_initialize ? 0 : 0xa5, size);
		return lifecycle::lifecycle_memory_block{storage, size, effective_alignment, numa_node, {}};
	}

	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::release */
	void release(lifecycle::lifecycle_memory_block block) noexcept override
	{
		std::free(block.data);
	}
};

/** @brief No-op cold log sink for synthetic store ownership. */
class store_log_provider final : public lifecycle::lifecycle_log_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_log_provider::write */
	void write([[maybe_unused]] const lifecycle::lifecycle_log_record_view &record) noexcept override
	{
	}
};

/** @brief Callback observations owned by one synthetic module context. */
struct store_callback_state {
	uint64_t activation_count{0};			///< Number of observed ACTIVATE callbacks.
	uint64_t process_count{0};			///< Number of observed passive packet callbacks.
	uint64_t run_count{0};				///< Number of observed active scheduling callbacks.
	uint64_t last_epoch{0};				///< Most recent callback's epoch identity.
	const void *last_packet_config{nullptr};	///< Most recent borrowed immutable packet-configuration view.
	kinetum_counter_t activation_counter{nullptr};	///< Target-attributed ACTIVATE callbacks.
};

/**
 * @brief Publish one synthetic immutable artifact to the live context.
 *
 * @param context Exact synthetic module context.
 * @param epoch Exact epoch being activated.
 * @param prepared Immutable prepared artifact view.
 */
void test_activate(kinetum_ctx *context, uint64_t epoch, const kinetum_prepared_config *prepared)
{
	auto *state = static_cast<store_callback_state *>(context->state);
	KINETUM_COUNTER_INC(state->activation_counter);
	++state->activation_count;
	state->last_epoch = epoch;
	state->last_packet_config = prepared->packet_config;
}

/**
 * @brief Forward one synthetic passive batch and record invocation.
 *
 * @param batch Exact passive batch supplied by the engine.
 * @return Forward mask covering every batch element.
 */
uint64_t test_process(kinetum_batch_t *batch)
{
	auto *state = static_cast<store_callback_state *>(batch->ctx->state);
	++state->process_count;
	return KINETUM_FORWARD_MASK(batch->count);
}

/**
 * @brief Accept one synthetic active input batch and record invocation.
 *
 * @param context Exact synthetic module context.
 * @param active_context Unused active-stage mechanism table.
 * @param batch Exact active input batch supplied by the engine.
 * @return Forward mask covering every batch element.
 */
uint64_t test_ingest(kinetum_ctx *context, kinetum_active_ctx *active_context, kinetum_batch_t *batch)
{
	(void)active_context;
	auto *state = static_cast<store_callback_state *>(context->state);
	++state->process_count;
	return KINETUM_FORWARD_MASK(batch->count);
}

/**
 * @brief Record one synthetic active scheduling turn.
 *
 * @param context Exact synthetic module context.
 * @param active_context Unused active-stage mechanism table.
 * @param triggers Unused trigger mask for this test callback.
 */
void test_run(kinetum_ctx *context, kinetum_active_ctx *active_context, uint32_t triggers)
{
	(void)active_context;
	(void)triggers;
	auto *state = static_cast<store_callback_state *>(context->state);
	++state->run_count;
}

/**
 * @brief Return one valid synthetic owner-worker health assessment.
 * @param context Exact synthetic sole-owner context.
 * @param active_epoch Exact nonzero active epoch.
 * @param active_config Optional synthetic immutable artifact.
 * @return One bounded healthy assessment.
 */
[[nodiscard]] kinetum_health_assessment test_health(kinetum_ctx *context, uint64_t active_epoch,
						    const void *active_config) noexcept
{
	(void)active_config;
	if (context == nullptr || context->state == nullptr || active_epoch == 0u) {
		std::terminate();
	}
	kinetum_health_assessment assessment{};
	assessment.health_score = 100u;
	std::memcpy(assessment.reason, "ready", sizeof("ready"));
	return assessment;
}

/**
 * @brief Exact synthetic store owner with fail-stop cleanup.
 *
 * Tests may leave ordinary PREPARED, RETAINED, or PUBLISHED state behind. The
 * fixture consumes each token in protocol order before the store is destroyed;
 * an unresolved external claim remains a test-process invariant failure.
 */
class module_store_fixture {
    public:
	/**
	 * @brief Construct one exact passive or active synthetic store.
	 *
	 * @param mode Exact descriptor execution mode.
	 */
	explicit module_store_fixture(kinetum_module_mode mode = KINETUM_MODULE_PASSIVE)
	{
		const auto host = quark::probe_host();
		if (!host.valid || host.memory_numa_nodes.empty() || host.cpus.empty()) {
			std::terminate();
		}
		const int32_t numa_node = host.memory_numa_nodes.front();
		context_.state = &state_;
		context_.numa_node = numa_node;
		context_.cpu_core_id = host.cpus.front().core_id;
		context_.worker_index = 5;
		descriptor_.module_id = MODULE_ID;
		descriptor_.mode = mode;
		descriptor_.activate_config = &test_activate;
		descriptor_.health_check = &test_health;
		if (mode == KINETUM_MODULE_PASSIVE) {
			descriptor_.process = &test_process;
		} else {
			descriptor_.ingest = &test_ingest;
			descriptor_.run = &test_run;
		}
		auto owner_or = lifecycle::lifecycle_context_owner::create(
			{MODULE_ID, "store@lane_0", MODULE_IMAGE_INDEX, CONTEXT_INDEX, context_.worker_index,
			 context_.cpu_core_id, numa_node, 0u, 1u},
			std::size_t{64} * 1024u, std::size_t{4} * 1024u, memory_, log_);
		if (!owner_or.is_ok()) {
			std::terminate();
		}
		lifecycle_owner_ = std::move(owner_or).value();
		lifecycle::lifecycle_operation_control telemetry_control(std::chrono::steady_clock::now() +
									 std::chrono::seconds(5));
		auto telemetry_init_or =
			lifecycle_owner_->begin_operation(lifecycle::lifecycle_phase::INIT, 0u, telemetry_control);
		if (!telemetry_init_or.is_ok()) {
			std::terminate();
		}
		auto telemetry_init = std::move(telemetry_init_or).value();
		if (kinetum_lifecycle_register_counter(&telemetry_init.context(), "activation_callbacks",
						       &state_.activation_counter) != KINETUM_OK) {
			std::terminate();
		}
		telemetry_init.release();
		auto channel_or = worker_telemetry_channel::create(context_.worker_index, 1u, numa_node, numa_node);
		if (!channel_or.is_ok()) {
			std::terminate();
		}
		telemetry_channel_ = std::move(channel_or).value();
		if (!lifecycle_owner_
			     ->bind_telemetry(TEST_RUNTIME_GENERATION, 4u, *telemetry_channel_,
					      descriptor_.health_check != nullptr)
			     .is_ok()) {
			std::terminate();
		}
		const std::array<uint32_t, 1> stages{0u};
		auto worker_telemetry_or = worker_runtime_telemetry::create(TEST_RUNTIME_GENERATION,
									    context_.worker_index, numa_node, stages,
									    {}, 1000u, *telemetry_channel_);
		if (!worker_telemetry_or.is_ok()) {
			std::terminate();
		}
		worker_telemetry_ = std::move(worker_telemetry_or).value();
		auto store_or = module_epoch_store::create(MODULE_IMAGE_INDEX, CONTEXT_INDEX, &descriptor_, &context_,
							   lifecycle_owner_.get());
		if (!store_or.is_ok()) {
			std::terminate();
		}
		store_ = std::move(store_or).value();
	}

	module_store_fixture(const module_store_fixture &) = delete;
	module_store_fixture &operator=(const module_store_fixture &) = delete;
	module_store_fixture(module_store_fixture &&) = delete;
	module_store_fixture &operator=(module_store_fixture &&) = delete;

	~module_store_fixture()
	{
		drain_();
		lifecycle_owner_->unbind_telemetry();
	}

	/**
	 * @brief Create one live token matching this exact store.
	 *
	 * @param epoch Exact token epoch.
	 * @param record Synthetic immutable prepared artifact.
	 * @return Live linear ownership token.
	 */
	[[nodiscard]] prepared_config_ownership token(uint64_t epoch, prepared_config_record record = {})
	{
		auto token_or = prepared_config_ownership::create(MODULE_IMAGE_INDEX, CONTEXT_INDEX, epoch, record);
		if (!token_or.is_ok()) {
			std::terminate();
		}
		return std::move(token_or).value();
	}

	/**
	 * @brief Stage and activate one exact epoch.
	 *
	 * @param epoch Exact epoch to publish.
	 * @param record Synthetic immutable prepared artifact.
	 */
	void publish(uint64_t epoch, prepared_config_record record = {})
	{
		if (store_->active_epoch() != 0u &&
		    (!lifecycle_owner_->reserve_telemetry_epoch(store_->active_epoch(), epoch).is_ok() ||
		     (worker_telemetry_->active_epoch() != 0u &&
		      !worker_telemetry_->reserve_target_epoch(store_->active_epoch(), epoch).is_ok()))) {
			std::terminate();
		}
		auto ownership = token(epoch, record);
		if (!store_->stage_prepared(ownership).is_ok() || !store_->activate_prepared(epoch, 1u).is_ok()) {
			std::terminate();
		}
		drain_telemetry_();
	}

	/**
	 * @brief Consume one synthetic token as if exact RETIRE completed.
	 *
	 * @param ownership Live token to consume.
	 * @param epoch Exact epoch required by the token.
	 */
	static void consume(prepared_config_ownership &ownership, uint64_t epoch)
	{
		if (!ownership.retire_exact(MODULE_IMAGE_INDEX, CONTEXT_INDEX, epoch).is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Record successful synthetic RETIRE through its store-bound claim.
	 *
	 * These store tests have no foreign module callback. Calling this helper is
	 * the explicit stand-in for a successfully completed matching RETIRE.
	 *
	 * @param claim Exact unresolved retirement claim to consume.
	 */
	static void consume_claim(module_retirement_claim &claim)
	{
		if (!claim.consume_after_retire().is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Return the exact store.
	 *
	 * @return Mutable store owned by this fixture.
	 */
	[[nodiscard]] module_epoch_store &store() noexcept
	{
		return *store_;
	}

	/**
	 * @brief Return synthetic callback observations.
	 *
	 * @return Mutable owner-local callback state.
	 */
	[[nodiscard]] store_callback_state &state() noexcept
	{
		return state_;
	}

	/** @return Absolute activation count captured in the latest completed module bank. */
	[[nodiscard]] uint64_t last_completed_activation_count() const noexcept
	{
		return last_completed_activation_count_;
	}

	/**
	 * @brief Return the stable synthetic context.
	 *
	 * @return Mutable context bound to this store.
	 */
	[[nodiscard]] kinetum_ctx &context() noexcept
	{
		return context_;
	}

	/**
	 * @brief Return the stable synthetic descriptor.
	 *
	 * @return Mutable descriptor bound to this store.
	 */
	[[nodiscard]] kinetum_module &descriptor() noexcept
	{
		return descriptor_;
	}

	/** @return Exact lifecycle publication owner bound to this context. */
	[[nodiscard]] lifecycle::lifecycle_context_owner &lifecycle_owner() noexcept
	{
		return *lifecycle_owner_;
	}

	/**
	 * @brief Reserve the exact module telemetry target used by a direct store test.
	 * @param epoch Prepared target epoch whose module and worker banks are reserved.
	 */
	void reserve_telemetry(uint64_t epoch)
	{
		if (!lifecycle_owner_->reserve_telemetry_epoch(store_->active_epoch(), epoch).is_ok() ||
		    (worker_telemetry_->active_epoch() != 0u &&
		     !worker_telemetry_->reserve_target_epoch(store_->active_epoch(), epoch).is_ok())) {
			std::terminate();
		}
	}

	/** @brief Drain every completed module/worker bank through the cold side. */
	void drain_telemetry()
	{
		drain_telemetry_();
	}

	/** @brief Retire every store/bank owner while an external health claim remains live. */
	void retire_for_health_owner_test() noexcept
	{
		drain_();
	}

	/** @return Exact worker bank authority used by activation component tests. */
	[[nodiscard]] worker_runtime_telemetry &worker_telemetry() noexcept
	{
		return *worker_telemetry_;
	}

	/**
	 * @brief Bind the worker telemetry Bootstrap bank beside the module store.
	 * @param epoch Nonzero bootstrap epoch shared with the module store.
	 */
	void bind_worker_telemetry(uint64_t epoch)
	{
		worker_telemetry_->bind_bootstrap_epoch(epoch, 1u);
	}

	/**
	 * @brief Publish and aggregate final module/worker telemetry for direct shutdown claims.
	 * @param epoch Active epoch whose final observations must be retired.
	 */
	void publish_shutdown_telemetry(uint64_t epoch)
	{
		if (worker_telemetry_->active_epoch() == epoch) {
			if (!worker_telemetry_->preflight_shutdown(epoch)) {
				std::terminate();
			}
			worker_telemetry_->publish_shutdown(epoch, 2u);
			worker_telemetry_->mark_owner_quiesced();
		}
		if (!lifecycle_owner_->preflight_publish_shutdown_telemetry(epoch)) {
			std::terminate();
		}
		lifecycle_owner_->publish_shutdown_telemetry(epoch, 2u);
		lifecycle_owner_->mark_telemetry_worker_quiesced();
		drain_telemetry_();
		if (worker_telemetry_->epoch_aggregated(epoch) &&
		    worker_telemetry_->retire_epoch(epoch, 0u).has_value()) {
			std::terminate();
		}
	}

	static constexpr const char *MODULE_ID = "test.store";	///< Exact synthetic module image identity.
	/** Compiled synthetic module-image identity. */
	static constexpr uint32_t MODULE_IMAGE_INDEX = 3;
	/** Compiled synthetic module-context identity. */
	static constexpr uint32_t CONTEXT_INDEX = 7;
	/** Runtime generation shared by store and telemetry owners. */
	static constexpr uint64_t TEST_RUNTIME_GENERATION = 7u;

    private:
	/** @brief Merge every completed synthetic module bank and consume returns. */
	void drain_telemetry_() noexcept
	{
		runtime_telemetry_bank_token token{};
		bool progressed = false;
		do {
			progressed = false;
			while (telemetry_channel_->take_completed(token)) {
				progressed = true;
				if (token.kind == runtime_telemetry_bank_token_kind::RETURN_RETAINED) {
					if (token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER) {
						worker_telemetry_->mark_epoch_aggregated(token.epoch);
					} else {
						lifecycle_owner_->mark_telemetry_epoch_aggregated(token.epoch);
					}
					continue;
				}
				if (token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER) {
					if (!worker_telemetry_->completed_bank(token).is_ok()) {
						std::terminate();
					}
					worker_telemetry_->complete_aggregation(token);
					if (token.reason != runtime_telemetry_publication_reason::CADENCE &&
					    token.companion_bank_index != UINT8_MAX) {
						worker_telemetry_->mark_epoch_aggregated(token.epoch);
					}
				} else {
					auto bank_or = lifecycle_owner_->completed_telemetry_bank(token);
					if (!bank_or.is_ok() || bank_or->counter_values.size() != 1u) {
						std::terminate();
					}
					last_completed_activation_count_ = bank_or->counter_values[0];
					lifecycle_owner_->complete_telemetry_aggregation(token);
					if (token.reason != runtime_telemetry_publication_reason::CADENCE &&
					    token.companion_bank_index != UINT8_MAX) {
						lifecycle_owner_->mark_telemetry_epoch_aggregated(token.epoch);
					}
				}
			}
			while (telemetry_channel_->take_returned(token)) {
				progressed = true;
				if (token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER) {
					worker_telemetry_->accept_returned(token);
				} else {
					lifecycle_owner_->accept_returned_telemetry(token);
				}
			}
		} while (progressed);
		if (store_ != nullptr && store_->active_epoch() != 0u) {
			const auto issued = lifecycle_owner_->take_reclaimed_telemetry_transfer(store_->active_epoch());
			if (issued.has_value() &&
			    (issued->epoch != store_->active_epoch() ||
			     (issued->kind != runtime_telemetry_bank_token_kind::BANK &&
			      issued->kind != runtime_telemetry_bank_token_kind::RETURN_RETAINED))) {
				std::terminate();
			}
		}
	}

	/** @brief Consume every ordinary store-owned token in legal order. */
	void drain_() noexcept
	{
		const uint64_t worker_active_epoch = worker_telemetry_->active_epoch();
		if (worker_active_epoch != 0u) {
			if (!worker_telemetry_->preflight_shutdown(worker_active_epoch)) {
				drain_telemetry_();
			}
			if (!worker_telemetry_->preflight_shutdown(worker_active_epoch)) {
				std::terminate();
			}
			worker_telemetry_->publish_shutdown(worker_active_epoch, 2u);
			worker_telemetry_->mark_owner_quiesced();
			drain_telemetry_();
		}
		const uint64_t prepared_epoch = store_->prepared_epoch();
		if (prepared_epoch != 0) {
			auto discarded_or = store_->discard_prepared(prepared_epoch);
			if (!discarded_or.is_ok()) {
				std::terminate();
			}
			auto ownership = std::move(discarded_or).value();
			if (store_->active_epoch() != 0u) {
				lifecycle_owner_->discard_telemetry_epoch(prepared_epoch);
			}
			consume(ownership, prepared_epoch);
		}
		const uint64_t shutdown_epoch = store_->active_epoch();
		if (shutdown_epoch != 0u) {
			if (lifecycle_owner_->telemetry_active_epoch() == shutdown_epoch) {
				if (!lifecycle_owner_->preflight_publish_shutdown_telemetry(shutdown_epoch)) {
					std::terminate();
				}
				lifecycle_owner_->publish_shutdown_telemetry(shutdown_epoch, 2u);
				lifecycle_owner_->mark_telemetry_worker_quiesced();
				drain_telemetry_();
			} else if (lifecycle_owner_->telemetry_active_epoch() != 0u ||
				   !lifecycle_owner_->telemetry_epoch_aggregated(shutdown_epoch)) {
				std::terminate();
			}
		}

		for (std::size_t index = 0; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
			const auto *slot = store_->slot(index);
			if (slot == nullptr || slot->state != epoch_slot_state::RETAINED) {
				continue;
			}
			auto claim_or = store_->claim_retained(slot->epoch);
			if (!claim_or.is_ok()) {
				std::terminate();
			}
			auto claim = std::move(claim_or).value();
			consume_claim(claim);
			const uint64_t retired_epoch = claim.epoch();
			if (!store_->complete_retirement(claim).is_ok()) {
				std::terminate();
			}
			const auto module_transfer =
				lifecycle_owner_->take_reclaimed_telemetry_transfer(store_->active_epoch());
			if (!module_transfer.has_value() ||
			    module_transfer->kind != runtime_telemetry_bank_token_kind::RETURN_RETAINED) {
				std::terminate();
			}
			lifecycle_owner_->mark_telemetry_epoch_aggregated(store_->active_epoch());
			if (worker_telemetry_->epoch_aggregated(retired_epoch)) {
				const auto transfer =
					worker_telemetry_->retire_epoch(retired_epoch, store_->active_epoch());
				if (!transfer.has_value() ||
				    transfer->kind != runtime_telemetry_bank_token_kind::RETURN_RETAINED) {
					std::terminate();
				}
				worker_telemetry_->mark_epoch_aggregated(store_->active_epoch());
			}
			drain_telemetry_();
		}

		const uint64_t active_epoch = store_->active_epoch();
		if (active_epoch != 0) {
			auto claim_or = store_->claim_published_for_shutdown(active_epoch);
			if (!claim_or.is_ok()) {
				std::terminate();
			}
			auto claim = std::move(claim_or).value();
			consume_claim(claim);
			if (!store_->complete_retirement(claim).is_ok()) {
				std::terminate();
			}
			if (worker_telemetry_->epoch_aggregated(active_epoch)) {
				(void)worker_telemetry_->retire_epoch(active_epoch, 0u);
			}
		}
		if (lifecycle_owner_->module_health_owner_claimed()) {
			if (!store_->health_owner_release_ready()) {
				std::terminate();
			}
		} else if (!store_->empty()) {
			std::terminate();
		}
	}

	store_callback_state state_{};	///< Synthetic callback observations.
	store_memory_provider memory_;	///< Context and epoch allocation owner.
	store_log_provider log_;	///< Cold lifecycle diagnostic receiver.
	kinetum_ctx context_{};		///< Exact packet callback shell.
	kinetum_module descriptor_{};	///< Synthetic module callback authority.
	std::unique_ptr<lifecycle::lifecycle_context_owner>
		lifecycle_owner_;				       ///< Lifecycle operations and module telemetry.
	std::unique_ptr<worker_telemetry_channel> telemetry_channel_;  ///< Worker/aggregator bank-token exchange.
	std::unique_ptr<worker_runtime_telemetry> worker_telemetry_;   ///< Worker-owned epoch observations.
	std::unique_ptr<module_epoch_store> store_;		       ///< Exact configuration-slot owner under test.
	uint64_t last_completed_activation_count_{0};		       ///< Latest immutable module-bank callback count.
};

static_assert(!std::is_copy_constructible_v<module_epoch_store>);
static_assert(!std::is_move_constructible_v<module_epoch_store>);
static_assert(!std::is_copy_constructible_v<module_retirement_claim>);
static_assert(std::is_move_constructible_v<module_retirement_claim>);
static_assert(std::is_nothrow_move_constructible_v<module_retirement_claim>);
static_assert(!std::is_move_assignable_v<module_retirement_claim>);
static_assert(std::is_const_v<std::remove_reference_t<decltype(std::declval<module_retirement_claim &>().ownership())>>,
	      "retirement claims must expose ownership only as a read-only borrow");
static_assert(std::is_nothrow_move_constructible_v<prepared_config_ownership>);
static_assert(std::is_nothrow_move_assignable_v<prepared_config_ownership>);

}  // namespace

/** @brief Publish a null/null artifact as explicit successful ownership state. */
TEST(module_epoch_store, publishes_initial_null_artifact_as_explicit_success)
{
	module_store_fixture fixture;
	auto token = fixture.token(11);
	EXPECT_TRUE(fixture.store().stage_prepared(token).is_ok());
	EXPECT_FALSE(token.owns_state());
	EXPECT_EQ(fixture.store().prepared_epoch(), 11u);
	EXPECT_TRUE(fixture.store().activate_prepared(11, 1u).is_ok());
	ASSERT_NE(fixture.store().active_view(), nullptr);
	EXPECT_EQ(fixture.store().active_view()->epoch, 11u);
	EXPECT_EQ(fixture.store().active_view()->packet_config, nullptr);
	EXPECT_EQ(fixture.state().activation_count, 1u);
}

/** @brief Cache one complete passive callback/config/context execution view. */
TEST(module_epoch_store, publishes_complete_passive_callback_view)
{
	module_store_fixture fixture;
	uint64_t config = 0x1234;
	fixture.publish(4, {&config, &config});
	const auto *view = fixture.store().active_view();
	ASSERT_NE(view, nullptr);
	EXPECT_EQ(view->context, &fixture.context());
	EXPECT_EQ(view->packet_config, &config);
	EXPECT_EQ(view->process, &test_process);
	EXPECT_EQ(view->ingest, nullptr);
	EXPECT_EQ(view->run, nullptr);
	EXPECT_EQ(view->mode, KINETUM_MODULE_PASSIVE);
}

/** @brief Cache one complete active callback/config/context execution view. */
TEST(module_epoch_store, publishes_complete_active_callback_view)
{
	module_store_fixture fixture(KINETUM_MODULE_ACTIVE);
	fixture.publish(5);
	const auto *view = fixture.store().active_view();
	ASSERT_NE(view, nullptr);
	EXPECT_EQ(view->process, nullptr);
	EXPECT_EQ(view->ingest, &test_ingest);
	EXPECT_EQ(view->run, &test_run);
	EXPECT_EQ(view->mode, KINETUM_MODULE_ACTIVE);
}

/** @brief Reject a foreign token without consuming its linear ownership. */
TEST(module_epoch_store, rejects_mismatched_token_without_consuming_it)
{
	module_store_fixture fixture;
	auto wrong_or = prepared_config_ownership::create(99, module_store_fixture::CONTEXT_INDEX, 3, {});
	ASSERT_TRUE(wrong_or.is_ok());
	auto wrong = std::move(wrong_or).value();
	const auto status = fixture.store().stage_prepared(wrong);
	EXPECT_FALSE(status.is_ok());
	EXPECT_TRUE(wrong.owns_state());
	EXPECT_TRUE(wrong.retire_exact(99, module_store_fixture::CONTEXT_INDEX, 3).is_ok());
	EXPECT_TRUE(fixture.store().empty());
}

/** @brief Return the same live token when a staged PREPARE is aborted. */
TEST(module_epoch_store, discard_returns_the_same_live_token)
{
	module_store_fixture fixture;
	auto token = fixture.token(6);
	ASSERT_TRUE(fixture.store().stage_prepared(token).is_ok());
	auto discarded_or = fixture.store().discard_prepared(6);
	ASSERT_TRUE(discarded_or.is_ok());
	auto discarded = std::move(discarded_or).value();
	EXPECT_TRUE(discarded.owns_state());
	EXPECT_EQ(discarded.epoch(), 6u);
	module_store_fixture::consume(discarded, 6);
	EXPECT_TRUE(fixture.store().empty());
}

/** @brief Retain the prior epoch and refuse shutdown until it is retired. */
TEST(module_epoch_store, second_publication_retains_exact_prior_epoch)
{
	module_store_fixture fixture;
	fixture.publish(2);
	fixture.reserve_telemetry(9);
	auto target = fixture.token(9);
	ASSERT_TRUE(fixture.store().stage_prepared(target).is_ok());
	ASSERT_TRUE(fixture.store().preflight_future_retained(2, 9).is_ok());
	ASSERT_TRUE(fixture.store().activate_prepared(9, 1u).is_ok());
	fixture.drain_telemetry();
	EXPECT_EQ(fixture.last_completed_activation_count(), 1u);
	EXPECT_EQ(fixture.state().activation_count, 2u);
	ASSERT_TRUE(fixture.store().preflight_claim_retained(2).is_ok());
	ASSERT_NE(fixture.store().active_view(), nullptr);
	EXPECT_EQ(fixture.store().active_epoch(), 9u);
	bool found_old = false;
	bool found_new = false;
	for (std::size_t index = 0; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
		const auto *slot = fixture.store().slot(index);
		found_old = found_old || (slot->epoch == 2 && slot->state == epoch_slot_state::RETAINED);
		found_new = found_new || (slot->epoch == 9 && slot->state == epoch_slot_state::PUBLISHED);
	}
	EXPECT_TRUE(found_old);
	EXPECT_TRUE(found_new);
	EXPECT_EQ(fixture.state().activation_count, 2u);
	const auto shutdown_claim = fixture.store().claim_published_for_shutdown(9);
	EXPECT_FALSE(shutdown_claim.is_ok());
	EXPECT_EQ(shutdown_claim.error().code(), common::status_code::FAILED_PRECONDITION);
	ASSERT_NE(fixture.store().active_view(), nullptr);
	EXPECT_EQ(fixture.store().active_epoch(), 9u);
}

/** @brief Refuse a third epoch while the retained slot remains owned. */
TEST(module_epoch_store, occupied_retained_slot_blocks_third_epoch)
{
	module_store_fixture fixture;
	fixture.publish(2);
	fixture.publish(9);
	auto third = fixture.token(12);
	const auto status = fixture.store().stage_prepared(third);
	EXPECT_FALSE(status.is_ok());
	EXPECT_EQ(status.code(), common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_TRUE(third.owns_state());
	module_store_fixture::consume(third, 12);
}

/** @brief Accumulate mismatch evidence while preserving one immutable first-fault record. */
TEST(module_epoch_store, mismatch_counter_accumulates_and_first_record_is_sticky)
{
	module_store_fixture fixture;
	fixture.publish(8);
	fixture.store().record_epoch_mismatch(7, 4, 2);
	fixture.store().record_epoch_mismatch(6, 5, 3);
	const auto diagnostics = fixture.store().diagnostics_after_quiescence();
	EXPECT_EQ(diagnostics.mismatch_count, 2u);
	EXPECT_EQ(diagnostics.sticky_fault, 1u);
	ASSERT_EQ(diagnostics.first_fault_valid, 1u);
	EXPECT_EQ(diagnostics.first_fault.packet_epoch, 7u);
	EXPECT_EQ(diagnostics.first_fault.active_epoch, 8u);
	EXPECT_EQ(diagnostics.first_fault.context_index, module_store_fixture::CONTEXT_INDEX);
	EXPECT_EQ(diagnostics.first_fault.stage_instance_index, 4u);
	EXPECT_EQ(diagnostics.first_fault.worker_index, 5u);
	EXPECT_EQ(diagnostics.first_fault.region_id, 2);
}

/** @brief Enforce one claimant and permit restoration only by that claimant. */
TEST(module_epoch_store, retained_claim_is_unique_and_restorable_by_claimant)
{
	module_store_fixture fixture;
	fixture.publish(1);
	fixture.publish(2);
	auto claim_or = fixture.store().claim_retained(1);
	ASSERT_TRUE(claim_or.is_ok());
	auto claim = std::move(claim_or).value();
	EXPECT_FALSE(fixture.store().claim_retained(1).is_ok());
	EXPECT_TRUE(fixture.store().restore_retirement(claim).is_ok());
	EXPECT_EQ(claim.claim_id(), 0u);
	EXPECT_FALSE(claim.ownership().owns_state());
	EXPECT_FALSE(fixture.store().restore_retirement(claim).is_ok());
	bool restored_retained_epoch = false;
	for (std::size_t index = 0; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
		const auto *slot = fixture.store().slot(index);
		restored_retained_epoch = restored_retained_epoch || (slot != nullptr && slot->epoch == 1 &&
								      slot->state == epoch_slot_state::RETAINED);
	}
	EXPECT_TRUE(restored_retained_epoch);
}

/** @brief Reject a valid-looking claim issued by a different exact store. */
TEST(module_epoch_store, foreign_store_cannot_restore_another_claim)
{
	module_store_fixture first;
	module_store_fixture second;
	first.publish(1);
	first.publish(2);
	second.publish(1);
	second.publish(2);
	auto first_claim_or = first.store().claim_retained(1);
	auto second_claim_or = second.store().claim_retained(1);
	ASSERT_TRUE(first_claim_or.is_ok());
	ASSERT_TRUE(second_claim_or.is_ok());
	auto first_claim = std::move(first_claim_or).value();
	auto second_claim = std::move(second_claim_or).value();
	EXPECT_FALSE(first.store().restore_retirement(second_claim).is_ok());
	EXPECT_TRUE(first_claim.ownership().owns_state());
	EXPECT_TRUE(second_claim.ownership().owns_state());
	EXPECT_TRUE(first.store().restore_retirement(first_claim).is_ok());
	EXPECT_TRUE(second.store().restore_retirement(second_claim).is_ok());
}

/** @brief Require exact claim-scoped consumption before clearing a claimed slot. */
TEST(module_epoch_store, completion_requires_claim_scoped_retire_consumption)
{
	module_store_fixture fixture;
	fixture.publish(1);
	fixture.publish(2);
	auto claim_or = fixture.store().claim_retained(1);
	ASSERT_TRUE(claim_or.is_ok());
	auto claim = std::move(claim_or).value();
	EXPECT_FALSE(fixture.store().complete_retirement(claim).is_ok());
	EXPECT_TRUE(claim.consume_after_retire().is_ok());
	EXPECT_FALSE(claim.consume_after_retire().is_ok());
	EXPECT_FALSE(fixture.store().restore_retirement(claim).is_ok());
	EXPECT_TRUE(fixture.store().complete_retirement(claim).is_ok());
	fixture.drain_telemetry();
	EXPECT_EQ(claim.claim_id(), 0u);
	EXPECT_FALSE(fixture.store().complete_retirement(claim).is_ok());
}

/** @brief Invalidate every claim identity field during move construction. */
TEST(module_epoch_store, move_invalidates_the_source_claim_nonce)
{
	module_store_fixture fixture;
	fixture.publish(1);
	fixture.publish(2);
	auto claim_or = fixture.store().claim_retained(1);
	ASSERT_TRUE(claim_or.is_ok());
	auto source = std::move(claim_or).value();
	auto destination = std::move(source);
	EXPECT_EQ(source.claim_id(), 0u);
	EXPECT_EQ(source.epoch(), 0u);
	EXPECT_FALSE(fixture.store().restore_retirement(source).is_ok());
	module_store_fixture::consume_claim(destination);
	EXPECT_TRUE(fixture.store().complete_retirement(destination).is_ok());
	fixture.drain_telemetry();
}

/** @brief Withdraw and exactly restore a published shutdown claim. */
TEST(module_epoch_store, shutdown_claim_withdraws_and_can_restore_active_view)
{
	module_store_fixture fixture;
	fixture.publish(14);
	fixture.publish_shutdown_telemetry(14);
	auto claim_or = fixture.store().claim_published_for_shutdown(14);
	ASSERT_TRUE(claim_or.is_ok());
	auto claim = std::move(claim_or).value();
	EXPECT_EQ(fixture.store().active_view(), nullptr);
	EXPECT_EQ(fixture.store().active_epoch(), 0u);
	EXPECT_TRUE(fixture.store().restore_retirement(claim).is_ok());
	ASSERT_NE(fixture.store().active_view(), nullptr);
	EXPECT_EQ(fixture.store().active_epoch(), 14u);
}

/** @brief Empty metadata, token, claim, and view authority at final shutdown. */
TEST(module_epoch_store, final_shutdown_retirement_empties_both_authorities)
{
	module_store_fixture fixture;
	fixture.publish(14);
	fixture.publish_shutdown_telemetry(14);
	auto claim_or = fixture.store().claim_published_for_shutdown(14);
	ASSERT_TRUE(claim_or.is_ok());
	auto claim = std::move(claim_or).value();
	module_store_fixture::consume_claim(claim);
	EXPECT_TRUE(fixture.store().complete_retirement(claim).is_ok());
	EXPECT_TRUE(fixture.store().empty());
	EXPECT_EQ(fixture.store().active_view(), nullptr);
}

/** @brief Observe a fully constructed token/view through the release/acquire handoff. */
TEST(module_epoch_store, release_acquire_handoff_publishes_complete_view)
{
	module_store_fixture fixture;
	uint64_t config = 0xfeed;
	auto token = fixture.token(21, {&config, &config});
	kinetum::common::status activation_status =
		kinetum::common::status::internal_error("owner did not observe PREPARE publication");
	std::thread producer([&fixture, &token]() {
		if (!fixture.store().stage_prepared(token).is_ok()) {
			std::terminate();
		}
	});
	std::thread owner([&fixture, &activation_status]() {
		while (fixture.store().prepared_epoch() != 21) {
			std::this_thread::yield();
		}
		activation_status = fixture.store().activate_prepared(21, 1u);
	});
	producer.join();
	owner.join();
	ASSERT_TRUE(activation_status.is_ok()) << activation_status.message();
	ASSERT_NE(fixture.store().active_view(), nullptr);
	EXPECT_EQ(fixture.store().active_view()->packet_config, &config);
	EXPECT_EQ(fixture.state().last_packet_config, &config);
}

/** @brief Activate modules, source queue roles, and ledger in one exact local order. */
TEST(worker_epoch_activation, complete_preflight_precedes_module_queue_and_ledger_commit)
{
	constexpr uint32_t worker_index = 5u;
	constexpr uint64_t runtime_generation = 7u;
	constexpr uint64_t active_epoch = 11u;
	constexpr uint64_t future_epoch = 13u;
	constexpr uint64_t transition_generation = 3u;
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	const int32_t numa_node = host.memory_numa_nodes.front();

	module_store_fixture fixture;
	auto staging_or = packet_epoch_input_staging::create(4u, 4u, numa_node);
	ASSERT_TRUE(staging_or.is_ok()) << staging_or.error().message();
	auto staging = std::move(staging_or).value();
	auto second_staging_or = packet_epoch_input_staging::create(8u, 8u, numa_node);
	ASSERT_TRUE(second_staging_or.is_ok()) << second_staging_or.error().message();
	auto second_staging = std::move(second_staging_or).value();
	auto ledger_or = worker_epoch_ledger::create(worker_index, runtime_generation, 8u);
	ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
	auto ledger = std::move(ledger_or).value();
	const std::array<worker_module_health_binding, 1> health_bindings{{
		{
			.stage_instance_index = 4u,
			.context_index = module_store_fixture::CONTEXT_INDEX,
			.context = &fixture.context(),
			.store = &fixture.store(),
			.descriptor = &fixture.descriptor(),
			.publication = &fixture.lifecycle_owner(),
		},
	}};
	auto health_or = worker_module_health::create(worker_index, runtime_generation, 100u, health_bindings, *ledger);
	ASSERT_TRUE(health_or.is_ok()) << health_or.error().message();
	auto health = std::move(health_or).value();
	fixture.publish(active_epoch);
	ledger->bind_bootstrap_epoch(active_epoch);
	std::array<module_epoch_store *, 1> stores{&fixture.store()};
	std::array<packet_epoch_input_staging *, 2> staging_owners{second_staging.get(), staging.get()};
	std::array<module_epoch_store *, 2> duplicate_stores{&fixture.store(), &fixture.store()};
	std::array<packet_epoch_input_staging *, 2> duplicate_staging{staging.get(), staging.get()};
	std::array<packet_epoch_input_staging *, 0> no_staging{};
	auto duplicate_store_or = worker_epoch_activation::create(worker_index, runtime_generation, duplicate_stores,
								  no_staging, *ledger, nullptr, health.get(),
								  fixture.worker_telemetry());
	ASSERT_FALSE(duplicate_store_or.is_ok());
	EXPECT_EQ(duplicate_store_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto duplicate_staging_or = worker_epoch_activation::create(worker_index, runtime_generation, stores,
								    duplicate_staging, *ledger, nullptr, health.get(),
								    fixture.worker_telemetry());
	ASSERT_FALSE(duplicate_staging_or.is_ok());
	EXPECT_EQ(duplicate_staging_or.error().code(), common::status_code::FAILED_PRECONDITION);
	auto activation_or = worker_epoch_activation::create(worker_index, runtime_generation, stores, staging_owners,
							     *ledger, nullptr, health.get(),
							     fixture.worker_telemetry());
	ASSERT_TRUE(activation_or.is_ok()) << activation_or.error().message();
	auto activation = std::move(activation_or).value();
	EXPECT_TRUE(activation->owns_ledger(*ledger));
	ASSERT_EQ(fixture.store().prepared_epoch(), 0u);
	fixture.bind_worker_telemetry(active_epoch);
	activation->bind_bootstrap_epoch(active_epoch);
	worker_epoch_activation_snapshot baseline{};
	ASSERT_EQ(activation->try_read(baseline), publication_read_result::AVAILABLE);
	EXPECT_EQ(baseline.publication_generation, 1u);
	EXPECT_EQ(baseline.transition_generation, 0u);
	EXPECT_EQ(baseline.from_epoch, 0u);
	EXPECT_EQ(baseline.to_epoch, active_epoch);
	EXPECT_EQ(baseline.active_epoch, active_epoch);
	EXPECT_EQ(baseline.activation_complete, 0u);
	auto prepared = fixture.token(future_epoch);
	fixture.reserve_telemetry(future_epoch);
	ASSERT_TRUE(fixture.store().stage_prepared(prepared).is_ok());
	auto health_claim = health->begin(0u);
	if (!health_claim.has_value()) {
		ADD_FAILURE() << "exact health callback did not produce its linear invocation";
		return;
	}
	EXPECT_FALSE(activation->preflight_begin_transition(transition_generation, active_epoch, future_epoch));
	health_claim.value().invoke(1u);
	health_claim.value().complete(2u);
	ASSERT_TRUE(activation->preflight_begin_transition(transition_generation, active_epoch, future_epoch));

	packet_record record{};
	record.metadata.epoch = future_epoch;
	ASSERT_TRUE(staging->reserve_future());
	staging->commit_future({&record, packet_work_phase::EXECUTE, {}});
	ledger->bind_future_epoch(future_epoch);
	ledger->advance_source_epoch(future_epoch);
	ledger->acquire(future_epoch);
	ASSERT_TRUE(activation->preflight(transition_generation, active_epoch, future_epoch).is_ok());
	EXPECT_EQ(fixture.state().activation_count, 1u);
	ASSERT_TRUE(activation->activate(transition_generation, active_epoch, future_epoch, 1u).is_ok());
	fixture.drain_telemetry();
	EXPECT_EQ(fixture.state().activation_count, 2u);
	EXPECT_EQ(fixture.store().active_epoch(), future_epoch);
	EXPECT_EQ(activation->active_epoch(), future_epoch);
	EXPECT_EQ(activation->last_transition_generation(), transition_generation);
	worker_epoch_activation_snapshot completed{};
	ASSERT_EQ(activation->try_read(completed), publication_read_result::AVAILABLE);
	EXPECT_EQ(completed.publication_generation, 2u);
	EXPECT_EQ(completed.transition_generation, transition_generation);
	EXPECT_EQ(completed.from_epoch, active_epoch);
	EXPECT_EQ(completed.to_epoch, future_epoch);
	EXPECT_EQ(completed.active_epoch, future_epoch);
	EXPECT_EQ(completed.activation_complete, 1u);
	EXPECT_EQ(activation->module_store_count(), 1u);
	EXPECT_EQ(activation->source_staging_count(), 2u);
	EXPECT_EQ(ledger->active_epoch(), future_epoch);
	EXPECT_EQ(ledger->future_epoch(), 0u);
	EXPECT_EQ(ledger->active_unretired(), 1u);
	std::array<packet_work_item, 1> observed{{{
		.record = nullptr,
		.phase = packet_work_phase::EXECUTE,
		.padding = {},
	}}};
	ASSERT_EQ(staging->pop_active_batch(observed.data(), observed.size()), 1u);
	EXPECT_EQ(observed[0].record, &record);
	ledger->retire(future_epoch);
	fixture.retire_for_health_owner_test();
	activation.reset();
	health.reset();
}

/** @brief A failed complete preflight mutates no module, queue role, or ledger identity. */
TEST(worker_epoch_activation, unresolved_old_work_rejects_before_every_irreversible_effect)
{
	constexpr uint32_t worker_index = 5u;
	constexpr uint64_t runtime_generation = 7u;
	constexpr uint64_t active_epoch = 11u;
	constexpr uint64_t future_epoch = 13u;
	constexpr uint64_t transition_generation = 3u;
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	const int32_t numa_node = host.memory_numa_nodes.front();

	module_store_fixture fixture;
	auto staging_or = packet_epoch_input_staging::create(4u, 4u, numa_node);
	ASSERT_TRUE(staging_or.is_ok()) << staging_or.error().message();
	auto staging = std::move(staging_or).value();
	auto ledger_or = worker_epoch_ledger::create(worker_index, runtime_generation, 8u);
	ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
	auto ledger = std::move(ledger_or).value();
	const std::array<worker_module_health_binding, 1> health_bindings{{
		{
			.stage_instance_index = 4u,
			.context_index = module_store_fixture::CONTEXT_INDEX,
			.context = &fixture.context(),
			.store = &fixture.store(),
			.descriptor = &fixture.descriptor(),
			.publication = &fixture.lifecycle_owner(),
		},
	}};
	auto health_or = worker_module_health::create(worker_index, runtime_generation, 100u, health_bindings, *ledger);
	ASSERT_TRUE(health_or.is_ok()) << health_or.error().message();
	auto health = std::move(health_or).value();
	fixture.publish(active_epoch);
	ledger->bind_bootstrap_epoch(active_epoch);
	std::array<module_epoch_store *, 1> stores{&fixture.store()};
	std::array<packet_epoch_input_staging *, 1> staging_owners{staging.get()};
	auto activation_or = worker_epoch_activation::create(worker_index, runtime_generation, stores, staging_owners,
							     *ledger, nullptr, health.get(),
							     fixture.worker_telemetry());
	ASSERT_TRUE(activation_or.is_ok()) << activation_or.error().message();
	auto activation = std::move(activation_or).value();
	ASSERT_EQ(fixture.store().prepared_epoch(), 0u);
	fixture.bind_worker_telemetry(active_epoch);
	activation->bind_bootstrap_epoch(active_epoch);
	auto prepared = fixture.token(future_epoch);
	fixture.reserve_telemetry(future_epoch);
	ASSERT_TRUE(fixture.store().stage_prepared(prepared).is_ok());

	packet_record old_record{};
	old_record.metadata.epoch = active_epoch;
	ASSERT_TRUE(staging->reserve_active());
	staging->commit_active({&old_record, packet_work_phase::EXECUTE, {}});
	ledger->acquire(active_epoch);
	ledger->bind_future_epoch(future_epoch);
	ledger->advance_source_epoch(future_epoch);
	const auto rejected = activation->activate(transition_generation, active_epoch, future_epoch, 1u);
	EXPECT_EQ(rejected.code(), common::status_code::FAILED_PRECONDITION);
	EXPECT_EQ(fixture.state().activation_count, 1u);
	EXPECT_EQ(fixture.store().active_epoch(), active_epoch);
	EXPECT_EQ(fixture.store().prepared_epoch(), future_epoch);
	EXPECT_EQ(ledger->active_epoch(), active_epoch);
	EXPECT_EQ(ledger->future_epoch(), future_epoch);
	EXPECT_EQ(staging->peek_active()->record, &old_record);

	std::array<packet_work_item, 1> observed{{{
		.record = nullptr,
		.phase = packet_work_phase::EXECUTE,
		.padding = {},
	}}};
	ASSERT_EQ(staging->pop_active_batch(observed.data(), observed.size()), 1u);
	ledger->retire(active_epoch);
	ASSERT_TRUE(activation->activate(transition_generation, active_epoch, future_epoch, 1u).is_ok());
	fixture.drain_telemetry();
	EXPECT_EQ(fixture.state().activation_count, 2u);
	fixture.retire_for_health_owner_test();
	activation.reset();
	health.reset();
}

}  // namespace kinetum::dp::module
