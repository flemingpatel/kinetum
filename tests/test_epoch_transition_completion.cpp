// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_transition_completion.cpp
 * @brief Exact two-leg completion, freeze, and terminal-publication tests.
 * @author Fleming Patel
 *
 * The fixture composes production coordinator, snapshot store, worker ledger,
 * sender/receiver policy, local activation, quiescence, certificate, runtime
 * status, and completion methods. Narrow module/preparation interfaces retain
 * no test-only completion mutation; they exercise both module-free and exact
 * claimed-RETIRE production shapes.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "src/common/canonical_content_identity.hpp"
#include "src/common/runtime_service_ids.hpp"
#include "src/common/status.hpp"
#include "src/dp/epoch/epoch_transition_completion.hpp"
#include "src/dp/epoch/epoch_transition_telemetry_completion.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "src/dp/epoch/worker_epoch_activation.hpp"
#include "src/dp/lifecycle/runtime_service_launcher.hpp"
#include "src/dp/module/worker_module_health.hpp"
#include "tests/module_abi_test_harness.hpp"
#include "tests/packet_runtime_test_fixture.hpp"
#include "tests/worker_telemetry_test_fixture.hpp"

#if !defined(KINETUM_TEST_MODULE_PATH)
#error "Exact passive test-module path is required"
#endif

namespace kinetum::dp
{
namespace
{

namespace runtime_fixture = kinetum::test::packet_runtime_fixture_detail;
using kinetum::test::packet_runtime_test_transition_timing;

/** Runtime identity shared by every completion participant. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 1u;
/** Initial packet-configuration epoch. */
constexpr uint64_t TEST_BOOTSTRAP_EPOCH = 1u;
/** Prepared replacement epoch. */
constexpr uint64_t TEST_TARGET_EPOCH = 2u;
/** Exact mutation sequence used by completion requests. */
constexpr uint64_t TEST_MUTATION_SEQUENCE = 2u;
/** Fixture UDP ingress endpoint. */
constexpr uint16_t TEST_RX_PORT = 43101u;
/** Fixture UDP egress endpoint. */
constexpr uint16_t TEST_TX_PORT = 43102u;

/**
 * @param now Exact steady-clock sample to encode.
 * @return Monotonic nanoseconds, or zero for a nonpositive sample.
 */
[[nodiscard]] uint64_t monotonic_ns(std::chrono::steady_clock::time_point now) noexcept
{
	const auto count = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
	return count > 0 ? static_cast<uint64_t>(count) : 0u;
}

/** @brief Module-free PREPARED bookkeeping used through the production interface. */
class module_free_prepared_completion final : public epoch_transition_prepared_completion {
    public:
	/**
	 * @brief Bind one exact PREPARED identity.
	 * @param identity Transaction identity retained until commit release or abort.
	 */
	void prepare(const common::epoch_transition_identity &identity) noexcept
	{
		if (prepared_) {
			std::terminate();
		}
		identity_ = identity;
		prepared_ = true;
	}

	/**
	 * @brief Release one exact test PREPARED identity after simulated cleanup.
	 * @param identity Exact retained transaction being aborted; mismatch terminates.
	 */
	void abort(const common::epoch_transition_identity &identity) noexcept
	{
		if (!completion_prepared(identity)) {
			std::terminate();
		}
		identity_ = {};
		prepared_ = false;
	}

	/** @copydoc kinetum::dp::epoch_transition_prepared_completion::completion_prepared */
	[[nodiscard]] bool
	completion_prepared(const common::epoch_transition_identity &identity) const noexcept override
	{
		return prepared_ && identity_ == identity;
	}

	/** @copydoc kinetum::dp::epoch_transition_prepared_completion::release_completion_preparation */
	void release_completion_preparation(const common::epoch_transition_identity &identity) noexcept override
	{
		if (!completion_prepared(identity)) {
			std::terminate();
		}
		identity_ = {};
		prepared_ = false;
	}

    private:
	common::epoch_transition_identity identity_{};	///< Exact prepared identity.
	bool prepared_{false};				///< Whether commit release is legal.
};

/** @brief Module-free aggregate activation and retirement production shape. */
class module_free_completion final : public epoch_transition_module_completion {
    public:
	/**
	 * @brief Bind the exact Bootstrap aggregate.
	 * @param epoch Initial nonzero epoch; rebinding an existing aggregate terminates.
	 */
	void bind_bootstrap(uint64_t epoch) noexcept
	{
		if (published_epoch_ != 0u || epoch == 0u) {
			std::terminate();
		}
		published_epoch_ = epoch;
		participant_active_epoch_ = epoch;
	}

	/**
	 * @brief Stage the exact live target before completion arming.
	 * @param from_epoch Exact currently published epoch.
	 * @param to_epoch Strictly newer target with no existing prepared owner.
	 */
	void prepare(uint64_t from_epoch, uint64_t to_epoch) noexcept
	{
		if (published_epoch_ != from_epoch || prepared_epoch_ != 0u || to_epoch <= from_epoch) {
			std::terminate();
		}
		prepared_epoch_ = to_epoch;
	}

	/**
	 * @brief Record that the sole worker completed local activation.
	 * @param from_epoch Exact published epoch before aggregate completion.
	 * @param to_epoch Exact prepared target now active on the worker.
	 */
	void activate(uint64_t from_epoch, uint64_t to_epoch) noexcept
	{
		if (published_epoch_ != from_epoch || prepared_epoch_ != to_epoch) {
			std::terminate();
		}
		participant_active_epoch_ = to_epoch;
	}

	/**
	 * @brief Discard one exact module-free target before commit.
	 * @param from_epoch Epoch still published and active on the worker.
	 * @param to_epoch Exact prepared target to discard.
	 */
	void abort(uint64_t from_epoch, uint64_t to_epoch) noexcept
	{
		if (published_epoch_ != from_epoch || prepared_epoch_ != to_epoch ||
		    participant_active_epoch_ != from_epoch) {
			std::terminate();
		}
		prepared_epoch_ = 0u;
	}

	[[nodiscard]] std::size_t completion_context_count() const noexcept override
	{
		return 0u;
	}
	[[nodiscard]] std::size_t completion_image_count() const noexcept override
	{
		return 0u;
	}
	[[nodiscard]] std::size_t completion_executor_count() const noexcept override
	{
		return 1u;
	}
	[[nodiscard]] uint32_t completion_context_index([[maybe_unused]] std::size_t ordinal) const noexcept override
	{
		return UINT32_MAX;
	}
	[[nodiscard]] uint32_t completion_image_index([[maybe_unused]] std::size_t ordinal) const noexcept override
	{
		return UINT32_MAX;
	}
	[[nodiscard]] std::size_t
	completion_executor_index([[maybe_unused]] std::size_t ordinal) const noexcept override
	{
		return 1u;
	}
	[[nodiscard]] uint64_t next_completion_task_sequence() noexcept override
	{
		std::terminate();
	}
	[[nodiscard]] common::status preflight_future_completion(uint64_t from_epoch,
								 uint64_t to_epoch) const noexcept override
	{
		return published_epoch_ == from_epoch && prepared_epoch_ == to_epoch ?
			       common::status::ok() :
			       common::status::failed_precondition("module-free future shape mismatch");
	}
	[[nodiscard]] common::status preflight_completion_activation(uint64_t from_epoch,
								     uint64_t to_epoch) const noexcept override
	{
		return published_epoch_ == from_epoch && prepared_epoch_ == to_epoch &&
				       participant_active_epoch_ == to_epoch ?
			       common::status::ok() :
			       common::status::failed_precondition("module-free activation mismatch");
	}
	void publish_completion_activation(uint64_t from_epoch, uint64_t to_epoch) noexcept override
	{
		if (!preflight_completion_activation(from_epoch, to_epoch).is_ok()) {
			std::terminate();
		}
		published_epoch_ = to_epoch;
		prepared_epoch_ = 0u;
	}
	[[nodiscard]] common::status
	preflight_completion_retained([[maybe_unused]] std::size_t ordinal,
				      [[maybe_unused]] uint64_t epoch) const noexcept override
	{
		return common::status::invalid_argument("module-free completion has no retained context");
	}
	[[nodiscard]] common::status_or<module::module_retirement_claim>
	claim_completion_retained([[maybe_unused]] std::size_t ordinal,
				  [[maybe_unused]] uint64_t epoch) noexcept override
	{
		return common::status::invalid_argument("module-free completion has no retained claim");
	}
	[[nodiscard]] common::status
	submit_completion_retire([[maybe_unused]] epoch_transition_retire_submission submission,
				 [[maybe_unused]] lifecycle::lifecycle_operation_control &control,
				 [[maybe_unused]] const module::module_retirement_claim &claim) noexcept override
	{
		return common::status::invalid_argument("module-free completion cannot submit RETIRE");
	}
	[[nodiscard]] std::optional<lifecycle::config_lifecycle_result> try_take_completion_result() noexcept override
	{
		return std::nullopt;
	}
	void complete_completion_retirement([[maybe_unused]] std::size_t ordinal,
					    [[maybe_unused]] module::module_retirement_claim &claim) noexcept override
	{
		std::terminate();
	}
	[[nodiscard]] bool completion_retirement_complete(uint64_t active_epoch) const noexcept override
	{
		return published_epoch_ == active_epoch && prepared_epoch_ == 0u &&
		       participant_active_epoch_ == active_epoch;
	}

    private:
	uint64_t published_epoch_{0};		///< Exact aggregate publication.
	uint64_t prepared_epoch_{0};		///< Exact staged target.
	uint64_t participant_active_epoch_{0};	///< Exact completed worker activation.
};

/** @brief Thread backend with an optional pre-entry gate for deadline evidence. */
class completion_executor_backend final : public lifecycle::runtime_service_backend {
    public:
	/** @param hold_entry Whether the executor must wait for explicit release. */
	explicit completion_executor_backend(bool hold_entry) noexcept
		: entry_released_(!hold_entry)
	{
	}

	/**
	 * @param service Unused compiled coordinator row supplied by the launcher.
	 * @return OK without changing the test thread's placement.
	 */
	[[nodiscard]] common::status
	bind_coordinator([[maybe_unused]] const common::compiled_runtime_service &service) noexcept override
	{
		return common::status::ok();
	}

	/** @copydoc kinetum::dp::lifecycle::runtime_service_backend::launch_executor */
	[[nodiscard]] common::status launch_executor(const common::compiled_runtime_service &service,
						     lifecycle::runtime_service_entry_fn entry,
						     void *argument) noexcept override
	{
		if (thread_.has_value()) {
			return common::status::failed_precondition(
				"completion test executor already owns one service thread");
		}
		try {
			thread_.emplace([this, entry, argument]() {
				while (!entry_released_.load(std::memory_order_acquire)) {
					std::this_thread::yield();
				}
				(void)entry(argument);
			});
			service_index_ = service.service_index;
		} catch (const std::exception &) {
			return common::status::resource_exhausted("completion test executor launch failed");
		}
		return common::status::ok();
	}

	/** @copydoc kinetum::dp::lifecycle::runtime_service_backend::join_executor */
	[[nodiscard]] common::status join_executor(const common::compiled_runtime_service &service) noexcept override
	{
		if (!thread_.has_value() || service_index_ != service.service_index) {
			return common::status(common::status_code::NOT_FOUND,
					      "completion test executor service was not launched");
		}
		thread_->join();
		thread_.reset();
		service_index_ = UINT32_MAX;
		return common::status::ok();
	}

	/** @brief Release a held executor entry exactly once or idempotently. */
	void release_entry() noexcept
	{
		entry_released_.store(true, std::memory_order_release);
	}

	/** @brief Release and join any thread left by an early test assertion. */
	~completion_executor_backend() override
	{
		release_entry();
		if (thread_.has_value() && thread_->joinable()) {
			thread_->join();
		}
	}

    private:
	std::atomic<bool> entry_released_{false};  ///< Optional pre-entry gate.
	std::optional<std::thread> thread_;	   ///< Sole launched executor thread.
	uint32_t service_index_{UINT32_MAX};	   ///< Exact launched service identity.
};

/** @brief Shutdown sink that refuses residual prepared ownership. */
class completion_result_consumer final : public lifecycle::config_lifecycle_result_consumer {
    public:
	/** @copydoc kinetum::dp::lifecycle::config_lifecycle_result_consumer::consume */
	void consume(lifecycle::config_lifecycle_result &&result) noexcept override
	{
		++count;
		if (result.has_prepared_ownership()) {
			std::terminate();
		}
	}

	std::size_t count{0};  ///< Residual results observed during exact shutdown.
};

/** @brief Observation-only completion seam for component-owned worker telemetry. */
class completion_telemetry_probe final : public epoch_transition_telemetry_completion {
    public:
	/** @copydoc kinetum::dp::epoch_transition_telemetry_completion::worker_epoch_aggregated */
	[[nodiscard]] bool worker_epoch_aggregated(uint64_t epoch) const noexcept override
	{
		return owner != nullptr && owner->telemetry->epoch_aggregated(epoch);
	}

	/** @copydoc kinetum::dp::epoch_transition_telemetry_completion::module_epoch_aggregated */
	[[nodiscard]] bool module_epoch_aggregated(uint64_t epoch) const noexcept override
	{
		return epoch != 0u && (!modules_present || module_epoch == epoch);
	}

	/** @copydoc kinetum::dp::epoch_transition_telemetry_completion::complete_module_epoch_retirement */
	void complete_module_epoch_retirement(uint64_t epoch, uint64_t active_epoch) noexcept override
	{
		if (modules_present && module_epoch != epoch) {
			std::terminate();
		}
		if (modules_present) {
			if (module_transfer_state == nullptr || consume_module_transfer == nullptr ||
			    active_epoch == 0u) {
				std::terminate();
			}
			consume_module_transfer(module_transfer_state, active_epoch);
		}
		module_epoch = 0u;
	}

	/** @copydoc kinetum::dp::epoch_transition_telemetry_completion::retire_worker_epoch */
	void retire_worker_epoch(uint64_t epoch, uint64_t active_epoch) noexcept override
	{
		if (owner == nullptr || !owner->telemetry->epoch_aggregated(epoch) || active_epoch == 0u) {
			std::terminate();
		}
		const auto transfer = owner->telemetry->retire_epoch(epoch, active_epoch);
		if (!transfer.has_value() || transfer->kind != runtime_telemetry_bank_token_kind::BANK) {
			std::terminate();
		}
		runtime_telemetry_bank_token token{};
		while (owner->channel->take_returned(token)) {
			owner->telemetry->accept_returned(token);
		}
	}

	test::worker_telemetry_test_owner *owner{nullptr};  ///< Exact production-shaped worker banks.
	uint64_t module_epoch{0};			    ///< Exact aggregated module epoch when present.
	bool modules_present{false};			    ///< Whether the fixture owns a module context.
	void *module_transfer_state{nullptr};		    ///< Exact test module completion owner.
	/** Reconcile one reclaimed target-bank transfer through the retained module completion owner. */
	void (*consume_module_transfer)(void *, uint64_t) noexcept {nullptr};
};

/** @brief Optional exact-result corruption injected behind the production interface. */
enum class completion_result_identity_fault : uint8_t {
	NONE = 0,	///< Executor echoes the exact submitted task identity.
	TASK_SEQUENCE,	///< Executor receives a different nonzero task sequence.
};

/** @brief One real module store plus one real lifecycle executor for reclamation tests. */
class claimed_module_completion final : public epoch_transition_module_completion {
    public:
	/**
	 * @brief Construct and launch one empty exact module completion authority.
	 *
	 * @param context Exact compiled module-context identity.
	 * @param hold_executor_entry Whether accepted RETIRE work remains unconsumed.
	 * @return Complete owner or exact module/executor admission failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<claimed_module_completion>>
	create(const provider::compiled_module_context &context, bool hold_executor_entry)
	{
		if constexpr (sizeof(std::size_t) < sizeof(uint64_t)) {
			if (context.context_memory_capacity_bytes >
				    static_cast<uint64_t>(std::numeric_limits<std::size_t>::max()) ||
			    context.epoch_arena_capacity_bytes >
				    static_cast<uint64_t>(std::numeric_limits<std::size_t>::max())) {
				return common::status(common::status_code::OUT_OF_RANGE,
						      "completion test module capacities exceed host size_t");
			}
		}
		test::module_test_resource_contract resources{
			.context_memory_capacity_bytes =
				static_cast<std::size_t>(context.context_memory_capacity_bytes),
			.epoch_arena_capacity_bytes = static_cast<std::size_t>(context.epoch_arena_capacity_bytes),
		};
		auto module_or = test::exact_module_test_context::create(
			context.module_id, std::filesystem::path(KINETUM_TEST_MODULE_PATH), resources,
			context.context_instance_id, context.module_context_index, context.stage_instance_index);
		if (!module_or.is_ok()) {
			return module_or.error();
		}
		auto module = std::move(module_or).value();
		auto adapter_or = module->make_lifecycle_adapter();
		if (!adapter_or.is_ok()) {
			return adapter_or.error();
		}
		std::unique_ptr<claimed_module_completion> owner;
		try {
			owner.reset(new claimed_module_completion(std::move(module), std::move(adapter_or).value(),
								  hold_executor_entry));
		} catch (const std::bad_alloc &) {
			return common::status::resource_exhausted("completion test module owner allocation failed");
		}
		const auto launched = owner->launch_();
		if (!launched.is_ok()) {
			return launched;
		}
		return owner;
	}

	/** @brief Stop the executor and retire the final active module generation. */
	~claimed_module_completion() override
	{
		shutdown();
	}

	/** @return OK after exact module Bootstrap preparation and activation. */
	[[nodiscard]] common::status bootstrap()
	{
		if (published_epoch_ != 0u || prepared_epoch_ != 0u || module_->active_epoch() != 0u) {
			return common::status::failed_precondition("completion test module Bootstrap is already owned");
		}
		const auto activated = module_->prepare_and_activate(TEST_BOOTSTRAP_EPOCH, "{}");
		if (activated.is_ok()) {
			published_epoch_ = TEST_BOOTSTRAP_EPOCH;
		}
		return activated;
	}

	/**
	 * @brief Stage the exact target module artifact without owner activation.
	 * @return PREPARE result for the target, or FAILED_PRECONDITION when another epoch already owns preparation.
	 */
	[[nodiscard]] common::status prepare_target()
	{
		if (published_epoch_ != TEST_BOOTSTRAP_EPOCH || prepared_epoch_ != 0u) {
			return common::status::failed_precondition("completion test module cannot stage this target");
		}
		const auto prepared = module_->prepare(TEST_TARGET_EPOCH, R"({"drop":true})");
		if (prepared.is_ok()) {
			prepared_epoch_ = TEST_TARGET_EPOCH;
		}
		return prepared;
	}

	/**
	 * @brief Retire one exact staged target before commit.
	 * @return OK after target retirement or when no target is staged; otherwise the retirement failure.
	 */
	[[nodiscard]] common::status abort_target() noexcept
	{
		if (prepared_epoch_ == 0u) {
			return common::status::ok();
		}
		const uint64_t epoch = prepared_epoch_;
		const auto retired = module_->retire_prepared(epoch);
		if (retired.is_ok()) {
			prepared_epoch_ = 0u;
		}
		return retired;
	}

	/** @return Stable production store consumed by worker activation. */
	[[nodiscard]] module::module_epoch_store &store() noexcept
	{
		return *module_->context().epoch_store;
	}

	/** @return Exact admitted context consumed by owner-worker health binding. */
	[[nodiscard]] module::module_context_instance &context() noexcept
	{
		return module_->context();
	}

	/** @return Exact lifecycle owner used to inject one overlapping callback claim. */
	[[nodiscard]] lifecycle::lifecycle_context_owner &lifecycle_owner() noexcept
	{
		return *module_->context().lifecycle_owner;
	}

	/** @brief Drain every completed module telemetry bank after owner activation. */
	void drain_telemetry() noexcept
	{
		module_->drain_telemetry_for_test();
	}

	/**
	 * @param epoch Exact old module epoch to inspect.
	 * @return true only when its telemetry banks are aggregated.
	 */
	[[nodiscard]] bool telemetry_epoch_aggregated(uint64_t epoch) const noexcept
	{
		return module_->telemetry_epoch_aggregated(epoch);
	}

	/**
	 * @brief Consume one exact reclaimed target-bank handoff after old retirement.
	 * @param active_epoch Target epoch receiving the reclaimed telemetry bank.
	 */
	void consume_reclaimed_telemetry_transfer(uint64_t active_epoch) noexcept
	{
		module_->consume_reclaimed_telemetry_transfer(active_epoch);
	}

	/**
	 * @brief Select exact-result identity behavior before RETIRE dispatch.
	 * @param fault Identity corruption to inject into the next executor result.
	 */
	void set_result_identity_fault(completion_result_identity_fault fault) noexcept
	{
		result_identity_fault_ = fault;
	}

	/** @brief Release a test-held executor so accepted work can complete. */
	void release_executor() noexcept
	{
		backend_.release_entry();
	}

	/** @return Number of executor results published into owning result storage. */
	[[nodiscard]] uint64_t published_result_count() const noexcept
	{
		return executor_.published_result_count();
	}

	/** @return Number of exact RETIRE tasks accepted by the executor. */
	[[nodiscard]] uint64_t accepted_task_count() const noexcept
	{
		return executor_.accepted_task_count();
	}

	/**
	 * @brief Inject one nonfatal safety fault after exact store retirement.
	 * @param faults Borrowed fault latch retained through the injected retirement event.
	 */
	void inject_protocol_fault_on_retirement(epoch_protocol_fault_latch &faults) noexcept
	{
		if (completion_faults_ != nullptr) {
			std::terminate();
		}
		completion_faults_ = &faults;
	}

	/** @brief Idempotently stop the executor while no completion task remains unresolved. */
	void shutdown() noexcept
	{
		if (shutdown_) {
			return;
		}
		backend_.release_entry();
		if (!launcher_.running()) {
			shutdown_ = true;
			return;
		}
		completion_result_consumer consumer;
		if (!launcher_.stop_and_join(consumer).is_ok() || consumer.count != 0u) {
			std::terminate();
		}
		shutdown_ = true;
	}

	/** @brief Retire the sole active target after complete quiescence, then join services. */
	void retire_active_and_shutdown() noexcept
	{
		if (published_epoch_ != 0u) {
			if (module_->active_epoch() != published_epoch_ || !module_->retire().is_ok()) {
				std::terminate();
			}
			published_epoch_ = 0u;
		}
		shutdown();
	}

	[[nodiscard]] std::size_t completion_context_count() const noexcept override
	{
		return 1u;
	}
	[[nodiscard]] std::size_t completion_image_count() const noexcept override
	{
		return 1u;
	}
	[[nodiscard]] std::size_t completion_executor_count() const noexcept override
	{
		return 1u;
	}
	[[nodiscard]] uint32_t completion_context_index(std::size_t ordinal) const noexcept override
	{
		return ordinal == 0u ? module_->context().context_index : UINT32_MAX;
	}
	[[nodiscard]] uint32_t completion_image_index(std::size_t ordinal) const noexcept override
	{
		return ordinal == 0u ? module_->context().image->module_image_index : UINT32_MAX;
	}
	[[nodiscard]] std::size_t completion_executor_index(std::size_t ordinal) const noexcept override
	{
		return ordinal == 0u ? 0u : 1u;
	}
	[[nodiscard]] uint64_t next_completion_task_sequence() noexcept override
	{
		if (next_task_sequence_ == 0u || next_task_sequence_ == std::numeric_limits<uint64_t>::max()) {
			std::terminate();
		}
		return next_task_sequence_++;
	}
	[[nodiscard]] common::status preflight_future_completion(uint64_t from_epoch,
								 uint64_t to_epoch) const noexcept override
	{
		if (published_epoch_ != from_epoch || prepared_epoch_ != to_epoch) {
			return common::status::failed_precondition(
				"completion test module future identity is incomplete");
		}
		return module_->context().epoch_store->preflight_future_retained(from_epoch, to_epoch);
	}
	[[nodiscard]] common::status preflight_completion_activation(uint64_t from_epoch,
								     uint64_t to_epoch) const noexcept override
	{
		if (published_epoch_ != from_epoch || prepared_epoch_ != to_epoch ||
		    module_->context().epoch_store->active_epoch() != to_epoch) {
			return common::status::failed_precondition(
				"completion test module activation identity is incomplete");
		}
		return module_->context().epoch_store->preflight_claim_retained(from_epoch);
	}
	void publish_completion_activation(uint64_t from_epoch, uint64_t to_epoch) noexcept override
	{
		if (!preflight_completion_activation(from_epoch, to_epoch).is_ok()) {
			std::terminate();
		}
		published_epoch_ = to_epoch;
		prepared_epoch_ = 0u;
	}
	[[nodiscard]] common::status preflight_completion_retained(std::size_t ordinal,
								   uint64_t epoch) const noexcept override
	{
		if (ordinal != 0u || published_epoch_ <= epoch || prepared_epoch_ != 0u) {
			return common::status::failed_precondition(
				"completion test module retained identity is incomplete");
		}
		return module_->context().epoch_store->preflight_claim_retained(epoch);
	}
	[[nodiscard]] common::status_or<module::module_retirement_claim>
	claim_completion_retained(std::size_t ordinal, uint64_t epoch) noexcept override
	{
		const auto preflight = preflight_completion_retained(ordinal, epoch);
		if (!preflight.is_ok()) {
			return preflight;
		}
		return module_->context().epoch_store->claim_retained(epoch);
	}
	[[nodiscard]] common::status
	submit_completion_retire(epoch_transition_retire_submission submission,
				 lifecycle::lifecycle_operation_control &control,
				 const module::module_retirement_claim &claim) noexcept override
	{
		if (submission.context_ordinal != 0u || submission.task_sequence == 0u || submission.padding != 0u ||
		    claim.ownership().module_image_index() != 0u ||
		    claim.ownership().context_index() != module_->context().context_index) {
			return common::status::failed_precondition(
				"completion test module RETIRE identity is incomplete");
		}
		uint64_t submitted_sequence = submission.task_sequence;
		if (result_identity_fault_ == completion_result_identity_fault::TASK_SEQUENCE) {
			if (submitted_sequence == std::numeric_limits<uint64_t>::max()) {
				std::terminate();
			}
			++submitted_sequence;
		}
		auto task_or = lifecycle::config_lifecycle_task::create_claimed_retire(
			submitted_sequence, *module_->context().lifecycle_owner, *adapter_, control, claim.ownership(),
			claim.claim_id());
		if (!task_or.is_ok()) {
			return task_or.error();
		}
		return executor_.submit(std::move(task_or).value());
	}
	[[nodiscard]] std::optional<lifecycle::config_lifecycle_result> try_take_completion_result() noexcept override
	{
		return executor_.try_take_result();
	}
	void complete_completion_retirement(std::size_t ordinal,
					    module::module_retirement_claim &claim) noexcept override
	{
		if (ordinal != 0u || !claim.consume_after_retire().is_ok() ||
		    !module_->context().epoch_store->complete_retirement(claim).is_ok()) {
			std::terminate();
		}
		if (completion_faults_ != nullptr) {
			auto *faults = completion_faults_;
			completion_faults_ = nullptr;
			if (!faults->record(epoch_protocol_first_fault{
				    .runtime_generation = TEST_RUNTIME_GENERATION,
				    .transition_generation = TEST_MUTATION_SEQUENCE,
				    .from_epoch = TEST_BOOTSTRAP_EPOCH,
				    .to_epoch = TEST_TARGET_EPOCH,
				    .observed_epoch = TEST_BOOTSTRAP_EPOCH,
				    .expected_value = TEST_TARGET_EPOCH,
				    .observed_value = TEST_BOOTSTRAP_EPOCH,
				    .observed_monotonic_ns = monotonic_ns(std::chrono::steady_clock::now()),
				    .worker_index = 0u,
				    .boundary_index = UINT32_MAX,
				    .context_index = UINT32_MAX,
				    .stage_instance_index = UINT32_MAX,
				    .code = epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH,
				    .disposition = epoch_protocol_fault_disposition::DROP_AND_RETIRE,
				    .padding = {},
			    })) {
				std::terminate();
			}
		}
		// The dedicated telemetry-completion seam remains the sole consumer
		// of the reclaimed-bank handoff produced by store completion.
	}
	[[nodiscard]] bool completion_retirement_complete(uint64_t active_epoch) const noexcept override
	{
		if (published_epoch_ != active_epoch || prepared_epoch_ != 0u ||
		    module_->context().epoch_store->active_epoch() != active_epoch) {
			return false;
		}
		std::size_t published_count = 0u;
		for (std::size_t index = 0u; index < EXACT_EPOCH_SLOT_COUNT; ++index) {
			const auto *slot = module_->context().epoch_store->slot(index);
			if (slot == nullptr ||
			    (slot->state != epoch_slot_state::EMPTY && slot->state != epoch_slot_state::PUBLISHED)) {
				return false;
			}
			published_count += slot->state == epoch_slot_state::PUBLISHED ? 1u : 0u;
		}
		return published_count == 1u;
	}

    private:
	/**
	 * @brief Adopt one exact module/context and its production lifecycle adapter.
	 * @param module Sole admitted module/context owner transferred into the fixture.
	 * @param adapter Lifecycle adapter borrowing that module/context.
	 * @param hold_executor_entry Whether accepted executor work waits for explicit test release.
	 */
	claimed_module_completion(std::unique_ptr<test::exact_module_test_context> module,
				  std::unique_ptr<module::module_lifecycle_adapter> adapter,
				  bool hold_executor_entry) noexcept
		: module_(std::move(module))
		, adapter_(std::move(adapter))
		, executor_(1u, 0)
		, backend_(hold_executor_entry)
	{
	}

	/** @return OK after one exact coordinator/executor launch. */
	[[nodiscard]] common::status launch_()
	{
		const std::vector<common::compiled_runtime_service> services{
			common::compiled_runtime_service{
				std::string(common::runtime_services::EPOCH_TRANSITION_COORDINATOR_ID), 0u,
				common::compiled_runtime_service_role::EPOCH_TRANSITION_COORDINATOR, 0, 0,
				common::MAX_COORDINATOR_COMMAND_MAILBOX_CAPACITY},
			common::compiled_runtime_service{
				common::runtime_services::make_lifecycle_executor_id(0), 1u,
				common::compiled_runtime_service_role::CONFIG_LIFECYCLE_EXECUTOR, 1, 0, 0u},
		};
		const common::compiled_lifecycle_service_topology topology{0u, {1u}};
		const std::vector<lifecycle::config_lifecycle_executor *> executors{&executor_};
		return launcher_.launch(topology, services, executors, backend_);
	}

	std::unique_ptr<test::exact_module_test_context> module_;    ///< Real image/context/store owner.
	std::unique_ptr<module::module_lifecycle_adapter> adapter_;  ///< Real RETIRE callback adapter.
	lifecycle::config_lifecycle_executor executor_;		     ///< Bounded owning task/result transport.
	completion_executor_backend backend_;			     ///< Deterministic executor thread owner.
	lifecycle::runtime_service_launcher launcher_;		     ///< Exact all-or-none service owner.
	uint64_t published_epoch_{0};				     ///< Aggregate module publication.
	uint64_t prepared_epoch_{0};				     ///< Aggregate module PREPARED target.
	uint64_t next_task_sequence_{1};			     ///< Never-reused task identity.
	completion_result_identity_fault result_identity_fault_{
		completion_result_identity_fault::NONE};	  ///< Optional exact-identity fault.
	epoch_protocol_fault_latch *completion_faults_{nullptr};  ///< Optional post-retirement race injection.
	bool shutdown_{false};					  ///< Whether service ownership is joined.
};

/** @brief Module ownership shape selected by one completion fixture. */
enum class completion_module_shape : uint8_t {
	MODULE_FREE = 0,       ///< No compiled or runtime module context exists.
	EXACT_MODULE,	       ///< One compiled context owns a real module store/executor.
	MISMATCHED_AUTHORITY,  ///< Exact graph is paired with a module-free completion authority.
};

/** @brief Complete module-free or exact-module production-shaped completion fixture. */
class completion_fixture final {
    public:
	/**
	 * @brief Construct every exact owner through its production factory.
	 * @param commit_timeout Exact compiled completion-only timeout.
	 * @param retirement_timeout Exact compiled update-freeze timeout.
	 * @param module_shape Module ownership shape under test.
	 * @param hold_executor_entry Whether claimed RETIRE execution remains held.
	 * @param status_runtime_generation Runtime identity bound by status publication.
	 * @return Complete fixture or exact construction/admission failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<completion_fixture>>
	create(std::chrono::milliseconds commit_timeout = std::chrono::seconds(5),
	       std::chrono::milliseconds retirement_timeout = std::chrono::seconds(5),
	       completion_module_shape module_shape = completion_module_shape::MODULE_FREE,
	       bool hold_executor_entry = false, uint64_t status_runtime_generation = TEST_RUNTIME_GENERATION)
	{
		std::unique_ptr<completion_fixture> fixture;
		try {
			fixture.reset(new completion_fixture());
		} catch (const std::bad_alloc &) {
			return common::status::resource_exhausted("completion fixture allocation failed");
		}
		const runtime_fixture::host_selection selection{.numa_node = 0, .cpu_cores = {0, 1, 2}};
		const bool with_module = module_shape != completion_module_shape::MODULE_FREE;
		const std::optional<std::string> module_id = with_module ? std::optional<std::string>{"test_module"} :
									   std::nullopt;
		constexpr uint64_t MODULE_CONTEXT_CAPACITY = UINT64_C(65536);
		constexpr uint64_t MODULE_EPOCH_CAPACITY = UINT64_C(65536);
		if (commit_timeout <= std::chrono::milliseconds::zero() || retirement_timeout < commit_timeout) {
			return common::status::invalid_argument("completion fixture transition timing is inconsistent");
		}
		const auto commit_ms = static_cast<uint64_t>(commit_timeout.count());
		const auto retirement_ms = static_cast<uint64_t>(retirement_timeout.count());
		const packet_runtime_test_transition_timing timing{
			.prepare_timeout_ms = commit_ms,
			.prepare_cancel_grace_ms = commit_ms,
			.prepared_lease_timeout_ms = commit_ms,
			.commit_timeout_ms = commit_ms,
			.retirement_timeout_ms = retirement_ms,
		};
		auto compiled_or = runtime_fixture::compile_runtime_fixture(
			runtime_fixture::make_pipeline(module_id), selection, TEST_RX_PORT, TEST_TX_PORT,
			with_module ? MODULE_CONTEXT_CAPACITY : 0u, with_module ? MODULE_EPOCH_CAPACITY : 0u, timing);
		if (!compiled_or.is_ok()) {
			return compiled_or.error();
		}
		fixture->compiled_ = std::move(compiled_or).value();
		const auto &compiled_policy = fixture->compiled_.topology.transition_topology.policy;
		if (!compiled_policy.enabled || compiled_policy.commit_timeout != commit_timeout ||
		    compiled_policy.retirement_timeout != retirement_timeout) {
			return common::status::internal_error(
				"completion fixture plan/compiler transition timing is not exact");
		}
		if (fixture->compiled_.topology.transition_topology.workers.size() != 1u ||
		    !fixture->compiled_.topology.transition_topology.boundaries.empty() ||
		    fixture->compiled_.topology.worker_schedules.size() != 1u) {
			return common::status::failed_precondition(
				"completion fixture requires one exact zero-boundary worker graph");
		}
		fixture->module_completion_ = &fixture->module_free_completion_;
		fixture->telemetry_probe_.modules_present = with_module;
		if (with_module) {
			if (fixture->compiled_.topology.module_contexts.size() != 1u) {
				return common::status::failed_precondition(
					"completion fixture requires one exact compiled module context");
			}
			auto modules_or = claimed_module_completion::create(
				fixture->compiled_.topology.module_contexts.front(), hold_executor_entry);
			if (!modules_or.is_ok()) {
				return modules_or.error();
			}
			fixture->claimed_modules_ = std::move(modules_or).value();
			fixture->telemetry_probe_.module_transfer_state = fixture->claimed_modules_.get();
			fixture->telemetry_probe_.consume_module_transfer = [](void *state,
									       uint64_t active_epoch) noexcept {
				if (state == nullptr) {
					std::terminate();
				}
				static_cast<claimed_module_completion *>(state)->consume_reclaimed_telemetry_transfer(
					active_epoch);
			};
			if (module_shape == completion_module_shape::EXACT_MODULE) {
				fixture->module_completion_ = fixture->claimed_modules_.get();
			}
		}

		auto coordinator_or = epoch_transition_coordinator::create(fixture->compiled_.topology);
		if (!coordinator_or.is_ok()) {
			return coordinator_or.error();
		}
		fixture->coordinator_ = std::move(coordinator_or).value();
		auto fault_binding =
			fixture->coordinator_->bind_protocol_faults(TEST_RUNTIME_GENERATION, fixture->protocol_faults_);
		if (!fault_binding.is_ok()) {
			return fault_binding;
		}
		const std::optional<std::pair<std::string, std::string>> bootstrap_module =
			with_module ? std::optional<std::pair<std::string, std::string>>{{"test_module", "{}"}} :
				      std::nullopt;
		auto bootstrap_or = runtime_fixture::make_bootstrap_request(fixture->compiled_.plan, bootstrap_module);
		if (!bootstrap_or.is_ok()) {
			return bootstrap_or.error();
		}
		fixture->bootstrap_request_ = std::move(bootstrap_or).value();
		auto bootstrap_canonical_or = common::canonicalize_config_snapshot(
			fixture->bootstrap_request_.snapshot(), fixture->compiled_.plan);
		if (!bootstrap_canonical_or.is_ok()) {
			return bootstrap_canonical_or.error();
		}
		auto bootstrap_artifact_or = config_snapshot_artifact::create(bootstrap_canonical_or.value());
		if (!bootstrap_artifact_or.is_ok()) {
			return bootstrap_artifact_or.error();
		}
		auto bootstrap_artifact = std::move(bootstrap_artifact_or).value();
		const common::epoch_transition_watermarks bootstrap_watermarks{TEST_BOOTSTRAP_EPOCH,
									       TEST_BOOTSTRAP_EPOCH};

		auto ledger_or = worker_epoch_ledger::create(0u, TEST_RUNTIME_GENERATION, 4096u);
		if (!ledger_or.is_ok()) {
			return ledger_or.error();
		}
		fixture->ledger_ = std::move(ledger_or).value();
		std::array<boundary_epoch_channel *, 0> channels{};
		std::array<boundary_future_output_hold *, 0> holds{};
		auto sender_or = worker_boundary_sender::create(0u, TEST_RUNTIME_GENERATION, channels, holds);
		auto receiver_or = worker_boundary_receiver::create(0u, TEST_RUNTIME_GENERATION, channels);
		if (!sender_or.is_ok() || !receiver_or.is_ok()) {
			return common::status::internal_error(
				"completion fixture endpoint owners rejected empty membership");
		}
		fixture->sender_ = std::move(sender_or).value();
		fixture->receiver_ = std::move(receiver_or).value();
		if (!fixture->sender_->bind_ledger(*fixture->ledger_).is_ok() ||
		    !fixture->receiver_->bind_ledger(*fixture->ledger_).is_ok()) {
			return common::status::internal_error("completion fixture could not bind its exact ledger");
		}
		const auto &schedule = fixture->compiled_.topology.worker_schedules.front();
		const auto &worker = fixture->compiled_.topology.transition_topology.workers.front();
		for (std::size_t index = 0u; index < schedule.source_storage_domain_indices.size(); ++index) {
			const std::size_t capacity = static_cast<std::size_t>(worker.source_epoch_staging_capacity);
			auto staging_or = packet_epoch_input_staging::create(
				capacity, std::optional<std::size_t>{capacity}, worker.numa_node);
			if (!staging_or.is_ok()) {
				return staging_or.error();
			}
			fixture->staging_.push_back(staging_or->get());
			fixture->staging_owners_.push_back(std::move(staging_or).value());
		}
		std::vector<module::module_epoch_store *> module_stores;
		if (fixture->claimed_modules_ != nullptr) {
			module_stores.push_back(&fixture->claimed_modules_->store());
		}
		auto worker_telemetry_or = test::worker_telemetry_test_owner::create(0u, TEST_RUNTIME_GENERATION, {});
		if (!worker_telemetry_or.is_ok()) {
			return worker_telemetry_or.error();
		}
		fixture->worker_telemetry_ = std::move(worker_telemetry_or).value();
		fixture->telemetry_probe_.owner = fixture->worker_telemetry_.get();
		if (fixture->claimed_modules_ != nullptr) {
			const auto &compiled_context = fixture->compiled_.topology.module_contexts.front();
			auto &context = fixture->claimed_modules_->context();
			const auto budget =
				std::chrono::duration_cast<std::chrono::nanoseconds>(worker.health_callback_budget);
			if (budget.count() <= 0 || context.image == nullptr || context.image->descriptor == nullptr ||
			    context.lifecycle_owner == nullptr || context.epoch_store == nullptr) {
				return common::status::failed_precondition(
					"completion fixture module health authorities are incomplete");
			}
			const std::array<module::worker_module_health_binding, 1> health_bindings{{
				{
					.stage_instance_index = compiled_context.stage_instance_index,
					.context_index = compiled_context.module_context_index,
					.context = &context.packet_context,
					.store = context.epoch_store.get(),
					.descriptor = context.image->descriptor,
					.publication = context.lifecycle_owner.get(),
				},
			}};
			auto health_or = module::worker_module_health::create(0u, TEST_RUNTIME_GENERATION,
									      static_cast<uint64_t>(budget.count()),
									      health_bindings, *fixture->ledger_);
			if (!health_or.is_ok()) {
				return health_or.error();
			}
			fixture->module_health_ = std::move(health_or).value();
		}
		auto activation_or = worker_epoch_activation::create(0u, TEST_RUNTIME_GENERATION, module_stores,
								     fixture->staging_, *fixture->ledger_, nullptr,
								     fixture->module_health_.get(),
								     *fixture->worker_telemetry_->telemetry);
		if (!activation_or.is_ok()) {
			return activation_or.error();
		}
		fixture->activation_ = std::move(activation_or).value();

		std::array<kinetum::algo::quiescence_reader *, 1> readers{&fixture->reader_};
		fixture->domain_ = std::make_unique<kinetum::algo::quiescence_domain>(readers);
		const std::array<epoch_transition_certificate_worker_source, 1> sources{
			epoch_transition_certificate_worker_source{
				.ledger = fixture->ledger_.get(),
				.activation = fixture->activation_.get(),
				.sender = fixture->sender_.get(),
				.receiver = fixture->receiver_.get(),
				.reader = &fixture->reader_,
			},
		};
		auto certificate_or = epoch_transition_certificate::create(TEST_RUNTIME_GENERATION,
									   fixture->coordinator_->participants(),
									   sources, channels, *fixture->domain_);
		if (!certificate_or.is_ok()) {
			return certificate_or.error();
		}
		fixture->certificate_ = std::move(certificate_or).value();
		auto completion_or = epoch_transition_completion::create(
			TEST_RUNTIME_GENERATION, *fixture->coordinator_, *fixture->certificate_, *fixture->domain_,
			fixture->prepared_completion_, *fixture->module_completion_, fixture->runtime_status_,
			fixture->telemetry_probe_, fixture->protocol_faults_,
			fixture->compiled_.topology.transition_topology.policy);
		if (!completion_or.is_ok()) {
			return completion_or.error();
		}
		fixture->completion_ = std::move(completion_or).value();
		if (!fixture->runtime_status_.publish_control_ready(status_runtime_generation, 1u)) {
			return common::status::internal_error("completion fixture could not publish CONTROL_READY");
		}
		const auto bound = fixture->coordinator_->bind_bootstrap_request("completion-bootstrap",
										 fixture->compiled_.plan.content_hash(),
										 TEST_BOOTSTRAP_EPOCH,
										 bootstrap_watermarks);
		if (!bound.is_ok()) {
			return bound;
		}
		const auto staged =
			fixture->coordinator_->stage_bootstrap_snapshot(TEST_BOOTSTRAP_EPOCH, bootstrap_artifact);
		if (!staged.is_ok()) {
			return staged;
		}
		const auto snapshot_preflight =
			fixture->coordinator_->preflight_bootstrap_publication(TEST_BOOTSTRAP_EPOCH);
		if (!snapshot_preflight.is_ok()) {
			if (!fixture->coordinator_->abort_bootstrap(TEST_BOOTSTRAP_EPOCH).is_ok()) {
				std::terminate();
			}
			return snapshot_preflight;
		}
		if (fixture->claimed_modules_ != nullptr) {
			const auto module_bootstrap = fixture->claimed_modules_->bootstrap();
			if (!module_bootstrap.is_ok()) {
				if (!fixture->coordinator_->abort_bootstrap(TEST_BOOTSTRAP_EPOCH).is_ok()) {
					std::terminate();
				}
				return module_bootstrap;
			}
		} else {
			fixture->module_free_completion_.bind_bootstrap(TEST_BOOTSTRAP_EPOCH);
		}
		fixture->ledger_->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
		fixture->sender_->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
		fixture->receiver_->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
		fixture->worker_telemetry_->telemetry->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH, 1u);
		fixture->activation_->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH);
		fixture->ledger_->publish();
		fixture->coordinator_->publish_bootstrap_or_terminate(TEST_BOOTSTRAP_EPOCH);
		if (!fixture->runtime_status_.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, 1u)) {
			return common::status::internal_error("completion fixture could not publish PACKET_READY");
		}
		return fixture;
	}

	/** @brief Retire the final published snapshot before exact owner destruction. */
	~completion_fixture()
	{
		if (completion_ != nullptr && completion_->active()) {
			std::terminate();
		}
		completion_.reset();
		certificate_.reset();
		domain_.reset();
		activation_.reset();
		if (claimed_modules_ != nullptr) {
			claimed_modules_->retire_active_and_shutdown();
		}
		module_health_.reset();
		if (coordinator_ != nullptr && !coordinator_->snapshot_store_empty() &&
		    !coordinator_->retire_published_after_quiescence(coordinator_->active_epoch()).is_ok()) {
			std::terminate();
		}
	}

	/**
	 * @brief Admit and publish one exact PREPARED transaction.
	 * @return OK after exact PREPARED publication, or an admission/preparation failure with owned cleanup.
	 */
	[[nodiscard]] common::status prepare()
	{
		auto snapshot = fixture_snapshot_(TEST_TARGET_EPOCH);
		auto canonical_or = common::canonicalize_config_snapshot(snapshot, compiled_.plan);
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		auto artifact_or = config_snapshot_artifact::create(canonical_or.value());
		if (!artifact_or.is_ok()) {
			return artifact_or.error();
		}
		auto artifact = std::move(artifact_or).value();
		identity_ = {};
		identity_.mutation_sequence = TEST_MUTATION_SEQUENCE;
		identity_.target_epoch = TEST_TARGET_EPOCH;
		identity_.validation_hash = artifact->validation_hash();
		identity_.idempotency_key_digest.fill(UINT8_C(0x5a));
		const auto now = std::chrono::steady_clock::now();
		const uint64_t admitted_ns = monotonic_ns(now);
		if (!coordinator_->admit_prepare(identity_, artifact, admitted_ns).is_ok()) {
			return common::status::internal_error("completion fixture PREPARE admission failed");
		}
		const auto telemetry_reserved =
			worker_telemetry_->telemetry->reserve_target_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
		if (!telemetry_reserved.is_ok()) {
			return cleanup_prepare_failure_(telemetry_reserved, false);
		}
		const auto module_prepared = claimed_modules_ != nullptr ? claimed_modules_->prepare_target() :
									   common::status::ok();
		if (!module_prepared.is_ok()) {
			worker_telemetry_->telemetry->discard_target_epoch(TEST_TARGET_EPOCH);
			return cleanup_prepare_failure_(module_prepared, false);
		}
		if (claimed_modules_ == nullptr) {
			module_free_completion_.prepare(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
		}
		prepared_completion_.prepare(identity_);
		const auto armed = completion_->arm_before_prepared(identity_);
		if (!armed.is_ok()) {
			worker_telemetry_->telemetry->discard_target_epoch(TEST_TARGET_EPOCH);
			return cleanup_prepare_failure_(armed, true);
		}
		const uint64_t prepared_ns = monotonic_ns(std::chrono::steady_clock::now());
		const auto prepared = coordinator_->mark_prepared(identity_, prepared_ns,
								  prepared_ns + UINT64_C(5000000000), UINT64_C(5000));
		if (!prepared.is_ok()) {
			worker_telemetry_->telemetry->discard_target_epoch(TEST_TARGET_EPOCH);
			return cleanup_prepare_failure_(
				common::status(prepared.code, "completion fixture PREPARED publication failed"), true);
		}
		return common::status::ok();
	}

	/**
	 * @brief Start grace/COMMITTING and publish exact worker completion without reader publication.
	 * @return OK after worker completion publication, or the first commit/worker transition failure.
	 */
	[[nodiscard]] common::status activate_without_reader()
	{
		const auto now = std::chrono::steady_clock::now();
		const auto committed = completion_->begin_commit(identity_, now);
		if (!committed.is_ok()) {
			return committed;
		}
		last_service_time_ = now;
		ledger_->bind_future_epoch(TEST_TARGET_EPOCH);
		if (!sender_->begin_transition(TEST_MUTATION_SEQUENCE, TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH) ||
		    !receiver_->begin_transition(TEST_MUTATION_SEQUENCE, TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH)) {
			return common::status::internal_error(
				"completion fixture could not bind worker transition identity");
		}
		ledger_->advance_source_epoch(TEST_TARGET_EPOCH);
		if (!receiver_->activation_ready() || !sender_->try_seal_after_old_work_drained()) {
			return common::status::internal_error(
				"completion fixture could not prove zero-inbound activation");
		}
		const auto activated =
			activation_->activate(TEST_MUTATION_SEQUENCE, TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH, 1u);
		if (!activated.is_ok()) {
			return activated;
		}
		runtime_telemetry_bank_token telemetry_token{};
		while (worker_telemetry_->channel->take_completed(telemetry_token)) {
			if (!worker_telemetry_->telemetry->completed_bank(telemetry_token).is_ok()) {
				return common::status::internal_error(
					"completion fixture worker telemetry token was not exact");
			}
			worker_telemetry_->telemetry->complete_aggregation(telemetry_token);
		}
		worker_telemetry_->telemetry->mark_epoch_aggregated(TEST_BOOTSTRAP_EPOCH);
		if (claimed_modules_ != nullptr) {
			claimed_modules_->drain_telemetry();
			if (!claimed_modules_->telemetry_epoch_aggregated(TEST_BOOTSTRAP_EPOCH)) {
				return common::status::internal_error(
					"completion fixture module telemetry did not aggregate exactly");
			}
			telemetry_probe_.module_epoch = TEST_BOOTSTRAP_EPOCH;
		}
		if (claimed_modules_ == nullptr) {
			module_free_completion_.activate(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
		}
		receiver_->acknowledge_activation(TEST_MUTATION_SEQUENCE, TEST_TARGET_EPOCH);
		if (!receiver_->all_acks_published() || !sender_->all_gates_open() ||
		    !sender_->packet_ownership_empty()) {
			return common::status::internal_error(
				"completion fixture zero-boundary policies did not converge");
		}
		receiver_->complete_receiver_transition(TEST_MUTATION_SEQUENCE);
		sender_->complete_sender_transition(TEST_MUTATION_SEQUENCE);
		ledger_->publish();
		return common::status::ok();
	}

	/**
	 * @brief Service one completion probe at a nondecreasing test-clock sample.
	 * @param now Exact monotonic sample selected by the fixture driver.
	 * @return Completion progress status, or INVALID_ARGUMENT for clock regression.
	 */
	[[nodiscard]] common::status service_progress_at(std::chrono::steady_clock::time_point now) noexcept
	{
		if (now == std::chrono::steady_clock::time_point{} || now < last_service_time_) {
			return common::status::invalid_argument(
				"completion fixture progress sample regressed its monotonic clock");
		}
		last_service_time_ = now;
		return completion_->service_progress(now);
	}

	/**
	 * @brief Service available results without regressing past an injected probe.
	 * @return Completion result-service status at one exact monotonic sample.
	 */
	[[nodiscard]] common::status service_results_now() noexcept
	{
		const auto now = std::max(std::chrono::steady_clock::now(), last_service_time_);
		last_service_time_ = now;
		return completion_->service_results(now);
	}

	/**
	 * @brief Service available results at an explicit nondecreasing sample.
	 * @param now Exact monotonic sample selected by a deadline test.
	 * @return Completion result-service status, or INVALID_ARGUMENT for clock regression.
	 */
	[[nodiscard]] common::status service_results_at(std::chrono::steady_clock::time_point now) noexcept
	{
		if (now == std::chrono::steady_clock::time_point{} || now < last_service_time_) {
			return common::status::invalid_argument(
				"completion fixture result sample regressed its monotonic clock");
		}
		last_service_time_ = now;
		return completion_->service_results(now);
	}

	/** @brief Publish the exact active grace from the sole worker reader. */
	void publish_reader() noexcept
	{
		if (reader_.publish_quiescent() == 0u) {
			std::terminate();
		}
	}

	/** @brief Arm one nonfatal safety fault inside exact store-retirement service. */
	void inject_protocol_fault_on_retirement() noexcept
	{
		if (claimed_modules_ == nullptr) {
			std::terminate();
		}
		claimed_modules_->inject_protocol_fault_on_retirement(protocol_faults_);
	}

	/**
	 * @brief Complete one exact module-free precommit abort and disarm completion.
	 * @return OK after ABORTED publication and disarming, or an exact state/cleanup failure.
	 */
	[[nodiscard]] common::status abort_prepared()
	{
		if (claimed_modules_ != nullptr || !completion_->active() ||
		    coordinator_->phase() != epoch_transition_phase::PREPARED) {
			return common::status::failed_precondition(
				"completion fixture abort requires one module-free PREPARED identity");
		}
		const auto identity = identity_;
		const auto cleanup = coordinator_->begin_prepared_abort_cleanup(identity);
		if (!cleanup.is_ok()) {
			return cleanup;
		}
		prepared_completion_.abort(identity);
		module_free_completion_.abort(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
		worker_telemetry_->telemetry->discard_target_epoch(TEST_TARGET_EPOCH);
		const uint64_t terminal_ns = monotonic_ns(std::chrono::steady_clock::now());
		const auto terminal = coordinator_->abort_before_commit(identity, terminal_ns,
									epoch_transition_failure_code::EXPLICIT_ABORT,
									"completion fixture exact precommit abort");
		if (!terminal.is_ok() || terminal.observation.outcome != epoch_transition_outcome::ABORTED) {
			return common::status::internal_error(
				"completion fixture coordinator did not publish exact ABORTED");
		}
		completion_->disarm_after_abort(identity);
		return common::status::ok();
	}

	/** @return Borrowed production completion owner. */
	[[nodiscard]] epoch_transition_completion &completion() noexcept
	{
		return *completion_;
	}
	/** @return Borrowed production transition coordinator. */
	[[nodiscard]] epoch_transition_coordinator &coordinator() noexcept
	{
		return *coordinator_;
	}
	/** @return Borrowed runtime-status publication used by the fixture. */
	[[nodiscard]] runtime_status_publication &runtime_status() noexcept
	{
		return runtime_status_;
	}
	/** @return Borrowed exact identity of the fixture's current transition. */
	[[nodiscard]] const common::epoch_transition_identity &identity() const noexcept
	{
		return identity_;
	}
	/** @return Borrowed real-module completion owner, or nullptr for a module-free fixture. */
	[[nodiscard]] claimed_module_completion *claimed_modules() noexcept
	{
		return claimed_modules_.get();
	}

    private:
	/** @brief Construct one empty fixture before exact factories populate it. */
	completion_fixture() = default;

	/**
	 * @brief Restore exact IDLE after one fixture-only post-admission failure.
	 * @param failure Original operation status returned after cleanup.
	 * @param bookkeeping_prepared Whether module/preparation bookkeeping owns N.
	 * @return @p failure after every staged owner and completion arm are gone.
	 */
	[[nodiscard]] common::status cleanup_prepare_failure_(common::status failure,
							      bool bookkeeping_prepared) noexcept
	{
		if (claimed_modules_ != nullptr) {
			if (!claimed_modules_->abort_target().is_ok()) {
				std::terminate();
			}
		} else if (bookkeeping_prepared) {
			module_free_completion_.abort(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
		}
		if (bookkeeping_prepared) {
			prepared_completion_.abort(identity_);
		}
		const uint64_t terminal_ns = monotonic_ns(std::chrono::steady_clock::now());
		const auto terminal = coordinator_->abort_before_commit(
			identity_, terminal_ns, epoch_transition_failure_code::PREPARE_FAILURE,
			"completion fixture restored exact precommit ownership after setup failure");
		if (!terminal.is_ok() || terminal.observation.outcome != epoch_transition_outcome::ABORTED) {
			std::terminate();
		}
		if (completion_->active()) {
			completion_->disarm_after_abort(identity_);
		}
		return failure;
	}

	/**
	 * @brief Build one canonical candidate matching this fixture's module shape.
	 * @param revision Positive fixture revision representable by the snapshot's signed field.
	 * @return Candidate snapshot carrying the fixture's module configuration when present.
	 */
	[[nodiscard]] kinetum::control::v1::ConfigSnapshot fixture_snapshot_(uint64_t revision) const
	{
		kinetum::control::v1::ConfigSnapshot snapshot;
		snapshot.set_snapshot_id("completion.snapshot." + std::to_string(revision));
		snapshot.set_revision(static_cast<int64_t>(revision));
		snapshot.set_created_unix_ms(1);
		if (claimed_modules_ != nullptr) {
			auto *module = snapshot.add_modules();
			module->set_module_id("test_module");
			module->set_config_blob(R"({"drop":true})");
		}
		return snapshot;
	}

	runtime_fixture::compiled_runtime_fixture compiled_;	     ///< Exact plan/topology authority.
	epoch_protocol_fault_latch protocol_faults_;		     ///< Shared transition-safety fault authority.
	std::unique_ptr<epoch_transition_coordinator> coordinator_;  ///< Sole phase/snapshot owner.
	std::unique_ptr<worker_epoch_ledger> ledger_;		     ///< Sole worker credit owner.
	std::unique_ptr<worker_boundary_sender> sender_;	     ///< Zero-boundary sender owner.
	std::unique_ptr<worker_boundary_receiver> receiver_;	     ///< Zero-boundary receiver owner.
	std::unique_ptr<test::worker_telemetry_test_owner> worker_telemetry_;  ///< Exact worker banks/channel.
	completion_telemetry_probe telemetry_probe_;			       ///< Observation-only completion binding.
	std::vector<std::unique_ptr<packet_epoch_input_staging>> staging_owners_;   ///< Source queue owners.
	std::vector<packet_epoch_input_staging *> staging_;			    ///< Exact activation projection.
	module_free_completion module_free_completion_;				    ///< Module-free aggregate owner.
	std::unique_ptr<claimed_module_completion> claimed_modules_;		    ///< Optional exact module owner.
	epoch_transition_module_completion *module_completion_{nullptr};	    ///< Selected module authority.
	std::unique_ptr<module::worker_module_health> module_health_;		    ///< Exact health claim owner.
	std::unique_ptr<worker_epoch_activation> activation_;			    ///< Sole local activation owner.
	kinetum::algo::quiescence_reader reader_;				    ///< Sole exact reader record.
	std::unique_ptr<kinetum::algo::quiescence_domain> domain_;		    ///< Exact reader domain.
	std::unique_ptr<epoch_transition_certificate> certificate_;		    ///< Immutable proof graph.
	module_free_prepared_completion prepared_completion_;			    ///< PREPARED bookkeeping owner.
	runtime_status_publication runtime_status_;				    ///< Exact status projection.
	std::unique_ptr<epoch_transition_completion> completion_;		    ///< Completion/reclamation owner.
	kinetum::dataplane::v1::BootstrapConfigSnapshotRequest bootstrap_request_;  ///< Exact Bootstrap request.
	common::epoch_transition_identity identity_{};				    ///< Exact live identity.
	std::chrono::steady_clock::time_point last_service_time_{};  ///< Nondecreasing injected clock authority.
};

/**
 * @brief Wait boundedly for exact executor result publication.
 * @param modules Exact claimed-module completion owner.
 * @param expected Required cumulative result count.
 * @return true when the count is observed before the fixed test deadline.
 */
[[nodiscard]] bool wait_for_module_results(const claimed_module_completion &modules, uint64_t expected) noexcept
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (std::chrono::steady_clock::now() < deadline) {
		if (modules.published_result_count() >= expected) {
			return true;
		}
		std::this_thread::yield();
	}
	return false;
}

/**
 * @brief Drive available claimed results until exact completion or a bound.
 * @param fixture Active exact-module completion fixture.
 * @return true only when completion reaches clean IDLE before the deadline.
 */
[[nodiscard]] bool complete_module_retirement(completion_fixture &fixture) noexcept
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (std::chrono::steady_clock::now() < deadline) {
		const auto serviced = fixture.service_results_now();
		if (!serviced.is_ok()) {
			return false;
		}
		if (!fixture.completion().active()) {
			return true;
		}
		std::this_thread::yield();
	}
	return false;
}

/**
 * @brief Service one certificate probe at the completion owner's exact due time.
 * @param fixture Active committed completion fixture.
 * @return Serviced steady-clock point or exact missing/progress failure.
 */
[[nodiscard]] common::status_or<std::chrono::steady_clock::time_point>
service_next_progress(completion_fixture &fixture) noexcept
{
	const auto next = fixture.completion().next_deadline();
	if (!next.has_value()) {
		return common::status::failed_precondition("completion fixture has no due progress probe");
	}
	auto serviced = fixture.service_progress_at(*next);
	if (!serviced.is_ok()) {
		return serviced;
	}
	return *next;
}

/** @brief Fail-stop child for one task-sequence echo contradiction. */
[[noreturn]] void result_identity_mismatch_child()
{
	auto fixture_or = completion_fixture::create(std::chrono::seconds(5), std::chrono::seconds(5),
						     completion_module_shape::EXACT_MODULE);
	if (!fixture_or.is_ok()) {
		std::_Exit(101);
	}
	auto fixture = std::move(fixture_or).value();
	auto *modules = fixture->claimed_modules();
	if (modules == nullptr) {
		std::_Exit(102);
	}
	modules->set_result_identity_fault(completion_result_identity_fault::TASK_SEQUENCE);
	if (!fixture->prepare().is_ok() || !fixture->activate_without_reader().is_ok() ||
	    !service_next_progress(*fixture).is_ok() ||
	    fixture->coordinator().phase() != epoch_transition_phase::RETIRING) {
		std::_Exit(103);
	}
	fixture->publish_reader();
	if (!service_next_progress(*fixture).is_ok() || !fixture->completion().ownership_withdrawn() ||
	    !wait_for_module_results(*modules, 1u)) {
		std::_Exit(104);
	}
	const auto failed = fixture->service_results_now();
	const auto observed = fixture->coordinator().query_transaction(fixture->identity());
	if (failed.is_ok() || fixture->coordinator().phase() != epoch_transition_phase::FAILED_STOP ||
	    observed.observation.failure_code != epoch_transition_failure_code::CERTIFICATE_CONTRADICTION) {
		std::_Exit(105);
	}
	(void)fixture.release();
	std::_Exit(0);
}

/** @brief Fail-stop child for one accepted RETIRE context rejection. */
[[noreturn]] void callback_failure_child()
{
	auto fixture_or = completion_fixture::create(std::chrono::seconds(5), std::chrono::seconds(5),
						     completion_module_shape::EXACT_MODULE);
	if (!fixture_or.is_ok()) {
		std::_Exit(111);
	}
	auto fixture = std::move(fixture_or).value();
	auto *modules = fixture->claimed_modules();
	if (modules == nullptr || !fixture->prepare().is_ok() || !fixture->activate_without_reader().is_ok() ||
	    !service_next_progress(*fixture).is_ok()) {
		std::_Exit(112);
	}
	lifecycle::lifecycle_operation_control blocker_control(std::chrono::steady_clock::now() +
							       std::chrono::seconds(5));
	auto blocker_or = modules->lifecycle_owner().begin_operation(lifecycle::lifecycle_phase::RETIRE,
								     TEST_BOOTSTRAP_EPOCH, blocker_control);
	if (!blocker_or.is_ok()) {
		std::_Exit(113);
	}
	auto blocker = std::move(blocker_or).value();
	fixture->publish_reader();
	if (!service_next_progress(*fixture).is_ok() || !wait_for_module_results(*modules, 1u)) {
		std::_Exit(114);
	}
	const auto failed = fixture->service_results_now();
	const auto observed = fixture->coordinator().query_transaction(fixture->identity());
	if (failed.is_ok() || fixture->coordinator().phase() != epoch_transition_phase::FAILED_STOP ||
	    observed.observation.failure_code != epoch_transition_failure_code::RETIRE_CALLBACK_FAILURE) {
		std::_Exit(115);
	}
	blocker.release();
	(void)fixture.release();
	std::_Exit(0);
}

/** @brief Fail-stop child for a claimed callback result observed after its deadline. */
[[noreturn]] void claimed_callback_deadline_child()
{
	constexpr auto TIMEOUT = std::chrono::seconds(5);
	auto fixture_or = completion_fixture::create(TIMEOUT, TIMEOUT, completion_module_shape::EXACT_MODULE, true);
	if (!fixture_or.is_ok()) {
		std::_Exit(121);
	}
	auto fixture = std::move(fixture_or).value();
	auto *modules = fixture->claimed_modules();
	if (modules == nullptr || !fixture->prepare().is_ok() || !fixture->activate_without_reader().is_ok() ||
	    !service_next_progress(*fixture).is_ok()) {
		std::_Exit(122);
	}
	fixture->publish_reader();
	auto reclamation_or = service_next_progress(*fixture);
	if (!reclamation_or.is_ok() || !fixture->completion().ownership_withdrawn() ||
	    modules->accepted_task_count() != 1u || modules->published_result_count() != 0u) {
		std::_Exit(123);
	}
	const auto reclamation_started = std::move(reclamation_or).value();
	modules->release_executor();
	if (!wait_for_module_results(*modules, 1u)) {
		std::_Exit(124);
	}
	const auto failed = fixture->service_results_at(reclamation_started + TIMEOUT + std::chrono::milliseconds(1));
	const auto observed = fixture->coordinator().query_transaction(fixture->identity());
	if (failed.is_ok() || fixture->coordinator().phase() != epoch_transition_phase::FAILED_STOP ||
	    observed.observation.failure_code != epoch_transition_failure_code::RETIRE_CALLBACK_DEADLINE_EXCEEDED) {
		std::_Exit(125);
	}
	(void)fixture.release();
	std::_Exit(0);
}

/** @brief Fail-stop child for a nonfatal worker fault racing claimed retirement. */
[[noreturn]] void post_withdrawal_protocol_fault_child()
{
	auto fixture_or = completion_fixture::create(std::chrono::seconds(5), std::chrono::seconds(5),
						     completion_module_shape::EXACT_MODULE, true);
	if (!fixture_or.is_ok()) {
		std::_Exit(131);
	}
	auto fixture = std::move(fixture_or).value();
	auto *modules = fixture->claimed_modules();
	if (modules == nullptr || !fixture->prepare().is_ok() || !fixture->activate_without_reader().is_ok() ||
	    !service_next_progress(*fixture).is_ok() ||
	    fixture->coordinator().phase() != epoch_transition_phase::RETIRING) {
		std::_Exit(132);
	}
	fixture->publish_reader();
	if (!service_next_progress(*fixture).is_ok() || !fixture->completion().ownership_withdrawn()) {
		std::_Exit(133);
	}
	fixture->inject_protocol_fault_on_retirement();
	modules->release_executor();
	if (!wait_for_module_results(*modules, 1u)) {
		std::_Exit(134);
	}
	const auto failed = fixture->service_results_now();
	const auto observed = fixture->coordinator().query_transaction(fixture->identity());
	if (failed.is_ok() || fixture->coordinator().phase() != epoch_transition_phase::FAILED_STOP ||
	    observed.observation.failure_code != epoch_transition_failure_code::PROTOCOL_FAULT) {
		std::_Exit(135);
	}
	(void)fixture.release();
	std::_Exit(0);
}

/** @brief Prove execution completion enters RETIRING before reader-grace completion. */
TEST(epoch_transition_completion, execution_and_reader_legs_publish_exact_retiring_then_complete_truth)
{
	auto fixture_or = completion_fixture::create();
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	epoch_transition_progress_snapshot bootstrap_progress{};
	ASSERT_EQ(fixture->coordinator().try_read_progress(bootstrap_progress), publication_read_result::AVAILABLE);
	const auto bootstrap_validation_hash = bootstrap_progress.active_validation_hash;
	ASSERT_TRUE(fixture->prepare().is_ok());
	ASSERT_TRUE(fixture->activate_without_reader().is_ok());
	const auto first_probe = fixture->completion().next_deadline();
	ASSERT_TRUE(first_probe.has_value());
	ASSERT_TRUE(fixture->completion().service_progress(*first_probe - std::chrono::nanoseconds(1)).is_ok());
	EXPECT_EQ(fixture->coordinator().phase(), epoch_transition_phase::COMMITTING);
	ASSERT_TRUE(service_next_progress(*fixture).is_ok());
	EXPECT_EQ(fixture->coordinator().phase(), epoch_transition_phase::RETIRING);
	EXPECT_EQ(fixture->coordinator().active_epoch(), TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(fixture->coordinator().retained_snapshot_epoch(), TEST_BOOTSTRAP_EPOCH);
	epoch_transition_progress_snapshot retiring_progress{};
	ASSERT_EQ(fixture->coordinator().try_read_progress(retiring_progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(retiring_progress.active_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(retiring_progress.active_validation_hash, bootstrap_validation_hash);
	runtime_status_snapshot retiring{};
	ASSERT_EQ(fixture->runtime_status().try_read(retiring), publication_read_result::AVAILABLE);
	EXPECT_EQ(retiring.active_epoch, TEST_TARGET_EPOCH);
	EXPECT_EQ(retiring.minimum_retained_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(retiring.last_activated_epoch, TEST_TARGET_EPOCH);
	auto later_identity = fixture->identity();
	later_identity.mutation_sequence = 3u;
	later_identity.target_epoch = 3u;
	later_identity.idempotency_key_digest.fill(UINT8_C(0x6b));
	const auto blocked = fixture->coordinator().query_transaction(later_identity);
	EXPECT_EQ(blocked.observation.resolution, common::transition_identity_resolution::OVERLAP);

	fixture->publish_reader();
	ASSERT_TRUE(service_next_progress(*fixture).is_ok());
	EXPECT_EQ(fixture->coordinator().phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(fixture->coordinator().active_epoch(), TEST_TARGET_EPOCH);
	EXPECT_EQ(fixture->coordinator().retained_snapshot_epoch(), 0u);
	epoch_transition_progress_snapshot complete_progress{};
	ASSERT_EQ(fixture->coordinator().try_read_progress(complete_progress), publication_read_result::AVAILABLE);
	EXPECT_EQ(complete_progress.active_epoch, TEST_TARGET_EPOCH);
	EXPECT_EQ(complete_progress.active_validation_hash, fixture->identity().validation_hash);
	ASSERT_EQ(fixture->coordinator().terminal_history_size(), 1u);
	const auto *terminal = fixture->coordinator().terminal_result(0u);
	ASSERT_NE(terminal, nullptr);
	EXPECT_EQ(terminal->outcome, epoch_transition_outcome::COMPLETE);
	EXPECT_EQ(terminal->duration_presence, TRANSITION_PREPARE_DURATION_PRESENT |
						       TRANSITION_COMMIT_DURATION_PRESENT |
						       TRANSITION_RETIREMENT_DURATION_PRESENT);
	runtime_status_snapshot complete{};
	ASSERT_EQ(fixture->runtime_status().try_read(complete), publication_read_result::AVAILABLE);
	EXPECT_EQ(complete.active_epoch, TEST_TARGET_EPOCH);
	EXPECT_EQ(complete.minimum_retained_epoch, TEST_TARGET_EPOCH);
	EXPECT_EQ(complete.last_activated_epoch, TEST_TARGET_EPOCH);
	const auto later = fixture->coordinator().query_transaction(later_identity);
	EXPECT_EQ(later.observation.resolution, common::transition_identity_resolution::UNKNOWN_FUTURE);
}

/** @brief Prove precommit arm failure mutates neither coordinator nor completion ownership. */
TEST(epoch_transition_completion, arm_is_all_or_none_before_prepared_publication)
{
	auto fixture_or = completion_fixture::create(std::chrono::seconds(5), std::chrono::seconds(5),
						     completion_module_shape::MODULE_FREE, false,
						     TEST_RUNTIME_GENERATION + 1u);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_FALSE(fixture->completion().active());
	const auto rejected = fixture->prepare();
	EXPECT_FALSE(rejected.is_ok());
	EXPECT_FALSE(fixture->completion().active());
	EXPECT_EQ(fixture->coordinator().phase(), epoch_transition_phase::IDLE);
}

/** @brief Prove failed commit preflight leaves PREPARED abortable and grace-inactive. */
TEST(epoch_transition_completion, commit_preflight_failure_preserves_abortable_prepared_ownership)
{
	auto fixture_or = completion_fixture::create();
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	ASSERT_TRUE(fixture->prepare().is_ok());
	const auto rejected =
		fixture->completion().begin_commit(fixture->identity(), std::chrono::steady_clock::time_point{});
	EXPECT_FALSE(rejected.is_ok());
	EXPECT_EQ(fixture->coordinator().phase(), epoch_transition_phase::PREPARED);
	EXPECT_TRUE(fixture->completion().active());
	EXPECT_FALSE(fixture->completion().next_deadline().has_value());
	ASSERT_TRUE(fixture->abort_prepared().is_ok());
	EXPECT_EQ(fixture->coordinator().phase(), epoch_transition_phase::IDLE);
	EXPECT_FALSE(fixture->completion().active());
}

/** @brief Prove exact module RETIRE result consumption empties E before COMPLETE. */
TEST(epoch_transition_completion, claimed_module_retirement_completes_store_before_terminal_publication)
{
	auto fixture_or = completion_fixture::create(std::chrono::seconds(5), std::chrono::seconds(5),
						     completion_module_shape::EXACT_MODULE);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	auto *modules = fixture->claimed_modules();
	ASSERT_NE(modules, nullptr);
	ASSERT_TRUE(fixture->prepare().is_ok());
	ASSERT_TRUE(fixture->activate_without_reader().is_ok());
	ASSERT_TRUE(service_next_progress(*fixture).is_ok());
	ASSERT_EQ(fixture->coordinator().phase(), epoch_transition_phase::RETIRING);
	fixture->publish_reader();
	ASSERT_TRUE(service_next_progress(*fixture).is_ok());
	EXPECT_TRUE(fixture->completion().ownership_withdrawn());
	EXPECT_EQ(fixture->coordinator().retained_snapshot_epoch(), TEST_BOOTSTRAP_EPOCH);
	ASSERT_TRUE(wait_for_module_results(*modules, 1u));
	ASSERT_TRUE(complete_module_retirement(*fixture));
	EXPECT_EQ(modules->accepted_task_count(), 1u);
	EXPECT_EQ(modules->published_result_count(), 1u);
	EXPECT_TRUE(modules->completion_retirement_complete(TEST_TARGET_EPOCH));
	EXPECT_EQ(fixture->coordinator().phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(fixture->coordinator().retained_snapshot_epoch(), 0u);
}

/** @brief Prove compiled module membership cannot pair with a module-free completion authority. */
TEST(epoch_transition_completion, creation_rejects_module_authority_membership_drift)
{
	auto rejected = completion_fixture::create(std::chrono::seconds(5), std::chrono::seconds(5),
						   completion_module_shape::MISMATCHED_AUTHORITY);
	ASSERT_FALSE(rejected.is_ok());
	EXPECT_EQ(rejected.error().code(), common::status_code::FAILED_PRECONDITION);
}

/** @brief Prove an inexact executor echo fail-stops before claim consumption. */
TEST(epoch_transition_completion, claimed_retire_result_identity_is_exact)
{
	EXPECT_EXIT(result_identity_mismatch_child(), ::testing::ExitedWithCode(0), "");
}

/** @brief Prove a non-SUCCESS claimed callback result retains ownership and fail-stops. */
TEST(epoch_transition_completion, claimed_retire_callback_failure_is_typed_fail_stop)
{
	EXPECT_EXIT(callback_failure_child(), ::testing::ExitedWithCode(0), "");
}

/** @brief Prove deadline expiry after the first claim is fail-stop, never update-freeze. */
TEST(epoch_transition_completion, post_withdrawal_callback_deadline_is_fail_stop)
{
	EXPECT_EXIT(claimed_callback_deadline_child(), ::testing::ExitedWithCode(0), "");
}

/** @brief Prove a late nonfatal worker fault cannot race claimed retirement into COMPLETE. */
TEST(epoch_transition_completion, post_withdrawal_protocol_fault_blocks_terminal_success)
{
	EXPECT_EXIT(post_withdrawal_protocol_fault_child(), ::testing::ExitedWithCode(0), "");
}

/** @brief Prove reader-grace timeout freezes all E ownership and permanently blocks convergence. */
TEST(epoch_transition_completion, reader_grace_timeout_latches_update_frozen_without_withdrawal)
{
	EXPECT_EXIT(
		{
			constexpr auto TIMEOUT = std::chrono::seconds(5);
			auto fixture_or = completion_fixture::create(TIMEOUT, TIMEOUT);
			if (!fixture_or.is_ok()) {
				std::_Exit(81);
			}
			auto fixture = std::move(fixture_or).value();
			if (!fixture->prepare().is_ok() || !fixture->activate_without_reader().is_ok() ||
			    !service_next_progress(*fixture).is_ok() ||
			    fixture->coordinator().phase() != epoch_transition_phase::RETIRING) {
				std::_Exit(82);
			}
			if (!fixture->completion().next_deadline().has_value() ||
			    !fixture->completion()
				     .service_deadline(std::chrono::steady_clock::now() + TIMEOUT +
						       std::chrono::milliseconds(1))
				     .is_ok() ||
			    !fixture->coordinator().retirement_frozen() ||
			    fixture->completion().ownership_withdrawn() ||
			    fixture->coordinator().retained_snapshot_epoch() != TEST_BOOTSTRAP_EPOCH) {
				std::_Exit(83);
			}
			fixture->publish_reader();
			if (!fixture->completion()
				     .service_progress(std::chrono::steady_clock::now() + TIMEOUT +
						       std::chrono::milliseconds(2))
				     .is_ok() ||
			    fixture->coordinator().phase() != epoch_transition_phase::RETIRING ||
			    !fixture->coordinator().retirement_frozen() ||
			    fixture->completion().ownership_withdrawn() ||
			    fixture->coordinator().retained_snapshot_epoch() != TEST_BOOTSTRAP_EPOCH ||
			    fixture->completion().next_deadline().has_value()) {
				std::_Exit(84);
			}
			(void)fixture.release();
			std::_Exit(0);
		},
		::testing::ExitedWithCode(0), "");
}

/** @brief Prove COMMITTING deadline is typed fail-stop and performs no old retirement. */
TEST(epoch_transition_completion, committing_timeout_fails_stop_without_reclamation)
{
	EXPECT_EXIT(
		{
			constexpr auto TIMEOUT = std::chrono::seconds(5);
			auto fixture_or = completion_fixture::create(TIMEOUT, TIMEOUT);
			if (!fixture_or.is_ok()) {
				std::_Exit(91);
			}
			auto fixture = std::move(fixture_or).value();
			if (!fixture->prepare().is_ok()) {
				std::_Exit(92);
			}
			const auto now = std::chrono::steady_clock::now();
			if (!fixture->completion().begin_commit(fixture->identity(), now).is_ok()) {
				std::_Exit(93);
			}
			if (!fixture->completion().next_deadline().has_value() ||
			    fixture->completion()
				    .service_deadline(now + TIMEOUT + std::chrono::milliseconds(1))
				    .is_ok() ||
			    fixture->coordinator().phase() != epoch_transition_phase::FAILED_STOP ||
			    fixture->completion().ownership_withdrawn() ||
			    fixture->coordinator().prepared_snapshot_epoch() != TEST_TARGET_EPOCH) {
				std::_Exit(94);
			}
			(void)fixture.release();
			std::_Exit(0);
		},
		::testing::ExitedWithCode(0), "");
}

}  // namespace
}  // namespace kinetum::dp
