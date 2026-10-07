// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_lifecycle_context.cpp
 * @brief Unit tests for cold lifecycle context, arena, and prepared ownership.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <memory_resource>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <kinetum/algo/platform.hpp>
#include "src/common/status.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "src/dp/lifecycle/prepared_config_ownership.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/quark/host_probe.hpp"
#include <kinetum/kinetum_sdk.hpp>

namespace kinetum::dp::lifecycle
{

namespace
{

static_assert(!std::is_copy_constructible_v<epoch_arena_ownership>);
static_assert(!std::is_copy_constructible_v<prepared_config_ownership>);
static_assert(alignof(lifecycle_operation_control) == kinetum::algo::CACHE_LINE_SIZE);
static_assert(sizeof(lifecycle_operation_control) == kinetum::algo::CACHE_LINE_SIZE);

/** Long-lived context allocation authority supplied to the fixture. */
constexpr std::size_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = 4096;
/** Immutable epoch-arena allocation authority supplied to the fixture. */
constexpr std::size_t TEST_EPOCH_ARENA_CAPACITY_BYTES = 256;

/** @brief Deterministic exact-memory provider for lifecycle component tests. */
class test_memory_provider final : public lifecycle_memory_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::allocate */
	[[nodiscard]] kinetum::common::status_or<lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept override
	{
		if (fail_next_) {
			fail_next_ = false;
			return kinetum::common::status::resource_exhausted("injected test allocation failure");
		}
		void *pointer = nullptr;
		if (posix_memalign(&pointer, alignment, size) != 0) {
			return kinetum::common::status(kinetum::common::status_code::RESOURCE_EXHAUSTED,
						       "test allocation failed");
		}
		if (zero_initialize) {
			std::memset(pointer, 0, size);
		} else {
			std::memset(pointer, 0xa5, size);
		}
		active_.insert(pointer);
		return lifecycle_memory_block{pointer,
					      size,
					      weak_alignment_ ? sizeof(void *) : alignment,
					      wrong_numa_ ? numa_node + 1 : numa_node,
					      {}};
	}

	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::release */
	void release(lifecycle_memory_block block) noexcept override
	{
		if (active_.erase(block.data) == 1u) {
			std::free(block.data);
			++release_count_;
		} else {
			++invalid_release_count_;
		}
	}

	/**
	 * @brief Select whether subsequent claims report a different NUMA node.
	 *
	 * @param value true to inject the malformed claim.
	 */
	void set_wrong_numa(bool value) noexcept
	{
		wrong_numa_ = value;
	}

	/**
	 * @brief Select whether subsequent claims report weaker alignment.
	 *
	 * @param value true to inject the malformed claim.
	 */
	void set_weak_alignment(bool value) noexcept
	{
		weak_alignment_ = value;
	}

	/** @brief Fail exactly the next provider allocation before side effects. */
	void fail_next_allocation() noexcept
	{
		fail_next_ = true;
	}

	/**
	 * @brief Return active allocation count.
	 *
	 * @return Number of exact blocks not yet released.
	 */
	[[nodiscard]] std::size_t active_count() const noexcept
	{
		return active_.size();
	}

	/**
	 * @brief Return successful provider-release count.
	 *
	 * @return Number of exact one-time releases.
	 */
	[[nodiscard]] std::size_t release_count() const noexcept
	{
		return release_count_;
	}

	/**
	 * @brief Return invalid or repeated release count.
	 *
	 * @return Number of release calls without matching ownership.
	 */
	[[nodiscard]] std::size_t invalid_release_count() const noexcept
	{
		return invalid_release_count_;
	}

    private:
	std::set<void *> active_;		///< Exact test-owned allocation starts.
	std::size_t release_count_{0};		///< Successful one-time releases.
	std::size_t invalid_release_count_{0};	///< Unknown or repeated release attempts.
	bool wrong_numa_{false};		///< Malformed NUMA-claim injection.
	bool weak_alignment_{false};		///< Malformed alignment-claim injection.
	bool fail_next_{false};			///< One-shot exact allocation failure.
};

/** @brief Test log sink proving provider access without platform logging state. */
class test_log_provider final : public lifecycle_log_provider {
    public:
	/** @copydoc kinetum::dp::lifecycle::lifecycle_log_provider::write */
	void write(const lifecycle_log_record_view &record) noexcept override
	{
		last_level_ = record.level;
		last_message_.assign(record.message);
		last_identity = record.identity;
		last_phase = record.phase;
		last_epoch = record.epoch;
		++write_count_;
	}

	lifecycle_context_identity last_identity{};  ///< Copied context identity survives the borrowed operation.
	lifecycle_phase last_phase{lifecycle_phase::INIT};  ///< Last actual cold phase.
	uint64_t last_epoch{0};				    ///< Last actual operation epoch.

	/**
	 * @brief Return the number of retained diagnostics.
	 *
	 * @return Number of write() invocations.
	 */
	[[nodiscard]] std::size_t write_count() const noexcept
	{
		return write_count_;
	}

	/**
	 * @brief Return the last retained diagnostic severity.
	 *
	 * @return Severity from the latest write().
	 */
	[[nodiscard]] lifecycle_log_level last_level() const noexcept
	{
		return last_level_;
	}

	/**
	 * @brief Return the last retained diagnostic text.
	 *
	 * @return Stable test-owned diagnostic text.
	 */
	[[nodiscard]] const std::string &last_message() const noexcept
	{
		return last_message_;
	}

    private:
	std::size_t write_count_{0};				      ///< Total write calls.
	lifecycle_log_level last_level_{lifecycle_log_level::DEBUG};  ///< Latest severity.
	std::string last_message_;				      ///< Latest copied message.
};

/**
 * @brief Build one valid immutable lifecycle identity.
 *
 * @param context_index Exact executable-context index.
 * @param numa_node Exact context NUMA node.
 * @return Complete admitted identity for a test owner.
 */
lifecycle_context_identity make_identity(uint32_t context_index = 7, int32_t numa_node = 0)
{
	return lifecycle_context_identity{
		"kinetum.test.module", "stage@lane_0", 3, context_index, 2, 5, numa_node, 0u, 1u};
}

/**
 * @brief Create a valid test owner or report a test failure.
 *
 * @param memory Exact test memory provider.
 * @param log Exact test log provider.
 * @param context_index Exact executable-context index.
 * @param numa_node Exact context NUMA node.
 * @param context_capacity Exact byte budget for this owner's long-lived context state.
 * @return Unique valid owner, or nullptr after recording a test failure.
 */
std::unique_ptr<lifecycle_context_owner> make_owner(test_memory_provider &memory, test_log_provider &log,
						    uint32_t context_index = 7, int32_t numa_node = 0,
						    std::size_t context_capacity = TEST_CONTEXT_MEMORY_CAPACITY_BYTES)
{
	auto owner_or = lifecycle_context_owner::create(make_identity(context_index, numa_node), context_capacity,
							TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log);
	if (!owner_or.is_ok()) {
		ADD_FAILURE() << owner_or.error().message();
		return nullptr;
	}
	return std::move(owner_or).value();
}

/**
 * @brief Return one future deadline suitable for a synchronous component test.
 *
 * @return Steady-clock time five seconds in the future.
 */
std::chrono::steady_clock::time_point future_deadline()
{
	return std::chrono::steady_clock::now() + std::chrono::seconds(5);
}

/**
 * @brief Clear every completed histogram through the production bounded prefix seam.
 * @param owner Lifecycle owner retaining the completed telemetry bank.
 * @param token Exact completed bank whose histograms are cleared.
 */
void clear_completed_histograms(lifecycle_context_owner &owner, const runtime_telemetry_bank_token &token)
{
	std::size_t histogram_count = 0u;
	for (std::size_t handle = 1u; handle <= owner.telemetry_handle_count(); ++handle) {
		const auto *descriptor = owner.telemetry_descriptor(static_cast<lifecycle_telemetry_handle>(handle));
		if (descriptor != nullptr && descriptor->kind == lifecycle_telemetry_kind::HISTOGRAM) {
			++histogram_count;
		}
	}
	std::size_t observed = 0u;
	for (std::size_t handle = 1u; handle <= owner.telemetry_handle_count(); ++handle) {
		const auto *descriptor = owner.telemetry_descriptor(static_cast<lifecycle_telemetry_handle>(handle));
		if (descriptor == nullptr || descriptor->kind != lifecycle_telemetry_kind::HISTOGRAM) {
			continue;
		}
		if (descriptor->kind_ordinal != observed) {
			std::terminate();
		}
		auto buckets_or = owner.completed_telemetry_histogram(token, descriptor->kind_ordinal);
		if (!buckets_or.is_ok()) {
			std::terminate();
		}
		const auto buckets = buckets_or.value();
		for (std::size_t begin = 0u; begin < buckets.size();) {
			const std::size_t count = std::min(LIFECYCLE_TELEMETRY_BUCKET_PREFIX, buckets.size() - begin);
			const bool complete = owner.clear_completed_telemetry_histogram_prefix(
				token, descriptor->kind_ordinal, begin, count);
			begin += count;
			if (complete != (observed + 1u == histogram_count && begin == buckets.size())) {
				std::terminate();
			}
		}
		++observed;
	}
}

}  // namespace

/** @brief Verify cancellation is one-way and deadline evaluation is monotonic. */
TEST(lifecycle_context, operation_control_publishes_cancellation_and_exact_deadline)
{
	const auto deadline = future_deadline();
	lifecycle_operation_control control(deadline);

	EXPECT_TRUE(control.deadline_bound());
	EXPECT_EQ(control.deadline(), deadline);
	EXPECT_FALSE(control.cancellation_requested());
	EXPECT_FALSE(control.deadline_expired(deadline - std::chrono::nanoseconds(1)));
	EXPECT_TRUE(control.deadline_expired(deadline));

	control.request_cancellation();
	EXPECT_TRUE(control.cancellation_requested());
	control.request_cancellation();
	EXPECT_TRUE(control.cancellation_requested());

	lifecycle_operation_control unbound(std::chrono::steady_clock::time_point{});
	EXPECT_FALSE(unbound.deadline_bound());
	EXPECT_TRUE(unbound.deadline_expired(std::chrono::steady_clock::now()));
}

/** @brief Verify malformed immutable identity is rejected before owner allocation. */
TEST(lifecycle_context, owner_rejects_invalid_identity_and_unknown_placement)
{
	test_memory_provider memory;
	test_log_provider log;

	auto empty = make_identity();
	empty.module_id.clear();
	EXPECT_FALSE(lifecycle_context_owner::create(std::move(empty), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
						     TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log)
			     .is_ok());

	auto embedded_nul = make_identity();
	embedded_nul.context_instance_id = std::string("stage\0lane_0", 12);
	EXPECT_FALSE(lifecycle_context_owner::create(std::move(embedded_nul), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
						     TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log)
			     .is_ok());

	auto unbounded = make_identity();
	unbounded.module_id.assign(KINETUM_MODULE_ABI_TEXT_CAPACITY, 'm');
	auto unbounded_or = lifecycle_context_owner::create(std::move(unbounded), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
							    TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log);
	ASSERT_FALSE(unbounded_or.is_ok());
	EXPECT_EQ(unbounded_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(unbounded_or.error().message(),
		  "lifecycle context requires bounded printable-ASCII module and context identity");

	auto unbounded_context = make_identity();
	unbounded_context.context_instance_id.assign(KINETUM_MODULE_ABI_TEXT_CAPACITY, 'c');
	auto unbounded_context_or = lifecycle_context_owner::create(std::move(unbounded_context),
								    TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
								    TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log);
	ASSERT_FALSE(unbounded_context_or.is_ok());
	EXPECT_EQ(unbounded_context_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
	EXPECT_EQ(unbounded_context_or.error().message(),
		  "lifecycle context requires bounded printable-ASCII module and context identity");

	auto unknown_cpu = make_identity();
	unknown_cpu.cpu_core_id = -1;
	EXPECT_FALSE(lifecycle_context_owner::create(std::move(unknown_cpu), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
						     TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log)
			     .is_ok());

	auto unknown_numa = make_identity();
	unknown_numa.numa_node = -1;
	EXPECT_FALSE(lifecycle_context_owner::create(std::move(unknown_numa), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
						     TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log)
			     .is_ok());
	for (const uint32_t count : {0u, 1u}) {
		auto invalid_population = make_identity();
		invalid_population.module_context_count = count;
		invalid_population.module_context_ordinal = count;
		EXPECT_FALSE(lifecycle_context_owner::create(std::move(invalid_population),
							     TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
							     TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log)
				     .is_ok());
	}
	EXPECT_EQ(memory.active_count(), 0u);
	EXPECT_EQ(memory.release_count(), 0u);
	EXPECT_EQ(memory.invalid_release_count(), 0u);
}

/** @brief Verify zero lifecycle-memory authority is rejected before allocation. */
TEST(lifecycle_context, owner_rejects_absent_context_or_epoch_capacity)
{
	test_memory_provider memory;
	test_log_provider log;
	EXPECT_FALSE(lifecycle_context_owner::create(make_identity(), 0, TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log)
			     .is_ok());
	EXPECT_FALSE(
		lifecycle_context_owner::create(make_identity(), TEST_CONTEXT_MEMORY_CAPACITY_BYTES, 0, memory, log)
			.is_ok());
	EXPECT_EQ(memory.active_count(), 0u);
}

/** @brief Verify exclusive borrowing, exact identity, and stale-shell rejection. */
TEST(lifecycle_context, operation_claim_is_exclusive_and_exposes_exact_identity)
{
	test_memory_provider memory;
	test_log_provider log;
	const std::string expected_module_id(KINETUM_MODULE_ABI_TEXT_CAPACITY - 1u, 'm');
	const std::string expected_context_id(KINETUM_MODULE_ABI_TEXT_CAPACITY - 1u, 'c');
	auto identity = make_identity();
	identity.module_id = expected_module_id;
	identity.context_instance_id = expected_context_id;
	identity.module_context_ordinal = 2u;
	identity.module_context_count = 3u;
	auto owner_or = lifecycle_context_owner::create(std::move(identity), TEST_CONTEXT_MEMORY_CAPACITY_BYTES,
							TEST_EPOCH_ARENA_CAPACITY_BYTES, memory, log);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto owner = std::move(owner_or).value();
	EXPECT_EQ(owner->identity().module_id, expected_module_id);
	EXPECT_EQ(owner->identity().context_instance_id, expected_context_id);
	lifecycle_operation_control unbound(std::chrono::steady_clock::time_point{});
	EXPECT_FALSE(owner->begin_operation(lifecycle_phase::INIT, 0, unbound).is_ok());
	lifecycle_operation_control control(future_deadline());

	auto operation_or = owner->begin_operation(lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();
	const auto *borrowed_context = &operation.context();
	EXPECT_EQ(lifecycle_identity(operation.context()).context_index, 7u);
	kinetum_lifecycle_identity admitted_identity{};
	ASSERT_EQ(kinetum_lifecycle_get_identity(borrowed_context, &admitted_identity), KINETUM_OK);
	EXPECT_STREQ(admitted_identity.module_id, expected_module_id.c_str());
	EXPECT_STREQ(admitted_identity.context_instance_id, expected_context_id.c_str());
	EXPECT_EQ(admitted_identity.module_context_ordinal, owner->identity().module_context_ordinal);
	EXPECT_EQ(admitted_identity.module_context_count, owner->identity().module_context_count);
	EXPECT_EQ(lifecycle_current_phase(operation.context()), lifecycle_phase::INIT);
	EXPECT_EQ(lifecycle_current_epoch(operation.context()), 0u);
	EXPECT_FALSE(owner->begin_operation(lifecycle_phase::FINI, 0, control).is_ok());
	lifecycle_log(operation.context(), lifecycle_log_level::INFO, "init-ready");
	EXPECT_EQ(log.write_count(), 1u);
	EXPECT_EQ(log.last_level(), lifecycle_log_level::INFO);
	EXPECT_EQ(log.last_message(), "init-ready");
	EXPECT_EQ(log.last_identity.module_id, expected_module_id);
	EXPECT_EQ(log.last_identity.context_instance_id, expected_context_id);
	EXPECT_EQ(log.last_identity.context_index, 7u);
	EXPECT_EQ(log.last_identity.worker_index, 2u);
	EXPECT_EQ(log.last_identity.cpu_core_id, 5);
	EXPECT_EQ(log.last_phase, lifecycle_phase::INIT);
	EXPECT_EQ(log.last_epoch, 0u);
	const auto rejected_before = common::packet_thread_log_rejections();
	{
		common::packet_thread_log_guard packet;
		kinetum_lifecycle_log(&operation.context(), KINETUM_LIFECYCLE_LOG_ERROR, "packet ABI log");
		lifecycle_log(operation.context(), lifecycle_log_level::ERROR, "packet native log");
	}
	EXPECT_EQ(common::packet_thread_log_rejections(), rejected_before + 2);
	EXPECT_EQ(log.write_count(), 1u);

	operation.release();
	kinetum_lifecycle_identity stale_identity{};
	stale_identity.context_index = 99;
	EXPECT_EQ(kinetum_lifecycle_get_identity(borrowed_context, &stale_identity), KINETUM_ERR_INVALID_ARG);
	EXPECT_EQ(stale_identity.context_index, 99u);
	int allocation_sentinel = 0;
	void *stale_allocation = &allocation_sentinel;
	EXPECT_EQ(kinetum_lifecycle_allocate_context(borrowed_context, 64, 64, 0, &stale_allocation),
		  KINETUM_ERR_INVALID_ARG);
	EXPECT_EQ(stale_allocation, &allocation_sentinel);
	kinetum_lifecycle_log(borrowed_context, KINETUM_LIFECYCLE_LOG_ERROR, "stale");
	EXPECT_EQ(log.write_count(), 1u);
	EXPECT_EQ(kinetum_lifecycle_deadline_ns(borrowed_context), 0u);
	EXPECT_TRUE(kinetum_lifecycle_cancellation_requested(borrowed_context));
	EXPECT_DEATH({ (void)operation.context(); }, "");
	EXPECT_TRUE(owner->begin_operation(lifecycle_phase::FINI, 0, control).is_ok());
}

/** @brief Verify long-lived INIT allocation is exact, zeroed, and released once. */
TEST(lifecycle_context, long_lived_allocation_tracks_exact_pointer_and_release)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	const std::size_t platform_allocations = memory.active_count();
	ASSERT_EQ(platform_allocations, 1u);
	lifecycle_operation_control control(future_deadline());
	auto operation_or = owner->begin_operation(lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();

	auto allocation_or = lifecycle_allocate_long_lived(operation.context(), 128, 64, true);
	ASSERT_TRUE(allocation_or.is_ok()) << allocation_or.error().message();
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(allocation_or.value()) % 64u, 0u);
	const auto *bytes = static_cast<const unsigned char *>(allocation_or.value());
	for (std::size_t i = 0; i < 128; ++i) {
		EXPECT_EQ(bytes[i], 0u);
	}
	EXPECT_TRUE(lifecycle_release_long_lived(operation.context(), allocation_or.value()).is_ok());
	EXPECT_EQ(lifecycle_release_long_lived(operation.context(), allocation_or.value()).code(),
		  kinetum::common::status_code::NOT_FOUND);
	EXPECT_EQ(memory.active_count(), platform_allocations);
	EXPECT_EQ(memory.invalid_release_count(), 0u);
	operation.release();
	owner.reset();
	EXPECT_EQ(memory.active_count(), 0u);
}

/** @brief Verify provider NUMA/alignment lies fail before publication and are reclaimed. */
TEST(lifecycle_context, owner_rejects_malformed_provider_claims_without_leaking)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	const std::size_t platform_allocations = memory.active_count();
	ASSERT_EQ(platform_allocations, 1u);
	lifecycle_operation_control control(future_deadline());
	auto operation_or = owner->begin_operation(lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();

	memory.set_wrong_numa(true);
	EXPECT_FALSE(lifecycle_allocate_long_lived(operation.context(), 64, 64, false).is_ok());
	EXPECT_EQ(memory.active_count(), platform_allocations);
	memory.set_wrong_numa(false);
	memory.set_weak_alignment(true);
	EXPECT_FALSE(lifecycle_allocate_long_lived(operation.context(), 64, 64, false).is_ok());
	EXPECT_EQ(memory.active_count(), platform_allocations);
	EXPECT_EQ(memory.release_count(), 2u);
	operation.release();
	owner.reset();
	EXPECT_EQ(memory.active_count(), 0u);
}

/** @brief Verify the long-lived allocation ledger has a hard non-growing bound. */
TEST(lifecycle_context, long_lived_allocation_ledger_rejects_unbounded_growth)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(future_deadline());
	auto operation_or = owner->begin_operation(lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();

	for (std::size_t i = 0; i < LIFECYCLE_MAX_LONG_LIVED_ALLOCATIONS; ++i) {
		ASSERT_TRUE(lifecycle_allocate_long_lived(operation.context(), 64, 64, false).is_ok());
	}
	const auto overflow = lifecycle_allocate_long_lived(operation.context(), 64, 64, false);
	ASSERT_FALSE(overflow.is_ok());
	EXPECT_EQ(overflow.error().code(), kinetum::common::status_code::RESOURCE_EXHAUSTED);
	operation.release();
	owner.reset();
	EXPECT_EQ(memory.active_count(), 0u);
}

/** @brief Verify telemetry names, duplicate rejection, stable handles, and registry bound. */
TEST(lifecycle_context, telemetry_registration_is_bounded_unique_and_init_only)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log, 7u, 0, std::size_t{1024} * 1024u);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(future_deadline());
	auto init_or = owner->begin_operation(lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(init_or.is_ok()) << init_or.error().message();
	auto init = std::move(init_or).value();

	kinetum_counter_t first = nullptr;
	ASSERT_EQ(kinetum_lifecycle_register_counter(&init.context(), "packets", &first), KINETUM_OK);
	ASSERT_NE(first, nullptr);
	kinetum_histogram_t duplicate = nullptr;
	EXPECT_EQ(kinetum_lifecycle_register_histogram(&init.context(), "packets", 1000, 3, &duplicate),
		  KINETUM_ERR_ALREADY_EXISTS);
	for (std::size_t i = 1; i < KINETUM_MAX_COUNTERS; ++i) {
		const std::string name = "metric_" + std::to_string(i);
		kinetum_counter_t counter = nullptr;
		ASSERT_EQ(kinetum_lifecycle_register_counter(&init.context(), name.c_str(), &counter), KINETUM_OK);
		ASSERT_NE(counter, nullptr);
	}
	kinetum_counter_t overflow = nullptr;
	EXPECT_EQ(kinetum_lifecycle_register_counter(&init.context(), "overflow", &overflow),
		  KINETUM_ERR_LIMIT_EXCEEDED);
	for (std::size_t i = 0u; i < KINETUM_MAX_HISTOGRAMS; ++i) {
		const std::string name = "histogram_" + std::to_string(i);
		kinetum_histogram_t histogram = nullptr;
		ASSERT_EQ(kinetum_lifecycle_register_histogram(&init.context(), name.c_str(), 1000u, 1, &histogram),
			  KINETUM_OK);
		ASSERT_NE(histogram, nullptr);
	}
	kinetum_histogram_t histogram_overflow = nullptr;
	EXPECT_EQ(kinetum_lifecycle_register_histogram(&init.context(), "histogram_overflow", 1000u, 1,
						       &histogram_overflow),
		  KINETUM_ERR_LIMIT_EXCEEDED);
	ASSERT_EQ(owner->telemetry_handle_count(), LIFECYCLE_MAX_TELEMETRY_HANDLES);
	ASSERT_NE(owner->telemetry_descriptor(1), nullptr);
	EXPECT_EQ(owner->telemetry_descriptor(1)->kind, lifecycle_telemetry_kind::COUNTER);
	EXPECT_STREQ(owner->telemetry_descriptor(1)->counter.name, "packets");
	init.release();

	auto fini_or = owner->begin_operation(lifecycle_phase::FINI, 0, control);
	ASSERT_TRUE(fini_or.is_ok()) << fini_or.error().message();
	auto fini = std::move(fini_or).value();
	kinetum_counter_t late = nullptr;
	EXPECT_EQ(kinetum_lifecycle_register_counter(&fini.context(), "late", &late), KINETUM_ERR_BUSY);
}

/** @brief Prove failed three-bank histogram allocation consumes no handle or ledger slot. */
TEST(lifecycle_context, histogram_registration_is_transactional_across_all_three_banks)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log, 7u, 0, std::size_t{1024} * 1024u);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(future_deadline());
	auto init_or = owner->begin_operation(lifecycle_phase::INIT, 0u, control);
	ASSERT_TRUE(init_or.is_ok()) << init_or.error().message();
	auto init = std::move(init_or).value();
	const std::size_t baseline_allocations = memory.active_count();
	memory.fail_next_allocation();
	kinetum_histogram_t rejected = nullptr;
	EXPECT_EQ(kinetum_lifecycle_register_histogram(&init.context(), "latency", 1000u, 2, &rejected),
		  KINETUM_ERR_NO_MEMORY);
	EXPECT_EQ(rejected, nullptr);
	EXPECT_EQ(owner->telemetry_handle_count(), 0u);
	EXPECT_EQ(memory.active_count(), baseline_allocations);

	kinetum_counter_t first = nullptr;
	ASSERT_EQ(kinetum_lifecycle_register_counter(&init.context(), "first", &first), KINETUM_OK);
	ASSERT_NE(first, nullptr);
	ASSERT_NE(owner->telemetry_descriptor(1u), nullptr);
	EXPECT_EQ(owner->telemetry_descriptor(1u)->handle, 1u);
}

/** @brief Prove module banks publish exact counters, histograms, mismatch, and epochs. */
TEST(lifecycle_context, module_telemetry_three_bank_epoch_lifetime_is_exact)
{
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	constexpr uint64_t RUNTIME_GENERATION = 13u;
	constexpr uint64_t FROM_EPOCH = 17u;
	constexpr uint64_t TO_EPOCH = 19u;
	constexpr uint16_t STAGE_INSTANCE = 4u;
	const int32_t numa_node = host.memory_numa_nodes.front();
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log, 7u, numa_node, std::size_t{1024} * 1024u);
	ASSERT_NE(owner, nullptr);
	auto channel_or = worker_telemetry_channel::create(2u, 1u, numa_node, numa_node);
	ASSERT_TRUE(channel_or.is_ok()) << channel_or.error().message();
	auto channel = std::move(channel_or).value();
	ASSERT_TRUE(owner->bind_telemetry(RUNTIME_GENERATION, STAGE_INSTANCE, *channel, true).is_ok());
	EXPECT_TRUE(owner->owns_telemetry_channel(*channel));
	auto foreign_channel_or = worker_telemetry_channel::create(2u, 1u, numa_node, numa_node);
	ASSERT_TRUE(foreign_channel_or.is_ok()) << foreign_channel_or.error().message();
	EXPECT_FALSE(owner->owns_telemetry_channel(*foreign_channel_or.value()));

	lifecycle_operation_control control(future_deadline());
	auto init_or = owner->begin_operation(lifecycle_phase::INIT, 0u, control);
	ASSERT_TRUE(init_or.is_ok()) << init_or.error().message();
	auto init = std::move(init_or).value();
	kinetum_counter_t counter = nullptr;
	kinetum_histogram_t histogram = nullptr;
	ASSERT_EQ(kinetum_lifecycle_register_counter(&init.context(), "packets", &counter), KINETUM_OK);
	ASSERT_EQ(kinetum_lifecycle_register_histogram(&init.context(), "latency", 1000u, 2, &histogram), KINETUM_OK);
	init.release();

	owner->bind_bootstrap_telemetry(FROM_EPOCH, 1u);
	KINETUM_COUNTER_ADD(counter, 7u);
	KINETUM_HISTOGRAM_RECORD_FAST(histogram, 11u);
	KINETUM_HISTOGRAM_RECORD_FAST(histogram, 29u);
	const runtime_telemetry_bank_token pressure{};
	for (std::size_t index = 0u; index < channel->capacity(); ++index) {
		ASSERT_TRUE(channel->publish_completed(pressure));
	}
	ASSERT_EQ(owner->service_telemetry_cadence(1u), runtime_telemetry_return_need::POLL_REQUIRED);
	runtime_telemetry_bank_token token{};
	for (std::size_t index = 0u; index < channel->capacity(); ++index) {
		ASSERT_TRUE(channel->take_completed(token));
	}
	ASSERT_EQ(owner->service_telemetry_cadence(1u), runtime_telemetry_return_need::EXPECTED);
	ASSERT_TRUE(channel->take_completed(token));
	auto cadence_or = owner->completed_telemetry_bank(token);
	ASSERT_TRUE(cadence_or.is_ok()) << cadence_or.error().message();
	ASSERT_EQ(cadence_or->counter_values.size(), 1u);
	ASSERT_EQ(cadence_or->histograms.size(), 1u);
	EXPECT_EQ(cadence_or->counter_values[0], 7u);
	EXPECT_EQ(cadence_or->histograms[0].total_count, 2u);
	EXPECT_EQ(cadence_or->histograms[0].min_value, 11u);
	EXPECT_EQ(cadence_or->histograms[0].max_value, 29u);
	EXPECT_EQ(cadence_or->skipped_publications, 1u);
	const auto *histogram_descriptor = owner->telemetry_descriptor(2u);
	ASSERT_NE(histogram_descriptor, nullptr);
	for (std::size_t bank = 0u; bank < LIFECYCLE_TELEMETRY_BANK_COUNT; ++bank) {
		ASSERT_NE(histogram_descriptor->histogram_counts[bank], nullptr);
		EXPECT_EQ(reinterpret_cast<std::uintptr_t>(histogram_descriptor->histogram_counts[bank]) %
				  kinetum::algo::CACHE_LINE_SIZE,
			  0u);
		if (bank != 0u) {
			const auto previous =
				reinterpret_cast<std::uintptr_t>(histogram_descriptor->histogram_counts[bank - 1u]);
			const auto current =
				reinterpret_cast<std::uintptr_t>(histogram_descriptor->histogram_counts[bank]);
			EXPECT_GE(current - previous, kinetum::algo::CACHE_LINE_SIZE);
		}
	}
	clear_completed_histograms(*owner, token);
	owner->complete_telemetry_aggregation(token);
	ASSERT_TRUE(channel->take_returned(token));
	owner->accept_returned_telemetry(token);

	owner->record_telemetry_mismatch(lifecycle_telemetry_mismatch_snapshot{
		.mismatch_count = 1u,
		.packet_epoch = TO_EPOCH,
		.active_epoch = FROM_EPOCH,
		.context_index = 7u,
		.worker_index = 2u,
		.stage_instance_index = STAGE_INSTANCE,
		.reserved = 0u,
		.region_id = 3,
		.first_fault_valid = 1u,
		.sticky_fault = 1u,
		.padding = {},
	});
	ASSERT_TRUE(owner->reserve_telemetry_epoch(FROM_EPOCH, TO_EPOCH).is_ok());
	ASSERT_TRUE(owner->preflight_activate_telemetry(FROM_EPOCH, TO_EPOCH));
	owner->activate_telemetry_epoch(FROM_EPOCH, TO_EPOCH, 2u);
	ASSERT_TRUE(channel->take_completed(token));
	ASSERT_EQ(token.reason, runtime_telemetry_publication_reason::ACTIVATION);
	ASSERT_NE(token.companion_bank_index, UINT8_MAX);
	auto activation_or = owner->completed_telemetry_bank(token);
	ASSERT_TRUE(activation_or.is_ok()) << activation_or.error().message();
	EXPECT_EQ(activation_or->counter_values[0], 7u);
	EXPECT_EQ(activation_or->mismatch.mismatch_count, 1u);
	EXPECT_EQ(activation_or->mismatch.packet_epoch, TO_EPOCH);
	clear_completed_histograms(*owner, token);
	owner->complete_telemetry_aggregation(token);
	owner->mark_telemetry_epoch_aggregated(FROM_EPOCH);
	ASSERT_TRUE(owner->telemetry_epoch_aggregated(FROM_EPOCH));
	owner->retire_telemetry_epoch(FROM_EPOCH, TO_EPOCH);
	ASSERT_TRUE(channel->take_returned(token));
	owner->accept_returned_telemetry(token);
	// The owner worker may reuse the returned bank before the coordinator
	// consumes the immutable retirement record.
	ASSERT_EQ(owner->service_telemetry_cadence(3u), runtime_telemetry_return_need::EXPECTED);
	ASSERT_TRUE(owner->take_reclaimed_telemetry_transfer(TO_EPOCH).has_value());
	ASSERT_TRUE(channel->take_completed(token));
	ASSERT_EQ(token.reason, runtime_telemetry_publication_reason::CADENCE);
	clear_completed_histograms(*owner, token);
	owner->complete_telemetry_aggregation(token);
	ASSERT_TRUE(channel->take_returned(token));
	owner->accept_returned_telemetry(token);

	ASSERT_TRUE(owner->preflight_publish_shutdown_telemetry(TO_EPOCH));
	owner->publish_shutdown_telemetry(TO_EPOCH, 4u);
	owner->mark_telemetry_worker_quiesced();
	ASSERT_TRUE(channel->take_completed(token));
	ASSERT_EQ(token.reason, runtime_telemetry_publication_reason::SHUTDOWN);
	ASSERT_NE(token.companion_bank_index, UINT8_MAX);
	clear_completed_histograms(*owner, token);
	owner->complete_telemetry_aggregation(token);
	owner->mark_telemetry_epoch_aggregated(TO_EPOCH);
	owner->retire_telemetry_epoch(TO_EPOCH, 0u);
	EXPECT_TRUE(owner->telemetry_empty());
	owner->unbind_telemetry();
}

/** @brief Validate health normalization, suppression, and immutable first-fault evidence. */
TEST(lifecycle_context, module_health_publication_is_coherent_bounded_and_fault_exact)
{
	const auto host = quark::probe_host();
	ASSERT_TRUE(host.valid);
	ASSERT_FALSE(host.memory_numa_nodes.empty());
	constexpr uint64_t RUNTIME_GENERATION = 13u;
	constexpr uint64_t EPOCH = 17u;
	constexpr uint16_t STAGE_INSTANCE = 4u;
	const int32_t numa_node = host.memory_numa_nodes.front();
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log, 7u, numa_node, std::size_t{1024} * 1024u);
	ASSERT_NE(owner, nullptr);
	auto channel_or = worker_telemetry_channel::create(2u, 1u, numa_node, numa_node);
	ASSERT_TRUE(channel_or.is_ok()) << channel_or.error().message();
	auto channel = std::move(channel_or).value();
	ASSERT_TRUE(owner->bind_telemetry(RUNTIME_GENERATION, STAGE_INSTANCE, *channel, true).is_ok());
	ASSERT_TRUE(owner->claim_module_health_owner(RUNTIME_GENERATION, STAGE_INSTANCE).is_ok());
	owner->bind_bootstrap_telemetry(EPOCH, 1u);

	kinetum_health_assessment healthy{};
	healthy.health_score = 97u;
	healthy.flags = static_cast<uint32_t>(KINETUM_HEALTH_F_DEGRADED);
	std::memset(healthy._padding, 0xa5, sizeof(healthy._padding));
	std::memset(healthy.reason, 'x', sizeof(healthy.reason));
	std::memcpy(healthy.reason, "warming", sizeof("warming"));
	owner->publish_module_health_attempt(healthy, {
							      .epoch = EPOCH,
							      .timestamp_ns = 10u,
							      .duration_ns = 3u,
							      .callback_budget_ns = 5u,
						      });
	lifecycle_module_health_observation observed{};
	ASSERT_TRUE(owner->try_read_module_health(observed));
	EXPECT_EQ(observed.publication_generation, 1u);
	EXPECT_EQ(observed.runtime_generation, RUNTIME_GENERATION);
	EXPECT_EQ(observed.observation_epoch, EPOCH);
	EXPECT_EQ(observed.observed_at_ns, 10u);
	EXPECT_EQ(observed.callback_duration_ns, 3u);
	EXPECT_EQ(observed.contract_fault_count, 0u);
	EXPECT_EQ(observed.latest_fault_mask, 0u);
	EXPECT_EQ(observed.signal_available, 1u);
	EXPECT_EQ(observed.signal.assessment.health_score, 97u);
	EXPECT_EQ(observed.signal.assessment.flags, KINETUM_HEALTH_F_DEGRADED);
	EXPECT_STREQ(observed.signal.assessment.reason, "warming");
	const std::array<unsigned char, sizeof(healthy._padding)> zero_padding{};
	EXPECT_EQ(std::memcmp(observed.signal.assessment._padding, zero_padding.data(), zero_padding.size()), 0);
	EXPECT_TRUE(std::all_of(observed.signal.assessment.reason + sizeof("warming"),
				observed.signal.assessment.reason + KINETUM_HEALTH_REASON_CAPACITY,
				[](char value) { return value == '\0'; }));
	EXPECT_EQ(observed.signal.epoch, EPOCH);
	EXPECT_EQ(observed.signal.timestamp_ns, 10u);
	ASSERT_EQ(owner->service_telemetry_cadence(13u), runtime_telemetry_return_need::EXPECTED);
	runtime_telemetry_bank_token cadence_token{};
	ASSERT_TRUE(channel->take_completed(cadence_token));
	EXPECT_EQ(cadence_token.published_at_ns, 13u);
	ASSERT_TRUE(owner->completed_telemetry_bank(cadence_token).is_ok());
	owner->complete_telemetry_aggregation(cadence_token);
	ASSERT_TRUE(channel->take_returned(cadence_token));
	owner->accept_returned_telemetry(cadence_token);

	kinetum_health_assessment malformed{};
	malformed.health_score = 101u;
	malformed.flags = UINT32_C(0x80000000);
	std::memset(malformed.reason, 'x', sizeof(malformed.reason));
	owner->publish_module_health_attempt(malformed, {
								.epoch = EPOCH,
								.timestamp_ns = 20u,
								.duration_ns = 6u,
								.callback_budget_ns = 5u,
							});
	ASSERT_TRUE(owner->try_read_module_health(observed));
	const uint16_t expected_faults =
		static_cast<uint16_t>(static_cast<uint16_t>(lifecycle_module_health_fault::SCORE_OUT_OF_RANGE) |
				      static_cast<uint16_t>(lifecycle_module_health_fault::UNKNOWN_FLAGS) |
				      static_cast<uint16_t>(lifecycle_module_health_fault::UNTERMINATED_REASON) |
				      static_cast<uint16_t>(lifecycle_module_health_fault::CALLBACK_BUDGET_EXCEEDED));
	EXPECT_EQ(observed.publication_generation, 2u);
	EXPECT_EQ(observed.observation_epoch, EPOCH);
	EXPECT_EQ(observed.observed_at_ns, 20u);
	EXPECT_EQ(observed.latest_fault_mask, expected_faults);
	EXPECT_EQ(observed.first_fault_mask, expected_faults);
	EXPECT_EQ(observed.contract_fault_count, 1u);
	EXPECT_EQ(observed.first_fault_epoch, EPOCH);
	EXPECT_EQ(observed.first_fault_timestamp_ns, 20u);
	EXPECT_EQ(observed.first_fault_duration_ns, 6u);
	EXPECT_EQ(observed.signal_available, 0u);
	const std::array<unsigned char, sizeof(kinetum_health_signal)> zero_signal{};
	EXPECT_EQ(std::memcmp(&observed.signal, zero_signal.data(), zero_signal.size()), 0);

	owner->publish_module_health_attempt(healthy, {
							      .epoch = EPOCH,
							      .timestamp_ns = 30u,
							      .duration_ns = 2u,
							      .callback_budget_ns = 5u,
						      });
	ASSERT_TRUE(owner->try_read_module_health(observed));
	EXPECT_EQ(observed.publication_generation, 3u);
	EXPECT_EQ(observed.latest_fault_mask, 0u);
	EXPECT_EQ(observed.first_fault_mask, expected_faults);
	EXPECT_EQ(observed.contract_fault_count, 1u);
	EXPECT_EQ(observed.signal_available, 1u);
	EXPECT_EQ(observed.signal.timestamp_ns, 30u);

	ASSERT_TRUE(owner->preflight_publish_shutdown_telemetry(EPOCH));
	owner->publish_shutdown_telemetry(EPOCH, 31u);
	owner->mark_telemetry_worker_quiesced();
	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(channel->take_completed(token));
	ASSERT_TRUE(owner->completed_telemetry_bank(token).is_ok());
	owner->complete_telemetry_aggregation(token);
	owner->mark_telemetry_epoch_aggregated(EPOCH);
	owner->retire_telemetry_epoch(EPOCH, 0u);
	EXPECT_TRUE(owner->telemetry_empty());
	owner->release_module_health_owner();
	EXPECT_FALSE(owner->claim_module_health_owner(RUNTIME_GENERATION, STAGE_INSTANCE).is_ok());
	owner->unbind_telemetry();
}

/** @brief Verify exact arena bump allocation, alignment, zeroing, and exhaustion. */
TEST(lifecycle_context, epoch_arena_is_fixed_aligned_and_single_epoch)
{
	test_memory_provider memory;
	auto arena_or = epoch_arena_ownership::create(memory, 7, 41, 0, 256, 64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	auto arena = std::move(arena_or).value();

	auto first = arena.allocate(17, 8, false);
	ASSERT_TRUE(first.is_ok()) << first.error().message();
	auto second = arena.allocate(32, 32, true);
	ASSERT_TRUE(second.is_ok()) << second.error().message();
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(first.value()) % 8u, 0u);
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(second.value()) % 32u, 0u);
	const auto *bytes = static_cast<const unsigned char *>(second.value());
	for (std::size_t i = 0; i < 32; ++i) {
		EXPECT_EQ(bytes[i], 0u);
	}
	EXPECT_FALSE(arena.allocate(256, 8, false).is_ok());
	EXPECT_EQ(arena.context_index(), 7u);
	EXPECT_EQ(arena.epoch(), 41u);
	EXPECT_EQ(arena.numa_node(), 0);
	EXPECT_EQ(arena.capacity(), 256u);
}

/** @brief Verify malformed arena allocation claims are reclaimed before ownership. */
TEST(lifecycle_context, epoch_arena_rejects_wrong_numa_and_weak_alignment_claims)
{
	test_memory_provider memory;
	memory.set_wrong_numa(true);
	EXPECT_FALSE(epoch_arena_ownership::create(memory, 7, 41, 0, 256, 64).is_ok());
	EXPECT_EQ(memory.active_count(), 0u);
	memory.set_wrong_numa(false);
	memory.set_weak_alignment(true);
	EXPECT_FALSE(epoch_arena_ownership::create(memory, 7, 41, 0, 256, 64).is_ok());
	EXPECT_EQ(memory.active_count(), 0u);
	EXPECT_EQ(memory.release_count(), 2u);
}

/** @brief Verify PREPARE accepts only the owner's exact context, epoch, and NUMA arena. */
TEST(lifecycle_context, prepare_operation_requires_exact_arena_identity)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log, 7, 0);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(future_deadline());

	auto wrong_or = epoch_arena_ownership::create(memory, 8, 41, 0, 256, 64);
	ASSERT_TRUE(wrong_or.is_ok()) << wrong_or.error().message();
	auto wrong = std::move(wrong_or).value();
	EXPECT_FALSE(owner->begin_operation(lifecycle_phase::PREPARE, 41, control, &wrong).is_ok());

	auto exact_or = epoch_arena_ownership::create(memory, 7, 41, 0, 256, 64);
	ASSERT_TRUE(exact_or.is_ok()) << exact_or.error().message();
	auto exact = std::move(exact_or).value();
	auto operation_or = owner->begin_operation(lifecycle_phase::PREPARE, 41, control, &exact);
	ASSERT_TRUE(operation_or.is_ok()) << operation_or.error().message();
	auto operation = std::move(operation_or).value();
	EXPECT_EQ(lifecycle_current_epoch(operation.context()), 41u);
	EXPECT_TRUE(lifecycle_allocate_epoch(operation.context(), 16, 8, true).is_ok());
}

/** @brief Verify PMR context storage cannot grow after INIT and is reclaimed during FINI. */
TEST(lifecycle_context, context_memory_resource_seals_and_reclaims_exact_allocations)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(future_deadline());
	auto init_or = owner->begin_operation(lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(init_or.is_ok()) << init_or.error().message();
	auto init = std::move(init_or).value();
	std::optional<lifecycle_context_operation> fini;
	const std::size_t platform_allocations = memory.active_count();

	{
		kinetum::sdk::context_memory_resource resource(&init.context());
		std::pmr::vector<uint64_t> values(&resource);
		values.reserve(8);
		values.push_back(41);
		EXPECT_EQ(memory.active_count(), platform_allocations + 1u);

		resource.seal();
		EXPECT_THROW(values.reserve(16), std::bad_alloc);
		init.release();

		auto fini_or = owner->begin_operation(lifecycle_phase::FINI, 0, control);
		ASSERT_TRUE(fini_or.is_ok()) << fini_or.error().message();
		fini.emplace(std::move(fini_or).value());
		resource.begin_reclamation(&fini->context());
	}

	ASSERT_TRUE(fini.has_value());
	fini->release();
	EXPECT_EQ(memory.active_count(), platform_allocations);
	EXPECT_EQ(memory.invalid_release_count(), 0u);
}

/** @brief Verify the authored aggregate context limit maps to exact ABI exhaustion. */
TEST(lifecycle_context, context_memory_rejects_the_first_byte_above_authored_capacity)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(future_deadline());
	auto init_or = owner->begin_operation(lifecycle_phase::INIT, 0, control);
	ASSERT_TRUE(init_or.is_ok()) << init_or.error().message();
	auto init = std::move(init_or).value();

	void *first = nullptr;
	ASSERT_EQ(kinetum_lifecycle_allocate_context(&init.context(), TEST_CONTEXT_MEMORY_CAPACITY_BYTES, 64,
						     KINETUM_LIFECYCLE_ALLOC_ZERO, &first),
		  KINETUM_OK);
	ASSERT_NE(first, nullptr);
	void *overflow = nullptr;
	EXPECT_EQ(kinetum_lifecycle_allocate_context(&init.context(), 1, 1, 0, &overflow), KINETUM_ERR_NO_MEMORY);
	EXPECT_EQ(overflow, nullptr);
	EXPECT_EQ(kinetum_lifecycle_release_context(&init.context(), first), KINETUM_OK);
}

/** @brief Verify PMR prepared storage is bounded by and retained with its exact epoch arena. */
TEST(lifecycle_context, epoch_memory_resource_seals_without_heap_fallback)
{
	test_memory_provider memory;
	test_log_provider log;
	auto owner = make_owner(memory, log);
	ASSERT_NE(owner, nullptr);
	lifecycle_operation_control control(future_deadline());
	const std::size_t platform_allocations = memory.active_count();

	{
		auto arena_or = epoch_arena_ownership::create(memory, 7, 41, 0, 256, 64);
		ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
		auto arena = std::move(arena_or).value();
		auto prepare_or = owner->begin_operation(lifecycle_phase::PREPARE, 41, control, &arena);
		ASSERT_TRUE(prepare_or.is_ok()) << prepare_or.error().message();
		auto prepare = std::move(prepare_or).value();

		kinetum::sdk::epoch_memory_resource resource(&prepare.context());
		std::pmr::vector<uint64_t> values(&resource);
		values.reserve(8);
		values.push_back(41);
		EXPECT_GT(arena.bytes_used(), 0u);

		resource.seal();
		EXPECT_THROW(values.reserve(16), std::bad_alloc);
		prepare.release();
		EXPECT_EQ(memory.active_count(), platform_allocations + 1u);
	}

	EXPECT_EQ(memory.active_count(), platform_allocations);
	EXPECT_EQ(memory.invalid_release_count(), 0u);
}

/** @brief Verify explicit success permits null handles and exact retirement remains mandatory. */
TEST(lifecycle_context, prepared_token_accepts_null_values_and_retires_exactly_once)
{
	auto token_or = prepared_config_ownership::create(3, 7, 41, {});
	ASSERT_TRUE(token_or.is_ok()) << token_or.error().message();
	auto token = std::move(token_or).value();
	ASSERT_TRUE(token.owns_state());
	auto record_or = token.borrow_exact(3, 7, 41);
	ASSERT_TRUE(record_or.is_ok()) << record_or.error().message();
	EXPECT_EQ(record_or.value().owner_handle, nullptr);
	EXPECT_EQ(record_or.value().packet_config, nullptr);
	EXPECT_FALSE(token.retire_exact(3, 8, 41).is_ok());
	EXPECT_TRUE(token.owns_state());
	EXPECT_TRUE(token.retire_exact(3, 7, 41).is_ok());
	EXPECT_FALSE(token.owns_state());
	EXPECT_FALSE(token.retire_exact(3, 7, 41).is_ok());
}

/** @brief Verify token moves retain the arena and live-token destruction is fatal. */
TEST(lifecycle_context, prepared_token_transfers_arena_and_fails_on_unretired_destruction)
{
	test_memory_provider memory;
	auto arena_or = epoch_arena_ownership::create(memory, 7, 41, 0, 256, 64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	std::optional<epoch_arena_ownership> arena;
	arena.emplace(std::move(arena_or).value());
	int module_state = 0;
	auto token_or = prepared_config_ownership::create(3, 7, 41, {&module_state, nullptr}, std::move(arena));
	ASSERT_TRUE(token_or.is_ok()) << token_or.error().message();
	auto token = std::move(token_or).value();
	auto moved = std::move(token);
	EXPECT_FALSE(token.owns_state());
	EXPECT_TRUE(moved.owns_state());
	ASSERT_NE(moved.arena(), nullptr);
	EXPECT_EQ(memory.active_count(), 1u);
	EXPECT_TRUE(moved.retire_exact(3, 7, 41).is_ok());
	EXPECT_EQ(memory.active_count(), 0u);

	EXPECT_DEATH(
		{
			auto leaked_or = prepared_config_ownership::create(3, 7, 99, {});
			if (!leaked_or.is_ok()) {
				std::_Exit(1);
			}
			auto leaked = std::move(leaked_or).value();
			(void)leaked;
		},
		"");
}

}  // namespace kinetum::dp::lifecycle
