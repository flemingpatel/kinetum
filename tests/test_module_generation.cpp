// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_module_generation.cpp
 * @brief Atomic generation admission and production lifecycle-adapter tests.
 * @author Fleming Patel
 *
 * These tests exercise exact canonical image authority, deterministic
 * generation indices, single-definition schema dependencies, all-or-nothing
 * context publication, image capability gates, prepared ownership, unload,
 * and foreign-callback serialization. No test constructs a packet runtime or
 * emulates an epoch-slot store.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "src/common/status.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/lifecycle/prepared_config_ownership.hpp"
#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/module/module_lifecycle_adapter.hpp"
#include "src/dp/module/module_manager.hpp"
#include "src/modules/acl/acl.pb.h"
#include "tests/module_abi_test_harness.hpp"

namespace kinetum::dp::module
{

namespace
{

/** Explicit lifecycle-memory authority shared by generation fixtures. */
constexpr kinetum::test::module_test_resource_contract TEST_MODULE_RESOURCES{
	64u * 1024u * 1024u,
	2u * 1024u * 1024u,
};

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::dp::lifecycle::epoch_arena_ownership;
using kinetum::dp::lifecycle::lifecycle_context_identity;
using kinetum::dp::lifecycle::lifecycle_operation_control;
using kinetum::dp::lifecycle::lifecycle_phase;
using kinetum::dp::lifecycle::lifecycle_prepare_callback_code;
using kinetum::dp::lifecycle::prepared_config_ownership;

/** @return Passive test-module identity and its compiled image path. */
module_image_spec passive_image()
{
	return {"test_module", std::filesystem::path(KINETUM_TEST_MODULE_PATH)};
}

/** @return Active test-module identity and its compiled image path. */
module_image_spec active_image()
{
	return {"kinetum.test_active", std::filesystem::path(KINETUM_TEST_ACTIVE_MODULE_PATH)};
}

/**
 * @brief Return the exact active image lacking replication authority.
 * @return Canonical active-async image identity and path.
 */
module_image_spec nonreplicable_active_image()
{
	return {"kinetum.test_active_async", std::filesystem::path(KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH)};
}

/** @return Serialization-test module identity and its compiled image path. */
module_image_spec serialized_image()
{
	return {"kinetum.test.serialized", std::filesystem::path(KINETUM_TEST_SERIALIZED_MODULE_PATH)};
}

/**
 * @brief Return the exact built-in ACL image authority.
 *
 * @return Canonical ACL image identity and path.
 */
module_image_spec acl_image()
{
	return {"kinetum.acl", std::filesystem::path(KINETUM_ACL_MODULE_PATH)};
}

/**
 * @brief Return the exact built-in NAT44 image authority.
 *
 * @return Canonical NAT44 image identity and path.
 */
module_image_spec nat44_image()
{
	return {"kinetum.nat44", std::filesystem::path(KINETUM_NAT44_MODULE_PATH)};
}

/**
 * @brief Return the exact built-in QoS image authority.
 *
 * @return Canonical QoS image identity and path.
 */
module_image_spec qos_image()
{
	return {"kinetum.qos", std::filesystem::path(KINETUM_QOS_MODULE_PATH)};
}

/**
 * @brief Prove no loader reference retains one exact image.
 *
 * @param path Exact canonical image path expected to be absent.
 */
void expect_image_unloaded(const std::filesystem::path &path)
{
	dlerror();
	void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
	const char *error = dlerror();
	EXPECT_EQ(handle, nullptr) << path << ": " << (error != nullptr ? error : "image remains loaded");
	if (handle != nullptr) {
		EXPECT_EQ(dlclose(handle), 0);
	}
}

/**
 * @brief Build one exact module-context authority record.
 *
 * @param context_id Executable context identity.
 * @param module_id Exact image identity.
 * @param resources Exact lifecycle-memory bounds authored by the test.
 * @param ordinal Canonical ordinal within this module's context population.
 * @param count Exact number of contexts sharing the same module configuration.
 * @param context_index Compiled executable-context index.
 * @param worker_index Sole owner-worker index.
 * @param cpu_core_id Exact owner logical CPU.
 * @param numa_node Exact owner NUMA node.
 * @return Complete admitted context specification.
 */
module_context_spec context_spec(std::string context_id, std::string module_id,
				 kinetum::test::module_test_resource_contract resources, uint32_t ordinal,
				 uint32_t count, uint32_t context_index = 0, uint32_t worker_index = 0,
				 int32_t cpu_core_id = 0, int32_t numa_node = 0)
{
	return {
		.context_instance_id = std::move(context_id),
		.module_id = std::move(module_id),
		.context_index = context_index,
		.worker_index = worker_index,
		.cpu_core_id = cpu_core_id,
		.numa_node = numa_node,
		.context_memory_capacity_bytes = resources.context_memory_capacity_bytes,
		.epoch_arena_capacity_bytes = resources.epoch_arena_capacity_bytes,
		.module_context_ordinal = ordinal,
		.module_context_count = count,
	};
}

/** @brief Owner set whose declaration order preserves manager prerequisites. */
struct generation_environment {
	/** @brief Construct one bounded callback-control interval. */
	generation_environment()
		: control(std::chrono::steady_clock::now() + std::chrono::seconds(5))
	{
	}

	kinetum::test::module_test_memory_provider memory;  ///< Exact allocation authority.
	kinetum::test::module_test_log_provider log;	    ///< Exact diagnostic authority.
	lifecycle_operation_control control;		    ///< INIT admission control.
	module_manager manager;				    ///< Destroyed before providers.
};

/** @brief Deterministic provider that fails one selected allocation attempt. */
class fail_on_allocation_provider final : public kinetum::dp::lifecycle::lifecycle_memory_provider {
    public:
	/**
	 * @brief Select the one-based allocation attempt that must fail.
	 * @param failure_attempt One-based allocation ordinal to reject.
	 */
	explicit fail_on_allocation_provider(std::size_t failure_attempt) noexcept
		: failure_attempt_(failure_attempt)
	{
	}

	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::allocate */
	[[nodiscard]] kinetum::common::status_or<kinetum::dp::lifecycle::lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept override
	{
		++allocation_attempts_;
		if (allocation_attempts_ == failure_attempt_) {
			return status::resource_exhausted("injected module INIT allocation failure");
		}

		const auto slot = std::find(active_.begin(), active_.end(), nullptr);
		if (slot == active_.end()) {
			return status::resource_exhausted("module rollback test allocation ledger is full");
		}
		const std::size_t effective_alignment = std::max(alignment, sizeof(void *));
		void *pointer = nullptr;
		if (posix_memalign(&pointer, effective_alignment, size) != 0) {
			return status::resource_exhausted("module rollback test allocation failed");
		}
		std::memset(pointer, zero_initialize ? 0 : 0xa5, size);
		*slot = pointer;
		++successful_allocations_;
		return kinetum::dp::lifecycle::lifecycle_memory_block{
			pointer, size, effective_alignment, numa_node, {}};
	}

	/** @copydoc kinetum::dp::lifecycle::lifecycle_memory_provider::release */
	void release(kinetum::dp::lifecycle::lifecycle_memory_block block) noexcept override
	{
		const auto slot = std::find(active_.begin(), active_.end(), block.data);
		if (slot == active_.end()) {
			std::terminate();
		}
		*slot = nullptr;
		std::free(block.data);
		++releases_;
	}

	/** @return Number of allocation attempts observed by the fixture. */
	[[nodiscard]] std::size_t allocation_attempts() const noexcept
	{
		return allocation_attempts_;
	}

	/** @return Number of allocations that returned owned blocks. */
	[[nodiscard]] std::size_t successful_allocations() const noexcept
	{
		return successful_allocations_;
	}

	/** @return Number of exact owned blocks released. */
	[[nodiscard]] std::size_t releases() const noexcept
	{
		return releases_;
	}

	/** @return Number of tracked blocks whose ownership remains outstanding. */
	[[nodiscard]] std::size_t outstanding_blocks() const noexcept
	{
		return static_cast<std::size_t>(std::count_if(active_.begin(), active_.end(),
							      [](const void *pointer) { return pointer != nullptr; }));
	}

    private:
	/** Fixed fixture capacity for simultaneously outstanding allocations. */
	static constexpr std::size_t MAX_TRACKED_BLOCKS = 8;
	std::array<void *, MAX_TRACKED_BLOCKS> active_{};  ///< Exact live blocks.
	std::size_t failure_attempt_{0};		   ///< One-based failure point.
	std::size_t allocation_attempts_{0};		   ///< Total allocation calls.
	std::size_t successful_allocations_{0};		   ///< Successful allocations.
	std::size_t releases_{0};			   ///< Exact release calls.
};

/**
 * @brief Execute and retire one explicit no-op configuration lifecycle.
 *
 * @param context Exact admitted context.
 * @param adapter Production adapter for @p context.
 * @param memory Exact arena-memory authority.
 * @param epoch Exact nonzero test epoch.
 * @return OK after PREPARE and RETIRE, or a pre-RETIRE setup error.
 */
[[nodiscard]] status exercise_noop_prepare_retire(module_context_instance &context, module_lifecycle_adapter &adapter,
						  kinetum::dp::lifecycle::lifecycle_memory_provider &memory,
						  uint64_t epoch)
{
	auto arena_or = epoch_arena_ownership::create(memory, context.context_index, epoch,
						      context.lifecycle_owner->identity().numa_node,
						      context.lifecycle_owner->epoch_arena_capacity_bytes(), 64);
	if (!arena_or.is_ok()) {
		return arena_or.error();
	}
	auto arena = std::move(arena_or).value();
	lifecycle_operation_control prepare_control(std::chrono::steady_clock::now() + std::chrono::milliseconds(250));
	auto prepare_or =
		context.lifecycle_owner->begin_operation(lifecycle_phase::PREPARE, epoch, prepare_control, &arena);
	if (!prepare_or.is_ok()) {
		return prepare_or.error();
	}
	auto prepare = std::move(prepare_or).value();
	const auto result = adapter.prepare(prepare.context(), nullptr, 0);
	prepare.release();
	if (result.code != lifecycle_prepare_callback_code::SUCCESS) {
		return status(status_code::MODULE_ERROR, "unrelated module image failed no-op PREPARE");
	}

	auto token_or = prepared_config_ownership::create(context.image->module_image_index, context.context_index,
							  epoch, result.prepared, std::move(arena));
	if (!token_or.is_ok()) {
		return token_or.error();
	}
	auto token = std::move(token_or).value();
	lifecycle_operation_control retire_control(std::chrono::steady_clock::now() + std::chrono::milliseconds(250));
	auto retire_or = context.lifecycle_owner->begin_operation(lifecycle_phase::RETIRE, epoch, retire_control);
	if (!retire_or.is_ok()) {
		// The accepted ownership token cannot be discarded or made retired
		// without executing the module callback exactly once.
		std::terminate();
	}
	auto retire = std::move(retire_or).value();
	adapter.retire(retire.context(), result.prepared);
	retire.release();
	return token.retire_exact(context.image->module_image_index, context.context_index, epoch);
}

/** @brief Remove one test-created filesystem entry on every test exit path. */
class scoped_path_cleanup {
    public:
	/**
	 * @brief Adopt one path that may or may not have been created.
	 * @param path Fixture-owned entry to remove at scope exit.
	 */
	explicit scoped_path_cleanup(std::filesystem::path path)
		: path_(std::move(path))
	{
	}

	scoped_path_cleanup(const scoped_path_cleanup &) = delete;
	scoped_path_cleanup &operator=(const scoped_path_cleanup &) = delete;

	/** @brief Remove the adopted entry without throwing from test cleanup. */
	~scoped_path_cleanup()
	{
		std::error_code ignored;
		std::filesystem::remove(path_, ignored);
	}

    private:
	std::filesystem::path path_;  ///< Test-created path to remove once.
};

/** @brief Reject a generation that has no complete image/context authority. */
TEST(module_generation, rejects_empty_generation)
{
	generation_environment environment;
	const status result =
		environment.manager.admit_generation({}, {}, environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_FALSE(environment.manager.has_generation());
	EXPECT_EQ(environment.manager.image_count(), 0u);
	EXPECT_EQ(environment.manager.context_count(), 0u);
}

/** @brief Reject malformed or duplicate image identities before loading code. */
TEST(module_generation, rejects_malformed_or_duplicate_module_ids)
{
	{
		generation_environment malformed;
		const std::string invalid_id("test\0module", 11);
		const status result = malformed.manager.admit_generation(
			{{invalid_id, passive_image().canonical_path}},
			{context_spec("module@lane_0", invalid_id, TEST_MODULE_RESOURCES, 0u, 1u)}, malformed.memory,
			malformed.log, malformed.control);

		EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
		EXPECT_NE(result.message().find("printable-ASCII"), std::string::npos);
		EXPECT_FALSE(malformed.manager.has_generation());
	}

	generation_environment environment;
	auto first = passive_image();
	auto duplicate = first;
	const status result = environment.manager.admit_generation(
		{first, duplicate}, {context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.message().find("duplicate module_id"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Reject malformed or duplicate executable context identities atomically. */
TEST(module_generation, rejects_malformed_or_duplicate_context_ids)
{
	{
		generation_environment malformed;
		const std::string invalid_id("module@lane_0\0alias", 19);
		const status result = malformed.manager.admit_generation(
			{passive_image()}, {context_spec(invalid_id, "test_module", TEST_MODULE_RESOURCES, 0u, 1u)},
			malformed.memory, malformed.log, malformed.control);

		EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
		EXPECT_NE(result.message().find("printable-ASCII"), std::string::npos);
		EXPECT_FALSE(malformed.manager.has_generation());
	}

	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image()},
		{context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 2u, 0),
		 context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 1u, 2u, 1)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.message().find("duplicate context_instance_id"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Reject duplicate compact context indices atomically. */
TEST(module_generation, rejects_duplicate_context_indices)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image()},
		{context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 2u, 7),
		 context_spec("module@lane_1", "test_module", TEST_MODULE_RESOURCES, 1u, 2u, 7)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.message().find("duplicate context_index"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Reject an image omitted from the complete context relation. */
TEST(module_generation, rejects_unreferenced_image)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image(), active_image()},
		{context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u)}, environment.memory,
		environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.message().find("has no admitted context"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Reject a context that names no image in the generation. */
TEST(module_generation, rejects_unknown_image_reference)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image()},
		{context_spec("module@lane_0", "kinetum.test.unknown", TEST_MODULE_RESOURCES, 0u, 1u)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_NE(result.message().find("references unknown image"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Reject relative image authority without repairing or searching it. */
TEST(module_generation, rejects_relative_image_path)
{
	generation_environment environment;
	module_image_spec relative{"test_module", "libkinetum_test_module.so"};
	const status result = environment.manager.admit_generation(
		{relative}, {context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::INVALID_ARGUMENT);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Reject a symlink representation even when its target is canonical. */
TEST(module_generation, rejects_symbolic_link_image_path)
{
	static std::atomic<uint64_t> sequence{0};
	const auto suffix = sequence.fetch_add(1, std::memory_order_relaxed);
	const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
	const auto link =
		std::filesystem::temp_directory_path() /
		("kinetum_module_generation_" + std::to_string(timestamp) + "_" + std::to_string(suffix) + ".so");
	scoped_path_cleanup cleanup(link);
	std::error_code error;
	std::filesystem::create_symlink(passive_image().canonical_path, link, error);
	ASSERT_FALSE(error) << error.message();

	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{{"test_module", link}}, {context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::FAILED_PRECONDITION);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Assign image indices from sorted identity, never input order. */
TEST(module_generation, assigns_deterministic_sorted_image_indices)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image(), active_image()},
		{context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u, 4),
		 context_spec("active@lane_0", "kinetum.test_active", TEST_MODULE_RESOURCES, 0u, 1u, 2)},
		environment.memory, environment.log, environment.control);
	ASSERT_TRUE(result.is_ok()) << result.message();

	ASSERT_NE(environment.manager.image(0), nullptr);
	ASSERT_NE(environment.manager.image(1), nullptr);
	EXPECT_EQ(environment.manager.image(0)->module_id, "kinetum.test_active");
	EXPECT_EQ(environment.manager.image(1)->module_id, "test_module");
	EXPECT_EQ(environment.manager.image("kinetum.test_active")->module_image_index, 0u);
	EXPECT_EQ(environment.manager.image("test_module")->module_image_index, 1u);
}

/** @brief Keep host authoring schemas independent of unloadable runtime images. */
TEST(module_generation, host_authoring_schema_is_independent_of_runtime_image)
{
	kinetum::module::acl::v1::AclRuleset host_ruleset;
	host_ruleset.set_default_action(kinetum::module::acl::v1::ACL_ACTION_PERMIT);
	ASSERT_FALSE(host_ruleset.SerializeAsString().empty());

	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{acl_image()}, {context_spec("acl@lane_0", "kinetum.acl", TEST_MODULE_RESOURCES, 0u, 1u, 0, 0, 0, 0)},
		environment.memory, environment.log, environment.control);
	ASSERT_TRUE(result.is_ok()) << result.message();
	ASSERT_NE(environment.manager.image("kinetum.acl"), nullptr);
	EXPECT_EQ(environment.manager.image_count(), 1u);
	EXPECT_EQ(environment.manager.context_count(), 1u);

	kinetum::module::acl::v1::AclRuleset second_ruleset;
	ASSERT_TRUE(second_ruleset.ParseFromString(host_ruleset.SerializeAsString()));
	EXPECT_EQ(second_ruleset.default_action(), kinetum::module::acl::v1::ACL_ACTION_PERMIT);
}

/** @brief Prove completed generations release every exact main image. */
TEST(module_generation, base_namespace_exact_images_are_reclaimable)
{
	constexpr std::size_t GENERATION_ADMISSION_COUNT = 3;
	for (std::size_t admission = 0; admission < GENERATION_ADMISSION_COUNT; ++admission) {
		{
			generation_environment environment;
			const status result = environment.manager.admit_generation(
				{acl_image(), nat44_image(), qos_image()},
				{context_spec("acl@lane_0", "kinetum.acl", TEST_MODULE_RESOURCES, 0u, 1u, 0, 0, 0, 0),
				 context_spec("nat44@lane_0", "kinetum.nat44", TEST_MODULE_RESOURCES, 0u, 1u, 1, 0, 0,
					      0),
				 context_spec("qos@lane_0", "kinetum.qos", TEST_MODULE_RESOURCES, 0u, 1u, 2, 0, 0, 0)},
				environment.memory, environment.log, environment.control);
			ASSERT_TRUE(result.is_ok()) << "admission=" << admission << " error=" << result.message();
		}
		expect_image_unloaded(std::filesystem::path(KINETUM_ACL_MODULE_PATH));
		expect_image_unloaded(std::filesystem::path(KINETUM_NAT44_MODULE_PATH));
		expect_image_unloaded(std::filesystem::path(KINETUM_QOS_MODULE_PATH));
	}
}

/** @brief Treat one byte-for-byte authority retry as an idempotent no-op. */
TEST(module_generation, accepts_exact_generation_retry)
{
	generation_environment environment;
	const std::vector<module_image_spec> images{passive_image()};
	const std::vector<module_context_spec> contexts{
		context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u, 3, 2, 5, 0)};
	ASSERT_TRUE(
		environment.manager
			.admit_generation(images, contexts, environment.memory, environment.log, environment.control)
			.is_ok());
	const auto *image_before = environment.manager.image("test_module");
	const auto *context_before = environment.manager.context(3);

	const status retry = environment.manager.admit_generation(images, contexts, environment.memory, environment.log,
								  environment.control);
	EXPECT_TRUE(retry.is_ok()) << retry.message();
	EXPECT_EQ(environment.manager.image("test_module"), image_before);
	EXPECT_EQ(environment.manager.context(3), context_before);
}

/** @brief Reject a retry whose lifecycle-memory authority differs by one field. */
TEST(module_generation, rejects_generation_retry_with_different_memory_capacity)
{
	generation_environment environment;
	const std::vector<module_image_spec> images{passive_image()};
	const std::vector<module_context_spec> contexts{
		context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u, 3, 2, 5, 0)};
	ASSERT_TRUE(
		environment.manager
			.admit_generation(images, contexts, environment.memory, environment.log, environment.control)
			.is_ok());
	const auto *context_before = environment.manager.context(3);

	auto changed_context = contexts.front();
	++changed_context.epoch_arena_capacity_bytes;
	const status retry = environment.manager.admit_generation(
		images, {std::move(changed_context)}, environment.memory, environment.log, environment.control);
	EXPECT_EQ(retry.code(), status_code::FAILED_PRECONDITION);
	EXPECT_EQ(environment.manager.context(3), context_before);
}

/** @brief A retained generation never remaps context ordinals or changes its population. */
TEST(module_generation, rejects_context_population_change_before_mutation)
{
	fail_on_allocation_provider memory(SIZE_MAX);
	kinetum::test::module_test_log_provider log;
	lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	module_manager manager;
	const std::vector<module_image_spec> images{passive_image()};
	const std::vector<module_context_spec> contexts{
		context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 2u, 2, 0, 0),
		context_spec("module@lane_1", "test_module", TEST_MODULE_RESOURCES, 1u, 2u, 7, 1, 1),
	};
	const auto admitted = manager.admit_generation(images, contexts, memory, log, control);
	ASSERT_TRUE(admitted.is_ok()) << admitted.message();
	const auto *first = manager.context(2u);
	const auto *second = manager.context(7u);
	const auto allocations = memory.allocation_attempts();
	const auto logs = log.write_count();
	for (const bool change_population : {false, true}) {
		auto changed = contexts;
		if (change_population) {
			changed[0].module_context_count = 3u;
			changed[1].module_context_count = 3u;
		} else {
			std::swap(changed[0].module_context_ordinal, changed[1].module_context_ordinal);
		}
		const auto retry = manager.admit_generation(images, changed, memory, log, control);
		EXPECT_EQ(retry.code(), status_code::FAILED_PRECONDITION);
		EXPECT_EQ(manager.context(2u), first);
		EXPECT_EQ(manager.context(7u), second);
		EXPECT_EQ(memory.allocation_attempts(), allocations);
		EXPECT_EQ(log.write_count(), logs);
	}
}

/** @brief Reject a different second generation without altering publication. */
TEST(module_generation, rejects_different_second_generation)
{
	generation_environment environment;
	ASSERT_TRUE(environment.manager
			    .admit_generation(
				    {passive_image()},
				    {context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u, 3)},
				    environment.memory, environment.log, environment.control)
			    .is_ok());
	const auto *original = environment.manager.context(3);

	const status second = environment.manager.admit_generation(
		{passive_image()}, {context_spec("module@lane_1", "test_module", TEST_MODULE_RESOURCES, 0u, 1u, 4)},
		environment.memory, environment.log, environment.control);
	EXPECT_EQ(second.code(), status_code::FAILED_PRECONDITION);
	EXPECT_EQ(environment.manager.context(3), original);
	EXPECT_EQ(environment.manager.context(4), nullptr);
	EXPECT_EQ(environment.manager.context_count(), 1u);
}

/** @brief Reject multiple contexts for an image lacking replication authority. */
TEST(module_generation, rejects_nonreplicable_image_contexts)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{nonreplicable_active_image()},
		{context_spec("active@lane_0", "kinetum.test_active_async", TEST_MODULE_RESOURCES, 0u, 2u, 0),
		 context_spec("active@lane_1", "kinetum.test_active_async", TEST_MODULE_RESOURCES, 1u, 2u, 1, 1, 1)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(result.message().find("KINETUM_MOD_F_REPLICABLE_CONTEXTS"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Admit distinct mutable contexts for a replicable image. */
TEST(module_generation, admits_replicable_image_contexts)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image()},
		{context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 2u, 2, 4, 6),
		 context_spec("module@lane_1", "test_module", TEST_MODULE_RESOURCES, 1u, 2u, 7, 5, 8)},
		environment.memory, environment.log, environment.control);
	ASSERT_TRUE(result.is_ok()) << result.message();

	ASSERT_NE(environment.manager.context(2), nullptr);
	ASSERT_NE(environment.manager.context(7), nullptr);
	EXPECT_NE(environment.manager.context(2), environment.manager.context(7));
	EXPECT_NE(environment.manager.context(2)->packet_context.state,
		  environment.manager.context(7)->packet_context.state);
	EXPECT_EQ(environment.manager.context_count(), 2u);
}

/** @brief Give every admitted context one distinct initially empty epoch store. */
TEST(module_generation, admitted_contexts_own_distinct_empty_epoch_stores)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image()},
		{context_spec("module@lane_1", "test_module", TEST_MODULE_RESOURCES, 1u, 2u, 7, 1, 8),
		 context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 2u, 2, 0, 6)},
		environment.memory, environment.log, environment.control);
	ASSERT_TRUE(result.is_ok()) << result.message();

	auto *first = environment.manager.context(2);
	auto *second = environment.manager.context(7);
	ASSERT_NE(first, nullptr);
	ASSERT_NE(second, nullptr);
	ASSERT_NE(first->epoch_store, nullptr);
	ASSERT_NE(second->epoch_store, nullptr);
	EXPECT_NE(first->epoch_store.get(), second->epoch_store.get());
	EXPECT_TRUE(first->epoch_store->empty());
	EXPECT_TRUE(second->epoch_store->empty());
	EXPECT_EQ(first->epoch_store->active_view(), nullptr);
	EXPECT_EQ(second->epoch_store->active_view(), nullptr);
}

/** @brief Enumerate the generation in deterministic compact-context order. */
TEST(module_generation, context_ordinals_follow_sorted_context_indices)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{passive_image()},
		{context_spec("module@lane_1", "test_module", TEST_MODULE_RESOURCES, 1u, 2u, 9, 1, 8),
		 context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 2u, 1, 0, 6)},
		environment.memory, environment.log, environment.control);
	ASSERT_TRUE(result.is_ok()) << result.message();

	ASSERT_NE(environment.manager.context_at_ordinal(0), nullptr);
	ASSERT_NE(environment.manager.context_at_ordinal(1), nullptr);
	EXPECT_EQ(environment.manager.context_at_ordinal(0), environment.manager.context(1));
	EXPECT_EQ(environment.manager.context_at_ordinal(1), environment.manager.context(9));
	EXPECT_EQ(environment.manager.context_at_ordinal(2), nullptr);
}

/** @brief Roll back prior INIT and partial state when a later INIT fails. */
TEST(module_generation, later_context_init_failure_rolls_back_atomically)
{
	// Each context first owns one platform telemetry registry. The test module's
	// INIT then requests one state block and one histogram-bank block. Failing
	// request five reaches the later context's state after the first context is
	// fully live and the later registry exists.
	fail_on_allocation_provider memory(5);
	kinetum::test::module_test_log_provider log;
	lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	module_manager manager;
	const status result = manager.admit_generation(
		{passive_image()},
		{context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 2u, 0),
		 context_spec("module@lane_1", "test_module", TEST_MODULE_RESOURCES, 1u, 2u, 1, 1, 1)},
		memory, log, control);

	EXPECT_EQ(result.code(), status_code::MODULE_ERROR);
	EXPECT_NE(result.message().find("module INIT failed"), std::string::npos);
	EXPECT_FALSE(manager.has_generation());
	EXPECT_EQ(manager.image_count(), 0u);
	EXPECT_EQ(manager.context_count(), 0u);
	EXPECT_EQ(log.write_count(), 3u);
	EXPECT_EQ(log.last_message(), "test_module.fini");
	EXPECT_EQ(memory.allocation_attempts(), 5u);
	EXPECT_EQ(memory.successful_allocations(), 4u);
	EXPECT_EQ(memory.releases(), 4u);
	EXPECT_EQ(memory.outstanding_blocks(), 0u);
}

/** @brief Prepare, activate, retire, and consume one exact production artifact. */
TEST(module_generation, production_adapter_preserves_exact_prepared_ownership)
{
	generation_environment environment;
	ASSERT_TRUE(environment.manager
			    .admit_generation(
				    {passive_image()},
				    {context_spec("module@lane_0", "test_module", TEST_MODULE_RESOURCES, 0u, 1u, 3)},
				    environment.memory, environment.log, environment.control)
			    .is_ok());
	auto *context = environment.manager.context(3);
	ASSERT_NE(context, nullptr);
	auto adapter_or = environment.manager.make_lifecycle_adapter(3);
	ASSERT_TRUE(adapter_or.is_ok()) << adapter_or.error().message();
	auto adapter = std::move(adapter_or).value();

	// Reusing compact indices does not make a different context identity valid.
	lifecycle_context_identity wrong_identity{"test_module",
						  "other@lane_0",
						  context->image->module_image_index,
						  context->context_index,
						  0,
						  0,
						  0,
						  0u,
						  1u};
	auto wrong_owner_or = kinetum::dp::lifecycle::lifecycle_context_owner::create(
		std::move(wrong_identity), context->lifecycle_owner->context_memory_capacity_bytes(),
		context->lifecycle_owner->epoch_arena_capacity_bytes(), environment.memory, environment.log);
	ASSERT_TRUE(wrong_owner_or.is_ok()) << wrong_owner_or.error().message();
	auto wrong_owner = std::move(wrong_owner_or).value();
	auto wrong_arena_or = epoch_arena_ownership::create(environment.memory, context->context_index, 40, 0,
							    wrong_owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(wrong_arena_or.is_ok()) << wrong_arena_or.error().message();
	auto wrong_arena = std::move(wrong_arena_or).value();
	lifecycle_operation_control wrong_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto wrong_operation_or =
		wrong_owner->begin_operation(lifecycle_phase::PREPARE, 40, wrong_control, &wrong_arena);
	ASSERT_TRUE(wrong_operation_or.is_ok()) << wrong_operation_or.error().message();
	auto wrong_operation = std::move(wrong_operation_or).value();
	const auto wrong_result = adapter->prepare(wrong_operation.context(), nullptr, 0);
	wrong_operation.release();
	EXPECT_EQ(wrong_result.code, lifecycle_prepare_callback_code::FAILURE);

	auto arena_or = epoch_arena_ownership::create(environment.memory, 3, 41, 0,
						      context->lifecycle_owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	auto arena = std::move(arena_or).value();
	lifecycle_operation_control prepare_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto prepare_operation_or =
		context->lifecycle_owner->begin_operation(lifecycle_phase::PREPARE, 41, prepare_control, &arena);
	ASSERT_TRUE(prepare_operation_or.is_ok()) << prepare_operation_or.error().message();
	auto prepare_operation = std::move(prepare_operation_or).value();
	const std::string_view payload = "{\"drop\":false}";
	const auto prepared = adapter->prepare(prepare_operation.context(), payload.data(), payload.size());
	prepare_operation.release();
	ASSERT_EQ(prepared.code, lifecycle_prepare_callback_code::SUCCESS);
	ASSERT_NE(prepared.prepared.packet_config, nullptr);

	auto token_or = prepared_config_ownership::create(context->image->module_image_index, context->context_index,
							  41, prepared.prepared, std::move(arena));
	ASSERT_TRUE(token_or.is_ok()) << token_or.error().message();
	auto token = std::move(token_or).value();
	const kinetum_prepared_config activation{prepared.prepared.owner_handle, prepared.prepared.packet_config};
	context->image->descriptor->activate_config(&context->packet_context, 41, &activation);

	lifecycle_operation_control retire_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto retire_operation_or =
		context->lifecycle_owner->begin_operation(lifecycle_phase::RETIRE, 41, retire_control);
	ASSERT_TRUE(retire_operation_or.is_ok()) << retire_operation_or.error().message();
	auto retire_operation = std::move(retire_operation_or).value();
	adapter->retire(retire_operation.context(), prepared.prepared);
	retire_operation.release();
	EXPECT_TRUE(token.retire_exact(context->image->module_image_index, context->context_index, 41).is_ok());
}

/** @brief Preserve null/null PREPARE success as explicit token state. */
TEST(module_generation, production_adapter_preserves_noop_success_state)
{
	generation_environment environment;
	ASSERT_TRUE(environment.manager
			    .admit_generation({active_image()},
					      {context_spec("active@lane_0", "kinetum.test_active",
							    TEST_MODULE_RESOURCES, 0u, 1u, 5)},
					      environment.memory, environment.log, environment.control)
			    .is_ok());
	auto *context = environment.manager.context(5);
	ASSERT_NE(context, nullptr);
	auto adapter_or = environment.manager.make_lifecycle_adapter(5);
	ASSERT_TRUE(adapter_or.is_ok()) << adapter_or.error().message();
	auto adapter = std::move(adapter_or).value();

	auto arena_or = epoch_arena_ownership::create(environment.memory, 5, 73, 0,
						      context->lifecycle_owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(arena_or.is_ok()) << arena_or.error().message();
	auto arena = std::move(arena_or).value();
	lifecycle_operation_control prepare_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto prepare_operation_or =
		context->lifecycle_owner->begin_operation(lifecycle_phase::PREPARE, 73, prepare_control, &arena);
	ASSERT_TRUE(prepare_operation_or.is_ok()) << prepare_operation_or.error().message();
	auto prepare_operation = std::move(prepare_operation_or).value();
	const auto prepared = adapter->prepare(prepare_operation.context(), nullptr, 0);
	prepare_operation.release();
	ASSERT_EQ(prepared.code, lifecycle_prepare_callback_code::SUCCESS);
	EXPECT_EQ(prepared.prepared.owner_handle, nullptr);
	EXPECT_EQ(prepared.prepared.packet_config, nullptr);

	auto token_or = prepared_config_ownership::create(context->image->module_image_index, context->context_index,
							  73, prepared.prepared, std::move(arena));
	ASSERT_TRUE(token_or.is_ok()) << token_or.error().message();
	auto token = std::move(token_or).value();
	EXPECT_TRUE(token.owns_state());
	lifecycle_operation_control retire_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto retire_operation_or =
		context->lifecycle_owner->begin_operation(lifecycle_phase::RETIRE, 73, retire_control);
	ASSERT_TRUE(retire_operation_or.is_ok()) << retire_operation_or.error().message();
	auto retire_operation = std::move(retire_operation_or).value();
	adapter->retire(retire_operation.context(), prepared.prepared);
	retire_operation.release();
	EXPECT_TRUE(token.retire_exact(context->image->module_image_index, context->context_index, 73).is_ok());
}

/** @brief Serialize one image while an unrelated image continues lifecycle work. */
TEST(module_generation, production_adapters_share_image_serialization)
{
	generation_environment environment;
	ASSERT_TRUE(environment.manager
			    .admit_generation({serialized_image(), active_image()},
					      {context_spec("serialized@lane_0", "kinetum.test.serialized",
							    TEST_MODULE_RESOURCES, 0u, 2u, 2),
					       context_spec("serialized@lane_1", "kinetum.test.serialized",
							    TEST_MODULE_RESOURCES, 1u, 2u, 7, 1, 1),
					       context_spec("active@lane_0", "kinetum.test_active",
							    TEST_MODULE_RESOURCES, 0u, 1u, 11, 2, 2)},
					      environment.memory, environment.log, environment.control)
			    .is_ok());
	auto *first_context = environment.manager.context(2);
	auto *second_context = environment.manager.context(7);
	auto *unrelated_context = environment.manager.context(11);
	ASSERT_NE(first_context, nullptr);
	ASSERT_NE(second_context, nullptr);
	ASSERT_NE(unrelated_context, nullptr);
	auto first_adapter_or = environment.manager.make_lifecycle_adapter(2);
	auto second_adapter_or = environment.manager.make_lifecycle_adapter(7);
	auto unrelated_adapter_or = environment.manager.make_lifecycle_adapter(11);
	ASSERT_TRUE(first_adapter_or.is_ok()) << first_adapter_or.error().message();
	ASSERT_TRUE(second_adapter_or.is_ok()) << second_adapter_or.error().message();
	ASSERT_TRUE(unrelated_adapter_or.is_ok()) << unrelated_adapter_or.error().message();
	auto first_adapter = std::move(first_adapter_or).value();
	auto second_adapter = std::move(second_adapter_or).value();
	auto unrelated_adapter = std::move(unrelated_adapter_or).value();

	using reset_fn = void (*)();
	using hold_fn = void (*)(bool);
	using read_fn = uint32_t (*)();
	auto reset_or = first_context->image->dynamic_library.symbol("kinetum_test_serialized_reset");
	auto hold_first_or = first_context->image->dynamic_library.symbol("kinetum_test_serialized_hold_first");
	auto prepare_entries_or =
		first_context->image->dynamic_library.symbol("kinetum_test_serialized_prepare_entries");
	auto max_active_or = first_context->image->dynamic_library.symbol("kinetum_test_serialized_max_active");
	ASSERT_TRUE(reset_or.is_ok()) << reset_or.error().to_string();
	ASSERT_TRUE(hold_first_or.is_ok()) << hold_first_or.error().to_string();
	ASSERT_TRUE(prepare_entries_or.is_ok()) << prepare_entries_or.error().to_string();
	ASSERT_TRUE(max_active_or.is_ok()) << max_active_or.error().to_string();
	auto *reset = reinterpret_cast<reset_fn>(reset_or.value());
	auto *hold_first = reinterpret_cast<hold_fn>(hold_first_or.value());
	auto *prepare_entries = reinterpret_cast<read_fn>(prepare_entries_or.value());
	auto *max_active = reinterpret_cast<read_fn>(max_active_or.value());
	ASSERT_NE(reset, nullptr);
	ASSERT_NE(hold_first, nullptr);
	ASSERT_NE(prepare_entries, nullptr);
	ASSERT_NE(max_active, nullptr);
	reset();
	{
		auto malformed_arena_or = epoch_arena_ownership::create(
			environment.memory, 2, 80, 0, first_context->lifecycle_owner->epoch_arena_capacity_bytes(), 64);
		ASSERT_TRUE(malformed_arena_or.is_ok()) << malformed_arena_or.error().message();
		auto malformed_arena = std::move(malformed_arena_or).value();
		lifecycle_operation_control malformed_control(std::chrono::steady_clock::now() +
							      std::chrono::seconds(5));
		auto malformed_operation_or = first_context->lifecycle_owner->begin_operation(
			lifecycle_phase::PREPARE, 80, malformed_control, &malformed_arena);
		ASSERT_TRUE(malformed_operation_or.is_ok()) << malformed_operation_or.error().message();
		auto malformed_operation = std::move(malformed_operation_or).value();
		const uint8_t addressed_empty_payload = 0;
		const auto malformed =
			first_adapter->prepare(malformed_operation.context(), &addressed_empty_payload, 0);
		malformed_operation.release();
		EXPECT_EQ(malformed.code, lifecycle_prepare_callback_code::FAILURE);
		EXPECT_EQ(prepare_entries(), 0u);
	}
	hold_first(true);

	std::atomic<uint32_t> first_state{0};
	std::optional<prepared_config_ownership> first_token;
	std::thread first_thread([&] {
		auto arena_or = epoch_arena_ownership::create(
			environment.memory, 2, 81, 0, first_context->lifecycle_owner->epoch_arena_capacity_bytes(), 64);
		if (!arena_or.is_ok()) {
			first_state.store(1, std::memory_order_release);
			return;
		}
		auto arena = std::move(arena_or).value();
		lifecycle_operation_control control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
		auto operation_or =
			first_context->lifecycle_owner->begin_operation(lifecycle_phase::PREPARE, 81, control, &arena);
		if (!operation_or.is_ok()) {
			first_state.store(2, std::memory_order_release);
			return;
		}
		auto operation = std::move(operation_or).value();
		const auto result = first_adapter->prepare(operation.context(), nullptr, 0);
		operation.release();
		if (result.code != lifecycle_prepare_callback_code::SUCCESS) {
			first_state.store(4, std::memory_order_release);
			return;
		}
		auto token_or = prepared_config_ownership::create(first_context->image->module_image_index,
								  first_context->context_index, 81, result.prepared,
								  std::move(arena));
		if (!token_or.is_ok()) {
			first_state.store(5, std::memory_order_release);
			return;
		}
		first_token.emplace(std::move(token_or).value());
		first_state.store(3, std::memory_order_release);
	});

	const bool first_entered = [&] {
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
		while (std::chrono::steady_clock::now() < deadline) {
			if (prepare_entries() == 1u) {
				return true;
			}
			if (first_state.load(std::memory_order_acquire) != 0u) {
				return false;
			}
			std::this_thread::yield();
		}
		return prepare_entries() == 1u;
	}();
	if (!first_entered) {
		hold_first(false);
		first_thread.join();
		FAIL() << "first serialization callback did not enter";
	}

	const status unrelated_status =
		exercise_noop_prepare_retire(*unrelated_context, *unrelated_adapter, environment.memory, 81);

	auto blocked_arena_or = epoch_arena_ownership::create(
		environment.memory, 7, 81, 0, second_context->lifecycle_owner->epoch_arena_capacity_bytes(), 64);
	if (!blocked_arena_or.is_ok()) {
		hold_first(false);
		first_thread.join();
		FAIL() << blocked_arena_or.error().message();
	}
	auto blocked_arena = std::move(blocked_arena_or).value();
	lifecycle_operation_control blocked_control(std::chrono::steady_clock::now() + std::chrono::milliseconds(20));
	auto blocked_operation_or = second_context->lifecycle_owner->begin_operation(lifecycle_phase::PREPARE, 81,
										     blocked_control, &blocked_arena);
	if (!blocked_operation_or.is_ok()) {
		hold_first(false);
		first_thread.join();
		FAIL() << blocked_operation_or.error().message();
	}
	auto blocked_operation = std::move(blocked_operation_or).value();
	const auto blocked = second_adapter->prepare(blocked_operation.context(), nullptr, 0);
	blocked_operation.release();
	EXPECT_EQ(blocked.code, lifecycle_prepare_callback_code::FAILURE);
	EXPECT_EQ(prepare_entries(), 1u);
	EXPECT_EQ(max_active(), 1u);

	hold_first(false);
	first_thread.join();
	EXPECT_TRUE(unrelated_status.is_ok()) << unrelated_status.message();
	ASSERT_EQ(first_state.load(std::memory_order_acquire), 3u);
	ASSERT_TRUE(first_token.has_value());
	lifecycle_operation_control first_retire_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto first_retire_or =
		first_context->lifecycle_owner->begin_operation(lifecycle_phase::RETIRE, 81, first_retire_control);
	ASSERT_TRUE(first_retire_or.is_ok()) << first_retire_or.error().message();
	auto first_retire = std::move(first_retire_or).value();
	const auto first_record_or =
		first_token->borrow_exact(first_context->image->module_image_index, first_context->context_index, 81);
	ASSERT_TRUE(first_record_or.is_ok()) << first_record_or.error().message();
	first_adapter->retire(first_retire.context(), first_record_or.value());
	first_retire.release();
	ASSERT_TRUE(
		first_token->retire_exact(first_context->image->module_image_index, first_context->context_index, 81)
			.is_ok());
	first_token.reset();

	auto second_arena_or = epoch_arena_ownership::create(
		environment.memory, 7, 82, 0, second_context->lifecycle_owner->epoch_arena_capacity_bytes(), 64);
	ASSERT_TRUE(second_arena_or.is_ok()) << second_arena_or.error().message();
	auto second_arena = std::move(second_arena_or).value();
	lifecycle_operation_control second_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto second_operation_or = second_context->lifecycle_owner->begin_operation(lifecycle_phase::PREPARE, 82,
										    second_control, &second_arena);
	ASSERT_TRUE(second_operation_or.is_ok()) << second_operation_or.error().message();
	auto second_operation = std::move(second_operation_or).value();
	const auto second = second_adapter->prepare(second_operation.context(), nullptr, 0);
	second_operation.release();
	ASSERT_EQ(second.code, lifecycle_prepare_callback_code::SUCCESS);
	auto second_token_or = prepared_config_ownership::create(second_context->image->module_image_index,
								 second_context->context_index, 82, second.prepared,
								 std::move(second_arena));
	ASSERT_TRUE(second_token_or.is_ok()) << second_token_or.error().message();
	auto second_token = std::move(second_token_or).value();
	lifecycle_operation_control second_retire_control(std::chrono::steady_clock::now() + std::chrono::seconds(5));
	auto second_retire_or =
		second_context->lifecycle_owner->begin_operation(lifecycle_phase::RETIRE, 82, second_retire_control);
	ASSERT_TRUE(second_retire_or.is_ok()) << second_retire_or.error().message();
	auto second_retire = std::move(second_retire_or).value();
	second_adapter->retire(second_retire.context(), second.prepared);
	second_retire.release();
	ASSERT_TRUE(
		second_token.retire_exact(second_context->image->module_image_index, second_context->context_index, 82)
			.is_ok());
	EXPECT_EQ(prepare_entries(), 2u);
	EXPECT_EQ(max_active(), 1u);
}

/** @brief Reject a module compiled for an older exact ABI revision. */
TEST(module_generation, rejects_older_module_abi)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{{"kinetum.test.abi_older", std::filesystem::path(KINETUM_TEST_OLDER_ABI_MODULE_PATH)}},
		{context_spec("older@lane_0", "kinetum.test.abi_older", TEST_MODULE_RESOURCES, 0u, 1u)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(result.message().find("module ABI version mismatch"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

/** @brief Reject a module compiled for a newer exact ABI revision. */
TEST(module_generation, rejects_newer_module_abi)
{
	generation_environment environment;
	const status result = environment.manager.admit_generation(
		{{"kinetum.test.abi_newer", std::filesystem::path(KINETUM_TEST_NEWER_ABI_MODULE_PATH)}},
		{context_spec("newer@lane_0", "kinetum.test.abi_newer", TEST_MODULE_RESOURCES, 0u, 1u)},
		environment.memory, environment.log, environment.control);

	EXPECT_EQ(result.code(), status_code::FAILED_PRECONDITION);
	EXPECT_NE(result.message().find("module ABI version mismatch"), std::string::npos);
	EXPECT_FALSE(environment.manager.has_generation());
}

}  // namespace

}  // namespace kinetum::dp::module
