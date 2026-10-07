// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_worker_input_scheduler.cpp
 * @brief Exact input binding, NUMA ownership, and carried-allowance lifecycle tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/worker_input_scheduler.hpp"
#include "src/quark/host_probe.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Require real allocatable NUMA evidence before constructing worker state. */
class WorkerInputSchedulerTest : public ::testing::Test {
    protected:
	/** @brief Resolve one process-available memory node; unavailable proof fails the test. */
	void SetUp() override
	{
		const auto host = quark::probe_host();
		ASSERT_TRUE(host.valid);
		ASSERT_FALSE(host.memory_numa_nodes.empty());
		numa_node_ = host.memory_numa_nodes.front();
	}
	int32_t numa_node_{-1};	 ///< Exact host memory node proved by SetUp.
};

/** @brief Retire both test queue roles even if a later assertion fails. */
class staging_cleanup final {
    public:
	/**
	 * @brief Borrow the staging owner until the cleanup guard is destroyed.
	 * @param staging Exact owner with active and future roles and no live reservation.
	 */
	explicit staging_cleanup(worker_epoch_input_staging<uint32_t> &staging) noexcept
		: staging_(staging)
	{
	}
	/** @brief Drain old and future values without changing their ownership outside the fixture. */
	~staging_cleanup()
	{
		std::array<uint32_t, 8> values{};
		while (staging_.pop_active_batch(values.data(), values.size()) != 0u) {
		}
		staging_.rotate_after_activation();
		while (staging_.pop_active_batch(values.data(), values.size()) != 0u) {
		}
	}
	/** @brief Cleanup ownership cannot be copied. */
	staging_cleanup(const staging_cleanup &) = delete;
	/** @brief Cleanup ownership cannot be copy-assigned. */
	staging_cleanup &operator=(const staging_cleanup &) = delete;

    private:
	worker_epoch_input_staging<uint32_t> &staging_;	 ///< Both roles remain alive until after this guard.
};

}  // namespace

/** @brief Invalid identities, quanta, ordering, and NUMA input reject before allocation. */
TEST(worker_input_scheduler, malformed_bindings_reject)
{
	constexpr worker_input_binding VALID{{worker_input_kind::RX_STREAM, 0u}, 64u};
	EXPECT_FALSE(worker_input_scheduler::create({}, -1).is_ok());
	const std::array<worker_input_binding, 5> invalid{{
		{{static_cast<worker_input_kind>(0u), 0u}, 64u},
		{{worker_input_kind::RX_STREAM, std::numeric_limits<uint32_t>::max()}, 64u},
		{{worker_input_kind::RX_STREAM, 0u}, 0u},
		{{worker_input_kind::RX_STREAM, 0u}, 65u},
		{{static_cast<worker_input_kind>(3u), 0u}, 64u},
	}};
	for (const auto &binding : invalid) {
		EXPECT_FALSE(worker_input_scheduler::create({&binding, 1u}, 0).is_ok());
	}
	const std::array<worker_input_binding, 2> duplicate{VALID, VALID};
	EXPECT_FALSE(worker_input_scheduler::create(duplicate, 0).is_ok());
	const std::array<worker_input_binding, 2> reversed{{{{worker_input_kind::BOUNDARY, 0u}, 64u}, VALID}};
	EXPECT_FALSE(worker_input_scheduler::create(reversed, 0).is_ok());
}

/** @brief Input-free workers retain a valid owner and perform no admission call. */
TEST_F(WorkerInputSchedulerTest, empty_schedule_performs_no_service)
{
	auto owner_or = worker_input_scheduler::create({}, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	uint32_t calls = 0u;
	owner_or.value()->service([&](const worker_input_endpoint &, uint16_t) noexcept {
		++calls;
		return algo::service_result{};
	});
	EXPECT_EQ(calls, 0u);
}

/** @brief RX and boundary ordinals share fair admission without losing their distinct namespaces. */
TEST_F(WorkerInputSchedulerTest, mixed_inputs_preserve_identity_and_exact_burst_limits)
{
	constexpr std::array<worker_input_binding, 3> BINDINGS{{
		{{worker_input_kind::RX_STREAM, 0u}, 4u},
		{{worker_input_kind::RX_STREAM, 1u}, 7u},
		{{worker_input_kind::BOUNDARY, 0u}, 3u},
	}};
	auto owner_or = worker_input_scheduler::create(BINDINGS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	std::array<uint32_t, 3> totals{};
	for (uint32_t turn = 0u; turn < 140u; ++turn) {
		uint16_t capacity = 1u;
		owner_or.value()->service([&](const worker_input_endpoint &input, uint16_t offered) noexcept {
			const uint32_t index = input.kind == worker_input_kind::RX_STREAM ? input.ordinal : 2u;
			EXPECT_EQ(input.kind, BINDINGS[index].endpoint.kind);
			EXPECT_EQ(input.ordinal, BINDINGS[index].endpoint.ordinal);
			EXPECT_LE(offered, BINDINGS[index].quantum);
			const uint16_t accepted = std::min(capacity, offered);
			capacity = static_cast<uint16_t>(capacity - accepted);
			totals[index] += accepted;
			return algo::service_result{accepted, algo::service_disposition::RETAINED};
		});
		EXPECT_EQ(capacity, 0u);
	}
	EXPECT_EQ(totals, (std::array<uint32_t, 3>{40u, 70u, 30u}));
}

/** @brief Role rotation and STOP cannot let allowance bookkeeping own, execute, or erase staged values. */
TEST_F(WorkerInputSchedulerTest, carried_allowance_survives_role_swap_and_retires_on_stop)
{
	constexpr std::array<worker_input_binding, 2> BINDINGS{{
		{{worker_input_kind::RX_STREAM, 0u}, 8u},
		{{worker_input_kind::BOUNDARY, 0u}, 8u},
	}};
	auto owner_or = worker_input_scheduler::create(BINDINGS, numa_node_);
	ASSERT_TRUE(owner_or.is_ok()) << owner_or.error().message();
	auto staging_or = worker_epoch_input_staging<uint32_t>::create(8u, std::optional<std::size_t>(8u), numa_node_);
	ASSERT_TRUE(staging_or.is_ok()) << staging_or.error().message();
	auto &staging = *staging_or.value();
	staging_cleanup cleanup(staging);
	for (uint32_t index = 0u; index < 4u; ++index) {
		ASSERT_TRUE(staging.reserve_active());
		staging.commit_active(uint32_t{1u});
	}
	uint32_t active_epoch = 1u;
	uint32_t source_epoch = 1u;
	uint16_t source_remaining = 16u;
	bool stopping = false;
	uint16_t last_rx_allowance = 0u;
	const auto admit = [&](const worker_input_endpoint &input, uint16_t allowance) noexcept {
		if (input.kind == worker_input_kind::BOUNDARY || stopping) {
			return algo::service_result{};
		}
		last_rx_allowance = allowance;
		const bool future = source_epoch != active_epoch;
		const auto available = future ? staging.future_available() : staging.active_available();
		const auto requested = static_cast<uint16_t>(std::min<std::size_t>(available, allowance));
		uint16_t admitted = 0u;
		while (admitted < std::min(requested, source_remaining)) {
			const bool reserved = future ? staging.reserve_future() : staging.reserve_active();
			if (!reserved) {
				break;
			}
			if (future) {
				staging.commit_future(uint32_t{source_epoch});
			} else {
				staging.commit_active(uint32_t{source_epoch});
			}
			++admitted;
		}
		source_remaining = static_cast<uint16_t>(source_remaining - admitted);
		return algo::service_result{admitted, admitted < requested ? algo::service_disposition::YIELDED :
									     algo::service_disposition::RETAINED};
	};
	owner_or.value()->service(admit);
	EXPECT_EQ(last_rx_allowance, 8u);
	std::array<uint32_t, 8> values{};
	EXPECT_EQ(staging.pop_active_batch(values.data(), values.size()), 8u);
	EXPECT_TRUE(std::all_of(values.begin(), values.end(), [](uint32_t epoch) { return epoch == 1u; }));
	source_epoch = 2u;
	source_remaining = 8u;
	owner_or.value()->service(admit);
	EXPECT_TRUE(staging.active_empty());
	EXPECT_FALSE(staging.future_empty());
	ASSERT_TRUE(staging.activation_ready());
	staging.rotate_after_activation();
	active_epoch = 2u;
	EXPECT_TRUE(staging.future_empty());
	stopping = true;
	owner_or.value()->service(admit);
	EXPECT_EQ(staging.pop_active_batch(values.data(), values.size()), 8u);
	EXPECT_TRUE(std::all_of(values.begin(), values.end(), [](uint32_t epoch) { return epoch == 2u; }));
	EXPECT_TRUE(staging.empty());

	// STOP is terminal for this owner; only a newly constructed generation resumes RX.
	owner_or.value().reset();
	auto replacement_or = worker_input_scheduler::create(BINDINGS, numa_node_);
	ASSERT_TRUE(replacement_or.is_ok()) << replacement_or.error().message();
	stopping = false;
	source_remaining = 1u;
	replacement_or.value()->service(admit);
	EXPECT_EQ(last_rx_allowance, 8u);
}

}  // namespace kinetum::dp
