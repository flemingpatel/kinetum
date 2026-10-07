// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_runtime_telemetry_aggregator.cpp
 * @brief Cold immutable-bank aggregation and identity-wall tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "src/common/runtime_sizing.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/module/module_runtime_generation.hpp"
#include "src/dp/runtime_status.hpp"
#include "src/dp/runtime_telemetry_aggregator.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/dp/worker_telemetry_channel.hpp"
#include "src/quark/host_probe.hpp"
#include "tests/packet_runtime_test_fixture.hpp"

#ifndef KINETUM_TEST_MODULE_PATH
#error "KINETUM_TEST_MODULE_PATH must be defined by CMake"
#endif

#ifndef KINETUM_TEST_SERIALIZED_MODULE_PATH
#error "KINETUM_TEST_SERIALIZED_MODULE_PATH must be defined by CMake"
#endif

namespace kinetum::dp
{
namespace
{

/** Runtime identity shared by all aggregated owners. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 23u;
/** Initial worker/module telemetry epoch. */
constexpr uint64_t TEST_BOOTSTRAP_EPOCH = 5u;
/** Target epoch receiving activated telemetry banks. */
constexpr uint64_t TEST_TARGET_EPOCH = 9u;
/** Context-memory authority supplied to the optional module fixture. */
constexpr uint64_t TEST_CONTEXT_MEMORY_CAPACITY_BYTES = 64u * 1024u;
/** Epoch-arena authority supplied to the optional module fixture. */
constexpr uint64_t TEST_EPOCH_ARENA_CAPACITY_BYTES = 64u * 1024u;

/** @brief Production-compiled module-free topology with one telemetry owner. */
class aggregate_fixture final {
    public:
	/**
	 * @brief Construct one module-free or exact single-module aggregate fixture.
	 * @param with_module Whether one passive module context is present.
	 * @param with_health_callback Whether that module implements owner health.
	 * @return Complete fixture or exact host/planner/allocation failure.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<aggregate_fixture>>
	create(bool with_module = false, bool with_health_callback = true)
	{
		if (!with_module && !with_health_callback) {
			return common::status::invalid_argument(
				"module-free telemetry fixture cannot select a module callback shape");
		}
		const auto host = quark::probe_host();
		auto selection_or = test::packet_runtime_fixture_detail::select_host(host);
		if (!selection_or.is_ok()) {
			return selection_or.error();
		}
		auto rx_or = test::packet_runtime_fixture_detail::udp_port_reservation::create();
		if (!rx_or.is_ok()) {
			return rx_or.error();
		}
		auto rx = std::move(rx_or).value();
		auto tx_or = test::packet_runtime_fixture_detail::udp_port_reservation::create();
		if (!tx_or.is_ok()) {
			return tx_or.error();
		}
		auto tx = std::move(tx_or).value();
		if (rx.port() == tx.port()) {
			return common::status::unavailable("telemetry test could not reserve distinct UDP identities");
		}
		const std::optional<std::string> module_id =
			with_module ? std::optional<std::string>{with_health_callback ? "test_module" :
											"kinetum.test.serialized"} :
				      std::nullopt;
		auto compiled_or = test::packet_runtime_fixture_detail::compile_runtime_fixture(
			test::packet_runtime_fixture_detail::make_pipeline(module_id), selection_or.value(), rx.port(),
			tx.port(), with_module ? TEST_CONTEXT_MEMORY_CAPACITY_BYTES : 0u,
			with_module ? TEST_EPOCH_ARENA_CAPACITY_BYTES : 0u);
		if (!compiled_or.is_ok()) {
			return compiled_or.error();
		}

		auto fixture = std::unique_ptr<aggregate_fixture>(new (std::nothrow) aggregate_fixture());
		if (fixture == nullptr) {
			return common::status::resource_exhausted("failed to allocate telemetry aggregate fixture");
		}
		fixture->compiled_ = std::move(compiled_or).value();
		if (fixture->compiled_.topology.transition_topology.workers.size() != 1u ||
		    fixture->compiled_.topology.worker_schedules.size() != 1u ||
		    fixture->compiled_.topology.module_contexts.size() != (with_module ? 1u : 0u) ||
		    !fixture->compiled_.topology.transition_topology.lifecycle_services.has_value()) {
			return common::status::failed_precondition(
				"telemetry aggregate fixture requires one exact worker and requested module shape");
		}
		std::vector<module::module_image_spec> module_images;
		if (with_module) {
			module_images.push_back(
				{*module_id, with_health_callback ?
						     std::filesystem::path(KINETUM_TEST_MODULE_PATH) :
						     std::filesystem::path(KINETUM_TEST_SERIALIZED_MODULE_PATH)});
		}
		auto modules_or = module::module_runtime_generation::create(fixture->compiled_.topology,
									    std::move(module_images));
		if (!modules_or.is_ok()) {
			return modules_or.error();
		}
		fixture->modules_ = std::move(modules_or).value();
		const auto &transition = fixture->compiled_.topology.transition_topology;
		const auto &worker = transition.workers.front();
		const auto coordinator_index = transition.lifecycle_services->coordinator_service_index;
		if (coordinator_index >= transition.runtime_services.size()) {
			return common::status::internal_error("telemetry aggregate coordinator identity is invalid");
		}
		auto channel_or =
			worker_telemetry_channel::create(worker.worker_index, with_module ? 1u : 0u, worker.numa_node,
							 transition.runtime_services[coordinator_index].numa_node);
		if (!channel_or.is_ok()) {
			return channel_or.error();
		}
		fixture->channel_ = std::move(channel_or).value();
		const auto cadence = std::chrono::duration_cast<std::chrono::nanoseconds>(worker.health_poll_interval);
		if (cadence.count() <= 0) {
			return common::status::failed_precondition("telemetry aggregate cadence is not representable");
		}
		const auto &schedule = fixture->compiled_.topology.worker_schedules.front();
		std::vector<uint32_t> stream_indices;
		std::merge(schedule.rx_stream_indices.begin(), schedule.rx_stream_indices.end(),
			   schedule.tx_stream_indices.begin(), schedule.tx_stream_indices.end(),
			   std::back_inserter(stream_indices));
		auto worker_or = worker_runtime_telemetry::create(
			TEST_RUNTIME_GENERATION, worker.worker_index, worker.numa_node,
			fixture->compiled_.topology.worker_schedules.front().stage_instance_indices, stream_indices,
			static_cast<uint64_t>(cadence.count()), *fixture->channel_);
		if (!worker_or.is_ok()) {
			return worker_or.error();
		}
		fixture->worker_ = std::move(worker_or).value();
		std::array<worker_telemetry_channel *, 1> channels{fixture->channel_.get()};
		std::array<worker_runtime_telemetry *, 1> workers{fixture->worker_.get()};
		const auto module_binding =
			fixture->modules_->bind_telemetry_channels(TEST_RUNTIME_GENERATION, channels);
		if (!module_binding.is_ok()) {
			return module_binding;
		}
		if (with_module) {
			fixture->module_owner_ = fixture->modules_->telemetry_context(0u);
			if (fixture->module_owner_ == nullptr ||
			    fixture->compiled_.topology.module_contexts.size() != 1u ||
			    fixture->compiled_.topology.module_contexts.front().stage_instance_index > UINT16_MAX) {
				fixture->modules_->unbind_telemetry_channels();
				return common::status::internal_error(
					"telemetry aggregate fixture lost its exact module owner");
			}
			const auto &context = fixture->compiled_.topology.module_contexts.front();
			const auto claimed = fixture->module_owner_->claim_module_health_owner(
				TEST_RUNTIME_GENERATION, static_cast<uint16_t>(context.stage_instance_index));
			if (!claimed.is_ok()) {
				fixture->modules_->unbind_telemetry_channels();
				return claimed;
			}
			fixture->module_health_claimed_ = true;
		}
		auto aggregator_or = runtime_telemetry_aggregator::create(TEST_RUNTIME_GENERATION,
									  fixture->compiled_.topology, channels,
									  workers, *fixture->modules_,
									  fixture->runtime_status_);
		if (!aggregator_or.is_ok()) {
			if (fixture->module_health_claimed_) {
				fixture->module_owner_->release_module_health_owner();
				fixture->module_health_claimed_ = false;
			}
			fixture->modules_->unbind_telemetry_channels();
			return aggregator_or.error();
		}
		fixture->aggregator_ = std::move(aggregator_or).value();
		if (!fixture->runtime_status_.publish_control_ready(TEST_RUNTIME_GENERATION, 1u)) {
			return common::status::internal_error("telemetry aggregate could not publish CONTROL_READY");
		}
		fixture->worker_->bind_bootstrap_epoch(TEST_BOOTSTRAP_EPOCH, 1u);
		if (fixture->module_owner_ != nullptr) {
			fixture->module_owner_->bind_bootstrap_telemetry(TEST_BOOTSTRAP_EPOCH, 1u);
		}
		if (!fixture->runtime_status_.publish_packet_ready(TEST_BOOTSTRAP_EPOCH, 1u)) {
			return common::status::internal_error("telemetry aggregate could not publish PACKET_READY");
		}
		return fixture;
	}

	aggregate_fixture(const aggregate_fixture &) = delete;
	aggregate_fixture &operator=(const aggregate_fixture &) = delete;
	aggregate_fixture(aggregate_fixture &&) = delete;
	aggregate_fixture &operator=(aggregate_fixture &&) = delete;

	/** @brief Close all bank ownership without relying on process teardown. */
	~aggregate_fixture()
	{
		if (worker_ == nullptr || aggregator_ == nullptr || channel_ == nullptr || modules_ == nullptr) {
			return;
		}
		settle_();
		const uint64_t epoch = worker_->active_epoch();
		if (epoch == 0u) {
			if (!worker_->empty() || !channel_->empty()) {
				std::terminate();
			}
			aggregator_.reset();
			if (module_health_claimed_) {
				module_owner_->release_module_health_owner();
				module_health_claimed_ = false;
			}
			modules_->unbind_telemetry_channels();
			worker_.reset();
			channel_.reset();
			modules_.reset();
			return;
		}
		if (!worker_->preflight_shutdown(epoch)) {
			std::terminate();
		}
		if (module_owner_ != nullptr && !module_owner_->preflight_publish_shutdown_telemetry(epoch)) {
			std::terminate();
		}
		if (module_owner_ != nullptr) {
			module_owner_->publish_shutdown_telemetry(epoch, shutdown_ns_);
		}
		worker_->publish_shutdown(epoch, shutdown_ns_);
		aggregator_->mark_workers_quiesced();
		while (!aggregator_->worker_epoch_aggregated(epoch)) {
			if (aggregator_->service(common::runtime_sizing::PACKET_MAX_BURST_SIZE) == 0u) {
				std::terminate();
			}
		}
		if (!aggregator_->module_epoch_aggregated(epoch)) {
			std::terminate();
		}
		if (module_owner_ != nullptr) {
			module_owner_->retire_telemetry_epoch(epoch, 0u);
		}
		aggregator_->complete_module_epoch_retirement(epoch, 0u);
		aggregator_->retire_worker_epoch(epoch, 0u);
		aggregator_.reset();
		if (module_health_claimed_) {
			module_owner_->release_module_health_owner();
			module_health_claimed_ = false;
		}
		modules_->unbind_telemetry_channels();
		worker_.reset();
		channel_.reset();
		modules_.reset();
	}

	/**
	 * @brief Deliver a cleared bank and keep final shutdown after its publication.
	 * @param token Exact worker or module return consumed from this fixture's channel.
	 */
	void accept_returned(const runtime_telemetry_bank_token &token) noexcept
	{
		if (token.published_at_ns == UINT64_MAX) {
			std::terminate();
		}
		shutdown_ns_ = std::max(shutdown_ns_, token.published_at_ns + 1u);
		if (token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER) {
			worker_->accept_returned(token);
		} else if (token.owner_kind == runtime_telemetry_bank_owner_kind::MODULE && module_owner_ != nullptr) {
			module_owner_->accept_returned_telemetry(token);
		} else {
			std::terminate();
		}
	}

	/** @brief Service cold tokens and dispatch every available worker return. */
	void settle_() noexcept
	{
		for (;;) {
			bool progressed = aggregator_->service(common::runtime_sizing::PACKET_MAX_BURST_SIZE) != 0u;
			runtime_telemetry_bank_token token{};
			while (channel_->take_returned(token)) {
				accept_returned(token);
				progressed = true;
			}
			if (!progressed) {
				return;
			}
		}
	}

	/**
	 * @brief Publish and completely aggregate one worker/module cadence baseline.
	 * @param now_ns Exact synthetic owner timestamp.
	 */
	void publish_owner_baseline(uint64_t now_ns) noexcept
	{
		if (worker_->service_turn(now_ns).return_need != runtime_telemetry_return_need::EXPECTED ||
		    (module_owner_ != nullptr &&
		     module_owner_->service_telemetry_cadence(now_ns) != runtime_telemetry_return_need::EXPECTED)) {
			std::terminate();
		}
		while (aggregator_->work_pending()) {
			if (aggregator_->service(common::runtime_sizing::PACKET_MAX_BURST_SIZE) == 0u) {
				std::terminate();
			}
		}
		settle_();
	}

	/** @return Mutable worker bank owner. */
	[[nodiscard]] worker_runtime_telemetry &worker() noexcept
	{
		return *worker_;
	}

	/** @return Mutable cold aggregator. */
	[[nodiscard]] runtime_telemetry_aggregator &aggregator() noexcept
	{
		return *aggregator_;
	}

	/** @return Exact bank channel. */
	[[nodiscard]] worker_telemetry_channel &channel() noexcept
	{
		return *channel_;
	}

	/** @return Exact admitted module telemetry owner, or null for module-free fixtures. */
	[[nodiscard]] lifecycle::lifecycle_context_owner *module_owner() noexcept
	{
		return module_owner_;
	}

	/** @return Immutable compiled topology. */
	[[nodiscard]] const provider::compiled_provider_topology &topology() const noexcept
	{
		return compiled_.topology;
	}

	/** @return Exact admitted module generation. */
	[[nodiscard]] module::module_runtime_generation &modules() noexcept
	{
		return *modules_;
	}

	/** @return Sole runtime-status publication. */
	[[nodiscard]] const runtime_status_publication &runtime_status() const noexcept
	{
		return runtime_status_;
	}

	/** @return Sole mutable status writer for transition-shape component evidence. */
	[[nodiscard]] runtime_status_publication &runtime_status_owner() noexcept
	{
		return runtime_status_;
	}

    private:
	aggregate_fixture() = default;

	test::packet_runtime_fixture_detail::compiled_runtime_fixture compiled_;  ///< Exact compiled identity owner.
	std::unique_ptr<module::module_runtime_generation> modules_;		  ///< Empty exact module generation.
	runtime_status_publication runtime_status_;				  ///< Exact readiness/epoch truth.
	std::unique_ptr<worker_telemetry_channel> channel_;			  ///< Exact SPSC bank transport.
	std::unique_ptr<worker_runtime_telemetry> worker_;			  ///< Exact worker bank owner.
	std::unique_ptr<runtime_telemetry_aggregator> aggregator_;		  ///< Sole cold bank consumer.
	lifecycle::lifecycle_context_owner *module_owner_{nullptr};		  ///< Optional exact module bank owner.
	bool module_health_claimed_{false};  ///< Whether the component fixture owns the linear health row.
	uint64_t shutdown_ns_{10u};	     ///< Synthetic shutdown time beyond every observed publication.
};

/** @brief Prove interval worker banks merge once into one coherent aggregate. */
TEST(runtime_telemetry_aggregator, interval_engine_and_stage_banks_merge_once)
{
	auto fixture_or = aggregate_fixture::create(true);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	EXPECT_FALSE(fixture->aggregator().collect({.include_stage_stats = true}).is_ok());
	const uint32_t global_stage = fixture->worker().stage_instance_indices().front();
	const uint32_t ordinal = fixture->worker().stage_ordinal(global_stage);
	ASSERT_NE(ordinal, UINT32_MAX);
	const auto &schedule = fixture->topology().worker_schedules.front();
	ASSERT_EQ(schedule.rx_stream_indices.size(), 1u);
	ASSERT_EQ(schedule.tx_stream_indices.size(), 1u);
	const uint32_t rx_stream = schedule.rx_stream_indices.front();
	const uint32_t tx_stream = schedule.tx_stream_indices.front();
	fixture->worker().record_stream(fixture->worker().stream_ordinal(rx_stream), 1u, 128u, 0u);
	fixture->worker().record_stream(fixture->worker().stream_ordinal(tx_stream), 1u, 120u, 0u);
	fixture->worker().record_drop();
	fixture->worker().record_stage_input(ordinal, 1u, 128u);
	fixture->worker().record_stage_output(ordinal, 120u);
	fixture->worker().record_stage_drop(ordinal);
	auto *module_owner = fixture->module_owner();
	ASSERT_NE(module_owner, nullptr);
	kinetum_counter *checked = nullptr;
	kinetum_histogram *packet_bytes = nullptr;
	for (std::size_t handle = 1u; handle <= module_owner->telemetry_handle_count(); ++handle) {
		const auto *descriptor =
			module_owner->telemetry_descriptor(static_cast<lifecycle::lifecycle_telemetry_handle>(handle));
		ASSERT_NE(descriptor, nullptr);
		if (descriptor->kind == lifecycle::lifecycle_telemetry_kind::COUNTER &&
		    std::string_view(descriptor->counter.name) == "test_module.checked") {
			checked = const_cast<kinetum_counter *>(&descriptor->counter);
		}
		if (descriptor->kind == lifecycle::lifecycle_telemetry_kind::HISTOGRAM &&
		    std::string_view(descriptor->histogram.name) == "test_module.packet_bytes") {
			packet_bytes = const_cast<kinetum_histogram *>(&descriptor->histogram);
		}
	}
	ASSERT_NE(checked, nullptr);
	ASSERT_NE(packet_bytes, nullptr);
	KINETUM_COUNTER_ADD(checked, 7u);
	KINETUM_HISTOGRAM_RECORD_FAST(packet_bytes, 64u);
	KINETUM_HISTOGRAM_RECORD_FAST(packet_bytes, 128u);
	ASSERT_EQ(fixture->worker().service_turn(1u).return_need, runtime_telemetry_return_need::EXPECTED);
	ASSERT_EQ(module_owner->service_telemetry_cadence(2u), runtime_telemetry_return_need::EXPECTED);
	ASSERT_EQ(fixture->aggregator().service(2u), 2u);
	EXPECT_FALSE(fixture->aggregator().collect({.include_stage_stats = true}).is_ok());
	while (fixture->aggregator().work_pending()) {
		ASSERT_EQ(fixture->aggregator().service(1u), 1u);
	}
	fixture->settle_();

	auto snapshot_or = fixture->aggregator().collect({
		.include_stage_stats = true,
		.include_module_metrics = true,
		.include_stream_stats = true,
	});
	ASSERT_TRUE(snapshot_or.is_ok()) << snapshot_or.error().message();
	const auto &snapshot = snapshot_or.value();
	EXPECT_EQ(snapshot.latest_bank_publication_monotonic_ns, 2u);
	EXPECT_EQ(snapshot.engine.rx_packets, 1u);
	EXPECT_EQ(snapshot.engine.tx_packets, 1u);
	EXPECT_EQ(snapshot.engine.dropped_packets, 1u);
	EXPECT_EQ(snapshot.engine.rx_bytes, 128u);
	EXPECT_EQ(snapshot.engine.tx_bytes, 120u);
	ASSERT_EQ(snapshot.streams.size(), 2u);
	EXPECT_EQ(snapshot.streams[rx_stream].packets, 1u);
	EXPECT_EQ(snapshot.streams[rx_stream].bytes, 128u);
	EXPECT_EQ(snapshot.streams[rx_stream].rejected_packets, 0u);
	EXPECT_EQ(snapshot.streams[tx_stream].packets, 1u);
	EXPECT_EQ(snapshot.streams[tx_stream].bytes, 120u);
	EXPECT_EQ(snapshot.streams[tx_stream].rejected_packets, 0u);
	EXPECT_EQ(snapshot.streams[rx_stream].published_monotonic_ns, 1u);
	auto checked_row = std::find_if(snapshot.module_counters.begin(), snapshot.module_counters.end(),
					[](const auto &row) { return row.name == "test_module.checked"; });
	ASSERT_NE(checked_row, snapshot.module_counters.end());
	EXPECT_EQ(checked_row->epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(checked_row->value, 7u);
	auto histogram_row = std::find_if(snapshot.module_histograms.begin(), snapshot.module_histograms.end(),
					  [](const auto &row) { return row.name == "test_module.packet_bytes"; });
	ASSERT_NE(histogram_row, snapshot.module_histograms.end());
	EXPECT_EQ(histogram_row->epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(histogram_row->count, 2u);
	EXPECT_EQ(histogram_row->minimum, 64u);
	EXPECT_EQ(histogram_row->maximum, 128u);
	const uint16_t logical_index = fixture->topology().stage_instances[global_stage].logical_stage_index;
	ASSERT_LT(logical_index, snapshot.stages.size());
	EXPECT_EQ(snapshot.stages[logical_index].in_packets, 1u);
	EXPECT_EQ(snapshot.stages[logical_index].out_packets, 1u);
	EXPECT_EQ(snapshot.stages[logical_index].dropped_packets, 1u);
}

/** @brief Engine transfer totals derive from the same stream rows even when detail is not selected. */
TEST(runtime_telemetry_aggregator, stream_selection_cannot_change_engine_transfer_totals)
{
	auto fixture_or = aggregate_fixture::create();
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	const auto &schedule = fixture->topology().worker_schedules.front();
	ASSERT_EQ(schedule.rx_stream_indices.size(), 1u);
	ASSERT_EQ(schedule.tx_stream_indices.size(), 1u);
	fixture->worker().record_stream(fixture->worker().stream_ordinal(schedule.rx_stream_indices.front()), 7u, 448u,
					2u);
	fixture->worker().record_stream(fixture->worker().stream_ordinal(schedule.tx_stream_indices.front()), 3u, 192u,
					0u);
	fixture->publish_owner_baseline(1u);
	auto summary = fixture->aggregator().collect({});
	auto detailed = fixture->aggregator().collect({.include_stream_stats = true});
	ASSERT_TRUE(summary.is_ok()) << summary.error().message();
	ASSERT_TRUE(detailed.is_ok()) << detailed.error().message();
	EXPECT_TRUE(summary->streams.empty());
	ASSERT_EQ(detailed->streams.size(), 2u);
	EXPECT_EQ(summary->engine.rx_packets, 7u);
	EXPECT_EQ(summary->engine.rx_bytes, 448u);
	EXPECT_EQ(summary->engine.tx_packets, 3u);
	EXPECT_EQ(summary->engine.tx_bytes, 192u);
	EXPECT_EQ(detailed->engine.rx_packets, summary->engine.rx_packets);
	EXPECT_EQ(detailed->engine.tx_packets, summary->engine.tx_packets);
	EXPECT_EQ(detailed->engine.dropped_packets, 0u);
	EXPECT_EQ(detailed->streams[schedule.rx_stream_indices.front()].rejected_packets, 2u);
}

/** @brief Exhausted accounting rejects collection while every bank still returns and retires. */
TEST(runtime_telemetry_aggregator, exhausted_stream_accounting_stays_failed_without_stranding_banks)
{
	auto fixture_or = aggregate_fixture::create();
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	const auto &schedule = fixture->topology().worker_schedules.front();
	ASSERT_EQ(schedule.rx_stream_indices.size(), 1u);
	const uint32_t stream = fixture->worker().stream_ordinal(schedule.rx_stream_indices.front());
	fixture->worker().record_stream(stream, 1u, UINT64_MAX - 1u, 0u);
	fixture->publish_owner_baseline(1u);
	ASSERT_TRUE(fixture->aggregator().collect({}).is_ok());
	fixture->worker().record_stream(stream, 1u, 64u, 0u);
	fixture->publish_owner_baseline(1u + fixture->worker().cadence_ns());
	auto failed = fixture->aggregator().collect({.include_stream_stats = true});
	ASSERT_FALSE(failed.is_ok());
	EXPECT_EQ(failed.error().code(), common::status_code::DATA_LOSS);
	EXPECT_TRUE(fixture->channel().empty());
	fixture->worker().record_stream(stream, 1u, 64u, 0u);
	fixture->publish_owner_baseline(1u + 2u * fixture->worker().cadence_ns());
	auto still_failed = fixture->aggregator().collect({});
	ASSERT_FALSE(still_failed.is_ok());
	EXPECT_EQ(still_failed.error().code(), common::status_code::DATA_LOSS);
	EXPECT_TRUE(fixture->channel().empty());
}

/** @brief Project only current-epoch health and leave a stale signal explicitly unavailable. */
TEST(runtime_telemetry_aggregator, health_rows_follow_coherent_runtime_epoch_without_relabeling)
{
	auto fixture_or = aggregate_fixture::create(true);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	auto *owner = fixture->module_owner();
	ASSERT_NE(owner, nullptr);
	kinetum_health_assessment assessment{};
	assessment.health_score = 88u;
	assessment.flags = static_cast<uint32_t>(KINETUM_HEALTH_F_DEGRADED);
	std::memcpy(assessment.reason, "warming", sizeof("warming"));
	owner->publish_module_health_attempt(assessment, {
								 .epoch = TEST_BOOTSTRAP_EPOCH,
								 .timestamp_ns = 2u,
								 .duration_ns = 1u,
								 .callback_budget_ns = 2u,
							 });
	fixture->publish_owner_baseline(2u);

	auto current_or = fixture->aggregator().collect({.include_module_health = true});
	ASSERT_TRUE(current_or.is_ok()) << current_or.error().message();
	ASSERT_EQ(current_or->module_health.size(), 1u);
	const auto &current = current_or->module_health.front();
	EXPECT_TRUE(current.callback_available);
	EXPECT_TRUE(current.signal_available);
	EXPECT_EQ(current.observation_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(current.signal.epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(current.signal.timestamp_ns, 2u);
	EXPECT_EQ(current.signal.assessment.health_score, 88u);
	EXPECT_STREQ(current.signal.assessment.reason, "warming");

	kinetum_health_assessment malformed{};
	malformed.health_score = 101u;
	std::memcpy(malformed.reason, "invalid", sizeof("invalid"));
	owner->publish_module_health_attempt(malformed, {
								.epoch = TEST_BOOTSTRAP_EPOCH,
								.timestamp_ns = 3u,
								.duration_ns = 3u,
								.callback_budget_ns = 2u,
							});
	auto faulted_or = fixture->aggregator().collect({.include_module_health = true});
	ASSERT_TRUE(faulted_or.is_ok()) << faulted_or.error().message();
	ASSERT_EQ(faulted_or->module_health.size(), 1u);
	const auto &faulted = faulted_or->module_health.front();
	const uint16_t expected_faults = static_cast<uint16_t>(
		static_cast<uint16_t>(lifecycle::lifecycle_module_health_fault::SCORE_OUT_OF_RANGE) |
		static_cast<uint16_t>(lifecycle::lifecycle_module_health_fault::CALLBACK_BUDGET_EXCEEDED));
	EXPECT_FALSE(faulted.signal_available);
	EXPECT_EQ(faulted.latest_fault_mask, expected_faults);
	EXPECT_EQ(faulted.first_fault_mask, expected_faults);
	EXPECT_EQ(faulted.contract_fault_count, 1u);
	EXPECT_EQ(faulted.first_fault_epoch, TEST_BOOTSTRAP_EPOCH);
	EXPECT_EQ(faulted.first_fault_timestamp_ns, 3u);
	EXPECT_EQ(faulted.first_fault_duration_ns, 3u);

	owner->publish_module_health_attempt(assessment, {
								 .epoch = TEST_BOOTSTRAP_EPOCH,
								 .timestamp_ns = 4u,
								 .duration_ns = 1u,
								 .callback_budget_ns = 2u,
							 });
	auto recovered_or = fixture->aggregator().collect({.include_module_health = true});
	ASSERT_TRUE(recovered_or.is_ok()) << recovered_or.error().message();
	ASSERT_EQ(recovered_or->module_health.size(), 1u);
	const auto &recovered = recovered_or->module_health.front();
	EXPECT_TRUE(recovered.signal_available);
	EXPECT_EQ(recovered.latest_fault_mask, 0u);
	EXPECT_EQ(recovered.first_fault_mask, expected_faults);
	EXPECT_EQ(recovered.contract_fault_count, 1u);
	EXPECT_EQ(recovered.first_fault_timestamp_ns, 3u);
	EXPECT_EQ(recovered.signal.timestamp_ns, 4u);

	ASSERT_TRUE(
		fixture->runtime_status_owner().publish_transition_activated(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH));
	auto stale_or = fixture->aggregator().collect({.include_module_health = true});
	ASSERT_TRUE(stale_or.is_ok()) << stale_or.error().message();
	ASSERT_EQ(stale_or->module_health.size(), 1u);
	const auto &stale = stale_or->module_health.front();
	EXPECT_TRUE(stale.callback_available);
	EXPECT_FALSE(stale.signal_available);
	EXPECT_EQ(stale.observation_epoch, TEST_BOOTSTRAP_EPOCH);
	const std::array<unsigned char, sizeof(kinetum_health_signal)> zero_signal{};
	EXPECT_EQ(std::memcmp(&stale.signal, zero_signal.data(), zero_signal.size()), 0);
}

/** @brief Preserve one explicit unavailable row for an admitted null callback. */
TEST(runtime_telemetry_aggregator, null_health_callback_is_an_unavailable_context_row)
{
	auto fixture_or = aggregate_fixture::create(true, false);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->publish_owner_baseline(2u);
	auto snapshot_or = fixture->aggregator().collect({.include_module_health = true});
	ASSERT_TRUE(snapshot_or.is_ok()) << snapshot_or.error().message();
	ASSERT_EQ(snapshot_or->module_health.size(), 1u);
	const auto &row = snapshot_or->module_health.front();
	EXPECT_EQ(row.module_id, "kinetum.test.serialized");
	EXPECT_FALSE(row.callback_available);
	EXPECT_FALSE(row.signal_available);
	EXPECT_EQ(row.publication_generation, 0u);
	EXPECT_EQ(row.observation_epoch, 0u);
}

/** @brief Serialize concurrent cold readers without inverting health generations. */
TEST(runtime_telemetry_aggregator, concurrent_collectors_never_invert_health_publication_order)
{
	auto fixture_or = aggregate_fixture::create(true);
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	fixture->publish_owner_baseline(2u);
	auto *owner = fixture->module_owner();
	ASSERT_NE(owner, nullptr);
	kinetum_health_assessment assessment{};
	assessment.health_score = 100u;
	std::memcpy(assessment.reason, "ready", sizeof("ready"));
	std::atomic<bool> start{false};
	std::atomic<uint64_t> failures{0u};

	std::thread writer([&]() {
		while (!start.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		for (uint64_t generation = 1u; generation <= 256u; ++generation) {
			owner->publish_module_health_attempt(assessment, {
										 .epoch = TEST_BOOTSTRAP_EPOCH,
										 .timestamp_ns = 100u + generation,
										 .duration_ns = 1u,
										 .callback_budget_ns = 2u,
									 });
		}
	});
	const auto collect = [&]() {
		while (!start.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		for (std::size_t attempt = 0u; attempt < 512u; ++attempt) {
			auto snapshot = fixture->aggregator().collect({.include_module_health = true});
			if (!snapshot.is_ok() || snapshot->module_health.size() != 1u) {
				failures.fetch_add(1u, std::memory_order_relaxed);
			}
		}
	};
	std::thread first_reader(collect);
	std::thread second_reader(collect);
	start.store(true, std::memory_order_release);
	writer.join();
	first_reader.join();
	second_reader.join();
	EXPECT_EQ(failures.load(std::memory_order_relaxed), 0u);
	auto final = fixture->aggregator().collect({.include_module_health = true});
	ASSERT_TRUE(final.is_ok()) << final.error().message();
	ASSERT_EQ(final->module_health.size(), 1u);
	EXPECT_EQ(final->module_health.front().publication_generation, 256u);
	EXPECT_EQ(final->module_health.front().signal.timestamp_ns, 356u);
}

/** @brief Prove the aggregator, not mutable owner state, gates old-bank retirement. */
TEST(runtime_telemetry_aggregator, activation_and_reclaimed_return_preserve_exact_epoch_ownership)
{
	auto fixture_or = aggregate_fixture::create();
	ASSERT_TRUE(fixture_or.is_ok()) << fixture_or.error().message();
	auto fixture = std::move(fixture_or).value();
	ASSERT_TRUE(fixture->worker().reserve_target_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH).is_ok());
	fixture->worker().activate_target_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH, 2u);
	EXPECT_FALSE(fixture->aggregator().worker_epoch_aggregated(TEST_BOOTSTRAP_EPOCH));
	ASSERT_EQ(fixture->aggregator().service(1u), 1u);
	ASSERT_TRUE(fixture->aggregator().worker_epoch_aggregated(TEST_BOOTSTRAP_EPOCH));
	ASSERT_TRUE(fixture->worker().preflight_shutdown(TEST_TARGET_EPOCH));
	fixture->worker().publish_shutdown(TEST_TARGET_EPOCH, 3u);
	fixture->aggregator().mark_workers_quiesced();
	ASSERT_EQ(fixture->aggregator().service(1u), 1u);
	EXPECT_TRUE(fixture->aggregator().worker_epoch_aggregated(TEST_BOOTSTRAP_EPOCH));
	EXPECT_FALSE(fixture->aggregator().worker_epoch_aggregated(TEST_TARGET_EPOCH));
	fixture->aggregator().complete_module_epoch_retirement(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
	fixture->aggregator().retire_worker_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
	ASSERT_TRUE(fixture->aggregator().worker_epoch_aggregated(TEST_TARGET_EPOCH));
	fixture->aggregator().complete_module_epoch_retirement(TEST_TARGET_EPOCH, 0u);
	fixture->aggregator().retire_worker_epoch(TEST_TARGET_EPOCH, 0u);
	EXPECT_TRUE(fixture->worker().empty());
	fixture.reset();

	// In the live-owner ordering, the worker may accept and reuse the reclaimed
	// target bank before the coordinator services its next cadence token.
	auto live_fixture_or = aggregate_fixture::create();
	ASSERT_TRUE(live_fixture_or.is_ok()) << live_fixture_or.error().message();
	auto live_fixture = std::move(live_fixture_or).value();
	const uint32_t rx_stream = live_fixture->topology().worker_schedules.front().rx_stream_indices.front();
	const uint32_t ordinal = live_fixture->worker().stream_ordinal(rx_stream);
	live_fixture->worker().record_stream(ordinal, 2u, 128u, 0u);
	ASSERT_TRUE(live_fixture->worker().reserve_target_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH).is_ok());
	live_fixture->worker().activate_target_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH, 2u);
	ASSERT_EQ(live_fixture->aggregator().service(1u), 1u);
	ASSERT_TRUE(live_fixture->aggregator().worker_epoch_aggregated(TEST_BOOTSTRAP_EPOCH));
	live_fixture->aggregator().complete_module_epoch_retirement(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
	live_fixture->aggregator().retire_worker_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
	runtime_telemetry_bank_token returned{};
	ASSERT_TRUE(live_fixture->channel().take_returned(returned));
	live_fixture->accept_returned(returned);
	live_fixture->worker().record_stream(ordinal, 3u, 192u, 1u);
	const uint64_t cadence_time = 2u + live_fixture->worker().cadence_ns();
	ASSERT_EQ(live_fixture->worker().service_turn(cadence_time).return_need,
		  runtime_telemetry_return_need::EXPECTED);
	ASSERT_EQ(live_fixture->aggregator().service(1u), 1u);
	ASSERT_TRUE(live_fixture->channel().take_returned(returned));
	live_fixture->accept_returned(returned);
	auto cumulative = live_fixture->aggregator().collect({.include_stream_stats = true});
	ASSERT_TRUE(cumulative.is_ok()) << cumulative.error().message();
	EXPECT_EQ(cumulative->engine.rx_packets, 5u);
	EXPECT_EQ(cumulative->engine.rx_bytes, 320u);
	ASSERT_LT(rx_stream, cumulative->streams.size());
	EXPECT_EQ(cumulative->streams[rx_stream].packets, 5u);
	EXPECT_EQ(cumulative->streams[rx_stream].bytes, 320u);
	EXPECT_EQ(cumulative->streams[rx_stream].rejected_packets, 1u);
	EXPECT_EQ(cumulative->streams[rx_stream].published_monotonic_ns, cadence_time);
	live_fixture.reset();

	// With multiple lifecycle callbacks, a module worker can reuse its reclaimed
	// bank and publish target cadence before the coordinator consumes the issued
	// retirement record. The later publication proves the earlier transfer.
	auto module_race_or = aggregate_fixture::create(true);
	ASSERT_TRUE(module_race_or.is_ok()) << module_race_or.error().message();
	auto module_race = std::move(module_race_or).value();
	auto *module_owner = module_race->module_owner();
	ASSERT_NE(module_owner, nullptr);
	ASSERT_TRUE(module_race->worker().reserve_target_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH).is_ok());
	ASSERT_TRUE(module_owner->reserve_telemetry_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH).is_ok());
	module_owner->activate_telemetry_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH, 2u);
	module_race->worker().activate_target_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH, 2u);
	module_race->aggregator().drain_quiescent();
	ASSERT_TRUE(module_race->aggregator().worker_epoch_aggregated(TEST_BOOTSTRAP_EPOCH));
	ASSERT_TRUE(module_race->aggregator().module_epoch_aggregated(TEST_BOOTSTRAP_EPOCH));
	module_owner->retire_telemetry_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
	ASSERT_TRUE(module_race->channel().take_returned(returned));
	ASSERT_EQ(returned.owner_kind, runtime_telemetry_bank_owner_kind::MODULE);
	module_race->accept_returned(returned);
	ASSERT_EQ(module_owner->service_telemetry_cadence(3u), runtime_telemetry_return_need::EXPECTED);
	module_race->aggregator().drain_quiescent();
	module_race->aggregator().complete_module_epoch_retirement(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
	module_race->aggregator().retire_worker_epoch(TEST_BOOTSTRAP_EPOCH, TEST_TARGET_EPOCH);
	module_race->settle_();
}

/** @brief Child process for malformed owner identity at the cold bank boundary. */
[[noreturn]] void malformed_token_child()
{
	auto fixture_or = aggregate_fixture::create();
	if (!fixture_or.is_ok()) {
		std::_Exit(91);
	}
	auto fixture = std::move(fixture_or).value();
	const runtime_telemetry_bank_token malformed{
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.epoch = TEST_BOOTSTRAP_EPOCH,
		.bank_generation = 1u,
		.published_at_ns = 1u,
		.worker_index = 0u,
		.owner_index = 1u,
		.stage_instance_index = UINT16_MAX,
		.bank_index = 0u,
		.companion_bank_index = UINT8_MAX,
		.owner_kind = runtime_telemetry_bank_owner_kind::WORKER,
		.reason = runtime_telemetry_publication_reason::CADENCE,
		.kind = runtime_telemetry_bank_token_kind::BANK,
		.padding = {},
	};
	if (!fixture->channel().publish_completed(malformed)) {
		std::_Exit(92);
	}
	(void)fixture->aggregator().service(1u);
	std::_Exit(93);
}

/** @brief Child process for a valid bank token whose publication reason is altered in transit. */
[[noreturn]] void mutated_transfer_identity_child()
{
	auto fixture_or = aggregate_fixture::create();
	if (!fixture_or.is_ok()) {
		std::_Exit(94);
	}
	auto fixture = std::move(fixture_or).value();
	if (fixture->worker().service_turn(1u).return_need != runtime_telemetry_return_need::EXPECTED) {
		std::_Exit(95);
	}
	runtime_telemetry_bank_token token{};
	if (!fixture->channel().take_completed(token)) {
		std::_Exit(96);
	}
	token.reason = runtime_telemetry_publication_reason::SHUTDOWN;
	if (!fixture->channel().publish_completed(token)) {
		std::_Exit(97);
	}
	(void)fixture->aggregator().service(1u);
	std::_Exit(98);
}

/** @brief Child process for an altered module-bank companion identity. */
[[noreturn]] void mutated_module_transfer_identity_child()
{
	auto fixture_or = aggregate_fixture::create(true);
	if (!fixture_or.is_ok()) {
		std::_Exit(99);
	}
	auto fixture = std::move(fixture_or).value();
	auto *module_owner = fixture->module_owner();
	if (module_owner == nullptr ||
	    module_owner->service_telemetry_cadence(1u) != runtime_telemetry_return_need::EXPECTED) {
		std::_Exit(100);
	}
	runtime_telemetry_bank_token token{};
	if (!fixture->channel().take_completed(token)) {
		std::_Exit(101);
	}
	token.companion_bank_index = 2u;
	if (!fixture->channel().publish_completed(token)) {
		std::_Exit(102);
	}
	(void)fixture->aggregator().service(1u);
	std::_Exit(103);
}

/** @brief Child process for an altered worker return token. */
[[noreturn]] void mutated_worker_return_identity_child()
{
	auto fixture_or = aggregate_fixture::create();
	if (!fixture_or.is_ok()) {
		std::_Exit(104);
	}
	auto fixture = std::move(fixture_or).value();
	if (fixture->worker().service_turn(1u).return_need != runtime_telemetry_return_need::EXPECTED ||
	    fixture->aggregator().service(1u) != 1u) {
		std::_Exit(105);
	}
	runtime_telemetry_bank_token token{};
	if (!fixture->channel().take_returned(token) || token.published_at_ns == UINT64_MAX) {
		std::_Exit(106);
	}
	++token.published_at_ns;
	fixture->worker().accept_returned(token);
	std::_Exit(107);
}

/** @brief Child process for an altered module return token. */
[[noreturn]] void mutated_module_return_identity_child()
{
	auto fixture_or = aggregate_fixture::create(true);
	if (!fixture_or.is_ok()) {
		std::_Exit(108);
	}
	auto fixture = std::move(fixture_or).value();
	auto *module_owner = fixture->module_owner();
	if (module_owner == nullptr ||
	    module_owner->service_telemetry_cadence(1u) != runtime_telemetry_return_need::EXPECTED) {
		std::_Exit(109);
	}
	while (fixture->aggregator().work_pending()) {
		if (fixture->aggregator().service(1u) != 1u) {
			std::_Exit(110);
		}
	}
	runtime_telemetry_bank_token token{};
	if (!fixture->channel().take_returned(token) || token.published_at_ns == UINT64_MAX) {
		std::_Exit(111);
	}
	++token.published_at_ns;
	module_owner->accept_returned_telemetry(token);
	std::_Exit(112);
}

/** @brief Child process for a histogram summary that disagrees with its immutable bucket bank. */
[[noreturn]] void inconsistent_histogram_bank_child()
{
	auto fixture_or = aggregate_fixture::create(true);
	if (!fixture_or.is_ok()) {
		std::_Exit(113);
	}
	auto fixture = std::move(fixture_or).value();
	auto *module_owner = fixture->module_owner();
	if (module_owner == nullptr) {
		std::_Exit(114);
	}
	kinetum_histogram *histogram = nullptr;
	for (std::size_t handle = 1u; handle <= module_owner->telemetry_handle_count(); ++handle) {
		const auto *descriptor =
			module_owner->telemetry_descriptor(static_cast<lifecycle::lifecycle_telemetry_handle>(handle));
		if (descriptor != nullptr && descriptor->kind == lifecycle::lifecycle_telemetry_kind::HISTOGRAM) {
			histogram = const_cast<kinetum_histogram *>(&descriptor->histogram);
			break;
		}
	}
	if (histogram == nullptr) {
		std::_Exit(115);
	}
	histogram->total_count = 1u;
	histogram->min_value = 0u;
	histogram->max_value = 0u;
	histogram->sum = 0u;
	if (module_owner->service_telemetry_cadence(1u) != runtime_telemetry_return_need::EXPECTED) {
		std::_Exit(116);
	}
	while (fixture->aggregator().work_pending()) {
		if (fixture->aggregator().service(1u) != 1u) {
			std::_Exit(117);
		}
	}
	std::_Exit(118);
}

/** @brief Prove a foreign worker/owner identity is terminate-class. */
TEST(runtime_telemetry_aggregator, malformed_owner_identity_fails_stop)
{
	auto availability_or = aggregate_fixture::create(true);
	ASSERT_TRUE(availability_or.is_ok()) << availability_or.error().message();
	std::array<worker_telemetry_channel *, 1> live_channel{&availability_or.value()->channel()};
	std::array<worker_runtime_telemetry *, 1> live_worker{&availability_or.value()->worker()};
	auto live_rejected = runtime_telemetry_aggregator::create(TEST_RUNTIME_GENERATION,
								  availability_or.value()->topology(), live_channel,
								  live_worker, availability_or.value()->modules(),
								  availability_or.value()->runtime_status());
	ASSERT_FALSE(live_rejected.is_ok());
	EXPECT_EQ(live_rejected.error().code(), common::status_code::FAILED_PRECONDITION);
	availability_or.value().reset();
	EXPECT_EXIT(malformed_token_child(), ::testing::KilledBySignal(SIGABRT), "");
	EXPECT_EXIT(mutated_transfer_identity_child(), ::testing::KilledBySignal(SIGABRT), "");
	EXPECT_EXIT(mutated_module_transfer_identity_child(), ::testing::KilledBySignal(SIGABRT), "");
	EXPECT_EXIT(mutated_worker_return_identity_child(), ::testing::KilledBySignal(SIGABRT), "");
	EXPECT_EXIT(mutated_module_return_identity_child(), ::testing::KilledBySignal(SIGABRT), "");
	EXPECT_EXIT(inconsistent_histogram_bank_child(), ::testing::KilledBySignal(SIGABRT), "");
}

/** @brief Child process for duplicate ownership of one immutable bank token. */
[[noreturn]] void duplicate_token_child()
{
	auto fixture_or = aggregate_fixture::create();
	if (!fixture_or.is_ok()) {
		std::_Exit(101);
	}
	auto fixture = std::move(fixture_or).value();
	if (fixture->worker().service_turn(1u).return_need != runtime_telemetry_return_need::EXPECTED) {
		std::_Exit(102);
	}
	runtime_telemetry_bank_token token{};
	if (!fixture->channel().take_completed(token) || !fixture->channel().publish_completed(token) ||
	    !fixture->channel().publish_completed(token)) {
		std::_Exit(103);
	}
	if (fixture->aggregator().service(1u) != 1u) {
		std::_Exit(104);
	}
	(void)fixture->aggregator().service(1u);
	std::_Exit(105);
}

/** @brief Prove duplicate delivery cannot merge or return one bank twice. */
TEST(runtime_telemetry_aggregator, duplicate_bank_token_fails_stop)
{
	auto availability_or = aggregate_fixture::create();
	ASSERT_TRUE(availability_or.is_ok()) << availability_or.error().message();
	availability_or.value().reset();
	EXPECT_EXIT(duplicate_token_child(), ::testing::KilledBySignal(SIGABRT), "");
}

/** @brief Child process for a retained-return acknowledgment with no issued transfer. */
[[noreturn]] void unissued_return_ack_child()
{
	auto fixture_or = aggregate_fixture::create();
	if (!fixture_or.is_ok()) {
		std::_Exit(111);
	}
	auto fixture = std::move(fixture_or).value();
	const runtime_telemetry_bank_token acknowledgment{
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.epoch = TEST_BOOTSTRAP_EPOCH,
		.bank_generation = 1u,
		.published_at_ns = 1u,
		.worker_index = 0u,
		.owner_index = 0u,
		.stage_instance_index = UINT16_MAX,
		.bank_index = 0u,
		.companion_bank_index = UINT8_MAX,
		.owner_kind = runtime_telemetry_bank_owner_kind::WORKER,
		.reason = runtime_telemetry_publication_reason::CADENCE,
		.kind = runtime_telemetry_bank_token_kind::RETURN_RETAINED,
		.padding = {},
	};
	if (!fixture->channel().publish_completed(acknowledgment)) {
		std::_Exit(112);
	}
	(void)fixture->aggregator().service(1u);
	std::_Exit(113);
}

/** @brief Prove return retention cannot be fabricated without an exact issued bank. */
TEST(runtime_telemetry_aggregator, unissued_return_retention_fails_stop)
{
	auto availability_or = aggregate_fixture::create();
	ASSERT_TRUE(availability_or.is_ok()) << availability_or.error().message();
	availability_or.value().reset();
	EXPECT_EXIT(unissued_return_ack_child(), ::testing::KilledBySignal(SIGABRT), "");
}

}  // namespace
}  // namespace kinetum::dp
