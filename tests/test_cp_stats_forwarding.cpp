// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_cp_stats_forwarding.cpp
 * @brief Tests for exact CP-to-DP statistics aggregation and status closure.
 * @author Fleming Patel
 *
 * Validates that control_service_impl::GetStats correctly:
 * 1. Forwards stats inclusion flags to DP
 * 2. Forwards one shared telemetry payload without field-by-field rebuilding
 * 3. Respects flag gating (no stage_stats when flag is false, etc.)
 * 4. Requires the explicit boundary selector and preserves optional presence
 * 5. Maps no CP or DP payload when transport or application status fails
 *
 * Uses test_grpc_helpers.hpp for the neutral fake DP service.
 * Native server contexts carry deadline and cancellation propagation.
 *
 * @see tests/test_grpc_helpers.hpp
 * @see src/cp/cp_grpc.cpp
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/client_interceptor.h>
#include <google/protobuf/unknown_field_set.h>

#include <unistd.h>

#include "gen/kinetum/control/v1/control.grpc.pb.h"
#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/cp/config_store.hpp"
#include "src/cp/control_loop.hpp"
#include "src/cp/cp_grpc.hpp"

#include "tests/test_grpc_helpers.hpp"

namespace kinetum::cp
{
namespace
{

/** @brief Process-local sequence for collision-free statistics fixture roots. */
std::atomic<uint64_t> CP_STATS_ROOT_SEQUENCE{0u};

/** @brief Exact maximum DP failure-text prefix relayed by CP. */
constexpr std::size_t MAX_RELAYED_STATS_FAILURE_BYTES = 512u;

/**
 * @brief Fill every aggregate payload family with nondefault test data.
 *
 * @param response Response to poison before calling the service under test.
 */
void poison_aggregate_stats(kinetum::control::v1::StatsResponse *response)
{
	response->mutable_active_config()->set_revision(99);
	response->mutable_active_config()->set_snapshot_id("poisoned.snapshot");
	response->mutable_telemetry()->mutable_runtime()->set_runtime_generation(99u);
	response->mutable_telemetry()->mutable_engine()->set_rx_packets(1u);
	response->mutable_telemetry()->add_stages();
	response->mutable_telemetry()->add_boundaries();
	response->mutable_telemetry()->add_regions();
	response->mutable_telemetry()->add_streams();
	response->mutable_telemetry()->add_storage_domains();
	response->mutable_telemetry()->add_steering_profiles();
	response->mutable_telemetry()->add_module_context_domains();
	response->mutable_telemetry()->add_ports();
}

/**
 * @brief Require that one failed aggregate contains no semantic payload.
 *
 * Clearing the status must leave a zero-byte protobuf. This proves every
 * current scalar and repeated payload field stayed at its default and also
 * makes future response fields fail the test if a failure path maps them.
 *
 * @param response Failed aggregate response.
 */
void expect_status_only(const kinetum::control::v1::StatsResponse &response)
{
	auto payload = response;
	payload.clear_status();
	EXPECT_EQ(payload.ByteSizeLong(), 0u);
}

/** @brief Forward real RPC contexts to the production handler through one optional test admission edge. */
class stats_forwarding_service final : public kinetum::control::v1::ControlService::Service {
    public:
	/**
	 * @brief Borrow the production service, which outlives this registered delegate.
	 * @param service Exact handler under test.
	 */
	explicit stats_forwarding_service(control_service_impl &service)
		: service_(service)
	{
	}

	/**
	 * @brief Forward one real call through the production handler.
	 * @param context Incoming deadline and cancellation authority.
	 * @param request Exact operator selection.
	 * @param response Caller-owned response populated by the handler.
	 * @return The production handler's transport result.
	 */
	grpc::Status GetStats(grpc::ServerContext *context, const kinetum::control::v1::StatsRequest *request,
			      kinetum::control::v1::StatsResponse *response) override
	{
		if (before_call) {
			before_call(*context);
		}
		auto transport = service_.GetStats(context, request, response);
		if (after_call) {
			after_call(*response);
		}
		return transport;
	}

	std::function<void(grpc::ServerContext &)> before_call;	 ///< Optional deterministic admission boundary.
	std::function<void(const kinetum::control::v1::StatsResponse &)> after_call;  ///< Handler-completion observation.

    private:
	control_service_impl &service_;	 ///< Production owner; never bypassed.
};

/** @brief Observe the actual outgoing statistics context before transport timeout encoding. */
class stats_call_observer final : public grpc::experimental::ClientInterceptorFactoryInterface {
    public:
	/**
	 * @brief Own one channel-local observation callback.
	 * @param observe Callback that borrows the outgoing context only during invocation.
	 */
	explicit stats_call_observer(std::function<void(const grpc::ClientContext &)> observe)
		: observe_(std::move(observe))
	{
	}

	/**
	 * @brief Inspect statistics admission without intercepting or changing the RPC.
	 * @param info Native method and client context supplied by gRPC.
	 * @return Null, leaving the call's transport and completion path unchanged.
	 */
	grpc::experimental::Interceptor *CreateClientInterceptor(grpc::experimental::ClientRpcInfo *info) override
	{
		if (std::string_view(info->method()) == "/kinetum.dataplane.v1.DataplaneService/GetStats") {
			observe_(*info->client_context());
		}
		return nullptr;
	}

    private:
	std::function<void(const grpc::ClientContext &)> observe_;  ///< Captures fixture-owned observation state.
};

// ===============================================================================
// Test fixture: wires fake DP -> control_loop -> control_service_impl
// ===============================================================================

/** @brief Own one exact CP store and scripted DP statistics service per test. */
class CpStatsForwardingTest : public ::testing::Test {
    protected:
	/** @brief Build one exact active CP store and configure the fake DP observation. */
	void SetUp() override
	{
		const uint64_t sequence = CP_STATS_ROOT_SEQUENCE.fetch_add(1u, std::memory_order_relaxed) + 1u;
		dir_ = std::filesystem::temp_directory_path() /
		       ("kinetum_cp_stats_" + std::to_string(static_cast<uint64_t>(::getpid())) + "_" +
			std::to_string(sequence));

		auto store_or = config_store::open(dir_);
		ASSERT_TRUE(store_or.is_ok()) << store_or.error().message();
		store_ = std::move(store_or).value();

		kinetum::control::v1::ConfigSnapshot snap;
		snap.set_snapshot_id("test_snap");
		snap.set_revision(1);
		snap.set_created_unix_ms(1000);
		kinetum::gluon::v1::DeploymentPlan module_free_plan;
		auto canonical_or = kinetum::common::canonicalize_config_snapshot(snap, module_free_plan);
		ASSERT_TRUE(canonical_or.is_ok()) << canonical_or.error().message();
		bootstrap_startup_authority authority;
		authority.snapshot = std::move(canonical_or).value();
		authority.plan_content_hash_bytes.fill(0x5au);
		authority.plan_content_hash = kinetum::common::bytes_to_hex(authority.plan_content_hash_bytes.data(),
									    authority.plan_content_hash_bytes.size());
		ASSERT_TRUE(store_->reconcile_bootstrap(&authority).is_ok());

		// Configure fake DP with known data
		dp_.service.rx_packets = 50000;
		dp_.service.tx_packets = 49500;
		dp_.service.dropped_packets = 500;
		dp_.service.active_epoch = 1;
		dp_.service.min_retained_epoch = 1;
		dp_.service.rx_bytes = 3'200'000;
		dp_.service.tx_bytes = 3'168'000;
		dp_.service.plan_content_hash.assign(
			reinterpret_cast<const char *>(authority.plan_content_hash_bytes.data()),
			authority.plan_content_hash_bytes.size());
		dp_.service.active_validation_hash.assign(
			reinterpret_cast<const char *>(authority.snapshot.validation_hash.data()),
			authority.snapshot.validation_hash.size());

		dp_.service.stage_stats = {
			{"rx", 10000, 10000, 0},
			{"parse", 10000, 9900, 100},
			{"acl", 9900, 9900, 0},
			{"tx", 9900, 9900, 0},
		};

		dp_.service.region_epoch_stats = {
			{0, 1, 1, 1, 0, 0, 0, 0},
			{1, 1, 1, 1, 0, 0, 0, 3},
		};

		dp_.service.boundary_epoch_stats = {
			{
				.boundary_id = "b_0_1_test",
				.boundary_index = 0,
				.from_stage_instance_index = 0,
				.to_stage_instance_index = 1,
				.sender_worker_index = 0,
				.receiver_worker_index = 1,
				.from_region_id = 0,
				.to_region_id = 1,
				.data_ring_capacity = 1024,
				.future_output_hold_capacity = 1024,
				.data_enqueued_sequence = 9900,
				.data_dequeued_sequence = 9900,
				.data_backpressure_events = 5,
				.transition_generation = 0,
				.from_epoch = 0,
				.to_epoch = 0,
				.cut_sequence = std::nullopt,
				.sender_phase = kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_OPEN,
				.receiver_phase = kinetum::telemetry::v1::BOUNDARY_RECEIVER_PHASE_OPEN,
				.cut_delivery_duration_ns = 0,
				.cut_drain_duration_ns = 0,
				.ack_gate_duration_ns = 0,
			},
		};

		dp_.service.stream_stats = {
			{"wan0.rx.lane_0", 1, kinetum::gluon::v1::IO_STREAM_DIRECTION_RX, 0, 0, 7,
			 dp_.service.latest_bank_publication_monotonic_ns, 50000, 3'200'000, 2},
			{"lan0.tx.lane_0", 2, kinetum::gluon::v1::IO_STREAM_DIRECTION_TX, 1, 1, 9,
			 dp_.service.latest_bank_publication_monotonic_ns, 49500, 3'168'000, 0},
		};

		dp_.service.storage_domain_stats = {
			{"storage.host.shared", std::nullopt, 131071, 12288, 64,
			 kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE, 1024, 130047},
		};

		dp_.service.port_stats = {
			{1, "wan0", "io.dpdk.0", "0000:01:00.0",
			 kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT, 1000, 0, 64000, 0, 2, 3, 0,
			 0},
			{2, "lan0", "io.dpdk.0", "0000:01:00.1",
			 kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT, 0, 998, 0, 63872, 0, 0, 1,
			 0},
		};

		dp_.service.traffic_steering_stats = {
			{"steering.rss0",
			 kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS,
			 false,
			 {"lan0.tx.lane_0", "wan0.rx.lane_0"}},
		};

		dp_.service.module_context_domains = {
			{"kinetum.acl", {"acl@lane_0"}},
		};
	}

	/** @brief Stop every fixture owner and remove its durable test root. */
	void TearDown() override
	{
		if (cp_server_) {
			cp_server_->Shutdown();
			cp_server_->Wait();
		}
		if (loop_) {
			loop_->stop();
		}
		dp_.shutdown();
		std::error_code ec;
		std::filesystem::remove_all(dir_, ec);
	}

	/**
	 * @brief Call CP GetStats through the service under test.
	 *
	 * Uses ASSERT_TRUE directly because gtest assertions in helper methods must
	 * preserve the fixture method's void return type.
	 *
	 * @param include_stage_stats Whether to request per-stage counters.
	 * @param include_region_epoch_stats Whether to request per-region counters.
	 * @param out Response object populated by the service call.
	 * @param include_stream_stats Whether to request compiled stream stats.
	 * @param include_storage_domain_stats Whether to request storage-domain stats.
	 * @param include_port_stats Whether to request logical-port driver stats.
	 * @param include_topology_stats Whether to request steering and flow-domain rows.
	 * @param include_boundary_epoch_stats Whether to request exact boundary progress.
	 */
	void call_get_stats(bool include_stage_stats, bool include_region_epoch_stats,
			    kinetum::control::v1::StatsResponse *out, bool include_stream_stats = false,
			    bool include_storage_domain_stats = false, bool include_port_stats = false,
			    bool include_topology_stats = false, bool include_boundary_epoch_stats = false)
	{
		ASSERT_NO_FATAL_FAILURE(start_services());

		kinetum::control::v1::StatsRequest req;
		auto *selection = req.mutable_selection();
		selection->set_include_stage_stats(include_stage_stats);
		selection->set_include_region_epoch_stats(include_region_epoch_stats);
		selection->set_include_boundary_epoch_stats(include_boundary_epoch_stats);
		selection->set_include_stream_stats(include_stream_stats);
		selection->set_include_storage_domain_stats(include_storage_domain_stats);
		selection->set_include_port_stats(include_port_stats);
		selection->set_include_topology_stats(include_topology_stats);

		grpc::ClientContext ctx;
		ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
		auto status = cp_stub_->GetStats(&ctx, req, out);
		ASSERT_TRUE(status.ok()) << "GetStats gRPC failed: " << status.error_message();
	}

	/**
	 * @brief Start both peers once so deadline and cancellation tests use native propagation.
	 * @param observe Optional outgoing statistics-context observer, owned by the DP channel.
	 */
	void start_services(std::function<void(const grpc::ClientContext &)> observe = {})
	{
		if (cp_service_) {
			return;
		}
		dp_.start();
		if (observe) {
			std::vector<std::unique_ptr<grpc::experimental::ClientInterceptorFactoryInterface>> observers;
			observers.push_back(std::make_unique<stats_call_observer>(std::move(observe)));
			dp_.stub = kinetum::dataplane::v1::DataplaneService::NewStub(
				grpc::experimental::CreateCustomChannelWithInterceptors(
					"localhost:" + std::to_string(dp_.port), grpc::InsecureChannelCredentials(),
					grpc::ChannelArguments{}, std::move(observers)));
		}
		loop_ = std::make_unique<control_loop>(store_.get(), dp_.stub);
		ASSERT_TRUE(loop_->start().is_ok());
		cp_service_ = std::make_unique<control_service_impl>(store_.get(), dp_.stub, *loop_);
		forwarder_ = std::make_unique<stats_forwarding_service>(*cp_service_);
		grpc::ServerBuilder builder;
		int port = 0;
		builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
		builder.RegisterService(forwarder_.get());
		cp_server_ = builder.BuildAndStart();
		ASSERT_NE(cp_server_, nullptr);
		ASSERT_GT(port, 0);
		cp_stub_ = kinetum::control::v1::ControlService::NewStub(
			grpc::CreateChannel("127.0.0.1:" + std::to_string(port), grpc::InsecureChannelCredentials()));
	}

	std::filesystem::path dir_;			       ///< Fixture-owned durable configuration directory.
	std::unique_ptr<config_store> store_;		       ///< Exact Control Plane storage authority.
	test::fake_dp_server dp_;			       ///< Scripted Data Plane RPC peer.
	std::unique_ptr<control_loop> loop_;		       ///< Production control loop forwarding the observation.
	std::unique_ptr<control_service_impl> cp_service_;     ///< Public Control Plane RPC surface under test.
	std::unique_ptr<stats_forwarding_service> forwarder_;  ///< Admission hook around the production service.
	std::unique_ptr<grpc::Server> cp_server_;	       ///< Server that owns genuine incoming call contexts.
	std::unique_ptr<kinetum::control::v1::ControlService::Stub> cp_stub_;  ///< Native operator-side client.
};

// ===============================================================================
// Tests
// ===============================================================================

// ---------------------------------------------------------------------------
// 1. Full stats forwarding (all flags true)
// ---------------------------------------------------------------------------

/**
 * @brief Verify forwards aggregate counters.
 */
TEST_F(CpStatsForwardingTest, forwards_aggregate_counters)
{
	dp_.service.stats_error_code = kinetum::common::v1::ERROR_CODE_OK;
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(true, true, &resp);

	ASSERT_TRUE(resp.has_telemetry());
	ASSERT_TRUE(resp.has_active_config());
	EXPECT_EQ(resp.telemetry().engine().rx_packets(), 50000u);
	EXPECT_EQ(resp.telemetry().engine().tx_packets(), 49500u);
	EXPECT_EQ(resp.telemetry().engine().dropped_packets(), 500u);
	EXPECT_EQ(resp.telemetry().engine().rx_bytes(), 3'200'000u);
	EXPECT_EQ(resp.telemetry().engine().tx_bytes(), 3'168'000u);
	EXPECT_EQ(resp.telemetry().engine().fanout_overflow(), 3u);
	EXPECT_EQ(resp.telemetry().runtime().active_epoch(), 1u);
	EXPECT_EQ(resp.telemetry().runtime().minimum_retained_epoch(), 1u);
	EXPECT_EQ(resp.active_config().revision(), 1);
	EXPECT_EQ(resp.active_config().snapshot_id(), "test_snap");
	EXPECT_EQ(resp.status().code(), 0);
}

/**
 * @brief Verify forwards stage stats when requested.
 */
TEST_F(CpStatsForwardingTest, forwards_stage_stats_when_requested)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(true, false, &resp);

	ASSERT_EQ(resp.telemetry().stages_size(), 4);
	EXPECT_EQ(resp.telemetry().stages(0).stage_id(), "rx");
	EXPECT_EQ(resp.telemetry().stages(0).in_packets(), 10000u);
	EXPECT_EQ(resp.telemetry().stages(0).dropped_packets(), 0u);

	EXPECT_EQ(resp.telemetry().stages(1).stage_id(), "parse");
	EXPECT_EQ(resp.telemetry().stages(1).in_packets(), 10000u);
	EXPECT_EQ(resp.telemetry().stages(1).out_packets(), 9900u);
	EXPECT_EQ(resp.telemetry().stages(1).dropped_packets(), 100u);
}

/**
 * @brief Verify forwards region stats when requested.
 */
TEST_F(CpStatsForwardingTest, forwards_region_epoch_stats_when_requested)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(false, true, &resp);

	ASSERT_EQ(resp.telemetry().regions_size(), 2);
	EXPECT_EQ(resp.telemetry().regions(0).region_id(), 0);
	EXPECT_EQ(resp.telemetry().regions(0).minimum_active_epoch(), 1u);
	EXPECT_EQ(resp.telemetry().regions(0).maximum_source_epoch(), 1u);

	EXPECT_EQ(resp.telemetry().regions(1).region_id(), 1);
	EXPECT_EQ(resp.telemetry().regions(1).fanout_overflow(), 3u);
}

/**
 * @brief Verify exact boundary rows forward only under their shared selector.
 */
TEST_F(CpStatsForwardingTest, boundary_epoch_stats_are_explicitly_selected)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(false, false, &resp, false, false, false, false, true);

	ASSERT_EQ(resp.telemetry().boundaries_size(), 1);
	const auto &bt = resp.telemetry().boundaries(0);
	EXPECT_EQ(bt.boundary_id(), "b_0_1_test");
	EXPECT_EQ(bt.from_region_id(), 0);
	EXPECT_EQ(bt.to_region_id(), 1);
	EXPECT_EQ(bt.data_enqueued_sequence(), 9900u);
	EXPECT_EQ(bt.data_dequeued_sequence(), 9900u);
	EXPECT_EQ(bt.data_backpressure_events(), 5u);
	EXPECT_EQ(bt.sender_phase(), kinetum::telemetry::v1::BOUNDARY_SENDER_PHASE_OPEN);
	EXPECT_EQ(bt.receiver_phase(), kinetum::telemetry::v1::BOUNDARY_RECEIVER_PHASE_OPEN);
	EXPECT_FALSE(bt.has_transition_generation());
}

/**
 * @brief Verify topology stats forward when requested.
 */
TEST_F(CpStatsForwardingTest, forwards_topology_stats_when_requested)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(false, false, &resp, true, true, false, true, true);

	const auto &telemetry = resp.telemetry();
	ASSERT_EQ(telemetry.streams_size(), 2);
	EXPECT_EQ(telemetry.streams(0).io_stream_id(), "wan0.rx.lane_0");
	EXPECT_EQ(telemetry.streams(0).logical_port_id(), 1u);
	EXPECT_EQ(telemetry.streams(0).direction(), kinetum::gluon::v1::IO_STREAM_DIRECTION_RX);
	EXPECT_EQ(telemetry.streams(0).owning_region_id(), 0);
	EXPECT_EQ(telemetry.streams(0).worker_index(), 0u);
	EXPECT_EQ(telemetry.streams(0).driver_queue_id(), 7u);
	EXPECT_EQ(telemetry.streams(0).published_monotonic_ns(), dp_.service.latest_bank_publication_monotonic_ns);
	EXPECT_EQ(telemetry.streams(0).packets(), 50000u);
	EXPECT_EQ(telemetry.streams(0).bytes(), 3'200'000u);
	EXPECT_EQ(telemetry.streams(0).rejected_packets(), 2u);
	EXPECT_TRUE(telemetry.streams(1).has_packets());
	EXPECT_TRUE(telemetry.streams(1).has_rejected_packets());
	EXPECT_EQ(telemetry.streams(1).packets(), 49500u);
	EXPECT_EQ(telemetry.streams(1).bytes(), 3'168'000u);
	EXPECT_EQ(telemetry.streams(1).rejected_packets(), 0u);

	ASSERT_EQ(telemetry.storage_domains_size(), 1);
	EXPECT_EQ(telemetry.storage_domains(0).storage_domain_id(), "storage.host.shared");
	EXPECT_FALSE(telemetry.storage_domains(0).has_host_numa_node());
	EXPECT_EQ(telemetry.storage_domains(0).buffer_count(), 131071u);
	EXPECT_EQ(telemetry.storage_domains(0).required_min_buffers(), 12288u);
	EXPECT_EQ(telemetry.storage_domains(0).safety_margin(), 64u);
	EXPECT_EQ(telemetry.storage_domains(0).observation_state(),
		  kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_APPROXIMATE);
	EXPECT_EQ(telemetry.storage_domains(0).in_use(), 1024u);
	EXPECT_EQ(telemetry.storage_domains(0).available(), 130047u);

	ASSERT_EQ(telemetry.ports_size(), 0);

	ASSERT_EQ(telemetry.steering_profiles_size(), 1);
	EXPECT_EQ(telemetry.steering_profiles(0).steering_profile_id(), "steering.rss0");
	EXPECT_EQ(telemetry.steering_profiles(0).kind(), kinetum::gluon::v1::TRAFFIC_STEERING_KIND_RSS);
	EXPECT_FALSE(telemetry.steering_profiles(0).symmetric());
	ASSERT_EQ(telemetry.steering_profiles(0).io_stream_ids_size(), 2);
	EXPECT_EQ(telemetry.steering_profiles(0).io_stream_ids(0), "lan0.tx.lane_0");

	ASSERT_EQ(telemetry.module_context_domains_size(), 1);
	EXPECT_EQ(telemetry.module_context_domains(0).module_id(), "kinetum.acl");
	ASSERT_EQ(telemetry.module_context_domains(0).context_instance_ids_size(), 1);
	EXPECT_EQ(telemetry.module_context_domains(0).context_instance_ids(0), "acl@lane_0");
}

/**
 * @brief Verify port stats forward when requested.
 */
TEST_F(CpStatsForwardingTest, forwards_port_stats_when_requested)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(false, false, &resp, false, false, true);

	ASSERT_EQ(resp.telemetry().ports_size(), 2);
	EXPECT_EQ(resp.telemetry().ports(0).logical_port_id(), 1u);
	EXPECT_EQ(resp.telemetry().ports(0).logical_name(), "wan0");
	EXPECT_EQ(resp.telemetry().ports(0).io_driver_instance_id(), "io.dpdk.0");
	EXPECT_EQ(resp.telemetry().ports(0).driver_port_id(), "0000:01:00.0");
	EXPECT_EQ(resp.telemetry().ports(0).observation_state(),
		  kinetum::telemetry::v1::PROVIDER_OBSERVATION_STATE_AVAILABLE_EXACT);
	EXPECT_EQ(resp.telemetry().ports(0).rx_packets(), 1000u);
	EXPECT_EQ(resp.telemetry().ports(0).tx_packets(), 0u);
	EXPECT_EQ(resp.telemetry().ports(0).rx_bytes(), 64000u);
	EXPECT_EQ(resp.telemetry().ports(0).tx_bytes(), 0u);
	EXPECT_EQ(resp.telemetry().ports(0).rx_missed(), 2u);
	EXPECT_EQ(resp.telemetry().ports(0).rx_errors(), 3u);
	EXPECT_EQ(resp.telemetry().ports(0).tx_errors(), 0u);
	EXPECT_EQ(resp.telemetry().ports(0).rx_no_buffer(), 0u);

	EXPECT_EQ(resp.telemetry().ports(1).logical_port_id(), 2u);
	EXPECT_EQ(resp.telemetry().ports(1).logical_name(), "lan0");
	EXPECT_EQ(resp.telemetry().ports(1).io_driver_instance_id(), "io.dpdk.0");
	EXPECT_EQ(resp.telemetry().ports(1).driver_port_id(), "0000:01:00.1");
	EXPECT_EQ(resp.telemetry().ports(1).rx_packets(), 0u);
	EXPECT_EQ(resp.telemetry().ports(1).tx_packets(), 998u);
	EXPECT_EQ(resp.telemetry().ports(1).tx_bytes(), 63872u);
	EXPECT_EQ(resp.telemetry().ports(1).tx_errors(), 1u);
}

// ---------------------------------------------------------------------------
// 2. Flag gating: stage_stats absent when not requested
// ---------------------------------------------------------------------------

/**
 * @brief Verify stage stats absent when not requested.
 */
TEST_F(CpStatsForwardingTest, stage_stats_absent_when_not_requested)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(false, true, &resp);

	EXPECT_EQ(resp.telemetry().stages_size(), 0);
}

// ---------------------------------------------------------------------------
// 3. Flag gating: region_epoch_stats absent when not requested
// ---------------------------------------------------------------------------

/**
 * @brief Verify region stats absent when not requested.
 */
TEST_F(CpStatsForwardingTest, region_epoch_stats_absent_when_not_requested)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(true, false, &resp);

	EXPECT_EQ(resp.telemetry().regions_size(), 0);
}

// ---------------------------------------------------------------------------
// 4. Both flags false: aggregate counters plus carried boundary telemetry
// ---------------------------------------------------------------------------

/**
 * @brief Verify minimal response with no flags.
 */
TEST_F(CpStatsForwardingTest, minimal_response_with_no_flags)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(false, false, &resp);

	// Aggregate counters always present
	EXPECT_EQ(resp.telemetry().engine().rx_packets(), 50000u);
	EXPECT_EQ(resp.telemetry().engine().tx_packets(), 49500u);

	// No stage or region stats
	EXPECT_EQ(resp.telemetry().stages_size(), 0);
	EXPECT_EQ(resp.telemetry().regions_size(), 0);
	EXPECT_EQ(resp.telemetry().streams_size(), 0);
	EXPECT_EQ(resp.telemetry().storage_domains_size(), 0);
	EXPECT_EQ(resp.telemetry().ports_size(), 0);
	EXPECT_EQ(resp.telemetry().steering_profiles_size(), 0);
	EXPECT_EQ(resp.telemetry().module_context_domains_size(), 0);
	EXPECT_EQ(resp.telemetry().boundaries_size(), 0);
}

/**
 * @brief Verify topology stats are absent when not requested.
 */
TEST_F(CpStatsForwardingTest, topology_stats_absent_when_not_requested)
{
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(true, true, &resp);

	EXPECT_EQ(resp.telemetry().streams_size(), 0);
	EXPECT_EQ(resp.telemetry().storage_domains_size(), 0);
	EXPECT_EQ(resp.telemetry().ports_size(), 0);
	EXPECT_EQ(resp.telemetry().steering_profiles_size(), 0);
	EXPECT_EQ(resp.telemetry().module_context_domains_size(), 0);
}

// ---------------------------------------------------------------------------
// 5. DP call counter: verify exactly one GetStats call per CP GetStats
// ---------------------------------------------------------------------------

/**
 * @brief Verify single DP call per cp call.
 */
TEST_F(CpStatsForwardingTest, single_dp_call_per_cp_call)
{
	int before = dp_.service.get_stats_calls.load();
	kinetum::control::v1::StatsResponse resp;
	call_get_stats(true, true, &resp);
	int after = dp_.service.get_stats_calls.load();

	EXPECT_EQ(after - before, 1);
}

/**
 * @brief Verify a DP application failure maps only its exact failed status.
 */
TEST_F(CpStatsForwardingTest, application_failure_maps_status_only)
{
	dp_.service.stats_status_code = static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE);
	dp_.service.stats_error_code = kinetum::common::v1::ERROR_CODE_UNAVAILABLE;
	dp_.service.stats_status_message = std::string(2u * MAX_RELAYED_STATS_FAILURE_BYTES, 'x');
	kinetum::control::v1::StatsResponse response;
	poison_aggregate_stats(&response);

	call_get_stats(true, true, &response, true, true, true, true, true);

	EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
	EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	EXPECT_EQ(response.status().message(), std::string(MAX_RELAYED_STATS_FAILURE_BYTES, 'x'));
	expect_status_only(response);
}

/**
 * @brief Verify a DP transport failure maps one unavailable status and no data.
 */
TEST_F(CpStatsForwardingTest, transport_failure_maps_status_only)
{
	dp_.service.stats_transport_code = grpc::StatusCode::UNAVAILABLE;
	dp_.service.stats_transport_message = "DP transport is unavailable";
	kinetum::control::v1::StatsResponse response;
	poison_aggregate_stats(&response);

	call_get_stats(true, true, &response, true, true, true, true, true);

	EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
	EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	EXPECT_EQ(response.status().message(), "DP transport is unavailable");
	expect_status_only(response);
}

/**
 * @brief Verify contradictory embedded status relations reject as data loss.
 */
TEST_F(CpStatsForwardingTest, malformed_application_status_maps_status_only)
{
	const auto expect_malformed = [this](int32_t status_code, kinetum::common::v1::ErrorCode error_code) {
		dp_.service.stats_status_code = status_code;
		dp_.service.stats_error_code = error_code;
		dp_.service.stats_status_message = "contradictory status";
		kinetum::control::v1::StatsResponse response;
		poison_aggregate_stats(&response);

		call_get_stats(true, true, &response, true, true, true, true, true);

		EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::DATA_LOSS));
		EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_DATA_LOSS);
		EXPECT_EQ(response.status().message(), "Data Plane returned a malformed statistics failure");
		expect_status_only(response);
	};

	expect_malformed(0, kinetum::common::v1::ERROR_CODE_INTERNAL);
	expect_malformed(static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE),
			 kinetum::common::v1::ERROR_CODE_OK);
	expect_malformed(0, static_cast<kinetum::common::v1::ErrorCode>(999));
}

/** @brief Every downstream transport category keeps its meaning and carries no aggregate data. */
TEST_F(CpStatsForwardingTest, transport_categories_are_not_flattened_to_unavailable)
{
	for (const auto code :
	     {grpc::StatusCode::CANCELLED, grpc::StatusCode::DEADLINE_EXCEEDED, grpc::StatusCode::PERMISSION_DENIED,
	      grpc::StatusCode::UNAUTHENTICATED, grpc::StatusCode::RESOURCE_EXHAUSTED, grpc::StatusCode::DATA_LOSS,
	      grpc::StatusCode::INTERNAL, grpc::StatusCode::FAILED_PRECONDITION}) {
		dp_.service.stats_transport_code = code;
		dp_.service.stats_transport_message = "downstream status";
		kinetum::control::v1::StatsResponse response;
		call_get_stats(false, false, &response);
		EXPECT_EQ(response.status().code(), static_cast<int32_t>(code));
		expect_status_only(response);
	}
}

/** @brief A transient status cannot conceal forbidden data or unknown response fields. */
TEST_F(CpStatsForwardingTest, malformed_transient_envelopes_are_terminal_data_loss)
{
	dp_.service.stats_status_code = static_cast<int32_t>(common::status_code::UNAVAILABLE);
	dp_.service.stats_error_code = kinetum::common::v1::ERROR_CODE_UNAVAILABLE;
	for (const bool poison_payload : {true, false}) {
		dp_.service.stats_response_observer =
			[poison_payload](grpc::ServerContext &, kinetum::dataplane::v1::StatsResponse &response) {
				if (poison_payload) {
					response.mutable_telemetry();
				} else {
					response.GetReflection()->MutableUnknownFields(&response)->AddVarint(99, 1u);
				}
			};
		kinetum::control::v1::StatsResponse response;
		call_get_stats(false, false, &response);
		EXPECT_EQ(response.status().code(), static_cast<int32_t>(common::status_code::DATA_LOSS));
		expect_status_only(response);
	}
}

/** @brief An expired incoming call reaches the handler but never launches a downstream observation. */
TEST_F(CpStatsForwardingTest, expired_incoming_deadline_short_circuits_before_dataplane_call)
{
	ASSERT_NO_FATAL_FAILURE(start_services());
	auto completed = std::make_shared<std::promise<kinetum::control::v1::StatsResponse>>();
	auto result = completed->get_future();
	std::promise<void> caller_completed;
	auto caller_done = caller_completed.get_future().share();
	forwarder_->before_call = [caller_done](grpc::ServerContext &context) {
		gpr_sleep_until(context.raw_deadline());
		// The application timeout reply must not race the client's transport deadline.
		caller_done.wait();
	};
	forwarder_->after_call = [completed](const kinetum::control::v1::StatsResponse &response) {
		completed->set_value(response);
	};
	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(100));
	kinetum::control::v1::StatsRequest request;
	request.mutable_selection();
	kinetum::control::v1::StatsResponse response;
	const auto transport = cp_stub_->GetStats(&context, request, &response);
	caller_completed.set_value();
	const auto completion = result.wait_for(std::chrono::seconds(2));
	// Join every callback before inspecting the final evidence, including failure paths.
	cp_server_->Shutdown();
	cp_server_->Wait();
	EXPECT_EQ(transport.error_code(), grpc::StatusCode::DEADLINE_EXCEEDED);
	ASSERT_EQ(completion, std::future_status::ready);
	const auto observed = result.get();
	EXPECT_EQ(observed.status().code(), static_cast<int32_t>(common::status_code::DEADLINE_EXCEEDED));
	expect_status_only(observed);
	EXPECT_EQ(dp_.service.get_stats_calls.load(), 0);
}

/** @brief Child deadlines honor both a short incoming budget and the local thirty-second cap. */
TEST_F(CpStatsForwardingTest, downstream_deadline_is_capped_by_incoming_and_local_limits)
{
	/** @brief One native deadline and the clock samples bracketing its selection. */
	struct deadline_observation {
		gpr_timespec deadline{};   ///< Native context deadline, before outgoing wire encoding.
		gpr_timespec realtime{};   ///< Realtime clock sampled before or after production selection.
		gpr_timespec monotonic{};  ///< Monotonic clock sampled on that same side of selection.
	};
	constexpr std::array BUDGETS{std::chrono::seconds(2), std::chrono::seconds(60)};
	constexpr std::size_t BUDGET_COUNT = BUDGETS.size();
	/** @brief Own every promise until the channel and its callbacks have retired. */
	struct child_observations {
		std::atomic<std::size_t> count{0u};  ///< Exact outgoing GetStats call count.
		std::array<std::promise<deadline_observation>, BUDGET_COUNT> values;  ///< One result per authored call.
	};
	const auto children = std::make_shared<child_observations>();
	ASSERT_NO_FATAL_FAILURE(start_services([children](const grpc::ClientContext &context) {
		const auto ordinal = children->count.fetch_add(1u, std::memory_order_relaxed);
		if (ordinal >= children->values.size()) {
			ADD_FAILURE() << "unexpected downstream statistics call";
			return;
		}
		const auto monotonic = gpr_now(GPR_CLOCK_MONOTONIC);
		const auto realtime = gpr_now(GPR_CLOCK_REALTIME);
		children->values[ordinal].set_value({context.raw_deadline(), realtime, monotonic});
	}));
	for (std::size_t ordinal = 0u; ordinal < BUDGETS.size(); ++ordinal) {
		SCOPED_TRACE(BUDGETS[ordinal].count());
		auto parent_deadline = std::make_shared<std::promise<deadline_observation>>();
		auto parent = parent_deadline->get_future();
		auto child = children->values[ordinal].get_future();
		forwarder_->before_call = [parent_deadline](grpc::ServerContext &context) {
			const auto realtime = gpr_now(GPR_CLOCK_REALTIME);
			const auto monotonic = gpr_now(GPR_CLOCK_MONOTONIC);
			parent_deadline->set_value({context.raw_deadline(), realtime, monotonic});
		};
		grpc::ClientContext context;
		context.set_deadline(std::chrono::system_clock::now() + BUDGETS[ordinal]);
		kinetum::control::v1::StatsRequest request;
		request.mutable_selection();
		kinetum::control::v1::StatsResponse response;
		const auto transport = cp_stub_->GetStats(&context, request, &response);
		ASSERT_TRUE(transport.ok()) << transport.error_message();
		EXPECT_EQ(response.status().code(), 0);
		ASSERT_EQ(parent.wait_for(std::chrono::seconds(1)), std::future_status::ready);
		ASSERT_EQ(child.wait_for(std::chrono::seconds(1)), std::future_status::ready);
		const auto incoming = parent.get();
		const auto outgoing = child.get();
		ASSERT_EQ(incoming.deadline.clock_type, GPR_CLOCK_MONOTONIC);
		ASSERT_EQ(outgoing.deadline.clock_type, GPR_CLOCK_REALTIME);
		const auto local_cap = gpr_time_from_seconds(30, GPR_TIMESPAN);
		// ServerContext converts its monotonic deadline using fresh clock samples.
		// Bound that conversion and the local cap by samples around the real handler.
		const auto lower = gpr_time_min(gpr_time_add(incoming.realtime,
							     gpr_time_sub(incoming.deadline, outgoing.monotonic)),
						gpr_time_add(incoming.realtime, local_cap));
		const auto upper = gpr_time_min(gpr_time_add(outgoing.realtime,
							     gpr_time_sub(incoming.deadline, incoming.monotonic)),
						gpr_time_add(outgoing.realtime, local_cap));
		EXPECT_GE(grpc::Timespec2Timepoint(outgoing.deadline), grpc::Timespec2Timepoint(lower));
		EXPECT_LE(grpc::Timespec2Timepoint(outgoing.deadline), grpc::Timespec2Timepoint(upper));
	}
	EXPECT_EQ(children->count.load(std::memory_order_relaxed), BUDGETS.size());
}

/** @brief Client cancellation propagates through CP while the downstream handler owns its work. */
TEST_F(CpStatsForwardingTest, incoming_cancellation_reaches_the_native_child_context)
{
	ASSERT_NO_FATAL_FAILURE(start_services());
	std::promise<void> entered;
	auto admission = entered.get_future();
	std::atomic<bool> cancelled{false};
	dp_.service.stats_response_observer = [&entered, &cancelled](grpc::ServerContext &context,
								     kinetum::dataplane::v1::StatsResponse &) {
		entered.set_value();
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
		while (!context.IsCancelled() && std::chrono::steady_clock::now() < deadline) {
			std::this_thread::yield();
		}
		cancelled.store(context.IsCancelled(), std::memory_order_release);
	};
	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
	auto call = std::async(std::launch::async, [this, &context] {
		kinetum::control::v1::StatsRequest request;
		request.mutable_selection();
		kinetum::control::v1::StatsResponse response;
		return cp_stub_->GetStats(&context, request, &response);
	});
	const auto admitted = admission.wait_for(std::chrono::seconds(2));
	context.TryCancel();
	const auto transport = call.get();
	cp_server_->Shutdown();
	cp_server_->Wait();
	dp_.shutdown();
	EXPECT_EQ(admitted, std::future_status::ready);
	EXPECT_EQ(transport.error_code(), grpc::StatusCode::CANCELLED);
	EXPECT_TRUE(cancelled.load(std::memory_order_acquire));
}

/** @brief Reject a transport-successful but intrinsically malformed payload. */
TEST_F(CpStatsForwardingTest, malformed_runtime_telemetry_maps_data_loss_status_only)
{
	dp_.service.plan_content_hash = "short";
	kinetum::control::v1::StatsResponse response;
	poison_aggregate_stats(&response);
	call_get_stats(false, false, &response);
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::DATA_LOSS));
	EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_DATA_LOSS);
	EXPECT_EQ(response.status().message(), "Data Plane returned malformed runtime telemetry");
	expect_status_only(response);
}

/** @brief An unexplained coherent DP epoch contradicts durable CP allocation truth. */
TEST_F(CpStatsForwardingTest, unexplained_active_epoch_split_maps_data_loss_status_only)
{
	dp_.service.active_epoch = 2u;
	dp_.service.min_retained_epoch = 2u;
	kinetum::control::v1::StatsResponse response;
	poison_aggregate_stats(&response);
	call_get_stats(false, false, &response);
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::DATA_LOSS));
	EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_DATA_LOSS);
	expect_status_only(response);
}

/** @brief Exact DP completion ahead of CP publication is retryable unavailability. */
TEST_F(CpStatsForwardingTest, completion_reply_loss_maps_unavailable_until_durable_promotion)
{
	kinetum::control::v1::ConfigSnapshot candidate;
	candidate.set_snapshot_id("stats-target");
	candidate.set_revision(2);
	candidate.set_created_unix_ms(2'000);
	auto transition_or = store_->begin_epoch_transition(candidate, "stats-target-key", 0u);
	ASSERT_TRUE(transition_or.is_ok()) << transition_or.error().message();
	ASSERT_TRUE(store_->advance_epoch_transition_phase(
				  transition_or->identity,
				  kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED)
			    .is_ok());
	ASSERT_TRUE(store_->advance_epoch_transition_phase(
				  transition_or->identity,
				  kinetum::control::internal::v1::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING)
			    .is_ok());
	dp_.service.active_epoch = transition_or->identity.target_epoch;
	dp_.service.min_retained_epoch = transition_or->identity.target_epoch;
	dp_.service.allocated_epoch_high_watermark = transition_or->identity.target_epoch;
	dp_.service.mutation_sequence_high_watermark = transition_or->identity.mutation_sequence;
	dp_.service.active_validation_hash.assign(
		reinterpret_cast<const char *>(transition_or->identity.validation_hash.data()),
		transition_or->identity.validation_hash.size());
	dp_.service.latest_completed_transition = kinetum::test::fake_completed_transition_stats{
		.mutation_sequence = transition_or->identity.mutation_sequence,
		.from_epoch = 1u,
		.to_epoch = transition_or->identity.target_epoch,
		.validation_hash = dp_.service.active_validation_hash,
		.idempotency_key_digest = std::string(
			reinterpret_cast<const char *>(transition_or->identity.idempotency_key_digest.data()),
			transition_or->identity.idempotency_key_digest.size()),
	};
	kinetum::control::v1::StatsResponse response;
	poison_aggregate_stats(&response);
	call_get_stats(false, false, &response);
	EXPECT_EQ(response.status().code(), static_cast<int32_t>(kinetum::common::status_code::UNAVAILABLE));
	EXPECT_EQ(response.status().error_code(), kinetum::common::v1::ERROR_CODE_UNAVAILABLE);
	EXPECT_EQ(response.status().message(), "Data Plane completion is awaiting durable Control Plane publication");
	expect_status_only(response);
}

}  // namespace
}  // namespace kinetum::cp
