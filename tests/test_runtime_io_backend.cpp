// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_runtime_io_backend.cpp
 * @brief Final provider-neutral runtime materialization and lifetime tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "src/common/status.hpp"
#include "src/common/application_status.hpp"
#include "src/dp/runtime_telemetry_source_owner.hpp"
#include "src/dp/runtime_telemetry_snapshot_source.hpp"

namespace kinetum::dp
{

namespace
{

/** Initial materialized generation published by the fixture. */
constexpr uint64_t FIRST_TEST_GENERATION = 41;
/** Replacement generation used to prove publication/retirement separation. */
constexpr uint64_t SECOND_TEST_GENERATION = 42;

/** @brief Shared deterministic gate and destruction evidence for a fake source. */
struct telemetry_source_probe {
	std::mutex mutex;				 ///< Protects all non-owner test predicates.
	std::condition_variable cv;			 ///< Wakes the test and blocked collection.
	bool collection_entered{false};			 ///< Whether collect reached foreign code.
	bool release_collection{false};			 ///< Whether blocked collection may return.
	bool destroyed{false};				 ///< Whether the source destructor ran.
	bool destroyed_without_owner_lock{false};	 ///< Whether destruction re-entered owner observation.
	runtime_telemetry_source_owner *owner{nullptr};	 ///< Owner inspected during destruction.
};

/** @brief Blocking coherent source used to prove claim and retirement ordering. */
class blocking_telemetry_source final : public runtime_telemetry_source {
    public:
	/**
	 * @brief Bind one source to its deterministic test gate.
	 * @param probe Borrowed gate and destruction observations retained through source retirement.
	 */
	explicit blocking_telemetry_source(telemetry_source_probe &probe) noexcept
		: probe_(probe)
	{
	}

	/** @brief Publish unlocked destruction evidence. */
	~blocking_telemetry_source() override
	{
		const bool owner_is_detached = probe_.owner != nullptr &&
					       !probe_.owner->published_generation().has_value();
		{
			std::lock_guard<std::mutex> lock(probe_.mutex);
			probe_.destroyed_without_owner_lock = owner_is_detached;
			probe_.destroyed = true;
		}
		probe_.cv.notify_all();
	}

	/** @return Fixed stage0 snapshot after the probe releases this blocked collection; the request is unused. */
	[[nodiscard]] common::status_or<runtime_telemetry_snapshot>
	collect(const runtime_telemetry_request &) const override
	{
		std::unique_lock<std::mutex> lock(probe_.mutex);
		probe_.collection_entered = true;
		probe_.cv.notify_all();
		probe_.cv.wait(lock, [this]() { return probe_.release_collection; });
		lock.unlock();

		runtime_telemetry_snapshot snapshot;
		snapshot.stages.push_back(runtime_stage_statistics{.stage_id = "stage0"});
		return snapshot;
	}

    private:
	telemetry_source_probe &probe_;	 ///< Deterministic foreign-callback gate.
};

/** @brief Throwing source used to prove exceptional claim release. */
class throwing_telemetry_source final : public runtime_telemetry_source {
    public:
	/**
	 * @brief Bind destruction evidence to the owning publication.
	 * @param probe Borrowed destruction observations retained through source retirement.
	 */
	explicit throwing_telemetry_source(telemetry_source_probe &probe) noexcept
		: probe_(probe)
	{
	}

	/** @brief Publish unlocked destruction evidence. */
	~throwing_telemetry_source() override
	{
		const bool owner_is_detached = probe_.owner != nullptr &&
					       !probe_.owner->published_generation().has_value();
		{
			std::lock_guard<std::mutex> lock(probe_.mutex);
			probe_.destroyed_without_owner_lock = owner_is_detached;
			probe_.destroyed = true;
		}
		probe_.cv.notify_all();
	}

	/**
	 * @brief Inject an exception without consuming the request.
	 * @return Never returns a snapshot.
	 * @throws std::runtime_error on every invocation.
	 */
	[[nodiscard]] common::status_or<runtime_telemetry_snapshot>
	collect(const runtime_telemetry_request &) const override
	{
		throw std::runtime_error("injected telemetry exception");
	}

    private:
	telemetry_source_probe &probe_;	 ///< Deterministic destruction evidence.
};

/** @brief Immediate source used to prove a newer generation can publish. */
class immediate_telemetry_source final : public runtime_telemetry_source {
    public:
	/** @return Empty successful snapshot without inspecting the request. */
	[[nodiscard]] common::status_or<runtime_telemetry_snapshot>
	collect(const runtime_telemetry_request &) const override
	{
		return runtime_telemetry_snapshot{};
	}
};

/** @brief Keep a real RPC handler's collection claim alive independently of its client. */
class claimed_statistics_service final : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/**
	 * @brief Borrow the published source owner for the registered server lifetime.
	 * @param owner Generation authority whose callback is controlled by the fixture.
	 */
	explicit claimed_statistics_service(runtime_telemetry_source_owner &owner)
		: owner_(owner)
	{
	}

	/**
	 * @brief Hold the production claim through its callback even after client cancellation.
	 * @param response Receives a status-only fixture refusal after callback completion.
	 * @return Transport OK; this fixture supplies no successful telemetry payload.
	 */
	grpc::Status GetStats(grpc::ServerContext *, const kinetum::dataplane::v1::StatsRequest *,
			      kinetum::dataplane::v1::StatsResponse *response) override
	{
		const auto observed = owner_.collect(FIRST_TEST_GENERATION, runtime_telemetry_request{});
		response->Clear();
		const auto code = observed.is_ok() ? common::status_code::UNAVAILABLE : observed.error().code();
		response->mutable_status()->set_code(static_cast<int32_t>(code));
		response->mutable_status()->set_error_code(common::application_error_code(code));
		return grpc::Status::OK;
	}

    private:
	runtime_telemetry_source_owner &owner_;	 ///< Must outlive server and every collection.
};

}  // namespace

/** @brief A retired proof is absent after a later preparation abort, never reused as current evidence. */
TEST(runtime_io_backend, completion_projection_requires_an_exact_current_or_terminal_owner)
{
	epoch_transition_progress_snapshot progress{.publication_generation = 1u,
						    .phase = epoch_transition_phase::IDLE,
						    .active_epoch = 8u,
						    .allocated_epoch_high_watermark = 8u,
						    .mutation_sequence_high_watermark = 5u,
						    .execution_participant_count = 1u,
						    .region_count = 1u,
						    .source_participant_count = 1u,
						    .sink_participant_count = 1u,
						    .quiescence_reader_count = 1u,
						    .terminal_history_size = 1u,
						    .last_terminal_outcome = epoch_transition_outcome::COMPLETE};
	progress.active_validation_hash.fill(0x5au);
	epoch_transition_telemetry_snapshot transactions{};
	transactions.publication_generation = 1u;
	auto &terminal = transactions.latest_terminal;
	terminal.present = true;
	terminal.identity.target_epoch = 8u;
	terminal.identity.mutation_sequence = 5u;
	terminal.identity.validation_hash.fill(0x5au);
	terminal.identity.idempotency_key_digest.fill(0x2au);
	terminal.from_epoch = 6u;
	terminal.to_epoch = 8u;
	terminal.admitted_monotonic_ns = 100u;
	terminal.prepared_monotonic_ns = 110u;
	terminal.commit_started_monotonic_ns = 120u;
	terminal.retiring_started_monotonic_ns = 130u;
	terminal.terminal_monotonic_ns = 140u;
	terminal.outcome = epoch_transition_outcome::COMPLETE;
	epoch_transition_completion_progress_snapshot completion{
		.publication_generation = 1u,
		.runtime_generation = FIRST_TEST_GENERATION,
		.transition_generation = 5u,
		.from_epoch = 6u,
		.to_epoch = 8u,
		.evaluated_monotonic_ns = 130u,
		.grace_generation = 1u,
		.grace_started_monotonic_ns = 120u,
		.grace_completion_observed_monotonic_ns = 130u,
		.grace_finished_monotonic_ns = 140u,
		.execution_complete = 1u,
		.execution_total = 1u,
		.reader_complete = 1u,
		.reader_total = 1u,
		.certificate_state = epoch_transition_certificate_state::RECLAMATION_READY,
		.ownership_withdrawn = true};
	ASSERT_EQ(validate_epoch_completion_progress(completion), publication_read_result::AVAILABLE);
	const auto exact = project_runtime_completion_progress(publication_read_result::AVAILABLE, completion, progress,
							       transactions);
	ASSERT_TRUE(exact.is_ok());
	ASSERT_TRUE(exact->has_value());
	EXPECT_EQ(exact->value().transition_generation, 5u);

	progress.allocated_epoch_high_watermark = 9u;
	progress.mutation_sequence_high_watermark = 6u;
	progress.terminal_history_size = 2u;
	progress.last_terminal_outcome = epoch_transition_outcome::ABORTED;
	terminal.identity.target_epoch = 9u;
	terminal.identity.mutation_sequence = 6u;
	terminal.from_epoch = 8u;
	terminal.to_epoch = 9u;
	terminal.admitted_monotonic_ns = 200u;
	terminal.prepared_monotonic_ns = 0u;
	terminal.commit_started_monotonic_ns = 0u;
	terminal.retiring_started_monotonic_ns = 0u;
	terminal.failure_observed_monotonic_ns = 210u;
	terminal.terminal_monotonic_ns = 210u;
	terminal.outcome = epoch_transition_outcome::ABORTED;
	terminal.failure_code = epoch_transition_failure_code::EXPLICIT_ABORT;
	const auto retired = project_runtime_completion_progress(publication_read_result::AVAILABLE, completion,
								 progress, transactions);
	ASSERT_TRUE(retired.is_ok());
	EXPECT_FALSE(retired->has_value());

	std::array invalid_proofs{completion, completion, completion, completion};
	invalid_proofs[0].certificate_state = epoch_transition_certificate_state::INCOMPLETE;
	invalid_proofs[1].certificate_fault = epoch_transition_certificate_fault::EXECUTION_STATE;
	invalid_proofs[1].fault_index = 0u;
	invalid_proofs[2].fault_index = 0u;
	invalid_proofs[3].evaluated_monotonic_ns = 0u;
	for (const auto &invalid_proof : invalid_proofs) {
		const auto read = validate_epoch_completion_progress(invalid_proof);
		ASSERT_EQ(read, publication_read_result::INVALID_STATE);
		const auto rejected = project_runtime_completion_progress(read, invalid_proof, progress, transactions);
		ASSERT_FALSE(rejected.is_ok());
		EXPECT_EQ(rejected.error().code(), common::status_code::DATA_LOSS);
	}

	progress.phase = epoch_transition_phase::PREPARED;
	progress.target_epoch = 10u;
	progress.mutation_sequence = 7u;
	progress.participants_frozen = true;
	transactions.active = terminal;
	transactions.active.identity.target_epoch = 10u;
	transactions.active.identity.mutation_sequence = 7u;
	transactions.active.to_epoch = 10u;
	transactions.active.admitted_monotonic_ns = 220u;
	transactions.active.prepared_monotonic_ns = 230u;
	transactions.active.prepared_lease_deadline_monotonic_ns = 300u;
	transactions.active.prepared_lease_deadline_unix_ms = 1u;
	transactions.active.terminal_monotonic_ns = 0u;
	transactions.active.failure_observed_monotonic_ns = 0u;
	transactions.active.outcome = epoch_transition_outcome::NONE;
	transactions.active.failure_code = epoch_transition_failure_code::NONE;
	progress.allocated_epoch_high_watermark = 10u;
	progress.mutation_sequence_high_watermark = 7u;
	const auto lag = project_runtime_completion_progress(publication_read_result::AVAILABLE, completion, progress,
							     transactions);
	ASSERT_FALSE(lag.is_ok());
	EXPECT_EQ(lag.error().code(), common::status_code::UNAVAILABLE);
	completion.transition_generation = 7u;
	completion.from_epoch = 6u;
	completion.to_epoch = 10u;
	const auto contradiction = project_runtime_completion_progress(publication_read_result::AVAILABLE, completion,
								       progress, transactions);
	ASSERT_FALSE(contradiction.is_ok());
	EXPECT_EQ(contradiction.error().code(), common::status_code::DATA_LOSS);
}

/** @brief Only the two real runtime-before-coordinator edges are retryable epoch mismatches. */
TEST(runtime_io_backend, runtime_epoch_projection_distinguishes_publication_gaps_from_contradictions)
{
	/** @brief One complete epoch tuple and its expected stable-authority disposition. */
	struct observation_case {
		epoch_transition_phase phase;	   ///< Coordinator phase observed at both collection boundaries.
		uint64_t active;		   ///< Runtime active and last-activated epoch.
		uint64_t retained;		   ///< Runtime minimum retained epoch.
		publication_read_result expected;  ///< Contract result for the tuple.
	};
	constexpr std::array CASES{
		observation_case{epoch_transition_phase::IDLE, 6u, 6u, publication_read_result::AVAILABLE},
		observation_case{epoch_transition_phase::PREPARING, 6u, 6u, publication_read_result::AVAILABLE},
		observation_case{epoch_transition_phase::PREPARED, 6u, 6u, publication_read_result::AVAILABLE},
		observation_case{epoch_transition_phase::COMMITTING, 6u, 6u, publication_read_result::AVAILABLE},
		observation_case{epoch_transition_phase::RETIRING, 8u, 6u, publication_read_result::AVAILABLE},
		observation_case{epoch_transition_phase::FAILED_STOP, 6u, 6u, publication_read_result::AVAILABLE},
		observation_case{epoch_transition_phase::FAILED_STOP, 8u, 6u, publication_read_result::AVAILABLE},
		observation_case{epoch_transition_phase::COMMITTING, 8u, 6u, publication_read_result::UNAVAILABLE},
		observation_case{epoch_transition_phase::RETIRING, 8u, 8u, publication_read_result::UNAVAILABLE},
		observation_case{epoch_transition_phase::IDLE, 8u, 8u, publication_read_result::INVALID_STATE},
		observation_case{epoch_transition_phase::PREPARING, 8u, 6u, publication_read_result::INVALID_STATE},
		observation_case{epoch_transition_phase::PREPARED, 8u, 6u, publication_read_result::INVALID_STATE},
		observation_case{epoch_transition_phase::COMMITTING, 8u, 8u, publication_read_result::INVALID_STATE},
		observation_case{epoch_transition_phase::RETIRING, 6u, 6u, publication_read_result::INVALID_STATE},
		observation_case{epoch_transition_phase::RETIRING, 8u, 5u, publication_read_result::INVALID_STATE},
		observation_case{epoch_transition_phase::FAILED_STOP, 7u, 6u, publication_read_result::INVALID_STATE},
		observation_case{epoch_transition_phase::FAILED_STOP, 9u, 9u, publication_read_result::INVALID_STATE},
	};
	for (const auto &row : CASES) {
		SCOPED_TRACE(static_cast<unsigned>(row.phase));
		SCOPED_TRACE(row.active);
		SCOPED_TRACE(row.retained);
		const runtime_status_snapshot runtime{
			.publication_generation = 1u,
			.readiness = runtime_readiness::PACKET_READY,
			.runtime_generation = FIRST_TEST_GENERATION,
			.active_epoch = row.active,
			.minimum_retained_epoch = row.retained,
			.last_activated_epoch = row.active,
			.active_workers = 1u,
			.expected_workers = 1u,
		};
		const bool transitioning = row.phase != epoch_transition_phase::IDLE;
		epoch_transition_progress_snapshot progress{
			.publication_generation = 1u,
			.phase = row.phase,
			.active_epoch = 6u,
			.target_epoch = transitioning ? 8u : 0u,
			.mutation_sequence = transitioning ? 2u : 0u,
			.allocated_epoch_high_watermark = transitioning ? 8u : 6u,
			.mutation_sequence_high_watermark = 2u,
			.participants_frozen = transitioning,
			.execution_participant_count = 1u,
			.region_count = 1u,
			.source_participant_count = 1u,
			.sink_participant_count = 1u,
			.quiescence_reader_count = 1u,
			.last_terminal_outcome = row.phase == epoch_transition_phase::FAILED_STOP ?
							 epoch_transition_outcome::FAILED_STOP :
							 epoch_transition_outcome::NONE,
		};
		progress.active_validation_hash.fill(0x5au);
		EXPECT_EQ(classify_runtime_status_transition(runtime, progress), row.expected);
	}
}

/** @brief A pre-PREPARED failure reports its state without inventing a completion owner. */
TEST(runtime_io_backend, failed_preparation_does_not_require_uncreated_completion_evidence)
{
	epoch_transition_progress_snapshot progress{
		.publication_generation = 1u,
		.phase = epoch_transition_phase::FAILED_STOP,
		.active_epoch = 8u,
		.target_epoch = 9u,
		.mutation_sequence = 7u,
		.allocated_epoch_high_watermark = 9u,
		.mutation_sequence_high_watermark = 7u,
		.participants_frozen = true,
		.execution_participant_count = 1u,
		.region_count = 1u,
		.source_participant_count = 1u,
		.sink_participant_count = 1u,
		.quiescence_reader_count = 1u,
		.last_terminal_outcome = epoch_transition_outcome::FAILED_STOP,
	};
	progress.active_validation_hash.fill(0x5au);
	epoch_transition_telemetry_snapshot transactions{};
	transactions.publication_generation = 1u;
	auto &active = transactions.active;
	active.present = true;
	active.identity.target_epoch = 9u;
	active.identity.mutation_sequence = 7u;
	active.identity.validation_hash.fill(0x6au);
	active.identity.idempotency_key_digest.fill(0x2au);
	active.from_epoch = 8u;
	active.to_epoch = 9u;
	active.admitted_monotonic_ns = 100u;
	active.failure_observed_monotonic_ns = 110u;
	active.failure_code = epoch_transition_failure_code::PROTOCOL_FAULT;

	const auto absent =
		project_runtime_completion_progress(publication_read_result::UNAVAILABLE, {}, progress, transactions);
	ASSERT_TRUE(absent.is_ok());
	EXPECT_FALSE(absent->has_value());
	const auto invalid =
		project_runtime_completion_progress(publication_read_result::INVALID_STATE, {}, progress, transactions);
	ASSERT_FALSE(invalid.is_ok());
	EXPECT_EQ(invalid.error().code(), common::status_code::DATA_LOSS);

	active.prepared_monotonic_ns = 105u;
	active.prepared_lease_deadline_monotonic_ns = 1000u;
	active.prepared_lease_deadline_unix_ms = 1000u;
	const auto armed_missing =
		project_runtime_completion_progress(publication_read_result::UNAVAILABLE, {}, progress, transactions);
	ASSERT_FALSE(armed_missing.is_ok());
	EXPECT_EQ(armed_missing.error().code(), common::status_code::UNAVAILABLE);
}

/** @brief Invalid evidence wins over unavailable records in every collection order. */
TEST(runtime_io_backend, collection_failure_precedence_is_independent_of_reader_order)
{
	for (const bool invalid_first : {false, true}) {
		common::status result;
		merge_runtime_telemetry_failure(result, invalid_first ?
								common::status::data_loss("invalid publication") :
								common::status::unavailable("publication in progress"));
		merge_runtime_telemetry_failure(result, invalid_first ?
								common::status::unavailable("publication in progress") :
								common::status::data_loss("invalid publication"));
		merge_runtime_telemetry_failure(result, common::status::ok());
		EXPECT_EQ(result.code(), common::status_code::DATA_LOSS);
		EXPECT_EQ(result.message(), "invalid publication");
	}
}

/** @brief Prove retirement fences waiters and destroys only after the active claim quiesces. */
TEST(runtime_io_backend, statistics_source_owner_quiesces_claim_before_unlocked_retirement)
{
	telemetry_source_probe probe;
	runtime_telemetry_source_owner owner;
	probe.owner = &owner;
	ASSERT_TRUE(owner.publish(FIRST_TEST_GENERATION, std::make_unique<blocking_telemetry_source>(probe)).is_ok());

	std::promise<common::status_code> active_result_promise;
	auto active_result = active_result_promise.get_future();
	std::thread active_collector([&owner, &active_result_promise]() {
		auto result =
			owner.collect(FIRST_TEST_GENERATION, runtime_telemetry_request{.include_stage_stats = true});
		active_result_promise.set_value(result.is_ok() ? common::status_code::OK : result.error().code());
	});
	bool collection_entered = false;
	{
		std::unique_lock<std::mutex> lock(probe.mutex);
		collection_entered = probe.cv.wait_for(lock, std::chrono::seconds(2),
						       [&probe]() { return probe.collection_entered; });
	}
	EXPECT_TRUE(collection_entered);
	if (!collection_entered) {
		{
			std::lock_guard<std::mutex> lock(probe.mutex);
			probe.release_collection = true;
		}
		probe.cv.notify_all();
		active_collector.join();
		owner.retire();
		return;
	}

	std::promise<void> retired_promise;
	auto retired = retired_promise.get_future();
	std::thread retirement([&owner, &retired_promise]() {
		owner.retire();
		retired_promise.set_value();
	});
	bool retirement_detached = false;
	const auto detach_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	do {
		retirement_detached = !owner.published_generation().has_value();
		if (!retirement_detached) {
			std::this_thread::yield();
		}
	} while (!retirement_detached && std::chrono::steady_clock::now() < detach_deadline);
	EXPECT_TRUE(retirement_detached);
	if (!retirement_detached) {
		{
			std::lock_guard<std::mutex> lock(probe.mutex);
			probe.release_collection = true;
		}
		probe.cv.notify_all();
		active_collector.join();
		retirement.join();
		return;
	}

	std::promise<common::status_code> waiting_result_promise;
	auto waiting_result = waiting_result_promise.get_future();
	std::thread waiting_collector([&owner, &waiting_result_promise]() {
		auto result = owner.collect(FIRST_TEST_GENERATION, runtime_telemetry_request{});
		waiting_result_promise.set_value(result.is_ok() ? common::status_code::OK : result.error().code());
	});

	EXPECT_EQ(waiting_result.wait_for(std::chrono::seconds(2)), std::future_status::ready);
	if (waiting_result.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
		EXPECT_EQ(waiting_result.get(), common::status_code::UNAVAILABLE);
	}
	EXPECT_EQ(retired.wait_for(std::chrono::milliseconds(20)), std::future_status::timeout);
	{
		std::lock_guard<std::mutex> lock(probe.mutex);
		probe.release_collection = true;
	}
	probe.cv.notify_all();

	active_collector.join();
	waiting_collector.join();
	retirement.join();
	EXPECT_EQ(active_result.get(), common::status_code::OK);
	EXPECT_EQ(retired.wait_for(std::chrono::seconds(0)), std::future_status::ready);
	EXPECT_TRUE(probe.destroyed);
	EXPECT_TRUE(probe.destroyed_without_owner_lock);
	EXPECT_FALSE(owner.published_generation().has_value());

	EXPECT_TRUE(owner.publish(SECOND_TEST_GENERATION, std::make_unique<immediate_telemetry_source>()).is_ok());
	EXPECT_TRUE(owner.collect(SECOND_TEST_GENERATION, runtime_telemetry_request{}).is_ok());
	owner.retire();
}

/** @brief A cancelled gRPC client cannot let retirement destroy a still-running collection source. */
TEST(runtime_io_backend, client_cancellation_does_not_release_an_accepted_collection_claim)
{
	telemetry_source_probe probe;
	runtime_telemetry_source_owner owner;
	probe.owner = &owner;
	ASSERT_TRUE(owner.publish(FIRST_TEST_GENERATION, std::make_unique<blocking_telemetry_source>(probe)).is_ok());
	claimed_statistics_service service(owner);
	grpc::ServerBuilder builder;
	int port = 0;
	builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
	builder.RegisterService(&service);
	auto server = builder.BuildAndStart();
	ASSERT_NE(server, nullptr);
	ASSERT_GT(port, 0);
	auto stub = kinetum::dataplane::v1::DataplaneService::NewStub(
		grpc::CreateChannel("127.0.0.1:" + std::to_string(port), grpc::InsecureChannelCredentials()));
	grpc::ClientContext context;
	context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
	auto reply = std::async(std::launch::async, [&context, &stub] {
		kinetum::dataplane::v1::StatsRequest request;
		request.mutable_selection();
		kinetum::dataplane::v1::StatsResponse response;
		return stub->GetStats(&context, request, &response);
	});
	bool admitted = false;
	{
		std::unique_lock lock(probe.mutex);
		admitted =
			probe.cv.wait_for(lock, std::chrono::seconds(2), [&probe] { return probe.collection_entered; });
	}
	context.TryCancel();
	const auto transport = reply.get();
	std::promise<void> retired_promise;
	auto retired = retired_promise.get_future();
	std::thread retirement([&] {
		owner.retire();
		retired_promise.set_value();
	});
	const auto detach_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (owner.published_generation().has_value() && std::chrono::steady_clock::now() < detach_deadline) {
		std::this_thread::yield();
	}
	EXPECT_TRUE(admitted);
	EXPECT_EQ(transport.error_code(), grpc::StatusCode::CANCELLED);
	EXPECT_FALSE(owner.published_generation().has_value());
	if (admitted) {
		EXPECT_EQ(retired.wait_for(std::chrono::seconds(0)), std::future_status::timeout);
	}
	{
		std::lock_guard lock(probe.mutex);
		if (admitted) {
			EXPECT_FALSE(probe.destroyed);
		}
		probe.release_collection = true;
	}
	probe.cv.notify_all();
	retirement.join();
	server->Shutdown();
	server->Wait();
	EXPECT_TRUE(probe.destroyed);
	EXPECT_TRUE(probe.destroyed_without_owner_lock);
}

/** @brief Prove a throwing foreign callback cannot strand the claim or locked destruction. */
TEST(runtime_io_backend, statistics_source_owner_releases_throwing_claim_before_retirement)
{
	telemetry_source_probe probe;
	runtime_telemetry_source_owner owner;
	probe.owner = &owner;
	ASSERT_TRUE(owner.publish(FIRST_TEST_GENERATION, std::make_unique<throwing_telemetry_source>(probe)).is_ok());

	auto result = owner.collect(FIRST_TEST_GENERATION, runtime_telemetry_request{});
	ASSERT_FALSE(result.is_ok());
	EXPECT_EQ(result.error().code(), common::status_code::INTERNAL_ERROR);

	owner.retire();
	EXPECT_TRUE(probe.destroyed);
	EXPECT_TRUE(probe.destroyed_without_owner_lock);
	EXPECT_FALSE(owner.published_generation().has_value());
	EXPECT_TRUE(owner.publish(SECOND_TEST_GENERATION, std::make_unique<immediate_telemetry_source>()).is_ok());
	owner.retire();
}

}  // namespace kinetum::dp
