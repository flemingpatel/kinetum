// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_transition_certificate.cpp
 * @brief Exact execution, boundary, and reader certificate tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <kinetum/algo/quiescence.hpp>

#include "src/dp/epoch/epoch_transition_certificate.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "tests/packet_runtime_test_fixture.hpp"
#include "tests/worker_telemetry_test_fixture.hpp"

namespace kinetum::dp
{
namespace
{

namespace runtime_fixture = kinetum::test::packet_runtime_fixture_detail;

/** Runtime generation shared by every certificate participant. */
constexpr uint64_t TEST_RUNTIME_GENERATION = 1u;
/** Exact worker transition-command generation. */
constexpr uint64_t TEST_TRANSITION_GENERATION = 3u;
/** Old epoch whose owners and readers must retire. */
constexpr uint64_t TEST_FROM_EPOCH = 11u;
/** Replacement epoch whose activation must be observed. */
constexpr uint64_t TEST_TO_EPOCH = 13u;
/** Reader-grace generation associated with the certificate request. */
constexpr uint64_t TEST_GRACE_GENERATION = 1u;
/** Fixture worker's exact unretired-credit bound. */
constexpr uint64_t TEST_MAXIMUM_UNRETIRED = 16u;
/** UDP ingress endpoint used by the compiled fixture. */
constexpr uint16_t TEST_RX_PORT = 43001u;
/** UDP egress endpoint used by the compiled fixture. */
constexpr uint16_t TEST_TX_PORT = 43002u;

/** @return Exact certificate request shared by pure classifier rows. */
[[nodiscard]] epoch_transition_certificate_request request()
{
	return {
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.transition_generation = TEST_TRANSITION_GENERATION,
		.from_epoch = TEST_FROM_EPOCH,
		.to_epoch = TEST_TO_EPOCH,
		.grace_generation = TEST_GRACE_GENERATION,
	};
}

/** @return Exact completed worker ledger publication with live target work. */
[[nodiscard]] worker_epoch_ledger_snapshot completed_ledger()
{
	return {
		.publication_generation = 2u,
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.worker_index = 0u,
		.active_epoch = TEST_TO_EPOCH,
		.source_epoch = TEST_TO_EPOCH,
		.active_unretired = 7u,
		.future_epoch = 0u,
		.future_unretired = 0u,
	};
}

/** @return Exact completed worker activation publication. */
[[nodiscard]] worker_epoch_activation_snapshot completed_activation()
{
	return {
		.publication_generation = 2u,
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.worker_index = 0u,
		.transition_generation = TEST_TRANSITION_GENERATION,
		.from_epoch = TEST_FROM_EPOCH,
		.to_epoch = TEST_TO_EPOCH,
		.active_epoch = TEST_TO_EPOCH,
		.activation_complete = 1u,
		.activation_monotonic_ns = 25u,
	};
}

/** @return Exact completed sender policy proof for boundary zero. */
[[nodiscard]] boundary_sender_transition_snapshot completed_sender()
{
	return {
		.publication_generation = 2u,
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.boundary_index = 0u,
		.transition_generation = TEST_TRANSITION_GENERATION,
		.from_epoch = TEST_FROM_EPOCH,
		.to_epoch = TEST_TO_EPOCH,
		.cut_sequence = 9u,
		.ack_observed = 1u,
		.cut_published_monotonic_ns = 10u,
		.ack_observed_monotonic_ns = 40u,
		.open_epoch = TEST_TO_EPOCH,
		.phase = boundary_epoch_sender_phase::OPEN,
	};
}

/** @return Exact completed receiver policy proof for boundary zero. */
[[nodiscard]] boundary_receiver_transition_snapshot completed_receiver()
{
	return {
		.publication_generation = 2u,
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.boundary_index = 0u,
		.transition_generation = TEST_TRANSITION_GENERATION,
		.from_epoch = TEST_FROM_EPOCH,
		.to_epoch = TEST_TO_EPOCH,
		.cut_sequence = 9u,
		.ack_published = 1u,
		.cut_observed_monotonic_ns = 15u,
		.cut_drained_monotonic_ns = 20u,
		.activation_monotonic_ns = 25u,
		.ack_published_monotonic_ns = 30u,
		.active_epoch = TEST_TO_EPOCH,
		.phase = boundary_epoch_receiver_phase::OPEN,
	};
}

/** @return Exact sender transport at or beyond the sealed cut. */
[[nodiscard]] boundary_sender_transport_snapshot completed_sender_transport()
{
	return {
		.publication_generation = 2u,
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.boundary_index = 0u,
		.data_enqueued_sequence = 12u,
	};
}

/** @return Exact receiver transport at the sealed cut. */
[[nodiscard]] boundary_receiver_transport_snapshot completed_receiver_transport()
{
	return {
		.publication_generation = 2u,
		.runtime_generation = TEST_RUNTIME_GENERATION,
		.boundary_index = 0u,
		.data_dequeued_sequence = 9u,
	};
}

/**
 * @brief Build one available worker observation from exact fixture publications.
 * @param ledger Complete ownership publication.
 * @param activation Complete activation publication.
 * @return Both independently available records.
 */
[[nodiscard]] epoch_transition_certificate_worker_read worker_read(const worker_epoch_ledger_snapshot &ledger,
								   const worker_epoch_activation_snapshot &activation)
{
	return {.value = {ledger, activation},
		.ledger = publication_read_result::AVAILABLE,
		.activation = publication_read_result::AVAILABLE};
}

/**
 * @brief Build one available boundary observation from exact fixture publications.
 * @param sender Complete sender policy.
 * @param receiver Complete receiver policy.
 * @param sender_transport Complete sender transport.
 * @param receiver_transport Complete receiver transport.
 * @return Four independently available records.
 */
[[nodiscard]] epoch_transition_certificate_boundary_read
boundary_read(const boundary_sender_transition_snapshot &sender, const boundary_receiver_transition_snapshot &receiver,
	      const boundary_sender_transport_snapshot &sender_transport,
	      const boundary_receiver_transport_snapshot &receiver_transport)
{
	return {.value = {sender, receiver, sender_transport, receiver_transport},
		.sender = publication_read_result::AVAILABLE,
		.receiver = publication_read_result::AVAILABLE,
		.sender_transport = publication_read_result::AVAILABLE,
		.receiver_transport = publication_read_result::AVAILABLE};
}

/** @brief Live target credit must not be misclassified as surviving old work. */
TEST(epoch_transition_certificate, activation_proves_old_drain_while_target_credit_remains_live)
{
	const auto result =
		classify_execution_certificate(request(), 0u, worker_read(completed_ledger(), completed_activation()));
	EXPECT_EQ(result.result, epoch_transition_certificate_record_result::COMPLETE);
	EXPECT_EQ(result.fault, epoch_transition_certificate_fault::NONE);

	auto old_ledger = completed_ledger();
	old_ledger.active_epoch = TEST_FROM_EPOCH;
	old_ledger.source_epoch = TEST_TO_EPOCH;
	old_ledger.future_epoch = TEST_TO_EPOCH;
	old_ledger.active_unretired = 0u;
	old_ledger.future_unretired = 7u;
	const auto pending =
		classify_execution_certificate(request(), 0u, worker_read(old_ledger, completed_activation()));
	EXPECT_EQ(pending.result, epoch_transition_certificate_record_result::INCOMPLETE);
	EXPECT_EQ(pending.fault, epoch_transition_certificate_fault::NONE);

	old_ledger.source_epoch = TEST_TO_EPOCH + 1u;
	old_ledger.future_epoch = TEST_TO_EPOCH + 1u;
	const auto unrelated =
		classify_execution_certificate(request(), 0u, worker_read(old_ledger, completed_activation()));
	EXPECT_EQ(unrelated.result, epoch_transition_certificate_record_result::CONTRADICTION);
	EXPECT_EQ(unrelated.fault, epoch_transition_certificate_fault::EXECUTION_STATE);
}

/** @brief Require exact sender/receiver cut identity and both ACK edges. */
TEST(epoch_transition_certificate, boundary_completion_requires_exact_cut_and_both_ack_edges)
{
	const auto exact = classify_boundary_certificate(request(), 0u,
							 boundary_read(completed_sender(), completed_receiver(),
								       completed_sender_transport(),
								       completed_receiver_transport()));
	EXPECT_EQ(exact.result, epoch_transition_certificate_record_result::COMPLETE);
	EXPECT_EQ(exact.fault, epoch_transition_certificate_fault::NONE);

	auto missing_sender_edge = completed_sender();
	missing_sender_edge.transition_generation = 0u;
	missing_sender_edge.from_epoch = 0u;
	missing_sender_edge.to_epoch = TEST_FROM_EPOCH;
	missing_sender_edge.cut_sequence = 0u;
	missing_sender_edge.ack_observed = 0u;
	missing_sender_edge.cut_published_monotonic_ns = 0u;
	missing_sender_edge.ack_observed_monotonic_ns = 0u;
	missing_sender_edge.open_epoch = TEST_FROM_EPOCH;
	const auto sender_pending = classify_boundary_certificate(
		request(), 0u,
		boundary_read(missing_sender_edge, completed_receiver(), completed_sender_transport(),
			      completed_receiver_transport()));
	EXPECT_EQ(sender_pending.result, epoch_transition_certificate_record_result::INCOMPLETE);
	EXPECT_EQ(sender_pending.fault, epoch_transition_certificate_fault::NONE);

	auto missing_receiver_edge = completed_receiver();
	missing_receiver_edge.transition_generation = 0u;
	missing_receiver_edge.from_epoch = 0u;
	missing_receiver_edge.to_epoch = TEST_FROM_EPOCH;
	missing_receiver_edge.cut_sequence = 0u;
	missing_receiver_edge.ack_published = 0u;
	missing_receiver_edge.cut_observed_monotonic_ns = 0u;
	missing_receiver_edge.cut_drained_monotonic_ns = 0u;
	missing_receiver_edge.activation_monotonic_ns = 0u;
	missing_receiver_edge.ack_published_monotonic_ns = 0u;
	missing_receiver_edge.active_epoch = TEST_FROM_EPOCH;
	const auto receiver_pending = classify_boundary_certificate(
		request(), 0u,
		boundary_read(completed_sender(), missing_receiver_edge, completed_sender_transport(),
			      completed_receiver_transport()));
	EXPECT_EQ(receiver_pending.result, epoch_transition_certificate_record_result::INCOMPLETE);
	EXPECT_EQ(receiver_pending.fault, epoch_transition_certificate_fault::NONE);

	auto lagging_transport = completed_receiver_transport();
	lagging_transport.data_dequeued_sequence = 8u;
	const auto pending =
		classify_boundary_certificate(request(), 0u,
					      boundary_read(completed_sender(), completed_receiver(),
							    completed_sender_transport(), lagging_transport));
	EXPECT_EQ(pending.result, epoch_transition_certificate_record_result::INCOMPLETE);

	auto mismatched_receiver = completed_receiver();
	mismatched_receiver.cut_sequence = 8u;
	const auto conflict = classify_boundary_certificate(request(), 0u,
							    boundary_read(completed_sender(), mismatched_receiver,
									  completed_sender_transport(),
									  completed_receiver_transport()));
	EXPECT_EQ(conflict.result, epoch_transition_certificate_record_result::CONTRADICTION);
	EXPECT_EQ(conflict.fault, epoch_transition_certificate_fault::CUT_IDENTITY);
}

/** @brief One lagging fan-in edge prevents aggregate completion without region inference. */
TEST(epoch_transition_certificate, fan_in_remains_incomplete_when_one_boundary_lags)
{
	auto first_sender = completed_sender();
	auto first_receiver = completed_receiver();
	auto first_sender_transport = completed_sender_transport();
	auto first_receiver_transport = completed_receiver_transport();
	const auto first = classify_boundary_certificate(
		request(), 0u,
		boundary_read(first_sender, first_receiver, first_sender_transport, first_receiver_transport));

	auto second_sender = completed_sender();
	auto second_receiver = completed_receiver();
	auto second_sender_transport = completed_sender_transport();
	auto second_receiver_transport = completed_receiver_transport();
	second_sender.boundary_index = 1u;
	second_receiver.boundary_index = 1u;
	second_sender_transport.boundary_index = 1u;
	second_receiver_transport.boundary_index = 1u;
	second_receiver_transport.data_dequeued_sequence = 8u;
	const auto second = classify_boundary_certificate(
		request(), 1u,
		boundary_read(second_sender, second_receiver, second_sender_transport, second_receiver_transport));
	EXPECT_EQ(first.result, epoch_transition_certificate_record_result::COMPLETE);
	EXPECT_EQ(second.result, epoch_transition_certificate_record_result::INCOMPLETE);
	EXPECT_FALSE(first.result == epoch_transition_certificate_record_result::COMPLETE &&
		     second.result == epoch_transition_certificate_record_result::COMPLETE);
}

/** @brief Future generations and ownership mismatch remain typed contradictions. */
TEST(epoch_transition_certificate, coherent_future_and_membership_mismatch_are_typed_contradictions)
{
	auto future = completed_activation();
	++future.transition_generation;
	const auto future_result =
		classify_execution_certificate(request(), 0u, worker_read(completed_ledger(), future));
	EXPECT_EQ(future_result.result, epoch_transition_certificate_record_result::CONTRADICTION);
	EXPECT_EQ(future_result.fault, epoch_transition_certificate_fault::EXECUTION_STATE);

	auto foreign = completed_ledger();
	foreign.worker_index = 1u;
	const auto foreign_result =
		classify_execution_certificate(request(), 0u, worker_read(foreign, completed_activation()));
	EXPECT_EQ(foreign_result.result, epoch_transition_certificate_record_result::CONTRADICTION);
	EXPECT_EQ(foreign_result.fault, epoch_transition_certificate_fault::EXECUTION_MEMBERSHIP);
}

/**
 * @brief Return the sender's complete legal publication at one current-transition phase.
 * @param phase Phase under test; UNBOUND has no current-transition publication.
 * @return Exact sender state and edge timestamps for the selected phase.
 */
[[nodiscard]] boundary_sender_transition_snapshot sender_in_phase(boundary_epoch_sender_phase phase)
{
	auto value = completed_sender();
	value.phase = phase;
	switch (phase) {
	case boundary_epoch_sender_phase::UNBOUND:
		std::terminate();
	case boundary_epoch_sender_phase::OPEN:
		break;
	case boundary_epoch_sender_phase::DRAINING:
		value.cut_sequence = 0u;
		[[fallthrough]];
	case boundary_epoch_sender_phase::CUT_PENDING:
		value.cut_published_monotonic_ns = 0u;
		[[fallthrough]];
	case boundary_epoch_sender_phase::WAITING_ACK:
		value.ack_observed = 0u;
		value.ack_observed_monotonic_ns = 0u;
		value.open_epoch = TEST_FROM_EPOCH;
		break;
	}
	return value;
}

/**
 * @brief Return the receiver's complete legal publication at one current-transition phase.
 * @param phase Phase under test; UNBOUND has no current-transition publication.
 * @return Exact receiver state and edge timestamps for the selected phase.
 */
[[nodiscard]] boundary_receiver_transition_snapshot receiver_in_phase(boundary_epoch_receiver_phase phase)
{
	auto value = completed_receiver();
	value.phase = phase;
	switch (phase) {
	case boundary_epoch_receiver_phase::UNBOUND:
		std::terminate();
	case boundary_epoch_receiver_phase::OPEN:
	case boundary_epoch_receiver_phase::ACK_PUBLISHED:
		break;
	case boundary_epoch_receiver_phase::WAITING_CUT:
		value.cut_sequence = 0u;
		value.cut_observed_monotonic_ns = 0u;
		[[fallthrough]];
	case boundary_epoch_receiver_phase::CUT_DRAINING:
		value.cut_drained_monotonic_ns = 0u;
		[[fallthrough]];
	case boundary_epoch_receiver_phase::CUT_DRAINED:
		value.activation_monotonic_ns = 0u;
		value.active_epoch = TEST_FROM_EPOCH;
		[[fallthrough]];
	case boundary_epoch_receiver_phase::ACK_PENDING:
		value.ack_published = 0u;
		value.ack_published_monotonic_ns = 0u;
		break;
	}
	return value;
}

/** @brief Every legal current CUT/ACK phase is incomplete until both endpoint proofs complete. */
TEST(epoch_transition_certificate, current_boundary_intermediates_are_not_contradictions)
{
	constexpr std::array SENDER_PHASES{boundary_epoch_sender_phase::DRAINING,
					   boundary_epoch_sender_phase::CUT_PENDING,
					   boundary_epoch_sender_phase::WAITING_ACK, boundary_epoch_sender_phase::OPEN};
	constexpr std::array RECEIVER_PHASES{
		boundary_epoch_receiver_phase::WAITING_CUT,   boundary_epoch_receiver_phase::CUT_DRAINING,
		boundary_epoch_receiver_phase::CUT_DRAINED,   boundary_epoch_receiver_phase::ACK_PENDING,
		boundary_epoch_receiver_phase::ACK_PUBLISHED, boundary_epoch_receiver_phase::OPEN};
	for (const auto sender_phase : SENDER_PHASES) {
		for (const auto receiver_phase : RECEIVER_PHASES) {
			SCOPED_TRACE(static_cast<unsigned>(sender_phase));
			SCOPED_TRACE(static_cast<unsigned>(receiver_phase));
			auto observed = boundary_read(sender_in_phase(sender_phase), receiver_in_phase(receiver_phase),
						      completed_sender_transport(), completed_receiver_transport());
			if (sender_phase == boundary_epoch_sender_phase::CUT_PENDING) {
				observed.value.sender_transport.pending_cut_epoch = TEST_TO_EPOCH;
				observed.value.sender_transport.pending_cut_sequence = 9u;
			}
			if (receiver_phase == boundary_epoch_receiver_phase::ACK_PENDING) {
				observed.value.receiver_transport.pending_ack_epoch = TEST_TO_EPOCH;
				observed.value.receiver_transport.pending_ack_sequence = 9u;
			}
			const bool complete = sender_phase == boundary_epoch_sender_phase::OPEN &&
					      (receiver_phase == boundary_epoch_receiver_phase::OPEN ||
					       receiver_phase == boundary_epoch_receiver_phase::ACK_PUBLISHED);
			const auto result = classify_boundary_certificate(request(), 0u, observed);
			EXPECT_EQ(result.result, complete ? epoch_transition_certificate_record_result::COMPLETE :
							    epoch_transition_certificate_record_result::INCOMPLETE);
			EXPECT_EQ(result.fault, epoch_transition_certificate_fault::NONE);
		}
	}
}

/** @brief Captured-cut conflict rejects before ACK completion; a captured zero cut is valid. */
TEST(epoch_transition_certificate, cut_identity_depends_on_capture_not_nonzero_sequence)
{
	auto observed = boundary_read(sender_in_phase(boundary_epoch_sender_phase::WAITING_ACK),
				      receiver_in_phase(boundary_epoch_receiver_phase::CUT_DRAINING),
				      completed_sender_transport(), completed_receiver_transport());
	observed.value.receiver.cut_sequence = 8u;
	observed.sender_transport = publication_read_result::UNAVAILABLE;
	const auto conflict = classify_boundary_certificate(request(), 0u, observed);
	EXPECT_EQ(conflict.result, epoch_transition_certificate_record_result::CONTRADICTION);
	EXPECT_EQ(conflict.fault, epoch_transition_certificate_fault::CUT_IDENTITY);

	observed = boundary_read(completed_sender(), completed_receiver(), completed_sender_transport(),
				 completed_receiver_transport());
	observed.value.sender.cut_sequence = 0u;
	observed.value.receiver.cut_sequence = 0u;
	EXPECT_EQ(classify_boundary_certificate(request(), 0u, observed).result,
		  epoch_transition_certificate_record_result::COMPLETE);
}

/** @brief Every invalid reader position dominates every unavailable sibling position. */
TEST(epoch_transition_certificate, invalid_boundary_read_outranks_unavailable_in_every_position)
{
	for (std::size_t invalid = 0u; invalid < 4u; ++invalid) {
		for (std::size_t unavailable = 0u; unavailable < 4u; ++unavailable) {
			if (invalid == unavailable) {
				continue;
			}
			for (const auto error :
			     {publication_read_result::INVALID_IDENTITY, publication_read_result::INVALID_STATE}) {
				auto observed = boundary_read(completed_sender(), completed_receiver(),
							      completed_sender_transport(),
							      completed_receiver_transport());
				const std::array fields{&observed.sender, &observed.receiver,
							&observed.sender_transport, &observed.receiver_transport};
				*fields[invalid] = error;
				*fields[unavailable] = publication_read_result::UNAVAILABLE;
				EXPECT_EQ(observed.result(), error);
				const auto result = classify_boundary_certificate(request(), 0u, observed);
				EXPECT_EQ(result.result, epoch_transition_certificate_record_result::CONTRADICTION);
				EXPECT_EQ(result.fault,
					  error == publication_read_result::INVALID_IDENTITY ?
						  epoch_transition_certificate_fault::BOUNDARY_MEMBERSHIP :
						  epoch_transition_certificate_fault::BOUNDARY_STATE);
			}
		}
	}
}

/** @brief Unavailable siblings cannot hide a coherent identity or request-relative contradiction. */
TEST(epoch_transition_certificate, partial_observations_preserve_available_contradictions)
{
	auto worker = worker_read(completed_ledger(), completed_activation());
	worker.ledger = publication_read_result::UNAVAILABLE;
	++worker.value.activation.transition_generation;
	EXPECT_EQ(classify_execution_certificate(request(), 0u, worker).fault,
		  epoch_transition_certificate_fault::EXECUTION_STATE);
	worker = worker_read(completed_ledger(), completed_activation());
	worker.activation = publication_read_result::UNAVAILABLE;
	++worker.value.ledger.worker_index;
	EXPECT_EQ(classify_execution_certificate(request(), 0u, worker).fault,
		  epoch_transition_certificate_fault::EXECUTION_MEMBERSHIP);

	for (const bool sender_available : {true, false}) {
		auto boundary = boundary_read(completed_sender(), completed_receiver(), completed_sender_transport(),
					      completed_receiver_transport());
		if (sender_available) {
			boundary.receiver = publication_read_result::UNAVAILABLE;
			++boundary.value.sender.to_epoch;
		} else {
			boundary.sender = publication_read_result::UNAVAILABLE;
			++boundary.value.receiver.to_epoch;
		}
		EXPECT_EQ(classify_boundary_certificate(request(), 0u, boundary).fault,
			  epoch_transition_certificate_fault::BOUNDARY_STATE);
	}
}

/** @brief Separate execution completion from the exact reader-grace leg. */
TEST(epoch_transition_certificate, single_worker_graph_separates_execution_and_reader_completion)
{
	const runtime_fixture::host_selection selection{.numa_node = 0, .cpu_cores = {0, 1, 2}};
	auto compiled_or = runtime_fixture::compile_runtime_fixture(runtime_fixture::make_pipeline(std::nullopt),
								    selection, TEST_RX_PORT, TEST_TX_PORT, 0u, 0u);
	ASSERT_TRUE(compiled_or.is_ok()) << compiled_or.error().message();
	auto compiled = std::move(compiled_or).value();
	auto participants_or = frozen_transition_participants::create(compiled.topology);
	ASSERT_TRUE(participants_or.is_ok()) << participants_or.error().message();
	auto participants = std::move(participants_or).value();
	ASSERT_EQ(participants->execution_participant_count(), 1u);
	ASSERT_EQ(participants->boundary_count(), 0u);
	ASSERT_EQ(compiled.topology.worker_schedules.size(), 1u);
	ASSERT_EQ(compiled.topology.transition_topology.workers.size(), 1u);

	auto ledger_or = worker_epoch_ledger::create(0u, TEST_RUNTIME_GENERATION, TEST_MAXIMUM_UNRETIRED);
	ASSERT_TRUE(ledger_or.is_ok()) << ledger_or.error().message();
	auto ledger = std::move(ledger_or).value();
	std::array<boundary_epoch_channel *, 0> channels{};
	std::array<boundary_future_output_hold *, 0> holds{};
	auto sender_or = worker_boundary_sender::create(0u, TEST_RUNTIME_GENERATION, channels, holds);
	auto receiver_or = worker_boundary_receiver::create(0u, TEST_RUNTIME_GENERATION, channels);
	ASSERT_TRUE(sender_or.is_ok()) << sender_or.error().message();
	ASSERT_TRUE(receiver_or.is_ok()) << receiver_or.error().message();
	auto sender = std::move(sender_or).value();
	auto receiver = std::move(receiver_or).value();
	ASSERT_TRUE(sender->bind_ledger(*ledger).is_ok());
	ASSERT_TRUE(receiver->bind_ledger(*ledger).is_ok());
	std::array<module::module_epoch_store *, 0> modules{};
	const auto &schedule = compiled.topology.worker_schedules.front();
	const auto &worker = compiled.topology.transition_topology.workers.front();
	ASSERT_FALSE(schedule.source_storage_domain_indices.empty());
	ASSERT_GT(worker.source_epoch_staging_capacity, 0u);
	std::vector<std::unique_ptr<packet_epoch_input_staging>> staging_owners;
	std::vector<packet_epoch_input_staging *> staging;
	staging_owners.reserve(schedule.source_storage_domain_indices.size());
	staging.reserve(schedule.source_storage_domain_indices.size());
	for (std::size_t index = 0u; index < schedule.source_storage_domain_indices.size(); ++index) {
		const std::size_t capacity = static_cast<std::size_t>(worker.source_epoch_staging_capacity);
		auto staging_or = packet_epoch_input_staging::create(capacity, std::optional<std::size_t>{capacity},
								     worker.numa_node);
		ASSERT_TRUE(staging_or.is_ok()) << staging_or.error().message();
		staging.push_back(staging_or->get());
		staging_owners.push_back(std::move(staging_or).value());
	}
	auto telemetry_or = test::worker_telemetry_test_owner::create(0u, TEST_RUNTIME_GENERATION, {});
	ASSERT_TRUE(telemetry_or.is_ok()) << telemetry_or.error().message();
	auto telemetry = std::move(telemetry_or).value();
	auto activation_or = worker_epoch_activation::create(0u, TEST_RUNTIME_GENERATION, modules, staging, *ledger,
							     nullptr, nullptr, *telemetry->telemetry);
	ASSERT_TRUE(activation_or.is_ok()) << activation_or.error().message();
	auto activation = std::move(activation_or).value();
	ASSERT_EQ(activation->source_staging_count(), schedule.source_storage_domain_indices.size());

	kinetum::algo::quiescence_reader reader;
	std::array<kinetum::algo::quiescence_reader *, 1> readers{&reader};
	kinetum::algo::quiescence_domain domain(readers);
	std::array<epoch_transition_certificate_worker_source, 1> sources{epoch_transition_certificate_worker_source{
		.ledger = ledger.get(),
		.activation = activation.get(),
		.sender = sender.get(),
		.receiver = receiver.get(),
		.reader = &reader,
	}};
	auto foreign_ledger_or = worker_epoch_ledger::create(0u, TEST_RUNTIME_GENERATION, TEST_MAXIMUM_UNRETIRED);
	ASSERT_TRUE(foreign_ledger_or.is_ok()) << foreign_ledger_or.error().message();
	auto foreign_ledger = std::move(foreign_ledger_or).value();
	auto mismatched_sources = sources;
	mismatched_sources[0].ledger = foreign_ledger.get();
	auto mismatched_certificate = epoch_transition_certificate::create(TEST_RUNTIME_GENERATION, *participants,
									   mismatched_sources, channels, domain);
	ASSERT_FALSE(mismatched_certificate.is_ok());
	EXPECT_EQ(mismatched_certificate.error().code(), common::status_code::FAILED_PRECONDITION);
	auto incomplete_sources = sources;
	incomplete_sources[0].reader = nullptr;
	auto incomplete_certificate = epoch_transition_certificate::create(TEST_RUNTIME_GENERATION, *participants,
									   incomplete_sources, channels, domain);
	ASSERT_FALSE(incomplete_certificate.is_ok());
	EXPECT_EQ(incomplete_certificate.error().code(), common::status_code::FAILED_PRECONDITION);
	auto certificate_or =
		epoch_transition_certificate::create(TEST_RUNTIME_GENERATION, *participants, sources, channels, domain);
	ASSERT_TRUE(certificate_or.is_ok()) << certificate_or.error().message();
	auto certificate = std::move(certificate_or).value();

	ledger->bind_bootstrap_epoch(TEST_FROM_EPOCH);
	sender->bind_bootstrap_epoch(TEST_FROM_EPOCH);
	receiver->bind_bootstrap_epoch(TEST_FROM_EPOCH);
	telemetry->telemetry->bind_bootstrap_epoch(TEST_FROM_EPOCH, 1u);
	activation->bind_bootstrap_epoch(TEST_FROM_EPOCH);
	const uint64_t grace_generation = domain.start_grace_period();
	ASSERT_EQ(grace_generation, TEST_GRACE_GENERATION);
	epoch_transition_certificate_request exact_request = request();
	exact_request.grace_generation = grace_generation;
	const auto initial = certificate->evaluate(exact_request);
	EXPECT_EQ(initial.state, epoch_transition_certificate_state::INCOMPLETE);
	EXPECT_EQ(initial.execution_complete, 0u);

	ASSERT_TRUE(telemetry->telemetry->reserve_target_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH).is_ok());
	ledger->bind_future_epoch(TEST_TO_EPOCH);
	ASSERT_TRUE(sender->begin_transition(TEST_TRANSITION_GENERATION, TEST_FROM_EPOCH, TEST_TO_EPOCH));
	ASSERT_TRUE(receiver->begin_transition(TEST_TRANSITION_GENERATION, TEST_FROM_EPOCH, TEST_TO_EPOCH));
	ledger->advance_source_epoch(TEST_TO_EPOCH);
	ASSERT_TRUE(receiver->activation_ready());
	ASSERT_TRUE(sender->try_seal_after_old_work_drained());
	ASSERT_TRUE(activation->activate(TEST_TRANSITION_GENERATION, TEST_FROM_EPOCH, TEST_TO_EPOCH, 1u).is_ok());
	receiver->acknowledge_activation(TEST_TRANSITION_GENERATION, TEST_TO_EPOCH);
	receiver->complete_receiver_transition(TEST_TRANSITION_GENERATION);
	sender->complete_sender_transition(TEST_TRANSITION_GENERATION);
	ledger->publish();

	const auto before_reader = certificate->evaluate(exact_request);
	EXPECT_EQ(before_reader.state, epoch_transition_certificate_state::EXECUTION_COMPLETE);
	EXPECT_EQ(before_reader.execution_complete, 1u);
	EXPECT_EQ(before_reader.boundary_total, 0u);
	EXPECT_EQ(before_reader.reader_complete, 0u);
	EXPECT_EQ(reader.publish_quiescent(), grace_generation);
	const auto complete = certificate->evaluate(exact_request);
	EXPECT_EQ(complete.state, epoch_transition_certificate_state::RECLAMATION_READY);
	EXPECT_EQ(complete.reader_complete, 1u);
	EXPECT_TRUE(domain.finish_grace_period(grace_generation));
	runtime_telemetry_bank_token telemetry_token{};
	while (telemetry->channel->take_completed(telemetry_token)) {
		ASSERT_TRUE(telemetry->telemetry->completed_bank(telemetry_token).is_ok());
		telemetry->telemetry->complete_aggregation(telemetry_token);
	}
	telemetry->telemetry->mark_epoch_aggregated(TEST_FROM_EPOCH);
	ASSERT_TRUE(telemetry->telemetry->epoch_aggregated(TEST_FROM_EPOCH));
	ASSERT_TRUE(telemetry->telemetry->retire_epoch(TEST_FROM_EPOCH, TEST_TO_EPOCH).has_value());
	while (telemetry->channel->take_returned(telemetry_token)) {
		telemetry->telemetry->accept_returned(telemetry_token);
	}
}

}  // namespace
}  // namespace kinetum::dp
