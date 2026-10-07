// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_epoch_transition_primitives.cpp
 * @brief Unit tests for exact ordered-cut epoch-transition primitives.
 * @author Fleming Patel
 *
 * These tests pin the isolated state and publication contracts before any live
 * runtime path consumes them. They intentionally test malformed, stale,
 * duplicate-different, overlap, and exhaustion cases alongside the valid path.
 */

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <thread>
#include <type_traits>

#include <kinetum/algo/single_writer_snapshot.hpp>
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/transition_idempotency_key.hpp"
#include "src/common/sha256.hpp"
#include "src/dp/epoch/exact_slot_table.hpp"
#include "src/dp/epoch/ordered_cut.hpp"
#include "src/dp/epoch/transition_state_machine.hpp"
#include "src/dp/epoch/transition_types.hpp"

namespace kinetum::dp
{

namespace
{

static_assert(!std::is_copy_constructible_v<algo::single_writer_snapshot<1>>);
static_assert(!std::is_move_constructible_v<algo::single_writer_snapshot<1>>);
static_assert(!std::is_copy_constructible_v<exact_protocol_record<boundary_epoch_cut>>);
static_assert(!std::is_move_constructible_v<exact_protocol_record<boundary_epoch_cut>>);
static_assert(!std::is_copy_constructible_v<successful_data_sequence>);
static_assert(!std::is_move_constructible_v<successful_data_sequence>);
static_assert(!std::is_copy_constructible_v<exact_epoch_slot_table>);
static_assert(!std::is_move_constructible_v<exact_epoch_slot_table>);
static_assert(!std::is_copy_constructible_v<epoch_transition_state_machine>);
static_assert(!std::is_move_constructible_v<epoch_transition_state_machine>);

/**
 * @brief Construct a deterministic exact identity for state-machine tests.
 *
 * @param mutation_sequence Durable mutation sequence.
 * @param target_epoch Durable target epoch.
 * @param digest_seed Byte seed distinguishing exact digest content.
 * @return Complete fixed-width transition identity.
 */
common::epoch_transition_identity make_identity(uint64_t mutation_sequence, uint64_t target_epoch, uint8_t digest_seed)
{
	common::epoch_transition_identity identity{};
	identity.mutation_sequence = mutation_sequence;
	identity.target_epoch = target_epoch;
	identity.validation_hash.fill(digest_seed);
	identity.idempotency_key_digest.fill(static_cast<uint8_t>(digest_seed + 1u));
	return identity;
}

/**
 * @brief Bootstrap a state machine and assert the exact idle baseline.
 *
 * @param machine State machine to bootstrap.
 * @param epoch Exact bootstrap epoch.
 */
void bootstrap_machine(epoch_transition_state_machine &machine, uint64_t epoch)
{
	ASSERT_EQ(machine.begin_bootstrap(epoch), epoch_state_result::APPLIED);
	ASSERT_EQ(machine.complete_bootstrap(epoch), epoch_state_result::APPLIED);
	ASSERT_EQ(machine.phase(), epoch_transition_phase::IDLE);
	ASSERT_EQ(machine.active_epoch(), epoch);
}

/**
 * @brief Stage and publish one exact initial slot epoch.
 *
 * @param slots Empty exact slot table.
 * @param epoch Exact bootstrap epoch.
 */
void publish_initial_slot(exact_epoch_slot_table &slots, uint64_t epoch)
{
	const auto staged = slots.stage_prepared(epoch);
	ASSERT_TRUE(staged.applied());
	const auto preflight = slots.preflight_publish_prepared(epoch);
	ASSERT_TRUE(preflight.applied());
	EXPECT_EQ(preflight.slot_index, staged.slot_index);
	const auto published = slots.publish_prepared(epoch);
	ASSERT_TRUE(published.applied());
	EXPECT_EQ(published.slot_index, staged.slot_index);
}

}  // namespace

/**
 * @brief Verify fixed transition identity compares every exact field.
 */
TEST(epoch_transition_primitives, identity_requires_nonzero_allocations_and_exact_digests)
{
	auto identity = make_identity(9, 21, 0x3a);
	EXPECT_TRUE(identity.valid());
	EXPECT_TRUE(make_identity(common::MAX_MUTATION_SEQUENCE, common::MAX_EPOCH_ID, 0x3b).valid());

	auto different_hash = identity;
	different_hash.validation_hash[7] = static_cast<uint8_t>(different_hash.validation_hash[7] ^ 0x1u);
	EXPECT_NE(identity, different_hash);

	auto invalid_mutation = identity;
	invalid_mutation.mutation_sequence = 0;
	EXPECT_FALSE(invalid_mutation.valid());

	auto invalid_epoch = identity;
	invalid_epoch.target_epoch = 0;
	EXPECT_FALSE(invalid_epoch.valid());

	auto exhausted_mutation = identity;
	exhausted_mutation.mutation_sequence = std::numeric_limits<uint64_t>::max();
	EXPECT_FALSE(exhausted_mutation.valid());

	auto exhausted_epoch = identity;
	exhausted_epoch.target_epoch = std::numeric_limits<uint64_t>::max();
	EXPECT_FALSE(exhausted_epoch.valid());
}

/**
 * @brief Verify transition keys enforce both byte bounds and printable ASCII.
 */
TEST(epoch_transition_contract, idempotency_key_is_bounded_printable_ascii)
{
	EXPECT_FALSE(common::validate_transition_idempotency_key("").is_ok());
	EXPECT_TRUE(common::validate_transition_idempotency_key(" ").is_ok());
	EXPECT_TRUE(common::validate_transition_idempotency_key(std::string(256, '~')).is_ok());
	EXPECT_FALSE(common::validate_transition_idempotency_key(std::string(257, 'a')).is_ok());
	EXPECT_FALSE(common::validate_transition_idempotency_key("line\nbreak").is_ok());
	EXPECT_FALSE(common::validate_transition_idempotency_key(std::string(1, static_cast<char>(0x80))).is_ok());
}

/** @brief Prove cryptographic producer keys satisfy the exact shared grammar. */
TEST(epoch_transition_contract, generated_idempotency_key_is_bounded_and_fail_closed)
{
	auto generated_or = common::generate_transition_idempotency_key("kinetumctl");
	ASSERT_TRUE(generated_or.is_ok()) << generated_or.error().message();
	EXPECT_EQ(generated_or->size(), std::string_view("kinetumctl-").size() + 64u);
	EXPECT_TRUE(generated_or->starts_with("kinetumctl-"));
	EXPECT_TRUE(common::validate_transition_idempotency_key(*generated_or).is_ok());
	EXPECT_FALSE(common::generate_transition_idempotency_key("").is_ok());
	EXPECT_FALSE(common::generate_transition_idempotency_key("UPPERCASE").is_ok());
}

/**
 * @brief Verify wire hash width and caller-key digestion produce exact identity.
 */
TEST(epoch_transition_contract, identity_builder_validates_and_digests_exact_fields)
{
	std::string validation_hash(common::SHA256_DIGEST_SIZE, static_cast<char>(0xa5));
	auto identity_or = common::make_epoch_transition_identity(17, 29, validation_hash, "retry-key");
	ASSERT_TRUE(identity_or.is_ok()) << identity_or.error().message();
	EXPECT_EQ(identity_or.value().mutation_sequence, 17u);
	EXPECT_EQ(identity_or.value().target_epoch, 29u);
	EXPECT_EQ(identity_or.value().validation_hash[0], 0xa5u);

	auto key_digest_or = common::sha256_raw("retry-key");
	ASSERT_TRUE(key_digest_or.is_ok()) << key_digest_or.error().message();
	EXPECT_EQ(identity_or.value().idempotency_key_digest, key_digest_or.value());

	EXPECT_FALSE(common::decode_transition_validation_hash(std::string(31, 'x')).is_ok());
	EXPECT_FALSE(common::decode_transition_validation_hash(std::string(33, 'x')).is_ok());
	EXPECT_FALSE(common::make_epoch_transition_identity(0, 29, validation_hash, "retry-key").is_ok());
	EXPECT_FALSE(common::make_epoch_transition_identity(17, 0, validation_hash, "retry-key").is_ok());
}

/**
 * @brief Verify bootstrap authority requires valid nonzero covering watermarks.
 */
TEST(epoch_transition_contract, bootstrap_watermarks_cover_the_active_epoch)
{
	const common::epoch_transition_watermarks valid{11, 7};
	EXPECT_TRUE(common::valid_bootstrap_watermarks(10, valid));
	EXPECT_TRUE(common::valid_bootstrap_watermarks(11, valid));
	EXPECT_FALSE(common::valid_bootstrap_watermarks(12, valid));
	EXPECT_FALSE(common::valid_bootstrap_watermarks(0, valid));
	EXPECT_FALSE(common::valid_bootstrap_watermarks(10, {0, 7}));
	EXPECT_FALSE(common::valid_bootstrap_watermarks(10, {11, 0}));
	EXPECT_FALSE(common::valid_bootstrap_watermarks(10, {std::numeric_limits<uint64_t>::max(),
							     std::numeric_limits<uint64_t>::max()}));
}

/**
 * @brief Verify watermark equality is only a journal-backed retry candidate.
 */
TEST(epoch_transition_contract, watermark_classifier_requires_both_allocations_to_advance)
{
	const auto identity = make_identity(11, 21, 0x4a);
	EXPECT_EQ(common::classify_transition_watermarks(identity, {20, 10}),
		  common::transition_watermark_result::ADVANCES);
	EXPECT_EQ(common::classify_transition_watermarks(identity, {21, 11}),
		  common::transition_watermark_result::EXACT_RETRY_CANDIDATE);
	EXPECT_EQ(common::classify_transition_watermarks(identity, {22, 11}),
		  common::transition_watermark_result::STALE);
	EXPECT_EQ(common::classify_transition_watermarks(identity, {21, 10}),
		  common::transition_watermark_result::INCONSISTENT);
	EXPECT_EQ(common::classify_transition_watermarks(identity, {20, 11}),
		  common::transition_watermark_result::INCONSISTENT);
	EXPECT_EQ(common::classify_transition_watermarks(identity, {0, 0}),
		  common::transition_watermark_result::INVALID);

	auto invalid_identity = identity;
	invalid_identity.target_epoch = 0;
	EXPECT_EQ(common::classify_transition_watermarks(invalid_identity, {20, 10}),
		  common::transition_watermark_result::INVALID);
}

/**
 * @brief Verify CUT and ACK fields enforce their exact non-wrapping domains.
 */
TEST(epoch_transition_primitives, cut_and_ack_require_epoch_but_allow_zero_sequence)
{
	const boundary_epoch_cut cut{7, 0};
	const boundary_epoch_ack ack{7, 0};
	EXPECT_TRUE(cut.valid());
	EXPECT_TRUE(ack.valid());
	EXPECT_TRUE((boundary_epoch_cut{common::MAX_EPOCH_ID, MAX_BOUNDARY_DATA_SEQUENCE}).valid());
	EXPECT_TRUE((boundary_epoch_ack{common::MAX_EPOCH_ID, MAX_BOUNDARY_DATA_SEQUENCE}).valid());
	EXPECT_FALSE((boundary_epoch_cut{0, 17}).valid());
	EXPECT_FALSE((boundary_epoch_ack{0, 17}).valid());
	EXPECT_FALSE((boundary_epoch_cut{7, std::numeric_limits<uint64_t>::max()}).valid());
	EXPECT_FALSE((boundary_epoch_ack{7, std::numeric_limits<uint64_t>::max()}).valid());
}

/**
 * @brief Verify exact duplicate CUTs are idempotent and conflicts preserve truth.
 */
TEST(epoch_transition_primitives, exact_cut_record_rejects_duplicate_different_content)
{
	exact_protocol_record<boundary_epoch_cut> observed;
	const boundary_epoch_cut accepted{4, 91};

	EXPECT_EQ(observed.observe({}), exact_record_result::INVALID);
	EXPECT_EQ(observed.observe({4, std::numeric_limits<uint64_t>::max()}), exact_record_result::INVALID);
	EXPECT_EQ(observed.observe(accepted), exact_record_result::ACCEPTED);
	EXPECT_EQ(observed.observe(accepted), exact_record_result::DUPLICATE);
	EXPECT_EQ(observed.observe({4, 92}), exact_record_result::CONFLICT);
	EXPECT_EQ(observed.observe({5, 91}), exact_record_result::CONFLICT);

	ASSERT_TRUE(observed.present());
	ASSERT_NE(observed.record(), nullptr);
	EXPECT_EQ(*observed.record(), accepted);

	EXPECT_FALSE(observed.clear_exact({4, 92}));
	ASSERT_TRUE(observed.present());
	EXPECT_TRUE(observed.clear_exact(accepted));
	EXPECT_FALSE(observed.present());
	EXPECT_EQ(observed.record(), nullptr);
	EXPECT_EQ(observed.observe({5, 93}), exact_record_result::ACCEPTED);
}

/**
 * @brief Verify exact duplicate ACKs cannot hide an epoch or cut mismatch.
 */
TEST(epoch_transition_primitives, exact_ack_record_validates_epoch_and_cut_together)
{
	exact_protocol_record<boundary_epoch_ack> observed;
	const boundary_epoch_ack accepted{11, 404};

	EXPECT_EQ(observed.observe(accepted), exact_record_result::ACCEPTED);
	EXPECT_EQ(observed.observe({11, 404}), exact_record_result::DUPLICATE);
	EXPECT_EQ(observed.observe({12, 404}), exact_record_result::CONFLICT);
	EXPECT_EQ(observed.observe({11, 405}), exact_record_result::CONFLICT);
	ASSERT_NE(observed.record(), nullptr);
	EXPECT_EQ(*observed.record(), accepted);
}

/**
 * @brief Verify only successful DATA operations consume sequence values.
 */
TEST(epoch_transition_primitives, data_sequence_advances_only_when_owner_records_success)
{
	successful_data_sequence sequence;

	EXPECT_EQ(sequence.value(), 0u);
	EXPECT_TRUE(sequence.record_success());
	EXPECT_EQ(sequence.value(), 1u);
	EXPECT_TRUE(sequence.record_success());
	EXPECT_EQ(sequence.value(), 2u);
}

/**
 * @brief Verify sequence exhaustion is detected before uint64 wrap.
 */
TEST(epoch_transition_primitives, data_sequence_reserves_wrap_value)
{
	EXPECT_TRUE(successful_data_sequence::can_advance(0));
	EXPECT_TRUE(successful_data_sequence::can_advance(successful_data_sequence::MAX_VALUE - 1u));
	EXPECT_FALSE(successful_data_sequence::can_advance(successful_data_sequence::MAX_VALUE));
	EXPECT_FALSE(successful_data_sequence::can_advance(std::numeric_limits<uint64_t>::max()));
}

/**
 * @brief Verify receiver progress distinguishes pending, exact, and contradictory cuts.
 */
TEST(epoch_transition_primitives, sequence_cut_progress_rejects_progress_beyond_cut)
{
	EXPECT_EQ(classify_sequence_cut(99, 100), sequence_cut_progress::PENDING);
	EXPECT_EQ(classify_sequence_cut(100, 100), sequence_cut_progress::REACHED);
	EXPECT_EQ(classify_sequence_cut(101, 100), sequence_cut_progress::CONTRADICTION);
	EXPECT_EQ(classify_sequence_cut(0, 0), sequence_cut_progress::REACHED);
	EXPECT_EQ(classify_sequence_cut(std::numeric_limits<uint64_t>::max(), 100), sequence_cut_progress::INVALID);
	EXPECT_EQ(classify_sequence_cut(100, std::numeric_limits<uint64_t>::max()), sequence_cut_progress::INVALID);
}

/**
 * @brief Verify exact slots require staged initial publication.
 */
TEST(epoch_transition_primitives, slot_table_requires_staged_nonzero_initial_publication)
{
	exact_epoch_slot_table slots;

	EXPECT_TRUE(slots.valid_layout());
	EXPECT_TRUE(slots.empty());
	EXPECT_EQ(slots.find_exact(1), nullptr);
	EXPECT_EQ(slots.preflight_stage_prepared(0).result, epoch_slot_result::INVALID_EPOCH);
	EXPECT_EQ(slots.stage_prepared(0).result, epoch_slot_result::INVALID_EPOCH);
	EXPECT_EQ(slots.stage_prepared(std::numeric_limits<uint64_t>::max()).result, epoch_slot_result::INVALID_EPOCH);

	const auto stage_preflight = slots.preflight_stage_prepared(7);
	ASSERT_TRUE(stage_preflight.applied());
	EXPECT_EQ(stage_preflight.slot_index, 0u);
	EXPECT_TRUE(slots.empty());
	const auto staged = slots.stage_prepared(7);
	ASSERT_TRUE(staged.applied());
	EXPECT_EQ(staged.slot_index, stage_preflight.slot_index);
	ASSERT_LT(staged.slot_index, EXACT_EPOCH_SLOT_COUNT);
	ASSERT_NE(slots.find_exact(7), nullptr);
	EXPECT_EQ(slots.find_exact(7)->state, epoch_slot_state::PREPARED);
	const auto preflight = slots.preflight_publish_prepared(7);
	ASSERT_TRUE(preflight.applied());
	EXPECT_EQ(preflight.slot_index, staged.slot_index);
	ASSERT_TRUE(slots.publish_prepared(7).applied());
	ASSERT_NE(slots.find_exact(7), nullptr);
	EXPECT_EQ(slots.find_exact(7)->state, epoch_slot_state::PUBLISHED);
	EXPECT_FALSE(slots.empty());
	EXPECT_TRUE(slots.valid_layout());
}

/**
 * @brief Verify ACTIVATE preflight proves legality without changing slot state.
 */
TEST(epoch_transition_primitives, slot_table_publication_preflight_is_nonmutating)
{
	exact_epoch_slot_table slots;
	ASSERT_NO_FATAL_FAILURE(publish_initial_slot(slots, 4));
	const auto staged = slots.stage_prepared(9);
	ASSERT_TRUE(staged.applied());

	const auto preflight = slots.preflight_publish_prepared(9);
	ASSERT_TRUE(preflight.applied());
	EXPECT_EQ(preflight.slot_index, staged.slot_index);
	ASSERT_NE(slots.find_exact(4), nullptr);
	ASSERT_NE(slots.find_exact(9), nullptr);
	EXPECT_EQ(slots.find_exact(4)->state, epoch_slot_state::PUBLISHED);
	EXPECT_EQ(slots.find_exact(9)->state, epoch_slot_state::PREPARED);

	ASSERT_TRUE(slots.publish_prepared(9).applied());
	EXPECT_EQ(slots.find_exact(4)->state, epoch_slot_state::RETAINED);
	EXPECT_EQ(slots.find_exact(9)->state, epoch_slot_state::PUBLISHED);
}

/**
 * @brief Verify prepared slots may abort without disturbing the active epoch.
 */
TEST(epoch_transition_primitives, slot_table_discards_only_exact_prepared_epoch)
{
	exact_epoch_slot_table slots;
	ASSERT_NO_FATAL_FAILURE(publish_initial_slot(slots, 3));

	const auto prepared = slots.stage_prepared(8);
	ASSERT_TRUE(prepared.applied());
	EXPECT_EQ(slots.stage_prepared(8).result, epoch_slot_result::EPOCH_ALREADY_PRESENT);
	EXPECT_EQ(slots.stage_prepared(9).result, epoch_slot_result::NO_EMPTY_SLOT);
	EXPECT_EQ(slots.discard_prepared(0).result, epoch_slot_result::INVALID_EPOCH);
	EXPECT_EQ(slots.discard_prepared(3).result, epoch_slot_result::INVALID_STATE);
	EXPECT_EQ(slots.discard_prepared(9).result, epoch_slot_result::EPOCH_NOT_FOUND);

	const auto discarded = slots.discard_prepared(8);
	ASSERT_TRUE(discarded.applied());
	EXPECT_EQ(discarded.slot_index, prepared.slot_index);
	EXPECT_EQ(slots.find_exact(8), nullptr);
	ASSERT_NE(slots.find_exact(3), nullptr);
	EXPECT_EQ(slots.find_exact(3)->state, epoch_slot_state::PUBLISHED);
	EXPECT_TRUE(slots.valid_layout());
}

/**
 * @brief Verify old slots block a later epoch until exact retirement.
 */
TEST(epoch_transition_primitives, slot_table_retains_old_epoch_before_reuse)
{
	exact_epoch_slot_table slots;
	ASSERT_NO_FATAL_FAILURE(publish_initial_slot(slots, 4));
	ASSERT_TRUE(slots.stage_prepared(10).applied());
	EXPECT_EQ(slots.publish_prepared(std::numeric_limits<uint64_t>::max()).result,
		  epoch_slot_result::INVALID_EPOCH);

	const auto published = slots.publish_prepared(10);
	ASSERT_TRUE(published.applied());
	ASSERT_NE(slots.find_exact(4), nullptr);
	ASSERT_NE(slots.find_exact(10), nullptr);
	EXPECT_EQ(slots.find_exact(4)->state, epoch_slot_state::RETAINED);
	EXPECT_EQ(slots.find_exact(10)->state, epoch_slot_state::PUBLISHED);
	EXPECT_EQ(slots.preflight_stage_prepared(15).result, epoch_slot_result::NO_EMPTY_SLOT);
	EXPECT_EQ(slots.stage_prepared(15).result, epoch_slot_result::NO_EMPTY_SLOT);
	EXPECT_EQ(slots.retire_retained(0).result, epoch_slot_result::INVALID_EPOCH);
	EXPECT_EQ(slots.retire_retained(10).result, epoch_slot_result::INVALID_STATE);

	ASSERT_TRUE(slots.retire_retained(4).applied());
	EXPECT_EQ(slots.find_exact(4), nullptr);
	EXPECT_TRUE(slots.stage_prepared(15).applied());
	EXPECT_TRUE(slots.valid_layout());
}

/**
 * @brief Verify exact slot lookup never maps an unknown epoch to another slot.
 */
TEST(epoch_transition_primitives, slot_table_has_no_previous_epoch_fallback)
{
	exact_epoch_slot_table slots;
	ASSERT_NO_FATAL_FAILURE(publish_initial_slot(slots, 20));
	ASSERT_TRUE(slots.stage_prepared(30).applied());

	EXPECT_EQ(slots.find_exact(19), nullptr);
	EXPECT_EQ(slots.find_exact(21), nullptr);
	EXPECT_EQ(slots.find_exact(29), nullptr);
	ASSERT_NE(slots.find_exact(20), nullptr);
	ASSERT_NE(slots.find_exact(30), nullptr);
}

/**
 * @brief Verify preparing an older or equal epoch fails closed.
 */
TEST(epoch_transition_primitives, slot_table_requires_monotonic_exact_epoch)
{
	exact_epoch_slot_table slots;
	ASSERT_NO_FATAL_FAILURE(publish_initial_slot(slots, 12));

	EXPECT_EQ(slots.stage_prepared(12).result, epoch_slot_result::EPOCH_ALREADY_PRESENT);
	EXPECT_EQ(slots.stage_prepared(11).result, epoch_slot_result::EPOCH_ORDER_VIOLATION);
	EXPECT_EQ(slots.stage_prepared(0).result, epoch_slot_result::INVALID_EPOCH);
	EXPECT_EQ(slots.stage_prepared(std::numeric_limits<uint64_t>::max()).result, epoch_slot_result::INVALID_EPOCH);
}

/**
 * @brief Verify final shutdown retires only the sole idle published epoch.
 */
TEST(epoch_transition_primitives, slot_table_final_shutdown_requires_idle_publication)
{
	exact_epoch_slot_table slots;
	ASSERT_NO_FATAL_FAILURE(publish_initial_slot(slots, 12));
	EXPECT_EQ(slots.preflight_retire_published(0).result, epoch_slot_result::INVALID_EPOCH);
	EXPECT_EQ(slots.preflight_retire_published(11).result, epoch_slot_result::EPOCH_NOT_FOUND);
	EXPECT_EQ(slots.retire_published(0).result, epoch_slot_result::INVALID_EPOCH);
	EXPECT_EQ(slots.retire_published(11).result, epoch_slot_result::EPOCH_NOT_FOUND);

	ASSERT_TRUE(slots.stage_prepared(13).applied());
	EXPECT_EQ(slots.preflight_retire_published(12).result, epoch_slot_result::INVALID_STATE);
	EXPECT_EQ(slots.retire_published(12).result, epoch_slot_result::INVALID_STATE);
	ASSERT_TRUE(slots.discard_prepared(13).applied());
	EXPECT_TRUE(slots.preflight_retire_published(12).applied());
	const auto retired = slots.retire_published(12);
	EXPECT_TRUE(retired.applied());
	EXPECT_EQ(retired.slot_index, 0u);
	EXPECT_TRUE(slots.empty());
	EXPECT_TRUE(slots.valid_layout());
}

/**
 * @brief Verify global state starts closed and bootstraps one exact epoch.
 */
TEST(epoch_transition_primitives, state_machine_requires_exact_bootstrap_before_prepare)
{
	epoch_transition_state_machine machine;
	const auto identity = make_identity(1, 2, 0x10);

	EXPECT_EQ(machine.phase(), epoch_transition_phase::AWAITING_BOOTSTRAP);
	EXPECT_EQ(machine.active_epoch(), 0u);
	EXPECT_EQ(machine.begin_prepare(identity), epoch_state_result::STATE_MISMATCH);
	EXPECT_EQ(machine.begin_bootstrap(0), epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(machine.begin_bootstrap(std::numeric_limits<uint64_t>::max()), epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(machine.begin_bootstrap(7), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.complete_bootstrap(std::numeric_limits<uint64_t>::max()),
		  epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(machine.complete_bootstrap(8), epoch_state_result::IDENTITY_MISMATCH);
	EXPECT_EQ(machine.complete_bootstrap(7), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(machine.active_epoch(), 7u);
	EXPECT_EQ(machine.target_epoch(), 0u);
	EXPECT_EQ(machine.identity(), nullptr);
}

/**
 * @brief Verify a complete transition follows every exact phase in order.
 */
TEST(epoch_transition_primitives, state_machine_completes_ordered_transition_with_epoch_gap)
{
	epoch_transition_state_machine machine;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(machine, 5));
	const auto identity = make_identity(17, 11, 0x21);

	EXPECT_EQ(machine.begin_prepare(identity), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.phase(), epoch_transition_phase::PREPARING);
	ASSERT_NE(machine.identity(), nullptr);
	EXPECT_EQ(*machine.identity(), identity);
	EXPECT_EQ(machine.begin_commit(identity), epoch_state_result::STATE_MISMATCH);
	EXPECT_EQ(machine.mark_prepared(identity), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.begin_retiring(identity), epoch_state_result::STATE_MISMATCH);
	EXPECT_EQ(machine.begin_commit(identity), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.complete_retirement(identity), epoch_state_result::STATE_MISMATCH);
	EXPECT_EQ(machine.begin_retiring(identity), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.complete_retirement(make_identity(0, 11, 0x21)), epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(machine.complete_retirement(identity), epoch_state_result::APPLIED);

	EXPECT_EQ(machine.phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(machine.active_epoch(), 11u);
	EXPECT_EQ(machine.target_epoch(), 0u);
	EXPECT_EQ(machine.identity(), nullptr);

	const auto next_identity = make_identity(18, 16, 0x22);
	EXPECT_EQ(machine.begin_prepare(next_identity), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.abort_before_commit(next_identity), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.active_epoch(), 11u);
}

/**
 * @brief Verify global phase and exact-slot lifecycle advance in lockstep.
 */
TEST(epoch_transition_primitives, state_machine_and_slots_complete_one_exact_generation)
{
	epoch_transition_state_machine machine;
	exact_epoch_slot_table slots;
	const auto identity = make_identity(41, 9, 0x23);

	ASSERT_EQ(machine.begin_bootstrap(3), epoch_state_result::APPLIED);
	ASSERT_TRUE(slots.stage_prepared(3).applied());
	ASSERT_TRUE(slots.preflight_publish_prepared(3).applied());
	ASSERT_TRUE(slots.publish_prepared(3).applied());
	ASSERT_EQ(machine.complete_bootstrap(3), epoch_state_result::APPLIED);

	ASSERT_EQ(machine.begin_prepare(identity), epoch_state_result::APPLIED);
	ASSERT_TRUE(slots.stage_prepared(identity.target_epoch).applied());
	ASSERT_EQ(machine.mark_prepared(identity), epoch_state_result::APPLIED);
	ASSERT_EQ(machine.begin_commit(identity), epoch_state_result::APPLIED);
	ASSERT_TRUE(slots.publish_prepared(identity.target_epoch).applied());
	ASSERT_EQ(machine.begin_retiring(identity), epoch_state_result::APPLIED);

	ASSERT_NE(slots.find_exact(3), nullptr);
	ASSERT_NE(slots.find_exact(identity.target_epoch), nullptr);
	EXPECT_EQ(slots.find_exact(3)->state, epoch_slot_state::RETAINED);
	EXPECT_EQ(slots.find_exact(identity.target_epoch)->state, epoch_slot_state::PUBLISHED);

	ASSERT_TRUE(slots.retire_retained(3).applied());
	ASSERT_EQ(machine.complete_retirement(identity), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(machine.active_epoch(), identity.target_epoch);
	EXPECT_EQ(slots.find_exact(3), nullptr);
	ASSERT_NE(slots.find_exact(identity.target_epoch), nullptr);
	EXPECT_TRUE(slots.valid_layout());
}

/**
 * @brief Verify another generation cannot enter any occupied transition phase.
 */
TEST(epoch_transition_primitives, state_machine_rejects_overlapping_transition_generation)
{
	epoch_transition_state_machine machine;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(machine, 2));
	const auto first = make_identity(10, 5, 0x31);
	const auto second = make_identity(11, 9, 0x32);

	ASSERT_EQ(machine.begin_prepare(first), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.begin_prepare(second), epoch_state_result::STATE_MISMATCH);
	ASSERT_EQ(machine.mark_prepared(first), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.begin_prepare(second), epoch_state_result::STATE_MISMATCH);
	ASSERT_EQ(machine.begin_commit(first), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.begin_prepare(second), epoch_state_result::STATE_MISMATCH);
	ASSERT_EQ(machine.begin_retiring(first), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.begin_prepare(second), epoch_state_result::STATE_MISMATCH);
}

/**
 * @brief Verify all phase advances require the exact admitted identity.
 */
TEST(epoch_transition_primitives, state_machine_rejects_identity_substitution)
{
	epoch_transition_state_machine machine;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(machine, 4));
	const auto admitted = make_identity(22, 8, 0x41);
	auto substituted = admitted;
	substituted.idempotency_key_digest[0] = static_cast<uint8_t>(substituted.idempotency_key_digest[0] ^ 0x1u);

	ASSERT_EQ(machine.begin_prepare(admitted), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.mark_prepared(make_identity(0, 8, 0x42)), epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(machine.mark_prepared(substituted), epoch_state_result::IDENTITY_MISMATCH);
	EXPECT_EQ(machine.abort_before_commit(substituted), epoch_state_result::IDENTITY_MISMATCH);
	EXPECT_EQ(machine.phase(), epoch_transition_phase::PREPARING);
	EXPECT_EQ(machine.mark_prepared(admitted), epoch_state_result::APPLIED);
	EXPECT_EQ(machine.begin_commit(substituted), epoch_state_result::IDENTITY_MISMATCH);
}

/**
 * @brief Verify abort is available before commit and forbidden after commit.
 */
TEST(epoch_transition_primitives, state_machine_abort_boundary_is_irreversible)
{
	epoch_transition_state_machine preparing;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(preparing, 1));
	const auto first = make_identity(2, 3, 0x51);
	ASSERT_EQ(preparing.begin_prepare(first), epoch_state_result::APPLIED);
	EXPECT_EQ(preparing.abort_before_commit(make_identity(0, 3, 0x51)), epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(preparing.abort_before_commit(first), epoch_state_result::APPLIED);
	EXPECT_EQ(preparing.phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(preparing.active_epoch(), 1u);

	epoch_transition_state_machine prepared;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(prepared, 1));
	const auto second = make_identity(3, 4, 0x52);
	ASSERT_EQ(prepared.begin_prepare(second), epoch_state_result::APPLIED);
	ASSERT_EQ(prepared.mark_prepared(second), epoch_state_result::APPLIED);
	EXPECT_EQ(prepared.abort_before_commit(second), epoch_state_result::APPLIED);
	EXPECT_EQ(prepared.phase(), epoch_transition_phase::IDLE);
	EXPECT_EQ(prepared.active_epoch(), 1u);

	epoch_transition_state_machine committing;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(committing, 1));
	const auto third = make_identity(4, 5, 0x53);
	ASSERT_EQ(committing.begin_prepare(third), epoch_state_result::APPLIED);
	ASSERT_EQ(committing.mark_prepared(third), epoch_state_result::APPLIED);
	ASSERT_EQ(committing.begin_commit(third), epoch_state_result::APPLIED);
	EXPECT_EQ(committing.abort_before_commit(third), epoch_state_result::STATE_MISMATCH);
	EXPECT_EQ(committing.phase(), epoch_transition_phase::COMMITTING);
}

/**
 * @brief Verify stale and invalid epochs cannot enter preparation.
 */
TEST(epoch_transition_primitives, state_machine_requires_later_nonzero_identity)
{
	epoch_transition_state_machine machine;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(machine, 10));

	EXPECT_EQ(machine.begin_prepare(make_identity(0, 11, 0x61)), epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(machine.begin_prepare(make_identity(1, 0, 0x62)), epoch_state_result::INVALID_ARGUMENT);
	EXPECT_EQ(machine.begin_prepare(make_identity(1, 10, 0x63)), epoch_state_result::EPOCH_ORDER_VIOLATION);
	EXPECT_EQ(machine.begin_prepare(make_identity(1, 9, 0x64)), epoch_state_result::EPOCH_ORDER_VIOLATION);
}

/**
 * @brief Verify FAILED_STOP is terminal and preserves transaction diagnostics.
 */
TEST(epoch_transition_primitives, state_machine_failed_stop_has_no_recovery_transition)
{
	epoch_transition_state_machine machine;
	ASSERT_NO_FATAL_FAILURE(bootstrap_machine(machine, 6));
	const auto identity = make_identity(31, 12, 0x71);
	ASSERT_EQ(machine.begin_prepare(identity), epoch_state_result::APPLIED);

	machine.enter_failed_stop();
	EXPECT_EQ(machine.phase(), epoch_transition_phase::FAILED_STOP);
	ASSERT_NE(machine.identity(), nullptr);
	EXPECT_EQ(*machine.identity(), identity);
	EXPECT_EQ(machine.begin_prepare(make_identity(32, 13, 0x72)), epoch_state_result::STATE_MISMATCH);
	EXPECT_EQ(machine.abort_before_commit(identity), epoch_state_result::STATE_MISMATCH);
	machine.enter_failed_stop();
	EXPECT_EQ(machine.phase(), epoch_transition_phase::FAILED_STOP);
}

/**
 * @brief Verify publication starts invalid and advances coherent generations.
 */
TEST(epoch_transition_primitives, single_writer_snapshot_requires_complete_publication)
{
	algo::single_writer_snapshot<3> publication;
	algo::single_writer_snapshot<3>::snapshot observed{};
	observed.generation = 99;
	observed.fields = {9, 9, 9};

	EXPECT_FALSE(publication.try_read(observed, 0));
	EXPECT_FALSE(publication.try_read(observed, 2));
	EXPECT_EQ(observed.generation, 99u);
	EXPECT_EQ(observed.fields, (std::array<uint64_t, 3>{9, 9, 9}));

	ASSERT_TRUE(publication.publish({1, 2, 3}));
	ASSERT_TRUE(publication.try_read(observed, 2));
	EXPECT_EQ(observed.generation, 1u);
	EXPECT_EQ(observed.fields, (std::array<uint64_t, 3>{1, 2, 3}));
	EXPECT_EQ(publication.completed_generation(), 1u);

	ASSERT_TRUE(publication.publish({4, 5, 6}));
	ASSERT_TRUE(publication.try_read(observed, 2));
	EXPECT_EQ(observed.generation, 2u);
	EXPECT_EQ(observed.fields, (std::array<uint64_t, 3>{4, 5, 6}));
}

/**
 * @brief Verify publication sequence refuses odd and near-wrap states.
 */
TEST(epoch_transition_primitives, single_writer_snapshot_guards_generation_wrap)
{
	using publication = algo::single_writer_snapshot<1>;
	constexpr uint64_t MAX = std::numeric_limits<uint64_t>::max();

	EXPECT_TRUE(publication::can_advance_sequence(0));
	EXPECT_TRUE(publication::can_advance_sequence(MAX - 3u));
	EXPECT_FALSE(publication::can_advance_sequence(1));
	EXPECT_FALSE(publication::can_advance_sequence(MAX - 2u));
	EXPECT_FALSE(publication::can_advance_sequence(MAX - 1u));
	EXPECT_FALSE(publication::can_advance_sequence(MAX));
}

/**
 * @brief Verify concurrent readers never accept a mixed publication.
 */
TEST(epoch_transition_primitives, single_writer_snapshot_is_coherent_under_observation)
{
	algo::single_writer_snapshot<4> publication;
	ASSERT_TRUE(publication.publish({1, 1, 1, 1}));

	std::atomic<bool> reader_ready{false};
	std::atomic<bool> stop_reader{false};
	std::atomic<bool> inconsistent{false};
	std::atomic<uint64_t> observations{0};
	std::atomic<uint64_t> max_generation{0};

	std::thread reader([&]() {
		reader_ready.store(true, std::memory_order_release);
		while (!stop_reader.load(std::memory_order_acquire)) {
			algo::single_writer_snapshot<4>::snapshot observed{};
			if (!publication.try_read(observed, 4)) {
				continue;
			}
			observations.fetch_add(1, std::memory_order_relaxed);
			const uint64_t prior_generation = max_generation.load(std::memory_order_relaxed);
			if (observed.generation > prior_generation) {
				max_generation.store(observed.generation, std::memory_order_relaxed);
			}
			const uint64_t expected = observed.fields[0];
			if (expected != observed.generation) {
				inconsistent.store(true, std::memory_order_relaxed);
			}
			for (const uint64_t field : observed.fields) {
				if (field != expected) {
					inconsistent.store(true, std::memory_order_relaxed);
				}
			}
		}
	});

	const auto ready_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
	while (!reader_ready.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < ready_deadline) {
		std::this_thread::yield();
	}
	const auto observation_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
	while (observations.load(std::memory_order_relaxed) == 0u &&
	       std::chrono::steady_clock::now() < observation_deadline) {
		std::this_thread::yield();
	}

	bool publish_failed = false;
	for (uint64_t value = 2; value < 10'000; ++value) {
		if (!publication.publish({value, value, value, value})) {
			publish_failed = true;
			break;
		}
	}
	const auto generation_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
	while (max_generation.load(std::memory_order_relaxed) <= 1u &&
	       std::chrono::steady_clock::now() < generation_deadline) {
		std::this_thread::yield();
	}
	stop_reader.store(true, std::memory_order_release);
	reader.join();

	EXPECT_TRUE(reader_ready.load(std::memory_order_relaxed));
	EXPECT_FALSE(publish_failed);
	EXPECT_FALSE(inconsistent.load(std::memory_order_relaxed));
	EXPECT_GT(observations.load(std::memory_order_relaxed), 0u);
	EXPECT_GT(max_generation.load(std::memory_order_relaxed), 1u);
}

}  // namespace kinetum::dp
