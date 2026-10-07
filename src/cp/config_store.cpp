// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file config_store.cpp
 * @brief Descriptor-rooted immutable snapshot corpus and atomic CP authority.
 * @author Fleming Patel
 */

#include "src/cp/config_store.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "src/common/application_status.hpp"
#include "src/common/bootstrap_config_snapshot.hpp"
#include "src/common/control_plane_contract.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/cp/guardrails_policy.hpp"

namespace kinetum::cp
{
namespace
{

/** Durable control-plane authority record owning bootstrap and mutation state. */
using authority_message = kinetum::control::internal::v1::ControlPlaneTransitionAuthority;
/** Persisted phase of the exact durable epoch mutation. */
using durable_phase = kinetum::control::internal::v1::DurableEpochTransitionPhase;
/** Durable transaction record reconciled against the data plane. */
using durable_transition = kinetum::control::internal::v1::DurableEpochTransition;
using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/** @brief Sole mutable transition-authority leaf. */
constexpr std::string_view TRANSITION_AUTHORITY_LEAF = "TRANSITION_AUTHORITY.pb";

/** @brief Prefix for immutable canonical snapshot objects. */
constexpr std::string_view SNAPSHOT_LEAF_PREFIX = "snap_";

/** @brief Suffix for immutable canonical snapshot objects. */
constexpr std::string_view SNAPSHOT_LEAF_SUFFIX = ".pbtxt";

/** @brief Exact lowercase SHA-256 width in a snapshot corpus leaf. */
constexpr std::size_t SNAPSHOT_LEAF_DIGEST_BYTES = 64u;

/** @brief Maximum protobuf-text expansion admitted for one corpus object. */
constexpr uint64_t MAX_STORE_PBTXT_BYTES = 64u * 1024u * 1024u;

/** @brief Fixed initial active epoch and both high watermarks. */
constexpr uint64_t INITIAL_BOOTSTRAP_IDENTITY = 1u;

/** @brief Bounded private-record overhead beyond one active Bootstrap request. */
constexpr uint64_t MAX_TRANSITION_AUTHORITY_OVERHEAD_BYTES = 64u * 1024u;

/** @brief Exact read/serialization ceiling for the private authority record. */
constexpr uint64_t MAX_TRANSITION_AUTHORITY_BYTES =
	kinetum::common::MAX_BOOTSTRAP_CONFIG_SNAPSHOT_REQUEST_BYTES + MAX_TRANSITION_AUTHORITY_OVERHEAD_BYTES;

static_assert(MAX_TRANSITION_AUTHORITY_BYTES > kinetum::common::MAX_BOOTSTRAP_CONFIG_SNAPSHOT_REQUEST_BYTES,
	      "transition authority must contain one Bootstrap request plus bounded metadata");

/**
 * @brief Test whether one durable phase is nonterminal.
 * @param phase Candidate generated durable phase.
 * @return true only for ALLOCATED, PREPARED, COMPLETION_PENDING, or ABORT_PENDING.
 */
[[nodiscard]] constexpr bool is_nonterminal_phase(durable_phase phase) noexcept
{
	switch (phase) {
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING:
		return true;
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Test whether one durable phase is terminal.
 * @param phase Candidate generated durable phase.
 * @return true only for COMPLETE or ABORTED.
 */
[[nodiscard]] constexpr bool is_terminal_phase(durable_phase phase) noexcept
{
	return phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE ||
	       phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED;
}

/**
 * @brief Validate one explicit durable CP phase edge.
 * @param from Exact current durable phase.
 * @param to Candidate successor phase.
 * @return true only for one of the four declared nonterminal edges.
 */
[[nodiscard]] constexpr bool legal_phase_edge(durable_phase from, durable_phase to) noexcept
{
	switch (from) {
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED:
		return to == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED ||
		       to == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING;
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED:
		return to == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING ||
		       to == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING;
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE:
	case durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::control::internal::v1::DurableEpochTransitionPhase_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/**
 * @brief Validate one semantic snapshot identity.
 * @param id Candidate semantic bytes.
 * @return OK for 1..256 bytes; INVALID_ARGUMENT otherwise.
 */
[[nodiscard]] status validate_snapshot_id(std::string_view id)
{
	if (!kinetum::common::valid_config_snapshot_id(id)) {
		return status::invalid_argument("snapshot_id must contain 1..256 bytes");
	}
	return status::ok();
}

/**
 * @brief Construct one canonical snapshot corpus leaf.
 * @param snapshot_id Exact admitted semantic identity.
 * @return Fixed-width digest-derived leaf or SHA-256 provider failure.
 */
[[nodiscard]] status_or<std::string> snapshot_leaf(std::string_view snapshot_id)
{
	auto digest_or = kinetum::common::sha256_hex(snapshot_id);
	if (!digest_or.is_ok()) {
		return digest_or.error();
	}
	return std::string(SNAPSHOT_LEAF_PREFIX) + std::move(digest_or).value() + std::string(SNAPSHOT_LEAF_SUFFIX);
}

/**
 * @brief Recognize one exact fixed-width corpus leaf.
 * @param leaf Candidate single-component name.
 * @return true only for `snap_<64 lowercase hexadecimal bytes>.pbtxt`.
 */
[[nodiscard]] bool is_snapshot_leaf(std::string_view leaf) noexcept
{
	if (leaf.size() != SNAPSHOT_LEAF_PREFIX.size() + SNAPSHOT_LEAF_DIGEST_BYTES + SNAPSHOT_LEAF_SUFFIX.size() ||
	    !leaf.starts_with(SNAPSHOT_LEAF_PREFIX) || !leaf.ends_with(SNAPSHOT_LEAF_SUFFIX)) {
		return false;
	}
	const std::string_view digest(leaf.data() + SNAPSHOT_LEAF_PREFIX.size(), SNAPSHOT_LEAF_DIGEST_BYTES);
	return std::all_of(digest.begin(), digest.end(),
			   [](char value) { return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'); });
}

/**
 * @brief Convert one immutable snapshot into public listing metadata.
 * @param snapshot Exact terminal snapshot.
 * @param active Whether the logical projection is active.
 * @return Complete SnapshotInfo projection.
 */
[[nodiscard]] kinetum::control::v1::SnapshotInfo snapshot_info(const kinetum::control::v1::ConfigSnapshot &snapshot,
							       bool active)
{
	kinetum::control::v1::SnapshotInfo info;
	info.set_snapshot_id(snapshot.snapshot_id());
	info.set_revision(snapshot.revision());
	info.set_created_unix_ms(snapshot.created_unix_ms());
	info.set_is_active(active);
	info.set_description(snapshot.description());
	info.set_author(snapshot.author());
	return info;
}

/** @brief Namespace-local parsed corpus value before store adoption. */
struct parsed_staged_snapshot {
	kinetum::control::v1::ConfigSnapshot snapshot;	   ///< Exact terminal message.
	kinetum::common::sha256_digest validation_hash{};  ///< Exact raw terminal identity.
};

/** @brief Decoded stateless snapshot-list continuation identity. */
struct snapshot_page_token {
	std::string cursor_hash;       ///< Lowercase SHA-256 binding listing truth and final row.
	std::string last_snapshot_id;  ///< Exact final semantic ID from the prior page.
};

/**
 * @brief Add one fixed-width integer to a listing-identity hash.
 * @param hasher Sole incremental hash owner.
 * @param value Nonnegative integer encoded in network byte order.
 */
void hash_listing_uint64(kinetum::common::sha256_hasher &hasher, uint64_t value)
{
	std::array<uint8_t, sizeof(value)> bytes{};
	for (std::size_t index = 0; index < bytes.size(); ++index) {
		const std::size_t shift = (bytes.size() - index - 1u) * 8u;
		bytes[index] = static_cast<uint8_t>((value >> shift) & UINT64_C(0xff));
	}
	hasher.update(bytes.data(), bytes.size());
}

/**
 * @brief Add one length-delimited byte string to a listing-identity hash.
 * @param hasher Sole incremental hash owner.
 * @param value Exact bytes to append.
 */
void hash_listing_bytes(kinetum::common::sha256_hasher &hasher, std::string_view value)
{
	hash_listing_uint64(hasher, static_cast<uint64_t>(value.size()));
	hasher.update(value);
}

/**
 * @brief Bind one continuation row to one immutable listing identity.
 * @param listing_hash Exact current corpus-and-active hash.
 * @param last_snapshot_id Final row emitted by the prior page.
 * @return Lowercase SHA-256 cursor identity or the hash-provider failure.
 */
status_or<std::string> snapshot_page_cursor_identity(std::string_view listing_hash, std::string_view last_snapshot_id)
{
	kinetum::common::sha256_hasher hasher;
	hasher.update("kinetum-snapshot-page-cursor-v1");
	hash_listing_bytes(hasher, listing_hash);
	hash_listing_bytes(hasher, last_snapshot_id);
	return hasher.finalize_hex();
}

/**
 * @brief Parse one bounded stateless snapshot-list continuation token.
 * @param token Candidate token bytes.
 * @return Complete token identity, or INVALID_ARGUMENT without store access.
 */
status_or<snapshot_page_token> decode_snapshot_page_token(std::string_view token)
{
	constexpr std::string_view PREFIX = "v1.";
	constexpr std::size_t HASH_END = PREFIX.size() + kinetum::common::SHA256_HEX_LENGTH;
	if (token.empty() || token.size() > kinetum::common::MAX_SNAPSHOT_LIST_PAGE_TOKEN_BYTES ||
	    !token.starts_with(PREFIX) || token.size() <= HASH_END || token[HASH_END] != '.') {
		return status::invalid_argument("snapshot listing page token is malformed");
	}
	const auto hash = token.substr(PREFIX.size(), kinetum::common::SHA256_HEX_LENGTH);
	const auto hash_status = kinetum::common::validate_sha256_hex_claim(hash, "snapshot listing token hash");
	const auto encoded_id = token.substr(HASH_END + 1u);
	if (!hash_status.is_ok() || encoded_id.empty() || (encoded_id.size() & 1u) != 0u ||
	    encoded_id.size() > kinetum::common::MAX_CONFIG_SNAPSHOT_ID_BYTES * 2u ||
	    !std::all_of(encoded_id.begin(), encoded_id.end(),
			 [](char value) { return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'); })) {
		return status::invalid_argument("snapshot listing page token is malformed");
	}
	auto id_or = kinetum::common::hex_to_bytes(encoded_id);
	if (!id_or.is_ok()) {
		return status::invalid_argument("snapshot listing page token is malformed");
	}
	std::string id(reinterpret_cast<const char *>(id_or->data()), id_or->size());
	if (!kinetum::common::valid_config_snapshot_id(id)) {
		return status::invalid_argument("snapshot listing page token is malformed");
	}
	return snapshot_page_token{std::string(hash), std::move(id)};
}

/**
 * @brief Encode the next stateless snapshot-list continuation token.
 * @param listing_hash Exact current listing identity.
 * @param last_snapshot_id Final emitted semantic ID.
 * @return Bounded printable token or hash-provider failure.
 */
status_or<std::string> encode_snapshot_page_token(std::string_view listing_hash, std::string_view last_snapshot_id)
{
	auto cursor_or = snapshot_page_cursor_identity(listing_hash, last_snapshot_id);
	if (!cursor_or.is_ok()) {
		return cursor_or.error();
	}
	const auto *bytes = reinterpret_cast<const uint8_t *>(last_snapshot_id.data());
	return "v1." + std::move(cursor_or).value() + "." +
	       kinetum::common::bytes_to_hex(bytes, last_snapshot_id.size());
}

/**
 * @brief Parse and fully re-admit one exact canonical corpus object.
 * @param bytes Exact descriptor-read protobuf text.
 * @param expected_leaf Digest-derived leaf selected by enumeration.
 * @return Parsed terminal object or DATA_LOSS/canonicalization failure.
 */
[[nodiscard]] status_or<parsed_staged_snapshot> parse_staged_record(const std::string &bytes,
								    std::string_view expected_leaf)
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	const auto parse_status = kinetum::common::parse_pbtxt_text(bytes, std::string(expected_leaf), &snapshot);
	if (!parse_status.is_ok()) {
		return status(status_code::DATA_LOSS, "snapshot corpus object contains malformed protobuf text",
			      std::string(parse_status.message()));
	}
	auto canonical_or = kinetum::common::canonical_config_snapshot_from_terminal(snapshot);
	if (!canonical_or.is_ok()) {
		return status(status_code::DATA_LOSS, "snapshot corpus object failed terminal re-admission",
			      std::string(canonical_or.error().message()));
	}
	auto leaf_or = snapshot_leaf(snapshot.snapshot_id());
	if (!leaf_or.is_ok()) {
		return leaf_or.error();
	}
	if (leaf_or.value() != expected_leaf) {
		return status::data_loss("snapshot corpus leaf digest disagrees with ConfigSnapshot.snapshot_id");
	}
	auto canonical_text_or = kinetum::common::print_pbtxt_text(snapshot);
	if (!canonical_text_or.is_ok()) {
		return canonical_text_or.error();
	}
	if (canonical_text_or.value() != bytes) {
		return status::data_loss("snapshot corpus object is not exact canonical protobuf text");
	}
	return parsed_staged_snapshot{
		.snapshot = std::move(snapshot),
		.validation_hash = canonical_or->validation_hash,
	};
}

/**
 * @brief Compare one canonical value with one terminal snapshot exactly.
 * @param canonical Exact canonical bytes/raw digest.
 * @param snapshot Candidate terminal message.
 * @return Exact byte-and-digest equality or terminal-admission failure.
 */
[[nodiscard]] status_or<bool> canonical_equals_snapshot(const kinetum::common::canonical_config_snapshot &canonical,
							const kinetum::control::v1::ConfigSnapshot &snapshot)
{
	auto existing_or = kinetum::common::canonical_config_snapshot_from_terminal(snapshot);
	if (!existing_or.is_ok()) {
		return existing_or.error();
	}
	return existing_or->validation_hash == canonical.validation_hash &&
	       existing_or->serialized_bytes == canonical.serialized_bytes;
}

/**
 * @brief Reconstruct and verify one fixed transition identity.
 * @param transition Candidate private durable record.
 * @return Fixed identity or the first numeric/key/hash/digest failure.
 */
[[nodiscard]] status_or<kinetum::common::epoch_transition_identity>
transition_identity(const durable_transition &transition)
{
	auto identity_or = kinetum::common::make_epoch_transition_identity(transition.mutation_sequence(),
									   transition.target_epoch(),
									   transition.validation_hash(),
									   transition.idempotency_key());
	if (!identity_or.is_ok()) {
		return identity_or.error();
	}
	const auto &digest = identity_or->idempotency_key_digest;
	if (transition.idempotency_key_digest().size() != digest.size() ||
	    !std::equal(digest.begin(), digest.end(), transition.idempotency_key_digest().begin(),
			[](uint8_t expected, char observed) { return expected == static_cast<uint8_t>(observed); })) {
		return status::data_loss("durable transition idempotency-key digest disagrees with its exact key");
	}
	return identity_or.value();
}

/**
 * @brief Populate one bounded terminal wire status from a common status.
 * @param source Exact common outcome to retain.
 * @param[out] target Cleared compact wire status. Must not be null.
 * @return OK after bounded mapping or the destination/diagnostic failure.
 */
[[nodiscard]] status set_terminal_status(const status &source, kinetum::common::v1::Status *target)
{
	if (target == nullptr) {
		return status::invalid_argument("terminal status destination must not be null");
	}
	status_code decoded{};
	if (!kinetum::common::decode_application_status_code(static_cast<int32_t>(source.code()), decoded) ||
	    decoded != source.code()) {
		return status::invalid_argument("terminal transition status code is undeclared");
	}
	if (!source.details().empty()) {
		return status::invalid_argument("terminal transition status does not admit unstructured details");
	}
	if (source.message().size() > kinetum::common::MAX_TRANSITION_DIAGNOSTIC_BYTES) {
		return status::resource_exhausted("terminal transition diagnostic exceeds the shared bound");
	}
	target->Clear();
	target->set_code(static_cast<int32_t>(source.code()));
	target->set_error_code(kinetum::common::application_error_code(source.code()));
	const auto message = source.message();
	target->set_message(message.empty() ? "" : message.data(), message.size());
	return status::ok();
}

/**
 * @brief Validate compact terminal-status representation for one phase.
 * @param transition Candidate private transition record.
 * @return OK for exact presence/category/bounds; otherwise explicit failure.
 */
[[nodiscard]] status validate_terminal_status(const durable_transition &transition)
{
	const bool terminal = is_terminal_phase(transition.phase());
	if (terminal != transition.has_terminal_status()) {
		return status::invalid_argument("durable terminal-status presence disagrees with transition phase");
	}
	if (!terminal) {
		return status::ok();
	}
	const auto &wire = transition.terminal_status();
	status_code code{};
	if (!kinetum::common::decode_application_status_code(wire.code(), code)) {
		return status::invalid_argument("durable terminal status code is undeclared");
	}
	if (wire.message().size() > kinetum::common::MAX_TRANSITION_DIAGNOSTIC_BYTES) {
		return status::resource_exhausted("durable terminal status diagnostic exceeds its compact bound");
	}
	if (!wire.details().empty()) {
		return status::invalid_argument("durable terminal status contains unsupported auxiliary fields");
	}
	if (wire.error_code() != kinetum::common::application_error_code(code)) {
		return status::invalid_argument("durable terminal status code and error classification disagree");
	}
	if (transition.phase() == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE) {
		return code == status_code::OK && wire.message().empty() ?
			       status::ok() :
			       status::invalid_argument("COMPLETE transition requires one exact empty success status");
	}
	return code != status_code::OK ? status::ok() :
					 status::invalid_argument("ABORTED transition requires exact terminal failure");
}

/**
 * @brief Validate one restart-stable pending-confirm record in isolation.
 * @param pending Candidate embedded record.
 * @return OK for one exact bounded deadline/identity tuple.
 */
[[nodiscard]] status validate_pending_confirm(const kinetum::control::v1::PendingConfirm &pending)
{
	const auto target_status = validate_snapshot_id(pending.snapshot_id());
	if (!target_status.is_ok()) {
		return target_status;
	}
	const auto rollback_status = validate_snapshot_id(pending.rollback_snapshot_id());
	if (!rollback_status.is_ok()) {
		return rollback_status;
	}
	const bool confirmation_digest_present = !pending.confirmation_key_digest().empty();
	if (pending.snapshot_id() == pending.rollback_snapshot_id() ||
	    !kinetum::common::valid_epoch_id(pending.epoch()) ||
	    !kinetum::common::valid_config_snapshot_revision(pending.revision()) || pending.created_unix_ms() < 0 ||
	    pending.deadline_unix_ms() < 0 || pending.original_timeout_ms() == 0u ||
	    pending.original_timeout_ms() > std::numeric_limits<uint32_t>::max() ||
	    pending.created_unix_ms() >
		    std::numeric_limits<int64_t>::max() - static_cast<int64_t>(pending.original_timeout_ms()) ||
	    pending.deadline_unix_ms() !=
		    pending.created_unix_ms() + static_cast<int64_t>(pending.original_timeout_ms()) ||
	    pending.confirmed() != confirmation_digest_present ||
	    (confirmation_digest_present &&
	     pending.confirmation_key_digest().size() != kinetum::common::SHA256_DIGEST_SIZE) ||
	    (!pending.confirmed() && pending.confirmed_time_remaining_ms() != 0u) ||
	    (pending.confirmed() && (pending.confirmed_time_remaining_ms() == 0u ||
				     pending.confirmed_time_remaining_ms() > pending.original_timeout_ms()))) {
		return status::invalid_argument("pending-confirm fields do not form one exact bounded deadline record");
	}
	return status::ok();
}

/**
 * @brief Test one raw wire digest against a fixed digest.
 * @param wire Candidate bytes from a private record.
 * @param digest Expected exact SHA-256 value.
 * @return true only for equal width and bytes.
 */
[[nodiscard]] bool digest_matches(std::string_view wire, const kinetum::common::sha256_digest &digest) noexcept
{
	return wire.size() == digest.size() &&
	       std::equal(digest.begin(), digest.end(), wire.begin(),
			  [](uint8_t expected, char observed) { return expected == static_cast<uint8_t>(observed); });
}

/**
 * @brief Populate one private bytes field from a fixed digest.
 * @param digest Exact source digest.
 * @param[out] target Destination string owned by a generated message.
 */
void set_digest(const kinetum::common::sha256_digest &digest, std::string *target)
{
	target->assign(reinterpret_cast<const char *>(digest.data()), digest.size());
}

/**
 * @brief Convert one public C++ intent cause to its private wire identity.
 * @param cause Candidate exact cause.
 * @return Corresponding declared wire value.
 */
[[nodiscard]] kinetum::control::internal::v1::DurableRollbackCause
rollback_cause_to_wire(rollback_intent_cause cause) noexcept
{
	using wire = kinetum::control::internal::v1::DurableRollbackCause;
	switch (cause) {
	case rollback_intent_cause::UNSPECIFIED:
		break;
	case rollback_intent_cause::COMMIT_CONFIRM_DEADLINE:
		return wire::DURABLE_ROLLBACK_CAUSE_COMMIT_CONFIRM_DEADLINE;
	case rollback_intent_cause::THRESHOLD_DEGRADATION:
		return wire::DURABLE_ROLLBACK_CAUSE_THRESHOLD_DEGRADATION;
	case rollback_intent_cause::CORRELATED_DEGRADATION:
		return wire::DURABLE_ROLLBACK_CAUSE_CORRELATED_DEGRADATION;
	case rollback_intent_cause::BOUNDARY_ACK_TIMEOUT:
		return wire::DURABLE_ROLLBACK_CAUSE_BOUNDARY_ACK_TIMEOUT;
	}
	std::terminate();
}

/**
 * @brief Test whether one C++ rollback cause is declared.
 * @param cause Candidate exact cause.
 * @return true only for one declared non-sentinel cause.
 */
[[nodiscard]] bool valid_rollback_cause(rollback_intent_cause cause) noexcept
{
	switch (cause) {
	case rollback_intent_cause::UNSPECIFIED:
		return false;
	case rollback_intent_cause::COMMIT_CONFIRM_DEADLINE:
	case rollback_intent_cause::THRESHOLD_DEGRADATION:
	case rollback_intent_cause::CORRELATED_DEGRADATION:
	case rollback_intent_cause::BOUNDARY_ACK_TIMEOUT:
		return true;
	}
	return false;
}

/**
 * @brief Convert one admitted private cause to its C++ identity.
 * @param cause Candidate wire cause.
 * @param[out] output Decoded C++ cause.
 * @return true only for one declared non-sentinel cause.
 */
[[nodiscard]] bool rollback_cause_from_wire(kinetum::control::internal::v1::DurableRollbackCause cause,
					    rollback_intent_cause &output) noexcept
{
	using wire = kinetum::control::internal::v1::DurableRollbackCause;
	switch (cause) {
	case wire::DURABLE_ROLLBACK_CAUSE_COMMIT_CONFIRM_DEADLINE:
		output = rollback_intent_cause::COMMIT_CONFIRM_DEADLINE;
		return true;
	case wire::DURABLE_ROLLBACK_CAUSE_THRESHOLD_DEGRADATION:
		output = rollback_intent_cause::THRESHOLD_DEGRADATION;
		return true;
	case wire::DURABLE_ROLLBACK_CAUSE_CORRELATED_DEGRADATION:
		output = rollback_intent_cause::CORRELATED_DEGRADATION;
		return true;
	case wire::DURABLE_ROLLBACK_CAUSE_BOUNDARY_ACK_TIMEOUT:
		output = rollback_intent_cause::BOUNDARY_ACK_TIMEOUT;
		return true;
	case wire::DURABLE_ROLLBACK_CAUSE_UNSPECIFIED:
	case kinetum::control::internal::v1::DurableRollbackCause_INT_MIN_SENTINEL_DO_NOT_USE_:
	case kinetum::control::internal::v1::DurableRollbackCause_INT_MAX_SENTINEL_DO_NOT_USE_:
		return false;
	}
	return false;
}

/** @brief Wrapper permitting a non-OK status to be a status_or value. */
struct decoded_terminal_failure {
	status value;  ///< Exact decoded non-OK failure.
};

/**
 * @brief Decode one compact private terminal status.
 * @param wire Candidate admitted status.
 * @return Wrapped common status or DATA_LOSS for an undeclared code.
 */
[[nodiscard]] status_or<decoded_terminal_failure> decode_terminal_status(const kinetum::common::v1::Status &wire)
{
	status_code code{};
	if (!kinetum::common::decode_exact_application_status(wire, code) || code == status_code::OK) {
		return status::data_loss("durable terminal status is malformed");
	}
	return decoded_terminal_failure{status(code, wire.message())};
}

/**
 * @brief Validate one compact non-OK status used by a durable intent latch.
 * @param wire Candidate private status.
 * @return OK only for a declared bounded failure without auxiliary fields.
 */
[[nodiscard]] status validate_compact_failure(const kinetum::common::v1::Status &wire)
{
	status_code code{};
	if (!kinetum::common::decode_application_status_code(wire.code(), code) || code == status_code::OK ||
	    wire.error_code() != kinetum::common::application_error_code(code) ||
	    wire.message().size() > kinetum::common::MAX_TRANSITION_DIAGNOSTIC_BYTES || !wire.details().empty()) {
		return status::invalid_argument("durable intent terminal status is not one compact typed failure");
	}
	return status::ok();
}

/**
 * @brief Reconstruct one durable guardrails policy result.
 * @param record Exact admitted private record.
 * @param exact_retry Whether no replacement was performed.
 * @return Public C++ view or DATA_LOSS for contradictory identity.
 */
[[nodiscard]] status_or<durable_guardrails_policy_view>
guardrails_policy_view(const kinetum::control::internal::v1::DurableGuardrailsPolicy &record, bool exact_retry)
{
	if (!record.has_policy()) {
		return status::data_loss("durable guardrails policy omits its explicit policy value");
	}
	auto canonical_or = canonicalize_guardrails_policy(record.policy());
	if (!canonical_or.is_ok() || !digest_matches(record.policy_hash(), canonical_or->policy_hash) ||
	    record.generation() == 0u) {
		return status::data_loss("durable guardrails policy failed identity reconstruction");
	}
	return durable_guardrails_policy_view{
		.policy = record.policy(),
		.generation = record.generation(),
		.policy_hash = canonical_or->policy_hash,
		.exact_retry = exact_retry,
	};
}

/**
 * @brief Reconstruct one exact durable rollback intent.
 * @param record Exact admitted private record.
 * @return Public C++ view or DATA_LOSS for malformed cause/status identity.
 */
[[nodiscard]] status_or<durable_rollback_intent_view>
rollback_intent_view(const kinetum::control::internal::v1::DurableRollbackIntent &record)
{
	rollback_intent_cause cause{};
	if (!rollback_cause_from_wire(record.cause(), cause) ||
	    record.guarded_validation_hash().size() != kinetum::common::SHA256_DIGEST_SIZE) {
		return status::data_loss("durable rollback intent cause or validation hash is malformed");
	}
	durable_rollback_intent_view view;
	view.request.target_snapshot_id = record.target_snapshot_id();
	view.request.guarded_snapshot_id = record.guarded_snapshot_id();
	view.request.guarded_epoch = record.guarded_epoch();
	view.request.guarded_revision = record.guarded_revision();
	std::copy_n(reinterpret_cast<const uint8_t *>(record.guarded_validation_hash().data()),
		    view.request.guarded_validation_hash.size(), view.request.guarded_validation_hash.begin());
	view.request.wait_for_mutation_sequence = record.wait_for_mutation_sequence();
	view.request.policy_generation = record.policy_generation();
	view.request.runtime_generation = record.runtime_generation();
	view.request.idempotency_key = record.idempotency_key();
	view.request.cause = cause;
	view.request.observed_monotonic_ns = record.observed_monotonic_ns();
	view.request.created_unix_ms = record.created_unix_ms();
	if (record.has_terminal_status()) {
		auto failure_or = decode_terminal_status(record.terminal_status());
		if (!failure_or.is_ok()) {
			return status::data_loss("durable rollback intent failure is malformed");
		}
		view.terminal_failure = std::move(failure_or).value().value;
	}
	return view;
}

}  // namespace

config_store::config_store(kinetum::common::durable_directory directory) noexcept
	: directory_(std::move(directory))
{
}

status_or<std::unique_ptr<config_store>> config_store::open(const std::filesystem::path &absolute_root)
{
	auto directory_or = kinetum::common::durable_directory::open(absolute_root);
	if (!directory_or.is_ok()) {
		return directory_or.error();
	}
	try {
		auto store = std::unique_ptr<config_store>(new config_store(std::move(directory_or).value()));
		const auto load_status = store->load_existing_state_();
		if (!load_status.is_ok()) {
			return load_status;
		}
		return store;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("config store construction exhausted memory");
	}
}

std::vector<config_store::staged_snapshot_record>::iterator config_store::lower_bound_(std::string_view id) noexcept
{
	return std::lower_bound(staged_.begin(), staged_.end(), id,
				[](const staged_snapshot_record &record, std::string_view value) {
					return record.snapshot.snapshot_id() < value;
				});
}

std::vector<config_store::staged_snapshot_record>::const_iterator
config_store::lower_bound_(std::string_view id) const noexcept
{
	return std::lower_bound(staged_.begin(), staged_.end(), id,
				[](const staged_snapshot_record &record, std::string_view value) {
					return record.snapshot.snapshot_id() < value;
				});
}

status_or<std::string> config_store::snapshot_listing_identity_locked_() const
{
	kinetum::common::sha256_hasher hasher;
	hasher.update("kinetum-snapshot-listing-v1");
	hash_listing_uint64(hasher, static_cast<uint64_t>(staged_.size()));
	for (const auto &record : staged_) {
		hash_listing_bytes(hasher, record.snapshot.snapshot_id());
		hasher.update(record.validation_hash.data(), record.validation_hash.size());
	}
	if (authority_ == nullptr) {
		hash_listing_uint64(hasher, 0u);
		return hasher.finalize_hex();
	}

	const auto &active = authority_->active_bootstrap();
	hash_listing_uint64(hasher, 1u);
	hash_listing_bytes(hasher, active.snapshot().snapshot_id());
	hash_listing_uint64(hasher, static_cast<uint64_t>(active.snapshot().revision()));
	hash_listing_uint64(hasher, active.active_epoch());
	hash_listing_uint64(hasher, active.allocated_epoch_high_watermark());
	hash_listing_uint64(hasher, active.mutation_sequence_high_watermark());
	hash_listing_bytes(hasher, active.plan_content_hash());
	hash_listing_bytes(hasher, active.snapshot().content_hash());
	return hasher.finalize_hex();
}

status config_store::load_existing_state_()
{
	auto names_or = directory_.list_files();
	if (!names_or.is_ok()) {
		return names_or.error();
	}
	try {
		std::unique_ptr<authority_message> loaded_authority;
		std::vector<staged_snapshot_record> loaded_staged;
		for (const auto &name : names_or.value()) {
			if (name == TRANSITION_AUTHORITY_LEAF) {
				if (loaded_authority != nullptr) {
					return status::data_loss(
						"durable store contains duplicate transition authority");
				}
				auto bytes_or = directory_.read_file(name, MAX_TRANSITION_AUTHORITY_BYTES);
				if (!bytes_or.is_ok()) {
					return bytes_or.error();
				}
				auto candidate = std::make_unique<authority_message>();
				if (!candidate->ParseFromString(bytes_or.value())) {
					return status::data_loss(
						"TRANSITION_AUTHORITY.pb contains malformed binary protobuf data");
				}
				auto deterministic_or =
					kinetum::common::serialize_protobuf_deterministically(*candidate);
				if (!deterministic_or.is_ok()) {
					return deterministic_or.error();
				}
				if (deterministic_or.value() != bytes_or.value()) {
					return status::data_loss(
						"TRANSITION_AUTHORITY.pb is not the exact deterministic wire representation");
				}
				loaded_authority = std::move(candidate);
				continue;
			}
			if (!is_snapshot_leaf(name)) {
				return status::data_loss("durable store contains an unknown file: " + name);
			}
			auto bytes_or = directory_.read_file(name, MAX_STORE_PBTXT_BYTES);
			if (!bytes_or.is_ok()) {
				return bytes_or.error();
			}
			auto record_or = parse_staged_record(bytes_or.value(), name);
			if (!record_or.is_ok()) {
				return record_or.error();
			}
			auto record = std::move(record_or).value();
			loaded_staged.push_back(staged_snapshot_record{
				.snapshot = std::move(record.snapshot),
				.validation_hash = record.validation_hash,
			});
		}

		std::sort(loaded_staged.begin(), loaded_staged.end(), [](const auto &lhs, const auto &rhs) {
			return lhs.snapshot.snapshot_id() < rhs.snapshot.snapshot_id();
		});
		for (std::size_t index = 1; index < loaded_staged.size(); ++index) {
			if (loaded_staged[index - 1u].snapshot.snapshot_id() ==
			    loaded_staged[index].snapshot.snapshot_id()) {
				return status::data_loss("snapshot corpus contains duplicate semantic identity");
			}
		}

		staged_ = std::move(loaded_staged);
		authority_ = std::move(loaded_authority);
		if (authority_ != nullptr) {
			auto validated_or = validate_authority_(*authority_);
			if (!validated_or.is_ok()) {
				return status(status_code::DATA_LOSS,
					      "TRANSITION_AUTHORITY.pb failed full re-admission",
					      std::string(validated_or.error().message()));
			}
		}
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("config store loading exhausted memory");
	}
}

status_or<std::string> config_store::validate_authority_(
	const kinetum::control::internal::v1::ControlPlaneTransitionAuthority &authority) const
{
	const auto unknown_status =
		kinetum::common::reject_unknown_protobuf_fields_recursive(authority, "ControlPlaneTransitionAuthority");
	if (!unknown_status.is_ok()) {
		return unknown_status;
	}
	const auto enum_status = kinetum::common::reject_invalid_protobuf_enum_values_recursive(
		authority, "ControlPlaneTransitionAuthority");
	if (!enum_status.is_ok()) {
		return enum_status;
	}
	if (!authority.has_active_bootstrap()) {
		return status::invalid_argument("transition authority requires one exact active Bootstrap request");
	}
	auto active_or = kinetum::common::validate_bootstrap_config_snapshot_request(authority.active_bootstrap());
	if (!active_or.is_ok()) {
		return active_or.error();
	}
	const auto active_position = lower_bound_(authority.active_bootstrap().snapshot().snapshot_id());
	if (active_position != staged_.end() &&
	    active_position->snapshot.snapshot_id() == authority.active_bootstrap().snapshot().snapshot_id()) {
		auto equal_or = canonical_equals_snapshot(active_or->snapshot, active_position->snapshot);
		if (!equal_or.is_ok()) {
			return equal_or.error();
		}
		if (!equal_or.value()) {
			return status::data_loss("active snapshot ID owns different canonical corpus bytes");
		}
	}

	if (authority.has_transition()) {
		const auto &transition = authority.transition();
		if (active_position == staged_.end() ||
		    active_position->snapshot.snapshot_id() != authority.active_bootstrap().snapshot().snapshot_id()) {
			return status::data_loss("durable transition requires active content in the canonical corpus");
		}
		if (!kinetum::control::internal::v1::DurableEpochTransitionPhase_IsValid(
			    static_cast<int>(transition.phase())) ||
		    transition.phase() == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_UNSPECIFIED) {
			return status::invalid_argument("durable transition phase is unspecified or undeclared");
		}
		const auto id_status = validate_snapshot_id(transition.snapshot_id());
		if (!id_status.is_ok()) {
			return id_status;
		}
		auto identity_or = transition_identity(transition);
		if (!identity_or.is_ok()) {
			return identity_or.error();
		}
		if (transition.target_epoch() != authority.active_bootstrap().allocated_epoch_high_watermark() ||
		    transition.mutation_sequence() != authority.active_bootstrap().mutation_sequence_high_watermark()) {
			return status::data_loss(
				"durable transition identity disagrees with allocator high watermarks");
		}
		const auto candidate = lower_bound_(transition.snapshot_id());
		if (candidate == staged_.end() || candidate->snapshot.snapshot_id() != transition.snapshot_id()) {
			return status::data_loss("durable transition references a missing canonical corpus object");
		}
		if (transition.validation_hash().size() != candidate->validation_hash.size() ||
		    !std::equal(candidate->validation_hash.begin(), candidate->validation_hash.end(),
				transition.validation_hash().begin(), [](uint8_t expected, char observed) {
					return expected == static_cast<uint8_t>(observed);
				})) {
			return status::data_loss("durable transition hash disagrees with canonical corpus content");
		}
		const auto terminal_status = validate_terminal_status(transition);
		if (!terminal_status.is_ok()) {
			return terminal_status;
		}
		if (transition.phase() == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE) {
			if ((transition.confirm_timeout_ms() != 0u) != authority.has_pending_confirm()) {
				return status::data_loss(
					"COMPLETE transition confirmation policy and pending state disagree");
			}
			if (authority.active_bootstrap().active_epoch() != transition.target_epoch() ||
			    authority.active_bootstrap().snapshot().snapshot_id() != transition.snapshot_id()) {
				return status::data_loss("COMPLETE transition disagrees with active Bootstrap state");
			}
		} else if (authority.active_bootstrap().active_epoch() >= transition.target_epoch()) {
			return status::data_loss("non-COMPLETE transition does not advance the active epoch");
		}
	}

	if (authority.has_pending_confirm()) {
		const auto pending_status = validate_pending_confirm(authority.pending_confirm());
		if (!pending_status.is_ok()) {
			return pending_status;
		}
		const auto &pending = authority.pending_confirm();
		if (pending.snapshot_id() != authority.active_bootstrap().snapshot().snapshot_id() ||
		    pending.epoch() != authority.active_bootstrap().active_epoch() ||
		    pending.revision() != authority.active_bootstrap().snapshot().revision()) {
			return status::data_loss("pending-confirm state disagrees with active Bootstrap identity");
		}
		if (pending.confirmed() &&
		    (!authority.has_transition() ||
		     authority.transition().phase() != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE)) {
			return status::data_loss("confirmed pending state lacks its exact COMPLETE transition owner");
		}
		const auto rollback = lower_bound_(pending.rollback_snapshot_id());
		if (rollback == staged_.end() || rollback->snapshot.snapshot_id() != pending.rollback_snapshot_id()) {
			return status::data_loss("pending-confirm rollback target is absent from canonical corpus");
		}
		if (authority.has_transition()) {
			const auto phase = authority.transition().phase();
			if (is_nonterminal_phase(phase) && pending.confirmed()) {
				return status::data_loss(
					"confirmed pending state cannot coexist with live transition intent");
			}
			if (phase != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE &&
			    authority.transition().confirm_timeout_ms() != 0u) {
				return status::data_loss(
					"pending-confirm rollback attempted to arm another confirmation deadline");
			}
			if (phase != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE &&
			    authority.transition().snapshot_id() != pending.rollback_snapshot_id()) {
				return status::data_loss(
					"pending-confirm state permits only its exact rollback transition");
			}
			if (phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE &&
			    (authority.transition().confirm_timeout_ms() == 0u ||
			     authority.transition().confirm_timeout_ms() != pending.original_timeout_ms())) {
				return status::data_loss(
					"COMPLETE transition disagrees with its pending-confirm timeout");
			}
		}
	}

	if (authority.has_guardrails_policy()) {
		const auto &record = authority.guardrails_policy();
		if (!record.has_policy()) {
			return status::data_loss("durable guardrails policy omits its explicit policy value");
		}
		auto canonical_or = canonicalize_guardrails_policy(record.policy());
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		if (record.generation() == 0u || record.generation() == std::numeric_limits<uint64_t>::max() ||
		    !digest_matches(record.policy_hash(), canonical_or->policy_hash) ||
		    record.idempotency_key_digest().size() != kinetum::common::SHA256_DIGEST_SIZE) {
			return status::data_loss("durable guardrails policy identity is malformed or contradictory");
		}
	}

	if (authority.has_rollback_intent()) {
		const auto &intent = authority.rollback_intent();
		rollback_intent_cause cause{};
		const auto target_status = validate_snapshot_id(intent.target_snapshot_id());
		const auto guarded_status = validate_snapshot_id(intent.guarded_snapshot_id());
		auto key_digest_or = kinetum::common::digest_transition_idempotency_key(intent.idempotency_key());
		if (!target_status.is_ok()) {
			return target_status;
		}
		if (!guarded_status.is_ok()) {
			return guarded_status;
		}
		if (!rollback_cause_from_wire(intent.cause(), cause) ||
		    intent.target_snapshot_id() == intent.guarded_snapshot_id() ||
		    !kinetum::common::valid_epoch_id(intent.guarded_epoch()) ||
		    !kinetum::common::valid_config_snapshot_revision(intent.guarded_revision()) ||
		    intent.guarded_validation_hash().size() != kinetum::common::SHA256_DIGEST_SIZE ||
		    (intent.wait_for_mutation_sequence() != 0u &&
		     !kinetum::common::valid_mutation_sequence(intent.wait_for_mutation_sequence())) ||
		    intent.runtime_generation() == 0u || intent.runtime_generation() > UINT32_MAX ||
		    intent.observed_monotonic_ns() == 0u || intent.created_unix_ms() < 0 || !key_digest_or.is_ok() ||
		    !digest_matches(intent.idempotency_key_digest(), key_digest_or.value())) {
			return status::data_loss("durable rollback intent identity is malformed");
		}

		const auto target = lower_bound_(intent.target_snapshot_id());
		if (target == staged_.end() || target->snapshot.snapshot_id() != intent.target_snapshot_id()) {
			return status::data_loss("durable rollback intent target is absent from the canonical corpus");
		}

		bool guarded_content_matches = false;
		if (authority.active_bootstrap().snapshot().snapshot_id() == intent.guarded_snapshot_id()) {
			auto guarded_or = kinetum::common::canonical_config_snapshot_from_terminal(
				authority.active_bootstrap().snapshot());
			guarded_content_matches =
				guarded_or.is_ok() &&
				authority.active_bootstrap().active_epoch() == intent.guarded_epoch() &&
				authority.active_bootstrap().snapshot().revision() == intent.guarded_revision() &&
				digest_matches(intent.guarded_validation_hash(), guarded_or->validation_hash);
		}
		if (!guarded_content_matches && authority.has_transition() &&
		    authority.transition().snapshot_id() == intent.guarded_snapshot_id()) {
			const auto guarded = lower_bound_(intent.guarded_snapshot_id());
			guarded_content_matches =
				guarded != staged_.end() &&
				guarded->snapshot.snapshot_id() == intent.guarded_snapshot_id() &&
				authority.transition().target_epoch() == intent.guarded_epoch() &&
				guarded->snapshot.revision() == intent.guarded_revision() &&
				digest_matches(intent.guarded_validation_hash(), guarded->validation_hash);
		}
		if (!guarded_content_matches && intent.has_terminal_status()) {
			const auto guarded = lower_bound_(intent.guarded_snapshot_id());
			guarded_content_matches =
				guarded != staged_.end() &&
				guarded->snapshot.snapshot_id() == intent.guarded_snapshot_id() &&
				guarded->snapshot.revision() == intent.guarded_revision() &&
				digest_matches(intent.guarded_validation_hash(), guarded->validation_hash);
		}
		if (!guarded_content_matches) {
			return status::data_loss(
				"durable rollback intent guarded content is not active, in flight, or terminally retained");
		}

		const bool confirmation_cause = cause == rollback_intent_cause::COMMIT_CONFIRM_DEADLINE;
		if (confirmation_cause != (intent.policy_generation() == 0u)) {
			return status::data_loss("durable rollback intent cause and policy generation disagree");
		}
		if (confirmation_cause) {
			if (!authority.has_pending_confirm() || authority.pending_confirm().confirmed() ||
			    authority.pending_confirm().snapshot_id() != intent.guarded_snapshot_id() ||
			    authority.pending_confirm().epoch() != intent.guarded_epoch() ||
			    authority.pending_confirm().revision() != intent.guarded_revision() ||
			    authority.pending_confirm().rollback_snapshot_id() != intent.target_snapshot_id() ||
			    intent.created_unix_ms() < authority.pending_confirm().deadline_unix_ms()) {
				return status::data_loss(
					"commit-confirm rollback intent disagrees with its expired record");
			}
		} else if (!authority.has_guardrails_policy() ||
			   authority.guardrails_policy().generation() != intent.policy_generation() ||
			   !authority.guardrails_policy().policy().enabled()) {
			return status::data_loss("guardrails rollback intent lacks its exact enabled policy");
		}

		const bool owns_current = authority.has_transition() &&
					  authority.transition().idempotency_key() == intent.idempotency_key() &&
					  authority.transition().snapshot_id() == intent.target_snapshot_id();
		if (owns_current && authority.transition().confirm_timeout_ms() != 0u) {
			return status::data_loss(
				"durable rollback intent attempted to arm another confirmation deadline");
		}
		if (!intent.has_terminal_status()) {
			const bool waits_on_live_predecessor =
				authority.has_transition() && is_nonterminal_phase(authority.transition().phase()) &&
				intent.wait_for_mutation_sequence() == authority.transition().mutation_sequence() &&
				authority.transition().snapshot_id() != intent.target_snapshot_id();
			if (authority.active_bootstrap().snapshot().snapshot_id() == intent.target_snapshot_id() &&
			    !waits_on_live_predecessor) {
				return status::data_loss(
					"durable rollback intent remained pending after its target became active");
			}
			if (owns_current &&
			    intent.wait_for_mutation_sequence() != authority.transition().mutation_sequence()) {
				return status::data_loss("durable rollback intent does not name its owned transition");
			}
			if (!owns_current && authority.has_transition() &&
			    is_nonterminal_phase(authority.transition().phase()) &&
			    intent.wait_for_mutation_sequence() != authority.transition().mutation_sequence()) {
				return status::data_loss("durable rollback intent does not name its live predecessor");
			}
			if (!owns_current && intent.wait_for_mutation_sequence() != 0u &&
			    (!authority.has_transition() ||
			     authority.transition().mutation_sequence() != intent.wait_for_mutation_sequence())) {
				return status::data_loss("durable rollback intent lost its exact predecessor wait");
			}
			if (authority.has_transition() && intent.wait_for_mutation_sequence() != 0u &&
			    intent.wait_for_mutation_sequence() == authority.transition().mutation_sequence() &&
			    authority.transition().phase() == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
				return status::data_loss(
					"durable rollback intent remained pending after its predecessor aborted");
			}
		}
		if (intent.has_terminal_status()) {
			const auto terminal = validate_compact_failure(intent.terminal_status());
			if (!terminal.is_ok()) {
				return terminal;
			}
		}
	}

	auto serialized_or = kinetum::common::serialize_protobuf_deterministically(authority);
	if (!serialized_or.is_ok()) {
		return serialized_or.error();
	}
	if (serialized_or->size() > MAX_TRANSITION_AUTHORITY_BYTES) {
		return status::resource_exhausted("Control Plane transition authority exceeds its exact binary bound");
	}
	return serialized_or.value();
}

status config_store::reconcile_bootstrap(const bootstrap_startup_authority *authority)
{
	try {
		std::unique_lock lock(mutex_);
		if (authority == nullptr) {
			return status::ok();
		}
		kinetum::control::v1::ConfigSnapshot source_snapshot;
		const auto source_status =
			kinetum::common::admit_terminal_config_snapshot(authority->snapshot, &source_snapshot);
		if (!source_status.is_ok()) {
			return source_status;
		}
		auto plan_hash_or =
			kinetum::common::decode_sha256_digest_claim(authority->plan_content_hash, "plan_content_hash");
		if (!plan_hash_or.is_ok()) {
			return plan_hash_or.error();
		}
		if (plan_hash_or.value() != authority->plan_content_hash_bytes) {
			return status::invalid_argument("bootstrap plan identity representations disagree");
		}

		if (authority_ != nullptr) {
			const auto &active = authority_->active_bootstrap();
			if (active.plan_content_hash() != authority->plan_content_hash) {
				return status::failed_precondition(
					"bootstrap plan identity conflicts with durable transition authority");
			}
			auto existing_or = kinetum::common::validate_bootstrap_config_snapshot_request(active);
			if (!existing_or.is_ok()) {
				return status::data_loss(
					"in-memory transition authority failed Bootstrap re-admission");
			}
			const bool pristine = active.active_epoch() == INITIAL_BOOTSTRAP_IDENTITY &&
					      active.allocated_epoch_high_watermark() == INITIAL_BOOTSTRAP_IDENTITY &&
					      active.mutation_sequence_high_watermark() == INITIAL_BOOTSTRAP_IDENTITY &&
					      !authority_->has_transition();
			if (pristine &&
			    (existing_or->snapshot.serialized_bytes != authority->snapshot.serialized_bytes ||
			     existing_or->snapshot.validation_hash != authority->snapshot.validation_hash)) {
				return status::failed_precondition(
					"bootstrap snapshot conflicts with pristine durable transition authority");
			}
			return status::ok();
		}

		const auto corpus_collision = lower_bound_(source_snapshot.snapshot_id());
		if (corpus_collision != staged_.end() &&
		    corpus_collision->snapshot.snapshot_id() == source_snapshot.snapshot_id()) {
			auto equal_or = canonical_equals_snapshot(authority->snapshot, corpus_collision->snapshot);
			if (!equal_or.is_ok()) {
				return equal_or.error();
			}
			if (!equal_or.value()) {
				return status::data_loss("bootstrap snapshot ID owns different canonical corpus bytes");
			}
		}

		kinetum::dataplane::v1::BootstrapConfigSnapshotRequest request;
		request.mutable_snapshot()->CopyFrom(source_snapshot);
		request.set_active_epoch(INITIAL_BOOTSTRAP_IDENTITY);
		request.set_allocated_epoch_high_watermark(INITIAL_BOOTSTRAP_IDENTITY);
		request.set_mutation_sequence_high_watermark(INITIAL_BOOTSTRAP_IDENTITY);
		request.set_plan_content_hash(authority->plan_content_hash);
		auto key_or = kinetum::common::derive_bootstrap_config_snapshot_idempotency_key(
			authority->snapshot.validation_hash, plan_hash_or.value(), INITIAL_BOOTSTRAP_IDENTITY,
			INITIAL_BOOTSTRAP_IDENTITY, INITIAL_BOOTSTRAP_IDENTITY);
		if (!key_or.is_ok()) {
			return key_or.error();
		}
		request.set_idempotency_key(std::move(key_or).value());
		auto request_or = kinetum::common::validate_bootstrap_config_snapshot_request(request);
		if (!request_or.is_ok()) {
			return request_or.error();
		}

		authority_message next;
		next.mutable_active_bootstrap()->CopyFrom(request);
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto publish_status =
			directory_.publish_new_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!publish_status.is_ok()) {
			return publish_status;
		}
		authority_.swap(next_owner);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("bootstrap reconciliation exhausted memory");
	}
}

status_or<kinetum::dataplane::v1::BootstrapConfigSnapshotRequest> config_store::active_bootstrap() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::not_found("no active Bootstrap authority exists");
		}
		return authority_->active_bootstrap();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("active Bootstrap copy exhausted memory");
	}
}

status_or<durable_runtime_authority_view> config_store::runtime_authority() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::not_found("no active Bootstrap authority exists");
		}
		const auto &active = authority_->active_bootstrap();
		auto active_hash_or = kinetum::common::decode_sha256_digest_claim(active.snapshot().content_hash(),
										  "active ConfigSnapshot.content_hash");
		auto plan_hash_or = kinetum::common::decode_sha256_digest_claim(active.plan_content_hash(),
										"active plan_content_hash");
		if (!active_hash_or.is_ok() || !plan_hash_or.is_ok()) {
			return status::data_loss("active runtime authority contains malformed content identity");
		}
		durable_runtime_authority_view view{
			.active =
				durable_active_runtime_view{
					.snapshot_id = active.snapshot().snapshot_id(),
					.revision = active.snapshot().revision(),
					.active_epoch = active.active_epoch(),
					.allocated_epoch_high_watermark = active.allocated_epoch_high_watermark(),
					.mutation_sequence_high_watermark = active.mutation_sequence_high_watermark(),
					.plan_content_hash = plan_hash_or.value(),
					.active_validation_hash = active_hash_or.value(),
				},
			.transition = std::nullopt,
		};
		if (authority_->has_transition()) {
			auto identity_or = transition_identity(authority_->transition());
			if (!identity_or.is_ok()) {
				return identity_or.error();
			}
			const auto candidate = lower_bound_(authority_->transition().snapshot_id());
			if (candidate == staged_.end() ||
			    candidate->snapshot.snapshot_id() != authority_->transition().snapshot_id()) {
				return status::data_loss("runtime fence transition target is absent from the corpus");
			}
			view.transition = durable_runtime_transition_view{
				.identity = identity_or.value(),
				.phase = authority_->transition().phase(),
				.snapshot_id = candidate->snapshot.snapshot_id(),
				.revision = candidate->snapshot.revision(),
			};
		}
		return view;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("runtime authority copy exhausted memory");
	}
}

status config_store::stage_snapshot_locked_(const kinetum::common::canonical_config_snapshot &canonical)
{
	kinetum::control::v1::ConfigSnapshot snapshot;
	const auto admission_status = kinetum::common::admit_terminal_config_snapshot(canonical, &snapshot);
	if (!admission_status.is_ok()) {
		return admission_status;
	}
	const auto position = lower_bound_(snapshot.snapshot_id());
	if (position != staged_.end() && position->snapshot.snapshot_id() == snapshot.snapshot_id()) {
		auto equal_or = canonical_equals_snapshot(canonical, position->snapshot);
		if (!equal_or.is_ok()) {
			return equal_or.error();
		}
		return equal_or.value() ? status::ok() :
					  status::data_loss("snapshot ID owns different canonical corpus bytes");
	}
	if (authority_ != nullptr &&
	    authority_->active_bootstrap().snapshot().snapshot_id() == snapshot.snapshot_id()) {
		auto equal_or = canonical_equals_snapshot(canonical, authority_->active_bootstrap().snapshot());
		if (!equal_or.is_ok()) {
			return equal_or.error();
		}
		if (!equal_or.value()) {
			return status::data_loss("snapshot ID disagrees with active canonical bytes");
		}
	}

	auto text_or = kinetum::common::print_pbtxt_text(snapshot);
	if (!text_or.is_ok()) {
		return text_or.error();
	}
	auto leaf_or = snapshot_leaf(snapshot.snapshot_id());
	if (!leaf_or.is_ok()) {
		return leaf_or.error();
	}
	const auto offset = static_cast<std::size_t>(std::distance(staged_.begin(), position));
	std::vector<staged_snapshot_record> next_staged(staged_);
	next_staged.insert(next_staged.begin() + static_cast<std::ptrdiff_t>(offset),
			   staged_snapshot_record{.snapshot = snapshot, .validation_hash = canonical.validation_hash});
	const auto publish_status = directory_.publish_new_file(leaf_or.value(), text_or.value());
	if (!publish_status.is_ok()) {
		return publish_status;
	}
	staged_.swap(next_staged);
	return status::ok();
}

status config_store::stage_snapshot(const kinetum::common::canonical_config_snapshot &canonical)
{
	try {
		std::unique_lock lock(mutex_);
		return stage_snapshot_locked_(canonical);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("snapshot corpus publication exhausted memory");
	}
}

status_or<durable_epoch_transition_view>
config_store::transition_view_locked_(const kinetum::control::internal::v1::DurableEpochTransition &transition,
				      bool exact_retry) const
{
	const auto candidate = lower_bound_(transition.snapshot_id());
	if (candidate == staged_.end() || candidate->snapshot.snapshot_id() != transition.snapshot_id()) {
		return status::data_loss("durable transition references a missing canonical corpus object");
	}
	durable_epoch_transition_view view;
	view.prepare_request.mutable_snapshot()->CopyFrom(candidate->snapshot);
	view.prepare_request.set_target_epoch(transition.target_epoch());
	view.prepare_request.set_idempotency_key(transition.idempotency_key());
	view.prepare_request.set_mutation_sequence(transition.mutation_sequence());
	auto identity_or = transition_identity(transition);
	if (!identity_or.is_ok()) {
		return identity_or.error();
	}
	view.identity = identity_or.value();
	view.phase = transition.phase();
	if (transition.has_terminal_status()) {
		view.terminal_status.CopyFrom(transition.terminal_status());
	}
	view.confirm_timeout_ms = transition.confirm_timeout_ms();
	view.exact_retry = exact_retry;
	return view;
}

status_or<durable_epoch_transition_view>
config_store::begin_epoch_transition(const kinetum::control::v1::ConfigSnapshot &candidate,
				     std::string_view idempotency_key, uint32_t confirm_timeout_ms)
{
	try {
		std::unique_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::failed_precondition("live transition requires an active Bootstrap authority");
		}
		const auto key_status = kinetum::common::validate_transition_idempotency_key(idempotency_key);
		if (!key_status.is_ok()) {
			return key_status;
		}
		auto canonical_or = kinetum::common::canonicalize_config_snapshot(
			candidate, authority_->active_bootstrap().snapshot());
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		kinetum::control::v1::ConfigSnapshot terminal_candidate;
		const auto candidate_status =
			kinetum::common::admit_terminal_config_snapshot(canonical_or.value(), &terminal_candidate);
		if (!candidate_status.is_ok()) {
			return candidate_status;
		}
		if (confirm_timeout_ms > 0u &&
		    terminal_candidate.snapshot_id() == authority_->active_bootstrap().snapshot().snapshot_id()) {
			return status::failed_precondition(
				"commit-confirmed transition requires a distinct rollback target");
		}
		auto key_digest_or = kinetum::common::digest_transition_idempotency_key(idempotency_key);
		if (!key_digest_or.is_ok()) {
			return key_digest_or.error();
		}

		if (authority_->has_transition()) {
			const auto &retained = authority_->transition();
			auto retained_identity_or = transition_identity(retained);
			if (!retained_identity_or.is_ok()) {
				return retained_identity_or.error();
			}
			if (retained_identity_or->idempotency_key_digest == key_digest_or.value()) {
				const auto retained_candidate = lower_bound_(retained.snapshot_id());
				if (retained_candidate == staged_.end() ||
				    retained_candidate->snapshot.snapshot_id() != retained.snapshot_id()) {
					return status::data_loss("retained transition corpus object is missing");
				}
				auto bytes_equal_or =
					canonical_equals_snapshot(canonical_or.value(), retained_candidate->snapshot);
				if (!bytes_equal_or.is_ok()) {
					return bytes_equal_or.error();
				}
				const bool exact = retained.idempotency_key() == idempotency_key &&
						   retained.snapshot_id() == terminal_candidate.snapshot_id() &&
						   bytes_equal_or.value() &&
						   retained.validation_hash().size() ==
							   canonical_or->validation_hash.size() &&
						   std::equal(canonical_or->validation_hash.begin(),
							      canonical_or->validation_hash.end(),
							      retained.validation_hash().begin(),
							      [](uint8_t expected, char observed) {
								      return expected == static_cast<uint8_t>(observed);
							      }) &&
						   retained.confirm_timeout_ms() == confirm_timeout_ms;
				if (!exact) {
					return status::failed_precondition(
						"idempotency key is retained by a nonexact durable transition");
				}
				return transition_view_locked_(retained, true);
			}
			if (is_nonterminal_phase(retained.phase())) {
				return status::failed_precondition("another durable transition remains unresolved");
			}
		}
		if (authority_->has_rollback_intent()) {
			const auto &intent = authority_->rollback_intent();
			if (intent.has_terminal_status()) {
				return status::failed_precondition(
					"terminal rollback intent requires operator recovery before another transition");
			}
			if (intent.idempotency_key() != idempotency_key ||
			    intent.target_snapshot_id() != terminal_candidate.snapshot_id()) {
				return status::failed_precondition(
					"unresolved rollback intent admits only its exact target and retained key");
			}
			if (confirm_timeout_ms != 0u) {
				return status::failed_precondition(
					"durable rollback intent cannot arm another confirmation deadline");
			}
			if (intent.wait_for_mutation_sequence() != 0u &&
			    (!authority_->has_transition() ||
			     authority_->transition().mutation_sequence() != intent.wait_for_mutation_sequence() ||
			     authority_->transition().phase() !=
				     durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE)) {
				return status::failed_precondition(
					"rollback intent is waiting for exact predecessor completion");
			}
		}
		if (authority_->has_pending_confirm()) {
			if (!authority_->pending_confirm().confirmed()) {
				if (terminal_candidate.snapshot_id() !=
				    authority_->pending_confirm().rollback_snapshot_id()) {
					return status::failed_precondition(
						"pending-confirm state admits only its exact rollback snapshot");
				}
				if (confirm_timeout_ms != 0u) {
					return status::failed_precondition(
						"pending-confirm rollback cannot arm another confirmation deadline");
				}
			}
		}

		const auto current_or =
			kinetum::common::validate_bootstrap_config_snapshot_request(authority_->active_bootstrap());
		if (!current_or.is_ok()) {
			return current_or.error();
		}
		if (current_or->watermarks.allocated_epoch >= kinetum::common::MAX_EPOCH_ID ||
		    current_or->watermarks.mutation_sequence >= kinetum::common::MAX_MUTATION_SEQUENCE) {
			return status::resource_exhausted(
				"Control Plane transition allocation reached the reserved wrap boundary");
		}
		const uint64_t next_epoch = current_or->watermarks.allocated_epoch + 1u;
		const uint64_t next_sequence = current_or->watermarks.mutation_sequence + 1u;

		authority_message next(*authority_);
		if (next.has_pending_confirm() && next.pending_confirm().confirmed()) {
			next.clear_pending_confirm();
		}
		auto *next_active = next.mutable_active_bootstrap();
		next_active->set_allocated_epoch_high_watermark(next_epoch);
		next_active->set_mutation_sequence_high_watermark(next_sequence);
		auto bootstrap_key_or = kinetum::common::derive_bootstrap_config_snapshot_idempotency_key(
			current_or->snapshot.validation_hash, current_or->plan_content_hash, current_or->active_epoch,
			next_epoch, next_sequence);
		if (!bootstrap_key_or.is_ok()) {
			return bootstrap_key_or.error();
		}
		next_active->set_idempotency_key(std::move(bootstrap_key_or).value());
		auto *transition = next.mutable_transition();
		transition->Clear();
		transition->set_snapshot_id(terminal_candidate.snapshot_id());
		transition->set_target_epoch(next_epoch);
		transition->set_mutation_sequence(next_sequence);
		transition->set_idempotency_key(idempotency_key.data(), idempotency_key.size());
		transition->set_validation_hash(reinterpret_cast<const char *>(canonical_or->validation_hash.data()),
						canonical_or->validation_hash.size());
		transition->set_idempotency_key_digest(reinterpret_cast<const char *>(key_digest_or->data()),
						       key_digest_or->size());
		transition->set_phase(durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED);
		transition->set_confirm_timeout_ms(confirm_timeout_ms);
		if (next.has_rollback_intent()) {
			// Allocation transfers the desired action from predecessor-wait
			// ownership to this exact rollback transaction. Rebinding in the same
			// authority replacement makes joint-restart orphan handling exact.
			next.mutable_rollback_intent()->set_wait_for_mutation_sequence(next_sequence);
		}

		const auto stage_active_status = stage_snapshot_locked_(current_or->snapshot);
		if (!stage_active_status.is_ok()) {
			return stage_active_status;
		}
		const auto stage_candidate_status = stage_snapshot_locked_(canonical_or.value());
		if (!stage_candidate_status.is_ok()) {
			return stage_candidate_status;
		}
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto view_or = transition_view_locked_(next.transition(), false);
		if (!view_or.is_ok()) {
			return view_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace_status = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace_status.is_ok()) {
			return replace_status;
		}
		authority_.swap(next_owner);
		return std::move(view_or).value();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable transition allocation exhausted memory");
	}
}

status_or<durable_epoch_transition_view> config_store::epoch_transition() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_transition()) {
			return status::not_found("no durable epoch transition record exists");
		}
		return transition_view_locked_(authority_->transition(), true);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable transition copy exhausted memory");
	}
}

status_or<durable_guardrails_policy_view>
config_store::configure_guardrails_policy(const kinetum::control::v1::GuardrailsPolicy &policy,
					  std::string_view idempotency_key, uint64_t expected_generation)
{
	try {
		const auto key_status = kinetum::common::validate_transition_idempotency_key(idempotency_key);
		if (!key_status.is_ok()) {
			return key_status;
		}
		auto canonical_or = canonicalize_guardrails_policy(policy);
		if (!canonical_or.is_ok()) {
			return canonical_or.error();
		}
		auto key_digest_or = kinetum::common::digest_transition_idempotency_key(idempotency_key);
		if (!key_digest_or.is_ok()) {
			return key_digest_or.error();
		}

		std::unique_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::failed_precondition("guardrails policy requires active Control Plane authority");
		}
		if (authority_->has_guardrails_policy()) {
			const auto &retained = authority_->guardrails_policy();
			if (digest_matches(retained.idempotency_key_digest(), key_digest_or.value())) {
				if (!digest_matches(retained.policy_hash(), canonical_or->policy_hash)) {
					return status::failed_precondition(
						"guardrails idempotency key is retained by different policy content");
				}
				return guardrails_policy_view(retained, true);
			}
		}
		if (authority_->has_rollback_intent()) {
			return status::failed_precondition(
				"guardrails policy cannot change while a safety intent remains unresolved");
		}
		const uint64_t current_generation =
			authority_->has_guardrails_policy() ? authority_->guardrails_policy().generation() : 0u;
		if (expected_generation != current_generation) {
			return status::failed_precondition("guardrails policy generation compare-and-swap failed");
		}
		if (current_generation == std::numeric_limits<uint64_t>::max() - 1u) {
			return status::resource_exhausted("guardrails policy generation is exhausted");
		}

		authority_message next(*authority_);
		auto *record = next.mutable_guardrails_policy();
		record->Clear();
		record->mutable_policy()->CopyFrom(canonical_or->policy);
		record->set_generation(current_generation + 1u);
		set_digest(canonical_or->policy_hash, record->mutable_policy_hash());
		set_digest(key_digest_or.value(), record->mutable_idempotency_key_digest());
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto result_or = guardrails_policy_view(*record, false);
		if (!result_or.is_ok()) {
			return result_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace.is_ok()) {
			return replace;
		}
		authority_.swap(next_owner);
		return std::move(result_or).value();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("guardrails policy publication exhausted memory");
	}
}

status_or<durable_guardrails_policy_view> config_store::guardrails_policy() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_guardrails_policy()) {
			return status::not_found("no durable guardrails policy exists");
		}
		return guardrails_policy_view(authority_->guardrails_policy(), true);
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("guardrails policy copy exhausted memory");
	}
}

status_or<bool> config_store::epoch_transition_key_matches(std::string_view idempotency_key) const
{
	try {
		std::shared_lock lock(mutex_);
		return authority_ != nullptr && authority_->has_transition() &&
		       authority_->transition().idempotency_key() == idempotency_key;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable transition key comparison exhausted memory");
	}
}

status
config_store::advance_epoch_transition_phase(const kinetum::common::epoch_transition_identity &identity,
					     kinetum::control::internal::v1::DurableEpochTransitionPhase next_phase)
{
	try {
		std::unique_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_transition()) {
			return status::not_found("no durable epoch transition record exists");
		}
		auto retained_identity_or = transition_identity(authority_->transition());
		if (!retained_identity_or.is_ok()) {
			return retained_identity_or.error();
		}
		if (retained_identity_or.value() != identity) {
			return status::failed_precondition("phase transition identity disagrees with durable record");
		}
		if (authority_->transition().phase() == next_phase) {
			return status::ok();
		}
		if (!legal_phase_edge(authority_->transition().phase(), next_phase)) {
			return status::failed_precondition("requested durable transition phase edge is illegal");
		}
		authority_message next(*authority_);
		next.mutable_transition()->set_phase(next_phase);
		next.mutable_transition()->clear_terminal_status();
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace_status = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace_status.is_ok()) {
			return replace_status;
		}
		authority_.swap(next_owner);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("durable phase publication exhausted memory");
	}
}

status config_store::complete_epoch_transition(const kinetum::common::epoch_transition_identity &identity,
					       int64_t completed_unix_ms)
{
	try {
		std::unique_lock lock(mutex_);
		if (completed_unix_ms < 0 || authority_ == nullptr || !authority_->has_transition()) {
			return completed_unix_ms < 0 ?
				       status::invalid_argument("completion Unix time must be nonnegative") :
				       status::not_found("no durable epoch transition record exists");
		}
		const auto &retained = authority_->transition();
		auto retained_identity_or = transition_identity(retained);
		if (!retained_identity_or.is_ok()) {
			return retained_identity_or.error();
		}
		if (retained_identity_or.value() != identity) {
			return status::failed_precondition("completion identity disagrees with durable record");
		}
		if (retained.phase() == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE) {
			return status::ok();
		}
		if (retained.phase() != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING) {
			return status::failed_precondition("completion requires durable COMPLETION_PENDING state");
		}
		const auto candidate = lower_bound_(retained.snapshot_id());
		if (candidate == staged_.end() || candidate->snapshot.snapshot_id() != retained.snapshot_id()) {
			return status::data_loss("completion candidate is absent from canonical corpus");
		}
		auto candidate_or = kinetum::common::canonical_config_snapshot_from_terminal(candidate->snapshot);
		if (!candidate_or.is_ok()) {
			return candidate_or.error();
		}
		auto current_or =
			kinetum::common::validate_bootstrap_config_snapshot_request(authority_->active_bootstrap());
		if (!current_or.is_ok()) {
			return current_or.error();
		}

		authority_message next(*authority_);
		auto *next_active = next.mutable_active_bootstrap();
		const std::string rollback_snapshot_id = next_active->snapshot().snapshot_id();
		next_active->mutable_snapshot()->CopyFrom(candidate->snapshot);
		next_active->set_active_epoch(retained.target_epoch());
		auto bootstrap_key_or = kinetum::common::derive_bootstrap_config_snapshot_idempotency_key(
			candidate_or->validation_hash, current_or->plan_content_hash, retained.target_epoch(),
			next_active->allocated_epoch_high_watermark(), next_active->mutation_sequence_high_watermark());
		if (!bootstrap_key_or.is_ok()) {
			return bootstrap_key_or.error();
		}
		next_active->set_idempotency_key(std::move(bootstrap_key_or).value());
		auto *next_transition = next.mutable_transition();
		next_transition->set_phase(durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETE);
		next_transition->mutable_terminal_status()->set_code(0);
		next_transition->mutable_terminal_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);

		if (retained.confirm_timeout_ms() > 0u) {
			const int64_t confirm_timeout_ms = static_cast<int64_t>(retained.confirm_timeout_ms());
			if (completed_unix_ms > std::numeric_limits<int64_t>::max() - confirm_timeout_ms) {
				return status::resource_exhausted("pending-confirm deadline would overflow Unix time");
			}
			auto *pending = next.mutable_pending_confirm();
			pending->Clear();
			pending->set_snapshot_id(retained.snapshot_id());
			pending->set_epoch(retained.target_epoch());
			pending->set_deadline_unix_ms(completed_unix_ms + confirm_timeout_ms);
			pending->set_rollback_snapshot_id(rollback_snapshot_id);
			pending->set_created_unix_ms(completed_unix_ms);
			pending->set_original_timeout_ms(retained.confirm_timeout_ms());
			pending->set_revision(candidate->snapshot.revision());
			pending->set_confirmed(false);
			pending->clear_confirmation_key_digest();
			pending->set_confirmed_time_remaining_ms(0u);
		} else {
			next.clear_pending_confirm();
		}
		if (next.has_rollback_intent() && !next.rollback_intent().has_terminal_status() &&
		    next.rollback_intent().target_snapshot_id() == retained.snapshot_id()) {
			next.clear_rollback_intent();
		}

		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace_status = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace_status.is_ok()) {
			return replace_status;
		}
		authority_.swap(next_owner);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("transition completion publication exhausted memory");
	}
}

status config_store::abort_epoch_transition(const kinetum::common::epoch_transition_identity &identity,
					    const status &failure, durable_abort_proof proof)
{
	try {
		std::unique_lock lock(mutex_);
		if (proof != durable_abort_proof::LOCAL_PRECOMMIT_INTENT &&
		    proof != durable_abort_proof::EXACT_DP_PRECOMMIT_TERMINAL) {
			return status::invalid_argument("durable abort proof is undeclared");
		}
		if (failure.is_ok()) {
			return status::invalid_argument("ABORTED transition requires a non-OK failure");
		}
		kinetum::common::v1::Status bounded_failure;
		const auto terminal_status = set_terminal_status(failure, &bounded_failure);
		if (!terminal_status.is_ok()) {
			return terminal_status;
		}
		if (authority_ == nullptr || !authority_->has_transition()) {
			return status::not_found("no durable epoch transition record exists");
		}
		auto retained_identity_or = transition_identity(authority_->transition());
		if (!retained_identity_or.is_ok()) {
			return retained_identity_or.error();
		}
		if (retained_identity_or.value() != identity) {
			return status::failed_precondition("abort identity disagrees with durable record");
		}
		const auto phase = authority_->transition().phase();
		if (phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
			const auto &retained = authority_->transition().terminal_status();
			return retained.code() == bounded_failure.code() &&
					       retained.error_code() == bounded_failure.error_code() &&
					       retained.message() == bounded_failure.message() ?
				       status::ok() :
				       status::failed_precondition(
					       "abort retry disagrees with retained terminal outcome");
		}
		if (phase != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ALLOCATED &&
		    phase != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_PREPARED &&
		    phase != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING &&
		    phase != durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORT_PENDING) {
			return status::failed_precondition("transition is no longer abortable");
		}
		if (phase == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_COMPLETION_PENDING &&
		    proof != durable_abort_proof::EXACT_DP_PRECOMMIT_TERMINAL) {
			return status::failed_precondition(
				"completion-pending abort requires exact DP pre-commit terminal proof");
		}
		authority_message next(*authority_);
		auto *transition = next.mutable_transition();
		transition->set_phase(durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED);
		transition->mutable_terminal_status()->CopyFrom(bounded_failure);
		if (next.has_rollback_intent() && !next.rollback_intent().has_terminal_status() &&
		    next.rollback_intent().wait_for_mutation_sequence() == transition->mutation_sequence()) {
			next.mutable_rollback_intent()->mutable_terminal_status()->CopyFrom(bounded_failure);
		}
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace_status = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace_status.is_ok()) {
			return replace_status;
		}
		authority_.swap(next_owner);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("transition abort publication exhausted memory");
	}
}

status config_store::discard_orphaned_epoch_transition_after_bootstrap()
{
	try {
		std::unique_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::ok();
		}
		authority_message next(*authority_);
		bool changed = false;
		if (next.has_transition() && !is_terminal_phase(next.transition().phase())) {
			const uint64_t orphaned_sequence = next.transition().mutation_sequence();
			const std::string orphaned_key = next.transition().idempotency_key();
			const std::string orphaned_target = next.transition().snapshot_id();
			if (next.has_rollback_intent() && !next.rollback_intent().has_terminal_status()) {
				auto *intent = next.mutable_rollback_intent();
				const bool target_is_active = intent->target_snapshot_id() ==
							      next.active_bootstrap().snapshot().snapshot_id();
				const bool owns_orphan = intent->idempotency_key() == orphaned_key &&
							 intent->target_snapshot_id() == orphaned_target;
				const bool waits_for_orphan = intent->wait_for_mutation_sequence() == orphaned_sequence;
				if (target_is_active) {
					// Fresh Bootstrap already restored the desired content. The
					// intent is satisfied without inventing another epoch.
					next.clear_rollback_intent();
				} else if (owns_orphan && waits_for_orphan) {
					// The attempted rollback allocation is process-local history,
					// but the desired action and its retry key survive. A new exact
					// epoch may be allocated only after this replacement commits.
					intent->set_wait_for_mutation_sequence(0u);
				} else if (waits_for_orphan) {
					return status::data_loss(
						"orphaned predecessor did not restore the rollback target");
				}
			}
			next.clear_transition();
			changed = true;
		}
		if (next.has_rollback_intent() && !next.rollback_intent().has_terminal_status() &&
		    next.rollback_intent().target_snapshot_id() == next.active_bootstrap().snapshot().snapshot_id()) {
			next.clear_rollback_intent();
			changed = true;
		}
		if (!changed) {
			return status::ok();
		}
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace_status = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace_status.is_ok()) {
			return replace_status;
		}
		authority_.swap(next_owner);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("orphaned transition publication exhausted memory");
	}
}

status_or<snapshot_listing_page> config_store::list_snapshot_page(uint32_t page_size, std::string_view page_token) const
{
	try {
		if (page_size == 0u || page_size > kinetum::common::MAX_SNAPSHOT_LIST_PAGE_SIZE) {
			return status::invalid_argument("snapshot listing page_size is outside the bounded range");
		}
		std::optional<snapshot_page_token> decoded_token;
		if (!page_token.empty()) {
			auto decoded_or = decode_snapshot_page_token(page_token);
			if (!decoded_or.is_ok()) {
				return decoded_or.error();
			}
			decoded_token.emplace(std::move(decoded_or).value());
		}

		std::shared_lock lock(mutex_);
		const std::string active_id =
			authority_ != nullptr ? authority_->active_bootstrap().snapshot().snapshot_id() : std::string{};
		const auto active_position = lower_bound_(active_id);
		const bool active_in_corpus = authority_ != nullptr && active_position != staged_.end() &&
					      active_position->snapshot.snapshot_id() == active_id;
		const std::size_t active_index =
			static_cast<std::size_t>(std::distance(staged_.begin(), active_position));
		const bool projects_distinct_active = authority_ != nullptr && !active_in_corpus;
		if (projects_distinct_active && staged_.size() == std::numeric_limits<std::size_t>::max()) {
			return status(status_code::OUT_OF_RANGE, "snapshot listing count exceeds the wire domain");
		}
		const std::size_t logical_count = staged_.size() + (projects_distinct_active ? 1u : 0u);
		static_assert(sizeof(std::size_t) <= sizeof(uint64_t),
			      "snapshot listing count must fit the uint64 wire domain");
		auto listing_hash_or = snapshot_listing_identity_locked_();
		if (!listing_hash_or.is_ok()) {
			return listing_hash_or.error();
		}
		const std::string &listing_hash = listing_hash_or.value();
		if (decoded_token.has_value()) {
			auto cursor_or = snapshot_page_cursor_identity(listing_hash, decoded_token->last_snapshot_id);
			if (!cursor_or.is_ok()) {
				return cursor_or.error();
			}
			if (decoded_token->cursor_hash != cursor_or.value()) {
				return status::aborted("snapshot listing changed before the next page");
			}
		}

		auto logical_snapshot = [&](std::size_t index) -> const kinetum::control::v1::ConfigSnapshot & {
			if (authority_ != nullptr && !active_in_corpus && index == active_index) {
				return authority_->active_bootstrap().snapshot();
			}
			const std::size_t corpus_index =
				authority_ != nullptr && !active_in_corpus && index > active_index ? index - 1u : index;
			return staged_[corpus_index].snapshot;
		};

		std::size_t first_index = 0u;
		if (decoded_token.has_value()) {
			const auto corpus_position = lower_bound_(decoded_token->last_snapshot_id);
			if (authority_ != nullptr && !active_in_corpus &&
			    decoded_token->last_snapshot_id == active_id) {
				first_index = active_index + 1u;
			} else if (corpus_position != staged_.end() &&
				   corpus_position->snapshot.snapshot_id() == decoded_token->last_snapshot_id) {
				const std::size_t corpus_index =
					static_cast<std::size_t>(std::distance(staged_.begin(), corpus_position));
				first_index = corpus_index + (authority_ != nullptr && !active_in_corpus &&
									      corpus_index >= active_index ?
								      2u :
								      1u);
			} else {
				return status::aborted("snapshot listing continuation no longer names a corpus row");
			}
		}
		if (first_index > logical_count) {
			return status::aborted("snapshot listing continuation exceeds the current corpus");
		}

		snapshot_listing_page result;
		result.total_count = static_cast<uint64_t>(logical_count);
		const std::size_t remaining = logical_count - first_index;
		const std::size_t count = std::min<std::size_t>(remaining, page_size);
		result.snapshots.reserve(count);
		for (std::size_t index = first_index; index < first_index + count; ++index) {
			const auto &snapshot = logical_snapshot(index);
			result.snapshots.push_back(
				snapshot_info(snapshot, authority_ != nullptr && snapshot.snapshot_id() == active_id));
		}
		if (first_index + count < logical_count) {
			auto token_or = encode_snapshot_page_token(listing_hash, result.snapshots.back().snapshot_id());
			if (!token_or.is_ok()) {
				return token_or.error();
			}
			result.next_page_token = std::move(token_or).value();
			if (result.next_page_token.size() > kinetum::common::MAX_SNAPSHOT_LIST_PAGE_TOKEN_BYTES) {
				return status(status_code::OUT_OF_RANGE,
					      "snapshot listing page token exceeds its bound");
			}
		}
		return result;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("snapshot listing exhausted memory");
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE, "snapshot listing exceeded host size limits");
	}
}

status_or<kinetum::control::v1::ConfigSnapshot> config_store::load_snapshot(std::string_view snapshot_id) const
{
	const auto id_status = validate_snapshot_id(snapshot_id);
	if (!id_status.is_ok()) {
		return id_status;
	}
	try {
		std::shared_lock lock(mutex_);
		if (authority_ != nullptr && authority_->active_bootstrap().snapshot().snapshot_id() == snapshot_id) {
			return authority_->active_bootstrap().snapshot();
		}
		const auto position = lower_bound_(snapshot_id);
		if (position == staged_.end() || position->snapshot.snapshot_id() != snapshot_id) {
			return status::not_found("snapshot does not exist in active or canonical corpus state");
		}
		return position->snapshot;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("snapshot copy exhausted memory");
	}
}

status_or<kinetum::control::v1::ConfigSnapshot> config_store::active_snapshot() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::not_found("no active snapshot authority exists");
		}
		return authority_->active_bootstrap().snapshot();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("active snapshot copy exhausted memory");
	}
}

status_or<std::string> config_store::active_snapshot_id() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::not_found("no active Bootstrap authority exists");
		}
		return authority_->active_bootstrap().snapshot().snapshot_id();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("active snapshot identity copy exhausted memory");
	}
}

status_or<durable_confirmation_result> config_store::confirm_pending_config(std::string_view snapshot_id,
									    uint64_t epoch, int64_t revision,
									    std::string_view idempotency_key,
									    int64_t now_unix_ms)
{
	try {
		const auto key_status = kinetum::common::validate_transition_idempotency_key(idempotency_key);
		if (!key_status.is_ok()) {
			return key_status;
		}
		auto key_digest_or = kinetum::common::digest_transition_idempotency_key(idempotency_key);
		if (!key_digest_or.is_ok()) {
			return key_digest_or.error();
		}
		std::unique_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_pending_confirm()) {
			return status::failed_precondition("no pending confirmation exists");
		}
		const auto &pending = authority_->pending_confirm();
		if (pending.snapshot_id() != snapshot_id || pending.epoch() != epoch ||
		    pending.revision() != revision) {
			return status::failed_precondition(
				"confirmation identity disagrees with the durable pending record");
		}
		if (pending.confirmed()) {
			if (!digest_matches(pending.confirmation_key_digest(), key_digest_or.value())) {
				return status::failed_precondition(
					"confirmation retry key disagrees with retained terminal success");
			}
			return durable_confirmation_result{
				.snapshot_id = pending.snapshot_id(),
				.epoch = pending.epoch(),
				.revision = pending.revision(),
				.time_remaining_ms = pending.confirmed_time_remaining_ms(),
				.exact_retry = true,
			};
		}
		if (authority_->has_rollback_intent()) {
			return authority_->rollback_intent().cause() ==
					       kinetum::control::internal::v1::
						       DURABLE_ROLLBACK_CAUSE_COMMIT_CONFIRM_DEADLINE ?
				       status::deadline_exceeded(
					       "confirmation deadline already owns a durable rollback intent") :
				       status::failed_precondition(
					       "configuration already owns a durable safety rollback intent");
		}
		if (now_unix_ms < 0 || now_unix_ms >= pending.deadline_unix_ms()) {
			return status::deadline_exceeded("confirmation deadline has expired");
		}
		const uint64_t remaining = static_cast<uint64_t>(pending.deadline_unix_ms() - now_unix_ms);
		if (remaining == 0u) {
			return status::deadline_exceeded("confirmation deadline has expired");
		}
		if (remaining > pending.original_timeout_ms()) {
			return status::failed_precondition(
				"confirmation clock precedes the durable confirmation interval");
		}

		authority_message next(*authority_);
		auto *confirmed = next.mutable_pending_confirm();
		confirmed->set_confirmed(true);
		set_digest(key_digest_or.value(), confirmed->mutable_confirmation_key_digest());
		confirmed->set_confirmed_time_remaining_ms(remaining);
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace.is_ok()) {
			return replace;
		}
		authority_.swap(next_owner);
		return durable_confirmation_result{
			.snapshot_id = confirmed->snapshot_id(),
			.epoch = confirmed->epoch(),
			.revision = confirmed->revision(),
			.time_remaining_ms = remaining,
			.exact_retry = false,
		};
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("confirmation publication exhausted memory");
	}
}

status_or<kinetum::control::v1::PendingConfirm> config_store::load_pending_confirm() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_pending_confirm()) {
			return status::not_found("no pending-confirm record exists");
		}
		return authority_->pending_confirm();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("pending-confirm copy exhausted memory");
	}
}

status_or<durable_rollback_intent_view> config_store::accept_rollback_intent(const rollback_intent_request &request)
{
	try {
		if (!kinetum::common::valid_config_snapshot_id(request.target_snapshot_id) ||
		    !kinetum::common::valid_config_snapshot_id(request.guarded_snapshot_id) ||
		    request.target_snapshot_id == request.guarded_snapshot_id ||
		    !kinetum::common::valid_epoch_id(request.guarded_epoch) ||
		    !kinetum::common::valid_config_snapshot_revision(request.guarded_revision) ||
		    (request.wait_for_mutation_sequence != 0u &&
		     !kinetum::common::valid_mutation_sequence(request.wait_for_mutation_sequence)) ||
		    request.runtime_generation == 0u || request.runtime_generation > UINT32_MAX ||
		    request.observed_monotonic_ns == 0u || request.created_unix_ms < 0 ||
		    !valid_rollback_cause(request.cause)) {
			return status::invalid_argument("rollback intent request identity is malformed");
		}
		const auto key_status = kinetum::common::validate_transition_idempotency_key(request.idempotency_key);
		if (!key_status.is_ok()) {
			return key_status;
		}
		auto key_digest_or = kinetum::common::digest_transition_idempotency_key(request.idempotency_key);
		if (!key_digest_or.is_ok()) {
			return key_digest_or.error();
		}
		std::unique_lock lock(mutex_);
		if (authority_ == nullptr) {
			return status::failed_precondition("rollback intent requires active Control Plane authority");
		}
		const auto target = lower_bound_(request.target_snapshot_id);
		if (target == staged_.end() || target->snapshot.snapshot_id() != request.target_snapshot_id) {
			return status::not_found("rollback intent target is absent from the canonical corpus");
		}
		if (authority_->has_rollback_intent()) {
			auto retained_or = rollback_intent_view(authority_->rollback_intent());
			if (!retained_or.is_ok()) {
				return retained_or.error();
			}
			const auto &retained = retained_or->request;
			const bool exact = retained.target_snapshot_id == request.target_snapshot_id &&
					   retained.guarded_snapshot_id == request.guarded_snapshot_id &&
					   retained.guarded_epoch == request.guarded_epoch &&
					   retained.guarded_revision == request.guarded_revision &&
					   retained.guarded_validation_hash == request.guarded_validation_hash &&
					   retained.wait_for_mutation_sequence == request.wait_for_mutation_sequence &&
					   retained.policy_generation == request.policy_generation &&
					   retained.runtime_generation == request.runtime_generation &&
					   retained.idempotency_key == request.idempotency_key &&
					   retained.cause == request.cause &&
					   retained.observed_monotonic_ns == request.observed_monotonic_ns &&
					   retained.created_unix_ms == request.created_unix_ms;
			if (!exact) {
				return status::failed_precondition(
					"another durable rollback intent is already retained");
			}
			return std::move(retained_or).value();
		}
		if (request.wait_for_mutation_sequence == 0u &&
		    authority_->active_bootstrap().snapshot().snapshot_id() == request.target_snapshot_id) {
			return status::failed_precondition("rollback target is already the durable active content");
		}
		if (authority_->has_transition() && is_nonterminal_phase(authority_->transition().phase()) &&
		    request.wait_for_mutation_sequence != authority_->transition().mutation_sequence()) {
			return status::failed_precondition(
				"rollback intent must bind the exact in-progress mutation sequence");
		}
		if (request.wait_for_mutation_sequence != 0u && authority_->has_transition() &&
		    request.wait_for_mutation_sequence == authority_->transition().mutation_sequence() &&
		    authority_->transition().phase() == durable_phase::DURABLE_EPOCH_TRANSITION_PHASE_ABORTED) {
			return status::failed_precondition(
				"rollback intent predecessor aborted before durable intent acceptance");
		}
		const bool confirmation_cause = request.cause == rollback_intent_cause::COMMIT_CONFIRM_DEADLINE;
		if (confirmation_cause != (request.policy_generation == 0u)) {
			return status::invalid_argument(
				"rollback intent cause and policy generation do not form one contract");
		}
		if (confirmation_cause &&
		    (!authority_->has_pending_confirm() || authority_->pending_confirm().confirmed() ||
		     authority_->pending_confirm().snapshot_id() != request.guarded_snapshot_id ||
		     authority_->pending_confirm().epoch() != request.guarded_epoch ||
		     authority_->pending_confirm().revision() != request.guarded_revision ||
		     authority_->pending_confirm().rollback_snapshot_id() != request.target_snapshot_id ||
		     request.created_unix_ms < authority_->pending_confirm().deadline_unix_ms())) {
			return status::failed_precondition(
				"commit-confirm rollback intent is stale or precedes its durable deadline");
		}
		if (!confirmation_cause && (!authority_->has_guardrails_policy() ||
					    authority_->guardrails_policy().generation() != request.policy_generation ||
					    !authority_->guardrails_policy().policy().enabled())) {
			return status::failed_precondition("rollback intent policy generation is no longer active");
		}
		bool guarded_exact = false;
		if (authority_->active_bootstrap().snapshot().snapshot_id() == request.guarded_snapshot_id &&
		    authority_->active_bootstrap().active_epoch() == request.guarded_epoch &&
		    authority_->active_bootstrap().snapshot().revision() == request.guarded_revision) {
			auto active_content_or = kinetum::common::canonical_config_snapshot_from_terminal(
				authority_->active_bootstrap().snapshot());
			guarded_exact = active_content_or.is_ok() &&
					active_content_or->validation_hash == request.guarded_validation_hash;
		}
		if (!guarded_exact && authority_->has_transition() &&
		    authority_->transition().snapshot_id() == request.guarded_snapshot_id &&
		    authority_->transition().target_epoch() == request.guarded_epoch) {
			const auto guarded = lower_bound_(request.guarded_snapshot_id);
			guarded_exact = guarded != staged_.end() &&
					guarded->snapshot.snapshot_id() == request.guarded_snapshot_id &&
					guarded->snapshot.revision() == request.guarded_revision &&
					guarded->validation_hash == request.guarded_validation_hash;
		}
		if (!guarded_exact) {
			return status::failed_precondition(
				"rollback intent guarded content changed before durable acceptance");
		}

		authority_message next(*authority_);
		auto *intent = next.mutable_rollback_intent();
		intent->set_target_snapshot_id(request.target_snapshot_id);
		intent->set_guarded_snapshot_id(request.guarded_snapshot_id);
		intent->set_guarded_epoch(request.guarded_epoch);
		intent->set_guarded_revision(request.guarded_revision);
		set_digest(request.guarded_validation_hash, intent->mutable_guarded_validation_hash());
		intent->set_wait_for_mutation_sequence(request.wait_for_mutation_sequence);
		intent->set_policy_generation(request.policy_generation);
		intent->set_runtime_generation(request.runtime_generation);
		intent->set_idempotency_key(request.idempotency_key);
		set_digest(key_digest_or.value(), intent->mutable_idempotency_key_digest());
		intent->set_cause(rollback_cause_to_wire(request.cause));
		intent->set_observed_monotonic_ns(request.observed_monotonic_ns);
		intent->set_created_unix_ms(request.created_unix_ms);
		intent->clear_terminal_status();
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto result_or = rollback_intent_view(*intent);
		if (!result_or.is_ok()) {
			return result_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace.is_ok()) {
			return replace;
		}
		authority_.swap(next_owner);
		return std::move(result_or).value();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("rollback intent publication exhausted memory");
	}
}

status_or<durable_rollback_intent_view> config_store::rollback_intent() const
{
	try {
		std::shared_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_rollback_intent()) {
			return status::not_found("no durable rollback intent exists");
		}
		return rollback_intent_view(authority_->rollback_intent());
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("rollback intent copy exhausted memory");
	}
}

status config_store::fail_rollback_intent(std::string_view idempotency_key, const status &failure)
{
	try {
		const auto key_status = kinetum::common::validate_transition_idempotency_key(idempotency_key);
		if (!key_status.is_ok()) {
			return key_status;
		}
		if (failure.is_ok()) {
			return status::invalid_argument("rollback intent failure must be non-OK");
		}
		kinetum::common::v1::Status bounded;
		const auto bounded_status = set_terminal_status(failure, &bounded);
		if (!bounded_status.is_ok()) {
			return bounded_status;
		}
		std::unique_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_rollback_intent()) {
			return status::not_found("no durable rollback intent exists");
		}
		const auto &retained = authority_->rollback_intent();
		if (retained.idempotency_key() != idempotency_key) {
			return status::failed_precondition("rollback intent failure key disagrees with durable intent");
		}
		if (retained.has_terminal_status()) {
			return retained.terminal_status().code() == bounded.code() &&
					       retained.terminal_status().error_code() == bounded.error_code() &&
					       retained.terminal_status().message() == bounded.message() ?
				       status::ok() :
				       status::failed_precondition(
					       "rollback intent retry disagrees with retained terminal failure");
		}
		authority_message next(*authority_);
		next.mutable_rollback_intent()->mutable_terminal_status()->CopyFrom(bounded);
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace.is_ok()) {
			return replace;
		}
		authority_.swap(next_owner);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("rollback intent failure publication exhausted memory");
	}
}

status config_store::clear_completed_rollback_intent(std::string_view idempotency_key, uint64_t completed_epoch)
{
	try {
		const auto key_status = kinetum::common::validate_transition_idempotency_key(idempotency_key);
		if (!key_status.is_ok()) {
			return key_status;
		}
		if (!kinetum::common::valid_epoch_id(completed_epoch)) {
			return status::invalid_argument("completed rollback epoch is invalid");
		}
		std::unique_lock lock(mutex_);
		if (authority_ == nullptr || !authority_->has_rollback_intent()) {
			return status::ok();
		}
		const auto &intent = authority_->rollback_intent();
		if (intent.has_terminal_status() || intent.idempotency_key() != idempotency_key ||
		    authority_->active_bootstrap().active_epoch() != completed_epoch ||
		    authority_->active_bootstrap().snapshot().snapshot_id() != intent.target_snapshot_id()) {
			return status::failed_precondition(
				"rollback intent cannot clear before exact target completion");
		}
		authority_message next(*authority_);
		next.clear_rollback_intent();
		auto serialized_or = validate_authority_(next);
		if (!serialized_or.is_ok()) {
			return serialized_or.error();
		}
		auto next_owner = std::make_unique<authority_message>(next);
		const auto replace = directory_.replace_file(TRANSITION_AUTHORITY_LEAF, serialized_or.value());
		if (!replace.is_ok()) {
			return replace;
		}
		authority_.swap(next_owner);
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted("completed rollback intent removal exhausted memory");
	}
}

}  // namespace kinetum::cp
