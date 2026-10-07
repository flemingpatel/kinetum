// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file epoch_transition_certificate.hpp
 * @brief Exact global transition and reader-grace certificate aggregation.
 * @author Fleming Patel
 *
 * One immutable certificate source graph borrows the frozen participant set,
 * coherent owner publications, exact boundary channels, and one backend-neutral
 * quiescence domain. Evaluation is observation-only: it neither advances a
 * coordinator phase, starts or finishes grace, retires ownership, nor latches
 * nearby progress.
 *
 * @par Thread Safety
 * Construction is cold and externally serialized before worker launch. After
 * publication the object is immutable; the sole coordinator may call evaluate()
 * while exact worker owners publish their independent coherent snapshots.
 *
 * @par Performance
 * Construction allocates fixed compact pointer arrays. Evaluation is bounded
 * O(execution_participants + boundaries + readers), allocation-free, lock-free,
 * clock-free, string-free work on the cold coordinator path.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/quiescence.hpp>

#include "src/common/status_or.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/frozen_transition_participants.hpp"
#include "src/dp/epoch/worker_epoch_activation.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/publication_read_result.hpp"

namespace kinetum::dp
{

class worker_boundary_receiver;
class worker_boundary_sender;

/** @brief Exact immutable identity evaluated by one certificate pass. */
struct epoch_transition_certificate_request {
	uint64_t runtime_generation{0};	    ///< Exact materialized runtime generation.
	uint64_t transition_generation{0};  ///< Exact mutation generation bound to workers.
	uint64_t from_epoch{0};		    ///< Exact old active epoch.
	uint64_t to_epoch{0};		    ///< Exact prepared target epoch.
	uint64_t grace_generation{0};	    ///< Exact active/completed reader grace.

	/** @return true when every numeric identity belongs to its exact domain. */
	[[nodiscard]] bool valid() const noexcept;
};

static_assert(sizeof(epoch_transition_certificate_request) == 40u,
	      "certificate request must remain a fixed five-word record");
static_assert(std::is_standard_layout_v<epoch_transition_certificate_request> &&
		      std::is_trivially_copyable_v<epoch_transition_certificate_request>,
	      "certificate request must retain value semantics");

/** @brief Classification of one coherent certificate contribution. */
enum class epoch_transition_certificate_record_result : uint8_t {
	INCOMPLETE = 0,	 ///< Missing, older, or not-yet-published exact progress.
	COMPLETE,	 ///< Exact contribution satisfies the requested generation.
	CONTRADICTION,	 ///< Coherent future, owner, epoch, or cut disagreement.
};

/** @brief Complete global certificate evaluation state. */
enum class epoch_transition_certificate_state : uint8_t {
	INCOMPLETE = 0,	     ///< Execution/boundary leg is not complete.
	EXECUTION_COMPLETE,  ///< RETIRING may begin; reader grace remains incomplete.
	RECLAMATION_READY,   ///< Execution/boundary and reader-grace legs are complete.
	CONTRADICTION,	     ///< One coherent exactness violation requires fail-stop.
};

/** @brief Typed source of the first coherent certificate contradiction. */
enum class epoch_transition_certificate_fault : uint8_t {
	NONE = 0,	       ///< No contradiction was observed.
	REQUEST_IDENTITY,      ///< Caller request or grace identity is malformed.
	EXECUTION_MEMBERSHIP,  ///< Worker/publication ownership is inconsistent.
	EXECUTION_STATE,       ///< Activation or ledger truth contradicts the request.
	BOUNDARY_MEMBERSHIP,   ///< Boundary endpoint/publication ownership is inconsistent.
	BOUNDARY_STATE,	       ///< Boundary publication cannot represent exact completion.
	CUT_IDENTITY,	       ///< Sender and receiver retained different exact cuts.
	READER_MEMBERSHIP,     ///< Grace generation or reader membership is unrelated.
};

/** @brief Typed classification and contradiction source for one contribution. */
struct epoch_transition_certificate_record_observation {
	epoch_transition_certificate_record_result result{
		epoch_transition_certificate_record_result::INCOMPLETE};  ///< Exact contribution state.
	epoch_transition_certificate_fault fault{
		epoch_transition_certificate_fault::NONE};  ///< Non-NONE only for CONTRADICTION.
};

static_assert(sizeof(epoch_transition_certificate_record_observation) == 2u,
	      "certificate record observation must remain a two-byte value");
static_assert(std::is_standard_layout_v<epoch_transition_certificate_record_observation> &&
		      std::is_trivially_copyable_v<epoch_transition_certificate_record_observation>,
	      "certificate record observation must retain value semantics");

/**
 * @brief Fixed observer-owned global certificate progress.
 *
 * Counts are current exact observations, not latched maxima. `fault_index`
 * addresses the compact worker, boundary, or reader namespace selected by
 * `fault`; UINT32_MAX means no indexed contradiction.
 */
struct alignas(kinetum::algo::CACHE_LINE_SIZE) epoch_transition_certificate_progress {
	uint64_t runtime_generation{0};	    ///< Exact evaluated runtime generation.
	uint64_t transition_generation{0};  ///< Exact evaluated mutation generation.
	uint64_t from_epoch{0};		    ///< Exact evaluated old epoch.
	uint64_t to_epoch{0};		    ///< Exact evaluated target epoch.
	uint32_t execution_complete{0};	    ///< Exact complete execution participants.
	uint32_t execution_total{0};	    ///< Frozen execution-participant population.
	uint32_t boundary_complete{0};	    ///< Exact complete boundary participants.
	uint32_t boundary_total{0};	    ///< Frozen boundary population.
	uint32_t reader_complete{0};	    ///< Exact readers in the requested grace.
	uint32_t reader_total{0};	    ///< Frozen reader population.
	uint32_t fault_index{UINT32_MAX};   ///< Compact identity selected by fault.
	epoch_transition_certificate_state state{epoch_transition_certificate_state::INCOMPLETE};  ///< Result.
	epoch_transition_certificate_fault fault{epoch_transition_certificate_fault::NONE};	   ///< Fault.
	std::array<uint8_t, 2> padding{};  ///< Explicit cache-line completion.
};

static_assert(sizeof(epoch_transition_certificate_progress) == kinetum::algo::CACHE_LINE_SIZE,
	      "certificate progress must occupy exactly one cache line");
static_assert(alignof(epoch_transition_certificate_progress) == kinetum::algo::CACHE_LINE_SIZE,
	      "certificate progress must retain cache-line alignment");
static_assert(std::is_standard_layout_v<epoch_transition_certificate_progress> &&
		      std::is_trivially_copyable_v<epoch_transition_certificate_progress>,
	      "certificate progress must retain value semantics");

/** @brief Immutable coherent source set for one exact execution participant. */
struct epoch_transition_certificate_worker_source {
	const worker_epoch_ledger *ledger{nullptr};		  ///< Sole worker credit publication.
	const worker_epoch_activation *activation{nullptr};	  ///< Sole local activation publication.
	const worker_boundary_sender *sender{nullptr};		  ///< Complete outbound policy owner.
	const worker_boundary_receiver *receiver{nullptr};	  ///< Complete inbound policy owner.
	const kinetum::algo::quiescence_reader *reader{nullptr};  ///< Exact frozen config reader.
};

/** @brief Coherent raw worker observations read through the sole certificate graph. */
struct epoch_transition_certificate_worker_observation {
	worker_epoch_ledger_snapshot ledger{};		///< Exact worker ownership snapshot.
	worker_epoch_activation_snapshot activation{};	///< Exact activation snapshot.
};

/** @brief Coherent raw boundary observations read through the sole certificate graph. */
struct epoch_transition_certificate_boundary_observation {
	boundary_sender_transition_snapshot sender{};		    ///< Sender policy progress.
	boundary_receiver_transition_snapshot receiver{};	    ///< Receiver policy progress.
	boundary_sender_transport_snapshot sender_transport{};	    ///< Sender DATA/control transport.
	boundary_receiver_transport_snapshot receiver_transport{};  ///< Receiver DATA/control transport.
};

/** @brief Independent worker reads retained for one cold observation attempt. */
struct epoch_transition_certificate_worker_read {
	epoch_transition_certificate_worker_observation value{};  ///< Only AVAILABLE members may be consumed.
	publication_read_result ledger{publication_read_result::UNAVAILABLE};	   ///< Ledger read and validation.
	publication_read_result activation{publication_read_result::UNAVAILABLE};  ///< Activation read and validation.

	/** @return Complete availability or the strongest independent failure. */
	[[nodiscard]] publication_read_result result() const noexcept
	{
		return combine_publication_reads(ledger, activation);
	}
};

/** @brief Independent boundary reads retained without discarding available evidence. */
struct epoch_transition_certificate_boundary_read {
	epoch_transition_certificate_boundary_observation value{};  ///< Only AVAILABLE members may be consumed.
	publication_read_result sender{publication_read_result::UNAVAILABLE};		   ///< Sender policy read.
	publication_read_result receiver{publication_read_result::UNAVAILABLE};		   ///< Receiver policy read.
	publication_read_result sender_transport{publication_read_result::UNAVAILABLE};	   ///< Sender transport read.
	publication_read_result receiver_transport{publication_read_result::UNAVAILABLE};  ///< Receiver transport read.

	/** @return Complete availability or the strongest independent failure. */
	[[nodiscard]] publication_read_result result() const noexcept
	{
		return combine_publication_reads(combine_publication_reads(sender, receiver),
						 combine_publication_reads(sender_transport, receiver_transport));
	}
};

/**
 * @brief Classify one worker's coherent activation and ledger observations.
 *
 * @param request Exact certificate identity.
 * @param expected_worker Exact frozen compact worker index.
 * @param observed Independent read outcomes and every available worker publication.
 * @return Incomplete, complete, or coherent contradiction.
 */
[[nodiscard]] epoch_transition_certificate_record_observation
classify_execution_certificate(const epoch_transition_certificate_request &request, uint32_t expected_worker,
			       const epoch_transition_certificate_worker_read &observed) noexcept;

/**
 * @brief Classify one boundary's exact policy and transport observations.
 *
 * @param request Exact certificate identity.
 * @param expected_boundary Exact frozen compact boundary index.
 * @param observed Independent read outcomes and every available endpoint publication.
 * @return Incomplete, complete, or coherent contradiction.
 */
[[nodiscard]] epoch_transition_certificate_record_observation
classify_boundary_certificate(const epoch_transition_certificate_request &request, uint32_t expected_boundary,
			      const epoch_transition_certificate_boundary_read &observed) noexcept;

/** @brief Immutable O(V+E) global certificate observation owner. */
class epoch_transition_certificate final {
    public:
	/**
	 * @brief Construct and audit one exact frozen certificate source graph.
	 *
	 * @param runtime_generation Exact materialized runtime generation.
	 * @param participants Sole immutable participant membership authority.
	 * @param workers Complete compact worker publication sources.
	 * @param boundaries Complete compact boundary transport owners.
	 * @param domain Exact reader domain bound in frozen-worker order.
	 * @return Immutable certificate owner or a fail-closed membership status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<epoch_transition_certificate>>
	create(uint64_t runtime_generation, const frozen_transition_participants &participants,
	       std::span<const epoch_transition_certificate_worker_source> workers,
	       std::span<boundary_epoch_channel *const> boundaries, const kinetum::algo::quiescence_domain &domain);

	/** @brief Certificate source graphs cannot be copied. */
	epoch_transition_certificate(const epoch_transition_certificate &) = delete;
	/** @brief Certificate source graphs cannot be copy-assigned. */
	epoch_transition_certificate &operator=(const epoch_transition_certificate &) = delete;
	/** @brief Borrowed source addresses prevent movement. */
	epoch_transition_certificate(epoch_transition_certificate &&) = delete;
	/** @brief Borrowed source addresses prevent move assignment. */
	epoch_transition_certificate &operator=(epoch_transition_certificate &&) = delete;
	/** @brief Destroy only immutable pointer arrays; all source owners remain external. */
	~epoch_transition_certificate() = default;

	/**
	 * @brief Evaluate every frozen source without latching or mutating progress.
	 *
	 * Missing, torn, or older publications remain incomplete. Every coherent
	 * exactness disagreement is reported as a typed contradiction. Reader grace
	 * is observed but never started or finished by this method.
	 *
	 * @param request Exact transition and grace identity to evaluate.
	 * @return Complete current progress over the immutable source graph.
	 */
	[[nodiscard]] epoch_transition_certificate_progress
	evaluate(const epoch_transition_certificate_request &request) const noexcept;

	/**
	 * @brief Read one worker through the graph's pre-resolved exact sources.
	 * @param worker_index Exact compact worker identity.
	 * @return Independent results and every available value from this attempt.
	 */
	[[nodiscard]] epoch_transition_certificate_worker_read observe_worker(uint32_t worker_index) const noexcept;

	/**
	 * @brief Read one boundary through the graph's pre-resolved exact sources.
	 * @param boundary_index Exact compact boundary identity.
	 * @return Independent results and every available value from this attempt.
	 */
	[[nodiscard]] epoch_transition_certificate_boundary_read
	observe_boundary(uint32_t boundary_index) const noexcept;

	/** @return Exact immutable execution-participant count. */
	[[nodiscard]] std::size_t execution_participant_count() const noexcept;
	/** @return Exact immutable boundary-participant count. */
	[[nodiscard]] std::size_t boundary_count() const noexcept;
	/** @return Exact immutable reader count. */
	[[nodiscard]] std::size_t reader_count() const noexcept;
	/** @return Exact materialized runtime-generation identity. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;
	/**
	 * @param participants Candidate frozen participant authority.
	 * @return true only for the exact authority borrowed at creation.
	 */
	[[nodiscard]] bool owns_participants(const frozen_transition_participants &participants) const noexcept;
	/**
	 * @param domain Candidate reader-grace domain.
	 * @return true only for the exact domain borrowed at creation.
	 */
	[[nodiscard]] bool owns_domain(const kinetum::algo::quiescence_domain &domain) const noexcept;

    private:
	/** @brief Pre-resolved exact boundary endpoint source ordinals. */
	struct boundary_source {
		uint32_t sender_worker{UINT32_MAX};		 ///< Exact sender worker.
		uint32_t sender_ordinal{UINT32_MAX};		 ///< Sender-local outbound ordinal.
		uint32_t receiver_worker{UINT32_MAX};		 ///< Exact receiver worker.
		uint32_t receiver_ordinal{UINT32_MAX};		 ///< Receiver-local inbound ordinal.
		const boundary_epoch_channel *channel{nullptr};	 ///< Sole boundary transport observation source.
	};

	/**
	 * @brief Adopt one fully audited immutable source graph.
	 *
	 * @param runtime_generation Exact materialized runtime generation.
	 * @param participants Sole frozen membership authority.
	 * @param workers Complete compact worker publication sources.
	 * @param boundaries Complete compact boundary source map.
	 * @param domain Exact reader grace authority.
	 */
	epoch_transition_certificate(uint64_t runtime_generation, const frozen_transition_participants &participants,
				     std::vector<epoch_transition_certificate_worker_source> workers,
				     std::vector<boundary_source> boundaries,
				     const kinetum::algo::quiescence_domain &domain) noexcept;

	uint64_t runtime_generation_{0};				   ///< Exact materialized generation.
	const frozen_transition_participants *participants_{nullptr};	   ///< Immutable membership authority.
	std::vector<epoch_transition_certificate_worker_source> workers_;  ///< Compact worker sources.
	std::vector<boundary_source> boundaries_;			   ///< Compact boundary source map.
	const kinetum::algo::quiescence_domain *domain_{nullptr};	   ///< Exact reader grace authority.
};

}  // namespace kinetum::dp
