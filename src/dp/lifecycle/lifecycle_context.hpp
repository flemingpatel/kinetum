// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file lifecycle_context.hpp
 * @brief Backend-neutral ownership for cold module-lifecycle execution.
 * @author Fleming Patel
 *
 * A lifecycle context exposes immutable module/context placement, bounded
 * long-lived allocation, one exact epoch arena during PREPARE, bounded
 * telemetry-handle registration, logging, and deadline/cancellation queries.
 * It intentionally carries no live kinetum_ctx and cannot execute packet work.
 *
 * The owner permits one active lifecycle operation at a time. The borrowed
 * context is valid only for that operation and never outlives the owner. INIT,
 * PREPARE, RETIRE, and FINI are represented; packet-worker ACTIVATE is
 * deliberately absent from this cold-path interface.
 *
 * @par Thread Safety
 * Operation admission is thread-safe and fail-closed. Exactly one successful
 * cold operation may use an owner at a time. Accessors on a borrowed context
 * are single-operation-thread only. Cancellation publication is the sole
 * cross-thread mutation exposed during a callback. After worker binding,
 * telemetry handles, cadence, activation, mismatch, return acceptance, and
 * shutdown are written only by that context's owner worker. The serialized
 * generation owner may assign or discard the one explicit free target slot
 * before publishing a worker trigger; it never scans worker-mutated banks. The
 * cold aggregator may access a bank only after exact SPSC transfer and
 * relinquishes it through the matching return/retirement protocol.
 *
 * @par Performance
 * Counter and histogram handles update exact-NUMA plain storage directly.
 * Owner cadence and activation perform bounded bank swaps and token publication
 * without allocation, locking, logging, formatting, clock reads, virtual
 * dispatch, or shared atomic RMW. Cold lifecycle operations retain their
 * existing allocator/log/deadline contract.
 */

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/single_writer_snapshot.hpp>
#include <kinetum/kinetum_sdk.h>
#include "src/common/module_health_contract.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/runtime_telemetry_bank.hpp"

namespace kinetum::dp
{
class epoch_transition_completion;
class epoch_transition_preparation;
class worker_telemetry_channel;
}  // namespace kinetum::dp

namespace kinetum::dp::lifecycle
{

/** @brief Maximum long-lived allocation records owned by one module context. */
inline constexpr std::size_t LIFECYCLE_MAX_LONG_LIVED_ALLOCATIONS = 64;

/** @brief Maximum telemetry handles registered by one module context. */
inline constexpr std::size_t LIFECYCLE_MAX_TELEMETRY_HANDLES =
	static_cast<std::size_t>(KINETUM_MAX_COUNTERS) + static_cast<std::size_t>(KINETUM_MAX_HISTOGRAMS);

/** @brief Exact active/standby/activation-reserve telemetry-bank population. */
inline constexpr std::size_t LIFECYCLE_TELEMETRY_BANK_COUNT = RUNTIME_TELEMETRY_BANK_COUNT;

/** @brief Registry slab plus one exact three-bank bucket block per histogram. */
inline constexpr std::size_t LIFECYCLE_MAX_INTERNAL_TELEMETRY_ALLOCATIONS = 1u + KINETUM_MAX_HISTOGRAMS;

/** @brief Maximum histogram buckets merged and cleared in one cold service unit. */
inline constexpr std::size_t LIFECYCLE_TELEMETRY_BUCKET_PREFIX = 64u;

/** @brief Maximum telemetry name length including the terminating NUL byte. */
inline constexpr std::size_t LIFECYCLE_TELEMETRY_NAME_CAPACITY = 64;

/**
 * @brief Cold lifecycle phase represented by a borrowed lifecycle context.
 *
 * ACTIVATE is intentionally absent: activation is a bounded owner-worker
 * operation and must never be dispatched to a lifecycle executor.
 */
enum class lifecycle_phase : uint8_t {
	INIT = 0,
	PREPARE,
	RETIRE,
	FINI,
};

/** @brief Severity accepted by the backend-neutral lifecycle log provider. */
enum class lifecycle_log_level : uint8_t {
	DEBUG = 0,
	INFO,
	WARNING,
	ERROR,
};

/** @brief Kind of one bounded module telemetry registration. */
enum class lifecycle_telemetry_kind : uint8_t {
	COUNTER = 0,
	HISTOGRAM,
};

/** @brief Stable one-based telemetry descriptor index; zero is invalid. */
using lifecycle_telemetry_handle = uint16_t;

/**
 * @brief Immutable identity and placement of one module context.
 *
 * String identities are retained only in the long-lived cold owner. Bounded
 * lifecycle task/result channels carry compact indices instead.
 */
struct lifecycle_context_identity {
	std::string module_id;		     ///< Loaded module-image identity.
	std::string context_instance_id;     ///< Exact executable context identity.
	uint32_t module_image_index{0};	     ///< Compact loaded-image index.
	uint32_t context_index{0};	     ///< Compact executable-context index.
	uint32_t worker_index{0};	     ///< Sole owner-worker index.
	int32_t cpu_core_id{-1};	     ///< Exact owner-worker CPU.
	int32_t numa_node{-1};		     ///< Exact context NUMA ownership.
	uint32_t module_context_ordinal{0};  ///< Exact generation-fixed ordinal within the module configuration.
	uint32_t module_context_count{0};    ///< Positive complete population sharing that module configuration.
};

/**
 * @brief Opaque allocation identity returned to one lifecycle memory provider.
 *
 * Core lifecycle owners preserve this value byte-for-byte and return it only
 * to the provider that issued the corresponding block. They never interpret
 * either field. A provider that does not require a token may leave both fields
 * zero; a provider that does use it owns the nonzero identity and reuse rules.
 */
struct lifecycle_memory_provider_token {
	std::size_t opaque_identity{0};	 ///< Provider-private allocation identity.
	uint64_t reuse_nonce{0};	 ///< Provider-private reuse discriminator.
};

/**
 * @brief Exact memory block returned by a lifecycle memory provider.
 */
struct lifecycle_memory_block {
	void *data{nullptr};				   ///< Start of the allocation.
	std::size_t size{0};				   ///< Usable bytes owned by the block.
	std::size_t alignment{0};			   ///< Guaranteed pointer alignment.
	int32_t numa_node{-1};				   ///< NUMA node on which storage was allocated.
	lifecycle_memory_provider_token provider_token{};  ///< Opaque issuing-provider round-trip token.
};

/**
 * @brief Backend-neutral allocator for lifecycle-owned memory.
 *
 * Implementations may use libnuma, DPDK socket allocation, or a deterministic
 * test provider. Returning storage on a different NUMA node or with weaker
 * alignment than requested violates the interface and is rejected by the
 * owner before publication.
 *
 * @par Thread Safety
 * A production provider may receive concurrent allocate and release calls
 * from independent cold lifecycle executors. Implementations synchronize
 * their own ownership state; callers never invoke either operation while
 * holding a platform ownership lock.
 *
 * @par Performance
 * Allocation and release are cold-path operations and may enter the operating
 * system. Neither operation is reachable from packet execution.
 */
class lifecycle_memory_provider {
    public:
	/** @brief Destroy one lifecycle memory-provider implementation. */
	virtual ~lifecycle_memory_provider() = default;

	/**
	 * @brief Allocate one exact lifecycle-owned block.
	 *
	 * @param numa_node Required nonnegative NUMA node.
	 * @param size Required positive byte count.
	 * @param alignment Required power-of-two pointer alignment.
	 * @param zero_initialize Whether every returned byte must be zeroed.
	 * @return Exact owned block, including any opaque provider token that must
	 *         be returned unchanged, or a failure without retained allocation.
	 */
	[[nodiscard]] virtual kinetum::common::status_or<lifecycle_memory_block>
	allocate(int32_t numa_node, std::size_t size, std::size_t alignment, bool zero_initialize) noexcept = 0;

	/**
	 * @brief Release one block previously returned by this provider.
	 *
	 * @param block Exact block, including its unchanged provider token, to
	 *              release once. Passing a foreign, stale, modified, or already
	 *              released block violates the provider contract.
	 */
	virtual void release(lifecycle_memory_block block) noexcept = 0;
};

/** @brief Exact facts borrowed from one live cold lifecycle operation. */
struct lifecycle_log_record_view {
	const lifecycle_context_identity &identity;  ///< Actual context and worker placement.
	lifecycle_phase phase;			     ///< Actual cold operation; never ACTIVATE or health.
	uint64_t epoch;				     ///< Exact operation epoch, zero for INIT/FINI.
	lifecycle_log_level level;		     ///< Admitted module diagnostic severity.
	std::string_view message;		     ///< Text borrowed only through write().
};

/** @brief Backend-neutral sink for cold lifecycle diagnostics. */
class lifecycle_log_provider {
    public:
	/** @brief Destroy one lifecycle log-provider implementation. */
	virtual ~lifecycle_log_provider() = default;

	/**
	 * @brief Publish one bounded-lifetime lifecycle diagnostic.
	 *
	 * @param record Exact identity, phase, epoch, severity, and text borrowed only for this call.
	 */
	virtual void write(const lifecycle_log_record_view &record) noexcept = 0;
};

/**
 * @brief Immutable operation deadline with one-way cancellation publication.
 *
 * The coordinator is the sole cancellation writer. A lifecycle executor is
 * the reader. The control occupies one full cache line so cancellation traffic
 * cannot invalidate adjacent task ownership state. Transition cleanup may
 * preallocate an unbound control with the zero time point, then bind one finite
 * deadline exactly once before publishing its task; no executor can observe
 * the unbound state.
 */
class alignas(kinetum::algo::CACHE_LINE_SIZE) lifecycle_operation_control {
    public:
	/**
	 * @brief Construct control for one admitted lifecycle operation.
	 *
	 * @param deadline Absolute steady-clock deadline fixed at admission, or the
	 *        zero time point for the transition owner's private preallocated state.
	 */
	explicit lifecycle_operation_control(std::chrono::steady_clock::time_point deadline) noexcept;

	lifecycle_operation_control(const lifecycle_operation_control &) = delete;
	lifecycle_operation_control &operator=(const lifecycle_operation_control &) = delete;
	lifecycle_operation_control(lifecycle_operation_control &&) = delete;
	lifecycle_operation_control &operator=(lifecycle_operation_control &&) = delete;

	/** @brief Publish an irreversible cooperative-cancellation request. */
	void request_cancellation() noexcept;

	/**
	 * @brief Observe whether cancellation has been requested.
	 *
	 * @return true after the coordinator's release publication is acquired.
	 */
	[[nodiscard]] bool cancellation_requested() const noexcept;

	/**
	 * @brief Return the immutable absolute operation deadline.
	 *
	 * @return Admission-time steady-clock deadline; zero only while an internal
	 *         preallocated control remains unpublished.
	 */
	[[nodiscard]] std::chrono::steady_clock::time_point deadline() const noexcept;

	/**
	 * @brief Return whether one immutable operation deadline has been bound.
	 * @return true for a constructor-supplied deadline or one pre-publication bind.
	 */
	[[nodiscard]] bool deadline_bound() const noexcept;

	/**
	 * @brief Test the deadline against an explicit monotonic time.
	 *
	 * @param now Current steady-clock time.
	 * @return true when unbound or when @p now is at or beyond the deadline.
	 */
	[[nodiscard]] bool deadline_expired(std::chrono::steady_clock::time_point now) const noexcept;

    private:
	friend class ::kinetum::dp::epoch_transition_completion;
	friend class ::kinetum::dp::epoch_transition_preparation;

	/**
	 * @brief Bind one preallocated control immediately before task publication.
	 * @param deadline Exact finite operation deadline.
	 * @return true only for the sole transition from unbound to bound.
	 */
	[[nodiscard]] bool bind_deadline_before_publication_(std::chrono::steady_clock::time_point deadline) noexcept;

	std::chrono::steady_clock::time_point deadline_;   ///< Immutable admission-time deadline.
	std::atomic<bool> cancellation_requested_{false};  ///< Release/acquire one-way cancellation flag.
	bool deadline_bound_{false};			   ///< Whether deadline_ is immutable operation authority.
};

static_assert(alignof(lifecycle_operation_control) == kinetum::algo::CACHE_LINE_SIZE,
	      "lifecycle operation control must own one cache-line alignment domain");
static_assert(sizeof(lifecycle_operation_control) == kinetum::algo::CACHE_LINE_SIZE,
	      "lifecycle operation control must not share a cache line with adjacent state");

/**
 * @brief Move-only fixed-capacity arena for one context and one exact epoch.
 *
 * The arena owns one provider block and performs bounded bump allocation. It
 * cannot grow, chain blocks, reclaim individual objects, or resolve arbitrary
 * epochs. Destruction releases the one block exactly once.
 */
class epoch_arena_ownership {
    public:
	/** @brief Construct an empty moved-from arena with no ownership. */
	epoch_arena_ownership() noexcept = default;

	epoch_arena_ownership(const epoch_arena_ownership &) = delete;
	epoch_arena_ownership &operator=(const epoch_arena_ownership &) = delete;
	/**
	 * @brief Transfer one exact arena without copying its provider block.
	 *
	 * @param other Exact arena emptied by the transfer.
	 */
	epoch_arena_ownership(epoch_arena_ownership &&other) noexcept;
	/**
	 * @brief Release current storage, then transfer one exact arena.
	 *
	 * @param other Exact arena emptied by the transfer.
	 * @return This arena owner.
	 */
	epoch_arena_ownership &operator=(epoch_arena_ownership &&other) noexcept;
	/** @brief Release the provider block exactly once when owned. */
	~epoch_arena_ownership();

	/**
	 * @brief Allocate one exact epoch arena through the injected provider.
	 *
	 * @param provider Provider that owns allocation and release and must outlive
	 *        the returned arena.
	 * @param context_index Exact context owner.
	 * @param epoch Nonzero epoch represented by the arena.
	 * @param numa_node Required nonnegative NUMA node.
	 * @param capacity Positive fixed arena capacity.
	 * @param alignment Power-of-two base alignment.
	 * @return Exact move-only arena, or failure with no retained block.
	 */
	[[nodiscard]] static kinetum::common::status_or<epoch_arena_ownership>
	create(lifecycle_memory_provider &provider, uint32_t context_index, uint64_t epoch, int32_t numa_node,
	       std::size_t capacity, std::size_t alignment);

	/**
	 * @brief Allocate one aligned object range from the bounded arena.
	 *
	 * @param size Positive byte count.
	 * @param alignment Power-of-two object alignment no stronger than the base.
	 * @param zero_initialize Whether the returned range must be zeroed.
	 * @return Borrowed arena storage, or RESOURCE_EXHAUSTED/INVALID_ARGUMENT.
	 */
	[[nodiscard]] kinetum::common::status_or<void *> allocate(std::size_t size, std::size_t alignment,
								  bool zero_initialize) noexcept;

	/**
	 * @brief Return whether this object owns an arena block.
	 *
	 * @return true only while one exact provider block is owned.
	 */
	[[nodiscard]] bool owns_memory() const noexcept;

	/**
	 * @brief Return the exact context index represented by this arena.
	 *
	 * @return Context index, or zero for an empty moved-from arena.
	 */
	[[nodiscard]] uint32_t context_index() const noexcept;

	/**
	 * @brief Return the exact nonzero epoch represented by this arena.
	 *
	 * @return Exact epoch, or zero for an empty moved-from arena.
	 */
	[[nodiscard]] uint64_t epoch() const noexcept;

	/**
	 * @brief Return the exact NUMA node represented by this arena.
	 *
	 * @return Provider-reported NUMA node, or -1 when empty.
	 */
	[[nodiscard]] int32_t numa_node() const noexcept;

	/**
	 * @brief Return the immutable total arena capacity.
	 *
	 * @return Total owned bytes, or zero when empty.
	 */
	[[nodiscard]] std::size_t capacity() const noexcept;

	/**
	 * @brief Return bytes consumed by successful arena allocations.
	 *
	 * @return Current monotonic bump offset in bytes.
	 */
	[[nodiscard]] std::size_t bytes_used() const noexcept;

    private:
	/**
	 * @brief Adopt one validated provider block as an exact epoch arena.
	 *
	 * @param provider Provider that must release @p block.
	 * @param block Exact validated provider block.
	 * @param context_index Exact owning context index.
	 * @param epoch Exact nonzero epoch represented by the block.
	 */
	epoch_arena_ownership(lifecycle_memory_provider &provider, lifecycle_memory_block block, uint32_t context_index,
			      uint64_t epoch) noexcept;

	/** @brief Release the exact provider block if this object still owns it. */
	void release_() noexcept;

	lifecycle_memory_provider *provider_{nullptr};	///< Exact allocation/release authority while owned.
	lifecycle_memory_block block_{};		///< One exact provider block.
	uint32_t context_index_{0};			///< Exact context owner while live.
	uint64_t epoch_{0};				///< Exact nonzero epoch while live.
	std::size_t offset_{0};				///< Monotonic aligned bump offset.
};

/** @brief One bounded owner-local telemetry registration. */
struct lifecycle_telemetry_descriptor {
	lifecycle_telemetry_handle handle{0};				   ///< Stable one-based handle.
	lifecycle_telemetry_kind kind{lifecycle_telemetry_kind::COUNTER};  ///< Registered metric kind.
	kinetum_counter counter{};					   ///< Counter storage when kind is COUNTER.
	kinetum_histogram histogram{};	///< Histogram storage when kind is HISTOGRAM.
	std::array<uint64_t *, LIFECYCLE_TELEMETRY_BANK_COUNT> histogram_counts{};  ///< Bucket-bank starts.
	uint32_t kind_ordinal{UINT32_MAX};  ///< Counter or histogram compact ordinal.
};

static_assert(std::is_standard_layout_v<lifecycle_telemetry_descriptor>);
static_assert(std::is_trivially_copyable_v<lifecycle_telemetry_descriptor>);

/** @brief Immutable summary copied from one completed histogram bank. */
struct lifecycle_histogram_bank_snapshot {
	uint64_t total_count{0};	 ///< Samples in the completed interval.
	uint64_t min_value{UINT64_MAX};	 ///< Minimum sample, or UINT64_MAX when empty.
	uint64_t max_value{0};		 ///< Maximum sample.
	uint64_t sum{0};		 ///< Saturating sample sum.
};

static_assert(std::is_standard_layout_v<lifecycle_histogram_bank_snapshot>);
static_assert(std::is_trivially_copyable_v<lifecycle_histogram_bank_snapshot>);

/** @brief Fixed owner-local module epoch-mismatch projection in one bank. */
struct lifecycle_telemetry_mismatch_snapshot {
	uint64_t mismatch_count{0};	   ///< Saturating mismatch count.
	uint64_t packet_epoch{0};	   ///< First rejected packet epoch.
	uint64_t active_epoch{0};	   ///< First exact active epoch.
	uint32_t context_index{0};	   ///< Exact module context.
	uint32_t worker_index{0};	   ///< Sole owner worker.
	uint16_t stage_instance_index{0};  ///< First exact stage instance.
	uint16_t reserved{0};		   ///< Must remain zero.
	int32_t region_id{-1};		   ///< First bounded region identity.
	uint8_t first_fault_valid{0};	   ///< One after first-fault capture.
	uint8_t sticky_fault{0};	   ///< One after any mismatch.
	uint8_t padding[6]{};		   ///< Fixed zero padding.
};

static_assert(sizeof(lifecycle_telemetry_mismatch_snapshot) == 48u);
static_assert(std::is_standard_layout_v<lifecycle_telemetry_mismatch_snapshot>);
static_assert(std::is_trivially_copyable_v<lifecycle_telemetry_mismatch_snapshot>);

/** @brief Lifecycle spelling of the shared module-health fault vocabulary. */
using lifecycle_module_health_fault = common::module_health_contract_fault;

/** @brief Lifecycle projection of the shared admitted fault mask. */
inline constexpr uint16_t LIFECYCLE_MODULE_HEALTH_FAULT_KNOWN_MASK = common::MODULE_HEALTH_CONTRACT_FAULT_KNOWN_MASK;

/** @brief One coherent context-scoped owner-worker health observation. */
struct alignas(64) lifecycle_module_health_observation {
	uint64_t publication_generation{0};    ///< Coherent snapshot generation.
	uint64_t runtime_generation{0};	       ///< Exact materialized runtime generation.
	uint64_t observation_epoch{0};	       ///< Exact epoch of the latest callback attempt.
	uint64_t observed_at_ns{0};	       ///< Platform-stamped latest attempt time.
	uint64_t callback_duration_ns{0};      ///< Measured latest callback duration.
	uint64_t contract_fault_count{0};      ///< Saturating malformed/over-budget attempt count.
	uint64_t first_fault_epoch{0};	       ///< Exact epoch of the first contract fault.
	uint64_t first_fault_timestamp_ns{0};  ///< Platform-stamped first-fault time.
	uint64_t first_fault_duration_ns{0};   ///< Measured first-fault callback duration.
	uint32_t worker_index{0};	       ///< Sole owner worker.
	uint32_t context_index{0};	       ///< Exact module context.
	uint16_t stage_instance_index{0};      ///< Exact executable stage instance.
	uint16_t latest_fault_mask{0};	       ///< Fault bits for the latest attempted callback.
	uint16_t first_fault_mask{0};	       ///< Immutable first-fault bit set.
	uint8_t callback_available{0};	       ///< One only for an admitted non-null callback.
	uint8_t signal_available{0};	       ///< One only when @c signal is valid.
	kinetum_health_signal signal{};	       ///< Normalized platform-stamped signal when available.
};

static_assert(sizeof(lifecycle_module_health_observation) == 192u);
static_assert(alignof(lifecycle_module_health_observation) == 64u);
static_assert(offsetof(lifecycle_module_health_observation, signal) == 128u);
static_assert(std::is_standard_layout_v<lifecycle_module_health_observation>);
static_assert(std::is_trivially_copyable_v<lifecycle_module_health_observation>);

/** @brief Exact platform timing and epoch facts for one health attempt. */
struct lifecycle_module_health_attempt {
	uint64_t epoch{0};		 ///< Exact active epoch borrowed by the callback.
	uint64_t timestamp_ns{0};	 ///< Cached owner-turn callback timestamp.
	uint64_t duration_ns{0};	 ///< Post-return measured callback duration.
	uint64_t callback_budget_ns{0};	 ///< Exact positive compiled worker budget.
};
static_assert(std::is_standard_layout_v<lifecycle_module_health_attempt>);
static_assert(std::is_trivially_copyable_v<lifecycle_module_health_attempt>);

/** @brief Cold immutable borrow of one completed module telemetry bank. */
struct lifecycle_module_telemetry_bank_view {
	std::span<const uint64_t> counter_values;			///< Absolute counter and gauge values.
	std::span<const lifecycle_histogram_bank_snapshot> histograms;	///< Completed interval summaries.
	uint8_t bank_index{UINT8_MAX};			   ///< Exact three-bank slot for histogram buckets.
	uint64_t skipped_publications{0};		   ///< Refused ordinary cadence swaps.
	lifecycle_telemetry_mismatch_snapshot mismatch{};  ///< Coherent mismatch evidence.
};

class lifecycle_context_owner;
struct lifecycle_borrow_state;

/**
 * @brief RAII claim for one borrowed lifecycle-context operation.
 *
 * Releasing or destroying the claim ends the operation and permits the next
 * cold callback. Moving transfers the claim; copied or overlapping claims are
 * impossible.
 */
class lifecycle_context_operation {
    public:
	lifecycle_context_operation(const lifecycle_context_operation &) = delete;
	lifecycle_context_operation &operator=(const lifecycle_context_operation &) = delete;
	lifecycle_context_operation &operator=(lifecycle_context_operation &&) = delete;
	/**
	 * @brief Transfer an exclusive operation claim.
	 *
	 * @param other Claim invalidated by the transfer.
	 */
	lifecycle_context_operation(lifecycle_context_operation &&other) noexcept;
	/** @brief End the claimed operation when still active. */
	~lifecycle_context_operation();

	/**
	 * @brief Return the opaque context borrowed by the admitted operation.
	 *
	 * Calling this method after release or on a moved-from claim is a fatal
	 * linear-ownership violation.
	 *
	 * @return Context valid until this claim is released or destroyed.
	 */
	[[nodiscard]] const ::kinetum_lifecycle_ctx &context() const noexcept;

	/** @brief End this operation immediately; repeated calls are harmless. */
	void release() noexcept;

    private:
	friend class lifecycle_context_owner;
	/**
	 * @brief Adopt the exclusive operation claim already held by an owner.
	 *
	 * @param owner Owner whose borrowed context remains active until release.
	 */
	explicit lifecycle_context_operation(lifecycle_context_owner &owner) noexcept;

	lifecycle_context_owner *owner_{nullptr};  ///< Claimed owner, or nullptr after release/move.
};

/**
 * @brief Long-lived owner of one opaque module lifecycle context.
 *
 * The owner retains immutable placement, provider references, a bounded
 * allocation ledger, and a bounded telemetry registry. It never owns or
 * exposes a live mutable packet-processing kinetum_ctx.
 */
class lifecycle_context_owner {
    public:
	/**
	 * @brief Construct one exact lifecycle context owner.
	 *
	 * @param identity Candidate module/context/worker placement, read during
	 *        admission and moved directly into the owner during construction.
	 *        Rejection before construction leaves it unchanged; construction
	 *        failure may consume it.
	 * @param context_memory_capacity_bytes Exact nonzero aggregate bound for
	 *        context-lifetime allocations.
	 * @param epoch_arena_capacity_bytes Exact nonzero capacity required for
	 *        every PREPARE arena owned by this context.
	 * @param memory_provider Exact NUMA-aware allocation authority that must
	 *        outlive the returned owner.
	 * @param log_provider Cold diagnostic authority that must outlive the
	 *        returned owner.
	 * @return Unique owner, or an admission error for malformed identity.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<lifecycle_context_owner>>
	create(lifecycle_context_identity &&identity, std::size_t context_memory_capacity_bytes,
	       std::size_t epoch_arena_capacity_bytes, lifecycle_memory_provider &memory_provider,
	       lifecycle_log_provider &log_provider);

	lifecycle_context_owner(const lifecycle_context_owner &) = delete;
	lifecycle_context_owner &operator=(const lifecycle_context_owner &) = delete;
	lifecycle_context_owner(lifecycle_context_owner &&) = delete;
	lifecycle_context_owner &operator=(lifecycle_context_owner &&) = delete;
	/** @brief Release all tracked long-lived allocations; active use is fatal. */
	~lifecycle_context_owner();

	/**
	 * @brief Claim one exact cold lifecycle operation.
	 *
	 * PREPARE requires a matching nonzero epoch arena. INIT and FINI require
	 * epoch zero. RETIRE requires a nonzero epoch and no arena. Every phase
	 * requires immutable deadline/cancellation control.
	 *
	 * @param phase Cold callback phase; ACTIVATE is not representable.
	 * @param epoch Zero for INIT/FINI, nonzero for PREPARE/RETIRE.
	 * @param control Stable deadline/cancellation control for the call.
	 * @param arena Exact PREPARE arena, otherwise nullptr.
	 * @return Exclusive borrowed operation, or fail-closed status.
	 */
	[[nodiscard]] kinetum::common::status_or<lifecycle_context_operation>
	begin_operation(lifecycle_phase phase, uint64_t epoch, lifecycle_operation_control &control,
			epoch_arena_ownership *arena = nullptr) noexcept;

	/**
	 * @brief Return immutable module/context placement.
	 *
	 * @return Owner-lifetime identity and placement record.
	 */
	[[nodiscard]] const lifecycle_context_identity &identity() const noexcept;

	/**
	 * @brief Return the exact context-lifetime allocation capacity.
	 *
	 * @return Immutable nonzero authored byte capacity.
	 */
	[[nodiscard]] std::size_t context_memory_capacity_bytes() const noexcept;

	/**
	 * @brief Return the exact capacity required for every epoch arena.
	 *
	 * @return Immutable nonzero authored byte capacity.
	 */
	[[nodiscard]] std::size_t epoch_arena_capacity_bytes() const noexcept;
	/** @return Exact platform-owned telemetry registry/bank overhead per context. */
	[[nodiscard]] static std::size_t telemetry_storage_bytes() noexcept;

	/**
	 * @brief Return the number of registered telemetry handles.
	 *
	 * @return Number of occupied descriptors in the bounded registry.
	 */
	[[nodiscard]] std::size_t telemetry_handle_count() const noexcept;

	/**
	 * @brief Resolve one registered telemetry descriptor by stable handle.
	 *
	 * @param handle One-based handle returned during lifecycle registration.
	 * @return Descriptor pointer, or nullptr for zero/out-of-range handles.
	 */
	[[nodiscard]] const lifecycle_telemetry_descriptor *
	telemetry_descriptor(lifecycle_telemetry_handle handle) const noexcept;

	/**
	 * @brief Bind exact runtime/stage identity and the worker bank channel.
	 * @param runtime_generation Exact materialized generation.
	 * @param stage_instance_index Exact module stage instance.
	 * @param channel Worker-owned SPSC transfer authority.
	 * @param health_callback_available Whether the admitted descriptor owns health.
	 * @return OK after one cold binding; otherwise no identity is published.
	 */
	[[nodiscard]] kinetum::common::status bind_telemetry(uint64_t runtime_generation, uint16_t stage_instance_index,
							     kinetum::dp::worker_telemetry_channel &channel,
							     bool health_callback_available) noexcept;
	/**
	 * @brief Release the cold channel binding after every bank is reclaimed.
	 *
	 * The generation owner calls this after packet-worker join, complete bank
	 * retirement, and source detachment. Live ownership is terminate-class.
	 */
	void unbind_telemetry() noexcept;

	/**
	 * @brief Bind active and standby banks to one fixed Bootstrap epoch.
	 * @param epoch Exact nonzero Bootstrap epoch.
	 * @param now_ns Sole owner-worker cached monotonic timestamp.
	 */
	void bind_bootstrap_telemetry(uint64_t epoch, uint64_t now_ns) noexcept;
	/**
	 * @brief Reserve the sole free bank for a future exact epoch.
	 * @param from_epoch Exact active epoch.
	 * @param to_epoch Exact adjacent transaction target identity.
	 * @return OK after one all-or-none reserve; otherwise active banks are unchanged.
	 */
	[[nodiscard]] kinetum::common::status reserve_telemetry_epoch(uint64_t from_epoch, uint64_t to_epoch) noexcept;
	/**
	 * @brief Prove the cold generation owner still holds one exact target reserve.
	 * @param from_epoch Exact stable active epoch.
	 * @param to_epoch Exact coordinator-reserved target epoch.
	 * @return true from the cold owner only when the target reserve is exact.
	 */
	[[nodiscard]] bool telemetry_target_reserved(uint64_t from_epoch, uint64_t to_epoch) const noexcept;
	/**
	 * @brief Release one unused target reserve during pre-commit cleanup.
	 * @param to_epoch Exact reserved target being aborted.
	 */
	void discard_telemetry_epoch(uint64_t to_epoch) noexcept;
	/**
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact reserved target epoch.
	 * @return true only when activation publication is bounded and non-failing.
	 */
	[[nodiscard]] bool preflight_activate_telemetry(uint64_t from_epoch, uint64_t to_epoch) const noexcept;
	/**
	 * @brief Publish final old telemetry and switch to the exact target bank.
	 * @param from_epoch Exact old execution epoch.
	 * @param to_epoch Exact target execution epoch.
	 * @param now_ns Sole owner-worker cached monotonic timestamp.
	 */
	void activate_telemetry_epoch(uint64_t from_epoch, uint64_t to_epoch, uint64_t now_ns) noexcept;
	/**
	 * @brief Service one worker-scheduled module cadence without a clock comparison.
	 * @param now_ns Sole cached timestamp shared by the worker turn.
	 * @return Exact return-ring work created or potentially available.
	 */
	[[nodiscard]] runtime_telemetry_return_need service_telemetry_cadence(uint64_t now_ns) noexcept;
	/**
	 * @brief Accept one return token dispatched by the sole worker-channel consumer.
	 * @param token Exact cleared-bank ownership transfer.
	 */
	void accept_returned_telemetry(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @param epoch Exact active epoch to publish at shutdown.
	 * @return true when final publication cannot strand a cadence return.
	 */
	[[nodiscard]] bool preflight_publish_shutdown_telemetry(uint64_t epoch) const noexcept;
	/**
	 * @brief Publish final active telemetry before the owner worker exits.
	 * @param epoch Exact active epoch.
	 * @param now_ns Sole owner-worker cached monotonic timestamp.
	 */
	void publish_shutdown_telemetry(uint64_t epoch, uint64_t now_ns) noexcept;
	/**
	 * @brief Update rare owner-local mismatch evidence in the current active bank.
	 * @param mismatch Complete cumulative projection from the sole module store.
	 */
	void record_telemetry_mismatch(const lifecycle_telemetry_mismatch_snapshot &mismatch) noexcept;
	/**
	 * @brief Validate and publish one completed owner-worker health attempt.
	 * @param assessment Raw module-owned callback result.
	 * @param attempt Exact epoch, platform timestamp, duration, and budget facts.
	 * @pre The sole worker health scheduler holds this context's linear claim.
	 */
	void publish_module_health_attempt(const kinetum_health_assessment &assessment,
					   lifecycle_module_health_attempt attempt) noexcept;
	/**
	 * @brief Read one coherent owner-completed module-health publication.
	 * @param[out] out Observer-owned coherent health destination.
	 * @return true after reading one complete publication; false when unavailable or torn.
	 */
	[[nodiscard]] bool try_read_module_health(lifecycle_module_health_observation &out) const noexcept;
	/** @return true only when the admitted descriptor owns a non-null health callback. */
	[[nodiscard]] bool health_callback_available() const noexcept;
	/**
	 * @brief Claim this context for its sole owner-worker health scheduler.
	 * @param runtime_generation Exact bound runtime generation.
	 * @param stage_instance_index Exact bound stage instance.
	 * @return OK after one linear claim; otherwise no ownership changes.
	 * @pre Telemetry is channel-bound but no Bootstrap epoch or health publication exists.
	 */
	[[nodiscard]] kinetum::common::status claim_module_health_owner(uint64_t runtime_generation,
									uint16_t stage_instance_index) noexcept;
	/** @brief Release the exact health-owner claim after worker quiescence. */
	void release_module_health_owner() noexcept;
	/** @return true while one exact worker health scheduler owns this context. */
	[[nodiscard]] bool module_health_owner_claimed() const noexcept;
	/**
	 * @brief Restore published-shutdown bank ownership before claim retry.
	 *
	 * A still-live owner receives active/standby banks again. After worker join,
	 * both banks remain aggregated-retained for cold retry only.
	 * @param epoch Exact published epoch restored with its module artifact.
	 */
	void restore_shutdown_telemetry(uint64_t epoch) noexcept;

	/**
	 * @brief Borrow one immutable completed bank after consuming its token.
	 * @param token Exact completed-bank ownership token.
	 * @return Immutable bank view, or failure without reading live owner state.
	 */
	[[nodiscard]] kinetum::common::status_or<lifecycle_module_telemetry_bank_view>
	completed_telemetry_bank(const runtime_telemetry_bank_token &token) const noexcept;
	/**
	 * @brief Borrow one exact immutable histogram bucket bank after token transfer.
	 * @param token Exact completed-bank ownership token.
	 * @param histogram_ordinal Compact registered histogram identity.
	 * @return Immutable completed buckets or a fail-closed identity status.
	 */
	[[nodiscard]] kinetum::common::status_or<std::span<const uint64_t>>
	completed_telemetry_histogram(const runtime_telemetry_bank_token &token,
				      uint32_t histogram_ordinal) const noexcept;
	/**
	 * @brief Clear the next exact bounded histogram prefix after it is merged.
	 * @param token Exact completed-bank ownership token.
	 * @param histogram_ordinal Compact registered histogram identity.
	 * @param begin Exact current bucket cursor.
	 * @param count Positive prefix no larger than LIFECYCLE_TELEMETRY_BUCKET_PREFIX.
	 * @return true only after every histogram in this bank is cleared.
	 */
	[[nodiscard]] bool clear_completed_telemetry_histogram_prefix(const runtime_telemetry_bank_token &token,
								      uint32_t histogram_ordinal, std::size_t begin,
								      std::size_t count) noexcept;
	/**
	 * @brief Complete one exact cold aggregation.
	 * @param token Exact token whose payload was merged once.
	 */
	void complete_telemetry_aggregation(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @param epoch Candidate exact old epoch.
	 * @return true only after the cold aggregator certifies both old banks.
	 */
	[[nodiscard]] bool telemetry_epoch_aggregated(uint64_t epoch) const noexcept;
	/**
	 * @brief Accept the cold aggregator's exact completed-epoch verdict.
	 * @param epoch Exact epoch whose two retained banks were observed.
	 */
	void mark_telemetry_epoch_aggregated(uint64_t epoch) noexcept;
	/**
	 * @brief Record that the owner worker exited and cannot consume returns.
	 *
	 * Only the cold generation owner calls this after join.
	 */
	void mark_telemetry_worker_quiesced() noexcept;
	/**
	 * @brief Reclaim an aggregated old epoch after exact reader grace.
	 * @param epoch Exact old epoch being retired.
	 * @param active_epoch Current target epoch, or zero for final shutdown.
	 */
	void retire_telemetry_epoch(uint64_t epoch, uint64_t active_epoch) noexcept;
	/**
	 * @param active_epoch Exact target expected in the pending transfer.
	 * @return One reclaimed-bank transfer created by the latest retirement.
	 */
	[[nodiscard]] std::optional<runtime_telemetry_bank_token>
	take_reclaimed_telemetry_transfer(uint64_t active_epoch) noexcept;
	/** @return true only when no telemetry bank or transfer remains. */
	[[nodiscard]] bool telemetry_empty() const noexcept;
	/** @return Exact active telemetry epoch, or zero before Bootstrap/after shutdown publication. */
	[[nodiscard]] uint64_t telemetry_active_epoch() const noexcept;
	/** @return Exact reserved telemetry target epoch, or zero when absent. */
	[[nodiscard]] uint64_t telemetry_prepared_epoch() const noexcept;
	/** @return Exact materialized runtime generation bound to telemetry. */
	[[nodiscard]] uint64_t telemetry_runtime_generation() const noexcept;
	/** @return Exact bound module stage instance, or UINT16_MAX before binding. */
	[[nodiscard]] uint16_t telemetry_stage_instance_index() const noexcept;
	/**
	 * @param channel Candidate immutable worker transport.
	 * @return true only for the exact channel borrowed by telemetry binding.
	 */
	[[nodiscard]] bool owns_telemetry_channel(const kinetum::dp::worker_telemetry_channel &channel) const noexcept;

    private:
	friend class lifecycle_context_operation;
	friend const lifecycle_context_identity &lifecycle_identity(const ::kinetum_lifecycle_ctx &) noexcept;
	friend lifecycle_phase lifecycle_current_phase(const ::kinetum_lifecycle_ctx &) noexcept;
	friend uint64_t lifecycle_current_epoch(const ::kinetum_lifecycle_ctx &) noexcept;
	friend bool lifecycle_cancellation_requested(const ::kinetum_lifecycle_ctx &) noexcept;
	friend std::chrono::steady_clock::time_point lifecycle_deadline(const ::kinetum_lifecycle_ctx &) noexcept;
	friend kinetum::common::status_or<void *>
	lifecycle_allocate_long_lived(const ::kinetum_lifecycle_ctx &, std::size_t, std::size_t, bool) noexcept;
	friend kinetum::common::status lifecycle_release_long_lived(const ::kinetum_lifecycle_ctx &, void *) noexcept;
	friend kinetum::common::status_or<void *> lifecycle_allocate_epoch(const ::kinetum_lifecycle_ctx &, std::size_t,
									   std::size_t, bool) noexcept;
	friend kinetum::common::status_or<kinetum_counter_t> lifecycle_register_counter(const ::kinetum_lifecycle_ctx &,
											std::string_view) noexcept;
	friend kinetum::common::status_or<kinetum_histogram_t>
	lifecycle_register_histogram(const ::kinetum_lifecycle_ctx &, std::string_view, uint64_t, int32_t) noexcept;
	friend void lifecycle_log(const ::kinetum_lifecycle_ctx &, lifecycle_log_level, std::string_view) noexcept;

	/** @brief One occupied slot in the fixed long-lived allocation ledger. */
	struct long_lived_allocation_record {
		lifecycle_memory_block block{};	 ///< Exact provider block while occupied.
		bool occupied{false};		 ///< Whether this slot owns its block.
	};

	/** @brief Linear state of one module telemetry bank. */
	enum class telemetry_bank_state : uint8_t {
		FREE = 0,
		ACTIVE,
		STANDBY,
		RESERVED,
		PUBLISHED,
		AGGREGATED_RETAINED,
		RETURNING,
	};

	/** @brief One fixed module telemetry publication bank. */
	struct alignas(64) telemetry_bank {
		std::array<uint64_t, KINETUM_MAX_COUNTERS> counter_values{};  ///< Absolute counter values.
		std::array<lifecycle_histogram_bank_snapshot, KINETUM_MAX_HISTOGRAMS> histograms{};  ///< Summaries.
		uint64_t epoch{0};					 ///< Exact assigned epoch.
		uint64_t generation{0};					 ///< Exact reuse generation.
		uint64_t skipped_publications{0};			 ///< Ordinary cadence refusals.
		lifecycle_telemetry_mismatch_snapshot mismatch{};	 ///< Rare exact-epoch mismatch evidence.
		uint32_t histogram_clear_ordinal{0};			 ///< Next histogram requiring cold clearing.
		uint32_t histogram_clear_offset{0};			 ///< Next bucket in that histogram.
		runtime_telemetry_bank_token transfer{};		 ///< Exact live transfer identity, or empty.
		telemetry_bank_state state{telemetry_bank_state::FREE};	 ///< Linear ownership state.
		std::array<uint8_t, 55> padding{};			 ///< Explicit cache-line completion.
	};
	static_assert(sizeof(telemetry_bank) == 1216u);
	static_assert(sizeof(telemetry_bank) % 64u == 0u);
	static_assert(alignof(telemetry_bank) == 64u);
	static_assert(std::is_standard_layout_v<telemetry_bank>);
	static_assert(std::is_trivially_copyable_v<telemetry_bank>);

	/** @brief Plain owner-local health fault state isolated from foreign readers. */
	struct alignas(64) module_health_owner_state {
		uint64_t contract_fault_count{0};      ///< Saturating failed-attempt population.
		uint64_t first_fault_epoch{0};	       ///< Exact first-fault epoch.
		uint64_t first_fault_timestamp_ns{0};  ///< Platform-stamped first-fault time.
		uint64_t first_fault_duration_ns{0};   ///< Measured first-fault duration.
		uint16_t first_fault_mask{0};	       ///< Immutable first-fault bit set.
		uint8_t callback_available{0};	       ///< Exact admitted descriptor fact.
		uint8_t owner_claimed{0};	       ///< One while the exact health scheduler owns this row.
		std::array<uint8_t, 28> padding{};     ///< Explicit cache-line completion.
	};
	static_assert(sizeof(module_health_owner_state) == 64u);
	static_assert(alignof(module_health_owner_state) == 64u);
	static_assert(std::is_standard_layout_v<module_health_owner_state>);
	static_assert(std::is_trivially_copyable_v<module_health_owner_state>);

	static constexpr std::size_t MODULE_HEALTH_PUBLICATION_FIELD_COUNT = 21u;  ///< Exact snapshot payload width.
	/** @brief Bounded coherent module-health read attempts. */
	static constexpr std::size_t MODULE_HEALTH_OBSERVATION_ATTEMPTS = 4u;
	/** @brief Fixed coherent publication mechanism for one context's health. */
	using module_health_snapshot = kinetum::algo::single_writer_snapshot<MODULE_HEALTH_PUBLICATION_FIELD_COUNT>;
	static_assert(sizeof(module_health_snapshot) == 192u);
	static_assert(alignof(module_health_snapshot) == kinetum::algo::CACHE_LINE_SIZE);

	/** @brief Exact-NUMA stable telemetry handle and bank storage. */
	struct telemetry_storage {
		std::array<lifecycle_telemetry_descriptor, LIFECYCLE_MAX_TELEMETRY_HANDLES>
			descriptors{};	///< Registered context-lifetime telemetry handles.
		std::array<telemetry_bank, LIFECYCLE_TELEMETRY_BANK_COUNT>
			banks{};				   ///< Fixed active/future/completed sample banks.
		lifecycle_telemetry_mismatch_snapshot mismatch{};  ///< Sole published projection of store diagnostics.
		module_health_owner_state health_owner{};	   ///< Owner-only health fault state.
		module_health_snapshot health_publication{};	   ///< Coherent foreign-readable health state.
	};
	static_assert(sizeof(telemetry_storage) % kinetum::algo::CACHE_LINE_SIZE == 0u);
	static_assert(alignof(telemetry_storage) >= kinetum::algo::CACHE_LINE_SIZE);
	static_assert(std::is_standard_layout_v<telemetry_storage>);
	static_assert(!std::is_copy_constructible_v<telemetry_storage>);
	static_assert(offsetof(telemetry_storage, health_owner) % kinetum::algo::CACHE_LINE_SIZE == 0u);
	static_assert(offsetof(telemetry_storage, health_publication) % kinetum::algo::CACHE_LINE_SIZE == 0u);

	/**
	 * @brief Construct one owner after identity admission succeeds.
	 *
	 * @param identity Admitted module/context placement moved directly into
	 *        retained ownership.
	 * @param context_memory_capacity_bytes Exact context-lifetime byte bound.
	 * @param epoch_arena_capacity_bytes Exact per-epoch arena byte bound.
	 * @param memory_provider Exact allocation and release authority.
	 * @param log_provider Cold diagnostic authority.
	 * @param telemetry_storage_block Exact provider-owned telemetry storage.
	 * @param telemetry_storage_pointer Placement-constructed storage address.
	 */
	lifecycle_context_owner(lifecycle_context_identity &&identity, std::size_t context_memory_capacity_bytes,
				std::size_t epoch_arena_capacity_bytes, lifecycle_memory_provider &memory_provider,
				lifecycle_log_provider &log_provider, lifecycle_memory_block telemetry_storage_block,
				telemetry_storage *telemetry_storage_pointer);

	/** @brief Clear borrowed operation state and release the exclusive claim. */
	void end_operation_() noexcept;
	/**
	 * @brief Allocate and ledger one exact long-lived provider block.
	 *
	 * @param size Positive exact byte count.
	 * @param alignment Required power-of-two pointer alignment.
	 * @param zero_initialize Whether every returned byte must be zeroed.
	 * @return Exact tracked storage, or a fail-closed status.
	 */
	[[nodiscard]] kinetum::common::status_or<void *> allocate_long_lived_(std::size_t size, std::size_t alignment,
									      bool zero_initialize) noexcept;
	/**
	 * @brief Release one exact ledgered long-lived provider block.
	 *
	 * @param pointer Exact allocation start previously returned by this owner.
	 * @return OK after one release; non-OK for unknown or repeated ownership.
	 */
	[[nodiscard]] kinetum::common::status release_long_lived_(void *pointer) noexcept;
	/**
	 * @brief Reserve one unique descriptor in the bounded telemetry registry.
	 *
	 * @param kind Supported telemetry kind.
	 * @param name Bounded nonempty printable-ASCII identity.
	 * @return Mutable descriptor owned by this context, or fail-closed status.
	 */
	[[nodiscard]] kinetum::common::status_or<lifecycle_telemetry_descriptor *>
	register_telemetry_(lifecycle_telemetry_kind kind, std::string_view name) noexcept;
	/**
	 * @brief Allocate one histogram's complete three-bank bucket extent.
	 * @param size Exact positive aggregate byte count.
	 * @param alignment Exact power-of-two alignment.
	 * @return Tracked context-budget storage or a fail-closed status.
	 */
	[[nodiscard]] kinetum::common::status_or<void *> allocate_telemetry_(std::size_t size,
									     std::size_t alignment) noexcept;
	/**
	 * @brief Clear payload storage in one exact bank without changing identity state.
	 * @param bank_index Exact bank to clear under current linear ownership.
	 */
	void clear_telemetry_bank_(uint8_t bank_index) noexcept;
	/**
	 * @brief Reset one proven-cleared bank's fixed summaries and clear cursor.
	 * @param bank_index Exact bank owned by the caller.
	 */
	void reset_telemetry_bank_metadata_(uint8_t bank_index) noexcept;
	/**
	 * @brief Remove the transfer identity from one proven-unowned bank.
	 * @param bank_index Exact bank under caller-owned state transition.
	 */
	void reset_telemetry_bank_transfer_(uint8_t bank_index) noexcept;
	/**
	 * @brief Snapshot absolute handles and interval summaries into one completed bank.
	 * @param bank_index Exact active bank becoming immutable.
	 */
	void capture_telemetry_bank_(uint8_t bank_index) noexcept;
	/**
	 * @brief Redirect every histogram handle to one already-cleared active bank.
	 * @param bank_index Exact new owner-writable bank.
	 */
	void select_histogram_bank_(uint8_t bank_index) noexcept;
	/**
	 * @brief Transfer one immutable bank to the cold completed ring.
	 * @param bank_index Exact completed bank.
	 * @param reason Cadence, activation, or shutdown publication reason.
	 * @param now_ns Sole cached worker timestamp.
	 * @param companion_bank_index Clean retained companion or UINT8_MAX.
	 */
	void publish_telemetry_bank_(uint8_t bank_index, runtime_telemetry_publication_reason reason, uint64_t now_ns,
				     uint8_t companion_bank_index = UINT8_MAX) noexcept;
	/**
	 * @brief Validate one cold token against immutable bank identity.
	 * @param token Candidate completed-bank token.
	 * @param bank Exact bank named by the token.
	 * @return true only for complete byte-exact ownership identity.
	 */
	[[nodiscard]] bool telemetry_token_matches_(const runtime_telemetry_bank_token &token,
						    const telemetry_bank &bank) const noexcept;

	lifecycle_context_identity identity_;			  ///< Immutable module/context/worker placement.
	std::size_t context_memory_capacity_bytes_{0};		  ///< Exact context-lifetime allocation bound.
	std::size_t epoch_arena_capacity_bytes_{0};		  ///< Exact required capacity of each epoch arena.
	std::size_t context_memory_bytes_in_use_{0};		  ///< Sum of live long-lived allocation bytes.
	lifecycle_memory_provider &memory_provider_;		  ///< Exact owner-lifetime memory authority.
	lifecycle_log_provider &log_provider_;			  ///< Exact owner-lifetime log authority.
	std::unique_ptr<lifecycle_borrow_state> borrowed_state_;  ///< Private operation state behind the C ABI.
	::kinetum_lifecycle_ctx borrowed_context_{};		  ///< Stable public two-pointer ABI shell.
	std::array<long_lived_allocation_record, LIFECYCLE_MAX_LONG_LIVED_ALLOCATIONS> allocations_{};	///< Fixed ledger.
	std::array<long_lived_allocation_record, KINETUM_MAX_HISTOGRAMS> telemetry_allocations_{};  ///< Internal buckets.
	lifecycle_memory_block telemetry_storage_block_{};  ///< Exact worker-NUMA stable telemetry storage.
	telemetry_storage *telemetry_storage_{nullptr};	    ///< Placement-constructed handles and banks.
	std::size_t telemetry_count_{0};		    ///< Occupied descriptor-registry prefix.
	std::size_t counter_count_{0};			    ///< Registered counters in the prefix.
	std::size_t histogram_count_{0};		    ///< Registered histograms in the prefix.
	std::array<std::array<uint64_t *, LIFECYCLE_TELEMETRY_BANK_COUNT>, KINETUM_MAX_HISTOGRAMS>
		telemetry_histogram_banks_{};  ///< Cold pre-resolved bucket-bank starts.
	std::array<uint32_t, KINETUM_MAX_HISTOGRAMS> telemetry_histogram_lengths_{};  ///< Exact bucket counts.
	uint64_t telemetry_runtime_generation_{0};	       ///< Exact bound runtime generation.
	uint16_t telemetry_stage_instance_index_{UINT16_MAX};  ///< Exact module stage identity.
	uint64_t telemetry_active_epoch_{0};		       ///< Exact active telemetry epoch.
	uint64_t telemetry_prepared_epoch_{0};		       ///< Exact reserved target epoch.
	uint64_t telemetry_aggregated_epoch_{0};	       ///< Cold-confirmed fully aggregated epoch.
	uint8_t telemetry_active_bank_{UINT8_MAX};	       ///< Current owner-writable bank.
	uint8_t telemetry_standby_bank_{UINT8_MAX};	       ///< Same-epoch clean standby.
	uint8_t telemetry_reserved_bank_{UINT8_MAX};	       ///< Target reserve.
	uint8_t telemetry_free_bank_{UINT8_MAX};	       ///< Cold-owned unassigned slot identity.
	bool telemetry_old_banks_retained_{false};	       ///< Missing standby is exact old-generation ownership.
	bool telemetry_worker_quiesced_{false};		       ///< Whether no worker can consume a returned bank.
	std::optional<runtime_telemetry_bank_token>
		telemetry_reclaimed_transfer_;				     ///< Immutable issued-retirement record.
	kinetum::dp::worker_telemetry_channel *telemetry_channel_{nullptr};  ///< Exact transfer authority.
	std::atomic<bool> operation_active_{false};			     ///< Exclusive operation claim publication.
};

/**
 * @brief Return immutable identity from a borrowed lifecycle context.
 *
 * @param context Active borrowed lifecycle context.
 * @return Owner-lifetime immutable identity and placement.
 */
[[nodiscard]] const lifecycle_context_identity &lifecycle_identity(const ::kinetum_lifecycle_ctx &context) noexcept;

/**
 * @brief Return the exact cold phase of a borrowed lifecycle context.
 *
 * @param context Active borrowed lifecycle context.
 * @return INIT, PREPARE, RETIRE, or FINI for the current operation.
 */
[[nodiscard]] lifecycle_phase lifecycle_current_phase(const ::kinetum_lifecycle_ctx &context) noexcept;

/**
 * @brief Return the exact epoch of a borrowed lifecycle context.
 *
 * @param context Active borrowed lifecycle context.
 * @return Zero for INIT/FINI or the exact PREPARE/RETIRE epoch.
 */
[[nodiscard]] uint64_t lifecycle_current_epoch(const ::kinetum_lifecycle_ctx &context) noexcept;

/**
 * @brief Acquire-observe cooperative cancellation for the current operation.
 *
 * @param context Active borrowed lifecycle context.
 * @return true after the coordinator publishes cancellation.
 */
[[nodiscard]] bool lifecycle_cancellation_requested(const ::kinetum_lifecycle_ctx &context) noexcept;

/**
 * @brief Return the immutable current-operation deadline.
 *
 * @param context Active borrowed lifecycle context.
 * @return Admission-time steady-clock deadline.
 */
[[nodiscard]] std::chrono::steady_clock::time_point lifecycle_deadline(const ::kinetum_lifecycle_ctx &context) noexcept;

/**
 * @brief Allocate bounded long-lived context memory during INIT.
 *
 * @param context Borrowed INIT lifecycle context.
 * @param size Positive byte count.
 * @param alignment Power-of-two pointer alignment.
 * @param zero_initialize Whether returned memory must be zeroed.
 * @return Tracked memory, or a fail-closed status.
 */
[[nodiscard]] kinetum::common::status_or<void *> lifecycle_allocate_long_lived(const ::kinetum_lifecycle_ctx &context,
									       std::size_t size, std::size_t alignment,
									       bool zero_initialize) noexcept;

/**
 * @brief Release one exact long-lived allocation during INIT rollback or FINI.
 *
 * @param context Borrowed INIT or FINI lifecycle context.
 * @param pointer Exact tracked allocation start.
 * @return OK after one release; non-OK for phase, pointer, or double-release faults.
 */
[[nodiscard]] kinetum::common::status lifecycle_release_long_lived(const ::kinetum_lifecycle_ctx &context,
								   void *pointer) noexcept;

/**
 * @brief Allocate bounded per-epoch memory during PREPARE.
 *
 * @param context Borrowed PREPARE lifecycle context.
 * @param size Positive byte count.
 * @param alignment Power-of-two object alignment.
 * @param zero_initialize Whether returned memory must be zeroed.
 * @return Storage owned by the exact prepared arena, or failure.
 */
[[nodiscard]] kinetum::common::status_or<void *> lifecycle_allocate_epoch(const ::kinetum_lifecycle_ctx &context,
									  std::size_t size, std::size_t alignment,
									  bool zero_initialize) noexcept;

/**
 * @brief Register one owner-local counter during INIT.
 *
 * @param context Borrowed INIT lifecycle context.
 * @param name Nonempty printable-ASCII name shorter than the fixed capacity.
 * @return Exact counter handle, or fail-closed status.
 */
[[nodiscard]] kinetum::common::status_or<kinetum_counter_t>
lifecycle_register_counter(const ::kinetum_lifecycle_ctx &context, std::string_view name) noexcept;

/**
 * @brief Register one owner-local HDR histogram during INIT.
 *
 * @param context Borrowed INIT lifecycle context.
 * @param name Nonempty printable-ASCII name shorter than the fixed capacity.
 * @param highest_trackable_value Positive inclusive sample ceiling.
 * @param significant_digits Precision in the inclusive range 1..5.
 * @return Exact histogram handle, or fail-closed status.
 */
[[nodiscard]] kinetum::common::status_or<kinetum_histogram_t>
lifecycle_register_histogram(const ::kinetum_lifecycle_ctx &context, std::string_view name,
			     uint64_t highest_trackable_value, int32_t significant_digits) noexcept;

/**
 * @brief Publish one cold diagnostic without exposing platform logging state.
 *
 * @param context Borrowed lifecycle context.
 * @param level Diagnostic severity.
 * @param message Message borrowed for this call only.
 */
void lifecycle_log(const ::kinetum_lifecycle_ctx &context, lifecycle_log_level level,
		   std::string_view message) noexcept;

}  // namespace kinetum::dp::lifecycle
