// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file worker_runtime_telemetry.hpp
 * @brief Exact-NUMA owner-local engine, stream, and stage telemetry banks.
 * @author Fleming Patel
 *
 * One packet worker updates one active plain bank. Ordinary publication swaps
 * to a clean same-epoch standby; transition activation swaps to a pre-reserved
 * target-epoch bank. Completed banks cross to the cold aggregator only through
 * the worker's telemetry channel.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

#include <kinetum/algo/platform.hpp>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/epoch/epoch_protocol_fault.hpp"
#include "src/dp/numa_memory.hpp"
#include "src/dp/runtime_telemetry_bank.hpp"
#include "src/dp/worker_telemetry_channel.hpp"

namespace kinetum::dp
{

/** @brief Plain exact engine counters in one interval bank. */
struct worker_engine_telemetry_counters {
	uint64_t dropped_packets{0};  ///< Exact terminal record retirements.
	uint64_t fanout_overflow{0};  ///< Additional branches refused by bounded ownership.
};
static_assert(sizeof(worker_engine_telemetry_counters) == 16u);
static_assert(alignof(worker_engine_telemetry_counters) == 8u);
static_assert(offsetof(worker_engine_telemetry_counters, dropped_packets) == 0u);
static_assert(offsetof(worker_engine_telemetry_counters, fanout_overflow) == 8u);
static_assert(std::is_standard_layout_v<worker_engine_telemetry_counters>);
static_assert(std::is_trivially_copyable_v<worker_engine_telemetry_counters>);

/**
 * @brief Owner-local software transfers and rejections for one I/O stream.
 *
 * UINT64_MAX marks exhausted accounting. Only completed banks are read by
 * another thread; neither TX acceptance nor rejection measures wire delivery.
 */
struct worker_stream_telemetry_counters {
	uint64_t packets{0};	       ///< Records transferred across the I/O boundary.
	uint64_t bytes{0};	       ///< Bytes in those exact transferred records.
	uint64_t rejected_packets{0};  ///< Records discarded without an I/O transfer.
};
static_assert(sizeof(worker_stream_telemetry_counters) == 24u);
static_assert(alignof(worker_stream_telemetry_counters) == 8u);
static_assert(offsetof(worker_stream_telemetry_counters, packets) == 0u);
static_assert(offsetof(worker_stream_telemetry_counters, bytes) == 8u);
static_assert(offsetof(worker_stream_telemetry_counters, rejected_packets) == 16u);
static_assert(std::is_standard_layout_v<worker_stream_telemetry_counters>);
static_assert(std::is_trivially_copyable_v<worker_stream_telemetry_counters>);

/** @brief Plain exact accounting for one owned stage instance. */
struct worker_stage_telemetry_counters {
	uint64_t in_packets{0};	      ///< Stage execution entries.
	uint64_t out_packets{0};      ///< Exact output ownership transfers.
	uint64_t dropped_packets{0};  ///< Exact stage-attributed terminal rejections.
	uint64_t in_bytes{0};	      ///< Bytes entering stage execution.
	uint64_t out_bytes{0};	      ///< Bytes transferred beyond the stage.
};
static_assert(std::is_standard_layout_v<worker_stage_telemetry_counters>);
static_assert(std::is_trivially_copyable_v<worker_stage_telemetry_counters>);

/** @brief Immutable completed worker bank observed by the cold aggregator. */
struct worker_runtime_telemetry_bank_view {
	worker_engine_telemetry_counters engine{};			     ///< Completed interval engine counters.
	std::span<const worker_stream_telemetry_counters> streams;	     ///< Compiled worker-owned stream order.
	std::span<const worker_stage_telemetry_counters> stages;	     ///< Compiled worker-owned stage order.
	std::array<uint64_t, EPOCH_PROTOCOL_FAULT_COUNT> protocol_faults{};  ///< Completed typed fault counts.
	uint64_t skipped_publications{0};				     ///< Cadence swaps refused without standby.
};

/** @brief Bounded outcome of the sole per-turn telemetry cadence comparison. */
struct worker_runtime_telemetry_service_result {
	runtime_telemetry_return_need return_need{runtime_telemetry_return_need::NONE};	 ///< Return-ring action.
	bool cadence_due{false};  ///< Whether this turn starts one module-context sweep.
};
static_assert(std::is_trivially_copyable_v<worker_runtime_telemetry_service_result>);

/**
 * @brief One worker's three-bank telemetry ownership authority.
 *
 * @par Thread Safety
 * The packet worker is the sole writer of active/standby selection and active
 * payload. The serialized generation owner moves only the explicit cold free-
 * slot identity into or out of target reserve before trigger publication; it
 * never searches worker-mutated banks. The cold aggregator accesses only SPSC-
 * transferred published banks, then returns cleared ownership through the
 * reverse SPSC direction. Construction, final retirement, and destruction are
 * externally serialized.
 *
 * @par Performance
 * Packet accounting is always-inline plain arithmetic through one pre-resolved
 * exact-NUMA cache-line view. The recurring service performs one owner-local
 * deadline comparison. No packet/cadence operation allocates, locks, logs,
 * formats, reads a clock, invokes a syscall, or performs a shared atomic RMW.
 */
class worker_runtime_telemetry final {
    public:
	/**
	 * @brief Create one exact-NUMA three-bank owner.
	 * @param runtime_generation Exact nonzero runtime generation.
	 * @param worker_index Exact compact worker identity.
	 * @param worker_numa_node Exact owner-worker NUMA node.
	 * @param stage_instance_indices Exact compiled stages owned by this worker.
	 * @param io_stream_indices Sorted exact compiled streams owned by this worker; empty is valid.
	 * @param cadence_ns Exact nonzero publication cadence in nanoseconds.
	 * @param channel Exact bank transfer authority that outlives this owner.
	 * @return Complete unbound owner or a fail-closed allocation status.
	 */
	[[nodiscard]] static common::status_or<std::unique_ptr<worker_runtime_telemetry>>
	create(uint64_t runtime_generation, uint32_t worker_index, int32_t worker_numa_node,
	       std::span<const uint32_t> stage_instance_indices, std::span<const uint32_t> io_stream_indices,
	       uint64_t cadence_ns, worker_telemetry_channel &channel);

	worker_runtime_telemetry(const worker_runtime_telemetry &) = delete;
	worker_runtime_telemetry &operator=(const worker_runtime_telemetry &) = delete;
	worker_runtime_telemetry(worker_runtime_telemetry &&) = delete;
	worker_runtime_telemetry &operator=(worker_runtime_telemetry &&) = delete;
	/** @brief Destroy only after every bank and transfer token is reclaimed. */
	~worker_runtime_telemetry();

	/**
	 * @brief Bind two banks to the fixed bootstrap epoch on the owner worker.
	 * @param epoch Exact nonzero Bootstrap epoch.
	 * @param now_ns Sole cached monotonic timestamp for initial cadence.
	 */
	void bind_bootstrap_epoch(uint64_t epoch, uint64_t now_ns) noexcept;
	/**
	 * @brief Reserve the sole free bank for one future epoch before PREPARED.
	 * @param from_epoch Exact active epoch.
	 * @param to_epoch Exact transition target epoch.
	 * @return OK after one all-or-none reserve; otherwise no state changes.
	 */
	[[nodiscard]] common::status reserve_target_epoch(uint64_t from_epoch, uint64_t to_epoch) noexcept;
	/**
	 * @brief Release one unused target reserve during pre-commit cleanup.
	 * @param to_epoch Exact reserved target being aborted.
	 */
	void discard_target_epoch(uint64_t to_epoch) noexcept;
	/**
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact reserved target epoch.
	 * @return true only when target activation can publish without failure.
	 */
	[[nodiscard]] bool preflight_activate(uint64_t from_epoch, uint64_t to_epoch) const noexcept;
	/**
	 * @param now_ns Candidate sole cached activation timestamp.
	 * @return true only when the next cadence deadline is representable.
	 */
	[[nodiscard]] bool activation_timestamp_representable(uint64_t now_ns) const noexcept;
	/**
	 * @brief Prove one same-turn owner publication batch fits the shared channel.
	 * @param publication_count Exact worker-plus-context publication population.
	 * @return true only when the complete prefix is non-failing.
	 */
	[[nodiscard]] bool preflight_completed_publications(std::size_t publication_count) const noexcept;
	/**
	 * @brief Publish final old truth and switch to the exact target reserve.
	 * @param from_epoch Exact old execution epoch.
	 * @param to_epoch Exact target execution epoch.
	 * @param now_ns Sole cached worker timestamp.
	 */
	void activate_target_epoch(uint64_t from_epoch, uint64_t to_epoch, uint64_t now_ns) noexcept;

	/**
	 * @brief Perform the sole per-turn deadline comparison and due worker swap.
	 * @param now_ns Sole cached worker timestamp.
	 * @return Whether cadence fired and what return-ring work follows.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE worker_runtime_telemetry_service_result
	service_turn(uint64_t now_ns) noexcept
	{
		if (KINETUM_LIKELY(now_ns < next_publication_ns_)) {
			return {};
		}
		return service_due_(now_ns);
	}
	/**
	 * @brief Accept one return token dispatched by the sole worker-channel consumer.
	 * @param token Exact cleared-bank transfer.
	 */
	void accept_returned(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @brief Consume one raw returned token as the sole worker-channel consumer.
	 * @param[out] token Replaced only after one successful ownership transfer.
	 * @return true after one token is consumed; false when the lane is empty.
	 */
	[[nodiscard]] bool take_returned(runtime_telemetry_bank_token &token) noexcept;
	/** @return true when the owner-worker return ring still contains a token. */
	[[nodiscard]] bool returned_tokens_pending() const noexcept;
	/**
	 * @param epoch Exact active epoch to publish at shutdown.
	 * @return true when final publication cannot strand a cadence return.
	 */
	[[nodiscard]] bool preflight_shutdown(uint64_t epoch) const noexcept;
	/**
	 * @brief Publish the final active bank before worker exit.
	 * @param epoch Exact active epoch.
	 * @param now_ns Sole cached worker timestamp.
	 */
	void publish_shutdown(uint64_t epoch, uint64_t now_ns) noexcept;
	/** @brief Record that the sole worker has exited and cannot consume returns. */
	void mark_owner_quiesced() noexcept;

	/**
	 * @brief Account one completed I/O burst in its sole owner's active bank.
	 * @param stream_ordinal Pre-resolved owner-local stream row.
	 * @param transferred_count Exact records admitted on RX or accepted on TX.
	 * @param bytes Sum of those record lengths, zero only for no transfer.
	 * @param rejected_count Inputs discarded before RX admission or a retired TX suffix.
	 */
	KINETUM_ALWAYS_INLINE void record_stream(uint32_t stream_ordinal, uint16_t transferred_count, uint64_t bytes,
						 uint16_t rejected_count) noexcept
	{
		if (hot_->streams == nullptr || stream_ordinal >= hot_->stream_count ||
		    ((transferred_count == 0u) != (bytes == 0u)) || bytes < transferred_count) {
			std::terminate();
		}
		auto &counter = hot_->streams[stream_ordinal];
		counter.packets += std::min(UINT64_MAX - counter.packets, uint64_t{transferred_count});
		counter.bytes += std::min(UINT64_MAX - counter.bytes, bytes);
		counter.rejected_packets += std::min(UINT64_MAX - counter.rejected_packets, uint64_t{rejected_count});
	}
	/** @brief Add one exact terminal record retirement. */
	KINETUM_ALWAYS_INLINE void record_drop() noexcept
	{
		auto *engine = hot_->engine;
		if (engine == nullptr) {
			std::terminate();
		}
		++engine->dropped_packets;
	}
	/** @brief Add one refused fan-out branch. */
	KINETUM_ALWAYS_INLINE void record_fanout_overflow() noexcept
	{
		auto *engine = hot_->engine;
		if (engine == nullptr) {
			std::terminate();
		}
		++engine->fanout_overflow;
	}
	/**
	 * @brief Add one rare exact protocol-fault classification.
	 * @param code Declared typed fault code.
	 */
	KINETUM_ALWAYS_INLINE void record_protocol_fault(epoch_protocol_fault_code code) noexcept
	{
		if (hot_->protocol_faults == nullptr || !valid_epoch_protocol_fault_code(code)) {
			std::terminate();
		}
		auto &counter = hot_->protocol_faults[epoch_protocol_fault_ordinal(code)];
		if (counter != UINT64_MAX) {
			++counter;
		}
	}
	/** @brief Record one coalesced module-sweep cadence that could not start. */
	KINETUM_ALWAYS_INLINE void record_publication_skip() noexcept
	{
		auto *engine = hot_->engine;
		if (engine == nullptr || hot_->bank_index >= RUNTIME_TELEMETRY_BANK_COUNT) {
			std::terminate();
		}
		auto &bank = banks_[hot_->bank_index];
		if (bank.state != bank_state::ACTIVE || bank.epoch != active_epoch_) {
			std::terminate();
		}
		if (bank.skipped_publications != UINT64_MAX) {
			++bank.skipped_publications;
		}
	}
	/**
	 * @brief Record one nonempty prefix entering an exact stage.
	 * @param stage_ordinal Pre-resolved owner-local stage row.
	 * @param packets Exact positive number of input records.
	 * @param bytes Sum of the prefix's positive record lengths.
	 */
	KINETUM_ALWAYS_INLINE void record_stage_input(uint32_t stage_ordinal, uint16_t packets, uint64_t bytes) noexcept
	{
		auto *stages = hot_->stages;
		if (stages == nullptr || stage_ordinal >= hot_->stage_count || packets == 0u || bytes < packets) {
			std::terminate();
		}
		auto &counter = stages[stage_ordinal];
		counter.in_packets += packets;
		counter.in_bytes += bytes;
	}
	/**
	 * @brief Record one exact stage output ownership transfer.
	 * @param stage_ordinal Pre-resolved owner-local stage row.
	 * @param bytes Exact positive transferred record length.
	 */
	KINETUM_ALWAYS_INLINE void record_stage_output(uint32_t stage_ordinal, uint64_t bytes) noexcept
	{
		auto *stages = hot_->stages;
		if (stages == nullptr || stage_ordinal >= hot_->stage_count || bytes == 0u) {
			std::terminate();
		}
		auto &counter = stages[stage_ordinal];
		++counter.out_packets;
		counter.out_bytes += bytes;
	}
	/**
	 * @brief Record one exact stage-attributed terminal rejection.
	 * @param stage_ordinal Pre-resolved owner-local stage row.
	 */
	KINETUM_ALWAYS_INLINE void record_stage_drop(uint32_t stage_ordinal) noexcept
	{
		auto *stages = hot_->stages;
		if (stages == nullptr || stage_ordinal >= hot_->stage_count) {
			std::terminate();
		}
		++stages[stage_ordinal].dropped_packets;
	}

	/**
	 * @param stage_instance_index Exact global stage identity.
	 * @return Local ordinal for one exact owned global stage, or UINT32_MAX.
	 */
	[[nodiscard]] uint32_t stage_ordinal(uint32_t stage_instance_index) const noexcept;
	/**
	 * @param io_stream_index Exact global stream identity.
	 * @return Cold-resolved local ordinal, or UINT32_MAX when this worker does not own it.
	 */
	[[nodiscard]] uint32_t stream_ordinal(uint32_t io_stream_index) const noexcept;
	/** @return Exact active telemetry epoch, or zero before Bootstrap. */
	[[nodiscard]] uint64_t active_epoch() const noexcept;
	/** @return Exact materialized runtime generation bound at construction. */
	[[nodiscard]] uint64_t runtime_generation() const noexcept;
	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept;
	/** @return Exact plan-derived publication cadence in nanoseconds. */
	[[nodiscard]] uint64_t cadence_ns() const noexcept;
	/** @return Exact worker NUMA node. */
	[[nodiscard]] int32_t numa_node() const noexcept;
	/** @return Exact usable bytes in the one worker mapping. */
	[[nodiscard]] std::size_t storage_bytes() const noexcept;
	/** @return Exact local-ordinal to global-stage projection. */
	[[nodiscard]] std::span<const uint32_t> stage_instance_indices() const noexcept;
	/** @return Sorted local-ordinal to global-stream projection. */
	[[nodiscard]] std::span<const uint32_t> io_stream_indices() const noexcept;
	/**
	 * @param channel Candidate immutable transport object.
	 * @return true only for the exact channel borrowed at construction.
	 */
	[[nodiscard]] bool owns_channel(const worker_telemetry_channel &channel) const noexcept;

	/**
	 * @brief Borrow one immutable bank after consuming its channel token.
	 * @param token Exact completed-bank ownership token.
	 * @return Immutable bank view or a fail-closed identity error.
	 */
	[[nodiscard]] common::status_or<worker_runtime_telemetry_bank_view>
	completed_bank(const runtime_telemetry_bank_token &token) const noexcept;
	/**
	 * @brief Complete one exact cold merge and return or retain its cleared bank.
	 * @param token Exact token whose payload was merged once.
	 */
	void complete_aggregation(const runtime_telemetry_bank_token &token) noexcept;
	/**
	 * @param epoch Candidate exact old epoch.
	 * @return true only when every old-epoch bank has completed aggregation.
	 */
	[[nodiscard]] bool epoch_aggregated(uint64_t epoch) const noexcept;
	/**
	 * @brief Accept the cold aggregator's exact completed-epoch verdict.
	 * @param epoch Exact epoch whose two retained banks were observed.
	 */
	void mark_epoch_aggregated(uint64_t epoch) noexcept;
	/**
	 * @brief Reclaim an aggregated old epoch after exact reader grace.
	 * @param epoch Exact old epoch.
	 * @param active_epoch Exact target epoch, or zero for final shutdown.
	 * @return Cleared target-bank transfer when one target worker remains.
	 */
	[[nodiscard]] std::optional<runtime_telemetry_bank_token> retire_epoch(uint64_t epoch,
									       uint64_t active_epoch) noexcept;

	/** @return true only when destruction has no bank or transfer ownership. */
	[[nodiscard]] bool empty() const noexcept;

    private:
	/** @brief Cache the owner worker's pre-resolved writable telemetry bank. */
	struct alignas(64) hot_bank_view {
		worker_engine_telemetry_counters *engine{nullptr};   ///< Pre-resolved active engine counters.
		worker_stream_telemetry_counters *streams{nullptr};  ///< Pre-resolved active stream counters.
		worker_stage_telemetry_counters *stages{nullptr};    ///< Pre-resolved active stage counters.
		uint64_t *protocol_faults{nullptr};		     ///< Pre-resolved active typed fault counters.
		uint32_t stream_count{0};			     ///< Exact compact stream population.
		uint32_t stage_count{0};			     ///< Exact compact stage population.
		uint8_t bank_index{UINT8_MAX};			     ///< Exact active bank identity.
		uint8_t padding[23]{};				     ///< Explicit cache-line completion.
	};
	static_assert(sizeof(hot_bank_view) == 64u);
	static_assert(alignof(hot_bank_view) == 64u);
	static_assert(offsetof(hot_bank_view, engine) == 0u);
	static_assert(offsetof(hot_bank_view, streams) == 8u);
	static_assert(offsetof(hot_bank_view, stages) == 16u);
	static_assert(offsetof(hot_bank_view, protocol_faults) == 24u);
	static_assert(offsetof(hot_bank_view, stream_count) == 32u);
	static_assert(offsetof(hot_bank_view, stage_count) == 36u);
	static_assert(offsetof(hot_bank_view, bank_index) == 40u);
	static_assert(offsetof(hot_bank_view, padding) == 41u);
	static_assert(std::is_standard_layout_v<hot_bank_view>);
	static_assert(std::is_trivially_copyable_v<hot_bank_view>);

	/** @brief Enumerate one telemetry bank's exact linear ownership state. */
	enum class bank_state : uint8_t {
		FREE = 0,
		ACTIVE,
		STANDBY,
		RESERVED,
		PUBLISHED,
		AGGREGATED_RETAINED,
		RETURNING,
	};

	/** @brief Store one cache-line-complete bank's counters and transfer identity. */
	struct alignas(64) bank_header {
		worker_engine_telemetry_counters engine{};  ///< Plain interval engine counters.
		std::array<uint64_t, EPOCH_PROTOCOL_FAULT_COUNT> protocol_faults{};  ///< Typed rare faults.
		uint64_t epoch{0};						     ///< Exact assigned epoch.
		uint64_t generation{0};			  ///< Nonzero publication reuse generation.
		uint64_t skipped_publications{0};	  ///< Cadence misses accumulated in this bank.
		runtime_telemetry_bank_token transfer{};  ///< Exact live transfer identity, or empty.
		bank_state state{bank_state::FREE};	  ///< Exact linear ownership state.
		uint8_t padding[55]{};			  ///< Fixed zero padding.
	};
	static_assert(sizeof(bank_header) == 256u);
	static_assert(sizeof(bank_header) % 64u == 0u);
	static_assert(alignof(bank_header) == 64u);
	static_assert(offsetof(bank_header, engine) == 0u);
	static_assert(offsetof(bank_header, protocol_faults) == 16u);
	static_assert(offsetof(bank_header, epoch) == 120u);
	static_assert(offsetof(bank_header, generation) == 128u);
	static_assert(offsetof(bank_header, skipped_publications) == 136u);
	static_assert(offsetof(bank_header, transfer) == 144u);
	static_assert(offsetof(bank_header, state) == 200u);
	static_assert(offsetof(bank_header, padding) == 201u);
	static_assert(std::is_standard_layout_v<bank_header>);
	static_assert(std::is_trivially_copyable_v<bank_header>);

	/** @brief Describe checked offsets within one worker's exact-NUMA mapping. */
	struct storage_layout {
		std::size_t hot_offset{0};	    ///< One owner-local pre-resolved bank view.
		std::size_t headers_offset{0};	    ///< Three bank headers.
		std::size_t stages_offset{0};	    ///< Three dense stage-counter arrays.
		std::size_t stage_bank_stride{0};   ///< Cache-line-complete bytes per stage bank.
		std::size_t streams_offset{0};	    ///< Three dense stream-counter arrays.
		std::size_t stream_bank_stride{0};  ///< Cache-line-complete bytes per stream bank.
		std::size_t total_bytes{0};	    ///< Complete mapping extent.
	};

	/**
	 * @brief Adopt one fully placement-constructed exact-NUMA owner.
	 * @param runtime_generation Exact generation identity.
	 * @param worker_index Exact compact worker identity.
	 * @param numa_node Exact worker NUMA node.
	 * @param cadence_ns Exact plan cadence.
	 * @param channel Exact token transport.
	 * @param stage_indices Local-to-global stage projection.
	 * @param stage_to_ordinal Global-to-local stage projection.
	 * @param stream_indices Sorted local-to-global stream projection.
	 * @param region Sole mapping owner.
	 * @param hot Placement-constructed hot selector.
	 * @param headers Placement-constructed bank headers.
	 * @param stages Placement-constructed stage-counter extent.
	 * @param stage_bank_stride Cache-line-complete bytes between stage banks.
	 * @param streams Placement-constructed stream-counter extent, or null when empty.
	 * @param stream_bank_stride Cache-line-complete bytes between stream banks.
	 */
	worker_runtime_telemetry(uint64_t runtime_generation, uint32_t worker_index, int32_t numa_node,
				 uint64_t cadence_ns, worker_telemetry_channel &channel,
				 std::vector<uint32_t> stage_indices, std::vector<uint32_t> stage_to_ordinal,
				 std::vector<uint32_t> stream_indices, numa_memory_region region, hot_bank_view *hot,
				 bank_header *headers, worker_stage_telemetry_counters *stages,
				 std::size_t stage_bank_stride, worker_stream_telemetry_counters *streams,
				 std::size_t stream_bank_stride) noexcept;

	/**
	 * @brief Derive one checked exact-NUMA mapping layout.
	 * @param stage_count Exact positive worker-owned stage population.
	 * @param stream_count Exact worker-owned stream population; zero is valid.
	 * @return Complete offsets/extent or an overflow status.
	 */
	[[nodiscard]] static common::status_or<storage_layout> compute_layout(std::size_t stage_count,
									      std::size_t stream_count) noexcept;
	/**
	 * @brief Perform one due cadence swap outside the recurring packet-loop path.
	 * @param now_ns Sole cached worker timestamp at or after the deadline.
	 * @return Due cadence and exact return-ring work classification.
	 */
	[[nodiscard]] KINETUM_COLD KINETUM_NOINLINE worker_runtime_telemetry_service_result
	service_due_(uint64_t now_ns) noexcept;
	/**
	 * @param bank_index Exact bank slot.
	 * @return Mutable stage-bank start.
	 */
	[[nodiscard]] worker_stage_telemetry_counters *stage_bank_(uint8_t bank_index) noexcept;
	/**
	 * @param bank_index Exact bank slot.
	 * @return Immutable stage-bank start.
	 */
	[[nodiscard]] const worker_stage_telemetry_counters *stage_bank_(uint8_t bank_index) const noexcept;
	/**
	 * @param bank_index Exact bank slot.
	 * @return Mutable stream-bank start, or null for a stream-free worker.
	 */
	[[nodiscard]] worker_stream_telemetry_counters *stream_bank_(uint8_t bank_index) noexcept;
	/**
	 * @param bank_index Exact bank slot.
	 * @return Immutable stream-bank start, or null for a stream-free worker.
	 */
	[[nodiscard]] const worker_stream_telemetry_counters *stream_bank_(uint8_t bank_index) const noexcept;
	/**
	 * @brief Publish one exact bank as the pre-resolved owner-writable view.
	 * @param bank_index Exact selected bank.
	 */
	void select_active_bank_(uint8_t bank_index) noexcept;
	/**
	 * @brief Clear one exact bank payload without changing identity state.
	 * @param bank_index Exact bank owned by the caller.
	 */
	void clear_bank_(uint8_t bank_index) noexcept;
	/**
	 * @brief Remove the transfer identity from one proven-unowned bank.
	 * @param bank_index Exact bank under caller-owned state transition.
	 */
	void reset_bank_transfer_(uint8_t bank_index) noexcept;
	/**
	 * @brief Transfer one immutable bank to the completed ring.
	 * @param bank_index Exact completed bank.
	 * @param reason Cadence, activation, or shutdown reason.
	 * @param now_ns Sole cached worker timestamp.
	 * @param companion_bank_index Clean retained companion or UINT8_MAX.
	 */
	void publish_bank_(uint8_t bank_index, runtime_telemetry_publication_reason reason, uint64_t now_ns,
			   uint8_t companion_bank_index = UINT8_MAX) noexcept;
	/**
	 * @brief Validate one completed token against immutable bank identity.
	 * @param token Candidate token.
	 * @param bank Exact named bank.
	 * @return true only for complete exact ownership identity.
	 */
	[[nodiscard]] bool token_matches_(const runtime_telemetry_bank_token &token,
					  const bank_header &bank) const noexcept;

	uint64_t runtime_generation_{0};		 ///< Exact materialized generation.
	uint32_t worker_index_{0};			 ///< Exact compact worker identity.
	int32_t numa_node_{-1};				 ///< Exact owner NUMA node.
	uint64_t cadence_ns_{0};			 ///< Exact plan-derived cadence.
	uint64_t next_publication_ns_{0};		 ///< Owner-local next cadence deadline.
	uint64_t active_epoch_{0};			 ///< Exact active bank epoch.
	uint64_t prepared_epoch_{0};			 ///< Exact reserved target epoch.
	uint64_t aggregated_epoch_{0};			 ///< Cold-confirmed fully aggregated epoch.
	uint8_t active_bank_{UINT8_MAX};		 ///< Current owner-writable bank.
	uint8_t standby_bank_{UINT8_MAX};		 ///< Clean same-epoch ordinary standby.
	uint8_t reserved_bank_{UINT8_MAX};		 ///< Cold-prepared target reserve.
	uint8_t free_bank_{UINT8_MAX};			 ///< Cold-owned unassigned slot identity.
	bool old_banks_retained_for_transition_{false};	 ///< Missing standby is exact old-generation ownership.
	bool owner_quiesced_{false};			 ///< Whether no worker can consume a returned bank.
	worker_telemetry_channel &channel_;		 ///< Exact cross-thread token transport.
	std::vector<uint32_t> stage_indices_;		 ///< Local ordinal to global stage identity.
	std::vector<uint32_t> stage_to_ordinal_;	 ///< Global stage to local ordinal or UINT32_MAX.
	std::vector<uint32_t> stream_indices_;		 ///< Sorted local ordinal to global stream identity.
	numa_memory_region region_;			 ///< Sole exact-NUMA three-bank mapping.
	hot_bank_view *hot_{nullptr};			 ///< Exact-NUMA pre-resolved packet-path view.
	bank_header *banks_{nullptr};			 ///< Three placement-constructed headers.
	worker_stage_telemetry_counters *stage_counters_{nullptr};    ///< Three dense stage arrays.
	worker_stream_telemetry_counters *stream_counters_{nullptr};  ///< Three dense stream arrays, or null.
	std::size_t stream_bank_stride_{0};  ///< Cache-line-complete byte stride between stream banks.
	std::size_t stage_bank_stride_{0};   ///< Cache-line-complete byte stride between stage banks.
};

}  // namespace kinetum::dp
