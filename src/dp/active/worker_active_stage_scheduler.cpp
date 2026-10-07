// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_active_stage_scheduler.cpp
 * @brief Instance-scoped synchronous and tracked-async active-stage scheduler implementation.
 * @author Fleming Patel
 */

#include "src/dp/active/worker_active_stage_scheduler.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/queue.hpp>
#include <kinetum/algo/timer_wheel.hpp>

#include "src/common/runtime_sizing.hpp"
#include "src/dp/active/worker_async_work.hpp"
#include "src/dp/epoch/worker_epoch_ledger.hpp"
#include "src/dp/numa_memory.hpp"
#include "src/provider/compiled_provider_topology.hpp"

namespace kinetum::dp
{
namespace
{

/** Absence sentinel for a compact scheduler slot. */
constexpr uint32_t INVALID_INDEX = std::numeric_limits<uint32_t>::max();
/** Maximum active work serviced by one scheduling turn. */
constexpr std::size_t WORK_BUDGET = common::runtime_sizing::PACKET_MAX_BURST_SIZE;
static_assert(KINETUM_MAX_BURST < UINT8_MAX);
static_assert(WORK_BUDGET <= UINT32_MAX / KINETUM_MAX_BURST);
/** Completion prefix budget leaving capacity for other active work. */
constexpr std::size_t ASYNC_COMPLETION_PREFIX_BUDGET = (WORK_BUDGET + 1u) / 2u;
static_assert(ASYNC_COMPLETION_PREFIX_BUDGET > 0u && ASYNC_COMPLETION_PREFIX_BUDGET < WORK_BUDGET);
/** Nanosecond quantum of the owner-local active timer wheel. */
constexpr uint64_t ACTIVE_TIMER_QUANTUM_NS = UINT64_C(1000000);

/**
 * @brief Add one checked slab extent after required alignment.
 * @param count Number of elements to reserve.
 * @param cursor Current slab end, advanced only on successful arithmetic.
 * @param offset Aligned start of the reserved extent, written on success.
 * @return true after overflow-free alignment and extent addition; false without changing outputs.
 * @tparam value_type Element type defining the extent's size and alignment.
 */
template <typename value_type>
[[nodiscard]] bool append_extent(std::size_t count, std::size_t &cursor, std::size_t &offset) noexcept
{
	if (count > std::numeric_limits<std::size_t>::max() / sizeof(value_type)) {
		return false;
	}
	const std::size_t alignment = alignof(value_type);
	const std::size_t remainder = cursor % alignment;
	const std::size_t padding = remainder == 0u ? 0u : alignment - remainder;
	const std::size_t bytes = count * sizeof(value_type);
	if (padding > std::numeric_limits<std::size_t>::max() - cursor ||
	    bytes > std::numeric_limits<std::size_t>::max() - cursor - padding) {
		return false;
	}
	cursor += padding;
	offset = cursor;
	cursor += bytes;
	return true;
}

/**
 * @brief Checked multiplication for variable control-payload storage.
 * @param left First size factor.
 * @param right Second size factor.
 * @param out Product written only when representable.
 * @return true for an overflow-free product; false otherwise.
 */
[[nodiscard]] bool multiply_size(std::size_t left, std::size_t right, std::size_t &out) noexcept
{
	if (left != 0u && right > std::numeric_limits<std::size_t>::max() / left) {
		return false;
	}
	out = left * right;
	return true;
}

/**
 * @brief Build one opaque non-invalid handle value.
 * @param generation Nonzero reuse generation.
 * @param slot Exact compact slot identity.
 * @return Packed generation/slot identity; zero generation or the invalid combined sentinel terminates.
 */
[[nodiscard]] uint64_t make_handle(uint32_t generation, uint32_t slot) noexcept
{
	const uint64_t result = (static_cast<uint64_t>(generation) << 32u) | slot;
	if (generation == 0u || result == UINT64_MAX) {
		std::terminate();
	}
	return result;
}

/**
 * @param value Opaque packed handle value.
 * @return Low 32-bit slot identity without validating liveness.
 */
[[nodiscard]] uint32_t handle_slot(uint64_t value) noexcept
{
	return static_cast<uint32_t>(value & UINT32_MAX);
}

/**
 * @param value Opaque packed handle value.
 * @return High 32-bit reuse generation without validating liveness.
 */
[[nodiscard]] uint32_t handle_generation(uint64_t value) noexcept
{
	return static_cast<uint32_t>(value >> 32u);
}

/**
 * @brief Advance one nonzero handle generation without accepting wrap.
 * @param current Current generation; UINT32_MAX fails stop before increment.
 * @return Next nonzero reuse generation.
 */
[[nodiscard]] uint32_t next_generation(uint32_t current) noexcept
{
	if (current == UINT32_MAX) {
		std::terminate();
	}
	return current + 1u;
}

}  // namespace

/** @brief Complete private storage, validation, and owner-turn implementation. */
class worker_active_stage_scheduler::implementation final {
    public:
	/** @brief Exact worker-local scheduler phase, never a global transition authority. */
	enum class phase : uint8_t {
		UNBOUND = 0,	   ///< Bootstrap view has not been bound.
		OPEN,		   ///< Ordinary active work is admitted.
		TRANSITION_DRAIN,  ///< New old-epoch work is closed before activation.
		SHUTDOWN_DRAIN,	   ///< New work is permanently closed for teardown.
	};

	/** @brief Linear retained-record slot state. */
	enum class retained_state : uint8_t {
		EMPTY = 0,	      ///< Slot belongs to the exact free list.
		PROVISIONAL,	      ///< Current INGEST callback may commit one retain.
		RETAINED,	      ///< Module owns one opaque live handle.
		EMIT_PENDING,	      ///< Platform owns one retryable dispatch disposition.
		DROP_PENDING,	      ///< Platform owns one retryable terminal disposition.
		RECIRCULATE_PENDING,  ///< Platform owns one retryable same-instance disposition.
		ASYNC_OWNED,	      ///< One packet-bound foreign token owns the retained packet.
	};

	/** @brief One generation-checked retained packet slot. */
	struct retained_slot {
		packet_record *record{nullptr};			///< Exact platform-owned packet.
		uint64_t epoch{0};				///< Immutable packet epoch.
		uint64_t bytes{0};				///< Exact retained payload bytes.
		uint16_t next_stage{KINETUM_NEXT_STAGE_UNSET};	///< Pending module-selected route.
		retained_state state{retained_state::EMPTY};	///< Linear disposition state.
		uint8_t ingest_lane{UINT8_MAX};		///< Current provisional lane; absent after callback commit.
		uint32_t generation{0};			///< Handle reuse generation.
		uint32_t next_free{INVALID_INDEX};	///< Intrusive free-list link.
		uint32_t next_live{INVALID_INDEX};	///< Intrusive retained-list link.
		uint32_t previous_live{INVALID_INDEX};	///< Intrusive retained-list link.
		uint32_t next_pending{INVALID_INDEX};	///< Intrusive pending-disposition link.
	};

	/** @brief One copied owner-local control message cell. */
	struct control_cell {
		uint64_t epoch{0};		       ///< Exact credit epoch.
		uint32_t subtype{0};		       ///< Exact compiled edge subtype.
		uint32_t length{0};		       ///< Exact copied payload bytes.
		uint32_t payload_slot{INVALID_INDEX};  ///< Exact preallocated payload owner.
	};

	/** @brief One exact compiled PULL edge and its sole pending bit. */
	struct pull_edge {
		uint32_t source_row{INVALID_INDEX};	  ///< Active source receiving PULL_READY.
		uint32_t destination_row{INVALID_INDEX};  ///< Downstream requester.
		uint64_t relation_bit{UINT64_MAX};	  ///< Exact source/destination matrix identity.
	};

	/** @brief One exact active stage-instance row in worker schedule order. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) instance_row {
		uint32_t stage_instance_index{INVALID_INDEX};	///< Exact global stage identity.
		uint32_t module_context_index{INVALID_INDEX};	///< Exact module context identity.
		int32_t region_id{-1};				///< Exact owner region.
		uint32_t trigger_mask{0};			///< Authored KINETUM_TRIGGER_* subset.
		module::module_epoch_store *store{nullptr};	///< Exact executable-view owner.
		const kinetum_module *descriptor{nullptr};	///< Exact admitted callback table.
		retained_slot *retained{nullptr};		///< Plan-sized retained slots.
		uint32_t retained_base_index{0};		///< First worker-global retained slot.
		uint32_t retained_capacity{0};			///< Exact slot population.
		uint32_t retained_free_head{INVALID_INDEX};	///< O(1) free-list head.
		uint32_t retained_live_head{INVALID_INDEX};	///< Intrusive live-list head.
		uint32_t retained_pending_head{INVALID_INDEX};	///< Pending disposition head.
		uint32_t retained_pending_tail{INVALID_INDEX};	///< Pending disposition tail.
		uint32_t retained_owned_count{0};		///< Reserved, live, and pending retained count.
		uint64_t retained_owned_bytes{0};		///< Reserved, live, and pending retained bytes.
		uint64_t retained_byte_capacity{0};		///< Exact authored byte bound.
		uint32_t timer_capacity{0};			///< Exact timer population.
		uint32_t timer_armed_count{0};			///< Timer-wheel slots currently armed.
		uint64_t timer_owned_count{0};			///< Armed plus callback-owned timers.
		kinetum::algo::work_queue_view<control_cell> *control_queue{nullptr};  ///< Shared FIFO core.
		uint32_t *control_payload_next_free{nullptr};	    ///< Intrusive payload-slot free list.
		uint32_t control_payload_free_head{INVALID_INDEX};  ///< O(1) payload-slot owner.
		std::byte *control_payloads{nullptr};		    ///< Cell-indexed payload storage.
		control_cell *control_delivery{nullptr};	    ///< Bounded callback-owned message prefix.
		uint32_t control_capacity{0};			    ///< Exact power-of-two capacity.
		uint32_t control_payload_capacity{0};		    ///< Exact per-cell payload bound.
		uint32_t control_owned_count{0};		    ///< Queued plus callback-owned messages.
		uint32_t *source_pull_edge_indices{nullptr};	    ///< Exact inbound request-bit set.
		uint32_t source_pull_edge_count{0};		    ///< Number of indexed request bits.
		uint32_t *pull_delivery{nullptr};		    ///< Bounded selected request-edge prefix.
		uint32_t pull_service_cursor{0};		    ///< Owner-local fair inspection cursor.
		uint32_t async_base_index{0};			    ///< First worker-global async slot.
		uint32_t async_capacity{0};			    ///< Exact logical token capacity.
		uint32_t async_free_head{INVALID_INDEX};	    ///< Owner-local async free-list head.
		uint32_t async_slot_owned_count{0};		    ///< Live or completion-queued token slots.
		uint32_t async_callback_owned_count{0};		    ///< Callback-owned completion count.
		uint64_t async_cancel_grace_ns{0};		    ///< Exact fail-stop grace in cached-time units.
		uint64_t async_cancel_deadline_ns{0};		    ///< Cached-time fail-stop deadline.
		worker_async_delivery *async_deliveries{nullptr};   ///< Internal callback delivery prefix.
		kinetum_async_completion *async_completion_views{nullptr};  ///< Public callback prefix.
		uint32_t async_delivery_count{0};			    ///< Exact entries in both prefixes.
		kinetum_active_timer_handle *expired{nullptr};		    ///< Bounded callback expiry batch.
		kinetum_retained_packet_handle *drain_retained{nullptr};    ///< Bounded drain prefix.
		uint32_t expired_count{0};				    ///< Current callback expiry count.
		uint32_t drain_retained_count{0};			    ///< Current callback retained count.
		bool callback_active{false};				    ///< Foreign callback currently executing.
		std::array<uint8_t, 3> padding{};			    ///< Complete word padding.
	};
	static_assert(alignof(instance_row) == kinetum::algo::CACHE_LINE_SIZE);
	static_assert(sizeof(instance_row) % kinetum::algo::CACHE_LINE_SIZE == 0u);
	static_assert(std::is_standard_layout_v<instance_row>);
	static_assert(std::is_trivially_copyable_v<instance_row>);
	static_assert(std::is_standard_layout_v<retained_slot>);
	static_assert(std::is_trivially_copyable_v<retained_slot>);
	static_assert(std::is_standard_layout_v<control_cell>);
	static_assert(std::is_trivially_copyable_v<control_cell>);
	static_assert(std::is_standard_layout_v<pull_edge>);
	static_assert(std::is_trivially_copyable_v<pull_edge>);

	/** @brief One sole callback invocation and service-budget owner. */
	struct invocation {
		kinetum_active_runtime_services runtime_services{};  ///< Typed SDK service prefix.
		implementation *owner{nullptr};			     ///< Exact scheduler owner.
		instance_row *row{nullptr};			     ///< Exact current active instance.
		std::span<packet_record *const> ingest_records;	     ///< Borrowed occupied prefix, only during INGEST.
		uint64_t provisional_async_mask{0};  ///< Provisional lanes moved into packet-bound tokens.
		uint32_t remaining_budget{0};	     ///< Bounded platform-service operations.
		uint64_t now_ns{0};		     ///< Sole cached timestamp.
	};
	static_assert(offsetof(invocation, runtime_services) == 0u);

	/** @brief Checked offsets for one exact-NUMA worker slab. */
	struct slab_layout {
		std::size_t total_bytes{0};		       ///< Complete usable slab extent.
		std::size_t rows_offset{0};		       ///< Schedule-row array.
		std::size_t stage_to_row_offset{0};	       ///< Dense global-stage index.
		std::size_t retained_offset{0};		       ///< Retained slot population.
		std::size_t timer_wheel_offset{0};	       ///< Caller-storage wheel object.
		std::size_t timers_offset{0};		       ///< Caller-storage timer entries.
		std::size_t timer_fine_heads_offset{0};	       ///< Fine wheel heads.
		std::size_t timer_coarse_heads_offset{0};      ///< Coarse wheel heads.
		std::size_t control_queues_offset{0};	       ///< Per-row queue views.
		std::size_t control_storage_offset{0};	       ///< Complete queue cell storage.
		std::size_t control_free_links_offset{0};      ///< Payload free-list links.
		std::size_t control_payload_offset{0};	       ///< Copied message bytes.
		std::size_t control_delivery_offset{0};	       ///< Callback delivery prefixes.
		std::size_t control_edge_bits_offset{0};       ///< Authorized control relation bits.
		std::size_t control_feedback_bits_offset{0};   ///< FEEDBACK control relation bits.
		std::size_t pull_edge_bits_offset{0};	       ///< Authorized PULL relation bits.
		std::size_t pull_pending_bits_offset{0};       ///< Mutable pending PULL bits.
		std::size_t pull_edges_offset{0};	       ///< Static PULL edge rows.
		std::size_t source_pull_indices_offset{0};     ///< Source-to-edge projection.
		std::size_t pull_delivery_offset{0};	       ///< Per-row selected PULL prefixes.
		std::size_t async_tracker_offset{0};	       ///< Caller-placed worker async owner.
		std::size_t async_slots_offset{0};	       ///< Exact logical token slots.
		std::size_t async_queue_offset{0};	       ///< Caller-storage MPMC cells.
		std::size_t async_deliveries_offset{0};	       ///< Internal callback deliveries.
		std::size_t async_completion_views_offset{0};  ///< Public callback projections.
		std::size_t expired_offset{0};		       ///< Per-row expiry prefixes.
		std::size_t drain_retained_offset{0};	       ///< Per-row retained drain prefixes.
		std::size_t origin_views_offset{0};	       ///< Worker-local active-origin inputs.
		std::size_t origin_records_offset{0};	       ///< Worker-local active-origin results.
		std::size_t ingest_slots_offset{0};	       ///< Per-lane provisional retention scratch.
	};

	/**
	 * @brief Retain construction inputs until exact validation and slab binding complete.
	 * @param worker_index Exact compact owner-worker identity.
	 * @param topology Sole compiled topology authority.
	 * @param contexts Complete exact active stage/context bindings.
	 * @param ledger Sole worker-local work-credit owner.
	 * @param packet_operations Narrow pre-resolved packet-kernel operations.
	 */
	implementation(uint32_t worker_index, const provider::compiled_provider_topology &topology,
		       std::span<const active_stage_context_binding> contexts, worker_epoch_ledger &ledger,
		       active_stage_packet_operations packet_operations) noexcept
		: worker_index_(worker_index)
		, topology_(topology)
		, context_bindings_(contexts)
		, ledger_(ledger)
		, packet_operations_(packet_operations)
	{
	}

	/** @brief Destroy only after every exact active owner is empty. */
	~implementation() noexcept
	{
		if (!empty() ||
		    (phase_ != phase::UNBOUND && phase_ != phase::OPEN && phase_ != phase::SHUTDOWN_DRAIN)) {
			std::terminate();
		}
		if (transition_generation_ != 0u || transition_from_epoch_ != 0u || transition_to_epoch_ != 0u) {
			std::terminate();
		}
		if ((origin_views_ == nullptr) != (origin_records_ == nullptr)) {
			std::terminate();
		}
		if (origin_views_ != nullptr) {
			for (std::size_t index = 0u; index < WORK_BUDGET; ++index) {
				if (origin_views_[index].data != nullptr || origin_views_[index].length != 0u ||
				    origin_views_[index].padding != 0u || origin_records_[index] != nullptr) {
					std::terminate();
				}
			}
		}
		const std::size_t relation_words = static_cast<std::size_t>(relation_bit_count_ / 64u) +
						   (relation_bit_count_ % 64u == 0u ? 0u : 1u);
		for (std::size_t index = 0u; index < relation_words; ++index) {
			if (pull_pending_bits_ == nullptr || pull_pending_bits_[index] != 0u) {
				std::terminate();
			}
		}
		for (uint32_t index = 0u; index < row_count_; ++index) {
			if (rows_[index].async_delivery_count != 0u || rows_[index].async_slot_owned_count != 0u ||
			    rows_[index].async_callback_owned_count != 0u) {
				std::terminate();
			}
			if (rows_[index].control_queue != nullptr) {
				std::destroy_at(rows_[index].control_queue);
				rows_[index].control_queue = nullptr;
			}
		}
		if (async_work_ != nullptr) {
			std::destroy_at(async_work_);
			async_work_ = nullptr;
			async_slots_ = nullptr;
		}
		if (timer_wheel_ != nullptr) {
			std::destroy_at(timer_wheel_);
			timer_wheel_ = nullptr;
		}
	}

	/** @return Complete cold admission and slab construction status. */
	[[nodiscard]] common::status initialize();

	/** @copydoc worker_active_stage_scheduler::worker_index */
	[[nodiscard]] uint32_t worker_index() const noexcept
	{
		return worker_index_;
	}
	/** @copydoc worker_active_stage_scheduler::size */
	[[nodiscard]] std::size_t size() const noexcept
	{
		return row_count_;
	}
	/** @copydoc worker_active_stage_scheduler::numa_node */
	[[nodiscard]] int32_t numa_node() const noexcept
	{
		if (!slab_.host_numa_node().has_value()) {
			std::terminate();
		}
		return *slab_.host_numa_node();
	}
	/** @copydoc worker_active_stage_scheduler::storage_bytes */
	[[nodiscard]] std::size_t storage_bytes() const noexcept
	{
		return slab_.size();
	}
	/** @copydoc worker_active_stage_scheduler::active_epoch */
	[[nodiscard]] uint64_t active_epoch() const noexcept
	{
		return active_epoch_;
	}
	/** @copydoc worker_active_stage_scheduler::owns_ledger */
	[[nodiscard]] bool owns_ledger(const worker_epoch_ledger &ledger) const noexcept
	{
		return &ledger_ == &ledger;
	}
	/** @copydoc worker_active_stage_scheduler::bind_bootstrap_epoch */
	void bind_bootstrap_epoch(uint64_t epoch) noexcept;
	/** @copydoc worker_active_stage_scheduler::preflight_begin_transition */
	[[nodiscard]] bool preflight_begin_transition(uint64_t generation, uint64_t from_epoch,
						      uint64_t to_epoch) const noexcept;
	/** @copydoc worker_active_stage_scheduler::begin_transition */
	[[nodiscard]] bool begin_transition(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch) noexcept;
	/** @copydoc worker_active_stage_scheduler::begin_shutdown */
	void begin_shutdown() noexcept;
	/** @copydoc worker_active_stage_scheduler::service_turn_synchronous */
	void service_turn_synchronous(uint64_t cached_now_ns) noexcept;
	/** @copydoc worker_active_stage_scheduler::service_turn_async */
	void service_turn_async(uint64_t cached_now_ns) noexcept;
	/** @copydoc worker_active_stage_scheduler::has_async_work */
	[[nodiscard]] bool has_async_work() const noexcept
	{
		return async_work_ != nullptr;
	}
	/** @copydoc worker_active_stage_scheduler::ingest_synchronous */
	[[nodiscard]] active_ingest_result ingest_synchronous(uint32_t stage_instance_index,
							      std::span<packet_record *const> records,
							      int32_t region_id, module_batch_scratch &scratch,
							      uint64_t cached_now_ns) noexcept;
	/** @copydoc worker_active_stage_scheduler::ingest_async */
	[[nodiscard]] active_ingest_result ingest_async(uint32_t stage_instance_index,
							std::span<packet_record *const> records, int32_t region_id,
							module_batch_scratch &scratch, uint64_t cached_now_ns) noexcept;
	/** @copydoc worker_active_stage_scheduler::transition_active */
	[[nodiscard]] bool transition_active(uint64_t generation, uint64_t from_epoch,
					     uint64_t to_epoch) const noexcept;
	/** @copydoc worker_active_stage_scheduler::activation_ready */
	[[nodiscard]] bool activation_ready(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch) const noexcept;
	/** @copydoc worker_active_stage_scheduler::preflight_activate */
	[[nodiscard]] bool preflight_activate(uint64_t generation, uint64_t from_epoch,
					      uint64_t to_epoch) const noexcept;
	/** @copydoc worker_active_stage_scheduler::activate */
	void activate(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch) noexcept;
	/** @copydoc worker_active_stage_scheduler::empty */
	[[nodiscard]] bool empty() const noexcept;

    private:
	/**
	 * @brief Test one transition bind against an exact ledger future-slot state.
	 * @param generation Nonzero transition generation.
	 * @param from_epoch Exact current active epoch.
	 * @param to_epoch Exact prepared target epoch.
	 * @param expected_future_epoch Zero during preflight or @p to_epoch after binding.
	 * @return true only when every scheduler/store/ledger identity is exact.
	 */
	[[nodiscard]] bool transition_bind_ready_(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch,
						  uint64_t expected_future_epoch) const noexcept;
	/**
	 * @brief Revalidate every compiled active authority in both directions.
	 * @param binding_by_stage Dense exact stage-to-context binding index.
	 * @param[out] source_pull_counts Exact PULL relation count for each active row.
	 * @return OK only for one complete active owner graph.
	 */
	[[nodiscard]] common::status
	validate_topology_(std::span<const active_stage_context_binding *const> binding_by_stage,
			   std::span<uint32_t> source_pull_counts) const;
	/** @return Checked offsets for the sole exact-NUMA worker slab. */
	[[nodiscard]] common::status_or<slab_layout> compute_layout_() const noexcept;
	/**
	 * @brief Allocate and bind the prevalidated slab without later failure.
	 * @param layout Complete checked slab layout.
	 * @param binding_by_stage Dense exact stage-to-context binding index.
	 * @param source_pull_counts Exact PULL relation count for each active row.
	 * @return NUMA allocation status, or OK after complete non-failing binding.
	 */
	[[nodiscard]] common::status bind_slab_(const slab_layout &layout,
						std::span<const active_stage_context_binding *const> binding_by_stage,
						std::span<const uint32_t> source_pull_counts);
	/** @param stage_index Global stage identity. @return Mutable active row, or null. */
	[[nodiscard]] instance_row *row_for_stage_(uint32_t stage_index) noexcept;
	/** @param stage_index Global stage identity. @return Immutable active row, or null. */
	[[nodiscard]] const instance_row *row_for_stage_(uint32_t stage_index) const noexcept;
	/**
	 * @brief Construct one callback-borrowed ABI context.
	 * @tparam has_async true only for a tracked-async worker loop.
	 * @param row Exact current instance row.
	 * @param now_ns Sole worker-cached timestamp.
	 * @param expose_async_completions true only for the owning RUN delivery.
	 * @return Complete runtime-written active context.
	 */
	template <bool has_async>
	[[nodiscard]] kinetum_active_ctx make_context_(instance_row &row, uint64_t now_ns,
						       bool expose_async_completions) noexcept;
	/**
	 * @brief Retry one bounded pending retained prefix.
	 * @param row Exact instance row.
	 * @param[in,out] budget Shared remaining turn budget.
	 */
	void service_pending_retained_(instance_row &row, std::size_t &budget) noexcept;
	/**
	 * @brief Service one schedule-ordered instance.
	 * @tparam has_async true only for a tracked-async worker loop.
	 * @param row Exact instance row.
	 * @param now_ns Sole cached worker timestamp.
	 * @param[in,out] budget Shared remaining turn budget.
	 */
	template <bool has_async>
	void service_instance_(instance_row &row, uint64_t now_ns, std::size_t &budget) noexcept;
	/** @brief Project one bounded exact retained prefix for a drain callback. @param row Exact instance row. */
	void collect_drain_retained_(instance_row &row) noexcept;
	/** @param row Exact instance row. @return true when it owns no synchronous work. */
	[[nodiscard]] bool row_synchronous_empty_(const instance_row &row) const noexcept;
	/** @param row Exact instance row. @return true when it owns no active work. */
	[[nodiscard]] bool row_empty_(const instance_row &row) const noexcept;
	/** @param row Exact PULL source row. @return true when no request bit is pending. */
	[[nodiscard]] bool pull_empty_(const instance_row &row) const noexcept;
	/** @param row Exact instance row. @return true when no selected PULL prefix survives. */
	[[nodiscard]] bool pull_delivery_empty_(const instance_row &row) const noexcept;
	/** @param words Exact relation bit plane. @param bit Pair identity. @return Current bit value. */
	[[nodiscard]] bool relation_bit_(const uint64_t *words, uint64_t bit) const noexcept;
	/**
	 * @brief Set one previously clear exact relation bit.
	 * @param words Exact mutable relation bit plane.
	 * @param bit Exact pair identity.
	 */
	void set_relation_bit_(uint64_t *words, uint64_t bit) noexcept;
	/**
	 * @brief Clear one previously set exact relation bit.
	 * @param words Exact mutable relation bit plane.
	 * @param bit Exact pair identity.
	 */
	void clear_relation_bit_(uint64_t *words, uint64_t bit) noexcept;

	/**
	 * @param row Exact instance row.
	 * @param record Sole candidate packet record.
	 * @return Provisional retained slot index, or INVALID_INDEX without transfer.
	 */
	[[nodiscard]] uint32_t allocate_retained_(instance_row &row, packet_record &record) noexcept;
	/**
	 * @brief Commit one provisional slot to retained ownership.
	 * @param row Exact instance row.
	 * @param slot_index Exact row-local retained slot.
	 */
	void commit_retained_(instance_row &row, uint32_t slot_index) noexcept;
	/**
	 * @brief Commit one validated provisional packet already transferred to async ownership.
	 * @param row Exact instance row.
	 * @param slot_index Exact row-local retained slot.
	 */
	void commit_async_retained_(instance_row &row, uint32_t slot_index) noexcept;
	/**
	 * @brief Acquire one retained slot's exact count and byte accounting.
	 * @param row Exact instance row.
	 * @param slot Exact packet ownership entering the retained population.
	 */
	void acquire_retained_accounting_(instance_row &row, const retained_slot &slot) noexcept;
	/**
	 * @brief Return one completed pending slot to its exact free list.
	 * @param row Exact instance row.
	 * @param slot_index Exact row-local retained slot.
	 */
	void free_retained_(instance_row &row, uint32_t slot_index) noexcept;
	/**
	 * @brief Remove one exact retained slot from the intrusive live list.
	 * @param row Exact instance row.
	 * @param slot_index Exact row-local retained slot.
	 */
	void remove_live_retained_(instance_row &row, uint32_t slot_index) noexcept;
	/**
	 * @brief Append one transferred slot to the pending-disposition FIFO.
	 * @param row Exact instance row.
	 * @param slot_index Exact row-local retained slot.
	 */
	void append_pending_retained_(instance_row &row, uint32_t slot_index) noexcept;
	/**
	 * @param row Exact context row.
	 * @param handle Candidate opaque retained handle.
	 * @return Exact live retained slot, or null for stale/foreign input.
	 */
	[[nodiscard]] retained_slot *resolve_retained_(instance_row &row,
						       kinetum_retained_packet_handle handle) noexcept;

	/**
	 * @brief Collect bounded expirations at one cached time.
	 * @param now_ns Sole cached worker timestamp.
	 * @param[in,out] budget Shared remaining turn budget.
	 */
	void collect_worker_timers_(uint64_t now_ns, std::size_t &budget) noexcept;
	/**
	 * @brief Cancel and expose a bounded live-timer scan.
	 * @param[in,out] budget Shared remaining turn budget.
	 */
	void collect_drain_timers_(std::size_t &budget) noexcept;
	/**
	 * @brief Drain a bounded completion prefix into exact instance callbacks.
	 * @param[in,out] budget Shared remaining turn budget.
	 */
	void collect_async_completions_(std::size_t &budget) noexcept;
	/**
	 * @brief Enforce exact cached-time cancellation bounds during drain.
	 * @param now_ns Sole cached worker timestamp.
	 */
	void enforce_async_cancellation_deadlines_(uint64_t now_ns) noexcept;
	/**
	 * @brief Execute one compile-time synchronous or tracked-async active turn.
	 * @tparam has_async true only for the completion/cancellation specialization.
	 * @param cached_now_ns Sole cached worker timestamp.
	 */
	template <bool has_async>
	void service_turn_(uint64_t cached_now_ns) noexcept;
	/**
	 * @brief Execute one compile-time synchronous or tracked-async INGEST path.
	 * @tparam has_async true only for the typed async-services specialization.
	 * @param stage_instance_index Exact current active stage instance.
	 * @param records Borrowed occupied input prefix for one exact context and epoch.
	 * @param region_id Exact owner region.
	 * @param scratch Sole worker-local batch scratch.
	 * @param cached_now_ns Sole cached worker timestamp.
	 * @return Total active-ingest disposition.
	 */
	template <bool has_async>
	[[nodiscard]] active_ingest_result ingest_(uint32_t stage_instance_index,
						   std::span<packet_record *const> records, int32_t region_id,
						   module_batch_scratch &scratch, uint64_t cached_now_ns) noexcept;
	/**
	 * @brief Return one exact async slot to its row-local free list.
	 * @param row Exact owning active row.
	 * @param slot_index Exact worker-global async slot.
	 */
	void release_async_slot_(instance_row &row, uint32_t slot_index) noexcept;
	/**
	 * @brief Restore one packet-bound retained slot under its advanced generation.
	 * @param row Exact owning active row.
	 * @param slot_index Exact row-local retained slot.
	 * @param publish_live true to link the restored handle into ordinary live ownership.
	 * @return Fresh exact retained handle.
	 */
	[[nodiscard]] kinetum_retained_packet_handle restore_async_retained_(instance_row &row, uint32_t slot_index,
									     bool publish_live = true) noexcept;

	/** @param context Callback ABI context. @return Exact live invocation owner. */
	[[nodiscard]] static invocation &invocation_from_(kinetum_active_ctx *context) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param batch Complete candidate origin batch.
	 * @return Accepted active-origin prefix through the exact callback context.
	 */
	[[nodiscard]] static uint32_t emit_(kinetum_active_ctx *context, const kinetum_emit_batch_t *batch) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param lane Current active-ingest lane.
	 * @return Provisional retained handle, or the invalid sentinel.
	 */
	[[nodiscard]] static kinetum_retained_packet_handle retain_input_(kinetum_active_ctx *context,
									  uint32_t lane) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param handle Exact live retained handle.
	 * @param next_stage Logical target or KINETUM_NEXT_STAGE_UNSET.
	 * @return true after the handle transfers to pending dispatch.
	 */
	[[nodiscard]] static bool emit_retained_(kinetum_active_ctx *context, kinetum_retained_packet_handle handle,
						 uint16_t next_stage) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param handle Exact live retained handle.
	 * @return true after the handle transfers to pending terminal drop.
	 */
	[[nodiscard]] static bool drop_retained_(kinetum_active_ctx *context,
						 kinetum_retained_packet_handle handle) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param delay_ns Positive relative delay in nanoseconds.
	 * @return Exact timer handle, or the invalid sentinel.
	 */
	[[nodiscard]] static kinetum_active_timer_handle arm_timer_(kinetum_active_ctx *context,
								    uint64_t delay_ns) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param handle Candidate exact live timer.
	 * @return true only when the handle was cancelled.
	 */
	[[nodiscard]] static bool cancel_timer_(kinetum_active_ctx *context,
						kinetum_active_timer_handle handle) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param peer_idx Exact destination stage-instance index.
	 * @param message Complete borrowed control message.
	 * @return true only when one exact control cell accepts the message.
	 */
	[[nodiscard]] static bool post_control_(kinetum_active_ctx *context, uint16_t peer_idx,
						const kinetum_control_msg *message) noexcept;
	/**
	 * @param context Exact callback-borrowed active context.
	 * @param upstream_idx Exact source stage-instance index.
	 * @return true for a declared new or already-pending request.
	 */
	[[nodiscard]] static bool request_pull_(kinetum_active_ctx *context, uint16_t upstream_idx) noexcept;
	/**
	 * @brief Begin one standalone exact foreign operation.
	 * @param services Exact callback-borrowed service shell.
	 * @param user_tag Module correlation value.
	 * @return Exact token or fixed invalid representation.
	 */
	[[nodiscard]] static kinetum_async_token begin_async_(kinetum_active_runtime_services *services,
							      uint64_t user_tag) noexcept;
	/**
	 * @brief Transfer one retained packet to one exact foreign operation.
	 * @param services Exact callback-borrowed service shell.
	 * @param retained Exact live retained handle.
	 * @param user_tag Module correlation value.
	 * @param[out] out_view Read-only packet view written only after transfer.
	 * @return Exact token or fixed invalid representation.
	 */
	[[nodiscard]] static kinetum_async_token begin_async_retained_(kinetum_active_runtime_services *services,
								       kinetum_retained_packet_handle retained,
								       uint64_t user_tag,
								       kinetum_async_packet_view *out_view) noexcept;
	/**
	 * @brief Abort one pre-transfer async token and restore exact ownership.
	 * @param services Exact callback-borrowed service shell.
	 * @param token Exact not-yet-transferred token.
	 * @param[out] out_retained Restored fresh handle or invalid standalone result.
	 * @return true only after exact restoration or retirement.
	 */
	[[nodiscard]] static bool abort_async_(kinetum_active_runtime_services *services, kinetum_async_token token,
					       kinetum_retained_packet_handle *out_retained) noexcept;
	/**
	 * @brief Transfer one retained packet to same-instance recirculation.
	 * @param services Exact callback-borrowed service shell.
	 * @param retained Exact live retained handle.
	 * @return true only after pending local staging accepts ownership.
	 */
	[[nodiscard]] static bool recirculate_retained_(kinetum_active_runtime_services *services,
							kinetum_retained_packet_handle retained) noexcept;
	/** @param services Candidate typed service prefix. @return Exact live invocation owner. */
	[[nodiscard]] static invocation &invocation_from_(kinetum_active_runtime_services *services) noexcept;

	uint32_t worker_index_{0};					  ///< Exact compact worker identity.
	const provider::compiled_provider_topology &topology_;		  ///< Sole compiled authority.
	std::span<const active_stage_context_binding> context_bindings_;  ///< Construction-only exact bindings.
	worker_epoch_ledger &ledger_;					  ///< Sole worker work-credit owner.
	active_stage_packet_operations packet_operations_;		  ///< Narrow packet-kernel surface.
	numa_memory_region slab_;					  ///< One exact-NUMA active-worker mapping.
	instance_row *rows_{nullptr};					  ///< Schedule-ordered slab rows.
	uint32_t row_count_{0};						  ///< Exact active instance count.
	uint32_t *stage_to_row_{nullptr};				  ///< Global stage to active-row map.
	uint32_t stage_count_{0};					  ///< Complete global stage namespace.
	pull_edge *pull_edges_{nullptr};				  ///< Exact worker-local PULL edge set.
	uint32_t pull_edge_count_{0};					  ///< Exact PULL edge count.
	kinetum::algo::timer_wheel_view<> *timer_wheel_{nullptr};	  ///< Shared caller-storage timer core.
	worker_async_work *async_work_{nullptr};			  ///< Caller-placed foreign-work authority.
	worker_async_work::slot_storage *async_slots_{nullptr};		  ///< Caller-placed logical token slots.
	uint32_t timer_entry_capacity_{0};				  ///< Aggregate plan-authored timer capacity.
	uint32_t timer_drain_cursor_{0};				  ///< Bounded shutdown/transition scan cursor.
	uint64_t relation_bit_count_{0};				  ///< Exact active-row pair universe.
	uint64_t *control_edge_bits_{nullptr};				  ///< Immutable authorized control relations.
	uint64_t *control_feedback_bits_{nullptr};			  ///< Immutable FEEDBACK edge classifications.
	uint64_t *pull_edge_bits_{nullptr};				  ///< Immutable authorized PULL relations.
	uint64_t *pull_pending_bits_{nullptr};	     ///< Mutable owner-local pending PULL relations.
	packet_origin_view *origin_views_{nullptr};  ///< Exact-NUMA active-origin input scratch.
	packet_record **origin_records_{nullptr};    ///< Exact-NUMA active-origin result scratch.
	uint32_t *ingest_slots_{nullptr};	     ///< Exact-NUMA provisional slot for each occupied INGEST lane.
	invocation invocation_{};		     ///< Sole non-nested callback context.
	phase phase_{phase::UNBOUND};		     ///< Worker-local active scheduling phase.
	uint64_t active_epoch_{0};		     ///< Exact current callback epoch.
	uint64_t transition_generation_{0};	     ///< Exact current drain generation.
	uint64_t transition_from_epoch_{0};	     ///< Exact current drain source.
	uint64_t transition_to_epoch_{0};	     ///< Exact current drain target.
};

common::status worker_active_stage_scheduler::implementation::validate_topology_(
	std::span<const active_stage_context_binding *const> binding_by_stage,
	std::span<uint32_t> source_pull_counts) const
{
	if (!packet_operations_.valid() || ledger_.worker_index() != worker_index_ ||
	    ledger_.runtime_generation() == 0u || worker_index_ >= topology_.worker_schedules.size() ||
	    worker_index_ >= topology_.transition_topology.workers.size()) {
		return common::status::failed_precondition(
			"active scheduler requires exact worker and packet-operation authority");
	}
	const auto &schedule = topology_.worker_schedules[worker_index_];
	const auto &worker = topology_.transition_topology.workers[worker_index_];
	if (schedule.worker_index != worker_index_ || worker.worker_index != worker_index_ || worker.numa_node < 0 ||
	    worker.cpu_core_ids.size() != 1u || schedule.active_stage_instance_indices.empty() ||
	    context_bindings_.size() != schedule.active_stage_instance_indices.size() ||
	    binding_by_stage.size() != topology_.stage_instances.size() ||
	    source_pull_counts.size() != schedule.active_stage_instance_indices.size()) {
		return common::status::failed_precondition(
			"active scheduler requires one nonempty exact owner-worker schedule");
	}

	std::vector<bool> incoming_packet(topology_.stage_instances.size(), false);
	std::vector<std::pair<uint32_t, uint32_t>> route_pull_pairs;
	for (const auto &stage : topology_.stage_instances) {
		for (const auto &route : stage.packet_routes) {
			if (route.destination_stage_instance_indices.empty() ||
			    (route.mode == provider::compiled_packet_edge_mode::PULL &&
			     route.destination_stage_instance_indices.size() != 1u)) {
				return common::status::failed_precondition(
					"active scheduler found an invalid packet destination set");
			}
			for (const uint16_t destination : route.destination_stage_instance_indices) {
				if (destination >= incoming_packet.size()) {
					return common::status::failed_precondition(
						"active scheduler found an out-of-range packet route");
				}
				incoming_packet[destination] = true;
			}
			if (route.mode == provider::compiled_packet_edge_mode::PULL &&
			    stage.worker_index == worker_index_) {
				route_pull_pairs.emplace_back(stage.stage_instance_index,
							      route.destination_stage_instance_indices.front());
			}
		}
	}

	std::vector<uint32_t> exact_active;
	std::vector<uint32_t> exact_async;
	std::vector<uint32_t> exact_loop;
	std::vector<uint32_t> exact_timer;
	std::vector<uint32_t> exact_pull;
	std::vector<uint32_t> exact_control;
	exact_active.reserve(schedule.stage_instance_indices.size());
	for (const uint32_t stage_index : schedule.stage_instance_indices) {
		if (stage_index >= topology_.stage_instances.size()) {
			return common::status::failed_precondition(
				"active scheduler stage schedule contains an out-of-range identity");
		}
		const auto &stage = topology_.stage_instances[stage_index];
		if (stage.worker_index != worker_index_ ||
		    stage.logical_stage_index >= topology_.logical_stages.size()) {
			return common::status::failed_precondition(
				"active scheduler stage has foreign worker or logical ownership");
		}
		const auto &logical = topology_.logical_stages[stage.logical_stage_index];
		if (logical.execution_mode != provider::compiled_stage_execution_mode::ACTIVE) {
			continue;
		}
		exact_active.push_back(stage_index);
		if (logical.kind != provider::compiled_stage_kind::MODULE || !stage.module_context_index.has_value() ||
		    *stage.module_context_index >= topology_.module_contexts.size() ||
		    stage.region_index >= topology_.execution_regions.size() ||
		    topology_.execution_regions[stage.region_index].region_id < 0 ||
		    !stage.active_origin_storage_domain_index.has_value() || !worker.is_source ||
		    *stage.active_origin_storage_domain_index >= topology_.storage_domains.size() ||
		    !std::binary_search(schedule.storage_domain_indices.begin(), schedule.storage_domain_indices.end(),
					*stage.active_origin_storage_domain_index) ||
		    !std::binary_search(schedule.source_storage_domain_indices.begin(),
					schedule.source_storage_domain_indices.end(),
					*stage.active_origin_storage_domain_index) ||
		    !std::binary_search(topology_.transition_topology.source_worker_indices.begin(),
					topology_.transition_topology.source_worker_indices.end(), worker_index_) ||
		    !std::binary_search(stage.reachable_storage_domain_indices.begin(),
					stage.reachable_storage_domain_indices.end(),
					*stage.active_origin_storage_domain_index)) {
			return common::status::failed_precondition(
				"active stage lacks exact module context or origin storage ownership");
		}
		const auto &compiled_context = topology_.module_contexts[*stage.module_context_index];
		const auto *binding = binding_by_stage[stage_index];
		const int32_t region_id = topology_.execution_regions[stage.region_index].region_id;
		const bool tracked_async = binding != nullptr && binding->descriptor != nullptr &&
					   (binding->descriptor->flags & KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK) != 0u;
		const bool async_resources = logical.async_work_capacity != 0u;
		const bool async_grace_present = logical.async_cancel_grace !=
						 std::chrono::steady_clock::duration::zero();
		const auto async_grace_ms =
			std::chrono::duration_cast<std::chrono::milliseconds>(logical.async_cancel_grace);
		const bool async_grace_exact = !async_grace_present ||
					       (async_grace_ms > std::chrono::milliseconds::zero() &&
						std::chrono::duration_cast<std::chrono::steady_clock::duration>(
							async_grace_ms) == logical.async_cancel_grace);
		if (compiled_context.stage_instance_index != stage_index ||
		    compiled_context.logical_stage_index != stage.logical_stage_index ||
		    compiled_context.worker_index != worker_index_ || compiled_context.region_id != region_id ||
		    compiled_context.numa_node != worker.numa_node ||
		    compiled_context.cpu_core_id != worker.cpu_core_ids.front() || binding == nullptr ||
		    binding->module_context_index != compiled_context.module_context_index ||
		    binding->store == nullptr || binding->descriptor == nullptr ||
		    binding->store->context_index() != compiled_context.module_context_index ||
		    binding->descriptor->mode != KINETUM_MODULE_ACTIVE || binding->descriptor->run == nullptr ||
		    tracked_async != async_resources || async_resources != async_grace_present || !async_grace_exact ||
		    (async_resources && topology_.transition_topology.policy.enabled &&
		     logical.async_cancel_grace >= topology_.transition_topology.policy.commit_timeout) ||
		    (topology_.transition_topology.policy.enabled &&
		     (binding->descriptor->flags & KINETUM_MOD_F_LIVE_EPOCH_TRANSITION) == 0u) ||
		    (incoming_packet[stage_index] && binding->descriptor->ingest == nullptr)) {
			return common::status::failed_precondition(
				"active stage descriptor, context, storage, or live capability is incomplete");
		}
		const bool timer = (logical.trigger_mask &
				    static_cast<uint32_t>(provider::compiled_active_stage_trigger::TIMER)) != 0u;
		const bool control = (logical.trigger_mask &
				      static_cast<uint32_t>(provider::compiled_active_stage_trigger::CONTROL)) != 0u;
		const bool control_fields_present = logical.control_mailbox_capacity != 0u ||
						    logical.control_message_capacity_bytes != 0u;
		const bool control_capacity_valid =
			logical.control_mailbox_capacity >= 2u &&
			(logical.control_mailbox_capacity & (logical.control_mailbox_capacity - 1u)) == 0u &&
			logical.control_message_capacity_bytes != 0u;
		if (logical.trigger_mask == 0u ||
		    (logical.trigger_mask & ~static_cast<uint32_t>(KINETUM_AUTHORED_ACTIVE_TRIGGER_MASK)) != 0u ||
		    (logical.retained_packet_capacity == 0u) != (logical.retained_byte_capacity == 0u) ||
		    (logical.retained_packet_capacity != 0u &&
		     logical.retained_byte_capacity < logical.retained_packet_capacity) ||
		    timer != (logical.timer_capacity != 0u) || control != control_fields_present ||
		    (control_fields_present && !control_capacity_valid) ||
		    (control && binding->descriptor->on_control == nullptr)) {
			return common::status::failed_precondition(
				"active stage synchronous resource contract is not exact");
		}
		if ((logical.trigger_mask & static_cast<uint32_t>(provider::compiled_active_stage_trigger::LOOP)) !=
		    0u) {
			exact_loop.push_back(stage_index);
		}
		if (timer) {
			exact_timer.push_back(stage_index);
		}
		if ((logical.trigger_mask &
		     static_cast<uint32_t>(provider::compiled_active_stage_trigger::PULL_READY)) != 0u) {
			exact_pull.push_back(stage_index);
		}
		if (control) {
			exact_control.push_back(stage_index);
		}
		if (async_resources) {
			exact_async.push_back(stage_index);
		}
	}
	const auto active_order = [&](uint32_t lhs, uint32_t rhs) {
		const auto &left = topology_.logical_stages[topology_.stage_instances[lhs].logical_stage_index];
		const auto &right = topology_.logical_stages[topology_.stage_instances[rhs].logical_stage_index];
		return std::tie(left.schedule_order, lhs) < std::tie(right.schedule_order, rhs);
	};
	std::sort(exact_active.begin(), exact_active.end(), active_order);
	std::sort(exact_async.begin(), exact_async.end(), active_order);
	std::sort(exact_loop.begin(), exact_loop.end(), active_order);
	std::sort(exact_timer.begin(), exact_timer.end(), active_order);
	std::sort(exact_pull.begin(), exact_pull.end(), active_order);
	std::sort(exact_control.begin(), exact_control.end(), active_order);
	if (exact_active != schedule.active_stage_instance_indices ||
	    exact_async != schedule.async_stage_instance_indices ||
	    exact_loop != schedule.loop_trigger_stage_instance_indices ||
	    exact_timer != schedule.timer_trigger_stage_instance_indices ||
	    exact_pull != schedule.pull_trigger_stage_instance_indices ||
	    exact_control != schedule.control_trigger_stage_instance_indices) {
		return common::status::failed_precondition(
			"active trigger schedules disagree with exact instance ownership");
	}

	std::vector<uint32_t> active_row_by_stage(topology_.stage_instances.size(), INVALID_INDEX);
	for (uint32_t row = 0u; row < exact_active.size(); ++row) {
		active_row_by_stage[exact_active[row]] = row;
	}
	std::vector<uint32_t> inbound_control_counts(exact_active.size(), 0u);
	std::vector<uint32_t> exact_control_edges;
	std::vector<std::pair<uint32_t, uint32_t>> control_pairs;
	for (uint32_t edge_index = 0u; edge_index < topology_.control_edges.size(); ++edge_index) {
		const auto &edge = topology_.control_edges[edge_index];
		if (edge.worker_index != worker_index_) {
			continue;
		}
		if (edge.control_edge_index != edge_index ||
		    edge.from_stage_instance_index >= active_row_by_stage.size() ||
		    edge.to_stage_instance_index >= active_row_by_stage.size()) {
			return common::status::failed_precondition("active control edge has invalid endpoint identity");
		}
		switch (edge.subtype) {
		case provider::compiled_control_edge_subtype::GENERIC:
		case provider::compiled_control_edge_subtype::FEEDBACK:
			break;
		default:
			return common::status::failed_precondition("active control edge has an invalid subtype");
		}
		const uint32_t source_row = active_row_by_stage[edge.from_stage_instance_index];
		const uint32_t destination_row = active_row_by_stage[edge.to_stage_instance_index];
		if (source_row >= exact_active.size() || destination_row >= exact_active.size()) {
			return common::status::failed_precondition(
				"active control edge lacks same-worker active endpoints");
		}
		exact_control_edges.push_back(edge_index);
		control_pairs.emplace_back(source_row, destination_row);
		if (inbound_control_counts[destination_row] == UINT32_MAX) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "active control edge count exceeds uint32");
		}
		++inbound_control_counts[destination_row];
	}
	std::sort(control_pairs.begin(), control_pairs.end());
	if (std::adjacent_find(control_pairs.begin(), control_pairs.end()) != control_pairs.end() ||
	    exact_control_edges != schedule.inbound_control_edge_indices) {
		return common::status::failed_precondition("active control-edge schedule is not exact and unique");
	}

	std::vector<std::pair<uint32_t, uint32_t>> projected_pull_pairs;
	for (uint32_t destination_row = 0u; destination_row < exact_active.size(); ++destination_row) {
		const auto &destination = topology_.stage_instances[exact_active[destination_row]];
		if (!std::is_sorted(destination.pull_source_stage_instance_indices.begin(),
				    destination.pull_source_stage_instance_indices.end()) ||
		    std::adjacent_find(destination.pull_source_stage_instance_indices.begin(),
				       destination.pull_source_stage_instance_indices.end()) !=
			    destination.pull_source_stage_instance_indices.end()) {
			return common::status::failed_precondition(
				"active PULL source projection is not sorted and unique");
		}
		for (const uint16_t source_stage : destination.pull_source_stage_instance_indices) {
			if (source_stage >= active_row_by_stage.size() ||
			    active_row_by_stage[source_stage] >= exact_active.size()) {
				return common::status::failed_precondition(
					"active PULL edge lacks same-worker active endpoints");
			}
			const uint32_t source_row = active_row_by_stage[source_stage];
			projected_pull_pairs.emplace_back(source_stage, destination.stage_instance_index);
			if (source_pull_counts[source_row] == UINT32_MAX) {
				return common::status(common::status_code::OUT_OF_RANGE,
						      "active PULL edge count exceeds uint32");
			}
			++source_pull_counts[source_row];
		}
	}
	std::sort(route_pull_pairs.begin(), route_pull_pairs.end());
	std::sort(projected_pull_pairs.begin(), projected_pull_pairs.end());
	if (std::adjacent_find(route_pull_pairs.begin(), route_pull_pairs.end()) != route_pull_pairs.end() ||
	    route_pull_pairs != projected_pull_pairs) {
		return common::status::failed_precondition("active PULL route and destination projections disagree");
	}
	for (uint32_t row = 0u; row < exact_active.size(); ++row) {
		const auto &logical =
			topology_.logical_stages[topology_.stage_instances[exact_active[row]].logical_stage_index];
		const bool control = (logical.trigger_mask &
				      static_cast<uint32_t>(provider::compiled_active_stage_trigger::CONTROL)) != 0u;
		const bool pull = (logical.trigger_mask &
				   static_cast<uint32_t>(provider::compiled_active_stage_trigger::PULL_READY)) != 0u;
		if (control != (inbound_control_counts[row] != 0u) || pull != (source_pull_counts[row] != 0u)) {
			return common::status::failed_precondition(
				"active control/PULL trigger and exact edge ownership disagree");
		}
	}
	return common::status::ok();
}

common::status_or<worker_active_stage_scheduler::implementation::slab_layout>
worker_active_stage_scheduler::implementation::compute_layout_() const noexcept
{
	const auto &schedule = topology_.worker_schedules[worker_index_];
	std::size_t retained_count = 0u;
	std::size_t timer_count = 0u;
	std::size_t control_count = 0u;
	std::size_t control_payload_bytes = 0u;
	std::size_t pull_count = 0u;
	std::size_t async_count = 0u;
	for (const uint32_t stage_index : schedule.active_stage_instance_indices) {
		const auto &stage = topology_.stage_instances[stage_index];
		const auto &logical = topology_.logical_stages[stage.logical_stage_index];
		if (logical.retained_packet_capacity > std::numeric_limits<std::size_t>::max() - retained_count ||
		    logical.timer_capacity > std::numeric_limits<std::size_t>::max() - timer_count ||
		    logical.control_mailbox_capacity > std::numeric_limits<std::size_t>::max() - control_count ||
		    logical.async_work_capacity > std::numeric_limits<std::size_t>::max() - async_count) {
			return common::status(
				common::status_code::OUT_OF_RANGE,
				kinetum::common::static_status_text(
					"active scheduler aggregate capacity exceeds the host size domain"));
		}
		retained_count += logical.retained_packet_capacity;
		timer_count += logical.timer_capacity;
		control_count += logical.control_mailbox_capacity;
		async_count += logical.async_work_capacity;
		std::size_t payload = 0u;
		if (!multiply_size(logical.control_mailbox_capacity, logical.control_message_capacity_bytes, payload) ||
		    payload > std::numeric_limits<std::size_t>::max() - control_payload_bytes) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      kinetum::common::static_status_text(
						      "active control payload slab exceeds the host size domain"));
		}
		control_payload_bytes += payload;
		if (stage.pull_source_stage_instance_indices.size() >
		    std::numeric_limits<std::size_t>::max() - pull_count) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      kinetum::common::static_status_text(
						      "active PULL edge population exceeds the host size domain"));
		}
		pull_count += stage.pull_source_stage_instance_indices.size();
	}

	const std::size_t rows = schedule.active_stage_instance_indices.size();
	const std::size_t stages = topology_.stage_instances.size();
	if (rows > UINT32_MAX || stages > UINT32_MAX || retained_count > UINT32_MAX || pull_count > UINT32_MAX ||
	    timer_count > UINT32_MAX || async_count > UINT32_MAX) {
		return common::status(
			common::status_code::OUT_OF_RANGE,
			kinetum::common::static_status_text("active scheduler compact population exceeds uint32"));
	}
	std::size_t relation_count = 0u;
	std::size_t handle_count = 0u;
	std::size_t async_handle_count = 0u;
	if (!multiply_size(rows, rows, relation_count) || !multiply_size(rows, WORK_BUDGET, handle_count) ||
	    !multiply_size(schedule.async_stage_instance_indices.size(), WORK_BUDGET, async_handle_count)) {
		return common::status(
			common::status_code::OUT_OF_RANGE,
			kinetum::common::static_status_text(
				"active scheduler relation or callback extent exceeds the host size domain"));
	}
	const std::size_t relation_word_count = (relation_count / 64u) + (relation_count % 64u == 0u ? 0u : 1u);
	std::size_t async_queue_capacity = 0u;
	if (async_count != 0u) {
		auto capacity_or = worker_async_work::queue_capacity_for(async_count);
		if (!capacity_or.is_ok()) {
			return std::move(capacity_or).error();
		}
		async_queue_capacity = capacity_or.value();
	}

	slab_layout layout;
	std::size_t cursor = 0u;
	if (!append_extent<instance_row>(rows, cursor, layout.rows_offset) ||
	    !append_extent<uint32_t>(stages, cursor, layout.stage_to_row_offset) ||
	    !append_extent<retained_slot>(retained_count, cursor, layout.retained_offset) ||
	    !append_extent<kinetum::algo::timer_wheel_view<>>(timer_count == 0u ? 0u : 1u, cursor,
							      layout.timer_wheel_offset) ||
	    !append_extent<kinetum::algo::timer_wheel_view<>::entry_type>(timer_count, cursor, layout.timers_offset) ||
	    !append_extent<uint32_t>(timer_count == 0u ? 0u : kinetum::algo::timer_wheel_view<>::FINE_SLOTS, cursor,
				     layout.timer_fine_heads_offset) ||
	    !append_extent<uint32_t>(timer_count == 0u ? 0u : kinetum::algo::timer_wheel_view<>::COARSE_SLOTS, cursor,
				     layout.timer_coarse_heads_offset) ||
	    !append_extent<kinetum::algo::work_queue_view<control_cell>>(rows, cursor, layout.control_queues_offset) ||
	    !append_extent<kinetum::algo::work_queue_view<control_cell>::storage_type>(control_count, cursor,
										       layout.control_storage_offset) ||
	    !append_extent<uint32_t>(control_count, cursor, layout.control_free_links_offset) ||
	    !append_extent<std::byte>(control_payload_bytes, cursor, layout.control_payload_offset) ||
	    !append_extent<control_cell>(handle_count, cursor, layout.control_delivery_offset) ||
	    !append_extent<uint64_t>(relation_word_count, cursor, layout.control_edge_bits_offset) ||
	    !append_extent<uint64_t>(relation_word_count, cursor, layout.control_feedback_bits_offset) ||
	    !append_extent<uint64_t>(relation_word_count, cursor, layout.pull_edge_bits_offset) ||
	    !append_extent<uint64_t>(relation_word_count, cursor, layout.pull_pending_bits_offset) ||
	    !append_extent<pull_edge>(pull_count, cursor, layout.pull_edges_offset) ||
	    !append_extent<uint32_t>(pull_count, cursor, layout.source_pull_indices_offset) ||
	    !append_extent<uint32_t>(handle_count, cursor, layout.pull_delivery_offset) ||
	    !append_extent<worker_async_work>(async_count == 0u ? 0u : 1u, cursor, layout.async_tracker_offset) ||
	    !append_extent<worker_async_work::slot_storage>(async_count, cursor, layout.async_slots_offset) ||
	    !append_extent<worker_async_work::completion_queue_storage>(async_queue_capacity, cursor,
									layout.async_queue_offset) ||
	    !append_extent<worker_async_delivery>(async_handle_count, cursor, layout.async_deliveries_offset) ||
	    !append_extent<kinetum_async_completion>(async_handle_count, cursor,
						     layout.async_completion_views_offset) ||
	    !append_extent<kinetum_active_timer_handle>(handle_count, cursor, layout.expired_offset) ||
	    !append_extent<kinetum_retained_packet_handle>(handle_count, cursor, layout.drain_retained_offset) ||
	    !append_extent<packet_origin_view>(WORK_BUDGET, cursor, layout.origin_views_offset) ||
	    !append_extent<packet_record *>(WORK_BUDGET, cursor, layout.origin_records_offset) ||
	    !append_extent<uint32_t>(KINETUM_MAX_BURST, cursor, layout.ingest_slots_offset) || cursor == 0u) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text(
					      "active scheduler checked slab layout is not representable"));
	}
	layout.total_bytes = cursor;
	return layout;
}

common::status worker_active_stage_scheduler::implementation::bind_slab_(
	const slab_layout &layout, std::span<const active_stage_context_binding *const> binding_by_stage,
	std::span<const uint32_t> source_pull_counts)
{
	const auto &schedule = topology_.worker_schedules[worker_index_];
	const auto &worker = topology_.transition_topology.workers[worker_index_];
	if (schedule.active_stage_instance_indices.size() > UINT32_MAX ||
	    topology_.stage_instances.size() > UINT32_MAX ||
	    binding_by_stage.size() != topology_.stage_instances.size() ||
	    source_pull_counts.size() != schedule.active_stage_instance_indices.size()) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "active scheduler compact identity population exceeds uint32");
	}
	auto slab_or = numa_memory_region::allocate({
		.usable_bytes = layout.total_bytes,
		.alignment_bytes = kinetum::algo::CACHE_LINE_SIZE,
		.host_numa_node = worker.numa_node,
	});
	if (!slab_or.is_ok()) {
		return slab_or.error();
	}
	slab_ = std::move(slab_or).value();
	auto *base = static_cast<std::byte *>(slab_.data());
	std::memset(base, 0, layout.total_bytes);
	const auto at = [base]<typename value_type>(std::size_t offset) noexcept {
		return reinterpret_cast<value_type *>(base + offset);
	};

	row_count_ = static_cast<uint32_t>(schedule.active_stage_instance_indices.size());
	stage_count_ = static_cast<uint32_t>(topology_.stage_instances.size());
	rows_ = at.template operator()<instance_row>(layout.rows_offset);
	stage_to_row_ = at.template operator()<uint32_t>(layout.stage_to_row_offset);
	auto *retained_base = at.template operator()<retained_slot>(layout.retained_offset);
	auto *timer_entries =
		at.template operator()<kinetum::algo::timer_wheel_view<>::entry_type>(layout.timers_offset);
	auto *timer_fine_heads = at.template operator()<uint32_t>(layout.timer_fine_heads_offset);
	auto *timer_coarse_heads = at.template operator()<uint32_t>(layout.timer_coarse_heads_offset);
	auto *control_queue_base =
		at.template operator()<kinetum::algo::work_queue_view<control_cell>>(layout.control_queues_offset);
	auto *control_storage_base = at.template operator()<kinetum::algo::work_queue_view<control_cell>::storage_type>(
		layout.control_storage_offset);
	auto *control_free_base = at.template operator()<uint32_t>(layout.control_free_links_offset);
	auto *payload_base = at.template operator()<std::byte>(layout.control_payload_offset);
	auto *control_delivery_base = at.template operator()<control_cell>(layout.control_delivery_offset);
	control_edge_bits_ = at.template operator()<uint64_t>(layout.control_edge_bits_offset);
	control_feedback_bits_ = at.template operator()<uint64_t>(layout.control_feedback_bits_offset);
	pull_edge_bits_ = at.template operator()<uint64_t>(layout.pull_edge_bits_offset);
	pull_pending_bits_ = at.template operator()<uint64_t>(layout.pull_pending_bits_offset);
	pull_edges_ = at.template operator()<pull_edge>(layout.pull_edges_offset);
	auto *source_pull_base = at.template operator()<uint32_t>(layout.source_pull_indices_offset);
	auto *pull_delivery_base = at.template operator()<uint32_t>(layout.pull_delivery_offset);
	auto *async_slots = at.template operator()<worker_async_work::slot_storage>(layout.async_slots_offset);
	auto *async_queue_storage =
		at.template operator()<worker_async_work::completion_queue_storage>(layout.async_queue_offset);
	auto *async_delivery_base = at.template operator()<worker_async_delivery>(layout.async_deliveries_offset);
	auto *async_completion_base =
		at.template operator()<kinetum_async_completion>(layout.async_completion_views_offset);
	auto *expired_base = at.template operator()<kinetum_active_timer_handle>(layout.expired_offset);
	auto *drain_base = at.template operator()<kinetum_retained_packet_handle>(layout.drain_retained_offset);
	origin_views_ = at.template operator()<packet_origin_view>(layout.origin_views_offset);
	origin_records_ = at.template operator()<packet_record *>(layout.origin_records_offset);
	ingest_slots_ = at.template operator()<uint32_t>(layout.ingest_slots_offset);
	for (std::size_t index = 0u; index < KINETUM_MAX_BURST; ++index) {
		std::construct_at(&ingest_slots_[index], INVALID_INDEX);
	}
	for (std::size_t index = 0u; index < WORK_BUDGET; ++index) {
		std::construct_at(&origin_views_[index]);
		std::construct_at(&origin_records_[index], nullptr);
	}
	std::fill_n(pull_delivery_base, static_cast<std::size_t>(row_count_) * WORK_BUDGET, INVALID_INDEX);

	std::fill_n(stage_to_row_, stage_count_, INVALID_INDEX);
	relation_bit_count_ = static_cast<uint64_t>(row_count_) * row_count_;

	std::size_t retained_cursor = 0u;
	std::size_t timer_total = 0u;
	std::size_t async_total = 0u;
	for (const uint32_t stage_index : schedule.active_stage_instance_indices) {
		const auto &logical =
			topology_.logical_stages[topology_.stage_instances[stage_index].logical_stage_index];
		timer_total += logical.timer_capacity;
		async_total += logical.async_work_capacity;
	}
	if (timer_total > UINT32_MAX || async_total > UINT32_MAX) {
		std::terminate();
	}
	timer_entry_capacity_ = static_cast<uint32_t>(timer_total);
	if (timer_entry_capacity_ != 0u) {
		for (uint32_t index = 0u; index < timer_entry_capacity_; ++index) {
			std::construct_at(&timer_entries[index]);
		}
		timer_wheel_ = std::construct_at(
			at.template operator()<kinetum::algo::timer_wheel_view<>>(layout.timer_wheel_offset),
			timer_entries, timer_entry_capacity_, timer_fine_heads, timer_coarse_heads);
	}
	if (async_total != 0u) {
		auto queue_capacity_or = worker_async_work::queue_capacity_for(async_total);
		if (!queue_capacity_or.is_ok()) {
			std::terminate();
		}
		for (std::size_t index = 0u; index < async_total; ++index) {
			std::construct_at(&async_slots[index]);
		}
		for (std::size_t index = 0u; index < queue_capacity_or.value(); ++index) {
			std::construct_at(&async_queue_storage[index]);
		}
		async_work_ = std::construct_at(at.template operator()<worker_async_work>(layout.async_tracker_offset),
						worker_async_work::construction_binding{
							.runtime_generation = ledger_.runtime_generation(),
							.worker_index = worker_index_,
							.ledger = &ledger_,
							.slots = async_slots,
							.slot_count = static_cast<uint32_t>(async_total),
							.queue_storage = async_queue_storage,
							.queue_capacity = queue_capacity_or.value(),
						});
		async_slots_ = async_slots;
	}
	std::size_t control_cursor = 0u;
	std::size_t payload_cursor = 0u;
	std::size_t async_cursor = 0u;
	std::size_t async_delivery_cursor = 0u;
	for (uint32_t row_index = 0u; row_index < row_count_; ++row_index) {
		std::construct_at(&rows_[row_index]);
		auto &row = rows_[row_index];
		const uint32_t stage_index = schedule.active_stage_instance_indices[row_index];
		const auto &stage = topology_.stage_instances[stage_index];
		const auto &logical = topology_.logical_stages[stage.logical_stage_index];
		if (!stage.module_context_index.has_value() ||
		    *stage.module_context_index >= topology_.module_contexts.size()) {
			std::terminate();
		}
		const auto &compiled_context = topology_.module_contexts[*stage.module_context_index];
		const auto *binding = binding_by_stage[stage_index];
		if (binding == nullptr || binding->store == nullptr || binding->descriptor == nullptr ||
		    binding->module_context_index != compiled_context.module_context_index ||
		    stage_to_row_[stage_index] != INVALID_INDEX) {
			std::terminate();
		}
		stage_to_row_[stage_index] = row_index;
		row.stage_instance_index = stage_index;
		row.module_context_index = compiled_context.module_context_index;
		row.region_id = topology_.execution_regions[stage.region_index].region_id;
		row.trigger_mask = logical.trigger_mask;
		row.store = binding->store;
		row.descriptor = binding->descriptor;
		row.retained_base_index = static_cast<uint32_t>(retained_cursor);
		row.retained_capacity = logical.retained_packet_capacity;
		row.retained_byte_capacity = logical.retained_byte_capacity;
		row.retained = retained_base + retained_cursor;
		row.retained_free_head = row.retained_capacity == 0u ? INVALID_INDEX : 0u;
		for (uint32_t index = 0u; index < row.retained_capacity; ++index) {
			std::construct_at(&row.retained[index]);
			row.retained[index].next_free = index + 1u < row.retained_capacity ? index + 1u : INVALID_INDEX;
		}
		retained_cursor += row.retained_capacity;

		row.timer_capacity = logical.timer_capacity;
		row.async_base_index = static_cast<uint32_t>(async_cursor);
		row.async_capacity = logical.async_work_capacity;
		const auto async_grace_ms =
			std::chrono::duration_cast<std::chrono::milliseconds>(logical.async_cancel_grace);
		if ((row.async_capacity == 0u) !=
			    (logical.async_cancel_grace == std::chrono::steady_clock::duration::zero()) ||
		    (row.async_capacity != 0u &&
		     (async_grace_ms <= std::chrono::milliseconds::zero() ||
		      std::chrono::duration_cast<std::chrono::steady_clock::duration>(async_grace_ms) !=
			      logical.async_cancel_grace ||
		      static_cast<uint64_t>(async_grace_ms.count()) > UINT64_MAX / UINT64_C(1000000)))) {
			std::terminate();
		}
		row.async_cancel_grace_ns = row.async_capacity == 0u ?
						    0u :
						    static_cast<uint64_t>(async_grace_ms.count()) * UINT64_C(1000000);
		row.async_free_head = row.async_capacity == 0u ? INVALID_INDEX : row.async_base_index;
		for (uint32_t index = 0u; index < row.async_capacity; ++index) {
			const uint32_t global_index = row.async_base_index + index;
			async_slots[global_index].owner_claimed = false;
			async_slots[global_index].next_free = index + 1u < row.async_capacity ? global_index + 1u :
												INVALID_INDEX;
		}
		async_cursor += row.async_capacity;
		if (row.async_capacity != 0u) {
			row.async_deliveries = async_delivery_base + async_delivery_cursor;
			row.async_completion_views = async_completion_base + async_delivery_cursor;
			for (std::size_t index = 0u; index < WORK_BUDGET; ++index) {
				std::construct_at(&row.async_deliveries[index]);
				std::construct_at(&row.async_completion_views[index]);
			}
			async_delivery_cursor += WORK_BUDGET;
		}

		row.control_capacity = logical.control_mailbox_capacity;
		row.control_payload_capacity = logical.control_message_capacity_bytes;
		row.control_payloads = payload_base + payload_cursor;
		row.control_delivery = control_delivery_base + static_cast<std::size_t>(row_index) * WORK_BUDGET;
		if (row.control_capacity != 0u) {
			row.control_queue = std::construct_at(&control_queue_base[row_index],
							      control_storage_base + control_cursor,
							      row.control_capacity);
			row.control_payload_next_free = control_free_base + control_cursor;
			row.control_payload_free_head = 0u;
			for (uint32_t index = 0u; index < row.control_capacity; ++index) {
				row.control_payload_next_free[index] =
					index + 1u < row.control_capacity ? index + 1u : INVALID_INDEX;
			}
		}
		control_cursor += row.control_capacity;
		payload_cursor += static_cast<std::size_t>(row.control_capacity) * row.control_payload_capacity;

		row.expired = expired_base + static_cast<std::size_t>(row_index) * WORK_BUDGET;
		row.drain_retained = drain_base + static_cast<std::size_t>(row_index) * WORK_BUDGET;
		row.pull_delivery = pull_delivery_base + static_cast<std::size_t>(row_index) * WORK_BUDGET;
	}
	if (async_cursor != async_total ||
	    async_delivery_cursor != schedule.async_stage_instance_indices.size() * WORK_BUDGET ||
	    ((async_total == 0u) != (async_work_ == nullptr))) {
		std::terminate();
	}

	for (const auto &edge : topology_.control_edges) {
		if (edge.worker_index != worker_index_) {
			continue;
		}
		const uint32_t source_row = stage_to_row_[edge.from_stage_instance_index];
		const uint32_t destination_row = stage_to_row_[edge.to_stage_instance_index];
		if (source_row >= row_count_ || destination_row >= row_count_) {
			std::terminate();
		}
		const uint64_t relation_bit = static_cast<uint64_t>(source_row) * row_count_ + destination_row;
		set_relation_bit_(control_edge_bits_, relation_bit);
		switch (edge.subtype) {
		case provider::compiled_control_edge_subtype::GENERIC:
			break;
		case provider::compiled_control_edge_subtype::FEEDBACK:
			set_relation_bit_(control_feedback_bits_, relation_bit);
			break;
		}
	}

	uint32_t source_pull_cursor = 0u;
	for (uint32_t row_index = 0u; row_index < row_count_; ++row_index) {
		rows_[row_index].source_pull_edge_indices = source_pull_base + source_pull_cursor;
		rows_[row_index].source_pull_edge_count = 0u;
		source_pull_cursor += source_pull_counts[row_index];
	}
	pull_edge_count_ = 0u;
	for (uint32_t destination_row = 0u; destination_row < row_count_; ++destination_row) {
		const auto &stage = topology_.stage_instances[rows_[destination_row].stage_instance_index];
		for (const uint16_t source_stage : stage.pull_source_stage_instance_indices) {
			if (source_stage >= stage_count_ || stage_to_row_[source_stage] >= row_count_ ||
			    pull_edge_count_ == UINT32_MAX) {
				std::terminate();
			}
			const uint32_t edge_index = pull_edge_count_++;
			const uint32_t source_row = stage_to_row_[source_stage];
			const uint64_t relation_bit = static_cast<uint64_t>(destination_row) * row_count_ + source_row;
			std::construct_at(&pull_edges_[edge_index]);
			pull_edges_[edge_index].source_row = source_row;
			pull_edges_[edge_index].destination_row = destination_row;
			pull_edges_[edge_index].relation_bit = relation_bit;
			set_relation_bit_(pull_edge_bits_, relation_bit);
			auto &source = rows_[source_row];
			if (source.source_pull_edge_count >= source_pull_counts[source_row]) {
				std::terminate();
			}
			source.source_pull_edge_indices[source.source_pull_edge_count++] = edge_index;
		}
	}
	for (uint32_t row_index = 0u; row_index < row_count_; ++row_index) {
		if (rows_[row_index].source_pull_edge_count != source_pull_counts[row_index]) {
			std::terminate();
		}
	}
	if (pull_edge_count_ != source_pull_cursor) {
		std::terminate();
	}

	return common::status::ok();
}

common::status worker_active_stage_scheduler::implementation::initialize()
{
	if (worker_index_ >= topology_.worker_schedules.size() ||
	    worker_index_ >= topology_.transition_topology.workers.size()) {
		return common::status::failed_precondition(
			"active scheduler worker identity is outside compiled topology");
	}
	std::vector<const active_stage_context_binding *> binding_by_stage(topology_.stage_instances.size(), nullptr);
	std::vector<bool> context_bound(topology_.module_contexts.size(), false);
	for (const auto &binding : context_bindings_) {
		if (binding.stage_instance_index >= binding_by_stage.size() ||
		    binding.module_context_index >= context_bound.size() || binding.store == nullptr ||
		    binding.descriptor == nullptr || binding_by_stage[binding.stage_instance_index] != nullptr ||
		    context_bound[binding.module_context_index]) {
			return common::status::failed_precondition(
				"active context bindings are incomplete, duplicate, or outside compiled identity");
		}
		binding_by_stage[binding.stage_instance_index] = &binding;
		context_bound[binding.module_context_index] = true;
	}
	const auto &schedule = topology_.worker_schedules[worker_index_];
	std::vector<uint32_t> source_pull_counts(schedule.active_stage_instance_indices.size(), 0u);
	if (const auto status = validate_topology_(binding_by_stage, source_pull_counts); !status.is_ok()) {
		return status;
	}
	auto layout_or = compute_layout_();
	if (!layout_or.is_ok()) {
		return layout_or.error();
	}
	auto status = bind_slab_(layout_or.value(), binding_by_stage, source_pull_counts);
	if (status.is_ok()) {
		context_bindings_ = {};
	}
	return status;
}

worker_active_stage_scheduler::implementation::instance_row *
worker_active_stage_scheduler::implementation::row_for_stage_(uint32_t stage_index) noexcept
{
	if (stage_index >= stage_count_ || stage_to_row_ == nullptr) {
		return nullptr;
	}
	const uint32_t row = stage_to_row_[stage_index];
	return row < row_count_ ? &rows_[row] : nullptr;
}

const worker_active_stage_scheduler::implementation::instance_row *
worker_active_stage_scheduler::implementation::row_for_stage_(uint32_t stage_index) const noexcept
{
	if (stage_index >= stage_count_ || stage_to_row_ == nullptr) {
		return nullptr;
	}
	const uint32_t row = stage_to_row_[stage_index];
	return row < row_count_ ? &rows_[row] : nullptr;
}

bool worker_active_stage_scheduler::implementation::relation_bit_(const uint64_t *words, uint64_t bit) const noexcept
{
	if (words == nullptr || bit >= relation_bit_count_) {
		std::terminate();
	}
	return (words[bit / 64u] & (UINT64_C(1) << (bit % 64u))) != 0u;
}

void worker_active_stage_scheduler::implementation::set_relation_bit_(uint64_t *words, uint64_t bit) noexcept
{
	if (relation_bit_(words, bit)) {
		std::terminate();
	}
	words[bit / 64u] |= UINT64_C(1) << (bit % 64u);
}

void worker_active_stage_scheduler::implementation::clear_relation_bit_(uint64_t *words, uint64_t bit) noexcept
{
	if (!relation_bit_(words, bit)) {
		std::terminate();
	}
	words[bit / 64u] &= ~(UINT64_C(1) << (bit % 64u));
}

uint32_t worker_active_stage_scheduler::implementation::allocate_retained_(instance_row &row,
									   packet_record &record) noexcept
{
	const uint64_t bytes = record.storage.length;
	if (row.retained_free_head == INVALID_INDEX || bytes == 0u ||
	    row.retained_owned_bytes > row.retained_byte_capacity ||
	    bytes > row.retained_byte_capacity - row.retained_owned_bytes) {
		return INVALID_INDEX;
	}
	const uint32_t index = row.retained_free_head;
	if (index >= row.retained_capacity) {
		std::terminate();
	}
	auto &slot = row.retained[index];
	if (slot.state != retained_state::EMPTY || slot.record != nullptr) {
		std::terminate();
	}
	row.retained_free_head = slot.next_free;
	slot.next_free = INVALID_INDEX;
	slot.generation = next_generation(slot.generation);
	slot.record = &record;
	slot.epoch = record.metadata.epoch;
	slot.bytes = bytes;
	slot.next_stage = KINETUM_NEXT_STAGE_UNSET;
	slot.next_live = INVALID_INDEX;
	slot.previous_live = INVALID_INDEX;
	slot.next_pending = INVALID_INDEX;
	slot.state = retained_state::PROVISIONAL;
	acquire_retained_accounting_(row, slot);
	return index;
}

void worker_active_stage_scheduler::implementation::commit_retained_(instance_row &row, uint32_t slot_index) noexcept
{
	if (slot_index >= row.retained_capacity) {
		std::terminate();
	}
	auto &slot = row.retained[slot_index];
	if (slot.state != retained_state::PROVISIONAL || slot.record == nullptr || slot.epoch != active_epoch_ ||
	    slot.generation == 0u || slot.next_live != INVALID_INDEX || slot.previous_live != INVALID_INDEX ||
	    slot.next_pending != INVALID_INDEX) {
		std::terminate();
	}
	slot.state = retained_state::RETAINED;
	slot.ingest_lane = UINT8_MAX;
	slot.next_live = row.retained_live_head;
	if (row.retained_live_head != INVALID_INDEX) {
		row.retained[row.retained_live_head].previous_live = slot_index;
	}
	row.retained_live_head = slot_index;
}

void worker_active_stage_scheduler::implementation::commit_async_retained_(instance_row &row,
									   uint32_t slot_index) noexcept
{
	if (slot_index >= row.retained_capacity) {
		std::terminate();
	}
	auto &slot = row.retained[slot_index];
	if (slot.state != retained_state::ASYNC_OWNED || slot.record == nullptr || slot.epoch != active_epoch_ ||
	    slot.generation == 0u || slot.next_live != INVALID_INDEX || slot.previous_live != INVALID_INDEX ||
	    slot.next_pending != INVALID_INDEX) {
		std::terminate();
	}
	slot.ingest_lane = UINT8_MAX;
}

void worker_active_stage_scheduler::implementation::acquire_retained_accounting_(instance_row &row,
										 const retained_slot &slot) noexcept
{
	if (slot.bytes == 0u || row.retained_owned_count >= row.retained_capacity ||
	    row.retained_owned_bytes > row.retained_byte_capacity ||
	    slot.bytes > row.retained_byte_capacity - row.retained_owned_bytes) {
		std::terminate();
	}
	++row.retained_owned_count;
	row.retained_owned_bytes += slot.bytes;
}

void worker_active_stage_scheduler::implementation::remove_live_retained_(instance_row &row,
									  uint32_t slot_index) noexcept
{
	auto &slot = row.retained[slot_index];
	if (slot.state != retained_state::RETAINED) {
		std::terminate();
	}
	if (slot.previous_live != INVALID_INDEX) {
		row.retained[slot.previous_live].next_live = slot.next_live;
	} else if (row.retained_live_head == slot_index) {
		row.retained_live_head = slot.next_live;
	} else {
		std::terminate();
	}
	if (slot.next_live != INVALID_INDEX) {
		row.retained[slot.next_live].previous_live = slot.previous_live;
	}
	slot.next_live = INVALID_INDEX;
	slot.previous_live = INVALID_INDEX;
}

void worker_active_stage_scheduler::implementation::append_pending_retained_(instance_row &row,
									     uint32_t slot_index) noexcept
{
	auto &slot = row.retained[slot_index];
	if ((slot.state != retained_state::EMIT_PENDING && slot.state != retained_state::DROP_PENDING &&
	     slot.state != retained_state::RECIRCULATE_PENDING) ||
	    slot.next_pending != INVALID_INDEX) {
		std::terminate();
	}
	if (row.retained_pending_tail == INVALID_INDEX) {
		if (row.retained_pending_head != INVALID_INDEX) {
			std::terminate();
		}
		row.retained_pending_head = slot_index;
	} else {
		row.retained[row.retained_pending_tail].next_pending = slot_index;
	}
	row.retained_pending_tail = slot_index;
}

void worker_active_stage_scheduler::implementation::free_retained_(instance_row &row, uint32_t slot_index) noexcept
{
	if (slot_index >= row.retained_capacity || row.retained_owned_count == 0u) {
		std::terminate();
	}
	auto &slot = row.retained[slot_index];
	if ((slot.state != retained_state::EMIT_PENDING && slot.state != retained_state::DROP_PENDING &&
	     slot.state != retained_state::RECIRCULATE_PENDING) ||
	    slot.record == nullptr || slot.bytes == 0u || row.retained_owned_bytes < slot.bytes) {
		std::terminate();
	}
	--row.retained_owned_count;
	row.retained_owned_bytes -= slot.bytes;
	slot.record = nullptr;
	slot.epoch = 0u;
	slot.bytes = 0u;
	slot.next_stage = KINETUM_NEXT_STAGE_UNSET;
	slot.state = retained_state::EMPTY;
	slot.ingest_lane = UINT8_MAX;
	slot.next_pending = INVALID_INDEX;
	slot.next_free = row.retained_free_head;
	row.retained_free_head = slot_index;
}

worker_active_stage_scheduler::implementation::retained_slot *
worker_active_stage_scheduler::implementation::resolve_retained_(instance_row &row,
								 kinetum_retained_packet_handle handle) noexcept
{
	if (handle.value == KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE) {
		return nullptr;
	}
	const uint32_t global_index = handle_slot(handle.value);
	const uint32_t generation = handle_generation(handle.value);
	if (global_index < row.retained_base_index || global_index - row.retained_base_index >= row.retained_capacity) {
		return nullptr;
	}
	const uint32_t index = global_index - row.retained_base_index;
	auto &slot = row.retained[index];
	return generation != 0u && slot.generation == generation && slot.state == retained_state::RETAINED &&
			       slot.record != nullptr && slot.epoch == active_epoch_ ?
		       &slot :
		       nullptr;
}

worker_active_stage_scheduler::implementation::invocation &
worker_active_stage_scheduler::implementation::invocation_from_(kinetum_active_ctx *context) noexcept
{
	if (context == nullptr || context->runtime_services == nullptr ||
	    context->runtime_services->platform_opaque == nullptr) {
		std::terminate();
	}
	auto &active = *static_cast<invocation *>(context->runtime_services->platform_opaque);
	if (active.owner == nullptr || active.row == nullptr || !active.row->callback_active ||
	    context->active_epoch != active.owner->active_epoch_ || context->now_ns != active.now_ns ||
	    context->active_packet_config != active.row->store->owner_executable_view().packet_config) {
		std::terminate();
	}
	return active;
}

worker_active_stage_scheduler::implementation::invocation &
worker_active_stage_scheduler::implementation::invocation_from_(kinetum_active_runtime_services *services) noexcept
{
	if (services == nullptr || services->platform_opaque == nullptr) {
		std::terminate();
	}
	auto &active = *static_cast<invocation *>(services->platform_opaque);
	if (active.owner == nullptr || active.row == nullptr || !active.row->callback_active ||
	    active.row->async_capacity == 0u || services->begin_async != &begin_async_ ||
	    services->begin_async_retained != &begin_async_retained_ || services->abort_async != &abort_async_ ||
	    services->recirculate_retained != &recirculate_retained_) {
		std::terminate();
	}
	return active;
}

uint32_t worker_active_stage_scheduler::implementation::emit_(kinetum_active_ctx *context,
							      const kinetum_emit_batch_t *batch) noexcept
{
	auto &active = invocation_from_(context);
	if (active.owner->phase_ != phase::OPEN || batch == nullptr || active.remaining_budget == 0u) {
		return 0u;
	}
	const uint32_t accepted = active.owner->packet_operations_.emit_origins(
		active.owner->packet_operations_.state, active.row->stage_instance_index, active.owner->active_epoch_,
		active.now_ns, batch, active.remaining_budget,
		std::span<packet_origin_view>(active.owner->origin_views_, WORK_BUDGET),
		std::span<packet_record *>(active.owner->origin_records_, WORK_BUDGET));
	if (accepted > active.remaining_budget || accepted > batch->count) {
		std::terminate();
	}
	active.remaining_budget -= accepted;
	return accepted;
}

kinetum_retained_packet_handle worker_active_stage_scheduler::implementation::retain_input_(kinetum_active_ctx *context,
											    uint32_t lane) noexcept
{
	auto &active = invocation_from_(context);
	kinetum_retained_packet_handle invalid{KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE};
	if (lane >= active.ingest_records.size()) {
		return invalid;
	}
	if (active.owner->ingest_slots_[lane] != INVALID_INDEX) {
		std::terminate();
	}
	if (active.remaining_budget == 0u) {
		return invalid;
	}
	const uint32_t slot = active.owner->allocate_retained_(*active.row, *active.ingest_records[lane]);
	if (slot == INVALID_INDEX) {
		return invalid;
	}
	active.owner->ingest_slots_[lane] = slot;
	active.row->retained[slot].ingest_lane = static_cast<uint8_t>(lane);
	--active.remaining_budget;
	return kinetum_retained_packet_handle{
		make_handle(active.row->retained[slot].generation, active.row->retained_base_index + slot)};
}

bool worker_active_stage_scheduler::implementation::emit_retained_(kinetum_active_ctx *context,
								   kinetum_retained_packet_handle handle,
								   uint16_t next_stage) noexcept
{
	auto &active = invocation_from_(context);
	if (active.remaining_budget == 0u ||
	    (next_stage != KINETUM_NEXT_STAGE_UNSET && next_stage >= active.owner->topology_.logical_stages.size())) {
		return false;
	}
	auto *slot = active.owner->resolve_retained_(*active.row, handle);
	if (slot == nullptr) {
		return false;
	}
	const uint32_t index = static_cast<uint32_t>(slot - active.row->retained);
	active.owner->remove_live_retained_(*active.row, index);
	slot->next_stage = next_stage;
	slot->state = retained_state::EMIT_PENDING;
	active.owner->append_pending_retained_(*active.row, index);
	--active.remaining_budget;
	return true;
}

bool worker_active_stage_scheduler::implementation::drop_retained_(kinetum_active_ctx *context,
								   kinetum_retained_packet_handle handle) noexcept
{
	auto &active = invocation_from_(context);
	if (active.remaining_budget == 0u) {
		return false;
	}
	auto *slot = active.owner->resolve_retained_(*active.row, handle);
	if (slot == nullptr) {
		return false;
	}
	const uint32_t index = static_cast<uint32_t>(slot - active.row->retained);
	active.owner->remove_live_retained_(*active.row, index);
	slot->state = retained_state::DROP_PENDING;
	active.owner->append_pending_retained_(*active.row, index);
	--active.remaining_budget;
	return true;
}

kinetum_active_timer_handle worker_active_stage_scheduler::implementation::arm_timer_(kinetum_active_ctx *context,
										      uint64_t delay_ns) noexcept
{
	auto &active = invocation_from_(context);
	kinetum_active_timer_handle invalid{KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE};
	if (active.owner->phase_ != phase::OPEN || delay_ns == 0u || active.remaining_budget == 0u ||
	    active.owner->timer_wheel_ == nullptr || active.row->timer_armed_count >= active.row->timer_capacity ||
	    delay_ns > std::numeric_limits<uint64_t>::max() - (ACTIVE_TIMER_QUANTUM_NS - 1u)) {
		return invalid;
	}
	const uint64_t delay_ticks = (delay_ns + ACTIVE_TIMER_QUANTUM_NS - 1u) / ACTIVE_TIMER_QUANTUM_NS;
	if (delay_ticks == 0u || delay_ticks >= kinetum::algo::timer_wheel_view<>::MAX_RANGE) {
		return invalid;
	}
	const uint32_t row_index = static_cast<uint32_t>(active.row - active.owner->rows_);
	const auto handle = active.owner->timer_wheel_->arm(delay_ticks, row_index);
	if (!handle.valid()) {
		return invalid;
	}
	++active.row->timer_armed_count;
	++active.row->timer_owned_count;
	active.owner->ledger_.acquire(active.owner->active_epoch_);
	--active.remaining_budget;
	return kinetum_active_timer_handle{handle.value};
}

bool worker_active_stage_scheduler::implementation::cancel_timer_(kinetum_active_ctx *context,
								  kinetum_active_timer_handle handle) noexcept
{
	auto &active = invocation_from_(context);
	if (active.remaining_budget == 0u || handle.value == KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE) {
		return false;
	}
	if (active.owner->timer_wheel_ == nullptr || active.row->timer_armed_count == 0u ||
	    active.row->timer_owned_count == 0u) {
		return false;
	}
	const kinetum::algo::timer_handle wheel_handle{handle.value};
	const uint32_t row_index = static_cast<uint32_t>(active.row - active.owner->rows_);
	if (active.owner->timer_wheel_->user_key(wheel_handle) != row_index ||
	    !active.owner->timer_wheel_->cancel(wheel_handle)) {
		return false;
	}
	--active.row->timer_armed_count;
	--active.row->timer_owned_count;
	active.owner->ledger_.retire(active.owner->active_epoch_);
	--active.remaining_budget;
	return true;
}

bool worker_active_stage_scheduler::implementation::post_control_(kinetum_active_ctx *context, uint16_t peer_idx,
								  const kinetum_control_msg *message) noexcept
{
	auto &active = invocation_from_(context);
	if (active.owner->phase_ != phase::OPEN || active.remaining_budget == 0u || message == nullptr ||
	    (message->len != 0u && message->data == nullptr) || peer_idx >= active.owner->stage_count_) {
		return false;
	}
	const uint32_t target_row_index = active.owner->stage_to_row_[peer_idx];
	const uint32_t source_row_index = static_cast<uint32_t>(active.row - active.owner->rows_);
	if (target_row_index >= active.owner->row_count_) {
		return false;
	}
	const uint64_t relation_bit =
		static_cast<uint64_t>(source_row_index) * active.owner->row_count_ + target_row_index;
	if (!active.owner->relation_bit_(active.owner->control_edge_bits_, relation_bit)) {
		return false;
	}
	const uint32_t expected_subtype =
		active.owner->relation_bit_(active.owner->control_feedback_bits_, relation_bit) ?
			KINETUM_CONTROL_SUBTYPE_FEEDBACK :
			KINETUM_CONTROL_SUBTYPE_GENERIC;
	if (message->subtype != expected_subtype) {
		return false;
	}
	auto &target = active.owner->rows_[target_row_index];
	if (target.control_queue == nullptr || target.control_payload_free_head == INVALID_INDEX ||
	    target.control_queue->full() || message->len > target.control_payload_capacity) {
		return false;
	}
	const uint32_t payload_slot = target.control_payload_free_head;
	if (payload_slot >= target.control_capacity) {
		std::terminate();
	}
	target.control_payload_free_head = target.control_payload_next_free[payload_slot];
	target.control_payload_next_free[payload_slot] = INVALID_INDEX;
	auto *payload =
		target.control_payloads + static_cast<std::size_t>(payload_slot) * target.control_payload_capacity;
	if (message->len != 0u) {
		std::memcpy(payload, message->data, message->len);
	}
	const control_cell cell{
		.epoch = active.owner->active_epoch_,
		.subtype = message->subtype,
		.length = message->len,
		.payload_slot = payload_slot,
	};
	if (!target.control_queue->try_push(cell)) {
		target.control_payload_next_free[payload_slot] = target.control_payload_free_head;
		target.control_payload_free_head = payload_slot;
		return false;
	}
	if (target.control_owned_count == UINT32_MAX) {
		std::terminate();
	}
	++target.control_owned_count;
	active.owner->ledger_.acquire(active.owner->active_epoch_);
	--active.remaining_budget;
	return true;
}

bool worker_active_stage_scheduler::implementation::request_pull_(kinetum_active_ctx *context,
								  uint16_t upstream_idx) noexcept
{
	auto &active = invocation_from_(context);
	if (active.owner->phase_ != phase::OPEN || active.remaining_budget == 0u ||
	    upstream_idx >= active.owner->stage_count_) {
		return false;
	}
	const uint32_t source_row = active.owner->stage_to_row_[upstream_idx];
	const uint32_t destination_row = static_cast<uint32_t>(active.row - active.owner->rows_);
	if (source_row >= active.owner->row_count_) {
		return false;
	}
	const uint64_t relation_bit = static_cast<uint64_t>(destination_row) * active.owner->row_count_ + source_row;
	if (!active.owner->relation_bit_(active.owner->pull_edge_bits_, relation_bit)) {
		return false;
	}
	if (active.owner->relation_bit_(active.owner->pull_pending_bits_, relation_bit)) {
		return true;
	}
	active.owner->set_relation_bit_(active.owner->pull_pending_bits_, relation_bit);
	active.owner->ledger_.acquire(active.owner->active_epoch_);
	--active.remaining_budget;
	return true;
}

void worker_active_stage_scheduler::implementation::release_async_slot_(instance_row &row, uint32_t slot_index) noexcept
{
	if (async_work_ == nullptr || async_slots_ == nullptr || slot_index < row.async_base_index ||
	    slot_index - row.async_base_index >= row.async_capacity || row.async_slot_owned_count == 0u ||
	    !async_work_->slot_release_ready(slot_index)) {
		std::terminate();
	}
	async_slots_[slot_index].owner_claimed = false;
	async_slots_[slot_index].next_free = row.async_free_head;
	row.async_free_head = slot_index;
	--row.async_slot_owned_count;
}

kinetum_retained_packet_handle
worker_active_stage_scheduler::implementation::restore_async_retained_(instance_row &row, uint32_t slot_index,
								       bool publish_live) noexcept
{
	if (slot_index >= row.retained_capacity) {
		std::terminate();
	}
	auto &slot = row.retained[slot_index];
	if (slot.state != retained_state::ASYNC_OWNED || slot.record == nullptr || slot.epoch != active_epoch_ ||
	    slot.generation == 0u || slot.next_live != INVALID_INDEX || slot.previous_live != INVALID_INDEX ||
	    slot.next_pending != INVALID_INDEX) {
		std::terminate();
	}
	slot.state = publish_live ? retained_state::RETAINED : retained_state::PROVISIONAL;
	if (publish_live) {
		slot.ingest_lane = UINT8_MAX;
		slot.next_live = row.retained_live_head;
		if (row.retained_live_head != INVALID_INDEX) {
			row.retained[row.retained_live_head].previous_live = slot_index;
		}
		row.retained_live_head = slot_index;
	}
	return kinetum_retained_packet_handle{make_handle(slot.generation, row.retained_base_index + slot_index)};
}

kinetum_async_token
worker_active_stage_scheduler::implementation::begin_async_(kinetum_active_runtime_services *services,
							    uint64_t user_tag) noexcept
{
	auto &active = invocation_from_(services);
	if (active.owner->phase_ != phase::OPEN || active.remaining_budget == 0u ||
	    active.owner->async_work_ == nullptr || active.owner->async_slots_ == nullptr ||
	    active.row->async_capacity == 0u) {
		return kinetum_invalid_async_token();
	}
	if (active.row->async_free_head == INVALID_INDEX) {
		if (active.row->async_slot_owned_count != active.row->async_capacity) {
			std::terminate();
		}
		return kinetum_invalid_async_token();
	}
	if (active.row->async_slot_owned_count >= active.row->async_capacity) {
		std::terminate();
	}
	const uint32_t slot_index = active.row->async_free_head;
	if (slot_index < active.row->async_base_index ||
	    slot_index - active.row->async_base_index >= active.row->async_capacity ||
	    active.owner->async_slots_[slot_index].owner_claimed ||
	    active.owner->async_slots_[slot_index].next_free == slot_index) {
		std::terminate();
	}
	active.row->async_free_head = active.owner->async_slots_[slot_index].next_free;
	active.owner->async_slots_[slot_index].next_free = INVALID_INDEX;
	active.owner->async_slots_[slot_index].owner_claimed = true;
	const auto token = active.owner->async_work_->begin({
		.slot_index = slot_index,
		.owner_index = static_cast<uint32_t>(active.row - active.owner->rows_),
		.epoch = active.owner->active_epoch_,
		.user_tag = user_tag,
		.retained_slot = UINT32_MAX,
		.standalone = true,
	});
	++active.row->async_slot_owned_count;
	--active.remaining_budget;
	return token;
}

kinetum_async_token worker_active_stage_scheduler::implementation::begin_async_retained_(
	kinetum_active_runtime_services *services, kinetum_retained_packet_handle retained, uint64_t user_tag,
	kinetum_async_packet_view *out_view) noexcept
{
	if (out_view != nullptr) {
		*out_view = {};
	}
	auto &active = invocation_from_(services);
	if (out_view == nullptr || active.owner->phase_ != phase::OPEN || active.remaining_budget == 0u ||
	    active.owner->async_work_ == nullptr || active.owner->async_slots_ == nullptr ||
	    active.row->async_capacity == 0u) {
		return kinetum_invalid_async_token();
	}
	if (active.row->async_free_head == INVALID_INDEX) {
		if (active.row->async_slot_owned_count != active.row->async_capacity) {
			std::terminate();
		}
		return kinetum_invalid_async_token();
	}
	if (active.row->async_slot_owned_count >= active.row->async_capacity) {
		std::terminate();
	}
	retained_slot *retained_owner = nullptr;
	bool provisional = false;
	const uint32_t global_retained_slot = handle_slot(retained.value);
	if (global_retained_slot >= active.row->retained_base_index &&
	    global_retained_slot - active.row->retained_base_index < active.row->retained_capacity) {
		const uint32_t local_slot = global_retained_slot - active.row->retained_base_index;
		auto &candidate = active.row->retained[local_slot];
		const uint32_t lane = candidate.ingest_lane;
		if (lane < active.ingest_records.size() && active.owner->ingest_slots_[lane] == local_slot &&
		    (active.provisional_async_mask & (UINT64_C(1) << lane)) == 0u &&
		    handle_generation(retained.value) == candidate.generation &&
		    candidate.state == retained_state::PROVISIONAL && candidate.record == active.ingest_records[lane] &&
		    candidate.epoch == active.owner->active_epoch_ && candidate.next_live == INVALID_INDEX &&
		    candidate.previous_live == INVALID_INDEX && candidate.next_pending == INVALID_INDEX) {
			retained_owner = &candidate;
			provisional = true;
		}
	}
	if (retained_owner == nullptr) {
		retained_owner = active.owner->resolve_retained_(*active.row, retained);
	}
	if (retained_owner == nullptr || retained_owner->record->storage.data == nullptr ||
	    retained_owner->record->storage.length == 0u ||
	    retained_owner->record->storage.contiguous_length < retained_owner->record->storage.length) {
		return kinetum_invalid_async_token();
	}
	const uint32_t retained_index = static_cast<uint32_t>(retained_owner - active.row->retained);
	const uint32_t slot_index = active.row->async_free_head;
	if (slot_index < active.row->async_base_index ||
	    slot_index - active.row->async_base_index >= active.row->async_capacity ||
	    active.owner->async_slots_[slot_index].owner_claimed ||
	    active.owner->async_slots_[slot_index].next_free == slot_index) {
		std::terminate();
	}
	active.row->async_free_head = active.owner->async_slots_[slot_index].next_free;
	active.owner->async_slots_[slot_index].next_free = INVALID_INDEX;
	active.owner->async_slots_[slot_index].owner_claimed = true;
	if (provisional) {
		active.provisional_async_mask |= UINT64_C(1) << retained_owner->ingest_lane;
	} else {
		active.owner->remove_live_retained_(*active.row, retained_index);
	}
	retained_owner->generation = next_generation(retained_owner->generation);
	retained_owner->state = retained_state::ASYNC_OWNED;
	const auto token = active.owner->async_work_->begin({
		.slot_index = slot_index,
		.owner_index = static_cast<uint32_t>(active.row - active.owner->rows_),
		.epoch = active.owner->active_epoch_,
		.user_tag = user_tag,
		.retained_slot = retained_index,
		.standalone = false,
	});
	++active.row->async_slot_owned_count;
	out_view->data = retained_owner->record->storage.data;
	out_view->len = retained_owner->record->storage.length;
	out_view->_padding = 0u;
	--active.remaining_budget;
	return token;
}

bool worker_active_stage_scheduler::implementation::abort_async_(kinetum_active_runtime_services *services,
								 kinetum_async_token token,
								 kinetum_retained_packet_handle *out_retained) noexcept
{
	if (out_retained != nullptr) {
		out_retained->value = KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE;
	}
	auto &active = invocation_from_(services);
	if (out_retained == nullptr || active.owner->phase_ != phase::OPEN || active.remaining_budget == 0u ||
	    active.owner->async_work_ == nullptr) {
		return false;
	}
	auto aborted = active.owner->async_work_->abort(token, static_cast<uint32_t>(active.row - active.owner->rows_));
	if (!aborted.has_value()) {
		return false;
	}
	if (aborted->owner_index != static_cast<uint32_t>(active.row - active.owner->rows_)) {
		std::terminate();
	}
	active.owner->release_async_slot_(*active.row, aborted->released_slot);
	if (aborted->retained_slot != UINT32_MAX) {
		if (aborted->retained_slot >= active.row->retained_capacity) {
			std::terminate();
		}
		const auto &slot = active.row->retained[aborted->retained_slot];
		const uint32_t lane = slot.ingest_lane;
		const bool provisional = lane < active.ingest_records.size() &&
					 active.owner->ingest_slots_[lane] == aborted->retained_slot &&
					 slot.record == active.ingest_records[lane] &&
					 (active.provisional_async_mask & (UINT64_C(1) << lane)) != 0u;
		*out_retained =
			active.owner->restore_async_retained_(*active.row, aborted->retained_slot, !provisional);
		if (provisional) {
			active.provisional_async_mask &= ~(UINT64_C(1) << lane);
		}
	} else if (!aborted->standalone) {
		std::terminate();
	}
	--active.remaining_budget;
	return true;
}

bool worker_active_stage_scheduler::implementation::recirculate_retained_(
	kinetum_active_runtime_services *services, kinetum_retained_packet_handle retained) noexcept
{
	auto &active = invocation_from_(services);
	// Recirculation is one same-instance OPEN transfer. A transition may inherit
	// one already-pending disposition, but DRAIN forbids another, so the local
	// queue can expose the record at most once before the module must retire it.
	if (active.owner->phase_ != phase::OPEN || active.remaining_budget == 0u) {
		return false;
	}
	auto *slot = active.owner->resolve_retained_(*active.row, retained);
	if (slot == nullptr) {
		return false;
	}
	const uint32_t index = static_cast<uint32_t>(slot - active.row->retained);
	active.owner->remove_live_retained_(*active.row, index);
	slot->state = retained_state::RECIRCULATE_PENDING;
	active.owner->append_pending_retained_(*active.row, index);
	--active.remaining_budget;
	return true;
}

template <bool has_async>
kinetum_active_ctx worker_active_stage_scheduler::implementation::make_context_(instance_row &row, uint64_t now_ns,
										bool expose_async_completions) noexcept
{
	const auto &view = row.store->owner_executable_view();
	if (view.mode != KINETUM_MODULE_ACTIVE || view.epoch != active_epoch_ || view.context == nullptr ||
	    view.run == nullptr || row.callback_active || invocation_.owner != nullptr) {
		std::terminate();
	}
	uint32_t state_flags = 0u;
	if (phase_ == phase::TRANSITION_DRAIN) {
		state_flags = KINETUM_ACTIVE_CTX_F_TRANSITION_DRAIN;
	} else if (phase_ == phase::SHUTDOWN_DRAIN) {
		state_flags = KINETUM_ACTIVE_CTX_F_SHUTDOWN_DRAIN;
	}
	invocation_ = {};
	invocation_.runtime_services.platform_opaque = &invocation_;
	if constexpr (has_async) {
		const bool async_enabled = row.async_capacity != 0u;
		invocation_.runtime_services.completions = async_enabled && expose_async_completions &&
									   row.async_delivery_count != 0u ?
								   row.async_completion_views :
								   nullptr;
		invocation_.runtime_services.completion_count =
			async_enabled && expose_async_completions ? row.async_delivery_count : 0u;
		invocation_.runtime_services.begin_async = async_enabled ? &begin_async_ : nullptr;
		invocation_.runtime_services.begin_async_retained = async_enabled ? &begin_async_retained_ : nullptr;
		invocation_.runtime_services.abort_async = async_enabled ? &abort_async_ : nullptr;
		invocation_.runtime_services.recirculate_retained = async_enabled ? &recirculate_retained_ : nullptr;
	}
	invocation_.owner = this;
	invocation_.row = &row;
	invocation_.remaining_budget = static_cast<uint32_t>(WORK_BUDGET);
	invocation_.now_ns = now_ns;
	row.callback_active = true;
	return kinetum_active_ctx{
		.now_ns = now_ns,
		.active_epoch = active_epoch_,
		.active_packet_config = view.packet_config,
		.drain_target_epoch = phase_ == phase::TRANSITION_DRAIN ? transition_to_epoch_ : 0u,
		.expired = row.expired_count == 0u ? nullptr : row.expired,
		.drain_retained = row.drain_retained_count == 0u ? nullptr : row.drain_retained,
		.expired_count = row.expired_count,
		.drain_retained_count = row.drain_retained_count,
		.region_id = static_cast<uint32_t>(row.region_id),
		.state_flags = state_flags,
		.emit = &emit_,
		.retain_input = &retain_input_,
		.emit_retained = &emit_retained_,
		.drop_retained = &drop_retained_,
		.arm_timer_after = &arm_timer_,
		.cancel_timer = &cancel_timer_,
		.post_control = &post_control_,
		.request_pull = &request_pull_,
		.runtime_services = &invocation_.runtime_services,
	};
}

void worker_active_stage_scheduler::implementation::service_pending_retained_(instance_row &row,
									      std::size_t &budget) noexcept
{
	while (budget != 0u && row.retained_pending_head != INVALID_INDEX) {
		const uint32_t index = row.retained_pending_head;
		if (index >= row.retained_capacity) {
			std::terminate();
		}
		auto &slot = row.retained[index];
		if ((slot.state != retained_state::EMIT_PENDING && slot.state != retained_state::DROP_PENDING &&
		     slot.state != retained_state::RECIRCULATE_PENDING) ||
		    slot.record == nullptr || slot.epoch != active_epoch_) {
			std::terminate();
		}
		const bool recirculate = slot.state == retained_state::RECIRCULATE_PENDING;
		const bool drop = slot.state == retained_state::DROP_PENDING;
		const bool published =
			recirculate ?
				packet_operations_.publish_recirculated(packet_operations_.state,
									row.stage_instance_index, slot.record) :
				packet_operations_.publish_retained(packet_operations_.state, row.stage_instance_index,
								    slot.record, slot.next_stage, drop);
		if (!published) {
			return;
		}
		row.retained_pending_head = slot.next_pending;
		if (row.retained_pending_head == INVALID_INDEX) {
			row.retained_pending_tail = INVALID_INDEX;
		}
		free_retained_(row, index);
		--budget;
	}
}

void worker_active_stage_scheduler::implementation::collect_worker_timers_(uint64_t now_ns,
									   std::size_t &budget) noexcept
{
	if (timer_wheel_ == nullptr || budget == 0u) {
		return;
	}
	std::array<kinetum::algo::timer_handle, WORK_BUDGET> expired{};
	const uint64_t target_tick = now_ns / ACTIVE_TIMER_QUANTUM_NS;
	const uint32_t count = timer_wheel_->advance_to(
		target_tick, expired.data(), static_cast<uint32_t>(std::min<std::size_t>(budget, expired.size())));
	if (count > budget) {
		std::terminate();
	}
	for (uint32_t index = 0u; index < count; ++index) {
		const uint64_t row_identity = timer_wheel_->user_key(expired[index]);
		if (row_identity >= row_count_) {
			std::terminate();
		}
		auto &row = rows_[row_identity];
		if (row.expired_count >= WORK_BUDGET || row.timer_armed_count == 0u || row.timer_owned_count == 0u) {
			std::terminate();
		}
		--row.timer_armed_count;
		row.expired[row.expired_count++] = kinetum_active_timer_handle{expired[index].value};
	}
	budget -= count;
}

void worker_active_stage_scheduler::implementation::collect_drain_timers_(std::size_t &budget) noexcept
{
	if (timer_wheel_ == nullptr || budget == 0u || timer_wheel_->active_count() == 0u) {
		return;
	}
	std::size_t inspected = 0u;
	while (budget != 0u && inspected < WORK_BUDGET && timer_wheel_->active_count() != 0u) {
		if (timer_drain_cursor_ >= timer_entry_capacity_) {
			timer_drain_cursor_ = 0u;
		}
		const uint32_t slot_index = timer_drain_cursor_++;
		++inspected;
		const auto handle = timer_wheel_->live_handle_at(slot_index);
		if (!handle.valid()) {
			continue;
		}
		const uint64_t row_identity = timer_wheel_->user_key(handle);
		if (row_identity >= row_count_) {
			std::terminate();
		}
		auto &row = rows_[row_identity];
		if (row.expired_count >= WORK_BUDGET || row.timer_armed_count == 0u || row.timer_owned_count == 0u) {
			std::terminate();
		}
		if (!timer_wheel_->cancel(handle)) {
			std::terminate();
		}
		--row.timer_armed_count;
		row.expired[row.expired_count++] = kinetum_active_timer_handle{handle.value};
		--budget;
	}
}

void worker_active_stage_scheduler::implementation::collect_async_completions_(std::size_t &budget) noexcept
{
	if (async_work_ == nullptr || budget == 0u) {
		return;
	}
	while (budget != 0u) {
		worker_async_delivery delivery{};
		if (!async_work_->try_take(delivery)) {
			return;
		}
		if (delivery.owner_index >= row_count_) {
			std::terminate();
		}
		auto &row = rows_[delivery.owner_index];
		if (row.async_capacity == 0u || row.async_deliveries == nullptr ||
		    row.async_completion_views == nullptr || row.async_delivery_count >= WORK_BUDGET ||
		    row.async_callback_owned_count == UINT32_MAX) {
			std::terminate();
		}
		release_async_slot_(row, delivery.released_slot);
		if (delivery.retained_slot != UINT32_MAX) {
			delivery.completion.retained = restore_async_retained_(row, delivery.retained_slot);
		} else if (!delivery.standalone) {
			std::terminate();
		}
		const uint32_t delivery_index = row.async_delivery_count++;
		row.async_deliveries[delivery_index] = delivery;
		row.async_completion_views[delivery_index] = delivery.completion;
		++row.async_callback_owned_count;
		--budget;
	}
}

void worker_active_stage_scheduler::implementation::enforce_async_cancellation_deadlines_(uint64_t now_ns) noexcept
{
	if (async_work_ == nullptr || (phase_ != phase::TRANSITION_DRAIN && phase_ != phase::SHUTDOWN_DRAIN)) {
		return;
	}
	const uint64_t cancellation_epoch = async_work_->cancellation_epoch();
	if (cancellation_epoch == 0u) {
		if (phase_ != phase::SHUTDOWN_DRAIN || !async_work_->drained()) {
			std::terminate();
		}
		for (uint32_t index = 0u; index < row_count_; ++index) {
			const auto &row = rows_[index];
			if (row.async_slot_owned_count != 0u || row.async_callback_owned_count != 0u ||
			    row.async_delivery_count != 0u || row.async_cancel_deadline_ns != 0u) {
				std::terminate();
			}
		}
		return;
	}
	if (cancellation_epoch != active_epoch_) {
		std::terminate();
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		auto &row = rows_[index];
		if (row.async_capacity == 0u) {
			continue;
		}
		if (row.async_cancel_grace_ns == 0u || row.async_cancel_grace_ns > UINT64_MAX - now_ns) {
			std::terminate();
		}
		if (row.async_cancel_deadline_ns == 0u) {
			row.async_cancel_deadline_ns = now_ns + row.async_cancel_grace_ns;
		}
		if ((row.async_slot_owned_count != 0u || row.async_callback_owned_count != 0u ||
		     row.async_delivery_count != 0u) &&
		    now_ns >= row.async_cancel_deadline_ns) {
			std::terminate();
		}
	}
}

void worker_active_stage_scheduler::implementation::collect_drain_retained_(instance_row &row) noexcept
{
	row.drain_retained_count = 0u;
	if (phase_ != phase::TRANSITION_DRAIN && phase_ != phase::SHUTDOWN_DRAIN) {
		return;
	}
	uint32_t index = row.retained_live_head;
	while (index != INVALID_INDEX && row.drain_retained_count < WORK_BUDGET) {
		if (index >= row.retained_capacity) {
			std::terminate();
		}
		const auto &slot = row.retained[index];
		if (slot.state != retained_state::RETAINED || slot.record == nullptr || slot.epoch != active_epoch_) {
			std::terminate();
		}
		row.drain_retained[row.drain_retained_count++] =
			kinetum_retained_packet_handle{make_handle(slot.generation, row.retained_base_index + index)};
		index = slot.next_live;
	}
}

bool worker_active_stage_scheduler::implementation::pull_empty_(const instance_row &row) const noexcept
{
	const uint32_t row_index = static_cast<uint32_t>(&row - rows_);
	for (uint32_t index = 0u; index < row.source_pull_edge_count; ++index) {
		const uint32_t edge_index = row.source_pull_edge_indices[index];
		if (edge_index >= pull_edge_count_ || pull_edges_[edge_index].source_row != row_index) {
			std::terminate();
		}
		if (relation_bit_(pull_pending_bits_, pull_edges_[edge_index].relation_bit)) {
			return false;
		}
	}
	return true;
}

bool worker_active_stage_scheduler::implementation::pull_delivery_empty_(const instance_row &row) const noexcept
{
	if (row.pull_delivery == nullptr) {
		std::terminate();
	}
	for (std::size_t index = 0u; index < WORK_BUDGET; ++index) {
		if (row.pull_delivery[index] != INVALID_INDEX) {
			return false;
		}
	}
	return true;
}

bool worker_active_stage_scheduler::implementation::row_synchronous_empty_(const instance_row &row) const noexcept
{
	return row.retained_owned_count == 0u && row.retained_owned_bytes == 0u &&
	       row.retained_live_head == INVALID_INDEX && row.retained_pending_head == INVALID_INDEX &&
	       row.retained_pending_tail == INVALID_INDEX && row.timer_armed_count == 0u &&
	       row.timer_owned_count == 0u && row.control_owned_count == 0u &&
	       (row.control_queue == nullptr || row.control_queue->empty()) && !row.callback_active &&
	       pull_empty_(row) && pull_delivery_empty_(row);
}

bool worker_active_stage_scheduler::implementation::row_empty_(const instance_row &row) const noexcept
{
	return row_synchronous_empty_(row) && row.async_slot_owned_count == 0u &&
	       row.async_callback_owned_count == 0u && row.async_delivery_count == 0u;
}

template <bool has_async>
void worker_active_stage_scheduler::implementation::service_instance_(instance_row &row, uint64_t now_ns,
								      std::size_t &budget) noexcept
{
	service_pending_retained_(row, budget);
	collect_drain_retained_(row);

	const uint32_t control_count =
		row.control_queue == nullptr ?
			0u :
			static_cast<uint32_t>(std::min<std::size_t>(row.control_queue->size(), budget));
	for (uint32_t index = 0u; index < control_count; ++index) {
		if (!row.control_queue->try_pop(row.control_delivery[index])) {
			std::terminate();
		}
	}
	uint32_t pull_count = 0u;
	uint32_t inspected_pull_edges = 0u;
	const uint32_t pull_work_limit =
		static_cast<uint32_t>(std::min<std::size_t>(row.source_pull_edge_count, WORK_BUDGET));
	const uint32_t pull_budget = static_cast<uint32_t>(budget - control_count);
	while (inspected_pull_edges < pull_work_limit && pull_count < pull_budget) {
		if (row.pull_service_cursor >= row.source_pull_edge_count) {
			row.pull_service_cursor = 0u;
		}
		const uint32_t edge_index = row.source_pull_edge_indices[row.pull_service_cursor];
		++row.pull_service_cursor;
		++inspected_pull_edges;
		if (edge_index >= pull_edge_count_ ||
		    pull_edges_[edge_index].source_row != static_cast<uint32_t>(&row - rows_)) {
			std::terminate();
		}
		if (relation_bit_(pull_pending_bits_, pull_edges_[edge_index].relation_bit)) {
			if (row.pull_delivery[pull_count] != INVALID_INDEX) {
				std::terminate();
			}
			row.pull_delivery[pull_count++] = edge_index;
		}
	}
	uint32_t triggers = 0u;
	if (phase_ == phase::OPEN &&
	    (row.trigger_mask & static_cast<uint32_t>(provider::compiled_active_stage_trigger::LOOP)) != 0u) {
		triggers |= KINETUM_TRIGGER_LOOP;
	}
	if (row.expired_count != 0u) {
		triggers |= KINETUM_TRIGGER_TIMER;
	}
	if (control_count != 0u) {
		triggers |= KINETUM_TRIGGER_CONTROL;
	}
	if (pull_count != 0u) {
		triggers |= KINETUM_TRIGGER_PULL_READY;
	}
	if constexpr (has_async) {
		if (row.async_delivery_count != 0u) {
			triggers |= KINETUM_TRIGGER_ASYNC_COMPLETE;
		}
	}
	bool drain_work_present = !row_synchronous_empty_(row);
	if constexpr (has_async) {
		drain_work_present = !row_empty_(row);
	}
	if ((phase_ == phase::TRANSITION_DRAIN || phase_ == phase::SHUTDOWN_DRAIN) &&
	    (drain_work_present || row.expired_count != 0u || control_count != 0u || pull_count != 0u)) {
		triggers |= KINETUM_TRIGGER_DRAIN;
	}
	if (triggers == 0u) {
		return;
	}

	auto context = make_context_<has_async>(row, now_ns, true);
	ledger_.acquire(active_epoch_);
	for (uint32_t index = 0u; index < control_count; ++index) {
		const auto &cell = row.control_delivery[index];
		if (cell.epoch != active_epoch_ || cell.length > row.control_payload_capacity ||
		    cell.payload_slot >= row.control_capacity || row.descriptor->on_control == nullptr) {
			std::terminate();
		}
		const auto *payload = row.control_payloads +
				      static_cast<std::size_t>(cell.payload_slot) * row.control_payload_capacity;
		const kinetum_control_msg message{
			.data = cell.length == 0u ? nullptr : payload,
			.len = cell.length,
			.subtype = cell.subtype,
		};
		// Each foreign callback receives a freshly reconstructed runtime view.
		// One callback cannot mutate the context observed by the next message.
		auto control_context = context;
		auto control_services = invocation_.runtime_services;
		control_services.completions = nullptr;
		control_services.completion_count = 0u;
		control_context.runtime_services = &control_services;
		control_context.expired = nullptr;
		control_context.drain_retained = nullptr;
		control_context.expired_count = 0u;
		control_context.drain_retained_count = 0u;
		row.descriptor->on_control(row.store->owner_executable_view().context, &control_context, &message);
	}
	collect_drain_retained_(row);
	context.drain_retained = row.drain_retained_count == 0u ? nullptr : row.drain_retained;
	context.drain_retained_count = row.drain_retained_count;
	row.descriptor->run(row.store->owner_executable_view().context, &context, triggers);
	row.callback_active = false;
	invocation_ = {};
	ledger_.retire(active_epoch_);

	if constexpr (has_async) {
		for (uint32_t index = 0u; index < row.async_delivery_count; ++index) {
			auto &delivery = row.async_deliveries[index];
			const auto &view = row.async_completion_views[index];
			if (async_work_ == nullptr || row.async_callback_owned_count == 0u ||
			    view.handle.value != delivery.completion.handle.value ||
			    view.retained.value != delivery.completion.retained.value ||
			    view.user_tag != delivery.completion.user_tag ||
			    view.outcome != delivery.completion.outcome || view._padding != 0u) {
				std::terminate();
			}
			async_work_->complete_delivery(delivery);
			--row.async_callback_owned_count;
			delivery = {};
			row.async_completion_views[index] = {};
		}
		row.async_delivery_count = 0u;
	}

	for (uint32_t index = 0u; index < row.expired_count; ++index) {
		if (row.timer_owned_count == 0u ||
		    row.expired[index].value == KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE) {
			std::terminate();
		}
		--row.timer_owned_count;
		ledger_.retire(active_epoch_);
		row.expired[index] = kinetum_active_timer_handle{KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE};
	}
	row.expired_count = 0u;
	row.drain_retained_count = 0u;

	for (uint32_t index = 0u; index < control_count; ++index) {
		auto &cell = row.control_delivery[index];
		if (cell.epoch != active_epoch_) {
			std::terminate();
		}
		const uint32_t payload_slot = cell.payload_slot;
		if (payload_slot >= row.control_capacity ||
		    row.control_payload_next_free[payload_slot] != INVALID_INDEX) {
			std::terminate();
		}
		row.control_payload_next_free[payload_slot] = row.control_payload_free_head;
		row.control_payload_free_head = payload_slot;
		cell = {};
		if (row.control_owned_count == 0u) {
			std::terminate();
		}
		--row.control_owned_count;
		ledger_.retire(active_epoch_);
	}
	budget -= control_count;

	for (uint32_t index = 0u; index < pull_count; ++index) {
		const uint32_t edge_index = row.pull_delivery[index];
		if (edge_index >= pull_edge_count_ ||
		    pull_edges_[edge_index].source_row != static_cast<uint32_t>(&row - rows_)) {
			std::terminate();
		}
		const auto &edge = pull_edges_[edge_index];
		if (!relation_bit_(pull_pending_bits_, edge.relation_bit)) {
			std::terminate();
		}
		clear_relation_bit_(pull_pending_bits_, edge.relation_bit);
		ledger_.retire(active_epoch_);
		row.pull_delivery[index] = INVALID_INDEX;
	}
	budget -= pull_count;
}

void worker_active_stage_scheduler::implementation::bind_bootstrap_epoch(uint64_t epoch) noexcept
{
	if (phase_ != phase::UNBOUND || active_epoch_ != 0u || epoch == 0u || invocation_.owner != nullptr ||
	    ledger_.active_epoch() != epoch || ledger_.source_epoch() != epoch || ledger_.future_epoch() != 0u) {
		std::terminate();
	}
	if (timer_wheel_ != nullptr && timer_wheel_->active_count() != 0u) {
		std::terminate();
	}
	if (async_work_ != nullptr && !async_work_->empty()) {
		std::terminate();
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		const auto &view = rows_[index].store->owner_executable_view();
		if (!row_empty_(rows_[index]) || view.mode != KINETUM_MODULE_ACTIVE || view.epoch != epoch ||
		    view.context == nullptr || view.run == nullptr ||
		    view.context_index != rows_[index].module_context_index) {
			std::terminate();
		}
	}
	active_epoch_ = epoch;
	phase_ = phase::OPEN;
}

bool worker_active_stage_scheduler::implementation::preflight_begin_transition(uint64_t generation, uint64_t from_epoch,
									       uint64_t to_epoch) const noexcept
{
	return transition_bind_ready_(generation, from_epoch, to_epoch, 0u);
}

bool worker_active_stage_scheduler::implementation::transition_bind_ready_(
	uint64_t generation, uint64_t from_epoch, uint64_t to_epoch, uint64_t expected_future_epoch) const noexcept
{
	if (phase_ != phase::OPEN || generation == 0u || from_epoch == 0u || to_epoch == 0u || from_epoch >= to_epoch ||
	    active_epoch_ != from_epoch || transition_generation_ != 0u || invocation_.owner != nullptr ||
	    ledger_.active_epoch() != from_epoch || ledger_.source_epoch() != from_epoch ||
	    ledger_.future_epoch() != expected_future_epoch ||
	    (async_work_ != nullptr && async_work_->cancellation_epoch() != 0u)) {
		return false;
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		const auto &row = rows_[index];
		const auto &view = row.store->owner_executable_view();
		if (row.callback_active || view.mode != KINETUM_MODULE_ACTIVE || view.epoch != from_epoch ||
		    row.store->prepared_epoch() != to_epoch) {
			return false;
		}
	}
	return true;
}

bool worker_active_stage_scheduler::implementation::begin_transition(uint64_t generation, uint64_t from_epoch,
								     uint64_t to_epoch) noexcept
{
	if (!transition_bind_ready_(generation, from_epoch, to_epoch, to_epoch)) {
		return false;
	}
	transition_generation_ = generation;
	transition_from_epoch_ = from_epoch;
	transition_to_epoch_ = to_epoch;
	if (async_work_ != nullptr) {
		async_work_->begin_cancellation(from_epoch);
	}
	phase_ = phase::TRANSITION_DRAIN;
	return true;
}

void worker_active_stage_scheduler::implementation::begin_shutdown() noexcept
{
	if (phase_ == phase::UNBOUND || active_epoch_ == 0u || invocation_.owner != nullptr) {
		std::terminate();
	}
	if (phase_ == phase::SHUTDOWN_DRAIN) {
		return;
	}
	if (async_work_ != nullptr && async_work_->cancellation_epoch() == 0u) {
		async_work_->begin_cancellation(active_epoch_);
	}
	phase_ = phase::SHUTDOWN_DRAIN;
}

template <bool has_async>
void worker_active_stage_scheduler::implementation::service_turn_(uint64_t cached_now_ns) noexcept
{
	if (phase_ == phase::UNBOUND || active_epoch_ == 0u || cached_now_ns == 0u || invocation_.owner != nullptr) {
		std::terminate();
	}
	std::size_t budget = WORK_BUDGET;
	if constexpr (has_async) {
		if (async_work_ == nullptr) {
			std::terminate();
		}
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		if (rows_[index].expired_count != 0u) {
			std::terminate();
		}
	}
	if constexpr (has_async) {
		enforce_async_cancellation_deadlines_(cached_now_ns);
		std::size_t async_budget = std::min(budget, ASYNC_COMPLETION_PREFIX_BUDGET);
		const std::size_t initial_async_budget = async_budget;
		collect_async_completions_(async_budget);
		budget -= initial_async_budget - async_budget;
	}
	if (phase_ == phase::OPEN) {
		collect_worker_timers_(cached_now_ns, budget);
	} else {
		collect_drain_timers_(budget);
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		service_instance_<has_async>(rows_[index], cached_now_ns, budget);
	}
	if constexpr (has_async) {
		if (phase_ == phase::SHUTDOWN_DRAIN && async_work_->drained() &&
		    async_work_->cancellation_epoch() != 0u) {
			async_work_->finish_cancellation(active_epoch_);
			for (uint32_t index = 0u; index < row_count_; ++index) {
				rows_[index].async_cancel_deadline_ns = 0u;
			}
		}
	}
}

void worker_active_stage_scheduler::implementation::service_turn_synchronous(uint64_t cached_now_ns) noexcept
{
	service_turn_<false>(cached_now_ns);
}

void worker_active_stage_scheduler::implementation::service_turn_async(uint64_t cached_now_ns) noexcept
{
	service_turn_<true>(cached_now_ns);
}

template <bool has_async>
active_ingest_result
worker_active_stage_scheduler::implementation::ingest_(uint32_t stage_instance_index,
						       std::span<packet_record *const> records, int32_t region_id,
						       module_batch_scratch &scratch, uint64_t cached_now_ns) noexcept
{
	if constexpr (has_async) {
		if (async_work_ == nullptr) {
			std::terminate();
		}
	}
	auto *row = row_for_stage_(stage_instance_index);
	if (row == nullptr || records.empty() || records.size() > KINETUM_MAX_BURST || region_id != row->region_id ||
	    phase_ == phase::UNBOUND || invocation_.owner != nullptr || ingest_slots_ == nullptr) {
		std::terminate();
	}
	for (std::size_t index = 0u; index < records.size(); ++index) {
		if (records[index] == nullptr || records[index]->metadata.epoch != active_epoch_) {
			std::terminate();
		}
		ingest_slots_[index] = INVALID_INDEX;
	}
	auto context = make_context_<has_async>(*row, cached_now_ns, false);
	invocation_.ingest_records = records;
	// Preserve the existing per-input service allowance. The fixed batch limit
	// bounds the whole invocation by the same maximum work as individual inputs.
	invocation_.remaining_budget = static_cast<uint32_t>(WORK_BUDGET * records.size());
	const uint64_t forwarded = execute_active_module_batch_mechanism(
		*row->store, static_cast<uint16_t>(stage_instance_index), region_id, records, context, scratch);
	const uint64_t async_owned = invocation_.provisional_async_mask;
	uint64_t retained = 0u;
	for (std::size_t index = 0u; index < records.size(); ++index) {
		const uint64_t bit = UINT64_C(1) << index;
		const uint32_t provisional = ingest_slots_[index];
		if (provisional == INVALID_INDEX) {
			if ((async_owned & bit) != 0u) {
				std::terminate();
			}
			continue;
		}
		if (provisional >= row->retained_capacity || (forwarded & bit) != 0u) {
			std::terminate();
		}
		const auto &slot = row->retained[provisional];
		const auto expected_state = (async_owned & bit) != 0u ? retained_state::ASYNC_OWNED :
									retained_state::PROVISIONAL;
		if (slot.state != expected_state || slot.ingest_lane != index || slot.record != records[index] ||
		    slot.epoch != active_epoch_ || slot.generation == 0u || slot.next_live != INVALID_INDEX ||
		    slot.previous_live != INVALID_INDEX || slot.next_pending != INVALID_INDEX) {
			std::terminate();
		}
		retained |= bit;
	}
	row->callback_active = false;
	invocation_ = {};
	for (std::size_t index = 0u; index < records.size(); ++index) {
		const uint32_t provisional = ingest_slots_[index];
		if (provisional != INVALID_INDEX) {
			if ((async_owned & (UINT64_C(1) << index)) != 0u) {
				commit_async_retained_(*row, provisional);
			} else {
				commit_retained_(*row, provisional);
			}
			ingest_slots_[index] = INVALID_INDEX;
		}
	}
	return {forwarded, retained};
}

active_ingest_result worker_active_stage_scheduler::implementation::ingest_synchronous(
	uint32_t stage_instance_index, std::span<packet_record *const> records, int32_t region_id,
	module_batch_scratch &scratch, uint64_t cached_now_ns) noexcept
{
	return ingest_<false>(stage_instance_index, records, region_id, scratch, cached_now_ns);
}

active_ingest_result worker_active_stage_scheduler::implementation::ingest_async(
	uint32_t stage_instance_index, std::span<packet_record *const> records, int32_t region_id,
	module_batch_scratch &scratch, uint64_t cached_now_ns) noexcept
{
	return ingest_<true>(stage_instance_index, records, region_id, scratch, cached_now_ns);
}

bool worker_active_stage_scheduler::implementation::transition_active(uint64_t generation, uint64_t from_epoch,
								      uint64_t to_epoch) const noexcept
{
	return phase_ == phase::TRANSITION_DRAIN && generation != 0u && generation == transition_generation_ &&
	       from_epoch == transition_from_epoch_ && to_epoch == transition_to_epoch_ && active_epoch_ == from_epoch;
}

bool worker_active_stage_scheduler::implementation::activation_ready(uint64_t generation, uint64_t from_epoch,
								     uint64_t to_epoch) const noexcept
{
	if (!transition_active(generation, from_epoch, to_epoch) || invocation_.owner != nullptr ||
	    ledger_.active_epoch() != from_epoch || ledger_.source_epoch() != to_epoch ||
	    ledger_.future_epoch() != to_epoch || (timer_wheel_ != nullptr && timer_wheel_->active_count() != 0u) ||
	    (async_work_ != nullptr && (async_work_->cancellation_epoch() != from_epoch || !async_work_->drained()))) {
		return false;
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		const auto &row = rows_[index];
		const auto &view = row.store->owner_executable_view();
		if (!row_empty_(row) || view.epoch != from_epoch || view.mode != KINETUM_MODULE_ACTIVE ||
		    row.store->prepared_epoch() != to_epoch) {
			return false;
		}
	}
	return true;
}

bool worker_active_stage_scheduler::implementation::preflight_activate(uint64_t generation, uint64_t from_epoch,
								       uint64_t to_epoch) const noexcept
{
	return activation_ready(generation, from_epoch, to_epoch);
}

void worker_active_stage_scheduler::implementation::activate(uint64_t generation, uint64_t from_epoch,
							     uint64_t to_epoch) noexcept
{
	if (!transition_active(generation, from_epoch, to_epoch) || invocation_.owner != nullptr ||
	    ledger_.active_epoch() != to_epoch || ledger_.source_epoch() != to_epoch || ledger_.future_epoch() != 0u ||
	    (async_work_ != nullptr && (async_work_->cancellation_epoch() != from_epoch || !async_work_->drained()))) {
		std::terminate();
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		const auto &row = rows_[index];
		const auto &view = row.store->owner_executable_view();
		if (!row_empty_(row) || view.mode != KINETUM_MODULE_ACTIVE || view.epoch != to_epoch ||
		    row.store->prepared_epoch() != 0u || view.context_index != row.module_context_index) {
			std::terminate();
		}
	}
	if (async_work_ != nullptr) {
		async_work_->finish_cancellation(from_epoch);
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		rows_[index].async_cancel_deadline_ns = 0u;
	}
	active_epoch_ = to_epoch;
	transition_generation_ = 0u;
	transition_from_epoch_ = 0u;
	transition_to_epoch_ = 0u;
	phase_ = phase::OPEN;
}

bool worker_active_stage_scheduler::implementation::empty() const noexcept
{
	if (invocation_.owner != nullptr) {
		return false;
	}
	for (uint32_t index = 0u; index < row_count_; ++index) {
		if (!row_empty_(rows_[index])) {
			return false;
		}
	}
	return (timer_wheel_ == nullptr || timer_wheel_->active_count() == 0u) &&
	       (async_work_ == nullptr || async_work_->empty());
}

common::status_or<std::unique_ptr<worker_active_stage_scheduler>>
worker_active_stage_scheduler::create(uint32_t worker_index, const provider::compiled_provider_topology &topology,
				      std::span<const active_stage_context_binding> contexts,
				      worker_epoch_ledger &ledger, active_stage_packet_operations packet_operations)
{
	auto implementation = std::unique_ptr<worker_active_stage_scheduler::implementation>(
		new (std::nothrow) worker_active_stage_scheduler::implementation(worker_index, topology, contexts,
										 ledger, packet_operations));
	if (implementation == nullptr) {
		return common::status::resource_exhausted("active scheduler owner allocation failed");
	}
	try {
		if (const auto status = implementation->initialize(); !status.is_ok()) {
			return status;
		}
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("active scheduler cold-table allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "active scheduler cold-table extent exceeds the host size domain");
	} catch (...) {
		return common::status::internal_error("active scheduler cold construction failed unexpectedly");
	}
	auto owner = std::unique_ptr<worker_active_stage_scheduler>(
		new (std::nothrow) worker_active_stage_scheduler(std::move(implementation)));
	if (owner == nullptr) {
		return common::status::resource_exhausted("active scheduler public owner allocation failed");
	}
	return owner;
}

worker_active_stage_scheduler::worker_active_stage_scheduler(std::unique_ptr<implementation> implementation) noexcept
	: implementation_(std::move(implementation))
{
}

worker_active_stage_scheduler::~worker_active_stage_scheduler() = default;

uint32_t worker_active_stage_scheduler::worker_index() const noexcept
{
	return implementation_->worker_index();
}

std::size_t worker_active_stage_scheduler::size() const noexcept
{
	return implementation_->size();
}

int32_t worker_active_stage_scheduler::numa_node() const noexcept
{
	return implementation_->numa_node();
}

std::size_t worker_active_stage_scheduler::storage_bytes() const noexcept
{
	return implementation_->storage_bytes();
}

uint64_t worker_active_stage_scheduler::active_epoch() const noexcept
{
	return implementation_->active_epoch();
}

bool worker_active_stage_scheduler::owns_ledger(const worker_epoch_ledger &ledger) const noexcept
{
	return implementation_->owns_ledger(ledger);
}

void worker_active_stage_scheduler::bind_bootstrap_epoch(uint64_t epoch) noexcept
{
	implementation_->bind_bootstrap_epoch(epoch);
}

bool worker_active_stage_scheduler::preflight_begin_transition(uint64_t generation, uint64_t from_epoch,
							       uint64_t to_epoch) const noexcept
{
	return implementation_->preflight_begin_transition(generation, from_epoch, to_epoch);
}

bool worker_active_stage_scheduler::begin_transition(uint64_t generation, uint64_t from_epoch,
						     uint64_t to_epoch) noexcept
{
	return implementation_->begin_transition(generation, from_epoch, to_epoch);
}

void worker_active_stage_scheduler::begin_shutdown() noexcept
{
	implementation_->begin_shutdown();
}

bool worker_active_stage_scheduler::has_async_work() const noexcept
{
	return implementation_->has_async_work();
}

void worker_active_stage_scheduler::service_turn_synchronous(uint64_t cached_now_ns) noexcept
{
	implementation_->service_turn_synchronous(cached_now_ns);
}

void worker_active_stage_scheduler::service_turn_async(uint64_t cached_now_ns) noexcept
{
	implementation_->service_turn_async(cached_now_ns);
}

active_ingest_result worker_active_stage_scheduler::ingest_synchronous(uint32_t stage_instance_index,
								       std::span<packet_record *const> records,
								       int32_t region_id, module_batch_scratch &scratch,
								       uint64_t cached_now_ns) noexcept
{
	return implementation_->ingest_synchronous(stage_instance_index, records, region_id, scratch, cached_now_ns);
}

active_ingest_result worker_active_stage_scheduler::ingest_async(uint32_t stage_instance_index,
								 std::span<packet_record *const> records,
								 int32_t region_id, module_batch_scratch &scratch,
								 uint64_t cached_now_ns) noexcept
{
	return implementation_->ingest_async(stage_instance_index, records, region_id, scratch, cached_now_ns);
}

bool worker_active_stage_scheduler::transition_active(uint64_t generation, uint64_t from_epoch,
						      uint64_t to_epoch) const noexcept
{
	return implementation_->transition_active(generation, from_epoch, to_epoch);
}

bool worker_active_stage_scheduler::activation_ready(uint64_t generation, uint64_t from_epoch,
						     uint64_t to_epoch) const noexcept
{
	return implementation_->activation_ready(generation, from_epoch, to_epoch);
}

bool worker_active_stage_scheduler::preflight_activate(uint64_t generation, uint64_t from_epoch,
						       uint64_t to_epoch) const noexcept
{
	return implementation_->preflight_activate(generation, from_epoch, to_epoch);
}

void worker_active_stage_scheduler::activate(uint64_t generation, uint64_t from_epoch, uint64_t to_epoch) noexcept
{
	implementation_->activate(generation, from_epoch, to_epoch);
}

bool worker_active_stage_scheduler::empty() const noexcept
{
	return implementation_->empty();
}

}  // namespace kinetum::dp
