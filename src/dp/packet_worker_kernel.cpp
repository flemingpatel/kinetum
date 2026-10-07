// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file packet_worker_kernel.cpp
 * @brief Pre-resolved packet worker and exact endpoint-transition integration.
 * @author Fleming Patel
 */

#include "src/dp/packet_worker_kernel.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <exception>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>

#include <kinetum/algo/compact_index_set.hpp>
#include <kinetum/algo/platform.hpp>
#include <kinetum/kinetum_sdk.h>

#include "src/common/runtime_sizing.hpp"
#include "src/common/time.hpp"
#include "src/dp/active/worker_active_stage_scheduler.hpp"
#include "src/dp/edge_condition.hpp"
#include "src/dp/epoch/boundary_epoch_channel.hpp"
#include "src/dp/epoch/epoch_transition_certificate.hpp"
#include "src/dp/epoch/epoch_transition_staging.hpp"
#include "src/dp/epoch/worker_boundary_receiver.hpp"
#include "src/dp/epoch/worker_boundary_sender.hpp"
#include "src/dp/epoch/worker_epoch_activation.hpp"
#include "src/dp/io_contract.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/module/module_manager.hpp"
#include "src/dp/module/worker_module_health.hpp"
#include "src/dp/numa_memory.hpp"
#include "src/dp/packet.hpp"
#include "src/dp/packet_mechanism.hpp"
#include "src/dp/packet_work_item.hpp"
#include "src/dp/worker_input_scheduler.hpp"
#include "src/dp/worker_runtime_command.hpp"
#include "src/dp/worker_runtime_telemetry.hpp"
#include "src/provider/compiled_provider_topology.hpp"
#include "src/provider/provider_runtime_materialization.hpp"

namespace kinetum::dp
{
namespace
{

/** Fixed bound on worker-local pending packet ownership. */
constexpr std::size_t LOCAL_STAGING_CAPACITY = kinetum::common::runtime_sizing::INTER_REGION_DATA_RING_CAPACITY;
/** Maximum records passed through one packet callback. */
constexpr std::size_t MAX_BURST = kinetum::common::runtime_sizing::PACKET_MAX_BURST_SIZE;
/** Absence sentinel for a pre-resolved runtime table ordinal. */
constexpr uint32_t INVALID_RUNTIME_ORDINAL = std::numeric_limits<uint32_t>::max();

static_assert(MAX_BURST > 0 && MAX_BURST <= std::numeric_limits<uint16_t>::max());

/** Exact ABI receive-callback type used to classify source schedules. */
using receive_burst_function = decltype(packet_rx_burst_operations::receive_burst);

/** @brief Once-selected source polling shape for one exact owner worker. */
enum class source_kernel_kind : uint8_t {
	NO_SOURCES = 1,	    ///< Owner with no native RX source.
	HOMOGENEOUS = 2,    ///< Every source shares one exact receive callback target.
	HETEROGENEOUS = 3,  ///< Source schedule carries distinct pre-resolved callbacks.
};

/** Worker-owned input staging retaining exact per-epoch packet ownership. */
using local_work_staging = packet_epoch_input_staging;
static_assert(alignof(local_work_staging) == kinetum::algo::CACHE_LINE_SIZE,
	      "worker input-staging ownership must retain cache-line isolation");
static_assert(sizeof(local_work_staging) % kinetum::algo::CACHE_LINE_SIZE == 0u,
	      "worker input-staging extent must occupy complete cache lines");

/** @brief Non-failing disposition after one accepted storage transition. */
enum class transition_post_action : uint8_t {
	RX_EXECUTE = 1,	    ///< Stream-to-stage transition completed.
	LOCAL_EXECUTE = 2,  ///< Stage-to-stage transition completed locally.
	BOUNDARY_SEND = 3,  ///< Stage-to-stage transition completed for a remote owner.
	TX_SUBMIT = 4,	    ///< Stage-to-stream transition completed.
};

/**
 * @brief Compare one compact endpoint against exact compiled endpoint facts.
 * @param left Candidate compiled endpoint.
 * @param kind Required endpoint namespace.
 * @param endpoint_index Required compact identity within that namespace.
 * @return true only when both namespace and index match.
 */
[[nodiscard]] bool endpoint_equal(const provider::compiled_packet_path_endpoint &left,
				  provider::compiled_packet_path_endpoint_kind kind, uint32_t endpoint_index) noexcept
{
	return left.kind == kind && left.endpoint_index == endpoint_index;
}

/**
 * @brief Check sorted compact membership without allocating.
 * @param values Sorted immutable membership vector.
 * @param value Candidate element to locate.
 * @return true when the vector contains the exact value.
 * @tparam value_type Ordered compact identity type.
 */
template <typename value_type>
[[nodiscard]] bool sorted_contains(const std::vector<value_type> &values, value_type value) noexcept
{
	return std::binary_search(values.begin(), values.end(), value);
}

}  // namespace

/** @brief Complete pre-resolved state and sole execution owner for one packet worker. */
class packet_worker_kernel::implementation final {
    public:
	/**
	 * @brief Bind one empty implementation to immutable generation authorities.
	 *
	 * @param worker_index Exact compact worker identity.
	 * @param topology Sole compiled provider and transition topology.
	 * @param providers Complete materialized provider generation.
	 * @param modules Stable admitted module generation.
	 * @param commands Sole process-generation transition/stop publication.
	 * @param telemetry Exact worker-local telemetry banks.
	 * @param protocol_faults Process-generation transition-safety fault authority.
	 * @param module_telemetry Exact context owners serviced by this worker.
	 */
	implementation(uint32_t worker_index, const provider::compiled_provider_topology &topology,
		       const provider::materialized_provider_runtime &providers, module::module_manager &modules,
		       worker_runtime_command_publication &commands, worker_runtime_telemetry &telemetry,
		       epoch_protocol_fault_latch &protocol_faults,
		       std::span<lifecycle::lifecycle_context_owner *const> module_telemetry) noexcept
		: worker_index_(worker_index)
		, topology_(topology)
		, providers_(providers)
		, modules_(modules)
		, commands_(&commands)
		, telemetry_(&telemetry)
		, protocol_faults_(&protocol_faults)
		, module_telemetry_(module_telemetry)
	{
	}

	/** @brief Fail stop if worker-owned packet state survives kernel teardown. */
	~implementation() noexcept;

	/**
	 * @brief Allocate and validate every direct worker table.
	 *
	 * @param boundaries Complete compact-indexed boundary-channel table.
	 * @param boundary_sender Sole complete outbound sender-policy authority.
	 * @param boundary_receiver Sole complete inbound receiver-policy authority.
	 * @return OK after all tables agree with compiled truth; otherwise an exact
	 *         cold construction failure.
	 */
	[[nodiscard]] common::status initialize(const std::vector<boundary_epoch_channel *> &boundaries,
						std::unique_ptr<worker_boundary_sender> boundary_sender,
						std::unique_ptr<worker_boundary_receiver> boundary_receiver);
	/**
	 * @brief Bind and revalidate one already activated owner-local epoch.
	 *
	 * @param bootstrap_epoch Exact valid epoch activated for every owned context.
	 * @param now_ns Sole owner-worker cached monotonic publication timestamp.
	 */
	void bind_bootstrap_epoch(uint64_t bootstrap_epoch, uint64_t now_ns) noexcept;

	/**
	 * @brief Run the sole owner-worker loop.
	 */
	void run() noexcept;

	/** @return Exact compact worker identity. */
	[[nodiscard]] uint32_t worker_index() const noexcept
	{
		return worker_index_;
	}

	/** @copydoc packet_worker_kernel::try_read_epoch_ownership */
	[[nodiscard]] publication_read_result try_read_epoch_ownership(worker_epoch_ledger_snapshot &out) const noexcept
	{
		return epoch_ledger_ != nullptr ? epoch_ledger_->try_read(out) : publication_read_result::UNAVAILABLE;
	}

	/** @copydoc packet_worker_kernel::quiescence_reader_registration */
	[[nodiscard]] kinetum::algo::quiescence_reader &quiescence_reader_registration() noexcept
	{
		return quiescence_reader_;
	}

	/** @copydoc packet_worker_kernel::transition_certificate_source */
	[[nodiscard]] epoch_transition_certificate_worker_source transition_certificate_source() const noexcept
	{
		if (epoch_ledger_ == nullptr || epoch_activation_ == nullptr || boundary_sender_ == nullptr ||
		    boundary_receiver_ == nullptr || !quiescence_reader_.bound()) {
			std::terminate();
		}
		return {
			.ledger = epoch_ledger_.get(),
			.activation = epoch_activation_.get(),
			.sender = boundary_sender_.get(),
			.receiver = boundary_receiver_.get(),
			.reader = &quiescence_reader_,
		};
	}

    private:
	/** @brief One exact pre-resolved directed stage target. */
	struct route_target {
		uint32_t stage_instance_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Destination stage.
		uint16_t logical_stage_index{
			provider::INVALID_COMPILED_STAGE_INSTANCE_INDEX};	     ///< Destination logical stage.
		uint32_t boundary_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Exact cross-worker edge.
		uint32_t sender_ordinal{INVALID_RUNTIME_ORDINAL};    ///< Direct owner-local sender policy.
		std::vector<uint32_t> transition_by_storage_domain;  ///< Direct transition or invalid sentinel.
	};

	/** @brief One priority matcher referring to a pre-resolved target ordinal. */
	struct priority_route {
		common::compiled_packet_route_condition condition{};  ///< Allocation-free predicate.
		uint32_t group_ordinal{INVALID_RUNTIME_ORDINAL};      ///< Exact logical destination group.
		uint32_t pull_target_ordinal{
			INVALID_RUNTIME_ORDINAL};  ///< Same-owner PULL destination when applicable.
	};

	/** @brief Cold-proved logical destination and its complete permitted context set. */
	struct route_group {
		uint16_t logical_stage_index{
			provider::INVALID_COMPILED_STAGE_INSTANCE_INDEX};  ///< Exact logical successor.
		uint32_t direct_target_ordinal{INVALID_RUNTIME_ORDINAL};   ///< Same-lane or explicit PULL target.
		kinetum_select_contexts_fn select_contexts{
			nullptr};				  ///< Exact declared selector; null for direct routes.
		uint32_t context_count{0};			  ///< Complete generation-fixed module population.
		std::vector<uint32_t> permitted_ordinals;	  ///< Canonical permitted context set.
		std::vector<uint64_t> permitted_bitmap;		  ///< Read-only exact membership projection.
		std::vector<uint32_t> target_by_context_ordinal;  ///< Direct context-to-concrete-target lookup.
	};

	/** @brief One exact worker-owned stage mechanism and routing table. */
	struct stage_runtime {
		bool owned{false};			 ///< Whether this global compact slot belongs to the worker.
		uint32_t telemetry_ordinal{UINT32_MAX};	 ///< Direct owner-local telemetry row.
		const provider::compiled_provider_stage_instance *facts{nullptr};     ///< Immutable stage facts.
		const provider::compiled_logical_stage *logical{nullptr};	      ///< Immutable logical semantics.
		module::module_epoch_store *module_store{nullptr};		      ///< Exact module view authority.
		packet_mechanism_kind mechanism{packet_mechanism_kind::RX};	      ///< Platform mechanism.
		int32_t region_id{-1};						      ///< Sole owner region.
		uint32_t rx_stream_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Exact ingress source.
		uint32_t stage_bound_tx_stream_index{
			provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Exact TX-stage egress.
		std::vector<route_target> targets;		     ///< Unique authored outgoing targets.
		std::vector<uint32_t> target_by_stage_instance;	     ///< Global target to local ordinal.
		std::vector<uint32_t> group_by_logical_stage;	     ///< Explicit logical successor lookup.
		std::vector<route_group> groups;	      ///< One exact destination group per logical successor.
		std::vector<uint32_t> fanout_group_ordinals;  ///< Authored logical branch order.
		std::vector<priority_route> priority_routes;  ///< Compiler-established evaluation order.
		kinetum::algo::compact_index_set reachable_storage_domains;  ///< O(1) executable-domain gate.
	};

	/** @brief Transient packet prefixes, placed and prefaulted on the owning worker's NUMA node. */
	struct alignas(kinetum::algo::CACHE_LINE_SIZE) execution_scratch {
		std::array<packet_record *, MAX_BURST> rx_records{};	  ///< Exact provider RX prefix.
		std::array<packet_work_item, MAX_BURST> local_work{};	  ///< Exact dequeued local prefix.
		std::array<packet_record *, MAX_BURST> module_records{};  ///< Compatible module input prefix.
		module_batch_scratch module{};				  ///< Sole packet ABI projection.
		kinetum_context_selection_batch selection{};		  ///< Read-only selector flow projection.
		std::array<uint32_t, MAX_BURST> selected_contexts{};	  ///< Selector output ordinals.
		std::array<packet_record *, MAX_BURST>
			pending_records{};		///< Contiguous selection prefix retaining reservations.
		stage_runtime *pending_stage{nullptr};	///< Exact source of the pending prefix.
		route_group *pending_group{nullptr};	///< Exact pending logical destination.
		uint32_t pending_domain{
			provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Retained local reservation owner.
		uint16_t pending_count{0};			     ///< Occupied selection prefix.
	};
	static_assert(std::is_standard_layout_v<execution_scratch>);
	static_assert(std::is_trivially_destructible_v<execution_scratch>);
	static_assert(sizeof(execution_scratch) % kinetum::algo::CACHE_LINE_SIZE == 0u);

	/** @brief One exact worker-owned RX queue and stream-to-stage edge. */
	struct rx_stream_runtime {
		uint32_t telemetry_ordinal{UINT32_MAX};	 ///< Pre-resolved owner-local stream counter row.
		bool owned{false};			 ///< Whether this compact stream is polled here.
		const provider::compiled_provider_io_stream *facts{nullptr};  ///< Immutable stream facts.
		const packet_rx_burst_operations *operations{nullptr};	      ///< Direct provider burst target.
		uint32_t stage_instance_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< RX stage.
		uint32_t storage_domain_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Native RX storage.
		uint32_t transition_index{provider::INVALID_COMPILED_PROVIDER_INDEX};	   ///< Stream-to-stage edge.
	};

	/** @brief One exact worker-owned TX queue and stage-to-stream edge table. */
	struct tx_stream_runtime {
		uint32_t telemetry_ordinal{UINT32_MAX};	 ///< Pre-resolved owner-local stream counter row.
		bool owned{false};			 ///< Whether this compact stream is submitted here.
		const provider::compiled_provider_io_stream *facts{nullptr};  ///< Immutable stream facts.
		const packet_tx_burst_operations *operations{nullptr};	      ///< Direct provider burst target.
		uint32_t stage_instance_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Attached TX stage.
		kinetum::algo::compact_index_set accepted_storage_domains;  ///< Immutable O(1) TX storage admission.
		std::vector<uint32_t> transition_by_storage_domain;	    ///< Stage-to-stream transition table.
	};

	/** @brief One grouped exact provider transition invocation. */
	struct transition_batch {
		std::array<packet_private, MAX_BURST> metadata{};  ///< Authority snapshot across callback.
		bool owned{false};				   ///< Transition belongs to this worker schedule.
		bool configured{false};	 ///< One endpoint use established retry/post behavior.
		const provider::compiled_storage_transition *facts{nullptr};  ///< Immutable transition facts.
		const kinetum_provider_storage_transition_operations *operations{nullptr};  ///< Burst target.
		packet_work_phase retry_phase{packet_work_phase::STAGE_DELIVER};  ///< Unaccepted suffix state.
		transition_post_action post_action{transition_post_action::LOCAL_EXECUTE};  ///< Accepted prefix state.
		std::array<packet_record *, MAX_BURST> sources{};	///< Exact attempted source owners.
		std::array<packet_record *, MAX_BURST> destinations{};	///< Accepted destination owners.
		uint16_t count{0};					///< Current bounded group size.
	};

	/** @brief One cold sorted lookup key for an owned packet-path transition. */
	struct transition_lookup_entry {
		provider::compiled_packet_path_endpoint_kind from_kind{
			provider::compiled_packet_path_endpoint_kind::IO_STREAM};  ///< Source namespace.
		uint32_t from_index{0};						   ///< Source compact identity.
		provider::compiled_packet_path_endpoint_kind to_kind{
			provider::compiled_packet_path_endpoint_kind::IO_STREAM};  ///< Destination namespace.
		uint32_t to_index{0};						   ///< Destination compact identity.
		uint32_t from_storage_domain{0};				   ///< Source storage identity.
		uint32_t transition_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Direct operation.
	};

	/** @brief One grouped exact provider TX invocation. */
	struct tx_batch {
		std::array<packet_private, MAX_BURST>
			metadata{};			   ///< Pre-call epoch/stage and suffix-integrity snapshots.
		bool owned{false};			   ///< Stream belongs to this worker.
		const tx_stream_runtime *stream{nullptr};  ///< Stable pre-resolved stream.
		std::array<packet_record *, MAX_BURST> records{};  ///< Exact caller-owned records.
		std::array<uint32_t, MAX_BURST> lengths{};	   ///< Pre-call byte counts for accepted ownership.
		std::array<uint16_t, MAX_BURST>
			storage_domains{};  ///< Pre-call original domains; accepted records may be gone.
		uint16_t count{0};	    ///< Current bounded group size.
	};

	/** @brief One grouped exact storage-domain retirement invocation. */
	struct release_batch {
		const packet_storage_domain_operations *operations{nullptr};  ///< Exact retirement owner.
		std::array<packet_record *, MAX_BURST> records{};	      ///< Exact owned records.
		uint16_t count{0};					      ///< Current bounded group size.
	};

	/** @brief One owner-local queue entry in the fixed hot iteration order. */
	struct local_queue_schedule_entry {
		uint32_t storage_domain_index{provider::INVALID_COMPILED_PROVIDER_INDEX};  ///< Global domain index.
		local_work_staging *staging{nullptr};  ///< Stable active/future role owner.
	};

	/** @return OK after allocating formula-sized staging for every scheduled storage domain. */
	[[nodiscard]] common::status initialize_storage_queues_();
	/**
	 * @brief Derive and construct the sole worker epoch ledger.
	 * @return OK after adopting the exact compiled physical-record ceiling.
	 */
	[[nodiscard]] common::status initialize_epoch_ledger_();
	/**
	 * @brief Bind the exact complete DATA/CUT/ACK channel table.
	 *
	 * @param boundaries Complete compact-indexed boundary authority.
	 * @param boundary_sender Sole complete outbound sender-policy authority.
	 * @param boundary_receiver Sole complete inbound receiver-policy authority.
	 * @return OK after exact sender/receiver coverage is established.
	 */
	[[nodiscard]] common::status
	initialize_boundaries_(const std::vector<boundary_epoch_channel *> &boundaries,
			       std::unique_ptr<worker_boundary_sender> boundary_sender,
			       std::unique_ptr<worker_boundary_receiver> boundary_receiver);
	/** @return OK after binding exact module and source-role activation participants. */
	[[nodiscard]] common::status initialize_epoch_activation_();
	/** @return OK after materializing the exact active schedule, if any. */
	[[nodiscard]] common::status initialize_active_scheduler_();
	/** @return OK after binding every exact module context to owner-worker health. */
	[[nodiscard]] common::status initialize_module_health_();
	/** @return OK after binding every owned transition operation and lookup key. */
	[[nodiscard]] common::status initialize_transition_batches_();
	/** @return OK after binding all owned RX/TX streams to exact burst tables. */
	[[nodiscard]] common::status initialize_streams_();
	/** @return OK after binding every RX stream and inbound boundary to one fair service order. */
	[[nodiscard]] common::status initialize_input_scheduler_();
	/**
	 * @brief Refresh the sole turn timestamp and active-scheduler cache.
	 * @tparam has_active_scheduler Whether this loop owns active callback state.
	 * @return Exact platform monotonic turn timestamp.
	 */
	template <bool has_active_scheduler>
	[[nodiscard]] KINETUM_ALWAYS_INLINE uint64_t refresh_turn_time_() noexcept
	{
		const uint64_t now_ns = common::update_cached_ns();
		if constexpr (has_active_scheduler) {
			cached_turn_time_ns_ = now_ns;
		}
		return now_ns;
	}
	/** @return OK after selecting one source polling kernel from callback identity. */
	[[nodiscard]] common::status select_source_kernel_() noexcept;
	/** @return OK after binding all owned passive stages and module views. */
	[[nodiscard]] common::status initialize_stages_();
	/**
	 * @brief Compile one owned stage's immutable direct routing tables.
	 *
	 * @param stage Mutable cold table for one already bound owned stage.
	 * @return OK after every authored successor has one exact direct route.
	 */
	[[nodiscard]] common::status initialize_stage_routes_(stage_runtime &stage);
	/** @return OK after binding each stream-adjacent transition to one disposition. */
	[[nodiscard]] common::status initialize_stream_transitions_();
	/** @return OK when every scheduled transition and boundary has one executable use. */
	[[nodiscard]] common::status validate_transition_coverage_() const;

	/**
	 * @brief Resolve one cold exact endpoint/domain transition.
	 *
	 * @param from_kind Source endpoint namespace.
	 * @param from_index Source compact endpoint identity.
	 * @param to_kind Destination endpoint namespace.
	 * @param to_index Destination compact endpoint identity.
	 * @param from_storage_domain Exact source storage-domain index.
	 * @return Direct transition index, or the invalid sentinel when absent.
	 */
	[[nodiscard]] uint32_t find_transition_(provider::compiled_packet_path_endpoint_kind from_kind,
						uint32_t from_index,
						provider::compiled_packet_path_endpoint_kind to_kind, uint32_t to_index,
						uint32_t from_storage_domain) const noexcept;
	/**
	 * @brief Resolve one cold exact directed stage boundary.
	 *
	 * @param from_stage_instance Exact source stage-instance index.
	 * @param to_stage_instance Exact destination stage-instance index.
	 * @return Exact boundary epoch channel, or null for a local edge.
	 */
	[[nodiscard]] boundary_epoch_channel *find_boundary_(uint32_t from_stage_instance,
							     uint32_t to_stage_instance) const noexcept;
	/**
	 * @brief Publish every owned sender/receiver boundary transport once.
	 *
	 * The sole worker calls this after Bootstrap binding and once after grouped
	 * packet work each turn. Work is fixed in the compiled endpoint count and
	 * performs no allocation, lock, clock read, formatting, or retry loop.
	 */
	void publish_boundary_transport_() noexcept;
	/** @brief Dispatch one bounded returned telemetry-bank prefix to exact owners. */
	void service_telemetry_returns_() noexcept;
	/**
	 * @brief Record one owner cadence result in bounded return-poll state.
	 * @param need Whether a return is expected or one reclaimed return may exist.
	 */
	void record_telemetry_return_need_(runtime_telemetry_return_need need) noexcept;
	/**
	 * @brief Record one worker-detected protocol fault before fail-closed disposition.
	 * @param code Violated packet/epoch invariant.
	 * @param disposition Required ownership disposition.
	 * @param boundary_index Affected boundary, or UINT32_MAX when unrelated.
	 * @param context_index Affected module context, or UINT32_MAX when unrelated.
	 * @param stage_instance_index Affected stage instance, or UINT32_MAX when unrelated.
	 * @param observed_epoch Packet or control epoch observed at the failure.
	 * @param expected_value Expected sequence, count, or identity selected by the fault code.
	 * @param observed_value Actual value that violated the expectation.
	 */
	void record_protocol_fault_(epoch_protocol_fault_code code, epoch_protocol_fault_disposition disposition,
				    uint32_t boundary_index, uint32_t context_index, uint32_t stage_instance_index,
				    uint64_t observed_epoch, uint64_t expected_value, uint64_t observed_value) noexcept;
	/** @brief Start or coalesce one bounded module-context publication sweep. */
	void schedule_module_telemetry_sweep_() noexcept;
	/**
	 * @brief Assign one transition its sole retry and accepted-prefix dispositions.
	 *
	 * @param transition_index Exact compact transition index.
	 * @param retry_phase Work phase retained by an unaccepted suffix.
	 * @param post_action Action applied to the accepted prefix.
	 * @return OK after the first consistent assignment or repeated exact assignment.
	 */
	[[nodiscard]] common::status configure_transition_(uint32_t transition_index, packet_work_phase retry_phase,
							   transition_post_action post_action);

	/**
	 * @param storage_domain_index Exact global storage-domain index.
	 * @return Mutable owner-local queue-role owner, or null when unscheduled/out of range.
	 */
	[[nodiscard]] local_work_staging *local_staging_(uint32_t storage_domain_index) noexcept;
	/**
	 * @param record Candidate packet record.
	 * @param expected_domain Exact expected compact storage-domain identity.
	 * @return true when the record belongs to the exact materialized generation/domain.
	 */
	[[nodiscard]] bool validate_record_(const packet_record *record, uint32_t expected_domain) const noexcept;
	/**
	 * @param record Candidate packet record.
	 * @return Validated compact storage-domain identity, or the invalid sentinel.
	 */
	[[nodiscard]] uint32_t record_storage_domain_(const packet_record *record) const noexcept;
	/**
	 * @param storage_domain_index Exact local queue's global storage-domain index.
	 * @return true when one owner-local publication slot was reserved.
	 */
	[[nodiscard]] bool reserve_local_slot_(uint32_t storage_domain_index) noexcept;
	/**
	 * @brief Publish one work item through a previously retained local reservation.
	 *
	 * @param storage_domain_index Exact reserved local queue identity.
	 * @param item Exact packet work ownership to publish.
	 */
	void commit_local_reservation_(uint32_t storage_domain_index, packet_work_item item) noexcept;
	/**
	 * @brief Release one retained local reservation without publication.
	 *
	 * @param storage_domain_index Exact reserved local queue identity.
	 */
	void release_local_reservation_(uint32_t storage_domain_index) noexcept;

	/**
	 * @brief Poll one exact RX queue through the caller-selected burst target.
	 *
	 * @param stream Pre-resolved owner-local RX stream.
	 * @param receive_burst Exact provider burst callback.
	 * @param allowance Positive remainder of this input's bounded opportunity.
	 * @param cached_time Owner-loop timestamp applied to accepted records.
	 * @return Transferred plus rejected work, and whether the input yielded.
	 */
	[[nodiscard]] algo::service_result poll_one_rx_(rx_stream_runtime &stream, receive_burst_function receive_burst,
							uint16_t allowance, uint64_t cached_time) noexcept;
	/**
	 * @brief Execute the common owner loop with one preselected source-polling shape.
	 *
	 * @tparam has_active_scheduler true for an active-capable worker.
	 * @tparam has_async_scheduler true only for a tracked-async active worker.
	 * @tparam poll_source_type Allocation-free callable for one admitted RX input.
	 * @param poll_source Pre-resolved source polling operation, given its ordinal,
	 *        positive allowance, and the cached turn timestamp.
	 */
	template <bool has_active_scheduler, bool has_async_scheduler, typename poll_source_type>
	void run_loop_(poll_source_type poll_source) noexcept;
	/**
	 * @brief Consume one new immutable transition/stop command at a turn boundary.
	 * @return true when STOP is current; false for RUN or a consumed transition.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool consume_runtime_command_() noexcept;
	/**
	 * @brief Validate and consume one pointer-distinct command off the fixed path.
	 * @param command Newly observed candidate record; null is terminate-class.
	 * @return true only for STOP; false after exact TRANSITION binding.
	 */
	[[nodiscard]] KINETUM_COLD KINETUM_NOINLINE bool
	consume_changed_runtime_command_(const worker_runtime_command_record *command) noexcept;
	/**
	 * @brief Complete one bounded transition turn after grouped packet work.
	 *
	 * Every outbound CUT must be channel-owned and every inbound CUT drained
	 * before local activation. Modules, queue roles, ledger truth, receiver
	 * marking, and ACK submission then execute without packet interleaving.
	 *
	 * @param now_ns Sole cached timestamp for a possible telemetry activation.
	 */
	void service_transition_after_packet_work_(uint64_t now_ns) noexcept;
	/**
	 * @brief Admit one bounded DATA prefix without bypassing its FIFO head.
	 * @param boundary Exact receiver-owned input channel.
	 * @param allowance Positive remainder of this input's bounded opportunity.
	 * @return Transferred records and whether the input yielded on an empty ring.
	 */
	[[nodiscard]] algo::service_result drain_one_boundary_(boundary_epoch_channel &boundary,
							       uint16_t allowance) noexcept;
	/**
	 * @brief Drain one bounded prefix from every owner-local storage queue.
	 * @tparam has_active_scheduler Compile-time worker-loop specialization.
	 * @tparam has_async_scheduler Compile-time tracked-async specialization.
	 */
	template <bool has_active_scheduler, bool has_async_scheduler>
	void process_local_queues_() noexcept;
	/**
	 * @brief Execute one already reserved local work item.
	 *
	 * @param item Exact packet pointer and current work phase.
	 * @param stage Already validated owner-local execution identity.
	 * @param reserved_domain Storage-domain queue reservation carried by @p item.
	 */
	void process_work_item_(packet_work_item item, stage_runtime &stage, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Validate a queued record's exact storage and owner-stage identity.
	 * @param item Borrowed current queue entry.
	 * @param reserved_domain Sole storage and reservation owner.
	 * @return Exact owned stage; an internal ownership mismatch terminates.
	 */
	[[nodiscard]] stage_runtime &work_stage_(packet_work_item item, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Invoke one pre-resolved platform stage mechanism.
	 *
	 * @param record Sole packet ownership.
	 * @param stage Exact current stage runtime.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void execute_stage_(packet_record *record, stage_runtime &stage, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Execute one available contiguous module prefix without waiting to fill it.
	 * @tparam has_active_scheduler Compile-time worker-loop specialization.
	 * @tparam has_async_scheduler Compile-time tracked-async specialization.
	 * @param records Exact same-stage and same-epoch records retaining local reservations.
	 * @param stage Sole executable context for the complete prefix.
	 * @param reserved_domain Original storage and reservation owner.
	 */
	template <bool has_active_scheduler, bool has_async_scheduler>
	void execute_module_batch_(std::span<packet_record *const> records, stage_runtime &stage,
				   uint32_t reserved_domain) noexcept;
	/**
	 * @brief Route one successfully executed stage result without provider selection.
	 *
	 * @param record Sole packet ownership.
	 * @param stage Exact completed stage runtime.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void dispatch_stage_result_(packet_record *record, stage_runtime &stage, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Stamp and dispatch one exact pre-resolved stage target.
	 *
	 * @param record Sole packet ownership.
	 * @param stage Exact source stage runtime.
	 * @param target_ordinal Stage-local direct target ordinal.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void dispatch_one_target_(packet_record *record, stage_runtime &stage, uint32_t target_ordinal,
				  uint32_t reserved_domain) noexcept;
	/**
	 * @brief Dispatch directly or append to the one contiguous context-selection prefix.
	 * @param record Sole packet ownership.
	 * @param stage Exact source stage.
	 * @param group_ordinal Exact logical destination group.
	 * @param reserved_domain Original storage and reservation owner.
	 */
	void dispatch_one_group_(packet_record *record, stage_runtime &stage, uint32_t group_ordinal,
				 uint32_t reserved_domain) noexcept;
	/** @brief Select and validate every occupied lane before transferring any prefix ownership. */
	void flush_context_selection_() noexcept;
	/**
	 * @brief Clone and dispatch one exact bounded unconditional fan-out.
	 *
	 * @param record Sole original packet ownership.
	 * @param stage Exact source stage runtime.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void dispatch_fanout_(packet_record *record, stage_runtime &stage, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Apply the stream-to-RX-stage storage edge before stage execution.
	 *
	 * @param record Sole packet ownership.
	 * @param stage Exact destination RX stage.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void deliver_rx_(packet_record *record, stage_runtime &stage, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Apply the next-stage storage edge before local or boundary delivery.
	 *
	 * @param record Sole packet ownership.
	 * @param stage Exact destination stage.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void deliver_stage_(packet_record *record, stage_runtime &stage, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Transfer, hold, or retain one record through exact sender policy.
	 *
	 * @param record Sole packet ownership.
	 * @param stage Exact destination stage.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void send_boundary_(packet_record *record, stage_runtime &stage, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Resolve and apply the TX-stage-to-stream storage edge.
	 *
	 * @param record Sole packet ownership.
	 * @param stage Exact TX stage runtime.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void deliver_tx_(packet_record *record, stage_runtime &stage, uint32_t reserved_domain) noexcept;

	/**
	 * @brief Resolve unset or explicit logical egress through the dense table.
	 *
	 * @param record Exact TX-bound packet observation.
	 * @param stage Exact TX stage runtime.
	 * @return Owner-local TX stream, or null for invalid/unowned egress.
	 */
	[[nodiscard]] tx_stream_runtime *resolve_tx_stream_(const packet_record &record,
							    const stage_runtime &stage) noexcept;
	/**
	 * @brief Transfer one reservation into a grouped exact storage-transition batch.
	 *
	 * @param transition_index Exact compact transition index.
	 * @param record Sole packet ownership.
	 * @param reserved_domain Current owner-local queue reservation.
	 * @return true when ownership entered the transition batch.
	 */
	[[nodiscard]] bool queue_transition_(uint32_t transition_index, packet_record *record,
					     uint32_t reserved_domain) noexcept;
	/**
	 * @brief Invoke one transition and conserve accepted and untouched ownership.
	 *
	 * @param batch Exact grouped transition invocation.
	 */
	void flush_transition_(transition_batch &batch) noexcept;
	/** @brief Flush every nonempty worker-owned transition batch. */
	void flush_transitions_() noexcept;
	/**
	 * @brief Transfer one exact TX-domain reservation into a grouped TX batch.
	 *
	 * @param stream Exact owner-local TX stream.
	 * @param record Sole packet whose executing TX stage was validated by worker
	 *        dispatch; a preceding storage transition preserves that metadata.
	 * @param reserved_domain Original domain whose local queue reservation transfers to this batch.
	 */
	void queue_tx_(tx_stream_runtime &stream, packet_record *record, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Submit one grouped TX batch and retire the untouched suffix exactly once.
	 *
	 * @param batch Exact grouped TX invocation.
	 */
	void flush_tx_(tx_batch &batch) noexcept;
	/** @brief Flush every nonempty worker-owned TX batch. */
	void flush_tx_batches_() noexcept;
	/** @brief Invoke each owner-local provider's conditional publication policy. */
	void maybe_flush_tx_() noexcept;
	/** @brief Submit all staged TX work and publish each exact provider queue finally. */
	void final_flush_tx_() noexcept;
	/**
	 * @brief Transfer one packet reservation into grouped storage retirement.
	 *
	 * @param record Sole packet ownership.
	 * @param reserved_domain Current owner-local queue reservation.
	 */
	void release_record_(packet_record *record, uint32_t reserved_domain) noexcept;
	/**
	 * @brief Retire one same-domain record group and release its reservations.
	 *
	 * @param batch Exact grouped storage-domain retirement invocation.
	 */
	void flush_release_(release_batch &batch) noexcept;
	/** @brief Flush every nonempty storage-domain retirement group. */
	void flush_releases_() noexcept;

	/**
	 * @brief Promote the already stamped next-stage identity to current authority.
	 *
	 * @param record Sole mutable packet record.
	 */
	void promote_next_stage_(packet_record &record) const noexcept;
	/**
	 * @brief Stamp one exact next-stage route without duplicating current ownership.
	 *
	 * @param record Sole mutable packet record.
	 * @param target Exact pre-resolved route target.
	 */
	void stamp_route_(packet_record &record, const route_target &target) const noexcept;
	/** @return true when every owner-local queue, batch, clone, and capacity reservation is drained. */
	[[nodiscard]] bool local_work_empty_() const noexcept;
	/** @return true only after every inbound producer closes and its DATA drains. */
	[[nodiscard]] bool inbound_closed_and_empty_() const noexcept;
	/** @brief Close every outbound producer exactly once after complete local drain. */
	void close_outbound_boundaries_() noexcept;
	/**
	 * @brief Copy and publish one active-origin prefix through common staging.
	 * @param state Exact packet-kernel implementation owner.
	 * @param stage_instance_index Exact active source stage.
	 * @param epoch Exact current active/source epoch.
	 * @param now_ns Sole worker-cached turn timestamp.
	 * @param batch Complete module-owned origin candidate.
	 * @param budget Maximum accepted prefix for this callback.
	 * @param origin_scratch Exact active-scheduler input projection.
	 * @param record_scratch Exact active-scheduler provider-result projection.
	 * @return Exact prefix transferred into common packet ownership.
	 */
	[[nodiscard]] static uint32_t emit_active_origins_(void *state, uint32_t stage_instance_index, uint64_t epoch,
							   uint64_t now_ns, const kinetum_emit_batch_t *batch,
							   uint32_t budget,
							   std::span<packet_origin_view> origin_scratch,
							   std::span<packet_record *> record_scratch) noexcept;
	/**
	 * @brief Stage one retained record for common dispatch or terminal drop.
	 * @param state Exact packet-kernel implementation owner.
	 * @param stage_instance_index Exact retaining active stage.
	 * @param record Sole retained record ownership.
	 * @param next_stage Logical target or KINETUM_NEXT_STAGE_UNSET.
	 * @param drop true for terminal release; false for common dispatch.
	 * @return true only after common staging accepts the disposition.
	 */
	[[nodiscard]] static bool publish_active_retained_(void *state, uint32_t stage_instance_index,
							   packet_record *record, uint16_t next_stage,
							   bool drop) noexcept;
	/**
	 * @brief Stage one retained record back to its exact active stage instance.
	 * @param state Exact packet-kernel implementation owner.
	 * @param stage_instance_index Exact retaining and recirculation stage.
	 * @param record Sole retained packet ownership.
	 * @return true only after exact local staging accepts ownership.
	 */
	[[nodiscard]] static bool publish_active_recirculated_(void *state, uint32_t stage_instance_index,
							       packet_record *record) noexcept;

	uint32_t worker_index_{0};				    ///< Exact compact worker identity.
	const provider::compiled_provider_topology &topology_;	    ///< Sole immutable graph authority.
	const provider::materialized_provider_runtime &providers_;  ///< Exact provider generation.
	module::module_manager &modules_;			    ///< Exact module generation.
	worker_runtime_command_publication *commands_{nullptr};	    ///< Sole transition/stop publication.
	worker_runtime_telemetry *telemetry_{nullptr};		    ///< Exact owner-local telemetry banks.
	epoch_protocol_fault_latch *protocol_faults_{nullptr};	///< Process-generation transition-safety fault latch.
	std::span<lifecycle::lifecycle_context_owner *const> module_telemetry_;	 ///< Exact context telemetry owners.
	std::vector<lifecycle::lifecycle_context_owner *> module_telemetry_by_context_;	 ///< O(1) return dispatch.
	const provider::compiled_provider_worker_schedule *schedule_{nullptr};		 ///< Exact worker schedule.
	const common::compiled_transition_worker *worker_{nullptr};			 ///< Boundary/CPU ownership.

	std::vector<std::unique_ptr<local_work_staging>> local_staging_owners_;	 ///< Domain-indexed role owners.
	std::vector<release_batch> release_batches_;			///< Global domain-indexed retirement groups.
	std::vector<local_queue_schedule_entry> local_queue_schedule_;	///< Fixed owner-local queue iteration.
	std::vector<release_batch *> release_flush_schedule_;		///< Fixed owner-local retirement order.
	std::vector<stage_runtime> stages_;				///< Global stage-indexed direct table.
	std::vector<rx_stream_runtime> rx_streams_;			///< Global stream-indexed RX table.
	std::vector<tx_stream_runtime> tx_streams_;			///< Global stream-indexed TX table.
	std::vector<transition_batch> transition_batches_;		///< Global transition-indexed groups.
	std::vector<transition_batch *> transition_flush_schedule_;	///< Fixed owner-local transition order.
	std::vector<transition_lookup_entry> transition_lookup_;	///< Sorted owned endpoint/domain lookup.
	std::vector<tx_batch> tx_batches_;				///< Global stream-indexed TX groups.
	std::vector<rx_stream_runtime *> rx_inputs_;		     ///< Immutable ordinal-to-RX-operation projection.
	std::unique_ptr<worker_input_scheduler> input_scheduler_;    ///< Sole fair admission order on worker NUMA.
	std::vector<tx_stream_runtime *> tx_flush_schedule_;	     ///< Fixed bounded TX flush order.
	std::vector<boundary_epoch_channel *> boundaries_by_index_;  ///< Complete compact boundary table.
	std::vector<boundary_epoch_channel *> inbound_boundaries_;   ///< Exact receiver channels.
	numa_memory_region scratch_storage_;			     ///< Sole owner-NUMA transient-prefix allocation.
	execution_scratch *scratch_{nullptr};			     ///< Stable view into scratch_storage_.
	std::vector<packet_record *> fanout_clones_;		     ///< Cold-sized per-packet clone scratch.
	std::unique_ptr<worker_epoch_ledger> epoch_ledger_;	     ///< Sole owner-local epoch work authority.
	std::unique_ptr<worker_boundary_sender> boundary_sender_;    ///< Ledger-borrowing sender-policy owner.
	std::unique_ptr<worker_boundary_receiver> boundary_receiver_;	    ///< Ledger-borrowing receiver policy.
	std::unique_ptr<worker_active_stage_scheduler> active_scheduler_;   ///< Exact active/async stage owner.
	std::unique_ptr<module::worker_module_health> module_health_;	    ///< Exact module-health claim owner.
	std::unique_ptr<worker_epoch_activation> epoch_activation_;	    ///< Exact local activation order.
	kinetum::algo::quiescence_reader quiescence_reader_;		    ///< Caller-placed exact config reader.
	source_kernel_kind source_kernel_{source_kernel_kind::NO_SOURCES};  ///< Once-selected source loop.
	receive_burst_function homogeneous_receive_burst_{nullptr};	    ///< Sole homogeneous callback target.
	bool outbound_closed_{false};					    ///< Exact-once shutdown publication.
	bool run_started_{false};					    ///< Sole owner entered the loop once.
	bool run_finished_{false};			     ///< Complete drain and final flush succeeded.
	uint64_t cached_turn_time_ns_{0};		     ///< Sole timestamp observed by active services this turn.
	std::size_t module_telemetry_cursor_{0};	     ///< Bounded round-robin context publication cursor.
	std::size_t module_telemetry_remaining_{0};	     ///< Contexts left in the current cadence sweep.
	std::size_t telemetry_cadence_returns_expected_{0};  ///< Ordinary completed banks awaiting return.
	bool module_telemetry_sweep_queued_{false};	     ///< One coalesced cadence behind the active sweep.
	bool telemetry_return_poll_requested_{false};	     ///< One bounded reclaimed-return probe is due.
	const worker_runtime_command_record *observed_command_{
		nullptr};  ///< Last non-STOP command consumed by this owner.
};

common::status
packet_worker_kernel::implementation::initialize(const std::vector<boundary_epoch_channel *> &boundaries,
						 std::unique_ptr<worker_boundary_sender> boundary_sender,
						 std::unique_ptr<worker_boundary_receiver> boundary_receiver)
{
	if (providers_.runtime_generation() == 0 ||
	    providers_.runtime_generation() > std::numeric_limits<uint32_t>::max() || commands_ == nullptr ||
	    commands_->runtime_generation() != providers_.runtime_generation()) {
		return common::status::failed_precondition(
			"packet worker requires one exact provider and command-publication generation");
	}
	if (worker_index_ >= topology_.worker_schedules.size() ||
	    worker_index_ >= topology_.transition_topology.workers.size()) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "packet worker index is outside the compiled topology");
	}
	schedule_ = &topology_.worker_schedules[worker_index_];
	worker_ = &topology_.transition_topology.workers[worker_index_];
	if (schedule_->worker_index != worker_index_ || worker_->worker_index != worker_index_ ||
	    worker_->cpu_core_ids.size() != 1 || telemetry_ == nullptr || protocol_faults_ == nullptr ||
	    telemetry_->worker_index() != worker_index_ || telemetry_->numa_node() != worker_->numa_node ||
	    telemetry_->storage_bytes() == 0u || telemetry_->active_epoch() != 0u) {
		return common::status::failed_precondition(
			"packet worker compact identity or exact CPU ownership is malformed");
	}
	module_telemetry_by_context_.assign(topology_.module_contexts.size(), nullptr);
	auto scratch_or = numa_memory_region::allocate({
		.usable_bytes = sizeof(execution_scratch),
		.alignment_bytes = alignof(execution_scratch),
		.host_numa_node = worker_->numa_node,
	});
	if (!scratch_or.is_ok()) {
		return scratch_or.error();
	}
	scratch_storage_ = std::move(scratch_or).value();
	scratch_ = std::construct_at(static_cast<execution_scratch *>(scratch_storage_.data()));
	for (auto *owner : module_telemetry_) {
		if (owner == nullptr || owner->identity().worker_index != worker_index_ ||
		    owner->identity().context_index >= module_telemetry_by_context_.size() ||
		    module_telemetry_by_context_[owner->identity().context_index] != nullptr) {
			return common::status::failed_precondition(
				"packet worker module telemetry projection is not exact and unique");
		}
		module_telemetry_by_context_[owner->identity().context_index] = owner;
	}

	auto result = initialize_storage_queues_();
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_epoch_ledger_();
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_boundaries_(boundaries, std::move(boundary_sender), std::move(boundary_receiver));
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_transition_batches_();
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_streams_();
	if (!result.is_ok()) {
		return result;
	}
	result = select_source_kernel_();
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_input_scheduler_();
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_stages_();
	if (!result.is_ok()) {
		return result;
	}
	for (const uint32_t stage_index : schedule_->stage_instance_indices) {
		result = initialize_stage_routes_(stages_[stage_index]);
		if (!result.is_ok()) {
			return result;
		}
	}
	result = initialize_stream_transitions_();
	if (!result.is_ok()) {
		return result;
	}
	result = validate_transition_coverage_();
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_active_scheduler_();
	if (!result.is_ok()) {
		return result;
	}
	result = initialize_module_health_();
	if (!result.is_ok()) {
		return result;
	}
	return initialize_epoch_activation_();
}

common::status packet_worker_kernel::implementation::initialize_storage_queues_()
{
	local_staging_owners_.resize(topology_.storage_domains.size());
	release_batches_.resize(topology_.storage_domains.size());
	local_queue_schedule_.reserve(schedule_->storage_domain_indices.size());
	release_flush_schedule_.reserve(schedule_->storage_domain_indices.size());
	const bool transition_enabled = topology_.transition_topology.policy.enabled;
	if ((!transition_enabled && worker_->source_epoch_staging_capacity != 0u) ||
	    (transition_enabled && (worker_->is_source != (worker_->source_epoch_staging_capacity != 0u)))) {
		return common::status::failed_precondition(
			"worker source role and source_epoch_staging_capacity are not exact");
	}
	if (worker_->is_source != !schedule_->source_storage_domain_indices.empty() ||
	    !std::is_sorted(schedule_->source_storage_domain_indices.begin(),
			    schedule_->source_storage_domain_indices.end()) ||
	    std::adjacent_find(schedule_->source_storage_domain_indices.begin(),
			       schedule_->source_storage_domain_indices.end()) !=
		    schedule_->source_storage_domain_indices.end()) {
		return common::status::failed_precondition(
			"worker source storage-domain schedule is not one exact sorted unique set");
	}
	for (const uint32_t source_domain : schedule_->source_storage_domain_indices) {
		if (!std::binary_search(schedule_->storage_domain_indices.begin(),
					schedule_->storage_domain_indices.end(), source_domain)) {
			return common::status::failed_precondition(
				"worker source storage domain is absent from its complete staging schedule");
		}
	}

	uint32_t previous = 0;
	bool have_previous = false;
	for (const uint32_t storage_domain_index : schedule_->storage_domain_indices) {
		if (storage_domain_index >= topology_.storage_domains.size() ||
		    (have_previous && storage_domain_index <= previous)) {
			return common::status::failed_precondition(
				"worker storage-domain schedule is not a sorted unique compact set");
		}
		const auto &facts = topology_.storage_domains[storage_domain_index];
		const auto *operations = providers_.storage_domain(storage_domain_index);
		if (facts.storage_domain_index != storage_domain_index || operations == nullptr ||
		    operations->domain_index != storage_domain_index ||
		    operations->generation != providers_.runtime_generation()) {
			return common::status::failed_precondition(
				"worker storage-domain operation does not match compiled generation truth");
		}
		const bool source_domain = std::binary_search(schedule_->source_storage_domain_indices.begin(),
							      schedule_->source_storage_domain_indices.end(),
							      storage_domain_index);
		const bool transition_source = source_domain && worker_->source_epoch_staging_capacity != 0u;
		const std::size_t active_capacity = transition_source ? worker_->source_epoch_staging_capacity :
									LOCAL_STAGING_CAPACITY;
		const std::optional<std::size_t> future_capacity =
			transition_source ? std::optional<std::size_t>(active_capacity) : std::nullopt;
		auto staging_or = local_work_staging::create(active_capacity, future_capacity, worker_->numa_node);
		if (!staging_or.is_ok()) {
			return staging_or.error();
		}
		local_staging_owners_[storage_domain_index] = std::move(staging_or).value();
		release_batches_[storage_domain_index].operations = operations;
		local_queue_schedule_.push_back(
			{storage_domain_index, local_staging_owners_[storage_domain_index].get()});
		release_flush_schedule_.push_back(&release_batches_[storage_domain_index]);
		previous = storage_domain_index;
		have_previous = true;
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_epoch_ledger_()
{
	if (schedule_ == nullptr || epoch_ledger_ != nullptr) {
		return common::status::internal_error("worker epoch ledger construction has invalid owner state");
	}

	uint64_t packet_storage_capacity = 0u;
	for (const uint32_t storage_domain_index : schedule_->storage_domain_indices) {
		if (storage_domain_index >= topology_.storage_domains.size()) {
			return common::status::failed_precondition(
				"worker epoch ledger references an unknown storage domain");
		}
		const uint64_t buffer_count = topology_.storage_domains[storage_domain_index].buffer_count;
		if (buffer_count == 0u) {
			return common::status::failed_precondition(
				"worker epoch ledger references a zero-population storage domain");
		}
		if (buffer_count > std::numeric_limits<uint64_t>::max() - packet_storage_capacity) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "worker epoch ledger credit ceiling overflows uint64");
		}
		packet_storage_capacity += buffer_count;
	}
	const bool owns_health_callback =
		std::any_of(module_telemetry_.begin(), module_telemetry_.end(),
			    [](const auto *owner) { return owner != nullptr && owner->health_callback_available(); });
	// Active and health callbacks are serialized by this sole worker, so one
	// transient event credit covers either callback class but never both.
	uint64_t synchronous_event_capacity =
		!schedule_->active_stage_instance_indices.empty() || owns_health_callback ? 1u : 0u;
	uint64_t active_timer_capacity = 0u;
	uint64_t active_async_capacity = 0u;
	for (const uint32_t stage_index : schedule_->active_stage_instance_indices) {
		if (stage_index >= topology_.stage_instances.size()) {
			return common::status::failed_precondition(
				"worker active-event ceiling references an unknown stage instance");
		}
		const auto &stage = topology_.stage_instances[stage_index];
		if (stage.logical_stage_index >= topology_.logical_stages.size()) {
			return common::status::failed_precondition(
				"worker active-event ceiling lost logical-stage ownership");
		}
		const auto &logical = topology_.logical_stages[stage.logical_stage_index];
		if (logical.timer_capacity > std::numeric_limits<uint64_t>::max() - active_timer_capacity) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "worker active-timer credit ceiling overflows uint64");
		}
		active_timer_capacity += logical.timer_capacity;
		if (logical.async_work_capacity > std::numeric_limits<uint64_t>::max() - active_async_capacity) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "worker tracked-async credit ceiling overflows uint64");
		}
		active_async_capacity += logical.async_work_capacity;
		const uint64_t terms[] = {logical.control_mailbox_capacity,
					  static_cast<uint64_t>(stage.pull_source_stage_instance_indices.size())};
		for (const uint64_t term : terms) {
			if (term > std::numeric_limits<uint64_t>::max() - synchronous_event_capacity) {
				return common::status(common::status_code::OUT_OF_RANGE,
						      "worker active-event credit ceiling overflows uint64");
			}
			synchronous_event_capacity += term;
		}
	}
	auto budget_or = compile_worker_epoch_credit_budget({
		.packet_storage_capacity = packet_storage_capacity,
		.synchronous_event_capacity = synchronous_event_capacity,
		.timer_capacity = active_timer_capacity,
		.async_work_capacity = active_async_capacity,
		.handoff_limit = MAX_BURST,
	});
	if (!budget_or.is_ok()) {
		return budget_or.error();
	}

	auto ledger_or = worker_epoch_ledger::create(worker_index_, providers_.runtime_generation(), budget_or->total);
	if (!ledger_or.is_ok()) {
		return ledger_or.error();
	}
	epoch_ledger_ = std::move(ledger_or).value();
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::select_source_kernel_() noexcept
{
	if (rx_inputs_.empty()) {
		source_kernel_ = source_kernel_kind::NO_SOURCES;
		homogeneous_receive_burst_ = nullptr;
		return common::status::ok();
	}

	const auto *first = rx_inputs_.front();
	if (first == nullptr || first->operations == nullptr || first->operations->receive_burst == nullptr) {
		return common::status::failed_precondition(kinetum::common::static_status_text(
			"worker source schedule contains an incomplete receive operation"));
	}
	const receive_burst_function candidate = first->operations->receive_burst;
	for (const auto *stream : rx_inputs_) {
		if (stream == nullptr || stream->operations == nullptr ||
		    stream->operations->receive_burst == nullptr) {
			return common::status::failed_precondition(kinetum::common::static_status_text(
				"worker source schedule contains an incomplete receive operation"));
		}
		if (stream->operations->receive_burst != candidate) {
			source_kernel_ = source_kernel_kind::HETEROGENEOUS;
			homogeneous_receive_burst_ = nullptr;
			return common::status::ok();
		}
	}

	source_kernel_ = source_kernel_kind::HOMOGENEOUS;
	homogeneous_receive_burst_ = candidate;
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_input_scheduler_()
{
	constexpr auto MAXIMUM = static_cast<std::size_t>(std::numeric_limits<uint32_t>::max());
	if (rx_inputs_.size() >= MAXIMUM || inbound_boundaries_.size() >= MAXIMUM - rx_inputs_.size()) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "worker input population exceeds compact service identity range");
	}
	std::vector<worker_input_binding> bindings;
	bindings.reserve(rx_inputs_.size() + inbound_boundaries_.size());
	for (std::size_t index = 0u; index < rx_inputs_.size(); ++index) {
		bindings.push_back({{worker_input_kind::RX_STREAM, static_cast<uint32_t>(index)},
				    rx_inputs_[index]->operations->maximum_burst});
	}
	for (std::size_t index = 0u; index < inbound_boundaries_.size(); ++index) {
		bindings.push_back({{worker_input_kind::BOUNDARY, static_cast<uint32_t>(index)},
				    static_cast<uint16_t>(MAX_BURST)});
	}
	auto scheduler_or = worker_input_scheduler::create(bindings, worker_->numa_node);
	if (!scheduler_or.is_ok()) {
		return scheduler_or.error();
	}
	input_scheduler_ = std::move(scheduler_or).value();
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_boundaries_(
	const std::vector<boundary_epoch_channel *> &boundaries,
	std::unique_ptr<worker_boundary_sender> boundary_sender,
	std::unique_ptr<worker_boundary_receiver> boundary_receiver)
{
	const auto &compiled = topology_.transition_topology.boundaries;
	if (boundaries.size() != compiled.size() || boundary_sender == nullptr || boundary_receiver == nullptr ||
	    epoch_ledger_ == nullptr || boundary_sender->worker_index() != worker_index_ ||
	    boundary_sender->runtime_generation() != providers_.runtime_generation() ||
	    boundary_sender->size() != worker_->outbound_boundary_indices.size() ||
	    boundary_receiver->worker_index() != worker_index_ ||
	    boundary_receiver->runtime_generation() != providers_.runtime_generation() ||
	    boundary_receiver->size() != worker_->inbound_boundary_indices.size()) {
		return common::status::failed_precondition(
			"packet runtime boundary endpoint-policy ownership does not equal compiled topology cardinality");
	}
	boundaries_by_index_ = boundaries;
	for (std::size_t index = 0; index < boundaries.size(); ++index) {
		const auto *boundary = boundaries[index];
		const auto &facts = compiled[index];
		if (facts.sender_worker_index >= topology_.transition_topology.workers.size() ||
		    facts.receiver_worker_index >= topology_.transition_topology.workers.size()) {
			return common::status::failed_precondition(
				"compiled boundary endpoint is outside the worker topology");
		}
		const int32_t sender_numa = topology_.transition_topology.workers[facts.sender_worker_index].numa_node;
		const int32_t receiver_numa =
			topology_.transition_topology.workers[facts.receiver_worker_index].numa_node;
		if (boundary == nullptr || facts.boundary_index != index || boundary->boundary_index() != index ||
		    boundary->sender_worker_index() != facts.sender_worker_index ||
		    boundary->receiver_worker_index() != facts.receiver_worker_index ||
		    boundary->from_stage_instance_index() != facts.from_stage_instance_index ||
		    boundary->to_stage_instance_index() != facts.to_stage_instance_index ||
		    boundary->runtime_generation() != providers_.runtime_generation() ||
		    boundary->data_ring_numa_node() != facts.data_ring_numa_node ||
		    boundary->sender_endpoint_numa_node() != sender_numa ||
		    boundary->receiver_endpoint_numa_node() != receiver_numa ||
		    boundary->cut_ring_numa_node() != receiver_numa || boundary->ack_ring_numa_node() != sender_numa ||
		    !boundary->endpoint_storage_sealed() || boundary->data_capacity() != facts.data_ring_capacity ||
		    !boundary->empty() || boundary->sender_closed()) {
			return common::status::failed_precondition(
				"materialized boundary epoch channel does not equal its compiled descriptor");
		}
	}

	inbound_boundaries_.reserve(worker_->inbound_boundary_indices.size());
	for (std::size_t receiver_ordinal = 0u; receiver_ordinal < worker_->inbound_boundary_indices.size();
	     ++receiver_ordinal) {
		const uint32_t boundary_index = worker_->inbound_boundary_indices[receiver_ordinal];
		if (boundary_index >= boundaries.size() ||
		    boundaries[boundary_index]->receiver_worker_index() != worker_index_ ||
		    boundary_receiver->boundary_index(static_cast<uint32_t>(receiver_ordinal)) != boundary_index ||
		    boundary_receiver->policy_numa_node(static_cast<uint32_t>(receiver_ordinal)) !=
			    worker_->numa_node) {
			return common::status::failed_precondition("worker inbound boundary ownership is malformed");
		}
		inbound_boundaries_.push_back(boundaries[boundary_index]);
	}
	for (std::size_t sender_ordinal = 0u; sender_ordinal < worker_->outbound_boundary_indices.size();
	     ++sender_ordinal) {
		const uint32_t boundary_index = worker_->outbound_boundary_indices[sender_ordinal];
		if (boundary_index >= boundaries.size() ||
		    boundaries[boundary_index]->sender_worker_index() != worker_index_ ||
		    boundary_sender->boundary_index(static_cast<uint32_t>(sender_ordinal)) != boundary_index ||
		    boundary_sender->hold_capacity(static_cast<uint32_t>(sender_ordinal)) !=
			    compiled[boundary_index].future_output_hold_capacity ||
		    boundary_sender->policy_numa_node(static_cast<uint32_t>(sender_ordinal)) != worker_->numa_node) {
			return common::status::failed_precondition("worker outbound boundary ownership is malformed");
		}
	}
	auto ledger_binding = boundary_sender->bind_ledger(*epoch_ledger_);
	if (!ledger_binding.is_ok()) {
		return ledger_binding;
	}
	auto receiver_ledger_binding = boundary_receiver->bind_ledger(*epoch_ledger_);
	if (!receiver_ledger_binding.is_ok()) {
		return receiver_ledger_binding;
	}
	if (telemetry_ == nullptr || protocol_faults_ == nullptr) {
		return common::status::internal_error("worker boundary diagnostics lost exact ownership");
	}
	auto ledger_fault_binding = epoch_ledger_->bind_protocol_faults(*telemetry_, *protocol_faults_);
	if (!ledger_fault_binding.is_ok()) {
		return ledger_fault_binding;
	}
	auto sender_fault_binding = boundary_sender->bind_protocol_faults(*telemetry_, *protocol_faults_);
	if (!sender_fault_binding.is_ok()) {
		return sender_fault_binding;
	}
	auto receiver_fault_binding = boundary_receiver->bind_protocol_faults(*telemetry_, *protocol_faults_);
	if (!receiver_fault_binding.is_ok()) {
		return receiver_fault_binding;
	}
	boundary_sender_ = std::move(boundary_sender);
	boundary_receiver_ = std::move(boundary_receiver);
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_epoch_activation_()
{
	if (epoch_ledger_ == nullptr || epoch_activation_ != nullptr || schedule_ == nullptr) {
		return common::status::internal_error("worker activation construction has invalid owner state");
	}
	std::vector<module::module_epoch_store *> module_stores;
	std::vector<packet_epoch_input_staging *> source_staging;
	module_stores.reserve(schedule_->stage_instance_indices.size());
	for (const uint32_t stage_index : schedule_->stage_instance_indices) {
		if (stage_index >= stages_.size() || !stages_[stage_index].owned ||
		    stages_[stage_index].facts == nullptr) {
			return common::status::failed_precondition(
				"worker activation stage projection is outside compiled ownership");
		}
		const auto &stage = stages_[stage_index];
		if (stage.module_store == nullptr) {
			continue;
		}
		if (!stage.facts->module_context_index.has_value() ||
		    *stage.facts->module_context_index >= topology_.module_contexts.size()) {
			return common::status::failed_precondition(
				"worker activation module stage lacks its compiled context identity");
		}
		const auto &compiled_context = topology_.module_contexts[*stage.facts->module_context_index];
		auto *context = modules_.context(compiled_context.module_context_index);
		if (compiled_context.worker_index != worker_index_ ||
		    compiled_context.stage_instance_index != stage_index || context == nullptr ||
		    context->context_index != compiled_context.module_context_index ||
		    context->epoch_store == nullptr || stage.module_store != context->epoch_store.get()) {
			return common::status::failed_precondition(
				"worker activation module projection disagrees with compiled context ownership");
		}
		if (protocol_faults_ == nullptr) {
			return common::status::internal_error("module epoch store lost protocol-fault authority");
		}
		auto fault_binding = context->epoch_store->bind_protocol_fault_latch(*protocol_faults_);
		if (!fault_binding.is_ok()) {
			return fault_binding;
		}
		module_stores.push_back(context->epoch_store.get());
	}
	if (worker_->owns_module_context != !module_stores.empty()) {
		return common::status::failed_precondition(
			"worker activation module projection disagrees with transition ownership");
	}
	if (topology_.transition_topology.policy.enabled) {
		source_staging.reserve(schedule_->source_storage_domain_indices.size());
		for (const uint32_t storage_domain_index : schedule_->source_storage_domain_indices) {
			auto *staging = local_staging_(storage_domain_index);
			if (staging == nullptr || !staging->has_future()) {
				return common::status::failed_precondition(
					"worker activation source projection lacks its exact future queue role");
			}
			source_staging.push_back(staging);
		}
	}
	auto activation_or = worker_epoch_activation::create(worker_index_, providers_.runtime_generation(),
							     module_stores, source_staging, *epoch_ledger_,
							     active_scheduler_.get(), module_health_.get(),
							     *telemetry_);
	if (!activation_or.is_ok()) {
		return activation_or.error();
	}
	epoch_activation_ = std::move(activation_or).value();
	if (epoch_activation_->module_store_count() != module_stores.size() ||
	    epoch_activation_->source_staging_count() != source_staging.size()) {
		return common::status::internal_error(
			"worker activation owner did not retain the exact compiled participant projection");
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_module_health_()
{
	if (schedule_ == nullptr || worker_ == nullptr || epoch_ledger_ == nullptr || module_health_ != nullptr) {
		return common::status::internal_error("module health construction has invalid owner state");
	}
	if (module_telemetry_.empty()) {
		if (worker_->owns_module_context) {
			return common::status::failed_precondition(
				"module health projection is absent for a module-owning worker");
		}
		return common::status::ok();
	}
	if (!worker_->owns_module_context) {
		return common::status::failed_precondition("module health projection exists for a module-free worker");
	}

	const auto callback_budget =
		std::chrono::duration_cast<std::chrono::nanoseconds>(worker_->health_callback_budget);
	if (callback_budget.count() <= 0 || std::chrono::duration_cast<std::chrono::steady_clock::duration>(
						    callback_budget) != worker_->health_callback_budget) {
		return common::status::failed_precondition(
			"module health callback budget is not exactly representable in nanoseconds");
	}

	std::vector<module::worker_module_health_binding> bindings;
	bindings.reserve(module_telemetry_.size());
	for (const uint32_t stage_index : schedule_->stage_instance_indices) {
		if (stage_index >= stages_.size() || !stages_[stage_index].owned ||
		    stages_[stage_index].facts == nullptr) {
			return common::status::failed_precondition(
				"module health stage projection is outside exact worker ownership");
		}
		const auto &stage = stages_[stage_index];
		if (!stage.facts->module_context_index.has_value()) {
			if (stage.module_store != nullptr) {
				return common::status::failed_precondition(
					"module-free health stage carries a module store");
			}
			continue;
		}
		const uint32_t context_index = *stage.facts->module_context_index;
		if (context_index >= topology_.module_contexts.size() ||
		    context_index >= module_telemetry_by_context_.size()) {
			return common::status::failed_precondition("module health stage references an unknown context");
		}
		const auto &compiled = topology_.module_contexts[context_index];
		auto *context = modules_.context(context_index);
		auto *publication = module_telemetry_by_context_[context_index];
		const auto *descriptor = context != nullptr && context->image != nullptr ? context->image->descriptor :
											   nullptr;
		const auto *identity = publication != nullptr ? &publication->identity() : nullptr;
		if (compiled.module_context_index != context_index || compiled.stage_instance_index != stage_index ||
		    compiled.worker_index != worker_index_ || compiled.cpu_core_id != worker_->cpu_core_ids.front() ||
		    compiled.numa_node != worker_->numa_node || context == nullptr || descriptor == nullptr ||
		    descriptor->module_id == nullptr || context->context_index != context_index ||
		    context->context_instance_id != compiled.context_instance_id ||
		    context->image->module_id != compiled.module_id || compiled.module_id != descriptor->module_id ||
		    context->packet_context.worker_index != worker_index_ ||
		    context->packet_context.cpu_core_id != compiled.cpu_core_id ||
		    context->packet_context.numa_node != compiled.numa_node || context->epoch_store == nullptr ||
		    stage.module_store != context->epoch_store.get() || publication != context->lifecycle_owner.get() ||
		    identity == nullptr || identity->context_index != context_index ||
		    identity->context_instance_id != compiled.context_instance_id ||
		    identity->module_id != compiled.module_id ||
		    identity->module_image_index != context->image->module_image_index ||
		    identity->worker_index != worker_index_ || identity->cpu_core_id != compiled.cpu_core_id ||
		    identity->numa_node != compiled.numa_node) {
			return common::status::failed_precondition(
				"module health context, image, store, lifecycle, or placement ownership is not exact");
		}
		if (bindings.size() >= module_telemetry_.size() || module_telemetry_[bindings.size()] != publication) {
			return common::status::failed_precondition(
				"module health context order disagrees with the worker telemetry projection");
		}
		bindings.push_back({
			.stage_instance_index = stage_index,
			.context_index = context_index,
			.context = &context->packet_context,
			.store = context->epoch_store.get(),
			.descriptor = descriptor,
			.publication = publication,
		});
	}
	if (bindings.size() != module_telemetry_.size()) {
		return common::status::failed_precondition(
			"module health projection does not cover every worker module context");
	}
	auto health_or = module::worker_module_health::create(worker_index_, providers_.runtime_generation(),
							      static_cast<uint64_t>(callback_budget.count()), bindings,
							      *epoch_ledger_);
	if (!health_or.is_ok()) {
		return health_or.error();
	}
	module_health_ = std::move(health_or).value();
	if (module_health_->size() != bindings.size()) {
		return common::status::internal_error(
			"module health owner did not retain the exact compiled context projection");
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_active_scheduler_()
{
	if (schedule_ == nullptr || epoch_ledger_ == nullptr || active_scheduler_ != nullptr) {
		return common::status::internal_error("active scheduler construction has invalid owner state");
	}
	if (schedule_->active_stage_instance_indices.empty()) {
		if (!schedule_->async_stage_instance_indices.empty() ||
		    !schedule_->loop_trigger_stage_instance_indices.empty() ||
		    !schedule_->timer_trigger_stage_instance_indices.empty() ||
		    !schedule_->pull_trigger_stage_instance_indices.empty() ||
		    !schedule_->control_trigger_stage_instance_indices.empty()) {
			return common::status::failed_precondition(
				"empty active schedule carries trigger-specific stage ownership");
		}
		return common::status::ok();
	}
	std::vector<active_stage_context_binding> active_contexts;
	active_contexts.reserve(schedule_->active_stage_instance_indices.size());
	for (const uint32_t stage_index : schedule_->active_stage_instance_indices) {
		if (stage_index >= stages_.size() || stages_[stage_index].facts == nullptr) {
			return common::status::failed_precondition(
				"active scheduler context projection is outside compiled stage ownership");
		}
		const auto &stage = *stages_[stage_index].facts;
		if (!stage.module_context_index.has_value()) {
			return common::status::failed_precondition(
				"active scheduler context projection lacks exact module ownership");
		}
		const uint32_t context_index = *stage.module_context_index;
		auto *context = modules_.context(context_index);
		if (context == nullptr || context->epoch_store == nullptr || context->image == nullptr ||
		    context->image->descriptor == nullptr) {
			return common::status::failed_precondition(
				"active scheduler context projection lost its admitted module owner");
		}
		active_contexts.push_back({
			.stage_instance_index = stage_index,
			.module_context_index = context_index,
			.store = context->epoch_store.get(),
			.descriptor = context->image->descriptor,
		});
	}
	auto scheduler_or = worker_active_stage_scheduler::create(
		worker_index_, topology_, active_contexts, *epoch_ledger_,
		active_stage_packet_operations{
			.state = this,
			.emit_origins = &implementation::emit_active_origins_,
			.publish_retained = &implementation::publish_active_retained_,
			.publish_recirculated = &implementation::publish_active_recirculated_,
		});
	if (!scheduler_or.is_ok()) {
		return scheduler_or.error();
	}
	active_scheduler_ = std::move(scheduler_or).value();
	if (active_scheduler_->size() != schedule_->active_stage_instance_indices.size() ||
	    active_scheduler_->has_async_work() != !schedule_->async_stage_instance_indices.empty() ||
	    active_scheduler_->numa_node() != worker_->numa_node || active_scheduler_->storage_bytes() == 0u) {
		return common::status::internal_error(
			"active scheduler did not retain exact compiled schedule and NUMA storage");
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_transition_batches_()
{
	transition_batches_.resize(topology_.storage_transitions.size());
	transition_flush_schedule_.reserve(schedule_->storage_transition_indices.size());
	transition_lookup_.reserve(schedule_->storage_transition_indices.size());
	uint32_t previous = 0;
	bool have_previous = false;
	for (const uint32_t transition_index : schedule_->storage_transition_indices) {
		if (transition_index >= topology_.storage_transitions.size() ||
		    (have_previous && transition_index <= previous)) {
			return common::status::failed_precondition(
				"worker storage-transition schedule is not a sorted unique compact set");
		}
		const auto &facts = topology_.storage_transitions[transition_index];
		const auto *operations = providers_.storage_transition(transition_index);
		if (facts.transition_index != transition_index || operations == nullptr ||
		    operations->transition_index != transition_index ||
		    operations->generation != providers_.runtime_generation() ||
		    operations->from_storage_domain_index != facts.from_storage_domain_index ||
		    operations->to_storage_domain_index != facts.to_storage_domain_index ||
		    local_staging_(facts.from_storage_domain_index) == nullptr ||
		    local_staging_(facts.to_storage_domain_index) == nullptr) {
			return common::status::failed_precondition(
				"worker storage-transition operation does not match compiled ownership");
		}
		auto &batch = transition_batches_[transition_index];
		batch.owned = true;
		batch.facts = &facts;
		batch.operations = operations;
		transition_flush_schedule_.push_back(&batch);
		transition_lookup_.push_back({
			.from_kind = facts.from_endpoint.kind,
			.from_index = facts.from_endpoint.endpoint_index,
			.to_kind = facts.to_endpoint.kind,
			.to_index = facts.to_endpoint.endpoint_index,
			.from_storage_domain = facts.from_storage_domain_index,
			.transition_index = transition_index,
		});
		previous = transition_index;
		have_previous = true;
	}
	const auto key = [](const transition_lookup_entry &entry) {
		return std::tuple{static_cast<uint8_t>(entry.from_kind), entry.from_index,
				  static_cast<uint8_t>(entry.to_kind), entry.to_index, entry.from_storage_domain};
	};
	std::sort(transition_lookup_.begin(), transition_lookup_.end(),
		  [&](const auto &left, const auto &right) { return key(left) < key(right); });
	for (std::size_t index = 1; index < transition_lookup_.size(); ++index) {
		if (key(transition_lookup_[index - 1]) == key(transition_lookup_[index])) {
			return common::status::failed_precondition(
				"worker owns competing transitions for one exact packet-path state");
		}
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_streams_()
{
	rx_streams_.resize(topology_.io_streams.size());
	tx_streams_.resize(topology_.io_streams.size());
	tx_batches_.resize(topology_.io_streams.size());
	rx_inputs_.reserve(schedule_->rx_stream_indices.size());
	tx_flush_schedule_.reserve(schedule_->tx_stream_indices.size());

	for (const uint32_t stream_index : schedule_->rx_stream_indices) {
		if (stream_index >= topology_.io_streams.size()) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "worker RX stream index is outside compiled topology");
		}
		const auto &facts = topology_.io_streams[stream_index];
		const auto *operations = providers_.rx_stream(stream_index);
		if (facts.io_stream_index != stream_index ||
		    facts.direction != provider::compiled_io_stream_direction::RX ||
		    facts.worker_index != worker_index_ ||
		    facts.stage_instance_index >= topology_.stage_instances.size() ||
		    local_staging_(facts.rx_storage_domain_index) == nullptr ||
		    !facts.tx_storage_domain_indices.empty() || !kinetum_provider_rx_operations_are_valid(operations) ||
		    operations->maximum_burst == 0 || operations->maximum_burst > MAX_BURST ||
		    facts.port_index >= topology_.ports.size() ||
		    operations->logical_port != topology_.ports[facts.port_index].logical_port_id) {
			return common::status::failed_precondition(
				"worker RX stream operation does not equal compiled stream truth");
		}
		auto &stream = rx_streams_[stream_index];
		stream.owned = true;
		stream.facts = &facts;
		stream.operations = operations;
		stream.stage_instance_index = facts.stage_instance_index;
		stream.telemetry_ordinal = telemetry_->stream_ordinal(stream_index);
		if (stream.telemetry_ordinal == UINT32_MAX) {
			return common::status::failed_precondition("I/O stream lacks its exact worker telemetry row");
		}
		stream.storage_domain_index = facts.rx_storage_domain_index;
		rx_inputs_.push_back(&stream);
	}

	for (const uint32_t stream_index : schedule_->tx_stream_indices) {
		if (stream_index >= topology_.io_streams.size()) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "worker TX stream index is outside compiled topology");
		}
		const auto &facts = topology_.io_streams[stream_index];
		const auto *operations = providers_.tx_stream(stream_index);
		if (facts.io_stream_index != stream_index ||
		    facts.direction != provider::compiled_io_stream_direction::TX ||
		    facts.worker_index != worker_index_ ||
		    facts.stage_instance_index >= topology_.stage_instances.size() ||
		    facts.rx_storage_domain_index != provider::INVALID_COMPILED_PROVIDER_INDEX ||
		    facts.tx_storage_domain_indices.empty() || !kinetum_provider_tx_operations_are_valid(operations) ||
		    operations->maximum_burst == 0 || operations->maximum_burst > MAX_BURST ||
		    facts.port_index >= topology_.ports.size() ||
		    operations->logical_port != topology_.ports[facts.port_index].logical_port_id) {
			return common::status::failed_precondition(
				"worker TX stream operation does not equal compiled stream truth");
		}
		auto &stream = tx_streams_[stream_index];
		stream.owned = true;
		stream.facts = &facts;
		stream.operations = operations;
		stream.stage_instance_index = facts.stage_instance_index;
		stream.telemetry_ordinal = telemetry_->stream_ordinal(stream_index);
		if (stream.telemetry_ordinal == UINT32_MAX) {
			return common::status::failed_precondition("I/O stream lacks its exact worker telemetry row");
		}
		stream.accepted_storage_domains = kinetum::algo::compact_index_set(topology_.storage_domains.size());
		for (const uint32_t domain : facts.tx_storage_domain_indices) {
			if (local_staging_(domain) == nullptr || !stream.accepted_storage_domains.insert(domain)) {
				return common::status::failed_precondition(
					"TX storage admission lacks exact local staging");
			}
		}
		stream.transition_by_storage_domain.assign(topology_.storage_domains.size(),
							   provider::INVALID_COMPILED_PROVIDER_INDEX);
		auto &batch = tx_batches_[stream_index];
		batch.owned = true;
		batch.stream = &stream;
		tx_flush_schedule_.push_back(&stream);
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_stages_()
{
	stages_.resize(topology_.stage_instances.size());
	std::vector<bool> active_schedule(stages_.size(), false);
	for (const uint32_t stage_index : schedule_->active_stage_instance_indices) {
		if (stage_index >= active_schedule.size() || active_schedule[stage_index]) {
			return common::status::failed_precondition(
				"worker active schedule contains an unknown or duplicate stage instance");
		}
		active_schedule[stage_index] = true;
	}
	std::size_t maximum_fanout = 0;
	std::size_t observed_active_stages = 0u;
	std::size_t observed_module_contexts = 0u;
	for (const uint32_t stage_index : schedule_->stage_instance_indices) {
		if (stage_index >= topology_.stage_instances.size()) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "worker stage index is outside compiled topology");
		}
		const auto &facts = topology_.stage_instances[stage_index];
		if (facts.stage_instance_index != stage_index || facts.worker_index != worker_index_ ||
		    facts.logical_stage_index >= topology_.logical_stages.size() ||
		    facts.region_index >= topology_.execution_regions.size() ||
		    facts.execution_provider_index >= topology_.execution_providers.size() ||
		    providers_.execution_provider(facts.execution_provider_index) == nullptr) {
			return common::status::failed_precondition(
				"worker stage ownership does not equal compiled execution truth");
		}
		const auto &logical = topology_.logical_stages[facts.logical_stage_index];
		const bool active = logical.execution_mode == provider::compiled_stage_execution_mode::ACTIVE;
		const bool scheduled_active = active_schedule[stage_index];
		if (logical.logical_stage_index != facts.logical_stage_index || active != scheduled_active) {
			return common::status::failed_precondition(
				"packet worker active schedule disagrees with exact stage execution mode");
		}
		observed_active_stages += active ? 1u : 0u;

		auto &stage = stages_[stage_index];
		stage.owned = true;
		stage.telemetry_ordinal = telemetry_ != nullptr ? telemetry_->stage_ordinal(stage_index) : UINT32_MAX;
		if (stage.telemetry_ordinal == UINT32_MAX) {
			return common::status::failed_precondition(
				"worker stage lacks its exact owner-local telemetry row");
		}
		stage.facts = &facts;
		stage.logical = &logical;
		stage.region_id = topology_.execution_regions[facts.region_index].region_id;
		stage.target_by_stage_instance.assign(topology_.stage_instances.size(), INVALID_RUNTIME_ORDINAL);
		stage.group_by_logical_stage.assign(topology_.logical_stages.size(), INVALID_RUNTIME_ORDINAL);
		stage.reachable_storage_domains = kinetum::algo::compact_index_set(topology_.storage_domains.size());
		uint32_t previous_storage_domain = 0;
		bool have_previous_storage_domain = false;
		for (const uint32_t storage_domain : facts.reachable_storage_domain_indices) {
			if ((have_previous_storage_domain && storage_domain <= previous_storage_domain) ||
			    !stage.reachable_storage_domains.insert(storage_domain)) {
				return common::status::failed_precondition(
					"stage reachable storage domains are not a sorted unique compact set");
			}
			previous_storage_domain = storage_domain;
			have_previous_storage_domain = true;
		}
		if (facts.dispatch_mode == provider::compiled_stage_dispatch_mode::UNCONDITIONAL_FANOUT) {
			maximum_fanout = std::max(maximum_fanout, facts.packet_routes.size());
		}

		switch (logical.kind) {
		case provider::compiled_stage_kind::RX:
			stage.mechanism = packet_mechanism_kind::RX;
			if (!facts.io_stream_index.has_value() || *facts.io_stream_index >= rx_streams_.size() ||
			    !rx_streams_[*facts.io_stream_index].owned ||
			    rx_streams_[*facts.io_stream_index].stage_instance_index != stage_index) {
				return common::status::failed_precondition(
					"RX stage lacks its exact worker-owned stream");
			}
			stage.rx_stream_index = *facts.io_stream_index;
			break;
		case provider::compiled_stage_kind::TX:
			stage.mechanism = packet_mechanism_kind::TX;
			if (!facts.io_stream_index.has_value() || *facts.io_stream_index >= tx_streams_.size() ||
			    !tx_streams_[*facts.io_stream_index].owned ||
			    tx_streams_[*facts.io_stream_index].stage_instance_index != stage_index) {
				return common::status::failed_precondition(
					"TX stage lacks its exact worker-owned stream");
			}
			stage.stage_bound_tx_stream_index = *facts.io_stream_index;
			break;
		case provider::compiled_stage_kind::PARSE_IPV4:
			stage.mechanism = packet_mechanism_kind::PARSE_IPV4;
			break;
		case provider::compiled_stage_kind::MODULE: {
			if (!facts.module_context_index.has_value() ||
			    *facts.module_context_index >= topology_.module_contexts.size()) {
				return common::status::failed_precondition(
					"module stage lacks exact context ownership");
			}
			const auto &compiled_context = topology_.module_contexts[*facts.module_context_index];
			auto *context = modules_.context(compiled_context.module_context_index);
			auto *telemetry_owner =
				compiled_context.module_context_index < module_telemetry_by_context_.size() ?
					module_telemetry_by_context_[compiled_context.module_context_index] :
					nullptr;
			if (context == nullptr || context->epoch_store == nullptr ||
			    telemetry_owner != context->lifecycle_owner.get() ||
			    observed_module_contexts >= module_telemetry_.size() ||
			    module_telemetry_[observed_module_contexts] != telemetry_owner ||
			    context->context_index != compiled_context.module_context_index ||
			    compiled_context.stage_instance_index != stage_index ||
			    compiled_context.worker_index != worker_index_ ||
			    compiled_context.region_id != stage.region_id || context->image == nullptr ||
			    context->image->module_id != logical.module_id) {
				return common::status::failed_precondition(
					"module stage does not equal admitted context ownership");
			}
			if (context->image->descriptor == nullptr ||
			    context->image->descriptor->mode !=
				    (active ? KINETUM_MODULE_ACTIVE : KINETUM_MODULE_PASSIVE)) {
				return common::status::failed_precondition(
					"module executable view mode disagrees with compiled stage execution mode");
			}
			stage.module_store = context->epoch_store.get();
			++observed_module_contexts;
			break;
		}
		}
	}
	if (observed_active_stages != schedule_->active_stage_instance_indices.size() ||
	    observed_module_contexts != module_telemetry_.size()) {
		return common::status::failed_precondition(
			"worker active or module-telemetry schedule is not a complete ownership projection");
	}
	if (maximum_fanout > topology_.stage_instances.size()) {
		return common::status::failed_precondition("compiled fan-out exceeds the executable stage domain");
	}
	fanout_clones_.assign(maximum_fanout > 0 ? maximum_fanout - 1 : 0, nullptr);
	return common::status::ok();
}

void packet_worker_kernel::implementation::bind_bootstrap_epoch(uint64_t bootstrap_epoch, uint64_t now_ns) noexcept
{
	if (bootstrap_epoch == 0 || now_ns == 0u || epoch_ledger_ == nullptr || boundary_sender_ == nullptr ||
	    boundary_receiver_ == nullptr || epoch_activation_ == nullptr || commands_ == nullptr ||
	    telemetry_ == nullptr || observed_command_ != nullptr || epoch_ledger_->active_epoch() != 0u ||
	    telemetry_->active_epoch() != 0u) {
		std::terminate();
	}
	const auto *baseline_command = commands_->observe();
	if (baseline_command == nullptr || !baseline_command->valid() ||
	    baseline_command->runtime_generation != providers_.runtime_generation() ||
	    baseline_command->kind != worker_runtime_command_kind::RUN) {
		std::terminate();
	}
	if (!quiescence_reader_.bound()) {
		std::terminate();
	}
	for (const uint32_t stage_index : schedule_->stage_instance_indices) {
		if (stage_index >= stages_.size()) {
			std::terminate();
		}
		const auto &stage = stages_[stage_index];
		if (!stage.owned || stage.facts == nullptr || stage.logical == nullptr) {
			std::terminate();
		}
		if (stage.logical->kind != provider::compiled_stage_kind::MODULE) {
			if (stage.module_store != nullptr) {
				std::terminate();
			}
			continue;
		}
		const auto *view = stage.module_store != nullptr ? stage.module_store->active_view() : nullptr;
		const kinetum_module_mode expected_mode =
			stage.logical->execution_mode == provider::compiled_stage_execution_mode::ACTIVE ?
				KINETUM_MODULE_ACTIVE :
				KINETUM_MODULE_PASSIVE;
		if (view == nullptr || view->epoch != bootstrap_epoch ||
		    !stage.facts->module_context_index.has_value() ||
		    view->context_index != *stage.facts->module_context_index || view->mode != expected_mode) {
			std::terminate();
		}
	}
	for (const auto *owner : module_telemetry_) {
		if (owner == nullptr || owner->telemetry_active_epoch() != bootstrap_epoch) {
			std::terminate();
		}
	}
	if (module_telemetry_.size() == std::numeric_limits<std::size_t>::max() ||
	    !telemetry_->preflight_completed_publications(module_telemetry_.size() + 1u)) {
		std::terminate();
	}
	telemetry_->bind_bootstrap_epoch(bootstrap_epoch, now_ns);
	epoch_ledger_->bind_bootstrap_epoch(bootstrap_epoch);
	boundary_sender_->bind_bootstrap_epoch(bootstrap_epoch);
	boundary_receiver_->bind_bootstrap_epoch(bootstrap_epoch);
	epoch_activation_->bind_bootstrap_epoch(bootstrap_epoch);
	const auto worker_telemetry = telemetry_->service_turn(now_ns);
	if (!worker_telemetry.cadence_due) {
		std::terminate();
	}
	record_telemetry_return_need_(worker_telemetry.return_need);
	for (auto *owner : module_telemetry_) {
		record_telemetry_return_need_(owner->service_telemetry_cadence(now_ns));
	}
	observed_command_ = baseline_command;
	publish_boundary_transport_();
}

common::status packet_worker_kernel::implementation::initialize_stage_routes_(stage_runtime &stage)
{
	if (!stage.owned || stage.facts == nullptr || stage.logical == nullptr) {
		return common::status::failed_precondition("worker route compilation requires one owned stage");
	}

	const auto resolve_target = [&](uint32_t destination_index) -> common::status_or<uint32_t> {
		if (destination_index >= topology_.stage_instances.size()) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "stage route destination exceeds the compiled stage domain");
		}
		const uint32_t existing = stage.target_by_stage_instance[destination_index];
		if (existing != INVALID_RUNTIME_ORDINAL) {
			return existing;
		}

		const auto &destination = topology_.stage_instances[destination_index];
		if (destination.stage_instance_index != destination_index ||
		    destination.logical_stage_index >= topology_.logical_stages.size() ||
		    destination.stage_instance_index > std::numeric_limits<uint16_t>::max()) {
			return common::status::failed_precondition(
				"stage route destination has a nonrepresentable executable identity");
		}
		route_target target;
		target.stage_instance_index = destination_index;
		target.logical_stage_index = destination.logical_stage_index;
		target.transition_by_storage_domain.assign(topology_.storage_domains.size(),
							   provider::INVALID_COMPILED_PROVIDER_INDEX);
		if (destination.worker_index != worker_index_) {
			auto *boundary = find_boundary_(stage.facts->stage_instance_index, destination_index);
			if (boundary == nullptr || boundary_sender_ == nullptr) {
				return common::status::failed_precondition(
					"cross-worker stage route lacks its exact sender-policy authority");
			}
			auto sender_ordinal_or = boundary_sender_->sender_ordinal(boundary->boundary_index());
			if (!sender_ordinal_or.is_ok()) {
				return sender_ordinal_or.error();
			}
			target.boundary_index = boundary->boundary_index();
			target.sender_ordinal = sender_ordinal_or.value();
		} else if (find_boundary_(stage.facts->stage_instance_index, destination_index) != nullptr) {
			return common::status::failed_precondition(
				"same-worker stage route unexpectedly owns a boundary channel");
		}

		for (const uint32_t source_domain : stage.facts->reachable_storage_domain_indices) {
			if (source_domain >= target.transition_by_storage_domain.size()) {
				return common::status::failed_precondition(
					"stage route carries an invalid reachable storage identity");
			}
			const uint32_t transition_index =
				find_transition_(provider::compiled_packet_path_endpoint_kind::STAGE_INSTANCE,
						 stage.facts->stage_instance_index,
						 provider::compiled_packet_path_endpoint_kind::STAGE_INSTANCE,
						 destination_index, source_domain);
			if (transition_index == provider::INVALID_COMPILED_PROVIDER_INDEX) {
				if (!sorted_contains(destination.reachable_storage_domain_indices, source_domain)) {
					return common::status::failed_precondition(
						"domain-preserving stage route is not executable by its destination");
				}
				continue;
			}
			if (transition_index >= topology_.storage_transitions.size()) {
				return common::status::failed_precondition(
					"stage route resolved an invalid storage-transition identity");
			}
			const auto &transition = topology_.storage_transitions[transition_index];
			if (!sorted_contains(destination.reachable_storage_domain_indices,
					     transition.to_storage_domain_index)) {
				return common::status::failed_precondition(
					"stage transition destination is not executable by its target");
			}
			target.transition_by_storage_domain[source_domain] = transition_index;
			const auto result = configure_transition_(transition_index, packet_work_phase::STAGE_DELIVER,
								  target.sender_ordinal != INVALID_RUNTIME_ORDINAL ?
									  transition_post_action::BOUNDARY_SEND :
									  transition_post_action::LOCAL_EXECUTE);
			if (!result.is_ok()) {
				return result;
			}
		}

		if (stage.targets.size() >= std::numeric_limits<uint32_t>::max()) {
			return common::status(common::status_code::OUT_OF_RANGE,
					      "stage route target count exceeds compact runtime range");
		}
		const uint32_t ordinal = static_cast<uint32_t>(stage.targets.size());
		stage.targets.push_back(std::move(target));
		stage.target_by_stage_instance[destination_index] = ordinal;
		return ordinal;
	};

	const auto &routes = stage.facts->packet_routes;
	if ((stage.facts->dispatch_mode == provider::compiled_stage_dispatch_mode::TERMINAL) != routes.empty()) {
		return common::status::failed_precondition("stage dispatch mode disagrees with its packet routes");
	}
	std::map<uint16_t, std::set<uint16_t>> destinations_by_logical_stage;
	for (const auto &route : routes) {
		const auto &destinations = route.destination_stage_instance_indices;
		if (destinations.empty() || !std::is_sorted(destinations.begin(), destinations.end()) ||
		    std::adjacent_find(destinations.begin(), destinations.end()) != destinations.end()) {
			return common::status::failed_precondition("packet route lacks a canonical destination set");
		}
		uint16_t logical_index = provider::INVALID_COMPILED_STAGE_INSTANCE_INDEX;
		for (const uint16_t destination : destinations) {
			auto ordinal_or = resolve_target(destination);
			if (!ordinal_or.is_ok()) {
				return ordinal_or.error();
			}
			const auto &facts = topology_.stage_instances[destination];
			if (logical_index != provider::INVALID_COMPILED_STAGE_INSTANCE_INDEX &&
			    logical_index != facts.logical_stage_index) {
				return common::status::failed_precondition(
					"packet route spans distinct logical destinations");
			}
			logical_index = facts.logical_stage_index;
			destinations_by_logical_stage[logical_index].insert(destination);
		}
	}
	stage.groups.reserve(destinations_by_logical_stage.size());
	for (const auto &[logical_index, destinations] : destinations_by_logical_stage) {
		const auto &logical = topology_.logical_stages[logical_index];
		const bool selected = logical.kind == provider::compiled_stage_kind::MODULE &&
				      logical.context_selection == provider::compiled_module_context_selection::MODULE;
		route_group group;
		group.logical_stage_index = logical_index;
		for (const uint16_t destination_index : destinations) {
			const auto &destination = topology_.stage_instances[destination_index];
			const uint32_t target = stage.target_by_stage_instance[destination_index];
			if (destination.lane_index == stage.facts->lane_index) {
				if (group.direct_target_ordinal != INVALID_RUNTIME_ORDINAL) {
					return common::status::failed_precondition(
						"logical route repeats its same-lane destination");
				}
				group.direct_target_ordinal = target;
			}
			if (!selected) {
				continue;
			}
			if (!destination.module_context_index.has_value() ||
			    *destination.module_context_index >= topology_.module_contexts.size()) {
				return common::status::failed_precondition("selected route lacks a module context");
			}
			const auto &context = topology_.module_contexts[*destination.module_context_index];
			const auto *loaded = modules_.context(context.module_context_index);
			const auto *descriptor =
				loaded != nullptr && loaded->image != nullptr ? loaded->image->descriptor : nullptr;
			if (descriptor == nullptr || descriptor->select_contexts == nullptr ||
			    (descriptor->flags & KINETUM_MOD_F_CONTEXT_SELECTION) == 0u ||
			    context.module_context_count == 0u ||
			    context.module_context_ordinal >= context.module_context_count) {
				return common::status::failed_precondition(
					"selected route lacks its admitted selector or population");
			}
			if (group.select_contexts == nullptr) {
				group.select_contexts = descriptor->select_contexts;
				group.context_count = context.module_context_count;
				group.target_by_context_ordinal.assign(group.context_count, INVALID_RUNTIME_ORDINAL);
				group.permitted_bitmap.assign(
					(static_cast<std::size_t>(group.context_count) + 63u) / 64u, 0u);
			} else if (group.select_contexts != descriptor->select_contexts ||
				   group.context_count != context.module_context_count) {
				return common::status::failed_precondition(
					"selected route mixes context populations or selectors");
			}
			auto &context_target = group.target_by_context_ordinal[context.module_context_ordinal];
			if (context_target != INVALID_RUNTIME_ORDINAL) {
				return common::status::failed_precondition("selected route repeats a context ordinal");
			}
			context_target = target;
			group.permitted_ordinals.push_back(context.module_context_ordinal);
			group.permitted_bitmap[context.module_context_ordinal / 64u] |=
				UINT64_C(1) << (context.module_context_ordinal % 64u);
		}
		if (group.direct_target_ordinal == INVALID_RUNTIME_ORDINAL ||
		    (!selected && destinations.size() != 1u)) {
			return common::status::failed_precondition(
				"logical route lacks its exact same-lane destination");
		}
		std::sort(group.permitted_ordinals.begin(), group.permitted_ordinals.end());
		stage.group_by_logical_stage[logical_index] = static_cast<uint32_t>(stage.groups.size());
		stage.groups.push_back(std::move(group));
	}
	for (const auto &route : routes) {
		const uint16_t destination = route.destination_stage_instance_indices.front();
		const uint32_t group =
			stage.group_by_logical_stage[topology_.stage_instances[destination].logical_stage_index];
		if (route.mode != provider::compiled_packet_edge_mode::PUSH &&
		    (route.mode != provider::compiled_packet_edge_mode::PULL ||
		     stage.logical->execution_mode != provider::compiled_stage_execution_mode::ACTIVE ||
		     route.destination_stage_instance_indices.size() != 1u ||
		     topology_.stage_instances[destination].worker_index != worker_index_)) {
			return common::status::failed_precondition(
				"PULL route requires one exact same-worker active source");
		}
		switch (stage.facts->dispatch_mode) {
		case provider::compiled_stage_dispatch_mode::TERMINAL:
			std::terminate();
		case provider::compiled_stage_dispatch_mode::UNCONDITIONAL_FANOUT:
			stage.fanout_group_ordinals.push_back(group);
			break;
		case provider::compiled_stage_dispatch_mode::PRIORITY_ROUTE:
			stage.priority_routes.push_back({route.condition, group,
							 route.mode == provider::compiled_packet_edge_mode::PULL ?
								 stage.target_by_stage_instance[destination] :
								 INVALID_RUNTIME_ORDINAL});
			break;
		}
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::initialize_stream_transitions_()
{
	for (auto *stream : rx_inputs_) {
		auto &stage = stages_[stream->stage_instance_index];
		const uint32_t transition_index = find_transition_(
			provider::compiled_packet_path_endpoint_kind::IO_STREAM, stream->facts->io_stream_index,
			provider::compiled_packet_path_endpoint_kind::STAGE_INSTANCE, stream->stage_instance_index,
			stream->storage_domain_index);
		if (transition_index == provider::INVALID_COMPILED_PROVIDER_INDEX) {
			if (!sorted_contains(stage.facts->reachable_storage_domain_indices,
					     stream->storage_domain_index)) {
				return common::status::failed_precondition(
					"RX stream requires a missing storage transition into its stage");
			}
			continue;
		}
		const auto &transition = topology_.storage_transitions[transition_index];
		if (!endpoint_equal(transition.from_endpoint, provider::compiled_packet_path_endpoint_kind::IO_STREAM,
				    stream->facts->io_stream_index) ||
		    !endpoint_equal(transition.to_endpoint,
				    provider::compiled_packet_path_endpoint_kind::STAGE_INSTANCE,
				    stream->stage_instance_index) ||
		    !sorted_contains(stage.facts->reachable_storage_domain_indices,
				     transition.to_storage_domain_index)) {
			return common::status::failed_precondition(
				"RX storage transition disagrees with its stream edge");
		}
		stream->transition_index = transition_index;
		const auto result = configure_transition_(transition_index, packet_work_phase::RX_DELIVER,
							  transition_post_action::RX_EXECUTE);
		if (!result.is_ok()) {
			return result;
		}
	}

	for (auto *stream : tx_flush_schedule_) {
		const auto &stage = stages_[stream->stage_instance_index];
		for (const uint32_t source_domain : stage.facts->reachable_storage_domain_indices) {
			const uint32_t transition_index = find_transition_(
				provider::compiled_packet_path_endpoint_kind::STAGE_INSTANCE,
				stream->stage_instance_index, provider::compiled_packet_path_endpoint_kind::IO_STREAM,
				stream->facts->io_stream_index, source_domain);
			if (transition_index == provider::INVALID_COMPILED_PROVIDER_INDEX) {
				if (!stream->accepted_storage_domains.contains(source_domain)) {
					return common::status::failed_precondition(
						"TX stream requires a missing storage transition from its stage");
				}
				continue;
			}
			const auto &transition = topology_.storage_transitions[transition_index];
			if (!endpoint_equal(transition.from_endpoint,
					    provider::compiled_packet_path_endpoint_kind::STAGE_INSTANCE,
					    stream->stage_instance_index) ||
			    !endpoint_equal(transition.to_endpoint,
					    provider::compiled_packet_path_endpoint_kind::IO_STREAM,
					    stream->facts->io_stream_index) ||
			    !stream->accepted_storage_domains.contains(transition.to_storage_domain_index)) {
				return common::status::failed_precondition(
					"TX storage transition disagrees with its stream edge");
			}
			stream->transition_by_storage_domain[source_domain] = transition_index;
			const auto result = configure_transition_(transition_index, packet_work_phase::TX_DELIVER,
								  transition_post_action::TX_SUBMIT);
			if (!result.is_ok()) {
				return result;
			}
		}
	}
	return common::status::ok();
}

common::status packet_worker_kernel::implementation::validate_transition_coverage_() const
{
	for (const auto &batch : transition_batches_) {
		if (batch.owned != batch.configured) {
			return common::status::failed_precondition(
				"worker transition schedule and executable edge coverage are not exact");
		}
	}
	if (boundary_sender_ == nullptr) {
		return common::status::failed_precondition("worker lacks its exact outbound sender authority");
	}
	for (std::size_t sender_ordinal = 0u; sender_ordinal < boundary_sender_->size(); ++sender_ordinal) {
		const uint32_t boundary_index = boundary_sender_->boundary_index(static_cast<uint32_t>(sender_ordinal));
		std::size_t uses = 0;
		for (const auto &stage : stages_) {
			if (!stage.owned) {
				continue;
			}
			uses += static_cast<std::size_t>(std::count_if(
				stage.targets.begin(), stage.targets.end(),
				[&](const route_target &target) { return target.boundary_index == boundary_index; }));
		}
		if (uses != 1u) {
			return common::status::failed_precondition(
				"outbound DATA boundary must implement one exact executable route");
		}
	}
	return common::status::ok();
}

uint32_t packet_worker_kernel::implementation::find_transition_(provider::compiled_packet_path_endpoint_kind from_kind,
								uint32_t from_index,
								provider::compiled_packet_path_endpoint_kind to_kind,
								uint32_t to_index,
								uint32_t from_storage_domain) const noexcept
{
	const auto requested = std::tuple{static_cast<uint8_t>(from_kind), from_index, static_cast<uint8_t>(to_kind),
					  to_index, from_storage_domain};
	const auto iterator =
		std::lower_bound(transition_lookup_.begin(), transition_lookup_.end(), requested,
				 [](const transition_lookup_entry &entry, const auto &key) {
					 return std::tuple{static_cast<uint8_t>(entry.from_kind), entry.from_index,
							   static_cast<uint8_t>(entry.to_kind), entry.to_index,
							   entry.from_storage_domain} < key;
				 });
	if (iterator == transition_lookup_.end()) {
		return provider::INVALID_COMPILED_PROVIDER_INDEX;
	}
	const auto found = std::tuple{static_cast<uint8_t>(iterator->from_kind), iterator->from_index,
				      static_cast<uint8_t>(iterator->to_kind), iterator->to_index,
				      iterator->from_storage_domain};
	return found == requested ? iterator->transition_index : provider::INVALID_COMPILED_PROVIDER_INDEX;
}

boundary_epoch_channel *packet_worker_kernel::implementation::find_boundary_(uint32_t from_stage_instance,
									     uint32_t to_stage_instance) const noexcept
{
	const auto &by_source = topology_.transition_topology.boundaries_by_source_stage_instance;
	if (from_stage_instance >= by_source.size()) {
		return nullptr;
	}
	const auto &edges = by_source[from_stage_instance];
	const auto iterator = std::lower_bound(edges.begin(), edges.end(), to_stage_instance,
					       [](const common::compiled_transition_edge &edge, uint32_t destination) {
						       return edge.to_stage_instance_index < destination;
					       });
	if (iterator == edges.end() || iterator->to_stage_instance_index != to_stage_instance ||
	    iterator->boundary_index >= boundaries_by_index_.size()) {
		return nullptr;
	}
	return boundaries_by_index_[iterator->boundary_index];
}

common::status packet_worker_kernel::implementation::configure_transition_(uint32_t transition_index,
									   packet_work_phase retry_phase,
									   transition_post_action post_action)
{
	if (transition_index >= transition_batches_.size()) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "worker route resolved a transition outside the compact table");
	}
	auto &batch = transition_batches_[transition_index];
	if (!batch.owned || batch.facts == nullptr || batch.operations == nullptr) {
		return common::status::failed_precondition(
			"worker route resolved a transition outside its exact schedule");
	}
	if (batch.configured && (batch.retry_phase != retry_phase || batch.post_action != post_action)) {
		return common::status::failed_precondition(
			"one storage transition was assigned competing runtime dispositions");
	}
	batch.configured = true;
	batch.retry_phase = retry_phase;
	batch.post_action = post_action;
	return common::status::ok();
}

local_work_staging *packet_worker_kernel::implementation::local_staging_(uint32_t storage_domain_index) noexcept
{
	return storage_domain_index < local_staging_owners_.size() ? local_staging_owners_[storage_domain_index].get() :
								     nullptr;
}

bool packet_worker_kernel::implementation::validate_record_(const packet_record *record,
							    uint32_t expected_domain) const noexcept
{
	if (record == nullptr || expected_domain >= topology_.storage_domains.size() ||
	    expected_domain >= release_batches_.size()) {
		return false;
	}
	const auto *operations = release_batches_[expected_domain].operations;
	if (operations == nullptr) {
		return false;
	}
	const auto &storage = record->storage;
	return storage.operations == operations && storage.generation == providers_.runtime_generation() &&
	       storage.generation == operations->generation && storage.domain_index == expected_domain &&
	       storage.domain_index == operations->domain_index && storage.length != 0 &&
	       storage.length <= operations->maximum_packet_length && storage.segment_count != 0 &&
	       storage.capabilities == operations->capabilities &&
	       (storage.capabilities & ~packet_storage_capabilities::KNOWN_MASK) == 0;
}

uint32_t packet_worker_kernel::implementation::record_storage_domain_(const packet_record *record) const noexcept
{
	if (record == nullptr) {
		return provider::INVALID_COMPILED_PROVIDER_INDEX;
	}
	const uint32_t domain = record->storage.domain_index;
	return validate_record_(record, domain) ? domain : provider::INVALID_COMPILED_PROVIDER_INDEX;
}

bool packet_worker_kernel::implementation::reserve_local_slot_(uint32_t storage_domain_index) noexcept
{
	auto *staging = local_staging_(storage_domain_index);
	return staging != nullptr && staging->reserve_active();
}

void packet_worker_kernel::implementation::commit_local_reservation_(uint32_t storage_domain_index,
								     packet_work_item item) noexcept
{
	auto *staging = local_staging_(storage_domain_index);
	if (staging == nullptr || item.record == nullptr) {
		std::terminate();
	}
	staging->commit_active(std::move(item));
}

void packet_worker_kernel::implementation::release_local_reservation_(uint32_t storage_domain_index) noexcept
{
	auto *staging = local_staging_(storage_domain_index);
	if (staging == nullptr) {
		std::terminate();
	}
	staging->release_active_reservation();
}

algo::service_result packet_worker_kernel::implementation::poll_one_rx_(rx_stream_runtime &stream,
									receive_burst_function receive_burst,
									uint16_t allowance,
									uint64_t cached_time) noexcept
{
	auto *staging = local_staging_(stream.storage_domain_index);
	if (staging == nullptr || stream.operations == nullptr || receive_burst == nullptr) {
		std::terminate();
	}
	const uint64_t source_epoch = epoch_ledger_->source_epoch();
	const bool future_role = source_epoch != epoch_ledger_->active_epoch();
	// Select the queue role once for the complete provider burst. The normal
	// fixed/active role remains the predicted branch and every packet in the
	// returned prefix inherits the same already observed source identity.
	const auto poll_role = [&]<bool future>() noexcept {
		std::size_t available = 0u;
		if constexpr (future) {
			available = staging->future_available();
		} else {
			available = staging->active_available();
		}
		const std::size_t requested = std::min<std::size_t>(available, allowance);
		if (requested == 0u) {
			return algo::service_result{0u, algo::service_disposition::RETAINED};
		}
		for (std::size_t index = 0; index < requested; ++index) {
			bool reserved = false;
			if constexpr (future) {
				reserved = staging->reserve_future();
			} else {
				reserved = staging->reserve_active();
			}
			if (!reserved) {
				std::terminate();
			}
			scratch_->rx_records[index] = nullptr;
		}
		const auto result = receive_burst(stream.operations->state, scratch_->rx_records.data(),
						  static_cast<uint16_t>(requested));
		const uint16_t received = result.transferred_count;
		if (kinetum_packet_rx_burst_result_is_valid(result, static_cast<uint16_t>(requested)) == 0u) {
			std::terminate();
		}
		const auto &stage = stages_[stream.stage_instance_index];
		uint64_t received_bytes = 0u;
		for (uint16_t index = 0; index < received; ++index) {
			auto *record = scratch_->rx_records[index];
			if (!validate_record_(record, stream.storage_domain_index) || !stage.owned ||
			    stage.facts == nullptr || stage.logical == nullptr ||
			    stage.facts->stage_instance_index > std::numeric_limits<uint16_t>::max()) {
				std::terminate();
			}
			initialize_packet_record(*record);
			record->metadata.timestamp_ns = cached_time;
			record->metadata.epoch = source_epoch;
			record->metadata.ingress_port = stream.operations->logical_port;
			record->metadata.current_stage = stage.logical->logical_stage_index;
			record->metadata.current_stage_instance =
				static_cast<uint16_t>(stage.facts->stage_instance_index);
			epoch_ledger_->acquire(record->metadata.epoch);
			received_bytes += record->storage.length;
			if constexpr (future) {
				staging->commit_future({record, packet_work_phase::RX_DELIVER, {}});
			} else {
				staging->commit_active({record, packet_work_phase::RX_DELIVER, {}});
			}
		}
		for (std::size_t index = received; index < requested; ++index) {
			if (scratch_->rx_records[index] != nullptr) {
				// The foreign RX callback may transfer ownership only through its
				// returned prefix. A published suffix pointer has no lawful owner.
				std::terminate();
			}
			if constexpr (future) {
				staging->release_future_reservation();
			} else {
				staging->release_active_reservation();
			}
		}
		if (received != 0u || result.rejected_count != 0u) {
			telemetry_->record_stream(stream.telemetry_ordinal, received, received_bytes,
						  result.rejected_count);
		}
		const auto work = static_cast<uint16_t>(received + result.rejected_count);
		return algo::service_result{work, work < requested ? algo::service_disposition::YIELDED :
								     algo::service_disposition::RETAINED};
	};
	if (KINETUM_UNLIKELY(future_role)) {
		if (source_epoch != epoch_ledger_->future_epoch() || !staging->has_future()) {
			std::terminate();
		}
		return poll_role.template operator()<true>();
	} else {
		return poll_role.template operator()<false>();
	}
}

algo::service_result packet_worker_kernel::implementation::drain_one_boundary_(boundary_epoch_channel &boundary,
									       uint16_t allowance) noexcept
{
	uint16_t received = 0u;
	while (received < allowance) {
		const auto *observed = boundary.peek_data();
		if (observed == nullptr) {
			return {received, algo::service_disposition::YIELDED};
		}
		const uint32_t domain = record_storage_domain_(observed);
		if (observed->metadata.epoch != epoch_ledger_->active_epoch()) {
			const uint64_t active_epoch = epoch_ledger_->active_epoch();
			epoch_protocol_fault_code code = epoch_protocol_fault_code::EPOCH_EXECUTION_MISMATCH;
			if (boundary_receiver_ != nullptr && boundary_receiver_->transition_active()) {
				if (observed->metadata.epoch == boundary_receiver_->transition_to_epoch() &&
				    active_epoch == boundary_receiver_->transition_from_epoch()) {
					code = epoch_protocol_fault_code::FUTURE_DATA_BEFORE_ACK;
				} else if (observed->metadata.epoch == boundary_receiver_->transition_from_epoch() &&
					   active_epoch == boundary_receiver_->transition_to_epoch()) {
					code = epoch_protocol_fault_code::OLD_DATA_AFTER_SEAL;
				}
			}
			record_protocol_fault_(code, epoch_protocol_fault_disposition::TERMINATE,
					       boundary.boundary_index(), UINT32_MAX,
					       boundary.to_stage_instance_index(), observed->metadata.epoch,
					       active_epoch, observed->metadata.epoch);
			std::terminate();
		}
		if (domain == provider::INVALID_COMPILED_PROVIDER_INDEX ||
		    observed->metadata.current_stage_instance != boundary.from_stage_instance_index() ||
		    observed->metadata.next_stage_instance != boundary.to_stage_instance_index() ||
		    boundary.to_stage_instance_index() >= stages_.size() ||
		    !stages_[boundary.to_stage_instance_index()].owned ||
		    !stages_[boundary.to_stage_instance_index()].reachable_storage_domains.contains(domain)) {
			std::terminate();
		}
		if (!reserve_local_slot_(domain)) {
			return {received, algo::service_disposition::RETAINED};
		}
		packet_record *record = nullptr;
		const auto receive_result = boundary.try_receive_data(record);
		if (KINETUM_UNLIKELY(receive_result != boundary_data_receive_result::RECEIVED)) {
			if (receive_result == boundary_data_receive_result::SEQUENCE_EXHAUSTED) {
				record_protocol_fault_(epoch_protocol_fault_code::SEQUENCE_EXHAUSTED,
						       epoch_protocol_fault_disposition::TERMINATE,
						       boundary.boundary_index(), UINT32_MAX,
						       boundary.to_stage_instance_index(), observed->metadata.epoch,
						       MAX_BOUNDARY_DATA_SEQUENCE, boundary.data_dequeued_sequence());
			} else if (receive_result != boundary_data_receive_result::EMPTY) {
				std::terminate();
			}
			std::terminate();
		}
		if (KINETUM_UNLIKELY(record != observed)) {
			std::terminate();
		}
		// Receiver ownership must exist before the channel records this
		// dequeue as successful sequence progress.
		epoch_ledger_->acquire(record->metadata.epoch);
		boundary.complete_data_receive(record);
		promote_next_stage_(*record);
		commit_local_reservation_(domain, {record, packet_work_phase::EXECUTE, {}});
		++received;
	}
	return {received, algo::service_disposition::RETAINED};
}

template <bool has_active_scheduler, bool has_async_scheduler>
void packet_worker_kernel::implementation::process_local_queues_() noexcept
{
	static_assert(has_active_scheduler || !has_async_scheduler);
	flush_context_selection_();
	for (const auto &entry : local_queue_schedule_) {
		const uint32_t domain = entry.storage_domain_index;
		auto *staging = entry.staging;
		if (staging == nullptr) {
			std::terminate();
		}
		const std::size_t count = staging->pop_active_batch(scratch_->local_work.data(), MAX_BURST);
		for (std::size_t index = 0; index < count; ++index) {
			if (!reserve_local_slot_(domain)) {
				std::terminate();
			}
		}
		for (std::size_t index = 0; index < count;) {
			const auto item = scratch_->local_work[index];
			auto &stage = work_stage_(item, domain);
			if (item.phase != packet_work_phase::EXECUTE ||
			    stage.logical->kind != provider::compiled_stage_kind::MODULE) {
				process_work_item_(item, stage, domain);
				scratch_->local_work[index++] = {};
				continue;
			}
			const uint64_t epoch = item.record->metadata.epoch;
			std::size_t size = 0u;
			do {
				scratch_->module_records[size++] = scratch_->local_work[index].record;
				scratch_->local_work[index++] = {};
				if (index == count) {
					break;
				}
				const auto next = scratch_->local_work[index];
				if (next.record == nullptr) {
					std::terminate();
				}
				if (next.phase != packet_work_phase::EXECUTE ||
				    next.record->metadata.current_stage_instance != stage.facts->stage_instance_index ||
				    next.record->metadata.epoch != epoch) {
					break;
				}
				(void)work_stage_(next, domain);
			} while (size < MAX_BURST);
			execute_module_batch_<has_active_scheduler, has_async_scheduler>(
				{scratch_->module_records.data(), size}, stage, domain);
			flush_context_selection_();
		}
		flush_context_selection_();
	}
}

packet_worker_kernel::implementation::stage_runtime &
packet_worker_kernel::implementation::work_stage_(packet_work_item item, uint32_t reserved_domain) noexcept
{
	if (!validate_record_(item.record, reserved_domain) ||
	    item.record->metadata.current_stage_instance >= stages_.size()) {
		std::terminate();
	}
	auto &stage = stages_[item.record->metadata.current_stage_instance];
	if (!stage.owned || stage.facts == nullptr || stage.logical == nullptr ||
	    item.record->metadata.current_stage != stage.logical->logical_stage_index) {
		std::terminate();
	}
	packet_prefetch(item.record);
	return stage;
}

void packet_worker_kernel::implementation::process_work_item_(packet_work_item item, stage_runtime &stage,
							      uint32_t reserved_domain) noexcept
{
	switch (item.phase) {
	case packet_work_phase::RX_DELIVER:
		deliver_rx_(item.record, stage, reserved_domain);
		return;
	case packet_work_phase::EXECUTE:
		execute_stage_(item.record, stage, reserved_domain);
		return;
	case packet_work_phase::STAGE_DELIVER:
		flush_context_selection_();
		deliver_stage_(item.record, stage, reserved_domain);
		return;
	case packet_work_phase::BOUNDARY_SEND:
		flush_context_selection_();
		send_boundary_(item.record, stage, reserved_domain);
		return;
	case packet_work_phase::TX_DELIVER:
		flush_context_selection_();
		deliver_tx_(item.record, stage, reserved_domain);
		return;
	}
	std::terminate();
}

void packet_worker_kernel::implementation::execute_stage_(packet_record *record, stage_runtime &stage,
							  uint32_t reserved_domain) noexcept
{
	if (record->metadata.epoch != epoch_ledger_->active_epoch() ||
	    stage.logical->kind == provider::compiled_stage_kind::MODULE) {
		std::terminate();
	}
	telemetry_->record_stage_input(stage.telemetry_ordinal, 1u, record->storage.length);
	if (!stage.reachable_storage_domains.contains(reserved_domain) ||
	    !packet_record_has_current_cpu_shape(record)) {
		telemetry_->record_stage_drop(stage.telemetry_ordinal);
		release_record_(record, reserved_domain);
		return;
	}
	switch (execute_packet_mechanism(stage.mechanism, record)) {
	case packet_mechanism_outcome::FORWARDED_RX:
	case packet_mechanism_outcome::FORWARDED:
	case packet_mechanism_outcome::FORWARDED_TX:
		break;
	case packet_mechanism_outcome::REJECTED:
		telemetry_->record_stage_drop(stage.telemetry_ordinal);
		release_record_(record, reserved_domain);
		return;
	}
	dispatch_stage_result_(record, stage, reserved_domain);
}

template <bool has_active_scheduler, bool has_async_scheduler>
void packet_worker_kernel::implementation::execute_module_batch_(std::span<packet_record *const> records,
								 stage_runtime &stage,
								 uint32_t reserved_domain) noexcept
{
	if (records.empty() || records.size() > MAX_BURST || stage.module_store == nullptr ||
	    stage.facts->stage_instance_index > std::numeric_limits<uint16_t>::max()) {
		std::terminate();
	}
	uint64_t bytes = 0u;
	uint16_t count = 0u;
	const bool reachable = stage.reachable_storage_domains.contains(reserved_domain);
	for (auto *record : records) {
		if (record->metadata.epoch != epoch_ledger_->active_epoch()) {
			std::terminate();
		}
		bytes += record->storage.length;
		if (!reachable || !packet_record_has_current_cpu_shape(record)) {
			telemetry_->record_stage_drop(stage.telemetry_ordinal);
			release_record_(record, reserved_domain);
		} else {
			scratch_->module_records[count++] = record;
		}
	}
	telemetry_->record_stage_input(stage.telemetry_ordinal, static_cast<uint16_t>(records.size()), bytes);
	if (count == 0u) {
		return;
	}
	const std::span<packet_record *const> occupied{scratch_->module_records.data(), count};
	const auto execute_passive = [&]() noexcept {
		return execute_module_batch_mechanism(*stage.module_store,
						      static_cast<uint16_t>(stage.facts->stage_instance_index),
						      stage.region_id, occupied, scratch_->module);
	};
	active_ingest_result result;
	if constexpr (has_active_scheduler) {
		if (stage.logical->execution_mode == provider::compiled_stage_execution_mode::ACTIVE) {
			if (active_scheduler_ == nullptr) {
				std::terminate();
			}
			if constexpr (has_async_scheduler) {
				result = active_scheduler_->ingest_async(stage.facts->stage_instance_index, occupied,
									 stage.region_id, scratch_->module,
									 cached_turn_time_ns_);
			} else {
				result = active_scheduler_->ingest_synchronous(stage.facts->stage_instance_index,
									       occupied, stage.region_id,
									       scratch_->module, cached_turn_time_ns_);
			}
		} else {
			result.forwarded_mask = execute_passive();
		}
	} else {
		result.forwarded_mask = execute_passive();
	}
	for (uint16_t lane = 0u; lane < count; ++lane) {
		auto *record = occupied[lane];
		const uint64_t bit = UINT64_C(1) << lane;
		if ((result.forwarded_mask & bit) != 0u) {
			dispatch_stage_result_(record, stage, reserved_domain);
		} else if ((result.retained_mask & bit) != 0u) {
			release_local_reservation_(reserved_domain);
		} else {
			telemetry_->record_stage_drop(stage.telemetry_ordinal);
			release_record_(record, reserved_domain);
		}
		scratch_->module_records[lane] = nullptr;
	}
}

void packet_worker_kernel::implementation::dispatch_stage_result_(packet_record *record, stage_runtime &stage,
								  uint32_t reserved_domain) noexcept
{
	if (stage.logical->kind == provider::compiled_stage_kind::TX) {
		flush_context_selection_();
		deliver_tx_(record, stage, reserved_domain);
		return;
	}
	if (record->metadata.module_next_stage != KINETUM_NEXT_STAGE_UNSET) {
		const uint16_t logical_target = record->metadata.module_next_stage;
		if (logical_target >= stage.group_by_logical_stage.size() ||
		    stage.group_by_logical_stage[logical_target] == INVALID_RUNTIME_ORDINAL) {
			telemetry_->record_stage_drop(stage.telemetry_ordinal);
			release_record_(record, reserved_domain);
			return;
		}
		dispatch_one_group_(record, stage, stage.group_by_logical_stage[logical_target], reserved_domain);
		return;
	}

	switch (stage.facts->dispatch_mode) {
	case provider::compiled_stage_dispatch_mode::TERMINAL:
		telemetry_->record_stage_drop(stage.telemetry_ordinal);
		release_record_(record, reserved_domain);
		break;
	case provider::compiled_stage_dispatch_mode::UNCONDITIONAL_FANOUT:
		dispatch_fanout_(record, stage, reserved_domain);
		break;
	case provider::compiled_stage_dispatch_mode::PRIORITY_ROUTE:
		for (const auto &route : stage.priority_routes) {
			if (evaluate_condition(route.condition, &record->metadata)) {
				if (route.pull_target_ordinal != INVALID_RUNTIME_ORDINAL) {
					flush_context_selection_();
					dispatch_one_target_(record, stage, route.pull_target_ordinal, reserved_domain);
				} else {
					dispatch_one_group_(record, stage, route.group_ordinal, reserved_domain);
				}
				return;
			}
		}
		telemetry_->record_stage_drop(stage.telemetry_ordinal);
		release_record_(record, reserved_domain);
		break;
	}
}

void packet_worker_kernel::implementation::dispatch_one_group_(packet_record *record, stage_runtime &stage,
							       uint32_t group_ordinal,
							       uint32_t reserved_domain) noexcept
{
	if (group_ordinal >= stage.groups.size()) {
		std::terminate();
	}
	auto &group = stage.groups[group_ordinal];
	if (group.select_contexts == nullptr) {
		flush_context_selection_();
		dispatch_one_target_(record, stage, group.direct_target_ordinal, reserved_domain);
		return;
	}
	if (scratch_->pending_count != 0u && (scratch_->pending_stage != &stage || scratch_->pending_group != &group ||
					      scratch_->pending_domain != reserved_domain ||
					      scratch_->pending_records[0]->metadata.epoch != record->metadata.epoch)) {
		flush_context_selection_();
	}
	if (scratch_->pending_count == 0u) {
		scratch_->pending_stage = &stage;
		scratch_->pending_group = &group;
		scratch_->pending_domain = reserved_domain;
	}
	scratch_->pending_records[scratch_->pending_count++] = record;
	if (scratch_->pending_count == MAX_BURST) {
		flush_context_selection_();
	}
}

void packet_worker_kernel::implementation::flush_context_selection_() noexcept
{
	const uint16_t count = scratch_->pending_count;
	if (count == 0u) {
		return;
	}
	auto &stage = *scratch_->pending_stage;
	const auto &group = *scratch_->pending_group;
	auto &batch = scratch_->selection;
	const uint32_t domain = scratch_->pending_domain;
	batch.count = count;
	for (uint16_t lane = 0u; lane < count; ++lane) {
		const auto &metadata = scratch_->pending_records[lane]->metadata;
		batch.src_ip[lane] = metadata.src_ipv4;
		batch.dst_ip[lane] = metadata.dst_ipv4;
		batch.src_port[lane] = metadata.src_port;
		batch.dst_port[lane] = metadata.dst_port;
		batch.proto[lane] = metadata.l4_proto;
		batch.input_port[lane] = metadata.ingress_port;
		batch.platform_flags[lane] = metadata.platform_flags;
		batch.flow_hash[lane] = metadata.flow_hash;
		scratch_->selected_contexts[lane] = INVALID_RUNTIME_ORDINAL;
	}
	kinetum_context_selection_targets targets{
		.context_count = group.context_count,
		.permitted_count = static_cast<uint32_t>(group.permitted_ordinals.size()),
		.permitted_ordinals = group.permitted_ordinals.data(),
		.permitted_bitmap = group.permitted_bitmap.data(),
	};
	const uint64_t selected = group.select_contexts(&batch, &targets, scratch_->selected_contexts.data());
	const uint64_t occupied = count == KINETUM_MAX_BURST ? UINT64_MAX : (UINT64_C(1) << count) - 1u;
	if ((selected & ~occupied) != 0u || batch.count != count ||
	    std::any_of(std::begin(batch.padding), std::end(batch.padding),
			[](uint8_t value) { return value != 0u; }) ||
	    targets.context_count != group.context_count ||
	    targets.permitted_count != group.permitted_ordinals.size() ||
	    targets.permitted_ordinals != group.permitted_ordinals.data() ||
	    targets.permitted_bitmap != group.permitted_bitmap.data()) {
		std::terminate();
	}
	for (uint16_t lane = 0u; lane < count; ++lane) {
		const auto &metadata = scratch_->pending_records[lane]->metadata;
		const uint32_t context = scratch_->selected_contexts[lane];
		if (batch.src_ip[lane] != metadata.src_ipv4 || batch.dst_ip[lane] != metadata.dst_ipv4 ||
		    batch.src_port[lane] != metadata.src_port || batch.dst_port[lane] != metadata.dst_port ||
		    batch.proto[lane] != metadata.l4_proto || batch.input_port[lane] != metadata.ingress_port ||
		    batch.platform_flags[lane] != metadata.platform_flags ||
		    batch.flow_hash[lane] != metadata.flow_hash ||
		    ((selected & (UINT64_C(1) << lane)) != 0u &&
		     (context >= group.target_by_context_ordinal.size() ||
		      group.target_by_context_ordinal[context] == INVALID_RUNTIME_ORDINAL))) {
			std::terminate();
		}
	}
	// All foreign output is admitted before any packet leaves this prefix.
	scratch_->pending_count = 0u;
	scratch_->pending_stage = nullptr;
	scratch_->pending_group = nullptr;
	scratch_->pending_domain = provider::INVALID_COMPILED_PROVIDER_INDEX;
	for (uint16_t lane = 0u; lane < count; ++lane) {
		auto *record = scratch_->pending_records[lane];
		scratch_->pending_records[lane] = nullptr;
		if ((selected & (UINT64_C(1) << lane)) != 0u) {
			dispatch_one_target_(record, stage,
					     group.target_by_context_ordinal[scratch_->selected_contexts[lane]],
					     domain);
		} else {
			telemetry_->record_stage_drop(stage.telemetry_ordinal);
			release_record_(record, domain);
		}
	}
}

void packet_worker_kernel::implementation::dispatch_one_target_(packet_record *record, stage_runtime &stage,
								uint32_t target_ordinal,
								uint32_t reserved_domain) noexcept
{
	if (target_ordinal >= stage.targets.size()) {
		std::terminate();
	}
	telemetry_->record_stage_output(stage.telemetry_ordinal, record->storage.length);
	stamp_route_(*record, stage.targets[target_ordinal]);
	deliver_stage_(record, stage, reserved_domain);
}

void packet_worker_kernel::implementation::dispatch_fanout_(packet_record *record, stage_runtime &stage,
							    uint32_t reserved_domain) noexcept
{
	const std::size_t target_count = stage.fanout_group_ordinals.size();
	if (target_count == 0 || target_count - 1u > fanout_clones_.size()) {
		std::terminate();
	}
	const auto *operations = record->storage.operations;
	for (std::size_t index = 1; index < target_count; ++index) {
		fanout_clones_[index - 1u] = nullptr;
		if (!reserve_local_slot_(reserved_domain)) {
			telemetry_->record_fanout_overflow();
			continue;
		}
		auto *clone = operations != nullptr && operations->clone_writable != nullptr ?
				      operations->clone_writable(operations->state, record) :
				      nullptr;
		if (clone == nullptr) {
			release_local_reservation_(reserved_domain);
			telemetry_->record_fanout_overflow();
			continue;
		}
		if (clone == record || !validate_record_(clone, reserved_domain) ||
		    std::memcmp(&clone->metadata, &record->metadata, sizeof(packet_private)) != 0) {
			std::terminate();
		}
		epoch_ledger_->acquire(clone->metadata.epoch);
		fanout_clones_[index - 1u] = clone;
	}

	dispatch_one_group_(record, stage, stage.fanout_group_ordinals[0], reserved_domain);
	for (std::size_t index = 1; index < target_count; ++index) {
		auto *clone = fanout_clones_[index - 1u];
		if (clone != nullptr) {
			dispatch_one_group_(clone, stage, stage.fanout_group_ordinals[index], reserved_domain);
			fanout_clones_[index - 1u] = nullptr;
		}
	}
}

packet_worker_kernel::implementation::~implementation() noexcept
{
	if ((run_started_ && !run_finished_) || (run_finished_ && !outbound_closed_) || !local_work_empty_() ||
	    (epoch_ledger_ != nullptr && !epoch_ledger_->empty()) || module_telemetry_remaining_ != 0u ||
	    telemetry_cadence_returns_expected_ != 0u || module_telemetry_sweep_queued_ ||
	    telemetry_return_poll_requested_ || telemetry_ == nullptr || telemetry_->active_epoch() != 0u ||
	    (epoch_activation_ != nullptr && (module_telemetry_.empty() != (module_health_ == nullptr))) ||
	    std::any_of(module_telemetry_.begin(), module_telemetry_.end(),
			[](const auto *owner) { return owner == nullptr || owner->telemetry_active_epoch() != 0u; })) {
		std::terminate();
	}
	if (scratch_ != nullptr) {
		std::destroy_at(scratch_);
	}
}

void packet_worker_kernel::implementation::deliver_rx_(packet_record *record, stage_runtime &stage,
						       uint32_t reserved_domain) noexcept
{
	if (stage.rx_stream_index >= rx_streams_.size()) {
		std::terminate();
	}
	const auto &stream = rx_streams_[stage.rx_stream_index];
	if (!stream.owned || stream.stage_instance_index != stage.facts->stage_instance_index ||
	    stream.storage_domain_index != reserved_domain) {
		std::terminate();
	}
	if (stream.transition_index != provider::INVALID_COMPILED_PROVIDER_INDEX) {
		(void)queue_transition_(stream.transition_index, record, reserved_domain);
		return;
	}
	execute_stage_(record, stage, reserved_domain);
}

void packet_worker_kernel::implementation::deliver_stage_(packet_record *record, stage_runtime &stage,
							  uint32_t reserved_domain) noexcept
{
	const uint16_t destination_index = record->metadata.next_stage_instance;
	if (destination_index >= stage.target_by_stage_instance.size()) {
		std::terminate();
	}
	const uint32_t target_ordinal = stage.target_by_stage_instance[destination_index];
	if (target_ordinal == INVALID_RUNTIME_ORDINAL || target_ordinal >= stage.targets.size()) {
		std::terminate();
	}
	const auto &target = stage.targets[target_ordinal];
	if (reserved_domain >= target.transition_by_storage_domain.size()) {
		std::terminate();
	}
	const uint32_t transition_index = target.transition_by_storage_domain[reserved_domain];
	if (transition_index != provider::INVALID_COMPILED_PROVIDER_INDEX) {
		(void)queue_transition_(transition_index, record, reserved_domain);
		return;
	}
	if (target.sender_ordinal != INVALID_RUNTIME_ORDINAL) {
		send_boundary_(record, stage, reserved_domain);
		return;
	}
	if (target.stage_instance_index >= stages_.size() || !stages_[target.stage_instance_index].owned ||
	    !stages_[target.stage_instance_index].reachable_storage_domains.contains(reserved_domain)) {
		std::terminate();
	}
	promote_next_stage_(*record);
	commit_local_reservation_(reserved_domain, {record, packet_work_phase::EXECUTE, {}});
}

void packet_worker_kernel::implementation::send_boundary_(packet_record *record, stage_runtime &stage,
							  uint32_t reserved_domain) noexcept
{
	const uint16_t destination_index = record->metadata.next_stage_instance;
	if (destination_index >= stage.target_by_stage_instance.size()) {
		std::terminate();
	}
	const uint32_t target_ordinal = stage.target_by_stage_instance[destination_index];
	if (target_ordinal == INVALID_RUNTIME_ORDINAL || target_ordinal >= stage.targets.size()) {
		std::terminate();
	}
	const auto &target = stage.targets[target_ordinal];
	if (KINETUM_UNLIKELY(boundary_sender_ == nullptr || target.sender_ordinal == INVALID_RUNTIME_ORDINAL)) {
		std::terminate();
	}
	switch (boundary_sender_->try_send(target.sender_ordinal, record)) {
	case boundary_epoch_send_result::TRANSFERRED:
	case boundary_epoch_send_result::HELD:
		// DATA/channel ownership retires the worker credit; held ownership keeps
		// it until release. Both outcomes retire this unpublished local slot.
		release_local_reservation_(reserved_domain);
		return;
	case boundary_epoch_send_result::BACKPRESSURED:
		commit_local_reservation_(reserved_domain, {record, packet_work_phase::BOUNDARY_SEND, {}});
		return;
	}
	std::terminate();
}

void packet_worker_kernel::implementation::deliver_tx_(packet_record *record, stage_runtime &stage,
						       uint32_t reserved_domain) noexcept
{
	auto *stream = resolve_tx_stream_(*record, stage);
	if (stream == nullptr) {
		telemetry_->record_stage_drop(stage.telemetry_ordinal);
		release_record_(record, reserved_domain);
		return;
	}
	if (stream->stage_instance_index == stage.facts->stage_instance_index &&
	    reserved_domain < stream->transition_by_storage_domain.size()) {
		const uint32_t transition_index = stream->transition_by_storage_domain[reserved_domain];
		if (transition_index != provider::INVALID_COMPILED_PROVIDER_INDEX) {
			// An authored edge conversion executes even when TX also admits the
			// original domain. Admission never overrides explicit graph intent.
			(void)queue_transition_(transition_index, record, reserved_domain);
			return;
		}
	}
	if (stream->accepted_storage_domains.contains(reserved_domain)) {
		queue_tx_(*stream, record, reserved_domain);
		return;
	}
	telemetry_->record_stage_drop(stage.telemetry_ordinal);
	release_record_(record, reserved_domain);
}

packet_worker_kernel::implementation::tx_stream_runtime *
packet_worker_kernel::implementation::resolve_tx_stream_(const packet_record &record,
							 const stage_runtime &stage) noexcept
{
	uint32_t stream_index = provider::INVALID_COMPILED_PROVIDER_INDEX;
	if (record.metadata.egress_port == KINETUM_PORT_UNSET) {
		stream_index = stage.stage_bound_tx_stream_index;
	} else if (record.metadata.egress_port != KINETUM_PORT_DROP &&
		   record.metadata.egress_port < schedule_->tx_stream_index_by_logical_port.size()) {
		stream_index = schedule_->tx_stream_index_by_logical_port[record.metadata.egress_port];
	}
	if (stream_index >= tx_streams_.size() || !tx_streams_[stream_index].owned) {
		return nullptr;
	}
	return &tx_streams_[stream_index];
}

bool packet_worker_kernel::implementation::queue_transition_(uint32_t transition_index, packet_record *record,
							     uint32_t reserved_domain) noexcept
{
	if (transition_index >= transition_batches_.size()) {
		std::terminate();
	}
	auto &batch = transition_batches_[transition_index];
	if (!batch.owned || !batch.configured || batch.facts == nullptr || batch.operations == nullptr ||
	    reserved_domain != batch.facts->from_storage_domain_index || !validate_record_(record, reserved_domain)) {
		std::terminate();
	}
	if (batch.count == MAX_BURST) {
		flush_transition_(batch);
	}
	if (batch.count >= MAX_BURST) {
		std::terminate();
	}
	const uint32_t destination_domain = batch.facts->to_storage_domain_index;
	if (destination_domain != reserved_domain && !reserve_local_slot_(destination_domain)) {
		commit_local_reservation_(reserved_domain, {record, batch.retry_phase, {}});
		return false;
	}
	const uint16_t index = batch.count;
	batch.sources[index] = record;
	batch.destinations[index] = nullptr;
	batch.metadata[index] = record->metadata;
	++batch.count;
	if (batch.count == MAX_BURST) {
		flush_transition_(batch);
	}
	return true;
}

void packet_worker_kernel::implementation::flush_transition_(transition_batch &batch) noexcept
{
	if (batch.count == 0) {
		return;
	}
	if (!batch.owned || !batch.configured || batch.facts == nullptr || batch.operations == nullptr) {
		std::terminate();
	}
	const uint16_t attempted = batch.count;
	const uint32_t source_domain = batch.facts->from_storage_domain_index;
	const uint32_t destination_domain = batch.facts->to_storage_domain_index;
	const uint16_t accepted = batch.operations->transfer_burst(batch.operations->state, batch.sources.data(),
								   batch.destinations.data(), attempted);
	if (accepted > attempted) {
		std::terminate();
	}

	for (uint16_t index = 0; index < accepted; ++index) {
		auto *destination = batch.destinations[index];
		if (!validate_record_(destination, destination_domain) ||
		    std::memcmp(&destination->metadata, &batch.metadata[index], sizeof(packet_private)) != 0) {
			std::terminate();
		}
		if ((batch.operations->mode == KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE &&
		     destination != batch.sources[index]) ||
		    (batch.operations->mode == KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY &&
		     destination == batch.sources[index])) {
			std::terminate();
		}
	}
	for (uint16_t index = accepted; index < attempted; ++index) {
		if (batch.destinations[index] != nullptr || !validate_record_(batch.sources[index], source_domain) ||
		    std::memcmp(&batch.sources[index]->metadata, &batch.metadata[index], sizeof(packet_private)) != 0) {
			std::terminate();
		}
	}

	for (uint16_t index = 0; index < accepted; ++index) {
		auto *destination = batch.destinations[index];
		if (destination_domain != source_domain) {
			release_local_reservation_(source_domain);
		}
		switch (batch.post_action) {
		case transition_post_action::RX_EXECUTE:
			commit_local_reservation_(destination_domain, {destination, packet_work_phase::EXECUTE, {}});
			break;
		case transition_post_action::LOCAL_EXECUTE:
			promote_next_stage_(*destination);
			commit_local_reservation_(destination_domain, {destination, packet_work_phase::EXECUTE, {}});
			break;
		case transition_post_action::BOUNDARY_SEND:
			commit_local_reservation_(destination_domain,
						  {destination, packet_work_phase::BOUNDARY_SEND, {}});
			break;
		case transition_post_action::TX_SUBMIT: {
			if (batch.facts->to_endpoint.kind != provider::compiled_packet_path_endpoint_kind::IO_STREAM ||
			    batch.facts->to_endpoint.endpoint_index >= tx_streams_.size()) {
				std::terminate();
			}
			auto &stream = tx_streams_[batch.facts->to_endpoint.endpoint_index];
			if (!stream.owned) {
				std::terminate();
			}
			queue_tx_(stream, destination, destination_domain);
			break;
		}
		}
	}
	for (uint16_t index = accepted; index < attempted; ++index) {
		if (destination_domain != source_domain) {
			release_local_reservation_(destination_domain);
		}
		commit_local_reservation_(source_domain, {batch.sources[index], batch.retry_phase, {}});
	}
	for (uint16_t index = 0; index < attempted; ++index) {
		batch.sources[index] = nullptr;
		batch.destinations[index] = nullptr;
		batch.metadata[index] = {};
	}
	batch.count = 0;
}

void packet_worker_kernel::implementation::flush_transitions_() noexcept
{
	for (auto *batch : transition_flush_schedule_) {
		if (batch == nullptr) {
			std::terminate();
		}
		flush_transition_(*batch);
	}
}

void packet_worker_kernel::implementation::queue_tx_(tx_stream_runtime &stream, packet_record *record,
						     uint32_t reserved_domain) noexcept
{
	if (!stream.owned || stream.facts == nullptr || stream.operations == nullptr ||
	    !stream.accepted_storage_domains.contains(reserved_domain) || !validate_record_(record, reserved_domain) ||
	    stream.facts->io_stream_index >= tx_batches_.size()) {
		std::terminate();
	}
	auto &batch = tx_batches_[stream.facts->io_stream_index];
	if (!batch.owned || batch.stream != &stream) {
		std::terminate();
	}
	if (batch.count == stream.operations->maximum_burst || batch.count == MAX_BURST) {
		flush_tx_(batch);
	}
	if (batch.count >= stream.operations->maximum_burst || batch.count >= MAX_BURST) {
		std::terminate();
	}
	const uint16_t index = batch.count;
	batch.records[index] = record;
	batch.metadata[index] = record->metadata;
	batch.lengths[index] = record->storage.length;
	batch.storage_domains[index] = record->storage.domain_index;
	++batch.count;
	if (batch.count == stream.operations->maximum_burst || batch.count == MAX_BURST) {
		flush_tx_(batch);
	}
}

void packet_worker_kernel::implementation::flush_tx_(tx_batch &batch) noexcept
{
	if (batch.count == 0) {
		return;
	}
	if (!batch.owned || batch.stream == nullptr || batch.stream->operations == nullptr) {
		std::terminate();
	}
	const auto *operations = batch.stream->operations;
	if (batch.stream->stage_instance_index >= stages_.size() ||
	    !stages_[batch.stream->stage_instance_index].owned) {
		std::terminate();
	}
	const uint16_t attempted = batch.count;
	const uint16_t accepted = operations->transmit_burst(operations->state, batch.records.data(), attempted);
	if (accepted > attempted) {
		std::terminate();
	}
	for (uint16_t index = accepted; index < attempted; ++index) {
		if (!validate_record_(batch.records[index], batch.storage_domains[index]) ||
		    batch.records[index]->storage.length != batch.lengths[index] ||
		    std::memcmp(&batch.records[index]->metadata, &batch.metadata[index], sizeof(packet_private)) != 0) {
			std::terminate();
		}
	}
	uint64_t accepted_bytes = 0u;
	for (uint16_t index = 0; index < accepted; ++index) {
		const uint32_t stage_ordinal = stages_[batch.metadata[index].current_stage_instance].telemetry_ordinal;
		epoch_ledger_->retire(batch.metadata[index].epoch);
		release_local_reservation_(batch.storage_domains[index]);
		telemetry_->record_stage_output(stage_ordinal, batch.lengths[index]);
		accepted_bytes += batch.lengths[index];
	}
	for (uint16_t index = accepted; index < attempted; ++index) {
		const uint32_t stage_ordinal = stages_[batch.metadata[index].current_stage_instance].telemetry_ordinal;
		telemetry_->record_stage_drop(stage_ordinal);
		release_record_(batch.records[index], batch.storage_domains[index]);
	}
	telemetry_->record_stream(batch.stream->telemetry_ordinal, accepted, accepted_bytes,
				  static_cast<uint16_t>(attempted - accepted));
	for (uint16_t index = 0; index < attempted; ++index) {
		batch.records[index] = nullptr;
		batch.metadata[index] = {};
		batch.lengths[index] = 0u;
		batch.storage_domains[index] = 0u;
	}
	batch.count = 0;
}

void packet_worker_kernel::implementation::flush_tx_batches_() noexcept
{
	for (auto *stream : tx_flush_schedule_) {
		if (stream == nullptr || stream->facts == nullptr ||
		    stream->facts->io_stream_index >= tx_batches_.size()) {
			std::terminate();
		}
		flush_tx_(tx_batches_[stream->facts->io_stream_index]);
	}
}

void packet_worker_kernel::implementation::maybe_flush_tx_() noexcept
{
	for (auto *stream : tx_flush_schedule_) {
		if (stream == nullptr || stream->operations == nullptr) {
			std::terminate();
		}
		const uint8_t requested = stream->operations->maybe_flush(stream->operations->state);
		if (requested > UINT8_C(1)) {
			std::terminate();
		}
		if (requested != 0) {
			stream->operations->flush(stream->operations->state);
		}
	}
}

void packet_worker_kernel::implementation::final_flush_tx_() noexcept
{
	flush_tx_batches_();
	flush_releases_();
	for (auto *stream : tx_flush_schedule_) {
		if (stream == nullptr || stream->operations == nullptr) {
			std::terminate();
		}
		stream->operations->flush(stream->operations->state);
	}
}

void packet_worker_kernel::implementation::release_record_(packet_record *record, uint32_t reserved_domain) noexcept
{
	if (!validate_record_(record, reserved_domain) || reserved_domain >= release_batches_.size()) {
		std::terminate();
	}
	auto &batch = release_batches_[reserved_domain];
	if (batch.operations == nullptr || batch.operations != record->storage.operations) {
		std::terminate();
	}
	if (batch.count == MAX_BURST) {
		flush_release_(batch);
	}
	if (batch.count >= MAX_BURST) {
		std::terminate();
	}
	epoch_ledger_->retire(record->metadata.epoch);
	batch.records[batch.count++] = record;
	telemetry_->record_drop();
	if (batch.count == MAX_BURST) {
		flush_release_(batch);
	}
}

void packet_worker_kernel::implementation::flush_release_(release_batch &batch) noexcept
{
	if (batch.count == 0) {
		return;
	}
	if (batch.operations == nullptr) {
		std::terminate();
	}
	const uint32_t domain = batch.operations->domain_index;
	const uint16_t count = batch.count;
	for (uint16_t index = 0; index < count; ++index) {
		if (!validate_record_(batch.records[index], domain)) {
			std::terminate();
		}
	}
	batch.operations->release_burst(batch.operations->state, batch.records.data(), count);
	for (uint16_t index = 0; index < count; ++index) {
		release_local_reservation_(domain);
		batch.records[index] = nullptr;
	}
	batch.count = 0;
}

void packet_worker_kernel::implementation::flush_releases_() noexcept
{
	for (auto *batch : release_flush_schedule_) {
		if (batch == nullptr) {
			std::terminate();
		}
		flush_release_(*batch);
	}
}

void packet_worker_kernel::implementation::promote_next_stage_(packet_record &record) const noexcept
{
	if (record.metadata.next_stage == INVALID_STAGE_ID || record.metadata.next_stage_instance == INVALID_STAGE_ID) {
		std::terminate();
	}
	record.metadata.current_stage = record.metadata.next_stage;
	record.metadata.current_stage_instance = record.metadata.next_stage_instance;
	record.metadata.next_stage = INVALID_STAGE_ID;
	record.metadata.next_stage_instance = INVALID_STAGE_ID;
	record.metadata.module_next_stage = INVALID_STAGE_ID;
}

void packet_worker_kernel::implementation::stamp_route_(packet_record &record,
							const route_target &target) const noexcept
{
	if (target.stage_instance_index > std::numeric_limits<uint16_t>::max()) {
		std::terminate();
	}
	record.metadata.next_stage = target.logical_stage_index;
	record.metadata.next_stage_instance = static_cast<uint16_t>(target.stage_instance_index);
	record.metadata.module_next_stage = INVALID_STAGE_ID;
}

bool packet_worker_kernel::implementation::local_work_empty_() const noexcept
{
	if (scratch_ != nullptr && scratch_->pending_count != 0u) {
		return false;
	}
	if (module_health_ != nullptr && !module_health_->quiescent()) {
		return false;
	}
	if (active_scheduler_ != nullptr && !active_scheduler_->empty()) {
		return false;
	}
	for (const auto &entry : local_queue_schedule_) {
		if (entry.staging == nullptr) {
			std::terminate();
		}
		if (!entry.staging->empty()) {
			return false;
		}
	}
	if (boundary_sender_ != nullptr && !boundary_sender_->packet_ownership_empty()) {
		return false;
	}
	for (const auto *batch : transition_flush_schedule_) {
		if (batch == nullptr) {
			std::terminate();
		}
		if (batch->count != 0) {
			return false;
		}
	}
	for (const auto *stream : tx_flush_schedule_) {
		if (stream == nullptr || stream->facts == nullptr ||
		    stream->facts->io_stream_index >= tx_batches_.size()) {
			std::terminate();
		}
		if (tx_batches_[stream->facts->io_stream_index].count != 0) {
			return false;
		}
	}
	for (const auto *batch : release_flush_schedule_) {
		if (batch == nullptr) {
			std::terminate();
		}
		if (batch->count != 0) {
			return false;
		}
	}
	for (const auto *record : fanout_clones_) {
		if (record != nullptr) {
			return false;
		}
	}
	return true;
}

bool packet_worker_kernel::implementation::inbound_closed_and_empty_() const noexcept
{
	for (const auto *boundary : inbound_boundaries_) {
		if (boundary == nullptr || !boundary->sender_closed() || !boundary->empty()) {
			return false;
		}
	}
	return true;
}

void packet_worker_kernel::implementation::publish_boundary_transport_() noexcept
{
	if (KINETUM_UNLIKELY(boundary_sender_ == nullptr)) {
		std::terminate();
	}
	boundary_sender_->publish_transport();
	for (auto *boundary : inbound_boundaries_) {
		if (KINETUM_UNLIKELY(boundary == nullptr)) {
			std::terminate();
		}
		boundary->publish_receiver_transport();
	}
}

void packet_worker_kernel::implementation::service_telemetry_returns_() noexcept
{
	if (telemetry_ == nullptr) {
		std::terminate();
	}
	runtime_telemetry_bank_token token{};
	for (std::size_t count = 0u; count < MAX_BURST && telemetry_->take_returned(token); ++count) {
		if (token.reason == runtime_telemetry_publication_reason::CADENCE) {
			if (telemetry_cadence_returns_expected_ == 0u) {
				std::terminate();
			}
			--telemetry_cadence_returns_expected_;
		} else if (token.reason != runtime_telemetry_publication_reason::RECLAIMED) {
			std::terminate();
		}
		if (token.owner_kind == runtime_telemetry_bank_owner_kind::WORKER) {
			telemetry_->accept_returned(token);
			continue;
		}
		if (token.owner_kind != runtime_telemetry_bank_owner_kind::MODULE ||
		    token.owner_index >= module_telemetry_by_context_.size() ||
		    module_telemetry_by_context_[token.owner_index] == nullptr) {
			std::terminate();
		}
		module_telemetry_by_context_[token.owner_index]->accept_returned_telemetry(token);
	}
	telemetry_return_poll_requested_ = telemetry_->returned_tokens_pending();
}

void packet_worker_kernel::implementation::record_telemetry_return_need_(runtime_telemetry_return_need need) noexcept
{
	switch (need) {
	case runtime_telemetry_return_need::NONE:
		return;
	case runtime_telemetry_return_need::EXPECTED:
		if (telemetry_cadence_returns_expected_ == std::numeric_limits<std::size_t>::max()) {
			std::terminate();
		}
		++telemetry_cadence_returns_expected_;
		return;
	case runtime_telemetry_return_need::POLL_REQUIRED:
		telemetry_return_poll_requested_ = true;
		return;
	}
	std::terminate();
}

void packet_worker_kernel::implementation::record_protocol_fault_(epoch_protocol_fault_code code,
								  epoch_protocol_fault_disposition disposition,
								  uint32_t boundary_index, uint32_t context_index,
								  uint32_t stage_instance_index,
								  uint64_t observed_epoch, uint64_t expected_value,
								  uint64_t observed_value) noexcept
{
	if (telemetry_ == nullptr || protocol_faults_ == nullptr || !valid_epoch_protocol_fault_code(code)) {
		std::terminate();
	}
	telemetry_->record_protocol_fault(code);
	const bool transition_active = boundary_receiver_ != nullptr && boundary_receiver_->transition_active();
	(void)protocol_faults_->record(epoch_protocol_first_fault{
		.runtime_generation = providers_.runtime_generation(),
		.transition_generation = transition_active ? boundary_receiver_->transition_generation() : 0u,
		.from_epoch = transition_active ? boundary_receiver_->transition_from_epoch() : 0u,
		.to_epoch = transition_active ? boundary_receiver_->transition_to_epoch() : 0u,
		.observed_epoch = observed_epoch,
		.expected_value = expected_value,
		.observed_value = observed_value,
		.observed_monotonic_ns = common::cached_ns(),
		.worker_index = worker_index_,
		.boundary_index = boundary_index,
		.context_index = context_index,
		.stage_instance_index = stage_instance_index,
		.code = code,
		.disposition = disposition,
		.padding = {},
	});
}

void packet_worker_kernel::implementation::schedule_module_telemetry_sweep_() noexcept
{
	if (module_telemetry_.empty()) {
		return;
	}
	if (module_telemetry_remaining_ == 0u) {
		module_telemetry_remaining_ = module_telemetry_.size();
		return;
	}
	if (!module_telemetry_sweep_queued_) {
		module_telemetry_sweep_queued_ = true;
		return;
	}
	telemetry_->record_publication_skip();
}

void packet_worker_kernel::implementation::close_outbound_boundaries_() noexcept
{
	if (outbound_closed_ || boundary_sender_ == nullptr) {
		std::terminate();
	}
	boundary_sender_->close_for_shutdown();
	outbound_closed_ = true;
}

uint32_t packet_worker_kernel::implementation::emit_active_origins_(void *state, uint32_t stage_instance_index,
								    uint64_t epoch, uint64_t now_ns,
								    const kinetum_emit_batch_t *batch, uint32_t budget,
								    std::span<packet_origin_view> origin_scratch,
								    std::span<packet_record *> record_scratch) noexcept
{
	auto *owner = static_cast<implementation *>(state);
	if (owner == nullptr || owner->epoch_ledger_ == nullptr || stage_instance_index >= owner->stages_.size() ||
	    epoch != owner->epoch_ledger_->active_epoch() || epoch != owner->epoch_ledger_->source_epoch() ||
	    now_ns != owner->cached_turn_time_ns_ || origin_scratch.size() < MAX_BURST ||
	    record_scratch.size() < MAX_BURST) {
		std::terminate();
	}
	if (batch == nullptr || batch->count == 0u || batch->count > KINETUM_MAX_BURST || budget == 0u) {
		return 0u;
	}
	auto &stage = owner->stages_[stage_instance_index];
	if (!stage.owned || stage.facts == nullptr || stage.logical == nullptr ||
	    stage.logical->execution_mode != provider::compiled_stage_execution_mode::ACTIVE ||
	    !stage.facts->active_origin_storage_domain_index.has_value()) {
		std::terminate();
	}
	const uint32_t domain = *stage.facts->active_origin_storage_domain_index;
	auto *staging = owner->local_staging_(domain);
	if (staging == nullptr || domain >= owner->release_batches_.size()) {
		std::terminate();
	}
	const auto *operations = owner->release_batches_[domain].operations;
	if (!kinetum_provider_packet_storage_operations_are_valid(operations) || operations->domain_index != domain ||
	    operations->generation != owner->providers_.runtime_generation()) {
		std::terminate();
	}
	if (!validate_active_origin_batch(batch, operations->maximum_packet_length,
					  owner->topology_.logical_stages.size())) {
		return 0u;
	}
	const std::size_t requested =
		std::min<std::size_t>({static_cast<std::size_t>(batch->count), static_cast<std::size_t>(budget),
				       MAX_BURST, staging->active_available()});
	if (requested == 0u) {
		return 0u;
	}
	for (std::size_t index = 0u; index < requested; ++index) {
		if (!staging->reserve_active()) {
			std::terminate();
		}
		origin_scratch[index] = packet_origin_view{
			.data = static_cast<const uint8_t *>(batch->data[index]),
			.length = batch->len[index],
			.padding = 0u,
		};
		record_scratch[index] = nullptr;
	}
	const uint16_t accepted = operations->copy_origins_burst(
		operations->state, origin_scratch.data(), record_scratch.data(), static_cast<uint16_t>(requested));
	for (std::size_t index = 0u; index < requested; ++index) {
		origin_scratch[index] = {};
	}
	if (accepted > requested) {
		std::terminate();
	}
	for (uint16_t index = 0u; index < accepted; ++index) {
		auto *record = record_scratch[index];
		if (!owner->validate_record_(record, domain) || record->storage.length != batch->len[index]) {
			std::terminate();
		}
		initialize_packet_record(*record);
		auto &metadata = record->metadata;
		metadata.timestamp_ns = batch->ts_ns[index] == 0u ? now_ns : batch->ts_ns[index];
		metadata.epoch = epoch;
		metadata.user_meta = batch->user_meta[index];
		metadata.flow_hash = batch->flow_hash[index];
		metadata.platform_flags = batch->platform_flags[index];
		metadata.user_flags = batch->user_flags[index];
		metadata.ingress_port = batch->input_port[index];
		metadata.egress_port = batch->output_port[index];
		metadata.module_next_stage = batch->next_stage[index];
		metadata.user_meta_valid = batch->user_meta_valid[index] != 0u ? 1u : 0u;
		metadata.src_ipv4 = batch->src_ip[index];
		metadata.dst_ipv4 = batch->dst_ip[index];
		metadata.src_port = batch->src_port[index];
		metadata.dst_port = batch->dst_port[index];
		metadata.ip_offset = batch->l3_off[index];
		metadata.l4_offset = batch->l4_off[index];
		metadata.l4_proto = batch->proto[index];
		metadata.dscp = batch->dscp[index];
		metadata.current_stage = stage.logical->logical_stage_index;
		metadata.current_stage_instance = static_cast<uint16_t>(stage_instance_index);
		owner->epoch_ledger_->acquire(epoch);
		owner->dispatch_stage_result_(record, stage, domain);
		record_scratch[index] = nullptr;
	}
	for (std::size_t index = accepted; index < requested; ++index) {
		if (record_scratch[index] != nullptr) {
			std::terminate();
		}
		staging->release_active_reservation();
	}
	return accepted;
}

bool packet_worker_kernel::implementation::publish_active_retained_(void *state, uint32_t stage_instance_index,
								    packet_record *record, uint16_t next_stage,
								    bool drop) noexcept
{
	auto *owner = static_cast<implementation *>(state);
	if (owner == nullptr || stage_instance_index >= owner->stages_.size() || record == nullptr) {
		std::terminate();
	}
	auto &stage = owner->stages_[stage_instance_index];
	const uint32_t domain = owner->record_storage_domain_(record);
	if (!stage.owned || stage.logical == nullptr || stage.facts == nullptr ||
	    stage.logical->execution_mode != provider::compiled_stage_execution_mode::ACTIVE ||
	    record->metadata.current_stage_instance != stage_instance_index ||
	    record->metadata.epoch != owner->epoch_ledger_->active_epoch() ||
	    domain == provider::INVALID_COMPILED_PROVIDER_INDEX ||
	    (!drop && next_stage != KINETUM_NEXT_STAGE_UNSET && next_stage >= owner->topology_.logical_stages.size())) {
		std::terminate();
	}
	if (drop) {
		if (!owner->reserve_local_slot_(domain)) {
			return false;
		}
		owner->telemetry_->record_stage_drop(stage.telemetry_ordinal);
		owner->release_record_(record, domain);
		return true;
	}
	if (!owner->reserve_local_slot_(domain)) {
		return false;
	}
	record->metadata.module_next_stage = next_stage;
	owner->dispatch_stage_result_(record, stage, domain);
	return true;
}

bool packet_worker_kernel::implementation::publish_active_recirculated_(void *state, uint32_t stage_instance_index,
									packet_record *record) noexcept
{
	auto *owner = static_cast<implementation *>(state);
	if (owner == nullptr || owner->epoch_ledger_ == nullptr || stage_instance_index >= owner->stages_.size() ||
	    record == nullptr) {
		std::terminate();
	}
	auto &stage = owner->stages_[stage_instance_index];
	const uint32_t domain = owner->record_storage_domain_(record);
	if (!stage.owned || stage.logical == nullptr || stage.facts == nullptr ||
	    stage.logical->execution_mode != provider::compiled_stage_execution_mode::ACTIVE ||
	    record->metadata.current_stage_instance != stage_instance_index ||
	    record->metadata.current_stage != stage.logical->logical_stage_index ||
	    record->metadata.epoch != owner->epoch_ledger_->active_epoch() ||
	    domain == provider::INVALID_COMPILED_PROVIDER_INDEX || !stage.reachable_storage_domains.contains(domain)) {
		std::terminate();
	}
	if (!owner->reserve_local_slot_(domain)) {
		return false;
	}
	record->metadata.next_stage = INVALID_STAGE_ID;
	record->metadata.next_stage_instance = INVALID_STAGE_ID;
	record->metadata.module_next_stage = INVALID_STAGE_ID;
	owner->telemetry_->record_stage_output(stage.telemetry_ordinal, record->storage.length);
	owner->commit_local_reservation_(domain, {record, packet_work_phase::EXECUTE, {}});
	return true;
}

KINETUM_ALWAYS_INLINE bool packet_worker_kernel::implementation::consume_runtime_command_() noexcept
{
	const auto *command = commands_->observe();
	if (KINETUM_LIKELY(command == observed_command_)) {
		return false;
	}
	return consume_changed_runtime_command_(command);
}

KINETUM_COLD KINETUM_NOINLINE bool packet_worker_kernel::implementation::consume_changed_runtime_command_(
	const worker_runtime_command_record *command) noexcept
{
	if (command == nullptr || !command->valid() || command->runtime_generation != providers_.runtime_generation()) {
		std::terminate();
	}
	switch (command->kind) {
	case worker_runtime_command_kind::RUN:
		// RUN is the immutable startup baseline and is never republished.
		std::terminate();
	case worker_runtime_command_kind::STOP:
		// Do not consume STOP into the pointer-equality fast state. Shutdown is
		// level-triggered: every later drain turn must continue suppressing RX
		// until the complete worker DAG is empty. Re-entering this cold branch is
		// shutdown-only and leaves fixed RUN execution unchanged.
		return true;
	case worker_runtime_command_kind::TRANSITION:
		break;
	}

	const bool activation_preflight = epoch_activation_->preflight_begin_transition(
		command->transition_generation, command->from_epoch, command->to_epoch);
	const bool sender_preflight = boundary_sender_->preflight_begin_transition(
		command->transition_generation, command->from_epoch, command->to_epoch);
	const bool receiver_preflight = boundary_receiver_->preflight_begin_transition(
		command->transition_generation, command->from_epoch, command->to_epoch);
	if (!activation_preflight || !sender_preflight || !receiver_preflight) {
		std::terminate();
	}

	epoch_ledger_->bind_future_epoch(command->to_epoch);
	if (!boundary_sender_->begin_transition(command->transition_generation, command->from_epoch,
						command->to_epoch) ||
	    !boundary_receiver_->begin_transition(command->transition_generation, command->from_epoch,
						  command->to_epoch) ||
	    (active_scheduler_ != nullptr &&
	     !active_scheduler_->begin_transition(command->transition_generation, command->from_epoch,
						  command->to_epoch))) {
		std::terminate();
	}
	epoch_ledger_->advance_source_epoch(command->to_epoch);
	// A prior generation may have returned one reclaimed target standby after
	// this worker's last cadence. Probe the exact return lane on the next rare
	// transition turn so rapid successive commits never depend on cadence time.
	telemetry_return_poll_requested_ = true;
	observed_command_ = command;
	return false;
}

void packet_worker_kernel::implementation::service_transition_after_packet_work_(uint64_t now_ns) noexcept
{
	if (boundary_sender_ == nullptr || boundary_receiver_ == nullptr || epoch_activation_ == nullptr ||
	    now_ns == 0u || !boundary_sender_->transition_active() || !boundary_receiver_->transition_active() ||
	    boundary_sender_->transition_generation() != boundary_receiver_->transition_generation() ||
	    boundary_sender_->transition_from_epoch() != boundary_receiver_->transition_from_epoch() ||
	    boundary_sender_->transition_to_epoch() != boundary_receiver_->transition_to_epoch()) {
		std::terminate();
	}

	boundary_receiver_->refresh_cut_progress();
	const bool receiver_activation_ready = boundary_receiver_->activation_ready();
	const bool active_scheduler_ready =
		active_scheduler_ == nullptr ||
		active_scheduler_->activation_ready(boundary_receiver_->transition_generation(),
						    boundary_receiver_->transition_from_epoch(),
						    boundary_receiver_->transition_to_epoch());
	if (!boundary_sender_->outbound_sealed()) {
		// Zero old credit is stable only after every inbound sequence cut is
		// drained. Sealing earlier could admit a late old inbound record after
		// this worker had already forbidden old outbound DATA.
		if (!receiver_activation_ready || !active_scheduler_ready) {
			return;
		}
		if (!boundary_sender_->try_seal_after_old_work_drained()) {
			std::terminate();
		}
	}
	if (boundary_sender_->all_cuts_published() && receiver_activation_ready && active_scheduler_ready) {
		const uint64_t generation = boundary_receiver_->transition_generation();
		const uint64_t from_epoch = boundary_receiver_->transition_from_epoch();
		const uint64_t to_epoch = boundary_receiver_->transition_to_epoch();
		const auto activated = epoch_activation_->activate(generation, from_epoch, to_epoch, now_ns);
		if (!activated.is_ok() || epoch_activation_->active_epoch() != to_epoch ||
		    epoch_activation_->last_transition_generation() != generation) {
			std::terminate();
		}
		boundary_receiver_->acknowledge_activation(generation, to_epoch);
		if (quiescence_reader_.publish_quiescent() == 0u) {
			std::terminate();
		}
	}
	(void)boundary_sender_->service_held_output(MAX_BURST);
	if (boundary_receiver_->all_acks_published() && boundary_sender_->all_gates_open() &&
	    boundary_sender_->packet_ownership_empty()) {
		const uint64_t generation = boundary_receiver_->transition_generation();
		boundary_receiver_->complete_receiver_transition(generation);
		boundary_sender_->complete_sender_transition(generation);
	}
}

template <bool has_active_scheduler, bool has_async_scheduler, typename poll_source_type>
void packet_worker_kernel::implementation::run_loop_(poll_source_type poll_source) noexcept
{
	static_assert(has_active_scheduler || !has_async_scheduler,
		      "tracked-async worker loops require the active scheduler");
	for (;;) {
		const bool stopping = consume_runtime_command_();
		if constexpr (has_active_scheduler) {
			if (active_scheduler_ == nullptr) {
				std::terminate();
			}
			if (stopping) {
				active_scheduler_->begin_shutdown();
			}
		}
		if (stopping || telemetry_cadence_returns_expected_ != 0u || telemetry_return_poll_requested_) {
			service_telemetry_returns_();
		}
		if (stopping) {
			module_telemetry_remaining_ = 0u;
			module_telemetry_sweep_queued_ = false;
		}
		uint64_t cached_time = 0u;
		if (KINETUM_LIKELY(module_telemetry_remaining_ == 0u)) {
			cached_time = refresh_turn_time_<has_active_scheduler>();
		} else {
			if (module_telemetry_.empty() || module_health_ == nullptr) {
				std::terminate();
			}
			if (module_telemetry_cursor_ >= module_telemetry_.size()) {
				module_telemetry_cursor_ = 0u;
			}
			const std::size_t context_ordinal = module_telemetry_cursor_++;
			auto *module_telemetry_owner = module_telemetry_[context_ordinal];
			if (module_telemetry_owner == nullptr) {
				std::terminate();
			}
			auto health_invocation = module_health_->begin(context_ordinal);
			cached_time = refresh_turn_time_<has_active_scheduler>();
			uint64_t publication_time = cached_time;
			if (health_invocation.has_value()) {
				health_invocation->invoke(cached_time);
				// This rare post-return sample measures health and may timestamp
				// only this context bank; cached_time remains the turn authority.
				publication_time = common::now_ns();
				health_invocation->complete(publication_time);
			}
			record_telemetry_return_need_(
				module_telemetry_owner->service_telemetry_cadence(publication_time));
			--module_telemetry_remaining_;
			if (module_telemetry_remaining_ == 0u && module_telemetry_sweep_queued_) {
				module_telemetry_remaining_ = module_telemetry_.size();
				module_telemetry_sweep_queued_ = false;
			}
		}
		const auto service_queued_work = [&]() noexcept {
			input_scheduler_->service([&](const worker_input_endpoint &input,
						      uint16_t allowance) noexcept -> algo::service_result {
				switch (input.kind) {
				case worker_input_kind::RX_STREAM:
					if (stopping) {
						return {0u, algo::service_disposition::YIELDED};
					}
					return poll_source(input.ordinal, allowance, cached_time);
				case worker_input_kind::BOUNDARY:
					return drain_one_boundary_(*inbound_boundaries_[input.ordinal], allowance);
				}
				std::terminate();
			});
			process_local_queues_<has_active_scheduler, has_async_scheduler>();
			flush_transitions_();
			flush_tx_batches_();
			flush_releases_();
			maybe_flush_tx_();
		};
		const bool sender_transition_active = boundary_sender_->transition_active();
		const bool receiver_transition_active = boundary_receiver_->transition_active();
		// A bitwise combine keeps fixed execution on one predicted branch. Exact
		// sender/receiver agreement is checked only after entering the rare arm.
		const bool transition_active = sender_transition_active | receiver_transition_active;
		if (KINETUM_UNLIKELY(transition_active)) {
			if (sender_transition_active != receiver_transition_active) {
				std::terminate();
			}
			boundary_receiver_->service_control();
			boundary_sender_->service_control();
			if constexpr (has_async_scheduler) {
				active_scheduler_->service_turn_async(cached_time);
			} else if constexpr (has_active_scheduler) {
				active_scheduler_->service_turn_synchronous(cached_time);
			}
			service_queued_work();
			service_transition_after_packet_work_(cached_time);
		} else {
			if constexpr (has_async_scheduler) {
				active_scheduler_->service_turn_async(cached_time);
			} else if constexpr (has_active_scheduler) {
				active_scheduler_->service_turn_synchronous(cached_time);
			}
			service_queued_work();
		}
		if (!stopping) {
			const auto telemetry_result = telemetry_->service_turn(cached_time);
			record_telemetry_return_need_(telemetry_result.return_need);
			if (telemetry_result.cadence_due) {
				schedule_module_telemetry_sweep_();
			}
		}
		epoch_ledger_->publish();
		publish_boundary_transport_();

		if (stopping && local_work_empty_() && inbound_closed_and_empty_()) {
			if (!epoch_ledger_->empty()) {
				std::terminate();
			}
			service_telemetry_returns_();
			if (module_telemetry_.size() == std::numeric_limits<std::size_t>::max() ||
			    telemetry_cadence_returns_expected_ != 0u || telemetry_return_poll_requested_ ||
			    !telemetry_->preflight_completed_publications(module_telemetry_.size() + 1u) ||
			    !telemetry_->preflight_shutdown(epoch_ledger_->active_epoch()) ||
			    !std::all_of(module_telemetry_.begin(), module_telemetry_.end(), [this](const auto *owner) {
				    return owner != nullptr &&
					   owner->preflight_publish_shutdown_telemetry(epoch_ledger_->active_epoch());
			    })) {
				continue;
			}
			close_outbound_boundaries_();
			final_flush_tx_();
			if (!local_work_empty_()) {
				std::terminate();
			}
			for (auto *owner : module_telemetry_) {
				owner->publish_shutdown_telemetry(epoch_ledger_->active_epoch(), cached_time);
			}
			telemetry_->publish_shutdown(epoch_ledger_->active_epoch(), cached_time);
			run_finished_ = true;
			return;
		}
	}
}

void packet_worker_kernel::implementation::run() noexcept
{
	if (run_started_ || epoch_ledger_ == nullptr || epoch_ledger_->active_epoch() == 0u || commands_ == nullptr ||
	    observed_command_ == nullptr || boundary_sender_ == nullptr || boundary_receiver_ == nullptr ||
	    epoch_activation_ == nullptr || input_scheduler_ == nullptr ||
	    (module_telemetry_.empty() != (module_health_ == nullptr))) {
		std::terminate();
	}
	run_started_ = true;
	const bool has_active_scheduler = active_scheduler_ != nullptr;
	const bool has_async_scheduler = has_active_scheduler && active_scheduler_->has_async_work();
	switch (source_kernel_) {
	case source_kernel_kind::NO_SOURCES: {
		const auto poll_source = [](uint32_t, uint16_t, uint64_t) noexcept -> algo::service_result {
			std::terminate();
		};
		if (!has_active_scheduler) {
			run_loop_<false, false>(poll_source);
		} else if (has_async_scheduler) {
			run_loop_<true, true>(poll_source);
		} else {
			run_loop_<true, false>(poll_source);
		}
		return;
	}
	case source_kernel_kind::HOMOGENEOUS: {
		const receive_burst_function receive_burst = homogeneous_receive_burst_;
		if (receive_burst == nullptr) {
			std::terminate();
		}
		const auto poll_source = [this, receive_burst](uint32_t ordinal, uint16_t allowance,
							       uint64_t cached_time) noexcept {
			return poll_one_rx_(*rx_inputs_[ordinal], receive_burst, allowance, cached_time);
		};
		if (!has_active_scheduler) {
			run_loop_<false, false>(poll_source);
		} else if (has_async_scheduler) {
			run_loop_<true, true>(poll_source);
		} else {
			run_loop_<true, false>(poll_source);
		}
		return;
	}
	case source_kernel_kind::HETEROGENEOUS: {
		const auto poll_source = [this](uint32_t ordinal, uint16_t allowance, uint64_t cached_time) noexcept {
			auto &stream = *rx_inputs_[ordinal];
			return poll_one_rx_(stream, stream.operations->receive_burst, allowance, cached_time);
		};
		if (!has_active_scheduler) {
			run_loop_<false, false>(poll_source);
		} else if (has_async_scheduler) {
			run_loop_<true, true>(poll_source);
		} else {
			run_loop_<true, false>(poll_source);
		}
		return;
	}
	}
	std::terminate();
}

common::status_or<std::unique_ptr<packet_worker_kernel>>
packet_worker_kernel::create(uint32_t worker_index, const provider::compiled_provider_topology &topology,
			     const provider::materialized_provider_runtime &providers, module::module_manager &modules,
			     worker_runtime_command_publication &commands,
			     const std::vector<boundary_epoch_channel *> &boundaries,
			     std::unique_ptr<worker_boundary_sender> boundary_sender,
			     std::unique_ptr<worker_boundary_receiver> boundary_receiver,
			     worker_runtime_telemetry &telemetry, epoch_protocol_fault_latch &protocol_faults,
			     std::span<lifecycle::lifecycle_context_owner *const> module_telemetry)
{
	auto implementation = std::unique_ptr<packet_worker_kernel::implementation>(new (
		std::nothrow) packet_worker_kernel::implementation(worker_index, topology, providers, modules, commands,
								   telemetry, protocol_faults, module_telemetry));
	if (implementation == nullptr) {
		return common::status::resource_exhausted("packet worker implementation allocation failed");
	}
	try {
		const auto result = implementation->initialize(boundaries, std::move(boundary_sender),
							       std::move(boundary_receiver));
		if (!result.is_ok()) {
			return result;
		}
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("packet worker cold-table allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE,
				      "packet worker cold-table extent exceeds the host size domain");
	} catch (...) {
		return common::status::internal_error("packet worker cold construction failed unexpectedly");
	}
	auto *kernel = new (std::nothrow) packet_worker_kernel(std::move(implementation));
	if (kernel == nullptr) {
		return common::status::resource_exhausted("packet worker owner allocation failed");
	}
	return std::unique_ptr<packet_worker_kernel>(kernel);
}

packet_worker_kernel::packet_worker_kernel(std::unique_ptr<implementation> implementation) noexcept
	: implementation_(std::move(implementation))
{
	if (implementation_ == nullptr) {
		std::terminate();
	}
}

packet_worker_kernel::~packet_worker_kernel() = default;

void packet_worker_kernel::bind_bootstrap_epoch(uint64_t bootstrap_epoch, uint64_t now_ns) noexcept
{
	implementation_->bind_bootstrap_epoch(bootstrap_epoch, now_ns);
}

void packet_worker_kernel::run() noexcept
{
	implementation_->run();
}

uint32_t packet_worker_kernel::worker_index() const noexcept
{
	return implementation_->worker_index();
}

publication_read_result packet_worker_kernel::try_read_epoch_ownership(worker_epoch_ledger_snapshot &out) const noexcept
{
	return implementation_->try_read_epoch_ownership(out);
}

kinetum::algo::quiescence_reader &packet_worker_kernel::quiescence_reader_registration() noexcept
{
	return implementation_->quiescence_reader_registration();
}

epoch_transition_certificate_worker_source packet_worker_kernel::transition_certificate_source() const noexcept
{
	return implementation_->transition_certificate_source();
}

}  // namespace kinetum::dp
