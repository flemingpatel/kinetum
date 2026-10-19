// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_dpdk_io.cpp
 * @brief Exact DPDK packet-storage and ethdev I/O ownership tests.
 * @author Fleming Patel
 *
 * Cold native APIs are injected at construction. Burst fixtures temporarily own
 * one native ethdev dispatch slot and exercise the production burst callback.
 * Neither mechanism adds test-only dispatch to production packet execution.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "src/dp/backends/dpdk/dpdk_io.hpp"
#include "src/dp/backends/dpdk/dpdk_packet_record.hpp"
#include "tests/dpdk_component_test_harness.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

using test_support::DPDK_DRIVER_TYPE_URL;
using test_support::DPDK_FACILITY_TYPE_URL;
using test_support::DPDK_STORAGE_TYPE_URL;
using test_support::facility_fixture;
using test_support::text_view;

/** Native object population used by the storage fixture. */
constexpr uint32_t TEST_BUFFER_COUNT = 128;
/** Fake mbuf data-room extent including initial headroom. */
constexpr uint16_t TEST_DATA_ROOM_BYTES = 2176;
/** Initial mbuf offset preserving the admitted headroom. */
constexpr uint16_t TEST_HEADROOM_BYTES = 128;
/** Maximum payload admitted by the fixture storage table. */
constexpr uint16_t TEST_MAXIMUM_PACKET_LENGTH = 2048;
/** Exact descriptor count expected by fake queue setup. */
constexpr uint16_t TEST_DESCRIPTOR_COUNT = 128;
/** Plan-visible port identity distinct from native ethdev numbering. */
constexpr uint16_t TEST_LOGICAL_PORT = 10;
/** Native ethdev identity resolved by the facility fake. */
constexpr uint16_t TEST_PHYSICAL_PORT = 7;
/** Maximum RX/TX queue count advertised by the fake PMD. */
constexpr uint16_t TEST_QUEUE_LIMIT = 8;
/** Exact RSS key width advertised by the fake PMD. */
constexpr std::size_t TEST_RSS_KEY_SIZE = 52;
/** MAC shared by compiled port facts and the native observation. */
constexpr std::array<uint8_t, 6> TEST_MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

/** One fake DPDK object preserving exact mbuf-private and payload geometry. */
struct fake_mbuf_object {
	rte_mbuf mbuf{};  ///< Native header consumed by provider-private helpers.
	alignas(kinetum_packet_record)
		std::array<std::byte, sizeof(kinetum_packet_record)> private_area{};  ///< Exact record bytes.
	std::array<uint8_t, TEST_DATA_ROOM_BYTES> payload{};			      ///< Exact native data room.
};

static_assert(offsetof(fake_mbuf_object, private_area) == sizeof(rte_mbuf));
static_assert(offsetof(fake_mbuf_object, payload) % alignof(kinetum_packet_record) == 0);

/** @brief Observable state behind one injected mbuf-pool API. */
struct mempool_state {
	rte_mempool pool{};						      ///< Stable opaque pool identity.
	std::vector<fake_mbuf_object> objects;				      ///< Exact native object population.
	uint32_t create_calls{0};					      ///< Native create attempts.
	uint32_t iterate_calls{0};					      ///< Native population walks.
	uint32_t free_calls{0};						      ///< Exact pool retirements.
	uint32_t in_use{0};						      ///< Injected cold occupancy result.
	uint32_t requested_count{0};					      ///< Exact requested population.
	uint32_t requested_cache_size{0};				      ///< Exact requested cache policy.
	uint16_t requested_private_size{0};				      ///< Exact private byte request.
	uint16_t requested_data_room{0};				      ///< Exact native data room.
	int requested_socket{-1};					      ///< Exact host NUMA socket.
	uint16_t reported_private_size{dp::DPDK_PACKET_RECORD_PRIVATE_SIZE};  ///< Native reported private bytes.
};

/** @brief Own one scoped native RX dispatch slot without changing production dispatch. */
class native_receive_fixture final {
    public:
	/**
	 * @brief Bind queue zero to a borrowed finite mbuf sequence.
	 * @param packets Native packet references retained through fixture destruction.
	 */
	explicit native_receive_fixture(std::span<rte_mbuf *const> packets) noexcept
		: saved_(rte_eth_fp_ops[TEST_PHYSICAL_PORT])
		, packets_(packets)
	{
		queues_[0] = this;
		auto &operations = rte_eth_fp_ops[TEST_PHYSICAL_PORT];
		operations.rxq.data = queues_.data();
		operations.rxq.clbk = callbacks_.data();
		operations.rx_pkt_burst = receive_;
	}

	/** @brief Keep restoration of the native dispatch slot under one owner. */
	native_receive_fixture(const native_receive_fixture &) = delete;
	/** @brief Forbid replacing a live dispatch restoration owner. */
	native_receive_fixture &operator=(const native_receive_fixture &) = delete;

	/** @brief Restore every native dispatch field before borrowed storage retires. */
	~native_receive_fixture()
	{
		rte_eth_fp_ops[TEST_PHYSICAL_PORT] = saved_;
	}

    private:
	/** @brief Retain DPDK's declared RX callback-slot type. */
	using callback_slot = std::remove_pointer_t<decltype(rte_ethdev_qdata::clbk)>;

	/**
	 * @brief Transfer the next bounded prefix through DPDK's actual burst dispatch.
	 * @param state Exact fixture bound as the native queue state.
	 * @param[out] packets Destination prefix populated with native packet references.
	 * @param capacity Maximum prefix the caller accepts.
	 * @return Exact populated prefix length.
	 */
	static uint16_t receive_(void *state, rte_mbuf **packets, uint16_t capacity) noexcept
	{
		auto &fixture = *static_cast<native_receive_fixture *>(state);
		const auto count = static_cast<uint16_t>(
			std::min<std::size_t>(capacity, fixture.packets_.size() - fixture.position_));
		for (uint16_t index = 0u; index < count; ++index) {
			packets[index] = fixture.packets_[fixture.position_++];
		}
		return count;
	}

	struct rte_eth_fp_ops saved_;		    ///< Complete native slot restored at scope exit.
	std::span<rte_mbuf *const> packets_;	    ///< Borrowed mbufs supplied by the fixture's storage owner.
	std::size_t position_{0};		    ///< Next native packet to transfer.
	std::array<void *, 1> queues_{};	    ///< Native queue-data pointers.
	std::array<callback_slot, 1> callbacks_{};  ///< Empty native callback lists.
};

/** @brief Observe native TX order and immediate retirement through the real dispatch slot. */
class native_transmit_fixture final {
    public:
	/**
	 * @brief Bind queue zero to a bounded native accepted-prefix operation.
	 * @param accepted_limit Maximum prefix the injected native TX callback accepts.
	 */
	explicit native_transmit_fixture(uint16_t accepted_limit) noexcept
		: saved_(rte_eth_fp_ops[TEST_PHYSICAL_PORT])
		, accepted_limit_(accepted_limit)
	{
		queues_[0] = this;
		auto &operations = rte_eth_fp_ops[TEST_PHYSICAL_PORT];
		operations.txq.data = queues_.data();
		operations.txq.clbk = callbacks_.data();
		operations.tx_pkt_burst = transmit_;
	}

	/** @brief Retain one restoration owner for the borrowed native slot. */
	native_transmit_fixture(const native_transmit_fixture &) = delete;
	/** @brief Forbid replacement of a live restoration owner. */
	native_transmit_fixture &operator=(const native_transmit_fixture &) = delete;

	/** @brief Restore the native slot before any borrowed pool retires. */
	~native_transmit_fixture()
	{
		rte_eth_fp_ops[TEST_PHYSICAL_PORT] = saved_;
	}

	/** @return Borrowed last native submission in original order, including its unaccepted suffix. */
	[[nodiscard]] std::span<rte_mbuf *const> submitted() const noexcept
	{
		return {submitted_.data(), submitted_count_};
	}

    private:
	/** @brief Retain the native TX callback-list slot type. */
	using callback_slot = std::remove_pointer_t<decltype(rte_ethdev_qdata::clbk)>;

	/**
	 * @brief Observe one exact native TX prefix and invalidate accepted provider records.
	 * @param state Exact fixture bound as native TX queue state.
	 * @param packets Borrowed submitted mbuf pointers.
	 * @param count Submitted prefix length within the fixed fixture bound.
	 * @return Accepted prefix limited by the fixture's configured acceptance.
	 */
	static uint16_t transmit_(void *state, rte_mbuf **packets, uint16_t count) noexcept
	{
		auto &fixture = *static_cast<native_transmit_fixture *>(state);
		if (count > fixture.submitted_.size()) {
			std::terminate();
		}
		fixture.submitted_count_ = count;
		std::copy_n(packets, count, fixture.submitted_.data());
		const uint16_t accepted = std::min(count, fixture.accepted_limit_);
		for (uint16_t index = 0; index < accepted; ++index) {
			*dp::dpdk_packet_record(packets[index]) = {};
		}
		return accepted;
	}

	struct rte_eth_fp_ops saved_;		    ///< Whole native slot restored at scope exit.
	uint16_t accepted_limit_;		    ///< Maximum native acceptance for one burst.
	uint16_t submitted_count_{0};		    ///< Exact population observed at native entry.
	std::array<rte_mbuf *, 64> submitted_{};    ///< Original mbufs in submission order.
	std::array<void *, 1> queues_{};	    ///< Native queue-data pointer.
	std::array<callback_slot, 1> callbacks_{};  ///< Empty native callback list.
};

/**
 * @brief Construct one exact fake mbuf population.
 * @param opaque Borrowed fake mempool state and recorded observations.
 * @param name Required non-null native pool name.
 * @param count Requested object population.
 * @param cache_size Requested cache size recorded for assertions.
 * @param private_size Requested record-private extent recorded for assertions.
 * @param data_room_size Native data-room extent assigned to the fake mbufs.
 * @param socket_id Requested NUMA socket recorded for assertions.
 * @return Stable fake pool identity, or nullptr for an absent name.
 */
rte_mempool *create_mempool(void *opaque, const char *name, uint32_t count, uint32_t cache_size, uint16_t private_size,
			    uint16_t data_room_size, int socket_id) noexcept
{
	auto &state = *static_cast<mempool_state *>(opaque);
	++state.create_calls;
	if (name == nullptr) {
		return nullptr;
	}
	state.requested_count = count;
	state.requested_cache_size = cache_size;
	state.requested_private_size = private_size;
	state.requested_data_room = data_room_size;
	state.requested_socket = socket_id;
	state.objects.clear();
	state.objects.resize(count);
	for (auto &object : state.objects) {
		object.mbuf = rte_mbuf{};
		object.mbuf.buf_addr = object.payload.data();
		object.mbuf.buf_len = data_room_size;
		object.mbuf.data_off = TEST_HEADROOM_BYTES;
		object.mbuf.nb_segs = 1;
		object.mbuf.next = nullptr;
		object.mbuf.pool = &state.pool;
	}
	return &state.pool;
}

/**
 * @brief Invoke the provider's exact population probe over every object.
 * @param opaque Borrowed fake mempool state and recorded observations.
 * @param pool Candidate fake pool identity.
 * @param callback Borrowed object-inspection callback.
 * @param argument Callback state borrowed during iteration.
 * @return Number of visited objects, or zero for a foreign pool or absent callback.
 */
uint32_t iterate_mempool(void *opaque, rte_mempool *pool, rte_mempool_obj_cb_t *callback, void *argument) noexcept
{
	auto &state = *static_cast<mempool_state *>(opaque);
	++state.iterate_calls;
	if (pool != &state.pool || callback == nullptr) {
		return 0;
	}
	static_assert(sizeof(unsigned int) == sizeof(uint32_t));
	for (std::size_t index = 0; index < state.objects.size(); ++index) {
		callback(pool, argument, &state.objects[index].mbuf, static_cast<unsigned int>(index));
	}
	return static_cast<uint32_t>(state.objects.size());
}

/**
 * @brief Return the injected exact mbuf private-area size.
 * @param opaque Borrowed fake mempool state and recorded observations.
 * @param pool Candidate fake pool identity.
 * @return Injected private size for the exact pool, otherwise zero.
 */
uint16_t mempool_private_size(void *opaque, const rte_mempool *pool) noexcept
{
	auto &state = *static_cast<mempool_state *>(opaque);
	return pool == &state.pool ? state.reported_private_size : 0;
}

/**
 * @brief Return the injected exact outstanding-record count.
 * @param opaque Borrowed fake mempool state and recorded observations.
 * @param pool Candidate fake pool identity.
 * @return Injected in-use count, or UINT32_MAX for a foreign pool.
 */
uint32_t mempool_in_use(void *opaque, const rte_mempool *pool) noexcept
{
	auto &state = *static_cast<mempool_state *>(opaque);
	return pool == &state.pool ? state.in_use : UINT32_MAX;
}

/**
 * @brief Retire one exact fake native pool.
 * @param opaque Borrowed fake mempool state and recorded observations.
 * @param pool Exact fake pool whose object population is cleared; a foreign pool terminates.
 */
void free_mempool(void *opaque, rte_mempool *pool) noexcept
{
	auto &state = *static_cast<mempool_state *>(opaque);
	if (pool != &state.pool) {
		std::terminate();
	}
	++state.free_calls;
	state.objects.clear();
}

/**
 * @brief Return one complete injected mbuf-pool API.
 * @param state Fixture state that outlives every use of the returned callbacks.
 * @return Native API table borrowing the supplied fixture state.
 */
dpdk_mempool_api mempool_api(mempool_state &state)
{
	return dpdk_mempool_api{
		.state = &state,
		.create = create_mempool,
		.iterate = iterate_mempool,
		.private_size = mempool_private_size,
		.in_use_count = mempool_in_use,
		.free = free_mempool,
	};
}

/**
 * @brief One exact DPDK storage request borrowing the shared facility.
 */
class storage_fixture {
    public:
	/**
	 * @brief Construct exact storage facts with a stable distinct instance identity.
	 * @param facility Live facility fixture retained through this storage owner's retirement.
	 * @param domain_index Compact identity distinguishing this pool from other fixture pools.
	 */
	explicit storage_fixture(facility_fixture &facility, uint32_t domain_index = 0)
		: instance_id_("dpdk.storage.")
	{
		instance_id_.append(std::to_string(domain_index));
		dependencies_[0] = facility.dependency();
		facts_ = kinetum_provider_packet_storage_facts{
			.storage_domain_index = domain_index,
			.buffer_count = TEST_BUFFER_COUNT,
			.data_room_bytes = TEST_DATA_ROOM_BYTES,
			.headroom_bytes = TEST_HEADROOM_BYTES,
			.alignment_bytes = 64,
			.cache_size_per_worker = 0,
			.required_buffer_count = 64,
			.safety_margin = 64,
			.host_numa_node = 0,
			.maximum_packet_length = TEST_MAXIMUM_PACKET_LENGTH,
			.access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU | KINETUM_PROVIDER_ACCESS_AGENT_NIC_DMA,
			.has_host_numa_node = 1,
			.padding = {0},
		};
		request_ = kinetum_provider_factory_request{
			.instance_id = text_view(instance_id_),
			.type_url = text_view(DPDK_STORAGE_TYPE_URL),
			.canonical_configuration = {},
			.compiled_facts =
				{
					.process_facility = nullptr,
					.io_driver = nullptr,
					.packet_storage = &facts_,
					.execution = nullptr,
					.storage_transition = nullptr,
				},
			.dependencies = dependencies_.data(),
			.dependency_count = static_cast<uint32_t>(dependencies_.size()),
			.dependency_padding = 0,
			.runtime_generation = 1,
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
			.logging = logging_.capability(),
		};
	}

	/** @brief Keep request backing and native pool ownership at one address. */
	storage_fixture(const storage_fixture &) = delete;
	/** @brief Forbid replacing a borrowed request and its retained pool owner. */
	storage_fixture &operator=(const storage_fixture &) = delete;

	/**
	 * @brief Construct and retain the exact storage owner.
	 * @param native Fake pool state retained through storage-owner retirement.
	 * @return Production storage-factory result; this fixture retains successful ownership.
	 */
	[[nodiscard]] kinetum_provider_status create(mempool_state &native) noexcept
	{
		return dpdk_packet_storage::create(request_, mempool_api(native), storage_, nullptr);
	}

	/** @return Reference to the fixture's retained storage owner. */
	[[nodiscard]] std::unique_ptr<dpdk_packet_storage> &storage() noexcept
	{
		return storage_;
	}

	/** @return Borrowed mutable storage facts used to author admission failures. */
	[[nodiscard]] kinetum_provider_packet_storage_facts &facts() noexcept
	{
		return facts_;
	}

	/** @return Borrowed dependency view of the live storage owner, or an empty handle before creation. */
	[[nodiscard]] kinetum_provider_dependency_handle dependency() const noexcept
	{
		if (storage_ == nullptr) {
			return {};
		}
		return kinetum_provider_dependency_handle{
			.instance_id = text_view(instance_id_),
			.type_url = text_view(DPDK_STORAGE_TYPE_URL),
			.instance = storage_.get(),
			.operations = &storage_->operations(),
			.role = KINETUM_PROVIDER_ROLE_PACKET_STORAGE,
			.padding = {0},
		};
	}

    private:
	std::string instance_id_;  ///< Owned identity borrowed by the request and dependencies.

	std::array<kinetum_provider_dependency_handle, 1> dependencies_{};  ///< Facility dependency.
	kinetum_provider_packet_storage_facts facts_{};			    ///< Exact shared-budget storage facts.
	kinetum_provider_factory_request request_{};			    ///< Exact storage factory request.
	kinetum::test_support::provider_log_capture logging_;		    ///< Retained cold diagnostic receiver.
	std::unique_ptr<dpdk_packet_storage> storage_;			    ///< Retained native pool owner.
};

/** @brief Adapter-global default state, distinct from every PF's key, HENA, and RETA. */
struct adapter_rss_state {
	uint32_t default_resets{0};	  ///< Ordinary start-time resets observed across all PFs.
	bool ordinary_toeplitz{false};	  ///< Whether the adapter currently carries the ordinary default.
	std::vector<std::string> events;  ///< Complete cross-port cold-operation order.
};

/** @brief Observable state behind one injected ethdev API. */
struct ethdev_state {
	std::vector<std::string> events;	     ///< Ordered native ownership trace.
	uint16_t physical_port{TEST_PHYSICAL_PORT};  ///< Exact native identity of this PF.
	adapter_rss_state *adapter{nullptr};	     ///< Optional shared-adapter observation owner.

	bool require_queue_pairs{false};	       ///< Enforce the TAP PMD's native RX/TX count equality.
	uint16_t maximum_rx_queues{TEST_QUEUE_LIMIT};  ///< Native RX queue population limit.
	uint16_t maximum_tx_queues{TEST_QUEUE_LIMIT};  ///< Native TX queue population limit.
	uint16_t maximum_rx_descriptors{1024};	       ///< Native RX descriptor limit.
	uint16_t maximum_tx_descriptors{1024};	       ///< Native TX descriptor limit.

	uint64_t tx_offloads{0};			///< Native default TX mode exposed during preflight.
	int configure_result{0};			///< Configured ethdev configure result.
	int mtu_result{0};				///< Configured MTU result.
	int rx_setup_result{0};				///< Configured RX queue result.
	int tx_setup_result{0};				///< Configured TX queue result.
	int start_result{0};				///< Configured start result.
	int stop_result{0};				///< Configured stop result.
	int close_result{0};				///< Configured close result.
	int reta_result{0};				///< Configured RETA result.
	int hash_read_result{0};			///< Native key/hash read result.
	int reta_read_result{0};			///< Native RETA read result.
	uint8_t key_read_extent{TEST_RSS_KEY_SIZE};	///< Native returned key extent.
	std::size_t key_read_limit{TEST_RSS_KEY_SIZE};	///< Bytes actually written by native readback.
	uint16_t reta_read_limit{UINT16_MAX};		///< Entries actually written by native readback.
	uint64_t hash_read_xor{0};			///< Independently injected changed hash-class bits.
	bool mutate_configured_key{false};		///< Corrupt the writable dev_conf key before programming.
	bool mutate_reta_input{false};			///< Corrupt the native update input before programming.
	bool corrupt_read_key{false};			///< Return an independently changed hardware key byte.
	bool corrupt_read_reta{false};			///< Return an independently changed hardware queue entry.
	bool started{false};				///< Native start succeeded and has not been stopped.
	bool start_entered{false};			///< Native start may have effects even when it returns failure.
	const char *driver_name{"net_i40e"};		///< Independently advertised PCI driver identity.
	int statistics_result{0};			///< Configured native statistics result.
	bool exit_success_on_close{false};		///< Death-test sentinel rejecting close after failed stop.
	bool exit_success_on_stop{false};  ///< Death-test sentinel rejecting rollback after uncertain start.
	uint32_t configure_calls{0};	   ///< Native configure attempts.
	uint32_t stop_calls{0};		   ///< Native stop attempts.
	uint32_t close_calls{0};	   ///< Native close attempts.
	uint32_t hash_read_calls{0};	   ///< Native key/hash read attempts.
	uint32_t reta_read_calls{0};	   ///< Native RETA read attempts.
	uint32_t statistics_calls{0};	   ///< Native statistics observations.
	uint16_t configured_rx_queues{0};  ///< Exact configured RX queue count.
	uint16_t configured_tx_queues{0};  ///< Exact configured TX queue count.
	uint16_t configured_mtu{0};	   ///< Exact configured MTU.
	std::array<rte_mempool *, TEST_QUEUE_LIMIT> rx_pools{};	  ///< Pool supplied to each native RX queue.
	std::array<uint16_t, TEST_QUEUE_LIMIT> rx_descriptors{};  ///< Descriptor bound supplied to each native RX queue.
	std::array<uint16_t, TEST_QUEUE_LIMIT> tx_descriptors{};  ///< Descriptor bound supplied to each native TX queue.
	uint16_t programmed_reta_size{0};			  ///< Exact RETA population.
	std::vector<uint16_t> programmed_reta;			  ///< Complete observed RETA queue mapping.
	std::vector<uint8_t> configured_rss_key;		  ///< Exact configured RSS key.
	std::span<const uint8_t> retained_rss_key;		  ///< dev_conf backing borrowed through native start.
	uint64_t configured_rss_hf{0};				  ///< Hash classes supplied through dev_conf.
	std::vector<uint8_t> hardware_rss_key;			  ///< Key installed only by successful native start.
	uint64_t hardware_rss_hf{0};				  ///< Native i40e alias view after start.
	rte_eth_stats statistics{};				  ///< Exact injected native counter snapshot.

	/**
	 * @brief Record one native operation locally and, when attached, in adapter-wide order.
	 * @param event Complete native operation name, consumed into the local trace.
	 */
	void record(std::string event)
	{
		if (adapter != nullptr) {
			adapter->events.push_back(std::to_string(physical_port) + ":" + event);
		}
		events.push_back(std::move(event));
	}

	/**
	 * @param port_id Native identity selected by the caller.
	 * @return This exact native port, or null when the requested identity is foreign.
	 */
	[[nodiscard]] ethdev_state *find_port(uint16_t port_id) noexcept
	{
		return port_id == physical_port ? this : nullptr;
	}
};

/** @brief Two independent physical functions sharing one adapter's RSS defaults. */
struct ethdev_adapter {
	adapter_rss_state rss;		    ///< Shared registers and complete operation order.
	std::array<ethdev_state, 2> ports;  ///< Per-PF device state.

	/** @brief Bind consecutive fixture ports to the same adapter-global state. */
	ethdev_adapter()
	{
		for (std::size_t index = 0; index < ports.size(); ++index) {
			ports[index].physical_port = static_cast<uint16_t>(TEST_PHYSICAL_PORT + index);
			ports[index].adapter = &rss;
		}
	}

	/**
	 * @param port_id Native identity selected by the caller.
	 * @return The exact requested PF, or null for a port outside this adapter.
	 */
	[[nodiscard]] ethdev_state *find_port(uint16_t port_id) noexcept
	{
		for (auto &port : ports) {
			if (port.physical_port == port_id) {
				return &port;
			}
		}
		return nullptr;
	}
};

/**
 * @brief Return exact PMD capabilities used by all I/O tests.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param info Destination for fixed queue/RSS limits and injected TX offloads.
 * @return Zero after filling capabilities for the exact port; -1 otherwise.
 */
int device_info(void *opaque, uint16_t port_id, rte_eth_dev_info *info) noexcept
{
	const auto &state = *static_cast<const ethdev_state *>(opaque);
	if (port_id != state.physical_port || info == nullptr) {
		return -1;
	}
	*info = rte_eth_dev_info{};
	info->driver_name = state.require_queue_pairs ? "net_tap" : state.driver_name;
	info->max_rx_queues = state.maximum_rx_queues;
	info->max_tx_queues = state.maximum_tx_queues;
	info->rx_desc_lim.nb_min = 64;
	info->rx_desc_lim.nb_max = state.maximum_rx_descriptors;
	info->rx_desc_lim.nb_align = 64;
	info->tx_desc_lim.nb_min = 64;
	info->tx_desc_lim.nb_max = state.maximum_tx_descriptors;
	info->tx_desc_lim.nb_align = 64;
	info->hash_key_size = state.require_queue_pairs ? 40 : static_cast<uint8_t>(TEST_RSS_KEY_SIZE);
	info->reta_size = state.require_queue_pairs ? 0 : 128;
	info->flow_type_rss_offloads = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_OTHER | RTE_ETH_RSS_NONFRAG_IPV4_UDP;
	info->default_txconf.offloads = state.tx_offloads;
	return 0;
}

/**
 * @brief Return exact port NUMA identity.
 * @param opaque Borrowed fake ethdev state carrying the exact port identity.
 * @param port_id Candidate native port identity.
 * @return NUMA node zero for the exact fixture port, or -1 for a foreign port.
 */
int device_socket(void *opaque, uint16_t port_id) noexcept
{
	const auto &state = *static_cast<const ethdev_state *>(opaque);
	return port_id == state.physical_port ? 0 : -1;
}

/**
 * @brief Observe the first native ownership-establishing call.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param rx_queues Requested RX queue population.
 * @param tx_queues Requested TX queue population.
 * @param configuration Native configuration whose key is borrowed through start and copied for observation.
 * @return Injected configure result for exact input, or -1 for malformed input.
 */
int configure_port(void *opaque, uint16_t port_id, uint16_t rx_queues, uint16_t tx_queues,
		   const rte_eth_conf *configuration) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	++state.configure_calls;
	state.record("configure");
	if (port_id != state.physical_port || configuration == nullptr) {
		return -1;
	}
	state.configured_rx_queues = rx_queues;
	state.configured_tx_queues = tx_queues;
	if (state.require_queue_pairs && rx_queues != tx_queues) {
		return -1;
	}
	const auto &rss = configuration->rx_adv_conf.rss_conf;
	state.configured_rss_hf = rss.rss_hf;
	if (rss.rss_key_len != 0 && rss.rss_key != nullptr) {
		if (state.mutate_configured_key) {
			rss.rss_key[0] ^= 1u;
		}
		state.configured_rss_key.assign(rss.rss_key, rss.rss_key + rss.rss_key_len);
		state.retained_rss_key = {rss.rss_key, rss.rss_key_len};
	}
	return state.configure_result;
}

/**
 * @brief Observe exact MTU application.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param mtu Requested MTU recorded for assertions.
 * @return Injected MTU result for the exact port, otherwise -1.
 */
int set_mtu(void *opaque, uint16_t port_id, uint16_t mtu) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	state.record("mtu");
	state.configured_mtu = mtu;
	return port_id == state.physical_port ? state.mtu_result : -1;
}

/**
 * @brief Observe one exact RX queue construction.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param queue_id Candidate native RX queue identity.
 * @param descriptors Requested descriptor count.
 * @param socket_id Requested queue NUMA socket.
 * @param configuration Required non-null native RX configuration.
 * @param pool Required pool identity retained as the queue's observed dependency.
 * @return Injected setup result for the fixture shape, or -1 on mismatch.
 */
int setup_rx_queue(void *opaque, uint16_t port_id, uint16_t queue_id, uint16_t descriptors, unsigned int socket_id,
		   const rte_eth_rxconf *configuration, rte_mempool *pool) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	state.record("rx" + std::to_string(queue_id));
	if (queue_id >= state.rx_pools.size() || queue_id >= state.configured_rx_queues) {
		return -1;
	}
	state.rx_pools[queue_id] = pool;
	state.rx_descriptors[queue_id] = descriptors;
	return port_id == state.physical_port && descriptors == TEST_DESCRIPTOR_COUNT && socket_id == 0 &&
			       configuration != nullptr && pool != nullptr ?
		       state.rx_setup_result :
		       -1;
}

/**
 * @brief Observe one exact TX queue construction.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param queue_id Native TX queue identity recorded in the event trace.
 * @param descriptors Requested descriptor count.
 * @param socket_id Requested queue NUMA socket.
 * @param configuration Required non-null native TX configuration.
 * @return Injected setup result for the fixture shape, or -1 on mismatch.
 */
int setup_tx_queue(void *opaque, uint16_t port_id, uint16_t queue_id, uint16_t descriptors, unsigned int socket_id,
		   const rte_eth_txconf *configuration) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	state.record("tx" + std::to_string(queue_id));
	if (queue_id >= state.tx_descriptors.size() || queue_id >= state.configured_tx_queues) {
		return -1;
	}
	state.tx_descriptors[queue_id] = descriptors;
	return port_id == state.physical_port && descriptors == TEST_DESCRIPTOR_COUNT && socket_id == 0 &&
			       configuration != nullptr ?
		       state.tx_setup_result :
		       -1;
}

/**
 * @brief Observe exact port start.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @return Injected start result for the exact port, otherwise -1.
 */
int start_port(void *opaque, uint16_t port_id) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	state.record("start");
	if (port_id != state.physical_port) {
		return -1;
	}
	state.start_entered = true;
	if (state.start_result != 0) {
		return state.start_result;
	}
	if (state.adapter != nullptr) {
		++state.adapter->default_resets;
		state.adapter->ordinary_toeplitz = true;
	}
	state.started = true;
	state.hardware_rss_key.assign(state.retained_rss_key.begin(), state.retained_rss_key.end());
	state.hardware_rss_hf = state.configured_rss_hf;
	if ((state.hardware_rss_hf & RTE_ETH_RSS_IPV4) != 0) {
		state.hardware_rss_hf |= RTE_ETH_RSS_NONFRAG_IPV4_OTHER;
	}
	return 0;
}

/**
 * @brief Observe exact started-port retirement.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @return Injected stop result for the exact port, otherwise -1.
 */
int stop_port(void *opaque, uint16_t port_id) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	if (state.exit_success_on_stop) {
		std::_Exit(0);
	}
	++state.stop_calls;
	state.record("stop");
	if (port_id != state.physical_port) {
		return -1;
	}
	if (state.stop_result != 0) {
		return state.stop_result;
	}
	state.started = false;
	return 0;
}

/**
 * @brief Observe exact configured-port retirement.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @return Injected close result for the exact port, otherwise -1; the configured exit probe does not return.
 */
int close_port(void *opaque, uint16_t port_id) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	if (state.exit_success_on_close) {
		std::_Exit(0);
	}
	++state.close_calls;
	state.record("close");
	state.retained_rss_key = {};
	return port_id == state.physical_port ? state.close_result : -1;
}

/**
 * @brief Return the exact resolved plan MAC.
 * @param opaque Borrowed fake ethdev state carrying the exact port identity.
 * @param port_id Candidate native port identity.
 * @param address Destination written with the fixture MAC only for valid input.
 * @return Zero after copying the MAC, or -1 for malformed input.
 */
int mac_address(void *opaque, uint16_t port_id, rte_ether_addr *address) noexcept
{
	const auto &state = *static_cast<const ethdev_state *>(opaque);
	if (port_id != state.physical_port || address == nullptr) {
		return -1;
	}
	std::copy(TEST_MAC.begin(), TEST_MAC.end(), address->addr_bytes);
	return 0;
}

/**
 * @brief Capture the complete exact RETA mapping.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param entries Borrowed native RETA groups requiring complete update masks.
 * @param reta_size Number of entries to observe.
 * @return Injected update result after complete capture, or -1 for malformed input.
 */
int update_reta(void *opaque, uint16_t port_id, rte_eth_rss_reta_entry64 *entries, uint16_t reta_size) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	state.record("reta");
	if (port_id != state.physical_port || entries == nullptr || reta_size == 0) {
		return -1;
	}
	state.programmed_reta_size = reta_size;
	state.programmed_reta.resize(reta_size);
	if (state.mutate_reta_input) {
		entries[0].reta[0] ^= 1u;
	}
	for (uint16_t index = 0; index < reta_size; ++index) {
		const std::size_t group = index / RTE_ETH_RETA_GROUP_SIZE;
		const uint16_t offset = index % RTE_ETH_RETA_GROUP_SIZE;
		if ((entries[group].mask & (UINT64_C(1) << offset)) == 0) {
			return -1;
		}
		state.programmed_reta[index] = entries[group].reta[offset];
	}
	return state.reta_result;
}

/**
 * @brief Read hardware state populated by native start, independently of provider expectations.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param configuration Output whose key pointer, alignment, and capacity must already be valid.
 * @return Injected native read outcome; partial or corrupt success is independently controllable.
 */
int read_rss_hash(void *opaque, uint16_t port_id, rte_eth_rss_conf *configuration) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	++state.hash_read_calls;
	state.record("rss_read");
	if (port_id != state.physical_port || !state.started || configuration == nullptr ||
	    configuration->rss_key == nullptr || configuration->rss_key_len < TEST_RSS_KEY_SIZE ||
	    reinterpret_cast<std::uintptr_t>(configuration->rss_key) % alignof(uint32_t) != 0 ||
	    state.hardware_rss_key.size() != TEST_RSS_KEY_SIZE || state.hash_read_result != 0) {
		return -1;
	}
	std::copy_n(state.hardware_rss_key.begin(), std::min(state.key_read_limit, TEST_RSS_KEY_SIZE),
		    configuration->rss_key);
	if (state.corrupt_read_key) {
		configuration->rss_key[0] ^= 1u;
	}
	configuration->rss_key_len = state.key_read_extent;
	configuration->rss_hf = state.hardware_rss_hf ^ state.hash_read_xor;
	return 0;
}

/**
 * @brief Read every masked native RETA entry from separately retained hardware state.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param entries Caller-owned masked output groups.
 * @param reta_size Must equal the complete native LUT extent.
 * @return Native success, optionally incomplete/corrupt, or the injected read error.
 */
int read_reta(void *opaque, uint16_t port_id, rte_eth_rss_reta_entry64 *entries, uint16_t reta_size) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	++state.reta_read_calls;
	state.record("reta_read");
	if (port_id != state.physical_port || !state.started || entries == nullptr || reta_size != 128 ||
	    state.programmed_reta.size() != reta_size || state.reta_read_result != 0) {
		return -1;
	}
	for (uint16_t index = 0; index < std::min(reta_size, state.reta_read_limit); ++index) {
		const auto group = index / RTE_ETH_RETA_GROUP_SIZE;
		const auto offset = index % RTE_ETH_RETA_GROUP_SIZE;
		if ((entries[group].mask & (UINT64_C(1) << offset)) == 0) {
			return -1;
		}
		entries[group].reta[offset] = state.programmed_reta[index];
	}
	if (state.corrupt_read_reta) {
		entries[0].reta[0] ^= 1u;
	}
	return 0;
}

/**
 * @brief Return one injected cold native port statistics snapshot.
 * @param opaque Borrowed fake ethdev state and recorded observations.
 * @param port_id Candidate native port identity.
 * @param statistics Destination written with the injected snapshot on success.
 * @return Zero for exact input and an enabled successful observation, otherwise -1.
 */
int read_statistics(void *opaque, uint16_t port_id, rte_eth_stats *statistics) noexcept
{
	auto &state = *static_cast<ethdev_state *>(opaque);
	++state.statistics_calls;
	if (port_id != state.physical_port || statistics == nullptr || state.statistics_result != 0) {
		return -1;
	}
	*statistics = state.statistics;
	return 0;
}

/**
 * @brief Route one injected native call to its exact PF using the same operation implementation.
 * @tparam operation Native fixture function operating on one ethdev_state.
 * @tparam native_type Single-port or shared-adapter fixture owner.
 * @tparam argument_types Remaining native argument types.
 * @param opaque Borrowed fixture owner.
 * @param port_id Native port to resolve before forwarding.
 * @param arguments Native call arguments forwarded unchanged.
 * @return The native fixture result, or -1 for an unknown port.
 */
template <auto operation, typename native_type, typename... argument_types>
int ethdev_dispatch(void *opaque, uint16_t port_id, argument_types... arguments) noexcept
{
	auto *port = static_cast<native_type *>(opaque)->find_port(port_id);
	return port != nullptr ? operation(port, port_id, arguments...) : -1;
}

/**
 * @brief Return one complete injected ethdev API.
 * @tparam native_type Single-port or shared-adapter fixture owner.
 * @param state Fixture state that outlives every use of the returned callbacks.
 * @return Native API table borrowing the supplied fixture state.
 */
template <typename native_type>
dpdk_ethdev_api ethdev_api(native_type &state)
{
	return dpdk_ethdev_api{
		.state = &state,
		.device_info = ethdev_dispatch<device_info, native_type>,
		.device_socket = ethdev_dispatch<device_socket, native_type>,
		.configure = ethdev_dispatch<configure_port, native_type>,
		.set_mtu = ethdev_dispatch<set_mtu, native_type>,
		.setup_rx_queue = ethdev_dispatch<setup_rx_queue, native_type>,
		.setup_tx_queue = ethdev_dispatch<setup_tx_queue, native_type>,
		.start = ethdev_dispatch<start_port, native_type>,
		.stop = ethdev_dispatch<stop_port, native_type>,
		.close = ethdev_dispatch<close_port, native_type>,
		.mac_address = ethdev_dispatch<mac_address, native_type>,
		.update_reta = ethdev_dispatch<update_reta, native_type>,
		.rss_hash_conf_get = ethdev_dispatch<read_rss_hash, native_type>,
		.reta_query = ethdev_dispatch<read_reta, native_type>,
		.statistics = ethdev_dispatch<read_statistics, native_type>,
	};
}

/**
 * @brief One exact DPDK driver request over a facility and storage dependency.
 */
class io_driver_fixture {
    public:
	/**
	 * @brief Construct one bidirectional single-queue driver.
	 * @param facility Live facility fixture retained through driver retirement.
	 * @param storage Live initial storage fixture retained through driver retirement.
	 * @param attachment_index Exact facility attachment supplying this driver's initial port.
	 */
	io_driver_fixture(facility_fixture &facility, storage_fixture &storage, uint32_t attachment_index = 0)
		: port_index_(attachment_index)
		, instance_id_("dpdk.driver." + std::to_string(facility.attachment(attachment_index).io_driver_index))
	{
		attachments_[0] = facility.attachment(attachment_index);
		ports_[0] = kinetum_provider_io_port_fact{
			.port_index = port_index_,
			.driver_port_index = 0,
			.logical_port_id = TEST_LOGICAL_PORT + port_index_,
			.mtu = 1500,
			.host_numa_node = 0,
			.direction = KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL,
			.has_host_numa_node = 1,
			.has_resolved_mac_address = 1,
			.direction_padding = 0,
			.resolved_mac_address = {TEST_MAC[0], TEST_MAC[1], TEST_MAC[2], TEST_MAC[3], TEST_MAC[4],
						 TEST_MAC[5]},
			.padding = {0},
		};
		streams_[0] = stream(0, 0, KINETUM_PROVIDER_IO_DIRECTION_RX);
		streams_[0].has_steering_profile = 1;
		streams_[0].steering_profile_index = port_index_;
		streams_[1] = stream(1, 0, KINETUM_PROVIDER_IO_DIRECTION_TX);
		steering_streams_[0] = streams_[0].io_stream_index;
		steering_[0] = kinetum_provider_steering_fact{
			.steering_profile_index = port_index_,
			.kind = KINETUM_PROVIDER_STEERING_NONE,
			.symmetric = 0,
			.kind_padding = {0},
			.hash_fields = nullptr,
			.hash_field_count = 0,
			.hash_field_padding = 0,
			.hash_key = {},
			.io_stream_indices = steering_streams_.data(),
			.io_stream_count = 1,
			.padding = {0},
		};
		facts_ = kinetum_provider_io_driver_facts{
			.io_driver_index = attachments_[0].io_driver_index,
			.index_padding = 0,
			.attachments = attachments_.data(),
			.attachment_count = static_cast<uint32_t>(attachments_.size()),
			.attachment_padding = 0,
			.ports = ports_.data(),
			.port_count = static_cast<uint32_t>(ports_.size()),
			.port_padding = 0,
			.streams = streams_.data(),
			.stream_count = 2,
			.stream_padding = 0,
			.steering_profiles = steering_.data(),
			.steering_profile_count = 1,
			.steering_padding = 0,
		};
		dependencies_[0] = facility.dependency();
		dependencies_[1] = storage.dependency();
		request_ = kinetum_provider_factory_request{
			.instance_id = text_view(instance_id_),
			.type_url = text_view(DPDK_DRIVER_TYPE_URL),
			.canonical_configuration = {},
			.compiled_facts =
				{
					.process_facility = nullptr,
					.io_driver = &facts_,
					.packet_storage = nullptr,
					.execution = nullptr,
					.storage_transition = nullptr,
				},
			.dependencies = dependencies_.data(),
			.dependency_count = 2,
			.dependency_padding = 0,
			.runtime_generation = 1,
			.role = KINETUM_PROVIDER_ROLE_IO_DRIVER,
			.padding = {0},
			.logging = logging_.capability(),
		};
	}

	/** @brief Remove the compiled NONE profile to exercise component-boundary refusal. */
	void remove_rx_steering_profile() noexcept
	{
		streams_[0].has_steering_profile = 0;
		facts_.steering_profiles = nullptr;
		facts_.steering_profile_count = 0;
	}

	/** @brief Mark NONE steering symmetric to exercise exact component refusal. */
	void make_none_steering_symmetric() noexcept
	{
		steering_[0].symmetric = 1;
	}

	/** @brief Retain only the exact RX stream and its required NONE steering row. */
	void retain_rx_only() noexcept
	{
		ports_[0].direction = KINETUM_PROVIDER_IO_DIRECTION_RX;
		facts_.stream_count = 1;
	}

	/** @brief Retain only one exact TX stream with no steering authority. */
	void retain_tx_only() noexcept
	{
		ports_[0].direction = KINETUM_PROVIDER_IO_DIRECTION_TX;
		streams_[0] = stream(0, 0, KINETUM_PROVIDER_IO_DIRECTION_TX);
		facts_.stream_count = 1;
		facts_.steering_profiles = nullptr;
		facts_.steering_profile_count = 0;
	}

	/** @brief Add an unmatched TX queue to exercise population rejection. */
	void add_tx_queue() noexcept
	{
		streams_[facts_.stream_count] = stream(facts_.stream_count, 1, KINETUM_PROVIDER_IO_DIRECTION_TX);
		++facts_.stream_count;
	}

	/**
	 * @brief Admit one additional exact pool to every TX queue without changing RX ownership.
	 * @param storage Second live pool retained through driver retirement.
	 */
	void admit_tx_storage(storage_fixture &storage) noexcept
	{
		dependencies_[2] = storage.dependency();
		request_.dependency_count = 3;
		tx_storage_domains_ = {0, storage.facts().storage_domain_index};
		for (uint32_t index = 0; index < facts_.stream_count; ++index) {
			auto &stream = streams_[index];
			if (stream.direction == KINETUM_PROVIDER_IO_DIRECTION_TX) {
				stream.storage_domain_indices = tx_storage_domains_.data();
				stream.storage_domain_count = static_cast<uint32_t>(tx_storage_domains_.size());
			}
		}
	}

	/** @brief Keep published native callbacks bound to one fixture owner. */
	io_driver_fixture(const io_driver_fixture &) = delete;
	/** @brief Forbid replacing request backing while a driver borrows it. */
	io_driver_fixture &operator=(const io_driver_fixture &) = delete;

	/** @brief Transform the request into exact two-queue ordinary i40e RSS. */
	void enable_rss() noexcept
	{
		for (std::size_t index = 0; index < rss_key_.size(); ++index) {
			rss_key_[index] = static_cast<uint8_t>(index + 1u + port_index_);
		}
		hash_fields_[0] = text_view("ipv4");
		hash_fields_[1] = text_view("udp");
		streams_[0].has_steering_profile = 1;
		streams_[0].steering_profile_index = port_index_;
		streams_[2] = stream(2, 1, KINETUM_PROVIDER_IO_DIRECTION_RX);
		streams_[2].has_steering_profile = 1;
		streams_[2].steering_profile_index = port_index_;
		streams_[3] = stream(3, 1, KINETUM_PROVIDER_IO_DIRECTION_TX);
		steering_streams_[0] = streams_[0].io_stream_index;
		steering_streams_[1] = streams_[2].io_stream_index;
		steering_[0] = kinetum_provider_steering_fact{
			.steering_profile_index = port_index_,
			.kind = KINETUM_PROVIDER_STEERING_RSS,
			.symmetric = 0,
			.kind_padding = {0},
			.hash_fields = hash_fields_.data(),
			.hash_field_count = static_cast<uint32_t>(hash_fields_.size()),
			.hash_field_padding = 0,
			.hash_key = {rss_key_.data(), static_cast<uint32_t>(rss_key_.size()), 0},
			.io_stream_indices = steering_streams_.data(),
			.io_stream_count = static_cast<uint32_t>(steering_streams_.size()),
			.padding = {0},
		};
		facts_.stream_count = 4;
		facts_.steering_profiles = steering_.data();
		facts_.steering_profile_count = 1;
	}

	/**
	 * @brief Construct and retain the exact native I/O owner.
	 * @tparam native_type Single-port or shared-adapter native fixture.
	 * @param native Fake ethdev state retained through driver retirement.
	 * @param diagnostic Optional caller-owned admission diagnostic.
	 * @return Production I/O-factory result; this fixture retains successful ownership.
	 */
	template <typename native_type>
	[[nodiscard]] kinetum_provider_status create(native_type &native,
						     kinetum_provider_diagnostic *diagnostic = nullptr) noexcept
	{
		return dpdk_io_driver::create(request_, ethdev_api(native), driver_, diagnostic);
	}

	/**
	 * @brief Invoke the exact whole-driver activation callback.
	 * @return Production activation status; a missing driver owner fails stop.
	 */
	[[nodiscard]] kinetum_provider_status activate() noexcept
	{
		if (driver_ == nullptr) {
			std::terminate();
		}
		std::array<char, 256> diagnostic_bytes{};
		kinetum_provider_diagnostic diagnostic{
			.data = diagnostic_bytes.data(),
			.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
			.size = 0,
		};
		const auto &operations = driver_->operations();
		return operations.activate_packet_io(operations.state, &diagnostic);
	}

	/**
	 * @brief Invoke the exact whole-driver deactivation callback.
	 * @return Production deactivation status; a missing driver owner fails stop.
	 */
	[[nodiscard]] kinetum_provider_status deactivate() noexcept
	{
		if (driver_ == nullptr) {
			std::terminate();
		}
		std::array<char, 256> diagnostic_bytes{};
		kinetum_provider_diagnostic diagnostic{
			.data = diagnostic_bytes.data(),
			.capacity = static_cast<uint32_t>(diagnostic_bytes.size()),
			.size = 0,
		};
		const auto &operations = driver_->operations();
		return operations.deactivate_packet_io(operations.state, &diagnostic);
	}

	/**
	 * @brief Return mutable exact stream facts for malformed-input cases.
	 * @param index Index below the fixture's fixed four-row storage size.
	 * @return Borrowed mutable stream row.
	 */
	[[nodiscard]] kinetum_provider_io_stream_fact &stream_fact(std::size_t index) noexcept
	{
		return streams_[index];
	}

	/** @return Mutable driver facts for explicit malformed-population cases. */
	[[nodiscard]] kinetum_provider_io_driver_facts &facts() noexcept
	{
		return facts_;
	}

	/** @return Mutable authored steering for focused admission failures. */
	[[nodiscard]] kinetum_provider_steering_fact &steering() noexcept
	{
		return steering_[0];
	}

	/** @return Reference to the fixture's retained native driver owner. */
	[[nodiscard]] std::unique_ptr<dpdk_io_driver> &driver() noexcept
	{
		return driver_;
	}

	/**
	 * @brief Select a cold log receiver for the next factory invocation.
	 * @param logging Capability whose owner outlives the resulting driver.
	 */
	void use_logging(kinetum_provider_cold_log logging) noexcept
	{
		request_.logging = logging;
	}

    private:
	/**
	 * @brief Construct one exact stream row.
	 * @param index Stream and stage-instance ordinal within this fixture port.
	 * @param queue Native queue and worker identity.
	 * @param direction RX or TX stream direction.
	 * @return Compiled fixture row with the fixed descriptor count and storage set.
	 */
	kinetum_provider_io_stream_fact stream(uint32_t index, uint32_t queue,
					       kinetum_provider_io_direction direction) const noexcept
	{
		return kinetum_provider_io_stream_fact{
			.io_stream_index = 4 * port_index_ + index,
			.port_index = port_index_,
			.stage_instance_index = 4 * port_index_ + index,
			.worker_index = queue,
			.driver_queue_id = queue,
			.descriptor_count = TEST_DESCRIPTOR_COUNT,
			.steering_profile_index = 0,
			.direction = direction,
			.has_steering_profile = 0,
			.padding = {0},
			.storage_domain_indices = STORAGE_DOMAINS.data(),
			.storage_domain_count = static_cast<uint32_t>(STORAGE_DOMAINS.size()),
			.storage_padding = 0,
		};
	}

	uint32_t port_index_;	   ///< Exact global port identity used by every fixture row.
	std::string instance_id_;  ///< Stable driver identity borrowed by the request.
	static constexpr std::array<uint32_t, 1> STORAGE_DOMAINS{0};  ///< Exact fixture allocation/admission set.

	std::array<kinetum_provider_driver_attachment_fact, 1> attachments_{};	///< Exact native port.
	std::array<kinetum_provider_io_port_fact, 1> ports_{};			///< Exact logical port.
	std::array<kinetum_provider_io_stream_fact, 4> streams_{};		///< Bounded RX/TX queues.
	std::array<kinetum_provider_text_view, 2> hash_fields_{};		///< Exact RSS field order.
	std::array<uint8_t, TEST_RSS_KEY_SIZE> rss_key_{};			///< Exact deterministic PMD key.
	std::array<uint32_t, 2> steering_streams_{};				///< Exact governed RX stream set.
	std::array<kinetum_provider_steering_fact, 1> steering_{};		///< Optional exact RSS row.
	kinetum_provider_io_driver_facts facts_{};				///< Complete role-specific fact tree.
	std::array<uint32_t, 2> tx_storage_domains_{};				///< Stable mixed-pool TX admission.
	std::array<kinetum_provider_dependency_handle, 3> dependencies_{};	///< Facility then exact storage set.
	kinetum_provider_factory_request request_{};				///< Exact driver factory request.
	kinetum::test_support::provider_log_capture logging_;			///< Retained cold diagnostic receiver.
	std::unique_ptr<dpdk_io_driver> driver_;				///< Retained ethdev ownership.
};

/** @brief Borrow two distinct port fact trees as one complete driver request. */
struct paired_driver_facts {
	std::array<kinetum_provider_driver_attachment_fact, 2> attachments;  ///< Exact facility-owned attachments.
	std::array<kinetum_provider_io_port_fact, 2> ports;  ///< Distinct global ports and local attachment positions.
	std::array<kinetum_provider_io_stream_fact, 8> streams{};  ///< Complete RX/TX facts from both ports.
	std::array<kinetum_provider_steering_fact, 2> steering;	   ///< Independent per-port steering authorities.

	/**
	 * @brief Combine two same-driver port fixtures while retaining their borrowed key and queue backing.
	 * @param first Initial port fixture whose request receives the combined facts.
	 * @param second Second port fixture retaining its key and steering-stream backing.
	 */
	paired_driver_facts(io_driver_fixture &first, io_driver_fixture &second)
	{
		auto &left = first.facts();
		const auto &right = second.facts();
		attachments = {*left.attachments, *right.attachments};
		ports = {*left.ports, *right.ports};
		ports[1].driver_port_index = 1;
		steering = {*left.steering_profiles, *right.steering_profiles};
		std::copy_n(left.streams, left.stream_count, streams.begin());
		std::copy_n(right.streams, right.stream_count, streams.begin() + left.stream_count);
		left.attachments = attachments.data();
		left.attachment_count = 2;
		left.ports = ports.data();
		left.port_count = 2;
		left.streams = streams.data();
		left.stream_count += right.stream_count;
		left.steering_profiles = steering.data();
		left.steering_profile_count = 2;
	}
};

/** @brief Verify retained native ownership when the failed-start diagnostic is emitted. */
struct native_start_failure_evidence {
	const ethdev_adapter &adapter;	///< Native claims, including the failed start.
	const mempool_state &pool;	///< Dependency that must remain owned.
	std::size_t failed_port;	///< Exact attempted prefix endpoint.
	std::string message;		///< Independent expected diagnostic.

	/**
	 * @brief Reject a wrong diagnostic or prior cleanup with the death test's nonmatching exit code.
	 * @param context Borrowed evidence retained through driver destruction.
	 * @param level Native fatal severity.
	 * @param event Exact failed-start event identity.
	 * @param function Actual termination helper name.
	 * @param message Complete bounded port/result diagnostic.
	 */
	static void receive(void *context, kinetum_provider_log_level level, kinetum_provider_text_view event,
			    kinetum_provider_text_view function, kinetum_provider_text_view message) noexcept
	{
		const auto &wanted = *static_cast<const native_start_failure_evidence *>(context);
		if (level != KINETUM_PROVIDER_LOG_CRITICAL || !kinetum_provider_text_view_is_valid(event) ||
		    !kinetum_provider_text_view_is_valid(function) || !kinetum_provider_text_view_is_valid(message) ||
		    std::string_view(event.data, event.size) != "dpdk.port.start_failed" ||
		    std::string_view(function.data, function.size) != "fail_stop_native_start" ||
		    std::string_view(message.data, message.size) != wanted.message || wanted.pool.free_calls != 0u) {
			std::_Exit(0);
		}
		for (std::size_t index = 0; index < wanted.adapter.ports.size(); ++index) {
			const auto &port = wanted.adapter.ports[index];
			if (port.start_entered != (index <= wanted.failed_port) ||
			    port.started != (index < wanted.failed_port) || port.stop_calls != 0u ||
			    port.close_calls != 0u) {
				std::_Exit(0);
			}
		}
		std::fputs("verified cold native-start diagnostic\n", stderr);
	}
};

/**
 * @brief Return the index of one exact event, or the event count when absent.
 * @param events Ordered native ownership trace.
 * @param event Exact event spelling to locate.
 * @return First matching ordinal, or events.size() when absent.
 */
std::size_t event_index(const std::vector<std::string> &events, std::string_view event)
{
	const auto found = std::find(events.begin(), events.end(), event);
	return static_cast<std::size_t>(std::distance(events.begin(), found));
}

}  // namespace

/** @brief Verify exactly sized, cache-aligned private storage admits record placement. */
TEST(dpdk_io, packet_record_private_area_accepts_exact_aligned_storage)
{
	alignas(kinetum_packet_record) std::array<std::byte, sizeof(kinetum_packet_record)> private_area{};

	const auto status = dp::validate_dpdk_packet_record_private_area(private_area.size(), private_area.data());

	EXPECT_TRUE(status.is_ok()) << status.to_string();
}

/** @brief Verify undersized, null, and misaligned private areas fail distinctly. */
TEST(dpdk_io, packet_record_private_area_rejects_every_invalid_shape)
{
	alignas(kinetum_packet_record) std::array<std::byte, sizeof(kinetum_packet_record) + 1> private_area{};

	const auto undersized =
		dp::validate_dpdk_packet_record_private_area(sizeof(kinetum_packet_record) - 1, private_area.data());
	const auto null_address = dp::validate_dpdk_packet_record_private_area(sizeof(kinetum_packet_record), nullptr);
	const auto misaligned =
		dp::validate_dpdk_packet_record_private_area(sizeof(kinetum_packet_record), private_area.data() + 1);

	EXPECT_NE(undersized.message().find("smaller than packet_record"), std::string::npos);
	EXPECT_NE(null_address.message().find("null packet_record private area"), std::string::npos);
	EXPECT_NE(misaligned.message().find("cache-aligned packet_record"), std::string::npos);
}

/** @brief Prove malformed nonempty DPDK TX fails stop before native submission. */
TEST(dpdk_io, tx_rejects_malformed_nonempty_burst)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	const auto &operations = driver.driver()->operations().tx_queues[0];
	std::array<kinetum_packet_record *, 1> records{};

	EXPECT_DEATH({ (void)operations.transmit_burst(operations.state, nullptr, 1); }, "");
	EXPECT_DEATH(
		{
			(void)operations.transmit_burst(operations.state, records.data(),
							static_cast<uint16_t>(operations.maximum_burst + 1u));
		},
		"");
}

/** @brief Each native RSS receive queue receives its own declared allocation pool. */
TEST(dpdk_io, rss_receive_queues_materialize_distinct_allocation_pools)
{
	constexpr std::array<uint32_t, 1> SECOND_STORAGE{1};
	facility_fixture facility;
	facility.add_packet_worker(1, 4);
	facility.add_memory_domain(1);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state first_pool;
	mempool_state second_pool;
	storage_fixture first(facility);
	storage_fixture second(facility, 1);
	ASSERT_EQ(first.create(first_pool), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(second.create(second_pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, first);
	driver.enable_rss();
	driver.admit_tx_storage(second);
	driver.stream_fact(2).storage_domain_indices = SECOND_STORAGE.data();
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(native.configured_rx_queues, 2u);
	EXPECT_EQ(native.configured_tx_queues, 2u);
	EXPECT_EQ(native.rx_pools[0], &first_pool.pool);
	EXPECT_EQ(native.rx_pools[1], &second_pool.pool);
	EXPECT_EQ(driver.driver()->operations().rx_queue_count, 2u);
}

/** @brief An incomplete accepted-domain dependency set rejects before native configuration. */
TEST(dpdk_io, missing_tx_storage_dependency_rejects_before_native_effects)
{
	constexpr std::array<uint32_t, 2> ADMITTED_STORAGE{0, 1};
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	driver.stream_fact(1).storage_domain_indices = ADMITTED_STORAGE.data();
	driver.stream_fact(1).storage_domain_count = static_cast<uint32_t>(ADMITTED_STORAGE.size());
	EXPECT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_EQ(driver.driver(), nullptr);
	EXPECT_EQ(native.configure_calls, 0u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(native.close_calls, 0u);
}

/** @brief Mixed-pool TX preserves native mbuf order and ownership across partial acceptance. */
TEST(dpdk_io, mixed_pool_tx_preserves_original_mbufs_and_accepted_prefix)
{
	facility_fixture facility;
	facility.add_memory_domain(1);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state first_pool;
	mempool_state second_pool;
	storage_fixture first(facility);
	storage_fixture second(facility, 1);
	ASSERT_EQ(first.create(first_pool), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(second.create(second_pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, first);
	driver.admit_tx_storage(second);
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	const auto &tx = driver.driver()->operations().tx_queues[0];
	std::array<rte_mbuf *, 3> mbufs{&first_pool.objects[0].mbuf, &second_pool.objects[0].mbuf,
					&first_pool.objects[1].mbuf};
	std::array<kinetum_packet_record *, 3> records{};
	for (std::size_t index = 0; index < mbufs.size(); ++index) {
		mbufs[index]->pkt_len = 64;
		mbufs[index]->data_len = 64;
		records[index] = dp::initialize_dpdk_packet_record(
			mbufs[index], index == 1 ? second.storage()->operations() : first.storage()->operations());
	}

	native_transmit_fixture dispatch(2);
	EXPECT_EQ(tx.transmit_burst(tx.state, records.data(), static_cast<uint16_t>(records.size())), 2u);
	ASSERT_EQ(dispatch.submitted().size(), mbufs.size());
	EXPECT_TRUE(std::equal(dispatch.submitted().begin(), dispatch.submitted().end(), mbufs.begin()));
	EXPECT_EQ(mbufs[0]->pool, &first_pool.pool);
	EXPECT_EQ(mbufs[1]->pool, &second_pool.pool);
	EXPECT_TRUE(dp::dpdk_packet_record_matches_storage(records[2], first.storage()->operations()));
	EXPECT_EQ(tx.transmit_burst(tx.state, records.data() + 2, 1), 1u);
	ASSERT_EQ(dispatch.submitted().size(), 1u);
	EXPECT_EQ(dispatch.submitted()[0], mbufs[2]);
}

/** @brief A forged native pool stops TX at the first invalid record and preserves its suffix. */
TEST(dpdk_io, mixed_pool_tx_rejects_native_pool_disagreement)
{
	facility_fixture facility;
	facility.add_memory_domain(1);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state first_pool;
	mempool_state second_pool;
	storage_fixture first(facility);
	storage_fixture second(facility, 1);
	ASSERT_EQ(first.create(first_pool), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(second.create(second_pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, first);
	driver.admit_tx_storage(second);
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	const auto &tx = driver.driver()->operations().tx_queues[0];
	std::array<kinetum_packet_record *, 3> records{};
	for (std::size_t index = 0; index < records.size(); ++index) {
		auto *mbuf = &first_pool.objects[index].mbuf;
		mbuf->pkt_len = 64;
		mbuf->data_len = 64;
		records[index] = dp::initialize_dpdk_packet_record(mbuf, first.storage()->operations());
	}
	first_pool.objects[1].mbuf.pool = &second_pool.pool;
	native_transmit_fixture dispatch(3);
	EXPECT_EQ(tx.transmit_burst(tx.state, records.data(), static_cast<uint16_t>(records.size())), 1u);
	ASSERT_EQ(dispatch.submitted().size(), 1u);
	EXPECT_EQ(records[1]->storage.operations, &first.storage()->operations());
	EXPECT_EQ(records[2]->storage.length, 64u);
}

/** @brief A native single-pool fast-free mode rejects multi-pool admission before configuration. */
TEST(dpdk_io, mixed_pool_tx_rejects_fast_free_before_native_effects)
{
	facility_fixture facility;
	facility.add_memory_domain(1);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state first_pool;
	mempool_state second_pool;
	storage_fixture first(facility);
	storage_fixture second(facility, 1);
	ASSERT_EQ(first.create(first_pool), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(second.create(second_pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	native.tx_offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
	io_driver_fixture driver(facility, first);
	driver.admit_tx_storage(second);
	EXPECT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(driver.driver(), nullptr);
	EXPECT_EQ(native.configure_calls, 0u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(native.close_calls, 0u);
}

/** @brief Prove exact storage construction inspects every native object before publication. */
TEST(dpdk_io, storage_materializes_exact_population_and_retires_once)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state native;
	storage_fixture storage(facility);

	ASSERT_EQ(storage.create(native), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_NE(storage.storage(), nullptr);
	EXPECT_EQ(native.create_calls, 1u);
	EXPECT_EQ(native.iterate_calls, 1u);
	EXPECT_EQ(native.requested_count, TEST_BUFFER_COUNT);
	EXPECT_EQ(native.requested_private_size, sizeof(kinetum_packet_record));
	EXPECT_EQ(native.requested_data_room, TEST_DATA_ROOM_BYTES);
	EXPECT_EQ(native.requested_socket, 0);
	EXPECT_EQ(storage.storage()->operations().domain_index, 0u);
	EXPECT_EQ(storage.storage()->operations().maximum_packet_length, TEST_MAXIMUM_PACKET_LENGTH);
	storage.storage().reset();
	EXPECT_EQ(native.free_calls, 1u);
}

/** @brief Reject an undersized private area and reclaim the unexposed native pool. */
TEST(dpdk_io, storage_private_area_failure_reclaims_candidate_before_publication)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state native;
	storage_fixture storage(facility);
	native.reported_private_size = static_cast<uint16_t>(sizeof(kinetum_packet_record) - 1u);

	const auto status = storage.create(native);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(storage.storage(), nullptr);
	EXPECT_EQ(native.create_calls, 1u);
	EXPECT_EQ(native.iterate_calls, 0u);
	EXPECT_EQ(native.free_calls, 1u);
}

/** @brief Publish one approximate typed DPDK storage occupancy observation. */
TEST(dpdk_io, storage_observation_preserves_exact_identity_and_typed_occupancy)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state native;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(native), KINETUM_PROVIDER_STATUS_OK);
	native.in_use = 3u;
	kinetum_provider_storage_observation observation{};
	const auto &operations = storage.storage()->operations();
	EXPECT_EQ(operations.observe_statistics(operations.state, &observation, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(observation.runtime_generation, 1u);
	EXPECT_EQ(observation.storage_domain_index, 0u);
	EXPECT_EQ(observation.state, KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE);
	EXPECT_EQ(observation.in_use, 3u);
	EXPECT_EQ(observation.available, TEST_BUFFER_COUNT - 3u);
	// The injected count models an observation only; no fake object left the pool.
	native.in_use = 0u;
	storage.storage().reset();
	EXPECT_EQ(native.free_calls, 1u);
}

/** @brief Materialize one cold queue set, activate it, then retire stop-before-close. */
TEST(dpdk_io, driver_materializes_exact_queue_operations_and_reverse_order_retirement)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);

	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_NE(driver.driver(), nullptr);
	const auto &operations = driver.driver()->operations();
	ASSERT_EQ(operations.rx_queue_count, 1u);
	ASSERT_EQ(operations.tx_queue_count, 1u);
	EXPECT_EQ(operations.rx_queues[0].logical_port, TEST_LOGICAL_PORT);
	EXPECT_EQ(operations.tx_queues[0].logical_port, TEST_LOGICAL_PORT);
	EXPECT_EQ(native.configured_rx_queues, 1u);
	EXPECT_EQ(native.configured_tx_queues, 1u);
	EXPECT_EQ(native.configured_mtu, 1500u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(event_index(native.events, "start"), native.events.size());
	ASSERT_NE(operations.activate_packet_io, nullptr);
	ASSERT_NE(operations.deactivate_packet_io, nullptr);
	ASSERT_EQ(driver.activate(), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
	driver.driver().reset();
	EXPECT_EQ(native.hash_read_calls, 0u);
	EXPECT_EQ(native.reta_read_calls, 0u);
	EXPECT_EQ(native.stop_calls, 1u);
	EXPECT_EQ(native.close_calls, 1u);
	EXPECT_LT(event_index(native.events, "stop"), event_index(native.events, "close"));
}

/** @brief Publish native port counters independently of absent native queue statistics. */
TEST(dpdk_io, driver_observation_is_whole_typed_and_port_exact)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	native.statistics.ipackets = 100u;
	native.statistics.opackets = 90u;
	native.statistics.ibytes = 6400u;
	native.statistics.obytes = 5760u;
	native.statistics.imissed = 2u;
	native.statistics.ierrors = 3u;
	native.statistics.oerrors = 4u;
	native.statistics.rx_nombuf = 5u;
	io_driver_fixture driver(facility, storage);
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	std::array<kinetum_provider_port_observation, 1> ports{};
	kinetum_provider_io_observation_batch batch{
		.ports = ports.data(),
		.port_count = static_cast<uint32_t>(ports.size()),
		.port_padding = 0u,
		.padding = {},
	};
	const auto &operations = driver.driver()->operations();
	ASSERT_EQ(operations.observe_statistics(operations.state, &batch, nullptr), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(native.statistics_calls, 1u);
	EXPECT_EQ(ports[0].port_index, 0u);
	EXPECT_EQ(ports[0].state, KINETUM_PROVIDER_OBSERVATION_AVAILABLE_EXACT);
	EXPECT_EQ(ports[0].rx_packets, 100u);
	EXPECT_EQ(ports[0].rx_no_buffer, 5u);
}

/** @brief Native RX compacts valid records and reports each rejected packet, including a segmented input. */
TEST(dpdk_io, native_receive_reports_transfers_and_rejections_without_queue_statistics)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(driver.activate(), KINETUM_PROVIDER_STATUS_OK);
	for (std::size_t index = 0; index < 5u; ++index) {
		auto &mbuf = pool.objects[index].mbuf;
		// Retain a fixture reference so the production free operation can be
		// observed without returning fixture-owned memory to a native pool.
		rte_mbuf_refcnt_set(&mbuf, 2u);
		mbuf.data_len = 32u;
		mbuf.pkt_len = 32u;
	}
	pool.objects[1].mbuf.data_len = 0u;
	pool.objects[1].mbuf.pkt_len = 0u;
	pool.objects[2].mbuf.data_len = TEST_MAXIMUM_PACKET_LENGTH + 1u;
	pool.objects[2].mbuf.pkt_len = TEST_MAXIMUM_PACKET_LENGTH + 1u;
	pool.objects[3].mbuf.nb_segs = 2u;
	pool.objects[3].mbuf.pkt_len = 64u;
	pool.objects[3].mbuf.next = &pool.objects[4].mbuf;
	std::array<rte_mbuf *, 4> input{
		&pool.objects[1].mbuf,
		&pool.objects[2].mbuf,
		&pool.objects[3].mbuf,
		&pool.objects[0].mbuf,
	};
	kinetum_packet_record *records[4]{};
	const auto &rx = driver.driver()->operations().rx_queues[0];
	{
		native_receive_fixture dispatch(input);
		const auto result = rx.receive_burst(rx.state, records, 4u);
		EXPECT_EQ(result.transferred_count, 1u);
		EXPECT_EQ(result.rejected_count, 3u);
		const bool valid = kinetum_packet_rx_burst_result_is_valid(result, 4u) != 0;
		EXPECT_TRUE(valid);
		if (valid && result.transferred_count != 0u) {
			EXPECT_EQ(records[0]->storage.native_handle, &pool.objects[0].mbuf);
			const auto &operations = storage.storage()->operations();
			operations.release_burst(operations.state, records, result.transferred_count);
		}
		std::fill(std::begin(records), std::end(records), nullptr);
		const auto empty = rx.receive_burst(rx.state, records, 4u);
		EXPECT_EQ(empty.transferred_count, 0u);
		EXPECT_EQ(empty.rejected_count, 0u);
	}
	for (std::size_t index = 0; index < 5u; ++index) {
		EXPECT_EQ(rte_mbuf_refcnt_read(&pool.objects[index].mbuf), 1u);
	}
	for (std::size_t index = 1; index < 5u; ++index) {
		rte_mbuf_refcnt_set(&pool.objects[index].mbuf, 2u);
	}
	std::fill(std::begin(records), std::end(records), nullptr);
	{
		native_receive_fixture dispatch(std::span<rte_mbuf *const>(input).first(3u));
		const auto result = rx.receive_burst(rx.state, records, 3u);
		EXPECT_EQ(result.transferred_count, 0u);
		EXPECT_EQ(result.rejected_count, 3u);
		EXPECT_TRUE(std::all_of(std::begin(records), std::end(records),
					[](const auto *record) { return record == nullptr; }));
	}
	for (std::size_t index = 1; index < 5u; ++index) {
		EXPECT_EQ(rte_mbuf_refcnt_read(&pool.objects[index].mbuf), 1u);
	}
	EXPECT_EQ(native.statistics_calls, 0u);
	EXPECT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
}

/** @brief One-sided drivers publish null operation pointers for their exact zero-count role. */
TEST(dpdk_io, one_sided_driver_operation_tables_obey_zero_count_nullability)
{
	{
		facility_fixture facility;
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		io_driver_fixture driver(facility, storage);
		driver.retain_rx_only();

		ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
		const auto &operations = driver.driver()->operations();
		EXPECT_EQ(operations.rx_queue_count, 1u);
		EXPECT_NE(operations.rx_queues, nullptr);
		EXPECT_EQ(operations.tx_queue_count, 0u);
		EXPECT_EQ(operations.tx_queues, nullptr);
		EXPECT_EQ(native.configured_rx_queues, 1u);
		EXPECT_EQ(native.configured_tx_queues, 0u);
		EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&operations), 1u);
	}

	{
		facility_fixture facility;
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		io_driver_fixture driver(facility, storage);
		driver.retain_tx_only();

		ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
		const auto &operations = driver.driver()->operations();
		EXPECT_EQ(operations.rx_queue_count, 0u);
		EXPECT_EQ(operations.rx_queues, nullptr);
		EXPECT_EQ(operations.tx_queue_count, 1u);
		EXPECT_NE(operations.tx_queues, nullptr);
		EXPECT_EQ(native.configured_rx_queues, 0u);
		EXPECT_EQ(native.configured_tx_queues, 1u);
		EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&operations), 1u);
	}
}

/** @brief TAP pairs native queues while publishing only the authored packet directions. */
TEST(dpdk_io, tap_queue_pairs_preserve_authored_operation_directions)
{
	for (const auto direction : {KINETUM_PROVIDER_IO_DIRECTION_RX, KINETUM_PROVIDER_IO_DIRECTION_TX,
				     KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL}) {
		SCOPED_TRACE(static_cast<uint32_t>(direction));
		facility_fixture facility;
		facility.use_tap_attachment();
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		native.require_queue_pairs = true;
		io_driver_fixture driver(facility, storage);
		if (direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
			driver.retain_rx_only();
		} else if (direction == KINETUM_PROVIDER_IO_DIRECTION_TX) {
			driver.retain_tx_only();
		}

		ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
		const auto &operations = driver.driver()->operations();
		EXPECT_EQ(operations.rx_queue_count, direction == KINETUM_PROVIDER_IO_DIRECTION_TX ? 0u : 1u);
		EXPECT_EQ(operations.tx_queue_count, direction == KINETUM_PROVIDER_IO_DIRECTION_RX ? 0u : 1u);
		EXPECT_EQ(operations.rx_queues == nullptr, direction == KINETUM_PROVIDER_IO_DIRECTION_TX);
		EXPECT_EQ(operations.tx_queues == nullptr, direction == KINETUM_PROVIDER_IO_DIRECTION_RX);
		EXPECT_EQ(kinetum_provider_io_driver_operations_are_valid(&operations), 1u);
		EXPECT_EQ(native.configured_rx_queues, 1u);
		EXPECT_EQ(native.configured_tx_queues, 1u);
		EXPECT_EQ(native.rx_pools[0], &pool.pool);
		EXPECT_EQ(native.rx_descriptors[0], TEST_DESCRIPTOR_COUNT);
		EXPECT_EQ(native.tx_descriptors[0], TEST_DESCRIPTOR_COUNT);
		EXPECT_LT(event_index(native.events, "rx0"), event_index(native.events, "tx0"));
		ASSERT_EQ(driver.activate(), KINETUM_PROVIDER_STATUS_OK);
		ASSERT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
		driver.driver().reset();
		EXPECT_EQ(native.hash_read_calls, 0u);
		EXPECT_EQ(native.reta_read_calls, 0u);
		EXPECT_EQ(native.stop_calls, 1u);
		EXPECT_EQ(native.close_calls, 1u);
	}
}

/** @brief TX-only TAP pairs follow native queue IDs even when authored stream order differs. */
TEST(dpdk_io, tap_queue_pairs_follow_native_queue_order)
{
	facility_fixture facility;
	facility.use_tap_attachment();
	facility.add_packet_worker(1, 4);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	native.require_queue_pairs = true;
	io_driver_fixture driver(facility, storage);
	driver.retain_tx_only();
	driver.add_tx_queue();
	std::swap(driver.stream_fact(0).driver_queue_id, driver.stream_fact(1).driver_queue_id);

	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(native.configured_rx_queues, 2u);
	EXPECT_EQ(native.configured_tx_queues, 2u);
	EXPECT_EQ(driver.driver()->operations().rx_queue_count, 0u);
	EXPECT_EQ(driver.driver()->operations().tx_queue_count, 2u);
	for (std::size_t queue = 0; queue < 2u; ++queue) {
		EXPECT_EQ(native.rx_pools[queue], &pool.pool);
		EXPECT_EQ(native.rx_descriptors[queue], TEST_DESCRIPTOR_COUNT);
		EXPECT_EQ(native.tx_descriptors[queue], TEST_DESCRIPTOR_COUNT);
	}
	EXPECT_LT(event_index(native.events, "rx0"), event_index(native.events, "rx1"));
	EXPECT_LT(event_index(native.events, "rx1"), event_index(native.events, "tx0"));
	EXPECT_LT(event_index(native.events, "tx0"), event_index(native.events, "tx1"));
}

/** @brief Every bidirectional port requires the compiled equal RX/TX populations. */
TEST(dpdk_io, unequal_bidirectional_queue_populations_reject_before_native_configuration)
{
	for (const bool tap : {false, true}) {
		for (const bool more_rx : {false, true}) {
			SCOPED_TRACE(tap);
			SCOPED_TRACE(more_rx);
			facility_fixture facility;
			if (tap) {
				facility.use_tap_attachment();
			}
			facility.add_packet_worker(1, 4);
			ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
			mempool_state pool;
			storage_fixture storage(facility);
			ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
			ethdev_state native;
			native.require_queue_pairs = tap;
			io_driver_fixture driver(facility, storage);
			if (more_rx) {
				driver.enable_rss();
				driver.facts().stream_count = 3;
			} else {
				driver.add_tx_queue();
			}
			EXPECT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
			EXPECT_EQ(driver.driver(), nullptr);
			EXPECT_EQ(native.configure_calls, 0u);
			EXPECT_EQ(native.close_calls, 0u);
		}
	}
}

/** @brief Queue populations cannot wrap into the native sixteen-bit count. */
TEST(dpdk_io, oversized_queue_population_rejects_before_native_narrowing)
{
	constexpr uint32_t QUEUE_COUNT = static_cast<uint32_t>(UINT16_MAX) + 1u;
	for (const bool tap : {false, true}) {
		SCOPED_TRACE(tap);
		facility_fixture facility;
		if (tap) {
			facility.use_tap_attachment();
		}
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		native.require_queue_pairs = tap;
		native.maximum_rx_queues = UINT16_MAX;
		native.maximum_tx_queues = UINT16_MAX;
		io_driver_fixture driver(facility, storage);
		driver.retain_tx_only();
		std::vector<kinetum_provider_io_stream_fact> streams(QUEUE_COUNT, driver.stream_fact(0));
		for (uint32_t index = 0; index < QUEUE_COUNT; ++index) {
			streams[index].io_stream_index = index;
			streams[index].stage_instance_index = index;
			streams[index].driver_queue_id = index;
		}
		driver.facts().streams = streams.data();
		driver.facts().stream_count = QUEUE_COUNT;
		EXPECT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
		EXPECT_EQ(driver.driver(), nullptr);
		EXPECT_EQ(native.configure_calls, 0u);
		EXPECT_EQ(native.close_calls, 0u);
	}
}

/** @brief A TX-only TAP pair uses a canonical admitted pool without inventing domain zero. */
TEST(dpdk_io, tap_tx_pair_uses_first_admitted_storage_domain)
{
	constexpr std::array<uint32_t, 2> ADMITTED_DOMAINS{1, 3};
	facility_fixture facility;
	facility.use_tap_attachment();
	facility.memory_domain().storage_domain_index = ADMITTED_DOMAINS[0];
	facility.add_memory_domain(ADMITTED_DOMAINS[1]);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state first_pool;
	mempool_state second_pool;
	storage_fixture first(facility, ADMITTED_DOMAINS[0]);
	storage_fixture second(facility, ADMITTED_DOMAINS[1]);
	ASSERT_EQ(first.create(first_pool), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(second.create(second_pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	native.require_queue_pairs = true;
	io_driver_fixture driver(facility, first);
	driver.retain_tx_only();
	driver.admit_tx_storage(second);
	driver.stream_fact(0).storage_domain_indices = ADMITTED_DOMAINS.data();

	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(native.rx_pools[0], &first_pool.pool);
	EXPECT_EQ(native.rx_descriptors[0], driver.stream_fact(0).descriptor_count);
	EXPECT_EQ(native.tx_descriptors[0], driver.stream_fact(0).descriptor_count);
	EXPECT_EQ(driver.driver()->operations().rx_queue_count, 0u);
	EXPECT_EQ(driver.driver()->operations().rx_queues, nullptr);
	EXPECT_EQ(driver.driver()->operations().tx_queue_count, 1u);
}

/** @brief TAP counterpart queue and descriptor limits reject before native configuration. */
TEST(dpdk_io, tap_counterpart_limits_reject_before_ethdev_configuration)
{
	for (const bool receive_only : {false, true}) {
		for (const bool descriptor_limit : {false, true}) {
			SCOPED_TRACE(receive_only);
			SCOPED_TRACE(descriptor_limit);
			facility_fixture facility;
			facility.use_tap_attachment();
			ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
			mempool_state pool;
			storage_fixture storage(facility);
			ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
			ethdev_state native;
			native.require_queue_pairs = true;
			io_driver_fixture driver(facility, storage);
			if (receive_only) {
				driver.retain_rx_only();
			} else {
				driver.retain_tx_only();
			}
			auto &maximum_descriptors = receive_only ? native.maximum_tx_descriptors :
								   native.maximum_rx_descriptors;
			auto &maximum_queues = receive_only ? native.maximum_tx_queues : native.maximum_rx_queues;
			if (descriptor_limit) {
				maximum_descriptors = TEST_DESCRIPTOR_COUNT / 2u;
			} else {
				maximum_queues = 0;
			}

			EXPECT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
			EXPECT_EQ(driver.driver(), nullptr);
			EXPECT_EQ(native.configure_calls, 0u);
			EXPECT_EQ(native.close_calls, 0u);
		}
	}
}

/** @brief Failed TAP counterpart setup closes the native port before its pool can retire. */
TEST(dpdk_io, tap_counterpart_setup_failure_retires_configured_port)
{
	for (const bool receive_only : {false, true}) {
		SCOPED_TRACE(receive_only);
		facility_fixture facility;
		facility.use_tap_attachment();
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		native.require_queue_pairs = true;
		io_driver_fixture driver(facility, storage);
		if (receive_only) {
			driver.retain_rx_only();
			native.tx_setup_result = -1;
		} else {
			driver.retain_tx_only();
			native.rx_setup_result = -1;
		}

		EXPECT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR);
		EXPECT_EQ(driver.driver(), nullptr);
		EXPECT_EQ(native.configure_calls, 1u);
		EXPECT_EQ(native.stop_calls, 0u);
		EXPECT_EQ(native.close_calls, 1u);
		EXPECT_EQ(native.events.back(), "close");
		EXPECT_EQ(pool.free_calls, 0u);
		storage.storage().reset();
		EXPECT_EQ(pool.free_calls, 1u);
	}
}

/** @brief A native close failure cannot make unresolved configured ownership recoverable. */
TEST(dpdk_io, driver_retirement_failure_fails_stop_with_unresolved_ownership)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	for (const int result : {-1, 1}) {
		native.close_result = result;
		EXPECT_DEATH({ driver.driver().reset(); }, "DPDK port [0-9]+ close failed");
	}

	// The death-test child owns the failed retirement. Restore the parent copy
	// so its independently retained exact generation can retire normally.
	native.close_result = 0;
}

/** @brief A failed stop suppresses close while the native port remains started. */
TEST(dpdk_io, driver_failed_stop_suppresses_close_without_releasing_ownership)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_EQ(driver.activate(), KINETUM_PROVIDER_STATUS_OK);
	native.stop_result = -1;
	native.exit_success_on_close = true;

	// Install the termination observer only after the intended stop failure.
	// An earlier abort or an incorrect close cannot satisfy the expected exit.
	EXPECT_EXIT(
		{
			if (driver.deactivate() != KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR ||
			    native.stop_calls != 1u || !native.started || native.close_calls != 0u) {
				std::_Exit(0);
			}
			std::set_terminate([] { std::_Exit(86); });
			driver.driver().reset();
			std::_Exit(0);
		},
		::testing::ExitedWithCode(86), "");

	native.stop_result = 0;
	native.exit_success_on_close = false;
	ASSERT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
}

/** @brief A single RX queue still requires its compiler-owned exact NONE steering row. */
TEST(dpdk_io, driver_rejects_single_rx_queue_without_exact_steering_profile)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	driver.remove_rx_steering_profile();

	const auto status = driver.create(native);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_EQ(driver.driver(), nullptr);
	EXPECT_EQ(native.configure_calls, 0u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(native.close_calls, 0u);
}

/** @brief NONE steering cannot carry a contradictory symmetric-RSS claim. */
TEST(dpdk_io, driver_rejects_symmetric_none_steering_before_native_effects)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	driver.make_none_steering_symmetric();

	const auto status = driver.create(native);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_EQ(driver.driver(), nullptr);
	EXPECT_EQ(native.configure_calls, 0u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(native.close_calls, 0u);
}

/** @brief Descriptor incompatibility rejects before the first native side effect. */
TEST(dpdk_io, descriptor_mismatch_rejects_before_ethdev_configuration)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	driver.stream_fact(0).descriptor_count = 65;

	const auto status = driver.create(native);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(native.configure_calls, 0u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(native.close_calls, 0u);
}

/** @brief Failure after configure closes the claimed port without a false stop. */
TEST(dpdk_io, mtu_failure_closes_configured_port_without_stopping_unstarted_port)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	native.mtu_result = -1;

	const auto status = driver.create(native);

	EXPECT_EQ(status, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	EXPECT_EQ(native.configure_calls, 1u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(native.close_calls, 1u);
	EXPECT_EQ(native.events.back(), "close");
}

/** @brief Native start failure reports its cause and terminates before rollback or destruction. */
TEST(dpdk_io, failed_native_start_retains_every_port_and_dependency)
{
	for (const bool separate_drivers : {false, true}) {
		for (const std::size_t failed_port : {0u, 1u}) {
			for (const int result : {-5, 1}) {
				SCOPED_TRACE(separate_drivers);
				SCOPED_TRACE(failed_port);
				SCOPED_TRACE(result);
				facility_fixture facility;
				facility.add_pci_attachment(separate_drivers ? 1u : 0u);
				ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
				mempool_state pool;
				storage_fixture storage(facility);
				ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
				ethdev_adapter native;
				native.ports[failed_port].start_result = result;
				native_start_failure_evidence expected{
					native, pool, failed_port,
					"DPDK port " + std::to_string(TEST_PHYSICAL_PORT + failed_port) +
						": ethdev start failed (result=" + std::to_string(result) +
						"); native state is uncertain; terminating"};
				io_driver_fixture first(facility, storage);
				io_driver_fixture second(facility, storage, 1);
				std::optional<paired_driver_facts> combined;
				if (!separate_drivers) {
					combined.emplace(first, second);
				}
				const kinetum_provider_cold_log logging{
					.context = &expected,
					.write = native_start_failure_evidence::receive,
				};
				first.use_logging(logging);
				second.use_logging(logging);
				ASSERT_EQ(first.create(native), KINETUM_PROVIDER_STATUS_OK);
				if (separate_drivers) {
					ASSERT_EQ(second.create(native), KINETUM_PROVIDER_STATUS_OK);
				}
				// Factory-request storage is no longer the logging authority.
				first.use_logging({});
				second.use_logging({});
				EXPECT_EXIT(
					{
						for (auto &port : native.ports) {
							port.exit_success_on_stop = true;
							port.exit_success_on_close = true;
						}
						std::set_terminate([] { std::_Exit(86); });
						(void)first.activate();
						if (separate_drivers) {
							(void)second.activate();
						}
						// Returning must fail this proof without running a live destructor.
						std::_Exit(0);
					},
					::testing::ExitedWithCode(86),
					"DPDK port [78]: ethdev start failed .*; native state is uncertain; terminating\n"
					"verified cold native-start diagnostic\n");
			}
		}
	}
}

/** @brief A rejected RETA rolls the started port back before configured closure. */
TEST(dpdk_io, activation_reta_failure_restores_cold_configured_ownership)
{
	facility_fixture facility;
	facility.add_packet_worker(1, 4);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	driver.enable_rss();
	native.reta_result = -1;

	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	const auto activated = driver.activate();
	EXPECT_EQ(activated, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
	if (activated == KINETUM_PROVIDER_STATUS_OK) {
		EXPECT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
	}
	EXPECT_EQ(native.stop_calls, 1u);
	EXPECT_EQ(native.hash_read_calls, 0u);
	EXPECT_EQ(native.reta_read_calls, 0u);
	driver.driver().reset();
	EXPECT_EQ(native.close_calls, 1u);
	EXPECT_LT(event_index(native.events, "stop"), event_index(native.events, "close"));
}

/** @brief Either native readback failure retires the started port before configured closure. */
TEST(dpdk_io, activation_rss_read_failure_rolls_back_started_port)
{
	for (const bool hash_failure : {true, false}) {
		SCOPED_TRACE(hash_failure);
		facility_fixture facility;
		facility.add_packet_worker(1, 4);
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		native.hash_read_result = hash_failure ? -1 : 0;
		native.reta_read_result = hash_failure ? 0 : -1;
		io_driver_fixture driver(facility, storage);
		driver.enable_rss();
		ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
		const auto activated = driver.activate();
		EXPECT_EQ(activated, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
		if (activated == KINETUM_PROVIDER_STATUS_OK) {
			EXPECT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
		}
		EXPECT_EQ(native.hash_read_calls, 1u);
		EXPECT_EQ(native.reta_read_calls, hash_failure ? 0u : 1u);
		EXPECT_EQ(native.stop_calls, 1u);
		driver.driver().reset();
		EXPECT_EQ(native.close_calls, 1u);
		EXPECT_LT(event_index(native.events, "stop"), event_index(native.events, "close"));
	}
}

/** @brief Ordinary RSS activates only after exact key, native alias mask, and RETA readback. */
TEST(dpdk_io, ordinary_rss_materializes_and_reads_back_exact_native_state)
{
	facility_fixture facility;
	facility.add_packet_worker(1, 4);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	driver.enable_rss();

	ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
	ASSERT_NE(driver.driver(), nullptr);
	EXPECT_EQ(driver.driver()->operations().rx_queue_count, 2u);
	EXPECT_EQ(driver.driver()->operations().tx_queue_count, 2u);
	EXPECT_EQ(native.configured_rss_key.size(), TEST_RSS_KEY_SIZE);
	EXPECT_EQ(native.programmed_reta_size, 0u);
	EXPECT_EQ(native.hash_read_calls, 0u);
	EXPECT_EQ(native.reta_read_calls, 0u);
	ASSERT_EQ(driver.activate(), KINETUM_PROVIDER_STATUS_OK);
	EXPECT_EQ(native.programmed_reta_size, 128u);
	EXPECT_EQ(native.programmed_reta.size(), 128u);
	for (std::size_t index = 0; index < native.programmed_reta.size(); ++index) {
		EXPECT_EQ(native.programmed_reta[index], static_cast<uint16_t>(index % 2u));
	}
	EXPECT_EQ(native.hash_read_calls, 1u);
	EXPECT_EQ(native.reta_read_calls, 1u);
	EXPECT_EQ(native.hardware_rss_hf,
		  RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_OTHER | RTE_ETH_RSS_NONFRAG_IPV4_UDP);
	EXPECT_EQ(native.hardware_rss_key, native.configured_rss_key);
	EXPECT_LT(event_index(native.events, "start"), event_index(native.events, "rss_read"));
	EXPECT_LT(event_index(native.events, "reta"), event_index(native.events, "reta_read"));
	ASSERT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
	driver.driver().reset();
	EXPECT_EQ(native.stop_calls, 1u);
	EXPECT_EQ(native.close_calls, 1u);
}

/** @brief Later ordinary PF starts preserve independently programmed RSS across driver boundaries. */
TEST(dpdk_io, ordinary_rss_survives_later_port_start_in_same_and_separate_drivers)
{
	for (const bool separate_drivers : {false, true}) {
		for (const bool second_rss : {false, true}) {
			SCOPED_TRACE(separate_drivers);
			SCOPED_TRACE(second_rss);
			facility_fixture facility;
			facility.add_packet_worker(1, 4);
			facility.add_pci_attachment(separate_drivers ? 1u : 0u);
			ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
			mempool_state pool;
			storage_fixture storage(facility);
			ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
			ethdev_adapter native;
			io_driver_fixture first(facility, storage);
			io_driver_fixture second(facility, storage, 1);
			first.enable_rss();
			if (second_rss) {
				second.enable_rss();
			}
			std::optional<paired_driver_facts> combined;
			if (!separate_drivers) {
				combined.emplace(first, second);
			}
			ASSERT_EQ(first.create(native), KINETUM_PROVIDER_STATUS_OK);
			if (separate_drivers) {
				ASSERT_EQ(second.create(native), KINETUM_PROVIDER_STATUS_OK);
			}
			native.rss.events.clear();
			const auto first_activated = first.activate();
			EXPECT_EQ(first_activated, KINETUM_PROVIDER_STATUS_OK);
			const auto second_activated = separate_drivers ? second.activate() : first_activated;
			EXPECT_EQ(second_activated, KINETUM_PROVIDER_STATUS_OK);
			EXPECT_EQ(native.rss.default_resets, 2u);
			EXPECT_TRUE(native.rss.ordinary_toeplitz);
			for (std::size_t port = 0; port < native.ports.size(); ++port) {
				const auto &observed = native.ports[port];
				const bool rss = port == 0 || second_rss;
				EXPECT_EQ(observed.hash_read_calls, rss ? 1u : 0u);
				EXPECT_EQ(observed.reta_read_calls, rss ? 1u : 0u);
				EXPECT_EQ(observed.hardware_rss_key, observed.configured_rss_key);
				EXPECT_EQ(observed.hardware_rss_key.size(), rss ? TEST_RSS_KEY_SIZE : 0u);
				EXPECT_EQ(observed.hardware_rss_hf, rss ? RTE_ETH_RSS_IPV4 |
										    RTE_ETH_RSS_NONFRAG_IPV4_OTHER |
										    RTE_ETH_RSS_NONFRAG_IPV4_UDP :
									  0u);
				EXPECT_EQ(observed.programmed_reta.size(), rss ? 128u : 0u);
				for (std::size_t index = 0; index < observed.programmed_reta.size(); ++index) {
					EXPECT_EQ(observed.programmed_reta[index], index % 2u);
				}
			}
			if (second_rss) {
				EXPECT_NE(native.ports[0].hardware_rss_key, native.ports[1].hardware_rss_key);
			}
			EXPECT_LT(event_index(native.rss.events, "7:reta_read"),
				  event_index(native.rss.events, "8:start"));
			if (separate_drivers && second_activated == KINETUM_PROVIDER_STATUS_OK) {
				EXPECT_EQ(second.deactivate(), KINETUM_PROVIDER_STATUS_OK);
			}
			if (first_activated == KINETUM_PROVIDER_STATUS_OK) {
				EXPECT_EQ(first.deactivate(), KINETUM_PROVIDER_STATUS_OK);
			}
			second.driver().reset();
			first.driver().reset();
			EXPECT_LT(event_index(native.rss.events, "8:stop"), event_index(native.rss.events, "7:stop"));
			EXPECT_LT(event_index(native.rss.events, "7:stop"), event_index(native.rss.events, "8:close"));
			EXPECT_LT(event_index(native.rss.events, "8:close"), event_index(native.rss.events, "7:close"));
			for (const auto &port : native.ports) {
				EXPECT_EQ(port.stop_calls, 1u);
				EXPECT_EQ(port.close_calls, 1u);
			}
		}
	}
}

/** @brief A later PF's RETA or readback failure stops the complete started prefix in reverse order. */
TEST(dpdk_io, later_port_rss_failure_retires_the_started_prefix)
{
	for (const std::string_view failure : {"RETA write", "key read", "RETA read"}) {
		SCOPED_TRACE(failure);
		facility_fixture facility;
		facility.add_packet_worker(1, 4);
		facility.add_pci_attachment(0);
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_adapter native;
		native.ports[1].reta_result = failure == "RETA write" ? -1 : 0;
		native.ports[1].hash_read_result = failure == "key read" ? -1 : 0;
		native.ports[1].reta_read_result = failure == "RETA read" ? -1 : 0;
		io_driver_fixture first(facility, storage);
		io_driver_fixture second(facility, storage, 1);
		first.enable_rss();
		second.enable_rss();
		paired_driver_facts combined(first, second);
		ASSERT_EQ(first.create(native), KINETUM_PROVIDER_STATUS_OK);
		native.rss.events.clear();
		const auto activated = first.activate();
		EXPECT_EQ(activated, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
		if (activated == KINETUM_PROVIDER_STATUS_OK) {
			EXPECT_EQ(first.deactivate(), KINETUM_PROVIDER_STATUS_OK);
		}
		EXPECT_LT(event_index(native.rss.events, "8:stop"), event_index(native.rss.events, "7:stop"));
		for (const auto &port : native.ports) {
			EXPECT_EQ(port.stop_calls, 1u);
			EXPECT_EQ(port.close_calls, 0u);
			EXPECT_FALSE(port.started);
		}
		first.driver().reset();
		EXPECT_LT(event_index(native.rss.events, "7:stop"), event_index(native.rss.events, "8:close"));
		EXPECT_LT(event_index(native.rss.events, "8:close"), event_index(native.rss.events, "7:close"));
		EXPECT_EQ(pool.free_calls, 0u);
		storage.storage().reset();
		EXPECT_EQ(pool.free_calls, 1u);
	}
}

/** @brief Post-EAL device identity must confirm the independently admitted i40e PF. */
TEST(dpdk_io, unexpected_pci_driver_rejects_before_native_configuration)
{
	facility_fixture facility;
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	for (const char *driver_name : {static_cast<const char *>(nullptr), "net_other"}) {
		ethdev_state native;
		native.driver_name = driver_name;
		io_driver_fixture driver(facility, storage);
		std::array<char, 256> message{};
		kinetum_provider_diagnostic diagnostic{message.data(), static_cast<uint32_t>(message.size()), 0};
		EXPECT_EQ(driver.create(native, &diagnostic), KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
		EXPECT_NE(std::string_view(message.data(), diagnostic.size).find("net_i40e"), std::string_view::npos);
		EXPECT_EQ(native.configure_calls, 0u);
	}
}

/** @brief Partial, altered, or self-mutated native outputs cannot satisfy independent expectations. */
TEST(dpdk_io, rss_readback_rejects_incomplete_and_contradictory_state)
{
	for (const std::string_view failure :
	     {"key bytes", "short extent", "long extent", "partial key", "missing alias", "extra class", "RETA entry",
	      "partial RETA", "changed dev_conf", "changed RETA input"}) {
		SCOPED_TRACE(failure);
		facility_fixture facility;
		facility.add_packet_worker(1, 4);
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		native.corrupt_read_key = failure == "key bytes";
		native.key_read_extent = failure == "short extent" ? 40 :
					 failure == "long extent"  ? 255 :
								     TEST_RSS_KEY_SIZE;
		native.key_read_limit = failure == "partial key" ? TEST_RSS_KEY_SIZE - 1u : TEST_RSS_KEY_SIZE;
		native.hash_read_xor = failure == "missing alias" ? RTE_ETH_RSS_NONFRAG_IPV4_OTHER :
				       failure == "extra class"	  ? RTE_ETH_RSS_NONFRAG_IPV4_TCP :
								    0;
		native.corrupt_read_reta = failure == "RETA entry";
		native.reta_read_limit = failure == "partial RETA" ? 127 : UINT16_MAX;
		native.mutate_configured_key = failure == "changed dev_conf";
		native.mutate_reta_input = failure == "changed RETA input";
		io_driver_fixture driver(facility, storage);
		driver.enable_rss();
		ASSERT_EQ(driver.create(native), KINETUM_PROVIDER_STATUS_OK);
		const auto activated = driver.activate();
		EXPECT_EQ(activated, KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
		if (activated == KINETUM_PROVIDER_STATUS_OK) {
			EXPECT_EQ(driver.deactivate(), KINETUM_PROVIDER_STATUS_OK);
		}
		EXPECT_EQ(native.stop_calls, 1u);
		driver.driver().reset();
		EXPECT_EQ(native.close_calls, 1u);
	}
}

/** @brief An explicit symmetry request rejects before native configuration, independently of planning. */
TEST(dpdk_io, symmetric_rss_rejects_before_native_configuration)
{
	facility_fixture facility;
	facility.add_packet_worker(1, 4);
	ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
	mempool_state pool;
	storage_fixture storage(facility);
	ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
	ethdev_state native;
	io_driver_fixture driver(facility, storage);
	driver.enable_rss();
	driver.steering().symmetric = 1;
	std::array<char, 256> message{};
	kinetum_provider_diagnostic diagnostic{message.data(), static_cast<uint32_t>(message.size()), 0};
	EXPECT_EQ(driver.create(native, &diagnostic), KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT);
	EXPECT_NE(std::string_view(message.data(), diagnostic.size).find("symmetric RSS"), std::string_view::npos);
	EXPECT_EQ(native.configure_calls, 0u);
	EXPECT_EQ(native.stop_calls, 0u);
	EXPECT_EQ(native.close_calls, 0u);
}

/** @brief Authored key extents must match the independent 52-byte hardware capability. */
TEST(dpdk_io, rss_key_extent_rejects_before_native_configuration)
{
	for (const uint32_t extent : {0u, 40u, 53u, 256u}) {
		SCOPED_TRACE(extent);
		facility_fixture facility;
		facility.add_packet_worker(1, 4);
		ASSERT_EQ(facility.create(), KINETUM_PROVIDER_STATUS_OK);
		mempool_state pool;
		storage_fixture storage(facility);
		ASSERT_EQ(storage.create(pool), KINETUM_PROVIDER_STATUS_OK);
		ethdev_state native;
		io_driver_fixture driver(facility, storage);
		driver.enable_rss();
		std::array<uint8_t, 256> key{};
		driver.steering().hash_key = {key.data(), extent, 0};
		std::array<char, 256> message{};
		kinetum_provider_diagnostic diagnostic{message.data(), static_cast<uint32_t>(message.size()), 0};
		EXPECT_EQ(driver.create(native, &diagnostic), KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION);
		EXPECT_NE(std::string_view(message.data(), diagnostic.size).find("device requires 52 bytes"),
			  std::string_view::npos);
		EXPECT_EQ(native.configure_calls, 0u);
	}
}

}  // namespace kinetum::provider::dpdk_component
