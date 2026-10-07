// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file dpdk_io.cpp
 * @brief Exact DPDK packet-storage and ethdev I/O role implementation.
 * @author Fleming Patel
 */

#include "src/dp/backends/dpdk/dpdk_io.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "src/common/runtime_sizing.hpp"
#include "src/dp/backends/dpdk/dpdk_packet_record.hpp"
#include "src/provider/components/component_support.hpp"

namespace kinetum::provider::dpdk_component
{
namespace
{

using component_support::fail;

/** Exact contract used to resolve the native EAL lifetime dependency. */
constexpr char DPDK_FACILITY_TYPE_URL[] = "type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig";
/** Exact contract admitted by the ethdev driver factory. */
constexpr char DPDK_DRIVER_TYPE_URL[] = "type.googleapis.com/kinetum.io.dpdk.v1.DpdkDriverConfig";
/** Exact contract used to resolve mbuf storage dependencies. */
constexpr char DPDK_STORAGE_TYPE_URL[] = "type.googleapis.com/kinetum.storage.dpdk.v1.DpdkStorageConfig";
/** Canonical IPv4 tuple field required by the admitted RSS contract. */
constexpr char RSS_FIELD_IPV4[] = "ipv4";
/** Canonical UDP tuple field required by the admitted RSS contract. */
constexpr char RSS_FIELD_UDP[] = "udp";
/** Maximum prefix supported by fixed packet-path native-pointer arrays. */
constexpr uint16_t MAX_BURST = static_cast<uint16_t>(common::runtime_sizing::PACKET_MAX_BURST_SIZE);
/** Byte-access and writable-clone capabilities proved for each materialized mbuf pool. */
constexpr uint32_t DPDK_STORAGE_CAPABILITIES =
	KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ | KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE |
	KINETUM_PACKET_STORAGE_NIC_RX_DMA | KINETUM_PACKET_STORAGE_NIC_TX_DMA | KINETUM_PACKET_STORAGE_WRITABLE_CLONE;
/** Agents whose access is admitted for DPDK-owned packet storage. */
constexpr uint8_t DPDK_STORAGE_ACCESS_AGENTS = KINETUM_PROVIDER_ACCESS_AGENT_CPU |
					       KINETUM_PROVIDER_ACCESS_AGENT_NIC_DMA;

/**
 * @brief Return true only for a complete cold mempool API.
 * @param api Borrowed candidate operation table.
 * @return true only when every required pool operation is present.
 */
[[nodiscard]] bool mempool_api_is_complete(const dpdk_mempool_api &api) noexcept
{
	return api.create != nullptr && api.iterate != nullptr && api.private_size != nullptr &&
	       api.in_use_count != nullptr && api.free != nullptr;
}

/**
 * @brief Return true only for a complete cold ethdev API.
 * @param api Borrowed candidate operation table.
 * @return true only when every required port and flow operation is present.
 */
[[nodiscard]] bool ethdev_api_is_complete(const dpdk_ethdev_api &api) noexcept
{
	return api.device_info != nullptr && api.device_socket != nullptr && api.configure != nullptr &&
	       api.set_mtu != nullptr && api.setup_rx_queue != nullptr && api.setup_tx_queue != nullptr &&
	       api.start != nullptr && api.stop != nullptr && api.close != nullptr && api.mac_address != nullptr &&
	       api.update_reta != nullptr && api.validate_flow != nullptr && api.create_flow != nullptr &&
	       api.destroy_flow != nullptr && api.statistics != nullptr;
}

/**
 * @brief Production wrapper creating one exact mbuf pool.
 * @param state Opaque API context; unused by this native wrapper.
 * @param name NUL-terminated pool identity.
 * @param count Requested mbuf population.
 * @param cache_size Per-lcore object cache size.
 * @param private_size Private bytes reserved for the platform record.
 * @param data_room_size Mbuf data-room bytes including headroom.
 * @param socket_id Required NUMA socket for the pool backing.
 * @return Sole native pool owner, or nullptr when DPDK cannot create it.
 */
rte_mempool *native_mempool_create(void *state, const char *name, uint32_t count, uint32_t cache_size,
				   uint16_t private_size, uint16_t data_room_size, int socket_id) noexcept
{
	(void)state;
	static_assert(sizeof(unsigned int) == sizeof(uint32_t));
	return rte_pktmbuf_pool_create(name, static_cast<unsigned int>(count), static_cast<unsigned int>(cache_size),
				       private_size, data_room_size, socket_id);
}

/**
 * @brief Production wrapper inspecting every object in one mempool.
 * @param state Opaque API context; unused by this native wrapper.
 * @param pool Borrowed materialized pool.
 * @param callback Callback invoked for each native object.
 * @param argument Callback state borrowed for the iteration.
 * @return Number of objects visited by the native iterator.
 */
uint32_t native_mempool_iterate(void *state, rte_mempool *pool, rte_mempool_obj_cb_t *callback, void *argument) noexcept
{
	(void)state;
	return rte_mempool_obj_iter(pool, callback, argument);
}

/**
 * @brief Production wrapper returning exact mbuf private bytes.
 * @param state Opaque API context; unused by this native wrapper.
 * @param pool Borrowed materialized mbuf pool.
 * @return Native private-area size in bytes.
 */
uint16_t native_mempool_private_size(void *state, const rte_mempool *pool) noexcept
{
	(void)state;
	// DPDK derives this immutable value through an accessor that accepts a
	// mutable pool pointer. Cast only at the native boundary; no state changes.
	return rte_pktmbuf_priv_size(const_cast<rte_mempool *>(pool));
}

/**
 * @brief Production wrapper returning cold pool occupancy.
 * @param state Opaque API context; unused by this native wrapper.
 * @param pool Borrowed materialized mbuf pool.
 * @return Approximate native count of objects held outside the pool.
 */
uint32_t native_mempool_in_use_count(void *state, const rte_mempool *pool) noexcept
{
	(void)state;
	return rte_mempool_in_use_count(pool);
}

/**
 * @brief Production wrapper retiring one exact mbuf pool.
 * @param state Opaque API context; unused by this native wrapper.
 * @param pool Sole quiescent pool transferred for destruction.
 */
void native_mempool_free(void *state, rte_mempool *pool) noexcept
{
	(void)state;
	rte_mempool_free(pool);
}

/**
 * @brief Production wrapper reading immutable PMD device information.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param info Caller-owned destination for native device capabilities.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_device_info(void *state, uint16_t port_id, rte_eth_dev_info *info) noexcept
{
	(void)state;
	return rte_eth_dev_info_get(port_id, info);
}

/**
 * @brief Production wrapper reading one ethdev socket identity.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @return Native NUMA socket identity or its error/unknown sentinel.
 */
int native_device_socket(void *state, uint16_t port_id) noexcept
{
	(void)state;
	return rte_eth_dev_socket_id(port_id);
}

/**
 * @brief Production wrapper configuring one exact ethdev.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param rx_queues Number of RX queues to configure.
 * @param tx_queues Number of TX queues to configure.
 * @param configuration Borrowed native port configuration.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_configure(void *state, uint16_t port_id, uint16_t rx_queues, uint16_t tx_queues,
		     const rte_eth_conf *configuration) noexcept
{
	(void)state;
	return rte_eth_dev_configure(port_id, rx_queues, tx_queues, configuration);
}

/**
 * @brief Production wrapper applying one exact MTU.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param mtu Requested MTU in bytes.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_set_mtu(void *state, uint16_t port_id, uint16_t mtu) noexcept
{
	(void)state;
	return rte_eth_dev_set_mtu(port_id, mtu);
}

/**
 * @brief Production wrapper constructing one RX queue.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param queue_id Dense RX queue identity.
 * @param descriptors Requested descriptor population.
 * @param socket_id Required NUMA socket for queue memory.
 * @param configuration Borrowed native RX configuration.
 * @param pool Borrowed packet pool retained throughout queue ownership.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_setup_rx_queue(void *state, uint16_t port_id, uint16_t queue_id, uint16_t descriptors,
			  unsigned int socket_id, const rte_eth_rxconf *configuration, rte_mempool *pool) noexcept
{
	(void)state;
	return rte_eth_rx_queue_setup(port_id, queue_id, descriptors, socket_id, configuration, pool);
}

/**
 * @brief Production wrapper constructing one TX queue.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param queue_id Dense TX queue identity.
 * @param descriptors Requested descriptor population.
 * @param socket_id Required NUMA socket for queue memory.
 * @param configuration Borrowed native TX configuration.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_setup_tx_queue(void *state, uint16_t port_id, uint16_t queue_id, uint16_t descriptors,
			  unsigned int socket_id, const rte_eth_txconf *configuration) noexcept
{
	(void)state;
	return rte_eth_tx_queue_setup(port_id, queue_id, descriptors, socket_id, configuration);
}

/**
 * @brief Production wrapper starting one configured ethdev.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_start(void *state, uint16_t port_id) noexcept
{
	(void)state;
	return rte_eth_dev_start(port_id);
}

/**
 * @brief Production wrapper stopping one started ethdev.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_stop(void *state, uint16_t port_id) noexcept
{
	(void)state;
	return rte_eth_dev_stop(port_id);
}

/**
 * @brief Production wrapper closing one stopped ethdev.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_close(void *state, uint16_t port_id) noexcept
{
	(void)state;
	return rte_eth_dev_close(port_id);
}

/**
 * @brief Production wrapper reading one ethdev MAC address.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param address Caller-owned destination for the native MAC address.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_mac_address(void *state, uint16_t port_id, rte_ether_addr *address) noexcept
{
	(void)state;
	return rte_eth_macaddr_get(port_id, address);
}

/**
 * @brief Production wrapper programming one complete RSS redirection table.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param entries Borrowed RETA groups and update masks.
 * @param reta_size Exact number of redirection entries represented by the groups.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_update_reta(void *state, uint16_t port_id, rte_eth_rss_reta_entry64 *entries, uint16_t reta_size) noexcept
{
	(void)state;
	return rte_eth_dev_rss_reta_update(port_id, entries, reta_size);
}

/**
 * @brief Production wrapper validating one exact ethdev flow rule.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param attributes Borrowed rule scope and direction.
 * @param pattern Borrowed terminated match-item array.
 * @param actions Borrowed terminated action array.
 * @param error Caller-owned native error description.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_validate_flow(void *state, uint16_t port_id, const rte_flow_attr *attributes, const rte_flow_item *pattern,
			 const rte_flow_action *actions, rte_flow_error *error) noexcept
{
	(void)state;
	return rte_flow_validate(port_id, attributes, pattern, actions, error);
}

/**
 * @brief Production wrapper installing one exact ethdev flow rule.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param attributes Borrowed rule scope and direction.
 * @param pattern Borrowed terminated match-item array.
 * @param actions Borrowed terminated action array.
 * @param error Caller-owned native error description.
 * @return Owned native flow handle, or nullptr on rejection.
 */
rte_flow *native_create_flow(void *state, uint16_t port_id, const rte_flow_attr *attributes,
			     const rte_flow_item *pattern, const rte_flow_action *actions,
			     rte_flow_error *error) noexcept
{
	(void)state;
	return rte_flow_create(port_id, attributes, pattern, actions, error);
}

/**
 * @brief Production wrapper retiring one exact ethdev flow rule.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param flow Owned flow handle to retire on success.
 * @param error Caller-owned native error description.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_destroy_flow(void *state, uint16_t port_id, rte_flow *flow, rte_flow_error *error) noexcept
{
	(void)state;
	return rte_flow_destroy(port_id, flow, error);
}

/**
 * @brief Production wrapper reading one cold ethdev statistics snapshot.
 * @param state Opaque API context; unused by this native wrapper.
 * @param port_id Exact DPDK ethdev port identity.
 * @param statistics Caller-owned destination for native port counters.
 * @return Unmodified native result: zero on success, or a native error code.
 */
int native_statistics(void *state, uint16_t port_id, rte_eth_stats *statistics) noexcept
{
	(void)state;
	return rte_eth_stats_get(port_id, statistics);
}

/**
 * @brief Return whether one descriptor count satisfies exact PMD limits.
 * @param count Candidate descriptor population.
 * @param limits Native minimum, maximum, and alignment constraints; zero leaves that constraint unspecified.
 * @return true only when every specified native limit is satisfied.
 */
[[nodiscard]] bool descriptor_count_is_exact(uint16_t count, const rte_eth_desc_lim &limits) noexcept
{
	if ((limits.nb_min != 0 && count < limits.nb_min) || (limits.nb_max != 0 && count > limits.nb_max) ||
	    (limits.nb_align != 0 && count % limits.nb_align != 0)) {
		return false;
	}
	return true;
}

/**
 * @brief Return true only when one six-byte fact equals a native MAC.
 * @param expected Six authenticated MAC bytes.
 * @param actual Native device MAC observation.
 * @return true for byte-exact equality.
 */
[[nodiscard]] bool mac_matches(const uint8_t expected[6], const rte_ether_addr &actual) noexcept
{
	return std::memcmp(expected, actual.addr_bytes, RTE_ETHER_ADDR_LEN) == 0;
}

/**
 * @brief Return one exact facility dependency owned by this component.
 * @param request Borrowed factory request with admitted dependency handles.
 * @return Unique matching facility, or nullptr for absence, duplicates, or inconsistent identity.
 */
[[nodiscard]] const dpdk_process_facility *facility_dependency(const kinetum_provider_factory_request &request) noexcept
{
	const dpdk_process_facility *match = nullptr;
	for (uint32_t index = 0; index < request.dependency_count; ++index) {
		const auto &dependency = request.dependencies[index];
		if (dependency.role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY) {
			continue;
		}
		if (match != nullptr || !component_support::text_equals(dependency.type_url, DPDK_FACILITY_TYPE_URL)) {
			return nullptr;
		}
		match = static_cast<const dpdk_process_facility *>(dependency.instance);
		if (match == nullptr || dependency.operations != &match->operations()) {
			return nullptr;
		}
	}
	return match;
}

/** @brief One preflighted native port and reverse-order rollback ledger row. */
struct dpdk_port_state {
	uint16_t physical_port{0};		     ///< Exact facility-resolved ethdev port.
	uint16_t mtu{0};			     ///< Exact configured MTU.
	uint32_t port_index{0};			     ///< Compact generic port identity.
	uint16_t rx_queue_count{0};		     ///< Exact dense RX queue count.
	uint16_t tx_queue_count{0};		     ///< Exact dense TX queue count.
	rte_eth_conf configuration{};		     ///< Fully preflighted port configuration.
	rte_eth_rxconf rx_configuration{};	     ///< PMD-provided RX queue defaults.
	rte_eth_txconf tx_configuration{};	     ///< PMD-provided TX queue defaults.
	std::vector<uint8_t> rss_key;		     ///< Owned exact RSS key bytes.
	std::vector<uint16_t> rss_queues;	     ///< Exact dense queue set used by an RSS flow action.
	std::vector<rte_eth_rss_reta_entry64> reta;  ///< Complete exact RETA update.
	uint16_t reta_size{0};			     ///< Exact PMD RETA size.
	rte_flow *symmetric_rss_flow{nullptr};	     ///< Owned exact symmetric RSS rule.
	bool symmetric_rss{false};		     ///< Whether this port requires the exact flow rule.
	bool configured{false};			     ///< Native configuration ownership exists.
	bool started{false};			     ///< Native started ownership exists.
};

}  // namespace

/** @brief Complete retained state for one exact DPDK storage domain. */
struct dpdk_packet_storage::implementation {
	dpdk_mempool_api api{};				 ///< Complete cold native pool API.
	const dpdk_process_facility *facility{nullptr};	 ///< Exact borrowed native memory authority.
	rte_mempool *pool{nullptr};			 ///< Sole owned native mbuf pool.
	uint32_t buffer_count{0};			 ///< Exact native object population.
	uint32_t alignment_bytes{0};			 ///< Required record/data alignment.
	int32_t host_numa_node{-1};			 ///< Exact pool NUMA placement.
};

/** @brief Complete retained state for one exact DPDK I/O driver. */
struct dpdk_io_driver::implementation {
	/** @brief One stable hot-path RX queue state. */
	struct rx_queue {
		uint16_t physical_port{0};		      ///< Exact ethdev port.
		uint16_t queue_id{0};			      ///< Exact dense RX queue.
		uint16_t logical_port{0};		      ///< Immutable logical ingress identity.
		uint16_t descriptors{0};		      ///< Exact configured descriptor count.
		const dpdk_packet_storage *storage{nullptr};  ///< Exact RX storage owner.
	};

	/** @brief One stable hot-path TX queue state. */
	struct tx_queue {
		uint16_t physical_port{0};   ///< Exact ethdev port.
		uint16_t queue_id{0};	     ///< Exact dense TX queue.
		uint16_t logical_port{0};    ///< Immutable logical egress identity.
		uint16_t descriptors{0};     ///< Exact configured descriptor count.
		int32_t host_numa_node{-1};  ///< Common proven NUMA placement for queue and admitted pools.
		std::vector<const dpdk_packet_storage *>
			storage_by_domain;  ///< O(1) admitted native owners; holes reject.
	};

	dpdk_ethdev_api api{};						      ///< Complete cold native ethdev API.
	const dpdk_process_facility *facility{nullptr};			      ///< Borrowed exact facility owner.
	std::unique_ptr<dpdk_port_state[]> ports;			      ///< Stable port ownership rows.
	uint32_t port_count{0};						      ///< Exact port row count.
	std::unique_ptr<rx_queue[]> rx_queues;				      ///< Stable hot RX queue states.
	uint32_t rx_queue_count{0};					      ///< Exact RX operation count.
	std::unique_ptr<tx_queue[]> tx_queues;				      ///< Stable hot TX queue states.
	uint32_t tx_queue_count{0};					      ///< Exact TX operation count.
	std::unique_ptr<kinetum_packet_rx_burst_operations[]> rx_operations;  ///< Published RX rows.
	std::unique_ptr<kinetum_packet_tx_burst_operations[]> tx_operations;  ///< Published TX rows.
	bool active{false};  ///< Whether every configured port owns live packet I/O.
};

namespace
{

/** @brief Population probe proving every DPDK packet-record and payload address. */
struct dpdk_pool_population_probe {
	uint32_t observed{0};	      ///< Native objects inspected.
	uint32_t alignment_bytes{0};  ///< Required power-of-two data alignment.
	uint32_t data_room_bytes{0};  ///< Exact expected native buffer bytes.
	uint32_t headroom_bytes{0};   ///< Exact expected initial data offset.
	bool valid{true};	      ///< Remains true only while every object is exact.
};

/**
 * @brief Inspect one materialized mbuf without beginning record ownership.
 * @param pool Native callback pool, unused by this probe.
 * @param argument Mutable population proof accumulated across this iteration.
 * @param object Borrowed mbuf to inspect.
 * @param object_index Native object ordinal, unused by this probe.
 */
void inspect_pool_object(rte_mempool *pool, void *argument, void *object, unsigned int object_index) noexcept
{
	(void)pool;
	(void)object_index;
	auto *probe = static_cast<dpdk_pool_population_probe *>(argument);
	if (probe == nullptr) {
		std::terminate();
	}
	++probe->observed;
	auto *mbuf = static_cast<rte_mbuf *>(object);
	if (mbuf == nullptr || !dp::dpdk_packet_record_private_area_is_aligned(rte_mbuf_to_priv(mbuf)) ||
	    mbuf->buf_len != probe->data_room_bytes || mbuf->data_off != probe->headroom_bytes) {
		probe->valid = false;
		return;
	}
	const auto address = reinterpret_cast<std::uintptr_t>(rte_pktmbuf_mtod(mbuf, uint8_t *));
	if (probe->alignment_bytes == 0 || address % probe->alignment_bytes != 0) {
		probe->valid = false;
	}
}

/**
 * @brief Resolve one exact DPDK storage dependency by compact domain.
 * @param request Borrowed factory request with admitted dependency handles.
 * @param storage_domain_index Required compiled storage-domain identity.
 * @return Unique matching storage owner, or nullptr for absence or ambiguity.
 */
[[nodiscard]] const dpdk_packet_storage *storage_dependency(const kinetum_provider_factory_request &request,
							    uint32_t storage_domain_index) noexcept
{
	const dpdk_packet_storage *match = nullptr;
	for (uint32_t index = 0; index < request.dependency_count; ++index) {
		const auto &dependency = request.dependencies[index];
		if (dependency.role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE) {
			continue;
		}
		const auto *candidate = static_cast<const dpdk_packet_storage *>(dependency.instance);
		if (!component_support::text_equals(dependency.type_url, DPDK_STORAGE_TYPE_URL) ||
		    candidate == nullptr || dependency.operations != &candidate->operations() ||
		    candidate->operations().domain_index != storage_domain_index) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = candidate;
	}
	return match;
}

/**
 * @brief Find one exact compiled port fact by compact global identity.
 * @param facts Borrowed complete driver facts.
 * @param port_index Required global port identity.
 * @return Unique matching port row, or nullptr for absence or duplicates.
 */
[[nodiscard]] const kinetum_provider_io_port_fact *find_port_fact(const kinetum_provider_io_driver_facts &facts,
								  uint32_t port_index) noexcept
{
	const kinetum_provider_io_port_fact *match = nullptr;
	for (uint32_t index = 0; index < facts.port_count; ++index) {
		if (facts.ports[index].port_index != port_index) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = &facts.ports[index];
	}
	return match;
}

/**
 * @brief Find one exact steering fact by compact identity.
 * @param facts Borrowed complete driver facts.
 * @param steering_index Required compiled steering identity.
 * @return Unique matching steering row, or nullptr for absence or duplicates.
 */
[[nodiscard]] const kinetum_provider_steering_fact *find_steering_fact(const kinetum_provider_io_driver_facts &facts,
								       uint32_t steering_index) noexcept
{
	const kinetum_provider_steering_fact *match = nullptr;
	for (uint32_t index = 0; index < facts.steering_profile_count; ++index) {
		if (facts.steering_profiles[index].steering_profile_index != steering_index) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = &facts.steering_profiles[index];
	}
	return match;
}

/**
 * @brief Return whether one logical port admits one stream direction.
 * @param port Compiled RX, TX, or bidirectional port direction.
 * @param stream Candidate RX or TX stream direction.
 * @return true only when the port admits the candidate direction.
 */
[[nodiscard]] bool direction_matches(kinetum_provider_io_direction port, kinetum_provider_io_direction stream) noexcept
{
	return stream == KINETUM_PROVIDER_IO_DIRECTION_RX ?
		       (port == KINETUM_PROVIDER_IO_DIRECTION_RX ||
			port == KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL) :
		       stream == KINETUM_PROVIDER_IO_DIRECTION_TX &&
			       (port == KINETUM_PROVIDER_IO_DIRECTION_TX ||
				port == KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL);
}

/**
 * @brief Return whether one exact stream belongs to one exact port/direction.
 * @param stream Borrowed compiled stream row.
 * @param port_index Required global port identity.
 * @param direction Required RX or TX direction.
 * @return true only when both identities match.
 */
[[nodiscard]] bool stream_matches(const kinetum_provider_io_stream_fact &stream, uint32_t port_index,
				  kinetum_provider_io_direction direction) noexcept
{
	return stream.port_index == port_index && stream.direction == direction;
}

/**
 * @brief Validate one exact steering profile against a live PMD and RX stream set.
 * @param facts Borrowed complete driver facts.
 * @param port Exact compiled port row.
 * @param device_info Native steering capabilities observed for that port.
 * @param native_port Materialization state receiving the owned RSS key, queue set, and RETA.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK after preparing admitted steering state, or a precise contract/capability failure.
 */
[[nodiscard]] kinetum_provider_status prepare_rss(const kinetum_provider_io_driver_facts &facts,
						  const kinetum_provider_io_port_fact &port,
						  const rte_eth_dev_info &device_info, dpdk_port_state &native_port,
						  kinetum_provider_diagnostic *diagnostic) noexcept
{
	const kinetum_provider_steering_fact *steering = nullptr;
	uint32_t rx_stream_count = 0;
	for (uint32_t index = 0; index < facts.stream_count; ++index) {
		const auto &stream = facts.streams[index];
		if (!stream_matches(stream, port.port_index, KINETUM_PROVIDER_IO_DIRECTION_RX)) {
			continue;
		}
		++rx_stream_count;
		if (stream.has_steering_profile == 0) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK RX queue has no exact steering profile");
		}
		const auto *candidate = find_steering_fact(facts, stream.steering_profile_index);
		if (candidate == nullptr || (steering != nullptr && steering != candidate)) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK RX queues do not share one exact steering profile");
		}
		steering = candidate;
	}
	if (rx_stream_count != native_port.rx_queue_count) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK RX queue ownership is incomplete");
	}
	if (rx_stream_count == 0) {
		if (steering != nullptr) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK port without RX queues references steering");
		}
		return KINETUM_PROVIDER_STATUS_OK;
	}
	if (steering == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK exact RX steering resolution lost its admitted profile");
	}
	if (steering->io_stream_count != rx_stream_count) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK steering stream set is incomplete");
	}
	for (uint32_t index = 0; index < steering->io_stream_count; ++index) {
		bool matched = false;
		for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
			const auto &stream = facts.streams[stream_index];
			matched = matched ||
				  (stream.io_stream_index == steering->io_stream_indices[index] &&
				   stream_matches(stream, port.port_index, KINETUM_PROVIDER_IO_DIRECTION_RX));
		}
		if (!matched) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK steering references a foreign RX stream");
		}
	}
	if (steering->kind == KINETUM_PROVIDER_STEERING_NONE) {
		return rx_stream_count == 1 && steering->symmetric == 0 && steering->hash_field_count == 0 &&
				       steering->hash_key.size == 0 ?
			       KINETUM_PROVIDER_STATUS_OK :
			       fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK NONE steering is not one exact queue");
	}
	if (steering->kind != KINETUM_PROVIDER_STEERING_RSS || rx_stream_count < 2 || steering->hash_field_count != 2 ||
	    !component_support::text_equals(steering->hash_fields[0], RSS_FIELD_IPV4) ||
	    !component_support::text_equals(steering->hash_fields[1], RSS_FIELD_UDP) || steering->hash_key.size == 0 ||
	    steering->hash_key.size > std::numeric_limits<uint8_t>::max() || device_info.hash_key_size == 0 ||
	    steering->hash_key.size != device_info.hash_key_size || device_info.reta_size == 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK RSS shape or key does not match the exact current contract");
	}
	const uint64_t rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_UDP;
	if ((device_info.flow_type_rss_offloads & rss_hf) != rss_hf) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK PMD does not support the exact RSS field set");
	}
	native_port.rss_key.assign(steering->hash_key.data, steering->hash_key.data + steering->hash_key.size);
	native_port.rss_queues.clear();
	native_port.rss_queues.reserve(steering->io_stream_count);
	for (uint32_t index = 0; index < steering->io_stream_count; ++index) {
		const kinetum_provider_io_stream_fact *matched_stream = nullptr;
		for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
			const auto &stream = facts.streams[stream_index];
			if (stream.io_stream_index != steering->io_stream_indices[index] ||
			    !stream_matches(stream, port.port_index, KINETUM_PROVIDER_IO_DIRECTION_RX)) {
				continue;
			}
			if (matched_stream != nullptr) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK steering stream identity is duplicated");
			}
			matched_stream = &stream;
		}
		if (matched_stream == nullptr || matched_stream->driver_queue_id > UINT16_MAX) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK steering queue identity is not representable");
		}
		const uint16_t queue = static_cast<uint16_t>(matched_stream->driver_queue_id);
		if (std::find(native_port.rss_queues.begin(), native_port.rss_queues.end(), queue) !=
		    native_port.rss_queues.end()) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK steering queue identity is duplicated");
		}
		native_port.rss_queues.push_back(queue);
	}
	native_port.symmetric_rss = steering->symmetric != 0;
	native_port.configuration.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	native_port.configuration.rx_adv_conf.rss_conf.rss_hf = rss_hf;
	native_port.configuration.rx_adv_conf.rss_conf.rss_key = native_port.rss_key.data();
	native_port.configuration.rx_adv_conf.rss_conf.rss_key_len = static_cast<uint8_t>(native_port.rss_key.size());
	native_port.reta_size = device_info.reta_size;
	const std::size_t group_count =
		(static_cast<std::size_t>(native_port.reta_size) + RTE_ETH_RETA_GROUP_SIZE - 1u) /
		RTE_ETH_RETA_GROUP_SIZE;
	native_port.reta.assign(group_count, rte_eth_rss_reta_entry64{});
	for (uint16_t reta_index = 0; reta_index < native_port.reta_size; ++reta_index) {
		const std::size_t group = reta_index / RTE_ETH_RETA_GROUP_SIZE;
		const uint16_t offset = reta_index % RTE_ETH_RETA_GROUP_SIZE;
		native_port.reta[group].mask |= UINT64_C(1) << offset;
		native_port.reta[group].reta[offset] = static_cast<uint16_t>(reta_index % native_port.rx_queue_count);
	}
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Install one exact symmetric-Toeplitz RSS action after port start.
 * @param api Borrowed native flow API.
 * @param port Started port retaining the prepared RSS state and any installed flow owner.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK when no symmetric rule is required or its installation succeeds; otherwise an explicit failure.
 */
[[nodiscard]] kinetum_provider_status install_symmetric_rss(const dpdk_ethdev_api &api, dpdk_port_state &port,
							    kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!port.symmetric_rss) {
		return KINETUM_PROVIDER_STATUS_OK;
	}
	if (!port.started || port.symmetric_rss_flow != nullptr || port.rss_key.empty() || port.rss_queues.size() < 2 ||
	    port.rss_key.size() > UINT32_MAX || port.rss_queues.size() > UINT32_MAX) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK symmetric RSS retained state is incomplete");
	}

	rte_flow_attr attributes{};
	attributes.ingress = 1;
	const std::array<rte_flow_item, 4> pattern{
		rte_flow_item{.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = nullptr, .last = nullptr, .mask = nullptr},
		rte_flow_item{.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = nullptr, .last = nullptr, .mask = nullptr},
		rte_flow_item{.type = RTE_FLOW_ITEM_TYPE_UDP, .spec = nullptr, .last = nullptr, .mask = nullptr},
		rte_flow_item{.type = RTE_FLOW_ITEM_TYPE_END, .spec = nullptr, .last = nullptr, .mask = nullptr},
	};
	rte_flow_action_rss rss{};
	rss.func = RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
	rss.level = 1;
	rss.types = RTE_ETH_RSS_NONFRAG_IPV4_UDP;
	rss.key_len = static_cast<uint32_t>(port.rss_key.size());
	rss.queue_num = static_cast<uint32_t>(port.rss_queues.size());
	rss.key = port.rss_key.data();
	rss.queue = port.rss_queues.data();
	const std::array<rte_flow_action, 2> actions{
		rte_flow_action{.type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &rss},
		rte_flow_action{.type = RTE_FLOW_ACTION_TYPE_END, .conf = nullptr},
	};
	rte_flow_error error{};
	if (api.validate_flow(api.state, port.physical_port, &attributes, pattern.data(), actions.data(), &error) !=
	    0) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK PMD does not support the exact symmetric RSS rule");
	}
	port.symmetric_rss_flow =
		api.create_flow(api.state, port.physical_port, &attributes, pattern.data(), actions.data(), &error);
	if (port.symmetric_rss_flow == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK failed to install the validated symmetric RSS rule");
	}
	return KINETUM_PROVIDER_STATUS_OK;
}

/**
 * @brief Retire one live port without releasing configured ownership.
 * @param api Borrowed native flow and ethdev API.
 * @param port Configured live port whose flow and start ownership are retired in order.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return OK after stopping the port; failure preserves unresolved ownership in the port state.
 */
[[nodiscard]] kinetum_provider_status deactivate_dpdk_port(const dpdk_ethdev_api &api, dpdk_port_state &port,
							   kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!port.configured || !port.started) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK deactivation found a port outside the exact live state");
	}
	if (port.symmetric_rss_flow != nullptr) {
		rte_flow_error error{};
		if (api.destroy_flow(api.state, port.physical_port, port.symmetric_rss_flow, &error) != 0) {
			return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
				    "DPDK failed to retire an exact symmetric RSS rule");
		}
		port.symmetric_rss_flow = nullptr;
	}
	if (api.stop(api.state, port.physical_port) != 0) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK failed to stop an exact ethdev port");
	}
	port.started = false;
	return KINETUM_PROVIDER_STATUS_OK;
}

}  // namespace

dpdk_mempool_api default_dpdk_mempool_api() noexcept
{
	return dpdk_mempool_api{
		.state = nullptr,
		.create = native_mempool_create,
		.iterate = native_mempool_iterate,
		.private_size = native_mempool_private_size,
		.in_use_count = native_mempool_in_use_count,
		.free = native_mempool_free,
	};
}

dpdk_ethdev_api default_dpdk_ethdev_api() noexcept
{
	return dpdk_ethdev_api{
		.state = nullptr,
		.device_info = native_device_info,
		.device_socket = native_device_socket,
		.configure = native_configure,
		.set_mtu = native_set_mtu,
		.setup_rx_queue = native_setup_rx_queue,
		.setup_tx_queue = native_setup_tx_queue,
		.start = native_start,
		.stop = native_stop,
		.close = native_close,
		.mac_address = native_mac_address,
		.update_reta = native_update_reta,
		.validate_flow = native_validate_flow,
		.create_flow = native_create_flow,
		.destroy_flow = native_destroy_flow,
		.statistics = native_statistics,
	};
}

dpdk_packet_storage::dpdk_packet_storage(std::unique_ptr<implementation> state) noexcept
	: state_(std::move(state))
{
	operations_.state = this;
	operations_.acquire_burst = acquire_burst_;
	operations_.clone_writable = clone_writable_;
	operations_.copy_origins_burst = copy_origins_burst_;
	operations_.release_burst = release_burst_;
	operations_.observe_statistics = observe_statistics_;
}

dpdk_packet_storage::~dpdk_packet_storage() noexcept
{
	if (state_->pool != nullptr) {
		if (state_->api.in_use_count(state_->api.state, state_->pool) != 0) {
			std::terminate();
		}
		state_->api.free(state_->api.state, state_->pool);
		state_->pool = nullptr;
	}
}

kinetum_provider_status dpdk_packet_storage::create(const kinetum_provider_factory_request &request,
						    const dpdk_mempool_api &api,
						    std::unique_ptr<dpdk_packet_storage> &output,
						    kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (output != nullptr || !mempool_api_is_complete(api) ||
	    kinetum_provider_factory_request_is_valid(&request) == 0 ||
	    request.role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE ||
	    !component_support::text_equals(request.type_url, DPDK_STORAGE_TYPE_URL) ||
	    request.runtime_generation > UINT32_MAX || request.dependency_count != 1) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK storage received a malformed exact request");
	}
	const auto *facility = facility_dependency(request);
	const auto &facts = *request.compiled_facts.packet_storage;
	if (facility == nullptr || !facility->active() ||
	    facility->operations().generation != request.runtime_generation ||
	    !facility->contains_memory_domain(facts) || facts.storage_domain_index >= KINETUM_INVALID_STORAGE_DOMAIN ||
	    facts.buffer_count == 0 || facts.buffer_count < facts.required_buffer_count || facts.data_room_bytes == 0 ||
	    facts.data_room_bytes > UINT16_MAX || facts.headroom_bytes != RTE_PKTMBUF_HEADROOM ||
	    facts.headroom_bytes >= facts.data_room_bytes || facts.alignment_bytes < alignof(kinetum_packet_record) ||
	    (facts.alignment_bytes & (facts.alignment_bytes - 1u)) != 0 ||
	    facts.cache_size_per_worker > RTE_MEMPOOL_CACHE_MAX_SIZE ||
	    facts.cache_size_per_worker > facts.buffer_count ||
	    facts.maximum_packet_length != facts.data_room_bytes - facts.headroom_bytes ||
	    facts.access_agents != DPDK_STORAGE_ACCESS_AGENTS || facts.has_host_numa_node != 1 ||
	    facts.host_numa_node < 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK storage facts do not describe one exact native domain");
	}

	try {
		auto state = std::make_unique<implementation>();
		state->api = api;
		state->buffer_count = facts.buffer_count;
		state->facility = facility;
		state->alignment_bytes = facts.alignment_bytes;
		state->host_numa_node = facts.host_numa_node;
		std::array<char, RTE_MEMPOOL_NAMESIZE> pool_name{};
		const int name_size = std::snprintf(pool_name.data(), pool_name.size(), "kntm_g%u_d%u",
						    static_cast<uint32_t>(request.runtime_generation),
						    facts.storage_domain_index);
		if (name_size <= 0 || static_cast<std::size_t>(name_size) >= pool_name.size()) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK storage identity does not fit a native pool name");
		}
		auto candidate = std::unique_ptr<dpdk_packet_storage>(new dpdk_packet_storage(std::move(state)));
		candidate->state_->pool = api.create(api.state, pool_name.data(), facts.buffer_count,
						     facts.cache_size_per_worker, dp::DPDK_PACKET_RECORD_PRIVATE_SIZE,
						     static_cast<uint16_t>(facts.data_room_bytes),
						     facts.host_numa_node);
		if (candidate->state_->pool == nullptr) {
			return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
				    "DPDK could not allocate the exact mbuf population");
		}
		candidate->operations_.generation = static_cast<uint32_t>(request.runtime_generation);
		candidate->operations_.domain_index = static_cast<uint16_t>(facts.storage_domain_index);
		candidate->operations_.maximum_packet_length = facts.maximum_packet_length;
		candidate->operations_.capabilities = DPDK_STORAGE_CAPABILITIES;
		if (candidate->state_->api.private_size(candidate->state_->api.state, candidate->state_->pool) <
		    sizeof(kinetum_packet_record)) {
			return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
				    "DPDK mbuf private storage is smaller than packet_record");
		}
		dpdk_pool_population_probe probe{
			.observed = 0,
			.alignment_bytes = facts.alignment_bytes,
			.data_room_bytes = facts.data_room_bytes,
			.headroom_bytes = facts.headroom_bytes,
			.valid = true,
		};
		const uint32_t iterated = candidate->state_->api.iterate(
			candidate->state_->api.state, candidate->state_->pool, inspect_pool_object, &probe);
		if (iterated != facts.buffer_count || probe.observed != facts.buffer_count || !probe.valid ||
		    !kinetum_provider_packet_storage_operations_are_valid(&candidate->operations_)) {
			return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
				    "DPDK mbuf population failed exact record or payload layout proof");
		}
		output = std::move(candidate);
		component_support::write_diagnostic(diagnostic, std::string_view{});
		return KINETUM_PROVIDER_STATUS_OK;
	} catch (const std::bad_alloc &) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "DPDK storage host-state allocation failed");
	} catch (...) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK storage construction raised an unexpected failure");
	}
}

const kinetum_packet_storage_domain_operations &dpdk_packet_storage::operations() const noexcept
{
	return operations_;
}

rte_mempool *dpdk_packet_storage::native_pool() const noexcept
{
	return state_->pool;
}

int32_t dpdk_packet_storage::host_numa_node() const noexcept
{
	return state_->host_numa_node;
}

const dpdk_process_facility *dpdk_packet_storage::facility() const noexcept
{
	return state_->facility;
}

uint16_t dpdk_packet_storage::acquire_burst_(void *state, kinetum_packet_record **records, uint16_t capacity) noexcept
{
	auto *storage = static_cast<dpdk_packet_storage *>(state);
	if (storage == nullptr || storage->state_->pool == nullptr || records == nullptr || capacity == 0) {
		return 0;
	}
	const uint16_t attempted = std::min(capacity, MAX_BURST);
	std::array<rte_mbuf *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> native;
	if (rte_pktmbuf_alloc_bulk(storage->state_->pool, native.data(), attempted) != 0) {
		return 0;
	}
	for (uint16_t index = 0; index < attempted; ++index) {
		records[index] = dp::initialize_dpdk_packet_record(native[index], storage->operations_);
		if (records[index] == nullptr) {
			std::terminate();
		}
	}
	return attempted;
}

kinetum_packet_record *dpdk_packet_storage::clone_writable_(void *state, const kinetum_packet_record *source) noexcept
{
	auto *storage = static_cast<dpdk_packet_storage *>(state);
	if (storage == nullptr || source == nullptr || storage->state_->pool == nullptr ||
	    !dp::dpdk_packet_record_matches_storage(source, storage->operations_) || source->storage.length == 0 ||
	    source->storage.length > storage->operations_.maximum_packet_length) {
		return nullptr;
	}
	rte_mbuf *native = rte_pktmbuf_alloc(storage->state_->pool);
	if (native == nullptr) {
		return nullptr;
	}
	auto *destination = rte_pktmbuf_append(native, static_cast<uint16_t>(source->storage.length));
	if (destination == nullptr) {
		rte_pktmbuf_free(native);
		return nullptr;
	}
	std::memcpy(destination, source->storage.data, source->storage.length);
	auto *record = dp::initialize_dpdk_packet_record(native, storage->operations_);
	if (record == nullptr) {
		std::terminate();
	}
	record->metadata = source->metadata;
	return record;
}

uint16_t dpdk_packet_storage::copy_origins_burst_(void *state, const kinetum_packet_origin_view *origins,
						  kinetum_packet_record **records, uint16_t count) noexcept
{
	auto *storage = static_cast<dpdk_packet_storage *>(state);
	if (storage == nullptr || storage->state_->pool == nullptr || origins == nullptr || records == nullptr ||
	    count == 0) {
		return 0;
	}
	const uint16_t attempted = std::min(count, MAX_BURST);
	for (uint16_t index = 0; index < attempted; ++index) {
		if (origins[index].data == nullptr || origins[index].length == 0 || origins[index].padding != 0 ||
		    origins[index].length > storage->operations_.maximum_packet_length) {
			return 0;
		}
	}
	std::array<rte_mbuf *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> native;
	if (rte_pktmbuf_alloc_bulk(storage->state_->pool, native.data(), attempted) != 0) {
		return 0;
	}
	for (uint16_t index = 0; index < attempted; ++index) {
		auto *destination = rte_pktmbuf_append(native[index], static_cast<uint16_t>(origins[index].length));
		if (destination == nullptr) {
			rte_pktmbuf_free_bulk(native.data(), attempted);
			return 0;
		}
		std::memcpy(destination, origins[index].data, origins[index].length);
	}
	for (uint16_t index = 0; index < attempted; ++index) {
		records[index] = dp::initialize_dpdk_packet_record(native[index], storage->operations_);
		if (records[index] == nullptr) {
			std::terminate();
		}
	}
	return attempted;
}

void dpdk_packet_storage::release_burst_(void *state, kinetum_packet_record *const *records, uint16_t count) noexcept
{
	auto *storage = static_cast<dpdk_packet_storage *>(state);
	if (storage == nullptr || storage->state_->pool == nullptr || records == nullptr || count == 0 ||
	    count > MAX_BURST) {
		std::terminate();
	}
	std::array<rte_mbuf *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> native;
	for (uint16_t index = 0; index < count; ++index) {
		if (!dp::dpdk_packet_record_matches_storage(records[index], storage->operations_)) {
			std::terminate();
		}
		native[index] = static_cast<rte_mbuf *>(records[index]->storage.native_handle);
	}
	// Claim the complete validated burst before publishing any mbuf back to the
	// native pool. A duplicate record fails on its second claim, closing the
	// release/reacquire ABA window in linear time without packet-path storage.
	for (uint16_t index = 0; index < count; ++index) {
		if (records[index]->storage.native_handle != native[index]) {
			std::terminate();
		}
		records[index]->storage.native_handle = nullptr;
	}
	rte_pktmbuf_free_bulk(native.data(), count);
}

kinetum_provider_status dpdk_packet_storage::observe_statistics_(void *state,
								 kinetum_provider_storage_observation *observation,
								 kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *storage = static_cast<dpdk_packet_storage *>(state);
	if (storage == nullptr || storage->state_ == nullptr || storage->state_->pool == nullptr ||
	    observation == nullptr ||
	    (diagnostic != nullptr && diagnostic->data == nullptr && diagnostic->capacity != 0u)) {
		return KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT;
	}
	*observation = {};
	observation->runtime_generation = storage->operations_.generation;
	observation->storage_domain_index = storage->operations_.domain_index;
	const uint32_t in_use = storage->state_->api.in_use_count(storage->state_->api.state, storage->state_->pool);
	if (in_use > storage->state_->buffer_count) {
		observation->state = KINETUM_PROVIDER_OBSERVATION_READ_FAILED;
	} else {
		observation->state = KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE;
		observation->in_use = in_use;
		observation->available = storage->state_->buffer_count - in_use;
	}
	if (diagnostic != nullptr) {
		diagnostic->size = 0u;
	}
	return KINETUM_PROVIDER_STATUS_OK;
}

dpdk_io_driver::dpdk_io_driver(std::unique_ptr<implementation> state) noexcept
	: state_(std::move(state))
{
	operations_.state = this;
	operations_.activate_packet_io = activate_packet_io_callback_;
	operations_.deactivate_packet_io = deactivate_packet_io_callback_;
	operations_.rx_queues = state_->rx_operations.get();
	operations_.tx_queues = state_->tx_operations.get();
	operations_.observe_statistics = observe_statistics_callback_;
	operations_.rx_queue_count = state_->rx_queue_count;
	operations_.tx_queue_count = state_->tx_queue_count;
}

dpdk_io_driver::~dpdk_io_driver() noexcept
{
	if (state_->active) {
		std::terminate();
	}
	for (uint32_t index = 0; index < state_->port_count; ++index) {
		const auto &port = state_->ports[index];
		if (port.started || port.symmetric_rss_flow != nullptr) {
			std::terminate();
		}
	}
	bool complete = true;
	for (uint32_t remaining = state_->port_count; remaining > 0; --remaining) {
		auto &port = state_->ports[remaining - 1u];
		if (port.configured) {
			const int result = state_->api.close(state_->api.state, port.physical_port);
			if (result != 0) {
				std::fprintf(stderr, "DPDK port %u close failed (result=%d)\n",
					     static_cast<unsigned int>(port.physical_port), result);
				complete = false;
				continue;
			}
			port.configured = false;
		}
	}
	if (!complete) {
		std::terminate();
	}
}

kinetum_provider_status dpdk_io_driver::activate_packet_io_(kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (state_->active) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK driver is already packet-active");
	}
	uint32_t activated_count = 0;
	auto rollback = [&]() noexcept {
		for (uint32_t remaining = activated_count; remaining > 0; --remaining) {
			if (deactivate_dpdk_port(state_->api, state_->ports[remaining - 1u], nullptr) !=
			    KINETUM_PROVIDER_STATUS_OK) {
				std::terminate();
			}
		}
	};
	for (uint32_t port_index = 0; port_index < state_->port_count; ++port_index) {
		auto &port = state_->ports[port_index];
		if (!port.configured || port.started || port.symmetric_rss_flow != nullptr) {
			rollback();
			return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
				    "DPDK activation found a port outside the exact cold state");
		}
		if (state_->api.start(state_->api.state, port.physical_port) != 0) {
			rollback();
			return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
				    "DPDK ethdev start failed");
		}
		port.started = true;
		++activated_count;
		if (port.reta_size != 0 && state_->api.update_reta(state_->api.state, port.physical_port,
								   port.reta.data(), port.reta_size) != 0) {
			rollback();
			return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
				    "DPDK PMD rejected the exact RSS redirection table");
		}
		const auto flow_status = install_symmetric_rss(state_->api, port, diagnostic);
		if (flow_status != KINETUM_PROVIDER_STATUS_OK) {
			rollback();
			return flow_status;
		}
	}
	state_->active = true;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

kinetum_provider_status dpdk_io_driver::deactivate_packet_io_(kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (!state_->active) {
		return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
			    "DPDK driver is not packet-active");
	}
	for (uint32_t remaining = state_->port_count; remaining > 0; --remaining) {
		const auto status = deactivate_dpdk_port(state_->api, state_->ports[remaining - 1u], diagnostic);
		if (status != KINETUM_PROVIDER_STATUS_OK) {
			return status;
		}
	}
	state_->active = false;
	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

kinetum_provider_status dpdk_io_driver::activate_packet_io_callback_(void *state,
								     kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *driver = static_cast<dpdk_io_driver *>(state);
	if (driver == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK activation received a null driver");
	}
	return driver->activate_packet_io_(diagnostic);
}

kinetum_provider_status dpdk_io_driver::deactivate_packet_io_callback_(void *state,
								       kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *driver = static_cast<dpdk_io_driver *>(state);
	if (driver == nullptr) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK deactivation received a null driver");
	}
	return driver->deactivate_packet_io_(diagnostic);
}

kinetum_provider_status
dpdk_io_driver::observe_statistics_callback_(void *state, kinetum_provider_io_observation_batch *observations,
					     kinetum_provider_diagnostic *diagnostic) noexcept
{
	auto *driver = static_cast<dpdk_io_driver *>(state);
	if (driver == nullptr || driver->state_ == nullptr || observations == nullptr ||
	    observations->port_count != driver->state_->port_count ||
	    (observations->port_count != 0u && observations->ports == nullptr) || observations->port_padding != 0u ||
	    !std::all_of(std::begin(observations->padding), std::end(observations->padding),
			 [](uint8_t byte) { return byte == 0u; })) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK statistics received a malformed caller-owned observation batch");
	}

	for (uint32_t position = 0u; position < driver->state_->port_count; ++position) {
		rte_eth_stats native{};
		const auto &source = driver->state_->ports[position];
		auto &target = observations->ports[position];
		target = {};
		target.port_index = source.port_index;
		if (driver->state_->api.statistics(driver->state_->api.state, source.physical_port, &native) != 0) {
			target.state = KINETUM_PROVIDER_OBSERVATION_READ_FAILED;
			continue;
		}
		target.state = KINETUM_PROVIDER_OBSERVATION_AVAILABLE_EXACT;
		target.rx_packets = native.ipackets;
		target.tx_packets = native.opackets;
		target.rx_bytes = native.ibytes;
		target.tx_bytes = native.obytes;
		target.rx_missed = native.imissed;
		target.rx_errors = native.ierrors;
		target.tx_errors = native.oerrors;
		target.rx_no_buffer = native.rx_nombuf;
	}

	component_support::write_diagnostic(diagnostic, std::string_view{});
	return KINETUM_PROVIDER_STATUS_OK;
}

kinetum_provider_status dpdk_io_driver::create(const kinetum_provider_factory_request &request,
					       const dpdk_ethdev_api &api, std::unique_ptr<dpdk_io_driver> &output,
					       kinetum_provider_diagnostic *diagnostic) noexcept
{
	if (output != nullptr || !ethdev_api_is_complete(api) ||
	    kinetum_provider_factory_request_is_valid(&request) == 0 ||
	    request.role != KINETUM_PROVIDER_ROLE_IO_DRIVER ||
	    !component_support::text_equals(request.type_url, DPDK_DRIVER_TYPE_URL) ||
	    request.runtime_generation > UINT32_MAX || request.dependency_count < 2) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK driver received a malformed exact request");
	}
	const auto *facility = facility_dependency(request);
	const auto &facts = *request.compiled_facts.io_driver;
	if (facility == nullptr || !facility->active() ||
	    facility->operations().generation != request.runtime_generation || facts.attachment_count == 0 ||
	    facts.port_count == 0 || facts.stream_count == 0) {
		return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
			    "DPDK driver facts or facility dependency are incomplete");
	}
	for (uint32_t dependency_index = 0; dependency_index < request.dependency_count; ++dependency_index) {
		const auto &dependency = request.dependencies[dependency_index];
		if (dependency_index == 0) {
			if (dependency.role != KINETUM_PROVIDER_ROLE_PROCESS_FACILITY ||
			    dependency.instance != facility) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK facility is not the first exact dependency");
			}
			continue;
		}
		if (dependency.role != KINETUM_PROVIDER_ROLE_PACKET_STORAGE ||
		    !component_support::text_equals(dependency.type_url, DPDK_STORAGE_TYPE_URL)) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK driver received a non-DPDK storage dependency");
		}
		const auto *storage = static_cast<const dpdk_packet_storage *>(dependency.instance);
		if (storage == nullptr || dependency.operations != &storage->operations() ||
		    storage->operations().generation != request.runtime_generation) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK storage dependency identity is inconsistent");
		}
		bool used = false;
		for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
			used = used || kinetum_provider_io_stream_uses_storage(&facts.streams[stream_index],
									       storage->operations().domain_index) != 0;
		}
		if (!used) {
			return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
				    "DPDK driver received an unused storage dependency");
		}
	}

	try {
		auto state = std::make_unique<implementation>();
		state->api = api;
		state->facility = facility;
		state->port_count = facts.port_count;
		state->ports = std::make_unique<dpdk_port_state[]>(facts.port_count);
		for (uint32_t index = 0; index < facts.stream_count; ++index) {
			if (facts.streams[index].direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
				++state->rx_queue_count;
			} else if (facts.streams[index].direction == KINETUM_PROVIDER_IO_DIRECTION_TX) {
				++state->tx_queue_count;
			} else {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK stream direction is not exact RX or TX");
			}
		}
		if (state->rx_queue_count != 0) {
			state->rx_queues = std::make_unique<implementation::rx_queue[]>(state->rx_queue_count);
			state->rx_operations =
				std::make_unique<kinetum_packet_rx_burst_operations[]>(state->rx_queue_count);
		}
		if (state->tx_queue_count != 0) {
			state->tx_queues = std::make_unique<implementation::tx_queue[]>(state->tx_queue_count);
			state->tx_operations =
				std::make_unique<kinetum_packet_tx_burst_operations[]>(state->tx_queue_count);
		}

		for (uint32_t port_position = 0; port_position < facts.port_count; ++port_position) {
			const auto &port = facts.ports[port_position];
			if (port.driver_port_index >= facts.attachment_count ||
			    port.logical_port_id >= KINETUM_INVALID_PORT || port.mtu == 0 || port.mtu > UINT16_MAX) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK port facts are not representable");
			}
			for (uint32_t earlier = 0; earlier < port_position; ++earlier) {
				if (facts.ports[earlier].port_index == port.port_index ||
				    facts.ports[earlier].driver_port_index == port.driver_port_index ||
				    facts.ports[earlier].logical_port_id == port.logical_port_id) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK port ownership is duplicated");
				}
			}
			const auto &attachment = facts.attachments[port.driver_port_index];
			if (attachment.io_driver_index != facts.io_driver_index ||
			    (attachment.kind != KINETUM_PROVIDER_ATTACHMENT_PCI &&
			     attachment.kind != KINETUM_PROVIDER_ATTACHMENT_TAP)) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK port references a foreign native attachment");
			}
			auto &native_port = state->ports[port_position];
			if (!facility->resolve_physical_port(attachment, native_port.physical_port)) {
				return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
					    "DPDK facility cannot resolve an exact driver attachment");
			}
			for (uint32_t earlier = 0; earlier < port_position; ++earlier) {
				if (state->ports[earlier].physical_port == native_port.physical_port) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK driver claims one ethdev through multiple ports");
				}
			}
			native_port.port_index = port.port_index;
			native_port.mtu = static_cast<uint16_t>(port.mtu);
			for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
				const auto &stream = facts.streams[stream_index];
				if (stream.port_index != port.port_index) {
					continue;
				}
				if (!direction_matches(port.direction, stream.direction) ||
				    stream.driver_queue_id > UINT16_MAX || stream.descriptor_count == 0 ||
				    stream.descriptor_count > UINT16_MAX) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK stream is not representable by its exact port");
				}
				if (stream.direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
					++native_port.rx_queue_count;
				} else {
					++native_port.tx_queue_count;
				}
			}
			for (uint16_t queue = 0; queue < native_port.rx_queue_count; ++queue) {
				uint32_t matches = 0;
				for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
					const auto &stream = facts.streams[stream_index];
					matches += stream_matches(stream, port.port_index,
								  KINETUM_PROVIDER_IO_DIRECTION_RX) &&
								   stream.driver_queue_id == queue ?
							   1u :
							   0u;
				}
				if (matches != 1) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK RX queue IDs are not one dense exact range");
				}
			}
			for (uint16_t queue = 0; queue < native_port.tx_queue_count; ++queue) {
				uint32_t matches = 0;
				for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
					const auto &stream = facts.streams[stream_index];
					matches += stream_matches(stream, port.port_index,
								  KINETUM_PROVIDER_IO_DIRECTION_TX) &&
								   stream.driver_queue_id == queue ?
							   1u :
							   0u;
				}
				if (matches != 1) {
					return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						    "DPDK TX queue IDs are not one dense exact range");
				}
			}

			rte_eth_dev_info device_info{};
			if (api.device_info(api.state, native_port.physical_port, &device_info) != 0 ||
			    native_port.rx_queue_count > device_info.max_rx_queues ||
			    native_port.tx_queue_count > device_info.max_tx_queues) {
				return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
					    "DPDK PMD cannot satisfy the exact queue population");
			}
			for (uint32_t stream_index = 0; stream_index < facts.stream_count; ++stream_index) {
				const auto &stream = facts.streams[stream_index];
				if (stream.port_index != port.port_index) {
					continue;
				}
				const auto &limits = stream.direction == KINETUM_PROVIDER_IO_DIRECTION_RX ?
							     device_info.rx_desc_lim :
							     device_info.tx_desc_lim;
				if (!descriptor_count_is_exact(static_cast<uint16_t>(stream.descriptor_count),
							       limits)) {
					return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
						    "DPDK PMD rejected an exact descriptor count");
				}
			}
			const int device_socket = api.device_socket(api.state, native_port.physical_port);
			if (port.has_host_numa_node != 0 &&
			    (device_socket < 0 || device_socket != port.host_numa_node)) {
				return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
					    "DPDK ethdev NUMA identity disagrees with plan truth");
			}
			if (port.has_resolved_mac_address != 0) {
				rte_ether_addr address{};
				if (api.mac_address(api.state, native_port.physical_port, &address) != 0 ||
				    !mac_matches(port.resolved_mac_address, address)) {
					return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
						    "DPDK ethdev MAC disagrees with resolved plan truth");
				}
			}
			native_port.configuration.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
			native_port.configuration.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
			native_port.rx_configuration = device_info.default_rxconf;
			native_port.tx_configuration = device_info.default_txconf;
			const auto rss_status = prepare_rss(facts, port, device_info, native_port, diagnostic);
			if (rss_status != KINETUM_PROVIDER_STATUS_OK) {
				return rss_status;
			}
		}

		uint32_t rx_position = 0;
		uint32_t tx_position = 0;
		for (uint32_t stream_position = 0; stream_position < facts.stream_count; ++stream_position) {
			const auto &stream = facts.streams[stream_position];
			const auto *port = find_port_fact(facts, stream.port_index);
			if (port == nullptr) {
				return fail(KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
					    "DPDK stream has no exact port dependency");
			}
			dpdk_port_state *native_port = nullptr;
			for (uint32_t index = 0; index < state->port_count; ++index) {
				if (state->ports[index].port_index == stream.port_index) {
					native_port = &state->ports[index];
					break;
				}
			}
			if (native_port == nullptr) {
				return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
					    "DPDK compiled port lookup lost an admitted stream");
			}
			int32_t storage_numa_node = -1;
			for (uint32_t domain_index = 0; domain_index < stream.storage_domain_count; ++domain_index) {
				const auto *storage =
					storage_dependency(request, stream.storage_domain_indices[domain_index]);
				if (storage == nullptr || storage->host_numa_node() < 0 ||
				    storage->native_pool() == nullptr || storage->facility() != facility ||
				    (domain_index != 0 && storage->host_numa_node() != storage_numa_node) ||
				    (port->has_host_numa_node != 0 &&
				     storage->host_numa_node() != port->host_numa_node) ||
				    storage->operations().maximum_packet_length < port->mtu) {
					return fail(
						KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT, diagnostic,
						"DPDK stream storage disagrees with its native facility, NUMA, or MTU");
				}
				storage_numa_node = storage->host_numa_node();
			}

			if (stream.direction == KINETUM_PROVIDER_IO_DIRECTION_RX) {
				auto &queue = state->rx_queues[rx_position];
				queue.physical_port = native_port->physical_port;
				queue.queue_id = static_cast<uint16_t>(stream.driver_queue_id);
				queue.logical_port = static_cast<uint16_t>(port->logical_port_id);
				queue.descriptors = static_cast<uint16_t>(stream.descriptor_count);
				queue.storage = storage_dependency(request, stream.storage_domain_indices[0]);
				state->rx_operations[rx_position] = kinetum_packet_rx_burst_operations{
					.state = &queue,
					.receive_burst = receive_burst_,
					.maximum_burst = MAX_BURST,
					.logical_port = queue.logical_port,
					.padding = {0},
				};
				++rx_position;
			} else {
				auto &queue = state->tx_queues[tx_position];
				queue.host_numa_node = storage_numa_node;
				queue.physical_port = native_port->physical_port;
				queue.queue_id = static_cast<uint16_t>(stream.driver_queue_id);
				queue.logical_port = static_cast<uint16_t>(port->logical_port_id);
				queue.descriptors = static_cast<uint16_t>(stream.descriptor_count);
				if (stream.storage_domain_count > 1u && ((native_port->configuration.txmode.offloads |
									  native_port->tx_configuration.offloads) &
									 RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) != 0) {
					return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
						    "DPDK TX fast-free mode cannot admit multiple storage domains");
				}
				queue.storage_by_domain.resize(
					static_cast<std::size_t>(
						stream.storage_domain_indices[stream.storage_domain_count - 1u]) +
						1u,
					nullptr);
				for (uint32_t domain_index = 0; domain_index < stream.storage_domain_count;
				     ++domain_index) {
					const uint32_t domain = stream.storage_domain_indices[domain_index];
					queue.storage_by_domain[domain] = storage_dependency(request, domain);
				}
				state->tx_operations[tx_position] = kinetum_packet_tx_burst_operations{
					.state = &queue,
					.transmit_burst = transmit_burst_,
					.flush = flush_,
					.maybe_flush = maybe_flush_,
					.maximum_burst = MAX_BURST,
					.logical_port = queue.logical_port,
					.padding = {0},
				};
				++tx_position;
			}
		}
		if (rx_position != state->rx_queue_count || tx_position != state->tx_queue_count) {
			return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
				    "DPDK queue operation publication is incomplete");
		}

		// Complete every allocation and capability check before this owner crosses
		// the first foreign call that establishes configured ethdev ownership.
		auto candidate = std::unique_ptr<dpdk_io_driver>(new dpdk_io_driver(std::move(state)));
		candidate->operations_.io_driver_index = facts.io_driver_index;
		for (uint32_t port_index = 0; port_index < candidate->state_->port_count; ++port_index) {
			auto &port = candidate->state_->ports[port_index];
			if (api.configure(api.state, port.physical_port, port.rx_queue_count, port.tx_queue_count,
					  &port.configuration) != 0) {
				return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
					    "DPDK ethdev configuration failed");
			}
			// Claim immediately: every later error must close this port before any
			// dependent storage domain can retire.
			port.configured = true;
			if (api.set_mtu(api.state, port.physical_port, port.mtu) != 0) {
				return fail(KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION, diagnostic,
					    "DPDK PMD rejected the exact MTU");
			}
			for (uint32_t index = 0; index < candidate->state_->rx_queue_count; ++index) {
				const auto &queue = candidate->state_->rx_queues[index];
				if (queue.physical_port != port.physical_port) {
					continue;
				}
				if (api.setup_rx_queue(api.state, port.physical_port, queue.queue_id, queue.descriptors,
						       static_cast<unsigned int>(queue.storage->host_numa_node()),
						       &port.rx_configuration, queue.storage->native_pool()) != 0) {
					return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
						    "DPDK RX queue setup failed");
				}
			}
			for (uint32_t index = 0; index < candidate->state_->tx_queue_count; ++index) {
				const auto &queue = candidate->state_->tx_queues[index];
				if (queue.physical_port != port.physical_port) {
					continue;
				}
				if (api.setup_tx_queue(api.state, port.physical_port, queue.queue_id, queue.descriptors,
						       static_cast<unsigned int>(queue.host_numa_node),
						       &port.tx_configuration) != 0) {
					return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
						    "DPDK TX queue setup failed");
				}
			}
		}
		if (!kinetum_provider_io_driver_operations_are_valid(&candidate->operations_)) {
			return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
				    "DPDK driver produced an invalid operation record");
		}
		output = std::move(candidate);
		component_support::write_diagnostic(diagnostic, std::string_view{});
		return KINETUM_PROVIDER_STATUS_OK;
	} catch (const std::bad_alloc &) {
		return fail(KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED, diagnostic,
			    "DPDK driver host-state allocation failed");
	} catch (...) {
		return fail(KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR, diagnostic,
			    "DPDK driver construction raised an unexpected failure");
	}
}

const kinetum_provider_io_driver_operations &dpdk_io_driver::operations() const noexcept
{
	return operations_;
}

kinetum_packet_rx_burst_result dpdk_io_driver::receive_burst_(void *state, kinetum_packet_record **records,
							      uint16_t capacity) noexcept
{
	auto *queue = static_cast<implementation::rx_queue *>(state);
	if (queue == nullptr || queue->storage == nullptr || records == nullptr || capacity == 0) {
		return {};
	}
	const uint16_t requested = std::min(capacity, MAX_BURST);
	std::array<rte_mbuf *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> native;
	const uint16_t received = rte_eth_rx_burst(queue->physical_port, queue->queue_id, native.data(), requested);
	if (received > requested) {
		std::terminate();
	}
	uint16_t published = 0;
	for (uint16_t index = 0; index < received; ++index) {
		auto *mbuf = native[index];
		if (mbuf == nullptr) {
			std::terminate();
		}
		if (!dp::dpdk_packet_is_contiguous(*mbuf) || rte_pktmbuf_pkt_len(mbuf) == 0 ||
		    rte_pktmbuf_pkt_len(mbuf) > queue->storage->operations().maximum_packet_length) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		auto *record = dp::initialize_dpdk_packet_record(mbuf, queue->storage->operations());
		if (record == nullptr) {
			std::terminate();
		}
		record->metadata.ingress_port = queue->logical_port;
		records[published++] = record;
	}
	return {.transferred_count = published, .rejected_count = static_cast<uint16_t>(received - published)};
}

uint16_t dpdk_io_driver::transmit_burst_(void *state, kinetum_packet_record *const *records, uint16_t count) noexcept
{
	auto *queue = static_cast<implementation::tx_queue *>(state);
	if (count == 0) {
		return 0;
	}
	if (queue == nullptr || queue->storage_by_domain.empty() || records == nullptr || count > MAX_BURST) {
		std::terminate();
	}
	const uint16_t attempted = count;
	std::array<rte_mbuf *, common::runtime_sizing::PACKET_MAX_BURST_SIZE> native;
	uint16_t valid_prefix = 0;
	for (; valid_prefix < attempted; ++valid_prefix) {
		const auto *record = records[valid_prefix];
		if (record == nullptr || record->storage.domain_index >= queue->storage_by_domain.size()) {
			break;
		}
		const auto *storage = queue->storage_by_domain[record->storage.domain_index];
		if (storage == nullptr || !dp::dpdk_packet_record_matches_storage(record, storage->operations()) ||
		    record->storage.length == 0 ||
		    record->storage.length > storage->operations().maximum_packet_length) {
			break;
		}
		auto *mbuf = static_cast<rte_mbuf *>(record->storage.native_handle);
		if (mbuf->pool != storage->native_pool()) {
			break;
		}
		native[valid_prefix] = mbuf;
	}
	if (valid_prefix == 0) {
		return 0;
	}
	const uint16_t accepted = rte_eth_tx_burst(queue->physical_port, queue->queue_id, native.data(), valid_prefix);
	if (accepted > valid_prefix) {
		std::terminate();
	}
	return accepted;
}

void dpdk_io_driver::flush_(void *state) noexcept
{
	if (state == nullptr) {
		std::terminate();
	}
}

uint8_t dpdk_io_driver::maybe_flush_(void *state) noexcept
{
	if (state == nullptr) {
		std::terminate();
	}
	return 0;
}

}  // namespace kinetum::provider::dpdk_component
