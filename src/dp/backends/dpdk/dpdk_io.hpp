// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dpdk_io.hpp
 * @brief Exact DPDK packet-storage and ethdev I/O role owners.
 * @author Fleming Patel
 *
 * DPDK storage and I/O are independent component roles. A storage instance
 * owns one exact mbuf population and the provider-neutral storage operation
 * table. An I/O instance owns configured ethdev ports and immutable RX/TX
 * queue tables, borrowing exact storage domains through component dependency
 * handles. Neither role initializes EAL; both depend on one
 * dpdk_process_facility that outlives them.
 *
 * @par Performance
 * Native function tables below are cold construction/test seams only. Published
 * RX/TX and storage callbacks call DPDK burst/mempool primitives directly, so
 * no second indirect call, provider branch, allocation, lock, protobuf, or
 * string operation is added to the packet path.
 */

#include <cstdint>
#include <memory>

#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mempool.h>

#include "src/dp/backends/dpdk/dpdk_native_visibility.hpp"
#include "src/dp/backends/dpdk/dpdk_process_facility.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::provider::dpdk_component
{

/** @brief Cold mbuf-pool construction and retirement API. */
struct dpdk_mempool_api {
	void *state;  ///< Optional injected native state.
	rte_mempool *(*create)(void *state, const char *name, uint32_t count, uint32_t cache_size,
			       uint16_t private_size, uint16_t data_room_size,
			       int socket_id) noexcept;	 ///< Create one mbuf pool.
	uint32_t (*iterate)(void *state, rte_mempool *pool, rte_mempool_obj_cb_t *callback,
			    void *argument) noexcept;  ///< Inspect every native pool object.
	uint16_t (*private_size)(void *state,
				 const rte_mempool *pool) noexcept;		  ///< Read exact mbuf private bytes.
	uint32_t (*in_use_count)(void *state, const rte_mempool *pool) noexcept;  ///< Cold occupancy read.
	void (*free)(void *state, rte_mempool *pool) noexcept;			  ///< Retire one quiescent pool.
};

/** @return Complete mempool operation table backed by the native DPDK calls. */
[[nodiscard]] dpdk_mempool_api default_dpdk_mempool_api() noexcept;

/** @brief Cold ethdev configuration and retirement API. */
struct dpdk_ethdev_api {
	void *state;  ///< Optional injected native state.
	int (*device_info)(void *state, uint16_t port_id,
			   rte_eth_dev_info *info) noexcept;	       ///< Read immutable PMD capabilities.
	int (*device_socket)(void *state, uint16_t port_id) noexcept;  ///< Read exact/unknown device NUMA.
	int (*configure)(void *state, uint16_t port_id, uint16_t rx_queues, uint16_t tx_queues,
			 const rte_eth_conf *configuration) noexcept;	       ///< Configure port.
	int (*set_mtu)(void *state, uint16_t port_id, uint16_t mtu) noexcept;  ///< Apply exact MTU.
	int (*setup_rx_queue)(void *state, uint16_t port_id, uint16_t queue_id, uint16_t descriptors,
			      unsigned int socket_id, const rte_eth_rxconf *configuration,
			      rte_mempool *pool) noexcept;  ///< Construct one RX queue.
	int (*setup_tx_queue)(void *state, uint16_t port_id, uint16_t queue_id, uint16_t descriptors,
			      unsigned int socket_id,
			      const rte_eth_txconf *configuration) noexcept;  ///< Construct one TX queue.
	int (*start)(void *state, uint16_t port_id) noexcept;		      ///< Start one fully configured port.
	int (*stop)(void *state, uint16_t port_id) noexcept;		      ///< Stop one started port.
	int (*close)(void *state, uint16_t port_id) noexcept;		      ///< Close one stopped configured port.
	int (*mac_address)(void *state, uint16_t port_id,
			   rte_ether_addr *address) noexcept;  ///< Read exact device MAC.
	int (*update_reta)(void *state, uint16_t port_id, rte_eth_rss_reta_entry64 *entries,
			   uint16_t reta_size) noexcept;  ///< Program the complete exact RETA.
	int (*validate_flow)(void *state, uint16_t port_id, const rte_flow_attr *attributes,
			     const rte_flow_item *pattern, const rte_flow_action *actions,
			     rte_flow_error *error) noexcept;  ///< Prove one exact flow rule is supported.
	rte_flow *(*create_flow)(void *state, uint16_t port_id, const rte_flow_attr *attributes,
				 const rte_flow_item *pattern, const rte_flow_action *actions,
				 rte_flow_error *error) noexcept;  ///< Install one validated flow rule.
	int (*destroy_flow)(void *state, uint16_t port_id, rte_flow *flow,
			    rte_flow_error *error) noexcept;  ///< Retire one owned flow rule.
	int (*statistics)(void *state, uint16_t port_id,
			  rte_eth_stats *statistics) noexcept;	///< Read one cold native port snapshot.
};

/** @return Complete ethdev operation table backed by the native DPDK calls. */
[[nodiscard]] dpdk_ethdev_api default_dpdk_ethdev_api() noexcept;

/**
 * @brief One exact DPDK mbuf-backed packet-storage domain.
 *
 * The owner validates the shared compiled budget, exact NUMA/data-room/
 * headroom/alignment facts, and the facility's matching memory-domain row.
 * Every native pool object is inspected before publication to prove private
 * packet-record placement and payload alignment. Destruction fails stop if
 * any record remains outside the pool.
 */
class dpdk_packet_storage final {
    public:
	/** @brief Disable copying because one object owns one native pool. */
	dpdk_packet_storage(const dpdk_packet_storage &) = delete;
	/** @brief Disable copy assignment because pool ownership is linear. */
	dpdk_packet_storage &operator=(const dpdk_packet_storage &) = delete;
	/** @brief Disable moves because the published operation table retains this address. */
	dpdk_packet_storage(dpdk_packet_storage &&) = delete;
	/** @brief Disable move assignment because operation state is address-stable. */
	dpdk_packet_storage &operator=(dpdk_packet_storage &&) = delete;

	/** @brief Retire one quiescent exact mbuf pool. */
	~dpdk_packet_storage() noexcept;

	/**
	 * @brief Construct one exact DPDK packet-storage dependency.
	 *
	 * @param request Canonical storage request with one exact DPDK facility.
	 * @param api Complete cold native pool API.
	 * @param[out] output Empty owner receiving the initialized storage domain.
	 * @param diagnostic Optional caller-owned bounded diagnostic.
	 * @return OK only after every native pool object passes layout validation.
	 */
	[[nodiscard]] static kinetum_provider_status create(const kinetum_provider_factory_request &request,
							    const dpdk_mempool_api &api,
							    std::unique_ptr<dpdk_packet_storage> &output,
							    kinetum_provider_diagnostic *diagnostic) noexcept;

	/** @return Borrowed immutable storage table, valid for this owner's lifetime. */
	[[nodiscard]] const kinetum_packet_storage_domain_operations &operations() const noexcept;
	/** @return Native pool borrowed by dependent RX queues while this storage owner remains alive. */
	[[nodiscard]] rte_mempool *native_pool() const noexcept;
	/** @return Exact host NUMA node required for native queue memory. */
	[[nodiscard]] int32_t host_numa_node() const noexcept;

	/**
	 * @brief Resolve the process facility that owns this native pool's memory domain.
	 * @return Exact borrowed facility, retained by this storage owner's dependencies.
	 */
	[[nodiscard]] const dpdk_process_facility *facility() const noexcept;

    private:
	struct implementation;

	/**
	 * @brief Adopt one completely validated native pool owner.
	 * @param state Sole implementation owner transferred into this storage domain.
	 */
	explicit dpdk_packet_storage(std::unique_ptr<implementation> state) noexcept;

	/**
	 * @brief Acquire one all-or-none bounded native record burst.
	 * @param state Borrowed storage owner.
	 * @param records Destination for newly owned records.
	 * @param capacity Available output slots, capped to the platform burst bound.
	 * @return Complete attempted count, or zero on invalid input or allocation failure.
	 */
	static uint16_t acquire_burst_(void *state, kinetum_packet_record **records, uint16_t capacity) noexcept;
	/**
	 * @brief Deep-clone one exact writable DPDK record.
	 * @param state Borrowed storage owner.
	 * @param source Live record from this domain, borrowed without transfer.
	 * @return Newly owned payload and metadata copy, or nullptr on rejection or exhaustion.
	 */
	static kinetum_packet_record *clone_writable_(void *state, const kinetum_packet_record *source) noexcept;
	/**
	 * @brief Validate and copy a bounded active-origin prefix into native records.
	 * @param state Borrowed storage owner.
	 * @param origins Borrowed input payload views.
	 * @param records Destination for newly owned records.
	 * @param count Input and output extent, capped to the platform burst bound.
	 * @return Complete attempted count, or zero with no transferred records on failure.
	 */
	static uint16_t copy_origins_burst_(void *state, const kinetum_packet_origin_view *origins,
					    kinetum_packet_record **records, uint16_t count) noexcept;
	/**
	 * @brief Validate then retire one complete exact native record burst.
	 * @param state Borrowed storage owner; invalid state fails stop.
	 * @param records Distinct live records from this domain, transferred back to the pool.
	 * @param count Positive count within the platform burst bound; invalid or duplicate ownership fails stop.
	 */
	static void release_burst_(void *state, kinetum_packet_record *const *records, uint16_t count) noexcept;
	/**
	 * @brief Publish one cold approximate native-pool occupancy observation.
	 * @param state Borrowed storage owner.
	 * @param observation Destination for domain identity and occupancy classification.
	 * @param diagnostic Optional caller-owned diagnostic buffer, cleared on success.
	 * @return OK with approximate counts or READ_FAILED state; INVALID_ARGUMENT for malformed arguments.
	 */
	[[nodiscard]] static kinetum_provider_status
	observe_statistics_(void *state, kinetum_provider_storage_observation *observation,
			    kinetum_provider_diagnostic *diagnostic) noexcept;

	std::unique_ptr<implementation> state_;			 ///< Exact native storage ownership.
	kinetum_packet_storage_domain_operations operations_{};	 ///< Published storage table.
};

/**
 * @brief One exact DPDK ethdev I/O-driver instance.
 *
 * Construction preflights every device, queue, descriptor, MTU, resolved MAC,
 * NUMA relation, RSS field/key, and RETA entry before the first port is
 * configured. Configured ownership is claimed immediately and unwound in
 * reverse order, but every port remains stopped. The cold lifecycle edge
 * starts the complete driver and programs exact RETA/flow state only after
 * fixed-epoch bootstrap. The owner never adjusts descriptor counts, enables
 * promiscuous mode, infers queue zero, or accepts a PMD default RSS mapping.
 */
class dpdk_io_driver final {
    public:
	/** @brief Disable copying because configured port/queue ownership is linear. */
	dpdk_io_driver(const dpdk_io_driver &) = delete;
	/** @brief Disable copy assignment because native ownership is linear. */
	dpdk_io_driver &operator=(const dpdk_io_driver &) = delete;
	/** @brief Disable moves because published queue state retains stable addresses. */
	dpdk_io_driver(dpdk_io_driver &&) = delete;
	/** @brief Disable move assignment because published queue tables are immutable. */
	dpdk_io_driver &operator=(dpdk_io_driver &&) = delete;

	/** @brief Close every already-stopped configured port before dependencies retire. */
	~dpdk_io_driver() noexcept;

	/**
	 * @brief Construct one exact DPDK I/O-driver instance.
	 *
	 * @param request Canonical driver request with facility then storage dependencies.
	 * @param api Complete cold native ethdev API.
	 * @param[out] output Empty owner receiving the configured driver.
	 * @param diagnostic Optional caller-owned bounded diagnostic.
	 * @return OK only after every exact queue is configured and the complete
	 *         driver remains cold.
	 */
	[[nodiscard]] static kinetum_provider_status create(const kinetum_provider_factory_request &request,
							    const dpdk_ethdev_api &api,
							    std::unique_ptr<dpdk_io_driver> &output,
							    kinetum_provider_diagnostic *diagnostic) noexcept;

	/** @return Borrowed immutable RX/TX operation tables, valid for this driver's lifetime. */
	[[nodiscard]] const kinetum_provider_io_driver_operations &operations() const noexcept;

    private:
	struct implementation;

	/**
	 * @brief Adopt one preallocated I/O owner before its first port configuration.
	 * @param state Sole implementation owner transferred into this driver.
	 */
	explicit dpdk_io_driver(std::unique_ptr<implementation> state) noexcept;

	/**
	 * @brief Start every configured port and publish exact steering atomically.
	 *
	 * @param diagnostic Optional caller-owned bounded diagnostic.
	 * @return OK only after the complete driver is live; otherwise exact rollback status.
	 */
	[[nodiscard]] kinetum_provider_status activate_packet_io_(kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @brief Retire exact steering and stop every port in reverse order.
	 *
	 * @param diagnostic Optional caller-owned bounded diagnostic.
	 * @return OK only after the complete driver is cold.
	 */
	[[nodiscard]] kinetum_provider_status deactivate_packet_io_(kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @brief Exact C-ABI adapter for whole-driver activation.
	 *
	 * @param state Exact DPDK I/O-driver instance.
	 * @param diagnostic Optional caller-owned bounded diagnostic.
	 * @return Exact valid provider status from whole-driver activation.
	 */
	[[nodiscard]] static kinetum_provider_status
	activate_packet_io_callback_(void *state, kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @brief Exact C-ABI adapter for whole-driver deactivation.
	 *
	 * @param state Exact DPDK I/O-driver instance.
	 * @param diagnostic Optional caller-owned bounded diagnostic.
	 * @return Exact valid provider status from whole-driver deactivation.
	 */
	[[nodiscard]] static kinetum_provider_status
	deactivate_packet_io_callback_(void *state, kinetum_provider_diagnostic *diagnostic) noexcept;
	/**
	 * @brief Fill one complete caller-owned cold driver observation batch.
	 * @param state Borrowed I/O-driver owner.
	 * @param observations Caller-owned port rows with fixed identities and storage.
	 * @param diagnostic Optional caller-owned bounded failure diagnostic.
	 * @return OK after classifying every requested row, or an explicit argument or identity error.
	 */
	[[nodiscard]] static kinetum_provider_status
	observe_statistics_callback_(void *state, kinetum_provider_io_observation_batch *observations,
				     kinetum_provider_diagnostic *diagnostic) noexcept;

	/**
	 * @brief Poll one exact native RX queue and publish valid record pointers.
	 * @param state Exact pre-resolved native queue state.
	 * @param[out] records Caller-owned array receiving the compact transferred prefix.
	 * @param capacity Maximum native input population to consume.
	 * @return Transferred record count and native inputs discarded before admission.
	 */
	static kinetum_packet_rx_burst_result receive_burst_(void *state, kinetum_packet_record **records,
							     uint16_t capacity) noexcept;
	/**
	 * @brief Transfer exactly the accepted prefix to one native TX queue.
	 * @param state Borrowed materialized TX queue.
	 * @param records Candidate records; only the returned prefix transfers to DPDK.
	 * @param count Candidate extent, capped to the platform burst bound.
	 * @return Native accepted count within the valid prefix; the caller retains every suffix record.
	 */
	static uint16_t transmit_burst_(void *state, kinetum_packet_record *const *records, uint16_t count) noexcept;
	/**
	 * @brief Require queue state; direct ethdev bursts retain no software TX buffer to flush.
	 * @param state Non-null materialized TX queue; null fails stop.
	 */
	static void flush_(void *state) noexcept;
	/**
	 * @param state Non-null materialized TX queue; null fails stop.
	 * @return Zero because direct ethdev bursts require no timed flush.
	 */
	static uint8_t maybe_flush_(void *state) noexcept;

	std::unique_ptr<implementation> state_;		      ///< Exact ethdev and queue ownership.
	kinetum_provider_io_driver_operations operations_{};  ///< Published I/O role table.
};

}  // namespace kinetum::provider::dpdk_component
