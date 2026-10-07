// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file udp_io.hpp
 * @brief Fixed-pool UDP development I/O driver.
 * @author Fleming Patel
 *
 * UDP remains a development provider, but it obeys the production ownership
 * contract: receive and transmit use Linux recvmmsg/sendmmsg bursts of
 * packet_record pointers. Each RX queue allocates from its declared domain;
 * TX retains records from its complete admitted storage set and reclaims them
 * through their original owners. No packet operation allocates or creates
 * shared ownership. Oversized datagrams are detected with MSG_TRUNC and never
 * enter the shared packet core.
 */

#include <sys/socket.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/packet.hpp"

namespace kinetum::dp
{

/** @brief Parsed deterministic IPv4 endpoint used only inside the UDP provider. */
struct udp_ipv4_endpoint {
	uint32_t address_network_order{0};  ///< Exact IPv4 address in network byte order.
	uint16_t port_network_order{0};	    ///< Exact UDP port in network byte order.
};

/** @brief Injectable allocation-free UDP receive syscall boundary. */
struct udp_receive_api {
	void *state{nullptr};  ///< Borrowed state retained for the receive-endpoint lifetime.
	/**
	 * @brief Receive at most one exact bounded datagram prefix.
	 * @param state Borrowed immutable implementation state.
	 * @param fd Owned nonblocking UDP socket.
	 * @param messages Writable native descriptor prefix.
	 * @param count Exact nonzero descriptor bound.
	 * @return Native accepted count, zero for no progress, or a negative result
	 *         with the exact native error in errno.
	 */
	int (*receive_messages)(void *state, int fd, mmsghdr *messages, uint16_t count) noexcept {nullptr};
};

/** @brief Injectable allocation-free UDP transmit syscall boundary. */
struct udp_transmit_api {
	void *state{nullptr};  ///< Borrowed state retained for the transmit-endpoint lifetime.
	/**
	 * @brief Transmit at most one exact bounded datagram prefix.
	 * @param state Borrowed immutable implementation state.
	 * @param fd Owned connected nonblocking UDP socket.
	 * @param messages Borrowed native descriptor prefix.
	 * @param count Exact nonzero descriptor bound.
	 * @return Native accepted count, zero for no progress, or a negative result
	 *         with the exact native error in errno.
	 */
	int (*transmit_messages)(void *state, int fd, mmsghdr *messages, uint16_t count) noexcept {nullptr};
};

/** @return Receive table backed by the Linux recvmmsg implementation. */
[[nodiscard]] udp_receive_api native_udp_receive_api() noexcept;

/** @return Transmit table backed by the Linux sendmmsg implementation. */
[[nodiscard]] udp_transmit_api native_udp_transmit_api() noexcept;

/**
 * @brief Parse one canonical numeric IPv4 UDP endpoint without allocation.
 *
 * This provider-private helper is the sole parser used by the component and
 * native mechanism tests. It requires the exact inet_ntop spelling, performs
 * no DNS lookup, and writes @p parsed only after complete validation.
 *
 * @param address Canonical numeric IPv4 text.
 * @param port Unsigned UDP port. Zero is valid only for an explicit
 *        non-plan RX bind such as component conformance; the shared compiler
 *        rejects kernel-chosen ephemeral identity in a materialized plan.
 * @param[out] parsed Parsed network-order address and port on success.
 * @return true only for one canonical address and uint16 port.
 */
[[nodiscard]] bool parse_udp_ipv4_endpoint(std::string_view address, uint32_t port, udp_ipv4_endpoint &parsed) noexcept;

/**
 * @brief Prove Linux supports the exact cold UDP receive lifecycle.
 *
 * Creates an unbound datagram socket, installs the drop-all and accept-all
 * classic-BPF filters used by reserve/activate/deactivate, and retires the
 * descriptor. It never reserves an endpoint or publishes packet authority.
 *
 * @return OK after both filters are accepted, or a host-capability failure.
 */
[[nodiscard]] kinetum::common::status prove_udp_rx_lifecycle_support() noexcept;

/** @brief One nonblocking UDP receive endpoint backed by a fixed pool. */
class udp_rx_port final {
    public:
	/**
	 * @brief Construct an unopened endpoint with its exact descriptor credits.
	 *
	 * @param storage_operations Exact storage domain that owns every admitted record
	 *        and outlives this endpoint.
	 * @param logical_port Exact plan-derived ingress port.
	 * @param descriptor_count Exact nonzero queue descriptor population.
	 * @param receive_api Immutable receive table; production uses the exact Linux implementation.
	 * @return Complete endpoint, or a cold allocation/storage-credit failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<udp_rx_port>>
	create(const packet_storage_domain_operations &storage_operations, uint16_t logical_port,
	       uint32_t descriptor_count, udp_receive_api receive_api = native_udp_receive_api());

	/** @brief Retire one cold socket and return every queue-owned descriptor credit. */
	~udp_rx_port();

	/**
	 * @brief Reserve one endpoint while the kernel drops every datagram.
	 *
	 * A drop-all socket filter is installed before bind, so no datagram can
	 * queue during CONTROL_READY and later emerge after activation.
	 *
	 * @param endpoint Exact network-order address and port.
	 * @return OK after exact cold reservation, ALREADY_EXISTS when the endpoint
	 *         is occupied, or another exact socket/filter/bind failure.
	 */
	kinetum::common::status reserve(const udp_ipv4_endpoint &endpoint);

	/**
	 * @brief Atomically replace the drop filter with the accept filter.
	 *
	 * @return OK only after this reserved endpoint becomes live.
	 */
	kinetum::common::status activate() noexcept;

	/**
	 * @brief Atomically replace the accept filter with the drop filter.
	 *
	 * @return OK only after this live endpoint becomes cold.
	 */
	kinetum::common::status deactivate() noexcept;

	/** @return Borrowed immutable receive operations, valid for this port's lifetime. */
	[[nodiscard]] const packet_rx_burst_operations &burst_operations() const noexcept
	{
		return burst_operations_;
	}

	/**
	 * @brief Close this already-cold endpoint after its owner worker stops.
	 *
	 * A close failure terminates before descriptor credits are reclaimed,
	 * because exact endpoint retirement is no longer provable.
	 */
	void shutdown() noexcept;

    private:
	/**
	 * @brief Adopt one exact RX descriptor array before credit reservation.
	 *
	 * @param storage_operations Exact storage-domain owner.
	 * @param logical_port Exact plan-derived ingress port.
	 * @param descriptors Exact empty descriptor array.
	 * @param descriptor_count Exact array capacity and required credit population.
	 * @param receive_api Exact immutable receive implementation.
	 */
	udp_rx_port(const packet_storage_domain_operations &storage_operations, uint16_t logical_port,
		    std::unique_ptr<packet_record *[]> descriptors, uint32_t descriptor_count,
		    udp_receive_api receive_api) noexcept;
	/**
	 * @brief Reserve the complete descriptor population in bounded ABI bursts.
	 * @return true after every exact credit is owned; false after a partial
	 *         reservation that the destructor will roll back.
	 */
	[[nodiscard]] bool reserve_descriptor_population_() noexcept;

	/**
	 * @brief Receive one bounded datagram burst into exact fixed-pool records.
	 *
	 * @param state Non-null udp_rx_port pointer for a nonempty request.
	 * @param records Destination record array.
	 * @param capacity Maximum records the caller can accept.
	 * @return Exact transferred prefix and pre-admission rejection counts;
	 *         unpublished records remain owned by the descriptor population.
	 */
	[[nodiscard]] static packet_rx_burst_result receive_burst_(void *state, packet_record **records,
								   uint16_t capacity) noexcept;
	/** @brief Refill currently empty queue descriptors from the exact storage owner. */
	void replenish_descriptors_() noexcept;
	/** @return Next descriptor record removed from the owner-local ring, or nullptr when empty. */
	[[nodiscard]] packet_record *pop_descriptor_() noexcept;
	/**
	 * @brief Return one queue-owned descriptor record to the owner-local ring.
	 * @param record Non-null live record transferred to one available descriptor slot.
	 */
	void push_descriptor_(packet_record *record) noexcept;
	/** @brief Return every currently held descriptor credit during cold teardown. */
	void release_descriptors_() noexcept;
	/**
	 * @brief Discard the finite receive backlog after the drop filter is live.
	 * @return OK after the socket reports no queued datagram, or an exact
	 *         receive failure while cold publication remains incomplete.
	 */
	[[nodiscard]] kinetum::common::status drain_receive_backlog_() noexcept;

	packet_rx_burst_operations burst_operations_{};	 ///< Immutable RX table published at startup.
	const packet_storage_domain_operations *storage_operations_{nullptr};  ///< Exact storage-domain owner.
	udp_receive_api receive_api_{};			  ///< Exact receive implementation fixed before publication.
	std::unique_ptr<packet_record *[]> descriptors_;  ///< Exact owner-local descriptor ring.
	uint32_t descriptor_capacity_{0};		  ///< Authored descriptor population.
	uint32_t descriptor_head_{0};			  ///< Owner-local next descriptor index.
	uint32_t descriptor_size_{0};			  ///< Currently populated descriptor slots.
	int fd_{-1};	      ///< Owned nonblocking socket, or -1 before reserve/after shutdown.
	bool active_{false};  ///< Whether the accept filter currently admits datagrams.
};

/** @brief One connected UDP transmit endpoint accepting record prefixes. */
class udp_tx_port final {
    public:
	/**
	 * @brief Construct an unconnected endpoint with an exact deferred queue.
	 *
	 * @param storage_operations Nonempty domain-sorted unique admission set; all tables
	 *        belong to one generation and outlive the endpoint.
	 * @param logical_port Exact plan-derived egress port.
	 * @param descriptor_count Exact nonzero queue descriptor population.
	 * @param transmit_api Immutable transmit table; production uses the exact Linux implementation.
	 * @return Complete endpoint, or a storage-admission/descriptor-allocation failure.
	 */
	[[nodiscard]] static kinetum::common::status_or<std::unique_ptr<udp_tx_port>>
	create(std::span<const packet_storage_domain_operations *const> storage_operations, uint16_t logical_port,
	       uint32_t descriptor_count, udp_transmit_api transmit_api = native_udp_transmit_api());

	/** @brief Close the socket after the runtime has stopped invoking its table. */
	~udp_tx_port();

	/**
	 * @brief Connect one already validated numeric IPv4 endpoint.
	 *
	 * @param endpoint Exact network-order address and port.
	 * @return OK after successful connect, or a socket failure.
	 */
	kinetum::common::status connect(const udp_ipv4_endpoint &endpoint);

	/** @return Borrowed immutable transmit operations, valid for this port's lifetime. */
	[[nodiscard]] const packet_tx_burst_operations &burst_operations() const noexcept
	{
		return burst_operations_;
	}

	/**
	 * @brief Close the endpoint and retire every unsent owner-held record.
	 *
	 * A close failure terminates before any deferred record is reclaimed,
	 * because exact endpoint retirement is no longer provable.
	 */
	void shutdown() noexcept;

    private:
	/**
	 * @brief Adopt one complete empty TX descriptor population.
	 *
	 * @param storage_operations Owned direct-index admission table; null cells reject.
	 * @param storage_domain_limit Exclusive compact-domain table bound.
	 * @param logical_port Exact plan-derived egress port.
	 * @param descriptors Exact empty descriptor array.
	 * @param descriptor_count Exact array population.
	 * @param transmit_api Exact immutable transmit implementation.
	 */
	udp_tx_port(std::unique_ptr<const packet_storage_domain_operations *[]> storage_operations,
		    uint32_t storage_domain_limit, uint16_t logical_port,
		    std::unique_ptr<packet_record *[]> descriptors, uint32_t descriptor_count,
		    udp_transmit_api transmit_api) noexcept;

	/**
	 * @brief Accept one ordered record prefix from the admitted storage domains.
	 *
	 * @param state Non-null udp_tx_port pointer for a nonempty call.
	 * @param records Exact owned records; a nonempty call requires a non-null array.
	 * @param count Bounded record count.
	 * @return Number of records accepted into this queue's exact descriptor
	 *         prefix; the suffix remains caller-owned. Acceptance is not delivery:
	 *         shutdown may reclaim deferred records that were never sent.
	 */
	[[nodiscard]] static uint16_t transmit_burst_(void *state, packet_record *const *records,
						      uint16_t count) noexcept;
	/**
	 * @brief Drain deferred records until the queue empties or a send makes no progress.
	 * @param state Non-null owning UDP TX port; null fails stop.
	 */
	static void flush_(void *state) noexcept;
	/**
	 * @param state Non-null owning UDP TX port; null fails stop.
	 * @return One while deferred records remain, otherwise zero; this call does not send them.
	 */
	[[nodiscard]] static uint8_t maybe_flush_(void *state) noexcept;
	/**
	 * @brief Retire one accepted prefix through its original pre-resolved storage owners.
	 * @param records Live records whose payloads are no longer needed by the sender.
	 * @param count Number of records to release through their admitted original domains.
	 */
	void release_accepted_(packet_record *const *records, uint16_t count) noexcept;
	/**
	 * @brief Validate one record against its admitted original storage table.
	 * @param record Borrowed candidate packet record.
	 * @return Exact storage operations, or nullptr for an unadmitted or malformed record.
	 */
	[[nodiscard]] const packet_storage_domain_operations *storage_for_(const packet_record *record) const noexcept;
	/** @return Deferred records accepted by sendmmsg and retired, or zero on no progress; not wire delivery. */
	[[nodiscard]] uint16_t drain_once_() noexcept;
	/**
	 * @brief Append one exact record after ownership transfers to this queue.
	 * @param record Non-null accepted record; missing descriptor capacity fails stop.
	 */
	void push_descriptor_(packet_record *record) noexcept;
	/**
	 * @param offset Offset from the owner-local descriptor head.
	 * @return Borrowed queued record, or nullptr when the offset or descriptor storage is unavailable.
	 */
	[[nodiscard]] packet_record *descriptor_at_(uint32_t offset) const noexcept;
	/**
	 * @brief Remove an already-sent descriptor prefix; the caller retains record-release responsibility.
	 * @param count Positive occupied prefix length; an invalid count or empty slot fails stop.
	 */
	void consume_descriptors_(uint16_t count) noexcept;
	/** @brief Drop and retire every unsent descriptor during cold teardown. */
	void retire_deferred_() noexcept;

	packet_tx_burst_operations burst_operations_{};	 ///< Immutable TX table published at startup.
	std::unique_ptr<const packet_storage_domain_operations *[]>
		storage_by_domain_;			  ///< Immutable O(1) admission table.
	uint32_t storage_domain_limit_{0};		  ///< Exclusive admitted-table index bound.
	udp_transmit_api transmit_api_{};		  ///< Exact transmit implementation fixed before publication.
	std::unique_ptr<packet_record *[]> descriptors_;  ///< Exact owner-local deferred ring.
	uint32_t descriptor_capacity_{0};		  ///< Authored descriptor population.
	uint32_t descriptor_head_{0};			  ///< Owner-local deferred prefix head.
	uint32_t descriptor_size_{0};			  ///< Number of exact records owned by the queue.
	int fd_{-1};  ///< Owned connected socket, or -1 before connect/after shutdown.
};

}  // namespace kinetum::dp
