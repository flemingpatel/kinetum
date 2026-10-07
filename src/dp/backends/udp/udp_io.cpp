// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file udp_io.cpp
 * @brief Fixed-pool UDP development I/O implementation.
 * @author Fleming Patel
 */

#include "src/dp/backends/udp/udp_io.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <linux/filter.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <iterator>
#include <limits>
#include <new>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "src/common/runtime_sizing.hpp"

namespace kinetum::dp
{

using kinetum::common::status;
using kinetum::common::status_code;

namespace
{

/** Classic-BPF verdict that discards the complete datagram. */
constexpr uint32_t UDP_FILTER_DROP = 0;

/** Classic-BPF verdict that admits the complete datagram. */
constexpr uint32_t UDP_FILTER_ACCEPT = std::numeric_limits<uint32_t>::max();

/**
 * @brief Close one owned UDP socket exactly once or fail stop.
 *
 * Linux releases the descriptor number before reporting most close errors.
 * Clear provider-local ownership before the call and never retry: a retry
 * could close an unrelated descriptor that another owner has already reused.
 * Any failure leaves exact endpoint retirement unproven, so dependent packet
 * credits must not be reclaimed in the same process.
 *
 * @param fd Provider-owned descriptor, or -1 when no socket is owned.
 */
void close_owned_socket(int &fd) noexcept
{
	if (fd < 0) {
		return;
	}
	const int owned_fd = std::exchange(fd, -1);
	if (::close(owned_fd) != 0) {
		std::terminate();
	}
}

/**
 * @brief Replace one UDP socket's receive filter atomically.
 *
 * @param fd Exact owned datagram descriptor.
 * @param verdict Classic-BPF return value for every datagram.
 * @return OK after kernel publication or a host-capability failure.
 */
[[nodiscard]] status install_udp_receive_filter(int fd, uint32_t verdict) noexcept
{
	if (fd < 0 || (verdict != UDP_FILTER_DROP && verdict != UDP_FILTER_ACCEPT)) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("UDP receive filter contract is malformed"));
	}
	sock_filter instructions[]{BPF_STMT(BPF_RET | BPF_K, verdict)};
	sock_fprog program{
		.len = static_cast<unsigned short>(std::size(instructions)),
		.filter = instructions,
	};
	if (::setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) != 0) {
		return verdict == UDP_FILTER_DROP ? status(status_code::FAILED_PRECONDITION,
							   kinetum::common::static_status_text(
								   "Linux rejected the UDP drop-all receive filter")) :
						    status(status_code::FAILED_PRECONDITION,
							   kinetum::common::static_status_text(
								   "Linux rejected the UDP accept-all receive filter"));
	}
	return status::ok();
}

/**
 * @brief Invoke Linux recvmmsg with the exact nonblocking/truncation policy.
 * @param state Opaque API context; unused by this native wrapper.
 * @param fd Bound receive socket.
 * @param messages Caller-owned receive buffers and per-message length outputs.
 * @param count Maximum messages represented by the array.
 * @return Native received-message count, or -1 with errno; MSG_TRUNC reports original datagram lengths.
 */
int receive_messages_native(void *state, int fd, mmsghdr *messages, uint16_t count) noexcept
{
	(void)state;
	return recvmmsg(fd, messages, count, MSG_DONTWAIT | MSG_TRUNC, nullptr);
}

/**
 * @brief Invoke Linux sendmmsg with the exact nonblocking policy.
 * @param state Opaque API context; unused by this native wrapper.
 * @param fd Connected transmit socket.
 * @param messages Borrowed datagrams and native result-length slots.
 * @param count Number of candidate datagrams.
 * @return Kernel-accepted prefix length, or -1 with errno; acceptance does not establish wire delivery.
 */
int transmit_messages_native(void *state, int fd, mmsghdr *messages, uint16_t count) noexcept
{
	(void)state;
	return sendmmsg(fd, messages, count, MSG_DONTWAIT);
}

/**
 * @brief Classify a negative nonblocking receive as retryable no-progress.
 * @param error Captured errno from the failed receive.
 * @return true for interruption or temporary unavailability; false otherwise.
 */
[[nodiscard]] bool receive_error_is_no_progress(int error) noexcept
{
	return error == EINTR || error == EAGAIN || error == EWOULDBLOCK;
}

/**
 * @brief Classify a negative nonblocking transmit as retained backpressure.
 * @param error Captured errno from the failed send.
 * @return true for interruption, temporary unavailability, or transient buffer/memory pressure.
 */
[[nodiscard]] bool transmit_error_is_no_progress(int error) noexcept
{
	return error == EINTR || error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS || error == ENOMEM;
}

/**
 * @brief Return whether one acquired record belongs to the exact dependency table.
 * @param record Candidate freshly acquired record, or nullptr.
 * @param storage Admitted owning domain's immutable operations.
 * @return true only for an initialized empty record with exact domain, generation, and byte-access facts.
 */
[[nodiscard]] bool record_matches_storage(const packet_record *record,
					  const packet_storage_domain_operations &storage) noexcept
{
	return record != nullptr && record->storage.operations == &storage &&
	       record->storage.native_handle != nullptr && record->storage.data != nullptr &&
	       record->storage.generation == storage.generation &&
	       record->storage.domain_index == storage.domain_index && record->storage.segment_count == 1 &&
	       record->storage.capabilities == storage.capabilities && record->storage.length == 0 &&
	       record->storage.contiguous_length == 0;
}

/**
 * @brief Return whether one storage table can own exact UDP packet credits.
 * @param storage Candidate borrowed storage operation table.
 * @return true for complete acquire/release operations, valid identity, and contiguous CPU read/write access.
 */
[[nodiscard]] bool storage_operations_are_complete(const packet_storage_domain_operations &storage) noexcept
{
	constexpr uint32_t REQUIRED_ACCESS = packet_storage_capabilities::CPU_CONTIGUOUS_READ |
					     packet_storage_capabilities::CPU_CONTIGUOUS_WRITE;
	return storage.state != nullptr && storage.acquire_burst != nullptr && storage.release_burst != nullptr &&
	       storage.maximum_packet_length != 0 && storage.domain_index != INVALID_STORAGE_DOMAIN &&
	       storage.generation != 0 && (storage.capabilities & REQUIRED_ACCESS) == REQUIRED_ACCESS;
}

}  // namespace

udp_receive_api native_udp_receive_api() noexcept
{
	return udp_receive_api{
		.state = nullptr,
		.receive_messages = receive_messages_native,
	};
}

udp_transmit_api native_udp_transmit_api() noexcept
{
	return udp_transmit_api{
		.state = nullptr,
		.transmit_messages = transmit_messages_native,
	};
}

bool parse_udp_ipv4_endpoint(std::string_view address_text, uint32_t port, udp_ipv4_endpoint &parsed) noexcept
{
	if (address_text.empty() || address_text.size() >= INET_ADDRSTRLEN ||
	    port > std::numeric_limits<uint16_t>::max()) {
		return false;
	}
	std::array<char, INET_ADDRSTRLEN> input{};
	std::memcpy(input.data(), address_text.data(), address_text.size());
	in_addr address{};
	if (inet_pton(AF_INET, input.data(), &address) != 1) {
		return false;
	}
	std::array<char, INET_ADDRSTRLEN> canonical{};
	const char *rendered = inet_ntop(AF_INET, &address, canonical.data(), canonical.size());
	if (rendered == nullptr || std::string_view(rendered) != address_text) {
		return false;
	}
	parsed = udp_ipv4_endpoint{
		.address_network_order = address.s_addr,
		.port_network_order = htons(static_cast<uint16_t>(port)),
	};
	return true;
}

status prove_udp_rx_lifecycle_support() noexcept
{
	int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text("Linux IPv4 datagram sockets are unavailable"));
	}
	auto result = install_udp_receive_filter(fd, UDP_FILTER_DROP);
	if (result.is_ok()) {
		result = install_udp_receive_filter(fd, UDP_FILTER_ACCEPT);
	}
	close_owned_socket(fd);
	return result;
}

common::status_or<std::unique_ptr<udp_rx_port>>
udp_rx_port::create(const packet_storage_domain_operations &storage_operations, uint16_t logical_port,
		    uint32_t descriptor_count, udp_receive_api receive_api)
{
	if (!storage_operations_are_complete(storage_operations) || descriptor_count == 0 ||
	    receive_api.receive_messages == nullptr) {
		return status(status_code::INVALID_ARGUMENT,
			      "UDP RX queue requires one exact bounded descriptor population");
	}
	auto descriptors = std::unique_ptr<packet_record *[]>{new (std::nothrow) packet_record *[descriptor_count] {}};
	if (descriptors == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED, "UDP RX descriptor allocation failed");
	}
	auto port = std::unique_ptr<udp_rx_port>{new (std::nothrow) udp_rx_port(
		storage_operations, logical_port, std::move(descriptors), descriptor_count, receive_api)};
	if (port == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED, "UDP RX queue allocation failed");
	}
	if (!port->reserve_descriptor_population_()) {
		return status(status_code::RESOURCE_EXHAUSTED, "UDP RX descriptor credits are unavailable");
	}
	return common::status_or<std::unique_ptr<udp_rx_port>>(std::in_place, std::move(port));
}

udp_rx_port::udp_rx_port(const packet_storage_domain_operations &storage_operations, uint16_t logical_port,
			 std::unique_ptr<packet_record *[]> descriptors, uint32_t descriptor_count,
			 udp_receive_api receive_api) noexcept
	: storage_operations_(&storage_operations)
	, receive_api_(receive_api)
	, descriptors_(std::move(descriptors))
	, descriptor_capacity_(descriptor_count)
{
	burst_operations_.state = this;
	burst_operations_.receive_burst = &udp_rx_port::receive_burst_;
	burst_operations_.maximum_burst = static_cast<uint16_t>(
		std::min<uint32_t>(descriptor_count, kinetum::common::runtime_sizing::PACKET_MAX_BURST_SIZE));
	burst_operations_.logical_port = logical_port;
}

bool udp_rx_port::reserve_descriptor_population_() noexcept
{
	constexpr uint32_t MAX_OPERATION_BURST = std::numeric_limits<uint16_t>::max();
	try {
		std::unordered_set<packet_record *> identities;
		identities.reserve(descriptor_capacity_);
		while (descriptor_size_ < descriptor_capacity_) {
			const uint32_t remaining = descriptor_capacity_ - descriptor_size_;
			const uint16_t requested = static_cast<uint16_t>(std::min(remaining, MAX_OPERATION_BURST));
			const uint32_t acquired_begin = descriptor_size_;
			const uint16_t acquired = storage_operations_->acquire_burst(
				storage_operations_->state, descriptors_.get() + descriptor_size_, requested);
			if (acquired > requested) {
				std::terminate();
			}
			descriptor_size_ += acquired;
			for (uint32_t index = acquired_begin; index < descriptor_size_; ++index) {
				if (!record_matches_storage(descriptors_[index], *storage_operations_) ||
				    !identities.insert(descriptors_[index]).second) {
					std::terminate();
				}
			}
			if (acquired != requested) {
				return false;
			}
		}
	} catch (const std::bad_alloc &) {
		return false;
	} catch (const std::length_error &) {
		return false;
	}
	return true;
}

udp_rx_port::~udp_rx_port()
{
	shutdown();
	release_descriptors_();
}

status udp_rx_port::reserve(const udp_ipv4_endpoint &endpoint)
{
	if (fd_ >= 0) {
		return status(status_code::FAILED_PRECONDITION, "UDP RX port already owns an endpoint");
	}

	fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd_ < 0) {
		return status(status_code::FAILED_PRECONDITION, "UDP RX socket creation failed");
	}
	auto filter_status = install_udp_receive_filter(fd_, UDP_FILTER_DROP);
	if (!filter_status.is_ok()) {
		shutdown();
		return filter_status;
	}

	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_port = endpoint.port_network_order;
	address.sin_addr.s_addr = endpoint.address_network_order;
	if (::bind(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
		const int bind_errno = errno;
		shutdown();
		if (bind_errno == EADDRINUSE) {
			return status::already_exists("UDP RX endpoint is already reserved");
		}
		return status(status_code::FAILED_PRECONDITION, "UDP RX endpoint reservation failed");
	}
	return status::ok();
}

status udp_rx_port::activate() noexcept
{
	if (fd_ < 0 || active_) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("UDP RX activation requires one cold reserved endpoint"));
	}
	auto result = install_udp_receive_filter(fd_, UDP_FILTER_ACCEPT);
	if (!result.is_ok()) {
		return result;
	}
	active_ = true;
	return status::ok();
}

status udp_rx_port::deactivate() noexcept
{
	if (fd_ < 0 || !active_) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text("UDP RX deactivation requires one live endpoint"));
	}
	auto result = install_udp_receive_filter(fd_, UDP_FILTER_DROP);
	if (!result.is_ok()) {
		return result;
	}
	auto drain_status = drain_receive_backlog_();
	if (!drain_status.is_ok()) {
		return drain_status;
	}
	active_ = false;
	return status::ok();
}

status udp_rx_port::drain_receive_backlog_() noexcept
{
	if (fd_ < 0) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("UDP RX backlog drain requires one reserved endpoint"));
	}
	uint8_t discarded_byte = 0;
	for (;;) {
		const ssize_t result = ::recv(fd_, &discarded_byte, sizeof(discarded_byte), MSG_DONTWAIT);
		if (result >= 0) {
			continue;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return status::ok();
		}
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text("UDP RX cold backlog drain failed"));
	}
}

void udp_rx_port::shutdown() noexcept
{
	if (active_) {
		std::terminate();
	}
	close_owned_socket(fd_);
}

packet_rx_burst_result udp_rx_port::receive_burst_(void *state, packet_record **records, uint16_t capacity) noexcept
{
	auto *port = static_cast<udp_rx_port *>(state);
	if (port == nullptr || records == nullptr || capacity == 0 || port->fd_ < 0) {
		return {};
	}

	port->replenish_descriptors_();
	const uint32_t requested_count = std::min<uint32_t>(
		std::min<uint32_t>(capacity, port->burst_operations_.maximum_burst), port->descriptor_size_);
	const uint16_t requested = static_cast<uint16_t>(requested_count);
	if (requested == 0) {
		return {};
	}

	constexpr std::size_t MAX_BURST = kinetum::common::runtime_sizing::PACKET_MAX_BURST_SIZE;
	std::array<iovec, MAX_BURST> vectors;
	std::array<mmsghdr, MAX_BURST> messages;
	std::array<packet_record *, MAX_BURST> native_records;
	for (uint16_t index = 0; index < requested; ++index) {
		native_records[index] = port->pop_descriptor_();
		if (!record_matches_storage(native_records[index], *port->storage_operations_)) {
			std::terminate();
		}
		// recvmmsg reads only the exact acquired prefix. Initialize each
		// consumed native header in that prefix instead of clearing the full
		// maximum-burst scratch on every poll.
		messages[index] = mmsghdr{};
		vectors[index].iov_base = native_records[index]->storage.data;
		vectors[index].iov_len = port->storage_operations_->maximum_packet_length;
		messages[index].msg_hdr.msg_iov = &vectors[index];
		messages[index].msg_hdr.msg_iovlen = 1;
	}

	const int result =
		port->receive_api_.receive_messages(port->receive_api_.state, port->fd_, messages.data(), requested);
	const int receive_error = result < 0 ? errno : 0;
	if (KINETUM_UNLIKELY(result > static_cast<int>(requested) ||
			     (result < 0 && !receive_error_is_no_progress(receive_error)))) {
		std::terminate();
	}
	const uint16_t received = result > 0 ? static_cast<uint16_t>(result) : 0;

	uint16_t published = 0;
	const uint32_t maximum_length = port->storage_operations_->maximum_packet_length;
	for (uint16_t index = 0; index < received; ++index) {
		auto *record = native_records[index];
		const uint32_t bytes = messages[index].msg_len;
		if (bytes == 0 || bytes > maximum_length) {
			// MSG_TRUNC reports the original datagram length. Never publish a
			// silently truncated packet into the shared parser/module core.
			initialize_packet_record(*record);
			record->storage.length = 0;
			record->storage.contiguous_length = 0;
			port->push_descriptor_(record);
			continue;
		}
		record->storage.length = bytes;
		record->storage.contiguous_length = bytes;
		records[published++] = record;
	}
	for (uint16_t index = received; index < requested; ++index) {
		port->push_descriptor_(native_records[index]);
	}
	port->replenish_descriptors_();
	return {.transferred_count = published, .rejected_count = static_cast<uint16_t>(received - published)};
}

void udp_rx_port::replenish_descriptors_() noexcept
{
	if (descriptor_size_ >= descriptor_capacity_) {
		return;
	}
	constexpr std::size_t MAX_BURST = kinetum::common::runtime_sizing::PACKET_MAX_BURST_SIZE;
	std::array<packet_record *, MAX_BURST> records;
	while (descriptor_size_ < descriptor_capacity_) {
		const uint32_t missing = descriptor_capacity_ - descriptor_size_;
		const uint16_t requested = static_cast<uint16_t>(std::min<std::size_t>(missing, MAX_BURST));
		const uint16_t acquired =
			storage_operations_->acquire_burst(storage_operations_->state, records.data(), requested);
		if (acquired > requested) {
			std::terminate();
		}
		for (uint16_t index = 0; index < acquired; ++index) {
			if (!record_matches_storage(records[index], *storage_operations_)) {
				std::terminate();
			}
			push_descriptor_(records[index]);
		}
		if (acquired != requested) {
			break;
		}
	}
}

packet_record *udp_rx_port::pop_descriptor_() noexcept
{
	if (descriptor_size_ == 0 || descriptors_ == nullptr) {
		std::terminate();
	}
	auto *record = descriptors_[descriptor_head_];
	descriptors_[descriptor_head_] = nullptr;
	descriptor_head_ = descriptor_head_ + 1u == descriptor_capacity_ ? 0u : descriptor_head_ + 1u;
	--descriptor_size_;
	return record;
}

void udp_rx_port::push_descriptor_(packet_record *record) noexcept
{
	if (record == nullptr || descriptors_ == nullptr || descriptor_size_ >= descriptor_capacity_) {
		std::terminate();
	}
	uint64_t tail = static_cast<uint64_t>(descriptor_head_) + descriptor_size_;
	if (tail >= descriptor_capacity_) {
		tail -= descriptor_capacity_;
	}
	const auto tail_index = static_cast<uint32_t>(tail);
	if (descriptors_[tail_index] != nullptr) {
		std::terminate();
	}
	descriptors_[tail_index] = record;
	++descriptor_size_;
}

void udp_rx_port::release_descriptors_() noexcept
{
	while (descriptor_size_ != 0) {
		constexpr uint32_t MAX_RELEASE = std::numeric_limits<uint16_t>::max();
		const uint32_t contiguous =
			std::min<uint32_t>(descriptor_size_, descriptor_capacity_ - descriptor_head_);
		const uint16_t count = static_cast<uint16_t>(std::min<uint32_t>(contiguous, MAX_RELEASE));
		storage_operations_->release_burst(storage_operations_->state, descriptors_.get() + descriptor_head_,
						   count);
		for (uint16_t index = 0; index < count; ++index) {
			descriptors_[descriptor_head_ + index] = nullptr;
		}
		descriptor_head_ += count;
		if (descriptor_head_ == descriptor_capacity_) {
			descriptor_head_ = 0;
		}
		descriptor_size_ -= count;
	}
}

common::status_or<std::unique_ptr<udp_tx_port>>
udp_tx_port::create(std::span<const packet_storage_domain_operations *const> storage_operations, uint16_t logical_port,
		    uint32_t descriptor_count, udp_transmit_api transmit_api)
{
	if (storage_operations.empty() || storage_operations.data() == nullptr ||
	    storage_operations.size() > INVALID_STORAGE_DOMAIN || descriptor_count == 0 ||
	    transmit_api.transmit_messages == nullptr) {
		return status(status_code::INVALID_ARGUMENT,
			      "UDP TX queue requires exact storage admission and a bounded descriptor population");
	}
	uint32_t generation = 0;
	uint32_t previous_domain = 0;
	for (std::size_t index = 0; index < storage_operations.size(); ++index) {
		const auto *storage = storage_operations[index];
		if (storage == nullptr || storage->state == nullptr || storage->release_burst == nullptr ||
		    storage->maximum_packet_length == 0 || storage->domain_index == INVALID_STORAGE_DOMAIN ||
		    storage->generation == 0 ||
		    (storage->capabilities & packet_storage_capabilities::CPU_CONTIGUOUS_READ) == 0 ||
		    (index != 0 && (storage->domain_index <= previous_domain || storage->generation != generation))) {
			return status(
				status_code::INVALID_ARGUMENT,
				"UDP TX storage admission must be sorted, unique, readable, and generation-exact");
		}
		previous_domain = storage->domain_index;
		generation = storage->generation;
	}
	const uint32_t domain_limit = previous_domain + 1u;
	auto storage_by_domain = std::unique_ptr<const packet_storage_domain_operations *[]>{
		new (std::nothrow) const packet_storage_domain_operations *[domain_limit] {}};
	if (storage_by_domain == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED, "UDP TX storage admission allocation failed");
	}
	for (const auto *storage : storage_operations) {
		storage_by_domain[storage->domain_index] = storage;
	}
	auto descriptors = std::unique_ptr<packet_record *[]>{new (std::nothrow) packet_record *[descriptor_count] {}};
	if (descriptors == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED, "UDP TX descriptor allocation failed");
	}
	auto port = std::unique_ptr<udp_tx_port>{
		new (std::nothrow) udp_tx_port(std::move(storage_by_domain), domain_limit, logical_port,
					       std::move(descriptors), descriptor_count, transmit_api)};
	if (port == nullptr) {
		return status(status_code::RESOURCE_EXHAUSTED, "UDP TX queue allocation failed");
	}
	return common::status_or<std::unique_ptr<udp_tx_port>>(std::in_place, std::move(port));
}

udp_tx_port::udp_tx_port(std::unique_ptr<const packet_storage_domain_operations *[]> storage_operations,
			 uint32_t storage_domain_limit, uint16_t logical_port,
			 std::unique_ptr<packet_record *[]> descriptors, uint32_t descriptor_count,
			 udp_transmit_api transmit_api) noexcept
	: storage_by_domain_(std::move(storage_operations))
	, storage_domain_limit_(storage_domain_limit)
	, transmit_api_(transmit_api)
	, descriptors_(std::move(descriptors))
	, descriptor_capacity_(descriptor_count)
{
	burst_operations_.state = this;
	burst_operations_.transmit_burst = &udp_tx_port::transmit_burst_;
	burst_operations_.flush = &udp_tx_port::flush_;
	burst_operations_.maybe_flush = &udp_tx_port::maybe_flush_;
	burst_operations_.maximum_burst = static_cast<uint16_t>(
		std::min<uint32_t>(descriptor_count, kinetum::common::runtime_sizing::PACKET_MAX_BURST_SIZE));
	burst_operations_.logical_port = logical_port;
}

udp_tx_port::~udp_tx_port()
{
	shutdown();
}

status udp_tx_port::connect(const udp_ipv4_endpoint &endpoint)
{
	if (fd_ >= 0) {
		return status(status_code::FAILED_PRECONDITION, "UDP TX endpoint is already connected");
	}

	fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd_ < 0) {
		return status(status_code::INTERNAL_ERROR, "UDP TX socket creation failed");
	}

	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_port = endpoint.port_network_order;
	address.sin_addr.s_addr = endpoint.address_network_order;
	if (::connect(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
		shutdown();
		return status(status_code::INTERNAL_ERROR, "UDP TX connect failed");
	}
	return status::ok();
}

void udp_tx_port::shutdown() noexcept
{
	close_owned_socket(fd_);
	retire_deferred_();
}

uint16_t udp_tx_port::transmit_burst_(void *state, packet_record *const *records, uint16_t count) noexcept
{
	auto *port = static_cast<udp_tx_port *>(state);
	if (count == 0) {
		return 0;
	}
	if (port == nullptr || records == nullptr || count > port->burst_operations_.maximum_burst ||
	    port->storage_by_domain_ == nullptr) {
		std::terminate();
	}
	for (uint16_t index = 0; index < count; ++index) {
		if (records[index] == nullptr || records[index]->storage.operations == nullptr ||
		    records[index]->storage.operations->state == nullptr ||
		    records[index]->storage.operations->release_burst == nullptr) {
			std::terminate();
		}
	}

	if (port->fd_ < 0) {
		return 0;
	}
	uint16_t valid_count = 0;
	for (; valid_count < count; ++valid_count) {
		if (port->storage_for_(records[valid_count]) == nullptr) {
			break;
		}
	}
	(void)port->drain_once_();
	const uint32_t available = port->descriptor_capacity_ - port->descriptor_size_;
	const uint16_t accepted = static_cast<uint16_t>(std::min<uint32_t>(valid_count, available));
	for (uint16_t index = 0; index < accepted; ++index) {
		port->push_descriptor_(records[index]);
	}
	(void)port->drain_once_();
	return accepted;
}

void udp_tx_port::flush_(void *state) noexcept
{
	auto *port = static_cast<udp_tx_port *>(state);
	if (port == nullptr) {
		std::terminate();
	}
	while (port->descriptor_size_ != 0 && port->drain_once_() != 0) {
	}
}

uint8_t udp_tx_port::maybe_flush_(void *state) noexcept
{
	auto *port = static_cast<udp_tx_port *>(state);
	if (port == nullptr) {
		std::terminate();
	}
	return port->descriptor_size_ != 0 ? UINT8_C(1) : UINT8_C(0);
}

uint16_t udp_tx_port::drain_once_() noexcept
{
	if (fd_ < 0 || descriptor_size_ == 0) {
		return 0;
	}
	constexpr std::size_t MAX_BURST = kinetum::common::runtime_sizing::PACKET_MAX_BURST_SIZE;
	std::array<iovec, MAX_BURST> vectors;
	std::array<mmsghdr, MAX_BURST> messages;
	std::array<packet_record *, MAX_BURST> records;
	const uint16_t native_count = static_cast<uint16_t>(std::min<std::size_t>(descriptor_size_, MAX_BURST));
	for (uint16_t index = 0; index < native_count; ++index) {
		auto *record = descriptor_at_(index);
		if (storage_for_(record) == nullptr) {
			std::terminate();
		}
		records[index] = record;
		messages[index] = mmsghdr{};
		vectors[index].iov_base = record->storage.data;
		vectors[index].iov_len = record->storage.length;
		messages[index].msg_hdr.msg_iov = &vectors[index];
		messages[index].msg_hdr.msg_iovlen = 1;
	}
	const int result = transmit_api_.transmit_messages(transmit_api_.state, fd_, messages.data(), native_count);
	const int transmit_error = result < 0 ? errno : 0;
	if (KINETUM_UNLIKELY(result > static_cast<int>(native_count) ||
			     (result < 0 && !transmit_error_is_no_progress(transmit_error)))) {
		std::terminate();
	}
	const uint16_t transmitted = result > 0 ? static_cast<uint16_t>(result) : 0;
	if (transmitted != 0) {
		consume_descriptors_(transmitted);
		release_accepted_(records.data(), transmitted);
	}
	return transmitted;
}

void udp_tx_port::push_descriptor_(packet_record *record) noexcept
{
	if (record == nullptr || descriptors_ == nullptr || descriptor_size_ >= descriptor_capacity_) {
		std::terminate();
	}
	uint64_t tail = static_cast<uint64_t>(descriptor_head_) + descriptor_size_;
	if (tail >= descriptor_capacity_) {
		tail -= descriptor_capacity_;
	}
	const auto tail_index = static_cast<uint32_t>(tail);
	if (descriptors_[tail_index] != nullptr) {
		std::terminate();
	}
	descriptors_[tail_index] = record;
	++descriptor_size_;
}

packet_record *udp_tx_port::descriptor_at_(uint32_t offset) const noexcept
{
	if (offset >= descriptor_size_ || descriptors_ == nullptr) {
		return nullptr;
	}
	uint64_t index = static_cast<uint64_t>(descriptor_head_) + offset;
	if (index >= descriptor_capacity_) {
		index -= descriptor_capacity_;
	}
	return descriptors_[static_cast<uint32_t>(index)];
}

void udp_tx_port::consume_descriptors_(uint16_t count) noexcept
{
	if (count == 0 || count > descriptor_size_) {
		std::terminate();
	}
	for (uint16_t index = 0; index < count; ++index) {
		if (descriptors_[descriptor_head_] == nullptr) {
			std::terminate();
		}
		descriptors_[descriptor_head_] = nullptr;
		descriptor_head_ = descriptor_head_ + 1u == descriptor_capacity_ ? 0u : descriptor_head_ + 1u;
	}
	descriptor_size_ -= count;
}

void udp_tx_port::retire_deferred_() noexcept
{
	constexpr std::size_t MAX_BURST = kinetum::common::runtime_sizing::PACKET_MAX_BURST_SIZE;
	std::array<packet_record *, MAX_BURST> records;
	while (descriptor_size_ != 0) {
		const uint16_t count = static_cast<uint16_t>(std::min<std::size_t>(descriptor_size_, MAX_BURST));
		for (uint16_t index = 0; index < count; ++index) {
			records[index] = descriptor_at_(index);
		}
		consume_descriptors_(count);
		release_accepted_(records.data(), count);
	}
}

void udp_tx_port::release_accepted_(packet_record *const *records, uint16_t count) noexcept
{
	if (records == nullptr || count == 0 || storage_by_domain_ == nullptr) {
		std::terminate();
	}
	uint16_t first = 0;
	while (first < count) {
		const auto *storage = storage_for_(records[first]);
		if (storage == nullptr) {
			std::terminate();
		}
		uint16_t end = static_cast<uint16_t>(first + 1u);
		while (end < count && storage_for_(records[end]) == storage) {
			++end;
		}
		storage->release_burst(storage->state, records + first, static_cast<uint16_t>(end - first));
		first = end;
	}
}

const packet_storage_domain_operations *udp_tx_port::storage_for_(const packet_record *record) const noexcept
{
	if (record == nullptr || record->storage.domain_index >= storage_domain_limit_) {
		return nullptr;
	}
	const auto *storage = storage_by_domain_[record->storage.domain_index];
	if (storage == nullptr || record->storage.operations != storage || record->storage.native_handle == nullptr ||
	    record->storage.data == nullptr || record->storage.length == 0 ||
	    record->storage.length > storage->maximum_packet_length ||
	    record->storage.contiguous_length != record->storage.length ||
	    record->storage.generation != storage->generation || record->storage.segment_count != 1 ||
	    record->storage.capabilities != storage->capabilities) {
		return nullptr;
	}
	return storage;
}

}  // namespace kinetum::dp
