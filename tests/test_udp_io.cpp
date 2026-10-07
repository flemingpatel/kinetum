// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_udp_io.cpp
 * @brief Unit tests for provider-private UDP packet operations.
 * @author Fleming Patel
 *
 * These tests exercise the plan-schema-free UDP mechanics that survive the
 * provider-authority cutover: strict numeric endpoint admission, fixed-pool
 * receive ownership, and exact accepted-prefix transmit ownership.
 */

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <utility>

#include "src/common/status_or.hpp"
#include "src/dp/backends/udp/udp_io.hpp"
#include "src/dp/fixed_packet_pool.hpp"
#include "tests/worker_telemetry_test_fixture.hpp"

namespace kinetum::dp
{

namespace
{

/** @brief Bounded fresh-port attempts for direct UDP mechanism rows. */
constexpr std::size_t MAX_RX_HANDOFF_ATTEMPTS = 8u;

/** @brief Test-owned socket descriptor with deterministic scope-exit closure. */
class scoped_test_socket {
    public:
	/**
	 * @brief Adopt one socket descriptor for scope-exit closure.
	 * @param descriptor Sole socket descriptor transferred into the fixture, or -1.
	 */
	explicit scoped_test_socket(int descriptor) noexcept
		: descriptor_(descriptor)
	{
	}

	scoped_test_socket(const scoped_test_socket &) = delete;
	scoped_test_socket &operator=(const scoped_test_socket &) = delete;
	scoped_test_socket(scoped_test_socket &&) = delete;
	scoped_test_socket &operator=(scoped_test_socket &&) = delete;

	/** @brief Close the exact adopted descriptor. */
	~scoped_test_socket()
	{
		if (descriptor_ >= 0) {
			::close(descriptor_);
		}
	}

	/** @return Borrowed socket descriptor. */
	[[nodiscard]] int get() const noexcept
	{
		return descriptor_;
	}

    private:
	int descriptor_{-1};  ///< Owned socket descriptor, or -1.
};

/**
 * @brief Reserve one loopback UDP endpoint and return its assigned address.
 *
 * The reservation socket closes before the caller consumes the address. RX
 * callers compose this selector only through the bounded typed-collision
 * helper below; TX-only callers need no local bind ownership.
 *
 * @return Loopback address carrying one kernel-assigned UDP port.
 */
[[nodiscard]] sockaddr_in reserve_loopback_endpoint()
{
	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	{
		scoped_test_socket reservation(::socket(AF_INET, SOCK_DGRAM, 0));
		EXPECT_GE(reservation.get(), 0);
		if (reservation.get() < 0) {
			return address;
		}
		EXPECT_EQ(::bind(reservation.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)), 0);
		socklen_t address_length = sizeof(address);
		EXPECT_EQ(::getsockname(reservation.get(), reinterpret_cast<sockaddr *>(&address), &address_length), 0);
	}
	return address;
}

/**
 * @brief Convert one test socket address into the exact provider endpoint.
 * @param address Borrowed IPv4 socket address in network byte order.
 * @return Provider endpoint preserving network-order address and port.
 */
[[nodiscard]] udp_ipv4_endpoint exact_endpoint(const sockaddr_in &address) noexcept
{
	return udp_ipv4_endpoint{
		.address_network_order = address.sin_addr.s_addr,
		.port_network_order = address.sin_port,
	};
}

/**
 * @brief Reserve one fresh explicit RX endpoint through the production method.
 *
 * @param port Cold queue that does not yet own a socket.
 * @return Exact bound loopback address, the first non-collision failure, or a
 *         bounded contention failure.
 */
[[nodiscard]] common::status_or<sockaddr_in> reserve_rx_endpoint(udp_rx_port &port)
{
	for (std::size_t attempt = 0u; attempt < MAX_RX_HANDOFF_ATTEMPTS; ++attempt) {
		const sockaddr_in address = reserve_loopback_endpoint();
		if (address.sin_port == 0) {
			return common::status::internal_error("UDP test reservation returned endpoint port zero");
		}
		const auto reservation = port.reserve(exact_endpoint(address));
		if (reservation.is_ok()) {
			return address;
		}
		if (reservation.code() != common::status_code::ALREADY_EXISTS) {
			return reservation;
		}
	}
	return common::status::already_exists("UDP test RX endpoint handoff remained contended");
}

/**
 * @brief Build one exact provider-free storage shape for UDP mechanism tests.
 *
 * @param record_count Logical packet-credit population.
 * @param data_room_bytes Bytes reserved for each packet payload.
 * @return Complete fixed-pool options with intentionally absent host NUMA.
 */
[[nodiscard]] fixed_packet_pool_options udp_test_pool_options(uint32_t record_count, uint32_t data_room_bytes) noexcept
{
	return fixed_packet_pool_options{
		.record_count = record_count,
		.data_room_bytes = data_room_bytes,
		.headroom_bytes = 0,
		.alignment_bytes = 64,
		.domain_index = 4,
		.generation = 9,
		.host_numa_node = std::nullopt,
	};
}

/**
 * @brief Deliberately violate the storage accepted-prefix contract.
 * @param state Unused fake storage context.
 * @param records Unused output array; no actual records are acquired.
 * @param capacity Advertised output bound deliberately exceeded by the reported count.
 * @return capacity plus one, narrowed to the ABI count type.
 */
uint16_t overreturn_storage_burst(void *state, packet_record **records, uint16_t capacity) noexcept
{
	(void)state;
	(void)records;
	return static_cast<uint16_t>(capacity + 1u);
}

/**
 * @brief Inert release callback needed only to form the malformed test table.
 * @param state Unused fake storage context.
 * @param records Unused candidate record array.
 * @param count Unused candidate extent.
 */
void inert_storage_release(void *state, packet_record *const *records, uint16_t count) noexcept
{
	(void)state;
	(void)records;
	(void)count;
}

/**
 * @brief Inert cold observation callback needed only for exact ABI shape.
 * @return OK without populating observations; used only by malformed storage fixtures.
 */
kinetum_provider_status inert_storage_observation(void *, kinetum_provider_storage_observation *,
						  kinetum_provider_diagnostic *) noexcept
{
	return KINETUM_PROVIDER_STATUS_OK;
}

/** @brief Construct UDP RX with a storage callback that overstates its prefix. */
void construct_rx_with_overreturning_storage()
{
	uint8_t state = 0;
	packet_storage_domain_operations storage{
		.state = &state,
		.acquire_burst = overreturn_storage_burst,
		.clone_writable = nullptr,
		.copy_origins_burst = nullptr,
		.release_burst = inert_storage_release,
		.observe_statistics = inert_storage_observation,
		.generation = 1,
		.domain_index = 1,
		.maximum_packet_length = 64,
		.capabilities = packet_storage_capabilities::CPU_CONTIGUOUS_READ |
				packet_storage_capabilities::CPU_CONTIGUOUS_WRITE,
		.padding = {0},
	};
	(void)udp_rx_port::create(storage, 7, 1);
}

/** @brief Complete malformed storage state that repeats one linear token. */
struct duplicate_descriptor_storage_state {
	packet_storage_domain_operations operations{};	///< Malformed operation authority.
	packet_record record{};				///< Sole token returned more than once.
	uint8_t payload{0};				///< Non-null test backing.
	bool return_partial{false};			///< Whether duplication precedes a short prefix.
};

/**
 * @brief Return the same storage token in every accepted output slot.
 * @param state Borrowed duplicate-token fixture state.
 * @param records Output array deliberately populated with duplicate ownership.
 * @param capacity Positive output extent large enough for the fixture's chosen duplicate prefix.
 * @return Injected prefix length containing at least two copies of the same token.
 */
uint16_t duplicate_descriptor_burst(void *state, packet_record **records, uint16_t capacity) noexcept
{
	auto *storage = static_cast<duplicate_descriptor_storage_state *>(state);
	if (storage == nullptr || records == nullptr || capacity == 0) {
		std::terminate();
	}
	const uint16_t acquired = storage->return_partial ? static_cast<uint16_t>(capacity - 1u) : capacity;
	if (acquired < 2u) {
		std::terminate();
	}
	for (uint16_t index = 0; index < acquired; ++index) {
		records[index] = &storage->record;
	}
	return acquired;
}

/**
 * @brief Complete one duplicate-credit fixture without a second storage shape.
 * @param state Fixture storage and operation tables to initialize.
 */
void initialize_duplicate_descriptor_storage(duplicate_descriptor_storage_state &state) noexcept
{
	state.operations.state = &state;
	state.operations.acquire_burst = duplicate_descriptor_burst;
	state.operations.release_burst = inert_storage_release;
	state.operations.observe_statistics = inert_storage_observation;
	state.operations.generation = 1;
	state.operations.domain_index = 1;
	state.operations.maximum_packet_length = 64;
	state.operations.capabilities = packet_storage_capabilities::CPU_CONTIGUOUS_READ |
					packet_storage_capabilities::CPU_CONTIGUOUS_WRITE;
	state.record.storage.native_handle = &state.record;
	state.record.storage.data = &state.payload;
	state.record.storage.operations = &state.operations;
	state.record.storage.generation = state.operations.generation;
	state.record.storage.domain_index = state.operations.domain_index;
	state.record.storage.segment_count = 1;
	state.record.storage.capabilities = state.operations.capabilities;
}

/** @brief Deterministic syscall state that never accepts a UDP datagram. */
struct blocked_datagram_state {
	uint32_t transmit_calls{0};  ///< Number of exact deferred-send attempts.
};

/** @brief Scope-exit reclamation for one record not yet transferred to a provider. */
struct test_record_deleter {
	const packet_storage_domain_operations *storage;  ///< Original pool retained by the test.
	/**
	 * @brief Return one still-owned record through its original storage table.
	 * @param record Sole retained record transferred back through the fixture's original domain.
	 */
	void operator()(packet_record *record) const noexcept
	{
		storage->release_burst(storage->state, &record, 1u);
	}
};

/** @brief Test-owned record whose accepted transfer explicitly releases the guard. */
using test_record_owner = std::unique_ptr<packet_record, test_record_deleter>;

/**
 * @brief Acquire and initialize one scope-owned one-byte UDP test record.
 * @param pool Original allocation and reclamation owner.
 * @param value Packet byte used to identify submission order.
 * @return Exact owned record, or an empty guard after an acquisition failure.
 */
[[nodiscard]] test_record_owner acquire_test_record(fixed_packet_pool &pool, uint8_t value)
{
	packet_record *record = nullptr;
	EXPECT_EQ(pool.acquire_burst(&record, 1u), 1u);
	if (record != nullptr) {
		record->storage.data[0] = value;
		record->storage.length = 1u;
		record->storage.contiguous_length = 1u;
	}
	return test_record_owner{record, test_record_deleter{&pool.operations()}};
}

/** @brief Bounded native-submission observations for ordered mixed-domain sends. */
struct prefix_datagram_state {
	std::array<const void *, 8> addresses{};  ///< Borrowed payload addresses seen before reclamation.
	std::array<uint8_t, 8> values{};	  ///< Submitted first bytes in exact native order.
	uint16_t observed{0};			  ///< Occupied observation prefix.
	uint16_t maximum_accept{1};		  ///< Exact per-call accepted-prefix ceiling.
};

/**
 * @brief Accept a bounded native prefix and retain only copied submission observations.
 * @param state Borrowed bounded prefix-observation state.
 * @param fd Nonnegative connected fixture socket.
 * @param messages Borrowed one-byte datagrams whose addresses and values are observed.
 * @param count Positive submitted prefix length.
 * @return Prefix accepted up to the injected limit, with native result lengths populated.
 */
int accept_datagram_prefix(void *state, int fd, mmsghdr *messages, uint16_t count) noexcept
{
	auto *observations = static_cast<prefix_datagram_state *>(state);
	if (observations == nullptr || fd < 0 || messages == nullptr || count == 0) {
		std::terminate();
	}
	const uint16_t accepted = std::min(count, observations->maximum_accept);
	for (uint16_t index = 0; index < accepted; ++index) {
		if (observations->observed >= observations->values.size() || messages[index].msg_hdr.msg_iovlen != 1u ||
		    messages[index].msg_hdr.msg_iov == nullptr || messages[index].msg_hdr.msg_iov[0].iov_len != 1u) {
			std::terminate();
		}
		const void *data = messages[index].msg_hdr.msg_iov[0].iov_base;
		observations->addresses[observations->observed] = data;
		observations->values[observations->observed] = *static_cast<const uint8_t *>(data);
		++observations->observed;
		messages[index].msg_len = 1u;
	}
	return accepted;
}

/** @brief Injectable native error and invocation count for UDP syscall edges. */
struct datagram_error_state {
	int error{0};	    ///< Exact errno value published with a negative result.
	uint32_t calls{0};  ///< Number of callback invocations.
};

/**
 * @brief Return one selected negative native result with exact errno.
 * @param state Borrowed callback-specific injection and observation state.
 * @param fd Nonnegative connected fixture socket.
 * @param messages Non-null borrowed candidate messages.
 * @param count Positive candidate prefix length.
 * @return -1 after publishing the selected errno and incrementing the call count.
 */
int return_datagram_error(void *state, int fd, mmsghdr *messages, uint16_t count) noexcept
{
	auto *error = static_cast<datagram_error_state *>(state);
	if (error == nullptr || error->error == 0 || fd < 0 || messages == nullptr || count == 0u) {
		std::terminate();
	}
	++error->calls;
	errno = error->error;
	return -1;
}

/**
 * @brief Leave every TX descriptor pending while recording the attempt.
 * @param state Borrowed callback-specific injection and observation state.
 * @param fd Nonnegative connected fixture socket.
 * @param messages Non-null borrowed candidate messages.
 * @param count Positive candidate prefix length.
 * @return Zero after recording the attempt; no datagram is accepted.
 */
int transmit_no_messages(void *state, int fd, mmsghdr *messages, uint16_t count) noexcept
{
	auto *blocked = static_cast<blocked_datagram_state *>(state);
	if (blocked == nullptr || fd < 0 || messages == nullptr || count == 0) {
		std::terminate();
	}
	++blocked->transmit_calls;
	return 0;
}

/**
 * @brief Exact test storage owner whose population crosses one uint16 ABI call.
 *
 * Every record is a distinct linear token. Acquisition and release counters
 * prove that the UDP queue chunks only operation calls while preserving the
 * provider's descending acquisition order across one wider authored
 * descriptor population.
 */
class cross_burst_storage final {
    public:
	/**
	 * @brief Allocate and initialize one exact test-owned record population.
	 * @param record_count Fixed logical record population retained by this fixture.
	 */
	explicit cross_burst_storage(uint32_t record_count)
		: records_(std::make_unique<packet_record[]>(record_count))
		, record_count_(record_count)
	{
		operations_.state = this;
		operations_.acquire_burst = &cross_burst_storage::acquire_burst_;
		operations_.release_burst = &cross_burst_storage::release_burst_;
		operations_.observe_statistics = inert_storage_observation;
		operations_.generation = 17;
		operations_.domain_index = 3;
		operations_.maximum_packet_length = 64;
		operations_.capabilities = packet_storage_capabilities::CPU_CONTIGUOUS_READ |
					   packet_storage_capabilities::CPU_CONTIGUOUS_WRITE;
		for (uint32_t index = 0; index < record_count_; ++index) {
			auto &record = records_[index];
			record.storage.data = &payload_;
			record.storage.operations = &operations_;
			record.storage.generation = operations_.generation;
			record.storage.domain_index = operations_.domain_index;
			record.storage.segment_count = 1;
			record.storage.capabilities = operations_.capabilities;
		}
	}

	/** @return Exact immutable storage operation table. */
	[[nodiscard]] const packet_storage_domain_operations &operations() const noexcept
	{
		return operations_;
	}

	/** @return Number of bounded acquisition calls. */
	[[nodiscard]] uint32_t acquire_calls() const noexcept
	{
		return acquire_calls_;
	}

	/** @return Number of bounded release calls. */
	[[nodiscard]] uint32_t release_calls() const noexcept
	{
		return release_calls_;
	}

	/** @return Number of records currently transferred out of this owner. */
	[[nodiscard]] uint32_t outstanding() const noexcept
	{
		return outstanding_;
	}

	/** @return Number of credits returned in their exact acquisition order. */
	[[nodiscard]] uint32_t ordered_release_count() const noexcept
	{
		return ordered_release_count_;
	}

    private:
	/**
	 * @brief Transfer one exact available record prefix to the caller.
	 * @param state Borrowed cross-burst storage fixture.
	 * @param records Output array receiving distinct records in descending slot order.
	 * @param capacity Positive output capacity.
	 * @return Available prefix length bounded by capacity.
	 */
	static uint16_t acquire_burst_(void *state, packet_record **records, uint16_t capacity) noexcept
	{
		auto *storage = static_cast<cross_burst_storage *>(state);
		if (storage == nullptr || records == nullptr || capacity == 0) {
			std::terminate();
		}
		++storage->acquire_calls_;
		const uint32_t remaining = storage->record_count_ - storage->next_record_;
		const uint16_t acquired = static_cast<uint16_t>(std::min<uint32_t>(remaining, capacity));
		for (uint16_t index = 0; index < acquired; ++index) {
			auto *record = &storage->records_[storage->record_count_ - 1u - storage->next_record_++];
			if (record->storage.native_handle != nullptr) {
				std::terminate();
			}
			record->storage.native_handle = record;
			records[index] = record;
		}
		storage->outstanding_ += acquired;
		return acquired;
	}

	/**
	 * @brief Reclaim one exact transferred record prefix.
	 * @param state Borrowed cross-burst storage fixture.
	 * @param records Live records returned in their exact acquisition order.
	 * @param count Positive returned prefix not exceeding outstanding ownership.
	 */
	static void release_burst_(void *state, packet_record *const *records, uint16_t count) noexcept
	{
		auto *storage = static_cast<cross_burst_storage *>(state);
		if (storage == nullptr || records == nullptr || count == 0 || count > storage->outstanding_) {
			std::terminate();
		}
		++storage->release_calls_;
		for (uint16_t index = 0; index < count; ++index) {
			auto *record = records[index];
			if (record == nullptr || record < storage->records_.get() ||
			    record >= storage->records_.get() + storage->record_count_ ||
			    storage->ordered_release_count_ >= storage->record_count_ ||
			    record !=
				    &storage->records_[storage->record_count_ - 1u - storage->ordered_release_count_] ||
			    record->storage.native_handle != record) {
				std::terminate();
			}
			record->storage.native_handle = nullptr;
			++storage->ordered_release_count_;
		}
		storage->outstanding_ -= count;
	}

	packet_storage_domain_operations operations_{};	 ///< Immutable operation authority.
	std::unique_ptr<packet_record[]> records_;	 ///< Exact test-owned token population.
	uint32_t record_count_{0};			 ///< Complete token population.
	uint32_t next_record_{0};			 ///< Next never-acquired token.
	uint32_t outstanding_{0};			 ///< Tokens currently transferred to the queue.
	uint32_t acquire_calls_{0};			 ///< Bounded acquisition calls.
	uint32_t release_calls_{0};			 ///< Bounded release calls.
	uint32_t ordered_release_count_{0};		 ///< Credits returned in provider acquisition order.
	uint8_t payload_{0};				 ///< Shared non-accessed non-null test backing.
};

}  // namespace

/** @brief Verify the provider parser accepts only canonical IPv4 and uint16 ports. */
TEST(udp_io, endpoint_parser_requires_canonical_numeric_ipv4_and_uint16_port)
{
	udp_ipv4_endpoint parsed{};
	EXPECT_FALSE(parse_udp_ipv4_endpoint("localhost", 9, parsed));
	EXPECT_FALSE(parse_udp_ipv4_endpoint("127.0.0.1", 65536, parsed));
	EXPECT_FALSE(parse_udp_ipv4_endpoint("127.000.0.1", 9, parsed));
	ASSERT_TRUE(parse_udp_ipv4_endpoint("127.0.0.1", 65535, parsed));
	EXPECT_EQ(parsed.address_network_order, htonl(INADDR_LOOPBACK));
	EXPECT_EQ(parsed.port_network_order, htons(UINT16_MAX));
}

/** @brief Prove datagrams arriving before activation cannot leak into packet execution. */
TEST(udp_io, reserved_rx_endpoint_drops_pre_activation_datagrams)
{
	sockaddr_in occupied_address{};
	occupied_address.sin_family = AF_INET;
	occupied_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	scoped_test_socket occupied_endpoint(::socket(AF_INET, SOCK_DGRAM, 0));
	ASSERT_GE(occupied_endpoint.get(), 0);
	ASSERT_EQ(::bind(occupied_endpoint.get(), reinterpret_cast<const sockaddr *>(&occupied_address),
			 sizeof(occupied_address)),
		  0);
	socklen_t occupied_length = sizeof(occupied_address);
	ASSERT_EQ(::getsockname(occupied_endpoint.get(), reinterpret_cast<sockaddr *>(&occupied_address),
				&occupied_length),
		  0);
	ASSERT_NE(occupied_address.sin_port, 0);

	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(2, 64));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	auto port_or = udp_rx_port::create(pool->operations(), 7, 1);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	const auto collision_status = port->reserve(exact_endpoint(occupied_address));
	ASSERT_EQ(collision_status.code(), common::status_code::ALREADY_EXISTS);
	EXPECT_EQ(collision_status.message(), "UDP RX endpoint is already reserved");
	auto address_or = reserve_rx_endpoint(*port);
	ASSERT_TRUE(address_or.is_ok()) << address_or.error().message();
	const sockaddr_in address = address_or.value();

	scoped_test_socket sender(::socket(AF_INET, SOCK_DGRAM, 0));
	ASSERT_GE(sender.get(), 0);
	constexpr std::array<uint8_t, 4> BEFORE_ACTIVATION{0xba, 0xad, 0xf0, 0x0d};
	ASSERT_EQ(::sendto(sender.get(), BEFORE_ACTIVATION.data(), BEFORE_ACTIVATION.size(), 0,
			   reinterpret_cast<const sockaddr *>(&address), sizeof(address)),
		  static_cast<ssize_t>(BEFORE_ACTIVATION.size()));

	const auto activation_status = port->activate();
	ASSERT_TRUE(activation_status.is_ok()) << activation_status.message();
	packet_record *records[1]{};
	const auto &operations = port->burst_operations();
	const auto before_activation = operations.receive_burst(operations.state, records, 1);
	EXPECT_EQ(before_activation.transferred_count, 0u);
	EXPECT_EQ(before_activation.rejected_count, 0u);

	constexpr std::array<uint8_t, 4> AFTER_ACTIVATION{0xca, 0xfe, 0xba, 0xbe};
	ASSERT_EQ(::sendto(sender.get(), AFTER_ACTIVATION.data(), AFTER_ACTIVATION.size(), 0,
			   reinterpret_cast<const sockaddr *>(&address), sizeof(address)),
		  static_cast<ssize_t>(AFTER_ACTIVATION.size()));
	const auto after_activation = operations.receive_burst(operations.state, records, 1);
	ASSERT_EQ(after_activation.transferred_count, 1u);
	EXPECT_EQ(after_activation.rejected_count, 0u);
	ASSERT_NE(records[0], nullptr);
	EXPECT_EQ(records[0]->storage.length, static_cast<uint32_t>(AFTER_ACTIVATION.size()));
	EXPECT_EQ(std::memcmp(records[0]->storage.data, AFTER_ACTIVATION.data(), AFTER_ACTIVATION.size()), 0);
	const auto &storage = pool->operations();
	storage.release_burst(storage.state, records, 1);

	const auto deactivation_status = port->deactivate();
	ASSERT_TRUE(deactivation_status.is_ok()) << deactivation_status.message();
}

/** @brief Prove cold publication discards every datagram accepted by the prior live interval. */
TEST(udp_io, deactivation_discards_accepted_backlog_before_reactivation)
{
	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(2, 64));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	auto port_or = udp_rx_port::create(pool->operations(), 7, 1);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	auto address_or = reserve_rx_endpoint(*port);
	ASSERT_TRUE(address_or.is_ok()) << address_or.error().message();
	const sockaddr_in address = address_or.value();
	ASSERT_TRUE(port->activate().is_ok());

	scoped_test_socket sender(::socket(AF_INET, SOCK_DGRAM, 0));
	ASSERT_GE(sender.get(), 0);
	constexpr std::array<uint8_t, 4> PRIOR_INTERVAL{0xde, 0xad, 0xfa, 0xce};
	ASSERT_EQ(::sendto(sender.get(), PRIOR_INTERVAL.data(), PRIOR_INTERVAL.size(), 0,
			   reinterpret_cast<const sockaddr *>(&address), sizeof(address)),
		  static_cast<ssize_t>(PRIOR_INTERVAL.size()));

	ASSERT_TRUE(port->deactivate().is_ok());
	ASSERT_TRUE(port->activate().is_ok());
	packet_record *records[1]{};
	const auto &operations = port->burst_operations();
	const auto before_reactivation = operations.receive_burst(operations.state, records, 1);
	EXPECT_EQ(before_reactivation.transferred_count, 0u);
	EXPECT_EQ(before_reactivation.rejected_count, 0u);

	constexpr std::array<uint8_t, 4> CURRENT_INTERVAL{0xca, 0xfe, 0xba, 0xbe};
	ASSERT_EQ(::sendto(sender.get(), CURRENT_INTERVAL.data(), CURRENT_INTERVAL.size(), 0,
			   reinterpret_cast<const sockaddr *>(&address), sizeof(address)),
		  static_cast<ssize_t>(CURRENT_INTERVAL.size()));
	const auto after_reactivation = operations.receive_burst(operations.state, records, 1);
	ASSERT_EQ(after_reactivation.transferred_count, 1u);
	EXPECT_EQ(after_reactivation.rejected_count, 0u);
	ASSERT_NE(records[0], nullptr);
	EXPECT_EQ(std::memcmp(records[0]->storage.data, CURRENT_INTERVAL.data(), CURRENT_INTERVAL.size()), 0);
	const auto &storage = pool->operations();
	storage.release_burst(storage.state, records, 1);
	ASSERT_TRUE(port->deactivate().is_ok());
}

/**
 * @brief Prove oversized input retires while later valid input compacts into the published prefix.
 */
TEST(udp_io, rx_rejects_truncation_and_compacts_valid_prefix)
{
	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(3, 8));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	auto port_or = udp_rx_port::create(pool->operations(), 7, 2);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	auto address_or = reserve_rx_endpoint(*port);
	ASSERT_TRUE(address_or.is_ok()) << address_or.error().message();
	const sockaddr_in address = address_or.value();
	const auto activation_status = port->activate();
	ASSERT_TRUE(activation_status.is_ok()) << activation_status.message();

	scoped_test_socket sender(::socket(AF_INET, SOCK_DGRAM, 0));
	ASSERT_GE(sender.get(), 0);
	constexpr std::array<uint8_t, 12> OVERSIZED{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	constexpr std::array<uint8_t, 4> VALID{0xde, 0xad, 0xbe, 0xef};
	ASSERT_EQ(::sendto(sender.get(), OVERSIZED.data(), OVERSIZED.size(), 0,
			   reinterpret_cast<const sockaddr *>(&address), sizeof(address)),
		  static_cast<ssize_t>(OVERSIZED.size()));
	ASSERT_EQ(::sendto(sender.get(), VALID.data(), VALID.size(), 0, reinterpret_cast<const sockaddr *>(&address),
			   sizeof(address)),
		  static_cast<ssize_t>(VALID.size()));

	packet_record *records[3]{};
	const auto &operations = port->burst_operations();
	const auto outcome = operations.receive_burst(operations.state, records, 3);
	const uint16_t received = outcome.transferred_count;

	ASSERT_EQ(received, 1u);
	EXPECT_EQ(outcome.rejected_count, 1u);
	ASSERT_NE(records[0], nullptr);
	EXPECT_EQ(records[0]->storage.length, static_cast<uint32_t>(VALID.size()));
	EXPECT_EQ(records[0]->storage.contiguous_length, static_cast<uint32_t>(VALID.size()));
	EXPECT_EQ(std::memcmp(records[0]->storage.data, VALID.data(), VALID.size()), 0);
	EXPECT_EQ(pool->outstanding(), 3u);
	EXPECT_EQ(pool->available_approx(), 0u);
	const auto &storage = pool->operations();
	storage.release_burst(storage.state, records, received);
	EXPECT_EQ(pool->outstanding(), 2u);
	EXPECT_EQ(pool->available_approx(), 1u);
	const auto deactivation_status = port->deactivate();
	ASSERT_TRUE(deactivation_status.is_ok()) << deactivation_status.message();
	port.reset();
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 3u);
}

/** @brief Prove a storage provider cannot overrun the RX caller's exact prefix. */
TEST(udp_io, rx_rejects_storage_prefix_overrun)
{
	EXPECT_DEATH(construct_rx_with_overreturning_storage(), "");
}

/** @brief Prove duplicate linear descriptor credits fail stop before publication. */
TEST(udp_io, rx_rejects_duplicate_linear_descriptor_credit)
{
	EXPECT_DEATH(
		{
			duplicate_descriptor_storage_state state;
			initialize_duplicate_descriptor_storage(state);
			(void)udp_rx_port::create(state.operations, 7, 2);
		},
		"");
	EXPECT_DEATH(
		{
			duplicate_descriptor_storage_state state;
			state.return_partial = true;
			initialize_duplicate_descriptor_storage(state);
			(void)udp_rx_port::create(state.operations, 7, 3);
		},
		"");
}

/** @brief Prove failed RX descriptor reservation returns every partial storage credit. */
TEST(udp_io, rx_descriptor_reservation_is_exact_and_transactional)
{
	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(3, 64));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();

	const auto port_or = udp_rx_port::create(pool->operations(), 7, 4);
	ASSERT_FALSE(port_or.is_ok());
	EXPECT_EQ(port_or.error().code(), common::status_code::RESOURCE_EXHAUSTED);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 3u);
}

/** @brief Prove a uint32 queue population crosses the uint16 ABI without narrowing. */
TEST(udp_io, rx_descriptor_reservation_crosses_burst_abi_without_narrowing)
{
	constexpr uint32_t DESCRIPTOR_COUNT = static_cast<uint32_t>(UINT16_MAX) + 1u;
	cross_burst_storage storage(DESCRIPTOR_COUNT);
	auto port_or = udp_rx_port::create(storage.operations(), 7, DESCRIPTOR_COUNT);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	EXPECT_EQ(storage.acquire_calls(), 2u);
	EXPECT_EQ(storage.outstanding(), DESCRIPTOR_COUNT);

	port.reset();
	EXPECT_EQ(storage.release_calls(), 2u);
	EXPECT_EQ(storage.outstanding(), 0u);
	EXPECT_EQ(storage.ordered_release_count(), DESCRIPTOR_COUNT);
}

/** @brief Prove UDP TX leaves an entirely unaccepted suffix caller-owned. */
TEST(udp_io, tx_preserves_unaccepted_suffix)
{
	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(3, 64));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	auto port_or = udp_tx_port::create(std::array{&pool->operations()}, 8, 3);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	packet_record *records[3]{};
	ASSERT_EQ(pool->acquire_burst(records, 3), 3u);
	ASSERT_EQ(pool->outstanding(), 3u);

	const auto &operations = port->burst_operations();
	const uint16_t transmitted = operations.transmit_burst(operations.state, records, 3);

	EXPECT_EQ(transmitted, 0u);
	EXPECT_EQ(pool->outstanding(), 3u);
	EXPECT_EQ(pool->available_approx(), 0u);
	const auto &storage = pool->operations();
	storage.release_burst(storage.state, records, 3);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 3u);
}

/** @brief Prove UDP TX consumes one successful prefix and leaves its suffix untouched. */
TEST(udp_io, tx_consumes_only_successful_prefix)
{
	scoped_test_socket receiver(::socket(AF_INET, SOCK_DGRAM, 0));
	ASSERT_GE(receiver.get(), 0);
	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	ASSERT_EQ(::bind(receiver.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)), 0);
	socklen_t address_length = sizeof(address);
	ASSERT_EQ(::getsockname(receiver.get(), reinterpret_cast<sockaddr *>(&address), &address_length), 0);

	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(2, 64));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	auto port_or = udp_tx_port::create(std::array{&pool->operations()}, 8, 2);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	const auto connect_status = port->connect(exact_endpoint(address));
	ASSERT_TRUE(connect_status.is_ok()) << connect_status.message();

	packet_record *records[2]{};
	ASSERT_EQ(pool->acquire_burst(records, 2), 2u);
	constexpr std::array<uint8_t, 4> PAYLOAD{0xde, 0xad, 0xbe, 0xef};
	std::memcpy(records[0]->storage.data, PAYLOAD.data(), PAYLOAD.size());
	records[0]->storage.length = static_cast<uint32_t>(PAYLOAD.size());
	records[0]->storage.contiguous_length = static_cast<uint32_t>(PAYLOAD.size());
	records[1]->storage.length = 0;
	records[1]->storage.contiguous_length = 0;

	const auto &operations = port->burst_operations();
	const uint16_t accepted = operations.transmit_burst(operations.state, records, 2);

	EXPECT_EQ(accepted, 1u);
	EXPECT_EQ(pool->outstanding(), 1u);
	std::array<uint8_t, 16> received{};
	const auto received_size = ::recv(receiver.get(), received.data(), received.size(), MSG_DONTWAIT);
	ASSERT_EQ(received_size, static_cast<ssize_t>(PAYLOAD.size()));
	EXPECT_EQ(std::memcmp(received.data(), PAYLOAD.data(), PAYLOAD.size()), 0);
	const auto &storage = pool->operations();
	storage.release_burst(storage.state, records + accepted, 1);
	EXPECT_EQ(pool->outstanding(), 0u);
	EXPECT_EQ(pool->available_approx(), 2u);
}

/** @brief Prove deferred TX descriptors own one exact prefix and retire it at shutdown. */
TEST(udp_io, tx_descriptor_backpressure_and_shutdown_conserve_every_record)
{
	const sockaddr_in address = reserve_loopback_endpoint();
	ASSERT_NE(address.sin_port, 0);
	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(2, 64));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	blocked_datagram_state blocked;
	const udp_transmit_api api{
		.state = &blocked,
		.transmit_messages = transmit_no_messages,
	};
	auto port_or = udp_tx_port::create(std::array{&pool->operations()}, 8, 1, api);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	const auto connect_status = port->connect(exact_endpoint(address));
	ASSERT_TRUE(connect_status.is_ok()) << connect_status.message();

	packet_record *records[2]{};
	ASSERT_EQ(pool->acquire_burst(records, 2), 2u);
	constexpr std::array<uint8_t, 1> PAYLOAD{0x5a};
	for (auto *record : records) {
		std::memcpy(record->storage.data, PAYLOAD.data(), PAYLOAD.size());
		record->storage.length = static_cast<uint32_t>(PAYLOAD.size());
		record->storage.contiguous_length = static_cast<uint32_t>(PAYLOAD.size());
	}

	const auto &operations = port->burst_operations();
	EXPECT_EQ(operations.transmit_burst(operations.state, records, 1), 1u);
	EXPECT_EQ(operations.transmit_burst(operations.state, records + 1, 1), 0u);
	EXPECT_EQ(operations.maybe_flush(operations.state), 1u);
	operations.flush(operations.state);
	EXPECT_GE(blocked.transmit_calls, 2u);
	EXPECT_EQ(pool->outstanding(), 2u);

	port->shutdown();
	EXPECT_EQ(pool->outstanding(), 1u);
	const auto &storage = pool->operations();
	storage.release_burst(storage.state, records + 1, 1);
	EXPECT_EQ(pool->outstanding(), 0u);
}

/** @brief TX storage admission rejects empty, null, duplicate, unsorted, and incompatible tables. */
TEST(udp_io, transmit_storage_set_requires_exact_order_and_generation)
{
	auto first_or = fixed_packet_pool::create(udp_test_pool_options(1, 64));
	auto second_options = udp_test_pool_options(1, 64);
	second_options.domain_index = 7;
	auto second_or = fixed_packet_pool::create(second_options);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first = std::move(first_or).value();
	auto second = std::move(second_or).value();
	const auto *first_storage = &first->operations();
	const auto *second_storage = &second->operations();
	auto foreign_generation = *second_storage;
	++foreign_generation.generation;
	auto unreadable = *second_storage;
	unreadable.capabilities &= ~packet_storage_capabilities::CPU_CONTIGUOUS_READ;
	const std::array<std::array<const packet_storage_domain_operations *, 2>, 5> invalid_sets{{
		{first_storage, nullptr},
		{first_storage, first_storage},
		{second_storage, first_storage},
		{first_storage, &foreign_generation},
		{first_storage, &unreadable},
	}};
	for (const auto &admitted : invalid_sets) {
		auto rejected = udp_tx_port::create(admitted, 8, 1);
		ASSERT_FALSE(rejected.is_ok());
		EXPECT_EQ(rejected.error().code(), common::status_code::INVALID_ARGUMENT);
	}
	auto empty = udp_tx_port::create({}, 8, 1);
	ASSERT_FALSE(empty.is_ok());
	EXPECT_EQ(empty.error().code(), common::status_code::INVALID_ARGUMENT);
}

/** @brief Mixed-domain native submissions keep their original buffers and ordered prefix. */
TEST(udp_io, mixed_storage_tx_preserves_buffers_order_and_original_reclamation)
{
	auto first_options = udp_test_pool_options(2, 64);
	auto second_options = udp_test_pool_options(1, 64);
	second_options.domain_index = 7;
	auto first_or = fixed_packet_pool::create(first_options);
	auto second_or = fixed_packet_pool::create(second_options);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first = std::move(first_or).value();
	auto second = std::move(second_or).value();
	prefix_datagram_state submitted;
	auto port_or =
		udp_tx_port::create(std::array{&first->operations(), &second->operations()}, 8, 3,
				    udp_transmit_api{.state = &submitted, .transmit_messages = accept_datagram_prefix});
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	ASSERT_TRUE(port->connect(exact_endpoint(reserve_loopback_endpoint())).is_ok());
	auto first_a = acquire_test_record(*first, 0xa0u);
	auto middle_b = acquire_test_record(*second, 0xb0u);
	auto last_a = acquire_test_record(*first, 0xa1u);
	ASSERT_TRUE(first_a && middle_b && last_a);
	const std::array<const void *, 3> original_addresses{first_a->storage.data, middle_b->storage.data,
							     last_a->storage.data};
	std::array<packet_record *, 3> records{first_a.get(), middle_b.get(), last_a.get()};
	const auto &operations = port->burst_operations();
	const uint16_t accepted = operations.transmit_burst(operations.state, records.data(), 3);
	if (accepted >= 1u) {
		(void)first_a.release();
	}
	if (accepted >= 2u) {
		(void)middle_b.release();
	}
	if (accepted >= 3u) {
		(void)last_a.release();
	}
	ASSERT_EQ(accepted, 3u);
	EXPECT_EQ(submitted.observed, 1u);
	EXPECT_EQ(first->outstanding(), 1u);
	EXPECT_EQ(second->outstanding(), 1u);
	operations.flush(operations.state);
	ASSERT_EQ(submitted.observed, 3u);
	EXPECT_EQ((std::array<uint8_t, 3>{submitted.values[0], submitted.values[1], submitted.values[2]}),
		  (std::array<uint8_t, 3>{0xa0u, 0xb0u, 0xa1u}));
	EXPECT_EQ((std::array<const void *, 3>{submitted.addresses[0], submitted.addresses[1], submitted.addresses[2]}),
		  original_addresses);
	EXPECT_EQ(first->outstanding(), 0u);
	EXPECT_EQ(second->outstanding(), 0u);
}

/** @brief Mixed-domain deferred shutdown releases every accepted buffer without a send. */
TEST(udp_io, mixed_storage_deferred_shutdown_reclaims_each_original_pool)
{
	auto first_or = fixed_packet_pool::create(udp_test_pool_options(2, 64));
	auto second_options = udp_test_pool_options(1, 64);
	second_options.domain_index = 7;
	auto second_or = fixed_packet_pool::create(second_options);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first = std::move(first_or).value();
	auto second = std::move(second_or).value();
	blocked_datagram_state blocked;
	auto port_or =
		udp_tx_port::create(std::array{&first->operations(), &second->operations()}, 8, 3,
				    udp_transmit_api{.state = &blocked, .transmit_messages = transmit_no_messages});
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	ASSERT_TRUE(port->connect(exact_endpoint(reserve_loopback_endpoint())).is_ok());
	auto first_a = acquire_test_record(*first, 0xa0u);
	auto middle_b = acquire_test_record(*second, 0xb0u);
	auto last_a = acquire_test_record(*first, 0xa1u);
	ASSERT_TRUE(first_a && middle_b && last_a);
	std::array<packet_record *, 3> records{first_a.get(), middle_b.get(), last_a.get()};
	const auto &operations = port->burst_operations();
	const uint16_t accepted = operations.transmit_burst(operations.state, records.data(), 3);
	if (accepted >= 1u) {
		(void)first_a.release();
	}
	if (accepted >= 2u) {
		(void)middle_b.release();
	}
	if (accepted >= 3u) {
		(void)last_a.release();
	}
	ASSERT_EQ(accepted, 3u);
	EXPECT_EQ(first->outstanding(), 2u);
	EXPECT_EQ(second->outstanding(), 1u);
	port->shutdown();
	EXPECT_EQ(first->outstanding(), 0u);
	EXPECT_EQ(second->outstanding(), 0u);
	EXPECT_EQ(operations.maybe_flush(operations.state), 0u);
}

/** @brief An unadmitted domain ends the accepted prefix and leaves the suffix caller-owned. */
TEST(udp_io, unadmitted_storage_preserves_the_complete_unaccepted_suffix)
{
	auto first_or = fixed_packet_pool::create(udp_test_pool_options(2, 64));
	auto second_options = udp_test_pool_options(1, 64);
	second_options.domain_index = 7;
	auto second_or = fixed_packet_pool::create(second_options);
	ASSERT_TRUE(first_or.is_ok()) << first_or.error().message();
	ASSERT_TRUE(second_or.is_ok()) << second_or.error().message();
	auto first = std::move(first_or).value();
	auto second = std::move(second_or).value();
	blocked_datagram_state blocked;
	auto port_or =
		udp_tx_port::create(std::array{&first->operations()}, 8, 3,
				    udp_transmit_api{.state = &blocked, .transmit_messages = transmit_no_messages});
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	ASSERT_TRUE(port->connect(exact_endpoint(reserve_loopback_endpoint())).is_ok());
	auto first_a = acquire_test_record(*first, 0xa0u);
	auto middle_b = acquire_test_record(*second, 0xb0u);
	auto last_a = acquire_test_record(*first, 0xa1u);
	ASSERT_TRUE(first_a && middle_b && last_a);
	std::array<packet_record *, 3> records{first_a.get(), middle_b.get(), last_a.get()};
	const auto &operations = port->burst_operations();
	const uint16_t accepted = operations.transmit_burst(operations.state, records.data(), 3);
	if (accepted >= 1u) {
		(void)first_a.release();
	}
	if (accepted >= 2u) {
		(void)middle_b.release();
	}
	if (accepted >= 3u) {
		(void)last_a.release();
	}
	ASSERT_EQ(accepted, 1u);
	ASSERT_TRUE(middle_b && last_a);
	EXPECT_EQ(middle_b->storage.data[0], 0xb0u);
	EXPECT_EQ(last_a->storage.data[0], 0xa1u);
	port->shutdown();
	EXPECT_EQ(first->outstanding(), 1u);
	EXPECT_EQ(second->outstanding(), 1u);
	middle_b.reset();
	last_a.reset();
	EXPECT_EQ(first->outstanding(), 0u);
	EXPECT_EQ(second->outstanding(), 0u);
}

/** @brief Unsent deferred shutdown preserves one acceptance without inventing a rejected transfer. */
TEST(udp_io, deferred_shutdown_keeps_acceptance_without_delivery_evidence)
{
	auto pool_or = fixed_packet_pool::create(udp_test_pool_options(1, 64));
	ASSERT_TRUE(pool_or.is_ok()) << pool_or.error().message();
	auto pool = std::move(pool_or).value();
	blocked_datagram_state blocked;
	const udp_transmit_api api{.state = &blocked, .transmit_messages = transmit_no_messages};
	auto port_or = udp_tx_port::create(std::array{&pool->operations()}, 8, 1, api);
	ASSERT_TRUE(port_or.is_ok()) << port_or.error().message();
	auto port = std::move(port_or).value();
	const sockaddr_in address = reserve_loopback_endpoint();
	ASSERT_NE(address.sin_port, 0);
	ASSERT_TRUE(port->connect(exact_endpoint(address)).is_ok());
	constexpr std::array<uint32_t, 1> STREAMS{0u};
	auto telemetry_or = test::worker_telemetry_test_owner::create(0u, 1u, STREAMS);
	ASSERT_TRUE(telemetry_or.is_ok()) << telemetry_or.error().message();
	auto telemetry = std::move(telemetry_or).value();
	telemetry->telemetry->bind_bootstrap_epoch(1u, 1u);
	packet_record *records[1]{};
	ASSERT_EQ(pool->acquire_burst(records, 1), 1u);
	records[0]->storage.data[0] = 0x5au;
	records[0]->storage.length = 1u;
	records[0]->storage.contiguous_length = 1u;
	const auto &operations = port->burst_operations();
	const uint16_t accepted = operations.transmit_burst(operations.state, records, 1);
	EXPECT_EQ(accepted, 1u);
	if (accepted == 0u) {
		pool->operations().release_burst(pool->operations().state, records, 1);
		return;
	}
	const uint32_t stream = telemetry->telemetry->stream_ordinal(STREAMS[0]);
	telemetry->telemetry->record_stream(stream, accepted, 1u, 0u);
	operations.flush(operations.state);
	EXPECT_EQ(blocked.transmit_calls, 2u);
	EXPECT_EQ(pool->outstanding(), 1u);
	port->shutdown();
	EXPECT_EQ(pool->outstanding(), 0u);
	ASSERT_EQ(telemetry->telemetry->service_turn(1u).return_need, runtime_telemetry_return_need::EXPECTED);
	runtime_telemetry_bank_token token{};
	ASSERT_TRUE(telemetry->channel->take_completed(token));
	const auto bank_or = telemetry->telemetry->completed_bank(token);
	ASSERT_TRUE(bank_or.is_ok()) << bank_or.error().message();
	const auto counters = bank_or->streams[stream];
	telemetry->telemetry->complete_aggregation(token);
	ASSERT_TRUE(telemetry->channel->take_returned(token));
	telemetry->telemetry->accept_returned(token);
	EXPECT_EQ(counters.packets, 1u);
	EXPECT_EQ(counters.bytes, 1u);
	EXPECT_EQ(counters.rejected_packets, 0u);
}

/** @brief Retryable UDP native errors preserve every RX and deferred-TX credit. */
TEST(udp_io, retryable_native_errors_are_bounded_no_progress)
{
	auto rx_pool_or = fixed_packet_pool::create(udp_test_pool_options(1, 64));
	ASSERT_TRUE(rx_pool_or.is_ok()) << rx_pool_or.error().message();
	auto rx_pool = std::move(rx_pool_or).value();
	datagram_error_state receive_error{.error = EAGAIN};
	auto rx_port_or = udp_rx_port::create(rx_pool->operations(), 7, 1,
					      udp_receive_api{.state = &receive_error,
							      .receive_messages = return_datagram_error});
	ASSERT_TRUE(rx_port_or.is_ok()) << rx_port_or.error().message();
	auto rx_port = std::move(rx_port_or).value();
	auto rx_address_or = reserve_rx_endpoint(*rx_port);
	ASSERT_TRUE(rx_address_or.is_ok()) << rx_address_or.error().message();
	ASSERT_TRUE(rx_port->activate().is_ok());
	packet_record *received[1]{};
	const auto &rx_operations = rx_port->burst_operations();
	const auto unavailable = rx_operations.receive_burst(rx_operations.state, received, 1);
	EXPECT_EQ(unavailable.transferred_count, 0u);
	EXPECT_EQ(unavailable.rejected_count, 0u);
	receive_error.error = EINTR;
	const auto interrupted = rx_operations.receive_burst(rx_operations.state, received, 1);
	EXPECT_EQ(interrupted.transferred_count, 0u);
	EXPECT_EQ(interrupted.rejected_count, 0u);
	EXPECT_EQ(receive_error.calls, 2u);
	EXPECT_EQ(rx_pool->outstanding(), 1u);
	ASSERT_TRUE(rx_port->deactivate().is_ok());
	rx_port.reset();
	EXPECT_EQ(rx_pool->outstanding(), 0u);

	const sockaddr_in tx_address = reserve_loopback_endpoint();
	ASSERT_NE(tx_address.sin_port, 0);
	auto tx_pool_or = fixed_packet_pool::create(udp_test_pool_options(1, 64));
	ASSERT_TRUE(tx_pool_or.is_ok()) << tx_pool_or.error().message();
	auto tx_pool = std::move(tx_pool_or).value();
	datagram_error_state transmit_error{.error = EAGAIN};
	auto tx_port_or = udp_tx_port::create(std::array{&tx_pool->operations()}, 8, 1,
					      udp_transmit_api{.state = &transmit_error,
							       .transmit_messages = return_datagram_error});
	ASSERT_TRUE(tx_port_or.is_ok()) << tx_port_or.error().message();
	auto tx_port = std::move(tx_port_or).value();
	ASSERT_TRUE(tx_port->connect(exact_endpoint(tx_address)).is_ok());
	packet_record *transmitted[1]{};
	ASSERT_EQ(tx_pool->acquire_burst(transmitted, 1), 1u);
	transmitted[0]->storage.data[0] = 0x5au;
	transmitted[0]->storage.length = 1u;
	transmitted[0]->storage.contiguous_length = 1u;
	const auto &tx_operations = tx_port->burst_operations();
	EXPECT_EQ(tx_operations.transmit_burst(tx_operations.state, transmitted, 1), 1u);
	for (const int error : {EINTR, ENOBUFS, ENOMEM}) {
		transmit_error.error = error;
		tx_operations.flush(tx_operations.state);
	}
	EXPECT_EQ(transmit_error.calls, 4u);
	EXPECT_EQ(tx_pool->outstanding(), 1u);
	tx_port->shutdown();
	EXPECT_EQ(tx_pool->outstanding(), 0u);
}

/** @brief Unexpected UDP native errors fail stop instead of becoming silent stalls. */
TEST(udp_io, unexpected_native_errors_fail_stop)
{
	EXPECT_DEATH(
		{
			auto pool_or = fixed_packet_pool::create(udp_test_pool_options(1, 64));
			if (!pool_or.is_ok()) {
				std::_Exit(EXIT_SUCCESS);
			}
			auto pool = std::move(pool_or).value();
			datagram_error_state native_error{.error = EBADF};
			auto port_or = udp_rx_port::create(pool->operations(), 7, 1,
							   udp_receive_api{.state = &native_error,
									   .receive_messages = return_datagram_error});
			if (!port_or.is_ok()) {
				std::_Exit(EXIT_SUCCESS);
			}
			auto port = std::move(port_or).value();
			auto address_or = reserve_rx_endpoint(*port);
			if (!address_or.is_ok() || !port->activate().is_ok()) {
				std::_Exit(EXIT_SUCCESS);
			}
			packet_record *records[1]{};
			const auto &operations = port->burst_operations();
			(void)operations.receive_burst(operations.state, records, 1);
			std::_Exit(EXIT_SUCCESS);
		},
		"");

	EXPECT_DEATH(
		{
			const sockaddr_in address = reserve_loopback_endpoint();
			if (address.sin_port == 0) {
				std::_Exit(EXIT_SUCCESS);
			}
			auto pool_or = fixed_packet_pool::create(udp_test_pool_options(1, 64));
			if (!pool_or.is_ok()) {
				std::_Exit(EXIT_SUCCESS);
			}
			auto pool = std::move(pool_or).value();
			datagram_error_state native_error{.error = EBADF};
			auto port_or = udp_tx_port::create(
				std::array{&pool->operations()}, 8, 1,
				udp_transmit_api{.state = &native_error, .transmit_messages = return_datagram_error});
			if (!port_or.is_ok()) {
				std::_Exit(EXIT_SUCCESS);
			}
			auto port = std::move(port_or).value();
			if (!port->connect(exact_endpoint(address)).is_ok()) {
				std::_Exit(EXIT_SUCCESS);
			}
			packet_record *records[1]{};
			if (pool->acquire_burst(records, 1) != 1u) {
				std::_Exit(EXIT_SUCCESS);
			}
			records[0]->storage.data[0] = 0x5au;
			records[0]->storage.length = 1u;
			records[0]->storage.contiguous_length = 1u;
			const auto &operations = port->burst_operations();
			(void)operations.transmit_burst(operations.state, records, 1);
			std::_Exit(EXIT_SUCCESS);
		},
		"");
}

/** @brief Prove malformed nonempty UDP TX fails stop before ownership can become ambiguous. */
TEST(udp_io, tx_rejects_malformed_nonempty_burst)
{
	EXPECT_DEATH(
		{
			auto pool_or = fixed_packet_pool::create(udp_test_pool_options(1, 64));
			if (!pool_or.is_ok()) {
				std::terminate();
			}
			auto pool = std::move(pool_or).value();
			auto port_or = udp_tx_port::create(std::array{&pool->operations()}, 8, 1);
			if (!port_or.is_ok()) {
				std::terminate();
			}
			auto port = std::move(port_or).value();
			const auto &operations = port->burst_operations();
			(void)operations.transmit_burst(operations.state, nullptr, 1);
		},
		"");
}

}  // namespace kinetum::dp
