// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file kinetum_tap_sender.cpp
 * @brief Native TAP packet sender for Kinetum physical-I/O validation.
 * @author Fleming Patel
 *
 * This AF_PACKET sender replaces the Python packet-generation path. It builds
 * raw Ethernet frames once at startup and patches only mutable fields
 * (sequence, tag, timestamp, and checksums) per packet.
 *
 * Controlled by the Python orchestrator as a subprocess:
 * - Configuration via CLI arguments
 * - One pre-authored generation-tag transition requested through SIGUSR1
 * - Stats output as JSON to stdout on exit
 * - Clean shutdown via SIGTERM
 *
 * Supports three traffic modes:
 * - standard: duration-based, fixed tag
 * - generation-tagged: duration-based, one initial-to-next 16-bit tag transition
 * - timed:             duration-based, fixed zero tag
 */

#include <arpa/inet.h>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "src/common/process_output.hpp"

// =============================================================================
// Constants (must match Python CONSTANTS in config/types.py)
// =============================================================================

static constexpr uint8_t MAGIC[] = {'K', 'I', 'N', 'E', 'T', 'U', 'M'};	 ///< Exact payload magic.
static constexpr size_t MAGIC_LEN = 7;					 ///< Bytes in `MAGIC`.
static constexpr size_t HEADER_SIZE = 21;  ///< Magic, sequence, tag, and binary64 timestamp bytes.

static constexpr size_t ETH_HDR_LEN = 14;  ///< Exact Ethernet-II header bytes.
static constexpr size_t IP_HDR_LEN = 20;   ///< Exact option-free IPv4 header bytes.
static constexpr size_t UDP_HDR_LEN = 8;   ///< Exact UDP header bytes.
static constexpr size_t MIN_PKT_SIZE = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + HEADER_SIZE;  ///< Wire floor.
static constexpr uint32_t MIN_CLI_PACKET_SIZE = 64;	    ///< Minimum authored Ethernet frame bytes.
static constexpr uint32_t MAX_CLI_PACKET_SIZE = 9000;	    ///< Maximum authored Ethernet frame bytes.
static constexpr uint32_t MAX_RATE_LIMIT_PPS = 1000000000;  ///< Maximum authored packet rate.
static constexpr size_t MAX_TAP_INTERFACES = 64;	    ///< Maximum unique ingress interfaces.
static constexpr uint32_t MAX_GENERATION_TAG = std::numeric_limits<uint16_t>::max();  ///< Tag ceiling.

static_assert(MIN_CLI_PACKET_SIZE >= MIN_PKT_SIZE, "minimum CLI frame must contain the complete validation payload");

// Default addresses (locally administered MACs)
static constexpr uint8_t SRC_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};  ///< Test source MAC.
static constexpr uint8_t DST_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};  ///< Test destination MAC.

// =============================================================================
// Globals
// =============================================================================

static volatile std::sig_atomic_t g_running = 1;  ///< Nonzero while the sender loop should continue.

/** One-way generation-tag transition request published by SIGUSR1. */
static volatile std::sig_atomic_t g_generation_advance_requested = 0;

/**
 * @brief Signal handler that requests a clean sender-loop stop.
 *
 * @param signum Signal number; ignored because all handled signals request the
 * same clean stop.
 */
static void termination_signal_handler(int signum)
{
	(void)signum;
	g_running = 0;
}

/**
 * @brief Publish the one pre-authored generation-tag transition.
 *
 * @param signum SIGUSR1; ignored because the next tag is immutable CLI input.
 */
static void generation_advance_signal_handler(int signum)
{
	(void)signum;
	g_generation_advance_requested = 1;
}

/**
 * @brief Install the complete sender signal policy before packet resources.
 *
 * Generation-tag mode requires SIGUSR1 to be blocked by the spawning owner.
 * The child installs its handler before unblocking that inherited signal, so a
 * request that arrives during startup remains pending rather than taking the
 * default action.
 *
 * @param generation_tagged True when the one-way tag transition is enabled.
 * @return True when every required handler and mask transition succeeds.
 */
static bool install_signal_policy(bool generation_tagged)
{
	if (generation_tagged) {
		sigset_t inherited_mask{};
		if (::sigprocmask(SIG_SETMASK, nullptr, &inherited_mask) != 0) {
			fprintf(stderr, "kinetum_tap_sender: failed to inspect inherited signal mask: %s\n",
				strerror(errno));
			return false;
		}
		if (::sigismember(&inherited_mask, SIGUSR1) != 1) {
			fprintf(stderr,
				"kinetum_tap_sender: generation-tag mode requires inherited SIGUSR1 blocking\n");
			return false;
		}
	}

	struct sigaction termination_action{};
	termination_action.sa_handler = termination_signal_handler;
	if (::sigemptyset(&termination_action.sa_mask) != 0 ||
	    ::sigaction(SIGTERM, &termination_action, nullptr) != 0 ||
	    ::sigaction(SIGINT, &termination_action, nullptr) != 0) {
		fprintf(stderr, "kinetum_tap_sender: failed to install termination signal policy: %s\n",
			strerror(errno));
		return false;
	}

	if (!generation_tagged) {
		return true;
	}

	struct sigaction generation_action{};
	generation_action.sa_handler = generation_advance_signal_handler;
	if (::sigemptyset(&generation_action.sa_mask) != 0 || ::sigaction(SIGUSR1, &generation_action, nullptr) != 0) {
		fprintf(stderr, "kinetum_tap_sender: failed to install generation signal policy: %s\n",
			strerror(errno));
		return false;
	}

	sigset_t generation_set{};
	if (::sigemptyset(&generation_set) != 0 || ::sigaddset(&generation_set, SIGUSR1) != 0) {
		fprintf(stderr, "kinetum_tap_sender: failed to construct generation signal set: %s\n", strerror(errno));
		return false;
	}
	if (::sigprocmask(SIG_UNBLOCK, &generation_set, nullptr) != 0) {
		fprintf(stderr, "kinetum_tap_sender: failed to unblock generation signal: %s\n", strerror(errno));
		return false;
	}
	return true;
}

// =============================================================================
// Packet Builder
// =============================================================================

/**
 * @brief Prebuilt Ethernet/IPv4/UDP packet with mutable-field offsets.
 */
struct packet_template {
	std::vector<uint8_t> data;  ///< Complete packet bytes patched and sent for each sequence number.

	// Offsets for mutable fields
	size_t seq_offset{0};	    ///< Payload: sequence number (4 bytes, network order)
	size_t tag_offset{0};	    ///< Payload: generation tag (2 bytes, network order)
	size_t ts_offset{0};	    ///< Payload: TX timestamp (8 bytes, double)
	size_t ip_id_offset{0};	    ///< IP header: identification field
	size_t ip_cksum_offset{0};  ///< IP header: checksum field
	size_t ip_hdr_start{0};	    ///< IP header: start offset
};

/** @brief Typed immutable inputs for one packet-template construction. */
struct packet_template_spec {
	uint32_t src_ip{0};    ///< Source IPv4 address in host byte order.
	uint32_t dst_ip{0};    ///< Destination IPv4 address in host byte order.
	uint16_t sport{0};     ///< UDP source port in host byte order.
	uint16_t dport{0};     ///< UDP destination port in host byte order.
	size_t total_size{0};  ///< Exact Ethernet frame size in bytes.
};

/**
 * @brief Compute the IPv4 header checksum for an in-memory header.
 *
 * @param hdr Pointer to the first byte of the IPv4 header.
 * @param len Header length in bytes.
 * @return Ones-complement IPv4 checksum in host byte order.
 */
static uint16_t compute_ip_checksum(const uint8_t *hdr, size_t len)
{
	uint32_t sum = 0;
	for (size_t i = 0; i + 1 < len; i += 2) {
		sum += static_cast<uint32_t>((static_cast<uint16_t>(hdr[i]) << 8) | hdr[i + 1]);
	}
	if (len & 1) {
		sum += static_cast<uint32_t>(hdr[len - 1]) << 8;
	}
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return static_cast<uint16_t>(~sum);
}

/**
 * @brief Return wall-clock seconds for sender/analyzer latency correlation.
 *
 * @return System-clock seconds since Unix epoch.
 */
static double now_seconds()
{
	auto now = std::chrono::system_clock::now();
	auto dur = now.time_since_epoch();
	return std::chrono::duration<double>(dur).count();
}

/**
 * @brief Build the immutable packet body and record offsets patched per send.
 *
 * @param spec Typed source/destination and exact frame-size inputs.
 * @return Packet template with immutable bytes initialized and mutable offsets recorded.
 */
static packet_template build_template(const packet_template_spec &spec)
{
	packet_template t;
	t.data.resize(spec.total_size, 0x58);  // 'X' padding

	uint8_t *p = t.data.data();

	// Ethernet header (14 bytes)
	memcpy(p + 0, DST_MAC, 6);
	memcpy(p + 6, SRC_MAC, 6);
	p[12] = 0x08;
	p[13] = 0x00;  // EtherType: IPv4

	// IPv4 header (20 bytes)
	t.ip_hdr_start = ETH_HDR_LEN;
	uint8_t *ip = p + t.ip_hdr_start;
	ip[0] = 0x45;  // Version=4, IHL=5
	ip[1] = 0x00;  // DSCP=0, ECN=0
	uint16_t ip_total_len = static_cast<uint16_t>(spec.total_size - ETH_HDR_LEN);
	ip[2] = static_cast<uint8_t>(ip_total_len >> 8);
	ip[3] = static_cast<uint8_t>(ip_total_len & 0xFF);
	// ip[4-5] = IP ID (patched per packet)
	t.ip_id_offset = t.ip_hdr_start + 4;
	ip[6] = 0x00;
	ip[7] = 0x00;  // Flags=0, Fragment=0
	ip[8] = 64;    // TTL
	ip[9] = 17;    // Protocol: UDP
	// ip[10-11] = checksum (computed after all fields set)
	t.ip_cksum_offset = t.ip_hdr_start + 10;
	ip[12] = static_cast<uint8_t>((spec.src_ip >> 24) & 0xFF);
	ip[13] = static_cast<uint8_t>((spec.src_ip >> 16) & 0xFF);
	ip[14] = static_cast<uint8_t>((spec.src_ip >> 8) & 0xFF);
	ip[15] = static_cast<uint8_t>(spec.src_ip & 0xFF);
	ip[16] = static_cast<uint8_t>((spec.dst_ip >> 24) & 0xFF);
	ip[17] = static_cast<uint8_t>((spec.dst_ip >> 16) & 0xFF);
	ip[18] = static_cast<uint8_t>((spec.dst_ip >> 8) & 0xFF);
	ip[19] = static_cast<uint8_t>(spec.dst_ip & 0xFF);

	// UDP header (8 bytes)
	uint8_t *udp = p + ETH_HDR_LEN + IP_HDR_LEN;
	udp[0] = static_cast<uint8_t>(spec.sport >> 8);
	udp[1] = static_cast<uint8_t>(spec.sport & 0xFF);
	udp[2] = static_cast<uint8_t>(spec.dport >> 8);
	udp[3] = static_cast<uint8_t>(spec.dport & 0xFF);
	uint16_t udp_len = static_cast<uint16_t>(spec.total_size - ETH_HDR_LEN - IP_HDR_LEN);
	udp[4] = static_cast<uint8_t>(udp_len >> 8);
	udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
	udp[6] = 0x00;
	udp[7] = 0x00;	// UDP checksum = 0 (optional for IPv4)

	// Payload: MAGIC + SEQ(4) + TAG(2) + TIMESTAMP(8) + padding.
	size_t payload_start = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
	memcpy(p + payload_start, MAGIC, MAGIC_LEN);
	t.seq_offset = payload_start + MAGIC_LEN;
	t.tag_offset = t.seq_offset + 4;
	t.ts_offset = t.tag_offset + 2;

	// Compute initial IP checksum
	ip[10] = 0;
	ip[11] = 0;
	uint16_t cksum = compute_ip_checksum(ip, IP_HDR_LEN);
	ip[10] = static_cast<uint8_t>(cksum >> 8);
	ip[11] = static_cast<uint8_t>(cksum & 0xFF);

	return t;
}

// =============================================================================
// Socket
// =============================================================================

/**
 * @brief Open and bind one AF_PACKET socket to a TAP interface.
 *
 * @param iface Interface name to bind.
 * @return Bound socket fd on success, -1 on failure.
 */
static int open_tap_socket(const char *iface)
{
	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		fprintf(stderr, "socket(AF_PACKET) failed: %s\n", strerror(errno));
		return -1;
	}

	unsigned int ifindex = if_nametoindex(iface);
	if (ifindex == 0) {
		fprintf(stderr, "if_nametoindex(%s) failed: %s\n", iface, strerror(errno));
		close(fd);
		return -1;
	}

	struct sockaddr_ll addr = {};
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = static_cast<int>(ifindex);

	if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
		fprintf(stderr, "bind(%s) failed: %s\n", iface, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

// =============================================================================
// Stats
// =============================================================================

/**
 * @brief Aggregate sender output serialized to stdout as JSON.
 */
struct sender_stats {
	uint64_t tx_count{0};					///< Successfully sent packet count.
	uint64_t error_count{0};				///< Failed send attempts and fatal sender errors.
	double start_time{0};					///< Wall-clock start time in seconds.
	double end_time{0};					///< Wall-clock end time in seconds.
	bool fatal_error{false};				///< True when the sender must exit nonzero.
	static constexpr size_t MAX_GENERATION_TAGS = 16;	///< Maximum distinct tags tracked in JSON.
	uint32_t generation_tags[MAX_GENERATION_TAGS]{};	///< Tags in insertion order.
	uint64_t generation_tag_counts[MAX_GENERATION_TAGS]{};	///< Packet counts by tag.
	size_t generation_tag_slots_used{0};			///< Number of occupied tag-count slots.

	/**
	 * @brief Increment the count for one generation tag.
	 *
	 * @param generation_tag Tag to account in the bounded JSON side table.
	 * @return True after exact accounting; false when the distinct-tag table is full.
	 */
	bool record_generation_tag(uint32_t generation_tag)
	{
		for (size_t i = 0; i < generation_tag_slots_used; ++i) {
			if (generation_tags[i] == generation_tag) {
				generation_tag_counts[i]++;
				return true;
			}
		}
		if (generation_tag_slots_used == MAX_GENERATION_TAGS) {
			return false;
		}
		generation_tags[generation_tag_slots_used] = generation_tag;
		generation_tag_counts[generation_tag_slots_used] = 1;
		generation_tag_slots_used++;
		return true;
	}

	/**
	 * @brief Render sender statistics using the JSON schema consumed by Python.
	 *
	 * @return Complete locale-independent JSON bytes.
	 */
	[[nodiscard]] std::string render_json() const
	{
		const double duration = end_time - start_time;
		const double actual_pps = duration > 0 ? static_cast<double>(tx_count) / duration : 0;
		std::ostringstream output;
		output.exceptions(std::ios::badbit | std::ios::failbit);
		output.imbue(std::locale::classic());
		output << "{\"tx_count\":" << tx_count << ",\"error_count\":" << error_count
		       << ",\"start_time\":" << std::fixed << std::setprecision(6) << start_time
		       << ",\"end_time\":" << end_time << ",\"duration_s\":" << std::setprecision(3) << duration
		       << ",\"actual_pps\":" << std::setprecision(1) << actual_pps << ",\"generation_tag_counts\":{";

		for (size_t i = 0; i < generation_tag_slots_used; ++i) {
			if (i > 0) {
				output << ',';
			}
			output << '"' << generation_tags[i] << "\":" << generation_tag_counts[i];
		}
		output << "}}\n";
		return output.str();
	}
};

// =============================================================================
// Rate Limiter (monotonic clock token bucket)
// =============================================================================

/**
 * @brief Busy-poll token bucket for deterministic TAP traffic generation.
 */
struct rate_limiter {
	uint64_t interval_ns{0};   ///< Positive nanoseconds between packets.
	uint64_t next_send_ns{0};  ///< Next monotonic timestamp at which send may proceed.

	/**
	 * @brief Build a limiter for the requested packet rate.
	 *
	 * @param pps Positive target packets per second.
	 */
	explicit rate_limiter(uint32_t pps)
		: interval_ns(1000000000ULL / pps)
	{
	}

	/**
	 * @brief Busy-wait until the next send time without crossing the run deadline.
	 * @param deadline_ns Absolute steady-clock run deadline in nanoseconds.
	 * @return True when one packet may be sent before the deadline.
	 */
	bool wait_until(uint64_t deadline_ns)
	{
		if (next_send_ns != 0 && next_send_ns >= deadline_ns)
			return false;
		uint64_t now;
		do {
			auto tp = std::chrono::steady_clock::now();
			now = static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch()).count());
			if (now >= deadline_ns)
				return false;
		} while (now < next_send_ns);
		next_send_ns = now + interval_ns;
		return true;
	}
};

// =============================================================================
// Send Loop
// =============================================================================

/** @brief Typed immutable controls for one bounded sender loop. */
struct send_loop_spec {
	uint32_t pps{0};		     ///< Positive target packet rate.
	double duration_s{0.0};		     ///< Positive bounded run duration.
	const char *mode{nullptr};	     ///< Exact admitted traffic mode.
	uint32_t initial_generation_tag{0};  ///< Initial packet-profile tag.
	uint32_t next_generation_tag{0};     ///< Immutable post-signal packet-profile tag.
};

/**
 * @brief Generate packets until duration expiry or signal-triggered shutdown.
 *
 * @param sockets Bound AF_PACKET sockets used in round-robin order.
 * @param tmpl Packet template patched in place before each send.
 * @param spec Typed duration, rate, mode, and generation-tag controls.
 * @return Sender statistics and fatal-error flag.
 */
static sender_stats run_send_loop(const std::vector<int> &sockets, packet_template &tmpl, const send_loop_spec &spec)
{
	sender_stats stats;
	rate_limiter limiter(spec.pps);

	const bool generation_tagged = strcmp(spec.mode, "generation-tagged") == 0;
	uint32_t current_tag = generation_tagged ? spec.initial_generation_tag : 0;
	uint64_t sequence = 0;
	size_t num_ports = sockets.size();
	size_t port_idx = 0;

	stats.start_time = now_seconds();
	const auto end_time = std::chrono::steady_clock::now() + std::chrono::duration<double>(spec.duration_s);
	const uint64_t end_time_ns = static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::nanoseconds>(end_time.time_since_epoch()).count());

	uint8_t *pkt = tmpl.data.data();
	size_t pkt_len = tmpl.data.size();

	while (g_running != 0 && limiter.wait_until(end_time_ns)) {
		if (sequence > std::numeric_limits<uint32_t>::max()) {
			fprintf(stderr, "kinetum_tap_sender: packet sequence domain exhausted\n");
			stats.error_count++;
			stats.fatal_error = true;
			break;
		}
		const auto seq = static_cast<uint32_t>(sequence);

		// Observe at most one pre-authored transition before this record.
		if (generation_tagged && g_generation_advance_requested != 0) {
			current_tag = spec.next_generation_tag;
		}

		// Patch mutable fields
		// Sequence number (network byte order)
		pkt[tmpl.seq_offset + 0] = static_cast<uint8_t>((seq >> 24) & 0xFF);
		pkt[tmpl.seq_offset + 1] = static_cast<uint8_t>((seq >> 16) & 0xFF);
		pkt[tmpl.seq_offset + 2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
		pkt[tmpl.seq_offset + 3] = static_cast<uint8_t>(seq & 0xFF);

		// Tag (network byte order)
		pkt[tmpl.tag_offset + 0] = static_cast<uint8_t>((current_tag >> 8) & 0xFF);
		pkt[tmpl.tag_offset + 1] = static_cast<uint8_t>(current_tag & 0xFF);

		// TX timestamp (double, network byte order)
		double ts = now_seconds();
		uint64_t ts_bits;
		memcpy(&ts_bits, &ts, 8);
		// Convert to big-endian
		for (size_t b = 0; b < 8; ++b)
			pkt[tmpl.ts_offset + b] = static_cast<uint8_t>((ts_bits >> (56 - b * 8)) & 0xFF);

		// IP ID (network byte order, low 16 bits of seq)
		pkt[tmpl.ip_id_offset + 0] = static_cast<uint8_t>((seq >> 8) & 0xFF);
		pkt[tmpl.ip_id_offset + 1] = static_cast<uint8_t>(seq & 0xFF);

		// Recompute IP checksum (only IP ID changed from template)
		uint8_t *ip = pkt + tmpl.ip_hdr_start;
		ip[10] = 0;
		ip[11] = 0;
		uint16_t cksum = compute_ip_checksum(ip, IP_HDR_LEN);
		ip[10] = static_cast<uint8_t>(cksum >> 8);
		ip[11] = static_cast<uint8_t>(cksum & 0xFF);

		// Send (round-robin across ports)
		int fd = sockets[port_idx];
		ssize_t sent = send(fd, pkt, pkt_len, 0);
		if (sent == static_cast<ssize_t>(pkt_len)) {
			stats.tx_count++;
			if (!stats.record_generation_tag(current_tag)) {
				fprintf(stderr, "kinetum_tap_sender: distinct generation-tag bound exhausted\n");
				stats.error_count++;
				stats.fatal_error = true;
				break;
			}
			sequence++;
		} else {
			stats.error_count++;
			if (sent >= 0) {
				fprintf(stderr, "kinetum_tap_sender: packet socket returned a partial frame\n");
				stats.fatal_error = true;
				break;
			}
		}

		++port_idx;
		if (port_idx == num_ports) {
			port_idx = 0;
		}
	}

	stats.end_time = now_seconds();
	return stats;
}

// =============================================================================
// Argument Parsing
// =============================================================================

/**
 * @brief Parsed native sender configuration.
 */
struct config {
	std::string mode{"standard"};	     ///< Traffic mode: standard, generation-tagged, or timed.
	std::vector<std::string> ports;	     ///< TAP interfaces to send on in round-robin order.
	uint32_t pps{1000};		     ///< Positive target packets per second.
	double duration_s{15.0};	     ///< Positive run duration in seconds.
	uint32_t initial_generation_tag{0};  ///< Initial uint16 profile tag.
	uint32_t next_generation_tag{0};     ///< Post-SIGUSR1 uint16 profile tag.
	uint32_t packet_size{64};	     ///< Ethernet frame size in bytes.
	uint32_t src_ip{0x0A000064};	     ///< Source IPv4 address, host order (10.0.0.100).
	uint32_t dst_ip{0xC0A80101};	     ///< Destination IPv4 address, host order (192.168.1.1).
	uint16_t sport{10000};		     ///< UDP source port.
	uint16_t dport{9999};		     ///< UDP destination port.
	bool show_help{false};		     ///< True when help should be printed and no run executed.
};

/** Complete native sender usage text. */
constexpr std::string_view USAGE = "Usage: kinetum_tap_sender [OPTIONS]\n"
				   "\n"
				   "Options:\n"
				   "  --mode <standard|generation-tagged|timed>  Traffic mode (default: standard)\n"
				   "  --ports <if0[,if1...]>         TAP interfaces, round-robin send order\n"
				   "  --pps <1..1000000000>          Target packets per second\n"
				   "  --duration <seconds>           Positive run duration\n"
				   "  --packet-size <64..9000>       Ethernet frame size in bytes\n"
				   "  --src-ip <addr>                Source IPv4 address\n"
				   "  --dst-ip <addr>                Destination IPv4 address\n"
				   "  --sport <1..65535>             UDP source port\n"
				   "  --dport <1..65535>             UDP destination port\n"
				   "  --initial-generation-tag <0..65535>  Initial packet-profile tag\n"
				   "  --next-generation-tag <0..65535>     Post-SIGUSR1 packet-profile tag\n"
				   "  --help                         Show this help\n";

/**
 * @brief Print the native sender CLI contract.
 *
 * @param stream Output stream that receives usage text.
 */
static void print_usage(FILE *stream)
{
	(void)fwrite(USAGE.data(), 1u, USAGE.size(), stream);
}

/**
 * @brief Parse an unsigned integer argument with full-string validation.
 *
 * @param text Raw argument text.
 * @param min_value Minimum accepted value, inclusive.
 * @param max_value Maximum accepted value, inclusive.
 * @param flag Flag name used in error messages.
 * @param out Parsed value on success.
 * @param error Error text on failure.
 * @return True when parsing succeeds and consumes the entire string.
 */
static bool parse_uint32_arg(std::string_view text, uint32_t min_value, uint32_t max_value, const char *flag,
			     uint32_t &out, std::string &error)
{
	if (text.empty()) {
		error = std::string(flag) + " requires a non-empty integer";
		return false;
	}

	uint32_t value = 0;
	const char *begin = text.data();
	const char *end = text.data() + text.size();
	const auto [ptr, ec] = std::from_chars(begin, end, value);
	if (ec != std::errc{} || ptr != end || value < min_value || value > max_value) {
		error = std::string(flag) + " must be an integer in range [" + std::to_string(min_value) + ", " +
			std::to_string(max_value) + "]";
		return false;
	}

	out = value;
	return true;
}

/**
 * @brief Parse a UDP port argument.
 *
 * @param text Raw argument text.
 * @param flag Flag name used in error messages.
 * @param out Parsed UDP port on success.
 * @param error Error text on failure.
 * @return True when the argument is a decimal port in range 1..65535.
 */
static bool parse_uint16_arg(std::string_view text, const char *flag, uint16_t &out, std::string &error)
{
	uint32_t value = 0;
	if (!parse_uint32_arg(text, 1, std::numeric_limits<uint16_t>::max(), flag, value, error)) {
		return false;
	}
	out = static_cast<uint16_t>(value);
	return true;
}

/**
 * @brief Parse a positive finite floating-point duration.
 *
 * @param text Raw argument text.
 * @param out Parsed duration in seconds on success.
 * @param error Error text on failure.
 * @return True when the argument is a finite positive number with no trailing junk.
 */
static bool parse_duration_arg(std::string_view text, double &out, std::string &error)
{
	if (text.empty()) {
		error = "--duration requires a non-empty value";
		return false;
	}
	for (char ch : text) {
		if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
			error = "--duration must not contain whitespace";
			return false;
		}
	}

	double value = 0.0;
	const char *begin = text.data();
	const char *end = begin + text.size();
	const auto [parsed_end, ec] = std::from_chars(begin, end, value, std::chars_format::general);
	if (ec != std::errc{} || parsed_end != end || !std::isfinite(value) || value <= 0.0) {
		error = "--duration must be a positive finite number";
		return false;
	}

	out = value;
	return true;
}

/**
 * @brief Parse an IPv4 address in dotted-decimal form.
 *
 * @param str Raw IPv4 argument.
 * @param out Parsed IPv4 address in host byte order.
 * @return True when parsing succeeds.
 */
static bool parse_ipv4_arg(const char *str, uint32_t &out)
{
	struct in_addr addr;
	if (inet_pton(AF_INET, str, &addr) == 1) {
		out = ntohl(addr.s_addr);
		return true;
	}
	return false;
}

/**
 * @brief Parse comma-separated TAP interface names.
 *
 * @param text Raw comma-separated interface list.
 * @param ports Parsed interface names on success.
 * @param error Error text on failure.
 * @return True when the list is non-empty and contains no empty entries.
 */
static bool parse_ports(std::string_view text, std::vector<std::string> &ports, std::string &error)
{
	if (text.empty()) {
		error = "--ports requires at least one interface";
		return false;
	}

	std::vector<std::string> parsed;
	size_t start = 0;
	while (start <= text.size()) {
		size_t end = text.find(',', start);
		std::string token(
			text.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start));
		if (token.empty()) {
			error = "--ports contains an empty interface name";
			return false;
		}
		if (token.size() >= IFNAMSIZ ||
		    std::any_of(token.begin(), token.end(),
				[](char value) {
					const auto byte = static_cast<unsigned char>(value);
					return byte <= 0x20u || byte > 0x7eu || value == '/';
				}) ||
		    std::find(parsed.begin(), parsed.end(), token) != parsed.end() ||
		    parsed.size() == MAX_TAP_INTERFACES) {
			error = "--ports contains an invalid, duplicate, or excessive interface name";
			return false;
		}
		parsed.emplace_back(std::move(token));
		if (end == std::string_view::npos) {
			break;
		}
		start = end + 1;
	}

	ports = std::move(parsed);
	return true;
}

/**
 * @brief Parse CLI arguments fail-closed, preserving the Python wrapper contract.
 *
 * @param argc Argument count from main.
 * @param argv Argument vector from main.
 * @param cfg Parsed sender configuration on success.
 * @param error Error text on failure.
 * @return True when all arguments are valid.
 */
static bool parse_args(int argc, char *argv[], config &cfg, std::string &error)
{
	bool initial_generation_tag_set = false;
	bool next_generation_tag_set = false;

	auto require_value = [&](int &i, const char *flag) -> const char * {
		if (i + 1 >= argc) {
			error = std::string(flag) + " requires an argument";
			return nullptr;
		}
		return argv[++i];
	};

	for (int i = 1; i < argc; ++i) {
		const char *arg = argv[i];
		if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
			cfg.show_help = true;
			return true;
		}
		if (strcmp(arg, "--mode") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr) {
				return false;
			}
			cfg.mode = value;
		} else if (strcmp(arg, "--ports") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr) {
				return false;
			}
			if (!parse_ports(value, cfg.ports, error)) {
				return false;
			}
		} else if (strcmp(arg, "--pps") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr || !parse_uint32_arg(value, 1, MAX_RATE_LIMIT_PPS, arg, cfg.pps, error)) {
				return false;
			}
		} else if (strcmp(arg, "--duration") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr || !parse_duration_arg(value, cfg.duration_s, error)) {
				return false;
			}
		} else if (strcmp(arg, "--initial-generation-tag") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr ||
			    !parse_uint32_arg(value, 0, MAX_GENERATION_TAG, arg, cfg.initial_generation_tag, error)) {
				return false;
			}
			initial_generation_tag_set = true;
		} else if (strcmp(arg, "--next-generation-tag") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr ||
			    !parse_uint32_arg(value, 0, MAX_GENERATION_TAG, arg, cfg.next_generation_tag, error)) {
				return false;
			}
			next_generation_tag_set = true;
		} else if (strcmp(arg, "--packet-size") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr || !parse_uint32_arg(value, MIN_CLI_PACKET_SIZE, MAX_CLI_PACKET_SIZE, arg,
								  cfg.packet_size, error)) {
				return false;
			}
		} else if (strcmp(arg, "--src-ip") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr) {
				return false;
			}
			if (!parse_ipv4_arg(value, cfg.src_ip)) {
				error = "--src-ip must be a valid IPv4 address";
				return false;
			}
		} else if (strcmp(arg, "--dst-ip") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr) {
				return false;
			}
			if (!parse_ipv4_arg(value, cfg.dst_ip)) {
				error = "--dst-ip must be a valid IPv4 address";
				return false;
			}
		} else if (strcmp(arg, "--sport") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr || !parse_uint16_arg(value, arg, cfg.sport, error)) {
				return false;
			}
		} else if (strcmp(arg, "--dport") == 0) {
			const char *value = require_value(i, arg);
			if (value == nullptr || !parse_uint16_arg(value, arg, cfg.dport, error)) {
				return false;
			}
		} else {
			error = std::string("unknown argument: ") + arg;
			return false;
		}
	}

	if (cfg.mode != "standard" && cfg.mode != "generation-tagged" && cfg.mode != "timed") {
		error = "--mode must be one of: standard, generation-tagged, timed";
		return false;
	}
	if (cfg.mode == "generation-tagged" && (!initial_generation_tag_set || !next_generation_tag_set)) {
		error = "generation-tagged mode requires both generation-tag values";
		return false;
	}
	if (cfg.mode == "generation-tagged" && cfg.initial_generation_tag == cfg.next_generation_tag) {
		error = "generation-tagged mode requires distinct generation-tag values";
		return false;
	}
	if (cfg.mode != "generation-tagged" && (initial_generation_tag_set || next_generation_tag_set)) {
		error = "generation-tag flags are valid only in generation-tagged mode";
		return false;
	}
	if (cfg.ports.empty()) {
		error = "--ports is required";
		return false;
	}
	const long double requested_packets =
		static_cast<long double>(cfg.pps) * static_cast<long double>(cfg.duration_s);
	if (requested_packets < 1.0L ||
	    requested_packets > static_cast<long double>(std::numeric_limits<uint32_t>::max())) {
		error = "--pps times --duration must fit the nonempty packet sequence domain";
		return false;
	}
	return true;
}

/**
 * @brief Close all opened sender sockets.
 *
 * @param sockets Socket descriptors to close.
 * @return True when every descriptor close completed without an OS error.
 */
[[nodiscard]] static bool close_sockets(const std::vector<int> &sockets) noexcept
{
	bool clean = true;
	for (int fd : sockets) {
		clean = close(fd) == 0 && clean;
	}
	return clean;
}

/** @brief Scope-bound ownership for one complete sender socket set. */
class sender_socket_set {
    public:
	/**
	 * @brief Preallocate exact storage before the first socket is opened.
	 * @param capacity Number of configured interfaces.
	 */
	explicit sender_socket_set(std::size_t capacity)
	{
		descriptors_.reserve(capacity);
	}

	/** @brief Socket-set ownership is linear and cannot be copied. */
	sender_socket_set(const sender_socket_set &) = delete;
	/** @brief Socket-set ownership is linear and cannot be copy-assigned. */
	sender_socket_set &operator=(const sender_socket_set &) = delete;

	/** @brief Close every descriptor still owned by this set. */
	~sender_socket_set() noexcept
	{
		(void)close_all();
	}

	/**
	 * @brief Adopt one newly opened descriptor or close it before rethrow.
	 * @param descriptor Exact AF_PACKET socket descriptor.
	 */
	void adopt(int descriptor)
	{
		try {
			descriptors_.push_back(descriptor);
		} catch (...) {
			close(descriptor);
			throw;
		}
	}

	/** @return Immutable descriptors in configured round-robin order. */
	[[nodiscard]] const std::vector<int> &descriptors() const noexcept
	{
		return descriptors_;
	}

	/**
	 * @brief Close and release the complete owned descriptor set.
	 * @return True when every descriptor close completed without an OS error.
	 */
	[[nodiscard]] bool close_all() noexcept
	{
		const bool clean = close_sockets(descriptors_);
		descriptors_.clear();
		return clean;
	}

    private:
	std::vector<int> descriptors_;	///< Owned socket descriptors.
};

/**
 * @brief Render the pre-traffic sender lifecycle record.
 *
 * @param cfg Exact admitted sender configuration.
 * @param port_count Number of admitted interface identities.
 * @return Complete locale-independent stderr record.
 */
[[nodiscard]] std::string render_sender_start(const config &cfg, std::size_t port_count)
{
	std::ostringstream output;
	output.exceptions(std::ios::badbit | std::ios::failbit);
	output.imbue(std::locale::classic());
	output << "kinetum_tap_sender: mode=" << cfg.mode << " ports=" << port_count << " pps=" << cfg.pps
	       << " duration=" << std::fixed << std::setprecision(1) << cfg.duration_s << "s size=" << cfg.packet_size
	       << "\n";
	return output.str();
}

/**
 * @brief Render a below-target-rate warning when one is required.
 *
 * @param configured_pps Positive configured packet rate.
 * @param actual_pps Measured packet rate.
 * @return Empty bytes at or above threshold, otherwise one complete record.
 */
[[nodiscard]] std::string render_rate_warning(uint32_t configured_pps, double actual_pps)
{
	if (configured_pps == 0 || actual_pps >= static_cast<double>(configured_pps) * 0.8) {
		return {};
	}
	std::ostringstream output;
	output.exceptions(std::ios::badbit | std::ios::failbit);
	output.imbue(std::locale::classic());
	output << "kinetum_tap_sender: WARNING only achieved " << std::fixed << std::setprecision(1)
	       << (actual_pps / static_cast<double>(configured_pps)) * 100.0 << "% of target (" << std::setprecision(0)
	       << actual_pps << "/" << configured_pps << " PPS)\n";
	return output.str();
}

/**
 * @brief Parse and execute one native TAP sender invocation.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit code: 0 on success, 1 on runtime failure, 2 on usage error.
 */
static int run_sender(int argc, char *argv[])
{
	config cfg;
	std::string error;
	if (!parse_args(argc, argv, cfg, error)) {
		fprintf(stderr, "kinetum_tap_sender: %s\n", error.c_str());
		print_usage(stderr);
		return 2;
	}
	if (cfg.show_help) {
		return kinetum::common::emit_process_output({
			.standard_output = USAGE,
			.standard_error = {},
			.complete_exit_code = 0,
		});
	}

	// Install handlers and complete inherited-mask choreography before sockets.
	if (!install_signal_policy(cfg.mode == "generation-tagged")) {
		return 1;
	}
	const std::string start_record = render_sender_start(cfg, cfg.ports.size());
	if (kinetum::common::emit_process_output({
		    .standard_output = {},
		    .standard_error = start_record,
		    .complete_exit_code = 0,
	    }) != 0) {
		return 1;
	}

	// Open sockets
	sender_socket_set sockets(cfg.ports.size());
	for (const auto &port : cfg.ports) {
		int fd = open_tap_socket(port.c_str());
		if (fd < 0) {
			fprintf(stderr, "Failed to open socket for %s\n", port.c_str());
			return 1;
		}
		sockets.adopt(fd);
	}

	// Build packet template
	auto tmpl = build_template(packet_template_spec{
		.src_ip = cfg.src_ip,
		.dst_ip = cfg.dst_ip,
		.sport = cfg.sport,
		.dport = cfg.dport,
		.total_size = cfg.packet_size,
	});

	auto stats = run_send_loop(sockets.descriptors(), tmpl,
				   send_loop_spec{
					   .pps = cfg.pps,
					   .duration_s = cfg.duration_s,
					   .mode = cfg.mode.c_str(),
					   .initial_generation_tag = cfg.initial_generation_tag,
					   .next_generation_tag = cfg.next_generation_tag,
				   });

	const double duration = stats.end_time - stats.start_time;
	const double actual_pps = duration > 0 ? static_cast<double>(stats.tx_count) / duration : 0;
	const bool socket_cleanup_complete = sockets.close_all();
	if (!socket_cleanup_complete) {
		fprintf(stderr, "kinetum_tap_sender: resource cleanup did not complete exactly\n");
		return 1;
	}

	if (stats.fatal_error) {
		return 1;
	}
	const std::string output = stats.render_json();
	const std::string warning = render_rate_warning(cfg.pps, actual_pps);
	return kinetum::common::emit_process_output({
		.standard_output = output,
		.standard_error = warning,
		.complete_exit_code = 0,
	});
}

/**
 * @brief Native TAP sender process entry point with total exception mapping.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit code: 0 on success, 1 on runtime failure, 2 on usage error.
 */
int main(int argc, char *argv[])
{
	try {
		return run_sender(argc, argv);
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "kinetum_tap_sender: operation exhausted memory\n");
	} catch (const std::length_error &) {
		fprintf(stderr, "kinetum_tap_sender: operation exceeds host size limits\n");
	} catch (const std::exception &) {
		fprintf(stderr, "kinetum_tap_sender: unexpected sender failure\n");
	} catch (...) {
		fprintf(stderr, "kinetum_tap_sender: unknown sender failure\n");
	}
	return 1;
}
