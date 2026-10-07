// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file kinetum_tap_analyzer.cpp
 * @brief Native pcap analyzer for Kinetum physical-I/O validation.
 * @author Fleming Patel
 *
 * Parses pcap files and extracts KINETUM payload fields (seq, tag,
 * timestamp) to compute loss, latency, generation-tag transition, and tag
 * distribution metrics. Replaces the Python/scapy analyzer for
 * high packet counts.
 *
 * Reads pcap format directly (no libpcap dependency). Outputs
 * analysis results as JSON to stdout.
 */

#include <algorithm>
#include <charconv>
#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <locale>
#include <map>
#include <memory>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <sys/stat.h>
#include <unordered_set>
#include <unistd.h>
#include <vector>

#include "src/common/process_output.hpp"

// =============================================================================
// Constants (must match KINETUM payload format)
// =============================================================================

static constexpr uint8_t MAGIC[] = {'K', 'I', 'N', 'E', 'T', 'U', 'M'};	 ///< Exact payload magic.
static constexpr size_t MAGIC_LEN = 7;					 ///< Bytes in `MAGIC`.
static constexpr size_t HEADER_SIZE = 21;  ///< Magic, sequence, tag, and binary64 timestamp bytes.

static constexpr size_t ETH_HDR_LEN = 14;  ///< Exact Ethernet-II header bytes.
static constexpr size_t IP_HDR_LEN = 20;   ///< Exact option-free IPv4 header bytes.
static constexpr size_t UDP_HDR_LEN = 8;   ///< Exact UDP header bytes.
static constexpr size_t PAYLOAD_OFFSET = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;  ///< Test payload offset.

static_assert(sizeof(double) == sizeof(uint64_t) && std::numeric_limits<double>::is_iec559,
	      "packet timestamps require one binary64 representation");

// =============================================================================
// Pcap File Format (raw parsing, no libpcap dependency)
// =============================================================================

/**
 * @brief On-disk global pcap header.
 */
struct pcap_file_header {
	uint32_t magic;		 ///< File byte-order and timestamp-resolution marker.
	uint16_t version_major;	 ///< Pcap major version.
	uint16_t version_minor;	 ///< Pcap minor version.
	int32_t thiszone;	 ///< GMT-to-local correction field from pcap.
	uint32_t sigfigs;	 ///< Timestamp accuracy field from pcap.
	uint32_t snaplen;	 ///< Maximum captured packet length.
	uint32_t linktype;	 ///< Link-layer type for packet records.
};

/** Complete native analyzer usage text. */
constexpr std::string_view USAGE = "Usage: kinetum_tap_analyzer --pcap <file> [--expected N] [--no-latency] [--help]\n";

/**
 * @brief On-disk per-packet pcap header.
 */
struct pcap_packet_header {
	uint32_t ts_sec;   ///< Capture timestamp seconds.
	uint32_t ts_usec;  ///< Capture timestamp microseconds.
	uint32_t caplen;   ///< Bytes present in the file.
	uint32_t origlen;  ///< Original packet length on the capture interface.
};

static_assert(std::is_standard_layout_v<pcap_file_header> && sizeof(pcap_file_header) == 24 &&
		      offsetof(pcap_file_header, magic) == 0 && offsetof(pcap_file_header, version_major) == 4 &&
		      offsetof(pcap_file_header, version_minor) == 6 && offsetof(pcap_file_header, thiszone) == 8 &&
		      offsetof(pcap_file_header, sigfigs) == 12 && offsetof(pcap_file_header, snaplen) == 16 &&
		      offsetof(pcap_file_header, linktype) == 20,
	      "pcap file header layout must be exact");
static_assert(std::is_standard_layout_v<pcap_packet_header> && sizeof(pcap_packet_header) == 16 &&
		      offsetof(pcap_packet_header, ts_sec) == 0 && offsetof(pcap_packet_header, ts_usec) == 4 &&
		      offsetof(pcap_packet_header, caplen) == 8 && offsetof(pcap_packet_header, origlen) == 12,
	      "pcap packet header layout must be exact");

// =============================================================================
// Byte Order Helpers
// =============================================================================

/**
 * @brief Read a big-endian uint16_t from the Kinetum payload.
 *
 * @param p Pointer to at least two bytes.
 * @return Parsed unsigned integer in host byte order.
 */
static uint16_t read_be16(const uint8_t *p)
{
	return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

/**
 * @brief Read a big-endian uint32_t from the Kinetum payload.
 *
 * @param p Pointer to at least four bytes.
 * @return Parsed unsigned integer in host byte order.
 */
static uint32_t read_be32(const uint8_t *p)
{
	return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
	       (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

/**
 * @brief Read a big-endian IEEE-754 double from the Kinetum payload.
 *
 * @param p Pointer to at least eight bytes.
 * @return Parsed double value in host byte order.
 */
static double read_be_double(const uint8_t *p)
{
	uint64_t bits = 0;
	for (size_t i = 0; i < 8; ++i) {
		bits = (bits << 8) | p[i];
	}
	double val;
	memcpy(&val, &bits, 8);
	return val;
}

// =============================================================================
// Analysis
// =============================================================================

/**
 * @brief Native analyzer counters serialized to stdout as JSON.
 */
struct analysis_result {
	uint64_t total_rx{0};			  ///< Packet records read from the pcap.
	uint64_t valid{0};			  ///< Records carrying a valid Kinetum payload.
	uint64_t invalid{0};			  ///< Records outside the exact packet-profile contract.
	uint64_t duplicates{0};			  ///< Repeated sequence numbers.
	uint64_t out_of_order{0};		  ///< Sequence numbers lower than the previous record.
	int64_t transition_seq{-1};		  ///< First sequence number whose tag differs from prior tag.
	uint64_t tag_transition_count{0};	  ///< Number of observed adjacent generation-tag changes.
	uint64_t max_gap{0};			  ///< Largest observed sequence-number gap.
	std::map<uint32_t, uint64_t> tag_counts;  ///< Valid packet counts by generation tag.
	std::vector<double> latencies;		  ///< Accepted latency samples in microseconds.
	uint64_t missing_count{0};		  ///< Sum of observed sequence-number gaps.
	bool fatal_error{false};		  ///< True when the pcap structure is malformed.

	/**
	 * @brief Render the analyzer result using the JSON schema consumed by Python.
	 *
	 * @param expected_count Expected packet count used to compute loss_pct.
	 * @return Complete locale-independent JSON bytes.
	 */
	[[nodiscard]] std::string render_json(uint64_t expected_count) const
	{
		double loss_pct = 0.0;
		if (expected_count > 0 && valid < expected_count) {
			loss_pct = static_cast<double>(expected_count - valid) / static_cast<double>(expected_count) *
				   100.0;
		}

		// Latency stats
		double lat_avg = 0, lat_min = 0, lat_max = 0, lat_p50 = 0, lat_p99 = 0;
		if (!latencies.empty()) {
			std::vector<double> sorted_lats = latencies;
			std::sort(sorted_lats.begin(), sorted_lats.end());
			size_t n = sorted_lats.size();
			double sum = 0;
			for (double l : sorted_lats) {
				sum += l;
			}
			lat_avg = sum / static_cast<double>(n);
			lat_min = sorted_lats.front();
			lat_max = sorted_lats.back();
			lat_p50 = sorted_lats[n / 2];
			lat_p99 = (n > 100) ? sorted_lats[static_cast<size_t>(static_cast<double>(n) * 0.99)] :
					      sorted_lats[n - 1];
		}

		std::ostringstream output;
		output.exceptions(std::ios::badbit | std::ios::failbit);
		output.imbue(std::locale::classic());
		output << "{\"total_rx\":" << total_rx << ",\"valid\":" << valid << ",\"invalid\":" << invalid
		       << ",\"duplicates\":" << duplicates << ",\"out_of_order\":" << out_of_order
		       << ",\"transition_seq\":" << transition_seq
		       << ",\"tag_transition_count\":" << tag_transition_count << ",\"max_gap\":" << max_gap
		       << ",\"loss_pct\":" << std::fixed << std::setprecision(4) << loss_pct
		       << ",\"missing_count\":" << missing_count << ",\"latency\":{\"avg\":" << std::setprecision(2)
		       << lat_avg << ",\"min\":" << lat_min << ",\"max\":" << lat_max << ",\"p50\":" << lat_p50
		       << ",\"p99\":" << lat_p99 << ",\"count\":" << latencies.size() << "},\"tag_counts\":{";

		bool first = true;
		for (const auto &[tag, count] : tag_counts) {
			if (!first) {
				output << ',';
			}
			output << '"' << tag << "\":" << count;
			first = false;
		}
		output << "}}\n";
		return output.str();
	}
};

/**
 * @brief Print native analyzer usage.
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
 * @param flag Flag name used in error messages.
 * @param out Parsed value on success.
 * @param error Error text on failure.
 * @return True when parsing succeeds and consumes the entire string.
 */
static bool parse_uint64_arg(std::string_view text, const char *flag, uint64_t &out, std::string &error)
{
	if (text.empty()) {
		error = std::string(flag) + " requires a non-empty integer";
		return false;
	}

	uint64_t value = 0;
	const char *begin = text.data();
	const char *end = text.data() + text.size();
	const auto [ptr, ec] = std::from_chars(begin, end, value);
	if (ec != std::errc{} || ptr != end) {
		error = std::string(flag) + " must be a non-negative integer";
		return false;
	}

	out = value;
	return true;
}

/**
 * @brief Analyze one pcap file and fail closed on malformed capture structure.
 *
 * @param path Pcap file path to read.
 * @param expected_count Expected packet count used for duplicate-set preallocation.
 * @param measure_latency True to compute latency samples from sender timestamps.
 * @return Analysis counters and fatal-error flag.
 */
static analysis_result analyze_pcap(const char *path, uint64_t expected_count, bool measure_latency)
{
	analysis_result result;

	if (path == nullptr || path[0] != '/') {
		fprintf(stderr, "analyzer: pcap path must be absolute\n");
		result.fatal_error = true;
		return result;
	}
	const int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		fprintf(stderr, "analyzer: failed to open %s: %s\n", path, strerror(errno));
		result.fatal_error = true;
		return result;
	}
	struct stat metadata{};
	if (fstat(fd, &metadata) < 0) {
		fprintf(stderr, "analyzer: failed to inspect %s: %s\n", path, strerror(errno));
		close(fd);
		result.fatal_error = true;
		return result;
	}
	if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1) {
		fprintf(stderr, "analyzer: pcap input is not one exact regular file\n");
		close(fd);
		result.fatal_error = true;
		return result;
	}
	FILE *raw_stream = fdopen(fd, "rb");
	if (raw_stream == nullptr) {
		fprintf(stderr, "analyzer: failed to bind pcap stream: %s\n", strerror(errno));
		close(fd);
		result.fatal_error = true;
		return result;
	}
	std::unique_ptr<FILE, int (*)(FILE *)> stream(raw_stream, &fclose);

	// Read pcap file header
	pcap_file_header fhdr;
	if (fread(&fhdr, sizeof(fhdr), 1, stream.get()) != 1) {
		fprintf(stderr, "analyzer: failed to read pcap header\n");
		result.fatal_error = true;
		return result;
	}

	// Validate magic (support both byte orders)
	bool swap_bytes = false;
	if (fhdr.magic == 0xd4c3b2a1) {
		swap_bytes = true;
	} else if (fhdr.magic != 0xa1b2c3d4) {
		fprintf(stderr, "analyzer: invalid pcap magic: 0x%08x\n", fhdr.magic);
		result.fatal_error = true;
		return result;
	}
	const uint16_t version_major = swap_bytes ? __builtin_bswap16(fhdr.version_major) : fhdr.version_major;
	const uint16_t version_minor = swap_bytes ? __builtin_bswap16(fhdr.version_minor) : fhdr.version_minor;
	const uint32_t snaplen = swap_bytes ? __builtin_bswap32(fhdr.snaplen) : fhdr.snaplen;
	const uint32_t linktype = swap_bytes ? __builtin_bswap32(fhdr.linktype) : fhdr.linktype;
	if (version_major != 2 || version_minor != 4 || snaplen < PAYLOAD_OFFSET + HEADER_SIZE || linktype != 1) {
		fprintf(stderr, "analyzer: unsupported pcap header contract\n");
		result.fatal_error = true;
		return result;
	}

	int64_t last_seq = -1;
	uint32_t last_tag = 0;
	bool has_last_tag = false;
	std::unordered_set<uint32_t> seen_sequences;
	if (expected_count > 0) {
		constexpr uint64_t MAX_RESERVE = 1000000;
		seen_sequences.reserve(static_cast<size_t>(std::min(expected_count, MAX_RESERVE)));
	}

	// Read packets
	pcap_packet_header phdr;
	std::vector<uint8_t> pkt_buf;

	for (;;) {
		const size_t header_bytes = fread(&phdr, 1, sizeof(phdr), stream.get());
		if (header_bytes == 0 && feof(stream.get()) != 0) {
			break;
		}
		if (header_bytes != sizeof(phdr)) {
			fprintf(stderr, "analyzer: truncated pcap packet header\n");
			result.fatal_error = true;
			break;
		}
		uint32_t caplen = swap_bytes ? __builtin_bswap32(phdr.caplen) : phdr.caplen;
		uint32_t origlen = swap_bytes ? __builtin_bswap32(phdr.origlen) : phdr.origlen;
		uint32_t ts_sec = swap_bytes ? __builtin_bswap32(phdr.ts_sec) : phdr.ts_sec;
		uint32_t ts_usec = swap_bytes ? __builtin_bswap32(phdr.ts_usec) : phdr.ts_usec;

		if (caplen > snaplen || caplen > 65535 || origlen > 65535 || origlen < caplen || ts_usec >= 1000000) {
			fprintf(stderr, "analyzer: corrupted pcap packet length: %" PRIu32 "\n", caplen);
			result.fatal_error = true;
			break;
		}

		pkt_buf.resize(caplen);
		if (fread(pkt_buf.data(), 1, caplen, stream.get()) != caplen) {
			fprintf(stderr, "analyzer: truncated pcap packet payload\n");
			result.fatal_error = true;
			break;
		}

		result.total_rx++;

		// Need at least ETH + IP + UDP + KINETUM header
		if (caplen < PAYLOAD_OFFSET + HEADER_SIZE) {
			result.invalid++;
			continue;
		}

		const uint8_t *ethernet = pkt_buf.data();
		const uint8_t *ip = ethernet + ETH_HDR_LEN;
		const uint8_t *udp = ip + IP_HDR_LEN;
		const uint16_t ip_total_length = read_be16(ip + 2);
		const uint16_t udp_length = read_be16(udp + 4);
		const bool exact_headers = read_be16(ethernet + 12) == 0x0800 && ip[0] == 0x45 && ip[9] == 17 &&
					   (read_be16(ip + 6) & 0x3fff) == 0 &&
					   ip_total_length >= IP_HDR_LEN + UDP_HDR_LEN + HEADER_SIZE &&
					   udp_length >= UDP_HDR_LEN + HEADER_SIZE &&
					   udp_length == ip_total_length - IP_HDR_LEN &&
					   ETH_HDR_LEN + ip_total_length == caplen && origlen == caplen;
		if (!exact_headers) {
			result.invalid++;
			continue;
		}

		const uint8_t *payload = pkt_buf.data() + PAYLOAD_OFFSET;

		// Verify MAGIC
		if (memcmp(payload, MAGIC, MAGIC_LEN) != 0) {
			result.invalid++;
			continue;
		}

		// Parse fields
		uint32_t seq = read_be32(payload + MAGIC_LEN);
		uint16_t tag = read_be16(payload + MAGIC_LEN + 4);
		double tx_time = read_be_double(payload + MAGIC_LEN + 6);
		if (expected_count > 0 && static_cast<uint64_t>(seq) >= expected_count) {
			result.invalid++;
			continue;
		}
		double latency_us = 0.0;
		if (measure_latency) {
			const double rx_time = static_cast<double>(ts_sec) + static_cast<double>(ts_usec) / 1e6;
			latency_us = (rx_time - tx_time) * 1e6;
			if (!std::isfinite(tx_time) || tx_time <= 0.0 || !std::isfinite(latency_us) ||
			    latency_us <= 0.0 || latency_us >= 1e9) {
				result.invalid++;
				continue;
			}
		}

		result.valid++;
		if (!seen_sequences.insert(seq).second) {
			result.duplicates++;
		}
		result.tag_counts[tag]++;

		// Transition detection
		if (has_last_tag && tag != last_tag) {
			result.tag_transition_count++;
			if (result.transition_seq < 0) {
				result.transition_seq = static_cast<int64_t>(seq);
			}
		}
		last_tag = tag;
		has_last_tag = true;

		// Gap and out-of-order detection
		if (last_seq >= 0) {
			int64_t s = static_cast<int64_t>(seq);
			if (s < last_seq) {
				result.out_of_order++;
			} else if (s > last_seq + 1) {
				uint64_t gap = static_cast<uint64_t>(s - last_seq - 1);
				if (gap > result.max_gap) {
					result.max_gap = gap;
				}
				if (result.missing_count > std::numeric_limits<uint64_t>::max() - gap) {
					fprintf(stderr, "analyzer: sequence-gap accounting overflow\n");
					result.fatal_error = true;
					break;
				}
				result.missing_count += gap;
			}
		}
		last_seq = static_cast<int64_t>(seq);

		// Latency measurement
		if (measure_latency) {
			result.latencies.push_back(latency_us);
		}
	}

	if (ferror(stream.get()) != 0) {
		fprintf(stderr, "analyzer: failed while reading pcap: %s\n", strerror(errno));
		result.fatal_error = true;
	}
	return result;
}

/**
 * @brief Native TAP pcap analyzer entry point.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit code: 0 on success, 1 on analysis/runtime failure, 2 on usage error.
 */
int main(int argc, char *argv[])
{
	try {
		const char *pcap_path = nullptr;
		uint64_t expected_count = 0;
		bool measure_latency = true;
		std::string error;

		for (int i = 1; i < argc; ++i) {
			if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
				return kinetum::common::emit_process_output({
					.standard_output = USAGE,
					.standard_error = {},
					.complete_exit_code = 0,
				});
			}
			if (strcmp(argv[i], "--pcap") == 0) {
				if (i + 1 >= argc) {
					fprintf(stderr, "kinetum_tap_analyzer: --pcap requires an argument\n");
					print_usage(stderr);
					return 2;
				}
				pcap_path = argv[++i];
			} else if (strcmp(argv[i], "--expected") == 0) {
				if (i + 1 >= argc) {
					fprintf(stderr, "kinetum_tap_analyzer: --expected requires an argument\n");
					print_usage(stderr);
					return 2;
				}
				if (!parse_uint64_arg(argv[++i], "--expected", expected_count, error)) {
					fprintf(stderr, "kinetum_tap_analyzer: %s\n", error.c_str());
					print_usage(stderr);
					return 2;
				}
				if (expected_count > std::numeric_limits<uint32_t>::max()) {
					fprintf(stderr,
						"kinetum_tap_analyzer: --expected exceeds the packet sequence domain\n");
					return 2;
				}
			} else if (strcmp(argv[i], "--no-latency") == 0) {
				measure_latency = false;
			} else {
				fprintf(stderr, "kinetum_tap_analyzer: unknown argument: %s\n", argv[i]);
				print_usage(stderr);
				return 2;
			}
		}

		if (!pcap_path) {
			fprintf(stderr, "kinetum_tap_analyzer: --pcap is required\n");
			print_usage(stderr);
			return 2;
		}

		auto result = analyze_pcap(pcap_path, expected_count, measure_latency);
		if (result.fatal_error) {
			return 1;
		}
		const std::string output = result.render_json(expected_count);
		return kinetum::common::emit_process_output({
			.standard_output = output,
			.standard_error = {},
			.complete_exit_code = 0,
		});
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "kinetum_tap_analyzer: operation exhausted memory\n");
		return 1;
	} catch (const std::length_error &) {
		fprintf(stderr, "kinetum_tap_analyzer: operation exceeds host size limits\n");
		return 1;
	} catch (const std::exception &) {
		fprintf(stderr, "kinetum_tap_analyzer: unexpected analysis failure\n");
		return 1;
	} catch (...) {
		fprintf(stderr, "kinetum_tap_analyzer: unknown analysis failure\n");
		return 1;
	}
}
