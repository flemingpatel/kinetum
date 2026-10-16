// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_validation_tap_analyzer.cpp
 * @brief Real-image packet identity, ordering, and output tests for the TAP analyzer.
 * @author Fleming Patel
 *
 * Authored classic PCAPs distinguish independent input interleaving from
 * within-input faults and prove exact membership independently of arrival order.
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include <google/protobuf/struct.pb.h>
#include <google/protobuf/util/json_util.h>
#include <kinetum/algo/net.hpp>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef KINETUM_VALIDATION_TAP_ANALYZER_PATH
#error "KINETUM_VALIDATION_TAP_ANALYZER_PATH must name the exact native analyzer image"
#endif

namespace kinetum::validation
{
namespace
{

/** Maximum lifetime of one exact analyzer child in this test process. */
constexpr unsigned int TEST_CHILD_TIMEOUT_SECONDS = 10u;

/** Complete-output ceiling for these bounded analyzer fixtures. */
constexpr std::size_t TEST_OUTPUT_CAPACITY = 65536;

/** Exact output destination for one analyzer child. */
enum class analyzer_output_destination : uint8_t {
	CAPTURE,  ///< Capture merged stdout/stderr.
	FULL,	  ///< Route stdout/stderr to /dev/full.
};

/** @brief Independently authored packet identity and traffic-profile tag. */
struct packet_spec {
	uint32_t sequence;	       ///< Global successful-send ordinal.
	uint16_t tag;		       ///< Traffic generation, independent of the DP epoch.
	uint32_t latency_us{1000000};  ///< Authored capture delay after the packet TX timestamp.
};

/** @brief Scope-bound owner for one complete authored classic-PCAP file. */
class pcap_fixture final {
    public:
	/**
	 * @brief Construct complete packet bytes before acquiring one temporary file.
	 * @param packets Exact arrival order to encode.
	 * @param transmit_seconds Exact wall-clock second encoded in every packet.
	 */
	explicit pcap_fixture(const std::vector<packet_spec> &packets, uint32_t transmit_seconds = 1)
	{
		std::vector<std::uint8_t> bytes{
			0xd4, 0xc3, 0xb2, 0xa1,	 // Little-endian microsecond magic.
			0x02, 0x00, 0x04, 0x00,	 // Version 2.4.
			0x00, 0x00, 0x00, 0x00,	 // Time-zone correction.
			0x00, 0x00, 0x00, 0x00,	 // Timestamp accuracy.
			0xff, 0xff, 0x00, 0x00,	 // Snapshot length 65535.
			0x01, 0x00, 0x00, 0x00,	 // Ethernet link type.
		};
		for (const auto &packet : packets) {
			std::array<uint8_t, 16> record{};
			const uint32_t seconds = transmit_seconds + packet.latency_us / 1000000u;
			const uint32_t microseconds = packet.latency_us % 1000000u;
			for (std::size_t index = 0; index < 4; ++index) {
				record[index] = static_cast<uint8_t>(seconds >> (8u * index));
				record[index + 4] = static_cast<uint8_t>(microseconds >> (8u * index));
			}
			record[8] = 64;
			record[12] = 64;
			bytes.insert(bytes.end(), record.begin(), record.end());
			std::array<uint8_t, 64> frame;
			frame.fill('X');
			std::fill_n(frame.begin(), 42, uint8_t{0});
			frame[0] = 2;
			frame[6] = 2;
			frame[12] = 8;
			frame[14] = 0x45;
			frame[22] = 64;
			frame[23] = 17;
			frame[26] = 10;
			frame[29] = 1;
			frame[30] = 198;
			frame[31] = 51;
			frame[32] = 100;
			frame[33] = 9;
			algo::net::write_be16(frame.data() + 16, 50);
			algo::net::write_be16(frame.data() + 18, static_cast<uint16_t>(packet.sequence));
			algo::net::write_be16(frame.data() + 34, 10000);
			algo::net::write_be16(frame.data() + 36, 9999);
			algo::net::write_be16(frame.data() + 38, 30);
			uint32_t checksum = 0;
			for (std::size_t offset = 14; offset < 34; offset += 2) {
				checksum += (static_cast<uint32_t>(frame[offset]) << 8) | frame[offset + 1];
			}
			while (checksum >> 16) {
				checksum = (checksum & 0xffffu) + (checksum >> 16);
			}
			algo::net::write_be16(frame.data() + 24, static_cast<uint16_t>(~checksum));
			constexpr std::array<uint8_t, 7> MAGIC{'K', 'I', 'N', 'E', 'T', 'U', 'M'};
			std::copy(MAGIC.begin(), MAGIC.end(), frame.begin() + 42);
			algo::net::write_be32(frame.data() + 49, packet.sequence);
			algo::net::write_be16(frame.data() + 53, packet.tag);
			const auto timestamp = std::bit_cast<uint64_t>(static_cast<double>(transmit_seconds));
			for (std::size_t index = 0; index < 8; ++index) {
				frame[55 + index] = static_cast<uint8_t>(timestamp >> (56u - 8u * index));
			}
			bytes.insert(bytes.end(), frame.begin(), frame.end());
		}
		path_ = (std::filesystem::temp_directory_path() / "kinetum_tap_analyzer.XXXXXX").string();
		const int descriptor = ::mkstemp(path_.data());
		if (descriptor < 0) {
			path_.clear();
			return;
		}
		std::size_t offset = 0;
		while (offset < bytes.size()) {
			const ssize_t count = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
			if (count > 0) {
				offset += static_cast<std::size_t>(count);
				continue;
			}
			if (count < 0 && errno == EINTR) {
				continue;
			}
			break;
		}
		const int close_result = ::close(descriptor);
		valid_ = offset == bytes.size() && close_result == 0;
	}

	/** @brief Remove the exact test file. */
	~pcap_fixture()
	{
		if (!path_.empty()) {
			(void)::unlink(path_.c_str());
		}
	}

	/** @brief Disable file-ownership aliasing. */
	pcap_fixture(const pcap_fixture &) = delete;

	/** @brief Disable replacement of file ownership. */
	pcap_fixture &operator=(const pcap_fixture &) = delete;

	/** @return true when the complete capture was written successfully. */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_;
	}

	/** @return Exact absolute PCAP path. */
	[[nodiscard]] const std::string &path() const noexcept
	{
		return path_;
	}

    private:
	std::string path_;   ///< Exact owned PCAP path, empty until ownership succeeds.
	bool valid_{false};  ///< Complete-capture publication result.
};

/** @brief Complete analyzer process observation. */
struct analyzer_result {
	int exit_code{-1};   ///< Normal process exit code, or -1 when abnormal.
	std::string output;  ///< Complete merged output when captured.
};

/**
 * @brief Launch the exact analyzer over one authored PCAP.
 *
 * @param pcap Exact PCAP input path.
 * @param destination Capture output or route it to /dev/full.
 * @param options Complete caller-authored analyzer options.
 * @return Child exit status and captured bytes.
 */
[[nodiscard]] analyzer_result run_analyzer(const std::string &pcap, analyzer_output_destination destination,
					   const std::vector<std::string> &options)
{
	std::vector<std::string> storage{KINETUM_VALIDATION_TAP_ANALYZER_PATH, "--pcap", pcap};
	storage.insert(storage.end(), options.begin(), options.end());
	std::vector<char *> argv;
	argv.reserve(storage.size() + 1u);
	for (auto &argument : storage) {
		argv.push_back(argument.data());
	}
	argv.push_back(nullptr);
	std::array<char, TEST_OUTPUT_CAPACITY> captured{};
	int output_pipe[2]{};
	if (::pipe(output_pipe) != 0) {
		return {};
	}

	const pid_t child = ::fork();
	if (child < 0) {
		(void)::close(output_pipe[0]);
		(void)::close(output_pipe[1]);
		return {};
	}
	if (child == 0) {
		(void)::close(output_pipe[0]);
		int output_descriptor = output_pipe[1];
		if (destination == analyzer_output_destination::FULL) {
			output_descriptor = ::open("/dev/full", O_WRONLY | O_CLOEXEC);
			if (output_descriptor < 0) {
				::_exit(126);
			}
		}
		if (::dup2(output_descriptor, STDOUT_FILENO) < 0 || ::dup2(output_descriptor, STDERR_FILENO) < 0) {
			::_exit(126);
		}
		if (output_descriptor != output_pipe[1]) {
			(void)::close(output_descriptor);
		}
		(void)::close(output_pipe[1]);
		(void)::alarm(TEST_CHILD_TIMEOUT_SECONDS);
		::execv(KINETUM_VALIDATION_TAP_ANALYZER_PATH, argv.data());
		::_exit(127);
	}

	(void)::close(output_pipe[1]);
	std::size_t captured_size = 0;
	bool complete = true;
	char buffer[512];
	for (;;) {
		const ssize_t count = ::read(output_pipe[0], buffer, sizeof(buffer));
		if (count > 0) {
			const auto extent = static_cast<std::size_t>(count);
			if (extent <= captured.size() - captured_size) {
				std::memcpy(captured.data() + captured_size, buffer, extent);
				captured_size += extent;
			} else {
				complete = false;
			}
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		complete = complete && count == 0;
		break;
	}
	(void)::close(output_pipe[0]);
	int wait_status = 0;
	pid_t waited = -1;
	do {
		waited = ::waitpid(child, &wait_status, 0);
	} while (waited < 0 && errno == EINTR);
	analyzer_result result;
	result.output.assign(captured.data(), captured_size);
	if (complete && waited == child && WIFEXITED(wait_status)) {
		result.exit_code = WEXITSTATUS(wait_status);
	}
	return result;
}

/**
 * @brief Require one numeric JSON fact without matching a nested field accidentally.
 * @param object Exact object containing the field.
 * @param name Field name.
 * @param expected Independently authored small integer answer.
 */
void expect_counter(const google::protobuf::Struct &object, const std::string &name, uint64_t expected)
{
	const auto found = object.fields().find(name);
	ASSERT_NE(found, object.fields().end()) << name;
	ASSERT_EQ(found->second.kind_case(), google::protobuf::Value::kNumberValue) << name;
	EXPECT_DOUBLE_EQ(found->second.number_value(), static_cast<double>(expected)) << name;
}

}  // namespace

/** @brief Prove analyzer JSON is byte-exact and incomplete delivery is failure. */
TEST(validation_tap_analyzer, result_delivery_is_complete_or_nonzero)
{
	pcap_fixture pcap({});
	ASSERT_TRUE(pcap.valid());
	const std::vector<std::string> options{"--expected", "0", "--stream-count", "1", "--no-latency"};
	const auto captured = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE, options);
	ASSERT_EQ(captured.exit_code, 0) << captured.output;
	EXPECT_EQ(captured.output,
		  "{\"total_rx\":0,\"valid\":0,\"invalid\":0,\"duplicates\":0,\"out_of_order\":0,"
		  "\"transition_seq\":-1,\"tag_transition_count\":0,\"max_gap\":0,\"loss_pct\":null,"
		  "\"missing_count\":0,\"latency\":null,\"tag_counts\":{},\"streams\":[{\"stream_index\":0,"
		  "\"expected_count\":0,\"valid\":0,\"duplicates\":0,\"out_of_order\":0,"
		  "\"missing_count\":0,\"transition_seq\":-1,\"tag_transition_count\":0,"
		  "\"first_tag\":null,\"last_tag\":null,\"tag_counts\":{}}]}\n");

	const auto unreported = run_analyzer(pcap.path(), analyzer_output_destination::FULL, options);
	EXPECT_EQ(unreported.exit_code, 1) << unreported.output;
}

/** @brief Independent input interleaving preserves order and cannot manufacture missing packets. */
TEST(validation_tap_analyzer, interleaved_inputs_retain_exact_membership_and_generation_changes)
{
	pcap_fixture pcap({{0, 1}, {2, 2}, {1, 1}, {3, 2}});
	ASSERT_TRUE(pcap.valid());
	const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE,
					   {"--expected", "4", "--stream-count", "2"});
	ASSERT_EQ(observed.exit_code, 0) << observed.output;
	google::protobuf::Struct json;
	ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(observed.output, &json).ok()) << observed.output;
	expect_counter(json, "valid", 4);
	expect_counter(json, "duplicates", 0);
	expect_counter(json, "out_of_order", 0);
	expect_counter(json, "missing_count", 0);
	expect_counter(json, "max_gap", 0);
	expect_counter(json, "tag_transition_count", 2);
	expect_counter(json, "transition_seq", 2);
	ASSERT_EQ(json.fields().at("streams").list_value().values_size(), 2);
	for (int index = 0; index < 2; ++index) {
		const auto &input = json.fields().at("streams").list_value().values(index).struct_value();
		expect_counter(input, "stream_index", static_cast<uint64_t>(index));
		expect_counter(input, "expected_count", 2);
		expect_counter(input, "valid", 2);
		expect_counter(input, "out_of_order", 0);
		expect_counter(input, "tag_transition_count", 1);
		expect_counter(input, "first_tag", 1);
		expect_counter(input, "last_tag", 2);
	}
}

/** @brief Every late unique packet is compared with its input's nondecreasing high-water mark. */
TEST(validation_tap_analyzer, within_input_reordering_is_not_hidden_by_a_previous_late_packet)
{
	pcap_fixture pcap({{0, 0}, {6, 0}, {2, 0}, {4, 0}, {1, 0}, {3, 0}, {5, 0}, {7, 0}});
	ASSERT_TRUE(pcap.valid());
	const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE,
					   {"--expected", "8", "--stream-count", "2"});
	ASSERT_EQ(observed.exit_code, 0) << observed.output;
	google::protobuf::Struct json;
	ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(observed.output, &json).ok());
	expect_counter(json, "valid", 8);
	expect_counter(json, "missing_count", 0);
	expect_counter(json, "out_of_order", 2);
	expect_counter(json.fields().at("streams").list_value().values(0).struct_value(), "out_of_order", 2);
	expect_counter(json.fields().at("streams").list_value().values(1).struct_value(), "out_of_order", 0);
}

/** @brief Duplicates cannot replace absent identities, including missing prefixes and suffixes. */
TEST(validation_tap_analyzer, missing_membership_includes_edges_and_excludes_duplicate_receipts)
{
	pcap_fixture pcap({{1, 0}, {4, 0}, {4, 0}});
	ASSERT_TRUE(pcap.valid());
	const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE,
					   {"--expected", "6", "--stream-count", "2"});
	ASSERT_EQ(observed.exit_code, 0) << observed.output;
	google::protobuf::Struct json;
	ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(observed.output, &json).ok());
	expect_counter(json, "total_rx", 3);
	expect_counter(json, "valid", 2);
	expect_counter(json, "duplicates", 1);
	expect_counter(json, "missing_count", 4);
	expect_counter(json, "max_gap", 2);
	expect_counter(json.fields().at("latency").struct_value(), "count", 2);
	for (int index = 0; index < 2; ++index) {
		expect_counter(json.fields().at("streams").list_value().values(index).struct_value(), "missing_count",
			       2);
	}
}

/** @brief Packet latency percentiles use exact nearest ranks at even and hundred-sample boundaries. */
TEST(validation_tap_analyzer, latency_percentiles_select_exact_observed_ranks)
{
	/** @brief One independently authored population and its expected percentile values. */
	struct percentile_case {
		uint32_t count;	 ///< Number of unique packets with delays 1..count microseconds.
		uint32_t p50;	 ///< Expected observed p50 in microseconds.
		uint32_t p99;	 ///< Expected observed p99 in microseconds.
	};
	constexpr std::array<percentile_case, 8> CASES{{{1, 1, 1},
							{2, 1, 2},
							{3, 2, 3},
							{4, 2, 4},
							{99, 50, 99},
							{100, 50, 99},
							{101, 51, 100},
							{200, 100, 198}}};
	for (const auto &sample : CASES) {
		SCOPED_TRACE(sample.count);
		std::vector<packet_spec> packets;
		packets.reserve(sample.count);
		for (uint32_t index = 0; index < sample.count; ++index) {
			packets.push_back({index, 0, index + 1u});
		}
		pcap_fixture pcap(packets);
		ASSERT_TRUE(pcap.valid());
		const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE,
						   {"--expected", std::to_string(sample.count), "--stream-count", "1"});
		ASSERT_EQ(observed.exit_code, 0) << observed.output;
		google::protobuf::Struct json;
		ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(observed.output, &json).ok());
		const auto &latency = json.fields().at("latency").struct_value();
		expect_counter(latency, "count", sample.count);
		expect_counter(latency, "min", 1);
		expect_counter(latency, "max", sample.count);
		expect_counter(latency, "p50", sample.p50);
		expect_counter(latency, "p99", sample.p99);
		EXPECT_DOUBLE_EQ(latency.fields().at("avg").number_value(),
				 (static_cast<double>(sample.count) + 1.0) / 2.0);
	}
}

/** @brief A duplicate packet cannot skew the mean, extrema, or percentile population. */
TEST(validation_tap_analyzer, duplicate_latency_is_excluded_from_all_statistics)
{
	pcap_fixture pcap({{0, 0, 1}, {1, 0, 3}, {1, 0, 99}});
	ASSERT_TRUE(pcap.valid());
	const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE,
					   {"--expected", "2", "--stream-count", "1"});
	ASSERT_EQ(observed.exit_code, 0) << observed.output;
	google::protobuf::Struct json;
	ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(observed.output, &json).ok());
	expect_counter(json, "duplicates", 1);
	const auto &latency = json.fields().at("latency").struct_value();
	expect_counter(latency, "count", 2);
	expect_counter(latency, "avg", 2);
	expect_counter(latency, "min", 1);
	expect_counter(latency, "max", 3);
	expect_counter(latency, "p50", 1);
	expect_counter(latency, "p99", 3);
}

/** @brief A one-microsecond capture interval remains exact at contemporary Unix timestamps. */
TEST(validation_tap_analyzer, epoch_seconds_do_not_erase_capture_microseconds)
{
	pcap_fixture pcap({{0, 0, 1}}, 1700000000u);
	ASSERT_TRUE(pcap.valid());
	const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE,
					   {"--expected", "1", "--stream-count", "1"});
	ASSERT_EQ(observed.exit_code, 0) << observed.output;
	google::protobuf::Struct json;
	ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(observed.output, &json).ok());
	const auto &latency = json.fields().at("latency").struct_value();
	for (const auto *field : {"avg", "min", "max", "p50", "p99", "count"}) {
		expect_counter(latency, field, 1);
	}
}

/** @brief Loss serialization retains a received packet even near the 100-percent endpoint. */
TEST(validation_tap_analyzer, loss_percentage_retains_small_counter_differences)
{
	pcap_fixture pcap({{0, 0}});
	ASSERT_TRUE(pcap.valid());
	const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE,
					   {"--expected", "100000000", "--stream-count", "1"});
	ASSERT_EQ(observed.exit_code, 0) << observed.output;
	google::protobuf::Struct json;
	ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(observed.output, &json).ok());
	expect_counter(json, "valid", 1);
	expect_counter(json, "missing_count", 99999999);
	EXPECT_DOUBLE_EQ(json.fields().at("loss_pct").number_value(), 99.999999);
}

/** @brief Missing population facts, invalid ranges, and repeated authoring are usage errors. */
TEST(validation_tap_analyzer, packet_and_stream_populations_require_explicit_exact_arguments)
{
	pcap_fixture pcap({});
	ASSERT_TRUE(pcap.valid());
	const std::vector<std::vector<std::string>> invalid_options{
		{"--expected", "0"},
		{"--stream-count", "1"},
		{"--expected", "0", "--stream-count", "0"},
		{"--expected", "0", "--stream-count", "65"},
		{"--expected", "0", "--stream-count", "2", "--stream-count", "1"},
		{"--expected", "0", "--expected", "1", "--stream-count", "1"},
	};
	for (const auto &options : invalid_options) {
		const auto observed = run_analyzer(pcap.path(), analyzer_output_destination::CAPTURE, options);
		EXPECT_EQ(observed.exit_code, 2) << observed.output;
	}
}

}  // namespace kinetum::validation
