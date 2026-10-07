// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file kinetumctl_main.cpp
 * @brief kinetumctl: gRPC CLI for ControlService.
 * @author Fleming Patel
 *
 * Usage examples:
 *   kinetumctl --endpoint 127.0.0.1:50051 stats
 *   kinetumctl --endpoint 127.0.0.1:50051 set-config examples/fan_in_edge_gateway/config_snapshot.pbtxt
 *   kinetumctl --endpoint 127.0.0.1:50051 confirm SNAPSHOT_ID --epoch E --revision R
 *   kinetumctl --endpoint 127.0.0.1:50051 list-snapshots
 *   kinetumctl --endpoint 127.0.0.1:50051 rollback SNAPSHOT_ID
 *   kinetumctl --endpoint 127.0.0.1:50051 guardrails on
 *       --poll-ms 250 --window-ms 5000 --max-drop-ratio 0.05 --min-tx-ratio 0.95
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>

#include "src/common/application_status.hpp"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/control_plane_contract.hpp"
#include "src/common/control_response_contract.hpp"
#include "src/common/dataplane_health_contract.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/file_io.hpp"
#include "src/common/generated_snapshot_identity.hpp"
#include "src/common/log.hpp"
#include "src/common/logging_status.hpp"
#include "src/common/grpc_logging.hpp"
#include "src/common/pbtxt.hpp"
#include "src/common/process_output.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/runtime_telemetry_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/tls.hpp"
#include "src/common/transition_idempotency_key.hpp"
#include "src/common/version.hpp"
#include "src/cp/guardrails_policy.hpp"
#include "gen/kinetum/control/v1/control.grpc.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"

namespace
{

/** Default 30-second gRPC deadline for one CLI attempt. */
constexpr auto DEFAULT_TIMEOUT = std::chrono::seconds(30);

/** Default number of retries for transient failures. */
constexpr int DEFAULT_RETRIES = 3;

/** Default initial retry delay in milliseconds. */
constexpr int DEFAULT_RETRY_DELAY_MS = 1000;

/** Maximum accepted retry count for one command invocation. */
constexpr int MAX_RETRIES = 100;

/** Maximum accepted initial retry delay in milliseconds. */
constexpr int MAX_RETRY_DELAY_MS = 3600000;

/** Maximum accepted guardrails poll interval in milliseconds. */
constexpr int64_t MAX_GUARDRAILS_POLL_MS = 3600000;

/** Maximum accepted guardrails evaluation window in milliseconds. */
constexpr int64_t MAX_GUARDRAILS_WINDOW_MS = 86400000;

/** @brief Maximum application-status diagnostic bytes emitted by the stats command. */
constexpr std::size_t MAX_STATS_STATUS_MESSAGE_BYTES = 512u;

/** @brief Exact interval rows authored by the canonical threshold-policy command. */
constexpr uint32_t GUARDRAILS_HISTORY_CAPACITY = 100u;

/** @brief Exact stable intervals required by the canonical threshold-policy command. */
constexpr uint32_t GUARDRAILS_BASELINE_SAMPLES = 10u;

/** @brief Exact automatic-rollback confidence authored by the CLI. */
constexpr double GUARDRAILS_AUTO_ROLLBACK_THRESHOLD = 0.80;

/** @brief Exact human-defer confidence authored by the CLI. */
constexpr double GUARDRAILS_DEFER_THRESHOLD = 0.50;

/** @brief Exact attribution magnitude floor authored by the CLI. */
constexpr double GUARDRAILS_ATTRIBUTION_DEGRADATION = 0.30;

static_assert(GUARDRAILS_BASELINE_SAMPLES <= GUARDRAILS_HISTORY_CAPACITY,
	      "CLI guardrails baseline must fit its authored history");

/**
 * @brief Set the per-attempt gRPC deadline.
 *
 * @param ctx Client context to modify.
 */
inline void set_deadline(grpc::ClientContext &ctx)
{
	ctx.set_deadline(std::chrono::system_clock::now() + DEFAULT_TIMEOUT);
}

/**
 * @brief Parse an unsigned decimal 64-bit integer without exceptions.
 *
 * Rejects empty strings, signs, trailing junk, and overflows.
 *
 * @param text User-provided argument text.
 * @param[out] out Parsed value on success.
 * @return true if the entire string is a valid uint64_t decimal literal.
 */
inline bool parse_uint64_arg(std::string_view text, uint64_t *out)
{
	if (!out || text.empty()) {
		return false;
	}

	uint64_t value = 0;
	const char *begin = text.data();
	const char *end = begin + text.size();
	const auto [ptr, ec] = std::from_chars(begin, end, value);
	if (ec != std::errc{} || ptr != end) {
		return false;
	}

	*out = value;
	return true;
}

/**
 * @brief Parse an unsigned decimal value into a bounded int.
 *
 * @param text User-provided argument text.
 * @param min_value Inclusive minimum accepted value.
 * @param max_value Inclusive maximum accepted value.
 * @param[out] out Parsed value on success.
 * @return true if the value is syntactically valid and in range.
 */
inline bool parse_int_arg(std::string_view text, int min_value, int max_value, int *out)
{
	uint64_t value = 0;
	if (!out || min_value < 0 || max_value < min_value || !parse_uint64_arg(text, &value) ||
	    value > static_cast<uint64_t>(max_value) || value < static_cast<uint64_t>(min_value)) {
		return false;
	}

	*out = static_cast<int>(value);
	return true;
}

/**
 * @brief Parse an unsigned decimal value into a bounded int64_t.
 *
 * @param text User-provided argument text.
 * @param min_value Inclusive minimum accepted value.
 * @param max_value Inclusive maximum accepted value.
 * @param[out] out Parsed value on success.
 * @return true if the value is syntactically valid and in range.
 */
inline bool parse_int64_arg(std::string_view text, int64_t min_value, int64_t max_value, int64_t *out)
{
	uint64_t value = 0;
	if (!out || min_value < 0 || max_value < min_value || !parse_uint64_arg(text, &value) ||
	    value > static_cast<uint64_t>(max_value) || value < static_cast<uint64_t>(min_value)) {
		return false;
	}

	*out = static_cast<int64_t>(value);
	return true;
}

/**
 * @brief Parse a bounded floating-point CLI argument without exceptions.
 *
 * @param text User-provided argument text.
 * @param min_value Inclusive minimum accepted value.
 * @param max_value Inclusive maximum accepted value.
 * @param[out] out Parsed value on success.
 * @return true if the entire string is a finite double in range.
 */
inline bool parse_double_arg(std::string_view text, double min_value, double max_value, double *out)
{
	if (!out || text.empty() || max_value < min_value) {
		return false;
	}

	double value = 0.0;
	const char *begin = text.data();
	const char *end = begin + text.size();
	const auto [ptr, ec] = std::from_chars(begin, end, value);
	if (ec != std::errc{} || ptr != end || !std::isfinite(value) || value < min_value || value > max_value) {
		return false;
	}

	*out = value;
	return true;
}

/**
 * @brief Consume the next argv token as a required flag value.
 *
 * @param argc Argument count from main.
 * @param argv Argument vector from main.
 * @param[in,out] index Index of the flag; advanced to the value on success.
 * @param flag Flag name for diagnostics.
 * @param[out] value Consumed value on success.
 * @return true if a value exists; false if the flag is missing its value.
 */
bool take_required_value(int argc, char **argv, int &index, std::string_view flag, std::string_view *value)
{
	if (!value || index + 1 >= argc) {
		std::cerr << flag << " requires a value\n";
		return false;
	}

	*value = argv[++index];
	return true;
}

/**
 * @brief Parse a comma-separated module-id list for selective rollback.
 *
 * Empty elements and duplicate module IDs are rejected so `--modules ,` cannot
 * silently turn into a full rollback.
 *
 * @param text Comma-separated module list.
 * @param[out] out Parsed module IDs appended on success.
 * @param[out] error Human-readable diagnostic on failure.
 * @return true if the list is non-empty and contains unique non-empty IDs.
 */
bool parse_module_list(std::string_view text, std::vector<std::string> *out, std::string *error)
{
	if (!out || text.empty()) {
		if (error) {
			*error = "--modules requires at least one module id";
		}
		return false;
	}

	std::vector<std::string> parsed;
	std::set<std::string_view> unique;
	std::size_t start = 0;
	while (start <= text.size()) {
		const std::size_t end = text.find(',', start);
		const std::size_t token_end = (end == std::string_view::npos) ? text.size() : end;
		const auto token = text.substr(start, token_end - start);
		if (token.empty()) {
			if (error) {
				*error = "--modules contains an empty module id";
			}
			return false;
		}
		for (char c : token) {
			if (static_cast<unsigned char>(c) <= 0x20) {
				if (error) {
					*error = "--modules entries must not contain whitespace";
				}
				return false;
			}
		}
		if (!unique.insert(token).second) {
			if (error) {
				*error = "--modules contains duplicate module id: " + std::string(token);
			}
			return false;
		}
		parsed.emplace_back(token);
		if (end == std::string_view::npos) {
			break;
		}
		start = end + 1;
	}

	out->insert(out->end(), parsed.begin(), parsed.end());
	return true;
}

/**
 * @brief Check whether a gRPC status code is retryable.
 *
 * @param code gRPC status code from a failed call.
 * @return true for transient transport failures; false otherwise.
 */
inline bool is_transient_error(grpc::StatusCode code)
{
	return code == grpc::StatusCode::UNAVAILABLE || code == grpc::StatusCode::DEADLINE_EXCEEDED;
}

/**
 * @brief Replace untrusted control bytes in one bounded diagnostic.
 * @param value Remote diagnostic bytes.
 * @return At most 512 printable ASCII bytes with controls replaced by `?`.
 */
std::string sanitized_diagnostic(std::string_view value)
{
	const std::size_t size = std::min(value.size(), MAX_STATS_STATUS_MESSAGE_BYTES);
	std::string result(size, '?');
	for (std::size_t index = 0; index < size; ++index) {
		const auto byte = static_cast<unsigned char>(value[index]);
		if (byte >= 0x20u && byte <= 0x7eu) {
			result[index] = static_cast<char>(byte);
		}
	}
	return result;
}

/**
 * @brief Deliver a bounded exception diagnostic without allocating in the exception handler.
 * @param message Borrowed exception text; controls are replaced with question marks.
 * @return The checked command-failure exit code.
 */
int report_terminal_exception(std::string_view message) noexcept
{
	constexpr std::string_view PREFIX = "Error: ";
	std::array<char, MAX_STATS_STATUS_MESSAGE_BYTES + PREFIX.size() + 1u> output{};
	std::copy(PREFIX.begin(), PREFIX.end(), output.begin());
	const auto size = std::min(message.size(), MAX_STATS_STATUS_MESSAGE_BYTES);
	for (std::size_t index = 0u; index < size; ++index) {
		const auto byte = static_cast<unsigned char>(message[index]);
		output[PREFIX.size() + index] = byte >= 0x20u && byte <= 0x7eu ? static_cast<char>(byte) : '?';
	}
	output[PREFIX.size() + size] = '\n';
	return kinetum::common::emit_process_output({
		.standard_output = {},
		.standard_error = {output.data(), PREFIX.size() + size + 1u},
		.complete_exit_code = 1,
	});
}

/**
 * @brief Format a user-friendly diagnostic for a failed gRPC call.
 *
 * @param status Final gRPC status.
 * @param endpoint Control-plane endpoint used by the command.
 * @return Multi-line diagnostic with an operator action hint.
 */
std::string format_error_message(const grpc::Status &status, const std::string &endpoint)
{
	std::string msg;
	const std::string detail = sanitized_diagnostic(status.error_message());
	switch (status.error_code()) {
	case grpc::StatusCode::UNAVAILABLE:
		msg = "Control plane unavailable at '" + endpoint +
		      "'.\n"
		      "  Details: " +
		      detail +
		      "\n"
		      "  Possible causes:\n"
		      "    - The service is not running or reachable\n"
		      "    - The service could not construct a trustworthy response\n"
		      "  How to fix:\n"
		      "    - Verify the service is running: systemctl status kinetum-cp\n"
		      "    - Check the endpoint address and port are correct\n"
		      "    - Check control plane logs for the reported detail";
		break;
	case grpc::StatusCode::DEADLINE_EXCEEDED:
		msg = "Request timed out: The control plane at '" + endpoint +
		      "' did not respond in time.\n"
		      "  Possible causes:\n"
		      "    - The service is overloaded or unresponsive\n"
		      "    - Network latency is too high\n"
		      "  How to fix:\n"
		      "    - Check service health and resource usage\n"
		      "    - Verify network connectivity and latency\n"
		      "    - Try again later after reducing service load";
		break;
	case grpc::StatusCode::PERMISSION_DENIED:
		msg = "Permission denied: Authentication or authorization failed.\n"
		      "  How to fix:\n"
		      "    - Verify TLS certificates are correct (--tls-ca, --tls-cert, --tls-key)\n"
		      "    - Ensure the client has proper access permissions";
		break;
	case grpc::StatusCode::UNAUTHENTICATED:
		msg = "Authentication failed: Invalid or missing credentials.\n"
		      "  How to fix:\n"
		      "    - Provide valid TLS certificates (--tls-ca, --tls-cert, --tls-key)\n"
		      "    - Verify certificate paths and permissions";
		break;
	case grpc::StatusCode::NOT_FOUND:
		msg = "Not found: The requested resource does not exist.\n"
		      "  How to fix:\n"
		      "    - Verify the resource identifier (e.g., snapshot_id) is correct\n"
		      "    - Use 'list-snapshots' to see available snapshots";
		break;
	case grpc::StatusCode::INVALID_ARGUMENT:
		msg = "Invalid argument: The request contains invalid parameters.\n"
		      "  Details: " +
		      detail +
		      "\n"
		      "  How to fix:\n"
		      "    - Check the command syntax and parameter values\n"
		      "    - Use --help for usage information";
		break;
	case grpc::StatusCode::INTERNAL:
		msg = "Internal error: The control plane encountered an unexpected error.\n"
		      "  Details: " +
		      detail +
		      "\n"
		      "  How to fix:\n"
		      "    - Check control plane logs for more details\n"
		      "    - Report the issue if it persists";
		break;
	default:
		msg = "gRPC error [" + std::to_string(static_cast<int>(status.error_code())) + "]: " + detail;
		break;
	}
	return msg;
}

/** @brief Exact output encoding selected independently for each command. */
enum class command_output_format : uint8_t {
	TEXT = 0,  ///< Canonical protobuf text.
	JSON = 1,  ///< Protobuf JSON with source field names.
};

/**
 * @brief Parse one command-local output-format value.
 * @param value Candidate `text` or `json` spelling.
 * @param[out] format Replaced only on success.
 * @return true for one declared spelling.
 */
[[nodiscard]] bool parse_output_format(std::string_view value, command_output_format *format) noexcept
{
	if (format == nullptr) {
		return false;
	}
	if (value == "text") {
		*format = command_output_format::TEXT;
		return true;
	}
	if (value == "json") {
		*format = command_output_format::JSON;
		return true;
	}
	return false;
}

/**
 * @brief Encode one fully validated successful response before output begins.
 * @param response Exact generated response.
 * @param format Selected output encoding.
 * @return Complete encoded bytes, or the encoding failure.
 */
[[nodiscard]] kinetum::common::status_or<std::string> encode_success_response(const google::protobuf::Message &response,
									      command_output_format format)
{
	if (format == command_output_format::TEXT) {
		return kinetum::common::print_pbtxt_text(response);
	}
	google::protobuf::util::JsonPrintOptions options;
	options.preserve_proto_field_names = true;
	options.always_print_primitive_fields = true;
	options.add_whitespace = true;
	std::string output;
	const auto converted = google::protobuf::util::MessageToJsonString(response, &output, options);
	if (!converted.ok()) {
		return kinetum::common::status::internal_error("failed to encode exact command response as JSON");
	}
	if (output.empty() || output.back() != '\n') {
		output.push_back('\n');
	}
	return output;
}

/**
 * @brief Emit one already validated success through a single stdout write.
 * @param response Exact generated response.
 * @param format Selected output encoding.
 * @return true after complete encoding and emission; false with stderr only.
 */
bool emit_success_response(const google::protobuf::Message &response, command_output_format format)
{
	auto encoded_or = encode_success_response(response, format);
	if (!encoded_or.is_ok()) {
		std::cerr << "failed to encode exact command response\n";
		return false;
	}
	const std::string &encoded = encoded_or.value();
	if (std::cmp_greater(encoded.size(), std::numeric_limits<std::streamsize>::max())) {
		std::cerr << "encoded command response exceeds the stdout representation bound\n";
		return false;
	}
	return kinetum::common::emit_process_output({
		       .standard_output = encoded,
		       .standard_error = {},
		       .complete_exit_code = 0,
	       }) == 0;
}

/**
 * @brief Emit one bounded single-line application failure diagnostic.
 * @param operation Stable command name.
 * @param application Canonical non-success status.
 */
void report_application_failure(std::string_view operation, const kinetum::common::v1::Status &application)
{
	std::cerr << operation << " failed with application status " << application.code();
	if (!application.message().empty()) {
		const std::string sanitized = sanitized_diagnostic(application.message());
		std::cerr << ": ";
		std::cerr.write(sanitized.data(), static_cast<std::streamsize>(sanitized.size()));
	}
	std::cerr << "\n";
}

/**
 * @brief Emit one bounded single-line response-contract diagnostic.
 * @param operation Stable command name.
 * @param failure Exact local validation failure; remote bytes are not trusted.
 */
void report_contract_failure(std::string_view operation, const kinetum::common::status &failure)
{
	const std::string diagnostic = sanitized_diagnostic(failure.message());
	std::cerr << operation << " response rejected: ";
	std::cerr.write(diagnostic.data(), static_cast<std::streamsize>(diagnostic.size()));
	std::cerr << "\n";
}

/**
 * @brief Validate one successful GetGuardrails payload and its policy hash.
 * @param response Response whose envelope already admitted exact success.
 * @return OK for exact unconfigured or configured state; DATA_LOSS otherwise.
 */
[[nodiscard]] kinetum::common::status
validate_successful_guardrails_read(const kinetum::control::v1::GetGuardrailsResponse &response)
{
	if ((response.policy_generation() == 0u) != !response.has_policy() ||
	    (response.policy_generation() == 0u) != response.policy_hash().empty() ||
	    (response.policy_generation() != 0u &&
	     response.policy_hash().size() != kinetum::common::SHA256_DIGEST_SIZE)) {
		return kinetum::common::status::data_loss("guardrails read returned malformed identity");
	}
	if (!response.has_policy()) {
		return kinetum::common::status::ok();
	}
	const auto policy_status = kinetum::cp::validate_guardrails_policy(response.policy());
	if (!policy_status.is_ok()) {
		return kinetum::common::status::data_loss("guardrails read returned malformed policy");
	}
	auto bytes_or = kinetum::common::serialize_protobuf_deterministically(response.policy());
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	auto hash_or = kinetum::common::sha256_raw(bytes_or.value());
	if (!hash_or.is_ok() ||
	    response.policy_hash() != std::string(reinterpret_cast<const char *>(hash_or->data()), hash_or->size())) {
		return kinetum::common::status::data_loss("guardrails read returned contradictory policy identity");
	}
	return kinetum::common::status::ok();
}

/**
 * @brief Execute a gRPC call with retry logic and exponential backoff.
 *
 * Only retries on transient errors (UNAVAILABLE, DEADLINE_EXCEEDED).
 *
 * @param call_func Function that creates a new context and executes the gRPC call
 * @param max_retries Maximum number of retry attempts
 * @param initial_delay_ms Initial delay between retries in milliseconds
 * @return The final gRPC status after all retry attempts
 */
grpc::Status execute_with_retry(const std::function<grpc::Status()> &call_func, int max_retries, int initial_delay_ms)
{
	grpc::Status status;
	int64_t delay_ms = initial_delay_ms;

	for (int attempt = 0; attempt <= max_retries; ++attempt) {
		status = call_func();

		if (status.ok()) {
			return status;
		}

		// Only retry on transient errors
		if (!is_transient_error(status.error_code())) {
			return status;
		}

		// Don't sleep after the last attempt
		if (attempt < max_retries) {
			const std::string detail = sanitized_diagnostic(status.error_message());
			KINETUM_LOG_WARN("kinetumctl", "rpc.retry",
					 "Transient error (attempt {}/{}): {}. Retrying in {}ms...", attempt + 1,
					 max_retries + 1, detail, delay_ms);
			std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
			if (delay_ms <= MAX_RETRY_DELAY_MS / 2) {
				delay_ms *= 2;
			} else {
				delay_ms = MAX_RETRY_DELAY_MS;
			}
		}
	}

	return status;
}

/**
 * @brief Execute one statistics selection under one transport/application retry budget.
 * @param stub Exact ControlService client.
 * @param request Immutable selection retained across attempts.
 * @param endpoint Operator-facing address for the final transport diagnostic.
 * @param max_retries Number of additional attempts, already admitted in 0..100.
 * @param initial_delay_ms Admitted initial backoff, bounded by MAX_RETRY_DELAY_MS.
 * @param format Success encoding selected by the caller.
 * @return Zero after one complete success write; one after one terminal diagnostic.
 */
int execute_stats_command(kinetum::control::v1::ControlService::Stub &stub,
			  const kinetum::control::v1::StatsRequest &request, const std::string &endpoint,
			  int max_retries, int initial_delay_ms, command_output_format format)
{
	int64_t delay_ms = initial_delay_ms;
	for (int attempt = 0; attempt <= max_retries; ++attempt) {
		grpc::ClientContext context;
		set_deadline(context);
		kinetum::control::v1::StatsResponse response;
		const auto transport = stub.GetStats(&context, request, &response);
		if (!transport.ok()) {
			if (!is_transient_error(transport.error_code()) || attempt == max_retries) {
				std::cerr << "statistics transport failed: "
					  << sanitized_diagnostic(format_error_message(transport, endpoint)) << "\n";
				return 1;
			}
		} else {
			const auto application = kinetum::common::validate_control_response_envelope(
				response, response.status(), "StatsResponse");
			if (!application.is_ok()) {
				report_contract_failure("statistics", application.error());
				return 1;
			}
			const auto code = application.value();
			if (code == kinetum::common::status_code::OK) {
				const auto valid = kinetum::common::validate_successful_control_stats_response(
					response, request.selection());
				if (!valid.is_ok()) {
					report_contract_failure("statistics", valid);
					return 1;
				}
				return emit_success_response(response, format) ? 0 : 1;
			}
			if (response.has_active_config() || response.has_telemetry()) {
				std::cerr << "statistics failure retained telemetry payload\n";
				return 1;
			}
			if ((code != kinetum::common::status_code::UNAVAILABLE &&
			     code != kinetum::common::status_code::DEADLINE_EXCEEDED) ||
			    attempt == max_retries) {
				report_application_failure("statistics", response.status());
				return 1;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
		delay_ms = std::min<int64_t>(delay_ms * 2, MAX_RETRY_DELAY_MS);
	}
	std::terminate();
}

/**
 * @brief Print command-line usage.
 *
 * @param os Destination stream.
 */
void usage(std::ostream &os)
{
	os << "Usage:\n"
	   << "  kinetumctl --endpoint ip:port [--tls-ca ca.pem --tls-cert client.pem --tls-key client.key]\n"
	   << "            [--retries N] [--retry-delay ms]\n"
	   << "           stats [--format text|json] [--stage-stats] [--module-metrics]\n"
	   << "                 [--module-health] [--worker-epoch-stats] [--region-epoch-stats]\n"
	   << "                 [--boundary-epoch-stats] [--stream-stats]\n"
	   << "                 [--storage-domain-stats] [--port-stats] [--topology-stats]\n"
	   << "           set-config <pbtxt> [--confirm-timeout <ms>] [--expected-revision <n>]\n"
	   << "           confirm <snapshot_id> --epoch <n> --revision <n>\n"
	   << "           list-snapshots [--page-size <n>]  # 1..256, default 100\n"
	   << "           get-active\n"
	   << "           rollback <snapshot_id> [--modules <m1,m2,...>] [--expected-revision <n>]\n"
	   << "           guardrails on --poll-ms <ms> --window-ms <ms> --max-drop-ratio <r>\n"
	   << "                         --min-tx-ratio <r> [--min-packets <n>]\n"
	   << "           guardrails off|show\n"
	   << "           health [--service cp|dp]\n"
	   << "           Every command accepts --format text|json.\n"
	   << "\n"
	   << "Options:\n"
	   << "  --help               Show this help text and exit\n"
	   << "  --endpoint ip:port   Service endpoint (CP default: 127.0.0.1:50051; required for DP health)\n"
	   << "  --retries N          Retry attempts for transient failures (0..100, default: 3)\n"
	   << "  --retry-delay ms     Initial retry delay in ms (0..3600000, default: 1000)\n"
	   << "                       Delay doubles after each retry (exponential backoff)\n"
	   << "  --tls-ca ca.pem      CA certificate for TLS\n"
	   << "  --tls-cert cert.pem  Client certificate for TLS\n"
	   << "  --tls-key key.pem    Client private key for TLS\n"
	   << "                       If any TLS flag is supplied, TLS material must load successfully\n"
	   << "\n"
	   << "Commit-Confirmed Pattern:\n"
	   << "  Use --confirm-timeout with set-config to enable commit-confirmed mode.\n"
	   << "  Requires an existing active snapshot as rollback target.\n"
	   << "  The config will auto-rollback to that snapshot if not confirmed within the timeout.\n"
	   << "  Example:\n"
	   << "    kinetumctl set-config config.pbtxt --confirm-timeout 300000  # 5 minutes\n"
	   << "    # ... verify config is working ...\n"
	   << "    kinetumctl confirm <snapshot_id> --epoch <epoch> --revision <revision>\n"
	   << "\n"
	   << "Selective Rollback:\n"
	   << "  Use --modules with rollback to rollback specific modules only.\n"
	   << "  Other modules keep their current configuration.\n"
	   << "  Requires: Both snapshots must have the same module ID set.\n"
	   << "  Example:\n"
	   << "    kinetumctl rollback snap_v1 --modules acl,qos  # Rollback ACL and QoS only\n"
	   << "    kinetumctl rollback snap_v1                    # Full rollback (all modules)\n";
}

/**
 * @brief Compose complete usage bytes for the successful help operation.
 *
 * @return Complete usage text before any process output begins.
 */
[[nodiscard]] std::string render_usage()
{
	std::ostringstream output;
	output.exceptions(std::ios::badbit | std::ios::failbit);
	usage(output);
	return output.str();
}

}  // namespace

/**
 * @brief Entry point for the kinetumctl command-line client.
 *
 * Parses global options, opens the ControlService gRPC channel, dispatches one
 * command, prints command output, and exits. Usage errors return `2`,
 * operational failures return `1`, and successful commands return `0`.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit code: `0` for success, `1` for operational failure, and
 * `2` for usage errors.
 */
int main(int argc, char **argv)
{
	kinetum::common::set_command_log_identity("kinetumctl");
	try {
		std::string endpoint = "127.0.0.1:50051";
		bool endpoint_supplied = false;
		command_output_format out_format = command_output_format::TEXT;
		int max_retries = DEFAULT_RETRIES;
		int retry_delay_ms = DEFAULT_RETRY_DELAY_MS;
		kinetum::common::tls_client_config tls;
		bool tls_enabled = false;

		int i = 1;
		for (; i < argc; i++) {
			const std::string_view a = argv[i];
			std::string_view value;
			if (a == "--help") {
				const std::string output = render_usage();
				return kinetum::common::emit_process_output({
					.standard_output = output,
					.standard_error = {},
					.complete_exit_code = 0,
				});
			}
			if (a == "--endpoint") {
				if (!take_required_value(argc, argv, i, a, &value)) {
					return 2;
				}
				if (value.empty() || value.size() > 512u || value.front() == '-' ||
				    !std::all_of(value.begin(), value.end(), [](char character) {
					    const auto byte = static_cast<unsigned char>(character);
					    return byte >= 0x21u && byte <= 0x7eu;
				    })) {
					std::cerr << "--endpoint must be one bounded printable atom\n";
					return 2;
				}
				endpoint = std::string(value);
				endpoint_supplied = true;
			} else if (a == "--tls-ca") {
				if (!take_required_value(argc, argv, i, a, &value)) {
					return 2;
				}
				tls.ca_pem_path = std::string(value);
				tls_enabled = true;
			} else if (a == "--tls-cert") {
				if (!take_required_value(argc, argv, i, a, &value)) {
					return 2;
				}
				tls.cert_pem_path = std::string(value);
				tls_enabled = true;
			} else if (a == "--tls-key") {
				if (!take_required_value(argc, argv, i, a, &value)) {
					return 2;
				}
				tls.key_pem_path = std::string(value);
				tls_enabled = true;
			} else if (a == "--retries") {
				if (!take_required_value(argc, argv, i, a, &value)) {
					return 2;
				}
				if (!parse_int_arg(value, 0, MAX_RETRIES, &max_retries)) {
					std::cerr << "invalid --retries: " << value << " (expected 0.." << MAX_RETRIES
						  << ")\n";
					return 2;
				}
			} else if (a == "--retry-delay") {
				if (!take_required_value(argc, argv, i, a, &value)) {
					return 2;
				}
				if (!parse_int_arg(value, 0, MAX_RETRY_DELAY_MS, &retry_delay_ms)) {
					std::cerr << "invalid --retry-delay: " << value << " (expected 0.."
						  << MAX_RETRY_DELAY_MS << ")\n";
					return 2;
				}
			} else {
				break;
			}
		}

		if (i >= argc) {
			usage(std::cerr);
			return 2;
		}

		std::string cmd = argv[i++];
		bool health_dp = false;
		if (cmd == "health") {
			bool service_supplied = false;
			while (i < argc) {
				const std::string_view argument = argv[i];
				std::string_view value;
				if ((argument != "--format" && argument != "--service") ||
				    !take_required_value(argc, argv, i, argument, &value)) {
					std::cerr << "invalid health argument: " << argument << '\n';
					return 2;
				}
				if (argument == "--service") {
					if (service_supplied || (value != "cp" && value != "dp")) {
						std::cerr << "health requires one --service cp|dp selection\n";
						return 2;
					}
					service_supplied = true;
					health_dp = value == "dp";
				} else if (!parse_output_format(value, &out_format)) {
					std::cerr << "invalid --format: " << value << " (expected: text or json)\n";
					return 2;
				}
				++i;
			}
			if (health_dp && !endpoint_supplied) {
				std::cerr << "DP health requires an explicit --endpoint\n";
				return 2;
			}
		}
		auto grpc_logging_or = kinetum::common::grpc_logging::create();
		if (!grpc_logging_or.is_ok()) {
			KINETUM_LOG_ERROR("kinetumctl", "grpc.logging.failed", "{}", grpc_logging_or.error().message());
			return 1;
		}
		auto grpc_logging = std::move(grpc_logging_or).value();

		std::shared_ptr<grpc::ChannelCredentials> creds;
		if (tls_enabled) {
			creds = kinetum::common::make_channel_credentials(tls);
			if (!creds) {
				std::cerr
					<< "failed to configure TLS credentials; check --tls-ca/--tls-cert/--tls-key\n";
				return 1;
			}
		} else {
			creds = grpc::InsecureChannelCredentials();
		}
		auto chan = grpc::CreateChannel(endpoint, creds);
		if (health_dp) {
			auto dataplane = kinetum::dataplane::v1::DataplaneService::NewStub(chan);
			kinetum::dataplane::v1::HealthRequest request;
			kinetum::dataplane::v1::HealthResponse response;
			const auto transport = execute_with_retry(
				[&] {
					response.Clear();
					grpc::ClientContext context;
					set_deadline(context);
					return dataplane->Health(&context, request, &response);
				},
				max_retries, retry_delay_ms);
			if (!transport.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "dp.health.transport_failed",
						  "Data Plane health RPC failed at {}: {}", endpoint,
						  sanitized_diagnostic(transport.error_message()));
				return 1;
			}
			const auto admitted = kinetum::common::validate_dataplane_startup_health(response);
			if (!admitted.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "dp.health.rejected", "{}", admitted.error().message());
				return 1;
			}
			return emit_success_response(response, out_format) ? 0 : 1;
		}
		auto stub = kinetum::control::v1::ControlService::NewStub(chan);

		if (cmd == "stats") {
			// Parse optional flags for this command.
			bool include_stage_stats = false;
			bool include_module_metrics = false;
			bool include_module_health = false;
			bool include_worker_epoch_stats = false;
			bool include_region_epoch_stats = false;
			bool include_boundary_epoch_stats = false;
			bool include_stream_stats = false;
			bool include_storage_domain_stats = false;
			bool include_port_stats = false;
			bool include_topology_stats = false;
			while (i < argc) {
				const std::string_view f = argv[i];
				if (f == "--format") {
					std::string_view value;
					if (!take_required_value(argc, argv, i, f, &value)) {
						return 2;
					}
					++i;
					if (!parse_output_format(value, &out_format)) {
						std::cerr << "invalid --format: " << value
							  << " (expected: text or json)\n";
						return 2;
					}
				} else if (f == "--stage-stats") {
					include_stage_stats = true;
					++i;
				} else if (f == "--module-metrics") {
					include_module_metrics = true;
					++i;
				} else if (f == "--module-health") {
					include_module_health = true;
					++i;
				} else if (f == "--worker-epoch-stats") {
					include_worker_epoch_stats = true;
					++i;
				} else if (f == "--region-epoch-stats") {
					include_region_epoch_stats = true;
					++i;
				} else if (f == "--boundary-epoch-stats") {
					include_boundary_epoch_stats = true;
					++i;
				} else if (f == "--stream-stats") {
					include_stream_stats = true;
					++i;
				} else if (f == "--storage-domain-stats") {
					include_storage_domain_stats = true;
					++i;
				} else if (f == "--port-stats") {
					include_port_stats = true;
					++i;
				} else if (f == "--topology-stats") {
					include_topology_stats = true;
					++i;
				} else {
					std::cerr << "unknown arg: " << f << "\n";
					return 2;
				}
			}

			kinetum::control::v1::StatsRequest req;
			auto *selection = req.mutable_selection();
			selection->set_include_stage_stats(include_stage_stats);
			selection->set_include_module_metrics(include_module_metrics);
			selection->set_include_module_health(include_module_health);
			selection->set_include_worker_epoch_stats(include_worker_epoch_stats);
			selection->set_include_region_epoch_stats(include_region_epoch_stats);
			selection->set_include_boundary_epoch_stats(include_boundary_epoch_stats);
			selection->set_include_stream_stats(include_stream_stats);
			selection->set_include_storage_domain_stats(include_storage_domain_stats);
			selection->set_include_port_stats(include_port_stats);
			selection->set_include_topology_stats(include_topology_stats);
			return execute_stats_command(*stub, req, endpoint, max_retries, retry_delay_ms, out_format);
		}

		if (cmd == "set-config") {
			if (i >= argc) {
				usage(std::cerr);
				return 2;
			}
			std::string path = argv[i++];
			uint64_t confirm_timeout_ms = 0;
			std::optional<int64_t> expected_revision;

			// Parse the optional commit-confirmed timeout.
			while (i < argc) {
				const std::string_view a = argv[i];
				std::string_view value;
				if (a == "--confirm-timeout") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					++i;
					if (!parse_uint64_arg(value, &confirm_timeout_ms)) {
						std::cerr << "invalid --confirm-timeout: " << value << "\n";
						return 2;
					}
					if (confirm_timeout_ms > std::numeric_limits<uint32_t>::max()) {
						std::cerr << "--confirm-timeout exceeds maximum supported value\n";
						return 2;
					}
				} else if (a == "--expected-revision") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					int64_t parsed = 0;
					if (!parse_int64_arg(value, 0, kinetum::common::MAX_CONFIG_SNAPSHOT_REVISION,
							     &parsed)) {
						std::cerr << "invalid --expected-revision: " << value << "\n";
						return 2;
					}
					expected_revision = parsed;
					++i;
				} else if (a == "--format") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_output_format(value, &out_format)) {
						std::cerr << "invalid --format: " << value
							  << " (expected: text or json)\n";
						return 2;
					}
					++i;
				} else {
					std::cerr << "unknown arg: " << a << "\n";
					return 2;
				}
			}

			kinetum::control::v1::ConfigSnapshot snap;
			auto s = kinetum::common::read_pbtxt_file(path, kinetum::common::DEFAULT_MAX_FILE_SIZE, &snap);
			if (!s.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "snapshot.read_failed", "{}", s.message());
				return 1;
			}

			kinetum::control::v1::SetConfigSnapshotRequest req;
			*req.mutable_snapshot() = snap;
			auto key_or = kinetum::common::generate_transition_idempotency_key("kinetumctl");
			if (!key_or.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "request.key_failed", "{}", key_or.error().message());
				return 1;
			}
			req.set_idempotency_key(std::move(key_or).value());
			if (confirm_timeout_ms > 0) {
				req.set_confirm_timeout_ms(confirm_timeout_ms);
			}
			if (expected_revision.has_value()) {
				req.set_expected_revision(*expected_revision);
			}
			kinetum::control::v1::SetConfigSnapshotResponse resp;

			auto st = execute_with_retry(
				[&]() {
					resp.Clear();
					grpc::ClientContext ctx;
					set_deadline(ctx);
					return stub->SetConfigSnapshot(&ctx, req, &resp);
				},
				max_retries, retry_delay_ms);

			if (!st.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}", format_error_message(st, endpoint));
				return 1;
			}
			auto application_or = kinetum::common::validate_control_response_envelope(
				resp, resp.status(), "SetConfigSnapshotResponse");
			if (!application_or.is_ok()) {
				report_contract_failure("set-config", application_or.error());
				return 1;
			}
			if (application_or.value() != kinetum::common::status_code::OK) {
				if (!resp.snapshot_id().empty() || resp.revision() != 0 || resp.epoch() != 0u) {
					std::cerr << "set-config failure retained success fields\n";
					return 1;
				}
				report_application_failure("set-config", resp.status());
				return 1;
			}
			if (resp.snapshot_id() != snap.snapshot_id() || resp.revision() != snap.revision() ||
			    !kinetum::common::valid_epoch_id(resp.epoch())) {
				std::cerr << "set-config returned contradictory success identity\n";
				return 1;
			}
			return emit_success_response(resp, out_format) ? 0 : 1;
		}

		if (cmd == "list-snapshots") {
			uint32_t page_size = kinetum::common::DEFAULT_SNAPSHOT_LIST_PAGE_SIZE;
			while (i < argc) {
				const std::string_view argument = argv[i];
				std::string_view value;
				if (argument == "--page-size") {
					if (!take_required_value(argc, argv, i, argument, &value)) {
						return 2;
					}
					uint64_t parsed = 0u;
					if (!parse_uint64_arg(value, &parsed) || parsed == 0u ||
					    parsed > kinetum::common::MAX_SNAPSHOT_LIST_PAGE_SIZE) {
						std::cerr << "invalid --page-size: " << value << "\n";
						return 2;
					}
					page_size = static_cast<uint32_t>(parsed);
					++i;
				} else if (argument == "--format") {
					if (!take_required_value(argc, argv, i, argument, &value)) {
						return 2;
					}
					if (!parse_output_format(value, &out_format)) {
						std::cerr << "invalid --format: " << value
							  << " (expected: text or json)\n";
						return 2;
					}
					++i;
				} else {
					std::cerr << "unknown arg: " << argument << "\n";
					return 2;
				}
			}

			kinetum::control::v1::ListSnapshotsResponse complete;
			std::string page_token;
			std::string previous_id;
			std::optional<uint64_t> total_count;
			uint32_t active_count = 0u;
			for (;;) {
				kinetum::control::v1::ListSnapshotsRequest req;
				req.set_page_size(page_size);
				req.set_page_token(page_token);
				kinetum::control::v1::ListSnapshotsResponse resp;
				auto st = execute_with_retry(
					[&]() {
						resp.Clear();
						grpc::ClientContext ctx;
						set_deadline(ctx);
						return stub->ListSnapshots(&ctx, req, &resp);
					},
					max_retries, retry_delay_ms);
				if (!st.ok()) {
					KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}",
							  format_error_message(st, endpoint));
					return 1;
				}
				auto application_or = kinetum::common::validate_control_response_envelope(
					resp, resp.status(), "ListSnapshotsResponse");
				if (!application_or.is_ok()) {
					report_contract_failure("list-snapshots", application_or.error());
					return 1;
				}
				if (application_or.value() != kinetum::common::status_code::OK) {
					if (resp.snapshots_size() != 0 || !resp.next_page_token().empty() ||
					    resp.total_count() != 0u) {
						std::cerr << "list-snapshots failure retained success fields\n";
						return 1;
					}
					report_application_failure("list-snapshots", resp.status());
					return 1;
				}
				if (!total_count.has_value()) {
					if (resp.total_count() >
					    static_cast<uint64_t>(std::numeric_limits<int>::max())) {
						std::cerr << "list-snapshots exceeds the CLI representation bound\n";
						return 1;
					}
					total_count = resp.total_count();
				} else if (*total_count != resp.total_count()) {
					std::cerr << "list-snapshots total changed across pages\n";
					return 1;
				}
				if (resp.snapshots_size() == 0 && !resp.next_page_token().empty()) {
					std::cerr << "list-snapshots returned an empty nonterminal page\n";
					return 1;
				}
				if (resp.snapshots_size() > static_cast<int>(page_size)) {
					std::cerr << "list-snapshots exceeded the requested page bound\n";
					return 1;
				}
				for (const auto &snapshot : resp.snapshots()) {
					if (!kinetum::common::valid_config_snapshot_id(snapshot.snapshot_id()) ||
					    !kinetum::common::valid_config_snapshot_revision(snapshot.revision()) ||
					    snapshot.created_unix_ms() < 0 ||
					    (!previous_id.empty() && snapshot.snapshot_id() <= previous_id)) {
						std::cerr
							<< "list-snapshots returned malformed or unordered identity\n";
						return 1;
					}
					previous_id = snapshot.snapshot_id();
					active_count += snapshot.is_active() ? 1u : 0u;
					complete.add_snapshots()->CopyFrom(snapshot);
				}
				if (static_cast<uint64_t>(complete.snapshots_size()) > *total_count ||
				    active_count > 1u) {
					std::cerr << "list-snapshots returned contradictory page cardinality\n";
					return 1;
				}
				if (static_cast<uint64_t>(complete.snapshots_size()) == *total_count &&
				    !resp.next_page_token().empty()) {
					std::cerr << "list-snapshots returned continuation after the exact end\n";
					return 1;
				}
				if (resp.next_page_token().empty()) {
					break;
				}
				if (resp.next_page_token() == page_token ||
				    resp.next_page_token().size() >
					    kinetum::common::MAX_SNAPSHOT_LIST_PAGE_TOKEN_BYTES) {
					std::cerr << "list-snapshots returned a malformed continuation\n";
					return 1;
				}
				page_token = resp.next_page_token();
			}
			if (!total_count.has_value() ||
			    static_cast<uint64_t>(complete.snapshots_size()) != *total_count) {
				std::cerr << "list-snapshots omitted rows from the exact listing\n";
				return 1;
			}
			complete.set_total_count(*total_count);
			complete.mutable_status()->set_code(static_cast<int32_t>(kinetum::common::status_code::OK));
			complete.mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
			return emit_success_response(complete, out_format) ? 0 : 1;
		}

		if (cmd == "get-active") {
			while (i < argc) {
				const std::string_view argument = argv[i];
				std::string_view value;
				if (argument != "--format" || !take_required_value(argc, argv, i, argument, &value)) {
					if (argument != "--format") {
						std::cerr << "unknown arg: " << argument << "\n";
					}
					return 2;
				}
				if (!parse_output_format(value, &out_format)) {
					std::cerr << "invalid --format: " << value << " (expected: text or json)\n";
					return 2;
				}
				++i;
			}
			kinetum::control::v1::GetActiveSnapshotRequest req;
			kinetum::control::v1::GetActiveSnapshotResponse resp;
			auto st = execute_with_retry(
				[&]() {
					resp.Clear();
					grpc::ClientContext ctx;
					set_deadline(ctx);
					return stub->GetActiveSnapshot(&ctx, req, &resp);
				},
				max_retries, retry_delay_ms);
			if (!st.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}", format_error_message(st, endpoint));
				return 1;
			}
			auto application_or = kinetum::common::validate_control_response_envelope(
				resp, resp.status(), "GetActiveSnapshotResponse");
			if (!application_or.is_ok()) {
				report_contract_failure("get-active", application_or.error());
				return 1;
			}
			if (application_or.value() != kinetum::common::status_code::OK) {
				if (resp.has_snapshot()) {
					std::cerr << "get-active failure retained a snapshot\n";
					return 1;
				}
				report_application_failure("get-active", resp.status());
				return 1;
			}
			if (!resp.has_snapshot() ||
			    !kinetum::common::canonical_config_snapshot_from_terminal(resp.snapshot()).is_ok()) {
				std::cerr << "get-active returned malformed snapshot identity\n";
				return 1;
			}
			return emit_success_response(resp, out_format) ? 0 : 1;
		}

		if (cmd == "rollback") {
			// Usage: rollback <snapshot_id> [--modules <module1,module2,...>]
			// Selective rollback: only rollback specified modules.
			if (i >= argc) {
				usage(std::cerr);
				return 2;
			}
			std::string sid = argv[i++];
			if (!kinetum::common::valid_config_snapshot_id(sid)) {
				std::cerr << "rollback snapshot identity is malformed\n";
				return 2;
			}
			std::vector<std::string> module_ids;
			bool modules_seen = false;
			std::optional<int64_t> expected_revision;

			// Parse optional module, CAS, and output flags.
			while (i < argc) {
				const std::string_view a = argv[i];
				std::string_view value;
				if (a == "--modules") {
					if (modules_seen) {
						std::cerr << "--modules may be provided only once\n";
						return 2;
					}
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					std::string error;
					if (!parse_module_list(value, &module_ids, &error)) {
						std::cerr << error << "\n";
						return 2;
					}
					modules_seen = true;
					++i;
				} else if (a == "--expected-revision") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					int64_t parsed = 0;
					if (!parse_int64_arg(value, 0, kinetum::common::MAX_CONFIG_SNAPSHOT_REVISION,
							     &parsed)) {
						std::cerr << "invalid --expected-revision: " << value << "\n";
						return 2;
					}
					expected_revision = parsed;
					++i;
				} else if (a == "--format") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_output_format(value, &out_format)) {
						std::cerr << "invalid --format: " << value
							  << " (expected: text or json)\n";
						return 2;
					}
					++i;
				} else {
					std::cerr << "unknown arg: " << a << "\n";
					return 2;
				}
			}

			kinetum::control::v1::RollbackRequest req;
			req.set_snapshot_id(sid);
			auto key_or = kinetum::common::generate_transition_idempotency_key("kinetumctl");
			if (!key_or.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "request.key_failed", "{}", key_or.error().message());
				return 1;
			}
			req.set_idempotency_key(std::move(key_or).value());
			if (expected_revision.has_value()) {
				req.set_expected_revision(*expected_revision);
			}
			for (const auto &mod_id : module_ids) {
				req.add_module_ids(mod_id);
			}
			std::string expected_snapshot_id = sid;
			if (!module_ids.empty()) {
				auto expected_or = kinetum::common::derive_generated_snapshot_id({
					.domain = "kinetum-selective-rollback-snapshot-v1",
					.prefix = "selective_",
					.idempotency_key = req.idempotency_key(),
				});
				if (!expected_or.is_ok()) {
					KINETUM_LOG_ERROR("kinetumctl", "snapshot.resolve_failed", "{}",
							  expected_or.error().message());
					return 1;
				}
				expected_snapshot_id = std::move(expected_or).value();
			}
			kinetum::control::v1::RollbackResponse resp;

			auto st = execute_with_retry(
				[&]() {
					resp.Clear();
					grpc::ClientContext ctx;
					set_deadline(ctx);
					return stub->Rollback(&ctx, req, &resp);
				},
				max_retries, retry_delay_ms);

			if (!st.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}", format_error_message(st, endpoint));
				return 1;
			}
			auto application_or = kinetum::common::validate_control_response_envelope(resp, resp.status(),
												  "RollbackResponse");
			if (!application_or.is_ok()) {
				report_contract_failure("rollback", application_or.error());
				return 1;
			}
			if (application_or.value() != kinetum::common::status_code::OK) {
				if (!resp.new_snapshot_id().empty() || resp.new_revision() != 0 || resp.epoch() != 0u) {
					std::cerr << "rollback failure retained success fields\n";
					return 1;
				}
				report_application_failure("rollback", resp.status());
				return 1;
			}
			if (resp.new_snapshot_id() != expected_snapshot_id ||
			    !kinetum::common::valid_config_snapshot_revision(resp.new_revision()) ||
			    !kinetum::common::valid_epoch_id(resp.epoch())) {
				std::cerr << "rollback returned contradictory success identity\n";
				return 1;
			}
			return emit_success_response(resp, out_format) ? 0 : 1;
		}

		if (cmd == "confirm") {
			// Usage: confirm <snapshot_id> --epoch <n> --revision <n>
			// Confirms a pending configuration, preventing auto-rollback.
			if (i >= argc) {
				usage(std::cerr);
				return 2;
			}
			std::string sid = argv[i++];
			uint64_t epoch = 0;
			int64_t revision = 0;
			bool saw_epoch = false;
			bool saw_revision = false;

			// Parse the complete required confirmation identity.
			while (i < argc) {
				const std::string_view a = argv[i];
				std::string_view value;
				if (a == "--epoch") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_uint64_arg(value, &epoch)) {
						std::cerr << "invalid --epoch: " << value << "\n";
						return 2;
					}
					saw_epoch = true;
					++i;
				} else if (a == "--revision") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_int64_arg(value, 0, kinetum::common::MAX_CONFIG_SNAPSHOT_REVISION,
							     &revision)) {
						std::cerr << "invalid --revision: " << value << "\n";
						return 2;
					}
					saw_revision = true;
					++i;
				} else if (a == "--format") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_output_format(value, &out_format)) {
						std::cerr << "invalid --format: " << value
							  << " (expected: text or json)\n";
						return 2;
					}
					++i;
				} else {
					std::cerr << "unknown arg: " << a << "\n";
					return 2;
				}
			}
			if (!kinetum::common::valid_config_snapshot_id(sid) || !saw_epoch ||
			    !kinetum::common::valid_epoch_id(epoch) || !saw_revision) {
				std::cerr << "confirm requires exact --epoch and --revision\n";
				return 2;
			}

			kinetum::control::v1::ConfirmConfigRequest req;
			req.set_snapshot_id(sid);
			req.set_epoch(epoch);
			req.set_revision(revision);
			auto confirm_key_or =
				kinetum::common::generate_transition_idempotency_key("kinetumctl-confirm");
			if (!confirm_key_or.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "request.key_failed", "{}",
						  confirm_key_or.error().message());
				return 1;
			}
			req.set_idempotency_key(std::move(confirm_key_or).value());
			kinetum::control::v1::ConfirmConfigResponse resp;

			auto st = execute_with_retry(
				[&]() {
					resp.Clear();
					grpc::ClientContext ctx;
					set_deadline(ctx);
					return stub->ConfirmConfig(&ctx, req, &resp);
				},
				max_retries, retry_delay_ms);

			if (!st.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}", format_error_message(st, endpoint));
				return 1;
			}
			auto application_or = kinetum::common::validate_control_response_envelope(
				resp, resp.status(), "ConfirmConfigResponse");
			if (!application_or.is_ok()) {
				report_contract_failure("confirm", application_or.error());
				return 1;
			}

			if (application_or.value() == kinetum::common::status_code::OK) {
				if (resp.snapshot_id() != sid || resp.epoch() != epoch || !resp.has_revision() ||
				    resp.revision() != revision || resp.time_remaining_ms() == 0u) {
					std::cerr << "confirm returned contradictory success identity\n";
					return 1;
				}
				return emit_success_response(resp, out_format) ? 0 : 1;
			}
			if (!resp.snapshot_id().empty() || resp.time_remaining_ms() != 0u || resp.epoch() != 0u ||
			    resp.has_revision()) {
				std::cerr << "confirm failure retained contradictory success fields\n";
				return 1;
			}
			report_application_failure("confirm", resp.status());
			return 1;
		}

		if (cmd == "guardrails") {
			// Usage:
			//   guardrails on --poll-ms <ms> --window-ms <ms> --max-drop-ratio <r> --min-tx-ratio <r>
			//   guardrails off|show
			if (i >= argc) {
				usage(std::cerr);
				return 2;
			}
			const std::string mode = argv[i++];
			if (mode == "show") {
				while (i < argc) {
					const std::string_view argument = argv[i];
					std::string_view value;
					if (argument != "--format" ||
					    !take_required_value(argc, argv, i, argument, &value)) {
						if (argument != "--format") {
							std::cerr << "unknown arg: " << argument << "\n";
						}
						return 2;
					}
					if (!parse_output_format(value, &out_format)) {
						std::cerr << "invalid --format: " << value
							  << " (expected: text or json)\n";
						return 2;
					}
					++i;
				}
				kinetum::control::v1::GetGuardrailsRequest request;
				kinetum::control::v1::GetGuardrailsResponse response;
				auto transport = execute_with_retry(
					[&]() {
						response.Clear();
						grpc::ClientContext context;
						set_deadline(context);
						return stub->GetGuardrails(&context, request, &response);
					},
					max_retries, retry_delay_ms);
				if (!transport.ok()) {
					KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}",
							  format_error_message(transport, endpoint));
					return 1;
				}
				auto application_or = kinetum::common::validate_control_response_envelope(
					response, response.status(), "GetGuardrailsResponse");
				if (!application_or.is_ok()) {
					report_contract_failure("guardrails show", application_or.error());
					return 1;
				}
				if (application_or.value() != kinetum::common::status_code::OK) {
					if (response.has_policy() || response.policy_generation() != 0u ||
					    !response.policy_hash().empty()) {
						std::cerr << "guardrails failure retained policy state\n";
						return 1;
					}
					report_application_failure("guardrails show", response.status());
					return 1;
				}
				const auto response_status = validate_successful_guardrails_read(response);
				if (!response_status.is_ok()) {
					report_contract_failure("guardrails show", response_status);
					return 1;
				}
				return emit_success_response(response, out_format) ? 0 : 1;
			}
			kinetum::control::v1::GuardrailsPolicy p;
			if (mode == "on") {
				p.set_enabled(true);
			} else if (mode == "off") {
				p.set_enabled(false);
			} else {
				std::cerr << "invalid guardrails mode: " << mode << " (expected: on, off, or show)\n";
				return 2;
			}

			bool saw_guardrails_option = false;
			bool saw_poll_ms = false;
			bool saw_window_ms = false;
			bool saw_max_drop_ratio = false;
			bool saw_min_tx_ratio = false;
			while (i < argc) {
				const std::string_view a = argv[i];
				std::string_view value;
				if (a == "--poll-ms") {
					saw_guardrails_option = true;
					int64_t parsed = 0;
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_int64_arg(value, 1, MAX_GUARDRAILS_POLL_MS, &parsed)) {
						std::cerr << "invalid --poll-ms: " << value << " (expected 1.."
							  << MAX_GUARDRAILS_POLL_MS << ")\n";
						return 2;
					}
					p.set_poll_interval_ms(static_cast<uint64_t>(parsed));
					saw_poll_ms = true;
					++i;
				} else if (a == "--window-ms") {
					saw_guardrails_option = true;
					int64_t parsed = 0;
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_int64_arg(value, 1, MAX_GUARDRAILS_WINDOW_MS, &parsed)) {
						std::cerr << "invalid --window-ms: " << value << " (expected 1.."
							  << MAX_GUARDRAILS_WINDOW_MS << ")\n";
						return 2;
					}
					p.set_evaluation_window_ms(static_cast<uint64_t>(parsed));
					saw_window_ms = true;
					++i;
				} else if (a == "--max-drop-ratio") {
					saw_guardrails_option = true;
					double parsed = 0.0;
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_double_arg(value, 0.0, 1.0, &parsed)) {
						std::cerr << "invalid --max-drop-ratio: " << value
							  << " (expected finite value in [0.0, 1.0])\n";
						return 2;
					}
					p.mutable_threshold()->set_max_drop_ratio(parsed);
					saw_max_drop_ratio = true;
					++i;
				} else if (a == "--min-tx-ratio") {
					saw_guardrails_option = true;
					double parsed = 0.0;
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_double_arg(value, 0.0, 1.0, &parsed)) {
						std::cerr << "invalid --min-tx-ratio: " << value
							  << " (expected finite value in [0.0, 1.0])\n";
						return 2;
					}
					p.mutable_threshold()->set_min_tx_ratio(parsed);
					saw_min_tx_ratio = true;
					++i;
				} else if (a == "--min-packets") {
					saw_guardrails_option = true;
					uint64_t parsed = 0;
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_uint64_arg(value, &parsed)) {
						std::cerr << "invalid --min-packets: " << value << "\n";
						return 2;
					}
					p.mutable_threshold()->set_min_packets_per_window(parsed);
					++i;
				} else if (a == "--format") {
					if (!take_required_value(argc, argv, i, a, &value)) {
						return 2;
					}
					if (!parse_output_format(value, &out_format)) {
						std::cerr << "invalid --format: " << value
							  << " (expected: text or json)\n";
						return 2;
					}
					++i;
				} else {
					std::cerr << "unknown arg: " << a << "\n";
					return 2;
				}
			}

			if (!p.enabled() && saw_guardrails_option) {
				std::cerr << "guardrails off does not accept policy flags\n";
				return 2;
			}
			if (p.enabled()) {
				if (!saw_poll_ms || !saw_window_ms || !saw_max_drop_ratio || !saw_min_tx_ratio) {
					std::cerr << "guardrails on requires --poll-ms, --window-ms, "
						     "--max-drop-ratio, and --min-tx-ratio\n";
					return 2;
				}
				if (p.evaluation_window_ms() < p.poll_interval_ms()) {
					std::cerr << "--window-ms must be >= --poll-ms\n";
					return 2;
				}
				const uint64_t required_intervals =
					p.evaluation_window_ms() / p.poll_interval_ms() +
					(p.evaluation_window_ms() % p.poll_interval_ms() != 0u ? 1u : 0u);
				if (required_intervals > GUARDRAILS_HISTORY_CAPACITY) {
					std::cerr << "guardrails window requires more than "
						  << GUARDRAILS_HISTORY_CAPACITY
						  << " retained intervals at the selected poll cadence\n";
					return 2;
				}
				p.set_telemetry_history_capacity(GUARDRAILS_HISTORY_CAPACITY);
				auto *attribution = p.mutable_attribution();
				attribution->set_auto_rollback_threshold(GUARDRAILS_AUTO_ROLLBACK_THRESHOLD);
				attribution->set_defer_threshold(GUARDRAILS_DEFER_THRESHOLD);
				attribution->set_baseline_samples(GUARDRAILS_BASELINE_SAMPLES);
				attribution->set_degradation_threshold(GUARDRAILS_ATTRIBUTION_DEGRADATION);
			}
			const auto policy_status = kinetum::cp::validate_guardrails_policy(p);
			if (!policy_status.is_ok()) {
				std::cerr << "guardrails policy is not internally coherent\n";
				return 2;
			}
			auto policy_bytes_or = kinetum::common::serialize_protobuf_deterministically(p);
			if (!policy_bytes_or.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "policy.encode_failed", "{}",
						  policy_bytes_or.error().message());
				return 1;
			}
			auto expected_policy_hash_or = kinetum::common::sha256_raw(policy_bytes_or.value());
			if (!expected_policy_hash_or.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "policy.hash_failed", "{}",
						  expected_policy_hash_or.error().message());
				return 1;
			}

			kinetum::control::v1::GetGuardrailsRequest current_request;
			kinetum::control::v1::GetGuardrailsResponse current_response;
			auto current_status = execute_with_retry(
				[&]() {
					current_response.Clear();
					grpc::ClientContext ctx;
					set_deadline(ctx);
					return stub->GetGuardrails(&ctx, current_request, &current_response);
				},
				max_retries, retry_delay_ms);
			if (!current_status.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}",
						  format_error_message(current_status, endpoint));
				return 1;
			}
			auto current_application_or = kinetum::common::validate_control_response_envelope(
				current_response, current_response.status(), "GetGuardrailsResponse");
			if (!current_application_or.is_ok()) {
				report_contract_failure("guardrails generation read", current_application_or.error());
				return 1;
			}
			if (current_application_or.value() != kinetum::common::status_code::OK) {
				if (current_response.has_policy() || current_response.policy_generation() != 0u ||
				    !current_response.policy_hash().empty()) {
					std::cerr << "guardrails generation failure retained policy state\n";
					return 1;
				}
				report_application_failure("guardrails generation read", current_response.status());
				return 1;
			}
			const auto current_validation = validate_successful_guardrails_read(current_response);
			if (!current_validation.is_ok()) {
				std::cerr << "guardrails generation read failed exact validation\n";
				return 1;
			}
			auto policy_key_or =
				kinetum::common::generate_transition_idempotency_key("kinetumctl-guardrails");
			if (!policy_key_or.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "request.key_failed", "{}",
						  policy_key_or.error().message());
				return 1;
			}
			kinetum::control::v1::ConfigureGuardrailsRequest req;
			*req.mutable_policy() = p;
			req.set_idempotency_key(std::move(policy_key_or).value());
			req.set_expected_policy_generation(current_response.policy_generation());
			kinetum::control::v1::ConfigureGuardrailsResponse resp;

			auto st = execute_with_retry(
				[&]() {
					resp.Clear();
					grpc::ClientContext ctx;
					set_deadline(ctx);
					return stub->ConfigureGuardrails(&ctx, req, &resp);
				},
				max_retries, retry_delay_ms);

			if (!st.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}", format_error_message(st, endpoint));
				return 1;
			}
			auto application_or = kinetum::common::validate_control_response_envelope(
				resp, resp.status(), "ConfigureGuardrailsResponse");
			if (!application_or.is_ok()) {
				report_contract_failure("guardrails", application_or.error());
				return 1;
			}

			if (application_or.value() == kinetum::common::status_code::OK) {
				if (current_response.policy_generation() >= std::numeric_limits<uint64_t>::max() - 1u ||
				    resp.policy_generation() != current_response.policy_generation() + 1u ||
				    resp.policy_hash() !=
					    std::string(reinterpret_cast<const char *>(expected_policy_hash_or->data()),
							expected_policy_hash_or->size())) {
					std::cerr << "guardrails returned contradictory success identity\n";
					return 1;
				}
				return emit_success_response(resp, out_format) ? 0 : 1;
			}
			if (resp.policy_generation() != 0u || !resp.policy_hash().empty()) {
				std::cerr << "guardrails failure retained contradictory success fields\n";
				return 1;
			}
			report_application_failure("guardrails", resp.status());
			return 1;
		}

		if (cmd == "health") {
			kinetum::control::v1::HealthCheckRequest request;
			kinetum::control::v1::HealthCheckResponse response;
			const auto transport = execute_with_retry(
				[&]() {
					response.Clear();
					grpc::ClientContext context;
					set_deadline(context);
					return stub->HealthCheck(&context, request, &response);
				},
				max_retries, retry_delay_ms);
			if (!transport.ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "rpc.failed", "{}",
						  format_error_message(transport, endpoint));
				return 1;
			}
			const auto unknown = kinetum::common::reject_unknown_protobuf_fields_recursive(
				response, "HealthCheckResponse");
			const auto enums = kinetum::common::reject_invalid_protobuf_enum_values_recursive(
				response, "HealthCheckResponse");
			if (!unknown.is_ok() || !enums.is_ok()) {
				std::cerr << "health response failed exact envelope validation\n";
				return 1;
			}
			if (response.status() != kinetum::control::v1::HealthCheckResponse::STATUS_SERVING) {
				std::cerr << "control plane is not serving\n";
				return 1;
			}
			if (response.version() != kinetum::common::KINETUM_VERSION_STRING ||
			    response.uptime_seconds() < 0) {
				std::cerr << "health response returned contradictory runtime identity\n";
				return 1;
			}
			const auto logging_status = kinetum::common::validate_logging_status(response.logging());
			if (!logging_status.is_ok()) {
				KINETUM_LOG_ERROR("kinetumctl", "cp.health.logging_invalid", "{}",
						  logging_status.message());
				return 1;
			}
			return emit_success_response(response, out_format) ? 0 : 1;
		}

		usage(std::cerr);
		return 2;

	} catch (const std::bad_alloc &) {
		std::cerr << "Error: command processing exhausted memory\n";
		return 1;
	} catch (const std::length_error &) {
		std::cerr << "Error: command processing exceeded host size limits\n";
		return 1;
	} catch (const std::exception &e) {
		return report_terminal_exception(e.what());
	}
}
