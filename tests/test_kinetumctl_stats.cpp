// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_kinetumctl_stats.cpp
 * @brief Real-image tests for fail-closed statistics and mutation identity.
 * @author Fleming Patel
 *
 * These tests launch the exact built kinetumctl image with posix_spawn(),
 * connect it to an in-process fake ControlService, and capture stdout and
 * stderr independently. A failed or contradictory application status carries
 * poisoned statistics, proving the CLI rejects before either text or JSON
 * formatting and emits only one bounded diagnostic.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <grpcpp/grpcpp.h>
#include <google/protobuf/unknown_field_set.h>

#include "gen/kinetum/control/v1/control.grpc.pb.h"
#include "gen/kinetum/control/v1/control.pb.h"
#include "gen/kinetum/dataplane/v1/dataplane.grpc.pb.h"
#include "gen/kinetum/gluon/v1/plan.pb.h"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/application_status.hpp"
#include "src/common/epoch_transition_contract.hpp"
#include "src/common/protobuf_contract.hpp"
#include "src/common/sha256.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/common/version.hpp"

/** @brief Process environment inherited by isolated kinetumctl children. */
extern char **environ;

namespace kinetum::ctl
{
namespace
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/** @brief Maximum bytes retained from each child output stream. */
constexpr std::size_t MAX_CAPTURE_BYTES = 4096u;

/** @brief Maximum expected bounded application-status diagnostic. */
constexpr std::size_t MAX_STATS_DIAGNOSTIC_BYTES = 640u;

/** @brief Complete child/capture deadline for one real-image invocation. */
constexpr auto CHILD_CAPTURE_TIMEOUT = std::chrono::seconds(10);

/** @brief Maximum wait between child-state observations. */
constexpr auto CHILD_POLL_INTERVAL = std::chrono::milliseconds(50);

/** @brief Fake status shape returned by the exact ControlService method. */
enum class fake_status_shape : uint8_t {
	APPLICATION_FAILURE,		   ///< Canonical status-only application failure.
	APPLICATION_FAILURE_WITH_PAYLOAD,  ///< Application failure retaining forbidden success fields.
	MALFORMED_SUCCESS,		   ///< Zero code paired with a non-OK classification.
	VALID_SUCCESS,			   ///< Complete final shared telemetry payload.
};

/** @brief Unique local descriptor owner for child-process capture. */
class unique_fd {
    public:
	/**
	 * @brief Adopt one descriptor.
	 * @param descriptor Sole descriptor transferred into this guard, or -1.
	 */
	explicit unique_fd(int descriptor = -1) noexcept
		: descriptor_(descriptor)
	{
	}

	/** @brief Close the descriptor. */
	~unique_fd()
	{
		reset();
	}

	/** @brief Disable descriptor aliasing. */
	unique_fd(const unique_fd &) = delete;

	/** @brief Disable descriptor aliasing by assignment. */
	unique_fd &operator=(const unique_fd &) = delete;

	/**
	 * @brief Transfer one descriptor.
	 * @param other Source guard left empty after transfer.
	 */
	unique_fd(unique_fd &&other) noexcept
		: descriptor_(std::exchange(other.descriptor_, -1))
	{
	}

	/**
	 * @brief Replace this descriptor with another unique owner.
	 * @param other Source guard left empty after a distinct-owner transfer.
	 * @return This guard after closing its former descriptor and transferring ownership.
	 */
	unique_fd &operator=(unique_fd &&other) noexcept
	{
		if (this != &other) {
			reset();
			descriptor_ = std::exchange(other.descriptor_, -1);
		}
		return *this;
	}

	/** @return Borrowed descriptor, or -1 for an empty guard. */
	[[nodiscard]] int get() const noexcept
	{
		return descriptor_;
	}

	/** @brief Close the descriptor and leave this owner empty. */
	void reset() noexcept
	{
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
			descriptor_ = -1;
		}
	}

    private:
	int descriptor_{-1};  ///< Unique descriptor.
};

/** @brief RAII owner for one initialized posix_spawn action list. */
class spawn_file_actions {
    public:
	/** @brief Destroy the action list when initialization succeeded. */
	~spawn_file_actions()
	{
		if (initialized_) {
			(void)::posix_spawn_file_actions_destroy(&actions_);
		}
	}

	/** @brief Disable action-list aliasing. */
	spawn_file_actions(const spawn_file_actions &) = delete;

	/** @brief Disable action-list aliasing by assignment. */
	spawn_file_actions &operator=(const spawn_file_actions &) = delete;

	/** @brief Construct an uninitialized action-list owner. */
	spawn_file_actions() noexcept = default;

	/**
	 * @brief Initialize the owned POSIX action list exactly once.
	 * @return OK after initialization, or the duplicate-initialization/native failure.
	 */
	[[nodiscard]] status initialize()
	{
		if (initialized_) {
			return status::failed_precondition("spawn file actions were initialized twice");
		}
		const int error = ::posix_spawn_file_actions_init(&actions_);
		if (error != 0) {
			return status(status_code::INTERNAL_ERROR, "failed to initialize spawn file actions",
				      std::strerror(error));
		}
		initialized_ = true;
		return status::ok();
	}

	/**
	 * @brief Add one descriptor duplication action.
	 *
	 * @param source Parent descriptor inherited by the child.
	 * @param target Child descriptor receiving the duplicate.
	 * @return OK after exact action admission.
	 */
	[[nodiscard]] status add_dup2(int source, int target)
	{
		const int error = ::posix_spawn_file_actions_adddup2(&actions_, source, target);
		if (error != 0) {
			return status(status_code::INTERNAL_ERROR, "failed to add spawn descriptor duplication",
				      std::strerror(error));
		}
		return status::ok();
	}

	/**
	 * @brief Add one child-side descriptor close action.
	 *
	 * @param descriptor Descriptor closed before exec.
	 * @return OK after exact action admission.
	 */
	[[nodiscard]] status add_close(int descriptor)
	{
		const int error = ::posix_spawn_file_actions_addclose(&actions_, descriptor);
		if (error != 0) {
			return status(status_code::INTERNAL_ERROR, "failed to add spawn descriptor close",
				      std::strerror(error));
		}
		return status::ok();
	}

	/** @return Borrowed initialized POSIX action list, or nullptr before initialization. */
	[[nodiscard]] posix_spawn_file_actions_t *get() noexcept
	{
		return initialized_ ? &actions_ : nullptr;
	}

    private:
	posix_spawn_file_actions_t actions_{};	///< Exact POSIX action storage.
	bool initialized_{false};		///< Whether destruction is required.
};

/** @brief Complete bounded child-process observation. */
struct child_result {
	int exit_code{-1};		       ///< Normal exit code or 128 plus terminating signal.
	std::string standard_output;	       ///< Bounded exact stdout prefix.
	std::string standard_error;	       ///< Bounded exact stderr prefix.
	bool standard_output_overflow{false};  ///< Whether stdout exceeded its bound.
	bool standard_error_overflow{false};   ///< Whether stderr exceeded its bound.
};

/**
 * @brief Configure one parent read descriptor for bounded multiplexed capture.
 *
 * @param descriptor Pipe read descriptor.
 * @return OK after adding close-on-exec and nonblocking status.
 */
status configure_capture_descriptor(int descriptor)
{
	const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
	if (descriptor_flags < 0 || ::fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
		return status(status_code::INTERNAL_ERROR, "failed to configure capture descriptor ownership",
			      std::strerror(errno));
	}
	const int status_flags = ::fcntl(descriptor, F_GETFL);
	if (status_flags < 0 || ::fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) != 0) {
		return status(status_code::INTERNAL_ERROR, "failed to configure nonblocking child capture",
			      std::strerror(errno));
	}
	return status::ok();
}

/**
 * @brief Retain one bounded output prefix while draining the complete pipe.
 *
 * @param bytes Newly read bytes.
 * @param count Number of valid bytes.
 * @param[out] output Bounded retained prefix.
 * @param[out] overflow Set when any byte exceeds the bound.
 */
void append_bounded_output(const char *bytes, std::size_t count, std::string *output, bool *overflow)
{
	const std::size_t available = MAX_CAPTURE_BYTES - output->size();
	const std::size_t retained = std::min(available, count);
	output->append(bytes, retained);
	if (retained != count) {
		*overflow = true;
	}
}

/**
 * @brief Drain one ready nonblocking capture descriptor.
 *
 * @param descriptor Unique read descriptor.
 * @param[out] output Bounded retained bytes.
 * @param[out] overflow Whether bytes exceeded the bound.
 * @return OK after draining currently available bytes, including exact EOF.
 */
status drain_capture(unique_fd *descriptor, std::string *output, bool *overflow)
{
	std::array<char, 512> buffer{};
	for (;;) {
		const ssize_t count = ::read(descriptor->get(), buffer.data(), buffer.size());
		if (count > 0) {
			append_bounded_output(buffer.data(), static_cast<std::size_t>(count), output, overflow);
			continue;
		}
		if (count == 0) {
			descriptor->reset();
			return status::ok();
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return status::ok();
		}
		return status(status_code::INTERNAL_ERROR, "failed to read child output", std::strerror(errno));
	}
}

/**
 * @brief Stop and reap a spawned child after a test-harness capture failure.
 *
 * @param child Exact child process ID.
 */
void stop_and_reap(pid_t child) noexcept
{
	(void)::kill(child, SIGKILL);
	int wait_status = 0;
	while (::waitpid(child, &wait_status, 0) < 0 && errno == EINTR) {
	}
}

/**
 * @brief Observe one child without blocking the capture deadline.
 *
 * @param child Exact child process ID.
 * @param[out] wait_status Terminal wait status when reaped.
 * @param[out] reaped Set exactly once after terminal observation.
 * @return OK while running or after reaping; INTERNAL_ERROR on wait failure.
 */
status observe_child(pid_t child, int *wait_status, bool *reaped)
{
	if (*reaped) {
		return status::ok();
	}
	for (;;) {
		const pid_t waited = ::waitpid(child, wait_status, WNOHANG);
		if (waited == child) {
			*reaped = true;
			return status::ok();
		}
		if (waited == 0) {
			return status::ok();
		}
		if (errno == EINTR) {
			continue;
		}
		return status(status_code::INTERNAL_ERROR, "failed to observe exact kinetumctl child",
			      std::strerror(errno));
	}
}

/**
 * @brief Spawn the exact kinetumctl image and capture both output streams.
 *
 * No shell, PATH lookup, or inherited output descriptor can participate.
 * Both pipes are drained concurrently so a diagnostic regression cannot
 * deadlock the test behind the pipe capacity.
 *
 * @param endpoint Exact fake ControlService endpoint.
 * @param command_arguments Exact command and command-local arguments.
 * @param retries Exact transient transport retry count.
 * @param explicit_endpoint Whether the invocation supplies its endpoint explicitly.
 * @return Complete bounded observation, or a harness setup/capture error.
 */
status_or<child_result> run_kinetumctl(const std::string &endpoint, const std::vector<std::string> &command_arguments,
				       int retries, bool explicit_endpoint = true)
{
	if (command_arguments.empty() || retries < 0) {
		return status::invalid_argument("kinetumctl child requires one command and nonnegative retry count");
	}
	int stdout_pipe[2]{-1, -1};
	if (::pipe(stdout_pipe) != 0) {
		return status(status_code::INTERNAL_ERROR, "failed to create stdout capture pipe",
			      std::strerror(errno));
	}
	unique_fd stdout_read(stdout_pipe[0]);
	unique_fd stdout_write(stdout_pipe[1]);

	int stderr_pipe[2]{-1, -1};
	if (::pipe(stderr_pipe) != 0) {
		return status(status_code::INTERNAL_ERROR, "failed to create stderr capture pipe",
			      std::strerror(errno));
	}
	unique_fd stderr_read(stderr_pipe[0]);
	unique_fd stderr_write(stderr_pipe[1]);

	for (const int descriptor : {stdout_read.get(), stdout_write.get(), stderr_read.get(), stderr_write.get()}) {
		const int flags = ::fcntl(descriptor, F_GETFD);
		if (flags < 0 || ::fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0) {
			return status(status_code::INTERNAL_ERROR, "failed to make capture descriptor close-on-exec",
				      std::strerror(errno));
		}
	}
	const auto stdout_config_status = configure_capture_descriptor(stdout_read.get());
	if (!stdout_config_status.is_ok()) {
		return stdout_config_status;
	}
	const auto stderr_config_status = configure_capture_descriptor(stderr_read.get());
	if (!stderr_config_status.is_ok()) {
		return stderr_config_status;
	}

	spawn_file_actions actions;
	const auto initialize_status = actions.initialize();
	if (!initialize_status.is_ok()) {
		return initialize_status;
	}
	auto action_status = actions.add_dup2(stdout_write.get(), STDOUT_FILENO);
	if (!action_status.is_ok()) {
		return action_status;
	}
	action_status = actions.add_dup2(stderr_write.get(), STDERR_FILENO);
	if (!action_status.is_ok()) {
		return action_status;
	}
	for (const int descriptor : {stdout_read.get(), stdout_write.get(), stderr_read.get(), stderr_write.get()}) {
		action_status = actions.add_close(descriptor);
		if (!action_status.is_ok()) {
			return action_status;
		}
	}

	std::vector<std::string> arguments{KINETUM_PRODUCTION_CTL_PATH, "--retries", std::to_string(retries),
					   "--retry-delay", "1"};
	if (explicit_endpoint) {
		arguments.insert(arguments.end(), {"--endpoint", endpoint});
	}
	arguments.insert(arguments.end(), command_arguments.begin(), command_arguments.end());
	std::vector<char *> argument_pointers;
	argument_pointers.reserve(arguments.size() + 1u);
	for (auto &argument : arguments) {
		argument_pointers.push_back(argument.data());
	}
	argument_pointers.push_back(nullptr);

	pid_t child = -1;
	const int spawn_error = ::posix_spawn(&child, KINETUM_PRODUCTION_CTL_PATH, actions.get(), nullptr,
					      argument_pointers.data(), environ);
	if (spawn_error != 0) {
		return status(status_code::INTERNAL_ERROR, "failed to spawn exact kinetumctl image",
			      std::strerror(spawn_error));
	}
	stdout_write.reset();
	stderr_write.reset();

	child_result result;
	int wait_status = 0;
	bool child_reaped = false;
	const auto deadline = std::chrono::steady_clock::now() + CHILD_CAPTURE_TIMEOUT;
	while (stdout_read.get() >= 0 || stderr_read.get() >= 0 || !child_reaped) {
		const auto observation_status = observe_child(child, &wait_status, &child_reaped);
		if (!observation_status.is_ok()) {
			if (!child_reaped) {
				stop_and_reap(child);
			}
			return observation_status;
		}
		if (stdout_read.get() < 0 && stderr_read.get() < 0 && child_reaped) {
			break;
		}

		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			if (!child_reaped) {
				stop_and_reap(child);
			}
			return status::deadline_exceeded(
				"kinetumctl stats child or output capture exceeded its deadline");
		}
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
		const auto wait_interval = std::min(remaining, CHILD_POLL_INTERVAL);
		const int poll_timeout_ms = static_cast<int>(std::max<int64_t>(1, wait_interval.count()));
		std::array<struct pollfd, 2> descriptors{{
			{stdout_read.get(), POLLIN | POLLHUP, 0},
			{stderr_read.get(), POLLIN | POLLHUP, 0},
		}};
		int poll_result = 0;
		do {
			poll_result = ::poll(descriptors.data(), descriptors.size(), poll_timeout_ms);
		} while (poll_result < 0 && errno == EINTR);
		if (poll_result < 0) {
			const auto capture_error = status(status_code::INTERNAL_ERROR, "failed to poll child output",
							  std::strerror(errno));
			if (!child_reaped) {
				stop_and_reap(child);
			}
			return capture_error;
		}

		for (std::size_t index = 0; index < descriptors.size(); ++index) {
			if ((descriptors[index].revents & POLLNVAL) != 0) {
				if (!child_reaped) {
					stop_and_reap(child);
				}
				return status::internal_error("child capture descriptor became invalid");
			}
			if ((descriptors[index].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
				continue;
			}
			unique_fd *capture = index == 0u ? &stdout_read : &stderr_read;
			std::string *output = index == 0u ? &result.standard_output : &result.standard_error;
			bool *overflow = index == 0u ? &result.standard_output_overflow :
						       &result.standard_error_overflow;
			const auto drain_status = drain_capture(capture, output, overflow);
			if (!drain_status.is_ok()) {
				if (!child_reaped) {
					stop_and_reap(child);
				}
				return drain_status;
			}
		}
	}

	if (WIFEXITED(wait_status)) {
		result.exit_code = WEXITSTATUS(wait_status);
	} else if (WIFSIGNALED(wait_status)) {
		result.exit_code = 128 + WTERMSIG(wait_status);
	} else {
		return status::internal_error("kinetumctl child produced an unsupported wait status");
	}
	return result;
}

/**
 * @param endpoint Exact fixture Control Plane endpoint.
 * @param format Requested CLI statistics format.
 * @return Checked child output/status observation, or process-launch failure.
 */
status_or<child_result> run_kinetumctl_stats(const std::string &endpoint, std::string_view format)
{
	return run_kinetumctl(endpoint, {"stats", "--format", std::string(format)}, 0);
}

/** @brief One deterministic statistics attempt in a client retry regression. */
struct stats_reply {
	grpc::StatusCode transport{grpc::StatusCode::OK};	    ///< Native transport outcome.
	status_code application{status_code::OK};		    ///< Canonical application outcome.
	fake_status_shape shape{fake_status_shape::VALID_SUCCESS};  ///< Exact or adversarial response shape.
	bool unknown_field{false};				    ///< Deliberately malformed transient envelope.
};

/** @brief Fake ControlService returning exact and malformed statistics shapes. */
class poisoned_stats_service final : public kinetum::control::v1::ControlService::Service {
    public:
	/**
	 * @brief Return one configured status and payload relation.
	 *
	 * @param context gRPC server context; unused.
	 * @param request Statistics request; unused.
	 * @param response Response receiving the selected exact or contradictory shape.
	 * @return Transport success so application admission is the only gate.
	 */
	grpc::Status GetStats(grpc::ServerContext *context, const kinetum::control::v1::StatsRequest *request,
			      kinetum::control::v1::StatsResponse *response) override
	{
		(void)context;
		const auto ordinal = calls.fetch_add(1u, std::memory_order_relaxed);
		{
			std::lock_guard lock(mutex);
			selections.push_back(request->SerializeAsString());
		}
		response->Clear();
		const auto scripted = ordinal < script.size() ?
					      script[ordinal] :
					      stats_reply{.application = status_code::UNAVAILABLE,
							  .shape = shape.load(std::memory_order_acquire)};
		if (scripted.transport != grpc::StatusCode::OK) {
			return grpc::Status(scripted.transport, "scripted transport failure");
		}
		if (scripted.unknown_field) {
			response->GetReflection()->MutableUnknownFields(response)->AddVarint(99, 1u);
		}
		const auto selected = scripted.shape;
		if (selected == fake_status_shape::APPLICATION_FAILURE ||
		    selected == fake_status_shape::APPLICATION_FAILURE_WITH_PAYLOAD) {
			response->mutable_status()->set_code(static_cast<int32_t>(scripted.application));
			response->mutable_status()->set_error_code(
				kinetum::common::application_error_code(scripted.application));
			std::string message(2048u, 'x');
			message[0] = '\n';
			message[1] = static_cast<char>(0x1b);
			message[2] = '\t';
			message[3] = '\r';
			response->mutable_status()->set_message(std::move(message));
			if (selected == fake_status_shape::APPLICATION_FAILURE) {
				return grpc::Status::OK;
			}
		} else if (selected == fake_status_shape::MALFORMED_SUCCESS) {
			response->mutable_status()->set_code(0);
			response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_INTERNAL);
			response->mutable_status()->set_message("contradictory success");
		} else {
			response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
			response->mutable_active_config()->set_revision(1);
			response->mutable_active_config()->set_snapshot_id("snapshot.1");
			auto *telemetry = response->mutable_telemetry();
			auto *runtime = telemetry->mutable_runtime();
			runtime->set_runtime_generation(1u);
			runtime->set_status_publication_generation(1u);
			runtime->set_active_epoch(1u);
			runtime->set_minimum_retained_epoch(1u);
			runtime->set_last_activated_epoch(1u);
			runtime->set_active_workers(1u);
			runtime->set_expected_workers(1u);
			runtime->set_collection_monotonic_ns(100u);
			runtime->set_latest_bank_publication_monotonic_ns(90u);
			telemetry->mutable_engine()->set_rx_packets(10u);
			auto *transition = telemetry->mutable_transition();
			transition->set_publication_generation(1u);
			transition->set_state(kinetum::telemetry::v1::EPOCH_TRANSITION_STATE_IDLE);
			transition->set_active_epoch(1u);
			transition->set_allocated_epoch_high_watermark(1u);
			transition->set_mutation_sequence_high_watermark(1u);
			transition->set_plan_content_hash(std::string(32u, '\x01'));
			transition->set_active_validation_hash(std::string(32u, '\x02'));
			transition->set_participant_set_frozen(false);
			transition->set_execution_participant_count(1u);
			transition->set_region_count(1u);
			transition->set_source_participant_count(1u);
			transition->set_sink_participant_count(1u);
			transition->set_quiescence_reader_count(1u);
			for (int code = 1; code <= 13; ++code) {
				auto *counter = telemetry->mutable_protocol_faults()->add_counters();
				counter->set_code(static_cast<kinetum::telemetry::v1::EpochProtocolFaultCode>(code));
			}
			return grpc::Status::OK;
		}
		response->mutable_active_config()->set_revision(999);
		response->mutable_active_config()->set_snapshot_id("poisoned.snapshot");
		response->mutable_telemetry()->mutable_runtime()->set_active_epoch(999u);
		response->mutable_telemetry()->mutable_engine()->set_rx_packets(1u);
		response->mutable_telemetry()->add_stages()->set_stage_id("poisoned.stage");
		response->mutable_telemetry()->add_regions()->set_region_id(99);
		response->mutable_telemetry()->add_ports()->set_logical_name("poisoned.port");
		return grpc::Status::OK;
	}

	std::atomic<fake_status_shape> shape{fake_status_shape::APPLICATION_FAILURE};  ///< Next response status shape.
	std::atomic<uint32_t> calls{0u};					       ///< Completed GetStats calls.
	std::vector<stats_reply> script;      ///< Replies fixed before the next client invocation.
	std::mutex mutex;		      ///< Protects complete observed request bytes.
	std::vector<std::string> selections;  ///< Proves exact selection identity across all attempts.
};

/** @brief Fixture owning one in-process fake CP server. */
class KinetumctlStatsTest : public ::testing::Test {
    protected:
	/** @brief Start the fake on one OS-assigned loopback port. */
	void SetUp() override
	{
		grpc::ServerBuilder builder;
		int selected_port = 0;
		builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &selected_port);
		builder.RegisterService(&service_);
		server_ = builder.BuildAndStart();
		ASSERT_NE(server_, nullptr);
		ASSERT_GT(selected_port, 0);
		endpoint_ = "127.0.0.1:" + std::to_string(selected_port);
	}

	/** @brief Stop the fake after every spawned client has exited. */
	void TearDown() override
	{
		if (server_ != nullptr) {
			server_->Shutdown();
		}
	}

	/**
	 * @brief Require one status shape to reject before both output formatters.
	 *
	 * @param shape Exact fake status relation.
	 * @param expected_diagnostic Stable stderr fragment.
	 */
	void expect_rejected_before_formatters(fake_status_shape shape, std::string_view expected_diagnostic)
	{
		service_.shape.store(shape, std::memory_order_release);
		const uint32_t calls_before = service_.calls.load(std::memory_order_relaxed);
		for (const std::string_view format : {std::string_view("text"), std::string_view("json")}) {
			auto result_or = run_kinetumctl_stats(endpoint_, format);
			ASSERT_TRUE(result_or.is_ok()) << result_or.error().message();
			const auto &result = result_or.value();
			EXPECT_EQ(result.exit_code, 1);
			EXPECT_TRUE(result.standard_output.empty()) << result.standard_output;
			EXPECT_FALSE(result.standard_output_overflow);
			EXPECT_FALSE(result.standard_error_overflow);
			EXPECT_FALSE(result.standard_error.empty());
			EXPECT_LE(result.standard_error.size(), MAX_STATS_DIAGNOSTIC_BYTES);
			EXPECT_EQ(std::count(result.standard_error.begin(), result.standard_error.end(), '\n'), 1);
			EXPECT_EQ(result.standard_error.find('\r'), std::string::npos);
			EXPECT_EQ(result.standard_error.find('\t'), std::string::npos);
			EXPECT_EQ(result.standard_error.find(static_cast<char>(0x1b)), std::string::npos);
			EXPECT_NE(result.standard_error.find(expected_diagnostic), std::string::npos)
				<< result.standard_error;
		}
		EXPECT_EQ(service_.calls.load(std::memory_order_relaxed), calls_before + 2u);
	}

	poisoned_stats_service service_;	///< Exact fake service implementation.
	std::unique_ptr<grpc::Server> server_;	///< Owned in-process server.
	std::string endpoint_;			///< Exact loopback endpoint selected by gRPC.
};

/** @brief Verify ordinary and payload-bearing failures reach neither formatter. */
TEST_F(KinetumctlStatsTest, application_failure_rejects_before_text_and_json_formatters)
{
	expect_rejected_before_formatters(fake_status_shape::APPLICATION_FAILURE, "application status 14");
	expect_rejected_before_formatters(fake_status_shape::APPLICATION_FAILURE_WITH_PAYLOAD,
					  "statistics failure retained telemetry payload");
}

/** @brief Verify a contradictory success status reaches neither formatter. */
TEST_F(KinetumctlStatsTest, malformed_success_rejects_before_text_and_json_formatters)
{
	expect_rejected_before_formatters(fake_status_shape::MALFORMED_SUCCESS, "malformed application status");
}

/** @brief Verify both formatters expose the one final shared message shape. */
TEST_F(KinetumctlStatsTest, successful_stats_render_canonical_shared_telemetry)
{
	service_.shape.store(fake_status_shape::VALID_SUCCESS, std::memory_order_release);
	auto text_or = run_kinetumctl_stats(endpoint_, "text");
	ASSERT_TRUE(text_or.is_ok()) << text_or.error().message();
	EXPECT_EQ(text_or->exit_code, 0);
	EXPECT_TRUE(text_or->standard_error.empty());
	EXPECT_NE(text_or->standard_output.find("active_config {"), std::string::npos);
	EXPECT_NE(text_or->standard_output.find("telemetry {"), std::string::npos);
	EXPECT_EQ(text_or->standard_output.find("boundary_telemetry"), std::string::npos);

	auto json_or = run_kinetumctl_stats(endpoint_, "json");
	ASSERT_TRUE(json_or.is_ok()) << json_or.error().message();
	EXPECT_EQ(json_or->exit_code, 0);
	EXPECT_TRUE(json_or->standard_error.empty());
	EXPECT_NE(json_or->standard_output.find("\"active_config\""), std::string::npos);
	EXPECT_NE(json_or->standard_output.find("\"protocol_faults\""), std::string::npos);
	EXPECT_EQ(json_or->standard_output.find("\"markers_sent\""), std::string::npos);
}

/** @brief Transport and application transients consume one budget and recovered attempts stay silent. */
TEST_F(KinetumctlStatsTest, mixed_transients_share_one_budget_and_emit_success_once)
{
	service_.script = {
		{.transport = grpc::StatusCode::UNAVAILABLE},
		{.application = status_code::DEADLINE_EXCEEDED, .shape = fake_status_shape::APPLICATION_FAILURE},
		{.transport = grpc::StatusCode::DEADLINE_EXCEEDED},
		{},
	};
	const auto result = run_kinetumctl(endpoint_, {"stats", "--format", "json"}, 3);
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_EQ(result->exit_code, 0);
	EXPECT_TRUE(result->standard_error.empty()) << result->standard_error;
	EXPECT_EQ(service_.calls.load(), 4u);
	const auto first = result->standard_output.find("\"active_config\"");
	ASSERT_NE(first, std::string::npos);
	EXPECT_EQ(result->standard_output.find("\"active_config\"", first + 1u), std::string::npos);
	std::lock_guard lock(service_.mutex);
	ASSERT_EQ(service_.selections.size(), 4u);
	EXPECT_TRUE(std::all_of(service_.selections.begin(), service_.selections.end(),
				[&](const auto &request) { return request == service_.selections.front(); }));
}

/** @brief Exhaustion produces one bounded failure instead of restarting a second retry loop. */
TEST_F(KinetumctlStatsTest, mixed_retry_exhaustion_stops_at_the_shared_attempt_limit)
{
	service_.script = {
		{.application = status_code::UNAVAILABLE, .shape = fake_status_shape::APPLICATION_FAILURE},
		{.transport = grpc::StatusCode::UNAVAILABLE},
		{.application = status_code::DEADLINE_EXCEEDED, .shape = fake_status_shape::APPLICATION_FAILURE},
		{},
	};
	const auto result = run_kinetumctl(endpoint_, {"stats"}, 2);
	ASSERT_TRUE(result.is_ok()) << result.error().message();
	EXPECT_EQ(result->exit_code, 1);
	EXPECT_EQ(service_.calls.load(), 3u);
	EXPECT_TRUE(result->standard_output.empty());
	EXPECT_LE(result->standard_error.size(), MAX_STATS_DIAGNOSTIC_BYTES);
	EXPECT_EQ(std::count(result->standard_error.begin(), result->standard_error.end(), '\n'), 1);
	EXPECT_NE(result->standard_error.find("application status 4"), std::string::npos);
}

/** @brief Invalid transient envelopes and terminal application errors never use remaining attempts. */
TEST_F(KinetumctlStatsTest, malformed_and_terminal_application_failures_never_retry)
{
	const std::array failures{
		stats_reply{.application = status_code::UNAVAILABLE,
			    .shape = fake_status_shape::APPLICATION_FAILURE_WITH_PAYLOAD},
		stats_reply{.application = status_code::UNAVAILABLE,
			    .shape = fake_status_shape::APPLICATION_FAILURE,
			    .unknown_field = true},
		stats_reply{.shape = fake_status_shape::MALFORMED_SUCCESS},
		stats_reply{.application = status_code::DATA_LOSS, .shape = fake_status_shape::APPLICATION_FAILURE},
		stats_reply{.application = status_code::CANCELLED, .shape = fake_status_shape::APPLICATION_FAILURE},
		stats_reply{.application = status_code::RESOURCE_EXHAUSTED,
			    .shape = fake_status_shape::APPLICATION_FAILURE},
		stats_reply{.application = status_code::PERMISSION_DENIED,
			    .shape = fake_status_shape::APPLICATION_FAILURE},
	};
	for (const auto &failure : failures) {
		service_.calls.store(0u);
		service_.script = {failure, {}};
		const auto result = run_kinetumctl(endpoint_, {"stats"}, 3);
		ASSERT_TRUE(result.is_ok()) << result.error().message();
		EXPECT_EQ(result->exit_code, 1);
		EXPECT_EQ(service_.calls.load(), 1u);
		EXPECT_TRUE(result->standard_output.empty());
		EXPECT_LE(result->standard_error.size(), MAX_STATS_DIAGNOSTIC_BYTES);
		EXPECT_EQ(std::count(result->standard_error.begin(), result->standard_error.end(), '\n'), 1);
	}
}

/** @brief Cancellation, authentication, and integrity transport errors remain terminal. */
TEST_F(KinetumctlStatsTest, terminal_transport_failures_never_retry)
{
	for (const auto code : {grpc::StatusCode::CANCELLED, grpc::StatusCode::UNAUTHENTICATED,
				grpc::StatusCode::DATA_LOSS, grpc::StatusCode::PERMISSION_DENIED}) {
		service_.calls.store(0u);
		service_.script = {{.transport = code}, {}};
		const auto result = run_kinetumctl(endpoint_, {"stats"}, 3);
		ASSERT_TRUE(result.is_ok()) << result.error().message();
		EXPECT_EQ(result->exit_code, 1);
		EXPECT_EQ(service_.calls.load(), 1u);
		EXPECT_TRUE(result->standard_output.empty());
		EXPECT_LE(result->standard_error.size(), MAX_STATS_DIAGNOSTIC_BYTES);
		EXPECT_EQ(std::count(result->standard_error.begin(), result->standard_error.end(), '\n'), 1);
	}
}

/** @brief CP fake that forces one transport retry and records exact mutation keys. */
class retrying_set_config_service final : public kinetum::control::v1::ControlService::Service {
    public:
	/**
	 * @brief Record mutation keys and inject one transport retry before an application response.
	 * @param request Borrowed mutation attempt.
	 * @param response Output carrying the exact or deliberately malformed application result after the retry.
	 * @return INVALID_ARGUMENT for null input, UNAVAILABLE on the first attempt, then transport OK.
	 */
	grpc::Status SetConfigSnapshot(grpc::ServerContext *,
				       const kinetum::control::v1::SetConfigSnapshotRequest *request,
				       kinetum::control::v1::SetConfigSnapshotResponse *response) override
	{
		if (request == nullptr || response == nullptr) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
		}
		const uint32_t call = calls.fetch_add(1u, std::memory_order_relaxed);
		{
			std::lock_guard<std::mutex> lock(mutex);
			keys.push_back(request->idempotency_key());
		}
		if (call == 0u) {
			return grpc::Status(grpc::StatusCode::UNAVAILABLE, "injected first transport failure");
		}
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(malformed_success.load(std::memory_order_acquire) ?
								   kinetum::common::v1::ERROR_CODE_UNSPECIFIED :
								   kinetum::common::v1::ERROR_CODE_OK);
		response->set_snapshot_id(request->snapshot().snapshot_id());
		response->set_revision(request->snapshot().revision());
		response->set_epoch(2u);
		return grpc::Status::OK;
	}

	std::atomic<uint32_t> calls{0u};	     ///< Completed handler entries.
	std::atomic<bool> malformed_success{false};  ///< Emit a contradictory success classification.
	std::mutex mutex;			     ///< Protects retained key observations.
	std::vector<std::string> keys;		     ///< Exact key from every transport attempt.
};

/** @brief Prove one key spans transport retries and malformed success fails closed. */
TEST(kinetumctl_mutation, generated_idempotency_key_is_stable_across_retry)
{
	retrying_set_config_service service;
	grpc::ServerBuilder builder;
	int selected_port = 0;
	builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &selected_port);
	builder.RegisterService(&service);
	auto server = builder.BuildAndStart();
	ASSERT_NE(server, nullptr);
	ASSERT_GT(selected_port, 0);

	const auto snapshot_path =
		std::filesystem::temp_directory_path() /
		("kinetumctl_transition_key_" + std::to_string(static_cast<uint64_t>(::getpid())) + ".pbtxt");
	{
		std::ofstream output(snapshot_path, std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(output.good());
		output << "snapshot_id: \"kinetumctl.retry\"\n"
		       << "revision: 2\n"
		       << "created_unix_ms: 2\n";
		output.close();
		ASSERT_TRUE(output.good());
	}
	const std::string endpoint = "127.0.0.1:" + std::to_string(selected_port);
	auto result_or = run_kinetumctl(endpoint, {"set-config", snapshot_path.string()}, 1);
	service.malformed_success.store(true, std::memory_order_release);
	auto malformed_or = run_kinetumctl(endpoint, {"set-config", snapshot_path.string()}, 0);
	std::error_code remove_error;
	(void)std::filesystem::remove(snapshot_path, remove_error);
	server->Shutdown();
	ASSERT_TRUE(result_or.is_ok()) << result_or.error().message();
	EXPECT_EQ(result_or->exit_code, 0) << result_or->standard_error;
	ASSERT_TRUE(malformed_or.is_ok()) << malformed_or.error().message();
	EXPECT_EQ(malformed_or->exit_code, 1);
	EXPECT_NE(malformed_or->standard_error.find("malformed application status"), std::string::npos);
	EXPECT_EQ(service.calls.load(std::memory_order_relaxed), 3u);
	std::lock_guard<std::mutex> lock(service.mutex);
	ASSERT_EQ(service.keys.size(), 3u);
	EXPECT_EQ(service.keys[0], service.keys[1]);
	EXPECT_TRUE(kinetum::common::validate_transition_idempotency_key(service.keys[0]).is_ok());
	EXPECT_TRUE(kinetum::common::validate_transition_idempotency_key(service.keys[2]).is_ok());
}

/** @brief CP fake recording exact guardrails and confirmation retry requests. */
class retrying_policy_service final : public kinetum::control::v1::ControlService::Service {
    public:
	/**
	 * @brief Return one exact unconfigured policy generation.
	 * @param context Borrowed gRPC context; unused.
	 * @param request Empty request; unused.
	 * @param response Destination response.
	 * @return Transport success.
	 */
	grpc::Status GetGuardrails(grpc::ServerContext *context,
				   const kinetum::control::v1::GetGuardrailsRequest *request,
				   kinetum::control::v1::GetGuardrailsResponse *response) override
	{
		(void)context;
		(void)request;
		if (response == nullptr) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null response");
		}
		response->Clear();
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		return grpc::Status::OK;
	}

	/**
	 * @brief Lose the first policy response and echo exact generation/hash next.
	 * @param context Borrowed gRPC context; unused.
	 * @param request Exact policy mutation request.
	 * @param response Destination response.
	 * @return Injected transient failure or exact transport success.
	 */
	grpc::Status ConfigureGuardrails(grpc::ServerContext *context,
					 const kinetum::control::v1::ConfigureGuardrailsRequest *request,
					 kinetum::control::v1::ConfigureGuardrailsResponse *response) override
	{
		(void)context;
		if (request == nullptr || response == nullptr) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
		}
		const uint32_t call = guardrails_calls.fetch_add(1u, std::memory_order_relaxed);
		{
			std::lock_guard<std::mutex> lock(mutex);
			guardrails_requests.push_back(*request);
		}
		if (call == 0u) {
			return grpc::Status(grpc::StatusCode::UNAVAILABLE, "injected guardrails response loss");
		}
		auto bytes_or = kinetum::common::serialize_protobuf_deterministically(request->policy());
		if (!bytes_or.is_ok()) {
			return grpc::Status(grpc::StatusCode::INTERNAL, "policy serialization failed");
		}
		auto hash_or = kinetum::common::sha256_raw(bytes_or.value());
		if (!hash_or.is_ok()) {
			return grpc::Status(grpc::StatusCode::INTERNAL, "policy hash failed");
		}
		response->Clear();
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_policy_generation(1u);
		if (corrupt_guardrails_hash.load(std::memory_order_acquire)) {
			response->set_policy_hash(std::string(hash_or->size(), '\x7f'));
		} else {
			response->set_policy_hash(reinterpret_cast<const char *>(hash_or->data()), hash_or->size());
		}
		return grpc::Status::OK;
	}

	/**
	 * @brief Lose the first confirmation response and exactly echo the retry.
	 * @param context Borrowed gRPC context; unused.
	 * @param request Exact confirmation request.
	 * @param response Destination response.
	 * @return Injected transient failure or exact transport success.
	 */
	grpc::Status ConfirmConfig(grpc::ServerContext *context,
				   const kinetum::control::v1::ConfirmConfigRequest *request,
				   kinetum::control::v1::ConfirmConfigResponse *response) override
	{
		(void)context;
		if (request == nullptr || response == nullptr) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null request or response");
		}
		const uint32_t call = confirm_calls.fetch_add(1u, std::memory_order_relaxed);
		{
			std::lock_guard<std::mutex> lock(mutex);
			confirm_requests.push_back(*request);
		}
		if (call == 0u) {
			return grpc::Status(grpc::StatusCode::UNAVAILABLE, "injected confirm response loss");
		}
		response->Clear();
		response->mutable_status()->set_code(0);
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_snapshot_id(request->snapshot_id());
		response->set_epoch(request->epoch());
		response->set_revision(request->revision());
		response->set_time_remaining_ms(zero_confirm_remaining.load(std::memory_order_acquire) ? 0u : 1u);
		return grpc::Status::OK;
	}

	std::atomic<uint32_t> guardrails_calls{0u};	   ///< Configure attempts.
	std::atomic<uint32_t> confirm_calls{0u};	   ///< Confirm attempts.
	std::atomic<bool> corrupt_guardrails_hash{false};  ///< Emit a contradictory success identity.
	std::atomic<bool> zero_confirm_remaining{false};   ///< Emit impossible zero remaining time on success.
	std::mutex mutex;				   ///< Protects complete request copies.
	std::vector<kinetum::control::v1::ConfigureGuardrailsRequest> guardrails_requests;  ///< Policy attempts.
	std::vector<kinetum::control::v1::ConfirmConfigRequest> confirm_requests;	    ///< Confirmation attempts.
};

/** @brief Real CLI retains one key and serializes every former policy default explicitly. */
TEST(kinetumctl_mutation, guardrails_policy_and_key_are_exact_across_transport_retry)
{
	retrying_policy_service service;
	grpc::ServerBuilder builder;
	int selected_port = 0;
	builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &selected_port);
	builder.RegisterService(&service);
	auto server = builder.BuildAndStart();
	ASSERT_NE(server, nullptr);
	ASSERT_GT(selected_port, 0);
	const std::string endpoint = "127.0.0.1:" + std::to_string(selected_port);
	auto result_or = run_kinetumctl(endpoint,
					{"guardrails", "on", "--poll-ms", "1000", "--window-ms", "30000",
					 "--max-drop-ratio", "0.05", "--min-tx-ratio", "0.70", "--min-packets", "1000"},
					1);
	auto oversized_window_or = run_kinetumctl(endpoint,
						  {"guardrails", "on", "--poll-ms", "1", "--window-ms", "101",
						   "--max-drop-ratio", "0.05", "--min-tx-ratio", "0.70"},
						  0);
	service.corrupt_guardrails_hash.store(true, std::memory_order_release);
	auto malformed_success_or = run_kinetumctl(endpoint,
						   {"guardrails", "on", "--poll-ms", "1000", "--window-ms", "30000",
						    "--max-drop-ratio", "0.05", "--min-tx-ratio", "0.70"},
						   0);
	server->Shutdown();
	ASSERT_TRUE(result_or.is_ok()) << result_or.error().message();
	EXPECT_EQ(result_or->exit_code, 0) << result_or->standard_error;
	ASSERT_TRUE(oversized_window_or.is_ok()) << oversized_window_or.error().message();
	EXPECT_EQ(oversized_window_or->exit_code, 2);
	EXPECT_NE(oversized_window_or->standard_error.find("requires more than 100 retained intervals"),
		  std::string::npos);
	ASSERT_TRUE(malformed_success_or.is_ok()) << malformed_success_or.error().message();
	EXPECT_EQ(malformed_success_or->exit_code, 1);
	EXPECT_TRUE(malformed_success_or->standard_output.empty());
	EXPECT_NE(malformed_success_or->standard_error.find("contradictory success identity"), std::string::npos);
	EXPECT_EQ(service.guardrails_calls.load(std::memory_order_relaxed), 3u);
	std::lock_guard<std::mutex> lock(service.mutex);
	ASSERT_EQ(service.guardrails_requests.size(), 3u);
	const auto &first = service.guardrails_requests.front();
	const auto &retry = service.guardrails_requests[1];
	EXPECT_EQ(first.SerializeAsString(), retry.SerializeAsString());
	EXPECT_TRUE(
		kinetum::common::validate_transition_idempotency_key(service.guardrails_requests[2].idempotency_key())
			.is_ok());
	EXPECT_TRUE(kinetum::common::validate_transition_idempotency_key(first.idempotency_key()).is_ok());
	EXPECT_TRUE(first.has_expected_policy_generation());
	EXPECT_EQ(first.expected_policy_generation(), 0u);
	EXPECT_EQ(first.policy().telemetry_history_capacity(), 100u);
	EXPECT_DOUBLE_EQ(first.policy().attribution().auto_rollback_threshold(), 0.80);
	EXPECT_DOUBLE_EQ(first.policy().attribution().defer_threshold(), 0.50);
	EXPECT_EQ(first.policy().attribution().baseline_samples(), 10u);
	EXPECT_DOUBLE_EQ(first.policy().attribution().degradation_threshold(), 0.30);
}

/** @brief Real CLI requires exact confirmation identity and retains one retry key. */
TEST(kinetumctl_mutation, confirmation_identity_and_key_are_exact_across_transport_retry)
{
	retrying_policy_service service;
	grpc::ServerBuilder builder;
	int selected_port = 0;
	builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &selected_port);
	builder.RegisterService(&service);
	auto server = builder.BuildAndStart();
	ASSERT_NE(server, nullptr);
	ASSERT_GT(selected_port, 0);
	const std::string endpoint = "127.0.0.1:" + std::to_string(selected_port);
	auto result_or = run_kinetumctl(endpoint, {"confirm", "snapshot.zero", "--epoch", "7", "--revision", "0"}, 1);
	auto reserved_epoch_or = run_kinetumctl(
		endpoint, {"confirm", "snapshot.zero", "--epoch", std::to_string(UINT64_MAX), "--revision", "0"}, 0);
	service.zero_confirm_remaining.store(true, std::memory_order_release);
	auto malformed_or =
		run_kinetumctl(endpoint, {"confirm", "snapshot.zero", "--epoch", "7", "--revision", "0"}, 0);
	server->Shutdown();
	ASSERT_TRUE(result_or.is_ok()) << result_or.error().message();
	EXPECT_EQ(result_or->exit_code, 0) << result_or->standard_error;
	ASSERT_TRUE(reserved_epoch_or.is_ok()) << reserved_epoch_or.error().message();
	EXPECT_EQ(reserved_epoch_or->exit_code, 2);
	ASSERT_TRUE(malformed_or.is_ok()) << malformed_or.error().message();
	EXPECT_EQ(malformed_or->exit_code, 1);
	EXPECT_EQ(service.confirm_calls.load(std::memory_order_relaxed), 3u);
	std::lock_guard<std::mutex> lock(service.mutex);
	ASSERT_EQ(service.confirm_requests.size(), 3u);
	EXPECT_EQ(service.confirm_requests[0].SerializeAsString(), service.confirm_requests[1].SerializeAsString());
	EXPECT_EQ(service.confirm_requests[0].snapshot_id(), "snapshot.zero");
	EXPECT_EQ(service.confirm_requests[0].epoch(), 7u);
	EXPECT_TRUE(service.confirm_requests[0].has_revision());
	EXPECT_EQ(service.confirm_requests[0].revision(), 0);
	EXPECT_TRUE(kinetum::common::validate_transition_idempotency_key(service.confirm_requests[0].idempotency_key())
			    .is_ok());
}

/** @brief CP fake providing exact success for the remaining CLI commands. */
class complete_cli_surface_service final : public kinetum::control::v1::ControlService::Service {
    public:
	/**
	 * @brief Return one of two exact listing pages.
	 * @param request Borrowed page-size-one listing request with the fixture's page token.
	 * @param response Output receiving one fixture row and any continuation token.
	 * @return Transport OK for a known page, otherwise INVALID_ARGUMENT.
	 */
	grpc::Status ListSnapshots(grpc::ServerContext *, const kinetum::control::v1::ListSnapshotsRequest *request,
				   kinetum::control::v1::ListSnapshotsResponse *response) override
	{
		if (request == nullptr || response == nullptr || request->page_size() != 1u) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "invalid listing request");
		}
		response->Clear();
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_total_count(2u);
		auto *row = response->add_snapshots();
		if (request->page_token().empty()) {
			row->set_snapshot_id("active.snapshot");
			row->set_revision(4);
			row->set_created_unix_ms(4);
			row->set_is_active(true);
			response->set_next_page_token("opaque-page-two");
		} else if (request->page_token() == "opaque-page-two") {
			row->set_snapshot_id("retained.snapshot");
			row->set_revision(3);
			row->set_created_unix_ms(3);
		} else {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "foreign listing token");
		}
		return grpc::Status::OK;
	}

	/**
	 * @brief Return one terminal canonical active snapshot.
	 * @param request Required non-null active-snapshot request.
	 * @param response Output receiving the canonical terminal fixture snapshot.
	 * @return Transport OK after canonicalization/admission, or the corresponding argument/internal failure.
	 */
	grpc::Status GetActiveSnapshot(grpc::ServerContext *,
				       const kinetum::control::v1::GetActiveSnapshotRequest *request,
				       kinetum::control::v1::GetActiveSnapshotResponse *response) override
	{
		if (request == nullptr || response == nullptr) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null active request");
		}
		kinetum::control::v1::ConfigSnapshot candidate;
		candidate.set_snapshot_id("active.snapshot");
		candidate.set_revision(4);
		candidate.set_created_unix_ms(4);
		kinetum::gluon::v1::DeploymentPlan plan;
		auto canonical_or = kinetum::common::canonicalize_config_snapshot(candidate, plan);
		if (!canonical_or.is_ok()) {
			return grpc::Status(grpc::StatusCode::INTERNAL, "canonicalization failed");
		}
		response->Clear();
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		const auto admitted = kinetum::common::admit_terminal_config_snapshot(canonical_or.value(),
										      response->mutable_snapshot());
		return admitted.is_ok() ? grpc::Status::OK :
					  grpc::Status(grpc::StatusCode::INTERNAL, "terminal admission failed");
	}

	/**
	 * @brief Echo one exact full rollback result.
	 * @param request Borrowed request selecting the rollback snapshot.
	 * @param response Output receiving the selected snapshot, fixed new revision, and exact epoch.
	 * @return Transport OK for valid pointers, otherwise INVALID_ARGUMENT.
	 */
	grpc::Status Rollback(grpc::ServerContext *, const kinetum::control::v1::RollbackRequest *request,
			      kinetum::control::v1::RollbackResponse *response) override
	{
		if (request == nullptr || response == nullptr) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null rollback request");
		}
		response->Clear();
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_new_snapshot_id(request->snapshot_id());
		response->set_new_revision(5);
		response->set_epoch(9u);
		return grpc::Status::OK;
	}

	/**
	 * @brief Return exact serving state and compiled product version.
	 * @param request Required non-null health request.
	 * @param response Output receiving serving state, compiled version, and explicit logging counters.
	 * @return Transport OK for valid pointers, otherwise INVALID_ARGUMENT.
	 */
	grpc::Status HealthCheck(grpc::ServerContext *, const kinetum::control::v1::HealthCheckRequest *request,
				 kinetum::control::v1::HealthCheckResponse *response) override
	{
		if (request == nullptr || response == nullptr) {
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "null health request");
		}
		response->Clear();
		response->set_status(kinetum::control::v1::HealthCheckResponse::STATUS_SERVING);
		response->set_version(kinetum::common::KINETUM_VERSION_STRING);
		response->set_uptime_seconds(1);
		auto *logging = response->mutable_logging();
		logging->set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_AVAILABLE);
		logging->set_accepted_records(0);
		logging->set_queue_rejections(0);
		logging->set_format_rejections(0);
		logging->set_unavailable_rejections(0);
		logging->set_undelivered_records(0);
		logging->set_write_failures(0);
		logging->set_console_failures(0);
		logging->set_truncated_records(0);
		logging->set_packet_thread_rejections(0);
		logging->set_delivery_timeouts(0);
		return grpc::Status::OK;
	}
};

/** @brief Prove every remaining ControlService command emits one exact result. */
TEST(kinetumctl_surface, listing_active_rollback_and_health_are_exact)
{
	complete_cli_surface_service service;
	grpc::ServerBuilder builder;
	int selected_port = 0;
	builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &selected_port);
	builder.RegisterService(&service);
	auto server = builder.BuildAndStart();
	ASSERT_NE(server, nullptr);
	ASSERT_GT(selected_port, 0);
	const std::string endpoint = "127.0.0.1:" + std::to_string(selected_port);
	const std::array<std::vector<std::string>, 4> COMMANDS{{
		{"list-snapshots", "--page-size", "1", "--format", "json"},
		{"get-active", "--format", "json"},
		{"rollback", "retained.snapshot", "--expected-revision", "4", "--format", "json"},
		{"health", "--format", "json"},
	}};
	for (const auto &command : COMMANDS) {
		auto result_or = run_kinetumctl(endpoint, command, 0);
		ASSERT_TRUE(result_or.is_ok()) << result_or.error().message();
		EXPECT_EQ(result_or->exit_code, 0) << result_or->standard_error;
		EXPECT_FALSE(result_or->standard_output.empty());
		EXPECT_TRUE(result_or->standard_error.empty()) << result_or->standard_error;
	}
	server->Shutdown();
}

/** @brief Exact DP health producer with independently selectable logging evidence. */
class dp_health_service final : public kinetum::dataplane::v1::DataplaneService::Service {
    public:
	/** @brief Negative fixtures omit required presence without changing packet readiness. */
	std::atomic<bool> omit_presence{false};
	/** @brief An unavailable logger is valid observation, never packet unavailability. */
	std::atomic<bool> unavailable{false};
	/**
	 * @brief Return a complete packet-ready identity with exact logging counters.
	 * @param response RPC-owned destination; negative fixtures alter only logging evidence.
	 * @return Successful transport with the fixture's exact typed observation.
	 */
	grpc::Status Health(grpc::ServerContext *, const kinetum::dataplane::v1::HealthRequest *,
			    kinetum::dataplane::v1::HealthResponse *response) override
	{
		response->mutable_status()->set_error_code(kinetum::common::v1::ERROR_CODE_OK);
		response->set_version(kinetum::common::KINETUM_VERSION_STRING);
		response->set_state(kinetum::dataplane::v1::HealthResponse::STATE_PACKET_READY);
		response->set_runtime_generation(1);
		response->set_active_epoch(1);
		response->set_active_workers(3);
		response->set_expected_workers(3);
		auto &logging = *response->mutable_logging();
		logging.set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_AVAILABLE);
		logging.set_accepted_records(0);
		logging.set_queue_rejections(0);
		logging.set_format_rejections(0);
		logging.set_unavailable_rejections(0);
		logging.set_undelivered_records(0);
		logging.set_write_failures(0);
		logging.set_console_failures(0);
		logging.set_truncated_records(0);
		logging.set_packet_thread_rejections(0);
		logging.set_delivery_timeouts(0);
		if (unavailable.load(std::memory_order_acquire)) {
			logging.set_destination(kinetum::common::v1::LoggingStatus::DESTINATION_STATE_UNAVAILABLE);
			logging.set_failure("append: errno=28");
			logging.set_write_failures(1);
		}
		if (omit_presence.load(std::memory_order_acquire)) {
			logging.clear_accepted_records();
		}
		return grpc::Status::OK;
	}
};

/** @brief DP health uses explicit authority, admits logging outage, and rejects missing counters. */
TEST(kinetumctl_surface, dp_health_validates_logging_without_changing_readiness)
{
	dp_health_service service;
	grpc::ServerBuilder builder;
	int selected_port = 0;
	builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &selected_port);
	builder.RegisterService(&service);
	auto server = builder.BuildAndStart();
	ASSERT_NE(server, nullptr);
	const std::string endpoint = "127.0.0.1:" + std::to_string(selected_port);
	const std::vector<std::string> COMMAND{"health", "--service", "dp", "--format", "json"};
	auto available = run_kinetumctl(endpoint, COMMAND, 0);
	service.unavailable.store(true, std::memory_order_release);
	auto unavailable = run_kinetumctl(endpoint, COMMAND, 0);
	service.omit_presence.store(true, std::memory_order_release);
	auto malformed = run_kinetumctl(endpoint, COMMAND, 0);
	auto implicit_endpoint = run_kinetumctl(endpoint, COMMAND, 0, false);
	server->Shutdown();
	ASSERT_TRUE(available.is_ok());
	EXPECT_EQ(available->exit_code, 0) << available->standard_error;
	EXPECT_NE(available->standard_output.find("STATE_PACKET_READY"), std::string::npos);
	ASSERT_TRUE(unavailable.is_ok());
	EXPECT_EQ(unavailable->exit_code, 0) << unavailable->standard_error;
	EXPECT_NE(unavailable->standard_output.find("DESTINATION_STATE_UNAVAILABLE"), std::string::npos);
	ASSERT_TRUE(malformed.is_ok());
	EXPECT_EQ(malformed->exit_code, 1);
	EXPECT_TRUE(malformed->standard_output.empty());
	ASSERT_TRUE(implicit_endpoint.is_ok());
	EXPECT_EQ(implicit_endpoint->exit_code, 2);
	EXPECT_TRUE(implicit_endpoint->standard_output.empty());
}

}  // namespace
}  // namespace kinetum::ctl
