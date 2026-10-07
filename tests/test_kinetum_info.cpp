// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_kinetum_info.cpp
 * @brief Real-image tests for component reporting and atomic kinetum-info output.
 * @author Fleming Patel
 *
 * These tests launch the exact built kinetum-info image with posix_spawn(),
 * capture stdout and stderr independently, and exercise output failure through
 * /dev/full. They do not substitute a test-only entry point for the production
 * parser, verifier, renderer, or emitter.
 */

#include <gtest/gtest.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/common/version.hpp"
#include "tooling/release/verification/runtime_verification.hpp"

#if !defined(KINETUM_PRODUCTION_INFO_PATH) || !defined(KINETUM_TEST_INFO_DPDK_VERSION) ||    \
	!defined(KINETUM_TEST_INFO_ENABLE_TLS) || !defined(KINETUM_TEST_INFO_ENABLE_MLIR) || \
	!defined(KINETUM_TEST_INFO_ENABLE_MLIR_DIALECT)
#error "kinetum-info tests require the exact production image and independent build facts"
#endif

/** @brief Process environment inherited by isolated kinetum-info children. */
extern char **environ;

namespace kinetum::release
{
namespace
{

/** Maximum bytes admitted from one captured output stream. */
constexpr std::size_t MAX_CAPTURE_BYTES = std::size_t{64} * 1024u;

/** Complete deadline for one production-image invocation. */
constexpr auto CHILD_TIMEOUT = std::chrono::seconds(10);

/** Maximum delay between child-state observations. */
constexpr auto CHILD_POLL_INTERVAL = std::chrono::milliseconds(10);

/** Exact output destination selected for one child stream. */
enum class stream_destination : uint8_t {
	CAPTURE,  ///< Capture complete bytes in a private regular file.
	FULL,	  ///< Route bytes to /dev/full to force a delivery failure.
};

/** Exact destination pair for one child response. */
struct output_destinations {
	stream_destination standard_output;  ///< Child stdout destination.
	stream_destination standard_error;   ///< Child stderr destination.
};

/** @brief Unique temporary directory owner for one test invocation group. */
class temporary_directory final {
    public:
	/** @brief Create one fresh directory through mkdtemp(). */
	temporary_directory()
	{
		std::string pattern = (std::filesystem::temp_directory_path() / "kinetum_info_test.XXXXXX").string();
		std::vector<char> writable(pattern.begin(), pattern.end());
		writable.push_back('\0');
		if (char *const created = ::mkdtemp(writable.data()); created != nullptr) {
			path_ = created;
		}
	}

	/** @brief Reclaim the exact temporary directory and its test artifacts. */
	~temporary_directory()
	{
		if (!path_.empty()) {
			std::error_code error;
			std::filesystem::remove_all(path_, error);
		}
	}

	/** @brief Disable duplicate cleanup ownership. */
	temporary_directory(const temporary_directory &) = delete;

	/** @brief Disable replacement of cleanup ownership. */
	temporary_directory &operator=(const temporary_directory &) = delete;

	/** @brief Disable moving so the cleanup identity remains stable. */
	temporary_directory(temporary_directory &&) = delete;

	/** @brief Disable move assignment of cleanup ownership. */
	temporary_directory &operator=(temporary_directory &&) = delete;

	/** @return Exact fresh directory, or an empty path on failure. */
	[[nodiscard]] const std::filesystem::path &path() const noexcept
	{
		return path_;
	}

    private:
	std::filesystem::path path_;  ///< Exact owned temporary directory.
};

/** @brief Restore fixture permissions even when an assertion or exception leaves the test. */
class directory_permissions_guard final {
    public:
	/**
	 * @brief Temporarily replace permissions on one fixture-owned directory.
	 * @param path Direct existing fixture directory.
	 * @param permissions Temporary permissions for the observation.
	 */
	directory_permissions_guard(std::filesystem::path path, std::filesystem::perms permissions)
		: path_(std::move(path))
		, original_(std::filesystem::status(path_).permissions())
	{
		std::filesystem::permissions(path_, permissions);
	}

	/** @brief Restore the original mode before the temporary-directory owner reclaims it. */
	~directory_permissions_guard()
	{
		std::error_code error;
		std::filesystem::permissions(path_, original_, error);
		if (error) {
			ADD_FAILURE() << "cannot restore fixture permissions: " << error.message();
		}
	}

	/** @brief Disable duplicate restoration ownership. */
	directory_permissions_guard(const directory_permissions_guard &) = delete;
	/** @brief Disable replacement of restoration ownership. */
	directory_permissions_guard &operator=(const directory_permissions_guard &) = delete;
	/** @brief Keep permission restoration in its original scope. */
	directory_permissions_guard(directory_permissions_guard &&) = delete;
	/** @brief Disable replacement through move assignment. */
	directory_permissions_guard &operator=(directory_permissions_guard &&) = delete;

    private:
	std::filesystem::path path_;	   ///< Fixture-owned directory whose mode is borrowed.
	std::filesystem::perms original_;  ///< Exact permissions restored on every exit.
};

/** @brief Scope-bound owner for one POSIX spawn file-action list. */
class spawn_file_actions final {
    public:
	/** @brief Initialize the action list and retain any initialization error. */
	spawn_file_actions() noexcept
		: error_(::posix_spawn_file_actions_init(&actions_))
		, initialized_(error_ == 0)
	{
	}

	/** @brief Destroy an action list only after successful initialization. */
	~spawn_file_actions()
	{
		if (initialized_) {
			(void)::posix_spawn_file_actions_destroy(&actions_);
		}
	}

	/** @brief Disable action-list aliasing. */
	spawn_file_actions(const spawn_file_actions &) = delete;

	/** @brief Disable action-list replacement. */
	spawn_file_actions &operator=(const spawn_file_actions &) = delete;

	/** @return First action-list error, or zero. */
	[[nodiscard]] int error() const noexcept
	{
		return error_;
	}

	/**
	 * @brief Add one exact child descriptor-open action.
	 *
	 * @param descriptor Child descriptor to replace.
	 * @param path Exact file or device path.
	 * @param flags Open flags applied in the child.
	 * @return Zero on success or the first POSIX error number.
	 */
	[[nodiscard]] int add_open(int descriptor, const std::filesystem::path &path, int flags) noexcept
	{
		if (error_ != 0) {
			return error_;
		}
		error_ = ::posix_spawn_file_actions_addopen(&actions_, descriptor, path.c_str(), flags, 0600);
		return error_;
	}

	/** @return Initialized actions for `posix_spawn()`, or null after failure. */
	[[nodiscard]] posix_spawn_file_actions_t *get() noexcept
	{
		return error_ == 0 ? &actions_ : nullptr;
	}

    private:
	posix_spawn_file_actions_t actions_{};	///< POSIX action storage.
	int error_{0};				///< First initialization/action error.
	bool initialized_{false};		///< Whether the action list must be destroyed.
};

/** @brief Complete observation from one exact production-image invocation. */
struct child_result {
	int exit_code{-1};	      ///< Normal process exit code or 128 plus signal.
	std::string standard_output;  ///< Complete bounded stdout bytes.
	std::string standard_error;   ///< Complete bounded stderr bytes.
	std::string harness_error;    ///< Test-owner setup or collection failure.
};

/**
 * @brief Construct one failed test-harness observation.
 *
 * @param diagnostic Complete harness diagnostic.
 * @return Failed observation with no process output claim.
 */
[[nodiscard]] child_result harness_failure(std::string diagnostic)
{
	child_result result;
	result.harness_error = std::move(diagnostic);
	return result;
}

/**
 * @brief Read one bounded regular capture file exactly.
 *
 * @param path Exact capture path.
 * @param[out] bytes Complete bytes on success.
 * @return Empty text on success or one harness diagnostic.
 */
[[nodiscard]] std::string read_capture(const std::filesystem::path &path, std::string *bytes)
{
	std::error_code error;
	const std::uintmax_t size = std::filesystem::file_size(path, error);
	if (error) {
		return "failed to stat child capture: " + error.message();
	}
	if (size > MAX_CAPTURE_BYTES) {
		return "child capture exceeded its exact bound";
	}
	std::ifstream stream(path, std::ios::binary);
	if (!stream) {
		return "failed to open child capture";
	}
	bytes->assign(static_cast<std::size_t>(size), '\0');
	stream.read(bytes->data(), static_cast<std::streamsize>(bytes->size()));
	if (stream.gcount() != static_cast<std::streamsize>(bytes->size()) || stream.bad()) {
		return "failed to read complete child capture";
	}
	return {};
}

/**
 * @brief Force-stop and reap a child whose bounded observation failed.
 *
 * @param child Exact live child identity.
 */
void stop_and_reap(pid_t child) noexcept
{
	(void)::kill(child, SIGKILL);
	int wait_status = 0;
	while (::waitpid(child, &wait_status, 0) < 0 && errno == EINTR) {
	}
}

/**
 * @brief Wait under one monotonic deadline for exact child termination.
 *
 * @param child Exact child identity.
 * @param[out] wait_status Terminal POSIX wait status.
 * @return Empty text after reaping or one harness diagnostic.
 */
[[nodiscard]] std::string wait_for_child(pid_t child, int *wait_status)
{
	const auto deadline = std::chrono::steady_clock::now() + CHILD_TIMEOUT;
	for (;;) {
		const pid_t waited = ::waitpid(child, wait_status, WNOHANG);
		if (waited == child) {
			return {};
		}
		if (waited < 0) {
			if (errno == EINTR) {
				continue;
			}
			return "failed to observe exact kinetum-info image";
		}

		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			stop_and_reap(child);
			return "kinetum-info image exceeded its test deadline";
		}
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
		const auto interval = remaining < CHILD_POLL_INTERVAL ? remaining : CHILD_POLL_INTERVAL;
		const int timeout_ms = static_cast<int>(interval.count() > 0 ? interval.count() : 1);
		int poll_result = 0;
		do {
			poll_result = ::poll(nullptr, 0, timeout_ms);
		} while (poll_result < 0 && errno == EINTR);
		if (poll_result < 0) {
			stop_and_reap(child);
			return "failed while waiting for exact kinetum-info image";
		}
	}
}

/**
 * @brief Launch the exact kinetum-info image and collect both streams.
 *
 * @param arguments Arguments following the image path.
 * @param destinations Exact stdout and stderr destinations.
 * @param artifacts Fresh directory owning capture files.
 * @return Complete process observation or an explicit harness error.
 */
[[nodiscard]] child_result run_kinetum_info(const std::vector<std::string> &arguments, output_destinations destinations,
					    const std::filesystem::path &artifacts)
{
	const std::filesystem::path stdout_path = artifacts / "stdout.txt";
	const std::filesystem::path stderr_path = artifacts / "stderr.txt";
	const std::filesystem::path full_path = "/dev/full";

	spawn_file_actions actions;
	int action_error = actions.error();
	if (action_error == 0) {
		action_error = actions.add_open(
			STDOUT_FILENO,
			destinations.standard_output == stream_destination::FULL ? full_path : stdout_path,
			destinations.standard_output == stream_destination::FULL ? O_WRONLY :
										   O_WRONLY | O_CREAT | O_TRUNC);
	}
	if (action_error == 0) {
		action_error = actions.add_open(
			STDERR_FILENO,
			destinations.standard_error == stream_destination::FULL ? full_path : stderr_path,
			destinations.standard_error == stream_destination::FULL ? O_WRONLY :
										  O_WRONLY | O_CREAT | O_TRUNC);
	}
	if (action_error != 0) {
		return harness_failure("failed to configure child output: " + std::string(std::strerror(action_error)));
	}

	std::vector<std::string> storage;
	storage.reserve(arguments.size() + 1u);
	storage.emplace_back(KINETUM_PRODUCTION_INFO_PATH);
	storage.insert(storage.end(), arguments.begin(), arguments.end());
	std::vector<char *> argv;
	argv.reserve(storage.size() + 1u);
	for (auto &argument : storage) {
		argv.push_back(argument.data());
	}
	argv.push_back(nullptr);

	pid_t child = -1;
	const int spawn_error =
		::posix_spawn(&child, KINETUM_PRODUCTION_INFO_PATH, actions.get(), nullptr, argv.data(), environ);
	if (spawn_error != 0) {
		return harness_failure("failed to spawn exact kinetum-info image: " +
				       std::string(std::strerror(spawn_error)));
	}

	int wait_status = 0;
	const std::string wait_error = wait_for_child(child, &wait_status);
	if (!wait_error.empty()) {
		return harness_failure(wait_error);
	}

	child_result result;
	if (WIFEXITED(wait_status)) {
		result.exit_code = WEXITSTATUS(wait_status);
	} else if (WIFSIGNALED(wait_status)) {
		result.exit_code = 128 + WTERMSIG(wait_status);
	}
	if (destinations.standard_output == stream_destination::CAPTURE) {
		result.harness_error = read_capture(stdout_path, &result.standard_output);
	}
	if (result.harness_error.empty() && destinations.standard_error == stream_destination::CAPTURE) {
		result.harness_error = read_capture(stderr_path, &result.standard_error);
	}
	return result;
}

/**
 * @brief Create one regular-file placeholder for presence inspection, not integrity verification.
 * @param prefix Fixture-owned installation root.
 * @param relative Exact resource path below the fixture root.
 * @return true after the file is fully written and closed.
 */
[[nodiscard]] bool write_presence_file(const std::filesystem::path &prefix, std::string_view relative)
{
	const auto path = prefix / std::filesystem::path(relative);
	std::error_code error;
	std::filesystem::create_directories(path.parent_path(), error);
	if (error) {
		return false;
	}
	std::ofstream output(path, std::ios::binary);
	output << "presence fixture\n";
	output.close();
	return !output.fail();
}

/**
 * @brief Create runtime path presence without claiming valid ELF or signed content.
 * @param prefix Fixture-owned installation root.
 * @return true after every verifier-declared runtime path exists.
 */
[[nodiscard]] bool stage_runtime_presence(const std::filesystem::path &prefix)
{
	for (const auto &artifact : expected_runtime_artifacts()) {
		if (!write_presence_file(prefix, artifact.relative_path)) {
			return false;
		}
	}
	return write_presence_file(prefix, RUNTIME_PAYLOAD_MANIFEST);
}

/**
 * @brief Create independently authored SDK metadata and exposed resource paths.
 * @param prefix Fixture-owned installation root.
 * @return true after all named resources exist; file contents remain unverified.
 */
[[nodiscard]] bool stage_sdk_presence(const std::filesystem::path &prefix)
{
	std::error_code error;
	std::filesystem::create_directories(prefix / "sdk/include/kinetum", error);
	if (error) {
		return false;
	}
	std::filesystem::create_directories(prefix / "sdk/examples", error);
	return !error && write_presence_file(prefix, "sdk/VERSION") &&
	       write_presence_file(prefix, "sdk/share/kinetum/release/sdk_payload_manifest.sha256") &&
	       write_presence_file(prefix, "sdk/lib/pkgconfig/kinetum.pc") &&
	       write_presence_file(prefix, "sdk/lib/cmake/Kinetum/KinetumConfig.cmake");
}

/**
 * @brief Compose the independent exact default-JSON oracle.
 *
 * @param prefix Exact explicit installation prefix supplied to the image.
 * @param runtime Expected runtime presence spelling.
 * @param sdk Expected SDK presence spelling.
 * @return Expected byte-for-byte default JSON response.
 */
[[nodiscard]] std::string expected_default_json(std::string_view prefix, std::string_view runtime = "not_installed",
						std::string_view sdk = "not_installed")
{
	std::string expected;
	expected += "{\n";
	expected += "  \"version\": \"";
	expected += kinetum::common::KINETUM_VERSION_STRING;
	expected += "\",\n";
	expected += "  \"dpdk_version\": \"" KINETUM_TEST_INFO_DPDK_VERSION "\",\n";
	expected += "  \"tls_enabled\": ";
	expected += KINETUM_TEST_INFO_ENABLE_TLS ? "true,\n" : "false,\n";
	expected += "  \"build_features\": {\n";
	expected += "    \"axiom_mlir_frontend\": ";
	expected += KINETUM_TEST_INFO_ENABLE_MLIR ? "true,\n" : "false,\n";
	expected += "    \"axiom_mlir_dialect\": ";
	expected += KINETUM_TEST_INFO_ENABLE_MLIR_DIALECT ? "true\n" : "false\n";
	expected += "  },\n";
	expected += "  \"platform_capabilities\": [\n";
	expected += "    \"coherent_runtime_telemetry\",\n";
	expected += "    \"commit_confirmed\",\n";
	expected += "    \"durable_guardrails\",\n";
	expected += "    \"exact_bootstrap\",\n";
	expected += "    \"ordered_epoch_transitions\",\n";
	expected += "    \"owner_worker_module_health\",\n";
	expected += "    \"selective_rollback\",\n";
	expected += "    \"synchronous_active_stages\",\n";
	expected += "    \"tracked_async_epoch_work\"\n";
	expected += "  ],\n";
	expected += "  \"prefix\": \"";
	expected.append(prefix);
	expected += "\",\n";
	expected += "  \"installation\": {\"runtime\": \"";
	expected.append(runtime);
	expected += "\", \"sdk\": \"";
	expected.append(sdk);
	expected += "\"},\n";
	std::vector<std::pair<std::string_view, std::string_view>> paths;
	if (runtime == "installed") {
		paths.emplace_back("binaries", "/bin");
		paths.emplace_back("modules", "/lib/modules");
	}
	if (sdk == "installed") {
		paths.emplace_back("headers", "/sdk/include/kinetum");
		paths.emplace_back("examples", "/sdk/examples");
		paths.emplace_back("pkgconfig", "/sdk/lib/pkgconfig/kinetum.pc");
		paths.emplace_back("cmake", "/sdk/lib/cmake/Kinetum/KinetumConfig.cmake");
	}
	expected += "  \"paths\": {";
	for (std::size_t index = 0; index < paths.size(); ++index) {
		expected += index == 0u ? "\n" : ",\n";
		expected += "    \"";
		expected.append(paths[index].first);
		expected += "\": \"";
		expected.append(prefix);
		expected.append(paths[index].second);
		expected += "\"";
	}
	if (!paths.empty()) {
		expected += "\n  ";
	}
	expected += "}\n";
	expected += "}\n";
	return expected;
}

}  // namespace

/** @brief Prove ordinary default JSON remains byte-exact and fully delivered. */
TEST(kinetum_info, default_json_schema_and_bytes_are_exact)
{
	temporary_directory artifacts;
	ASSERT_FALSE(artifacts.path().empty());
	const std::string prefix = artifacts.path().string();
	const auto result = run_kinetum_info({"--json", "--prefix", prefix},
					     {.standard_output = stream_destination::CAPTURE,
					      .standard_error = stream_destination::CAPTURE},
					     artifacts.path());
	ASSERT_TRUE(result.harness_error.empty()) << result.harness_error;
	EXPECT_EQ(result.exit_code, 0);
	EXPECT_TRUE(result.standard_error.empty()) << result.standard_error;
	EXPECT_EQ(result.standard_output, expected_default_json(prefix));
	for (const auto &arguments : std::array<std::vector<std::string>, 2>{
		     {{"--prefix", "", "--json"}, {"--prefix", prefix, "--prefix", prefix, "--json"}}}) {
		const auto rejected = run_kinetum_info(arguments,
						       {.standard_output = stream_destination::CAPTURE,
							.standard_error = stream_destination::CAPTURE},
						       artifacts.path());
		ASSERT_TRUE(rejected.harness_error.empty()) << rejected.harness_error;
		EXPECT_EQ(rejected.exit_code, 2);
		EXPECT_TRUE(rejected.standard_output.empty());
		EXPECT_NE(rejected.standard_error.find("one nonempty argument"), std::string::npos);
	}

	const auto unicode_prefix = artifacts.path() / "unicode_\xc2\xa2_\xe2\x82\xac_\xf0\x9f\x98\x80";
	ASSERT_TRUE(std::filesystem::create_directory(unicode_prefix));
	const auto unicode = run_kinetum_info({"--json", "--prefix", unicode_prefix.string()},
					      {.standard_output = stream_destination::CAPTURE,
					       .standard_error = stream_destination::CAPTURE},
					      artifacts.path());
	ASSERT_TRUE(unicode.harness_error.empty()) << unicode.harness_error;
	EXPECT_EQ(unicode.exit_code, 0);
	EXPECT_TRUE(unicode.standard_error.empty());
	EXPECT_EQ(unicode.standard_output, expected_default_json(unicode_prefix.string()));

	for (const std::string_view invalid : {"\x80", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82"}) {
		const auto invalid_prefix = artifacts.path() / ("invalid_" + std::string(invalid));
		ASSERT_TRUE(std::filesystem::create_directory(invalid_prefix));
		for (const bool check : {false, true}) {
			std::vector<std::string> arguments{"--json", "--prefix", invalid_prefix.string()};
			if (check) {
				arguments.push_back("--check");
			}
			const auto rejected = run_kinetum_info(arguments,
							       {.standard_output = stream_destination::CAPTURE,
								.standard_error = stream_destination::CAPTURE},
							       artifacts.path());
			ASSERT_TRUE(rejected.harness_error.empty()) << rejected.harness_error;
			EXPECT_EQ(rejected.exit_code, 1);
			EXPECT_TRUE(rejected.standard_error.empty());
			EXPECT_EQ(rejected.standard_output,
				  "{\"status\": \"error\", \"message\": \"JSON output contains invalid UTF-8\"}\n");
		}
	}
}

/** @brief Report empty, runtime-only, SDK-only, and combined prefixes without invented paths. */
TEST(kinetum_info, component_presence_controls_text_and_json_paths)
{
	temporary_directory artifacts;
	ASSERT_FALSE(artifacts.path().empty());
	for (const bool runtime : {false, true}) {
		for (const bool sdk : {false, true}) {
			const auto prefix = artifacts.path() / (std::string(runtime ? "runtime" : "empty") +
								(sdk ? "_sdk" : "_without_sdk"));
			ASSERT_TRUE(std::filesystem::create_directory(prefix));
			if (runtime) {
				ASSERT_TRUE(stage_runtime_presence(prefix));
			}
			if (sdk) {
				ASSERT_TRUE(stage_sdk_presence(prefix));
			}
			const auto json = run_kinetum_info({"--json", "--prefix", prefix.string()},
							   {stream_destination::CAPTURE, stream_destination::CAPTURE},
							   artifacts.path());
			ASSERT_TRUE(json.harness_error.empty()) << json.harness_error;
			EXPECT_EQ(json.exit_code, 0);
			EXPECT_TRUE(json.standard_error.empty());
			EXPECT_EQ(json.standard_output,
				  expected_default_json(prefix.string(), runtime ? "installed" : "not_installed",
							sdk ? "installed" : "not_installed"));
			const auto text = run_kinetum_info({"--prefix", prefix.string()},
							   {stream_destination::CAPTURE, stream_destination::CAPTURE},
							   artifacts.path());
			ASSERT_TRUE(text.harness_error.empty()) << text.harness_error;
			EXPECT_EQ(text.exit_code, 0);
			EXPECT_TRUE(text.standard_error.empty());
			EXPECT_NE(text.standard_output.find(runtime ? "Runtime:     installed\n" :
								      "Runtime:     not installed\n"),
				  std::string::npos);
			EXPECT_NE(text.standard_output.find(sdk ? "SDK:         installed\n" :
								  "SDK:         not installed\n"),
				  std::string::npos);
			EXPECT_EQ(text.standard_output.find("Binaries:") != std::string::npos, runtime);
			EXPECT_EQ(text.standard_output.find("SDK Headers:") != std::string::npos, sdk);
			EXPECT_EQ(text.standard_output.find("Integration:") != std::string::npos, sdk);
		}
	}
}

/** @brief Report partial and indirect components without treating them as absent or installed. */
TEST(kinetum_info, incomplete_components_do_not_advertise_resource_paths)
{
	temporary_directory artifacts;
	ASSERT_FALSE(artifacts.path().empty());
	const auto prefix = artifacts.path() / "prefix";
	ASSERT_TRUE(std::filesystem::create_directory(prefix));
	ASSERT_TRUE(write_presence_file(prefix, "VERSION"));
	ASSERT_TRUE(std::filesystem::create_directory(prefix / "sdk"));
	for (const unsigned int variant : {0u, 1u, 2u, 3u, 4u}) {
		if (variant != 0u) {
			std::filesystem::remove_all(prefix / "sdk");
		}
		if (variant == 1u) {
			std::filesystem::create_directory_symlink(artifacts.path() / "absent", prefix / "sdk");
		} else if (variant == 2u) {
			ASSERT_TRUE(stage_sdk_presence(prefix));
			ASSERT_TRUE(std::filesystem::remove(prefix / "sdk/lib/pkgconfig/kinetum.pc"));
		} else if (variant == 3u) {
			ASSERT_TRUE(write_presence_file(prefix, "sdk"));
		} else if (variant == 4u) {
			ASSERT_TRUE(stage_sdk_presence(prefix));
			ASSERT_TRUE(std::filesystem::remove(prefix /
							    "sdk/share/kinetum/release/sdk_payload_manifest.sha256"));
		}
		const auto result = run_kinetum_info({"--json", "--prefix", prefix.string()},
						     {stream_destination::CAPTURE, stream_destination::CAPTURE},
						     artifacts.path());
		ASSERT_TRUE(result.harness_error.empty()) << result.harness_error;
		EXPECT_EQ(result.exit_code, 0);
		EXPECT_TRUE(result.standard_error.empty());
		EXPECT_EQ(result.standard_output, expected_default_json(prefix.string(), "incomplete", "incomplete"));
	}
}

/** @brief An SDK inspection failure preserves independent runtime presence and is never absence. */
TEST(kinetum_info, sdk_inspection_failure_is_separate_from_runtime_presence)
{
	temporary_directory artifacts;
	ASSERT_FALSE(artifacts.path().empty());
	const auto prefix = artifacts.path() / "prefix";
	ASSERT_TRUE(stage_runtime_presence(prefix));
	ASSERT_TRUE(stage_sdk_presence(prefix));
	const directory_permissions_guard permissions(prefix / "sdk", std::filesystem::perms::none);
	struct stat metadata{};
	const int observed = ::stat((prefix / "sdk/VERSION").c_str(), &metadata);
	const int inspection_error = errno;
	ASSERT_TRUE(observed == 0 || inspection_error == EACCES);
	const auto result = run_kinetum_info({"--json", "--prefix", prefix.string()},
					     {stream_destination::CAPTURE, stream_destination::CAPTURE},
					     artifacts.path());
	ASSERT_TRUE(result.harness_error.empty()) << result.harness_error;
	EXPECT_EQ(result.exit_code, observed == 0 ? 0 : 1);
	EXPECT_TRUE(result.standard_error.empty());
	EXPECT_EQ(result.standard_output,
		  expected_default_json(prefix.string(), "installed", observed == 0 ? "installed" : "unavailable"));
}

/** @brief Prove every public output mode maps incomplete delivery to exit one. */
TEST(kinetum_info, every_mode_rejects_incomplete_output_delivery)
{
	temporary_directory artifacts;
	ASSERT_FALSE(artifacts.path().empty());
	const std::string prefix = artifacts.path().string();
	const std::array<std::vector<std::string>, 8> invocations{{
		{"--version"},
		{"--help"},
		{"--prefix", prefix},
		{"--json", "--prefix", prefix},
		{"--check", "--prefix", prefix},
		{"--check", "--json", "--prefix", prefix},
		{"--prefix"},
		{"--unknown-option"},
	}};
	for (const auto &arguments : invocations) {
		const auto result = run_kinetum_info(arguments,
						     {.standard_output = stream_destination::FULL,
						      .standard_error = stream_destination::FULL},
						     artifacts.path());
		ASSERT_TRUE(result.harness_error.empty()) << result.harness_error;
		EXPECT_EQ(result.exit_code, 1);
	}
}

/** @brief A failed runtime check emits complete runtime JSON even when an SDK is present. */
TEST(kinetum_info, failed_check_emits_one_complete_json_document)
{
	temporary_directory artifacts;
	ASSERT_FALSE(artifacts.path().empty());
	ASSERT_TRUE(stage_sdk_presence(artifacts.path()));
	const std::string prefix = artifacts.path().string();
	const auto result = run_kinetum_info({"--check", "--json", "--prefix", prefix},
					     {.standard_output = stream_destination::CAPTURE,
					      .standard_error = stream_destination::CAPTURE},
					     artifacts.path());
	ASSERT_TRUE(result.harness_error.empty()) << result.harness_error;
	EXPECT_EQ(result.exit_code, 1);
	EXPECT_TRUE(result.standard_error.empty()) << result.standard_error;
	ASSERT_GE(result.standard_output.size(), 4u);
	EXPECT_EQ(result.standard_output.substr(0, 2), "{\n");
	EXPECT_EQ(result.standard_output.substr(result.standard_output.size() - 2u), "}\n");
	EXPECT_NE(result.standard_output.find("  \"status\": \"failed\",\n"), std::string::npos);
	EXPECT_NE(result.standard_output.find("  \"errors\": "), std::string::npos);
	EXPECT_NE(result.standard_output.find("  \"runtime_payload\": "), std::string::npos);
	EXPECT_NE(result.standard_output.find("  \"provider_release\": "), std::string::npos);
	EXPECT_NE(result.standard_output.find("  \"components\": [\n"), std::string::npos);
	EXPECT_NE(result.standard_output.find("  \"build_features\": {\n"), std::string::npos);
	EXPECT_NE(result.standard_output.find("  \"dpdk_version\": \"" KINETUM_TEST_INFO_DPDK_VERSION "\""),
		  std::string::npos);
	EXPECT_NE(result.standard_output.find("  \"paths\": {}\n"), std::string::npos);
	EXPECT_EQ(result.standard_output.find("\"installation\""), std::string::npos);
	EXPECT_EQ(result.standard_output.find("/sdk/"), std::string::npos);
}

}  // namespace kinetum::release
