// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_pack_source_admission.cpp
 * @brief Unit and real-image tests for deployment-bundle source admission.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/common/status.hpp"
#include "src/pack/pack_source_admission.hpp"

namespace kinetum::pack
{
namespace
{

namespace fs = std::filesystem;

#ifndef KINETUM_TEST_SOURCE_ROOT
#error "KINETUM_TEST_SOURCE_ROOT must identify the repository source root"
#endif

#if !defined(KINETUM_PRODUCTION_PACK_PATH) || !defined(KINETUM_PRODUCTION_BUNDLE_VERIFY_PATH)
#error "pack source tests require the exact packer and bundle-verifier images"
#endif

/** @brief Own one temporary directory tree for pack-source tests. */
class PackSourceAdmissionTest : public ::testing::Test {
    protected:
	/** @brief Create canonical required files and optional source directories. */
	void SetUp() override
	{
		const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
		root_ = fs::temp_directory_path() /
			("kinetum_pack_sources_" + std::to_string(static_cast<long long>(::getpid())) + "_" +
			 std::string(info->name()));
		std::error_code ec;
		fs::remove_all(root_, ec);
		ec.clear();
		fs::create_directories(root_ / "modules", ec);
		ASSERT_FALSE(ec) << ec.message();
		root_ = fs::canonical(root_, ec);
		ASSERT_FALSE(ec) << ec.message();
		pipeline_ = create_file("pipeline.pbtxt", 0644);
		hardware_ = create_file("hardware.pbtxt", 0644);
		snapshot_ = create_file("snapshot.pbtxt", 0644);
		deployment_bindings_ = create_file("bindings.pbtxt", 0644);
	}

	/** @brief Remove every test-owned artifact. */
	void TearDown() override
	{
		std::error_code ec;
		fs::remove_all(root_, ec);
	}

	/**
	 * @brief Create one regular source artifact with exact POSIX permissions.
	 *
	 * @param relative_path Path relative to the test root.
	 * @param mode POSIX mode applied after writing.
	 * @return Canonical absolute artifact path.
	 */
	fs::path create_file(const std::string &relative_path, mode_t mode)
	{
		const fs::path path = root_ / relative_path;
		std::ofstream output(path, std::ios::binary | std::ios::trunc);
		output << "pack-source-test\n";
		output.close();
		EXPECT_TRUE(output.good());
		EXPECT_EQ(::chmod(path.c_str(), mode), 0);
		return path;
	}

	/**
	 * @brief Construct one complete valid source specification.
	 *
	 * @return Exact required source files with no optional module source.
	 */
	pack_source_spec valid_spec() const
	{
		pack_source_spec spec;
		spec.pipeline = pipeline_;
		spec.hardware = hardware_;
		spec.bootstrap_snapshot = snapshot_;
		spec.deployment_bindings = deployment_bindings_;
		return spec;
	}

	fs::path root_;			///< Canonical test-owned root.
	fs::path pipeline_;		///< Required test pipeline.
	fs::path hardware_;		///< Required test hardware inventory.
	fs::path snapshot_;		///< Required test bootstrap snapshot.
	fs::path deployment_bindings_;	///< Required test deployment bindings.
};

/** @brief Bounded observation of one exact packer child process. */
struct pack_process_result {
	int exit_code{-1};   ///< Normal process exit code, or -1 for abnormal exit.
	std::string output;  ///< Bounded prefix of the merged diagnostic stream.
};

/** Exact output destination for one tested production image. */
enum class process_output_destination : uint8_t {
	CAPTURE,  ///< Capture merged stdout/stderr through the bounded observer.
	FULL,	  ///< Route both streams to /dev/full.
};

/** Maximum diagnostic bytes retained from one packer invocation. */
constexpr std::size_t MAX_PACK_DIAGNOSTIC_BYTES = std::size_t{64} * 1024u;

/** Complete child/output-observation deadline for one packer invocation. */
constexpr auto PACK_PROCESS_TIMEOUT = std::chrono::seconds(30);

/** Maximum delay between exact child-state observations. */
constexpr auto PACK_PROCESS_POLL_INTERVAL = std::chrono::milliseconds(50);

/**
 * @brief Retain a bounded prefix while draining the complete child stream.
 *
 * @param bytes Newly observed bytes.
 * @param[out] result Process observation receiving the bounded prefix.
 */
void append_pack_output(std::string_view bytes, pack_process_result *result)
{
	const std::size_t available = MAX_PACK_DIAGNOSTIC_BYTES - result->output.size();
	result->output.append(bytes.substr(0u, std::min(available, bytes.size())));
}

/**
 * @brief Append one bounded observer diagnostic with its exact system error.
 *
 * @param operation Failed observer operation.
 * @param error Captured errno value.
 * @param[out] result Process observation receiving the diagnostic.
 */
void append_pack_observer_error(std::string_view operation, int error, pack_process_result *result)
{
	append_pack_output(operation, result);
	append_pack_output(": ", result);
	append_pack_output(std::strerror(error), result);
	append_pack_output("\n", result);
}

/**
 * @brief Terminate one packer process group and reap its exact child.
 *
 * The process-group signal also closes descendants that might retain the
 * capture descriptor after the direct child exits.
 *
 * @param child Exact direct-child identity and process-group identity.
 * @param[in,out] reaped Whether the direct child was already reaped.
 * @param[out] wait_status Terminal direct-child wait status when observed.
 */
void stop_pack_process_group(pid_t child, bool *reaped, int *wait_status) noexcept
{
	(void)::kill(-child, SIGKILL);
	if (*reaped) {
		return;
	}
	(void)::kill(child, SIGKILL);
	for (;;) {
		const pid_t waited = ::waitpid(child, wait_status, 0);
		if (waited == child) {
			*reaped = true;
			return;
		}
		if (waited < 0 && errno == EINTR) {
			continue;
		}
		return;
	}
}

/**
 * @brief Launch one exact production image with bounded output ownership.
 *
 * Observation is bounded by time and retained bytes. The complete merged
 * stream is drained so a diagnostic regression cannot deadlock on pipe
 * capacity; timeout or observer failure terminates the exact child process
 * group before returning.
 *
 * @param image Exact production image path.
 * @param arguments Arguments following the process image.
 * @param destination Capture output or route it to /dev/full.
 * @return Normal exit status and bounded merged stdout/stderr bytes.
 */
[[nodiscard]] pack_process_result run_production_image(const char *image, const std::vector<std::string> &arguments,
						       process_output_destination destination)
{
	pack_process_result result;
	result.output.reserve(MAX_PACK_DIAGNOSTIC_BYTES);

	int output_pipe[2]{};
	if (::pipe(output_pipe) != 0) {
		const int error = errno;
		append_pack_observer_error("failed to create packer output pipe", error, &result);
		return result;
	}
	for (const int descriptor : output_pipe) {
		const int flags = ::fcntl(descriptor, F_GETFD);
		if (flags < 0 || ::fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0) {
			const int error = errno;
			(void)::close(output_pipe[0]);
			(void)::close(output_pipe[1]);
			append_pack_observer_error("failed to protect packer output descriptor", error, &result);
			return result;
		}
	}
	const int read_flags = ::fcntl(output_pipe[0], F_GETFL);
	if (read_flags < 0 || ::fcntl(output_pipe[0], F_SETFL, read_flags | O_NONBLOCK) != 0) {
		const int error = errno;
		(void)::close(output_pipe[0]);
		(void)::close(output_pipe[1]);
		append_pack_observer_error("failed to make packer output nonblocking", error, &result);
		return result;
	}

	std::vector<std::string> storage;
	storage.reserve(arguments.size() + 1u);
	storage.emplace_back(image);
	storage.insert(storage.end(), arguments.begin(), arguments.end());
	std::vector<char *> argv;
	argv.reserve(storage.size() + 1u);
	for (auto &argument : storage) {
		argv.push_back(argument.data());
	}
	argv.push_back(nullptr);

	const pid_t child = ::fork();
	if (child < 0) {
		const int error = errno;
		(void)::close(output_pipe[0]);
		(void)::close(output_pipe[1]);
		append_pack_observer_error("failed to fork production packer", error, &result);
		return result;
	}
	if (child == 0) {
		(void)::close(output_pipe[0]);
		if (::setpgid(0, 0) != 0) {
			::_exit(126);
		}
		int output_descriptor = output_pipe[1];
		if (destination == process_output_destination::FULL) {
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
		::execv(image, argv.data());
		::_exit(127);
	}

	(void)::close(output_pipe[1]);
	int wait_status = 0;
	bool child_reaped = false;
	bool pipe_eof = false;
	bool observer_failed = false;
	const auto deadline = std::chrono::steady_clock::now() + PACK_PROCESS_TIMEOUT;
	char buffer[1024];
	while (!child_reaped || !pipe_eof) {
		while (!pipe_eof) {
			const ssize_t count = ::read(output_pipe[0], buffer, sizeof(buffer));
			if (count > 0) {
				append_pack_output(std::string_view(buffer, static_cast<std::size_t>(count)), &result);
				continue;
			}
			if (count == 0) {
				pipe_eof = true;
				break;
			}
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}
			const int error = errno;
			append_pack_observer_error("failed to read production packer output", error, &result);
			observer_failed = true;
			break;
		}
		if (observer_failed) {
			break;
		}

		while (!child_reaped) {
			const pid_t waited = ::waitpid(child, &wait_status, WNOHANG);
			if (waited == child) {
				child_reaped = true;
				break;
			}
			if (waited == 0) {
				break;
			}
			if (errno == EINTR) {
				continue;
			}
			const int error = errno;
			append_pack_observer_error("failed to observe production packer", error, &result);
			observer_failed = true;
			break;
		}
		if (observer_failed || (child_reaped && pipe_eof)) {
			break;
		}

		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			append_pack_output("production packer observation exceeded its deadline\n", &result);
			observer_failed = true;
			break;
		}
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
		const auto wait_interval = std::min(remaining, PACK_PROCESS_POLL_INTERVAL);
		const int poll_timeout_ms =
			static_cast<int>(std::max<std::chrono::milliseconds::rep>(1, wait_interval.count()));
		struct pollfd descriptor{pipe_eof ? -1 : output_pipe[0], POLLIN | POLLHUP, 0};
		int poll_result = 0;
		do {
			poll_result = ::poll(&descriptor, 1u, poll_timeout_ms);
		} while (poll_result < 0 && errno == EINTR);
		if (poll_result < 0) {
			const int error = errno;
			append_pack_observer_error("failed to poll production packer output", error, &result);
			observer_failed = true;
			break;
		}
		if ((descriptor.revents & POLLNVAL) != 0) {
			append_pack_output("production packer output descriptor became invalid\n", &result);
			observer_failed = true;
			break;
		}
	}

	if (observer_failed) {
		stop_pack_process_group(child, &child_reaped, &wait_status);
	}
	(void)::close(output_pipe[0]);
	if (!observer_failed && child_reaped && WIFEXITED(wait_status)) {
		result.exit_code = WEXITSTATUS(wait_status);
	}
	return result;
}

/**
 * @brief Launch the production packer and capture its ordinary output.
 *
 * @param arguments Arguments following the packer image.
 * @return Normal exit status and bounded merged output.
 */
[[nodiscard]] pack_process_result run_production_pack(const std::vector<std::string> &arguments)
{
	return run_production_image(KINETUM_PRODUCTION_PACK_PATH, arguments, process_output_destination::CAPTURE);
}

/**
 * @brief Construct one complete module-free production pack invocation.
 *
 * @param output Exact output identity under test.
 * @return Arguments following the production pack image.
 */
[[nodiscard]] std::vector<std::string> production_pack_arguments(const fs::path &output)
{
	const fs::path example = fs::path(KINETUM_TEST_SOURCE_ROOT) / "examples/passthrough";
	return {
		"--axiom",
		(example / "passthrough.axiom.pbtxt").string(),
		"--hw",
		(example / "hardware_inventory_tap.pbtxt").string(),
		"--bindings",
		(example / "passthrough_tap_bindings.pbtxt").string(),
		"--bootstrap-snapshot",
		(example / "config_snapshot.pbtxt").string(),
		"--regions",
		"1",
		"--out",
		output.string(),
	};
}

/** @brief Verify undeclared binary-source options fail at the shipped CLI. */
TEST(pack_source_admission, production_cli_rejects_undeclared_binary_authority_options)
{
	const auto skipped = run_production_pack({"--skip_binaries"});
	EXPECT_EQ(skipped.exit_code, 2) << skipped.output;
	EXPECT_NE(skipped.output.find("Unknown argument: --skip_binaries"), std::string::npos);

	const auto directory = run_production_pack({"--bin_dir", "/tmp"});
	EXPECT_EQ(directory.exit_code, 2) << directory.output;
	EXPECT_NE(directory.output.find("Unknown argument: --bin_dir"), std::string::npos);

	const auto underscored_bootstrap = run_production_pack({"--bootstrap_snapshot", "/tmp/snapshot"});
	EXPECT_EQ(underscored_bootstrap.exit_code, 2) << underscored_bootstrap.output;
	EXPECT_NE(underscored_bootstrap.output.find("Unknown argument: --bootstrap_snapshot"), std::string::npos);

	const auto underscored_modules = run_production_pack({"--modules_dir", "/tmp/modules"});
	EXPECT_EQ(underscored_modules.exit_code, 2) << underscored_modules.output;
	EXPECT_NE(underscored_modules.output.find("Unknown argument: --modules_dir"), std::string::npos);
}

/** @brief Verify help publishes only the final deployment-bundle authority. */
TEST(pack_source_admission, production_help_contains_no_runtime_binary_source)
{
	const auto help = run_production_pack({"--help"});
	ASSERT_EQ(help.exit_code, 0) << help.output;
	EXPECT_EQ(help.output.find("--skip_binaries"), std::string::npos);
	EXPECT_EQ(help.output.find("--bin_dir"), std::string::npos);
	EXPECT_EQ(help.output.find("--bootstrap_snapshot"), std::string::npos);
	EXPECT_EQ(help.output.find("--modules_dir"), std::string::npos);
	EXPECT_NE(help.output.find("--bootstrap-snapshot"), std::string::npos);
	EXPECT_NE(help.output.find("--modules-dir"), std::string::npos);
	EXPECT_EQ(help.output.find("    bin/"), std::string::npos);
}

/** @brief Prove generated bundle guidance delegates host prerequisites to exact authorities. */
TEST_F(PackSourceAdmissionTest, generated_bundle_readme_states_provider_prerequisite_boundary)
{
	const fs::path output = root_ / "documented-bundle";
	const auto result = run_production_pack(production_pack_arguments(output));
	ASSERT_EQ(result.exit_code, 0) << result.output;

	std::ifstream input(output / "README_BUNDLE.md", std::ios::binary);
	ASSERT_TRUE(input.is_open());
	const std::string readme{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
	EXPECT_TRUE(input.good() || input.eof());
	EXPECT_NE(readme.find("Satisfy the exact deployment bindings and host-proof requirements"), std::string::npos);
	EXPECT_NE(readme.find("this bundle does not configure host resources"), std::string::npos);
	EXPECT_EQ(readme.find("Requires hugepage configuration and NIC binding"), std::string::npos);
}

/** @brief Prove pack and verifier refuse success when result delivery fails. */
TEST_F(PackSourceAdmissionTest, production_result_delivery_failure_preserves_artifact_truth)
{
	const fs::path verified_output = root_ / "verified-output";
	const auto packed = run_production_pack(production_pack_arguments(verified_output));
	ASSERT_EQ(packed.exit_code, 0) << packed.output;

	const auto verifier = run_production_image(KINETUM_PRODUCTION_BUNDLE_VERIFY_PATH,
						   {"--bundle", verified_output.string()},
						   process_output_destination::FULL);
	EXPECT_EQ(verifier.exit_code, 1) << verifier.output;
	EXPECT_TRUE(fs::is_directory(verified_output));

	const fs::path unpublished_output = root_ / "unpublished-output";
	const auto unreported_pack = run_production_image(KINETUM_PRODUCTION_PACK_PATH,
							  production_pack_arguments(unpublished_output),
							  process_output_destination::FULL);
	EXPECT_EQ(unreported_pack.exit_code, 1) << unreported_pack.output;
	EXPECT_FALSE(fs::exists(unpublished_output));
}

/** @brief Verify output publication never repairs or replaces caller identity. */
TEST_F(PackSourceAdmissionTest, production_output_requires_one_absent_leaf_beneath_exact_parent)
{
	std::error_code error;
	const fs::path indirect_target = root_ / "indirect-target";
	ASSERT_TRUE(fs::create_directory(indirect_target, error));
	ASSERT_FALSE(error) << error.message();
	const fs::path indirect_parent = root_ / "indirect-parent";
	fs::create_directory_symlink(indirect_target, indirect_parent, error);
	ASSERT_FALSE(error) << error.message();
	const auto indirect = run_production_pack(production_pack_arguments(indirect_parent / "bundle"));
	EXPECT_EQ(indirect.exit_code, 2) << indirect.output;
	EXPECT_FALSE(fs::exists(indirect_target / "bundle"));

	const fs::path nested_parent = root_ / "nested-parent";
	ASSERT_TRUE(fs::create_directory(nested_parent, error));
	ASSERT_FALSE(error) << error.message();
	const fs::path normalized_target = root_ / "normalized-bundle";
	const auto repaired =
		run_production_pack(production_pack_arguments(nested_parent / ".." / normalized_target.filename()));
	EXPECT_EQ(repaired.exit_code, 2) << repaired.output;
	EXPECT_FALSE(fs::exists(normalized_target));

	const fs::path occupied = create_file("occupied-bundle", 0644);
	const auto existing_file = run_production_pack(production_pack_arguments(occupied));
	EXPECT_EQ(existing_file.exit_code, 2) << existing_file.output;
	EXPECT_TRUE(fs::is_regular_file(occupied));

	const fs::path occupied_directory = root_ / "occupied-directory";
	ASSERT_TRUE(fs::create_directory(occupied_directory, error));
	ASSERT_FALSE(error) << error.message();
	const fs::path sentinel = create_file("occupied-directory/sentinel", 0644);
	const auto existing_directory = run_production_pack(production_pack_arguments(occupied_directory));
	EXPECT_EQ(existing_directory.exit_code, 2) << existing_directory.output;
	std::ifstream sentinel_input(sentinel, std::ios::binary);
	ASSERT_TRUE(sentinel_input.is_open());
	std::string sentinel_line;
	ASSERT_TRUE(static_cast<bool>(std::getline(sentinel_input, sentinel_line)));
	EXPECT_EQ(sentinel_line, "pack-source-test");
	EXPECT_EQ(sentinel_input.peek(), std::char_traits<char>::eof());

	const fs::path dangling_target = root_ / "absent-target";
	const fs::path dangling_output = root_ / "dangling-output";
	fs::create_symlink(dangling_target, dangling_output, error);
	ASSERT_FALSE(error) << error.message();
	const auto dangling = run_production_pack(production_pack_arguments(dangling_output));
	EXPECT_EQ(dangling.exit_code, 2) << dangling.output;
	EXPECT_FALSE(fs::exists(dangling_target));
}

/** @brief Verify every explicit relative file and directory is canonicalized. */
TEST_F(PackSourceAdmissionTest, explicit_relative_sources_are_canonicalized_once)
{
	std::error_code ec;
	pack_source_spec spec = valid_spec();
	spec.pipeline = fs::relative(pipeline_, fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	spec.hardware = fs::relative(hardware_, fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	spec.bootstrap_snapshot = fs::relative(snapshot_, fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	spec.deployment_bindings = fs::relative(deployment_bindings_, fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();
	spec.module_directory = fs::relative(root_ / "modules", fs::current_path(), ec);
	ASSERT_FALSE(ec) << ec.message();

	auto sources_or = admit_pack_sources(spec);
	ASSERT_TRUE(sources_or.is_ok()) << sources_or.error().message();
	EXPECT_EQ(sources_or->pipeline, pipeline_);
	EXPECT_EQ(sources_or->hardware, hardware_);
	EXPECT_EQ(sources_or->bootstrap_snapshot, snapshot_);
	EXPECT_EQ(sources_or->deployment_bindings, deployment_bindings_);
	ASSERT_TRUE(sources_or->module_directory.has_value());
	EXPECT_EQ(*sources_or->module_directory, root_ / "modules");
}

/** @brief Verify the module directory is the sole optional source authority. */
TEST_F(PackSourceAdmissionTest, explicit_module_directory_is_the_only_optional_source)
{
	pack_source_spec spec = valid_spec();
	spec.module_directory = root_ / "modules";
	auto sources_or = admit_pack_sources(spec);
	ASSERT_TRUE(sources_or.is_ok()) << sources_or.error().message();
	ASSERT_TRUE(sources_or->module_directory.has_value());
	EXPECT_EQ(*sources_or->module_directory, root_ / "modules");
}

/** @brief Verify omitting modules publishes no optional source authority. */
TEST_F(PackSourceAdmissionTest, omitted_module_directory_publishes_no_optional_source)
{
	auto sources_or = admit_pack_sources(valid_spec());
	ASSERT_TRUE(sources_or.is_ok()) << sources_or.error().message();
	EXPECT_FALSE(sources_or->module_directory.has_value());
}

/** @brief Verify a missing explicit source directory is rejected. */
TEST_F(PackSourceAdmissionTest, missing_explicit_module_directory_is_rejected)
{
	pack_source_spec spec = valid_spec();
	spec.module_directory = root_ / "missing";
	auto sources_or = admit_pack_sources(spec);
	ASSERT_FALSE(sources_or.is_ok());
	EXPECT_EQ(sources_or.error().code(), kinetum::common::status_code::NOT_FOUND);
}

/** @brief Verify every required source file participates in atomic admission. */
TEST_F(PackSourceAdmissionTest, missing_required_source_is_rejected)
{
	pack_source_spec spec = valid_spec();
	spec.hardware = root_ / "missing-hardware.pbtxt";

	auto sources_or = admit_pack_sources(spec);
	ASSERT_FALSE(sources_or.is_ok());
	EXPECT_EQ(sources_or.error().code(), kinetum::common::status_code::NOT_FOUND);
}

/** @brief Verify one authority binds every reserved built-in ID to its exact source image. */
TEST_F(PackSourceAdmissionTest, builtin_module_image_mapping_is_exact)
{
	const auto acl_or = resolve_builtin_module_image("kinetum.acl");
	ASSERT_TRUE(acl_or.is_ok()) << acl_or.error().message();
	EXPECT_EQ(acl_or->source_filename, "libkinetum_acl.so");

	const auto nat44_or = resolve_builtin_module_image("kinetum.nat44");
	ASSERT_TRUE(nat44_or.is_ok()) << nat44_or.error().message();
	EXPECT_EQ(nat44_or->source_filename, "libkinetum_nat44.so");

	const auto qos_or = resolve_builtin_module_image("kinetum.qos");
	ASSERT_TRUE(qos_or.is_ok()) << qos_or.error().message();
	EXPECT_EQ(qos_or->source_filename, "libkinetum_qos.so");

	const auto unknown_or = resolve_builtin_module_image("kinetum.future");
	ASSERT_FALSE(unknown_or.is_ok());
	EXPECT_EQ(unknown_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

/** @brief Verify auxiliary shared objects are exact, deterministic, and exclude main images. */
TEST_F(PackSourceAdmissionTest, module_dependencies_are_sorted_and_exclude_main_images)
{
	const fs::path main_image = create_file("modules/libkinetum_acl.so", 0755);
	const fs::path dependency_z = create_file("modules/libz_support.so.2", 0644);
	const fs::path dependency_a = create_file("modules/liba_codec.so", 0644);
	(void)create_file("modules/README.txt", 0644);

	const std::unordered_map<std::string, fs::path> main_sources{{"kinetum.acl", main_image}};
	auto dependencies_or = admit_module_dependencies(root_ / "modules", main_sources);
	ASSERT_TRUE(dependencies_or.is_ok()) << dependencies_or.error().message();
	ASSERT_EQ(dependencies_or->size(), 2u);
	EXPECT_EQ((*dependencies_or)[0].filename, "liba_codec.so");
	EXPECT_EQ((*dependencies_or)[0].source, dependency_a);
	EXPECT_EQ((*dependencies_or)[1].filename, "libz_support.so.2");
	EXPECT_EQ((*dependencies_or)[1].source, dependency_z);
}

/** @brief Verify an auxiliary dependency cannot escape the flat source through a symlink. */
TEST_F(PackSourceAdmissionTest, module_dependency_symlink_is_rejected)
{
	const fs::path external = create_file("external_dependency.so", 0644);
	const fs::path link = root_ / "modules/liblinked_dependency.so";
	std::error_code ec;
	fs::create_symlink(external, link, ec);
	ASSERT_FALSE(ec) << ec.message();

	auto dependencies_or = admit_module_dependencies(root_ / "modules", {});
	ASSERT_FALSE(dependencies_or.is_ok());
	EXPECT_EQ(dependencies_or.error().code(), kinetum::common::status_code::FAILED_PRECONDITION);
}

/** @brief Verify dependency basenames use the bundle's one-component grammar. */
TEST_F(PackSourceAdmissionTest, unsafe_module_dependency_filename_is_rejected)
{
	(void)create_file("modules/libbad schema.so", 0644);

	auto dependencies_or = admit_module_dependencies(root_ / "modules", {});
	ASSERT_FALSE(dependencies_or.is_ok());
	EXPECT_EQ(dependencies_or.error().code(), kinetum::common::status_code::INVALID_ARGUMENT);
}

}  // namespace
}  // namespace kinetum::pack
