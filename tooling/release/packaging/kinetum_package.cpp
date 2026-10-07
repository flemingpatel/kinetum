// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file kinetum_package.cpp
 * @brief Independent package preparation, signing, and installation owner.
 * @author Fleming Patel
 *
 * CMake chooses staged membership; this process verifies complete bytes before
 * publication. Native provider preparation and untrusted archive decoding run
 * in disposable process groups. Signing reads its seed only after decoding
 * has finished and never invokes target code. No operation changes host setup
 * or starts a runtime service.
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <linux/fs.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tooling/release/packaging/package_files.hpp"
#include "tooling/release/packaging/package_release.hpp"
#include "tooling/release/verification/runtime_verification.hpp"
#include "src/common/canonical_content_identity.hpp"
#include "src/common/file_io.hpp"
#include "src/common/path_admission.hpp"
#include "src/common/process_image.hpp"
#include "src/common/process_output.hpp"
#include "src/common/sha256.hpp"
#include "src/provider/provider_release_trust.hpp"
#include "src/provider/provider_installation.hpp"

namespace
{

namespace fs = std::filesystem;
namespace release = kinetum::release;
namespace common = kinetum::common;
namespace provider = kinetum::provider;
using common::status;
using common::status_code;
using common::status_or;
using common::static_status_text;

constexpr std::string_view VERSION = KINETUM_VERSION_STR;  ///< Root-injected release identity.
constexpr std::string_view SDK_MANIFEST = "share/kinetum/release/sdk_payload_manifest.sha256";	///< SDK integrity rows.
constexpr std::size_t MAX_CHILD_OUTPUT_BYTES = 64u * 1024u * 1024u;  ///< Complete child-output bound.
constexpr std::size_t MAX_BUILD_CACHE_BYTES = 4u * 1024u * 1024u;    ///< CMake input-location cache bound.
constexpr auto TOOL_TIMEOUT = std::chrono::hours(2);		     ///< Staging/verification tool wall deadline.
constexpr auto WORKER_TIMEOUT = std::chrono::minutes(10);	     ///< Archive/admission worker wall deadline.

/** Exact public product selection. Private validation is outside this dispatcher. */
enum class product_kind { RUNTIME, SDK };
/** One CMake-authored fixed-file staging and source correspondence. */
struct fixed_projection {
	product_kind product;		 ///< Product owning this fixed file.
	std::string_view source;	 ///< Relative source authority; empty for native dependency output.
	std::string_view destination;	 ///< Relative path in the staged envelope.
	std::string_view source_sha256;	 ///< Source bytes used by the configured producer.
	std::string_view staged_sha256;	 ///< Exact configured/copied output bytes.
};
/** One CMake-authored whole-tree source/staged association. */
struct tree_projection {
	std::string_view relative_source;  ///< Relative root in the configured source tree.
	std::string_view destination;	   ///< Relative staged envelope root.
};

#include "package_projections.inc"
#include "install_bootstrap.inc"

/** Complete finite CLI synopsis; operation-specific admission remains in parse_command. */
constexpr std::string_view USAGE =
	"Kinetum package " KINETUM_VERSION_STR "\n"
	"  kinetum_package prepare --product <runtime|sdk> --build-dir <existing-build>\n"
	"      [--output-dir <directory>] [--release-url <https-url> (SDK only)]\n"
	"  kinetum_package sign --candidate <archive> --key <seed-file>\n"
	"      [--output-dir <directory>] [--release-url <https-url>]\n"
	"  kinetum_package install --archive <archive> [--sha256 <expected-sha256>]\n"
	"      [--prefix <absolute-prefix>]\n"
	"  kinetum_package keygen --output <new-seed-file>\n"
	"Prepare consumes the selected build without configuring or compiling it.\n"
	"Invoke that build's kinetum_package or a byte-identical copy.\n"
	"Prepare/sign create their output directory (default: ./dist) and derive archive names.\n"
	"Final packages include their own checksum and installer; --release-url enables archive downloads.\n"
	"Prepare verifies product bytes. Release qualification is a separate required gate.\n";

/** Parsed borrowed arguments; argv remains alive until the process returns. */
struct command {
	std::string_view operation;			      ///< One complete public operation name.
	std::map<std::string_view, std::string_view> values;  ///< Unique admitted complete option spellings.
};

/**
 * @brief Preserve one cold filesystem/process diagnostic.
 * @param action Failed operation description.
 * @param error Saved syscall error number.
 * @return INTERNAL_ERROR with owned operation and errno diagnostics.
 */
status system_error(std::string_view action, int error = errno)
{
	return status(status_code::INTERNAL_ERROR, std::string(action), std::strerror(error));
}

/**
 * @brief Admit a literal HTTPS release directory without shell syntax or credentials.
 * @param url Explicit versioned HTTPS asset-directory literal.
 * @return OK for bounded caller syntax safe for the fixed shell literal; endpoint reachability is not probed.
 */
status validate_release_url(std::string_view url)
{
	if (!url.starts_with("https://") || url.size() <= 8u || url.back() == '/' || url[8] == '/' ||
	    !std::all_of(url.begin() + 8, url.end(), [](char value) {
		    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
			   (value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.' ||
			   value == '~' || value == ':' || value == '/' || value == '%' || value == '+';
	    })) {
		return status::invalid_argument(static_status_text(
			"release URL must be a literal HTTPS directory without credentials, query, fragment, or trailing slash"));
	}
	return status::ok();
}

/**
 * @brief Parse only the exact option set owned by the selected operation.
 * @param argc Process argument count.
 * @param argv Process arguments borrowed until command execution finishes.
 * @return One exact operation and unique option set, or INVALID_ARGUMENT before effects.
 */
status_or<command> parse_command(int argc, char **argv)
{
	if (argc < 2) {
		return status::invalid_argument(static_status_text("a package operation is required"));
	}
	command result{argv[1], {}};
	std::set<std::string_view> required;
	std::set<std::string_view> optional;
	if (result.operation == "prepare") {
		required = {"--product", "--build-dir"};
		optional = {"--output-dir", "--release-url"};
	} else if (result.operation == "sign") {
		required = {"--candidate", "--key"};
		optional = {"--output-dir", "--release-url"};
	} else if (result.operation == "install") {
		required = {"--archive"};
		optional = {"--sha256", "--prefix"};
	} else if (result.operation == "keygen") {
		required = {"--output"};
	} else {
		return status::invalid_argument(static_status_text("unknown package operation"));
	}
	for (int index = 2; index < argc; ++index) {
		const std::string_view option(argv[index]);
		if ((!required.contains(option) && !optional.contains(option)) || result.values.contains(option) ||
		    index + 1 >= argc) {
			return status::invalid_argument(
				static_status_text("unknown, duplicate, or valueless package option"));
		}
		const std::string_view value(argv[++index]);
		if (value.empty() || value.size() > release::MAX_PAYLOAD_PATH_BYTES) {
			return status::invalid_argument(
				static_status_text("package option value is empty or over bound"));
		}
		result.values.emplace(option, value);
	}
	for (const auto option : required) {
		if (!result.values.contains(option)) {
			return status::invalid_argument(static_status_text("required package option is missing"));
		}
	}
	if (result.values.contains("--release-url")) {
		if (result.operation == "prepare" && result.values.at("--product") != "sdk") {
			return status::invalid_argument(
				static_status_text("a release URL requires a final SDK package or runtime signing"));
		}
		const auto url = validate_release_url(result.values.at("--release-url"));
		if (!url.is_ok()) {
			return url;
		}
	}
	if (result.operation == "install" && result.values.contains("--sha256")) {
		const auto digest = common::validate_sha256_hex_claim(result.values.at("--sha256"), "--sha256");
		if (!digest.is_ok()) {
			return digest;
		}
	}
	return result;
}

/**
 * @brief Admit a product without aliases or prefix matching.
 * @param value Complete CLI product spelling.
 * @return Runtime or SDK; every other value is INVALID_ARGUMENT.
 */
status_or<product_kind> parse_product(std::string_view value)
{
	if (value == "runtime") {
		return product_kind::RUNTIME;
	}
	if (value == "sdk") {
		return product_kind::SDK;
	}
	return status::invalid_argument(static_status_text("product must be runtime or sdk"));
}

/**
 * @brief Return the complete public product spelling.
 * @param product Admitted public product.
 * @return Static product spelling; invalid internal state terminates.
 */
std::string_view product_name(product_kind product) noexcept
{
	switch (product) {
	case product_kind::RUNTIME:
		return "runtime";
	case product_kind::SDK:
		return "sdk";
	}
	std::terminate();
}

/**
 * @brief Return the architecture part of a qualified tuple.
 * @param tuple Admitted supported target tuple.
 * @return Static architecture atom; invalid internal state terminates.
 */
std::string_view architecture(provider::provider_target_tuple tuple) noexcept
{
	switch (tuple) {
	case provider::provider_target_tuple::LINUX_GNU_AARCH64:
		return "aarch64";
	case provider::provider_target_tuple::LINUX_GNU_X86_64:
		return "x86_64";
	}
	std::terminate();
}

/**
 * @brief Form one versioned envelope root from semantic product identity.
 * @param product Admitted public product.
 * @return Versioned archive-root name derived from the compiled VERSION.
 */
std::string envelope_name(product_kind product)
{
	return "kinetum-" + std::string(product_name(product)) + "-" + std::string(VERSION);
}

/**
 * @brief Form one complete native candidate or final archive name.
 * @param product Admitted product.
 * @param tuple Artifact target tuple.
 * @param candidate True only for an unsigned runtime candidate.
 * @return Exact versioned archive basename; the caller owns the returned string.
 */
std::string archive_name(product_kind product, provider::provider_target_tuple tuple, bool candidate)
{
	return envelope_name(product) + "-" + std::string(architecture(tuple)) +
	       (candidate ? ".candidate.tar.gz" : ".tar.gz");
}

/**
 * @brief Require an existing destination directory to be direct and installer-owned.
 * @param path Existing canonical directory, never an indirection to repair.
 * @return OK for current-UID ownership without group/other write access, otherwise failure.
 */
status admit_owned_directory(const fs::path &path)
{
	const auto exact = common::validate_exact_directory(path, "installation directory");
	if (!exact.is_ok()) {
		return exact;
	}
	struct stat metadata{};
	if (::lstat(path.c_str(), &metadata) != 0) {
		return system_error("cannot inspect installation directory");
	}
	if (metadata.st_uid != ::geteuid() || (metadata.st_mode & 0022) != 0) {
		return status::permission_denied(
			static_status_text("installation directory is not owned and protected"));
	}
	return status::ok();
}

/**
 * @brief Admit one output pathname without resolving a pre-existing final object.
 * @param input Explicit output name; its parent must already exist.
 * @return Absolute exact path under an owned parent, without creating or replacing anything.
 */
status_or<fs::path> output_path(std::string_view input)
{
	const fs::path supplied{std::string(input)};
	std::error_code error;
	const auto absolute = fs::absolute(supplied, error);
	if (error) {
		return status(status_code::INVALID_ARGUMENT, "cannot resolve output path", error.message());
	}
	if (absolute != absolute.lexically_normal() || absolute.filename().empty() || absolute.filename() == "." ||
	    absolute.filename() == ".." || absolute.native().find('\0') != std::string::npos) {
		return status::invalid_argument(static_status_text("output must name one exact file or directory"));
	}
	const auto owned = admit_owned_directory(absolute.parent_path());
	if (!owned.is_ok()) {
		return owned;
	}
	return absolute;
}

/** One private descriptor owner used while walking output and key paths. */
struct file_descriptor {
	/**
	 * @brief Adopt one descriptor, including -1 for an unsuccessful open.
	 * @param descriptor Unique close obligation transferred into this owner.
	 */
	explicit file_descriptor(int descriptor) noexcept
		: value(descriptor)
	{
	}
	/**
	 * @brief Transfer the sole close obligation.
	 * @param other Source left without a descriptor.
	 */
	file_descriptor(file_descriptor &&other) noexcept
		: value(std::exchange(other.value, -1))
	{
	}
	/** @brief Prevent duplicate close ownership. */
	file_descriptor(const file_descriptor &) = delete;
	/** @brief Keep descriptor ownership construction-fixed. */
	file_descriptor &operator=(const file_descriptor &) = delete;
	/** @brief Close the owned descriptor on every return and unwind. */
	~file_descriptor()
	{
		if (value >= 0) {
			(void)::close(value);
		}
	}
	int value;  ///< Sole close obligation; -1 after explicit retirement or move.
};

/**
 * @brief Walk an exact directory through held parents without following links.
 * @param path Absolute normalized directory path.
 * @param create_missing Whether this archive-output operation may create missing directories.
 * @return Held final directory, or an explicit traversal/creation failure.
 * @details Creation requires a current-owner parent without group/other write access.
 *          New directories have mode 0755; existing modes are never changed.
 *          Created empty output directories may remain after a later failure.
 */
status_or<file_descriptor> open_package_directory(const fs::path &path, bool create_missing)
{
	file_descriptor current(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	if (current.value < 0) {
		return system_error("cannot open filesystem root");
	}
	for (const auto &component : path.relative_path()) {
		if (component.empty()) {
			continue;
		}
		const std::string leaf = component.string();
		bool created = false;
		int next = ::openat(current.value, leaf.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (next < 0 && errno == ENOENT && create_missing) {
			struct stat parent{};
			if (::fstat(current.value, &parent) != 0) {
				return system_error("cannot inspect archive output parent");
			}
			if (parent.st_uid != ::geteuid() || (parent.st_mode & 0022) != 0) {
				return status::permission_denied(static_status_text(
					"new archive output directories require an owned protected parent"));
			}
			if (::mkdirat(current.value, leaf.c_str(), 0700) == 0) {
				created = true;
			} else if (errno != EEXIST) {
				return system_error("cannot create archive output directory");
			}
			next = ::openat(current.value, leaf.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		}
		if (next < 0) {
			return system_error("cannot open direct package directory");
		}
		(void)::close(std::exchange(current.value, next));
		if (created && ::fchmod(current.value, 0755) != 0) {
			return system_error("cannot set archive output directory mode");
		}
	}
	return current;
}

/**
 * @brief Resolve an explicit archive output directory, defaulting to invocation-relative dist.
 * @param arguments Parsed prepare/sign command.
 * @return Absolute normalized output directory without filesystem effects.
 * @details Parent-traversal components reject before normalization can erase an indirect path.
 */
status_or<fs::path> archive_output_directory(const command &arguments)
{
	const auto input = arguments.values.contains("--output-dir") ? arguments.values.at("--output-dir") : "dist";
	const fs::path supplied(input);
	for (const auto &component : supplied) {
		if (component == "..") {
			return status::invalid_argument(
				static_status_text("archive output directory must not contain '..'"));
		}
	}
	std::error_code error;
	auto absolute = fs::absolute(supplied, error);
	if (error) {
		return status(status_code::INVALID_ARGUMENT, "cannot resolve archive output directory",
			      error.message());
	}
	return absolute.lexically_normal();
}

/**
 * @brief Create missing archive output directories and admit the final held directory.
 * @param path Absolute normalized output directory selected before overlap checks.
 * @return OK for a current-owner directory without group/other write permissions.
 */
status create_archive_output_directory(const fs::path &path)
{
	auto directory_or = open_package_directory(path, true);
	if (!directory_or.is_ok()) {
		return directory_or.error();
	}
	struct stat metadata{};
	if (::fstat(directory_or->value, &metadata) != 0) {
		return system_error("cannot inspect archive output directory");
	}
	if (metadata.st_uid != ::geteuid() || (metadata.st_mode & 0022) != 0) {
		return status::permission_denied(
			static_status_text("archive output directory is not owned and protected"));
	}
	return status::ok();
}

/**
 * @brief Reject every existing filesystem form without following symbolic links.
 * @param path Exact prospective output.
 * @return OK only for no directory entry; links and every existing type reject.
 */
status require_absent(const fs::path &path)
{
	struct stat metadata{};
	if (::lstat(path.c_str(), &metadata) == 0) {
		return status::already_exists(static_status_text("output already exists"));
	}
	return errno == ENOENT ? status::ok() : system_error("cannot admit absent output");
}

/**
 * @brief Give one private staged tree the existing release held-file policy.
 * @param root Exact private staged root owned by this process.
 * @return Held-file and directory authority for current-UID immutable candidate bytes.
 */
common::held_file_policy tree_policy(const fs::path &root)
{
	return provider::release_candidate_file_policy(root, static_cast<uint32_t>(::geteuid()));
}

/**
 * @brief Hold source/build bytes without imposing installed-file permissions.
 * @param path Exact source/build input or VERSION metadata checked by its product owner.
 * @param maximum Inclusive byte bound checked before hashing.
 * @return One direct, single-link regular file with stable observed identity.
 * @pre The caller keeps the bytes unchanged; product metadata also passes its enclosing tree policy.
 */
status_or<common::held_file> source_file(const fs::path &path, uint64_t maximum)
{
	common::held_file_policy policy;
	policy.required_owner_uid.reset();
	policy.maximum_size_bytes = maximum;
	return common::open_held_regular_file(path, policy);
}

/**
 * @brief Hold an archive or staged file with group/world write access forbidden.
 * @param path Exact immutable input path.
 * @param maximum Inclusive byte bound checked before hashing.
 * @return One held regular file; caller ownership keeps its descriptor alive.
 */
status_or<common::held_file> input_file(const fs::path &path, uint64_t maximum)
{
	common::held_file_policy policy;
	policy.required_owner_uid.reset();
	policy.forbidden_mode_bits = 0022u;
	policy.maximum_size_bytes = maximum;
	return common::open_held_regular_file(path, policy);
}

/**
 * @brief Read a small held text file under its declared limit.
 * @param path Exact immutable input path.
 * @param maximum Inclusive text-byte limit.
 * @return Owned text whose second read matches its admitted same-descriptor identity.
 */
status_or<std::string> text_file(const fs::path &path, uint64_t maximum)
{
	auto file_or = source_file(path, maximum);
	if (!file_or.is_ok()) {
		return file_or.error();
	}
	return common::read_held_file(file_or.value(), maximum);
}

/**
 * @brief Compare one observed digest against canonical published lowercase hex.
 * @param identity Observed same-descriptor size and digest.
 * @param expected Canonical lowercase SHA-256 claim.
 * @return OK for exact digest equality; malformed text or disagreement rejects.
 */
status compare_digest(const common::held_file_identity &identity, std::string_view expected)
{
	const auto representation = common::validate_sha256_hex_claim(expected, "package SHA-256");
	if (!representation.is_ok()) {
		return representation;
	}
	if (common::bytes_to_hex(identity.sha256.data(), identity.sha256.size()) != expected) {
		return status::data_loss(static_status_text("file SHA-256 differs from its declared authority"));
	}
	return status::ok();
}

/**
 * @brief Require exact root-injected version bytes without a second version parser.
 * @param path Exact source or product VERSION file.
 * @return OK only for the compiled version plus one LF; no normalization occurs.
 */
status verify_version_file(const fs::path &path)
{
	auto bytes_or = text_file(path, 256u);
	if (!bytes_or.is_ok()) {
		return bytes_or.error();
	}
	return bytes_or.value() == std::string(VERSION) + '\n' ?
		       status::ok() :
		       status::data_loss(
			       static_status_text("source or package VERSION differs from the packaging executable"));
}

/**
 * @brief Read the source root owned by the selected CMake build.
 * @param build Canonical existing build directory selected by the caller.
 * @return Exact source root, rejecting a missing, empty, or repeated source entry.
 * @details CMake owns configuration admission and staging. Other cache entries are not
 *          interpreted here; the complete file is bounded and held during its read.
 */
status_or<fs::path> read_source_root(const fs::path &build)
{
	auto cache_or = text_file(build / "CMakeCache.txt", MAX_BUILD_CACHE_BYTES);
	if (!cache_or.is_ok()) {
		return cache_or.error();
	}
	std::string_view source;
	constexpr std::string_view KEY = "CMAKE_HOME_DIRECTORY";
	std::string_view remaining(cache_or.value());
	while (!remaining.empty()) {
		const auto newline = remaining.find('\n');
		const auto line = remaining.substr(0, newline);
		remaining = newline == std::string_view::npos ? std::string_view{} : remaining.substr(newline + 1u);
		const auto colon = line.find(':');
		if (line.substr(0, colon) != KEY) {
			continue;
		}
		const auto equal = colon == std::string_view::npos ? colon : line.find('=', colon + 1u);
		if (equal == std::string_view::npos || !source.empty() || equal + 1u == line.size()) {
			return status::invalid_argument(
				static_status_text("CMake source location is missing, empty, or repeated"));
		}
		source = line.substr(equal + 1u);
	}
	if (source.empty() || source.size() > release::MAX_PAYLOAD_PATH_BYTES ||
	    source.find('\0') != std::string_view::npos) {
		return status::invalid_argument(
			static_status_text("selected build lacks a bounded CMake source location"));
	}
	const fs::path path(source);
	const auto exact = common::validate_exact_directory(path, KEY);
	if (!exact.is_ok()) {
		return exact;
	}
	return path;
}

/**
 * @brief Bind staged build policy to the exact running packager image.
 * @param staged Installer copied by the selected build's CMake envelope component.
 * @return OK only for byte-identical images, including size, before native admission.
 */
status verify_packager_identity(const fs::path &staged)
{
	auto image_or = common::current_process_image();
	if (!image_or.is_ok()) {
		return image_or.error();
	}
	auto running_or = source_file(image_or.value(), release::MAX_PAYLOAD_FILE_BYTES);
	if (!running_or.is_ok()) {
		return running_or.error();
	}
	struct stat kernel{};
	struct stat held{};
	if (::stat("/proc/self/exe", &kernel) != 0 || ::fstat(running_or->descriptor(), &held) != 0) {
		return system_error("cannot verify running packager inode");
	}
	if (kernel.st_dev != held.st_dev || kernel.st_ino != held.st_ino) {
		return status::failed_precondition(static_status_text("running packager pathname changed"));
	}
	auto staged_or = input_file(staged, release::MAX_PAYLOAD_FILE_BYTES);
	if (!staged_or.is_ok()) {
		return staged_or.error();
	}
	const auto same = common::verify_held_file_identity(staged_or.value(), running_or->identity().sha256,
							    running_or->identity().size_bytes);
	return same.is_ok() ?
		       status::ok() :
		       status::failed_precondition(static_status_text(
			       "selected build has a different packager; invoke that build's kinetum_package or a byte-identical copy"));
}

/** One filesystem candidate awaiting final no-replacement publication. */
struct pending_file {
	std::string candidate;		      ///< Owned mutable mkstemp pathname, then immutable.
	fs::path output;		      ///< Final explicit file pathname.
	common::held_file_identity identity;  ///< Complete bytes proven before reporting.
	bool armed;			      ///< Candidate cleanup remains owned until publication.
};

/** Transient directory ownership survives expected exceptions until diagnostics are emitted. */
class workspace {
    public:
	/** @brief Begin with no temporary filesystem authority. */
	workspace() = default;
	/** @brief Prevent duplicate cleanup ownership. */
	workspace(const workspace &) = delete;
	/** @brief Prevent duplicate cleanup ownership. */
	workspace &operator=(const workspace &) = delete;
	/**
	 * @brief Create an exclusive mode-0700 working directory under an admitted parent.
	 * @param parent Existing exact owner-controlled parent.
	 * @return New absolute root; this workspace owns cleanup even if later allocation fails.
	 */
	[[nodiscard]] status_or<fs::path> create(const fs::path &parent)
	{
		std::string pattern = (parent / ".kinetum-package-XXXXXX").string();
		// Reserve and construct the eventual owner before mkdtemp can create it.
		directories_.reserve(directories_.size() + 1u);
		directories_.push_back(std::move(pattern));
		char *created = ::mkdtemp(directories_.back().data());
		if (created == nullptr) {
			directories_.pop_back();
			return system_error("cannot create private package work");
		}
		return fs::path(directories_.back());
	}
	/**
	 * @brief Retire every owned directory, reporting all cleanup failures.
	 * @return OK after every root retires; failure leaves ownership armed for fail-stop.
	 */
	[[nodiscard]] status cleanup() noexcept
	{
		bool failed = false;
		for (auto iterator = directories_.rbegin(); iterator != directories_.rend(); ++iterator) {
			if (iterator->empty()) {
				continue;
			}
			try {
				std::error_code error;
				(void)fs::remove_all(*iterator, error);
				if (!error) {
					iterator->clear();
					continue;
				}
			} catch (const std::bad_alloc &) {
				// Ownership remains armed; cleanup failure is terminal below.
			} catch (const std::length_error &) {
				// The original operation's diagnostic is retained by the caller.
			}
			failed = true;
			(void)common::emit_process_output({{}, "kinetum_package: cannot retire private directory ", 1});
			(void)common::emit_process_output({{}, *iterator, 1});
			(void)common::emit_process_output({{}, "\n", 1});
		}
		return failed ? status::internal_error(static_status_text("package directory cleanup failed")) :
				status::ok();
	}
	/** @brief Fail stop if an unexpected exception bypasses explicit cleanup. */
	~workspace()
	{
		if (!cleanup().is_ok()) {
			(void)common::emit_process_output(
				{{}, "kinetum_package: unresolved private directory cleanup\n", 1});
			std::abort();
		}
	}

    private:
	std::vector<std::string> directories_;	///< Exact created directories, retired in reverse order.
};

/**
 * @brief Render a status while its borrowed diagnostic views remain alive.
 * @param failure Live non-OK status whose views remain valid through emission.
 * @return Nonzero process-output result; error reporting never allocates.
 */
int report_error(const status &failure) noexcept
{
	(void)common::emit_process_output({{}, "kinetum_package: ", 1});
	(void)common::emit_process_output({{}, failure.message(), 1});
	if (!failure.details().empty()) {
		(void)common::emit_process_output({{}, ": ", 1});
		(void)common::emit_process_output({{}, failure.details(), 1});
	}
	return common::emit_process_output({{}, "\n", 1});
}

/** Main-thread descriptor ownership of SIGINT/SIGTERM; no asynchronous handler exists. */
class signal_input {
    public:
	/** @brief Begin before signal-mask admission. */
	signal_input() = default;
	/** @brief Prevent duplicate signal-descriptor ownership. */
	signal_input(const signal_input &) = delete;
	/** @brief Prevent duplicate signal-descriptor ownership. */
	signal_input &operator=(const signal_input &) = delete;
	/**
	 * @brief Block before children or filesystem effects, then own a signalfd.
	 * @return OK only after mask, descriptor and child/output dispositions are established.
	 */
	[[nodiscard]] status start()
	{
		sigset_t mask;
		if (::sigemptyset(&mask) != 0 || ::sigaddset(&mask, SIGINT) != 0 || ::sigaddset(&mask, SIGTERM) != 0 ||
		    ::sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) {
			return system_error("cannot block package termination signals");
		}
		descriptor_ = ::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
		if (descriptor_ < 0) {
			return system_error("cannot open package signal descriptor");
		}
		struct sigaction action{};
		action.sa_handler = SIG_DFL;
		// Inherited SIGCHLD ignore/NOCLDWAIT would erase the retained leader
		// before this process retires its group and performs the exact reap.
		if (::sigemptyset(&action.sa_mask) != 0 || ::sigaction(SIGINT, &action, nullptr) != 0 ||
		    ::sigaction(SIGTERM, &action, nullptr) != 0 || ::sigaction(SIGCHLD, &action, nullptr) != 0) {
			return system_error("cannot establish package termination dispositions");
		}
		action.sa_handler = SIG_IGN;
		if (::sigaction(SIGPIPE, &action, nullptr) != 0) {
			return system_error("cannot establish package output signal policy");
		}
		return status::ok();
	}
	/** @brief Close the sole signal descriptor when the process is done. */
	~signal_input()
	{
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
	}
	/** @return Borrowed pollable descriptor, valid after start and until destruction. */
	[[nodiscard]] int descriptor() const noexcept
	{
		return descriptor_;
	}
	/** @return OK with no pending signal, sticky CANCELLED, or an invalid-record failure. */
	[[nodiscard]] status check()
	{
		if (cancelled_) {
			return status::cancelled(static_status_text("package operation was interrupted"));
		}
		signalfd_siginfo record{};
		ssize_t count;
		do {
			count = ::read(descriptor_, &record, sizeof(record));
		} while (count < 0 && errno == EINTR);
		if (count < 0 && errno == EAGAIN) {
			return status::ok();
		}
		if (count != static_cast<ssize_t>(sizeof(record)) ||
		    (record.ssi_signo != SIGINT && record.ssi_signo != SIGTERM)) {
			return status::internal_error(
				static_status_text("package signal descriptor returned an invalid record"));
		}
		cancelled_ = true;
		return status::cancelled(static_status_text("package operation was interrupted"));
	}

    private:
	int descriptor_{-1};	 ///< Sole main-thread event descriptor.
	bool cancelled_{false};	 ///< Cancellation remains terminal once observed.
};

/** A child PID remains unreaped until its private process group is retired. */
class child_process {
    public:
	/**
	 * @brief Adopt a newly forked, still-owned child PID.
	 * @param pid Positive unreaped child identity; its group must remain owner-controlled.
	 */
	explicit child_process(pid_t pid) noexcept
		: pid_(pid)
	{
	}
	/** @brief Prevent duplicate process-group ownership. */
	child_process(const child_process &) = delete;
	/** @brief Prevent duplicate process-group ownership. */
	child_process &operator=(const child_process &) = delete;
	/** @brief Kill the owned group once, then reap its leader with no PID-reuse window. */
	void finish() noexcept
	{
		if (pid_ < 0 || (::kill(-pid_, SIGKILL) != 0 && errno != ESRCH)) {
			(void)common::emit_process_output({{}, "kinetum_package: child-group retirement failed\n", 1});
			std::abort();
		}
		int result = 0;
		pid_t observed;
		do {
			observed = ::waitpid(pid_, &result, 0);
		} while (observed < 0 && errno == EINTR);
		if (observed != pid_) {
			(void)common::emit_process_output(
				{{}, "kinetum_package: child reap authority is unresolved\n", 1});
			std::abort();
		}
		pid_ = -1;
	}
	/** @brief Retire unreported child ownership during allocation unwinding. */
	~child_process()
	{
		if (pid_ < 0) {
			return;
		}
		finish();
	}

    private:
	pid_t pid_;  ///< Positive until group retirement and exact leader reap.
};

/**
 * @brief Run one disposable single-threaded worker with bounded output and time.
 * @param signals Main-thread cancellation owner.
 * @param timeout Positive child execution/capture deadline.
 * @param retained_descriptor Sole input descriptor inherited beyond standard streams, or -1.
 * @param execute Cold child operation; a tool exec never returns on success.
 * @tparam operation Callable returning status in the child.
 * @return Outcome after exactly one group retirement and leader reap, with complete output delivery.
 * @pre This process has one thread; captured inputs remain alive throughout the call.
 */
template <typename operation>
status run_child(signal_input &signals, std::chrono::steady_clock::duration timeout, int retained_descriptor,
		 operation &&execute)
{
	const auto ready = signals.check();
	if (!ready.is_ok()) {
		return ready;
	}
	int pipe_descriptors[2];
	if (::pipe2(pipe_descriptors, O_CLOEXEC | O_NONBLOCK) != 0) {
		return system_error("cannot create package child output pipe");
	}
	const pid_t pid = ::fork();
	if (pid < 0) {
		const int error = errno;
		(void)::close(pipe_descriptors[0]);
		(void)::close(pipe_descriptors[1]);
		return system_error("cannot create package worker", error);
	}
	if (pid == 0) {
		if (::setpgid(0, 0) != 0) {
			::_exit(126);
		}
		const int input = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (input < 0 || ::dup2(input, STDIN_FILENO) < 0 || ::dup2(pipe_descriptors[1], STDOUT_FILENO) < 0 ||
		    ::dup2(pipe_descriptors[1], STDERR_FILENO) < 0 || ::fcntl(STDOUT_FILENO, F_SETFL, 0) < 0) {
			::_exit(126);
		}
		// No seed, parent signal input, or unrelated descriptor enters a worker.
		if (retained_descriptor < 3) {
			if (::syscall(SYS_close_range, 3u, UINT_MAX, 0u) != 0) {
				::_exit(126);
			}
		} else {
			if (retained_descriptor > 3 &&
			    ::syscall(SYS_close_range, 3u, static_cast<unsigned>(retained_descriptor - 1), 0u) != 0) {
				::_exit(126);
			}
			if (::syscall(SYS_close_range, static_cast<unsigned>(retained_descriptor) + 1u, UINT_MAX, 0u) !=
			    0) {
				::_exit(126);
			}
		}
		sigset_t mask;
		struct sigaction defaults{};
		defaults.sa_handler = SIG_DFL;
		if (::sigemptyset(&mask) != 0 || ::sigemptyset(&defaults.sa_mask) != 0 ||
		    ::sigaction(SIGINT, &defaults, nullptr) != 0 || ::sigaction(SIGTERM, &defaults, nullptr) != 0 ||
		    ::sigprocmask(SIG_SETMASK, &mask, nullptr) != 0) {
			::_exit(126);
		}
		try {
			const auto result = execute();
			if (!result.is_ok()) {
				(void)report_error(result);
				::_exit(1);
			}
			::_exit(0);
		} catch (const std::bad_alloc &) {
			(void)common::emit_process_output({{}, "package worker exhausted memory\n", 1});
			::_exit(1);
		} catch (const std::length_error &) {
			(void)common::emit_process_output({{}, "package worker exceeded a representation bound\n", 1});
			::_exit(1);
		}
	}
	child_process child(pid);
	(void)::close(pipe_descriptors[1]);
	/** @brief Close the parent capture pipe even during allocation unwinding. */
	struct pipe_owner {
		int value;  ///< Sole capture-pipe close obligation.
		/** @brief Close the parent pipe on normal completion and unwinding. */
		~pipe_owner()
		{
			(void)::close(value);
		}
	} capture{pipe_descriptors[0]};
	if (::setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
		return system_error("cannot bind package worker process group");
	}
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	std::string output;
	status outcome = status::ok();
	bool eof = false;
	siginfo_t observed{};
	for (;;) {
		std::array<char, 65536> buffer{};
		const ssize_t count = ::read(capture.value, buffer.data(), buffer.size());
		const int read_error = count < 0 ? errno : 0;
		if (count > 0) {
			const auto size = static_cast<std::size_t>(count);
			if (size > MAX_CHILD_OUTPUT_BYTES - output.size()) {
				outcome = status::resource_exhausted(
					static_status_text("package worker exceeded its output bound"));
				break;
			}
			output.append(buffer.data(), size);
		} else if (count == 0) {
			eof = true;
		} else if (read_error != EINTR && read_error != EAGAIN) {
			outcome = system_error("cannot capture package child output", read_error);
			break;
		}
		if (::waitid(P_PID, static_cast<id_t>(pid), &observed, WEXITED | WNOHANG | WNOWAIT) != 0 &&
		    errno != EINTR) {
			outcome = system_error("cannot observe package child");
			break;
		}
		if (observed.si_pid == pid && (eof || read_error == EAGAIN)) {
			if (observed.si_code != CLD_EXITED || observed.si_status != 0) {
				outcome = status::internal_error(
					static_status_text("package child did not complete successfully"));
			} else if (!eof) {
				outcome = status::failed_precondition(
					static_status_text("package child left descendant output ownership live"));
			}
			break;
		}
		outcome = signals.check();
		if (!outcome.is_ok()) {
			break;
		}
		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			outcome = status::deadline_exceeded(static_status_text("package worker deadline expired"));
			break;
		}
		pollfd events[2]{{capture.value, POLLIN, 0}, {signals.descriptor(), POLLIN, 0}};
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
		const int timeout_ms = static_cast<int>(std::min<int64_t>(remaining, 20));
		if (::poll(events, 2, timeout_ms) < 0 && errno != EINTR) {
			outcome = system_error("cannot poll package worker");
			break;
		}
	}
	child.finish();
	const auto rendered = outcome.is_ok() ? common::process_output_view{output, {}, 0} :
						common::process_output_view{{}, output, 0};
	if (common::emit_process_output(rendered) != 0) {
		if (!outcome.is_ok()) {
			(void)report_error(outcome);
		}
		return status::internal_error(static_status_text("cannot deliver package child output"));
	}
	return outcome;
}

/**
 * @brief Execute an explicit tool with one closed environment and null stdin.
 * @param signals Main-thread cancellation owner.
 * @param arguments Owned exact executable path and argv, with no shell interpretation.
 * @return Child outcome after bounded execution, group retirement, and output delivery.
 */
status run_tool(signal_input &signals, std::vector<std::string> arguments)
{
	std::vector<char *> argv;
	argv.reserve(arguments.size() + 1u);
	for (auto &argument : arguments) {
		argv.push_back(argument.data());
	}
	argv.push_back(nullptr);
	char path[] = "PATH=/usr/bin:/bin";
	char locale[] = "LC_ALL=C";
	char language[] = "LANG=C";
	char *environment[]{path, locale, language, nullptr};
	return run_child(signals, TOOL_TIMEOUT, -1, [&argv, &environment]() -> status {
		::execve(argv.front(), argv.data(), environment);
		return system_error("cannot execute package tool");
	});
}

/**
 * @brief Create a fixed private subdirectory and set its mode independently of umask.
 * @param path Absent child under an owned working parent.
 * @param mode Final permission bits independent of umask.
 * @return OK after creation and exact mode assignment; caller owns cleanup on failure.
 */
status make_directory(const fs::path &path, mode_t mode)
{
	if (::mkdir(path.c_str(), 0700) != 0) {
		return system_error("cannot create package directory");
	}
	return ::chmod(path.c_str(), mode) == 0 ? status::ok() : system_error("cannot set package directory mode");
}

/**
 * @brief Check CMake's fixed-file and whole-tree projections without selecting membership.
 * @param product Product whose CMake projections are checked.
 * @param source Immutable exact source root for native preparation; empty for signing.
 * @param envelope Complete private staged package root.
 * @param native_prepare Whether to check source bytes and native dependency outputs for this builder.
 * @return OK only when every applicable fixed file and complete tree matches its authority.
 */
status verify_projections(product_kind product, const fs::path &source, const fs::path &envelope, bool native_prepare)
{
	for (const auto &projection : FIXED_PROJECTIONS) {
		if (projection.product != product || (!native_prepare && projection.source.empty())) {
			continue;
		}
		if (native_prepare && !projection.source.empty()) {
			auto original_or = source_file(source / projection.source, release::MAX_PAYLOAD_FILE_BYTES);
			if (!original_or.is_ok()) {
				return original_or.error();
			}
			const auto same_source = compare_digest(original_or->identity(), projection.source_sha256);
			if (!same_source.is_ok()) {
				return same_source;
			}
		}
		auto output_or = input_file(envelope / projection.destination, release::MAX_PAYLOAD_FILE_BYTES);
		if (!output_or.is_ok()) {
			return output_or.error();
		}
		const auto same_output = compare_digest(output_or->identity(), projection.staged_sha256);
		if (!same_output.is_ok()) {
			return same_output;
		}
	}
	if (product == product_kind::SDK) {
		for (const auto &projection : TREE_PROJECTIONS) {
			const fs::path original = source / projection.relative_source;
			common::held_file_policy source_policy;
			source_policy.required_owner_uid.reset();
			const auto same_tree = release::verify_payload_projection(
				original, envelope / projection.destination, source_policy, tree_policy(envelope));
			if (!same_tree.is_ok()) {
				return same_tree;
			}
		}
	}
	return status::ok();
}

/**
 * @brief Check every ELF found in admitted membership, including the package executable.
 * @param root Immutable admitted envelope.
 * @param files Complete observed membership held by the caller.
 * @param tuple Required target identity.
 * @return OK for exact target/version on every ELF, including the installer.
 */
status verify_elfs(const fs::path &root, std::span<const release::payload_file> files,
		   provider::provider_target_tuple tuple)
{
	for (const auto &entry : files) {
		auto held_or = input_file(root / entry.relative_path, release::MAX_PAYLOAD_FILE_BYTES);
		if (!held_or.is_ok()) {
			return held_or.error();
		}
		std::array<unsigned char, 4> magic{};
		ssize_t count;
		do {
			count = ::pread(held_or->descriptor(), magic.data(), magic.size(), 0);
		} while (count < 0 && errno == EINTR);
		if (count < 0) {
			return system_error("cannot inspect staged file magic");
		}
		if (entry.relative_path == "kinetum_package" ||
		    (count == 4 && magic == std::array<unsigned char, 4>{0x7f, 'E', 'L', 'F'})) {
			const auto verified = release::verify_package_elf(held_or.value(), tuple, VERSION);
			if (!verified.is_ok()) {
				return verified;
			}
		}
	}
	return status::ok();
}

/**
 * @brief Register and complete one unpublished archive under final-file ownership.
 * @param envelope Complete immutable package tree.
 * @param output Exact final name under an admitted existing parent.
 * @param pending Empty owner populated before private-file creation.
 * @return OK with a completed unpublished archive; pending retains cleanup on failure.
 */
status stage_archive(const fs::path &envelope, const fs::path &output, std::optional<pending_file> &pending)
{
	std::string pattern = (output.parent_path() / ".kinetum-archive-XXXXXX").string();
	// The owning record exists before mkstemp mutates its name. The same open
	// descriptor receives the archive; there is no close/unlink/reopen window.
	if (pending.has_value()) {
		return status::internal_error(static_status_text("one operation cannot own two output archives"));
	}
	pending.emplace(pending_file{std::move(pattern), output, {}, false});
	const int raw = ::mkostemp(pending->candidate.data(), O_CLOEXEC);
	if (raw < 0) {
		return system_error("cannot create private archive output");
	}
	pending->armed = true;
	/** @brief Close the private write descriptor on every path. */
	struct output_owner {
		int value;  ///< Private archive descriptor, or -1 after checked close.
		/** @brief Close an unfinished private output while its namespace remains owned. */
		~output_owner()
		{
			if (value >= 0) {
				(void)::close(value);
			}
		}
	} output_fd{raw};
	auto files_or = release::read_package_tree(envelope, tree_policy(envelope));
	if (!files_or.is_ok()) {
		return files_or.error();
	}
	const auto written =
		release::write_package_archive(envelope, files_or.value(), output_fd.value, tree_policy(envelope));
	if (!written.is_ok()) {
		return written;
	}
	if (::close(std::exchange(output_fd.value, -1)) != 0) {
		return system_error("cannot close archive output");
	}
	auto completed_or = input_file(pending->candidate, release::MAX_PACKAGE_ARCHIVE_BYTES);
	if (!completed_or.is_ok()) {
		return completed_or.error();
	}
	pending->identity = completed_or->identity();
	return status::ok();
}

/**
 * @brief Decode in a disposable process that cannot inherit the signing descriptor.
 * @param signals Main-thread cancellation owner.
 * @param archive Held input outliving the decoder process.
 * @param destination Empty mode-0700 owned directory.
 * @param product Exact expected envelope identity.
 * @return OK after complete admission/extraction and decoder-group retirement.
 */
status extract_archive(signal_input &signals, const common::held_file &archive, const fs::path &destination,
		       product_kind product)
{
	const std::string root = envelope_name(product);
	return run_child(signals, WORKER_TIMEOUT, archive.descriptor(), [&archive, &destination, &root] {
		return release::extract_package_archive(archive, destination, root);
	});
}

/**
 * @brief Verify every envelope file belongs to the selected product or its one installer.
 * @param root Private immutable extracted or staged envelope.
 * @param product Selected public product.
 * @param tuple Required artifact target.
 * @return OK for one installer of the required tuple and only the selected product subtree.
 */
status verify_envelope(const fs::path &root, product_kind product, provider::provider_target_tuple tuple)
{
	auto files_or = release::read_package_tree(root, tree_policy(root));
	if (!files_or.is_ok()) {
		return files_or.error();
	}
	const std::string prefix = std::string(product_name(product)) + "/";
	bool installer = false;
	for (const auto &file : files_or.value()) {
		if (file.relative_path == "kinetum_package") {
			installer = file.mode == 0755u;
		} else if (!std::string_view(file.relative_path).starts_with(prefix)) {
			return status::data_loss(static_status_text("package envelope contains an unowned member"));
		}
	}
	if (!installer) {
		return status::data_loss(static_status_text("package envelope lacks its executable installer"));
	}
	const auto version = verify_version_file(root / product_name(product) / "VERSION");
	if (!version.is_ok()) {
		return version;
	}
	return verify_elfs(root, files_or.value(), tuple);
}

/**
 * @brief Check a completed product without loading any of its images.
 * @param root Exact immutable runtime or SDK payload.
 * @param product Selected product contract.
 * @param tuple Required runtime artifact target.
 * @return OK only for complete product integrity; runtime also authenticates provider provenance.
 */
status verify_product(const fs::path &root, product_kind product, provider::provider_target_tuple tuple)
{
	const auto version = verify_version_file(root / "VERSION");
	if (!version.is_ok()) {
		return version;
	}
	if (product == product_kind::RUNTIME) {
		const auto result = release::verify_runtime_payload(root, tuple, tree_policy(root));
		if (!result.payload.is_ok()) {
			return result.payload;
		}
		return result.provider;
	}
	auto files_or = release::read_verified_payload(root, SDK_MANIFEST, tree_policy(root));
	if (!files_or.is_ok()) {
		return files_or.error();
	}
	// Fixed SDK metadata is CMake-derived. Tree projection and independent
	// consumer qualification happen before release; installation verifies the
	// resulting complete manifest under the authenticated delivery channel.
	for (const auto &projection : FIXED_PROJECTIONS) {
		if (projection.product != product_kind::SDK) {
			continue;
		}
		const fs::path relative = fs::path(projection.destination).lexically_relative("sdk");
		auto file_or = input_file(root / relative, release::MAX_PAYLOAD_FILE_BYTES);
		if (!file_or.is_ok()) {
			return file_or.error();
		}
		const auto identical = compare_digest(file_or->identity(), projection.staged_sha256);
		if (!identical.is_ok()) {
			return identical;
		}
	}
	for (const std::string_view required : {"include/kinetum/kinetum_sdk.h", "include/kinetum/kinetum_sdk.hpp"}) {
		const auto found = std::find_if(files_or->begin(), files_or->end(), [required](const auto &file) {
			return file.relative_path == required && file.identity.size_bytes != 0;
		});
		if (found == files_or->end()) {
			return status::data_loss(
				static_status_text("SDK product lacks a required consumer entry point"));
		}
	}
	return status::ok();
}

/**
 * @brief Read back one completed private archive and compare its full decoded copy set.
 * @param signals Main-thread cancellation owner.
 * @param work Owner of the temporary decoded tree.
 * @param original Immutable source envelope.
 * @param pending Completed private archive and its output authority.
 * @param product Expected envelope product.
 * @return OK for equal complete decoded bytes, modes, and membership before publication.
 */
status verify_written_archive(signal_input &signals, workspace &work, const fs::path &original,
			      const pending_file &pending, product_kind product)
{
	auto extracted_or = work.create(pending.output.parent_path());
	if (!extracted_or.is_ok()) {
		return extracted_or.error();
	}
	auto archive_or = input_file(pending.candidate, release::MAX_PACKAGE_ARCHIVE_BYTES);
	if (!archive_or.is_ok()) {
		return archive_or.error();
	}
	const auto extracted = extract_archive(signals, archive_or.value(), extracted_or.value(), product);
	if (!extracted.is_ok()) {
		return extracted;
	}
	const fs::path observed = extracted_or.value() / envelope_name(product);
	auto before_or = release::read_package_tree(original, tree_policy(original));
	if (!before_or.is_ok()) {
		return before_or.error();
	}
	auto after_or = release::read_package_tree(observed, tree_policy(observed));
	if (!after_or.is_ok()) {
		return after_or.error();
	}
	if (before_or->size() != after_or->size()) {
		return status::data_loss(static_status_text("archive round trip changed membership"));
	}
	for (std::size_t index = 0; index < before_or->size(); ++index) {
		const auto &before = (*before_or)[index];
		const auto &after = (*after_or)[index];
		if (before.relative_path != after.relative_path || before.identity.sha256 != after.identity.sha256 ||
		    before.identity.size_bytes != after.identity.size_bytes || before.mode != after.mode) {
			return status::data_loss(static_status_text("archive round trip changed bytes or modes"));
		}
	}
	return status::ok();
}

/**
 * @brief Stage one public product from an existing configured and completed build.
 * @param arguments Product, required build directory, and optional output directory.
 * @param signals Main-thread cancellation owner.
 * @param work Owner of transient staging and readback directories.
 * @param pending Archive owner populated before file effects.
 * @return OK for a complete unpublished candidate; no configure or compilation occurs.
 */
status prepare(const command &arguments, signal_input &signals, workspace &work, std::optional<pending_file> &pending)
{
	auto product_or = parse_product(arguments.values.at("--product"));
	if (!product_or.is_ok()) {
		return product_or.error();
	}
	const auto product = product_or.value();
	const auto tuple = provider::native_provider_target_tuple();
	auto build_or =
		common::admit_explicit_directory(fs::path(arguments.values.at("--build-dir")), "existing build");
	if (!build_or.is_ok()) {
		return build_or.error();
	}
	const auto &build = build_or.value();
	auto source_or = read_source_root(build);
	if (!source_or.is_ok()) {
		return source_or.error();
	}
	const auto &source = source_or.value();
	const auto source_version = verify_version_file(source / "VERSION");
	if (!source_version.is_ok()) {
		return source_version;
	}
	auto output_directory_or = archive_output_directory(arguments);
	if (!output_directory_or.is_ok()) {
		return output_directory_or.error();
	}
	const auto &output_directory = output_directory_or.value();
	const fs::path output = output_directory / archive_name(product, tuple, product == product_kind::RUNTIME);
	if (product == product_kind::SDK) {
		for (const auto &projection : TREE_PROJECTIONS) {
			const fs::path input = source / projection.relative_source;
			for (const auto &destination : {build, output_directory}) {
				const auto relative = destination.lexically_relative(input);
				if (!relative.empty() && *relative.begin() != "..") {
					return status::invalid_argument(static_status_text(
						"SDK build and output paths must remain outside projected input trees"));
				}
			}
		}
	}
	const auto created = create_archive_output_directory(output_directory);
	if (!created.is_ok()) {
		return created;
	}
	auto stage_or = work.create(output_directory);
	if (!stage_or.is_ok()) {
		return stage_or.error();
	}
	const fs::path envelope = stage_or.value() / envelope_name(product);
	const auto made = make_directory(envelope, 0755);
	if (!made.is_ok()) {
		return made;
	}
	const auto staged_installer =
		run_tool(signals, {"/usr/bin/cmake", "--install", build.string(), "--config", "Release", "--prefix",
				   envelope.string(), "--component", "KinetumPackageEnvelope"});
	if (!staged_installer.is_ok()) {
		return staged_installer;
	}
	const auto same_packager = verify_packager_identity(envelope / "kinetum_package");
	if (!same_packager.is_ok()) {
		return same_packager;
	}
	const std::string component = product == product_kind::RUNTIME ? "KinetumRuntimePayload" : "KinetumSDK";
	const auto staged_payload =
		run_tool(signals, {"/usr/bin/cmake", "--install", build.string(), "--config", "Release", "--prefix",
				   envelope.string(), "--component", component});
	if (!staged_payload.is_ok()) {
		return staged_payload;
	}
	const auto projections = verify_projections(product, source, envelope, true);
	if (!projections.is_ok()) {
		return projections;
	}
	const fs::path payload = envelope / product_name(product);
	if (product == product_kind::RUNTIME) {
		const auto prepared = run_child(signals, WORKER_TIMEOUT, -1, [&payload, tuple] {
			return release::prepare_provider_release_candidate(payload, tuple,
									   static_cast<uint32_t>(::geteuid()));
		});
		if (!prepared.is_ok()) {
			return prepared;
		}
	} else {
		const auto manifest = release::generate_payload_manifest(payload, SDK_MANIFEST, tree_policy(payload));
		if (!manifest.is_ok()) {
			return manifest;
		}
		const auto checked = verify_product(payload, product, tuple);
		if (!checked.is_ok()) {
			return checked;
		}
	}
	const auto checked = verify_envelope(envelope, product, tuple);
	if (!checked.is_ok()) {
		return checked;
	}
	const auto staged = stage_archive(envelope, output, pending);
	if (!staged.is_ok()) {
		return staged;
	}
	return verify_written_archive(signals, work, envelope, *pending, product);
}

/** Product and tuple derived from one complete current-version asset basename. */
struct package_identity {
	product_kind product;			///< Runtime or SDK.
	provider::provider_target_tuple tuple;	///< One supported ELF tuple.
};

/**
 * @brief Admit the exact requested final archive or unsigned-runtime-candidate name.
 * @param path Explicit archive path.
 * @param candidate Whether the input must be an unsigned runtime candidate.
 * @return Product and tuple only for an exact current-version basename of the requested form.
 */
status_or<package_identity> identify_archive(const fs::path &path, bool candidate)
{
	for (const auto product : {product_kind::RUNTIME, product_kind::SDK}) {
		if (candidate && product != product_kind::RUNTIME) {
			continue;
		}
		for (const auto tuple : {provider::provider_target_tuple::LINUX_GNU_AARCH64,
					 provider::provider_target_tuple::LINUX_GNU_X86_64}) {
			if (path.filename() == archive_name(product, tuple, candidate)) {
				return package_identity{product, tuple};
			}
		}
	}
	return status::invalid_argument(static_status_text(
		"archive name does not identify the required product, version, and candidate/final form"));
}

/**
 * @brief Decode without key access, then sign statically with no child or target-code call.
 * @param arguments Explicit candidate and key file, plus optional archive output directory.
 * @param signals Main-thread cancellation owner.
 * @param work Owner of private decoding and readback trees.
 * @param pending Final archive ownership before publication.
 * @return OK after static signing and full readback; private key bytes retire before archive work.
 */
status sign(const command &arguments, signal_input &signals, workspace &work, std::optional<pending_file> &pending)
{
	const auto protected_process = release::protect_provider_release_key_process();
	if (!protected_process.is_ok()) {
		return protected_process;
	}
	auto candidate_path_or =
		common::admit_explicit_regular_file(fs::path(arguments.values.at("--candidate")), "runtime candidate");
	if (!candidate_path_or.is_ok()) {
		return candidate_path_or.error();
	}
	auto identity_or = identify_archive(candidate_path_or.value(), true);
	if (!identity_or.is_ok()) {
		return identity_or.error();
	}
	const auto tuple = identity_or->tuple;
	auto archive_or = input_file(candidate_path_or.value(), release::MAX_PACKAGE_ARCHIVE_BYTES);
	if (!archive_or.is_ok()) {
		return archive_or.error();
	}
	auto output_directory_or = archive_output_directory(arguments);
	if (!output_directory_or.is_ok()) {
		return output_directory_or.error();
	}
	const auto created = create_archive_output_directory(output_directory_or.value());
	if (!created.is_ok()) {
		return created;
	}
	const fs::path output = output_directory_or.value() / archive_name(product_kind::RUNTIME, tuple, false);
	auto stage_or = work.create(output_directory_or.value());
	if (!stage_or.is_ok()) {
		return stage_or.error();
	}
	const auto extracted = extract_archive(signals, archive_or.value(), stage_or.value(), product_kind::RUNTIME);
	if (!extracted.is_ok()) {
		return extracted;
	}
	const fs::path envelope = stage_or.value() / envelope_name(product_kind::RUNTIME);
	const fs::path payload = envelope / "runtime";
	const auto checked = verify_envelope(envelope, product_kind::RUNTIME, tuple);
	if (!checked.is_ok()) {
		return checked;
	}
	const auto projections = verify_projections(product_kind::RUNTIME, {}, envelope, false);
	if (!projections.is_ok()) {
		return projections;
	}
	const auto manifest_absent = require_absent(payload / release::RUNTIME_PAYLOAD_MANIFEST);
	if (!manifest_absent.is_ok()) {
		return manifest_absent;
	}
	{
		// The decoder is reaped before the key is opened. This scope launches
		// nothing; both private storage and its descriptor retire before archive work.
		const fs::path supplied_key(arguments.values.at("--key"));
		for (const auto &component : supplied_key) {
			if (component == "..") {
				return status::invalid_argument(
					static_status_text("signing-key path must not contain '..'"));
			}
		}
		std::error_code error;
		const auto key_path = fs::absolute(supplied_key, error).lexically_normal();
		if (error || key_path.filename().empty()) {
			return status::invalid_argument(static_status_text("cannot resolve signing-key file"));
		}
		auto parent_or = open_package_directory(key_path.parent_path(), false);
		if (!parent_or.is_ok()) {
			return parent_or.error();
		}
		file_descriptor seed(::openat(parent_or->value, key_path.filename().c_str(),
					      O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
		if (seed.value < 0) {
			return system_error("cannot open direct signing-key file");
		}
		{
			auto key_or = release::admit_provider_release_signing_key(
				seed.value, static_cast<uint32_t>(::geteuid()),
				provider::provider_release_trust_anchor());
			if (!key_or.is_ok()) {
				return key_or.error();
			}
			const auto finalized = release::finalize_provider_release_candidate(
				payload, tuple, static_cast<uint32_t>(::geteuid()), key_or.value(),
				provider::provider_release_trust_anchor());
			if (!finalized.is_ok()) {
				return finalized;
			}
		}
		if (::close(std::exchange(seed.value, -1)) != 0) {
			return system_error("cannot retire release signing descriptor");
		}
	}
	const auto manifest =
		release::generate_payload_manifest(payload, release::RUNTIME_PAYLOAD_MANIFEST, tree_policy(payload));
	if (!manifest.is_ok()) {
		return manifest;
	}
	const auto verified = verify_product(payload, product_kind::RUNTIME, tuple);
	if (!verified.is_ok()) {
		return verified;
	}
	const auto staged = stage_archive(envelope, output, pending);
	if (!staged.is_ok()) {
		return staged;
	}
	return verify_written_archive(signals, work, envelope, *pending, product_kind::RUNTIME);
}

/**
 * @brief Admit existing owned paths, including a partially completed prior installation.
 * @param prefix Exact destination root, possibly absent.
 * @param files Incoming verified membership defining owned top-level domains.
 * @param product Runtime or SDK replacement scope.
 * @return OK for a safe owned domain and preserved peers; no destination is modified.
 */
status admit_destination(const fs::path &prefix, std::span<const release::payload_file> files, product_kind product)
{
	std::map<std::string, bool> owned_roots;
	for (const auto &file : files) {
		const std::string path = product == product_kind::SDK ? "sdk/" + file.relative_path :
									file.relative_path;
		const std::size_t separator = path.find('/');
		owned_roots.emplace(path.substr(0, separator), separator != std::string::npos);
	}
	struct stat root{};
	if (::lstat(prefix.c_str(), &root) != 0) {
		return errno == ENOENT ? status::ok() : system_error("cannot inspect installation prefix");
	}
	const auto owned = admit_owned_directory(prefix);
	if (!owned.is_ok()) {
		return owned;
	}
	std::error_code error;
	fs::recursive_directory_iterator iterator(prefix, fs::directory_options::none, error), end;
	if (error) {
		return status(status_code::INTERNAL_ERROR, "cannot enumerate installation prefix", error.message());
	}
	std::size_t entries = 0;
	for (; iterator != end; iterator.increment(error)) {
		if (error) {
			return status(status_code::INTERNAL_ERROR, "cannot traverse installation prefix",
				      error.message());
		}
		const std::string relative = iterator->path().lexically_relative(prefix).generic_string();
		struct stat metadata{};
		if (::lstat(iterator->path().c_str(), &metadata) != 0) {
			return system_error("cannot inspect installed entry");
		}
		const bool top_level = relative.find('/') == std::string::npos;
		const bool peer = product == product_kind::RUNTIME ? (relative == "sdk" || relative == "dependencies") :
								     relative != "sdk";
		if (top_level && peer) {
			// SDK owns only sdk/. Runtime peers are exactly sdk/ and dependencies/.
			if (product == product_kind::RUNTIME &&
			    (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
			     (metadata.st_mode & 0022) != 0)) {
				return status::permission_denied(static_status_text(
					"independent installed peer is not an owned protected directory"));
			}
			iterator.disable_recursion_pending();
			continue;
		}
		if (++entries > release::MAX_PAYLOAD_ENTRIES) {
			return status::resource_exhausted(
				static_status_text("installed domain exceeds its entry bound"));
		}
		if (metadata.st_uid != ::geteuid() || metadata.st_dev != root.st_dev ||
		    (metadata.st_mode & 0022) != 0 ||
		    (!S_ISDIR(metadata.st_mode) && (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1))) {
			return status::permission_denied(static_status_text(
				"installed domain contains indirect, unowned, linked, or mounted state"));
		}
		if (top_level) {
			const auto owned_root = owned_roots.find(relative);
			if (owned_root == owned_roots.end() ||
			    owned_root->second != static_cast<bool>(S_ISDIR(metadata.st_mode))) {
				return status::data_loss(
					static_status_text("installation would replace an unowned root"));
			}
		}
	}
	if (error) {
		return status(status_code::INTERNAL_ERROR, "cannot finish installation traversal", error.message());
	}
	return status::ok();
}

/** One performed top-level transfer, retained until final verification succeeds. */
struct installed_entry {
	std::string name;  ///< One exact direct child.
	bool exchanged;	   ///< The prior child remains at the source name for restoration.
	bool applied;	   ///< This transfer has happened and may require reversal.
};

/**
 * @brief Restore performed transfers in reverse order, preserving all failure causes.
 * @param source Held directory retaining replaced objects.
 * @param destination Held installed prefix.
 * @param entries Transfer ledger updated only on successful reversals.
 * @return OK after every reversal and both syncs; failure retains unresolved ownership for fail-stop.
 */
status restore_installation(int source, int destination, std::vector<installed_entry> &entries) noexcept
{
	bool failed = false;
	for (auto iterator = entries.rbegin(); iterator != entries.rend(); ++iterator) {
		if (!iterator->applied) {
			continue;
		}
		const long result = iterator->exchanged ?
					    ::syscall(SYS_renameat2, source, iterator->name.c_str(), destination,
						      iterator->name.c_str(), RENAME_EXCHANGE) :
					    ::syscall(SYS_renameat2, destination, iterator->name.c_str(), source,
						      iterator->name.c_str(), RENAME_NOREPLACE);
		if (result != 0) {
			failed = true;
			(void)common::emit_process_output({{}, "kinetum_package: failed to restore ", 1});
			(void)common::emit_process_output({{}, iterator->name, 1});
			(void)common::emit_process_output({{}, "\n", 1});
		} else {
			iterator->applied = false;
		}
	}
	const bool source_synced = ::fsync(source) == 0;
	const bool destination_synced = ::fsync(destination) == 0;
	if (!source_synced) {
		(void)common::emit_process_output(
			{{}, "kinetum_package: restoration source durability is unconfirmed\n", 1});
	}
	if (!destination_synced) {
		(void)common::emit_process_output(
			{{}, "kinetum_package: restored destination durability is unconfirmed\n", 1});
	}
	if (failed) {
		return status::internal_error(static_status_text("installation restoration is incomplete"));
	}
	return source_synced && destination_synced ?
		       status::ok() :
		       status::internal_error(
			       static_status_text("prior entries were restored but their durability is unconfirmed"));
}

/**
 * @brief Install exact verified objects while retaining prior objects for failure restoration.
 * @param arguments Exact archive/digest/prefix inputs.
 * @param signals Main-thread cancellation owner.
 * @param work Owner of the private source and retained prior objects.
 * @return OK after installed verification; recoverable failure restores prior objects, double failure aborts.
 */
status install(const command &arguments, signal_input &signals, workspace &work)
{
	auto archive_path_or =
		common::admit_explicit_regular_file(fs::path(arguments.values.at("--archive")), "package archive");
	if (!archive_path_or.is_ok()) {
		return archive_path_or.error();
	}
	auto identity_or = identify_archive(archive_path_or.value(), false);
	if (!identity_or.is_ok()) {
		return identity_or.error();
	}
	const auto identity = identity_or.value();
	if (identity.product == product_kind::RUNTIME && ::geteuid() != 0) {
		return status::permission_denied(
			static_status_text("runtime installation requires root-owned production files"));
	}
	if (identity.tuple != provider::native_provider_target_tuple()) {
		return status::failed_precondition(
			static_status_text("installation archive does not match the native host tuple"));
	}
	const fs::path supplied_prefix(arguments.values.contains("--prefix") ? arguments.values.at("--prefix") :
									       "/opt/kinetum");
	if (!supplied_prefix.is_absolute() || supplied_prefix != supplied_prefix.lexically_normal() ||
	    supplied_prefix == "/") {
		return status::invalid_argument(
			static_status_text("installation prefix must be exact, absolute, and non-root"));
	}
	auto prefix_or = output_path(supplied_prefix.native());
	if (!prefix_or.is_ok()) {
		return prefix_or.error();
	}
	const fs::path prefix = prefix_or.value();
	/** @brief Keep installer serialization and exact directory descriptors until completion. */
	struct installation_descriptors {
		int parent{-1};	      ///< Held publication parent and installer lock.
		int source{-1};	      ///< Verified new entries and retained prior objects.
		int destination{-1};  ///< Installed prefix participating in transfers.
		/** @brief Retire transfer descriptors before releasing installer serialization. */
		~installation_descriptors()
		{
			if (source >= 0) {
				(void)::close(source);
			}
			if (destination >= 0) {
				(void)::close(destination);
			}
			if (parent >= 0) {
				(void)::close(parent);
			}
		}
	} descriptors;
	descriptors.parent = ::open(prefix.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (descriptors.parent < 0) {
		return system_error("cannot retain installation parent");
	}
	if (::flock(descriptors.parent, LOCK_EX | LOCK_NB) != 0) {
		return status::failed_precondition(
			static_status_text("installation parent is in use by another installer"));
	}
	auto archive_or = input_file(archive_path_or.value(), release::MAX_PACKAGE_ARCHIVE_BYTES);
	if (!archive_or.is_ok()) {
		return archive_or.error();
	}
	if (arguments.values.contains("--sha256")) {
		const auto digest = compare_digest(archive_or->identity(), arguments.values.at("--sha256"));
		if (!digest.is_ok()) {
			return digest;
		}
	}
	auto stage_or = work.create(prefix.parent_path());
	if (!stage_or.is_ok()) {
		return stage_or.error();
	}
	const auto extracted = extract_archive(signals, archive_or.value(), stage_or.value(), identity.product);
	if (!extracted.is_ok()) {
		return extracted;
	}
	const fs::path envelope = stage_or.value() / envelope_name(identity.product);
	const fs::path payload = envelope / product_name(identity.product);
	const auto envelope_status = verify_envelope(envelope, identity.product, identity.tuple);
	if (!envelope_status.is_ok()) {
		return envelope_status;
	}
	const auto product_status = verify_product(payload, identity.product, identity.tuple);
	if (!product_status.is_ok()) {
		return product_status;
	}
	auto files_or = release::read_verified_payload(
		payload, identity.product == product_kind::RUNTIME ? release::RUNTIME_PAYLOAD_MANIFEST : SDK_MANIFEST,
		tree_policy(payload));
	if (!files_or.is_ok()) {
		return files_or.error();
	}
	const auto destination_status = admit_destination(prefix, files_or.value(), identity.product);
	if (!destination_status.is_ok()) {
		return destination_status;
	}
	std::set<std::string> names;
	for (const auto &file : files_or.value()) {
		names.insert(identity.product == product_kind::SDK ?
				     "sdk" :
				     file.relative_path.substr(0, file.relative_path.find('/')));
	}
	std::vector<installed_entry> entries;
	entries.reserve(names.size());
	for (const auto &name : names) {
		entries.push_back({name, false, false});
	}
	const std::string report = "Installing verified " + std::string(product_name(identity.product)) + " " +
				   std::string(VERSION) + " into " + prefix.string() + "\n";
	const auto ready = signals.check();
	if (!ready.is_ok()) {
		return ready;
	}
	if (common::emit_process_output({report, {}, 0}) != 0) {
		return status::internal_error(
			static_status_text("cannot deliver installation report before replacement"));
	}
	const std::string prefix_name = prefix.filename().string();
	/** A newly created prefix is temporary until installation is verified. */
	struct empty_prefix {
		int parent;	    ///< Borrowed held parent, outliving this guard.
		const char *name;   ///< Preconstructed exact leaf, outliving this guard.
		bool armed{false};  ///< Only this invocation created the still-uncommitted prefix.
		/** @brief Remove only the empty prefix owned by this invocation. */
		bool discard() noexcept
		{
			if (armed && ::unlinkat(parent, name, AT_REMOVEDIR) != 0) {
				return false;
			}
			armed = false;
			return true;
		}
		/** @brief Fail stop if an unexpected unwind leaves prefix ownership unresolved. */
		~empty_prefix()
		{
			if (!discard()) {
				(void)common::emit_process_output(
					{{}, "kinetum_package: unresolved new-prefix cleanup\n", 1});
				std::abort();
			}
		}
	} prefix_guard{descriptors.parent, prefix_name.c_str()};
	status outcome = status::ok();
	/** @brief Perform transfers while retaining every prior object for reversal. */
	const auto transfer = [&]() -> status {
		struct stat metadata{};
		if (::fstatat(descriptors.parent, prefix_name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
			if (errno != ENOENT || ::mkdirat(descriptors.parent, prefix_name.c_str(), 0700) != 0) {
				return system_error("cannot create installation prefix");
			}
			prefix_guard.armed = true;
		}
		descriptors.destination = ::openat(descriptors.parent, prefix_name.c_str(),
						   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		descriptors.source = ::open((identity.product == product_kind::SDK ? envelope : payload).c_str(),
					    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (descriptors.destination < 0 || descriptors.source < 0) {
			return system_error("cannot hold installation transfer roots");
		}
		if (prefix_guard.armed && ::fchmod(descriptors.destination, 0755) != 0) {
			return system_error("cannot set installation-prefix mode");
		}
		for (auto &entry : entries) {
			const auto cancellation = signals.check();
			if (!cancellation.is_ok()) {
				return cancellation;
			}
			struct stat existing{};
			entry.exchanged = ::fstatat(descriptors.destination, entry.name.c_str(), &existing,
						    AT_SYMLINK_NOFOLLOW) == 0;
			if (!entry.exchanged && errno != ENOENT) {
				return system_error("cannot inspect exact installation destination");
			}
			if (::syscall(SYS_renameat2, descriptors.source, entry.name.c_str(), descriptors.destination,
				      entry.name.c_str(), entry.exchanged ? RENAME_EXCHANGE : RENAME_NOREPLACE) != 0) {
				return system_error("cannot transfer verified installation entry");
			}
			entry.applied = true;
		}
		status verified = status::ok();
		if (identity.product == product_kind::RUNTIME) {
			verified = verify_version_file(prefix / "VERSION");
			if (verified.is_ok()) {
				const auto runtime =
					release::verify_installed_runtime(prefix, identity.tuple, tree_policy(prefix));
				verified = runtime.payload.is_ok() ? runtime.provider : runtime.payload;
			}
		} else {
			verified = verify_product(prefix / "sdk", identity.product, identity.tuple);
		}
		if (!verified.is_ok()) {
			return verified;
		}
		if (::fsync(descriptors.destination) != 0 || ::fsync(descriptors.parent) != 0 ||
		    ::fsync(descriptors.source) != 0) {
			return system_error("cannot sync installed directory identities");
		}
		return status::ok();
	};
	try {
		outcome = transfer();
	} catch (const std::bad_alloc &) {
		outcome = status::resource_exhausted(
			static_status_text("installation exhausted memory before verification completed"));
	} catch (const std::length_error &) {
		outcome =
			status::resource_exhausted(static_status_text("installation exceeded a representation bound"));
	}
	if (outcome.is_ok()) {
		prefix_guard.armed = false;
		return outcome;
	}
	const bool transferred =
		std::any_of(entries.begin(), entries.end(), [](const auto &entry) { return entry.applied; });
	const auto restored = transferred ? restore_installation(descriptors.source, descriptors.destination, entries) :
					    status::ok();
	if (!restored.is_ok() || !prefix_guard.discard()) {
		(void)report_error(outcome);
		if (!restored.is_ok()) {
			(void)report_error(restored);
		} else {
			(void)common::emit_process_output(
				{{}, "kinetum_package: empty-prefix cleanup also failed\n", 1});
		}
		(void)common::emit_process_output({{}, "Retaining installation recovery tree: ", 1});
		(void)common::emit_process_output({{}, stage_or->native(), 1});
		(void)common::emit_process_output({{}, "\n", 1});
		std::abort();
	}
	return outcome;
}

/**
 * @brief Substitute a required bootstrap token with already-admitted literal data.
 * @param text Owned bootstrap text being composed.
 * @param token Required fixed template token.
 * @param value Admitted literal substitution.
 * @return OK after complete substitution, or INTERNAL_ERROR when the compiled token is missing.
 */
status replace_token(std::string &text, std::string_view token, std::string_view value)
{
	std::size_t position = text.find(token);
	if (position == std::string::npos) {
		return status::internal_error(static_status_text("compiled install bootstrap lacks a required token"));
	}
	while (position != std::string::npos) {
		text.replace(position, token.size(), value);
		position = text.find(token, position + value.size());
	}
	return status::ok();
}

/** Workspace-owned checksum and installer for one final archive. */
struct staged_companions {
	fs::path directory;			   ///< Private root owned by the enclosing workspace.
	std::vector<release::payload_file> files;  ///< Publication order: checksum, then installer.
};

/**
 * @brief Complete one archive's delivery files without examining any other package.
 * @param arguments Final SDK preparation or runtime signing inputs; an optional URL enables downloads.
 * @param archive Fully verified private archive, whose recorded bytes determine every digest.
 * @param work Owner of companion storage through publication or failure cleanup.
 * @return Complete workspace-owned files; no public filename is changed.
 */
status_or<staged_companions> stage_companions(const command &arguments, const pending_file &archive, workspace &work)
{
	auto identity_or = identify_archive(archive.output, false);
	if (!identity_or.is_ok()) {
		return identity_or.error();
	}
	const auto identity = identity_or.value();
	const std::string archive_basename = archive.output.filename().string();
	const std::string digest = common::bytes_to_hex(archive.identity.sha256.data(), common::SHA256_DIGEST_SIZE);
	const std::array<release::payload_file, 1> archive_row{{{archive_basename, archive.identity, 0644u}}};
	auto checksum_or = release::render_payload_manifest(archive_row);
	if (!checksum_or.is_ok()) {
		return checksum_or.error();
	}
	auto root_or = work.create(archive.output.parent_path());
	if (!root_or.is_ok()) {
		return root_or.error();
	}
	staged_companions result{std::move(root_or.value()), {}};
	result.files.reserve(2u);
	/** @brief Write and record complete bytes while workspace retains failure cleanup. */
	const auto stage = [&result](std::string_view name, std::string_view bytes) -> status {
		const fs::path candidate = result.directory / name;
		const auto written = common::publish_new_string_file(candidate, bytes);
		if (!written.is_ok()) {
			return written;
		}
		auto held_or = input_file(candidate, release::MAX_PAYLOAD_MANIFEST_BYTES);
		if (!held_or.is_ok()) {
			return held_or.error();
		}
		result.files.push_back({std::string(name), held_or->identity(), 0644u});
		return status::ok();
	};
	const auto checksum = stage(archive_basename + ".sha256", checksum_or.value());
	if (!checksum.is_ok()) {
		return checksum;
	}
	std::string script(INSTALL_BOOTSTRAP);
	const std::array<std::pair<std::string_view, std::string_view>, 5> substitutions{{
		{"@VERSION@", VERSION},
		{"@PRODUCT@", product_name(identity.product)},
		{"@ARCH@", architecture(identity.tuple)},
		{"@SHA256@", digest},
		{"@RELEASE_URL@", arguments.values.contains("--release-url") ? arguments.values.at("--release-url") :
									       std::string_view{}},
	}};
	for (const auto &[token, value] : substitutions) {
		const auto replaced = replace_token(script, token, value);
		if (!replaced.is_ok()) {
			return replaced;
		}
	}
	// A proper prefix of the generated stream must not execute even a
	// prerequisite operation. The closing compound token is terminal.
	while (!script.empty() && script.back() == '\n') {
		script.pop_back();
	}
	if (!script.starts_with("#!/bin/sh\n{\n") || script.back() != '}') {
		return status::internal_error(
			static_status_text("install bootstrap lacks its complete-compound stream boundary"));
	}
	const std::string name =
		envelope_name(identity.product) + "-" + std::string(architecture(identity.tuple)) + ".install.sh";
	const auto installer = stage(name, script);
	if (!installer.is_ok()) {
		return installer;
	}
	return result;
}

/**
 * @brief Reject a foreign existing output before publishing any new companion.
 * @param path Exact public filename under the admitted output directory.
 * @param expected Complete intended content identity.
 * @return OK for absence or exact owned mode-0644 bytes; other states reject.
 * @note Final no-replacement publication independently checks an existing or race-created winner.
 */
status preflight_output(const fs::path &path, const common::held_file_identity &expected)
{
	struct stat named{};
	if (::lstat(path.c_str(), &named) != 0) {
		return errno == ENOENT ? status::ok() : system_error("cannot inspect package output");
	}
	auto held_or = input_file(path, release::MAX_PACKAGE_ARCHIVE_BYTES);
	if (!held_or.is_ok()) {
		return held_or.error();
	}
	struct stat metadata{};
	if (::fstat(held_or->descriptor(), &metadata) != 0) {
		return system_error("cannot inspect held package output");
	}
	if (metadata.st_uid != ::geteuid() || (metadata.st_mode & 07777) != 0644) {
		return status::already_exists(
			static_status_text("existing package output has a foreign owner or mode"));
	}
	if (held_or->identity().size_bytes != expected.size_bytes || held_or->identity().sha256 != expected.sha256) {
		return status::already_exists(static_status_text("existing package output contains different bytes"));
	}
	return status::ok();
}

/**
 * @brief Retire the single unpublished archive, preserving a cleanup failure.
 * @param pending Optional private archive cleanup owner, disarmed on successful removal.
 * @return OK when no private archive remains; failure leaves its name armed for fail-stop.
 */
status discard_file(std::optional<pending_file> &pending) noexcept
{
	if (!pending.has_value() || !pending->armed) {
		return status::ok();
	}
	if (::unlink(pending->candidate.c_str()) != 0 && errno != ENOENT) {
		(void)common::emit_process_output({{}, "kinetum_package: cannot retire private output ", 1});
		(void)common::emit_process_output({{}, pending->candidate, 1});
		(void)common::emit_process_output({{}, "\n", 1});
		return status::internal_error(static_status_text("private package output cleanup failed"));
	}
	pending->armed = false;
	return status::ok();
}

/**
 * @brief Publish a new private seed without feeding private bytes to generic hash buffers.
 * @param output Exact new file under the already admitted owned parent.
 * @param signals Main-thread cancellation owner.
 * @return OK after mode-0400 no-replacement publication; private bytes never enter generic hash buffers.
 */
status keygen(const fs::path &output, signal_input &signals)
{
	const auto protected_process = release::protect_provider_release_key_process();
	if (!protected_process.is_ok()) {
		return protected_process;
	}
	const auto absent = require_absent(output);
	if (!absent.is_ok()) {
		return absent;
	}
	const std::string output_name = output.filename().string();
	/** Secret-file namespace ownership survives expected allocation failures. */
	struct seed_output {
		/** @brief Adopt the held destination directory before allocating its temporary name. */
		explicit seed_output(int directory) noexcept
			: parent(directory)
		{
		}
		/** @brief Prevent two cleanup owners for a private key file. */
		seed_output(const seed_output &) = delete;
		/** @brief Prevent two cleanup owners for a private key file. */
		seed_output &operator=(const seed_output &) = delete;
		/** @brief Retire one unpublished seed; no secret bytes are reread. */
		bool discard() noexcept
		{
			if (file >= 0) {
				(void)::close(std::exchange(file, -1));
			}
			if (armed) {
				if (::unlinkat(parent, name.c_str() + leaf_offset, 0) != 0) {
					return false;
				}
				armed = false;
			}
			return true;
		}
		/** @brief Keep unexpected unwinding from abandoning private key authority. */
		~seed_output()
		{
			if (!discard()) {
				(void)common::emit_process_output(
					{{}, "kinetum_package: unresolved private seed cleanup\n", 1});
				std::abort();
			}
			(void)::close(parent);
		}
		int parent;		     ///< Held directory used by create, cleanup and publication.
		int file{-1};		     ///< Unique private output descriptor.
		std::string name;	     ///< mkstemp name under the held /proc/self/fd directory.
		std::size_t leaf_offset{0};  ///< Precomputed start of its direct child name.
		bool armed{false};	     ///< The private name exists until publication/cleanup.
	};
	const int parent = ::open(output.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (parent < 0) {
		return system_error("cannot hold private seed output parent");
	}
	seed_output candidate(parent);
	status result = status::ok();
	try {
		candidate.name = "/proc/self/fd/" + std::to_string(parent) + "/.kinetum-seed-XXXXXX";
		candidate.leaf_offset = candidate.name.rfind('/') + 1u;
		candidate.file = ::mkostemp(candidate.name.data(), O_CLOEXEC);
		if (candidate.file < 0) {
			return system_error("cannot create private seed output");
		}
		candidate.armed = true;
		auto anchor_or = release::stage_provider_release_signing_key(candidate.file);
		if (!anchor_or.is_ok()) {
			result = anchor_or.error();
		} else {
			struct stat held{};
			struct stat named{};
			if (::fstat(candidate.file, &held) != 0 ||
			    ::fstatat(parent, candidate.name.c_str() + candidate.leaf_offset, &named,
				      AT_SYMLINK_NOFOLLOW) != 0) {
				result = system_error("cannot verify private seed namespace identity");
			} else if (held.st_dev != named.st_dev || held.st_ino != named.st_ino || held.st_nlink != 1 ||
				   held.st_size != static_cast<off_t>(common::ED25519_PRIVATE_KEY_SIZE) ||
				   (held.st_mode & 07777) != 0400) {
				result = status::data_loss(static_status_text("private seed output identity changed"));
			} else if (::close(std::exchange(candidate.file, -1)) != 0) {
				result = system_error("cannot close completed private seed");
			} else {
				const std::string report =
					"Public anchor: " + common::bytes_to_hex(anchor_or->data(), anchor_or->size()) +
					"\nPublishing private seed: " + output.string() + "\n";
				result = signals.check();
				if (result.is_ok() && common::emit_process_output({report, {}, 0}) != 0) {
					result = status::internal_error(
						static_status_text("cannot deliver private-seed publication report"));
				}
				if (result.is_ok()) {
					if (::syscall(SYS_renameat2, parent,
						      candidate.name.c_str() + candidate.leaf_offset, parent,
						      output_name.c_str(), RENAME_NOREPLACE) != 0) {
						result = system_error("cannot publish seed without replacement");
					} else {
						candidate.armed = false;
						if (::fsync(parent) != 0) {
							(void)common::emit_process_output(
								{{},
								 "kinetum_package: published seed durability is unresolved\n",
								 1});
							std::abort();
						}
						// Nothing fallible follows successful publication.
						return status::ok();
					}
				}
			}
		}
	} catch (const std::bad_alloc &) {
		result = status::resource_exhausted(static_status_text("private-seed preparation exhausted memory"));
	} catch (const std::length_error &) {
		result = status::resource_exhausted(
			static_status_text("private-seed preparation exceeded a representation bound"));
	}
	if (!candidate.discard()) {
		(void)report_error(result);
		(void)common::emit_process_output({{}, "kinetum_package: private-seed cleanup also failed\n", 1});
		std::abort();
	}
	return result;
}

/**
 * @brief Execute the admitted operation under one cleanup/publication owner.
 * @param arguments Exact parsed operation with argv-backed views still alive.
 * @return Zero only after the operation and cleanup/publication complete; expected failures return one.
 */
int execute_command(const command &arguments)
{
	workspace work;
	std::optional<pending_file> archive;
	signal_input signals;
	status result = status::ok();
	try {
		result = signals.start();
		if (result.is_ok()) {
			if (arguments.operation == "prepare") {
				result = prepare(arguments, signals, work, archive);
			} else if (arguments.operation == "sign") {
				result = sign(arguments, signals, work, archive);
			} else if (arguments.operation == "install") {
				result = install(arguments, signals, work);
			} else {
				auto output_or = output_path(arguments.values.at("--output"));
				if (!output_or.is_ok()) {
					result = output_or.error();
				} else {
					result = keygen(output_or.value(), signals);
				}
				if (result.is_ok()) {
					return 0;
				}
			}
		}
		if (result.is_ok() && archive.has_value()) {
			std::optional<staged_companions> companions;
			if (arguments.operation == "sign" || arguments.values.at("--product") == "sdk") {
				auto staged_or = stage_companions(arguments, *archive, work);
				if (!staged_or.is_ok()) {
					result = staged_or.error();
				} else {
					companions.emplace(std::move(staged_or.value()));
				}
			}
			if (result.is_ok()) {
				result = preflight_output(archive->output, archive->identity);
			}
			if (result.is_ok() && companions.has_value()) {
				for (const auto &file : companions->files) {
					result = preflight_output(archive->output.parent_path() / file.relative_path,
								  file.identity);
					if (!result.is_ok()) {
						break;
					}
				}
			}
			std::string report;
			if (result.is_ok()) {
				if (companions.has_value()) {
					for (const auto &file : companions->files) {
						report += "Publishing ";
						report += (archive->output.parent_path() / file.relative_path).native();
						report.push_back('\n');
					}
				}
				report += "Publishing " + archive->output.string() + "\n";
				result = signals.check();
			}
			if (result.is_ok() && common::emit_process_output({report, {}, 0}) != 0) {
				result = status::internal_error(
					static_status_text("cannot deliver package publication report"));
			}
			if (result.is_ok() && companions.has_value()) {
				for (const auto &file : companions->files) {
					result = signals.check();
					if (!result.is_ok()) {
						break;
					}
					result = release::publish_package_file(
						companions->directory / file.relative_path,
						archive->output.parent_path() / file.relative_path, file.identity);
					if (!result.is_ok()) {
						break;
					}
				}
			}
			if (result.is_ok()) {
				result = work.cleanup();
				if (!result.is_ok()) {
					(void)report_error(result);
					(void)discard_file(archive);
					std::abort();
				}
				result = signals.check();
			}
			if (result.is_ok()) {
				result = release::publish_package_file(archive->candidate, archive->output,
								       archive->identity);
				if (result.is_ok()) {
					archive->armed = false;
					// Nothing fallible follows the final archive commit. Requested
					// companions, reporting, and transient cleanup are already complete.
					return 0;
				}
			}
		}
	} catch (const std::bad_alloc &) {
		result = status::resource_exhausted(static_status_text("packaging exhausted memory"));
	} catch (const std::length_error &) {
		result = status::resource_exhausted(static_status_text("packaging exceeded a representation bound"));
	}
	if (!result.is_ok()) {
		(void)report_error(result);
	}
	const auto discarded = discard_file(archive);
	const auto cleaned = work.cleanup();
	if (!discarded.is_ok()) {
		(void)report_error(discarded);
	}
	if (!cleaned.is_ok()) {
		(void)report_error(cleaned);
	}
	if (!discarded.is_ok() || !cleaned.is_ok()) {
		std::abort();
	}
	return result.is_ok() ? 0 : 1;
}

}  // namespace

/**
 * @brief Parse a finite public command and map expected cold allocation failures.
 * @param argc Process argument count.
 * @param argv Process arguments valid for the complete invocation.
 * @return Zero for delivered success, two for syntax errors, or one for operation/output failure.
 */
int main(int argc, char **argv)
try {
	if (argc == 2 && std::string_view(argv[1]) == "--help") {
		return common::emit_process_output({USAGE, {}, 0});
	}
	auto command_or = parse_command(argc, argv);
	if (!command_or.is_ok()) {
		(void)report_error(command_or.error());
		return common::emit_process_output({{}, USAGE, 2});
	}
	return execute_command(command_or.value());
} catch (const std::bad_alloc &) {
	return common::emit_process_output({{}, "kinetum_package: allocation failed\n", 1});
} catch (const std::length_error &) {
	return common::emit_process_output({{}, "kinetum_package: representation bound exceeded\n", 1});
}
