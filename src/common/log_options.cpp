// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file log_options.cpp
 * @brief Exact service logging option admission and child argument projection.
 * @author Fleming Patel
 */

#include "src/common/log_options.hpp"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <limits>

namespace kinetum::common
{
namespace
{

/** @brief Exact accepted severity spellings in increasing priority order. */
constexpr std::array<std::string_view, 5> LEVEL_NAMES{"debug", "info", "warn", "error", "fatal"};

/**
 * @param text Exact lowercase severity spelling.
 * @return Declared severity or an exact argument error.
 */
status_or<log_level> parse_level(std::string_view text)
{
	for (std::size_t index = 0; index < LEVEL_NAMES.size(); ++index) {
		if (text == LEVEL_NAMES[index]) {
			return static_cast<log_level>(index + 1);
		}
	}
	return status::invalid_argument("unknown logging level: " + std::string(text));
}

/**
 * @param text Complete caller-authored numeric argument.
 * @return Canonical unsigned decimal value, or a spelling/overflow error.
 */
status_or<uint64_t> parse_number(std::string_view text)
{
	uint64_t result = 0;
	if (text.empty() || (text.size() > 1 && text.front() == '0')) {
		return status::invalid_argument(
			static_status_text("logging limit requires canonical unsigned decimal"));
	}
	const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
	if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
		return status::invalid_argument(static_status_text("invalid logging limit"));
	}
	return result;
}

}  // namespace

std::optional<std::size_t> log_component_index(std::string_view name) noexcept
{
	const auto found = std::find(LOG_COMPONENTS.begin(), LOG_COMPONENTS.end(), name);
	if (found == LOG_COMPONENTS.end()) {
		return std::nullopt;
	}
	return static_cast<std::size_t>(found - LOG_COMPONENTS.begin());
}

status validate_log_options(const log_options &options)
{
	const std::filesystem::path path(options.directory);
	if (options.directory.find('\0') != std::string::npos || !path.is_absolute() || path == path.root_path() ||
	    path.lexically_normal() != path || path.filename().empty()) {
		return status::invalid_argument(
			static_status_text("log directory must be an absolute normalized non-root path"));
	}
	if (!valid_log_level(options.level)) {
		return status::invalid_argument(static_status_text("invalid default logging level"));
	}
	for (const auto level : options.component_levels) {
		if (level.has_value() && !valid_log_level(*level)) {
			return status::invalid_argument(static_status_text("invalid component logging level"));
		}
	}
	if (options.keep_files < 2 || options.keep_files > 32 || options.maximum_bytes < LOG_ENCODED_BYTES ||
	    options.maximum_bytes > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) / options.keep_files) {
		return status::invalid_argument(static_status_text(
			"logging retention requires 2..32 files and a representable limit of at least 34816 bytes per file"));
	}
	return status::ok();
}

std::vector<std::string> log_arguments(const log_options &options)
{
	if (!validate_log_options(options).is_ok()) {
		std::terminate();
	}
	std::vector<std::string> result{
		"--log-dir",	    options.directory,
		"--log-level",	    std::string(LEVEL_NAMES[static_cast<std::size_t>(options.level) - 1]),
		"--log-max-bytes",  std::to_string(options.maximum_bytes),
		"--log-keep-files", std::to_string(options.keep_files)};
	for (std::size_t index = 0; index < LOG_COMPONENTS.size(); ++index) {
		const auto level = options.component_levels[index];
		if (level.has_value()) {
			result.emplace_back("--log-component-level");
			result.emplace_back(std::string(LOG_COMPONENTS[index]) + "=" +
					    std::string(LEVEL_NAMES[static_cast<std::size_t>(*level) - 1]));
		}
	}
	if (options.console) {
		result.emplace_back("--log-console");
	}
	return result;
}

std::string_view log_option_help() noexcept
{
	return "\nLogging options:\n"
	       "  --log-dir <absolute-dir>       Log directory (default: /var/log/kinetum)\n"
	       "  --log-level <level>            debug|info|warn|error|fatal (default: info)\n"
	       "  --log-component-level <name>=<level>  Override one known component\n"
	       "  --log-max-bytes <bytes>        File size limit (default: 16777216)\n"
	       "  --log-keep-files <count>       Total files, 2..32 (default: 8)\n"
	       "  --log-console                 Mirror records to stderr\n"
	       "  SIGUSR1 reopens the same log destination without changing settings.\n";
}

status_or<bool> log_option_parser::consume(int &index, int argc, char *const argv[])
{
	const std::string_view option(argv[index]);
	constexpr std::array<std::string_view, 6> OPTIONS{"--log-dir",	      "--log-level",   "--log-max-bytes",
							  "--log-keep-files", "--log-console", "--log-component-level"};
	const auto found = std::find(OPTIONS.begin(), OPTIONS.end(), option);
	if (found == OPTIONS.end()) {
		return false;
	}
	const auto slot = static_cast<std::size_t>(found - OPTIONS.begin());
	const auto bit = static_cast<uint8_t>(1u << slot);
	if (slot != 5 && (seen_ & bit) != 0) {
		return status::invalid_argument("duplicate logging option: " + std::string(option));
	}
	if (slot == 4) {
		options_.console = true;
		seen_ |= bit;
		return true;
	}
	if (index + 1 >= argc) {
		return status::invalid_argument("missing value for " + std::string(option));
	}
	const std::string_view value(argv[++index]);
	switch (slot) {
	case 0:
		options_.directory = value;
		break;
	case 1: {
		auto level = parse_level(value);
		if (!level.is_ok()) {
			return level.error();
		}
		options_.level = level.value();
		break;
	}
	case 2:
	case 3: {
		auto number = parse_number(value);
		if (!number.is_ok()) {
			return number.error();
		}
		if (slot == 2) {
			options_.maximum_bytes = number.value();
		} else {
			if (number.value() > std::numeric_limits<uint32_t>::max()) {
				return status::invalid_argument(
					static_status_text("logging file count exceeds uint32"));
			}
			options_.keep_files = static_cast<uint32_t>(number.value());
		}
		break;
	}
	case 5: {
		const auto separator = value.find('=');
		if (separator == std::string_view::npos) {
			return status::invalid_argument(
				static_status_text("component logging level requires name=level"));
		}
		const auto component = log_component_index(value.substr(0, separator));
		if (!component.has_value() || options_.component_levels[*component].has_value()) {
			return status::invalid_argument(static_status_text("unknown or duplicate logging component"));
		}
		auto level = parse_level(value.substr(separator + 1));
		if (!level.is_ok()) {
			return level.error();
		}
		options_.component_levels[*component] = level.value();
		break;
	}
	default:
		std::terminate();
	}
	seen_ |= bit;
	return true;
}

}  // namespace kinetum::common
