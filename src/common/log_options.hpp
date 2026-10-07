// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file log_options.hpp
 * @brief One immutable logging configuration and CLI parser for platform services.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/log_record.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/** Closed component names shared by admission, emission, and operator filters. */
inline constexpr std::array<std::string_view, 14> LOG_COMPONENTS{
	"cp",	   "cp.health", "dp",	"gluon",  "grpc",     "kinetum_axiom", "kinetumctl",
	"logging", "module",	"pack", "photon", "provider", "quark",	       "tls"};

/** @brief Per-invocation settings; never consulted by a packet worker. */
struct log_options {
	std::string directory{"/var/log/kinetum"};  ///< Explicit absolute destination.
	log_level level{log_level::INFO};	    ///< Default minimum emitted severity.
	std::array<std::optional<log_level>, LOG_COMPONENTS.size()> component_levels{};	 ///< Exact overrides.
	uint64_t maximum_bytes{UINT64_C(16) * 1024 * 1024};  ///< Active file ceiling before a whole-record rotation.
	uint32_t keep_files{8};				     ///< Total retained files, including active, within 2..32.
	bool console{false};				     ///< Independent complete-record stderr mirror.
};

/**
 * @param name Exact component spelling.
 * @return Closed component index, or no value for an unknown name.
 */
[[nodiscard]] std::optional<std::size_t> log_component_index(std::string_view name) noexcept;

/**
 * @brief Validate all settings, including programmatically authored settings.
 * @param options Complete candidate; validation never changes it.
 * @return OK or the first directory, level, or representability error.
 */
[[nodiscard]] status validate_log_options(const log_options &options);

/**
 * @brief Render exact admitted settings for a supervised child's argv.
 * @param options Already validated selection; contradictory input terminates.
 * @return Owned option/value strings preserving every configured setting.
 */
[[nodiscard]] std::vector<std::string> log_arguments(const log_options &options);

/** @return Shared service help text for the complete logging CLI. */
[[nodiscard]] std::string_view log_option_help() noexcept;

/** @brief Single-pass parser retaining duplicate evidence outside configuration. */
class log_option_parser final {
    public:
	/** @param options Unpublished caller-owned configuration, borrowed for the complete parse. */
	explicit log_option_parser(log_options &options) noexcept
		: options_(options)
	{
	}
	/**
	 * @brief Consume exactly one recognized logging option and its value.
	 * @param index Current argument index; advances past a consumed value only.
	 * @param argc Complete process argument count.
	 * @param argv Borrowed complete process argument vector.
	 * @return True for consumed input, false for another owner's option, or error.
	 */
	[[nodiscard]] status_or<bool> consume(int &index, int argc, char *const argv[]);

    private:
	log_options &options_;	///< Sole unpublished settings being parsed.
	uint8_t seen_{0};	///< Singleton-option presence; duplicates reject even if equal.
};

}  // namespace kinetum::common
