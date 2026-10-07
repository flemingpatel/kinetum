// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file grpc_logging.hpp
 * @brief Exact gRPC diagnostic registration lifetime.
 * @author Fleming Patel
 */

#include <memory>
#include <string_view>

#include "src/common/log_record.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Process owner of native gRPC logging, nested inside the logger lifetime.
 *
 * Create before constructing any gRPC objects. Every channel, server, observer,
 * and callback producer must retire before destruction. The owner holds one
 * gRPC initialization reference, performs blocking final shutdown, unregisters
 * the declared native hook, then closes and drains accepted callbacks.
 */
class grpc_logging final {
    public:
	/** @return Sole native registration owner, or allocation/duplicate-ownership failure before effects. */
	[[nodiscard]] static status_or<std::unique_ptr<grpc_logging>> create();
	/** @brief Quiesce native callers before retiring the hook and callback gate. */
	~grpc_logging();
	grpc_logging(const grpc_logging &) = delete;
	grpc_logging &operator=(const grpc_logging &) = delete;

    private:
	/** @brief Construct one unpublished owner before native effects. */
	grpc_logging() noexcept = default;
	bool owned_{false};  ///< True only after acquiring the process registration claim.
};

namespace detail
{

/** @brief Native facts borrowed only through the synchronous capture callback. */
struct grpc_log_record_view {
	log_level level;	   ///< Exact native severity mapped to the platform filter.
	std::string_view file;	   ///< Native source filename when available.
	int line;		   ///< Native source line when available.
	std::string_view message;  ///< Native unprefixed bytes, never retained.
};

/** @brief Register the native GPR callback before gRPC initialization. */
void install_grpc_log_capture() noexcept;
/** @brief Apply admitted filters after gRPC's own one-time logging initialization. */
void configure_grpc_log_capture() noexcept;
/** @brief Unregister the same required native hook after gRPC callers retire. */
void remove_grpc_log_capture() noexcept;
/**
 * @brief Copy native facts through one admitted callback claim.
 * @param record Native views valid through this synchronous call only.
 */
void capture_grpc_log(grpc_log_record_view record) noexcept;

}  // namespace detail
}  // namespace kinetum::common
