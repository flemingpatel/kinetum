// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file stage_configuration.hpp
 * @brief Non-owning readers for exact Axiom stage configuration.
 * @author Fleming Patel
 *
 * Axiom represents each stage's kind-specific configuration with one typed
 * oneof. Planning consumes these readers only after complete contract
 * admission, avoiding string-key scans and allocation.
 */

#include <string_view>

#include "gen/kinetum/axiom/v1/axiom.pb.h"

namespace kinetum::axiom
{

/**
 * @brief Return one stage's typed logical-interface identity.
 *
 * RX and TX stages use this identity to bind logical pipeline stages to
 * plan-owned logical ports. Contract validation guarantees presence before a
 * production caller uses the result.
 *
 * @param stage Pipeline stage proto.
 * @return Borrowed interface name, or an empty view for a non-I/O stage.
 *
 * @par Thread Safety
 * Safe while @p stage is not mutated concurrently. The returned view cannot
 * outlive or cross mutation of the owning protobuf message.
 *
 * @par Performance
 * Constant-time, allocation-free cold-path access.
 */
[[nodiscard]] inline std::string_view stage_interface(const kinetum::axiom::v1::Stage &stage) noexcept
{
	return stage.has_io() ? std::string_view(stage.io().interface()) : std::string_view{};
}

}  // namespace kinetum::axiom
