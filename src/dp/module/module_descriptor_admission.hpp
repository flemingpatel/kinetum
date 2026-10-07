// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_descriptor_admission.hpp
 * @brief Private dataplane admission for one exact module descriptor.
 * @author Fleming Patel
 *
 * Descriptor interpretation is loader policy, not a service exported to
 * module images. This authority therefore lives behind the dataplane module
 * boundary and returns a precise platform status to its sole production
 * consumer.
 */

#include "src/common/status.hpp"
#include <kinetum/kinetum_sdk.h>

namespace kinetum::dp::module
{

/**
 * @brief Validate one descriptor against the exact host ABI contract.
 *
 * Validation requires bounded printable identities, exact ABI-version
 * equality, known capability bits, every mandatory lifecycle callback, and
 * the exact callback shape for the declared execution mode. No version range,
 * alternate callback shape, or compatibility interpretation is accepted.
 *
 * @param descriptor Borrowed immutable descriptor returned by the module's
 *        sole registration symbol.
 * @return OK for one exact descriptor, otherwise FAILED_PRECONDITION with a
 *         precise violated contract.
 */
[[nodiscard]] kinetum::common::status validate_module_descriptor(const kinetum_module *descriptor);

}  // namespace kinetum::dp::module
