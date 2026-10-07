// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file protobuf_contract.hpp
 * @brief Shared strict protobuf-tree validation and deterministic serialization.
 * @author Fleming Patel
 *
 * These cold-path primitives provide the wire-shape checks shared by canonical
 * content identity and typed provider contracts. Traversal follows protobuf
 * message fields only: strings and bytes remain scalar leaves and are never
 * interpreted as nested wire data.
 *
 * These primitives do not invent an admission-size policy. Each caller must
 * establish its owning message or payload bound before invoking traversal or
 * serialization.
 *
 * Deterministic serialization is stable for Kinetum's pinned protobuf runtime
 * and one-tree build. It is not a cross-version canonical protobuf format.
 * Callers remain responsible for field-specific normalization before invoking
 * the serializer.
 *
 * @par Thread Safety
 * The operations are stateless and safe for concurrent calls. An input message
 * must not be mutated while an operation reads it.
 *
 * @par Performance
 * Reflection, traversal, allocation, and serialization are cold-path work and
 * must not run on packet workers or from module packet callbacks.
 */

#include <string>
#include <string_view>

#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace google::protobuf
{
class Message;
}  // namespace google::protobuf

namespace kinetum::common
{

/**
 * @brief Reject unknown wire fields anywhere in a protobuf message tree.
 *
 * Only fields whose protobuf C++ type is MESSAGE are traversed recursively.
 * Bytes and strings are opaque scalar leaves regardless of their contents.
 *
 * @param root Root protobuf message to inspect.
 * @param contract_name Stable trusted contract name used in diagnostics.
 * @return OK when every visited message has an empty unknown-field set;
 *         INVALID_ARGUMENT at the first message containing unknown input;
 *         RESOURCE_EXHAUSTED or OUT_OF_RANGE for allocation/representation
 *         failure; or INTERNAL_ERROR for another protobuf exception.
 */
[[nodiscard]] status reject_unknown_protobuf_fields_recursive(const google::protobuf::Message &root,
							      std::string_view contract_name);

/**
 * @brief Reject enum numbers absent from their generated descriptors.
 *
 * The validation walks every enum field in the protobuf message tree. A valid
 * declared sentinel such as an `*_UNSPECIFIED` value remains a field-specific
 * policy decision; this primitive rejects only wire-forward numeric values the
 * pinned generated contract does not define.
 *
 * @param root Root protobuf message to inspect.
 * @param contract_name Stable trusted contract name used in diagnostics.
 * @return OK when every enum number is declared; INVALID_ARGUMENT at the first
 *         unrecognized enum value; RESOURCE_EXHAUSTED or OUT_OF_RANGE for
 *         allocation/representation failure; or INTERNAL_ERROR for another
 *         protobuf exception.
 */
[[nodiscard]] status reject_invalid_protobuf_enum_values_recursive(const google::protobuf::Message &root,
								   std::string_view contract_name);

/**
 * @brief Serialize a validated protobuf using deterministic field emission.
 *
 * The caller must apply all contract-specific set normalization and validation
 * first. Repeated-field order is preserved exactly by this operation.
 *
 * @param message Validated and normalized protobuf message.
 * @return Exact deterministic bytes; INTERNAL_ERROR when protobuf cannot
 *         serialize the complete message or raises another exception;
 *         RESOURCE_EXHAUSTED on allocation failure; or OUT_OF_RANGE when the
 *         representation exceeds the host string domain.
 */
[[nodiscard]] status_or<std::string> serialize_protobuf_deterministically(const google::protobuf::Message &message);

}  // namespace kinetum::common
