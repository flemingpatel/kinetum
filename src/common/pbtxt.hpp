// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file pbtxt.hpp
 * @brief Protobuf text format I/O utilities.
 * @author Fleming Patel
 *
 * Provides strict parsing plus complete file read/write operations for the
 * human-authored protobuf-text configuration and fixture surface. Callers own
 * the exact positive read bound; parsing rejects partial or malformed input.
 *
 * Thread-safety: All functions are thread-safe.
 *
 * @note Requires linking against libprotobuf.
 *
 * @see file_io.hpp for underlying file operations
 */

#include <cstddef>
#include <string>

#include "google/protobuf/message.h"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Strictly parse protobuf text from an already owned byte string.
 *
 * Parses exactly the supplied text into the destination message and rejects
 * unknown fields. The helper performs no file I/O and imposes no independent
 * size policy; the caller must bound the byte string at its owning admission
 * boundary. This separation lets integrity-sensitive callers hash and parse
 * the same bytes without reopening a mutable path.
 *
 * @param text Exact protobuf text bytes to parse.
 * @param source_name Diagnostic identity for the bytes, such as a file path.
 * @param[out] msg Destination protobuf message. Must not be null.
 * @return OK on success; INVALID_ARGUMENT for a null destination or strict
 *         parse failure; RESOURCE_EXHAUSTED or OUT_OF_RANGE for allocation or
 *         representation failure; or INTERNAL_ERROR for another protobuf
 *         library exception.
 *
 * @par Thread Safety
 * Thread-safe for distinct destination messages. The caller must not mutate
 * `text` or `msg` concurrently.
 *
 * @par Performance
 * Cold-path operation. Parsing allocates according to the destination schema
 * and must not run on a packet worker.
 */
status parse_pbtxt_text(const std::string &text, const std::string &source_name, google::protobuf::Message *msg);

/**
 * @brief Read a protobuf message from a text format file.
 *
 * Reads the file contents and parses them as protobuf text format into
 * the provided message. Unknown fields are rejected so configuration admission
 * fails closed on typos or unsupported future fields.
 *
 * @param path Filesystem path to the .pbtxt file.
 * @param maximum_bytes Exact positive whole-file byte bound selected by the
 *        caller before parser allocation.
 * @param[out] msg Pointer to the protobuf message to populate. Must not be null.
 * @return status::ok() on success, NOT_FOUND if the file cannot be read,
 *         RESOURCE_EXHAUSTED if the caller's bound is exceeded,
 *         INVALID_ARGUMENT for a zero bound, null destination, or strict parse
 *         failure, or the parser's typed allocation/library failure.
 *
 * @see write_pbtxt_file for the inverse operation
 */
status read_pbtxt_file(const std::string &path, std::size_t maximum_bytes, google::protobuf::Message *msg);

/**
 * @brief Serialize one protobuf message to the canonical repository text form.
 *
 * The helper performs no file I/O. It is the owning serialization authority
 * for descriptor-rooted persistence callers that must write the exact returned
 * bytes without reopening a pathname.
 *
 * @param msg Message to serialize.
 * @return Multi-line UTF-8-escaped protobuf text; INTERNAL_ERROR when the
 *         printer cannot serialize the complete message or raises another
 *         exception; RESOURCE_EXHAUSTED on allocation failure; or OUT_OF_RANGE
 *         when the representation exceeds the host string domain.
 *
 * @par Thread Safety
 * Thread-safe while @p msg is not mutated concurrently.
 *
 * @par Performance
 * Cold-path operation that allocates the complete text representation.
 */
[[nodiscard]] status_or<std::string> print_pbtxt_text(const google::protobuf::Message &msg);

/**
 * @brief Write a protobuf message to a file in text format.
 *
 * Serializes the message to protobuf text format and writes it to the
 * specified file. Uses UTF-8 string escaping to preserve
 * international characters.
 *
 * @param path Filesystem path to write the .pbtxt file
 * @param msg The protobuf message to serialize
 * @return OK on success; otherwise the first serialization or file-write
 *         status, RESOURCE_EXHAUSTED or OUT_OF_RANGE for local
 *         allocation/representation failure, or INTERNAL_ERROR for another
 *         library exception.
 *
 * @note Output is multi-line formatted (not single-line) for readability.
 *
 * @see read_pbtxt_file for the inverse operation
 */
status write_pbtxt_file(const std::string &path, const google::protobuf::Message &msg);

}  // namespace kinetum::common
