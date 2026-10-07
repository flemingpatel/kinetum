// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file pbtxt.cpp
 * @brief Protobuf text format I/O implementation.
 * @author Fleming Patel
 *
 * Implements text format parsing and serialization using the Protocol
 * Buffers TextFormat API. Unknown fields reject, the caller supplies the exact
 * positive file bound, and parser exceptions become typed status rather than
 * crossing the common boundary.
 */

#include "src/common/pbtxt.hpp"

#include <cstddef>
#include <exception>
#include <new>
#include <stdexcept>
#include <string>

#include <google/protobuf/text_format.h>

#include "src/common/file_io.hpp"

namespace kinetum::common
{

status parse_pbtxt_text(const std::string &text, const std::string &source_name, google::protobuf::Message *msg)
{
	try {
		if (msg == nullptr) {
			return status(status_code::INVALID_ARGUMENT, "pbtxt destination message must not be null",
				      source_name);
		}
		google::protobuf::TextFormat::Parser parser;
		parser.AllowUnknownField(false);
		if (!parser.ParseFromString(text, msg)) {
			return status(status_code::INVALID_ARGUMENT, "failed to parse pbtxt", source_name);
		}
		return status::ok();
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      static_status_text("protobuf-text parsing exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("protobuf-text parsing exceeded the host size domain"));
	} catch (const std::exception &) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text parser raised an external-library exception"));
	} catch (...) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text parser raised an unknown exception"));
	}
}

status read_pbtxt_file(const std::string &path, std::size_t maximum_bytes, google::protobuf::Message *msg)
{
	try {
		if (maximum_bytes == 0u || msg == nullptr) {
			return status::invalid_argument(static_status_text(
				"protobuf-text file input requires a positive bound and destination"));
		}
		auto data_or = read_file_to_string(path, maximum_bytes);
		if (!data_or.is_ok()) {
			return data_or.error();
		}

		return parse_pbtxt_text(data_or.value(), path, msg);
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      static_status_text("protobuf-text file reading exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("protobuf-text file reading exceeded the host size domain"));
	} catch (const std::exception &) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text file reading raised an external-library exception"));
	} catch (...) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text file reading raised an unknown exception"));
	}
}

status_or<std::string> print_pbtxt_text(const google::protobuf::Message &msg)
{
	try {
		std::string out;
		google::protobuf::TextFormat::Printer printer;
		printer.SetSingleLineMode(false);
		printer.SetUseUtf8StringEscaping(true);
		if (!printer.PrintToString(msg, &out)) {
			return status::internal_error("failed to serialize protobuf text");
		}
		return out;
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      static_status_text("protobuf-text serialization exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("protobuf-text serialization exceeded the host size domain"));
	} catch (const std::exception &) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text serialization raised an external-library exception"));
	} catch (...) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text serialization raised an unknown exception"));
	}
}

status write_pbtxt_file(const std::string &path, const google::protobuf::Message &msg)
{
	try {
		auto text_or = print_pbtxt_text(msg);
		if (!text_or.is_ok()) {
			return status(text_or.error().code(), std::string(text_or.error().message()), path);
		}
		return write_string_to_file(path, text_or.value());
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      static_status_text("protobuf-text file writing exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("protobuf-text file writing exceeded the host size domain"));
	} catch (const std::exception &) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text file writing raised an external-library exception"));
	} catch (...) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf-text file writing raised an unknown exception"));
	}
}

}  // namespace kinetum::common
