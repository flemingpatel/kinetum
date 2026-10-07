// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file axiom_pbtxt_io.cpp
 * @brief Implementation of Axiom Pipeline Protocol Buffer Text I/O
 * @author Fleming Patel
 *
 * This file implements the high-level pipeline loading operations with
 * integrated validation and error handling.
 *
 * The loader applies a fixed input-byte bound while reading, parses with
 * unknown fields disabled, preserves every authored value, and invokes the
 * complete semantic contract before returning a message.
 */

#include "src/axiom/axiom_pbtxt_io.hpp"

#include <exception>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>

#include "src/axiom/axiom_contract.hpp"
#include "src/common/file_io.hpp"
#include "src/common/pbtxt.hpp"

namespace kinetum::axiom
{

kinetum::common::status_or<kinetum::axiom::v1::Pipeline> load_pipeline_pbtxt(std::string_view path,
									     const contract_options &opt)
{
	// Wrap protobuf operations in try-catch to handle exceptions from external library
	try {
		// Read through the bounded whole-file authority before parser allocation.
		auto file_contents = kinetum::common::read_file_to_string(std::string(path), MAX_PIPELINE_SOURCE_BYTES);
		if (!file_contents.is_ok()) [[unlikely]] {
			return file_contents.error();
		}

		// Parse the exact bounded bytes through the sole common text-format owner.
		kinetum::axiom::v1::Pipeline pipeline;
		const auto parse_status =
			kinetum::common::parse_pbtxt_text(file_contents.value(), std::string(path), &pipeline);
		if (!parse_status.is_ok()) [[unlikely]] {
			return parse_status;
		}

		// Validate the exact authored semantic contract.
		if (auto validation_status = verify_contract(pipeline, opt); !validation_status.is_ok()) [[unlikely]] {
			// Propagate validation error with detailed diagnostic
			return validation_status;
		}

		// Success: return validated pipeline
		return pipeline;

	} catch (const std::bad_alloc &) {
		return kinetum::common::status::resource_exhausted("Axiom protobuf-text loading exhausted memory");
	} catch (const std::length_error &) {
		return kinetum::common::status(kinetum::common::status_code::OUT_OF_RANGE,
					       "Axiom protobuf-text loading exceeds the host size domain");
	} catch (const std::exception &e) {
		// Catch exceptions from protobuf library
		return kinetum::common::status(kinetum::common::status_code::INTERNAL_ERROR,
					       "Protobuf parsing failed: exception from protobuf library",
					       std::string(e.what()));
	} catch (...) {
		// Catch any other exceptions
		return kinetum::common::status(kinetum::common::status_code::INTERNAL_ERROR,
					       "Protobuf parsing failed: unknown exception from protobuf library");
	}
}

}  // namespace kinetum::axiom
