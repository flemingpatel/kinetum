// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file protobuf_contract.cpp
 * @brief Shared strict protobuf-tree validation and deterministic serialization.
 * @author Fleming Patel
 *
 * Message traversal is iterative so deeply nested admitted input cannot consume
 * the native call stack. Scalar bytes remain opaque leaves.
 */

#include "src/common/protobuf_contract.hpp"

#include <exception>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message.h>
#include <google/protobuf/unknown_field_set.h>

namespace kinetum::common
{

namespace
{

using google::protobuf::FieldDescriptor;
using google::protobuf::Message;

/**
 * @brief Append every populated direct child message to an iterative worklist.
 *
 * Scalar strings and bytes are intentionally ignored, even when their bytes
 * resemble protobuf wire data.
 *
 * @param message Parent message whose populated message fields are inspected.
 * @param pending Non-null traversal worklist receiving borrowed child pointers.
 */
void append_nested_messages(const Message &message, std::vector<const Message *> *pending)
{
	const auto *descriptor = message.GetDescriptor();
	const auto *reflection = message.GetReflection();
	for (int field_index = 0; field_index < descriptor->field_count(); ++field_index) {
		const FieldDescriptor *field = descriptor->field(field_index);
		if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE) {
			continue;
		}
		if (field->is_repeated()) {
			const int field_size = reflection->FieldSize(message, field);
			for (int value_index = 0; value_index < field_size; ++value_index) {
				pending->push_back(&reflection->GetRepeatedMessage(message, field, value_index));
			}
		} else if (reflection->HasField(message, field)) {
			pending->push_back(&reflection->GetMessage(message, field));
		}
	}
}

}  // namespace

status reject_unknown_protobuf_fields_recursive(const google::protobuf::Message &root, std::string_view contract_name)
{
	try {
		std::vector<const Message *> pending;
		pending.push_back(&root);

		while (!pending.empty()) {
			const Message *message = pending.back();
			pending.pop_back();
			const auto *reflection = message->GetReflection();
			if (reflection->GetUnknownFields(*message).field_count() != 0) {
				return status::invalid_argument(std::string(contract_name) +
								" contains unknown protobuf fields in " +
								message->GetDescriptor()->full_name());
			}
			append_nested_messages(*message, &pending);
		}

		return status::ok();
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      static_status_text("protobuf unknown-field validation exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("protobuf unknown-field validation exceeded the host size domain"));
	} catch (const std::exception &) {
		return status(
			status_code::INTERNAL_ERROR,
			static_status_text("protobuf unknown-field validation raised an external-library exception"));
	} catch (...) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf unknown-field validation raised an unknown exception"));
	}
}

status reject_invalid_protobuf_enum_values_recursive(const google::protobuf::Message &root,
						     std::string_view contract_name)
{
	try {
		std::vector<const Message *> pending;
		pending.push_back(&root);

		while (!pending.empty()) {
			const Message *message = pending.back();
			pending.pop_back();
			const auto *descriptor = message->GetDescriptor();
			const auto *reflection = message->GetReflection();

			for (int field_index = 0; field_index < descriptor->field_count(); ++field_index) {
				const FieldDescriptor *field = descriptor->field(field_index);
				if (field->cpp_type() != FieldDescriptor::CPPTYPE_ENUM) {
					continue;
				}

				if (field->is_repeated()) {
					const int field_size = reflection->FieldSize(*message, field);
					for (int value_index = 0; value_index < field_size; ++value_index) {
						const int value =
							reflection->GetRepeatedEnumValue(*message, field, value_index);
						if (field->enum_type()->FindValueByNumber(value) == nullptr) {
							return status::invalid_argument(
								std::string(contract_name) +
								" contains an unknown enum number in " +
								descriptor->full_name() + "." + field->name());
						}
					}
					continue;
				}

				const int value = reflection->GetEnumValue(*message, field);
				if (field->enum_type()->FindValueByNumber(value) == nullptr) {
					return status::invalid_argument(std::string(contract_name) +
									" contains an unknown enum number in " +
									descriptor->full_name() + "." + field->name());
				}
			}

			append_nested_messages(*message, &pending);
		}

		return status::ok();
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      static_status_text("protobuf enum validation exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("protobuf enum validation exceeded the host size domain"));
	} catch (const std::exception &) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf enum validation raised an external-library exception"));
	} catch (...) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("protobuf enum validation raised an unknown exception"));
	}
}

status_or<std::string> serialize_protobuf_deterministically(const google::protobuf::Message &message)
{
	try {
		std::string serialized;
		serialized.reserve(message.ByteSizeLong());
		bool serialized_ok = false;
		{
			google::protobuf::io::StringOutputStream output(&serialized);
			google::protobuf::io::CodedOutputStream coded_output(&output);
			coded_output.SetSerializationDeterministic(true);
			serialized_ok = message.SerializeToCodedStream(&coded_output) && !coded_output.HadError();
		}
		if (!serialized_ok) {
			return status::internal_error("deterministic protobuf serialization failed for " +
						      message.GetDescriptor()->full_name());
		}
		return serialized;
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      static_status_text("deterministic protobuf serialization exhausted memory"));
	} catch (const std::length_error &) {
		return status(status_code::OUT_OF_RANGE,
			      static_status_text("deterministic protobuf serialization exceeded the host size domain"));
	} catch (const std::exception &) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text(
				      "deterministic protobuf serialization raised an external-library exception"));
	} catch (...) {
		return status(status_code::INTERNAL_ERROR,
			      static_status_text("deterministic protobuf serialization raised an unknown exception"));
	}
}

}  // namespace kinetum::common
