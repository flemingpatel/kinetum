// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_config_test_helpers.hpp
 * @brief Host-only authoring and lifetime helpers for module config tests.
 * @author Fleming Patel
 *
 * Built-in module images accept one strict snake-case JSON contract and do not
 * link generated Protobuf registries. Tests may still use module-owned proto
 * messages as typed authoring models. This header deterministically encodes
 * those messages into the production JSON shape and gives direct compiler
 * tests a PMR owner whose lifetime covers the returned immutable policy.
 */

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "src/modules/acl/acl_impl.hpp"
#include "src/modules/nat44/nat44_impl.hpp"
#include "src/modules/qos/qos_impl.hpp"

namespace kinetum::test
{
namespace detail
{

/**
 * @brief Append one byte string as a valid JSON string.
 * @param value Borrowed string bytes to escape.
 * @param output Destination receiving the quoted string; null is rejected.
 * @throws std::invalid_argument when the output pointer is null.
 */
inline void append_json_string(std::string_view value, std::string *output)
{
	if (output == nullptr) {
		throw std::invalid_argument("module JSON output is null");
	}
	constexpr char HEX[] = "0123456789abcdef";
	output->push_back('"');
	for (const char character : value) {
		const auto byte = static_cast<unsigned char>(character);
		switch (byte) {
		case '"':
			output->append("\\\"");
			break;
		case '\\':
			output->append("\\\\");
			break;
		case '\b':
			output->append("\\b");
			break;
		case '\f':
			output->append("\\f");
			break;
		case '\n':
			output->append("\\n");
			break;
		case '\r':
			output->append("\\r");
			break;
		case '\t':
			output->append("\\t");
			break;
		default:
			if (byte < 0x20u) {
				output->append("\\u00");
				output->push_back(HEX[byte >> 4u]);
				output->push_back(HEX[byte & 0x0fu]);
			} else {
				output->push_back(static_cast<char>(byte));
			}
			break;
		}
	}
	output->push_back('"');
}

/**
 * @brief Append one integer with locale-independent decimal spelling.
 * @param value Integer to encode as a JSON number.
 * @param output Non-null destination receiving the decimal bytes.
 * @tparam integer_type Integer type accepted by std::to_chars.
 * @throws std::runtime_error when conversion exceeds the fixed local buffer.
 */
template <typename integer_type>
inline void append_integer(integer_type value, std::string *output)
{
	char buffer[32]{};
	const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
	if (result.ec != std::errc{}) {
		throw std::runtime_error("module JSON integer conversion failed");
	}
	output->append(buffer, static_cast<std::size_t>(result.ptr - buffer));
}

/**
 * @brief Append one reflected message with deterministic field ordering.
 * @param message Borrowed configuration message.
 * @param output Destination receiving the JSON object; partial text may remain on failure.
 * @param depth Current nesting depth, bounded to 16.
 * @throws std::invalid_argument for a null output or excessive nesting.
 */
inline void append_message(const google::protobuf::Message &message, std::string *output, std::size_t depth);

/**
 * @brief Append one scalar or nested-message field value.
 * @param message Borrowed message owning the reflected field.
 * @param field Descriptor selecting the value to encode.
 * @param repeated_index Element index for a repeated field, or a negative value for a singular field.
 * @param output Non-null destination receiving the encoded value.
 * @param depth Current message nesting depth.
 */
inline void append_field_value(const google::protobuf::Message &message, const google::protobuf::FieldDescriptor &field,
			       int repeated_index, std::string *output, std::size_t depth)
{
	const auto *reflection = message.GetReflection();
	const bool repeated = repeated_index >= 0;
	switch (field.cpp_type()) {
	case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
		append_integer(repeated ? reflection->GetRepeatedInt32(message, &field, repeated_index) :
					  reflection->GetInt32(message, &field),
			       output);
		break;
	case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
		append_integer(repeated ? reflection->GetRepeatedInt64(message, &field, repeated_index) :
					  reflection->GetInt64(message, &field),
			       output);
		break;
	case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
		append_integer(repeated ? reflection->GetRepeatedUInt32(message, &field, repeated_index) :
					  reflection->GetUInt32(message, &field),
			       output);
		break;
	case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
		append_integer(repeated ? reflection->GetRepeatedUInt64(message, &field, repeated_index) :
					  reflection->GetUInt64(message, &field),
			       output);
		break;
	case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
		output->append((repeated ? reflection->GetRepeatedBool(message, &field, repeated_index) :
					   reflection->GetBool(message, &field)) ?
				       "true" :
				       "false");
		break;
	case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: {
		const auto *value = repeated ? reflection->GetRepeatedEnum(message, &field, repeated_index) :
					       reflection->GetEnum(message, &field);
		append_integer(value->number(), output);
		break;
	}
	case google::protobuf::FieldDescriptor::CPPTYPE_STRING: {
		std::string scratch;
		const std::string &value =
			repeated ? reflection->GetRepeatedStringReference(message, &field, repeated_index, &scratch) :
				   reflection->GetStringReference(message, &field, &scratch);
		append_json_string(value, output);
		break;
	}
	case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
		append_message(repeated ? reflection->GetRepeatedMessage(message, &field, repeated_index) :
					  reflection->GetMessage(message, &field),
			       output, depth + 1u);
		break;
	case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
	case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
		throw std::invalid_argument("floating-point module config fields are outside the strict JSON contract");
	}
}

inline void append_message(const google::protobuf::Message &message, std::string *output, std::size_t depth)
{
	constexpr std::size_t MAX_DEPTH = 16;
	if (output == nullptr || depth > MAX_DEPTH) {
		throw std::invalid_argument("module JSON message nesting exceeds the test encoder contract");
	}
	const auto *reflection = message.GetReflection();
	std::vector<const google::protobuf::FieldDescriptor *> fields;
	reflection->ListFields(message, &fields);
	std::sort(fields.begin(), fields.end(),
		  [](const auto *left, const auto *right) noexcept { return left->number() < right->number(); });

	output->push_back('{');
	bool first_field = true;
	for (const auto *field : fields) {
		if (field == nullptr || field->is_map()) {
			throw std::invalid_argument("maps are outside the strict module JSON contract");
		}
		if (!first_field) {
			output->push_back(',');
		}
		first_field = false;
		append_json_string(field->name(), output);
		output->push_back(':');
		if (!field->is_repeated()) {
			append_field_value(message, *field, -1, output, depth);
			continue;
		}
		output->push_back('[');
		const int count = reflection->FieldSize(message, field);
		for (int index = 0; index < count; ++index) {
			if (index != 0) {
				output->push_back(',');
			}
			append_field_value(message, *field, index, output, depth);
		}
		output->push_back(']');
	}
	output->push_back('}');
}

/** @brief Own a direct compiler's monotonic storage and immutable result. */
template <typename compiled_type>
struct compiled_policy_owner {
	std::pmr::monotonic_buffer_resource memory;  ///< Owns every allocation borrowed by the compiled policy.
	compiled_type policy;			     ///< Immutable result destroyed before its backing resource.

	/**
	 * @brief Construct the policy with its lifetime-owning resource and explicit identity.
	 * @tparam argument_types Additional production-constructor argument types.
	 * @param arguments Exact constructor inputs supplied by the fixture.
	 */
	template <typename... argument_types>
	explicit compiled_policy_owner(argument_types &&...arguments)
		: policy(memory, std::forward<argument_types>(arguments)...)
	{
	}
};

/**
 * @brief Compile test JSON while retaining its PMR owner by aliasing pointer.
 * @param json Borrowed exact module configuration bytes.
 * @param compiler Compiler invoked synchronously with the retained resource and output policy.
 * @param arguments Exact additional production-constructor inputs.
 * @return Shared immutable policy retaining its resource, or an empty pointer for a rejected compilation.
 * @tparam compiled_type Policy type constructed from the retained memory resource.
 * @tparam compiler_type Callable implementing the module's configuration compiler signature.
 * @tparam argument_types Additional production-constructor argument types.
 */
template <typename compiled_type, typename compiler_type, typename... argument_types>
[[nodiscard]] inline std::shared_ptr<const compiled_type>
compile_for_test(std::string_view json, compiler_type compiler, argument_types &&...arguments)
{
	auto owner = std::make_shared<compiled_policy_owner<compiled_type>>(std::forward<argument_types>(arguments)...);
	const auto result = compiler(json.data(), json.size(), &owner->memory, &owner->policy,
				     modules::config::cancellation_probe{});
	if (result != modules::config::compile_result::OK) {
		return {};
	}
	const compiled_type *policy = &owner->policy;
	return std::shared_ptr<const compiled_type>(owner, policy);
}

}  // namespace detail

/**
 * @brief Encode one module-owned authoring message as strict runtime JSON.
 *
 * Only populated fields are emitted, in field-number order, with original
 * snake-case names and integer enum values. Unlike Protobuf's standard JSON
 * mapping, 64-bit integers remain JSON numbers because that is the module
 * runtime contract.
 *
 * @param message Typed host-side module configuration.
 * @return Deterministic compact JSON accepted by the production module reader.
 */
[[nodiscard]] inline std::string module_config_json(const google::protobuf::Message &message)
{
	std::string output;
	detail::append_message(message, &output, 0);
	return output;
}

/**
 * @brief Directly compile an ACL JSON fixture with retained PMR ownership.
 * @param json Borrowed exact module configuration bytes.
 * @return Immutable compiled policy retaining its resource, or an empty pointer on rejection.
 */
[[nodiscard]] inline std::shared_ptr<const modules::acl::acl_compiled> compile_acl_for_test(std::string_view json)
{
	return detail::compile_for_test<modules::acl::acl_compiled>(json, modules::acl::compile_acl_from_json);
}

/**
 * @brief Directly compile a NAT44 JSON fixture with retained PMR ownership.
 * @param json Borrowed exact module configuration bytes.
 * @param partition Explicit module-context identity for the compiled policy.
 * @return Immutable compiled policy retaining its resource, or an empty pointer on rejection.
 */
[[nodiscard]] inline std::shared_ptr<const modules::nat44::nat_pools_compiled>
compile_nat_for_test(std::string_view json, modules::nat44::context_partition partition)
{
	return detail::compile_for_test<modules::nat44::nat_pools_compiled>(json, modules::nat44::compile_nat_from_json,
									    partition);
}

/**
 * @brief Directly compile a QoS JSON fixture with retained PMR ownership.
 * @param json Borrowed exact module configuration bytes.
 * @return Immutable compiled policy retaining its resource, or an empty pointer on rejection.
 */
[[nodiscard]] inline std::shared_ptr<const modules::qos::qos_profiles_compiled>
compile_qos_for_test(std::string_view json)
{
	return detail::compile_for_test<modules::qos::qos_profiles_compiled>(json, modules::qos::compile_qos_from_json);
}

}  // namespace kinetum::test
