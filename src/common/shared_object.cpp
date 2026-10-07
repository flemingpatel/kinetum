// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file shared_object.cpp
 * @brief Exact RTLD_NOW/RTLD_LOCAL shared-object ownership implementation.
 * @author Fleming Patel
 */

#include "src/common/shared_object.hpp"

#include <array>
#include <charconv>
#include <cstring>
#include <exception>
#include <string>
#include <system_error>
#include <utility>

#include <dlfcn.h>

#include "src/common/status.hpp"

namespace kinetum::common
{
namespace
{

/**
 * @brief Close one exact loader handle or fail stop.
 *
 * A failed close means the ownership record and dynamic loader disagree about
 * whether foreign code remains resident. Continuing would make subsequent ABI
 * and callback lifetime reasoning false.
 *
 * @param handle Sole handle, or null for an empty owner.
 */
void close_or_terminate(void *handle) noexcept
{
	if (handle != nullptr && ::dlclose(handle) != 0) {
		std::terminate();
	}
}

/**
 * @brief Open one exact loader path.
 *
 * @param path Non-null exact NUL-terminated path passed to dlopen.
 * @return Unique handle, or an explicit immediate-load failure.
 */
status_or<void *> open_exact_path(const char *path)
{
	::dlerror();
	void *handle = ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (handle == nullptr) {
		const char *error = ::dlerror();
		return status(status_code::FAILED_PRECONDITION,
			      "exact shared-object load failed for '" + std::string(path) + "'",
			      error != nullptr ? std::string(error) : "unknown loader error");
	}
	return handle;
}

}  // namespace

shared_object::shared_object(void *handle) noexcept
	: handle_(handle)
{
}

shared_object::~shared_object()
{
	close_or_terminate(handle_);
}

shared_object::shared_object(shared_object &&other) noexcept
	: handle_(std::exchange(other.handle_, nullptr))
{
}

shared_object &shared_object::operator=(shared_object &&other) noexcept
{
	if (this != &other) {
		close_or_terminate(handle_);
		handle_ = std::exchange(other.handle_, nullptr);
	}
	return *this;
}

status_or<shared_object> shared_object::open_path(const std::filesystem::path &path)
{
	if (path.empty()) {
		return status::invalid_argument("shared-object path must not be empty");
	}
	const std::string exact_path = path.string();
	auto handle_or = open_exact_path(exact_path.c_str());
	if (!handle_or.is_ok()) {
		return handle_or.error();
	}
	return shared_object(handle_or.value());
}

status_or<shared_object> shared_object::open_descriptor(int descriptor)
{
	if (descriptor < 0) {
		return status::invalid_argument("shared-object descriptor must be nonnegative");
	}
	static constexpr char DESCRIPTOR_PREFIX[] = "/proc/self/fd/";
	std::array<char, 64> descriptor_path{};
	std::memcpy(descriptor_path.data(), DESCRIPTOR_PREFIX, sizeof(DESCRIPTOR_PREFIX) - 1u);
	auto conversion = std::to_chars(descriptor_path.data() + sizeof(DESCRIPTOR_PREFIX) - 1u,
					descriptor_path.data() + descriptor_path.size() - 1u, descriptor);
	if (conversion.ec != std::errc{}) {
		return status::internal_error("shared-object descriptor path exceeds its fixed representation");
	}
	*conversion.ptr = '\0';
	auto handle_or = open_exact_path(descriptor_path.data());
	if (!handle_or.is_ok()) {
		return handle_or.error();
	}
	return shared_object(handle_or.value());
}

bool shared_object::valid() const noexcept
{
	return handle_ != nullptr;
}

status_or<void *> shared_object::symbol(const char *name) const
{
	if (!valid()) {
		return status::failed_precondition("cannot resolve a symbol from an empty shared-object owner");
	}
	if (name == nullptr || *name == '\0') {
		return status::invalid_argument("shared-object symbol name must be nonempty");
	}

	::dlerror();
	void *address = ::dlsym(handle_, name);
	const char *error = ::dlerror();
	if (error != nullptr || address == nullptr) {
		return status(status_code::NOT_FOUND, "exact shared-object symbol is unavailable",
			      error != nullptr ? std::string(error) : "null symbol");
	}
	return address;
}

}  // namespace kinetum::common
