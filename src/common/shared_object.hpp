// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file shared_object.hpp
 * @brief Exact RTLD_NOW/RTLD_LOCAL shared-object ownership.
 * @author Fleming Patel
 *
 * This mechanism owns only dynamic-loader handle and symbol mechanics. It does
 * not decide artifact provenance, ABI policy, descriptor meaning, module
 * admission, provider selection, or unload safety. Callers establish those
 * policies before and after opening one exact path.
 *
 * @par Thread Safety
 * One shared_object uniquely owns its handle. Symbol lookup must not race with
 * move or destruction. Different handles may be used concurrently subject to
 * the dynamic loader's process semantics.
 */

#include <filesystem>

#include "src/common/status_or.hpp"

namespace kinetum::common
{

/**
 * @brief Unique owner of one immediately and locally bound shared object.
 */
class shared_object {
    public:
	/** @brief Construct an empty owner. */
	shared_object() noexcept = default;

	/** @brief Close an owned handle, failing stop if loader state disagrees. */
	~shared_object();

	/** @brief Disable handle aliasing. */
	shared_object(const shared_object &) = delete;

	/** @brief Disable handle aliasing by assignment. */
	shared_object &operator=(const shared_object &) = delete;

	/**
	 * @brief Transfer one exact loader handle.
	 * @param other Source owner, left empty after transfer.
	 */
	shared_object(shared_object &&other) noexcept;

	/**
	 * @brief Close this owner's handle, then transfer another; self-assignment leaves ownership intact.
	 * @param other Source owner, left empty after a distinct-owner transfer.
	 * @return This owner after transfer; an unsuccessful close fails stop.
	 */
	shared_object &operator=(shared_object &&other) noexcept;

	/**
	 * @brief Open one exact filesystem path with RTLD_NOW/RTLD_LOCAL.
	 *
	 * @param path Exact caller-admitted path.
	 * @return Unique handle, or an immediate dynamic-loader failure.
	 */
	[[nodiscard]] static status_or<shared_object> open_path(const std::filesystem::path &path);

	/**
	 * @brief Open one already-held descriptor through `/proc/self/fd/N`.
	 *
	 * @param descriptor Open descriptor retained by the caller for at least the
	 *        duration of this call.
	 * @return Unique handle, or an immediate dynamic-loader failure.
	 */
	[[nodiscard]] static status_or<shared_object> open_descriptor(int descriptor);

	/** @return true while this value owns a loader handle. */
	[[nodiscard]] bool valid() const noexcept;

	/**
	 * @brief Resolve one exact dynamic symbol from this object.
	 *
	 * @param name Non-null, nonempty, NUL-terminated exact symbol name.
	 * @return Non-null symbol address, or an explicit lookup failure.
	 */
	[[nodiscard]] status_or<void *> symbol(const char *name) const;

    private:
	/**
	 * @brief Adopt one successful dlopen handle.
	 * @param handle Sole loader handle transferred into this owner.
	 */
	explicit shared_object(void *handle) noexcept;

	void *handle_{nullptr};	 ///< Sole dynamic-loader handle.
};

}  // namespace kinetum::common
