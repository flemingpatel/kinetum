// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file log_file.hpp
 * @brief Single-writer, descriptor-owned rotating service log destination.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <string_view>

#include "src/common/log_options.hpp"

namespace kinetum::common
{

/** @brief Allocation-free I/O failure retaining the first failing operation. */
struct log_io_result {
	int error{0};		    ///< Native errno, or zero after complete delivery.
	const char *operation{""};  ///< Static operation name, never borrowed foreign text.
	/** @return True only for complete success. */
	[[nodiscard]] bool is_ok() const noexcept
	{
		return error == 0;
	}
};

/**
 * @brief Exact role-file ownership, independent of record producers.
 *
 * Startup owns open(); the sole writer subsequently owns append(), reopen(),
 * and close(). A separate stable lock inode excludes another process across
 * active-file renames. No failure truncates a file or selects another directory.
 * Rotation temporarily parks the oldest file at index keep_files; it is removed
 * only after the new active file exists. A gap left by an interrupted rename is
 * completed without overwriting a surviving archive.
 */
class log_file final {
    public:
	/** @brief Construct an empty destination. */
	log_file() noexcept = default;
	/** @brief Close every retained descriptor; explicit close() reports errors. */
	~log_file();
	log_file(const log_file &) = delete;
	log_file &operator=(const log_file &) = delete;

	/**
	 * @brief Admit an exact directory and lock one declared service's file set.
	 * @param options Validated immutable retention and directory settings.
	 * @param application kinetum_photon, kinetum_cp, or kinetum_dp.
	 * @return First admission error; partial ownership is released on failure.
	 */
	[[nodiscard]] status open(const log_options &options, std::string_view application);
	/**
	 * @brief Append one complete encoded record, rotating before its first byte.
	 * @param record Complete newline-terminated encoded bytes.
	 * @return First I/O failure, or complete delivery. After failure, require explicit reopen().
	 */
	[[nodiscard]] log_io_result append(std::string_view record) noexcept;
	/** @return Readmission of the same held directory and active file, or the first I/O failure. */
	[[nodiscard]] log_io_result reopen() noexcept;
	/** @return First close failure after relinquishing every descriptor, or success. */
	[[nodiscard]] log_io_result close() noexcept;

    private:
	/**
	 * @param index Exact active/archive index in names_.
	 * @param absence_allowed Whether ENOENT is an admitted outcome.
	 * @return Complete ownership/type/size proof or the first failure.
	 */
	[[nodiscard]] log_io_result check_leaf_(uint32_t index, bool absence_allowed) const noexcept;
	/** @return Active-file admission with incomplete tails preserved, or the first I/O failure. */
	[[nodiscard]] log_io_result open_active_() noexcept;
	/** @return Rotation into the first hole without inode replacement, or the first I/O failure. */
	[[nodiscard]] log_io_result rotate_() noexcept;
	/** @return Exact family admission, including the interrupted-rotation slot, or the first failure. */
	[[nodiscard]] log_io_result check_family_() const noexcept;
	/** @return Removal of the parked oldest file after active admission, or the first I/O failure. */
	[[nodiscard]] log_io_result finish_rotation_() noexcept;

	int directory_{-1};				///< Held, protected terminal directory.
	int lock_{-1};					///< Stable process-lifetime advisory lock inode.
	int active_{-1};				///< Sole append descriptor, never opened with truncation.
	uint64_t size_{0};				///< Bytes already present in the held active inode.
	uint64_t maximum_bytes_{0};			///< Admitted whole-record file ceiling.
	uint32_t keep_files_{0};			///< Retention count including the active file.
	std::array<std::array<char, 64>, 33> names_{};	///< Closed role-name family plus rotation slot.
};

}  // namespace kinetum::common
