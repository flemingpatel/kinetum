// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file log_service.hpp
 * @brief Process-owned service logging lifecycle and loss observations.
 * @author Fleming Patel
 */

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include "src/common/log_options.hpp"

namespace kinetum::common
{

/** @brief Logging destination state, independent of runtime serving readiness. */
enum class log_destination_state : uint8_t {
	AVAILABLE = 1,	///< The admitted file destination accepts complete records.
	UNAVAILABLE,	///< An I/O failure requires explicit reopen of the same destination.
	CLOSED,		///< Emitters have retired and the writer has joined.
};

/**
 * @brief Monotone process logging observations, never behavioral authority.
 *
 * Counters are sampled individually; they are not a simultaneous conservation
 * equation while producers are running. A quiescent snapshot is exact. Filtered
 * messages are absent from every loss counter. Console loss is independent of
 * delivery to the persistent file.
 */
struct log_health {
	uint64_t packet_thread_rejections{0};  ///< Native records refused without entering cold logging.
	uint64_t delivery_timeouts{0};	       ///< Foreign ERROR+ waits expired; final file fate remains independent.
	log_destination_state destination{log_destination_state::CLOSED};  ///< File availability.
	uint64_t accepted_records{0};	     ///< Successfully published ordinary or reserved records.
	uint64_t queue_rejections{0};	     ///< New records refused by exhausted or contended bounded admission.
	uint64_t format_rejections{0};	     ///< Records not admitted because construction failed.
	uint64_t unavailable_rejections{0};  ///< New records refused by an unavailable destination.
	uint64_t undelivered_records{0};     ///< Accepted records without complete file delivery.
	uint64_t write_failures{0};	     ///< Failed file append, rotation, reopen, or close operations.
	uint64_t console_failures{0};	     ///< Failed mirror or emergency stderr delivery.
	uint64_t truncated_records{0};	     ///< Admitted records explicitly marked as truncated.
	std::array<char, 256> failure{};     ///< First cause of the current destination outage.
};

/** @return Current process observations, or CLOSED before admission and after retirement. */
[[nodiscard]] log_health process_log_health() noexcept;

/**
 * @brief Sole process owner of the bounded record arena and its writer thread.
 *
 * Block process-control signals before start(). The owner must outlive every
 * service emitter, native callback registration, module/provider retirement,
 * and health reader. Destruction closes admission, allows two seconds to drain,
 * and joins. An unresolved writer fails stop; it is never detached or freed.
 */
class log_service final {
    public:
	/**
	 * @brief Admit files, start the writer, and publish the sole service frontend.
	 * @param options Complete immutable settings.
	 * @param application Exact fixed service role.
	 * @param writer_cpu Compiled DP coordinator CPU; absent for CP and Photon.
	 * @return Complete owner or a pre-publication startup failure.
	 */
	[[nodiscard]] static status_or<std::unique_ptr<log_service>>
	start(const log_options &options, std::string_view application,
	      std::optional<int32_t> writer_cpu = std::nullopt);
	/** @brief Drain and join after every external emitter has retired. */
	~log_service();
	log_service(const log_service &) = delete;
	log_service &operator=(const log_service &) = delete;
	/** @brief Request writer-owned reopen; repeated pending requests coalesce. */
	void request_reopen() noexcept;
	/** @brief End mandatory startup-error mirroring after the service's existing startup gate. */
	void startup_complete() noexcept;
	/** @return Independently sampled counters and coherent destination/cause; never waits for file I/O. */
	[[nodiscard]] log_health health() const noexcept;

    private:
	/** @brief Implementation owns all queue, descriptor, and synchronization state. */
	class implementation;
	/** @param state Fully allocated unpublished implementation transferred to this owner. */
	explicit log_service(std::unique_ptr<implementation> state) noexcept;
	std::unique_ptr<implementation> state_;	 ///< Exact lifetime of all producers' owned records.

	friend bool log_enabled(log_level, std::string_view) noexcept;
	friend void submit_log(struct log_site, void *, std::size_t (*)(void *, std::span<char>)) noexcept;
	friend void submit_foreign_log(struct log_site, void *, std::size_t (*)(void *, std::span<char>)) noexcept;
	friend void offer_fatal_log(struct log_site, std::string_view) noexcept;
	friend bool flush_logs() noexcept;
	friend void reject_log_record() noexcept;
};

}  // namespace kinetum::common
