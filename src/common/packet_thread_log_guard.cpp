// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file packet_thread_log_guard.cpp
 * @brief Exact thread exclusion and single-writer rejection publication.
 * @author Fleming Patel
 */

#include "src/common/packet_thread_log_guard.hpp"

#include <exception>
#include <limits>
#include <mutex>

namespace kinetum::common
{
namespace
{

// This state belongs to the host image, never to a dynamically loaded provider.
// Initial-exec TLS keeps rejection independent of lazy TLS allocation/resolution.
/** Current exact packet scope; installed and removed only by its owning thread. */
[[gnu::tls_model("initial-exec")]] constinit thread_local packet_thread_log_guard *CURRENT_PACKET_THREAD = nullptr;
/** Protects only scope registration, retirement, and cold reads. */
std::mutex REGISTRY_MUTEX;
/** Intrusive caller-storage scopes, all alive while the registry mutex is held. */
packet_thread_log_guard *LIVE_SCOPES = nullptr;
/** Counts transferred from scopes whose packet owners have retired. */
uint64_t RETIRED_REJECTIONS = 0;

/**
 * @param left Existing nonnegative count.
 * @param right Additional independently observed count.
 * @return Monotone sum without wrap; UINT64_MAX denotes exhausted representation.
 */
[[nodiscard]] uint64_t add_count(uint64_t left, uint64_t right) noexcept
{
	return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static_assert(std::atomic<uint64_t>::is_always_lock_free);

}  // namespace

packet_thread_log_guard::packet_thread_log_guard() noexcept
{
	if (CURRENT_PACKET_THREAD != nullptr) {
		std::terminate();
	}
	std::lock_guard lock(REGISTRY_MUTEX);
	next_ = LIVE_SCOPES;
	if (next_ != nullptr) {
		next_->previous_ = this;
	}
	LIVE_SCOPES = this;
	CURRENT_PACKET_THREAD = this;
}

packet_thread_log_guard::~packet_thread_log_guard()
{
	if (CURRENT_PACKET_THREAD != this) {
		std::terminate();
	}
	std::lock_guard lock(REGISTRY_MUTEX);
	RETIRED_REJECTIONS = add_count(RETIRED_REJECTIONS, rejected_);
	if (previous_ != nullptr) {
		previous_->next_ = next_;
	} else {
		LIVE_SCOPES = next_;
	}
	if (next_ != nullptr) {
		next_->previous_ = previous_;
	}
	CURRENT_PACKET_THREAD = nullptr;
}

bool reject_packet_thread_log() noexcept
{
	auto *const scope = CURRENT_PACKET_THREAD;
	if (scope == nullptr) {
		return false;
	}
	if (scope->rejected_ != UINT64_MAX) {
		++scope->rejected_;
		scope->published_.store(scope->rejected_, std::memory_order_relaxed);
	}
	return true;
}

uint64_t packet_thread_log_rejections() noexcept
{
	std::lock_guard lock(REGISTRY_MUTEX);
	uint64_t total = RETIRED_REJECTIONS;
	for (const auto *scope = LIVE_SCOPES; scope != nullptr; scope = scope->next_) {
		total = add_count(total, scope->published_.load(std::memory_order_relaxed));
	}
	return total;
}

}  // namespace kinetum::common
