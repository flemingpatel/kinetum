// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file runtime_telemetry_source_owner.cpp
 * @brief Exact generation claims for cold runtime telemetry.
 * @author Fleming Patel
 */

#include "src/dp/runtime_telemetry_source_owner.hpp"

#include <exception>
#include <new>
#include <utility>

namespace kinetum::dp
{

runtime_telemetry_source_owner::~runtime_telemetry_source_owner() noexcept
{
	retire();
}

common::status runtime_telemetry_source_owner::publish(uint64_t runtime_generation,
						       std::unique_ptr<runtime_telemetry_source> source)
{
	if (runtime_generation == 0) {
		return common::status::invalid_argument("runtime telemetry generation must be nonzero");
	}
	if (!source) {
		return common::status::invalid_argument("runtime telemetry source is required");
	}

	std::lock_guard<std::mutex> lock(mutex_);
	if (source_ || claim_active_ || accepting_claims_) {
		return common::status::failed_precondition("runtime telemetry source is already published");
	}
	if (runtime_generation <= last_generation_) {
		return common::status::failed_precondition(
			"runtime telemetry generation must be strictly newer than the retired generation");
	}

	source_ = std::move(source);
	published_generation_ = runtime_generation;
	last_generation_ = runtime_generation;
	accepting_claims_ = true;
	return common::status::ok();
}

common::status_or<runtime_telemetry_snapshot>
runtime_telemetry_source_owner::collect(uint64_t runtime_generation, const runtime_telemetry_request &request) const
{
	runtime_telemetry_source *source = nullptr;
	{
		std::unique_lock<std::mutex> lock(mutex_);
		if (!source_ || !accepting_claims_ || runtime_generation != published_generation_) {
			return common::status::unavailable(
				"runtime telemetry source is unavailable for the requested generation");
		}
		cv_.wait(lock, [this, runtime_generation]() {
			return !claim_active_ || !accepting_claims_ || !source_ ||
			       published_generation_ != runtime_generation;
		});
		if (!source_ || !accepting_claims_ || runtime_generation != published_generation_) {
			return common::status::unavailable(
				"runtime telemetry generation retired while the observation was waiting");
		}
		claim_active_ = true;
		source = source_.get();
	}

	bool claim_held = true;
	try {
		auto result = source->collect(request);
		release_claim_();
		claim_held = false;
		return result;
	} catch (const std::bad_alloc &) {
		if (claim_held) {
			release_claim_();
		}
		return common::status::resource_exhausted("runtime telemetry collection exhausted memory");
	} catch (...) {
		if (claim_held) {
			release_claim_();
		}
		return common::status::internal_error("runtime telemetry source raised an exception");
	}
}

void runtime_telemetry_source_owner::retire() noexcept
{
	std::unique_ptr<runtime_telemetry_source> retired;
	try {
		std::unique_lock<std::mutex> lock(mutex_);
		if (!source_) {
			if (claim_active_ || accepting_claims_ || published_generation_ != 0) {
				std::terminate();
			}
			return;
		}

		accepting_claims_ = false;
		cv_.notify_all();
		cv_.wait(lock, [this]() { return !claim_active_; });
		retired = std::move(source_);
		published_generation_ = 0;
	} catch (...) {
		std::terminate();
	}

	// A provider source may execute foreign teardown. It must never run while
	// the platform's publication/claim mutex is held.
	retired.reset();
}

std::optional<uint64_t> runtime_telemetry_source_owner::published_generation() const noexcept
{
	try {
		std::lock_guard<std::mutex> lock(mutex_);
		if (!source_ || !accepting_claims_) {
			return std::nullopt;
		}
		return published_generation_;
	} catch (...) {
		std::terminate();
	}
}

void runtime_telemetry_source_owner::release_claim_() const noexcept
{
	try {
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (!claim_active_ || !source_) {
				std::terminate();
			}
			claim_active_ = false;
		}
		cv_.notify_all();
	} catch (...) {
		std::terminate();
	}
}

}  // namespace kinetum::dp
