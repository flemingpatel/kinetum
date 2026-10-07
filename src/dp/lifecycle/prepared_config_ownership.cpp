// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file prepared_config_ownership.cpp
 * @brief Exact prepared-configuration token implementation.
 * @author Fleming Patel
 */

#include "src/dp/lifecycle/prepared_config_ownership.hpp"

#include <exception>
#include <utility>

namespace kinetum::dp::lifecycle
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

prepared_config_ownership::prepared_config_ownership(uint32_t module_image_index, uint32_t context_index,
						     uint64_t epoch, prepared_config_record record,
						     std::optional<epoch_arena_ownership> arena) noexcept
	: module_image_index_(module_image_index)
	, context_index_(context_index)
	, epoch_(epoch)
	, record_(record)
	, arena_(std::move(arena))
	, owns_state_(true)
{
}

prepared_config_ownership::prepared_config_ownership(prepared_config_ownership &&other) noexcept
{
	move_from_(other);
}

prepared_config_ownership &prepared_config_ownership::operator=(prepared_config_ownership &&other) noexcept
{
	if (this == &other) {
		return *this;
	}
	if (owns_state_) {
		std::terminate();
	}
	move_from_(other);
	return *this;
}

prepared_config_ownership::~prepared_config_ownership()
{
	if (owns_state_) {
		std::terminate();
	}
}

status_or<prepared_config_ownership> prepared_config_ownership::create(uint32_t module_image_index,
								       uint32_t context_index, uint64_t epoch,
								       prepared_config_record record,
								       std::optional<epoch_arena_ownership> arena)
{
	if (epoch == 0) {
		return status(status_code::INVALID_ARGUMENT, "prepared ownership requires a nonzero exact epoch");
	}
	if (arena.has_value() &&
	    (!arena->owns_memory() || arena->context_index() != context_index || arena->epoch() != epoch)) {
		return status(status_code::INVALID_ARGUMENT,
			      "prepared ownership arena does not match the exact context and epoch");
	}
	return prepared_config_ownership(module_image_index, context_index, epoch, record, std::move(arena));
}

bool prepared_config_ownership::owns_state() const noexcept
{
	return owns_state_;
}

uint32_t prepared_config_ownership::module_image_index() const noexcept
{
	return module_image_index_;
}

uint32_t prepared_config_ownership::context_index() const noexcept
{
	return context_index_;
}

uint64_t prepared_config_ownership::epoch() const noexcept
{
	return epoch_;
}

status_or<prepared_config_record> prepared_config_ownership::borrow_exact(uint32_t module_image_index,
									  uint32_t context_index,
									  uint64_t epoch) const noexcept
{
	if (!owns_state_) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("prepared ownership token has already been consumed"));
	}
	if (module_image_index_ != module_image_index || context_index_ != context_index || epoch_ != epoch) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "prepared ownership identity does not match module, context, and epoch"));
	}
	return record_;
}

status prepared_config_ownership::retire_exact(uint32_t module_image_index, uint32_t context_index,
					       uint64_t epoch) noexcept
{
	if (!owns_state_) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("prepared ownership token has already been consumed"));
	}
	if (module_image_index_ != module_image_index || context_index_ != context_index || epoch_ != epoch) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "prepared retirement identity does not match module, context, and epoch"));
	}

	arena_.reset();
	record_ = {};
	module_image_index_ = 0;
	context_index_ = 0;
	epoch_ = 0;
	owns_state_ = false;
	return status::ok();
}

const epoch_arena_ownership *prepared_config_ownership::arena() const noexcept
{
	return arena_ ? &*arena_ : nullptr;
}

void prepared_config_ownership::move_from_(prepared_config_ownership &other) noexcept
{
	module_image_index_ = std::exchange(other.module_image_index_, 0);
	context_index_ = std::exchange(other.context_index_, 0);
	epoch_ = std::exchange(other.epoch_, 0);
	record_ = std::exchange(other.record_, {});
	arena_ = std::move(other.arena_);
	other.arena_.reset();
	owns_state_ = std::exchange(other.owns_state_, false);
}

}  // namespace kinetum::dp::lifecycle
