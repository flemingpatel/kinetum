// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file module_manager.cpp
 * @brief Exact module-generation admission and ownership implementation.
 * @author Fleming Patel
 */

#include "src/dp/module/module_manager.hpp"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <limits>
#include <new>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "src/common/log.hpp"
#include "src/common/path_admission.hpp"
#include "src/dp/module/module_descriptor_admission.hpp"
#include "src/dp/module/module_epoch_store.hpp"
#include "src/dp/module/module_lifecycle_adapter.hpp"
#include "src/sdk/module_abi_text.hpp"

namespace kinetum::dp::module
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;
using kinetum::dp::lifecycle::lifecycle_context_identity;
using kinetum::dp::lifecycle::lifecycle_context_owner;
using kinetum::dp::lifecycle::lifecycle_log_provider;
using kinetum::dp::lifecycle::lifecycle_memory_provider;
using kinetum::dp::lifecycle::lifecycle_operation_control;
using kinetum::dp::lifecycle::lifecycle_phase;

namespace
{

/** @brief Maximum delay before a waiting lifecycle turn rechecks cancellation. */
constexpr auto LIFECYCLE_CANCELLATION_OBSERVATION_INTERVAL = std::chrono::milliseconds(1);

/**
 * @brief Read cancellation from one lifecycle-operation authority.
 *
 * @param opaque Borrowed non-null lifecycle_operation_control pointer.
 * @return true when cancellation has been requested.
 */
[[nodiscard]] bool control_cancelled_probe(const void *opaque) noexcept
{
	const auto *control = static_cast<const lifecycle_operation_control *>(opaque);
	return control->cancellation_requested();
}

/**
 * @brief Supply the non-cancellable probe used by mandatory FINI.
 *
 * @param opaque Ignored callback context.
 * @return Always false.
 */
[[nodiscard]] bool never_cancelled_probe([[maybe_unused]] const void *opaque) noexcept
{
	return false;
}

/**
 * @brief Translate one exact module callback failure into platform status.
 *
 * @param operation Human-readable lifecycle operation.
 * @param module_id Exact admitted module identity.
 * @param context_id Exact admitted context identity.
 * @param error Exact module ABI error.
 * @return MODULE_ERROR carrying all callback identity and error evidence.
 */
[[nodiscard]] status module_callback_status(std::string_view operation, std::string_view module_id,
					    std::string_view context_id, kinetum_error error)
{
	std::ostringstream message;
	message << "module " << operation << " failed: module_id=" << module_id << " context_instance_id=" << context_id
		<< " error=" << kinetum_strerror(error) << " (" << error << ')';
	return status(status_code::MODULE_ERROR, message.str());
}

/**
 * @brief Construct one exact image loading or registration failure.
 *
 * @param message Complete loader diagnostic.
 * @return MODULE_ERROR carrying @p message.
 */
[[nodiscard]] status module_load_status(std::string message)
{
	return status(status_code::MODULE_ERROR, std::move(message));
}

}  // namespace

/** @brief Own one atomically admitted module-image and context generation. */
struct module_manager::admitted_module_generation {
	std::vector<module_image_spec> image_specs;			 ///< Canonical exact-retry authority.
	std::vector<module_context_spec> context_specs;			 ///< Canonical exact-retry authority.
	lifecycle_memory_provider *memory_provider{nullptr};		 ///< Borrowed generation-lifetime authority.
	lifecycle_log_provider *log_provider{nullptr};			 ///< Borrowed generation-lifetime authority.
	std::vector<std::unique_ptr<loaded_module_image>> images;	 ///< Stable image owners.
	std::vector<std::unique_ptr<module_context_instance>> contexts;	 ///< Stable context owners.
	std::unordered_map<std::string, loaded_module_image *> image_by_id;	   ///< Exact image index.
	std::unordered_map<std::string, module_context_instance *> context_by_id;  ///< Exact context index.
	std::unordered_map<uint32_t, module_context_instance *> context_by_index;  ///< Compact context index.
};

module_manager::module_manager() = default;

loaded_module_image::~loaded_module_image() noexcept
{
	descriptor = nullptr;
}

module_context_instance::~module_context_instance() = default;

module_lifecycle_serialization::claim::claim(module_lifecycle_serialization &owner) noexcept
	: owner_(&owner)
{
}

module_lifecycle_serialization::claim::claim(claim &&other) noexcept
	: owner_(std::exchange(other.owner_, nullptr))
{
}

module_lifecycle_serialization::claim::~claim()
{
	release();
}

void module_lifecycle_serialization::claim::release() noexcept
{
	if (owner_) {
		owner_->release_();
		owner_ = nullptr;
	}
}

status_or<module_lifecycle_serialization::claim>
module_lifecycle_serialization::acquire(std::chrono::steady_clock::time_point deadline, cancellation_probe probe,
					const void *probe_context) noexcept
{
	std::unique_lock<std::mutex> lock(mutex_);
	for (;;) {
		if (probe && probe(probe_context)) {
			return status(status_code::CANCELLED,
				      kinetum::common::static_status_text(
					      "module image lifecycle turn cancelled before callback admission"));
		}
		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			return status(
				status_code::DEADLINE_EXCEEDED,
				kinetum::common::static_status_text(
					"module image lifecycle turn deadline expired before callback admission"));
		}
		if (!active_) {
			active_ = true;
			return claim(*this);
		}

		// The mutex is held only while observing turn state. Timed wakeups make
		// cancellation observable even when the active foreign callback does not
		// complete or publish a condition-variable notification.
		const auto observation_deadline = std::min(deadline, now + LIFECYCLE_CANCELLATION_OBSERVATION_INTERVAL);
		condition_.wait_until(lock, observation_deadline);
	}
}

void module_lifecycle_serialization::release_() noexcept
{
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (!active_) {
			std::terminate();
		}
		active_ = false;
	}
	condition_.notify_one();
}

module_manager::~module_manager()
{
	// Destruction requires every packet worker and lifecycle executor to have
	// joined. No manager lock is held while foreign FINI code executes.
	if (generation_) {
		destroy_staged_generation_(generation_->contexts, generation_->images);
		generation_.reset();
	}
}

void module_manager::destroy_staged_generation_(std::vector<std::unique_ptr<module_context_instance>> &contexts,
						std::vector<std::unique_ptr<loaded_module_image>> &images) noexcept
{
	lifecycle_operation_control finish_control(std::chrono::steady_clock::time_point::max());
	for (auto context_it = contexts.rbegin(); context_it != contexts.rend(); ++context_it) {
		auto &context = *context_it;
		if (context && context->epoch_store && !context->epoch_store->empty()) {
			// FINI cannot run while an exact prepared/published/retained artifact
			// remains owned: module code needed by RETIRE would be torn down first.
			std::terminate();
		}
		if (!context || !context->initialized || !context->image || !context->lifecycle_owner ||
		    !context->image->descriptor || !context->image->descriptor->fini) {
			continue;
		}

		auto turn_or = context->image->lifecycle_serialization.acquire(
			std::chrono::steady_clock::time_point::max(), never_cancelled_probe, nullptr);
		if (!turn_or.is_ok()) {
			std::terminate();
		}
		auto turn = std::move(turn_or).value();
		auto operation_or = context->lifecycle_owner->begin_operation(lifecycle_phase::FINI, 0, finish_control);
		if (!operation_or.is_ok()) {
			std::terminate();
		}
		auto operation = std::move(operation_or).value();
		try {
			context->image->descriptor->fini(&operation.context(), context->packet_context.state);
		} catch (...) {
			std::terminate();
		}
		context->packet_context.state = nullptr;
		context->initialized = false;
	}
	contexts.clear();
	images.clear();
}

status module_manager::admit_generation(std::vector<module_image_spec> images,
					std::vector<module_context_spec> contexts,
					kinetum::dp::lifecycle::lifecycle_memory_provider &memory_provider,
					kinetum::dp::lifecycle::lifecycle_log_provider &log_provider,
					lifecycle_operation_control &control)
{
	if (images.empty() || contexts.empty()) {
		return status(status_code::INVALID_ARGUMENT,
			      "module generation requires at least one image and one context");
	}
	if (images.size() > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
		return status(status_code::OUT_OF_RANGE, "module generation image count exceeds compact index range");
	}

	std::sort(images.begin(), images.end(),
		  [](const auto &lhs, const auto &rhs) { return lhs.module_id < rhs.module_id; });
	std::sort(contexts.begin(), contexts.end(), [](const auto &lhs, const auto &rhs) {
		if (lhs.context_index != rhs.context_index) {
			return lhs.context_index < rhs.context_index;
		}
		return lhs.context_instance_id < rhs.context_instance_id;
	});

	{
		std::unique_lock<std::shared_mutex> lock(mutex_);
		if (generation_) {
			if (generation_->image_specs == images && generation_->context_specs == contexts &&
			    generation_->memory_provider == &memory_provider &&
			    generation_->log_provider == &log_provider) {
				return status::ok();
			}
			return status(status_code::FAILED_PRECONDITION,
				      "module manager already owns a different admitted generation");
		}
		if (admission_in_progress_) {
			return status(status_code::FAILED_PRECONDITION,
				      "module generation admission is already in progress");
		}
		admission_in_progress_ = true;
	}

	const auto fail_admission = [this](status failure) {
		std::unique_lock<std::shared_mutex> lock(mutex_);
		admission_in_progress_ = false;
		return failure;
	};

	std::vector<std::unique_ptr<loaded_module_image>> staged_images;
	std::vector<std::unique_ptr<module_context_instance>> staged_contexts;
	try {
		staged_images.reserve(images.size());
		staged_contexts.reserve(contexts.size());

		std::unordered_set<std::string> image_ids;
		std::unordered_set<std::string> image_paths;
		std::unordered_map<std::string, std::size_t> image_position_by_id;
		std::unordered_map<std::string, std::vector<std::string>> context_ids_by_image;
		std::unordered_set<std::string> context_ids;
		std::unordered_set<uint32_t> context_indices;
		image_ids.reserve(images.size());
		image_paths.reserve(images.size());
		image_position_by_id.reserve(images.size());
		context_ids_by_image.reserve(images.size());
		context_ids.reserve(contexts.size());
		context_indices.reserve(contexts.size());

		const auto fail_staged = [&](status failure) {
			destroy_staged_generation_(staged_contexts, staged_images);
			return fail_admission(std::move(failure));
		};

		for (std::size_t index = 0; index < images.size(); ++index) {
			const auto &spec = images[index];
			if (!kinetum::sdk::valid_module_abi_text(spec.module_id)) {
				return fail_staged(status(status_code::INVALID_ARGUMENT,
							  "module generation contains a module_id outside the bounded "
							  "printable-ASCII ABI contract"));
			}
			if (!image_ids.insert(spec.module_id).second) {
				return fail_staged(status(status_code::INVALID_ARGUMENT,
							  "module generation contains duplicate module_id '" +
								  spec.module_id + "'"));
			}
			const std::string path = spec.canonical_path.string();
			if (!image_paths.insert(path).second) {
				return fail_staged(
					status(status_code::INVALID_ARGUMENT,
					       "module generation aliases one image path under multiple IDs: " + path));
			}
			if (const auto path_status =
				    kinetum::common::validate_exact_regular_file(spec.canonical_path, "module image");
			    !path_status.is_ok()) {
				return fail_staged(path_status);
			}
			image_position_by_id.emplace(spec.module_id, index);
			context_ids_by_image.emplace(spec.module_id, std::vector<std::string>{});
		}

		for (const auto &spec : contexts) {
			if (!kinetum::sdk::valid_module_abi_text(spec.context_instance_id) ||
			    !kinetum::sdk::valid_module_abi_text(spec.module_id)) {
				return fail_staged(status(status_code::INVALID_ARGUMENT,
							  "module context requires bounded printable-ASCII context and "
							  "module identity"));
			}
			if (spec.cpu_core_id < 0 || spec.numa_node < 0) {
				return fail_staged(
					status(status_code::INVALID_ARGUMENT,
					       "module context requires exact nonnegative CPU and NUMA ownership: " +
						       spec.context_instance_id));
			}
			if (spec.context_memory_capacity_bytes == 0u || spec.epoch_arena_capacity_bytes == 0u) {
				return fail_staged(
					status(status_code::INVALID_ARGUMENT,
					       "module context requires nonzero context and epoch memory capacities: " +
						       spec.context_instance_id));
			}
			if (!context_ids.insert(spec.context_instance_id).second) {
				return fail_staged(status(status_code::INVALID_ARGUMENT,
							  "module generation contains duplicate context_instance_id '" +
								  spec.context_instance_id + "'"));
			}
			if (!context_indices.insert(spec.context_index).second) {
				return fail_staged(status(status_code::INVALID_ARGUMENT,
							  "module generation contains duplicate context_index " +
								  std::to_string(spec.context_index)));
			}
			auto ids_it = context_ids_by_image.find(spec.module_id);
			if (ids_it == context_ids_by_image.end()) {
				return fail_staged(
					status(status_code::INVALID_ARGUMENT,
					       "module context references unknown image '" + spec.module_id + "'"));
			}
			ids_it->second.push_back(spec.context_instance_id);
		}
		for (auto &[module_id, ids] : context_ids_by_image) {
			(void)module_id;
			std::sort(ids.begin(), ids.end());
		}
		for (const auto &spec : contexts) {
			const auto &ids = context_ids_by_image.at(spec.module_id);
			const auto position = std::lower_bound(ids.begin(), ids.end(), spec.context_instance_id);
			const auto ordinal = static_cast<std::size_t>(position - ids.begin());
			if (spec.module_context_count != ids.size() || spec.module_context_ordinal != ordinal) {
				return fail_staged(status::invalid_argument(
					"module context ordinal or population disagrees with exact generation membership"));
			}
		}
		for (const auto &[module_id, ids] : context_ids_by_image) {
			if (ids.empty()) {
				return fail_staged(status(status_code::INVALID_ARGUMENT,
							  "module image has no admitted context: " + module_id));
			}
		}

		using register_fn = const kinetum_module *(*)();
		for (std::size_t index = 0; index < images.size(); ++index) {
			const auto &spec = images[index];
			auto image = std::make_unique<loaded_module_image>();
			image->module_image_index = static_cast<uint32_t>(index);
			image->module_id = spec.module_id;
			image->canonical_path = spec.canonical_path;

			auto library_or = common::shared_object::open_path(spec.canonical_path);
			if (!library_or.is_ok()) {
				const auto &error = library_or.error();
				const std::string_view detail = error.details().empty() ? error.message() :
											  error.details();
				return fail_staged(module_load_status("exact module image load failed for '" +
								      spec.canonical_path.string() +
								      "': " + std::string(detail)));
			}
			image->dynamic_library = std::move(library_or).value();

			auto symbol_or = image->dynamic_library.symbol("kinetum_module_register");
			if (!symbol_or.is_ok()) {
				const auto &error = symbol_or.error();
				const std::string_view detail = error.details().empty() ? error.message() :
											  error.details();
				return fail_staged(module_load_status(
					"exact module image lacks kinetum_module_register: module_id=" +
					spec.module_id + " error=" + std::string(detail)));
			}
			auto *register_module = reinterpret_cast<register_fn>(symbol_or.value());

			const kinetum_module *descriptor = nullptr;
			try {
				descriptor = register_module();
			} catch (...) {
				return fail_staged(module_load_status(
					"kinetum_module_register threw across the C ABI: module_id=" + spec.module_id));
			}
			image->descriptor = descriptor;
			if (!descriptor) {
				return fail_staged(module_load_status(
					"kinetum_module_register returned null: module_id=" + spec.module_id));
			}
			if (const auto descriptor_status = validate_module_descriptor(descriptor);
			    !descriptor_status.is_ok()) {
				return fail_staged(descriptor_status);
			}
			if (spec.module_id != descriptor->module_id) {
				const std::string actual = descriptor->module_id ? descriptor->module_id : "<null>";
				return fail_staged(status(status_code::FAILED_PRECONDITION,
							  "module descriptor identity mismatch: expected='" +
								  spec.module_id + "' actual='" + actual + "'"));
			}
			image->module_version = descriptor->module_version;
			staged_images.push_back(std::move(image));
		}

		for (const auto &[module_id, ids] : context_ids_by_image) {
			const auto image_position = image_position_by_id.at(module_id);
			const auto *descriptor = staged_images[image_position]->descriptor;
			if (ids.size() > 1u && (descriptor->flags & KINETUM_MOD_F_REPLICABLE_CONTEXTS) == 0) {
				return fail_staged(status(status_code::FAILED_PRECONDITION,
							  "module image owns multiple contexts without "
							  "KINETUM_MOD_F_REPLICABLE_CONTEXTS: " +
								  module_id));
			}
		}

		for (const auto &spec : contexts) {
			auto context = std::make_unique<module_context_instance>();
			context->context_instance_id = spec.context_instance_id;
			context->context_index = spec.context_index;
			context->image = staged_images[image_position_by_id.at(spec.module_id)].get();

			lifecycle_context_identity identity{
				.module_id = spec.module_id,
				.context_instance_id = spec.context_instance_id,
				.module_image_index = context->image->module_image_index,
				.context_index = spec.context_index,
				.worker_index = spec.worker_index,
				.cpu_core_id = spec.cpu_core_id,
				.numa_node = spec.numa_node,
				.module_context_ordinal = spec.module_context_ordinal,
				.module_context_count = spec.module_context_count,
			};
			auto owner_or = lifecycle_context_owner::create(std::move(identity),
									spec.context_memory_capacity_bytes,
									spec.epoch_arena_capacity_bytes,
									memory_provider, log_provider);
			if (!owner_or.is_ok()) {
				return fail_staged(owner_or.error());
			}
			context->lifecycle_owner = std::move(owner_or).value();

			auto turn_or = context->image->lifecycle_serialization.acquire(
				control.deadline(), control_cancelled_probe, &control);
			if (!turn_or.is_ok()) {
				return fail_staged(turn_or.error());
			}
			auto turn = std::move(turn_or).value();
			auto operation_or =
				context->lifecycle_owner->begin_operation(lifecycle_phase::INIT, 0, control);
			if (!operation_or.is_ok()) {
				// The serialization owner lives inside the staged image. End
				// this borrowed turn before rollback destroys that image.
				turn.release();
				return fail_staged(operation_or.error());
			}
			auto operation = std::move(operation_or).value();
			void *state = nullptr;
			kinetum_error init_result = KINETUM_ERR_INTERNAL;
			try {
				init_result = context->image->descriptor->init(&operation.context(), &state);
			} catch (...) {
				if (state != nullptr) {
					std::terminate();
				}
				operation.release();
				turn.release();
				return fail_staged(module_load_status(
					"module INIT threw across the C ABI: module_id=" + spec.module_id +
					" context_instance_id=" + spec.context_instance_id));
			}
			operation.release();
			turn.release();
			if (init_result != KINETUM_OK) {
				if (state != nullptr) {
					std::terminate();
				}
				return fail_staged(module_callback_status("INIT", spec.module_id,
									  spec.context_instance_id, init_result));
			}

			context->packet_context.state = state;
			context->packet_context.numa_node = spec.numa_node;
			context->packet_context.cpu_core_id = spec.cpu_core_id;
			context->packet_context.worker_index = spec.worker_index;
			context->initialized = true;
			auto *initialized_context = context.get();
			staged_contexts.push_back(std::move(context));
			auto epoch_store_or = module_epoch_store::create(initialized_context->image->module_image_index,
									 initialized_context->context_index,
									 initialized_context->image->descriptor,
									 &initialized_context->packet_context,
									 initialized_context->lifecycle_owner.get());
			if (!epoch_store_or.is_ok()) {
				return fail_staged(epoch_store_or.error());
			}
			initialized_context->epoch_store = std::move(epoch_store_or).value();
		}

		std::unordered_map<std::string, loaded_module_image *> staged_image_by_id;
		std::unordered_map<std::string, module_context_instance *> staged_context_by_id;
		std::unordered_map<uint32_t, module_context_instance *> staged_context_by_index;
		staged_image_by_id.reserve(staged_images.size());
		staged_context_by_id.reserve(staged_contexts.size());
		staged_context_by_index.reserve(staged_contexts.size());
		for (auto &image : staged_images) {
			staged_image_by_id.emplace(image->module_id, image.get());
		}
		for (auto &context : staged_contexts) {
			staged_context_by_id.emplace(context->context_instance_id, context.get());
			staged_context_by_index.emplace(context->context_index, context.get());
		}

		auto staged_generation = std::make_unique<admitted_module_generation>();
		staged_generation->image_specs = std::move(images);
		staged_generation->context_specs = std::move(contexts);
		staged_generation->memory_provider = &memory_provider;
		staged_generation->log_provider = &log_provider;
		staged_generation->images = std::move(staged_images);
		staged_generation->contexts = std::move(staged_contexts);
		staged_generation->image_by_id = std::move(staged_image_by_id);
		staged_generation->context_by_id = std::move(staged_context_by_id);
		staged_generation->context_by_index = std::move(staged_context_by_index);
		const auto image_count = staged_generation->images.size();
		const auto context_count = staged_generation->contexts.size();

		{
			std::unique_lock<std::shared_mutex> lock(mutex_);
			if (!admission_in_progress_ || generation_) {
				lock.unlock();
				destroy_staged_generation_(staged_generation->contexts, staged_generation->images);
				std::terminate();
			}
			// One non-throwing owner-pointer publication is the atomic visibility
			// point for every image, context, retry fact, and lookup index.
			generation_ = std::move(staged_generation);
			admission_in_progress_ = false;
		}

		KINETUM_LOG_INFO("module", "module.admitted", "admitted exact module generation: images={} contexts={}",
				 image_count, context_count);
		return status::ok();
	} catch (const std::bad_alloc &) {
		destroy_staged_generation_(staged_contexts, staged_images);
		return fail_admission(
			status(status_code::RESOURCE_EXHAUSTED, "module generation admission exhausted host memory"));
	} catch (const std::exception &error) {
		destroy_staged_generation_(staged_contexts, staged_images);
		return fail_admission(status(status_code::INTERNAL_ERROR,
					     "module generation admission raised an unexpected host exception: " +
						     std::string(error.what())));
	} catch (...) {
		destroy_staged_generation_(staged_contexts, staged_images);
		return fail_admission(status(status_code::INTERNAL_ERROR,
					     "module generation admission raised an unknown host exception"));
	}
}

bool module_manager::has_generation() const noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return generation_ != nullptr;
}

const loaded_module_image *module_manager::image(const std::string &module_id) const noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!generation_) {
		return nullptr;
	}
	const auto it = generation_->image_by_id.find(module_id);
	return it == generation_->image_by_id.end() ? nullptr : it->second;
}

const loaded_module_image *module_manager::image(uint32_t module_image_index) const noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!generation_ || static_cast<std::size_t>(module_image_index) >= generation_->images.size()) {
		return nullptr;
	}
	return generation_->images[module_image_index].get();
}

module_context_instance *module_manager::context(const std::string &context_instance_id) noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!generation_) {
		return nullptr;
	}
	const auto it = generation_->context_by_id.find(context_instance_id);
	return it == generation_->context_by_id.end() ? nullptr : it->second;
}

module_context_instance *module_manager::context(uint32_t context_index) noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!generation_) {
		return nullptr;
	}
	const auto it = generation_->context_by_index.find(context_index);
	return it == generation_->context_by_index.end() ? nullptr : it->second;
}

module_context_instance *module_manager::context_at_ordinal(std::size_t ordinal) noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	if (!generation_ || ordinal >= generation_->contexts.size()) {
		return nullptr;
	}
	return generation_->contexts[ordinal].get();
}

status_or<std::unique_ptr<module_lifecycle_adapter>>
module_manager::make_lifecycle_adapter(uint32_t context_index) const
{
	loaded_module_image *image = nullptr;
	const lifecycle_context_identity *identity = nullptr;
	{
		std::shared_lock<std::shared_mutex> lock(mutex_);
		if (!generation_) {
			return status(status_code::NOT_FOUND,
				      "module lifecycle adapter requires an admitted generation");
		}
		const auto it = generation_->context_by_index.find(context_index);
		if (it == generation_->context_by_index.end() || !it->second || !it->second->image) {
			return status(status_code::NOT_FOUND,
				      "module lifecycle adapter context_index is not admitted: " +
					      std::to_string(context_index));
		}
		image = it->second->image;
		identity = &it->second->lifecycle_owner->identity();
	}
	try {
		return std::make_unique<module_lifecycle_adapter>(*image, *identity);
	} catch (const std::bad_alloc &) {
		return status(status_code::RESOURCE_EXHAUSTED, "failed to allocate module lifecycle adapter");
	}
}

std::size_t module_manager::image_count() const noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return generation_ ? generation_->images.size() : 0;
}

std::size_t module_manager::context_count() const noexcept
{
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return generation_ ? generation_->contexts.size() : 0;
}

}  // namespace kinetum::dp::module
