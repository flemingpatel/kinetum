// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file module_manager.hpp
 * @brief Atomic admission and ownership of one exact module generation.
 * @author Fleming Patel
 *
 * A module generation is admitted as one immutable set of code images and
 * context instances. Image indices are assigned by sorted module identity;
 * context indices and owner-worker placement are supplied by the compiled
 * execution topology. Admission validates every path, descriptor, identity,
 * capability, and context before publishing any lookup result.
 *
 * The manager accepts only canonical absolute regular-file identities for main
 * images. It has no main-image relative resolution, loader search, aliasing,
 * lazy load, stage ELF discovery, configuration callback, or foreign-thread
 * health path. Declared shared dependencies are link-time DT_NEEDED authority
 * colocated with the verified image artifact set. Module
 * lifecycle callbacks run without the manager mutex. A dedicated image-local
 * serialization domain orders INIT, PREPARE, RETIRE, and FINI for contexts
 * backed by the same code image while allowing different images to progress in
 * parallel.
 *
 * @par Thread Safety
 * Generation admission is serialized and may occur once. An exact retry is a
 * no-op; any different second generation is rejected. Published image and
 * context lookups are thread-safe and remain stable until destruction. The
 * caller must stop every owner worker and lifecycle executor before destroying
 * the manager.
 *
 * @par Performance
 * This component is cold-path only. Packet execution caches stable descriptor
 * and context pointers after exact epoch-view construction; it never calls a
 * manager lookup.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include "src/common/shared_object.hpp"
#include "src/common/status.hpp"
#include "src/common/status_or.hpp"
#include "src/dp/lifecycle/lifecycle_context.hpp"
#include <kinetum/kinetum_sdk.h>

namespace kinetum::dp::module
{

class module_epoch_store;

class module_lifecycle_adapter;

/**
 * @brief Image-wide logical serialization for foreign lifecycle callbacks.
 *
 * The condition-variable mutex protects only turn admission/publication and is
 * released before the foreign callback starts. A live claim is therefore a
 * logical image turn, not a platform lock held across module code.
 */
class module_lifecycle_serialization {
    public:
	/** @brief Cooperative cancellation probe used while awaiting an image turn. */
	using cancellation_probe = bool (*)(const void *) noexcept;

	/** @brief Move-only ownership of one image lifecycle turn. */
	class claim {
	    public:
		claim(const claim &) = delete;
		claim &operator=(const claim &) = delete;
		claim &operator=(claim &&) = delete;
		/**
		 * @brief Transfer one live turn and empty the source claim.
		 *
		 * @param other Live or empty claim whose ownership is transferred.
		 */
		claim(claim &&other) noexcept;
		/** @brief Publish turn completion when this claim is live. */
		~claim();

		/** @brief Release the image turn immediately; repeated release is harmless. */
		void release() noexcept;

	    private:
		friend class module_lifecycle_serialization;
		/**
		 * @brief Adopt one turn already reserved by an image domain.
		 *
		 * @param owner Serialization domain whose active turn is transferred.
		 */
		explicit claim(module_lifecycle_serialization &owner) noexcept;
		module_lifecycle_serialization *owner_{nullptr};  ///< Live turn owner.
	};

	/**
	 * @brief Wait for and claim one image lifecycle turn.
	 *
	 * The wait periodically observes cancellation so one blocked image does not
	 * hide an already-cancelled queued callback until the full deadline.
	 *
	 * @param deadline Absolute monotonic operation deadline.
	 * @param probe Optional cooperative cancellation probe.
	 * @param probe_context Opaque argument supplied to @p probe.
	 * @return Live logical turn, CANCELLED, or DEADLINE_EXCEEDED.
	 */
	[[nodiscard]] kinetum::common::status_or<claim> acquire(std::chrono::steady_clock::time_point deadline,
								cancellation_probe probe,
								const void *probe_context) noexcept;

    private:
	friend class claim;
	/** @brief Publish completion of one live turn and wake a waiter. */
	void release_() noexcept;

	std::mutex mutex_;		     ///< Turn-state wait-protocol mutex.
	std::condition_variable condition_;  ///< Waiters for the next image turn.
	bool active_{false};		     ///< Whether one claim owns the turn.
};

/** @brief Exact external authority for one module code image. */
struct module_image_spec {
	std::string module_id;		       ///< Expected descriptor identity.
	std::filesystem::path canonical_path;  ///< Exact canonical absolute file.

	/**
	 * @brief Compare complete image authority for exact generation retries.
	 *
	 * @param other Candidate image authority.
	 * @return true only when identity and canonical path are equal.
	 */
	[[nodiscard]] bool operator==(const module_image_spec &other) const = default;
};

/** @brief Exact compiled ownership of one mutable module context. */
struct module_context_spec {
	std::string context_instance_id;	       ///< Stable executable context identity.
	std::string module_id;			       ///< Exact owning module image identity.
	uint32_t context_index{0};		       ///< Compiled executable-context index.
	uint32_t worker_index{0};		       ///< Sole owner-worker index.
	int32_t cpu_core_id{-1};		       ///< Exact owner-worker logical CPU.
	int32_t numa_node{-1};			       ///< Exact context NUMA node.
	std::size_t context_memory_capacity_bytes{0};  ///< Exact context-lifetime allocation bound.
	std::size_t epoch_arena_capacity_bytes{0};     ///< Exact capacity required for each epoch arena.
	uint32_t module_context_ordinal{0};	       ///< Generation-fixed ordinal within the module configuration.
	uint32_t module_context_count{0};	       ///< Complete positive context population for that configuration.

	/**
	 * @brief Compare complete context authority for exact generation retries.
	 *
	 * @param other Candidate context authority.
	 * @return true only when identity, index, worker, CPU, NUMA, lifecycle-memory,
	 *         and module-scoped ordinal/population facts match.
	 */
	[[nodiscard]] bool operator==(const module_context_spec &other) const = default;
};

/**
 * @brief Stable immutable record for one admitted module code image.
 *
 * The dynamic-library handle and descriptor remain valid until manager
 * destruction. `lifecycle_serialization` is the sole image-wide foreign-code
 * serialization authority; it is never acquired by packet execution.
 */
struct loaded_module_image {
	/**
	 * @brief Close the exact dynamic-library owner handle when still live.
	 *
	 * Destruction is valid only after all dependent contexts and callback claims
	 * have ended.
	 */
	~loaded_module_image() noexcept;

	/** @brief Construct an empty image record before transactional admission. */
	loaded_module_image() = default;
	loaded_module_image(const loaded_module_image &) = delete;
	loaded_module_image &operator=(const loaded_module_image &) = delete;
	loaded_module_image(loaded_module_image &&) = delete;
	loaded_module_image &operator=(loaded_module_image &&) = delete;

	uint32_t module_image_index{0};				 ///< Sorted generation-local index.
	std::string module_id;					 ///< Exact descriptor identity.
	std::string module_version;				 ///< Exact admitted descriptor version.
	std::filesystem::path canonical_path;			 ///< Exact admitted file identity.
	common::shared_object dynamic_library;			 ///< Sole exact-image loader handle.
	const kinetum_module *descriptor{nullptr};		 ///< Immutable image descriptor.
	module_lifecycle_serialization lifecycle_serialization;	 ///< Image-local cold callback order.
};

/**
 * @brief Stable owner of one admitted live module context.
 *
 * The lifecycle owner contains all cold services. `packet_context` contains
 * only context-local mutable state and immutable owner placement; no cold
 * service is reachable from packet callbacks.
 */
struct module_context_instance {
	/** @brief Construct one empty context record before transactional admission. */
	module_context_instance() = default;
	module_context_instance(const module_context_instance &) = delete;
	module_context_instance &operator=(const module_context_instance &) = delete;
	module_context_instance(module_context_instance &&) = delete;
	module_context_instance &operator=(module_context_instance &&) = delete;
	/** @brief Destroy only after the exact epoch store has become empty. */
	~module_context_instance();

	std::string context_instance_id;      ///< Exact executable context identity.
	uint32_t context_index{0};	      ///< Compiled executable-context index.
	loaded_module_image *image{nullptr};  ///< Stable owning code image.
	std::unique_ptr<kinetum::dp::lifecycle::lifecycle_context_owner> lifecycle_owner;  ///< Stable cold-service owner.
	kinetum_ctx packet_context{};			  ///< One-cache-line owner-worker context.
	bool initialized{false};			  ///< Whether successful INIT requires FINI.
	std::unique_ptr<module_epoch_store> epoch_store;  ///< Exact artifact and executable-view owner.
};

/**
 * @brief Atomic owner of one exact module image/context generation.
 *
 * Every image is loaded by canonical path with immediate local binding. A
 * generation-scoped image must not register process-global constructor state
 * whose authority can outlive image unload. Built-in runtime images therefore
 * use strict image-local configuration readers; generated Protobuf registries
 * remain host/offline authoring authorities only.
 */
class module_manager {
    public:
	/** @brief Construct an empty manager with no admitted generation. */
	module_manager();

	/**
	 * @brief Finalize all contexts and unload all images.
	 *
	 * FINI runs after callers have joined owner workers and lifecycle services.
	 * Contexts are finalized in reverse context-index order; images are unloaded
	 * only after every context using them has completed FINI.
	 */
	~module_manager();

	module_manager(const module_manager &) = delete;
	module_manager &operator=(const module_manager &) = delete;
	module_manager(module_manager &&) = delete;
	module_manager &operator=(module_manager &&) = delete;

	/**
	 * @brief Admit one complete exact module generation atomically.
	 *
	 * Image input order is non-authoritative: the manager sorts unique module
	 * identities and assigns deterministic zero-based image indices. Context
	 * indices come from the compiled topology and need not be contiguous because
	 * platform stages may occupy intervening executable indices.
	 *
	 * All images must be referenced by at least one context. Multiple contexts
	 * for one image require `KINETUM_MOD_F_REPLICABLE_CONTEXTS`. INIT executes
	 * only after every image and context relation has passed structural
	 * validation. Images load by exact canonical path with `RTLD_NOW | RTLD_LOCAL`
	 * before registration. Module-owned shared dependencies must be link-complete,
	 * versioned, and colocated with the image under its `$ORIGIN` contract.
	 * If any INIT fails, already initialized staged contexts receive FINI and
	 * every staged image is unloaded before this method returns.
	 *
	 * @param images Complete image authority for the generation.
	 * @param contexts Complete context ownership for the generation.
	 * @param memory_provider Exact lifecycle allocation authority that must
	 *        outlive this manager.
	 * @param log_provider Exact lifecycle diagnostic authority that must outlive
	 *        this manager.
	 * @param control Stable deadline/cancellation authority for all INIT calls.
	 * @return OK after complete publication or an exact retry; otherwise the
	 *         exact structural-validation, canonical-path admission, host
	 *         allocation, cancellation/deadline, dynamic-loading, registration,
	 *         or INIT-callback failure status produced before publication.
	 */
	[[nodiscard]] kinetum::common::status
	admit_generation(std::vector<module_image_spec> images, std::vector<module_context_spec> contexts,
			 kinetum::dp::lifecycle::lifecycle_memory_provider &memory_provider,
			 kinetum::dp::lifecycle::lifecycle_log_provider &log_provider,
			 kinetum::dp::lifecycle::lifecycle_operation_control &control);

	/**
	 * @brief Return whether a complete generation has been published.
	 *
	 * @return true only after atomic admission succeeds.
	 */
	[[nodiscard]] bool has_generation() const noexcept;

	/**
	 * @brief Resolve one admitted image by exact module identity.
	 *
	 * @param module_id Exact descriptor module identity.
	 * @return Stable image pointer, or nullptr when absent.
	 */
	[[nodiscard]] const loaded_module_image *image(const std::string &module_id) const noexcept;

	/**
	 * @brief Resolve one admitted image by deterministic compact index.
	 *
	 * @param module_image_index Generation-local image index.
	 * @return Stable image pointer, or nullptr when out of range.
	 */
	[[nodiscard]] const loaded_module_image *image(uint32_t module_image_index) const noexcept;

	/**
	 * @brief Resolve one admitted context by exact executable identity.
	 *
	 * @param context_instance_id Exact context identity.
	 * @return Stable context pointer, or nullptr when absent.
	 */
	[[nodiscard]] module_context_instance *context(const std::string &context_instance_id) noexcept;

	/**
	 * @brief Resolve one admitted context by compiled executable index.
	 *
	 * @param context_index Exact executable-context index.
	 * @return Stable context pointer, or nullptr when absent.
	 */
	[[nodiscard]] module_context_instance *context(uint32_t context_index) noexcept;

	/**
	 * @brief Resolve one admitted context by deterministic generation ordinal.
	 *
	 * This cold-path enumeration authority lets runtime admission prove
	 * two-directional set equality without scanning sparse context indices or
	 * exposing the manager's lookup maps.
	 *
	 * @param ordinal Position in sorted context-index order.
	 * @return Stable context pointer, or nullptr when out of range.
	 */
	[[nodiscard]] module_context_instance *context_at_ordinal(std::size_t ordinal) noexcept;

	/**
	 * @brief Construct the production lifecycle adapter for one context.
	 *
	 * The returned adapter borrows the stable image record and must not outlive
	 * this manager. Different adapters for one image share its exact
	 * serialization domain.
	 *
	 * @param context_index Exact admitted executable-context index.
	 * @return Unique adapter, or NOT_FOUND for an absent context.
	 */
	[[nodiscard]] kinetum::common::status_or<std::unique_ptr<module_lifecycle_adapter>>
	make_lifecycle_adapter(uint32_t context_index) const;

	/**
	 * @brief Return the number of published module images.
	 *
	 * @return Zero before admission, otherwise exact generation cardinality.
	 */
	[[nodiscard]] std::size_t image_count() const noexcept;

	/**
	 * @brief Return the number of published module contexts.
	 *
	 * @return Zero before admission, otherwise exact generation cardinality.
	 */
	[[nodiscard]] std::size_t context_count() const noexcept;

    private:
	/** @brief Opaque atomically published image/context generation authority. */
	struct admitted_module_generation;

	/**
	 * @brief Roll back one staged generation without publishing it.
	 *
	 * @param contexts Staged contexts finalized in reverse order and cleared.
	 * @param images Staged images unloaded after every context is cleared.
	 */
	static void destroy_staged_generation_(std::vector<std::unique_ptr<module_context_instance>> &contexts,
					       std::vector<std::unique_ptr<loaded_module_image>> &images) noexcept;

	mutable std::shared_mutex mutex_;			  ///< Publication and stable lookup guard.
	bool admission_in_progress_{false};			  ///< One staging owner at a time.
	std::unique_ptr<admitted_module_generation> generation_;  ///< Atomically published exact authority.
};

}  // namespace kinetum::dp::module
