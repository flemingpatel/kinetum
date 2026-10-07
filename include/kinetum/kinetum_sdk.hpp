// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file kinetum_sdk.hpp
 * @brief Header-only C++ wrappers for the exact Kinetum module ABI.
 * @author Fleming Patel
 *
 * This header provides modern C++ conveniences on top of the C SDK:
 * - Inline passive-module dispatch and indexed packet access
 * - An owner-local counter wrapper plus the C histogram surface
 * - Compile-time module descriptor generation
 * - Generic user metadata accessors (MECHANISM, not domain-specific)
 *
 * @section philosophy Design Philosophy (Mechanism vs Policy)
 *
 * This C++ wrapper follows the same mechanism vs policy separation as the C SDK:
 * - **Mechanisms provided**: Indexed packet access, telemetry, exact lifecycle
 * - **NOT provided**: Domain-specific types (SATCOM, GTP, etc.)
 * - Users define their own domain types and use generic user_meta accessors
 *
 * @section perf Performance Guarantees
 *
 * All hot-path operations are:
 * - O(1) complexity
 * - Single-owner and lock-free
 * - Zero-allocation after initialization
 * - Cache-line aware
 *
 * @section patterns Design Patterns
 *
 * 1. **Pre-Registered Counters**: Register at init, O(1) updates in hot path
 * 2. **Exact Config View**: The runtime supplies batch->epoch_config directly
 * 3. **CRTP Module Base**: Direct C callback generation
 * 4. **User Metadata Templates**: Type-safe access to user-defined metadata
 *
 * @section algo Algorithm Library (kinetum::algo)
 *
 * Bounded algorithms available to customer modules:
 *
 * | Algorithm | Use Case | Performance |
 * |-----------|----------|-------------|
 * | `cuckoo_map<K,V,H>` | Flow/session indexes with a non-throwing field-wise hash | O(1) worst-case lookup |
 * | `spsc_ring_static<T,N>` / `spsc_ring<T>` | Inter-stage queues | Compile-time/runtime bounded SPSC |
 * | `token_bucket` | Exact-rational rate limiting | O(1), allocation-free check |
 * | `lru_cache<K,V>` | Exact-membership cold/read-mostly bounded cache | Average O(1) touch/evict |
 * | `match_cidr_batch()` | Scalar-equivalent SIMD ACL evaluation | Batched mask comparison |
 *
 * Example in custom module:
 * @code
 * struct flow_key_hash {
 *     std::size_t operator()(const flow_key& key) const noexcept {
 *         uint64_t hash = kinetum::algo::FNV1A_OFFSET_BASIS;
 *         const auto mix = [&hash](uint64_t field) noexcept {
 *             for (uint32_t shift = 0; shift < 64; shift += 8) {
 *                 hash ^= static_cast<uint8_t>(field >> shift);
 *                 hash *= kinetum::algo::FNV1A_PRIME;
 *             }
 *         };
 *         mix(key.src_ip); mix(key.dst_ip); mix(key.src_port);
 *         mix(key.dst_port); mix(key.protocol);
 *         return static_cast<std::size_t>(hash);
 *     }
 * };
 *
 * class my_flow_tracker : public module_base<my_flow_tracker> {
 * public:
 *     explicit my_flow_tracker(const kinetum_lifecycle_ctx* lifecycle)
 *         : module_base(lifecycle), flows_(4096, context_memory_resource()) {}
 *
 * private:
 *     // O(1) worst-case lookup for flow state
 *     kinetum::algo::cuckoo_map<flow_key, flow_state, flow_key_hash> flows_;
 *
 *     uint64_t do_process(kinetum_batch_t* batch) noexcept {
 *         for (uint16_t i = 0; i < batch->count; i++) {
 *             flow_key key{KINETUM_PKT_SRC_IP(batch, i), KINETUM_PKT_DST_IP(batch, i), ...};
 *             if (auto* state = flows_.find(key)) {
 *                 // Lookup checks the two fixed candidate buckets.
 *             }
 *         }
 *         return 0;
 *     }
 * };
 * @endcode
 *
 * The key equality, field-wise hash, and copied key/value operations must be
 * non-throwing because a packet-path cuckoo lookup or displacement cannot
 * recover from an escaping element operation.
 *
 */

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory_resource>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <kinetum/kinetum_sdk.h>

// ============================================================================
// Algorithm Library - Available to all customer modules
// ============================================================================
// These bounded algorithms are exposed to customer modules:
// - kinetum::algo::cuckoo_map      - O(1) lookup with an exact field-wise hash
// - kinetum::algo::spsc_ring_static / spsc_ring - Lock-free bounded SPSC queues
// - kinetum::algo::token_bucket    - Exact-rational rate limiting
// - kinetum::algo::lru_cache       - Exact-membership bounded cold cache
// - kinetum::algo::match_cidr_batch - Scalar-equivalent SIMD batch classification
// - See docs/ALGORITHM_LIBRARY.md for the full contract
#include <kinetum/algo/algo.hpp>

namespace kinetum
{
namespace sdk
{

// ============================================================================
// Forward Declarations
// ============================================================================

template <typename ModuleT>
class module_base;

class counter;

/**
 * @brief PMR adapter for one context's tracked lifecycle allocations.
 *
 * Construction-time allocations are delegated to the exact INIT lifecycle
 * owner. Successful initialization seals the resource, making later container
 * growth fail rather than falling back to the process heap. FINI reattaches the
 * exact owner so member destruction releases every tracked allocation before
 * the context's outer storage is returned.
 */
class context_memory_resource final : public std::pmr::memory_resource {
    public:
	/**
	 * @brief Bind one newly constructing context to its INIT authority.
	 * @param lifecycle Non-null lifecycle shell borrowed through successful INIT.
	 */
	explicit context_memory_resource(const kinetum_lifecycle_ctx *lifecycle) noexcept
		: lifecycle_(lifecycle)
	{
		if (lifecycle_ == nullptr) {
			std::terminate();
		}
	}

	context_memory_resource(const context_memory_resource &) = delete;
	context_memory_resource &operator=(const context_memory_resource &) = delete;
	context_memory_resource(context_memory_resource &&) = delete;
	context_memory_resource &operator=(context_memory_resource &&) = delete;

	/** @brief Require all resource-owned allocations to have been reclaimed. */
	~context_memory_resource() override
	{
		if (outstanding_allocations_ != 0) {
			std::terminate();
		}
	}

	/** @brief Seal allocation after successful INIT and discard the borrowed shell. */
	void seal() noexcept
	{
		if (state_ != state::CONSTRUCTING || lifecycle_ == nullptr) {
			std::terminate();
		}
		state_ = state::SEALED;
		lifecycle_ = nullptr;
	}

	/**
	 * @brief Bind the exact FINI shell before context-member destruction.
	 * @param lifecycle Non-null lifecycle shell matching this context.
	 */
	void begin_reclamation(const kinetum_lifecycle_ctx *lifecycle) noexcept
	{
		if (state_ != state::SEALED || lifecycle == nullptr) {
			std::terminate();
		}
		state_ = state::RECLAIMING;
		lifecycle_ = lifecycle;
	}

    private:
	/** @brief Exact allocation phase controlling context-resource operations. */
	enum class state : uint8_t {
		CONSTRUCTING = 0,  ///< INIT may allocate and release context blocks.
		SEALED,		   ///< Published context permits no allocator operation.
		RECLAIMING,	   ///< FINI may release the exact retained blocks.
	};

	/**
	 * @brief Allocate one context-lifetime block through the bound lifecycle shell.
	 * @param bytes Positive requested byte count.
	 * @param alignment Requested power-of-two alignment.
	 * @return Non-null exact block owned by this resource.
	 * @throws std::bad_alloc when allocation is unavailable or the resource is sealed.
	 */
	[[nodiscard]] void *do_allocate(std::size_t bytes, std::size_t alignment) override
	{
		if (state_ != state::CONSTRUCTING || lifecycle_ == nullptr || bytes == 0) {
			throw std::bad_alloc();
		}
		void *storage = nullptr;
		const uint32_t flags = alignment >= KINETUM_CACHE_LINE ?
					       static_cast<uint32_t>(KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) :
					       uint32_t{0};
		if (kinetum_lifecycle_allocate_context(lifecycle_, bytes, alignment, flags, &storage) != KINETUM_OK ||
		    storage == nullptr) {
			throw std::bad_alloc();
		}
		++outstanding_allocations_;
		return storage;
	}

	/**
	 * @brief Release one exact context block during construction or reclamation.
	 * @param pointer Exact non-null block returned by this resource.
	 * @param bytes PMR-provided byte count; lifecycle identity owns validation.
	 * @param alignment PMR-provided alignment; lifecycle identity owns validation.
	 */
	void do_deallocate(void *pointer, [[maybe_unused]] std::size_t bytes,
			   [[maybe_unused]] std::size_t alignment) override
	{
		if (pointer == nullptr || lifecycle_ == nullptr ||
		    (state_ != state::CONSTRUCTING && state_ != state::RECLAIMING) || outstanding_allocations_ == 0 ||
		    kinetum_lifecycle_release_context(lifecycle_, pointer) != KINETUM_OK) {
			std::terminate();
		}
		--outstanding_allocations_;
	}

	/**
	 * @brief Compare exact resource object identity.
	 * @param other Resource to compare.
	 * @return True only for this same adapter object.
	 */
	[[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
	{
		return this == &other;
	}

	const kinetum_lifecycle_ctx *lifecycle_{nullptr};  ///< Borrowed shell valid only in allocating phases.
	std::size_t outstanding_allocations_{0};	   ///< Exact unreleased context-block population.
	state state_{state::CONSTRUCTING};		   ///< Current allocation phase.
};

/**
 * @brief PMR adapter for immutable storage in one exact PREPARE arena.
 *
 * The arena is bump-allocated and reclaimed as one linear ownership token, so
 * PMR deallocation is intentionally a no-op. `seal()` removes the borrowed
 * lifecycle shell before publication; any post-prepare growth then fails
 * closed instead of reaching a process allocator.
 */
class epoch_memory_resource final : public std::pmr::memory_resource {
    public:
	/**
	 * @brief Bind one exact PREPARE operation.
	 * @param lifecycle Non-null lifecycle shell owning the target epoch arena.
	 */
	explicit epoch_memory_resource(const kinetum_lifecycle_ctx *lifecycle) noexcept
		: lifecycle_(lifecycle)
	{
		if (lifecycle_ == nullptr) {
			std::terminate();
		}
	}

	epoch_memory_resource(const epoch_memory_resource &) = delete;
	epoch_memory_resource &operator=(const epoch_memory_resource &) = delete;
	epoch_memory_resource(epoch_memory_resource &&) = delete;
	epoch_memory_resource &operator=(epoch_memory_resource &&) = delete;

	/** @brief Prevent further allocation before publishing the prepared artifact. */
	void seal() noexcept
	{
		if (lifecycle_ == nullptr) {
			std::terminate();
		}
		lifecycle_ = nullptr;
	}

    private:
	/**
	 * @brief Allocate one immutable block from the exact PREPARE arena.
	 * @param bytes Positive requested byte count.
	 * @param alignment Requested power-of-two alignment.
	 * @return Non-null exact block owned by the arena.
	 * @throws std::bad_alloc when allocation is unavailable or the resource is sealed.
	 */
	[[nodiscard]] void *do_allocate(std::size_t bytes, std::size_t alignment) override
	{
		if (lifecycle_ == nullptr || bytes == 0) {
			throw std::bad_alloc();
		}
		void *storage = nullptr;
		const uint32_t flags = alignment >= KINETUM_CACHE_LINE ?
					       static_cast<uint32_t>(KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) :
					       uint32_t{0};
		if (kinetum_lifecycle_allocate_epoch(lifecycle_, bytes, alignment, flags, &storage) != KINETUM_OK ||
		    storage == nullptr) {
			throw std::bad_alloc();
		}
		return storage;
	}

	/**
	 * @brief Accept PMR deallocation while retaining arena-wide ownership.
	 * @param pointer PMR-provided block retained by the complete arena.
	 * @param bytes PMR-provided byte count.
	 * @param alignment PMR-provided alignment.
	 */
	void do_deallocate([[maybe_unused]] void *pointer, [[maybe_unused]] std::size_t bytes,
			   [[maybe_unused]] std::size_t alignment) override
	{
		// The platform releases the complete exact-epoch arena after RETIRE.
	}

	/**
	 * @brief Compare exact resource object identity.
	 * @param other Resource to compare.
	 * @return True only for this same adapter object.
	 */
	[[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
	{
		return this == &other;
	}

	const kinetum_lifecycle_ctx *lifecycle_{nullptr};  ///< Borrowed PREPARE shell, null after sealing.
};

/**
 * @brief Copy one compile-time health reason without formatting.
 *
 * The source array must include its terminating NUL and fit the fixed ABI
 * field. This helper performs one bounded copy suitable for the owner-worker
 * health callback.
 *
 * @tparam N Source array extent including the terminating NUL.
 * @param assessment Module-owned assessment to update.
 * @param reason Compile-time reason literal.
 */
template <std::size_t N>
KINETUM_ALWAYS_INLINE void set_health_reason_literal(kinetum_health_assessment &assessment,
						     const char (&reason)[N]) noexcept
{
	static_assert(N <= KINETUM_HEALTH_REASON_CAPACITY,
		      "health reason literal exceeds KINETUM_HEALTH_REASON_CAPACITY");
	std::memcpy(assessment.reason, reason, N);
}

// ============================================================================
// Owner-Local Telemetry Handles
// ============================================================================

/**
 * @brief C++ wrapper for one pre-registered owner-local counter.
 *
 * Registration is cold INIT work. Packet execution performs one plain update
 * through the cached handle; the context owner is the sole writer.
 */
class counter {
    public:
	/** @brief Construct an empty counter wrapper. */
	counter() noexcept = default;

	/**
	 * @brief Register one counter during module INIT.
	 *
	 * @param lifecycle Borrowed INIT lifecycle context.
	 * @param name Bounded printable-ASCII metric name.
	 * @return Counter wrapper; false when registration fails.
	 */
	[[nodiscard]] static counter create(const kinetum_lifecycle_ctx *lifecycle, const char *name) noexcept
	{
		counter result;
		(void)kinetum_lifecycle_register_counter(lifecycle, name, &result.handle_);
		return result;
	}

	/** @brief Increment the owner-local value once. */
	void inc() const noexcept
	{
		KINETUM_COUNTER_INC(handle_);
	}

	/**
	 * @brief Add one value to the owner-local counter.
	 *
	 * @param delta Value to add.
	 */
	void add(uint64_t delta) const noexcept
	{
		KINETUM_COUNTER_ADD(handle_, delta);
	}

	/**
	 * @brief Read the current owner-local value.
	 *
	 * @return Current value, or zero for an empty wrapper.
	 */
	[[nodiscard]] uint64_t get() const noexcept
	{
		return KINETUM_COUNTER_GET(handle_);
	}

	/**
	 * @brief Test whether registration succeeded.
	 *
	 * @return true when this wrapper owns a valid borrowed handle.
	 */
	[[nodiscard]] explicit operator bool() const noexcept
	{
		return handle_ != nullptr;
	}

	/**
	 * @brief Return the exact C telemetry handle.
	 *
	 * @return Borrowed owner-local counter handle.
	 */
	[[nodiscard]] kinetum_counter_t native() const noexcept
	{
		return handle_;
	}

    private:
	kinetum_counter_t handle_{nullptr};  ///< Owner-lifetime borrowed handle.
};

// ============================================================================
// Exact Packet Configuration View
// ============================================================================

/**
 * @brief Resolve the immutable exact configuration carried by one batch.
 *
 * This helper performs no lookup: the batch pointer is the sole configuration
 * authority for this callback. A null result is an explicit missing-config
 * condition that the module must handle fail closed.
 *
 * @tparam config_type Module-owned immutable configuration type.
 * @param batch Batch supplied by the runtime.
 * @return Exact borrowed configuration pointer, or nullptr when unavailable.
 */
template <typename config_type>
[[nodiscard]] KINETUM_ALWAYS_INLINE const config_type *exact_config(const kinetum_batch_t *batch) noexcept
{
	return batch != nullptr ? static_cast<const config_type *>(batch->epoch_config) : nullptr;
}

// ============================================================================
// Exact Passive Module Base
// ============================================================================

/**
 * @brief CRTP base for one passive module using the exact lifecycle ABI.
 *
 * Derived supplies explicit identity, flags, initialization, three-phase
 * configuration, packet processing, and finalization methods. Health is
 * optional; an absent method produces a null callback and unavailable health.
 * Context selection is required exactly when its capability flag is declared.
 * Descriptor construction compile-time verifies every
 * mandatory method's exact return type and non-throwing contract.
 *
 * @tparam derived_type Concrete passive module type.
 */
template <typename derived_type>
class module_base {
    public:
	/**
	 * @brief Return the immutable module descriptor.
	 *
	 * @return Immutable descriptor borrowed while this image's loader handle
	 *         remains open.
	 */
	[[nodiscard]] static const kinetum_module *descriptor() noexcept
	{
		static_assert(callback_contract_is_exact_(),
			      "module_base requires exact metadata and noexcept lifecycle/packet callbacks");
		static_assert(std::is_nothrow_destructible_v<derived_type>,
			      "module_base requires a non-throwing concrete-module destructor");
		static const kinetum_module MODULE_DESCRIPTOR{
			.module_id = derived_type::module_id(),
			.module_version = derived_type::module_version(),
			.abi_version = KINETUM_MODULE_ABI_VERSION,
			.flags = derived_type::flags(),
			.mode = KINETUM_MODULE_PASSIVE,
			.prepare_config = &module_base::prepare_config_trampoline,
			.activate_config = &module_base::activate_config_trampoline,
			.retire_config = &module_base::retire_config_trampoline,
			.process = &module_base::process_trampoline,
			.ingest = nullptr,
			.run = nullptr,
			.on_control = nullptr,
			.init = &module_base::init_trampoline,
			.fini = &module_base::fini_trampoline,
			.health_check = health_callback_(),
			.select_contexts = selection_callback_(),
		};
		return &MODULE_DESCRIPTOR;
	}

    private:
	/** Permit only the exact CRTP concrete type to construct this base. */
	friend derived_type;

	/**
	 * @brief Bind context-owned PMR storage to the exact INIT operation.
	 * @param lifecycle Non-null lifecycle shell for this context construction.
	 */
	explicit module_base(const kinetum_lifecycle_ctx *lifecycle) noexcept
		: context_memory_(lifecycle)
	{
	}

    protected:
	/**
	 * @brief Return the allocator for context-lifetime mutable state.
	 *
	 * Containers constructed from this resource may allocate only during the
	 * concrete module constructor. The trampoline seals it before publication.
	 *
	 * @return Borrowed context-lifetime memory resource.
	 */
	[[nodiscard]] std::pmr::memory_resource *context_memory_resource() noexcept
	{
		return &context_memory_;
	}

	/**
	 * @brief Resolve concrete context-local module state.
	 *
	 * @param ctx Exact live context.
	 * @return Context-owned concrete module object, or nullptr.
	 */
	[[nodiscard]] static derived_type *self(kinetum_ctx *ctx) noexcept
	{
		return ctx != nullptr ? static_cast<derived_type *>(ctx->state) : nullptr;
	}

    private:
	/**
	 * @brief Verify the generated descriptor contract at compile time.
	 *
	 * @return true only for exact noexcept metadata and callback methods.
	 */
	[[nodiscard]] static consteval bool callback_contract_is_exact_() noexcept
	{
		return requires(derived_type &module, const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
				const void *config, std::size_t config_len, kinetum_prepared_config *out_prepared,
				const kinetum_prepared_config *prepared, kinetum_batch_t *batch) {
			{ derived_type::module_id() } noexcept -> std::same_as<const char *>;
			{ derived_type::module_version() } noexcept -> std::same_as<const char *>;
			{ derived_type::flags() } noexcept -> std::same_as<uint32_t>;
			{ module.do_init(lifecycle) } noexcept -> std::same_as<kinetum_error>;
			{ module.do_fini(lifecycle) } noexcept -> std::same_as<void>;
			{
				derived_type::do_prepare_config(lifecycle, epoch, config, config_len, out_prepared)
			} noexcept -> std::same_as<kinetum_error>;
			{ module.do_activate_config(epoch, prepared) } noexcept -> std::same_as<void>;
			{
				derived_type::do_retire_config(lifecycle, epoch, *out_prepared)
			} noexcept -> std::same_as<void>;
			{ module.do_process(batch) } noexcept -> std::same_as<uint64_t>;
		} && std::is_constructible_v<derived_type, const kinetum_lifecycle_ctx *>;
	}

	/**
	 * @brief Allocate and initialize one concrete context state.
	 *
	 * @param lifecycle Borrowed INIT lifecycle context.
	 * @param out_state Output state published only after complete success.
	 * @return KINETUM_OK or an exact module/platform error.
	 */
	static kinetum_error init_trampoline(const kinetum_lifecycle_ctx *lifecycle, void **out_state) noexcept
	{
		if (lifecycle == nullptr || out_state == nullptr) {
			return KINETUM_ERR_INVALID_ARG;
		}
		*out_state = nullptr;

		void *storage = nullptr;
		constexpr uint32_t allocation_flags =
			alignof(derived_type) >= KINETUM_CACHE_LINE ?
				static_cast<uint32_t>(KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) :
				uint32_t{0};
		const auto allocation_error = kinetum_lifecycle_allocate_context(
			lifecycle, sizeof(derived_type), alignof(derived_type), allocation_flags, &storage);
		if (allocation_error != KINETUM_OK) {
			return allocation_error;
		}

		derived_type *module = nullptr;
		try {
			module = new (storage) derived_type(lifecycle);
		} catch (const std::bad_alloc &) {
			if (kinetum_lifecycle_release_context(lifecycle, storage) != KINETUM_OK) {
				std::terminate();
			}
			return KINETUM_ERR_NO_MEMORY;
		} catch (...) {
			if (kinetum_lifecycle_release_context(lifecycle, storage) != KINETUM_OK) {
				std::terminate();
			}
			return KINETUM_ERR_INTERNAL;
		}
		const auto init_error = module->do_init(lifecycle);
		if (init_error != KINETUM_OK) {
			// FINI is paired only with successful INIT. The lifecycle owner
			// rolls back tracked resources from a failed admission attempt.
			module->~derived_type();
			const auto release_error = kinetum_lifecycle_release_context(lifecycle, storage);
			return release_error == KINETUM_OK ? init_error : release_error;
		}
		module->context_memory_.seal();

		*out_state = module;
		return KINETUM_OK;
	}

	/**
	 * @brief Finalize and release detached concrete context state.
	 *
	 * @param lifecycle Borrowed FINI lifecycle context.
	 * @param state Exact state returned by successful INIT.
	 */
	static void fini_trampoline(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
	{
		if (lifecycle == nullptr || state == nullptr) {
			std::terminate();
		}
		auto *module = static_cast<derived_type *>(state);
		module->context_memory_.begin_reclamation(lifecycle);
		module->do_fini(lifecycle);
		module->~derived_type();
		if (kinetum_lifecycle_release_context(lifecycle, state) != KINETUM_OK) {
			std::terminate();
		}
	}

	::kinetum::sdk::context_memory_resource context_memory_;  ///< Exact context-lifetime PMR adapter.

	/**
	 * @brief Invoke concrete immutable configuration preparation.
	 *
	 * @param lifecycle Borrowed PREPARE lifecycle context.
	 * @param epoch Exact nonzero prepared epoch.
	 * @param config Opaque module configuration bytes.
	 * @param config_len Exact opaque byte count.
	 * @param out_prepared Output ownership record.
	 * @return KINETUM_OK or an exact module error.
	 */
	static kinetum_error prepare_config_trampoline(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
						       const void *config, size_t config_len,
						       kinetum_prepared_config *out_prepared) noexcept
	{
		if (lifecycle == nullptr || epoch == 0 || out_prepared == nullptr) {
			return KINETUM_ERR_INVALID_ARG;
		}
		*out_prepared = {};
		const auto error = derived_type::do_prepare_config(lifecycle, epoch, config, config_len, out_prepared);
		if (error != KINETUM_OK &&
		    (out_prepared->owner_handle != nullptr || out_prepared->packet_config != nullptr)) {
			std::terminate();
		}
		return error;
	}

	/**
	 * @brief Invoke bounded owner-worker activation.
	 *
	 * @param ctx Sole-owner live context.
	 * @param epoch Exact nonzero activated epoch.
	 * @param prepared Borrowed exact prepared record.
	 */
	static void activate_config_trampoline(kinetum_ctx *ctx, uint64_t epoch,
					       const kinetum_prepared_config *prepared) noexcept
	{
		auto *module = self(ctx);
		if (module == nullptr || epoch == 0 || prepared == nullptr) {
			std::terminate();
		}
		module->do_activate_config(epoch, prepared);
	}

	/**
	 * @brief Invoke exact cold retirement.
	 *
	 * @param lifecycle Borrowed RETIRE lifecycle context.
	 * @param epoch Exact nonzero retired epoch.
	 * @param retired Transferred exact ownership record.
	 */
	static void retire_config_trampoline(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
					     kinetum_prepared_config retired) noexcept
	{
		if (lifecycle == nullptr || epoch == 0) {
			std::terminate();
		}
		derived_type::do_retire_config(lifecycle, epoch, retired);
	}

	/**
	 * @brief Invoke concrete passive packet processing.
	 *
	 * @param batch Exact configured SoA batch.
	 * @return Packet forward mask.
	 */
	static uint64_t process_trampoline(kinetum_batch_t *batch) noexcept
	{
		auto *module = batch != nullptr ? self(batch->ctx) : nullptr;
		if (module == nullptr) {
			std::terminate();
		}
		return module->do_process(batch);
	}

	/**
	 * @brief Invoke optional concrete owner-worker health.
	 *
	 * @param ctx Sole-owner live context.
	 * @param active_epoch Exact active epoch.
	 * @param active_packet_config Exact immutable active configuration.
	 * @return Concrete module-owned health assessment.
	 */
	static kinetum_health_assessment health_check_trampoline(kinetum_ctx *ctx, uint64_t active_epoch,
								 const void *active_packet_config) noexcept
	{
		auto *module = self(ctx);
		if (module == nullptr) {
			std::terminate();
		}
		return module->do_health_check(active_epoch, active_packet_config);
	}

	/**
	 * @brief Resolve the explicitly declared stateless context selector.
	 * @return Exact nonthrowing selector, or null when the method is absent.
	 * Descriptor admission separately requires exact flag/callback agreement.
	 */
	[[nodiscard]] static constexpr kinetum_select_contexts_fn selection_callback_() noexcept
	{
		if constexpr (requires { &derived_type::select_contexts; }) {
			static_assert(
				requires(const kinetum_context_selection_batch *batch,
					 const kinetum_context_selection_targets *targets, uint32_t *selected) {
					{
						derived_type::select_contexts(batch, targets, selected)
					} noexcept -> std::same_as<uint64_t>;
				},
				"declared context selection requires an exact noexcept static callback");
			return &derived_type::select_contexts;
		}
		return nullptr;
	}

	/**
	 * @brief Select optional health without synthesizing a healthy signal.
	 *
	 * @return Health trampoline when the exact method exists; otherwise nullptr.
	 */
	[[nodiscard]] static constexpr kinetum_health_check_fn health_callback_() noexcept
	{
		if constexpr (requires(derived_type &module, uint64_t epoch, const void *config) {
				      {
					      module.do_health_check(epoch, config)
				      } -> std::same_as<kinetum_health_assessment>;
			      }) {
			static_assert(noexcept(std::declval<derived_type &>().do_health_check(
					      uint64_t{}, static_cast<const void *>(nullptr))),
				      "module_base health callback must be noexcept");
			return &module_base::health_check_trampoline;
		}
		return nullptr;
	}
};

/**
 * @brief Export one C++ module through the sole C descriptor symbol.
 *
 * @param module_class Concrete module_base-derived class.
 */
#define KINETUM_MODULE_REGISTER(module_class)                                                \
	extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void) \
	{                                                                                    \
		return module_class::descriptor();                                           \
	}

// ============================================================================
// Cold Utility Functions
// ============================================================================

/**
 * @brief Convert one host-order IPv4 address to canonical dotted decimal.
 *
 * @param ip IPv4 address in host byte order.
 * @return Canonical dotted-decimal text.
 */
[[nodiscard]] inline std::string ipv4_to_string(uint32_t ip)
{
	char buffer[16]{};
	const std::size_t size = ::kinetum::algo::format_ipv4(ip, buffer, sizeof(buffer));
	if (size == 0) {
		std::terminate();
	}
	return std::string(buffer, size);
}

/**
 * @brief Parse canonical dotted-decimal IPv4 text.
 *
 * @param text Exact text with no whitespace, leading zeros, or trailing data.
 * @param ip Output IPv4 address in host byte order.
 * @return true only for the canonical four-octet grammar.
 */
[[nodiscard]] constexpr bool string_to_ipv4(std::string_view text, uint32_t &ip) noexcept
{
	return ::kinetum::algo::parse_ipv4(text, &ip);
}

}  // namespace sdk
}  // namespace kinetum
