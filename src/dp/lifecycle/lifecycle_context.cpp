// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file lifecycle_context.cpp
 * @brief Backend-neutral cold lifecycle-context ownership implementation.
 * @author Fleming Patel
 */

#include "src/dp/lifecycle/lifecycle_context.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <utility>

#include "src/sdk/module_abi_text.hpp"
#include "src/common/log_record.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "src/dp/worker_telemetry_channel.hpp"

namespace kinetum::dp::lifecycle
{

using kinetum::common::status;
using kinetum::common::status_code;
using kinetum::common::status_or;

/** @brief Private borrowed state referenced by the public two-pointer ABI shell. */
struct lifecycle_borrow_state {
	lifecycle_context_owner *owner{nullptr};	///< Sole long-lived context owner.
	lifecycle_phase phase{lifecycle_phase::INIT};	///< Exact borrowed-operation phase.
	uint64_t epoch{0};				///< Exact borrowed-operation epoch.
	lifecycle_operation_control *control{nullptr};	///< Stable deadline/cancellation state.
	epoch_arena_ownership *arena{nullptr};		///< PREPARE arena, otherwise nullptr.
};

namespace
{

/**
 * @brief Check whether an integer is a valid allocation alignment.
 *
 * @param alignment Candidate byte alignment.
 * @return true for a nonzero power of two.
 */
[[nodiscard]] constexpr bool is_power_of_two(std::size_t alignment) noexcept
{
	return alignment != 0 && (alignment & (alignment - 1u)) == 0;
}

/**
 * @brief Check an actual pointer against a promised alignment.
 *
 * @param pointer Pointer returned by a memory provider.
 * @param alignment Required power-of-two alignment.
 * @return true when the pointer is nonnull and aligned.
 */
[[nodiscard]] bool pointer_is_aligned(const void *pointer, std::size_t alignment) noexcept
{
	return pointer != nullptr && (reinterpret_cast<std::uintptr_t>(pointer) & (alignment - 1u)) == 0;
}

/**
 * @brief Validate one provider block before platform ownership is published.
 *
 * @param block Provider result.
 * @param requested_numa Exact requested NUMA node.
 * @param requested_size Exact requested usable capacity.
 * @param requested_alignment Exact requested minimum alignment.
 * @return OK when every provider claim is strong enough and internally true.
 */
[[nodiscard]] status validate_provider_block(const lifecycle_memory_block &block, int32_t requested_numa,
					     std::size_t requested_size, std::size_t requested_alignment) noexcept
{
	if (!block.data || block.size != requested_size || block.numa_node != requested_numa ||
	    block.alignment < requested_alignment || !is_power_of_two(block.alignment) ||
	    !pointer_is_aligned(block.data, block.alignment)) {
		return status(
			status_code::DATA_LOSS,
			kinetum::common::static_status_text(
				"lifecycle memory provider returned storage that violates exact size, NUMA, or alignment"));
	}
	return status::ok();
}

/**
 * @brief Check the bounded telemetry-name contract.
 *
 * @param name Candidate module telemetry name.
 * @return true for nonempty printable ASCII fitting the fixed descriptor.
 */
[[nodiscard]] bool valid_telemetry_name(std::string_view name) noexcept
{
	if (name.empty() || name.size() >= LIFECYCLE_TELEMETRY_NAME_CAPACITY) {
		return false;
	}
	return std::all_of(name.begin(), name.end(), [](char character) {
		const auto value = static_cast<unsigned char>(character);
		return value >= 0x20u && value <= 0x7eu;
	});
}

/**
 * @brief Round one telemetry extent without overflowing its size domain.
 * @param value Unaligned byte count.
 * @param alignment Required nonzero power-of-two alignment.
 * @param[out] rounded Aligned result written only on success.
 * @return true when the rounded value is representable.
 */
[[nodiscard]] bool round_up_telemetry_extent(std::size_t value, std::size_t alignment, std::size_t &rounded) noexcept
{
	if (!is_power_of_two(alignment) || value > std::numeric_limits<std::size_t>::max() - (alignment - 1u)) {
		return false;
	}
	rounded = (value + alignment - 1u) & ~(alignment - 1u);
	return true;
}

/** @brief Fixed field order in one coherent module-health publication. */
enum module_health_publication_field : uint8_t {
	HEALTH_RUNTIME_GENERATION = 0u,	  ///< Exact materialized runtime generation.
	HEALTH_WORKER_INDEX,		  ///< Sole owner worker.
	HEALTH_CONTEXT_INDEX,		  ///< Exact module context.
	HEALTH_STAGE_INSTANCE_INDEX,	  ///< Exact executable stage instance.
	HEALTH_OBSERVATION_EPOCH,	  ///< Exact callback-attempt epoch.
	HEALTH_OBSERVED_AT_NS,		  ///< Cached owner-turn attempt timestamp.
	HEALTH_LATEST_FAULT_MASK,	  ///< Complete latest-attempt fault bits.
	HEALTH_FIRST_FAULT_MASK,	  ///< Immutable first-fault bits.
	HEALTH_CALLBACK_DURATION_NS,	  ///< Measured latest callback duration.
	HEALTH_CONTRACT_FAULT_COUNT,	  ///< Saturating fault population.
	HEALTH_FIRST_FAULT_EPOCH,	  ///< Immutable first-fault epoch.
	HEALTH_FIRST_FAULT_TIMESTAMP_NS,  ///< Immutable first-fault timestamp.
	HEALTH_FIRST_FAULT_DURATION_NS,	  ///< Immutable first-fault duration.
	HEALTH_SIGNAL_WORD_0,		  ///< First normalized signal word.
};

static_assert(HEALTH_SIGNAL_WORD_0 + sizeof(kinetum_health_signal) / sizeof(uint64_t) == 21u);
static_assert(sizeof(kinetum_health_signal) % sizeof(uint64_t) == 0u);
static_assert(std::is_trivially_copyable_v<kinetum_health_signal>);
static_assert(KINETUM_HEALTH_REASON_CAPACITY <= UINT8_MAX);

/** @brief Complete bounded validation result for one module assessment. */
struct health_assessment_validation {
	uint16_t faults{0};	  ///< Complete typed fault bit set.
	uint8_t reason_bytes{0};  ///< Valid reason prefix including its NUL, or zero.
};

/**
 * @brief Classify every bounded contract fault in one callback attempt.
 * @param assessment Raw module-owned result.
 * @param duration_ns Platform-measured callback duration.
 * @param callback_budget_ns Exact compiled worker budget.
 * @return Complete fault set and one validated reason-prefix extent.
 */
[[nodiscard]] health_assessment_validation validate_health_assessment(const kinetum_health_assessment &assessment,
								      uint64_t duration_ns,
								      uint64_t callback_budget_ns) noexcept
{
	health_assessment_validation validation{};
	if (assessment.health_score > 100u) {
		validation.faults |= static_cast<uint16_t>(lifecycle_module_health_fault::SCORE_OUT_OF_RANGE);
	}
	if ((assessment.flags & ~static_cast<uint32_t>(KINETUM_HEALTH_F_KNOWN_MASK)) != 0u) {
		validation.faults |= static_cast<uint16_t>(lifecycle_module_health_fault::UNKNOWN_FLAGS);
	}
	const auto *terminator =
		static_cast<const char *>(std::memchr(assessment.reason, '\0', KINETUM_HEALTH_REASON_CAPACITY));
	if (terminator == nullptr) {
		validation.faults |= static_cast<uint16_t>(lifecycle_module_health_fault::UNTERMINATED_REASON);
	} else {
		validation.reason_bytes = static_cast<uint8_t>(terminator - assessment.reason + 1);
	}
	if (duration_ns > callback_budget_ns) {
		validation.faults |= static_cast<uint16_t>(lifecycle_module_health_fault::CALLBACK_BUDGET_EXCEEDED);
	}
	return validation;
}

/**
 * @brief Verify that a suppressed signal carries no residual module bytes.
 * @param signal Candidate fixed publication payload.
 * @return true when every object byte is zero.
 */
[[nodiscard]] bool health_signal_is_zero(const kinetum_health_signal &signal) noexcept
{
	const auto *bytes = reinterpret_cast<const unsigned char *>(&signal);
	return std::all_of(bytes, bytes + sizeof(signal), [](unsigned char value) { return value == 0u; });
}

/**
 * @brief Verify semantic bounds and zeroed module-inaccessible signal bytes.
 * @param signal Candidate successful publication payload.
 * @return true only for one completely normalized platform-owned signal.
 */
[[nodiscard]] bool health_signal_is_normalized(const kinetum_health_signal &signal) noexcept
{
	if (signal.assessment.health_score > 100u ||
	    (signal.assessment.flags & ~static_cast<uint32_t>(KINETUM_HEALTH_F_KNOWN_MASK)) != 0u ||
	    std::any_of(signal.assessment._padding, signal.assessment._padding + sizeof(signal.assessment._padding),
			[](uint8_t value) { return value != 0u; })) {
		return false;
	}
	const auto *terminator =
		static_cast<const char *>(std::memchr(signal.assessment.reason, '\0', KINETUM_HEALTH_REASON_CAPACITY));
	return terminator != nullptr &&
	       std::all_of(terminator + 1, signal.assessment.reason + KINETUM_HEALTH_REASON_CAPACITY,
			   [](char value) { return value == '\0'; });
}

/** @brief Immutable private operation table and shell-recognition authority. */
extern const kinetum_lifecycle_ops LIFECYCLE_ABI_OPS;

/**
 * @brief Resolve private operation state from the exact public ABI shell.
 *
 * @param context Candidate borrowed shell.
 * @return Active state, or nullptr for an unrecognized shell.
 */
[[nodiscard]] lifecycle_borrow_state *borrow_state(const ::kinetum_lifecycle_ctx *context) noexcept
{
	if (context == nullptr || context->ops != &LIFECYCLE_ABI_OPS || context->platform_opaque == nullptr) {
		return nullptr;
	}
	auto *state = static_cast<lifecycle_borrow_state *>(context->platform_opaque);
	if (state->control == nullptr) {
		return nullptr;
	}
	return state;
}

/**
 * @brief Translate platform status into the bounded C ABI error set.
 *
 * @param value Platform status to translate.
 * @return Exact public lifecycle error classification.
 */
[[nodiscard]] kinetum_error lifecycle_error(const status &value) noexcept
{
	if (value.is_ok()) {
		return KINETUM_OK;
	}
	switch (value.code()) {
	case status_code::INVALID_ARGUMENT:
	case status_code::OUT_OF_RANGE:
		return KINETUM_ERR_INVALID_ARG;
	case status_code::NOT_FOUND:
		return KINETUM_ERR_NOT_FOUND;
	case status_code::ALREADY_EXISTS:
		return KINETUM_ERR_ALREADY_EXISTS;
	case status_code::RESOURCE_EXHAUSTED:
		// Registry cardinality is an authored resource limit. Allocation
		// owners normalize exhausted memory to POOL_EXHAUSTED below.
		return KINETUM_ERR_LIMIT_EXCEEDED;
	case status_code::POOL_EXHAUSTED:
		return KINETUM_ERR_NO_MEMORY;
	case status_code::FAILED_PRECONDITION:
	case status_code::ABORTED:
		return KINETUM_ERR_BUSY;
	case status_code::DEADLINE_EXCEEDED:
		return KINETUM_ERR_TIMEOUT;
	case status_code::CANCELLED:
		return KINETUM_ERR_CANCELLED;
	case status_code::UNIMPLEMENTED:
		return KINETUM_ERR_NOT_SUPPORTED;
	default:
		return KINETUM_ERR_INTERNAL;
	}
}

/**
 * @brief Translate an allocation result into the exact memory ABI outcome.
 *
 * @param value Platform allocation status.
 * @return KINETUM_ERR_NO_MEMORY for an exhausted authored/provider capacity;
 *         otherwise the ordinary lifecycle error classification.
 */
[[nodiscard]] kinetum_error lifecycle_allocation_error(const status &value) noexcept
{
	if (value.code() == status_code::RESOURCE_EXHAUSTED || value.code() == status_code::POOL_EXHAUSTED) {
		return KINETUM_ERR_NO_MEMORY;
	}
	return lifecycle_error(value);
}

/**
 * @brief Resolve immutable identity through one active borrowed operation.
 *
 * @param context Candidate active lifecycle shell.
 * @param out_identity Output identity written only on success.
 * @return KINETUM_OK, or KINETUM_ERR_INVALID_ARG for an inactive or malformed
 *         shell or output pointer.
 */
kinetum_error abi_get_identity(const ::kinetum_lifecycle_ctx *context,
			       kinetum_lifecycle_identity *out_identity) noexcept
{
	const auto *state = borrow_state(context);
	if (state == nullptr || state->owner == nullptr || out_identity == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	const auto &identity = state->owner->identity();
	*out_identity = {
		.module_id = identity.module_id.c_str(),
		.context_instance_id = identity.context_instance_id.c_str(),
		.module_image_index = identity.module_image_index,
		.context_index = identity.context_index,
		.worker_index = identity.worker_index,
		.cpu_core_id = identity.cpu_core_id,
		.numa_node = identity.numa_node,
		.module_context_ordinal = identity.module_context_ordinal,
		.module_context_count = identity.module_context_count,
	};
	return KINETUM_OK;
}

/**
 * @brief Allocate tracked long-lived memory through an active INIT operation.
 *
 * @param context Candidate active lifecycle shell.
 * @param size Positive allocation size.
 * @param alignment Required power-of-two alignment.
 * @param flags KINETUM_LIFECYCLE_ALLOC_* flags.
 * @param out_pointer Output pointer written only on success.
 * @return Exact bounded lifecycle ABI result.
 */
kinetum_error abi_allocate_context(const ::kinetum_lifecycle_ctx *context, std::size_t size, std::size_t alignment,
				   uint32_t flags, void **out_pointer) noexcept
{
	if (borrow_state(context) == nullptr || out_pointer == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_pointer = nullptr;
	constexpr uint32_t KNOWN_FLAGS = KINETUM_LIFECYCLE_ALLOC_ZERO | KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED;
	if ((flags & ~KNOWN_FLAGS) != 0 ||
	    ((flags & KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) != 0 && alignment < KINETUM_CACHE_LINE)) {
		return KINETUM_ERR_INVALID_ARG;
	}
	auto pointer_or =
		lifecycle_allocate_long_lived(*context, size, alignment, (flags & KINETUM_LIFECYCLE_ALLOC_ZERO) != 0);
	if (!pointer_or.is_ok()) {
		return lifecycle_allocation_error(pointer_or.error());
	}
	*out_pointer = pointer_or.value();
	return KINETUM_OK;
}

/**
 * @brief Release one exact tracked long-lived allocation.
 *
 * @param context Candidate active INIT or FINI lifecycle shell.
 * @param pointer Exact live allocation owned by the same context.
 * @return Exact bounded lifecycle ABI result.
 */
kinetum_error abi_release_context(const ::kinetum_lifecycle_ctx *context, void *pointer) noexcept
{
	if (borrow_state(context) == nullptr || pointer == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	return lifecycle_error(lifecycle_release_long_lived(*context, pointer));
}

/**
 * @brief Allocate immutable storage from the active PREPARE arena.
 *
 * @param context Candidate active PREPARE lifecycle shell.
 * @param size Positive allocation size.
 * @param alignment Required power-of-two alignment.
 * @param flags KINETUM_LIFECYCLE_ALLOC_* flags.
 * @param out_pointer Output pointer written only on success.
 * @return Exact bounded lifecycle ABI result.
 */
kinetum_error abi_allocate_epoch(const ::kinetum_lifecycle_ctx *context, std::size_t size, std::size_t alignment,
				 uint32_t flags, void **out_pointer) noexcept
{
	if (borrow_state(context) == nullptr || out_pointer == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_pointer = nullptr;
	constexpr uint32_t KNOWN_FLAGS = KINETUM_LIFECYCLE_ALLOC_ZERO | KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED;
	if ((flags & ~KNOWN_FLAGS) != 0 ||
	    ((flags & KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED) != 0 && alignment < KINETUM_CACHE_LINE)) {
		return KINETUM_ERR_INVALID_ARG;
	}
	auto pointer_or =
		lifecycle_allocate_epoch(*context, size, alignment, (flags & KINETUM_LIFECYCLE_ALLOC_ZERO) != 0);
	if (!pointer_or.is_ok()) {
		return lifecycle_allocation_error(pointer_or.error());
	}
	*out_pointer = pointer_or.value();
	return KINETUM_OK;
}

/**
 * @brief Register one bounded owner-local counter during active INIT.
 *
 * @param context Candidate active INIT lifecycle shell.
 * @param name Nonempty bounded printable-ASCII metric name.
 * @param out_counter Output handle written only on success.
 * @return Exact bounded lifecycle ABI result.
 */
kinetum_error abi_register_counter(const ::kinetum_lifecycle_ctx *context, const char *name,
				   kinetum_counter_t *out_counter) noexcept
{
	if (borrow_state(context) == nullptr || name == nullptr || out_counter == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_counter = nullptr;
	auto counter_or = lifecycle_register_counter(*context, name);
	if (!counter_or.is_ok()) {
		return lifecycle_error(counter_or.error());
	}
	*out_counter = counter_or.value();
	return KINETUM_OK;
}

/**
 * @brief Register one bounded owner-local histogram during active INIT.
 *
 * @param context Candidate active INIT lifecycle shell.
 * @param name Nonempty bounded printable-ASCII metric name.
 * @param highest_trackable_value Positive inclusive sample ceiling.
 * @param significant_digits Supported HDR precision.
 * @param out_histogram Output handle written only on success.
 * @return Exact bounded lifecycle ABI result.
 */
kinetum_error abi_register_histogram(const ::kinetum_lifecycle_ctx *context, const char *name,
				     uint64_t highest_trackable_value, int32_t significant_digits,
				     kinetum_histogram_t *out_histogram) noexcept
{
	if (borrow_state(context) == nullptr || name == nullptr || out_histogram == nullptr) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_histogram = nullptr;
	auto histogram_or = lifecycle_register_histogram(*context, name, highest_trackable_value, significant_digits);
	if (!histogram_or.is_ok()) {
		return lifecycle_error(histogram_or.error());
	}
	*out_histogram = histogram_or.value();
	return KINETUM_OK;
}

/**
 * @brief Publish one already-formatted diagnostic from an active operation.
 *
 * @param context Candidate active lifecycle shell.
 * @param level Bounded lifecycle severity.
 * @param message Borrowed NUL-terminated message.
 */
void abi_log(const ::kinetum_lifecycle_ctx *context, kinetum_lifecycle_log_level level, const char *message) noexcept
{
	if (common::reject_packet_thread_log()) {
		return;
	}
	if (borrow_state(context) == nullptr || message == nullptr) {
		return;
	}
	lifecycle_log_level mapped{};
	switch (level) {
	case KINETUM_LIFECYCLE_LOG_DEBUG:
		mapped = lifecycle_log_level::DEBUG;
		break;
	case KINETUM_LIFECYCLE_LOG_INFO:
		mapped = lifecycle_log_level::INFO;
		break;
	case KINETUM_LIFECYCLE_LOG_WARNING:
		mapped = lifecycle_log_level::WARNING;
		break;
	case KINETUM_LIFECYCLE_LOG_ERROR:
		mapped = lifecycle_log_level::ERROR;
		break;
	default:
		return;
	}
	lifecycle_log(*context, mapped, std::string_view(message, ::strnlen(message, common::LOG_MESSAGE_BYTES + 1)));
}

/**
 * @brief Resolve the active operation's absolute monotonic deadline.
 *
 * @param context Candidate active lifecycle shell.
 * @return Absolute monotonic nanoseconds, or zero for an inactive or malformed
 *         shell.
 */
uint64_t abi_deadline_ns(const ::kinetum_lifecycle_ctx *context) noexcept
{
	if (borrow_state(context) == nullptr) {
		return 0;
	}
	const auto deadline = lifecycle_deadline(*context);
	if (deadline == std::chrono::steady_clock::time_point::max()) {
		return std::numeric_limits<uint64_t>::max();
	}
	const auto duration = std::chrono::duration<long double, std::nano>(deadline.time_since_epoch());
	const long double nanoseconds = duration.count();
	if (nanoseconds <= 0.0L) {
		return 0;
	}
	if (nanoseconds >= static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
		return std::numeric_limits<uint64_t>::max();
	}
	return static_cast<uint64_t>(nanoseconds);
}

/**
 * @brief Observe cooperative cancellation for one active operation.
 *
 * @param context Candidate active lifecycle shell.
 * @return true after cancellation publication or for an inactive or malformed
 *         shell.
 */
bool abi_cancellation_requested(const ::kinetum_lifecycle_ctx *context) noexcept
{
	if (borrow_state(context) == nullptr) {
		return true;
	}
	return lifecycle_cancellation_requested(*context);
}

const kinetum_lifecycle_ops LIFECYCLE_ABI_OPS{
	.get_identity = abi_get_identity,
	.allocate_context = abi_allocate_context,
	.release_context = abi_release_context,
	.allocate_epoch = abi_allocate_epoch,
	.register_counter = abi_register_counter,
	.register_histogram = abi_register_histogram,
	.log = abi_log,
	.deadline_ns = abi_deadline_ns,
	.cancellation_requested = abi_cancellation_requested,
};

}  // namespace

lifecycle_operation_control::lifecycle_operation_control(std::chrono::steady_clock::time_point deadline) noexcept
	: deadline_(deadline)
	, deadline_bound_(deadline != std::chrono::steady_clock::time_point{})
{
}

void lifecycle_operation_control::request_cancellation() noexcept
{
	// The coordinator's release publication makes every prior operation-state
	// write visible to the lifecycle executor that acquire-observes cancellation.
	cancellation_requested_.store(true, std::memory_order_release);
}

bool lifecycle_operation_control::cancellation_requested() const noexcept
{
	// This acquire pairs with request_cancellation() and is the only cross-thread
	// observation exposed to foreign lifecycle code during one operation.
	return cancellation_requested_.load(std::memory_order_acquire);
}

std::chrono::steady_clock::time_point lifecycle_operation_control::deadline() const noexcept
{
	return deadline_;
}

bool lifecycle_operation_control::deadline_bound() const noexcept
{
	return deadline_bound_;
}

bool lifecycle_operation_control::bind_deadline_before_publication_(
	std::chrono::steady_clock::time_point deadline) noexcept
{
	if (deadline_bound_ || deadline == std::chrono::steady_clock::time_point{} ||
	    deadline == std::chrono::steady_clock::time_point::max()) {
		return false;
	}
	deadline_ = deadline;
	deadline_bound_ = true;
	return true;
}

bool lifecycle_operation_control::deadline_expired(std::chrono::steady_clock::time_point now) const noexcept
{
	return !deadline_bound_ || now >= deadline_;
}

epoch_arena_ownership::epoch_arena_ownership(lifecycle_memory_provider &provider, lifecycle_memory_block block,
					     uint32_t context_index, uint64_t epoch) noexcept
	: provider_(&provider)
	, block_(block)
	, context_index_(context_index)
	, epoch_(epoch)
{
}

epoch_arena_ownership::epoch_arena_ownership(epoch_arena_ownership &&other) noexcept
	: provider_(std::exchange(other.provider_, nullptr))
	, block_(std::exchange(other.block_, {}))
	, context_index_(std::exchange(other.context_index_, 0))
	, epoch_(std::exchange(other.epoch_, 0))
	, offset_(std::exchange(other.offset_, 0))
{
}

epoch_arena_ownership &epoch_arena_ownership::operator=(epoch_arena_ownership &&other) noexcept
{
	if (this == &other) {
		return *this;
	}
	release_();
	provider_ = std::exchange(other.provider_, nullptr);
	block_ = std::exchange(other.block_, {});
	context_index_ = std::exchange(other.context_index_, 0);
	epoch_ = std::exchange(other.epoch_, 0);
	offset_ = std::exchange(other.offset_, 0);
	return *this;
}

epoch_arena_ownership::~epoch_arena_ownership()
{
	release_();
}

status_or<epoch_arena_ownership> epoch_arena_ownership::create(lifecycle_memory_provider &provider,
							       uint32_t context_index, uint64_t epoch,
							       int32_t numa_node, std::size_t capacity,
							       std::size_t alignment)
{
	if (epoch == 0) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("epoch arena requires a nonzero exact epoch"));
	}
	if (numa_node < 0) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("epoch arena requires nonnegative NUMA ownership"));
	}
	if (capacity == 0 || !is_power_of_two(alignment)) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "epoch arena requires positive capacity and power-of-two alignment"));
	}

	auto block_or = provider.allocate(numa_node, capacity, alignment, true);
	if (!block_or.is_ok()) {
		return std::move(block_or).error();
	}
	auto block = std::move(block_or).value();
	if (const auto block_status = validate_provider_block(block, numa_node, capacity, alignment);
	    !block_status.is_ok()) {
		provider.release(block);
		return block_status;
	}
	return epoch_arena_ownership(provider, block, context_index, epoch);
}

status_or<void *> epoch_arena_ownership::allocate(std::size_t size, std::size_t alignment,
						  bool zero_initialize) noexcept
{
	if (!owns_memory()) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text("epoch arena has no owned storage"));
	}
	if (size == 0 || !is_power_of_two(alignment) || alignment > block_.alignment) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text(
				"epoch arena allocation requires positive size and supported power-of-two alignment"));
	}

	if (offset_ > block_.size) {
		return status(status_code::INTERNAL_ERROR,
			      kinetum::common::static_status_text("epoch arena offset invariant is corrupted"));
	}
	auto *const base = static_cast<std::byte *>(block_.data);
	auto *const current = base + offset_;
	const std::uintptr_t misalignment = reinterpret_cast<std::uintptr_t>(current) & (alignment - 1u);
	const std::size_t padding = misalignment == 0u ? 0u : alignment - misalignment;
	if (padding > block_.size - offset_ || size > block_.size - offset_ - padding) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text("epoch arena fixed capacity is exhausted"));
	}

	const std::size_t aligned_offset = offset_ + padding;
	void *const pointer = base + aligned_offset;
	if (zero_initialize) {
		std::memset(pointer, 0, size);
	}
	offset_ = aligned_offset + size;
	return pointer;
}

bool epoch_arena_ownership::owns_memory() const noexcept
{
	return provider_ != nullptr && block_.data != nullptr;
}

uint32_t epoch_arena_ownership::context_index() const noexcept
{
	return context_index_;
}

uint64_t epoch_arena_ownership::epoch() const noexcept
{
	return epoch_;
}

int32_t epoch_arena_ownership::numa_node() const noexcept
{
	return block_.numa_node;
}

std::size_t epoch_arena_ownership::capacity() const noexcept
{
	return block_.size;
}

std::size_t epoch_arena_ownership::bytes_used() const noexcept
{
	return offset_;
}

void epoch_arena_ownership::release_() noexcept
{
	if (provider_ && block_.data) {
		provider_->release(block_);
	}
	provider_ = nullptr;
	block_ = {};
	context_index_ = 0;
	epoch_ = 0;
	offset_ = 0;
}

lifecycle_context_operation::lifecycle_context_operation(lifecycle_context_owner &owner) noexcept
	: owner_(&owner)
{
}

lifecycle_context_operation::lifecycle_context_operation(lifecycle_context_operation &&other) noexcept
	: owner_(std::exchange(other.owner_, nullptr))
{
}

lifecycle_context_operation::~lifecycle_context_operation()
{
	release();
}

const ::kinetum_lifecycle_ctx &lifecycle_context_operation::context() const noexcept
{
	if (!owner_) {
		std::terminate();
	}
	return owner_->borrowed_context_;
}

void lifecycle_context_operation::release() noexcept
{
	if (owner_) {
		owner_->end_operation_();
		owner_ = nullptr;
	}
}

lifecycle_context_owner::lifecycle_context_owner(lifecycle_context_identity &&identity,
						 std::size_t context_memory_capacity_bytes,
						 std::size_t epoch_arena_capacity_bytes,
						 lifecycle_memory_provider &memory_provider,
						 lifecycle_log_provider &log_provider,
						 lifecycle_memory_block telemetry_storage_block,
						 telemetry_storage *telemetry_storage_pointer)
	: identity_(std::move(identity))
	, context_memory_capacity_bytes_(context_memory_capacity_bytes)
	, epoch_arena_capacity_bytes_(epoch_arena_capacity_bytes)
	, memory_provider_(memory_provider)
	, log_provider_(log_provider)
	, borrowed_state_(std::make_unique<lifecycle_borrow_state>())
	, telemetry_storage_block_(telemetry_storage_block)
	, telemetry_storage_(telemetry_storage_pointer)
{
	if (telemetry_storage_ == nullptr ||
	    !validate_provider_block(telemetry_storage_block_, identity_.numa_node,
				     sizeof(lifecycle_context_owner::telemetry_storage),
				     alignof(lifecycle_context_owner::telemetry_storage))
		     .is_ok()) {
		std::terminate();
	}
	borrowed_state_->owner = this;
	borrowed_context_.ops = &LIFECYCLE_ABI_OPS;
	borrowed_context_.platform_opaque = borrowed_state_.get();
}

status_or<std::unique_ptr<lifecycle_context_owner>>
lifecycle_context_owner::create(lifecycle_context_identity &&identity, std::size_t context_memory_capacity_bytes,
				std::size_t epoch_arena_capacity_bytes, lifecycle_memory_provider &memory_provider,
				lifecycle_log_provider &log_provider)
{
	if (!kinetum::sdk::valid_module_abi_text(identity.module_id) ||
	    !kinetum::sdk::valid_module_abi_text(identity.context_instance_id)) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text(
				"lifecycle context requires bounded printable-ASCII module and context identity"));
	}
	if (identity.cpu_core_id < 0 || identity.numa_node < 0) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "lifecycle context requires nonnegative CPU and NUMA ownership"));
	}
	if (identity.module_context_count == 0u || identity.module_context_ordinal >= identity.module_context_count) {
		return status::invalid_argument(
			"lifecycle context requires an exact module-scoped ordinal and population");
	}
	if (context_memory_capacity_bytes == 0u || epoch_arena_capacity_bytes == 0u) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "lifecycle context requires nonzero context and epoch memory capacities"));
	}
	static_assert(std::is_nothrow_move_constructible_v<lifecycle_context_identity>);
	auto telemetry_block_or = memory_provider.allocate(identity.numa_node, sizeof(telemetry_storage),
							   alignof(telemetry_storage), true);
	if (!telemetry_block_or.is_ok()) {
		return telemetry_block_or.error();
	}
	auto telemetry_block = std::move(telemetry_block_or).value();
	if (const auto block_status = validate_provider_block(telemetry_block, identity.numa_node,
							      sizeof(telemetry_storage), alignof(telemetry_storage));
	    !block_status.is_ok()) {
		memory_provider.release(telemetry_block);
		return block_status;
	}
	auto *telemetry_storage =
		std::construct_at(static_cast<lifecycle_context_owner::telemetry_storage *>(telemetry_block.data));
	try {
		return std::unique_ptr<lifecycle_context_owner>(new lifecycle_context_owner(
			std::move(identity), context_memory_capacity_bytes, epoch_arena_capacity_bytes, memory_provider,
			log_provider, telemetry_block, telemetry_storage));
	} catch (const std::bad_alloc &) {
		std::destroy_at(telemetry_storage);
		memory_provider.release(telemetry_block);
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text("failed to allocate lifecycle context owner"));
	}
}

lifecycle_context_owner::~lifecycle_context_owner()
{
	if (operation_active_.load(std::memory_order_acquire)) {
		std::terminate();
	}
	if (!telemetry_empty() || telemetry_runtime_generation_ != 0u ||
	    telemetry_stage_instance_index_ != UINT16_MAX || telemetry_channel_ != nullptr) {
		std::terminate();
	}
	for (auto &record : allocations_) {
		if (record.occupied) {
			if (record.block.size > context_memory_bytes_in_use_) {
				std::terminate();
			}
			context_memory_bytes_in_use_ -= record.block.size;
			memory_provider_.release(record.block);
			record = {};
		}
	}
	for (auto &record : telemetry_allocations_) {
		if (record.occupied) {
			if (record.block.size > context_memory_bytes_in_use_) {
				std::terminate();
			}
			context_memory_bytes_in_use_ -= record.block.size;
			memory_provider_.release(record.block);
			record = {};
		}
	}
	if (context_memory_bytes_in_use_ != 0u) {
		std::terminate();
	}
	std::destroy_at(telemetry_storage_);
	telemetry_storage_ = nullptr;
	memory_provider_.release(telemetry_storage_block_);
	telemetry_storage_block_ = {};
}

status_or<lifecycle_context_operation> lifecycle_context_owner::begin_operation(lifecycle_phase phase, uint64_t epoch,
										lifecycle_operation_control &control,
										epoch_arena_ownership *arena) noexcept
{
	if (!control.deadline_bound()) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "lifecycle operation requires one bound monotonic deadline"));
	}
	switch (phase) {
	case lifecycle_phase::INIT:
	case lifecycle_phase::FINI:
		if (epoch != 0 || arena != nullptr) {
			return status(
				status_code::INVALID_ARGUMENT,
				kinetum::common::static_status_text(
					"INIT and FINI lifecycle operations require epoch zero and no epoch arena"));
		}
		break;
	case lifecycle_phase::PREPARE:
		if (epoch == 0 || !arena || !arena->owns_memory() ||
		    arena->context_index() != identity_.context_index || arena->epoch() != epoch ||
		    arena->numa_node() != identity_.numa_node || arena->capacity() != epoch_arena_capacity_bytes_) {
			return status(
				status_code::INVALID_ARGUMENT,
				kinetum::common::static_status_text(
					"PREPARE requires one exact context, epoch, NUMA node, and authored-capacity arena"));
		}
		break;
	case lifecycle_phase::RETIRE:
		if (epoch == 0 || arena != nullptr) {
			return status(status_code::INVALID_ARGUMENT,
				      kinetum::common::static_status_text(
					      "RETIRE requires a nonzero exact epoch and no prepare arena"));
		}
		break;
	default:
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("unsupported cold lifecycle phase"));
	}

	bool expected = false;
	if (!operation_active_.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
						       std::memory_order_acquire)) {
		return status(
			status_code::FAILED_PRECONDITION,
			kinetum::common::static_status_text("lifecycle context already owns an active cold operation"));
	}

	borrowed_state_->phase = phase;
	borrowed_state_->epoch = epoch;
	borrowed_state_->control = &control;
	borrowed_state_->arena = arena;
	return lifecycle_context_operation(*this);
}

const lifecycle_context_identity &lifecycle_context_owner::identity() const noexcept
{
	return identity_;
}

std::size_t lifecycle_context_owner::context_memory_capacity_bytes() const noexcept
{
	return context_memory_capacity_bytes_;
}

std::size_t lifecycle_context_owner::epoch_arena_capacity_bytes() const noexcept
{
	return epoch_arena_capacity_bytes_;
}

std::size_t lifecycle_context_owner::telemetry_storage_bytes() noexcept
{
	return sizeof(telemetry_storage);
}

std::size_t lifecycle_context_owner::telemetry_handle_count() const noexcept
{
	return telemetry_count_;
}

const lifecycle_telemetry_descriptor *
lifecycle_context_owner::telemetry_descriptor(lifecycle_telemetry_handle handle) const noexcept
{
	if (handle == 0 || static_cast<std::size_t>(handle) > telemetry_count_) {
		return nullptr;
	}
	return &telemetry_storage_->descriptors[static_cast<std::size_t>(handle - 1u)];
}

status lifecycle_context_owner::bind_telemetry(uint64_t runtime_generation, uint16_t stage_instance_index,
					       kinetum::dp::worker_telemetry_channel &channel,
					       bool health_callback_available) noexcept
{
	if (runtime_generation == 0u || stage_instance_index == UINT16_MAX ||
	    channel.worker_index() != identity_.worker_index || channel.returned_numa_node() != identity_.numa_node ||
	    telemetry_runtime_generation_ != 0u || telemetry_channel_ != nullptr || telemetry_active_epoch_ != 0u ||
	    telemetry_prepared_epoch_ != 0u || telemetry_aggregated_epoch_ != 0u || telemetry_old_banks_retained_ ||
	    telemetry_worker_quiesced_ || telemetry_reclaimed_transfer_.has_value() ||
	    telemetry_storage_->health_owner.callback_available != 0u ||
	    telemetry_storage_->health_owner.owner_claimed != 0u ||
	    telemetry_storage_->health_publication.completed_generation() != 0u) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"module telemetry cannot bind the requested runtime identity"));
	}
	telemetry_runtime_generation_ = runtime_generation;
	telemetry_stage_instance_index_ = stage_instance_index;
	telemetry_channel_ = &channel;
	telemetry_storage_->health_owner.callback_available = static_cast<uint8_t>(health_callback_available);
	return status::ok();
}

void lifecycle_context_owner::unbind_telemetry() noexcept
{
	if (telemetry_runtime_generation_ == 0u || telemetry_channel_ == nullptr || !telemetry_empty() ||
	    telemetry_storage_->health_owner.owner_claimed != 0u) {
		std::terminate();
	}
	telemetry_runtime_generation_ = 0u;
	telemetry_stage_instance_index_ = UINT16_MAX;
	telemetry_channel_ = nullptr;
	telemetry_storage_->health_owner.callback_available = uint8_t{0};
}

void lifecycle_context_owner::clear_telemetry_bank_(uint8_t bank_index) noexcept
{
	if (bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	reset_telemetry_bank_metadata_(bank_index);
	reset_telemetry_bank_transfer_(bank_index);
	for (std::size_t ordinal = 0u; ordinal < histogram_count_; ++ordinal) {
		auto *counts = telemetry_histogram_banks_[ordinal][bank_index];
		const uint32_t length = telemetry_histogram_lengths_[ordinal];
		if (counts == nullptr || length == 0u) {
			std::terminate();
		}
		std::fill_n(counts, length, uint64_t{0});
	}
}

void lifecycle_context_owner::reset_telemetry_bank_metadata_(uint8_t bank_index) noexcept
{
	if (bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	auto &bank = telemetry_storage_->banks[bank_index];
	bank.counter_values.fill(0u);
	bank.histograms.fill(lifecycle_histogram_bank_snapshot{});
	bank.skipped_publications = 0u;
	bank.mismatch = {};
	bank.histogram_clear_ordinal = 0u;
	bank.histogram_clear_offset = 0u;
}

void lifecycle_context_owner::reset_telemetry_bank_transfer_(uint8_t bank_index) noexcept
{
	if (bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	telemetry_storage_->banks[bank_index].transfer = {};
}

void lifecycle_context_owner::capture_telemetry_bank_(uint8_t bank_index) noexcept
{
	if (bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	auto &completed = telemetry_storage_->banks[bank_index];
	if (completed.histogram_clear_ordinal != 0u || completed.histogram_clear_offset != 0u) {
		std::terminate();
	}
	for (std::size_t index = 0u; index < telemetry_count_; ++index) {
		auto &descriptor = telemetry_storage_->descriptors[index];
		if (descriptor.kind == lifecycle_telemetry_kind::COUNTER) {
			if (descriptor.kind_ordinal >= counter_count_) {
				std::terminate();
			}
			completed.counter_values[descriptor.kind_ordinal] = descriptor.counter.value;
			continue;
		}
		if (descriptor.kind != lifecycle_telemetry_kind::HISTOGRAM ||
		    descriptor.kind_ordinal >= histogram_count_) {
			std::terminate();
		}
		const std::size_t ordinal = descriptor.kind_ordinal;
		if (descriptor.histogram.counts != telemetry_histogram_banks_[ordinal][bank_index] ||
		    descriptor.histogram.counts_len != telemetry_histogram_lengths_[ordinal] ||
		    (descriptor.histogram.total_count == 0u &&
		     (descriptor.histogram.min_value != UINT64_MAX || descriptor.histogram.max_value != 0u ||
		      descriptor.histogram.sum != 0u)) ||
		    (descriptor.histogram.total_count != 0u &&
		     (descriptor.histogram.min_value > descriptor.histogram.max_value ||
		      descriptor.histogram.max_value > descriptor.histogram.highest_trackable_value))) {
			std::terminate();
		}
		completed.histograms[descriptor.kind_ordinal] = {
			.total_count = descriptor.histogram.total_count,
			.min_value = descriptor.histogram.min_value,
			.max_value = descriptor.histogram.max_value,
			.sum = descriptor.histogram.sum,
		};
	}
	completed.mismatch = telemetry_storage_->mismatch;
}

void lifecycle_context_owner::select_histogram_bank_(uint8_t bank_index) noexcept
{
	if (bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	for (std::size_t index = 0u; index < telemetry_count_; ++index) {
		auto &descriptor = telemetry_storage_->descriptors[index];
		if (descriptor.kind == lifecycle_telemetry_kind::COUNTER) {
			continue;
		}
		if (descriptor.kind != lifecycle_telemetry_kind::HISTOGRAM ||
		    descriptor.kind_ordinal >= histogram_count_ || descriptor.histogram_counts[bank_index] == nullptr) {
			std::terminate();
		}
		descriptor.histogram.counts = descriptor.histogram_counts[bank_index];
		descriptor.histogram.total_count = 0u;
		descriptor.histogram.min_value = UINT64_MAX;
		descriptor.histogram.max_value = 0u;
		descriptor.histogram.sum = 0u;
	}
}

void lifecycle_context_owner::bind_bootstrap_telemetry(uint64_t epoch, uint64_t now_ns) noexcept
{
	if (epoch == 0u || now_ns == 0u || telemetry_runtime_generation_ == 0u || telemetry_channel_ == nullptr ||
	    telemetry_active_epoch_ != 0u || telemetry_prepared_epoch_ != 0u || telemetry_active_bank_ != UINT8_MAX ||
	    telemetry_standby_bank_ != UINT8_MAX || telemetry_reserved_bank_ != UINT8_MAX ||
	    telemetry_free_bank_ != UINT8_MAX || telemetry_aggregated_epoch_ != 0u || telemetry_old_banks_retained_ ||
	    telemetry_worker_quiesced_ || telemetry_reclaimed_transfer_.has_value()) {
		std::terminate();
	}
	for (uint8_t index = 0u; index < LIFECYCLE_TELEMETRY_BANK_COUNT; ++index) {
		auto &bank = telemetry_storage_->banks[index];
		if (bank.state != telemetry_bank_state::FREE || bank.epoch != 0u ||
		    !runtime_telemetry_bank_token_is_empty(bank.transfer)) {
			std::terminate();
		}
		clear_telemetry_bank_(index);
	}
	telemetry_active_epoch_ = epoch;
	telemetry_active_bank_ = 0u;
	telemetry_standby_bank_ = 1u;
	telemetry_free_bank_ = 2u;
	auto &active = telemetry_storage_->banks[telemetry_active_bank_];
	auto &standby = telemetry_storage_->banks[telemetry_standby_bank_];
	active.epoch = epoch;
	active.state = telemetry_bank_state::ACTIVE;
	standby.epoch = epoch;
	standby.state = telemetry_bank_state::STANDBY;
	select_histogram_bank_(telemetry_active_bank_);
}

status lifecycle_context_owner::reserve_telemetry_epoch(uint64_t from_epoch, uint64_t to_epoch) noexcept
{
	if (from_epoch == 0u || to_epoch <= from_epoch || telemetry_active_epoch_ != from_epoch ||
	    telemetry_prepared_epoch_ != 0u || telemetry_reserved_bank_ != UINT8_MAX ||
	    telemetry_free_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT || telemetry_aggregated_epoch_ != 0u ||
	    telemetry_worker_quiesced_ || telemetry_reclaimed_transfer_.has_value() ||
	    telemetry_storage_->banks[telemetry_free_bank_].state != telemetry_bank_state::FREE ||
	    telemetry_storage_->banks[telemetry_free_bank_].epoch != 0u ||
	    !runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_free_bank_].transfer)) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"module telemetry cannot reserve the requested target epoch"));
	}
	const uint8_t target = telemetry_free_bank_;
	auto &bank = telemetry_storage_->banks[target];
	bank.epoch = to_epoch;
	bank.state = telemetry_bank_state::RESERVED;
	telemetry_reserved_bank_ = target;
	telemetry_free_bank_ = UINT8_MAX;
	telemetry_prepared_epoch_ = to_epoch;
	return status::ok();
}

bool lifecycle_context_owner::telemetry_target_reserved(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	return from_epoch != 0u && to_epoch > from_epoch && telemetry_active_epoch_ == from_epoch &&
	       telemetry_prepared_epoch_ == to_epoch && !telemetry_worker_quiesced_ &&
	       !telemetry_reclaimed_transfer_.has_value() && telemetry_free_bank_ == UINT8_MAX &&
	       telemetry_reserved_bank_ < LIFECYCLE_TELEMETRY_BANK_COUNT &&
	       telemetry_storage_->banks[telemetry_reserved_bank_].state == telemetry_bank_state::RESERVED &&
	       telemetry_storage_->banks[telemetry_reserved_bank_].epoch == to_epoch &&
	       runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_reserved_bank_].transfer);
}

void lifecycle_context_owner::discard_telemetry_epoch(uint64_t to_epoch) noexcept
{
	if (to_epoch == 0u || telemetry_prepared_epoch_ != to_epoch ||
	    telemetry_reserved_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT || telemetry_free_bank_ != UINT8_MAX) {
		std::terminate();
	}
	auto &bank = telemetry_storage_->banks[telemetry_reserved_bank_];
	if (bank.state != telemetry_bank_state::RESERVED || bank.epoch != to_epoch ||
	    !runtime_telemetry_bank_token_is_empty(bank.transfer)) {
		std::terminate();
	}
	const uint8_t discarded = telemetry_reserved_bank_;
	bank.epoch = 0u;
	bank.state = telemetry_bank_state::FREE;
	telemetry_reserved_bank_ = UINT8_MAX;
	telemetry_free_bank_ = discarded;
	telemetry_prepared_epoch_ = 0u;
}

void lifecycle_context_owner::accept_returned_telemetry(const runtime_telemetry_bank_token &token) noexcept
{
	if (telemetry_channel_ == nullptr) {
		std::terminate();
	}
	if (token.runtime_generation != telemetry_runtime_generation_ || token.worker_index != identity_.worker_index ||
	    token.owner_index != identity_.context_index ||
	    token.stage_instance_index != telemetry_stage_instance_index_ ||
	    token.owner_kind != runtime_telemetry_bank_owner_kind::MODULE ||
	    token.bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT || token.companion_bank_index != UINT8_MAX ||
	    (token.reason != runtime_telemetry_publication_reason::CADENCE &&
	     token.reason != runtime_telemetry_publication_reason::RECLAIMED) ||
	    token.kind != runtime_telemetry_bank_token_kind::BANK ||
	    !runtime_telemetry_bank_token_padding_zero(token)) {
		std::terminate();
	}
	auto &bank = telemetry_storage_->banks[token.bank_index];
	if (bank.state != telemetry_bank_state::RETURNING ||
	    !runtime_telemetry_bank_tokens_equal(token, bank.transfer) ||
	    (token.reason == runtime_telemetry_publication_reason::CADENCE && token.published_at_ns == 0u) ||
	    (token.reason == runtime_telemetry_publication_reason::RECLAIMED && token.published_at_ns != 0u)) {
		std::terminate();
	}
	if (token.epoch == telemetry_active_epoch_ && telemetry_standby_bank_ == UINT8_MAX) {
		reset_telemetry_bank_metadata_(token.bank_index);
		reset_telemetry_bank_transfer_(token.bank_index);
		bank.epoch = telemetry_active_epoch_;
		bank.state = telemetry_bank_state::STANDBY;
		telemetry_standby_bank_ = token.bank_index;
		telemetry_old_banks_retained_ = false;
	} else {
		if (telemetry_channel_->completed_available() == 0u) {
			std::terminate();
		}
		bank.state = telemetry_bank_state::AGGREGATED_RETAINED;
		auto acknowledgment = token;
		acknowledgment.kind = runtime_telemetry_bank_token_kind::RETURN_RETAINED;
		if (!telemetry_channel_->publish_completed(acknowledgment)) {
			std::terminate();
		}
	}
}

bool lifecycle_context_owner::preflight_activate_telemetry(uint64_t from_epoch, uint64_t to_epoch) const noexcept
{
	return telemetry_target_reserved(from_epoch, to_epoch) && telemetry_aggregated_epoch_ == 0u &&
	       !telemetry_worker_quiesced_ && !telemetry_reclaimed_transfer_.has_value() &&
	       telemetry_active_bank_ < LIFECYCLE_TELEMETRY_BANK_COUNT &&
	       telemetry_reserved_bank_ < LIFECYCLE_TELEMETRY_BANK_COUNT &&
	       telemetry_storage_->banks[telemetry_active_bank_].state == telemetry_bank_state::ACTIVE &&
	       telemetry_storage_->banks[telemetry_active_bank_].epoch == from_epoch &&
	       runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_active_bank_].transfer) &&
	       telemetry_storage_->banks[telemetry_reserved_bank_].state == telemetry_bank_state::RESERVED &&
	       telemetry_storage_->banks[telemetry_reserved_bank_].epoch == to_epoch &&
	       runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_reserved_bank_].transfer) &&
	       (telemetry_standby_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT ||
		(telemetry_storage_->banks[telemetry_standby_bank_].state == telemetry_bank_state::STANDBY &&
		 telemetry_storage_->banks[telemetry_standby_bank_].epoch == from_epoch &&
		 runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_standby_bank_].transfer))) &&
	       telemetry_channel_->completed_available() >= 1u;
}

void lifecycle_context_owner::publish_telemetry_bank_(uint8_t bank_index, runtime_telemetry_publication_reason reason,
						      uint64_t now_ns, uint8_t companion_bank_index) noexcept
{
	if (bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT || now_ns == 0u || telemetry_channel_ == nullptr ||
	    (companion_bank_index != UINT8_MAX &&
	     (companion_bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT || companion_bank_index == bank_index)) ||
	    (reason == runtime_telemetry_publication_reason::CADENCE && companion_bank_index != UINT8_MAX) ||
	    (reason != runtime_telemetry_publication_reason::CADENCE &&
	     reason != runtime_telemetry_publication_reason::ACTIVATION &&
	     reason != runtime_telemetry_publication_reason::SHUTDOWN)) {
		std::terminate();
	}
	auto &bank = telemetry_storage_->banks[bank_index];
	if ((bank.state != telemetry_bank_state::ACTIVE && bank.state != telemetry_bank_state::STANDBY) ||
	    bank.epoch == 0u || bank.generation == UINT64_MAX ||
	    !runtime_telemetry_bank_token_is_empty(bank.transfer)) {
		std::terminate();
	}
	if (companion_bank_index != UINT8_MAX &&
	    (telemetry_storage_->banks[companion_bank_index].state != telemetry_bank_state::AGGREGATED_RETAINED ||
	     telemetry_storage_->banks[companion_bank_index].epoch != bank.epoch)) {
		std::terminate();
	}
	++bank.generation;
	bank.state = telemetry_bank_state::PUBLISHED;
	const runtime_telemetry_bank_token token{
		.runtime_generation = telemetry_runtime_generation_,
		.epoch = bank.epoch,
		.bank_generation = bank.generation,
		.published_at_ns = now_ns,
		.worker_index = identity_.worker_index,
		.owner_index = identity_.context_index,
		.stage_instance_index = telemetry_stage_instance_index_,
		.bank_index = bank_index,
		.companion_bank_index = companion_bank_index,
		.owner_kind = runtime_telemetry_bank_owner_kind::MODULE,
		.reason = reason,
		.kind = runtime_telemetry_bank_token_kind::BANK,
		.padding = {},
	};
	bank.transfer = token;
	if (!telemetry_channel_->publish_completed(token)) {
		std::terminate();
	}
}

void lifecycle_context_owner::activate_telemetry_epoch(uint64_t from_epoch, uint64_t to_epoch, uint64_t now_ns) noexcept
{
	if (now_ns == 0u || !preflight_activate_telemetry(from_epoch, to_epoch)) {
		std::terminate();
	}
	const uint8_t old_active = telemetry_active_bank_;
	const uint8_t old_standby = telemetry_standby_bank_;
	capture_telemetry_bank_(old_active);
	if (old_standby < LIFECYCLE_TELEMETRY_BANK_COUNT) {
		auto &standby = telemetry_storage_->banks[old_standby];
		if (standby.state != telemetry_bank_state::STANDBY || standby.epoch != from_epoch) {
			std::terminate();
		}
		standby.state = telemetry_bank_state::AGGREGATED_RETAINED;
	}
	publish_telemetry_bank_(old_active, runtime_telemetry_publication_reason::ACTIVATION, now_ns, old_standby);
	telemetry_active_bank_ = telemetry_reserved_bank_;
	telemetry_reserved_bank_ = UINT8_MAX;
	telemetry_standby_bank_ = UINT8_MAX;
	telemetry_old_banks_retained_ = true;
	telemetry_prepared_epoch_ = 0u;
	telemetry_active_epoch_ = to_epoch;
	telemetry_storage_->banks[telemetry_active_bank_].state = telemetry_bank_state::ACTIVE;
	select_histogram_bank_(telemetry_active_bank_);
}

runtime_telemetry_return_need lifecycle_context_owner::service_telemetry_cadence(uint64_t now_ns) noexcept
{
	if (now_ns == 0u || telemetry_active_epoch_ == 0u || telemetry_active_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT ||
	    telemetry_worker_quiesced_ ||
	    telemetry_storage_->banks[telemetry_active_bank_].state != telemetry_bank_state::ACTIVE ||
	    telemetry_storage_->banks[telemetry_active_bank_].epoch != telemetry_active_epoch_ ||
	    !runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_active_bank_].transfer)) {
		std::terminate();
	}
	if (telemetry_standby_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		auto &active = telemetry_storage_->banks[telemetry_active_bank_];
		if (active.skipped_publications != UINT64_MAX) {
			++active.skipped_publications;
		}
		return runtime_telemetry_return_need::POLL_REQUIRED;
	}
	if (telemetry_storage_->banks[telemetry_standby_bank_].state != telemetry_bank_state::STANDBY ||
	    telemetry_storage_->banks[telemetry_standby_bank_].epoch != telemetry_active_epoch_ ||
	    !runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_standby_bank_].transfer)) {
		std::terminate();
	}
	if (telemetry_channel_->completed_available() == 0u) {
		auto &active = telemetry_storage_->banks[telemetry_active_bank_];
		if (active.skipped_publications != UINT64_MAX) {
			++active.skipped_publications;
		}
		return runtime_telemetry_return_need::POLL_REQUIRED;
	}
	const uint8_t completed_index = telemetry_active_bank_;
	const uint8_t next_index = telemetry_standby_bank_;
	capture_telemetry_bank_(completed_index);
	telemetry_active_bank_ = next_index;
	telemetry_standby_bank_ = UINT8_MAX;
	select_histogram_bank_(telemetry_active_bank_);
	publish_telemetry_bank_(completed_index, runtime_telemetry_publication_reason::CADENCE, now_ns);
	telemetry_storage_->banks[telemetry_active_bank_].state = telemetry_bank_state::ACTIVE;
	return runtime_telemetry_return_need::EXPECTED;
}

bool lifecycle_context_owner::preflight_publish_shutdown_telemetry(uint64_t epoch) const noexcept
{
	if (epoch == 0u || epoch != telemetry_active_epoch_ || telemetry_prepared_epoch_ != 0u ||
	    telemetry_active_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT || telemetry_reserved_bank_ != UINT8_MAX ||
	    telemetry_channel_ == nullptr ||
	    telemetry_storage_->banks[telemetry_active_bank_].state != telemetry_bank_state::ACTIVE ||
	    telemetry_storage_->banks[telemetry_active_bank_].epoch != epoch ||
	    !runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_active_bank_].transfer) ||
	    telemetry_worker_quiesced_ || telemetry_reclaimed_transfer_.has_value() ||
	    telemetry_channel_->completed_available() == 0u) {
		return false;
	}
	if (telemetry_standby_bank_ < LIFECYCLE_TELEMETRY_BANK_COUNT) {
		const auto &standby = telemetry_storage_->banks[telemetry_standby_bank_];
		if (telemetry_free_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
			return false;
		}
		const auto &free = telemetry_storage_->banks[telemetry_free_bank_];
		return free.state == telemetry_bank_state::FREE && free.epoch == 0u &&
		       runtime_telemetry_bank_token_is_empty(free.transfer) &&
		       standby.state == telemetry_bank_state::STANDBY && standby.epoch == epoch &&
		       runtime_telemetry_bank_token_is_empty(standby.transfer);
	}
	return telemetry_free_bank_ == UINT8_MAX && telemetry_old_banks_retained_;
}

void lifecycle_context_owner::publish_shutdown_telemetry(uint64_t epoch, uint64_t now_ns) noexcept
{
	if (now_ns == 0u || !preflight_publish_shutdown_telemetry(epoch)) {
		std::terminate();
	}
	const uint8_t completed = telemetry_active_bank_;
	const uint8_t companion = telemetry_standby_bank_;
	capture_telemetry_bank_(completed);
	if (telemetry_standby_bank_ < LIFECYCLE_TELEMETRY_BANK_COUNT) {
		auto &standby = telemetry_storage_->banks[telemetry_standby_bank_];
		standby.state = telemetry_bank_state::AGGREGATED_RETAINED;
	}
	publish_telemetry_bank_(completed, runtime_telemetry_publication_reason::SHUTDOWN, now_ns, companion);
	telemetry_active_bank_ = UINT8_MAX;
	telemetry_standby_bank_ = UINT8_MAX;
	telemetry_active_epoch_ = 0u;
	telemetry_old_banks_retained_ = false;
}

void lifecycle_context_owner::record_telemetry_mismatch(const lifecycle_telemetry_mismatch_snapshot &mismatch) noexcept
{
	if (telemetry_active_epoch_ == 0u || telemetry_active_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT ||
	    mismatch.context_index != identity_.context_index || mismatch.worker_index != identity_.worker_index ||
	    mismatch.stage_instance_index != telemetry_stage_instance_index_ || mismatch.reserved != 0u ||
	    mismatch.first_fault_valid != 1u || mismatch.sticky_fault != 1u || mismatch.mismatch_count == 0u ||
	    mismatch.packet_epoch == 0u ||
	    !std::all_of(std::begin(mismatch.padding), std::end(mismatch.padding),
			 [](uint8_t byte) { return byte == 0u; }) ||
	    mismatch.mismatch_count < telemetry_storage_->mismatch.mismatch_count) {
		std::terminate();
	}
	if (telemetry_storage_->mismatch.first_fault_valid == 0u) {
		if (mismatch.active_epoch != telemetry_active_epoch_) {
			std::terminate();
		}
	} else if ((telemetry_storage_->mismatch.packet_epoch != mismatch.packet_epoch ||
		    telemetry_storage_->mismatch.active_epoch != mismatch.active_epoch ||
		    telemetry_storage_->mismatch.context_index != mismatch.context_index ||
		    telemetry_storage_->mismatch.worker_index != mismatch.worker_index ||
		    telemetry_storage_->mismatch.stage_instance_index != mismatch.stage_instance_index ||
		    telemetry_storage_->mismatch.region_id != mismatch.region_id)) {
		std::terminate();
	}
	telemetry_storage_->mismatch = mismatch;
}

void lifecycle_context_owner::publish_module_health_attempt(const kinetum_health_assessment &assessment,
							    lifecycle_module_health_attempt attempt) noexcept
{
	if (telemetry_runtime_generation_ == 0u || telemetry_stage_instance_index_ == UINT16_MAX ||
	    telemetry_channel_ == nullptr || telemetry_active_epoch_ != attempt.epoch || attempt.epoch == 0u ||
	    attempt.timestamp_ns == 0u || attempt.callback_budget_ns == 0u ||
	    telemetry_storage_->health_owner.callback_available != 1u ||
	    telemetry_storage_->health_owner.owner_claimed != 1u) {
		std::terminate();
	}
	const auto validation = validate_health_assessment(assessment, attempt.duration_ns, attempt.callback_budget_ns);
	const uint16_t faults = validation.faults;
	auto &health = telemetry_storage_->health_owner;
	if (faults != 0u) {
		if (health.contract_fault_count != UINT64_MAX) {
			++health.contract_fault_count;
		}
		if (health.first_fault_mask == 0u) {
			health.first_fault_mask = faults;
			health.first_fault_epoch = attempt.epoch;
			health.first_fault_timestamp_ns = attempt.timestamp_ns;
			health.first_fault_duration_ns = attempt.duration_ns;
		}
	}

	kinetum_health_signal signal{};
	if (faults == 0u) {
		if (validation.reason_bytes == 0u) {
			std::terminate();
		}
		signal.assessment.health_score = assessment.health_score;
		signal.assessment.flags = assessment.flags;
		std::memcpy(signal.assessment.reason, assessment.reason, validation.reason_bytes);
		signal.epoch = attempt.epoch;
		signal.timestamp_ns = attempt.timestamp_ns;
	}

	std::array<uint64_t, MODULE_HEALTH_PUBLICATION_FIELD_COUNT> fields{};
	fields[HEALTH_RUNTIME_GENERATION] = telemetry_runtime_generation_;
	fields[HEALTH_WORKER_INDEX] = identity_.worker_index;
	fields[HEALTH_CONTEXT_INDEX] = identity_.context_index;
	fields[HEALTH_STAGE_INSTANCE_INDEX] = telemetry_stage_instance_index_;
	fields[HEALTH_OBSERVATION_EPOCH] = attempt.epoch;
	fields[HEALTH_OBSERVED_AT_NS] = attempt.timestamp_ns;
	fields[HEALTH_LATEST_FAULT_MASK] = faults;
	fields[HEALTH_FIRST_FAULT_MASK] = health.first_fault_mask;
	fields[HEALTH_CALLBACK_DURATION_NS] = attempt.duration_ns;
	fields[HEALTH_CONTRACT_FAULT_COUNT] = health.contract_fault_count;
	fields[HEALTH_FIRST_FAULT_EPOCH] = health.first_fault_epoch;
	fields[HEALTH_FIRST_FAULT_TIMESTAMP_NS] = health.first_fault_timestamp_ns;
	fields[HEALTH_FIRST_FAULT_DURATION_NS] = health.first_fault_duration_ns;
	std::memcpy(fields.data() + HEALTH_SIGNAL_WORD_0, &signal, sizeof(signal));
	if (!telemetry_storage_->health_publication.publish(fields)) {
		std::terminate();
	}
}

bool lifecycle_context_owner::try_read_module_health(lifecycle_module_health_observation &out) const noexcept
{
	module_health_snapshot::snapshot observed{};
	if (!telemetry_storage_->health_publication.try_read(observed, MODULE_HEALTH_OBSERVATION_ATTEMPTS)) {
		return false;
	}
	if (observed.fields[HEALTH_WORKER_INDEX] > UINT32_MAX || observed.fields[HEALTH_CONTEXT_INDEX] > UINT32_MAX ||
	    observed.fields[HEALTH_STAGE_INSTANCE_INDEX] > UINT16_MAX ||
	    observed.fields[HEALTH_LATEST_FAULT_MASK] > UINT16_MAX ||
	    observed.fields[HEALTH_FIRST_FAULT_MASK] > UINT16_MAX) {
		std::terminate();
	}
	lifecycle_module_health_observation result{
		.publication_generation = observed.generation,
		.runtime_generation = observed.fields[HEALTH_RUNTIME_GENERATION],
		.observation_epoch = observed.fields[HEALTH_OBSERVATION_EPOCH],
		.observed_at_ns = observed.fields[HEALTH_OBSERVED_AT_NS],
		.callback_duration_ns = observed.fields[HEALTH_CALLBACK_DURATION_NS],
		.contract_fault_count = observed.fields[HEALTH_CONTRACT_FAULT_COUNT],
		.first_fault_epoch = observed.fields[HEALTH_FIRST_FAULT_EPOCH],
		.first_fault_timestamp_ns = observed.fields[HEALTH_FIRST_FAULT_TIMESTAMP_NS],
		.first_fault_duration_ns = observed.fields[HEALTH_FIRST_FAULT_DURATION_NS],
		.worker_index = static_cast<uint32_t>(observed.fields[HEALTH_WORKER_INDEX]),
		.context_index = static_cast<uint32_t>(observed.fields[HEALTH_CONTEXT_INDEX]),
		.stage_instance_index = static_cast<uint16_t>(observed.fields[HEALTH_STAGE_INSTANCE_INDEX]),
		.latest_fault_mask = static_cast<uint16_t>(observed.fields[HEALTH_LATEST_FAULT_MASK]),
		.first_fault_mask = static_cast<uint16_t>(observed.fields[HEALTH_FIRST_FAULT_MASK]),
		.callback_available = uint8_t{1},
		.signal_available = static_cast<uint8_t>(observed.fields[HEALTH_LATEST_FAULT_MASK] == 0u),
		.signal = {},
	};
	std::memcpy(&result.signal, observed.fields.data() + HEALTH_SIGNAL_WORD_0, sizeof(result.signal));
	const bool first_fault_absent = result.first_fault_mask == 0u && result.contract_fault_count == 0u &&
					result.first_fault_epoch == 0u && result.first_fault_timestamp_ns == 0u &&
					result.first_fault_duration_ns == 0u;
	const bool first_fault_present = result.first_fault_mask != 0u && result.contract_fault_count != 0u &&
					 result.first_fault_epoch != 0u && result.first_fault_timestamp_ns != 0u;
	const bool valid_signal = result.signal_available == 1u && result.latest_fault_mask == 0u &&
				  result.signal.epoch == result.observation_epoch &&
				  result.signal.timestamp_ns == result.observed_at_ns &&
				  health_signal_is_normalized(result.signal);
	const bool suppressed_signal = result.signal_available == 0u && result.latest_fault_mask != 0u &&
				       health_signal_is_zero(result.signal);
	if (result.runtime_generation != telemetry_runtime_generation_ ||
	    result.worker_index != identity_.worker_index || result.context_index != identity_.context_index ||
	    result.stage_instance_index != telemetry_stage_instance_index_ || result.observation_epoch == 0u ||
	    result.observed_at_ns == 0u ||
	    (result.latest_fault_mask & ~LIFECYCLE_MODULE_HEALTH_FAULT_KNOWN_MASK) != 0u ||
	    (result.first_fault_mask & ~LIFECYCLE_MODULE_HEALTH_FAULT_KNOWN_MASK) != 0u ||
	    (result.latest_fault_mask != 0u && result.contract_fault_count == 0u) ||
	    (first_fault_present && (result.first_fault_epoch > result.observation_epoch ||
				     result.first_fault_timestamp_ns > result.observed_at_ns)) ||
	    (!first_fault_absent && !first_fault_present) || (!valid_signal && !suppressed_signal)) {
		std::terminate();
	}
	out = result;
	return true;
}

bool lifecycle_context_owner::health_callback_available() const noexcept
{
	return telemetry_storage_->health_owner.callback_available == 1u;
}

status lifecycle_context_owner::claim_module_health_owner(uint64_t runtime_generation,
							  uint16_t stage_instance_index) noexcept
{
	if (runtime_generation == 0u || runtime_generation != telemetry_runtime_generation_ ||
	    stage_instance_index == UINT16_MAX || stage_instance_index != telemetry_stage_instance_index_ ||
	    telemetry_channel_ == nullptr || telemetry_storage_->health_owner.callback_available > 1u ||
	    telemetry_storage_->health_owner.owner_claimed != 0u || telemetry_active_epoch_ != 0u ||
	    telemetry_prepared_epoch_ != 0u || telemetry_aggregated_epoch_ != 0u || telemetry_old_banks_retained_ ||
	    telemetry_worker_quiesced_ || telemetry_reclaimed_transfer_.has_value() || !telemetry_empty() ||
	    telemetry_storage_->health_publication.completed_generation() != 0u) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"module health owner claim does not match exact telemetry identity"));
	}
	telemetry_storage_->health_owner.owner_claimed = uint8_t{1};
	return status::ok();
}

void lifecycle_context_owner::release_module_health_owner() noexcept
{
	if (telemetry_runtime_generation_ == 0u || telemetry_channel_ == nullptr ||
	    telemetry_storage_->health_owner.owner_claimed != 1u) {
		std::terminate();
	}
	telemetry_storage_->health_owner.owner_claimed = uint8_t{0};
}

bool lifecycle_context_owner::module_health_owner_claimed() const noexcept
{
	return telemetry_storage_->health_owner.owner_claimed == 1u;
}

void lifecycle_context_owner::restore_shutdown_telemetry(uint64_t epoch) noexcept
{
	if (epoch == 0u || telemetry_active_epoch_ != 0u || telemetry_prepared_epoch_ != 0u ||
	    telemetry_active_bank_ != UINT8_MAX || telemetry_standby_bank_ != UINT8_MAX ||
	    telemetry_reserved_bank_ != UINT8_MAX || telemetry_aggregated_epoch_ != epoch ||
	    telemetry_reclaimed_transfer_.has_value() || telemetry_free_bank_ >= LIFECYCLE_TELEMETRY_BANK_COUNT ||
	    telemetry_storage_->banks[telemetry_free_bank_].state != telemetry_bank_state::FREE ||
	    telemetry_storage_->banks[telemetry_free_bank_].epoch != 0u ||
	    !runtime_telemetry_bank_token_is_empty(telemetry_storage_->banks[telemetry_free_bank_].transfer)) {
		std::terminate();
	}
	uint8_t active = UINT8_MAX;
	uint8_t standby = UINT8_MAX;
	for (uint8_t index = 0u; index < LIFECYCLE_TELEMETRY_BANK_COUNT; ++index) {
		auto &bank = telemetry_storage_->banks[index];
		if (bank.epoch != epoch) {
			continue;
		}
		if (bank.state != telemetry_bank_state::AGGREGATED_RETAINED) {
			std::terminate();
		}
		if (active == UINT8_MAX) {
			active = index;
		} else if (standby == UINT8_MAX) {
			standby = index;
		} else {
			std::terminate();
		}
	}
	if (active == UINT8_MAX || standby == UINT8_MAX) {
		std::terminate();
	}
	if (telemetry_worker_quiesced_) {
		return;
	}
	reset_telemetry_bank_metadata_(active);
	reset_telemetry_bank_metadata_(standby);
	reset_telemetry_bank_transfer_(active);
	reset_telemetry_bank_transfer_(standby);
	telemetry_storage_->banks[active].state = telemetry_bank_state::ACTIVE;
	telemetry_storage_->banks[standby].state = telemetry_bank_state::STANDBY;
	telemetry_active_epoch_ = epoch;
	telemetry_active_bank_ = active;
	telemetry_standby_bank_ = standby;
	telemetry_old_banks_retained_ = false;
	telemetry_aggregated_epoch_ = 0u;
	select_histogram_bank_(active);
}

bool lifecycle_context_owner::telemetry_token_matches_(const runtime_telemetry_bank_token &token,
						       const telemetry_bank &bank) const noexcept
{
	return token.runtime_generation == telemetry_runtime_generation_ &&
	       token.worker_index == identity_.worker_index && token.owner_index == identity_.context_index &&
	       token.stage_instance_index == telemetry_stage_instance_index_ &&
	       token.owner_kind == runtime_telemetry_bank_owner_kind::MODULE &&
	       token.bank_index < LIFECYCLE_TELEMETRY_BANK_COUNT && token.epoch == bank.epoch &&
	       token.bank_generation == bank.generation && token.published_at_ns != 0u &&
	       token.kind == runtime_telemetry_bank_token_kind::BANK &&
	       runtime_telemetry_bank_token_padding_zero(token) &&
	       runtime_telemetry_bank_tokens_equal(token, bank.transfer);
}

status_or<lifecycle_module_telemetry_bank_view>
lifecycle_context_owner::completed_telemetry_bank(const runtime_telemetry_bank_token &token) const noexcept
{
	if (token.bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		return status::invalid_argument(
			kinetum::common::static_status_text("module telemetry token bank index is invalid"));
	}
	const auto &bank = telemetry_storage_->banks[token.bank_index];
	if (bank.state != telemetry_bank_state::PUBLISHED || !telemetry_token_matches_(token, bank)) {
		return status::failed_precondition(
			kinetum::common::static_status_text("module telemetry token does not own its exact bank"));
	}
	return lifecycle_module_telemetry_bank_view{
		.counter_values = std::span<const uint64_t>(bank.counter_values.data(), counter_count_),
		.histograms =
			std::span<const lifecycle_histogram_bank_snapshot>(bank.histograms.data(), histogram_count_),
		.bank_index = token.bank_index,
		.skipped_publications = bank.skipped_publications,
		.mismatch = bank.mismatch,
	};
}

status_or<std::span<const uint64_t>>
lifecycle_context_owner::completed_telemetry_histogram(const runtime_telemetry_bank_token &token,
						       uint32_t histogram_ordinal) const noexcept
{
	if (!completed_telemetry_bank(token).is_ok()) {
		return status::failed_precondition(kinetum::common::static_status_text(
			"module telemetry histogram lacks exact completed-bank ownership"));
	}
	if (histogram_ordinal >= histogram_count_ || token.bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		return status::invalid_argument(kinetum::common::static_status_text(
			"module telemetry histogram ordinal is outside the registered prefix"));
	}
	const auto *counts = telemetry_histogram_banks_[histogram_ordinal][token.bank_index];
	const uint32_t length = telemetry_histogram_lengths_[histogram_ordinal];
	if (counts == nullptr || length == 0u) {
		return status::internal_error(kinetum::common::static_status_text(
			"module telemetry histogram bucket projection is incomplete"));
	}
	return std::span<const uint64_t>(counts, length);
}

bool lifecycle_context_owner::clear_completed_telemetry_histogram_prefix(const runtime_telemetry_bank_token &token,
									 uint32_t histogram_ordinal, std::size_t begin,
									 std::size_t count) noexcept
{
	if (count == 0u || count > LIFECYCLE_TELEMETRY_BUCKET_PREFIX || !completed_telemetry_bank(token).is_ok() ||
	    histogram_ordinal >= histogram_count_ || token.bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT) {
		std::terminate();
	}
	auto &bank = telemetry_storage_->banks[token.bank_index];
	const uint32_t length = telemetry_histogram_lengths_[histogram_ordinal];
	auto *counts = telemetry_histogram_banks_[histogram_ordinal][token.bank_index];
	if (bank.histogram_clear_ordinal != histogram_ordinal || bank.histogram_clear_offset != begin ||
	    counts == nullptr || length == 0u || begin >= length || count > static_cast<std::size_t>(length) - begin) {
		std::terminate();
	}
	std::fill_n(counts + begin, count, uint64_t{0});
	const std::size_t next = begin + count;
	if (next == length) {
		bank.histogram_clear_ordinal = histogram_ordinal + 1u;
		bank.histogram_clear_offset = 0u;
	} else {
		bank.histogram_clear_offset = static_cast<uint32_t>(next);
	}
	return bank.histogram_clear_ordinal == histogram_count_ && bank.histogram_clear_offset == 0u;
}

void lifecycle_context_owner::complete_telemetry_aggregation(const runtime_telemetry_bank_token &token) noexcept
{
	if (token.bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT || !completed_telemetry_bank(token).is_ok()) {
		std::terminate();
	}
	auto &bank = telemetry_storage_->banks[token.bank_index];
	if (bank.histogram_clear_ordinal != histogram_count_ || bank.histogram_clear_offset != 0u) {
		std::terminate();
	}
	reset_telemetry_bank_metadata_(token.bank_index);
	if (token.reason == runtime_telemetry_publication_reason::CADENCE) {
		bank.state = telemetry_bank_state::RETURNING;
		if (!telemetry_channel_->return_cleared(token)) {
			std::terminate();
		}
	} else {
		bank.state = telemetry_bank_state::AGGREGATED_RETAINED;
	}
}

bool lifecycle_context_owner::telemetry_epoch_aggregated(uint64_t epoch) const noexcept
{
	return epoch != 0u && telemetry_aggregated_epoch_ == epoch;
}

void lifecycle_context_owner::mark_telemetry_epoch_aggregated(uint64_t epoch) noexcept
{
	if (epoch == 0u || telemetry_aggregated_epoch_ != 0u || telemetry_reclaimed_transfer_.has_value()) {
		std::terminate();
	}
	std::size_t retained = 0u;
	for (const auto &bank : telemetry_storage_->banks) {
		if (bank.epoch != epoch) {
			continue;
		}
		if (bank.state != telemetry_bank_state::AGGREGATED_RETAINED) {
			std::terminate();
		}
		++retained;
	}
	if (retained != 2u) {
		std::terminate();
	}
	telemetry_aggregated_epoch_ = epoch;
}

void lifecycle_context_owner::mark_telemetry_worker_quiesced() noexcept
{
	if (telemetry_worker_quiesced_ || telemetry_active_epoch_ != 0u || telemetry_active_bank_ != UINT8_MAX ||
	    telemetry_standby_bank_ != UINT8_MAX || telemetry_prepared_epoch_ != 0u ||
	    telemetry_reserved_bank_ != UINT8_MAX || telemetry_old_banks_retained_ ||
	    telemetry_reclaimed_transfer_.has_value()) {
		std::terminate();
	}
	telemetry_worker_quiesced_ = true;
}

void lifecycle_context_owner::retire_telemetry_epoch(uint64_t epoch, uint64_t active_epoch) noexcept
{
	if (!telemetry_epoch_aggregated(epoch) || telemetry_reclaimed_transfer_.has_value() ||
	    (active_epoch != 0u && telemetry_free_bank_ != UINT8_MAX) ||
	    (active_epoch != 0u && !telemetry_worker_quiesced_ && active_epoch != telemetry_active_epoch_)) {
		std::terminate();
	}
	uint8_t return_index = UINT8_MAX;
	std::size_t retired_bank_count = 0u;
	std::size_t successor_bank_count = 0u;
	std::size_t free_bank_count = 0u;
	for (uint8_t index = 0u; index < LIFECYCLE_TELEMETRY_BANK_COUNT; ++index) {
		const auto &bank = telemetry_storage_->banks[index];
		if (bank.epoch != epoch) {
			if (active_epoch == 0u && index == telemetry_free_bank_ && bank.epoch == 0u &&
			    bank.state == telemetry_bank_state::FREE &&
			    runtime_telemetry_bank_token_is_empty(bank.transfer)) {
				++free_bank_count;
			}
			if (active_epoch != 0u && bank.epoch == active_epoch &&
			    bank.state == (telemetry_worker_quiesced_ ? telemetry_bank_state::AGGREGATED_RETAINED :
									telemetry_bank_state::ACTIVE) &&
			    (telemetry_worker_quiesced_ || index == telemetry_active_bank_) &&
			    (telemetry_worker_quiesced_ ? !runtime_telemetry_bank_token_is_empty(bank.transfer) :
							  runtime_telemetry_bank_token_is_empty(bank.transfer))) {
				++successor_bank_count;
			}
			continue;
		}
		if (bank.state != telemetry_bank_state::AGGREGATED_RETAINED) {
			std::terminate();
		}
		++retired_bank_count;
		if (active_epoch != 0u && return_index == UINT8_MAX && bank.generation != 0u) {
			return_index = index;
		}
	}
	if (retired_bank_count != 2u || (active_epoch == 0u && free_bank_count != 1u) ||
	    (active_epoch != 0u && (return_index == UINT8_MAX || successor_bank_count != 1u))) {
		std::terminate();
	}
	uint8_t returned = UINT8_MAX;
	uint8_t freed = UINT8_MAX;
	for (uint8_t index = 0u; index < LIFECYCLE_TELEMETRY_BANK_COUNT; ++index) {
		auto &bank = telemetry_storage_->banks[index];
		if (bank.epoch != epoch) {
			continue;
		}
		reset_telemetry_bank_metadata_(index);
		reset_telemetry_bank_transfer_(index);
		if (active_epoch != 0u && index == return_index) {
			bank.epoch = active_epoch;
			bank.state = telemetry_worker_quiesced_ ? telemetry_bank_state::AGGREGATED_RETAINED :
								  telemetry_bank_state::RETURNING;
			runtime_telemetry_bank_token token{
				.runtime_generation = telemetry_runtime_generation_,
				.epoch = active_epoch,
				.bank_generation = bank.generation,
				.published_at_ns = 0u,
				.worker_index = identity_.worker_index,
				.owner_index = identity_.context_index,
				.stage_instance_index = telemetry_stage_instance_index_,
				.bank_index = index,
				.companion_bank_index = UINT8_MAX,
				.owner_kind = runtime_telemetry_bank_owner_kind::MODULE,
				.reason = runtime_telemetry_publication_reason::RECLAIMED,
				.kind = telemetry_worker_quiesced_ ?
						runtime_telemetry_bank_token_kind::RETURN_RETAINED :
						runtime_telemetry_bank_token_kind::BANK,
				.padding = {},
			};
			bank.transfer = token;
			if (!telemetry_worker_quiesced_ && !telemetry_channel_->return_cleared(token)) {
				std::terminate();
			}
			telemetry_reclaimed_transfer_ = token;
			returned = index;
		} else {
			bank.epoch = 0u;
			bank.state = telemetry_bank_state::FREE;
			if (active_epoch != 0u) {
				if (freed != UINT8_MAX) {
					std::terminate();
				}
				freed = index;
			}
		}
	}
	if (active_epoch != 0u) {
		if (returned == UINT8_MAX || freed == UINT8_MAX) {
			std::terminate();
		}
		telemetry_free_bank_ = freed;
	} else {
		for (const auto &bank : telemetry_storage_->banks) {
			if (bank.state != telemetry_bank_state::FREE || bank.epoch != 0u ||
			    !runtime_telemetry_bank_token_is_empty(bank.transfer)) {
				std::terminate();
			}
		}
		telemetry_free_bank_ = UINT8_MAX;
	}
	telemetry_aggregated_epoch_ = 0u;
}

std::optional<runtime_telemetry_bank_token>
lifecycle_context_owner::take_reclaimed_telemetry_transfer(uint64_t active_epoch) noexcept
{
	if (active_epoch == 0u) {
		if (telemetry_reclaimed_transfer_.has_value()) {
			std::terminate();
		}
		return std::nullopt;
	}
	if (!telemetry_reclaimed_transfer_.has_value() || telemetry_reclaimed_transfer_->epoch != active_epoch) {
		return std::nullopt;
	}
	const auto &issued = *telemetry_reclaimed_transfer_;
	if (issued.runtime_generation != telemetry_runtime_generation_ || issued.bank_generation == 0u ||
	    issued.worker_index != identity_.worker_index || issued.owner_index != identity_.context_index ||
	    issued.stage_instance_index != telemetry_stage_instance_index_ ||
	    issued.bank_index >= LIFECYCLE_TELEMETRY_BANK_COUNT || issued.companion_bank_index != UINT8_MAX ||
	    issued.owner_kind != runtime_telemetry_bank_owner_kind::MODULE ||
	    issued.reason != runtime_telemetry_publication_reason::RECLAIMED || issued.published_at_ns != 0u ||
	    issued.kind != (telemetry_worker_quiesced_ ? runtime_telemetry_bank_token_kind::RETURN_RETAINED :
							 runtime_telemetry_bank_token_kind::BANK) ||
	    !runtime_telemetry_bank_token_padding_zero(issued)) {
		std::terminate();
	}
	// The worker may already have accepted and reused the bank. This immutable
	// issued record lets the coordinator reconcile that lawful race without
	// consulting mutable owner state.
	auto result = telemetry_reclaimed_transfer_;
	telemetry_reclaimed_transfer_.reset();
	return result;
}

bool lifecycle_context_owner::telemetry_empty() const noexcept
{
	if (telemetry_active_epoch_ != 0u || telemetry_prepared_epoch_ != 0u || telemetry_active_bank_ != UINT8_MAX ||
	    telemetry_standby_bank_ != UINT8_MAX || telemetry_reserved_bank_ != UINT8_MAX ||
	    telemetry_free_bank_ != UINT8_MAX || telemetry_aggregated_epoch_ != 0u || telemetry_old_banks_retained_ ||
	    telemetry_reclaimed_transfer_.has_value()) {
		return false;
	}
	for (const auto &bank : telemetry_storage_->banks) {
		if (bank.state != telemetry_bank_state::FREE || bank.epoch != 0u ||
		    !runtime_telemetry_bank_token_is_empty(bank.transfer)) {
			return false;
		}
	}
	return true;
}

uint64_t lifecycle_context_owner::telemetry_active_epoch() const noexcept
{
	return telemetry_active_epoch_;
}

uint64_t lifecycle_context_owner::telemetry_prepared_epoch() const noexcept
{
	return telemetry_prepared_epoch_;
}

uint64_t lifecycle_context_owner::telemetry_runtime_generation() const noexcept
{
	return telemetry_runtime_generation_;
}

uint16_t lifecycle_context_owner::telemetry_stage_instance_index() const noexcept
{
	return telemetry_stage_instance_index_;
}

bool lifecycle_context_owner::owns_telemetry_channel(const worker_telemetry_channel &channel) const noexcept
{
	return telemetry_channel_ == &channel;
}

void lifecycle_context_owner::end_operation_() noexcept
{
	borrowed_state_->epoch = 0;
	borrowed_state_->control = nullptr;
	borrowed_state_->arena = nullptr;
	operation_active_.store(false, std::memory_order_release);
}

status_or<void *> lifecycle_context_owner::allocate_long_lived_(std::size_t size, std::size_t alignment,
								bool zero_initialize) noexcept
{
	if (size == 0 || !is_power_of_two(alignment)) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text(
				      "long-lived allocation requires positive size and power-of-two alignment"));
	}
	if (context_memory_bytes_in_use_ > context_memory_capacity_bytes_ ||
	    size > context_memory_capacity_bytes_ - context_memory_bytes_in_use_) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text(
				      "module context exhausted its exact context-lifetime memory capacity"));
	}
	auto record_it = std::find_if(allocations_.begin(), allocations_.end(),
				      [](const auto &record) { return !record.occupied; });
	if (record_it == allocations_.end()) {
		return status(
			status_code::RESOURCE_EXHAUSTED,
			kinetum::common::static_status_text("lifecycle context long-lived allocation ledger is full"));
	}

	auto block_or = memory_provider_.allocate(identity_.numa_node, size, alignment, zero_initialize);
	if (!block_or.is_ok()) {
		return std::move(block_or).error();
	}
	auto block = std::move(block_or).value();
	if (auto block_status = validate_provider_block(block, identity_.numa_node, size, alignment);
	    !block_status.is_ok()) {
		memory_provider_.release(block);
		return block_status;
	}
	record_it->block = block;
	record_it->occupied = true;
	context_memory_bytes_in_use_ += block.size;
	return block.data;
}

status lifecycle_context_owner::release_long_lived_(void *pointer) noexcept
{
	if (!pointer) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text("long-lived release requires a nonnull exact pointer"));
	}
	auto record_it = std::find_if(allocations_.begin(), allocations_.end(), [pointer](const auto &record) {
		return record.occupied && record.block.data == pointer;
	});
	if (record_it == allocations_.end()) {
		return status(status_code::NOT_FOUND,
			      kinetum::common::static_status_text(
				      "long-lived release does not name an allocation owned by this context"));
	}
	if (record_it->block.size > context_memory_bytes_in_use_) {
		std::terminate();
	}
	context_memory_bytes_in_use_ -= record_it->block.size;
	memory_provider_.release(record_it->block);
	*record_it = {};
	return status::ok();
}

status_or<lifecycle_telemetry_descriptor *> lifecycle_context_owner::register_telemetry_(lifecycle_telemetry_kind kind,
											 std::string_view name) noexcept
{
	if (kind != lifecycle_telemetry_kind::COUNTER && kind != lifecycle_telemetry_kind::HISTOGRAM) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("unsupported lifecycle telemetry kind"));
	}
	const std::size_t name_capacity = kind == lifecycle_telemetry_kind::COUNTER ?
						  sizeof(telemetry_storage_->descriptors[0].counter.name) :
						  sizeof(telemetry_storage_->descriptors[0].histogram.name);
	if (!valid_telemetry_name(name) || name.size() >= name_capacity) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text(
				"lifecycle telemetry name violates the selected handle's bounded ASCII contract"));
	}
	for (std::size_t index = 0; index < telemetry_count_; ++index) {
		const auto &registered = telemetry_storage_->descriptors[index];
		const char *registered_name = registered.kind == lifecycle_telemetry_kind::COUNTER ?
						      registered.counter.name :
						      registered.histogram.name;
		if (std::string_view(registered_name) == name) {
			return status(status_code::ALREADY_EXISTS,
				      kinetum::common::static_status_text(
					      "lifecycle telemetry name is already registered by this context"));
		}
	}
	if ((kind == lifecycle_telemetry_kind::COUNTER && counter_count_ == KINETUM_MAX_COUNTERS) ||
	    (kind == lifecycle_telemetry_kind::HISTOGRAM && histogram_count_ == KINETUM_MAX_HISTOGRAMS) ||
	    telemetry_count_ == LIFECYCLE_MAX_TELEMETRY_HANDLES) {
		return status(status_code::RESOURCE_EXHAUSTED,
			      kinetum::common::static_status_text("lifecycle context telemetry registry is full"));
	}

	auto &descriptor = telemetry_storage_->descriptors[telemetry_count_];
	descriptor = {};
	descriptor.handle = static_cast<lifecycle_telemetry_handle>(telemetry_count_ + 1u);
	descriptor.kind = kind;
	descriptor.kind_ordinal =
		static_cast<uint32_t>(kind == lifecycle_telemetry_kind::COUNTER ? counter_count_ : histogram_count_);
	++telemetry_count_;
	if (kind == lifecycle_telemetry_kind::COUNTER) {
		++counter_count_;
	} else {
		++histogram_count_;
	}
	return &descriptor;
}

status_or<void *> lifecycle_context_owner::allocate_telemetry_(std::size_t size, std::size_t alignment) noexcept
{
	if (size == 0u || !is_power_of_two(alignment) ||
	    context_memory_bytes_in_use_ > context_memory_capacity_bytes_ ||
	    size > context_memory_capacity_bytes_ - context_memory_bytes_in_use_) {
		return status(status_code::POOL_EXHAUSTED,
			      kinetum::common::static_status_text(
				      "module telemetry exceeds its exact context-lifetime memory capacity"));
	}
	auto record_it = std::find_if(telemetry_allocations_.begin(), telemetry_allocations_.end(),
				      [](const auto &record) { return !record.occupied; });
	if (record_it == telemetry_allocations_.end()) {
		return status(status_code::POOL_EXHAUSTED,
			      kinetum::common::static_status_text("module histogram allocation ledger is full"));
	}
	auto block_or = memory_provider_.allocate(identity_.numa_node, size, alignment, true);
	if (!block_or.is_ok()) {
		if (block_or.error().code() == status_code::RESOURCE_EXHAUSTED ||
		    block_or.error().code() == status_code::POOL_EXHAUSTED) {
			return std::move(block_or).error().reclassified(status_code::POOL_EXHAUSTED);
		}
		return std::move(block_or).error();
	}
	auto block = std::move(block_or).value();
	if (auto block_status = validate_provider_block(block, identity_.numa_node, size, alignment);
	    !block_status.is_ok()) {
		memory_provider_.release(block);
		return block_status;
	}
	record_it->block = block;
	record_it->occupied = true;
	context_memory_bytes_in_use_ += block.size;
	return block.data;
}

const lifecycle_context_identity &lifecycle_identity(const ::kinetum_lifecycle_ctx &context) noexcept
{
	const auto *state = borrow_state(&context);
	if (state == nullptr || state->owner == nullptr) {
		std::terminate();
	}
	return state->owner->identity_;
}

lifecycle_phase lifecycle_current_phase(const ::kinetum_lifecycle_ctx &context) noexcept
{
	const auto *state = borrow_state(&context);
	if (state == nullptr || state->control == nullptr) {
		std::terminate();
	}
	return state->phase;
}

uint64_t lifecycle_current_epoch(const ::kinetum_lifecycle_ctx &context) noexcept
{
	const auto *state = borrow_state(&context);
	if (state == nullptr || state->control == nullptr) {
		std::terminate();
	}
	return state->epoch;
}

bool lifecycle_cancellation_requested(const ::kinetum_lifecycle_ctx &context) noexcept
{
	const auto *state = borrow_state(&context);
	return state == nullptr || state->control == nullptr || state->control->cancellation_requested();
}

std::chrono::steady_clock::time_point lifecycle_deadline(const ::kinetum_lifecycle_ctx &context) noexcept
{
	const auto *state = borrow_state(&context);
	if (state == nullptr || state->control == nullptr) {
		std::terminate();
	}
	return state->control->deadline();
}

status_or<void *> lifecycle_allocate_long_lived(const ::kinetum_lifecycle_ctx &context, std::size_t size,
						std::size_t alignment, bool zero_initialize) noexcept
{
	auto *state = borrow_state(&context);
	if (state == nullptr || state->owner == nullptr) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("invalid lifecycle context shell"));
	}
	if (state->phase != lifecycle_phase::INIT) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text(
				      "long-lived lifecycle allocation is available only during INIT"));
	}
	return state->owner->allocate_long_lived_(size, alignment, zero_initialize);
}

status lifecycle_release_long_lived(const ::kinetum_lifecycle_ctx &context, void *pointer) noexcept
{
	auto *state = borrow_state(&context);
	if (state == nullptr || state->owner == nullptr) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("invalid lifecycle context shell"));
	}
	if (state->phase != lifecycle_phase::INIT && state->phase != lifecycle_phase::FINI) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text(
				      "long-lived lifecycle release is available only during INIT rollback or FINI"));
	}
	return state->owner->release_long_lived_(pointer);
}

status_or<void *> lifecycle_allocate_epoch(const ::kinetum_lifecycle_ctx &context, std::size_t size,
					   std::size_t alignment, bool zero_initialize) noexcept
{
	auto *state = borrow_state(&context);
	if (state == nullptr || state->phase != lifecycle_phase::PREPARE || state->arena == nullptr) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text(
				      "epoch allocation is available only through the exact PREPARE arena"));
	}
	return state->arena->allocate(size, alignment, zero_initialize);
}

status_or<kinetum_counter_t> lifecycle_register_counter(const ::kinetum_lifecycle_ctx &context,
							std::string_view name) noexcept
{
	auto *state = borrow_state(&context);
	if (state == nullptr || state->owner == nullptr) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("invalid lifecycle context shell"));
	}
	if (state->phase != lifecycle_phase::INIT) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text(
				      "lifecycle telemetry registration is available only during INIT"));
	}
	auto descriptor_or = state->owner->register_telemetry_(lifecycle_telemetry_kind::COUNTER, name);
	if (!descriptor_or.is_ok()) {
		return std::move(descriptor_or).error();
	}
	auto *descriptor = descriptor_or.value();
	descriptor->counter.value = 0;
	std::copy(name.begin(), name.end(), descriptor->counter.name);
	descriptor->counter.name[name.size()] = '\0';
	return &descriptor->counter;
}

status_or<kinetum_histogram_t> lifecycle_register_histogram(const ::kinetum_lifecycle_ctx &context,
							    std::string_view name, uint64_t highest_trackable_value,
							    int32_t significant_digits) noexcept
{
	auto *state = borrow_state(&context);
	if (state == nullptr || state->owner == nullptr) {
		return status(status_code::INVALID_ARGUMENT,
			      kinetum::common::static_status_text("invalid lifecycle context shell"));
	}
	if (state->phase != lifecycle_phase::INIT) {
		return status(status_code::FAILED_PRECONDITION,
			      kinetum::common::static_status_text(
				      "lifecycle telemetry registration is available only during INIT"));
	}
	if (highest_trackable_value == 0 || significant_digits < 1 || significant_digits > 5) {
		return status(
			status_code::INVALID_ARGUMENT,
			kinetum::common::static_status_text(
				"histogram registration requires a positive ceiling and 1..5 significant digits"));
	}

	int32_t sub_bucket_count_magnitude = 0;
	uint64_t precision = 2;
	for (int32_t digit = 0; digit < significant_digits; ++digit) {
		if (precision > std::numeric_limits<uint64_t>::max() / 10u) {
			return status(status_code::OUT_OF_RANGE,
				      kinetum::common::static_status_text("histogram precision geometry overflow"));
		}
		precision *= 10u;
	}
	while ((uint64_t{1} << sub_bucket_count_magnitude) < precision) {
		++sub_bucket_count_magnitude;
	}
	const int32_t half_magnitude = std::max(1, sub_bucket_count_magnitude) - 1;
	const int32_t sub_bucket_count = 1 << (half_magnitude + 1);
	const int32_t sub_bucket_half_count = sub_bucket_count / 2;
	const int32_t unit_magnitude = 0;
	const int32_t sub_bucket_mask = sub_bucket_count - 1;

	int32_t bucket_count = 1;
	uint64_t smallest_untrackable = static_cast<uint64_t>(sub_bucket_count);
	while (smallest_untrackable <= highest_trackable_value) {
		if (smallest_untrackable > std::numeric_limits<uint64_t>::max() / 2u) {
			break;
		}
		smallest_untrackable <<= 1u;
		++bucket_count;
	}
	const uint64_t counts_len_wide =
		static_cast<uint64_t>(bucket_count + 1) * static_cast<uint64_t>(sub_bucket_half_count);
	if (counts_len_wide == 0 || counts_len_wide > std::numeric_limits<uint32_t>::max() ||
	    counts_len_wide > std::numeric_limits<std::size_t>::max() / sizeof(uint64_t)) {
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text("histogram bucket geometry exceeds bounded storage"));
	}

	auto descriptor_or = state->owner->register_telemetry_(lifecycle_telemetry_kind::HISTOGRAM, name);
	if (!descriptor_or.is_ok()) {
		return std::move(descriptor_or).error();
	}
	auto *descriptor = descriptor_or.value();
	const auto rollback_descriptor = [&]() {
		*descriptor = {};
		--state->owner->telemetry_count_;
		--state->owner->histogram_count_;
	};
	const std::size_t counts_bytes = static_cast<std::size_t>(counts_len_wide) * sizeof(uint64_t);
	std::size_t bank_stride = 0u;
	if (!round_up_telemetry_extent(counts_bytes, kinetum::algo::CACHE_LINE_SIZE, bank_stride) ||
	    bank_stride == 0u ||
	    bank_stride > std::numeric_limits<std::size_t>::max() / LIFECYCLE_TELEMETRY_BANK_COUNT) {
		rollback_descriptor();
		return status(status_code::OUT_OF_RANGE,
			      kinetum::common::static_status_text(
				      "histogram three-bank extent exceeds the host size domain"));
	}
	auto counts_or = state->owner->allocate_telemetry_(bank_stride * LIFECYCLE_TELEMETRY_BANK_COUNT,
							   kinetum::algo::CACHE_LINE_SIZE);
	if (!counts_or.is_ok()) {
		rollback_descriptor();
		return std::move(counts_or).error();
	}
	auto *counts = static_cast<std::byte *>(counts_or.value());
	for (std::size_t index = 0u; index < LIFECYCLE_TELEMETRY_BANK_COUNT; ++index) {
		descriptor->histogram_counts[index] = reinterpret_cast<uint64_t *>(counts + index * bank_stride);
		for (std::size_t bucket = 0u; bucket < static_cast<std::size_t>(counts_len_wide); ++bucket) {
			std::construct_at(descriptor->histogram_counts[index] + bucket, uint64_t{0});
		}
	}

	auto &histogram = descriptor->histogram;
	histogram.highest_trackable_value = highest_trackable_value;
	histogram.total_count = 0;
	histogram.min_value = std::numeric_limits<uint64_t>::max();
	histogram.max_value = 0;
	histogram.sum = 0;
	histogram.counts = descriptor->histogram_counts[0];
	histogram.counts_len = static_cast<uint32_t>(counts_len_wide);
	histogram.significant_digits = significant_digits;
	histogram.unit_magnitude = unit_magnitude;
	histogram.sub_bucket_half_count_magnitude = half_magnitude;
	histogram.sub_bucket_count = sub_bucket_count;
	histogram.sub_bucket_half_count = sub_bucket_half_count;
	histogram.sub_bucket_mask = sub_bucket_mask;
	histogram.bucket_count = bucket_count;
	std::copy(name.begin(), name.end(), histogram.name);
	histogram.name[name.size()] = '\0';
	const std::size_t ordinal = descriptor->kind_ordinal;
	if (ordinal >= state->owner->telemetry_histogram_banks_.size()) {
		std::terminate();
	}
	state->owner->telemetry_histogram_banks_[ordinal] = descriptor->histogram_counts;
	state->owner->telemetry_histogram_lengths_[ordinal] = histogram.counts_len;
	return &histogram;
}

void lifecycle_log(const ::kinetum_lifecycle_ctx &context, lifecycle_log_level level, std::string_view message) noexcept
{
	if (common::reject_packet_thread_log()) {
		return;
	}
	const auto *state = borrow_state(&context);
	if (state == nullptr || state->owner == nullptr) {
		return;
	}
	// No platform or ownership lock is held while the provider is invoked.
	state->owner->log_provider_.write({state->owner->identity_, state->phase, state->epoch, level, message});
}
}  // namespace kinetum::dp::lifecycle
