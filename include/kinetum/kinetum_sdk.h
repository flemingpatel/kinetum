// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file kinetum_sdk.h
 * @brief Canonical public C ABI for Kinetum packet modules and lifecycle.
 * @author Fleming Patel
 *
 * The SDK separates cold lifecycle work from owner-worker packet execution.
 * INIT, PREPARE, RETIRE, and FINI receive a platform-owned lifecycle context;
 * packet callbacks receive one cache-line live context and an exact immutable
 * configuration pointer. Modules never select a current or previous epoch.
 *
 * Packet callbacks are single-owner operations. They must not allocate, block,
 * log, register telemetry, throw across the C ABI, or retain packet/config
 * pointers after return.
 * Lifecycle callbacks may allocate through tracked services and may be
 * expensive, but configuration preparation must not mutate live context state.
 * Explicit no-op lifecycle callbacks are defined with internal linkage so a
 * module image remains self-contained and imports no host SDK runtime symbol.
 *
 * A module descriptor is admitted only when its ABI version is exactly equal
 * to the host ABI version, every mandatory callback is present, and every flag
 * is known. Version ranges and alternate descriptor interpretations are not
 * part of this contract.
 */

#if !defined(__GNUC__) && !defined(__clang__)
#error "Kinetum modules require a GNU-compatible compiler"
#endif

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "Kinetum modules support only x86-64 and AArch64 target architectures"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Kinetum modules support only little-endian target architectures"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__AVX2__) || defined(__SSE2__)
#include <immintrin.h>
#elif defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
#include <arm_neon.h>
#endif

#ifdef __cplusplus
#include <type_traits>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Version and Limits
// =============================================================================

/** Module ABI major version component. */
#define KINETUM_MODULE_ABI_VERSION_MAJOR 0u

/** Module ABI minor version component. */
#define KINETUM_MODULE_ABI_VERSION_MINOR 1u

/** Module ABI patch version component. */
#define KINETUM_MODULE_ABI_VERSION_PATCH 0u

/** Exact module ABI identity encoded as major.minor.patch bytes. */
#define KINETUM_MODULE_ABI_VERSION                                                               \
	((KINETUM_MODULE_ABI_VERSION_MAJOR << 24u) | (KINETUM_MODULE_ABI_VERSION_MINOR << 16u) | \
	 KINETUM_MODULE_ABI_VERSION_PATCH)

/**
 * Maximum storage for one NUL-terminated module-ABI identity or version.
 * Valid text therefore contains 1..255 printable-ASCII bytes followed by NUL.
 */
#define KINETUM_MODULE_ABI_TEXT_CAPACITY 256u

/** Maximum records in one module callback or active-origin batch. */
#define KINETUM_MAX_BURST 64

/** Maximum pre-registered counters per module. */
#define KINETUM_MAX_COUNTERS 64

/** Maximum pre-registered histograms per module. */
#define KINETUM_MAX_HISTOGRAMS 16

/** Cache line size for alignment on the supported little-endian target tuples. */
#define KINETUM_CACHE_LINE 64

/**
 * SIMD vector width compiled into the image-local C comparison mechanisms.
 * A scalar build reports one byte; callers must never infer host capability.
 */
#if defined(__AVX2__)
#define KINETUM_SIMD_WIDTH 32
#elif defined(__SSE2__) || (defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__)))
#define KINETUM_SIMD_WIDTH 16
#else
#define KINETUM_SIMD_WIDTH 1
#endif

/** Maximum plan-admitted logical ports visible through the module ABI. */
#define KINETUM_MAX_PORTS 64

/**
 * @brief Defer final egress selection to the compiled TX stage binding.
 *
 * A forwarded packet whose batch->output_port[i] remains unset uses the exact
 * logical egress bound to the TX stage it reaches. Missing or unknown compiled
 * egress authority fails closed; the runtime never selects an arbitrary port.
 */
#define KINETUM_PORT_UNSET 0xFFFFu

/**
 * @brief Select terminal discard if the packet reaches TX dispatch.
 *
 * Setting batch->output_port[i] to this value controls final egress only. It
 * does not replace the callback's return-mask contract: clear the packet's bit
 * for an immediate module-stage drop, or keep it set when intentionally
 * forwarding toward terminal TX discard.
 */
#define KINETUM_PORT_DROP 0xFFFEu

/**
 * @brief Indicate that a module did not select an executable successor.
 *
 * When batch->next_stage[i] remains unset for a forwarded packet, the runtime
 * uses compiled edge conditions and then unconditional fan-out to select the
 * next executable stage.
 *
 * Dispatch priority order:
 *   1. Module next_stage[i] (if != KINETUM_NEXT_STAGE_UNSET)
 *   2. Edge condition match (evaluated by priority, first match wins)
 *   3. Broadcast to all successors (default behavior)
 */
#define KINETUM_NEXT_STAGE_UNSET 0xFFFFu

// =============================================================================
// Compiler Hints (Performance Optimization)
// =============================================================================

/** Mark one expression as the expected branch outcome. */
#define KINETUM_LIKELY(x) __builtin_expect(!!(x), 1)

/** Mark one expression as the unexpected branch outcome. */
#define KINETUM_UNLIKELY(x) __builtin_expect(!!(x), 0)

/** Require inlining of one small hot-path function. */
#define KINETUM_ALWAYS_INLINE __attribute__((always_inline)) inline

/** Mark a function as execution-frequency hot. */
#define KINETUM_HOT __attribute__((hot))

/** Mark a function as execution-frequency cold. */
#define KINETUM_COLD __attribute__((cold))

/** Export one deliberately public symbol from an otherwise hidden module image. */
#define KINETUM_MODULE_EXPORT __attribute__((visibility("default")))

/** Express one exact alignment in both the C11 and C++20 SDK surfaces. */
#if defined(__cplusplus)
#define KINETUM_ALIGNAS(bytes) alignas(bytes)
#else
#define KINETUM_ALIGNAS(bytes) _Alignas(bytes)
#endif

/** Cache-line alignment for structures. */
#define KINETUM_ALIGNED __attribute__((aligned(KINETUM_CACHE_LINE)))

/** Prefetch for immediate read reuse at the highest locality. */
#define KINETUM_PREFETCH_L1(addr) __builtin_prefetch((addr), 0, 3)

/** Prefetch for near-term read reuse at medium locality. */
#define KINETUM_PREFETCH_L2(addr) __builtin_prefetch((addr), 0, 2)

/** Prefetch for later read reuse at low locality. */
#define KINETUM_PREFETCH_L3(addr) __builtin_prefetch((addr), 0, 1)

/** Prefetch one non-temporal streaming read. */
#define KINETUM_PREFETCH_NTA(addr) __builtin_prefetch((addr), 0, 0)

/** Prefetch one address for an imminent write. */
#define KINETUM_PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)

// =============================================================================
// Error Codes
// =============================================================================

/** Fixed-width SDK error value crossing the module ABI. */
typedef int32_t kinetum_error;

/** SDK error constants. */
enum {
	KINETUM_OK = 0,			  ///< Success.
	KINETUM_ERR_INVALID_ARG = -1,	  ///< Invalid argument.
	KINETUM_ERR_NO_MEMORY = -2,	  ///< Memory allocation failed.
	KINETUM_ERR_NOT_FOUND = -3,	  ///< Resource not found.
	KINETUM_ERR_ALREADY_EXISTS = -4,  ///< Resource already exists.
	KINETUM_ERR_LIMIT_EXCEEDED = -5,  ///< Bounded resource exhausted.
	KINETUM_ERR_NOT_SUPPORTED = -6,	  ///< Operation is not supported.
	KINETUM_ERR_BUSY = -7,		  ///< Exact owner is busy.
	KINETUM_ERR_TIMEOUT = -8,	  ///< Operation deadline expired.
	KINETUM_ERR_CONFIG_INVALID = -9,  ///< Module configuration is invalid.
	KINETUM_ERR_CANCELLED = -10,	  ///< Cooperative cancellation observed.
	KINETUM_ERR_INTERNAL = -99,	  ///< Internal module or host fault.
};

/**
 * @brief Return the fixed diagnostic text for one SDK error value.
 *
 * The returned string has static image-local storage and requires no host SDK
 * runtime symbol. Unknown values map to `Unknown error`.
 *
 * @param error Exact SDK error value.
 * @return Immutable image-local diagnostic text valid while the containing
 *         image remains loaded.
 */
static inline const char *kinetum_strerror(kinetum_error error)
{
	switch (error) {
	case KINETUM_OK:
		return "Success";
	case KINETUM_ERR_INVALID_ARG:
		return "Invalid argument";
	case KINETUM_ERR_NO_MEMORY:
		return "Memory allocation failed";
	case KINETUM_ERR_NOT_FOUND:
		return "Resource not found";
	case KINETUM_ERR_ALREADY_EXISTS:
		return "Resource already exists";
	case KINETUM_ERR_LIMIT_EXCEEDED:
		return "Limit exceeded";
	case KINETUM_ERR_NOT_SUPPORTED:
		return "Operation not supported";
	case KINETUM_ERR_BUSY:
		return "Resource busy";
	case KINETUM_ERR_TIMEOUT:
		return "Operation timed out";
	case KINETUM_ERR_CONFIG_INVALID:
		return "Invalid configuration";
	case KINETUM_ERR_CANCELLED:
		return "Operation cancelled";
	case KINETUM_ERR_INTERNAL:
		return "Internal error";
	default:
		return "Unknown error";
	}
}

// =============================================================================
// Packet Facts and Module Flags
//
// platform_flags contains only facts the current platform parser can produce.
// user_flags is a separate module-owned word for domain-specific state.
// =============================================================================

/** @name Current Platform Parser Facts
 * @{ */

#define KINETUM_PKT_F_L3_IPV4 (1u << 0)	  ///< Parsed L3 is IPv4.
#define KINETUM_PKT_F_L4_TCP (1u << 2)	  ///< IPv4 protocol field identifies TCP.
#define KINETUM_PKT_F_L4_UDP (1u << 3)	  ///< IPv4 protocol field identifies UDP.
#define KINETUM_PKT_F_FRAGMENT (1u << 6)  ///< Parsed IPv4 packet is fragmented.

/** Exact mask of facts the current parser produces and accepts. */
#define KINETUM_PKT_F_PLATFORM_MASK \
	(KINETUM_PKT_F_L3_IPV4 | KINETUM_PKT_F_L4_TCP | KINETUM_PKT_F_L4_UDP | KINETUM_PKT_F_FRAGMENT)

/** @} */

/** @name User Flags - Defined by users for their domain
 *
 * User flags occupy a separate module-owned word. They never share bit space
 * with platform parser facts.
 * @code
 * // In your domain header (e.g., my_satcom.h):
 * #define MY_PKT_F_SATCOM      (KINETUM_USER_F_BASE << 0)
 * #define MY_PKT_F_ACM_CHANGE  (KINETUM_USER_F_BASE << 1)
 * #define MY_PKT_F_GTP_U       (KINETUM_USER_F_BASE << 2)
 * @endcode
 * @{ */

/** Base bit for user-defined flags. */
#define KINETUM_USER_F_BASE 1u

/** @} */

// =============================================================================
// Persistent Module Metadata
//
// user_meta is one optional 64-bit module-owned word. Modules encode any
// domain-specific type or version information inside that word or user_flags;
// the platform does not advertise a second metadata-type lane.
// =============================================================================

// =============================================================================
// Packet callback batches
//
// The runtime owns one provider-neutral packet record per packet. Callbacks see
// a transient structure-of-arrays projection of those exact records; there is
// no native-provider handle, hidden packet object, or second disposition field.
// =============================================================================

/**
 * @brief Exact transient view of already-owned packet records.
 *
 * The return mask of the callback is the sole packet-disposition authority.
 * Bit i set means forward record i; bit i clear means consume it as a drop.
 * The callback must not return bits outside `[0, count)`.
 *
 * Parsed fields and packet bytes are one coherent contract: a module that
 * mutates bytes must update every parsed field invalidated by that mutation.
 * The runtime never reparses a packet between module stages.
 * `data`, `len`, `input_port`, `ts_ns`, `count`, `region_id`, `epoch`,
 * `epoch_config`, and `ctx` are borrowed runtime authority and must not be
 * changed. The payload bytes referenced by `data` are writable, but this ABI
 * does not permit replacing the backing, resizing a packet, or changing
 * structural packet facts that have no mutable lane. Parsed addresses, ports,
 * protocol, DSCP, offsets, flags, flow hash, output port, next stage, and user
 * metadata are mutable and are published back to the sole packet record after
 * the callback. L3/L4 offsets must remain within `len`, DSCP is six bits,
 * `user_meta_valid` is zero or one, and platform flags use only the documented
 * platform mask. TCP and UDP facts are exclusive and must agree with `proto`;
 * every L4 or fragment fact requires IPv4, while an unparsed packet carries
 * neither a protocol nor parsed flags. Violating runtime authority is a module
 * contract fault.
 *
 * `user_meta`, `user_meta_valid`, and `user_flags` are persistent module-owned
 * packet state. The runtime copies them from each record before the callback
 * and copies them back afterward. Fan-out clones receive independent snapshots
 * of those values at clone time and may diverge without cross-branch writes.
 */
typedef struct KINETUM_ALIGNED kinetum_batch {
	KINETUM_ALIGNAS(64) void *data[KINETUM_MAX_BURST];	   ///< Mutable bytes; backing pointers are immutable.
	KINETUM_ALIGNAS(64) uint32_t len[KINETUM_MAX_BURST];	   ///< Immutable logical lengths.
	KINETUM_ALIGNAS(64) uint16_t l3_off[KINETUM_MAX_BURST];	   ///< Mutable L3 byte offsets.
	KINETUM_ALIGNAS(64) uint16_t l4_off[KINETUM_MAX_BURST];	   ///< Mutable L4 byte offsets.
	KINETUM_ALIGNAS(64) uint32_t src_ip[KINETUM_MAX_BURST];	   ///< Mutable source IPv4 values.
	KINETUM_ALIGNAS(64) uint32_t dst_ip[KINETUM_MAX_BURST];	   ///< Mutable destination IPv4 values.
	KINETUM_ALIGNAS(64) uint16_t src_port[KINETUM_MAX_BURST];  ///< Mutable source ports.
	KINETUM_ALIGNAS(64) uint16_t dst_port[KINETUM_MAX_BURST];  ///< Mutable destination ports.
	KINETUM_ALIGNAS(64) uint8_t proto[KINETUM_MAX_BURST];	   ///< Mutable IP protocols.
	KINETUM_ALIGNAS(64) uint8_t dscp[KINETUM_MAX_BURST];	   ///< Mutable six-bit DSCP values.
	KINETUM_ALIGNAS(64) uint32_t platform_flags[KINETUM_MAX_BURST];	 ///< Mutable platform flags.
	KINETUM_ALIGNAS(64) uint32_t user_flags[KINETUM_MAX_BURST];	 ///< Mutable persistent user flags.
	KINETUM_ALIGNAS(64) uint32_t flow_hash[KINETUM_MAX_BURST];	 ///< Mutable flow hashes.
	KINETUM_ALIGNAS(64) uint16_t input_port[KINETUM_MAX_BURST];	 ///< Immutable ingress ports.
	KINETUM_ALIGNAS(64) uint16_t output_port[KINETUM_MAX_BURST];	 ///< Mutable egress ports.
	KINETUM_ALIGNAS(64) uint16_t next_stage[KINETUM_MAX_BURST];	 ///< Mutable logical next stages.
	KINETUM_ALIGNAS(64) uint64_t ts_ns[KINETUM_MAX_BURST];		 ///< Immutable packet timestamps.
	KINETUM_ALIGNAS(64) uint64_t user_meta[KINETUM_MAX_BURST];	 ///< Mutable persistent user words.
	KINETUM_ALIGNAS(64) uint8_t user_meta_valid[KINETUM_MAX_BURST];	 ///< Mutable presence bits.
	uint16_t count;							 ///< Immutable occupied prefix length.
	uint16_t region_id;						 ///< Immutable owner-worker region.
	uint32_t padding;						 ///< Layout padding; must remain zero.
	uint64_t epoch;							 ///< Immutable packet/executable epoch.
	const void *epoch_config;					 ///< Immutable exact packet configuration.
	struct kinetum_ctx *ctx;					 ///< Immutable exact context pointer.
} kinetum_batch_t;

/**
 * @brief Borrowed packet origins supplied by an active module.
 *
 * `emit()` validates the complete batch before performing any allocation or
 * dispatch, then copies an accepted prefix into records owned by the active
 * stage's storage domain. Payload pointers remain module-owned and borrowed
 * only for the duration of `emit()`. DSCP, offset, platform-flag, metadata-
 * presence, size, and target-stage bounds are validated before the first
 * storage credit is acquired. Parser facts obey the same IPv4/L4/protocol
 * relations as callback batches. A zero timestamp selects the owner worker's
 * cached loop time; no callback-side clock read is required.
 */
typedef struct KINETUM_ALIGNED kinetum_emit_batch {
	KINETUM_ALIGNAS(64) const void *data[KINETUM_MAX_BURST];	 ///< Borrowed origin bytes.
	KINETUM_ALIGNAS(64) uint32_t len[KINETUM_MAX_BURST];		 ///< Exact origin lengths.
	KINETUM_ALIGNAS(64) uint16_t l3_off[KINETUM_MAX_BURST];		 ///< L3 byte offsets.
	KINETUM_ALIGNAS(64) uint16_t l4_off[KINETUM_MAX_BURST];		 ///< L4 byte offsets.
	KINETUM_ALIGNAS(64) uint32_t src_ip[KINETUM_MAX_BURST];		 ///< Source IPv4 values.
	KINETUM_ALIGNAS(64) uint32_t dst_ip[KINETUM_MAX_BURST];		 ///< Destination IPv4 values.
	KINETUM_ALIGNAS(64) uint16_t src_port[KINETUM_MAX_BURST];	 ///< Source ports.
	KINETUM_ALIGNAS(64) uint16_t dst_port[KINETUM_MAX_BURST];	 ///< Destination ports.
	KINETUM_ALIGNAS(64) uint8_t proto[KINETUM_MAX_BURST];		 ///< IP protocols.
	KINETUM_ALIGNAS(64) uint8_t dscp[KINETUM_MAX_BURST];		 ///< Six-bit DSCP values.
	KINETUM_ALIGNAS(64) uint32_t platform_flags[KINETUM_MAX_BURST];	 ///< Platform flags.
	KINETUM_ALIGNAS(64) uint32_t user_flags[KINETUM_MAX_BURST];	 ///< Persistent user flags.
	KINETUM_ALIGNAS(64) uint32_t flow_hash[KINETUM_MAX_BURST];	 ///< Flow hashes.
	KINETUM_ALIGNAS(64) uint16_t input_port[KINETUM_MAX_BURST];	 ///< Logical source ports.
	KINETUM_ALIGNAS(64) uint16_t output_port[KINETUM_MAX_BURST];	 ///< Logical egress ports.
	KINETUM_ALIGNAS(64) uint16_t next_stage[KINETUM_MAX_BURST];	 ///< Logical target stages.
	KINETUM_ALIGNAS(64) uint64_t ts_ns[KINETUM_MAX_BURST];		 ///< Timestamp or zero for cached now.
	KINETUM_ALIGNAS(64) uint64_t user_meta[KINETUM_MAX_BURST];	 ///< Persistent user words.
	KINETUM_ALIGNAS(64) uint8_t user_meta_valid[KINETUM_MAX_BURST];	 ///< Presence bits.
	uint16_t count;							 ///< Exact occupied prefix length.
} kinetum_emit_batch_t;

// =============================================================================
// SoA Accessor Macros - Ergonomic Access Without Breaking SoA Layout
//
// These macros provide clean syntax. Compiler optimizes to direct array access.
// =============================================================================

/** Get packet data pointer */
#define KINETUM_PKT_DATA(batch, i) ((batch)->data[i])
/** Get packet length */
#define KINETUM_PKT_LEN(batch, i) ((batch)->len[i])
/** Get L3 (IP) header offset */
#define KINETUM_PKT_L3_OFF(batch, i) ((batch)->l3_off[i])
/** Get L4 (TCP/UDP) header offset */
#define KINETUM_PKT_L4_OFF(batch, i) ((batch)->l4_off[i])
/** Get source IP (host byte order) */
#define KINETUM_PKT_SRC_IP(batch, i) ((batch)->src_ip[i])
/** Get destination IP (host byte order) */
#define KINETUM_PKT_DST_IP(batch, i) ((batch)->dst_ip[i])
/** Get source port (host byte order) */
#define KINETUM_PKT_SRC_PORT(batch, i) ((batch)->src_port[i])
/** Get destination port (host byte order) */
#define KINETUM_PKT_DST_PORT(batch, i) ((batch)->dst_port[i])
/** Get IP protocol */
#define KINETUM_PKT_PROTO(batch, i) ((batch)->proto[i])
/** Get DSCP value */
#define KINETUM_PKT_DSCP(batch, i) ((batch)->dscp[i])
/** Get flow hash */
#define KINETUM_PKT_HASH(batch, i) ((batch)->flow_hash[i])
/** Get current platform parser facts. */
#define KINETUM_PKT_PLATFORM_FLAGS(batch, i) ((batch)->platform_flags[i])
/** Get timestamp */
#define KINETUM_PKT_TS(batch, i) ((batch)->ts_ns[i])

/**
 * @brief Clear one lane from the callback's sole forward mask.
 *
 * @param forward_mask Caller-owned disposition mask.
 * @param index Occupied batch-lane index in `[0, KINETUM_MAX_BURST)`.
 */
static KINETUM_ALWAYS_INLINE void kinetum_drop_lane(uint64_t *forward_mask, uint32_t index)
{
	*forward_mask &= ~(UINT64_C(1) << index);
}

/**
 * @brief Set one lane in the sole forward mask and select its logical egress.
 *
 * @param forward_mask Caller-owned disposition mask.
 * @param batch Exact callback batch.
 * @param index Occupied batch-lane index in `[0, batch->count)`.
 * @param port Logical egress identity or a documented port sentinel.
 */
static KINETUM_ALWAYS_INLINE void kinetum_forward_lane(uint64_t *forward_mask, kinetum_batch_t *batch, uint32_t index,
						       uint16_t port)
{
	*forward_mask |= UINT64_C(1) << index;
	batch->output_port[index] = port;
}

/** Clear packet i from the callback's sole forward mask; arguments are evaluated once. */
#define KINETUM_DROP(forward_mask, i) kinetum_drop_lane(&(forward_mask), (uint32_t)(i))

/** Set packet i in the sole forward mask and select its egress; arguments are evaluated once. */
#define KINETUM_FORWARD(forward_mask, batch, i, port) \
	kinetum_forward_lane(&(forward_mask), (batch), (uint32_t)(i), (uint16_t)(port))

// =============================================================================
// Owner-Local Telemetry
//
// Handles are registered during INIT and updated only by the context's owner
// worker. The hot path therefore uses plain loads/stores/adds: cross-thread
// readers consume coherent worker publications rather than touching these
// mutable leaves. A shared module scope must use a separate admitted sharding
// contract; it may not silently turn these handles into contended atomics.
// =============================================================================

/**
 * @brief CPU pause hint for bounded spin loops.
 *
 * Reduces power consumption and improves performance in spin-wait loops
 * by hinting to the CPU that this is a busy-wait.
 */
#if defined(__x86_64__)
#define KINETUM_PAUSE() __builtin_ia32_pause()
#else
#define KINETUM_PAUSE() __asm__ __volatile__("yield" ::: "memory")
#endif

/**
 * @brief One pre-registered owner-local counter.
 *
 * @note Modules must obtain handles from the lifecycle context during INIT.
 */
typedef struct kinetum_counter {
	uint64_t value;	 ///< Plain single-writer value.
	char name[56];	 ///< Stable bounded metric identity.
} KINETUM_ALIGNED kinetum_counter;

/** Opaque handle for pre-registered counter (pointer to kinetum_counter). */
typedef struct kinetum_counter *kinetum_counter_t;

/**
 * @brief One pre-registered owner-local HDR histogram.
 *
 * The lifecycle owner supplies the exact bucket array. Packet execution only
 * mutates this record and its counts through the cached handle.
 */
typedef struct kinetum_histogram {
	uint64_t highest_trackable_value;	  ///< Largest accepted sample value.
	uint64_t total_count;			  ///< Number of recorded samples.
	uint64_t min_value;			  ///< Smallest recorded sample.
	uint64_t max_value;			  ///< Largest recorded sample.
	uint64_t sum;				  ///< Saturating sum of recorded samples.
	uint64_t *counts;			  ///< Lifecycle-owned bucket array.
	uint32_t counts_len;			  ///< Number of entries in @p counts.
	int32_t significant_digits;		  ///< Registration precision.
	int32_t unit_magnitude;			  ///< HDR unit-magnitude parameter.
	int32_t sub_bucket_half_count_magnitude;  ///< HDR half-count magnitude.
	int32_t sub_bucket_count;		  ///< Complete HDR sub-bucket count.
	int32_t sub_bucket_half_count;		  ///< Half of @p sub_bucket_count.
	int32_t sub_bucket_mask;		  ///< HDR bucket-selection mask.
	int32_t bucket_count;			  ///< Number of HDR bucket groups.
	char name[64];				  ///< Stable bounded metric identity.
} KINETUM_ALIGNED kinetum_histogram;

/** Opaque handle for pre-registered histogram. */
typedef struct kinetum_histogram *kinetum_histogram_t;

// =============================================================================
// Hot-Path Inline Mechanisms
//
// These macros bypass function pointer indirection and registry lookup.
// Use them in process() for counters updated per packet. Registration occurs
// through kinetum_lifecycle_ctx during INIT.
//
// Hot-path contract: one direct owner-local update, no callback dispatch,
// metric-name lookup, allocation, lock, or shared atomic operation.
// =============================================================================

/**
 * @brief Increment counter by delta (hot-path, inline).
 *
 * Use this in process() for per-packet counters to avoid callback
 * indirection and metric-name lookup.
 *
 * @param counter kinetum_counter_t handle from counter_register().
 * @param delta Nonnegative bounded value to add. Use KINETUM_COUNTER_SET for a gauge.
 */
#define KINETUM_COUNTER_ADD(counter, delta)                    \
	do {                                                   \
		if (KINETUM_LIKELY((counter) != NULL)) {       \
			(counter)->value += (uint64_t)(delta); \
		}                                              \
	} while (0)

/**
 * @brief Increment counter by 1 (hot-path, inline).
 *
 * @param counter kinetum_counter_t handle.
 */
#define KINETUM_COUNTER_INC(counter) KINETUM_COUNTER_ADD((counter), 1)

/**
 * @brief Read counter value (hot-path, inline).
 *
 * @param counter kinetum_counter_t handle.
 * @return Current counter value, or 0 if NULL.
 */
#define KINETUM_COUNTER_GET(counter) (KINETUM_LIKELY((counter) != NULL) ? (counter)->value : 0u)

/**
 * @brief Set counter value (hot-path, inline).
 *
 * Use for gauges (current values, not cumulative).
 *
 * @param counter kinetum_counter_t handle.
 * @param _val_ New value.
 */
#define KINETUM_COUNTER_SET(counter, _val_)                   \
	do {                                                  \
		if (KINETUM_LIKELY((counter) != NULL)) {      \
			(counter)->value = (uint64_t)(_val_); \
		}                                             \
	} while (0)

// =============================================================================
// Histogram Inline Recording
// =============================================================================

/**
 * @brief Record one exact sample into an owner-local HDR histogram.
 *
 * @param hist Registered histogram handle.
 * @param value Value to record.
 */
static KINETUM_ALWAYS_INLINE void kinetum_histogram_record(kinetum_histogram_t hist, uint64_t value)
{
	if (KINETUM_UNLIKELY(hist == NULL || hist->counts == NULL || hist->counts_len == 0u)) {
		return;
	}
	if (value > hist->highest_trackable_value) {
		value = hist->highest_trackable_value;
	}

	const unsigned long long combined = (unsigned long long)(value | (uint64_t)(uint32_t)hist->sub_bucket_mask);
	const int32_t power = 64 - (int32_t)__builtin_clzll(combined);
	const int32_t bucket = power - hist->unit_magnitude - (hist->sub_bucket_half_count_magnitude + 1);
	const int32_t sub_bucket = (int32_t)(value >> (bucket + hist->unit_magnitude));
	const int32_t index = (bucket + 1) * hist->sub_bucket_half_count + sub_bucket - hist->sub_bucket_half_count;
	if (KINETUM_UNLIKELY(index < 0 || (uint32_t)index >= hist->counts_len)) {
		return;
	}

	hist->counts[index] += 1u;
	hist->total_count += 1u;
	if (value < hist->min_value) {
		hist->min_value = value;
	}
	if (value > hist->max_value) {
		hist->max_value = value;
	}
	hist->sum = UINT64_MAX - hist->sum < value ? UINT64_MAX : hist->sum + value;
}

/**
 * @brief Record one sample through the direct owner-local histogram helper.
 * @param hist Registered histogram handle.
 * @param value Value to record.
 */
#define KINETUM_HISTOGRAM_RECORD_FAST(hist, value) kinetum_histogram_record((hist), (uint64_t)(value))

/**
 * @brief HDR Histogram percentile query result.
 */
typedef struct kinetum_percentiles {
	uint64_t p50;	 ///< 50th percentile (median)
	uint64_t p90;	 ///< 90th percentile
	uint64_t p99;	 ///< 99th percentile
	uint64_t p999;	 ///< 99.9th percentile
	uint64_t max;	 ///< Maximum value
	uint64_t min;	 ///< Minimum value
	uint64_t count;	 ///< Total sample count
	uint64_t sum;	 ///< Sum of all values
} kinetum_percentiles;

/**
 * @brief Compute one inclusive per-mille rank without overflowing uint64_t.
 *
 * @param count Positive sample count.
 * @param per_mille Percentile in the inclusive range 1..1000.
 * @return One-based inclusive rank.
 */
static inline uint64_t kinetum_histogram_percentile_rank(uint64_t count, uint32_t per_mille)
{
	const uint64_t quotient = count / 1000u;
	const uint64_t remainder = count % 1000u;
	return quotient * (uint64_t)per_mille + (remainder * (uint64_t)per_mille + 999u) / 1000u;
}

/**
 * @brief Resolve one validated HDR bucket index to its lower-bound value.
 *
 * @param histogram Stable owner-local histogram geometry.
 * @param index Valid flat bucket index.
 * @return Represented lower-bound sample value.
 */
static inline uint64_t kinetum_histogram_value_at(const kinetum_histogram *histogram, uint32_t index)
{
	const int32_t signed_index = (int32_t)index;
	const int32_t bucket =
		signed_index >= histogram->sub_bucket_half_count ?
			(signed_index - histogram->sub_bucket_half_count) / histogram->sub_bucket_half_count :
			0;
	const int32_t sub_bucket =
		signed_index >= histogram->sub_bucket_half_count ?
			(signed_index - histogram->sub_bucket_half_count) % histogram->sub_bucket_half_count +
				histogram->sub_bucket_half_count :
			signed_index;
	return (uint64_t)sub_bucket << (uint32_t)(bucket + histogram->unit_magnitude);
}

/**
 * @brief Resolve one fixed percentile from a stable owner-local histogram.
 *
 * @param histogram Histogram not being mutated concurrently.
 * @param per_mille Percentile in the inclusive range 1..1000.
 * @return Bucket value at the inclusive rank, or zero when empty.
 */
static inline uint64_t kinetum_histogram_percentile(const kinetum_histogram *histogram, uint32_t per_mille)
{
	uint64_t observed = 0;
	uint32_t index;
	uint64_t target;

	if (histogram == NULL || histogram->total_count == 0 || histogram->counts == NULL ||
	    histogram->counts_len == 0) {
		return 0;
	}

	target = kinetum_histogram_percentile_rank(histogram->total_count, per_mille);
	for (index = 0; index < histogram->counts_len; ++index) {
		const uint64_t count = histogram->counts[index];
		observed = UINT64_MAX - observed < count ? UINT64_MAX : observed + count;
		if (observed >= target) {
			return kinetum_histogram_value_at(histogram, index);
		}
	}
	return histogram->highest_trackable_value;
}

/**
 * @brief Read one bucket-quantized percentile summary from a stable histogram.
 *
 * The context owner must not mutate @p histogram while this cold helper reads
 * it. Production publication uses completed immutable histogram banks rather
 * than reading the owner-worker's active bank concurrently.
 *
 * @param histogram Owner-local histogram to summarize.
 * @param out_summary Output summary, zeroed when the histogram is empty.
 */
static inline void kinetum_histogram_percentiles(const kinetum_histogram_t histogram, kinetum_percentiles *out_summary)
{
	if (out_summary == NULL) {
		return;
	}
	memset(out_summary, 0, sizeof(*out_summary));
	if (histogram == NULL || histogram->total_count == 0) {
		return;
	}

	out_summary->p50 = kinetum_histogram_percentile(histogram, 500);
	out_summary->p90 = kinetum_histogram_percentile(histogram, 900);
	out_summary->p99 = kinetum_histogram_percentile(histogram, 990);
	out_summary->p999 = kinetum_histogram_percentile(histogram, 999);
	out_summary->max = histogram->max_value;
	out_summary->min = histogram->min_value;
	out_summary->count = histogram->total_count;
	out_summary->sum = histogram->sum;
}

// ============================================================================
// Cold Lifecycle ABI
// ============================================================================

/** Forward declaration of the live owner-worker context. */
typedef struct kinetum_ctx kinetum_ctx;

/** Forward declaration of the cold lifecycle service table. */
typedef struct kinetum_lifecycle_ops kinetum_lifecycle_ops;

/**
 * @brief Immutable module-context identity exposed during cold lifecycle work.
 *
 * String storage remains platform-owned and valid for the lifetime of the
 * lifecycle context. Numeric indices are deterministic within one admitted
 * deployment generation.
 */
typedef struct kinetum_lifecycle_identity {
	const char *module_id;		  ///< Bounded printable-ASCII image identity.
	const char *context_instance_id;  ///< Bounded printable-ASCII context identity.
	uint32_t module_image_index;	  ///< Deterministic loaded-image index.
	uint32_t context_index;		  ///< Deterministic executable-context index.
	uint32_t worker_index;		  ///< Sole owner-worker index.
	int32_t cpu_core_id;		  ///< Exact owner-worker logical CPU.
	int32_t numa_node;		  ///< Exact context NUMA node.
	uint32_t module_context_ordinal;  ///< Generation-fixed ordinal within this module's context population.
	uint32_t module_context_count;	  ///< Exact positive population sharing this module configuration.
} kinetum_lifecycle_identity;

/** Fixed-width cold lifecycle log severity. */
typedef int32_t kinetum_lifecycle_log_level;

/** Cold lifecycle log severity values. */
enum {
	KINETUM_LIFECYCLE_LOG_DEBUG = 0,
	KINETUM_LIFECYCLE_LOG_INFO = 1,
	KINETUM_LIFECYCLE_LOG_WARNING = 2,
	KINETUM_LIFECYCLE_LOG_ERROR = 3,
};

/** Cold lifecycle allocation flags. */
enum {
	KINETUM_LIFECYCLE_ALLOC_ZERO = 1u << 0,
	KINETUM_LIFECYCLE_ALLOC_CACHE_ALIGNED = 1u << 1,
};

/**
 * @brief Opaque platform-owned context supplied only to cold callbacks.
 *
 * Modules may inspect the immutable service-table pointer but must treat
 * platform_opaque as an uninterpreted borrowed value. No live kinetum_ctx is
 * reachable through this shell.
 */
typedef struct kinetum_lifecycle_ctx {
	const kinetum_lifecycle_ops *ops;  ///< Exact cold service-table authority.
	void *platform_opaque;		   ///< Borrowed platform operation state.
} kinetum_lifecycle_ctx;

/**
 * @brief Cold lifecycle services for one exact module-context operation.
 *
 * Every operation is bounded by the platform owner. Allocation, telemetry
 * registration, and logging are unavailable from packet callbacks because the
 * live kinetum_ctx intentionally contains no pointer back to this table.
 */
struct kinetum_lifecycle_ops {
	/**
	 * @brief Resolve immutable identity for this exact operation.
	 *
	 * @param lifecycle Borrowed lifecycle shell.
	 * @param out_identity Output identity written only on success.
	 * @return KINETUM_OK or a precise lifecycle error.
	 */
	kinetum_error (*get_identity)(const kinetum_lifecycle_ctx *lifecycle, kinetum_lifecycle_identity *out_identity);
	/**
	 * @brief Allocate tracked long-lived context memory.
	 *
	 * @param lifecycle Borrowed INIT lifecycle shell.
	 * @param size Positive byte count.
	 * @param alignment Required power-of-two alignment.
	 * @param flags KINETUM_LIFECYCLE_ALLOC_* flags.
	 * @param out_pointer Output pointer written only on success.
	 * @return KINETUM_OK or a precise lifecycle error.
	 */
	kinetum_error (*allocate_context)(const kinetum_lifecycle_ctx *lifecycle, size_t size, size_t alignment,
					  uint32_t flags, void **out_pointer);
	/**
	 * @brief Release one exact tracked context allocation.
	 *
	 * @param lifecycle Borrowed lifecycle shell for the same owner.
	 * @param pointer Exact live allocation to release once.
	 * @return KINETUM_OK or a precise lifecycle error.
	 */
	kinetum_error (*release_context)(const kinetum_lifecycle_ctx *lifecycle, void *pointer);
	/**
	 * @brief Allocate immutable bytes from the exact PREPARE arena.
	 *
	 * @param lifecycle Borrowed PREPARE lifecycle shell.
	 * @param size Positive byte count.
	 * @param alignment Required power-of-two alignment.
	 * @param flags KINETUM_LIFECYCLE_ALLOC_* flags.
	 * @param out_pointer Output pointer written only on success.
	 * @return KINETUM_OK or a precise lifecycle error.
	 */
	kinetum_error (*allocate_epoch)(const kinetum_lifecycle_ctx *lifecycle, size_t size, size_t alignment,
					uint32_t flags, void **out_pointer);
	/**
	 * @brief Register one owner-local counter during INIT.
	 *
	 * @param lifecycle Borrowed INIT lifecycle shell.
	 * @param name Nonempty bounded printable-ASCII identity.
	 * @param out_counter Output handle written only on success.
	 * @return KINETUM_OK or a precise lifecycle error.
	 */
	kinetum_error (*register_counter)(const kinetum_lifecycle_ctx *lifecycle, const char *name,
					  kinetum_counter_t *out_counter);
	/**
	 * @brief Register one owner-local HDR histogram during INIT.
	 *
	 * @param lifecycle Borrowed INIT lifecycle shell.
	 * @param name Nonempty bounded printable-ASCII identity.
	 * @param highest_trackable_value Positive inclusive sample ceiling.
	 * @param significant_digits Supported precision.
	 * @param out_histogram Output handle written only on success.
	 * @return KINETUM_OK or a precise lifecycle error.
	 */
	kinetum_error (*register_histogram)(const kinetum_lifecycle_ctx *lifecycle, const char *name,
					    uint64_t highest_trackable_value, int32_t significant_digits,
					    kinetum_histogram_t *out_histogram);
	/**
	 * @brief Publish one already formatted cold diagnostic.
	 *
	 * The runtime copies at most 8 KiB before return and marks truncation.
	 * ERROR diagnostics bypass suppression and allow a 100 ms file-confirmation
	 * wait; failure or timeout attempts best-effort emergency stderr.
	 * Delivery and filtering never change the lifecycle operation's outcome.
	 * This service is unavailable during packet, activation, and health callbacks.
	 *
	 * @param lifecycle Borrowed lifecycle shell.
	 * @param level KINETUM_LIFECYCLE_LOG_* severity.
	 * @param message Borrowed NUL-terminated message.
	 */
	void (*log)(const kinetum_lifecycle_ctx *lifecycle, kinetum_lifecycle_log_level level, const char *message);
	/**
	 * @brief Read the exact absolute monotonic operation deadline.
	 *
	 * @param lifecycle Borrowed lifecycle shell.
	 * @return Absolute monotonic nanoseconds.
	 */
	uint64_t (*deadline_ns)(const kinetum_lifecycle_ctx *lifecycle);
	/**
	 * @brief Observe cooperative cancellation for this operation.
	 *
	 * @param lifecycle Borrowed lifecycle shell.
	 * @return true after cancellation is published.
	 */
	bool (*cancellation_requested)(const kinetum_lifecycle_ctx *lifecycle);
};

/**
 * @brief Resolve immutable identity for one lifecycle operation.
 *
 * @param lifecycle Borrowed cold lifecycle context.
 * @param out_identity Output identity written only on success.
 * @return KINETUM_OK or a precise lifecycle error.
 */
static KINETUM_ALWAYS_INLINE kinetum_error kinetum_lifecycle_get_identity(const kinetum_lifecycle_ctx *lifecycle,
									  kinetum_lifecycle_identity *out_identity)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->get_identity == NULL ||
	    out_identity == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	return lifecycle->ops->get_identity(lifecycle, out_identity);
}

/**
 * @brief Allocate tracked long-lived context memory.
 *
 * @param lifecycle Borrowed INIT lifecycle context.
 * @param size Positive allocation size.
 * @param alignment Required power-of-two alignment.
 * @param flags KINETUM_LIFECYCLE_ALLOC_* flags.
 * @param out_pointer Output pointer written only on success.
 * @return KINETUM_OK or a precise lifecycle error.
 */
static KINETUM_ALWAYS_INLINE kinetum_error kinetum_lifecycle_allocate_context(const kinetum_lifecycle_ctx *lifecycle,
									      size_t size, size_t alignment,
									      uint32_t flags, void **out_pointer)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->allocate_context == NULL ||
	    out_pointer == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	return lifecycle->ops->allocate_context(lifecycle, size, alignment, flags, out_pointer);
}

/**
 * @brief Release one tracked long-lived context allocation.
 *
 * @param lifecycle Borrowed cold lifecycle context for the same owner.
 * @param pointer Exact live allocation to release once.
 * @return KINETUM_OK or a precise lifecycle error.
 */
static KINETUM_ALWAYS_INLINE kinetum_error kinetum_lifecycle_release_context(const kinetum_lifecycle_ctx *lifecycle,
									     void *pointer)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->release_context == NULL || pointer == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	return lifecycle->ops->release_context(lifecycle, pointer);
}

/**
 * @brief Allocate immutable storage from the exact PREPARE epoch arena.
 *
 * The platform owns and releases the arena with the prepared token. Individual
 * epoch allocations cannot be released or garbage-collected by a module.
 *
 * @param lifecycle Borrowed PREPARE lifecycle context.
 * @param size Positive allocation size.
 * @param alignment Required power-of-two alignment.
 * @param flags KINETUM_LIFECYCLE_ALLOC_* flags.
 * @param out_pointer Output pointer written only on success.
 * @return KINETUM_OK or a precise lifecycle error.
 */
static KINETUM_ALWAYS_INLINE kinetum_error kinetum_lifecycle_allocate_epoch(const kinetum_lifecycle_ctx *lifecycle,
									    size_t size, size_t alignment,
									    uint32_t flags, void **out_pointer)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->allocate_epoch == NULL ||
	    out_pointer == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	return lifecycle->ops->allocate_epoch(lifecycle, size, alignment, flags, out_pointer);
}

/**
 * @brief Register one owner-local counter during INIT.
 *
 * @param lifecycle Borrowed INIT lifecycle context.
 * @param name Nonempty bounded printable-ASCII metric name.
 * @param out_counter Output hot-path handle written only on success.
 * @return KINETUM_OK or a precise lifecycle error.
 */
static KINETUM_ALWAYS_INLINE kinetum_error kinetum_lifecycle_register_counter(const kinetum_lifecycle_ctx *lifecycle,
									      const char *name,
									      kinetum_counter_t *out_counter)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->register_counter == NULL || name == NULL ||
	    out_counter == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	return lifecycle->ops->register_counter(lifecycle, name, out_counter);
}

/**
 * @brief Register one owner-local HDR histogram during INIT.
 *
 * @param lifecycle Borrowed INIT lifecycle context.
 * @param name Nonempty bounded printable-ASCII metric name.
 * @param highest_trackable_value Positive inclusive sample ceiling.
 * @param significant_digits Precision in the supported range.
 * @param out_histogram Output hot-path handle written only on success.
 * @return KINETUM_OK or a precise lifecycle error.
 */
static KINETUM_ALWAYS_INLINE kinetum_error kinetum_lifecycle_register_histogram(const kinetum_lifecycle_ctx *lifecycle,
										const char *name,
										uint64_t highest_trackable_value,
										int32_t significant_digits,
										kinetum_histogram_t *out_histogram)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->register_histogram == NULL || name == NULL ||
	    out_histogram == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	return lifecycle->ops->register_histogram(lifecycle, name, highest_trackable_value, significant_digits,
						  out_histogram);
}

/**
 * @brief Publish one already formatted cold lifecycle message.
 *
 * @param lifecycle Borrowed cold lifecycle context.
 * @param level KINETUM_LIFECYCLE_LOG_* severity.
 * @param message Borrowed NUL-terminated message.
 */
static KINETUM_ALWAYS_INLINE void kinetum_lifecycle_log(const kinetum_lifecycle_ctx *lifecycle,
							kinetum_lifecycle_log_level level, const char *message)
{
	if (lifecycle != NULL && lifecycle->ops != NULL && lifecycle->ops->log != NULL && message != NULL) {
		lifecycle->ops->log(lifecycle, level, message);
	}
}

/**
 * @brief Return the exact monotonic operation deadline.
 *
 * @param lifecycle Borrowed cold lifecycle context.
 * @return Absolute monotonic nanoseconds, or zero for an invalid context.
 */
static KINETUM_ALWAYS_INLINE uint64_t kinetum_lifecycle_deadline_ns(const kinetum_lifecycle_ctx *lifecycle)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->deadline_ns == NULL) {
		return 0;
	}
	return lifecycle->ops->deadline_ns(lifecycle);
}

/**
 * @brief Observe cooperative lifecycle cancellation.
 *
 * Invalid context state fails closed as cancellation.
 *
 * @param lifecycle Borrowed cold lifecycle context.
 * @return true after cancellation publication or for an invalid context.
 */
static KINETUM_ALWAYS_INLINE bool kinetum_lifecycle_cancellation_requested(const kinetum_lifecycle_ctx *lifecycle)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || lifecycle->ops->cancellation_requested == NULL) {
		return true;
	}
	return lifecycle->ops->cancellation_requested(lifecycle);
}

// =============================================================================
// Live Owner-Worker Context
// =============================================================================

/**
 * @brief One cache-line live context owned by exactly one packet worker.
 *
 * The context exposes only mutable module state and immutable placement facts.
 * Cold allocation, logging, registration, and lifecycle services are
 * structurally unreachable from packet execution.
 */
struct KINETUM_ALIGNED kinetum_ctx {
	void *state;		///< Context-local mutable module state.
	int32_t numa_node;	///< Exact owner-worker NUMA node.
	int32_t cpu_core_id;	///< Exact owner-worker logical CPU.
	uint32_t worker_index;	///< Sole owner-worker index.
};

// ============================================================================
// Exact Configuration Lifecycle
// ============================================================================

/**
 * @brief Exact immutable artifact returned by successful PREPARE.
 *
 * Explicit token state, not pointer non-nullness, represents success. Both
 * pointers may be null for a valid no-configuration module.
 */
typedef struct kinetum_prepared_config {
	void *owner_handle;	    ///< Module-owned artifact reclaimed by RETIRE.
	const void *packet_config;  ///< Immutable exact packet-execution view.
} kinetum_prepared_config;

/**
 * @brief Prepare one exact immutable module configuration.
 *
 * @param lifecycle Borrowed cold lifecycle context.
 * @param epoch Exact nonzero epoch being prepared.
 * @param config Opaque module configuration bytes, or NULL when config_len is zero.
 * @param config_len Exact opaque byte count.
 * @param out_prepared Output record written only on success.
 * @return KINETUM_OK on ownership transfer or a precise error with no transfer.
 */
typedef kinetum_error (*kinetum_prepare_config_fn)(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
						   const void *config, size_t config_len,
						   kinetum_prepared_config *out_prepared);

/**
 * @brief Activate one previously prepared exact configuration.
 *
 * This owner-worker callback is bounded and infallible. It may publish pointers
 * into context-local state but may not allocate, parse, block, log, or reclaim.
 *
 * @param ctx Sole-owner live context.
 * @param epoch Exact nonzero epoch being activated.
 * @param prepared Borrowed exact prepared record.
 */
typedef void (*kinetum_activate_config_fn)(kinetum_ctx *ctx, uint64_t epoch, const kinetum_prepared_config *prepared);

/**
 * @brief Retire one exact prepared artifact after quiescence and grace.
 *
 * @param lifecycle Borrowed cold lifecycle context.
 * @param epoch Exact nonzero retired epoch.
 * @param retired Exact ownership record transferred back once.
 */
typedef void (*kinetum_retire_config_fn)(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
					 kinetum_prepared_config retired);

/**
 * @brief Initialize one context before its owner worker launches.
 *
 * @param lifecycle Borrowed INIT lifecycle context.
 * @param out_state Output live-state pointer written only on success; null is valid.
 * @return KINETUM_OK or a precise error with no transferred state.
 */
typedef kinetum_error (*kinetum_init_fn)(const kinetum_lifecycle_ctx *lifecycle, void **out_state);

/**
 * @brief Finalize detached context state after owner-worker join.
 *
 * @param lifecycle Borrowed FINI lifecycle context.
 * @param state Exact state returned by successful INIT; null is valid.
 */
typedef void (*kinetum_fini_fn)(const kinetum_lifecycle_ctx *lifecycle, void *state);

/**
 * @brief Prepare an explicit no-configuration artifact.
 *
 * Only an empty payload is valid. Success writes a null/null prepared record;
 * the successful ownership state is carried by the caller's token, not by
 * pointer non-nullness.
 *
 * @param lifecycle Borrowed PREPARE lifecycle context.
 * @param epoch Exact nonzero epoch.
 * @param config Must be null when @p config_len is zero.
 * @param config_len Must be zero.
 * @param out_prepared Output null/null record written only on success.
 * @return KINETUM_OK or KINETUM_ERR_INVALID_ARG.
 */
static inline kinetum_error kinetum_noop_prepare_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
							const void *config, size_t config_len,
							kinetum_prepared_config *out_prepared)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || epoch == 0 || out_prepared == NULL || config != NULL ||
	    config_len != 0) {
		return KINETUM_ERR_INVALID_ARG;
	}
	out_prepared->owner_handle = NULL;
	out_prepared->packet_config = NULL;
	return KINETUM_OK;
}

/**
 * @brief Activate an explicit no-configuration artifact.
 *
 * @param ctx Sole-owner live context.
 * @param epoch Exact nonzero epoch.
 * @param prepared Borrowed null/null prepared record.
 * @note A malformed activation record is a module-contract violation and
 *       terminates the process.
 */
static inline void kinetum_noop_activate_config(kinetum_ctx *ctx, uint64_t epoch,
						const kinetum_prepared_config *prepared)
{
	if (ctx == NULL || epoch == 0 || prepared == NULL || prepared->owner_handle != NULL ||
	    prepared->packet_config != NULL) {
		abort();
	}
}

/**
 * @brief Retire an explicit no-configuration artifact.
 *
 * @param lifecycle Borrowed RETIRE lifecycle context.
 * @param epoch Exact nonzero retired epoch.
 * @param retired Transferred null/null prepared record.
 * @note A malformed retirement record is a module-contract violation and
 *       terminates the process.
 */
static inline void kinetum_noop_retire_config(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
					      kinetum_prepared_config retired)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || epoch == 0 || retired.owner_handle != NULL ||
	    retired.packet_config != NULL) {
		abort();
	}
}

/**
 * @brief Initialize an explicit stateless context.
 *
 * @param lifecycle Borrowed INIT lifecycle context.
 * @param out_state Output null state written only on success.
 * @return KINETUM_OK or KINETUM_ERR_INVALID_ARG.
 */
static inline kinetum_error kinetum_noop_init(const kinetum_lifecycle_ctx *lifecycle, void **out_state)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || out_state == NULL) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_state = NULL;
	return KINETUM_OK;
}

/**
 * @brief Finalize an explicit stateless context.
 *
 * @param lifecycle Borrowed FINI lifecycle context.
 * @param state Null state returned by kinetum_noop_init().
 * @note A malformed finalization record is a module-contract violation and
 *       terminates the process.
 */
static inline void kinetum_noop_fini(const kinetum_lifecycle_ctx *lifecycle, void *state)
{
	if (lifecycle == NULL || lifecycle->ops == NULL || state != NULL) {
		abort();
	}
}

/**
 * @brief Process one exact configured packet batch on its sole owner worker.
 *
 * @param batch Mutable batch carrying exact context and configuration pointers.
 * @return Sole disposition mask. Bit i set forwards packet i; bit i clear
 *         drops it. Bits at or above batch->count must remain clear.
 */
typedef uint64_t (*kinetum_process_batch_fn)(kinetum_batch_t *batch);

// ============================================================================
// Module Health
// ============================================================================

/** Module health flags. */
enum {
	KINETUM_HEALTH_F_OK = 0x0000,
	KINETUM_HEALTH_F_DEGRADED = 0x0001,
	KINETUM_HEALTH_F_CRITICAL = 0x0002,
	KINETUM_HEALTH_F_CONFIG_ISSUE = 0x0100,
};

/** Complete health flag set accepted by the owner-worker publisher. */
#define KINETUM_HEALTH_F_KNOWN_MASK \
	(KINETUM_HEALTH_F_DEGRADED | KINETUM_HEALTH_F_CRITICAL | KINETUM_HEALTH_F_CONFIG_ISSUE)

/** Fixed capacity of a module-owned health reason, including its NUL. */
#define KINETUM_HEALTH_REASON_CAPACITY 40u

/**
 * @brief Fixed module-owned health assessment.
 *
 * A null callback means health is unavailable; the platform never synthesizes
 * a healthy assessment for an unimplemented callback. Epoch and collection
 * time are platform-owned provenance and therefore do not appear here. The
 * owner validates score, known flags, and reason termination before publication.
 */
typedef struct kinetum_health_assessment {
	uint8_t health_score;			      ///< Domain score in the inclusive range 0..100.
	uint8_t _padding[3];			      ///< Fixed ABI padding.
	uint32_t flags;				      ///< KINETUM_HEALTH_F_* bit mask.
	char reason[KINETUM_HEALTH_REASON_CAPACITY];  ///< Bounded NUL-terminated diagnostic.
} kinetum_health_assessment;

/**
 * @brief Fixed coherent owner-worker health publication.
 *
 * The platform composes this record after a callback returns by pairing the
 * module assessment with the exact owner-worker epoch and cached collection
 * time. Modules never write publication provenance.
 */
typedef struct KINETUM_ALIGNED kinetum_health_signal {
	kinetum_health_assessment assessment;  ///< Exact module-owned assessment.
	uint64_t epoch;			       ///< Platform-stamped exact active epoch.
	uint64_t timestamp_ns;		       ///< Platform-stamped monotonic collection time.
} kinetum_health_signal;

/**
 * @brief Produce health for one exact active owner-worker view.
 *
 * @param ctx Sole-owner live context.
 * @param active_epoch Exact active epoch.
 * @param active_packet_config Borrowed exact immutable active configuration.
 * @return Fixed module-owned assessment for platform publication.
 */
typedef kinetum_health_assessment (*kinetum_health_check_fn)(kinetum_ctx *ctx, uint64_t active_epoch,
							     const void *active_packet_config);

// =============================================================================
// Module Descriptor
// =============================================================================

/** Fixed-width module execution mode. */
typedef int32_t kinetum_module_mode;

/** Module execution-mode values. */
enum {
	KINETUM_MODULE_PASSIVE = 0,
	KINETUM_MODULE_ACTIVE = 1,
};

/** Module supports distinct mutable contexts for one loaded image. */
#define KINETUM_MOD_F_REPLICABLE_CONTEXTS (1u << 0)

/** Module satisfies the exact PREPARE/ACTIVATE/RETIRE transition contract. */
#define KINETUM_MOD_F_LIVE_EPOCH_TRANSITION (1u << 1)

/**
 * @brief Module routes every foreign epoch reference through exact tracked-work
 * tokens, completion delivery, cancellation, and worker-ledger ownership.
 */
#define KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK (1u << 2)

/** Module owns stateless batched selection of its admitted packet contexts. */
#define KINETUM_MOD_F_CONTEXT_SELECTION (1u << 3)

/** Complete module flag set admitted by this ABI revision. */
#define KINETUM_MOD_F_KNOWN_MASK                                                   \
	(KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION | \
	 KINETUM_MOD_F_TRACKED_ASYNC_EPOCH_WORK | KINETUM_MOD_F_CONTEXT_SELECTION)

/** Active-stage trigger mask bits. */
enum {
	KINETUM_TRIGGER_LOOP = 1u << 0,		   ///< Authored per-turn active work.
	KINETUM_TRIGGER_TIMER = 1u << 1,	   ///< Authored timer expiry work.
	KINETUM_TRIGGER_PULL_READY = 1u << 2,	   ///< Authored pending PULL work.
	KINETUM_TRIGGER_CONTROL = 1u << 3,	   ///< Authored copied-control work.
	KINETUM_TRIGGER_DRAIN = 1u << 4,	   ///< Platform transition/shutdown drain.
	KINETUM_TRIGGER_ASYNC_COMPLETE = 1u << 5,  ///< Platform tracked-completion delivery.
};

/** Trigger bits an authored Axiom active-stage mask may contain. */
#define KINETUM_AUTHORED_ACTIVE_TRIGGER_MASK \
	(KINETUM_TRIGGER_LOOP | KINETUM_TRIGGER_TIMER | KINETUM_TRIGGER_PULL_READY | KINETUM_TRIGGER_CONTROL)

/** Active-context state bits supplied only by the owner worker. */
enum {
	KINETUM_ACTIVE_CTX_F_TRANSITION_DRAIN = 1u << 0,
	KINETUM_ACTIVE_CTX_F_SHUTDOWN_DRAIN = 1u << 1,
};

/** Invalid raw value for an opaque retained-packet handle. */
#define KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE UINT64_MAX

/** Invalid raw value for an opaque active-timer handle. */
#define KINETUM_INVALID_ACTIVE_TIMER_HANDLE_VALUE UINT64_MAX

/** Invalid raw value for an opaque asynchronous-work handle. */
#define KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE UINT64_MAX

/** @brief Opaque generation-checked ownership of one retained packet record. */
typedef struct kinetum_retained_packet_handle {
	uint64_t value;	 ///< Runtime-owned slot and reuse generation.
} kinetum_retained_packet_handle;

/** @brief Opaque generation-checked ownership of one owner-local timer. */
typedef struct kinetum_active_timer_handle {
	uint64_t value;	 ///< Runtime-owned slot and reuse generation.
} kinetum_active_timer_handle;

/** @brief Opaque generation-checked ownership of one foreign work operation. */
typedef struct kinetum_async_work_handle {
	uint64_t value;	 ///< Runtime-owned slot and reuse generation.
} kinetum_async_work_handle;

/** Fixed-width terminal outcome reported by a foreign completion producer. */
typedef int32_t kinetum_async_outcome;

/** Exact terminal foreign-completion outcomes. */
enum {
	KINETUM_ASYNC_OUTCOME_UNSPECIFIED = 0,	///< Invalid/nonterminal sentinel.
	KINETUM_ASYNC_OUTCOME_SUCCESS = 1,	///< Foreign operation completed successfully.
	KINETUM_ASYNC_OUTCOME_CANCELLED = 2,	///< Foreign operation completed cancellation.
	KINETUM_ASYNC_OUTCOME_FAILED = 3,	///< Foreign operation completed with failure.
};

/**
 * @brief Read-only packet bytes transferred with one packet-bound async token.
 *
 * The view remains valid until exact terminal completion publication or a
 * successful pre-transfer abort. Foreign code must not mutate these bytes.
 */
typedef struct kinetum_async_packet_view {
	const void *data;   ///< Stable borrowed packet bytes.
	uint32_t len;	    ///< Exact readable byte count.
	uint32_t _padding;  ///< Fixed ABI padding; always zero.
} kinetum_async_packet_view;

struct kinetum_async_token;

/**
 * @brief Publish one exact terminal outcome from a foreign completion thread.
 * @param token Exact copied foreign-operation capability.
 * @param outcome One non-UNSPECIFIED terminal outcome.
 * @return true only for the sole winning terminal publication.
 */
typedef bool (*kinetum_async_complete_fn)(const struct kinetum_async_token *token, kinetum_async_outcome outcome);

/**
 * @brief Observe exact transition/shutdown cancellation from a foreign thread.
 * @param token Exact copied foreign-operation capability.
 * @return true for cancellation, a stale token, or malformed capability.
 */
typedef bool (*kinetum_async_cancellation_requested_fn)(const struct kinetum_async_token *token);

/** @brief Stable foreign-thread operation table carried by every exact token. */
typedef struct kinetum_async_token_ops {
	kinetum_async_complete_fn complete;				 ///< Exact terminal publication.
	kinetum_async_cancellation_requested_fn cancellation_requested;	 ///< Exact cancellation query.
} kinetum_async_token_ops;

/**
 * @brief Copyable exact capability transferred to one foreign operation.
 *
 * Modules treat all fields as opaque and call only the header-defined helpers.
 * The platform owner outlives every unresolved token.
 */
typedef struct kinetum_async_token {
	kinetum_async_work_handle handle;    ///< Exact slot/reuse identity.
	const kinetum_async_token_ops *ops;  ///< Stable foreign completion authority.
	void *platform_opaque;		     ///< Stable exact runtime-generation portal.
} kinetum_async_token;

/** @brief One owner-worker delivery after exact foreign terminal publication. */
typedef struct kinetum_async_completion {
	kinetum_async_work_handle handle;	  ///< Completed exact token identity.
	kinetum_retained_packet_handle retained;  ///< Restored packet handle, or invalid.
	uint64_t user_tag;			  ///< Module-supplied correlation value.
	kinetum_async_outcome outcome;		  ///< Exact terminal foreign outcome.
	uint32_t _padding;			  ///< Fixed ABI padding; always zero.
} kinetum_async_completion;

/**
 * @brief Validate one complete copied foreign-operation capability.
 * @param token Candidate copied token.
 * @return true only for one complete exact token representation.
 */
static KINETUM_ALWAYS_INLINE bool kinetum_async_token_valid(const kinetum_async_token *token)
{
	return token != NULL && token->handle.value != KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE && token->ops != NULL &&
	       token->ops->complete != NULL && token->ops->cancellation_requested != NULL &&
	       token->platform_opaque != NULL;
}

/**
 * @brief Publish one terminal result from the exact foreign operation.
 * @param token Exact copied foreign-operation capability.
 * @param outcome One non-UNSPECIFIED terminal outcome.
 * @return true only when this token wins its sole terminal publication.
 */
static KINETUM_ALWAYS_INLINE bool kinetum_async_complete(const kinetum_async_token *token,
							 kinetum_async_outcome outcome)
{
	if (!kinetum_async_token_valid(token) || outcome <= KINETUM_ASYNC_OUTCOME_UNSPECIFIED ||
	    outcome > KINETUM_ASYNC_OUTCOME_FAILED) {
		return false;
	}
	return token->ops->complete(token, outcome);
}

/**
 * @brief Observe cancellation or stale identity for one copied token.
 * @param token Candidate copied foreign-operation capability.
 * @return true for requested cancellation, stale identity, or malformed input.
 */
static KINETUM_ALWAYS_INLINE bool kinetum_async_cancellation_requested(const kinetum_async_token *token)
{
	return !kinetum_async_token_valid(token) || token->ops->cancellation_requested(token);
}

/** @brief Platform-defined active control edge subtype values. */
enum {
	KINETUM_CONTROL_SUBTYPE_GENERIC = 0u,	///< General command/control edge.
	KINETUM_CONTROL_SUBTYPE_FEEDBACK = 1u,	///< Latency-sensitive feedback edge.
};

/** @brief One opaque control message delivered to an active stage. */
typedef struct kinetum_control_msg {
	const void *data;  ///< Borrowed message bytes.
	uint32_t len;	   ///< Exact byte count.
	uint32_t subtype;  ///< Exact KINETUM_CONTROL_SUBTYPE_* edge classification.
} kinetum_control_msg;

/** Forward declaration for active service callback signatures. */
struct kinetum_active_ctx;
struct kinetum_active_runtime_services;

/**
 * @brief Begin one standalone foreign operation under a new exact ledger credit.
 * @param services Exact callback-borrowed service shell.
 * @param user_tag Module correlation value echoed at completion.
 * @return Exact foreign token or the fixed invalid representation.
 */
typedef kinetum_async_token (*kinetum_active_begin_async_fn)(struct kinetum_active_runtime_services *services,
							     uint64_t user_tag);

/**
 * @brief Transfer one retained packet into foreign read-only ownership.
 * @param services Exact callback-borrowed service shell.
 * @param retained Exact live retained handle invalidated on success.
 * @param user_tag Module correlation value echoed at completion.
 * @param out_view Read-only packet view written only on success.
 * @return Exact foreign token or the fixed invalid representation.
 */
typedef kinetum_async_token (*kinetum_active_begin_async_retained_fn)(struct kinetum_active_runtime_services *services,
								      kinetum_retained_packet_handle retained,
								      uint64_t user_tag,
								      kinetum_async_packet_view *out_view);

/**
 * @brief Abort one token after synchronous foreign-submit refusal.
 * @param services Exact callback-borrowed service shell.
 * @param token Exact token that has not entered foreign completion ownership.
 * @param out_retained Restored new-generation retained handle, or invalid for standalone work.
 * @return true only when exact ownership is restored or retired.
 */
typedef bool (*kinetum_active_abort_async_fn)(struct kinetum_active_runtime_services *services,
					      kinetum_async_token token, kinetum_retained_packet_handle *out_retained);

/**
 * @brief Transfer one retained packet into same-instance recirculation ownership.
 * @param services Exact callback-borrowed service shell.
 * @param retained Exact live retained handle invalidated on success.
 * @return true only after bounded same-instance staging accepts ownership.
 */
typedef bool (*kinetum_active_recirculate_retained_fn)(struct kinetum_active_runtime_services *services,
						       kinetum_retained_packet_handle retained);

/**
 * @brief Typed active-runtime services reached through one callback context.
 *
 * The shell is borrowed only for the current owner-worker callback. Modules use
 * the header-defined helpers below and never inspect platform_opaque. Foreign
 * threads retain only kinetum_async_token, whose portal has generation lifetime.
 */
typedef struct kinetum_active_runtime_services {
	const kinetum_async_completion *completions;		      ///< Borrowed exact completed prefix for RUN.
	uint32_t completion_count;				      ///< Exact entries in completions.
	uint32_t _padding;					      ///< Fixed ABI padding; always zero.
	kinetum_active_begin_async_fn begin_async;		      ///< Begin standalone tracked work.
	kinetum_active_begin_async_retained_fn begin_async_retained;  ///< Transfer retained work.
	kinetum_active_abort_async_fn abort_async;		      ///< Undo pre-transfer submission.
	kinetum_active_recirculate_retained_fn recirculate_retained;  ///< Same-instance recirculation.
	void *platform_opaque;					      ///< Exact private invocation owner.
} kinetum_active_runtime_services;

/**
 * @brief Copy and dispatch one valid active-origin prefix.
 * @param ctx Exact callback-borrowed active context.
 * @param batch Complete module-owned origin batch.
 * @return Exact accepted prefix copied into platform packet ownership.
 */
typedef uint32_t (*kinetum_active_emit_fn)(struct kinetum_active_ctx *ctx, const kinetum_emit_batch_t *batch);

/**
 * @brief Provisionally retain one lane from the current active-ingest batch.
 * @param ctx Exact callback-borrowed active context.
 * @param lane Occupied lane in the current INGEST batch. An index outside
 *        that prefix returns an invalid handle without transfer.
 * @return Exact opaque handle, or the fixed invalid value without transfer.
 */
typedef kinetum_retained_packet_handle (*kinetum_active_retain_input_fn)(struct kinetum_active_ctx *ctx, uint32_t lane);

/**
 * @brief Transfer one retained handle into exact platform dispatch ownership.
 * @param ctx Exact callback-borrowed active context.
 * @param handle Exact live context-bound retained handle.
 * @param next_stage Logical target stage or KINETUM_NEXT_STAGE_UNSET.
 * @return true only after platform pending-dispatch ownership accepts the handle.
 */
typedef bool (*kinetum_active_emit_retained_fn)(struct kinetum_active_ctx *ctx, kinetum_retained_packet_handle handle,
						uint16_t next_stage);

/**
 * @brief Transfer one retained handle into exact terminal-drop ownership.
 * @param ctx Exact callback-borrowed active context.
 * @param handle Exact live context-bound retained handle.
 * @return true only after platform pending-drop ownership accepts the handle.
 */
typedef bool (*kinetum_active_drop_retained_fn)(struct kinetum_active_ctx *ctx, kinetum_retained_packet_handle handle);

/**
 * @brief Arm one owner-local timer after an exact positive nanosecond delay.
 * @param ctx Exact callback-borrowed active context.
 * @param delay_ns Relative delay rounded up to the runtime wheel quantum.
 * @return Exact opaque timer handle, or the fixed invalid value without ownership.
 */
typedef kinetum_active_timer_handle (*kinetum_active_arm_timer_fn)(struct kinetum_active_ctx *ctx, uint64_t delay_ns);

/**
 * @brief Cancel one exact owner-local timer before expiry transfer.
 * @param ctx Exact callback-borrowed active context.
 * @param handle Exact currently armed timer handle.
 * @return true only when cancellation consumed the timer and its credit.
 */
typedef bool (*kinetum_active_cancel_timer_fn)(struct kinetum_active_ctx *ctx, kinetum_active_timer_handle handle);

/**
 * @brief Copy one bounded same-worker control message.
 * @param ctx Exact callback-borrowed active context.
 * @param peer_idx Exact destination stage-instance index.
 * @param message Complete borrowed message whose subtype equals the authored edge.
 * @return true only when one declared edge and destination cell accept it.
 */
typedef bool (*kinetum_active_post_control_fn)(struct kinetum_active_ctx *ctx, uint16_t peer_idx,
					       const kinetum_control_msg *message);

/**
 * @brief Publish one deduplicated same-worker upstream PULL request.
 * @param ctx Exact callback-borrowed active context.
 * @param upstream_idx Exact source stage-instance index.
 * @return true when the declared request bit is newly set or already pending.
 */
typedef bool (*kinetum_active_request_pull_fn)(struct kinetum_active_ctx *ctx, uint16_t upstream_idx);

/**
 * @brief Exact owner-worker view supplied to one active-stage callback.
 *
 * All pointers are borrowed for the current callback only. Handles are the
 * sole module-visible ownership identities for work retained across callbacks;
 * no service exposes a packet record or provider-native handle. The runtime
 * writes every field before callback entry and validates every service against
 * the exact current stage instance.
 */
typedef struct kinetum_active_ctx {
	uint64_t now_ns;				       ///< Worker-cached monotonic loop time in nanoseconds.
	uint64_t active_epoch;				       ///< Exact active epoch for callback work.
	const void *active_packet_config;		       ///< Exact immutable active configuration.
	uint64_t drain_target_epoch;			       ///< Exact target epoch; zero outside transition drain.
	const kinetum_active_timer_handle *expired;	       ///< Borrowed bounded expiry/drain prefix.
	const kinetum_retained_packet_handle *drain_retained;  ///< Borrowed drain-visible live prefix.
	uint32_t expired_count;				       ///< Number of exact entries in expired.
	uint32_t drain_retained_count;			       ///< Number of exact entries in drain_retained.
	uint32_t region_id;				       ///< Exact owning logical-region identity.
	uint32_t state_flags;				       ///< KINETUM_ACTIVE_CTX_F_* exact state.
	kinetum_active_emit_fn emit;			       ///< Copy and dispatch one valid origin prefix.
	kinetum_active_retain_input_fn retain_input;	       ///< Retain one current ingest lane.
	kinetum_active_emit_retained_fn emit_retained;	       ///< Submit one retained packet for dispatch.
	kinetum_active_drop_retained_fn drop_retained;	       ///< Submit one retained packet for drop.
	kinetum_active_arm_timer_fn arm_timer_after;	       ///< Arm one owner-local relative timer.
	kinetum_active_cancel_timer_fn cancel_timer;	       ///< Cancel one exact live timer.
	kinetum_active_post_control_fn post_control;	       ///< Copy one bounded same-worker message.
	kinetum_active_request_pull_fn request_pull;	       ///< Publish one exact upstream request.
	kinetum_active_runtime_services *runtime_services;     ///< Borrowed typed scheduler services.
} kinetum_active_ctx;

/** @brief Construct the fixed invalid token representation. @return Fixed invalid token representation. */
static KINETUM_ALWAYS_INLINE kinetum_async_token kinetum_invalid_async_token(void)
{
	kinetum_async_token token = {{KINETUM_INVALID_ASYNC_WORK_HANDLE_VALUE}, NULL, NULL};
	return token;
}

/**
 * @brief Begin one standalone exact foreign operation from an active callback.
 * @param ctx Exact callback-borrowed active context.
 * @param user_tag Module correlation value echoed at completion.
 * @return Exact token, or the fixed invalid representation without ownership.
 */
static KINETUM_ALWAYS_INLINE kinetum_async_token kinetum_active_begin_async(kinetum_active_ctx *ctx, uint64_t user_tag)
{
	if (ctx == NULL || ctx->runtime_services == NULL || ctx->runtime_services->begin_async == NULL) {
		return kinetum_invalid_async_token();
	}
	return ctx->runtime_services->begin_async(ctx->runtime_services, user_tag);
}

/**
 * @brief Transfer one retained packet to one exact foreign operation.
 * @param ctx Exact callback-borrowed active context.
 * @param retained Exact live retained handle invalidated on success.
 * @param user_tag Module correlation value echoed at completion.
 * @param[out] out_view Read-only packet view, cleared before any refusal.
 * @return Exact token, or the fixed invalid representation without transfer.
 */
static KINETUM_ALWAYS_INLINE kinetum_async_token
kinetum_active_begin_async_retained(kinetum_active_ctx *ctx, kinetum_retained_packet_handle retained, uint64_t user_tag,
				    kinetum_async_packet_view *out_view)
{
	if (out_view != NULL) {
		out_view->data = NULL;
		out_view->len = 0u;
		out_view->_padding = 0u;
	}
	if (ctx == NULL || ctx->runtime_services == NULL || ctx->runtime_services->begin_async_retained == NULL ||
	    out_view == NULL) {
		return kinetum_invalid_async_token();
	}
	return ctx->runtime_services->begin_async_retained(ctx->runtime_services, retained, user_tag, out_view);
}

/**
 * @brief Abort one pre-transfer token and restore any packet-bound ownership.
 * @param ctx Exact callback-borrowed active context.
 * @param token Exact token not yet transferred to foreign completion ownership.
 * @param[out] out_retained Restored fresh handle, or invalid for standalone work/refusal.
 * @return true only after exact ownership is restored or retired.
 */
static KINETUM_ALWAYS_INLINE bool kinetum_active_abort_async(kinetum_active_ctx *ctx, kinetum_async_token token,
							     kinetum_retained_packet_handle *out_retained)
{
	if (out_retained != NULL) {
		out_retained->value = KINETUM_INVALID_RETAINED_PACKET_HANDLE_VALUE;
	}
	return ctx != NULL && ctx->runtime_services != NULL && ctx->runtime_services->abort_async != NULL &&
	       out_retained != NULL && ctx->runtime_services->abort_async(ctx->runtime_services, token, out_retained);
}

/**
 * @brief Transfer one retained packet to same-instance recirculation.
 * @param ctx Exact callback-borrowed active context.
 * @param retained Exact live retained handle invalidated on success.
 * @return true only after bounded local staging accepts ownership.
 */
static KINETUM_ALWAYS_INLINE bool kinetum_active_recirculate_retained(kinetum_active_ctx *ctx,
								      kinetum_retained_packet_handle retained)
{
	return ctx != NULL && ctx->runtime_services != NULL && ctx->runtime_services->recirculate_retained != NULL &&
	       ctx->runtime_services->recirculate_retained(ctx->runtime_services, retained);
}

/**
 * @brief Return the exact borrowed foreign-completion prefix for this RUN callback.
 * @param ctx Exact callback-borrowed active context.
 * @param[out] out_count Exact returned prefix length; cleared on refusal.
 * @return Borrowed immutable prefix, or null when no completion is delivered.
 */
static KINETUM_ALWAYS_INLINE const kinetum_async_completion *
kinetum_active_async_completions(const kinetum_active_ctx *ctx, uint32_t *out_count)
{
	if (out_count == NULL) {
		return NULL;
	}
	*out_count = 0u;
	if (ctx == NULL || ctx->runtime_services == NULL) {
		return NULL;
	}
	*out_count = ctx->runtime_services->completion_count;
	return ctx->runtime_services->completions;
}

/**
 * @brief Ingest one configured batch into an active stage.
 *
 * @param ctx Sole-owner live context.
 * @param active_ctx Exact active scheduling and ownership services.
 * @param batch Exact configured packet batch.
 * @return Sole disposition mask: set bits continue through runtime dispatch;
 *         clear bits drop. The callback never acquires packet-record ownership.
 */
typedef uint64_t (*kinetum_ingest_fn)(kinetum_ctx *ctx, kinetum_active_ctx *active_ctx, kinetum_batch_t *batch);

/**
 * @brief Run one active-stage scheduling turn.
 *
 * @param ctx Sole-owner live context.
 * @param active_ctx Exact active scheduling view.
 * @param triggers KINETUM_TRIGGER_* reasons for this turn.
 */
typedef void (*kinetum_run_fn)(kinetum_ctx *ctx, kinetum_active_ctx *active_ctx, uint32_t triggers);

/**
 * @brief Deliver one control message to an active stage.
 *
 * @param ctx Sole-owner live context.
 * @param active_ctx Exact active scheduling and ownership services.
 * @param message Borrowed exact control message.
 */
typedef void (*kinetum_on_control_fn)(kinetum_ctx *ctx, kinetum_active_ctx *active_ctx,
				      const kinetum_control_msg *message);

/**
 * @brief Read-only flow facts supplied to one stateless context selector.
 *
 * Only the occupied prefix is observable. The platform owns this transient
 * SoA projection; the callback cannot retain or modify it. No packet bytes,
 * mutable module context, provider handle, or per-epoch configuration is
 * exposed. Every selection uses the same generation-fixed context population.
 */
typedef struct KINETUM_ALIGNED kinetum_context_selection_batch {
	KINETUM_ALIGNAS(64) uint32_t src_ip[KINETUM_MAX_BURST];		 ///< Source IPv4 values.
	KINETUM_ALIGNAS(64) uint32_t dst_ip[KINETUM_MAX_BURST];		 ///< Destination IPv4 values.
	KINETUM_ALIGNAS(64) uint32_t platform_flags[KINETUM_MAX_BURST];	 ///< Parser facts.
	KINETUM_ALIGNAS(64) uint32_t flow_hash[KINETUM_MAX_BURST];	 ///< Current flow hashes.
	KINETUM_ALIGNAS(64) uint16_t src_port[KINETUM_MAX_BURST];	 ///< Source transport ports.
	KINETUM_ALIGNAS(64) uint16_t dst_port[KINETUM_MAX_BURST];	 ///< Destination transport ports.
	KINETUM_ALIGNAS(64) uint16_t input_port[KINETUM_MAX_BURST];	 ///< Immutable logical ingress ports.
	KINETUM_ALIGNAS(64) uint8_t proto[KINETUM_MAX_BURST];		 ///< IP protocols.
	uint16_t count;							 ///< Occupied prefix length.
	uint8_t padding[62];						 ///< Zero layout padding.
} kinetum_context_selection_batch;

/**
 * @brief Immutable context population and exact permitted destination set.
 *
 * The platform derives both views from one admitted membership. Ordinals are
 * strictly increasing and below context_count. The bitmap contains exactly
 * those ordinals, in ceil(context_count / 64) words; unused high bits are zero.
 * The callback borrows these views only for its invocation.
 */
typedef struct kinetum_context_selection_targets {
	uint32_t context_count;		     ///< Positive module-wide context population.
	uint32_t permitted_count;	     ///< Positive destination count for this logical edge.
	const uint32_t *permitted_ordinals;  ///< Sorted admitted context ordinals.
	const uint64_t *permitted_bitmap;    ///< Constant-time membership bits indexed by context ordinal.
} kinetum_context_selection_targets;

/**
 * @brief Test exact context membership in a borrowed selection target set.
 * @param targets Borrowed admitted target view.
 * @param ordinal Candidate module-scoped context ordinal.
 * @return true only when the ordinal is in range and its membership bit is set.
 */
static KINETUM_ALWAYS_INLINE bool kinetum_context_is_permitted(const kinetum_context_selection_targets *targets,
							       uint32_t ordinal)
{
	return targets != NULL && targets->permitted_bitmap != NULL && ordinal < targets->context_count &&
	       (targets->permitted_bitmap[ordinal / 64u] & (UINT64_C(1) << (ordinal % 64u))) != 0u;
}

/**
 * @brief Select admitted contexts without accessing mutable module state.
 *
 * Different packet workers may invoke this callback concurrently.
 * The callback is pure packet-path work: no allocation, locks, I/O, logging,
 * clocks, exceptions, or retained references. A set return bit admits its
 * input lane and requires one permitted ordinal in selected_contexts[i]. A
 * clear bit rejects that lane. Out-of-prefix bits, input mutation, or an
 * unpermitted accepted ordinal are module ABI violations.
 *
 * @param batch Borrowed immutable occupied flow-fact prefix.
 * @param targets Borrowed immutable generation and edge membership.
 * @param selected_contexts Caller-owned output with room for batch->count ordinals.
 * @return Sole admission mask for the occupied prefix.
 */
typedef uint64_t (*kinetum_select_contexts_fn)(const kinetum_context_selection_batch *batch,
					       const kinetum_context_selection_targets *targets,
					       uint32_t *selected_contexts);

/**
 * @brief Sole module code-image descriptor exported by kinetum_module_register.
 *
 * Lifecycle and initialization callbacks are mandatory. Mode-specific packet
 * callbacks are validated exactly; the explicit mode and flags are the sole
 * capability authorities.
 */
typedef struct kinetum_module {
	const char *module_id;			     ///< Bounded printable-ASCII semantic identity.
	const char *module_version;		     ///< Bounded printable-ASCII release string.
	uint32_t abi_version;			     ///< Exact KINETUM_MODULE_ABI_VERSION.
	uint32_t flags;				     ///< KINETUM_MOD_F_* capabilities.
	kinetum_module_mode mode;		     ///< Explicit execution mode.
	kinetum_prepare_config_fn prepare_config;    ///< Mandatory cold PREPARE.
	kinetum_activate_config_fn activate_config;  ///< Mandatory owner ACTIVATE.
	kinetum_retire_config_fn retire_config;	     ///< Mandatory cold RETIRE.
	kinetum_process_batch_fn process;	     ///< Required only for PASSIVE.
	kinetum_ingest_fn ingest;		     ///< Optional ACTIVE push input.
	kinetum_run_fn run;			     ///< Required only for ACTIVE.
	kinetum_on_control_fn on_control;	     ///< Optional ACTIVE control.
	kinetum_init_fn init;			     ///< Mandatory pre-worker INIT.
	kinetum_fini_fn fini;			     ///< Mandatory post-worker FINI.
	kinetum_health_check_fn health_check;	     ///< Optional owner-worker health.
	kinetum_select_contexts_fn select_contexts;  ///< Required exactly when context selection is declared.
} kinetum_module;

/**
 * @brief Resolve the sole descriptor exported by a module image.
 *
 * @return Immutable descriptor borrowed while this image's loader handle
 *         remains open, or null for an invalid image.
 */
KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void);

// ============================================================================
// ABI Layout Contract
// ============================================================================

/** @cond INTERNAL_ABI_ASSERTIONS */

#if defined(__cplusplus)
#define KINETUM_ABI_STATIC_ASSERT(condition, message) static_assert((condition), message)
#define KINETUM_ABI_ALIGNOF(type) alignof(type)
#define KINETUM_ABI_ASSERT_LAYOUT(type, alignment, byte_size)                                            \
	static_assert(std::is_standard_layout_v<type>, #type " must remain standard-layout");            \
	KINETUM_ABI_STATIC_ASSERT(KINETUM_ABI_ALIGNOF(type) == (alignment), #type " alignment changed"); \
	KINETUM_ABI_STATIC_ASSERT(sizeof(type) == (byte_size), #type " size changed")
#else
#define KINETUM_ABI_STATIC_ASSERT(condition, message) _Static_assert((condition), message)
#define KINETUM_ABI_ALIGNOF(type) _Alignof(type)
#define KINETUM_ABI_ASSERT_LAYOUT(type, alignment, byte_size)                                            \
	KINETUM_ABI_STATIC_ASSERT(KINETUM_ABI_ALIGNOF(type) == (alignment), #type " alignment changed"); \
	KINETUM_ABI_STATIC_ASSERT(sizeof(type) == (byte_size), #type " size changed")
#endif

#define KINETUM_ABI_ASSERT_OFFSET(type, member, byte_offset) \
	KINETUM_ABI_STATIC_ASSERT(offsetof(type, member) == (byte_offset), #type "." #member " offset changed")

KINETUM_ABI_STATIC_ASSERT(sizeof(void *) == 8, "Kinetum module ABI requires 64-bit pointers");
KINETUM_ABI_STATIC_ASSERT(sizeof(bool) == 1, "Kinetum module ABI requires one-byte bool");
KINETUM_ABI_STATIC_ASSERT(sizeof(kinetum_error) == 4, "kinetum_error width changed");
KINETUM_ABI_STATIC_ASSERT(sizeof(kinetum_module_mode) == 4, "kinetum_module_mode width changed");
KINETUM_ABI_ASSERT_LAYOUT(kinetum_batch_t, 64, 4224);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, data, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, len, 512);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, l3_off, 768);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, l4_off, 896);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, src_ip, 1024);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, dst_ip, 1280);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, src_port, 1536);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, dst_port, 1664);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, proto, 1792);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, dscp, 1856);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, platform_flags, 1920);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, user_flags, 2176);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, flow_hash, 2432);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, input_port, 2688);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, output_port, 2816);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, next_stage, 2944);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, ts_ns, 3072);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, user_meta, 3584);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, user_meta_valid, 4096);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, count, 4160);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, region_id, 4162);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, padding, 4164);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, epoch, 4168);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, epoch_config, 4176);
KINETUM_ABI_ASSERT_OFFSET(kinetum_batch_t, ctx, 4184);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_emit_batch_t, 64, 4224);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, data, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, len, 512);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, l3_off, 768);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, l4_off, 896);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, src_ip, 1024);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, dst_ip, 1280);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, src_port, 1536);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, dst_port, 1664);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, proto, 1792);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, dscp, 1856);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, platform_flags, 1920);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, user_flags, 2176);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, flow_hash, 2432);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, input_port, 2688);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, output_port, 2816);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, next_stage, 2944);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, ts_ns, 3072);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, user_meta, 3584);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, user_meta_valid, 4096);
KINETUM_ABI_ASSERT_OFFSET(kinetum_emit_batch_t, count, 4160);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_counter, 64, 64);
KINETUM_ABI_ASSERT_OFFSET(kinetum_counter, value, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_counter, name, 8);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_histogram, 64, 192);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, highest_trackable_value, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, total_count, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, min_value, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, max_value, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, sum, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, counts, 40);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, counts_len, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, significant_digits, 52);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, unit_magnitude, 56);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, sub_bucket_half_count_magnitude, 60);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, sub_bucket_count, 64);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, sub_bucket_half_count, 68);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, sub_bucket_mask, 72);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, bucket_count, 76);
KINETUM_ABI_ASSERT_OFFSET(kinetum_histogram, name, 80);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_percentiles, 8, 64);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, p50, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, p90, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, p99, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, p999, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, max, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, min, 40);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, count, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_percentiles, sum, 56);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_lifecycle_identity, 8, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, module_id, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, context_instance_id, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, module_image_index, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, context_index, 20);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, worker_index, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, cpu_core_id, 28);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, numa_node, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, module_context_ordinal, 36);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_identity, module_context_count, 40);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_lifecycle_ops, 8, 72);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, get_identity, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, allocate_context, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, release_context, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, allocate_epoch, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, register_counter, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, register_histogram, 40);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, log, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, deadline_ns, 56);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ops, cancellation_requested, 64);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_lifecycle_ctx, 8, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ctx, ops, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_lifecycle_ctx, platform_opaque, 8);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_ctx, 64, 64);
KINETUM_ABI_ASSERT_OFFSET(kinetum_ctx, state, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_ctx, numa_node, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_ctx, cpu_core_id, 12);
KINETUM_ABI_ASSERT_OFFSET(kinetum_ctx, worker_index, 16);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_prepared_config, 8, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_prepared_config, owner_handle, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_prepared_config, packet_config, 8);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_health_assessment, 4, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_health_assessment, health_score, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_health_assessment, _padding, 1);
KINETUM_ABI_ASSERT_OFFSET(kinetum_health_assessment, flags, 4);
KINETUM_ABI_ASSERT_OFFSET(kinetum_health_assessment, reason, 8);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_health_signal, 64, 64);
KINETUM_ABI_ASSERT_OFFSET(kinetum_health_signal, assessment, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_health_signal, epoch, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_health_signal, timestamp_ns, 56);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_control_msg, 8, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_control_msg, data, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_control_msg, len, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_control_msg, subtype, 12);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_retained_packet_handle, 8, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_retained_packet_handle, value, 0);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_active_timer_handle, 8, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_timer_handle, value, 0);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_async_work_handle, 8, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_work_handle, value, 0);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_async_outcome, 4, 4);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_async_packet_view, 8, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_packet_view, data, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_packet_view, len, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_packet_view, _padding, 12);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_async_token_ops, 8, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_token_ops, complete, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_token_ops, cancellation_requested, 8);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_async_token, 8, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_token, handle, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_token, ops, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_token, platform_opaque, 16);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_async_completion, 8, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_completion, handle, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_completion, retained, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_completion, user_tag, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_completion, outcome, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_async_completion, _padding, 28);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_active_runtime_services, 8, 56);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, completions, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, completion_count, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, _padding, 12);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, begin_async, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, begin_async_retained, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, abort_async, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, recirculate_retained, 40);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_runtime_services, platform_opaque, 48);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_active_ctx, 8, 136);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, now_ns, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, active_epoch, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, active_packet_config, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, drain_target_epoch, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, expired, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, drain_retained, 40);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, expired_count, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, drain_retained_count, 52);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, region_id, 56);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, state_flags, 60);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, emit, 64);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, retain_input, 72);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, emit_retained, 80);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, drop_retained, 88);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, arm_timer_after, 96);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, cancel_timer, 104);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, post_control, 112);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, request_pull, 120);
KINETUM_ABI_ASSERT_OFFSET(kinetum_active_ctx, runtime_services, 128);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_context_selection_batch, 64, 1536);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, src_ip, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, dst_ip, 256);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, platform_flags, 512);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, flow_hash, 768);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, src_port, 1024);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, dst_port, 1152);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, input_port, 1280);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, proto, 1408);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, count, 1472);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_batch, padding, 1474);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_context_selection_targets, 8, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_targets, context_count, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_targets, permitted_count, 4);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_targets, permitted_ordinals, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_context_selection_targets, permitted_bitmap, 16);

KINETUM_ABI_ASSERT_LAYOUT(kinetum_module, 8, 120);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, module_id, 0);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, module_version, 8);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, abi_version, 16);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, flags, 20);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, mode, 24);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, prepare_config, 32);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, activate_config, 40);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, retire_config, 48);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, process, 56);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, ingest, 64);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, run, 72);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, on_control, 80);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, init, 88);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, fini, 96);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, health_check, 104);
KINETUM_ABI_ASSERT_OFFSET(kinetum_module, select_contexts, 112);

#undef KINETUM_ABI_ASSERT_OFFSET
#undef KINETUM_ABI_ASSERT_LAYOUT
#undef KINETUM_ABI_ALIGNOF
#undef KINETUM_ABI_STATIC_ASSERT
/** @endcond */

/**
 * @brief Create forward mask for first N packets.
 *
 * @param count Number of packets.
 * @return Bitmask with the first min(count, KINETUM_MAX_BURST) bits set.
 */
static KINETUM_ALWAYS_INLINE uint64_t kinetum_forward_mask(uint32_t count)
{
	return count >= KINETUM_MAX_BURST ? UINT64_MAX : (UINT64_C(1) << count) - UINT64_C(1);
}

/** Create a forward mask while evaluating count exactly once. */
#define KINETUM_FORWARD_MASK(count) kinetum_forward_mask((uint32_t)(count))

// =============================================================================
// SIMD Batch Operations (Mechanism-Only Design)
//
// Each helper compares one existing contiguous SoA column and returns one
// low-64-bit lane mask. Modules compose those masks into their own policy;
// the helpers own no packet classification or disposition rule. C++ modules
// may use algo/simd_classify.hpp for richer scalar-equivalent batch patterns.
// =============================================================================

/**
 * @section simd_example SIMD Batch Operations Example (SoA Batch API)
 *
 * @code{.c}
 * // DSCP-based traffic filter over one existing SoA column.
 * static uint64_t dscp_filter(kinetum_batch_t* batch) {
 *     const uint16_t count = batch->count;
 *
 *     // The comparison is mechanism; the threshold and disposition are policy.
 *     uint64_t high_dscp = kinetum_simd_cmp_u8_ge(batch->dscp, count, 48);
 *     uint64_t forward_mask = KINETUM_FORWARD_MASK(count);
 *
 *     // Clear denied lanes in the callback's sole disposition mask.
 *     for (uint16_t i = 0; i < count; ++i) {
 *         if (high_dscp & (1ULL << i)) {
 *             KINETUM_DROP(forward_mask, i);
 *         }
 *     }
 *     return forward_mask;
 * }
 *
 * // Port-based filter using SoA arrays
 * static uint64_t port_filter(kinetum_batch_t* batch) {
 *     const uint16_t count = batch->count;
 *
 *     uint64_t ssh_mask = kinetum_simd_cmp_u16_eq(batch->dst_port, count, 22);
 *
 *     return KINETUM_FORWARD_MASK(count) & ~ssh_mask;
 * }
 *
 * // Complex multi-condition filter using SoA
 * static uint64_t complex_filter(kinetum_batch_t* batch) {
 *     const uint16_t count = batch->count;
 *
 *     uint64_t high_priority = kinetum_simd_cmp_u8_lt(batch->dscp, count, 32);
 *     uint64_t ssh_traffic = kinetum_simd_cmp_u16_eq(batch->dst_port, count, 22);
 *     uint64_t https_range = kinetum_simd_cmp_u16_range(batch->dst_port, count, 443, 444);
 *
 *     // Compose module policy from independent comparison masks.
 *     return (high_priority | ssh_traffic | https_range) & KINETUM_FORWARD_MASK(count);
 * }
 * @endcode
 */

// -----------------------------------------------------------------------------
// Generic SIMD Comparisons (Array -> Bitmask)
//
// These helpers compare raw arrays against thresholds and return bitmasks.
// Users compose them into domain-specific policies. Each helper examines at
// most the first 64 values because one result bitmask represents exactly 64
// lanes. A null array or zero count returns zero; later values are ignored.
// -----------------------------------------------------------------------------

#if defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
/**
 * @brief Pack eight normalized NEON comparison lanes into one mask byte.
 *
 * @param lanes Eight lanes whose values are exactly zero or one.
 * @return Bit N set exactly when lane N is one.
 */
static KINETUM_ALWAYS_INLINE uint8_t kinetum_simd_neon_pack_lanes(uint8x8_t lanes)
{
	static const uint8_t lane_weights[8] = {1u, 2u, 4u, 8u, 16u, 32u, 64u, 128u};
	return vaddv_u8(vmul_u8(lanes, vld1_u8(lane_weights)));
}
#endif

/**
 * @brief Compare uint8_t array, return mask where values >= threshold.
 *
 * MECHANISM: Generic comparison, no domain semantics.
 *
 * @param values Input array.
 * @param count Number of values (max 64).
 * @param threshold Comparison threshold.
 * @return Bitmask where bit N is set if values[N] >= threshold.
 */
static KINETUM_ALWAYS_INLINE uint64_t kinetum_simd_cmp_u8_ge(const uint8_t *values, uint16_t count, uint8_t threshold)
{
	uint64_t mask = 0;
	uint16_t index = 0;

	if (values == NULL || count == 0) {
		return 0;
	}
	if (count > 64) {
		count = 64;
	}

#if defined(__AVX2__)
	{
		const __m256i bias = _mm256_set1_epi8((char)0x80);
		const __m256i threshold_vector = _mm256_xor_si256(_mm256_set1_epi8((char)threshold), bias);
		for (; (uint32_t)index + 32u <= (uint32_t)count; index = (uint16_t)(index + 32u)) {
			__m256i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m256i biased = _mm256_xor_si256(value_vector, bias);
			const __m256i greater = _mm256_cmpgt_epi8(biased, threshold_vector);
			const __m256i equal = _mm256_cmpeq_epi8(biased, threshold_vector);
			const uint32_t block = (uint32_t)_mm256_movemask_epi8(_mm256_or_si256(greater, equal));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__SSE2__)
	{
		const __m128i bias = _mm_set1_epi8((char)0x80);
		const __m128i threshold_vector = _mm_xor_si128(_mm_set1_epi8((char)threshold), bias);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			__m128i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m128i biased = _mm_xor_si128(value_vector, bias);
			const __m128i greater = _mm_cmpgt_epi8(biased, threshold_vector);
			const __m128i equal = _mm_cmpeq_epi8(biased, threshold_vector);
			const uint32_t block = (uint32_t)_mm_movemask_epi8(_mm_or_si128(greater, equal));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
	{
		const uint8x16_t threshold_vector = vdupq_n_u8(threshold);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			const uint8x16_t comparison = vcgeq_u8(vld1q_u8(&values[index]), threshold_vector);
			const uint8x16_t bits = vshrq_n_u8(comparison, 7);
			const uint16_t low = (uint16_t)kinetum_simd_neon_pack_lanes(vget_low_u8(bits));
			const uint16_t high = (uint16_t)kinetum_simd_neon_pack_lanes(vget_high_u8(bits));
			mask |= (uint64_t)(low | (uint16_t)(high << 8u)) << index;
		}
	}
#endif

	for (; index < count; ++index) {
		if (values[index] >= threshold) {
			mask |= UINT64_C(1) << index;
		}
	}
	return mask;
}

/**
 * @brief Compare uint8_t array, return mask where values > threshold.
 *
 * MECHANISM: Generic comparison, no domain semantics.
 *
 * @param values Input array.
 * @param count Number of values (max 64).
 * @param threshold Comparison threshold.
 * @return Bitmask where bit N is set if values[N] > threshold.
 */
static KINETUM_ALWAYS_INLINE uint64_t kinetum_simd_cmp_u8_gt(const uint8_t *values, uint16_t count, uint8_t threshold)
{
	uint64_t mask = 0;
	uint16_t index = 0;

	if (values == NULL || count == 0) {
		return 0;
	}
	if (count > 64) {
		count = 64;
	}

#if defined(__AVX2__)
	{
		const __m256i bias = _mm256_set1_epi8((char)0x80);
		const __m256i threshold_vector = _mm256_xor_si256(_mm256_set1_epi8((char)threshold), bias);
		for (; (uint32_t)index + 32u <= (uint32_t)count; index = (uint16_t)(index + 32u)) {
			__m256i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m256i biased = _mm256_xor_si256(value_vector, bias);
			const uint32_t block =
				(uint32_t)_mm256_movemask_epi8(_mm256_cmpgt_epi8(biased, threshold_vector));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__SSE2__)
	{
		const __m128i bias = _mm_set1_epi8((char)0x80);
		const __m128i threshold_vector = _mm_xor_si128(_mm_set1_epi8((char)threshold), bias);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			__m128i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m128i biased = _mm_xor_si128(value_vector, bias);
			const uint32_t block = (uint32_t)_mm_movemask_epi8(_mm_cmpgt_epi8(biased, threshold_vector));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
	{
		const uint8x16_t threshold_vector = vdupq_n_u8(threshold);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			const uint8x16_t comparison = vcgtq_u8(vld1q_u8(&values[index]), threshold_vector);
			const uint8x16_t bits = vshrq_n_u8(comparison, 7);
			const uint16_t low = (uint16_t)kinetum_simd_neon_pack_lanes(vget_low_u8(bits));
			const uint16_t high = (uint16_t)kinetum_simd_neon_pack_lanes(vget_high_u8(bits));
			mask |= (uint64_t)(low | (uint16_t)(high << 8u)) << index;
		}
	}
#endif

	for (; index < count; ++index) {
		if (values[index] > threshold) {
			mask |= UINT64_C(1) << index;
		}
	}
	return mask;
}

/**
 * @brief Compare uint8_t array, return mask where values < threshold.
 *
 * MECHANISM: Generic comparison, no domain semantics.
 *
 * @param values Input array.
 * @param count Number of values (max 64).
 * @param threshold Comparison threshold.
 * @return Bitmask where bit N is set if values[N] < threshold.
 */
static KINETUM_ALWAYS_INLINE uint64_t kinetum_simd_cmp_u8_lt(const uint8_t *values, uint16_t count, uint8_t threshold)
{
	uint64_t mask = 0;
	uint16_t index = 0;

	if (values == NULL || count == 0) {
		return 0;
	}
	if (count > 64) {
		count = 64;
	}

#if defined(__AVX2__)
	{
		const __m256i bias = _mm256_set1_epi8((char)0x80);
		const __m256i threshold_vector = _mm256_xor_si256(_mm256_set1_epi8((char)threshold), bias);
		for (; (uint32_t)index + 32u <= (uint32_t)count; index = (uint16_t)(index + 32u)) {
			__m256i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m256i biased = _mm256_xor_si256(value_vector, bias);
			const uint32_t block =
				(uint32_t)_mm256_movemask_epi8(_mm256_cmpgt_epi8(threshold_vector, biased));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__SSE2__)
	{
		const __m128i bias = _mm_set1_epi8((char)0x80);
		const __m128i threshold_vector = _mm_xor_si128(_mm_set1_epi8((char)threshold), bias);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			__m128i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m128i biased = _mm_xor_si128(value_vector, bias);
			const uint32_t block = (uint32_t)_mm_movemask_epi8(_mm_cmpgt_epi8(threshold_vector, biased));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
	{
		const uint8x16_t threshold_vector = vdupq_n_u8(threshold);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			const uint8x16_t comparison = vcltq_u8(vld1q_u8(&values[index]), threshold_vector);
			const uint8x16_t bits = vshrq_n_u8(comparison, 7);
			const uint16_t low = (uint16_t)kinetum_simd_neon_pack_lanes(vget_low_u8(bits));
			const uint16_t high = (uint16_t)kinetum_simd_neon_pack_lanes(vget_high_u8(bits));
			mask |= (uint64_t)(low | (uint16_t)(high << 8u)) << index;
		}
	}
#endif

	for (; index < count; ++index) {
		if (values[index] < threshold) {
			mask |= UINT64_C(1) << index;
		}
	}
	return mask;
}

/**
 * @brief Compare uint8_t array, return mask where values == target.
 *
 * MECHANISM: Generic comparison, no domain semantics.
 *
 * @param values Input array.
 * @param count Number of values (max 64).
 * @param target Value to match.
 * @return Bitmask where bit N is set if values[N] == target.
 */
static KINETUM_ALWAYS_INLINE uint64_t kinetum_simd_cmp_u8_eq(const uint8_t *values, uint16_t count, uint8_t target)
{
	uint64_t mask = 0;
	uint16_t index = 0;

	if (values == NULL || count == 0) {
		return 0;
	}
	if (count > 64) {
		count = 64;
	}

#if defined(__AVX2__)
	{
		const __m256i target_vector = _mm256_set1_epi8((char)target);
		for (; (uint32_t)index + 32u <= (uint32_t)count; index = (uint16_t)(index + 32u)) {
			__m256i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const uint32_t block =
				(uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(value_vector, target_vector));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__SSE2__)
	{
		const __m128i target_vector = _mm_set1_epi8((char)target);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			__m128i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const uint32_t block = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(value_vector, target_vector));
			mask |= (uint64_t)block << index;
		}
	}
#elif defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
	{
		const uint8x16_t target_vector = vdupq_n_u8(target);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			const uint8x16_t comparison = vceqq_u8(vld1q_u8(&values[index]), target_vector);
			const uint8x16_t bits = vshrq_n_u8(comparison, 7);
			const uint16_t low = (uint16_t)kinetum_simd_neon_pack_lanes(vget_low_u8(bits));
			const uint16_t high = (uint16_t)kinetum_simd_neon_pack_lanes(vget_high_u8(bits));
			mask |= (uint64_t)(low | (uint16_t)(high << 8u)) << index;
		}
	}
#endif

	for (; index < count; ++index) {
		if (values[index] == target) {
			mask |= UINT64_C(1) << index;
		}
	}
	return mask;
}

#if defined(__AVX2__) || defined(__SSE2__)
/**
 * @brief Pack duplicated x86 uint16_t comparison bits into lane bits.
 *
 * @param bits Byte-level movemask with one equal adjacent pair per word lane.
 * @return Compact uint16_t-lane mask in the low 16 bits.
 */
static KINETUM_ALWAYS_INLINE uint32_t kinetum_simd_compress_even_bits(uint32_t bits)
{
	bits &= UINT32_C(0x55555555);
	bits = (bits | (bits >> 1u)) & UINT32_C(0x33333333);
	bits = (bits | (bits >> 2u)) & UINT32_C(0x0f0f0f0f);
	bits = (bits | (bits >> 4u)) & UINT32_C(0x00ff00ff);
	return (bits | (bits >> 8u)) & UINT32_C(0x0000ffff);
}
#endif

/**
 * @brief Compare uint16_t array, return mask where values == target.
 *
 * MECHANISM: Generic comparison, no domain semantics.
 *
 * @param values Input array.
 * @param count Number of values (max 64).
 * @param target Value to match.
 * @return Bitmask where bit N is set if values[N] == target.
 */

static KINETUM_ALWAYS_INLINE uint64_t kinetum_simd_cmp_u16_eq(const uint16_t *values, uint16_t count, uint16_t target)
{
	uint64_t mask = 0;
	uint16_t index = 0;

	if (values == NULL || count == 0) {
		return 0;
	}
	if (count > 64) {
		count = 64;
	}

#if defined(__AVX2__)
	{
		const __m256i target_vector = _mm256_set1_epi16((int16_t)target);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			__m256i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const uint32_t bytes =
				(uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi16(value_vector, target_vector));
			mask |= (uint64_t)kinetum_simd_compress_even_bits(bytes) << index;
		}
	}
#elif defined(__SSE2__)
	{
		const __m128i target_vector = _mm_set1_epi16((int16_t)target);
		for (; (uint32_t)index + 8u <= (uint32_t)count; index = (uint16_t)(index + 8u)) {
			__m128i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const uint32_t bytes =
				(uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi16(value_vector, target_vector));
			mask |= (uint64_t)kinetum_simd_compress_even_bits(bytes) << index;
		}
	}
#elif defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
	{
		const uint16x8_t target_vector = vdupq_n_u16(target);
		for (; (uint32_t)index + 8u <= (uint32_t)count; index = (uint16_t)(index + 8u)) {
			const uint16x8_t comparison = vceqq_u16(vld1q_u16(&values[index]), target_vector);
			const uint8x8_t bits = vmovn_u16(vshrq_n_u16(comparison, 15));
			const uint8_t block = kinetum_simd_neon_pack_lanes(bits);
			mask |= (uint64_t)block << index;
		}
	}
#endif

	for (; index < count; ++index) {
		if (values[index] == target) {
			mask |= UINT64_C(1) << index;
		}
	}
	return mask;
}

/**
 * @brief Compare uint16_t array, return mask where values in [lo, hi].
 *
 * MECHANISM: Generic comparison, no domain semantics.
 *
 * @param values Input array.
 * @param count Number of values (max 64).
 * @param lo Minimum value (inclusive).
 * @param hi Maximum value (inclusive).
 * @return Bitmask where bit N is set if lo <= values[N] <= hi.
 */
static KINETUM_ALWAYS_INLINE uint64_t kinetum_simd_cmp_u16_range(const uint16_t *values, uint16_t count, uint16_t lo,
								 uint16_t hi)
{
	uint64_t mask = 0;
	uint16_t index = 0;

	if (values == NULL || count == 0 || lo > hi) {
		return 0;
	}
	if (count > 64) {
		count = 64;
	}

#if defined(__AVX2__)
	{
		const __m256i bias = _mm256_set1_epi16((int16_t)0x8000);
		const __m256i all = _mm256_set1_epi16((int16_t)-1);
		const __m256i lo_vector = _mm256_xor_si256(_mm256_set1_epi16((int16_t)lo), bias);
		const __m256i hi_vector = _mm256_xor_si256(_mm256_set1_epi16((int16_t)hi), bias);
		for (; (uint32_t)index + 16u <= (uint32_t)count; index = (uint16_t)(index + 16u)) {
			__m256i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m256i biased = _mm256_xor_si256(value_vector, bias);
			const __m256i ge_lo = _mm256_andnot_si256(_mm256_cmpgt_epi16(lo_vector, biased), all);
			const __m256i le_hi = _mm256_andnot_si256(_mm256_cmpgt_epi16(biased, hi_vector), all);
			const uint32_t bytes = (uint32_t)_mm256_movemask_epi8(_mm256_and_si256(ge_lo, le_hi));
			mask |= (uint64_t)kinetum_simd_compress_even_bits(bytes) << index;
		}
	}
#elif defined(__SSE2__)
	{
		const __m128i bias = _mm_set1_epi16((int16_t)0x8000);
		const __m128i all = _mm_set1_epi16((int16_t)-1);
		const __m128i lo_vector = _mm_xor_si128(_mm_set1_epi16((int16_t)lo), bias);
		const __m128i hi_vector = _mm_xor_si128(_mm_set1_epi16((int16_t)hi), bias);
		for (; (uint32_t)index + 8u <= (uint32_t)count; index = (uint16_t)(index + 8u)) {
			__m128i value_vector;
			__builtin_memcpy(&value_vector, &values[index], sizeof(value_vector));
			const __m128i biased = _mm_xor_si128(value_vector, bias);
			const __m128i ge_lo = _mm_andnot_si128(_mm_cmpgt_epi16(lo_vector, biased), all);
			const __m128i le_hi = _mm_andnot_si128(_mm_cmpgt_epi16(biased, hi_vector), all);
			const uint32_t bytes = (uint32_t)_mm_movemask_epi8(_mm_and_si128(ge_lo, le_hi));
			mask |= (uint64_t)kinetum_simd_compress_even_bits(bytes) << index;
		}
	}
#elif defined(__aarch64__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
	{
		const uint16x8_t lo_vector = vdupq_n_u16(lo);
		const uint16x8_t hi_vector = vdupq_n_u16(hi);
		for (; (uint32_t)index + 8u <= (uint32_t)count; index = (uint16_t)(index + 8u)) {
			const uint16x8_t value_vector = vld1q_u16(&values[index]);
			const uint16x8_t comparison =
				vandq_u16(vcgeq_u16(value_vector, lo_vector), vcleq_u16(value_vector, hi_vector));
			const uint8x8_t bits = vmovn_u16(vshrq_n_u16(comparison, 15));
			const uint8_t block = kinetum_simd_neon_pack_lanes(bits);
			mask |= (uint64_t)block << index;
		}
	}
#endif

	for (; index < count; ++index) {
		if (values[index] >= lo && values[index] <= hi) {
			mask |= UINT64_C(1) << index;
		}
	}
	return mask;
}

#ifdef __cplusplus
}
#endif
