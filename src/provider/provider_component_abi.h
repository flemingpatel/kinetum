// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file provider_component_abi.h
 * @brief Exact C11 ABI shared by the runtime and provider components.
 * @author Fleming Patel
 *
 * This header is the sole physical declaration authority for provider-neutral
 * packet records, pre-resolved packet operation tables, and the cold provider
 * component query boundary. It is valid C11 and C++20, contains no protobuf or
 * provider-native declaration, and relies only on fixed-width values, byte
 * spans, opaque handles, and fixed callbacks.
 *
 * The ABI is exact-release rather than backward compatible. A changed field,
 * offset, callback, or provider contract changes the generated ABI identity;
 * runtime and components must be rebuilt from the same tree. There are no
 * descriptor-size negotiations, flags, reserved extension fields, or fallback
 * readers.
 *
 * @par Packet-path performance
 * Packet metadata occupies two cache lines and the storage descriptor one
 * cache line. Each role-specific operation table is immutable and occupies one
 * cache line. The loader and component descriptor are cold-path mechanisms and
 * are never consulted after worker materialization.
 *
 * @par Thread safety
 * One owner mutates a packet record at a time. Operation-table state follows
 * the exact ownership contract established by materialization. Component
 * query storage is immutable for the complete process lifetime.
 */

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
#include <type_traits>

/** Give provider entry points C linkage when compiled as C++. */
#define KINETUM_PROVIDER_EXTERN_C extern "C"
/** Prohibit C++ exceptions from crossing provider callbacks. */
#define KINETUM_PROVIDER_NOEXCEPT noexcept
/** Require a compile-time ABI invariant with its failure diagnostic. */
#define KINETUM_PROVIDER_STATIC_ASSERT(condition, message) static_assert((condition), message)
/** Query a type's ABI alignment in C++ declarations. */
#define KINETUM_PROVIDER_ALIGNOF(type) alignof(type)
/** Require ABI records to have standard layout and trivial copy semantics. */
#define KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(type)                                             \
	static_assert(std::is_standard_layout_v<type>, #type " must remain standard-layout"); \
	static_assert(std::is_trivially_copyable_v<type>, #type " must remain trivially copyable")
#else
/** Declare provider entry points with external C linkage. */
#define KINETUM_PROVIDER_EXTERN_C extern
/** Preserve the callback declaration shape in C, which has no exception specification. */
#define KINETUM_PROVIDER_NOEXCEPT
/** Require a compile-time ABI invariant with its failure diagnostic. */
#define KINETUM_PROVIDER_STATIC_ASSERT(condition, message) _Static_assert((condition), message)
/** Query a type's ABI alignment in C11 declarations. */
#define KINETUM_PROVIDER_ALIGNOF(type) _Alignof(type)
/** Require a complete C ABI record type; C++ additionally verifies its type traits. */
#define KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(type) _Static_assert(sizeof(type) > 0, #type " must be complete")
#endif

#if defined(__GNUC__) || defined(__clang__)
/** Enforce the declared ABI alignment on provider records. */
#define KINETUM_PROVIDER_ALIGNAS(bytes) __attribute__((aligned(bytes)))
/** Export a provider entry point from an otherwise hidden component image. */
#define KINETUM_PROVIDER_EXPORT __attribute__((visibility("default")))
#else
#error "The exact provider component ABI requires a GNU-compatible Linux compiler"
#endif

/** Exact provider ABI identity width in bytes. */
#define KINETUM_PROVIDER_ABI_IDENTITY_SIZE UINT32_C(32)

/** Exact SHA-256 artifact identity width in bytes. */
#define KINETUM_PROVIDER_ARTIFACT_IDENTITY_SIZE UINT32_C(32)

/** Exact provider component query symbol. */
#define KINETUM_PROVIDER_COMPONENT_QUERY_SYMBOL "kinetum_provider_component_query"

/** Exact packet metadata width in bytes. */
#define KINETUM_PACKET_PRIVATE_SIZE UINT32_C(128)

/** Exact complete packet-record width in bytes. */
#define KINETUM_PACKET_RECORD_SIZE UINT32_C(192)

/** Invalid compact stage identity. */
#define KINETUM_INVALID_STAGE_ID UINT16_MAX

/** Invalid logical port identity. */
#define KINETUM_INVALID_PORT UINT16_MAX

/** Invalid packet-storage-domain identity. */
#define KINETUM_INVALID_STORAGE_DOMAIN UINT16_MAX

/** Parser proved one IPv4 header. */
#define KINETUM_PACKET_PLATFORM_L3_IPV4 (UINT32_C(1) << 0)

/** Parsed IPv4 protocol field identifies TCP. */
#define KINETUM_PACKET_PLATFORM_L4_TCP (UINT32_C(1) << 2)

/** Parsed IPv4 protocol field identifies UDP. */
#define KINETUM_PACKET_PLATFORM_L4_UDP (UINT32_C(1) << 3)

/** Parser proved IPv4 fragmentation is present. */
#define KINETUM_PACKET_PLATFORM_FRAGMENT (UINT32_C(1) << 6)

/** Storage provides a CPU-readable contiguous span. */
#define KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ (UINT32_C(1) << 0)

/** Storage provides a CPU-writable contiguous span. */
#define KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE (UINT32_C(1) << 1)

/** Storage admits NIC receive DMA. */
#define KINETUM_PACKET_STORAGE_NIC_RX_DMA (UINT32_C(1) << 2)

/** Storage admits NIC transmit DMA. */
#define KINETUM_PACKET_STORAGE_NIC_TX_DMA (UINT32_C(1) << 3)

/** Storage can create an independently writable clone. */
#define KINETUM_PACKET_STORAGE_WRITABLE_CLONE (UINT32_C(1) << 4)

/** Fixed-width status returned by a provider callback. */
typedef int32_t kinetum_provider_status;

/** Provider callback completed successfully. */
#define KINETUM_PROVIDER_STATUS_OK INT32_C(0)

/** Provider callback rejected malformed input. */
#define KINETUM_PROVIDER_STATUS_INVALID_ARGUMENT INT32_C(1)

/** Provider callback rejected an unsatisfied prerequisite. */
#define KINETUM_PROVIDER_STATUS_FAILED_PRECONDITION INT32_C(2)

/** Provider callback could not acquire a bounded resource. */
#define KINETUM_PROVIDER_STATUS_RESOURCE_EXHAUSTED INT32_C(3)

/** Provider callback encountered a native implementation failure. */
#define KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR INT32_C(4)

/** Fixed-width provider role. */
typedef uint8_t kinetum_provider_role;

/** Process- or device-generation facility role. */
#define KINETUM_PROVIDER_ROLE_PROCESS_FACILITY UINT8_C(1)

/** Native endpoint and queue-transfer role. */
#define KINETUM_PROVIDER_ROLE_IO_DRIVER UINT8_C(2)

/** Packet-byte and record-ownership role. */
#define KINETUM_PROVIDER_ROLE_PACKET_STORAGE UINT8_C(3)

/** Stage-execution resource role. */
#define KINETUM_PROVIDER_ROLE_EXECUTION UINT8_C(4)

/** Explicit packet-storage handoff role. */
#define KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION UINT8_C(5)

/** Immutable byte range borrowed for one callback. */
typedef struct kinetum_provider_byte_view {
	const uint8_t *data;  ///< First byte, or null only when size is zero.
	uint32_t size;	      ///< Exact byte count.
	uint32_t padding;     ///< Layout padding; must be zero.
} kinetum_provider_byte_view;

/** Immutable UTF-8/ASCII text range borrowed for one callback. */
typedef struct kinetum_provider_text_view {
	const char *data;  ///< First byte, or null only when size is zero.
	uint32_t size;	   ///< Exact byte count without a terminating NUL.
	uint32_t padding;  ///< Layout padding; must be zero.
} kinetum_provider_text_view;

/** Fixed-width cold diagnostic level; zero is invalid. */
typedef uint8_t kinetum_provider_log_level;
/** Debug diagnostic, equivalent to RFC 5424 severity 7. */
#define KINETUM_PROVIDER_LOG_DEBUG UINT8_C(1)
/** Informational diagnostic, equivalent to RFC 5424 severity 6. */
#define KINETUM_PROVIDER_LOG_INFO UINT8_C(2)
/** Notice diagnostic, equivalent to RFC 5424 severity 5. */
#define KINETUM_PROVIDER_LOG_NOTICE UINT8_C(3)
/** Warning diagnostic, equivalent to RFC 5424 severity 4. */
#define KINETUM_PROVIDER_LOG_WARNING UINT8_C(4)
/** Error diagnostic, equivalent to RFC 5424 severity 3. */
#define KINETUM_PROVIDER_LOG_ERROR UINT8_C(5)
/** Critical diagnostic, equivalent to RFC 5424 severity 2. */
#define KINETUM_PROVIDER_LOG_CRITICAL UINT8_C(6)
/** Alert diagnostic, equivalent to RFC 5424 severity 1. */
#define KINETUM_PROVIDER_LOG_ALERT UINT8_C(7)
/** Emergency diagnostic, equivalent to RFC 5424 severity 0. */
#define KINETUM_PROVIDER_LOG_EMERGENCY UINT8_C(8)

/**
 * @brief Borrowed host logging capability for one admitted provider instance.
 *
 * The factory may copy this capability into its instance. Its context remains
 * valid through the instance's destroy callback, after every provider-created
 * emitter has joined. It may be invoked only by cold factory, lifecycle, native
 * diagnostic, and destruction code. Authored packet operations and owner-worker
 * callbacks never invoke it. A native library may call its hook on a packet
 * owner; the host rejects and counts that call without inspecting text, waiting,
 * taking a lock, or queueing. Query and host proof receive no logging capability.
 *
 * write() copies bounded text synchronously; no view survives the call. Event
 * is a stable 1..32-byte PRINTUSASCII identifier. Function is the actual source
 * function or an empty view when unavailable. Severity never authorizes a
 * process action. On cold threads ERROR and above bypass filtering and wait at
 * most 100 ms for their exact file-write result. Known refusal/failure or timeout
 * attempts best-effort emergency stderr; a timeout does not prove file loss.
 * Failure to retain a diagnostic does not change provider work.
 */
typedef struct kinetum_provider_cold_log {
	void *context;	///< Host-owned exact instance identity, borrowed through destruction.
	void (*write)(void *context, kinetum_provider_log_level level, kinetum_provider_text_view event,
		      kinetum_provider_text_view function, kinetum_provider_text_view message)
		KINETUM_PROVIDER_NOEXCEPT;  ///< Cold bounded diagnostic submission, never a packet operation.
} kinetum_provider_cold_log;

/**
 * @brief Caller-owned bounded provider diagnostic.
 *
 * The callback may write at most capacity bytes and then sets size to the
 * number written. It must not replace data or capacity. Diagnostics are
 * failure-only: a successful callback leaves size zero. Data may be null only
 * when capacity is zero. A callback must not retain this view.
 */
typedef struct kinetum_provider_diagnostic {
	char *data;	    ///< Caller-owned output bytes.
	uint32_t capacity;  ///< Writable bytes at data.
	uint32_t size;	    ///< Bytes written, never greater than capacity.
} kinetum_provider_diagnostic;

/** Fixed-width availability of one provider-owned statistics row. */
typedef uint8_t kinetum_provider_observation_state;

/** Provider returned one exact native snapshot. */
#define KINETUM_PROVIDER_OBSERVATION_AVAILABLE_EXACT UINT8_C(1)

/** Provider returned an explicitly approximate concurrent snapshot. */
#define KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE UINT8_C(2)

/** Provider does not implement this native observation. */
#define KINETUM_PROVIDER_OBSERVATION_UNSUPPORTED UINT8_C(3)

/** A supported native observation failed for this row. */
#define KINETUM_PROVIDER_OBSERVATION_READ_FAILED UINT8_C(4)

/**
 * @brief Caller-owned packet-storage occupancy observation.
 *
 * The provider writes identity and values together. Non-available states require
 * both values to remain zero. For either available state, in_use plus available
 * equals the compiled storage-domain population; approximation describes the
 * concurrent sample, not an unaccounted record. Time provenance is stamped by
 * platform core after callback return and therefore does not cross the provider
 * ABI.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_provider_storage_observation {
	uint64_t runtime_generation;		   ///< Exact materialized runtime generation.
	uint32_t storage_domain_index;		   ///< Exact compact storage-domain identity.
	kinetum_provider_observation_state state;  ///< Exact availability classification.
	uint8_t identity_padding[3];		   ///< Zeroed identity alignment padding.
	uint64_t in_use;			   ///< Exact or approximate externally owned record count.
	uint64_t available;			   ///< Exact or approximate immediately available count.
	uint8_t padding[32];			   ///< Zeroed cache-line completion.
} kinetum_provider_storage_observation;

/** @brief Caller-owned provider-native logical-port counter observation. */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_provider_port_observation {
	uint32_t port_index;			   ///< Exact compact global port identity.
	kinetum_provider_observation_state state;  ///< Exact availability classification.
	uint8_t identity_padding[3];		   ///< Zeroed identity alignment padding.
	uint64_t rx_packets;			   ///< Native cumulative receive packets.
	uint64_t tx_packets;			   ///< Native cumulative transmit packets.
	uint64_t rx_bytes;			   ///< Native cumulative receive bytes.
	uint64_t tx_bytes;			   ///< Native cumulative transmit bytes.
	uint64_t rx_missed;			   ///< Native receive misses.
	uint64_t rx_errors;			   ///< Native receive errors.
	uint64_t tx_errors;			   ///< Native transmit errors.
	uint64_t rx_no_buffer;			   ///< Native receive-buffer exhaustion count.
	uint8_t padding[56];			   ///< Zeroed two-cache-line completion.
} kinetum_provider_port_observation;

/**
 * @brief Caller-owned complete native port-observation batch.
 *
 * Rows are preallocated in the exact canonical driver-local fact order. The
 * callback may not replace, resize, retain, or reorder them. Each row echoes its
 * compact global identity so core can reject a swapped or partial projection.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_provider_io_observation_batch {
	kinetum_provider_port_observation *ports;  ///< Complete caller-owned port rows.
	uint32_t port_count;			   ///< Exact driver port population.
	uint32_t port_padding;			   ///< Must remain zero.
	uint8_t padding[48];			   ///< Zeroed cache-line completion.
} kinetum_provider_io_observation_batch;

/**
 * @brief Observe one complete packet-storage occupancy row on the cold path.
 * @param state Component-owned exact storage instance.
 * @param[out] observation Caller-owned row replaced with one typed observation.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return One declared provider status; OK requires a complete typed row.
 */
typedef kinetum_provider_status (*kinetum_provider_observe_storage_fn)(
	void *state, kinetum_provider_storage_observation *observation,
	kinetum_provider_diagnostic *diagnostic) KINETUM_PROVIDER_NOEXCEPT;

/**
 * @brief Observe one complete I/O-driver port batch on the cold path.
 * @param state Component-owned exact I/O-driver instance.
 * @param[in,out] observations Caller-owned arrays whose identity order and
 *        storage cannot be replaced, resized, retained, or reordered.
 * @param diagnostic Optional caller-owned bounded failure diagnostic.
 * @return One declared provider status; OK requires every row classified.
 */
typedef kinetum_provider_status (*kinetum_provider_observe_io_fn)(
	void *state, kinetum_provider_io_observation_batch *observations,
	kinetum_provider_diagnostic *diagnostic) KINETUM_PROVIDER_NOEXCEPT;

/**
 * @brief Cold whole-driver packet-I/O lifecycle callback.
 *
 * Activation is the sole operation allowed to make an I/O driver's receive
 * sources live. It must either activate the complete driver or return with the
 * complete driver cold. Deactivation must either prove every source cold or
 * retain the unresolved live ownership and report failure. The platform calls
 * both operations without holding a platform lock; neither callback is
 * reachable from packet execution.
 */
typedef kinetum_provider_status (*kinetum_provider_io_lifecycle_fn)(
	void *state, kinetum_provider_diagnostic *diagnostic) KINETUM_PROVIDER_NOEXCEPT;

/**
 * @brief Sole per-packet metadata authority shared by every provider.
 *
 * Cache line zero contains routing, epoch, and module-persistent metadata.
 * Cache line one contains parsed Ethernet/IPv4/L4 facts. Foreign code that
 * mutates packet bytes owns updating every parsed field invalidated by that
 * mutation; the runtime does not reparse between pipeline stages.
 *
 * user_meta is copied into the module ABI before a callback and copied back
 * afterward when user_meta_valid is nonzero. A writable fan-out clone receives
 * an independent value snapshot; sibling branches may diverge after cloning.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_packet_private {
	uint64_t timestamp_ns;		  ///< Owner-cached ingress/origination timestamp.
	uint64_t epoch;			  ///< Immutable packet-admission epoch.
	uint64_t user_meta;		  ///< Persistent module-owned user word.
	uint32_t flow_hash;		  ///< Current parsed/module-updated flow hash.
	uint32_t platform_flags;	  ///< Exact parser-produced fact mask.
	uint32_t user_flags;		  ///< Persistent module-owned flag word.
	uint16_t ingress_port;		  ///< Immutable logical ingress port.
	uint16_t egress_port;		  ///< Selected logical egress port.
	uint16_t next_stage;		  ///< Next logical stage identity.
	uint16_t current_stage;		  ///< Current logical stage identity.
	uint16_t next_stage_instance;	  ///< Next executable stage-instance index.
	uint16_t current_stage_instance;  ///< Current executable stage-instance index.
	uint16_t module_next_stage;	  ///< Module-selected stage, or invalid.
	uint8_t user_meta_valid;	  ///< One when user_meta carries a value.
	uint8_t padding_hot[13];	  ///< Zeroed cache-line geometry padding.
	uint32_t src_ipv4;		  ///< Parsed/module-updated source IPv4 in host order.
	uint32_t dst_ipv4;		  ///< Parsed/module-updated destination IPv4 in host order.
	uint16_t src_port;		  ///< Parsed/module-updated source port in host order.
	uint16_t dst_port;		  ///< Parsed/module-updated destination port in host order.
	uint16_t eth_type;		  ///< Parsed Ethernet type in host order.
	uint16_t ip_offset;		  ///< Byte offset of the current IP header.
	uint16_t l4_offset;		  ///< Byte offset of the current L4 header.
	uint16_t ip_header_len;		  ///< Parsed IPv4 header length.
	uint16_t ip_total_len;		  ///< Parsed IPv4 total length.
	uint8_t l4_proto;		  ///< Parsed/module-updated IP protocol.
	uint8_t dscp;			  ///< Parsed/module-updated six-bit DSCP.
	uint8_t padding_parsed[40];	  ///< Zeroed cache-line geometry padding.
} kinetum_packet_private;

struct kinetum_packet_record;

/**
 * @brief Borrowed packet bytes supplied by an active origin.
 *
 * A complete origin batch is validated before the storage owner allocates or
 * copies anything. The borrowed view never becomes packet ownership and may
 * not be retained after copy_origins_burst returns.
 */
typedef struct kinetum_packet_origin_view {
	const uint8_t *data;  ///< Borrowed contiguous payload.
	uint32_t length;      ///< Exact payload bytes.
	uint32_t padding;     ///< Layout padding; must be zero.
} kinetum_packet_origin_view;

/**
 * @brief Immutable operations for one packet-storage domain.
 *
 * acquire_burst transfers ownership of exactly the returned prefix into the
 * caller's pointer array. It never returns more than capacity and does not
 * publish or transfer ownership through the untouched suffix. A zero result is
 * bounded exhaustion or a malformed empty request; it never authorizes a
 * fallback storage domain.
 *
 * release_burst retires every exact owned record in records[0,count). A null
 * entry inside a nonempty burst is a caller contract fault. A singular clone
 * is intentional: one invocation corresponds to one additional successor in a
 * compiled, statically bounded fan-out vector; there is no unbounded
 * module-selected clone loop.
 *
 * copy_origins_burst validates the complete authored input before consuming
 * storage. Malformed input returns zero with no ownership transfer; valid input
 * may return a capacity-limited prefix, and the caller dispatches only that
 * exact prefix.
 *
 * The table is immutable after materialization. state is opaque mutable
 * provider state: sharing this table across workers is legal only when the
 * materializer proves that the provider's storage operations admit those
 * concurrent owners.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_packet_storage_domain_operations {
	void *state;  ///< Opaque state governed by the materialized ownership contract.
	/** @brief Acquire and transfer one capacity-bounded owned-record prefix. */
	uint16_t (*acquire_burst)(void *state, struct kinetum_packet_record **records,
				  uint16_t capacity) KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Return one independently writable owned clone, or null on bounded exhaustion. */
	struct kinetum_packet_record *(*clone_writable)(void *state, const struct kinetum_packet_record *source)
		KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Materialize and transfer one validated capacity-limited origin prefix. */
	uint16_t (*copy_origins_burst)(void *state, const kinetum_packet_origin_view *origins,
				       struct kinetum_packet_record **records,
				       uint16_t count) KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Retire every exact owned record in one nonempty validated burst. */
	void (*release_burst)(void *state, struct kinetum_packet_record *const *records,
			      uint16_t count) KINETUM_PROVIDER_NOEXCEPT;
	kinetum_provider_observe_storage_fn observe_statistics;	 ///< Cold typed occupancy observation.
	uint32_t generation;					 ///< Exact runtime-generation identity.
	uint16_t domain_index;					 ///< Compiled storage-domain index.
	uint16_t maximum_packet_length;				 ///< Maximum contiguous payload bytes.
	uint32_t capabilities;					 ///< Exact storage-capability mask.
	uint8_t padding[4];					 ///< Zeroed cache-line geometry padding.
} kinetum_packet_storage_domain_operations;

/**
 * @brief Provider-private storage locator carried by one packet record.
 *
 * Core code may use data only when CPU_CONTIGUOUS_READ is capability-proven.
 * native_handle is interpreted only by the provider that created the record
 * and is never exposed through the module ABI.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_packet_storage_descriptor {
	void *native_handle;  ///< Provider-private backing identity.
	uint8_t *data;	      ///< Mutable contiguous bytes when capability-proven.
	const kinetum_packet_storage_domain_operations *operations;  ///< Exact storage owner.
	uint32_t length;					     ///< Exact logical packet length.
	uint32_t contiguous_length;				     ///< Bytes contiguous from data.
	uint32_t generation;					     ///< Runtime-generation identity.
	uint16_t domain_index;					     ///< Compiled storage-domain index.
	uint16_t segment_count;					     ///< Native segment count.
	uint32_t capabilities;					     ///< Materialized capability mask.
	uint8_t padding[20];					     ///< Zeroed cache-line geometry padding.
} kinetum_packet_storage_descriptor;

/** Sole packet representation transferred through the dataplane. */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_packet_record {
	kinetum_packet_private metadata;	    ///< Sole writable metadata authority.
	kinetum_packet_storage_descriptor storage;  ///< Exact provider-backed storage.
} kinetum_packet_record;

/**
 * @brief Exact ownership transfer and pre-admission discard from one RX burst.
 *
 * Only transferred_count grants ownership of the compact returned prefix.
 * The provider has already retired rejected_count native inputs. Their sum
 * cannot exceed the supplied capacity. Both counts zero means no input was
 * consumed; rejected-only input is work without a runtime ownership transfer.
 */
typedef struct kinetum_packet_rx_burst_result {
	uint16_t transferred_count;  ///< Exact compact prefix transferred to the caller.
	uint16_t rejected_count;     ///< Native inputs consumed and discarded before transfer.
} kinetum_packet_rx_burst_result;

/**
 * @brief Validate the complete consumed-input bound for one receive result.
 * @param result Exact transferred-prefix and provider-rejection counts.
 * @param capacity Maximum input population supplied to the receive callback.
 * @return One when the widened sum fits capacity, otherwise zero.
 */
static inline uint8_t kinetum_packet_rx_burst_result_is_valid(kinetum_packet_rx_burst_result result,
							      uint16_t capacity) KINETUM_PROVIDER_NOEXCEPT
{
	return (uint32_t)result.transferred_count + (uint32_t)result.rejected_count <= (uint32_t)capacity ? UINT8_C(1) :
													    UINT8_C(0);
}

/**
 * @brief Immutable receive-burst operations owned by one exact I/O queue.
 *
 * The table has exactly one packet-worker caller. state may be mutable queue
 * state, but no second worker may invoke the same receive table concurrently.
 * receive_burst transfers only the result's transferred_count prefix and
 * reports provider-owned discards separately. Neither count conveys delivery
 * evidence or changes packet ownership outside this call.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_packet_rx_burst_operations {
	void *state;  ///< Opaque mutable state owned by the exact RX queue worker.
	/** @brief Transfer ownership of one bounded prefix into caller storage. */
	kinetum_packet_rx_burst_result (*receive_burst)(void *state, kinetum_packet_record **records,
							uint16_t capacity) KINETUM_PROVIDER_NOEXCEPT;
	uint16_t maximum_burst;	 ///< Maximum admitted destination capacity.
	uint16_t logical_port;	 ///< Exact logical ingress port.
	uint8_t padding[44];	 ///< Zeroed cache-line geometry padding.
} kinetum_packet_rx_burst_operations;

/**
 * @brief Immutable transmit-burst operations owned by one exact I/O queue.
 *
 * transmit_burst consumes exactly records[0,return_value). The caller retains
 * ownership of the untouched suffix records[return_value,count). A provider
 * must never free, retire, translate, or otherwise consume that suffix. The
 * table belongs to one exact TX queue owner; state is not implicitly
 * multi-producer merely because the table itself is immutable. maybe_flush
 * returns zero or one through uint8_t so the C ABI never depends on a C++ bool
 * representation.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_packet_tx_burst_operations {
	void *state;  ///< Opaque mutable state owned by the exact TX queue worker.
	/** @brief Consume exactly one accepted prefix while leaving its suffix untouched. */
	uint16_t (*transmit_burst)(void *state, kinetum_packet_record *const *records,
				   uint16_t count) KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Publish all records deferred by this exact TX queue owner. */
	void (*flush)(void *state) KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Flush when provider policy requires it and return zero or one. */
	uint8_t (*maybe_flush)(void *state) KINETUM_PROVIDER_NOEXCEPT;
	uint16_t maximum_burst;	 ///< Maximum admitted source count.
	uint16_t logical_port;	 ///< Exact logical egress port.
	uint8_t padding[28];	 ///< Zeroed cache-line geometry padding.
} kinetum_packet_tx_burst_operations;

/** Fixed-width compiled CPU-owner kind. */
typedef uint8_t kinetum_provider_cpu_owner_kind;

/** Packet worker owns the compiled CPU. */
#define KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER UINT8_C(1)

/** Epoch-transition coordinator owns the compiled CPU. */
#define KINETUM_PROVIDER_CPU_OWNER_TRANSITION_COORDINATOR UINT8_C(2)

/** Configuration-lifecycle executor owns the compiled CPU. */
#define KINETUM_PROVIDER_CPU_OWNER_LIFECYCLE_EXECUTOR UINT8_C(3)

/** Fixed-width native attachment kind after strict provider configuration compilation. */
typedef uint8_t kinetum_provider_attachment_kind;

/** Canonical PCI function attachment. */
#define KINETUM_PROVIDER_ATTACHMENT_PCI UINT8_C(1)

/** Canonical Linux TAP interface attachment. */
#define KINETUM_PROVIDER_ATTACHMENT_TAP UINT8_C(2)

/** Canonical numeric IPv4 UDP endpoint attachment. */
#define KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4 UINT8_C(3)

/** Fixed-width compiled I/O direction. */
typedef uint8_t kinetum_provider_io_direction;

/** Receive-only compiled operation. */
#define KINETUM_PROVIDER_IO_DIRECTION_RX UINT8_C(1)

/** Transmit-only compiled operation. */
#define KINETUM_PROVIDER_IO_DIRECTION_TX UINT8_C(2)

/** Port admits both receive and transmit operations. */
#define KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL UINT8_C(3)

/** Fixed-width compiled steering kind. */
typedef uint8_t kinetum_provider_steering_kind;

/** One explicit queue with no steering operation. */
#define KINETUM_PROVIDER_STEERING_NONE UINT8_C(1)

/** Exact receive-side scaling profile. */
#define KINETUM_PROVIDER_STEERING_RSS UINT8_C(2)

/** Fixed-width typed packet-path endpoint kind. */
typedef uint8_t kinetum_provider_endpoint_kind;

/** Endpoint index addresses one compiled I/O stream. */
#define KINETUM_PROVIDER_ENDPOINT_IO_STREAM UINT8_C(1)

/** Endpoint index addresses one compiled stage instance. */
#define KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE UINT8_C(2)

/** Fixed-width current storage-transition mechanism. */
typedef uint8_t kinetum_provider_transition_mode;

/** Same-domain ownership handoff without copying packet bytes. */
#define KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE UINT8_C(1)

/** Distinct-domain bounded copy with exact source retirement. */
#define KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY UINT8_C(2)

/** CPU may directly access the compiled storage domain. */
#define KINETUM_PROVIDER_ACCESS_AGENT_CPU (UINT8_C(1) << 0)

/** NIC DMA may directly access the compiled storage domain. */
#define KINETUM_PROVIDER_ACCESS_AGENT_NIC_DMA (UINT8_C(1) << 1)

/** One exact generic CPU assignment consumed by a process facility. */
typedef struct kinetum_provider_cpu_assignment {
	uint32_t owner_index;		       ///< Compact worker or runtime-service index.
	int32_t cpu_core_id;		       ///< Exact plan-owned logical CPU.
	int32_t numa_node;		       ///< Exact plan-owned NUMA node.
	kinetum_provider_cpu_owner_kind kind;  ///< Exact owner role.
	uint8_t padding[3];		       ///< Zeroed layout padding.
} kinetum_provider_cpu_assignment;

/** One canonical native attachment compiled from an exact driver configuration. */
typedef struct kinetum_provider_driver_attachment_fact {
	kinetum_provider_text_view driver_port_id;	 ///< Exact driver-local port identity.
	kinetum_provider_text_view attachment_identity;	 ///< Canonical BDF, TAP name, or IPv4 text.
	uint32_t io_driver_index;			 ///< Owning compact I/O-driver identity.
	uint32_t endpoint_port;				 ///< UDP port; zero for PCI and TAP.
	kinetum_provider_attachment_kind kind;		 ///< Exact attachment interpretation.
	uint8_t padding[7];				 ///< Zeroed layout padding.
} kinetum_provider_driver_attachment_fact;

/** One storage-domain memory requirement aggregated into a process facility. */
typedef struct kinetum_provider_memory_domain_fact {
	uint32_t storage_domain_index;	 ///< Exact compact storage-domain identity.
	uint32_t buffer_count;		 ///< Exact admitted record population.
	uint32_t data_room_bytes;	 ///< Exact bytes reserved per payload slot.
	uint32_t headroom_bytes;	 ///< Exact bytes reserved before packet data.
	uint32_t alignment_bytes;	 ///< Exact record/payload alignment.
	uint32_t cache_size_per_worker;	 ///< Exact provider-local cache policy.
	int32_t host_numa_node;		 ///< Valid only when has_host_numa_node is one.
	uint8_t has_host_numa_node;	 ///< One when host_numa_node is plan truth.
	uint8_t padding[3];		 ///< Zeroed layout padding.
} kinetum_provider_memory_domain_fact;

/** Exact process-facility facts derived from the complete compiled graph. */
typedef struct kinetum_provider_process_facility_facts {
	uint32_t facility_index;				 ///< Compact facility instance identity.
	int32_t main_core_id;					 ///< Exact process coordinator CPU for this facility.
	const kinetum_provider_cpu_assignment *cpu_assignments;	 ///< Stable owner/core rows.
	uint32_t cpu_assignment_count;				 ///< Exact CPU row count.
	uint32_t cpu_assignment_padding;			 ///< Zeroed layout padding.
	const kinetum_provider_driver_attachment_fact *attachments;  ///< Exact native attachment set.
	uint32_t attachment_count;				     ///< Exact attachment row count.
	uint32_t attachment_padding;				     ///< Zeroed layout padding.
	const kinetum_provider_memory_domain_fact *memory_domains;   ///< Exact dependent memory domains.
	uint32_t memory_domain_count;				     ///< Exact memory-domain row count.
	uint8_t padding[12];					     ///< Zeroed layout padding.
} kinetum_provider_process_facility_facts;

/** One exact logical-to-driver-local port fact. */
typedef struct kinetum_provider_io_port_fact {
	uint32_t port_index;			  ///< Compact logical-port index.
	uint32_t driver_port_index;		  ///< Compact index in the driver's attachment set.
	uint32_t logical_port_id;		  ///< Module-visible logical port.
	uint32_t mtu;				  ///< Exact nonzero MTU.
	int32_t host_numa_node;			  ///< Valid only when has_host_numa_node is one.
	kinetum_provider_io_direction direction;  ///< Exact admitted port directions.
	uint8_t has_host_numa_node;		  ///< One when host_numa_node is plan truth.
	uint8_t has_resolved_mac_address;	  ///< One when all six MAC bytes are present.
	uint8_t direction_padding;		  ///< Zeroed layout padding.
	uint8_t resolved_mac_address[6];	  ///< Exact resolved MAC bytes.
	uint8_t padding[2];			  ///< Zeroed layout padding.
} kinetum_provider_io_port_fact;

/**
 * @brief One exact driver queue and direction-specific storage contract.
 *
 * RX carries one allocation-domain index. TX carries its complete nonempty
 * admission set. Indices are strictly ascending, valid compact domain values;
 * the immutable array remains borrowed for the fact record's lifetime.
 */
typedef struct kinetum_provider_io_stream_fact {
	uint32_t io_stream_index;		  ///< Compact stream identity.
	uint32_t port_index;			  ///< Exact compiled port index.
	uint32_t stage_instance_index;		  ///< Attached executable stage.
	uint32_t worker_index;			  ///< Sole queue owner worker.
	uint32_t driver_queue_id;		  ///< Driver-local queue identity.
	uint32_t descriptor_count;		  ///< Exact descriptor population.
	uint32_t steering_profile_index;	  ///< Valid only when has_steering_profile is one.
	kinetum_provider_io_direction direction;  ///< RX or TX queue operation.
	uint8_t has_steering_profile;		  ///< One when a profile is attached.
	uint8_t padding[2];			  ///< Zeroed layout padding.
	const uint32_t *storage_domain_indices;	  ///< Exact RX singleton or TX admission set.
	uint32_t storage_domain_count;		  ///< Nonzero complete domain count; one for RX.
	uint32_t storage_padding;		  ///< Zeroed pointer/count layout padding.
} kinetum_provider_io_stream_fact;

/**
 * @brief Query one already validated stream's immutable storage membership.
 * @param stream Validated call-borrowed stream fact.
 * @param domain Compact storage identity to find.
 * @return One exactly when the stream names this storage domain.
 */
static inline uint8_t kinetum_provider_io_stream_uses_storage(const kinetum_provider_io_stream_fact *stream,
							      uint32_t domain) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t first = 0;
	uint32_t last;
	if (stream == NULL || stream->storage_domain_indices == NULL || domain >= KINETUM_INVALID_STORAGE_DOMAIN) {
		return 0;
	}
	last = stream->storage_domain_count;
	while (first < last) {
		const uint32_t middle = first + (last - first) / 2u;
		if (stream->storage_domain_indices[middle] < domain) {
			first = middle + 1u;
		} else {
			last = middle;
		}
	}
	return first < stream->storage_domain_count && stream->storage_domain_indices[first] == domain;
}

/** One exact normalized steering profile consumed by an I/O component. */
typedef struct kinetum_provider_steering_fact {
	uint32_t steering_profile_index;		///< Compact profile identity.
	kinetum_provider_steering_kind kind;		///< Exact current steering mechanism.
	uint8_t symmetric;				///< One only for exact symmetric steering.
	uint8_t kind_padding[2];			///< Zeroed layout padding.
	const kinetum_provider_text_view *hash_fields;	///< Order-contractual field names.
	uint32_t hash_field_count;			///< Exact field count.
	uint32_t hash_field_padding;			///< Zeroed layout padding.
	kinetum_provider_byte_view hash_key;		///< Exact deterministic key bytes.
	const uint32_t *io_stream_indices;		///< Sorted governed stream indices.
	uint32_t io_stream_count;			///< Exact governed stream count.
	uint8_t padding[12];				///< Zeroed layout padding.
} kinetum_provider_steering_fact;

/** Exact I/O-driver facts derived without provider-side protobuf parsing. */
typedef struct kinetum_provider_io_driver_facts {
	uint32_t io_driver_index;				     ///< Compact I/O-driver instance identity.
	uint32_t index_padding;					     ///< Zeroed layout padding.
	const kinetum_provider_driver_attachment_fact *attachments;  ///< Exact configured attachments.
	uint32_t attachment_count;				     ///< Exact attachment count.
	uint32_t attachment_padding;				     ///< Zeroed layout padding.
	const kinetum_provider_io_port_fact *ports;		     ///< Exact logical/driver port bindings.
	uint32_t port_count;					     ///< Exact port count.
	uint32_t port_padding;					     ///< Zeroed layout padding.
	const kinetum_provider_io_stream_fact *streams;		     ///< Strictly ascending stream-index rows.
	uint32_t stream_count;					     ///< Exact stream count.
	uint32_t stream_padding;				     ///< Zeroed layout padding.
	const kinetum_provider_steering_fact *steering_profiles;     ///< Exact steering rows.
	uint32_t steering_profile_count;			     ///< Exact profile count.
	uint32_t steering_padding;				     ///< Zeroed layout padding.
} kinetum_provider_io_driver_facts;

/** Exact packet-storage facts and shared checked credit result. */
typedef struct kinetum_provider_packet_storage_facts {
	uint32_t storage_domain_index;	 ///< Compact storage-domain identity.
	uint32_t buffer_count;		 ///< Exact admitted record population.
	uint32_t data_room_bytes;	 ///< Exact payload-slot bytes.
	uint32_t headroom_bytes;	 ///< Exact bytes before packet data.
	uint32_t alignment_bytes;	 ///< Exact record/payload alignment.
	uint32_t cache_size_per_worker;	 ///< Exact provider-local cache policy.
	uint32_t required_buffer_count;	 ///< Shared checked formula result.
	uint32_t safety_margin;		 ///< One shared maximum-burst safety term.
	int32_t host_numa_node;		 ///< Valid only when has_host_numa_node is one.
	uint16_t maximum_packet_length;	 ///< Exact representable contiguous payload bound.
	uint8_t access_agents;		 ///< Exact compiled access-agent mask.
	uint8_t has_host_numa_node;	 ///< One when host_numa_node is plan truth.
	uint8_t padding[8];		 ///< Zeroed layout padding.
} kinetum_provider_packet_storage_facts;

/** Exact execution-provider stage and worker ownership facts. */
typedef struct kinetum_provider_execution_facts {
	uint32_t execution_provider_index;	 ///< Compact execution-provider identity.
	uint8_t required_access_agents;		 ///< Exact storage-access agent mask.
	uint8_t index_padding[3];		 ///< Zeroed layout padding.
	const uint32_t *stage_instance_indices;	 ///< Sorted executable stage indices.
	uint32_t stage_instance_count;		 ///< Exact stage count.
	uint32_t stage_padding;			 ///< Zeroed layout padding.
	const uint32_t *worker_indices;		 ///< Sorted owner-worker indices.
	uint32_t worker_count;			 ///< Exact owner-worker count.
	uint32_t worker_padding;		 ///< Zeroed layout padding.
} kinetum_provider_execution_facts;

/** One exact typed packet-path endpoint. */
typedef struct kinetum_provider_endpoint_fact {
	kinetum_provider_endpoint_kind kind;  ///< Endpoint namespace.
	uint8_t padding[3];		      ///< Zeroed layout padding.
	uint32_t endpoint_index;	      ///< Compact role-relative index.
} kinetum_provider_endpoint_fact;

/** Exact storage-transition facts for one directed domain handoff. */
typedef struct kinetum_provider_storage_transition_facts {
	uint32_t transition_index;		       ///< Compact transition identity.
	kinetum_provider_endpoint_fact from_endpoint;  ///< Exact directed source.
	kinetum_provider_endpoint_fact to_endpoint;    ///< Exact directed destination.
	uint32_t from_storage_domain_index;	       ///< Exact source storage owner.
	uint32_t to_storage_domain_index;	       ///< Exact destination storage owner.
	uint32_t staging_capacity;		       ///< Exact bounded-copy credits.
	int32_t staging_numa_node;		       ///< Valid only when has_staging_numa_node is one.
	kinetum_provider_transition_mode mode;	       ///< Exact transition mechanism.
	uint8_t has_staging_numa_node;		       ///< One when staging NUMA is plan truth.
	uint8_t padding[10];			       ///< Zeroed layout padding.
} kinetum_provider_storage_transition_facts;

/**
 * @brief Role-partitioned compiled fact authority for one factory request.
 *
 * Exactly one member is non-null, and it is the member named by request.role.
 * Every pointed-to record and subordinate array is immutable and borrowed for
 * the factory call only. This law prevents a component from interpreting one
 * role's bytes as another role's facts.
 */
typedef struct kinetum_provider_compiled_fact_record {
	const kinetum_provider_process_facility_facts *process_facility;      ///< PROCESS_FACILITY facts.
	const kinetum_provider_io_driver_facts *io_driver;		      ///< IO_DRIVER facts.
	const kinetum_provider_packet_storage_facts *packet_storage;	      ///< PACKET_STORAGE facts.
	const kinetum_provider_execution_facts *execution;		      ///< EXECUTION facts.
	const kinetum_provider_storage_transition_facts *storage_transition;  ///< STORAGE_TRANSITION facts.
} kinetum_provider_compiled_fact_record;

/**
 * @brief Exact facility-owned runtime-service entry callback.
 *
 * The return value is a backend thread-exit value, not join success or
 * failure. A join succeeds when the backend proves callback completion and
 * releases the borrowed callback storage, independently of this value.
 */
typedef int32_t (*kinetum_provider_runtime_service_entry_fn)(void *argument) KINETUM_PROVIDER_NOEXCEPT;

/**
 * @brief Immutable cold lifecycle operations for one process facility.
 *
 * The current DPDK facility owns two native execution mechanisms that cannot
 * be reconstructed by provider-neutral core: external packet-worker thread
 * registration and exact EAL-lcore lifecycle-service launch. The materializer
 * resolves this table once and gives the generic launch protocols only these
 * callbacks; native lcore identities never cross the ABI.
 *
 * register_worker_thread is invoked by the exact packet-worker thread after
 * owner-local CPU setup and before the all-or-none worker gate opens. A
 * successful call owns one native registration until the same thread invokes
 * unregister_worker_thread exactly once. The component must reject duplicate
 * compact-worker registration internally.
 *
 * bind_runtime_service_coordinator proves that the caller is the exact
 * compiled coordinator. launch_runtime_service retains @p entry and
 * @p argument only after success; join_runtime_service releases that borrowed
 * lifetime only after proving callback completion and retains ownership on a
 * genuine join failure so the caller may retry. The callback's integer result
 * is not join status. The facility instance and this table outlive every
 * registered worker and launched service.
 *
 * This is startup/shutdown machinery. No callback is reachable from packet
 * burst execution.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_provider_process_facility_operations {
	void *state;  ///< Component-owned process-facility instance state.
	/** @brief Acquire calling-thread native registration for one compact worker. */
	kinetum_provider_status (*register_worker_thread)(
		void *state, uint32_t worker_index, kinetum_provider_diagnostic *diagnostic) KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Release calling-thread native registration exactly once. */
	void (*unregister_worker_thread)(void *state, uint32_t worker_index) KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Bind/prove the caller-owned exact lifecycle coordinator. */
	kinetum_provider_status (*bind_runtime_service_coordinator)(
		void *state, uint32_t service_index, int32_t cpu_core_id,
		kinetum_provider_diagnostic *diagnostic) KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Launch one exact lifecycle executor with retained entry storage. */
	kinetum_provider_status (*launch_runtime_service)(void *state, uint32_t service_index, int32_t cpu_core_id,
							  kinetum_provider_runtime_service_entry_fn entry,
							  void *argument, kinetum_provider_diagnostic *diagnostic)
		KINETUM_PROVIDER_NOEXCEPT;
	/** @brief Join one exact lifecycle executor, retaining ownership on failure. */
	kinetum_provider_status (*join_runtime_service)(void *state, uint32_t service_index, int32_t cpu_core_id,
							kinetum_provider_diagnostic *diagnostic)
		KINETUM_PROVIDER_NOEXCEPT;
	uint64_t generation;	  ///< Exact nonzero runtime-generation identity.
	uint32_t facility_index;  ///< Exact compact process-facility identity.
	uint8_t padding[4];	  ///< Zeroed cache-line geometry padding.
} kinetum_provider_process_facility_operations;

/**
 * @brief Immutable operations and queue tables for one exact I/O driver.
 *
 * The compiled `streams` fact array is strictly ascending by io_stream_index.
 * `rx_queues[k]` corresponds to the kth RX row encountered while scanning that
 * array; `tx_queues[k]` corresponds to the kth TX row. Transactional
 * materialization must preserve those filtered positions when it binds compact
 * stream indices to operation tables. Materialization publishes this record
 * cold. The coordinator activates the complete driver only after module commit
 * and complete worker readiness while packet bodies remain closed, then
 * deactivates it after those workers join and before any dependency retires.
 * Each queue table retains its sole-worker ownership contract; neither array
 * may be reordered by a component.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_provider_io_driver_operations {
	void *state;						///< Component-owned cold driver instance state.
	kinetum_provider_io_lifecycle_fn activate_packet_io;	///< Make the complete driver live atomically.
	kinetum_provider_io_lifecycle_fn deactivate_packet_io;	///< Prove the complete driver cold atomically.
	const kinetum_packet_rx_burst_operations *rx_queues;	///< Immutable RX queue tables.
	const kinetum_packet_tx_burst_operations *tx_queues;	///< Immutable TX queue tables.
	kinetum_provider_observe_io_fn observe_statistics;	///< Cold complete driver observation.
	uint32_t rx_queue_count;				///< Exact RX table count.
	uint32_t tx_queue_count;				///< Exact TX table count.
	uint32_t io_driver_index;				///< Exact compiled driver identity.
	uint8_t padding[4];					///< Zeroed cache-line geometry padding.
} kinetum_provider_io_driver_operations;

/**
 * @brief Immutable materialized record for the current CPU execution role.
 *
 * CPU stage execution remains the platform batch mechanism. This record binds
 * that mechanism to one exact execution instance and access proof; it adds no
 * second per-packet callback or provider lookup.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_provider_execution_operations {
	void *state;			    ///< Component-owned execution instance state.
	uint32_t execution_provider_index;  ///< Exact compiled execution identity.
	uint8_t required_access_agents;	    ///< Exact admitted access-agent mask.
	uint8_t padding[51];		    ///< Zeroed cache-line geometry padding.
} kinetum_provider_execution_operations;

/**
 * @brief Immutable burst operation for one exact storage transition.
 *
 * transfer_burst consumes exactly sources[0,return_value) and publishes one
 * owned destination pointer for each consumed source. The caller retains the
 * untouched suffix. A zero-copy transition may publish the same pointer after
 * logical ownership transfer; a bounded-copy transition publishes distinct
 * destination storage and retires each consumed source exactly once. The
 * source and destination pointer-array ranges may overlap; the operation acts
 * as if it captured the complete attempted source prefix before publishing any
 * destination pointer.
 */
typedef struct KINETUM_PROVIDER_ALIGNAS(64) kinetum_provider_storage_transition_operations {
	void *state;  ///< Component-owned transition state.
	/** @brief Transfer one exact accepted prefix without consuming its suffix. */
	uint16_t (*transfer_burst)(void *state, kinetum_packet_record *const *sources,
				   kinetum_packet_record **destinations, uint16_t count) KINETUM_PROVIDER_NOEXCEPT;
	uint32_t generation;			///< Exact runtime-generation identity.
	uint32_t transition_index;		///< Exact compiled transition identity.
	uint32_t from_storage_domain_index;	///< Exact source storage owner.
	uint32_t to_storage_domain_index;	///< Exact destination storage owner.
	kinetum_provider_transition_mode mode;	///< Exact materialized transition mechanism.
	uint8_t padding[31];			///< Zeroed cache-line geometry padding.
} kinetum_provider_storage_transition_operations;

/**
 * @brief Borrowed handle for one already materialized provider dependency.
 *
 * Factory requests list plan-declared process facilities first in stable
 * instance-identity order, followed by compiler-derived role dependencies in
 * provider-role then stable instance-identity order. Every row has one unique
 * `(role, instance_id)` key, matching contract type_url, non-null opaque
 * instance, and non-null exact immutable role operation record. A component
 * may retain only instance and operations. Text views and the dependency array
 * are borrowed for the factory call and must not be retained.
 *
 * The materializer constructs every dependency before its dependent, keeps
 * both retained handles valid until every dependent is destroyed, and destroys
 * dependents before dependencies. Component admission enforces descriptor
 * role/factory shape. The transactional materializer enforces request ordering,
 * identity, operation-table nullability, and lifetime before invoking a factory.
 */
typedef struct kinetum_provider_dependency_handle {
	kinetum_provider_text_view instance_id;	 ///< Exact compiled provider-instance identity.
	kinetum_provider_text_view type_url;	 ///< Exact provider contract identity.
	const void *instance;			 ///< Borrowed non-null component-owned instance.
	const void *operations;			 ///< Non-null immutable role-specific operation record.
	kinetum_provider_role role;		 ///< Exact role of this dependency.
	uint8_t padding[7];			 ///< Zeroed layout padding.
} kinetum_provider_dependency_handle;

/**
 * @brief Exact cold factory request for one provider contract row.
 *
 * canonical_configuration is the pure catalog's already-normalized payload.
 * compiled_facts contains exactly one immutable role-specific C record selected
 * by role and covered by the ABI identity; it is never protobuf or native
 * provider state. dependencies is null exactly when dependency_count is zero.
 * The component must not retain any
 * borrowed text, byte, or array view after the callback returns; only the
 * dependency instance/operation handles and the copied cold logging capability
 * have the longer lifetime stated by their declarations.
 */
typedef struct kinetum_provider_factory_request {
	kinetum_provider_text_view instance_id;			 ///< Exact compiled instance identity.
	kinetum_provider_text_view type_url;			 ///< Exact canonical contract identity.
	kinetum_provider_byte_view canonical_configuration;	 ///< Canonical payload bytes.
	kinetum_provider_compiled_fact_record compiled_facts;	 ///< Exactly one role-matching fact pointer.
	const kinetum_provider_dependency_handle *dependencies;	 ///< Exact ordered borrowed dependencies.
	uint32_t dependency_count;				 ///< Exact dependency row count.
	uint32_t dependency_padding;				 ///< Zeroed layout padding.
	uint64_t runtime_generation;				 ///< Exact materialization generation.
	kinetum_provider_role role;				 ///< Exact role of this request.
	uint8_t padding[7];					 ///< Zeroed layout padding.
	kinetum_provider_cold_log logging;			 ///< Required host capability borrowed through destroy.
} kinetum_provider_factory_request;

/**
 * @brief Generic cold instance result returned by one exact role factory.
 *
 * The caller zero-initializes the result. Failure leaves all three fields null.
 * Success publishes a non-null instance, role-specific immutable operation
 * record, and destroy callback for every role. Failure publishes none of the
 * three. Transactional materialization validates this exact nullability before
 * adopting ownership and then validates the role-specific record.
 */
typedef struct kinetum_provider_factory_result {
	void *instance;						    ///< Component-owned opaque instance.
	const void *operations;					    ///< Immutable role-specific operation table.
	void (*destroy)(void *instance) KINETUM_PROVIDER_NOEXCEPT;  ///< Exact instance reclamation.
} kinetum_provider_factory_result;

/**
 * @brief Non-materializing host-proof request.
 *
 * compiled_facts contains exactly one immutable role-specific C record selected
 * by role, under the same structural law used by factory requests. A proof
 * callback may inspect native state ephemerally but may not reserve resources,
 * initialize a facility, create a persistent thread, or publish an operation
 * table. Every borrowed view and fact tree is valid only for the callback.
 */
typedef struct kinetum_provider_host_proof_request {
	kinetum_provider_text_view type_url;		       ///< Exact canonical contract identity.
	kinetum_provider_byte_view canonical_configuration;    ///< Canonical payload bytes.
	kinetum_provider_compiled_fact_record compiled_facts;  ///< Exactly one role-matching fact pointer.
	kinetum_provider_role role;			       ///< Exact role of this proof request.
	uint8_t padding[7];				       ///< Zeroed layout padding.
} kinetum_provider_host_proof_request;

/** Exact cold factory callback for one contract row. */
typedef kinetum_provider_status (*kinetum_provider_factory_fn)(
	const kinetum_provider_factory_request *request, kinetum_provider_factory_result *result,
	kinetum_provider_diagnostic *diagnostic) KINETUM_PROVIDER_NOEXCEPT;

/** Exact non-materializing host-proof callback for one contract row. */
typedef kinetum_provider_status (*kinetum_provider_host_proof_fn)(const kinetum_provider_host_proof_request *request,
								  kinetum_provider_diagnostic *diagnostic)
	KINETUM_PROVIDER_NOEXCEPT;

/**
 * @brief Role-partitioned cold factory authority for one contract row.
 *
 * Exactly one member is non-null, and it is the member named by the enclosing
 * contract row's role. Every other member is null. This makes role ownership a
 * structural descriptor fact instead of a role tag beside an untyped callback.
 * Component admission enforces the law before publishing any row; transactional
 * materialization invokes only the already-admitted matching member.
 */
typedef struct kinetum_provider_factory_record {
	kinetum_provider_factory_fn process_facility;	 ///< Non-null only for PROCESS_FACILITY.
	kinetum_provider_factory_fn io_driver;		 ///< Non-null only for IO_DRIVER.
	kinetum_provider_factory_fn packet_storage;	 ///< Non-null only for PACKET_STORAGE.
	kinetum_provider_factory_fn execution;		 ///< Non-null only for EXECUTION.
	kinetum_provider_factory_fn storage_transition;	 ///< Non-null only for STORAGE_TRANSITION.
} kinetum_provider_factory_record;

/**
 * @brief Return whether a provider role is one exact declared ABI value.
 *
 * @param role Candidate fixed-width role.
 * @return One only for a declared role; zero otherwise.
 */
static inline uint8_t kinetum_provider_role_is_valid(kinetum_provider_role role) KINETUM_PROVIDER_NOEXCEPT
{
	return role >= KINETUM_PROVIDER_ROLE_PROCESS_FACILITY && role <= KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION;
}

/**
 * @brief Return whether a provider callback status is one exact ABI value.
 *
 * @param status Candidate fixed-width status.
 * @return One only for the closed declared status set; zero otherwise.
 */
static inline uint8_t kinetum_provider_status_is_valid(kinetum_provider_status status) KINETUM_PROVIDER_NOEXCEPT
{
	return status >= KINETUM_PROVIDER_STATUS_OK && status <= KINETUM_PROVIDER_STATUS_IMPLEMENTATION_ERROR;
}

/**
 * @brief Validate one typed provider observation state.
 * @param state Candidate fixed-width state.
 * @return One only for the complete declared state set.
 */
static inline uint8_t
kinetum_provider_observation_state_is_valid(kinetum_provider_observation_state state) KINETUM_PROVIDER_NOEXCEPT
{
	return state >= KINETUM_PROVIDER_OBSERVATION_AVAILABLE_EXACT &&
	       state <= KINETUM_PROVIDER_OBSERVATION_READ_FAILED;
}

/**
 * @brief Return whether an observation state owns numeric counter values.
 * @param state Candidate valid state.
 * @return One only for exact or approximate availability.
 */
static inline uint8_t
kinetum_provider_observation_has_values(kinetum_provider_observation_state state) KINETUM_PROVIDER_NOEXCEPT
{
	return state == KINETUM_PROVIDER_OBSERVATION_AVAILABLE_EXACT ||
	       state == KINETUM_PROVIDER_OBSERVATION_AVAILABLE_APPROXIMATE;
}

/**
 * @brief Validate the complete current process-facility operation record.
 *
 * @param operations Candidate immutable facility operations.
 * @return One only for exact state, callbacks, generation, and zero padding.
 */
static inline uint8_t kinetum_provider_process_facility_operations_are_valid(
	const kinetum_provider_process_facility_operations *operations) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (operations == NULL || operations->state == NULL || operations->register_worker_thread == NULL ||
	    operations->unregister_worker_thread == NULL || operations->bind_runtime_service_coordinator == NULL ||
	    operations->launch_runtime_service == NULL || operations->join_runtime_service == NULL ||
	    operations->generation == 0) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(operations->padding); ++index) {
		if (operations->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one exact packet-storage operation record.
 *
 * @param operations Candidate immutable storage operations.
 * @return One only for complete callbacks, exact identity, known capabilities,
 *         and zero padding.
 */
static inline uint8_t kinetum_provider_packet_storage_operations_are_valid(
	const kinetum_packet_storage_domain_operations *operations) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	const uint32_t known_capabilities = KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_READ |
					    KINETUM_PACKET_STORAGE_CPU_CONTIGUOUS_WRITE |
					    KINETUM_PACKET_STORAGE_NIC_RX_DMA | KINETUM_PACKET_STORAGE_NIC_TX_DMA |
					    KINETUM_PACKET_STORAGE_WRITABLE_CLONE;
	if (operations == NULL || operations->state == NULL || operations->acquire_burst == NULL ||
	    operations->clone_writable == NULL || operations->copy_origins_burst == NULL ||
	    operations->release_burst == NULL || operations->observe_statistics == NULL ||
	    operations->generation == 0 || operations->domain_index == KINETUM_INVALID_STORAGE_DOMAIN ||
	    operations->maximum_packet_length == 0 || operations->capabilities == 0 ||
	    (operations->capabilities & ~known_capabilities) != 0) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(operations->padding); ++index) {
		if (operations->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one exact receive-queue operation record.
 *
 * @param operations Candidate immutable RX operations.
 * @return One only for a complete queue, nonzero bound, exact logical port,
 *         and zero padding.
 */
static inline uint8_t
kinetum_provider_rx_operations_are_valid(const kinetum_packet_rx_burst_operations *operations) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (operations == NULL || operations->state == NULL || operations->receive_burst == NULL ||
	    operations->maximum_burst == 0 || operations->logical_port == KINETUM_INVALID_PORT) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(operations->padding); ++index) {
		if (operations->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one exact transmit-queue operation record.
 *
 * @param operations Candidate immutable TX operations.
 * @return One only for complete callbacks, a nonzero bound, exact logical
 *         port, and zero padding.
 */
static inline uint8_t
kinetum_provider_tx_operations_are_valid(const kinetum_packet_tx_burst_operations *operations) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (operations == NULL || operations->state == NULL || operations->transmit_burst == NULL ||
	    operations->flush == NULL || operations->maybe_flush == NULL || operations->maximum_burst == 0 ||
	    operations->logical_port == KINETUM_INVALID_PORT) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(operations->padding); ++index) {
		if (operations->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one exact I/O-driver operation record.
 *
 * Queue arrays are null exactly when their count is zero. Every published row
 * is itself complete, and one driver must own at least one queue operation.
 *
 * @param operations Candidate immutable driver operations.
 * @return One only for exact array shape, complete queue rows, and zero
 *         padding.
 */
static inline uint8_t kinetum_provider_io_driver_operations_are_valid(
	const kinetum_provider_io_driver_operations *operations) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (operations == NULL || operations->state == NULL || operations->activate_packet_io == NULL ||
	    operations->deactivate_packet_io == NULL || operations->observe_statistics == NULL ||
	    (operations->rx_queue_count == 0) != (operations->rx_queues == NULL) ||
	    (operations->tx_queue_count == 0) != (operations->tx_queues == NULL) ||
	    (operations->rx_queue_count == 0 && operations->tx_queue_count == 0) ||
	    operations->io_driver_index == UINT32_MAX) {
		return 0;
	}
	for (index = 0; index < operations->rx_queue_count; ++index) {
		if (!kinetum_provider_rx_operations_are_valid(&operations->rx_queues[index])) {
			return 0;
		}
	}
	for (index = 0; index < operations->tx_queue_count; ++index) {
		if (!kinetum_provider_tx_operations_are_valid(&operations->tx_queues[index])) {
			return 0;
		}
	}
	for (index = 0; index < (uint32_t)sizeof(operations->padding); ++index) {
		if (operations->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one exact execution-provider operation record.
 *
 * @param operations Candidate immutable execution operations.
 * @return One only for a non-null instance, one current access-agent mask,
 *         and zero padding.
 */
static inline uint8_t kinetum_provider_execution_operations_are_valid(
	const kinetum_provider_execution_operations *operations) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	const uint8_t known_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU | KINETUM_PROVIDER_ACCESS_AGENT_NIC_DMA;
	if (operations == NULL || operations->state == NULL || operations->required_access_agents == 0 ||
	    (operations->required_access_agents & (uint8_t)~known_access_agents) != 0) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(operations->padding); ++index) {
		if (operations->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one exact storage-transition operation record.
 *
 * @param operations Candidate immutable transition operations.
 * @return One only for a complete bounded burst callback, exact identities,
 *         a current mode, and zero padding.
 */
static inline uint8_t kinetum_provider_storage_transition_operations_are_valid(
	const kinetum_provider_storage_transition_operations *operations) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (operations == NULL || operations->state == NULL || operations->transfer_burst == NULL ||
	    operations->generation == 0 || operations->from_storage_domain_index == KINETUM_INVALID_STORAGE_DOMAIN ||
	    operations->to_storage_domain_index == KINETUM_INVALID_STORAGE_DOMAIN ||
	    (operations->mode != KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE &&
	     operations->mode != KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY)) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(operations->padding); ++index) {
		if (operations->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one immutable operation record against its exact role.
 *
 * @param role Exact provider role.
 * @param operations Candidate role-specific operation record.
 * @return One only when the record satisfies that role's complete current ABI.
 */
static inline uint8_t kinetum_provider_operations_match_role(kinetum_provider_role role,
							     const void *operations) KINETUM_PROVIDER_NOEXCEPT
{
	if (operations == NULL) {
		return 0;
	}
	switch (role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		return kinetum_provider_process_facility_operations_are_valid(
			(const kinetum_provider_process_facility_operations *)operations);
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		return kinetum_provider_io_driver_operations_are_valid(
			(const kinetum_provider_io_driver_operations *)operations);
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		return kinetum_provider_packet_storage_operations_are_valid(
			(const kinetum_packet_storage_domain_operations *)operations);
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		return kinetum_provider_execution_operations_are_valid(
			(const kinetum_provider_execution_operations *)operations);
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		return kinetum_provider_storage_transition_operations_are_valid(
			(const kinetum_provider_storage_transition_operations *)operations);
	default:
		return 0;
	}
}

/**
 * @brief Validate one borrowed text view without interpreting its bytes.
 *
 * @param view Candidate borrowed text.
 * @return One only when padding is zero and a nonzero size has a non-null pointer.
 */
static inline uint8_t kinetum_provider_text_view_is_valid(kinetum_provider_text_view view) KINETUM_PROVIDER_NOEXCEPT
{
	return view.padding == 0 && (view.size == 0 || view.data != NULL);
}

/**
 * @brief Validate one borrowed byte view without interpreting its bytes.
 *
 * @param view Candidate borrowed bytes.
 * @return One only when padding is zero and a nonzero size has a non-null pointer.
 */
static inline uint8_t kinetum_provider_byte_view_is_valid(kinetum_provider_byte_view view) KINETUM_PROVIDER_NOEXCEPT
{
	return view.padding == 0 && (view.size == 0 || view.data != NULL);
}

/**
 * @brief Compare two already-valid text views by unsigned byte order.
 *
 * @param left First borrowed text.
 * @param right Second borrowed text.
 * @return Negative, zero, or positive under exact lexicographic ordering.
 */
static inline int kinetum_provider_compare_text_views(kinetum_provider_text_view left,
						      kinetum_provider_text_view right) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index = 0;
	const uint32_t common_size = left.size < right.size ? left.size : right.size;
	for (; index < common_size; ++index) {
		const uint8_t left_byte = (uint8_t)left.data[index];
		const uint8_t right_byte = (uint8_t)right.data[index];
		if (left_byte < right_byte) {
			return -1;
		}
		if (left_byte > right_byte) {
			return 1;
		}
	}
	if (left.size < right.size) {
		return -1;
	}
	if (left.size > right.size) {
		return 1;
	}
	return 0;
}

/**
 * @brief Return whether one fixed byte range is completely zero.
 *
 * @param bytes Non-null byte range when @p size is nonzero.
 * @param size Exact byte count.
 * @return One only for a null/zero pair or an all-zero nonempty range.
 */
static inline uint8_t kinetum_provider_bytes_are_zero(const uint8_t *bytes, uint32_t size) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (size == 0) {
		return bytes == NULL;
	}
	if (bytes == NULL) {
		return 0;
	}
	for (index = 0; index < size; ++index) {
		if (bytes[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate pointer presence for one borrowed fixed-width array.
 *
 * @param values Borrowed first element.
 * @param count Exact element count.
 * @return One only when null means zero elements and non-null means nonzero.
 */
static inline uint8_t kinetum_provider_pointer_count_is_valid(const void *values,
							      uint32_t count) KINETUM_PROVIDER_NOEXCEPT
{
	return (count == 0) == (values == NULL);
}

/**
 * @brief Validate one compiled process-facility fact tree's ABI shape.
 *
 * This function validates closed enum values, borrowed-array nullability,
 * borrowed text views, booleans, and every explicit padding field. Semantic
 * CPU, NUMA, attachment, and memory agreement remains the shared compiler's
 * authority.
 *
 * @param facts Candidate immutable facility facts.
 * @return One only for one structurally exact C fact tree.
 */
static inline uint8_t kinetum_provider_process_facility_facts_are_valid(
	const kinetum_provider_process_facility_facts *facts) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (facts == NULL || facts->cpu_assignment_padding != 0 || facts->attachment_padding != 0 ||
	    !kinetum_provider_pointer_count_is_valid(facts->cpu_assignments, facts->cpu_assignment_count) ||
	    !kinetum_provider_pointer_count_is_valid(facts->attachments, facts->attachment_count) ||
	    !kinetum_provider_pointer_count_is_valid(facts->memory_domains, facts->memory_domain_count) ||
	    !kinetum_provider_bytes_are_zero(facts->padding, (uint32_t)sizeof(facts->padding))) {
		return 0;
	}
	for (index = 0; index < facts->cpu_assignment_count; ++index) {
		const kinetum_provider_cpu_assignment *assignment = &facts->cpu_assignments[index];
		if ((assignment->kind != KINETUM_PROVIDER_CPU_OWNER_PACKET_WORKER &&
		     assignment->kind != KINETUM_PROVIDER_CPU_OWNER_TRANSITION_COORDINATOR &&
		     assignment->kind != KINETUM_PROVIDER_CPU_OWNER_LIFECYCLE_EXECUTOR) ||
		    !kinetum_provider_bytes_are_zero(assignment->padding, (uint32_t)sizeof(assignment->padding))) {
			return 0;
		}
	}
	for (index = 0; index < facts->attachment_count; ++index) {
		const kinetum_provider_driver_attachment_fact *attachment = &facts->attachments[index];
		if (!kinetum_provider_text_view_is_valid(attachment->driver_port_id) ||
		    !kinetum_provider_text_view_is_valid(attachment->attachment_identity) ||
		    (attachment->kind != KINETUM_PROVIDER_ATTACHMENT_PCI &&
		     attachment->kind != KINETUM_PROVIDER_ATTACHMENT_TAP &&
		     attachment->kind != KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4) ||
		    !kinetum_provider_bytes_are_zero(attachment->padding, (uint32_t)sizeof(attachment->padding))) {
			return 0;
		}
	}
	for (index = 0; index < facts->memory_domain_count; ++index) {
		const kinetum_provider_memory_domain_fact *memory = &facts->memory_domains[index];
		if (memory->has_host_numa_node > 1 ||
		    (memory->has_host_numa_node == 0 && memory->host_numa_node != 0) ||
		    (memory->has_host_numa_node == 1 && memory->host_numa_node < 0) ||
		    !kinetum_provider_bytes_are_zero(memory->padding, (uint32_t)sizeof(memory->padding))) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one compiled I/O-driver fact tree's ABI shape.
 *
 * @param facts Candidate immutable driver facts.
 * @return One only for closed enums, exact pointer/count pairs, strictly
 *         increasing stream identities, valid views, canonical booleans, and
 *         zero padding.
 */
static inline uint8_t
kinetum_provider_io_driver_facts_are_valid(const kinetum_provider_io_driver_facts *facts) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (facts == NULL || facts->index_padding != 0 || facts->attachment_padding != 0 || facts->port_padding != 0 ||
	    facts->stream_padding != 0 || facts->steering_padding != 0 ||
	    !kinetum_provider_pointer_count_is_valid(facts->attachments, facts->attachment_count) ||
	    !kinetum_provider_pointer_count_is_valid(facts->ports, facts->port_count) ||
	    !kinetum_provider_pointer_count_is_valid(facts->streams, facts->stream_count) ||
	    !kinetum_provider_pointer_count_is_valid(facts->steering_profiles, facts->steering_profile_count)) {
		return 0;
	}
	for (index = 0; index < facts->attachment_count; ++index) {
		const kinetum_provider_driver_attachment_fact *attachment = &facts->attachments[index];
		if (!kinetum_provider_text_view_is_valid(attachment->driver_port_id) ||
		    !kinetum_provider_text_view_is_valid(attachment->attachment_identity) ||
		    (attachment->kind != KINETUM_PROVIDER_ATTACHMENT_PCI &&
		     attachment->kind != KINETUM_PROVIDER_ATTACHMENT_TAP &&
		     attachment->kind != KINETUM_PROVIDER_ATTACHMENT_UDP_IPV4) ||
		    !kinetum_provider_bytes_are_zero(attachment->padding, (uint32_t)sizeof(attachment->padding))) {
			return 0;
		}
	}
	for (index = 0; index < facts->port_count; ++index) {
		const kinetum_provider_io_port_fact *port = &facts->ports[index];
		if ((port->direction != KINETUM_PROVIDER_IO_DIRECTION_RX &&
		     port->direction != KINETUM_PROVIDER_IO_DIRECTION_TX &&
		     port->direction != KINETUM_PROVIDER_IO_DIRECTION_BIDIRECTIONAL) ||
		    port->has_host_numa_node > 1 || port->has_resolved_mac_address > 1 ||
		    (port->has_host_numa_node == 0 && port->host_numa_node != 0) ||
		    (port->has_host_numa_node == 1 && port->host_numa_node < 0) ||
		    (port->has_resolved_mac_address == 0 &&
		     !kinetum_provider_bytes_are_zero(port->resolved_mac_address,
						      (uint32_t)sizeof(port->resolved_mac_address))) ||
		    port->direction_padding != 0 ||
		    !kinetum_provider_bytes_are_zero(port->padding, (uint32_t)sizeof(port->padding))) {
			return 0;
		}
	}
	for (index = 0; index < facts->stream_count; ++index) {
		const kinetum_provider_io_stream_fact *stream = &facts->streams[index];
		uint32_t domain_index;
		if ((stream->direction != KINETUM_PROVIDER_IO_DIRECTION_RX &&
		     stream->direction != KINETUM_PROVIDER_IO_DIRECTION_TX) ||
		    (index != 0 && facts->streams[index - 1].io_stream_index >= stream->io_stream_index) ||
		    stream->has_steering_profile > 1 ||
		    (stream->has_steering_profile == 0 && stream->steering_profile_index != 0) ||
		    !kinetum_provider_bytes_are_zero(stream->padding, (uint32_t)sizeof(stream->padding)) ||
		    stream->storage_padding != 0 || stream->storage_domain_indices == NULL ||
		    stream->storage_domain_count == 0 ||
		    stream->storage_domain_count > KINETUM_INVALID_STORAGE_DOMAIN ||
		    (stream->direction == KINETUM_PROVIDER_IO_DIRECTION_RX && stream->storage_domain_count != 1u)) {
			return 0;
		}
		for (domain_index = 0; domain_index < stream->storage_domain_count; ++domain_index) {
			if (stream->storage_domain_indices[domain_index] >= KINETUM_INVALID_STORAGE_DOMAIN ||
			    (domain_index != 0 && stream->storage_domain_indices[domain_index - 1u] >=
							  stream->storage_domain_indices[domain_index])) {
				return 0;
			}
		}
	}
	for (index = 0; index < facts->steering_profile_count; ++index) {
		uint32_t field_index;
		const kinetum_provider_steering_fact *steering = &facts->steering_profiles[index];
		if ((steering->kind != KINETUM_PROVIDER_STEERING_NONE &&
		     steering->kind != KINETUM_PROVIDER_STEERING_RSS) ||
		    steering->symmetric > 1 ||
		    !kinetum_provider_bytes_are_zero(steering->kind_padding,
						     (uint32_t)sizeof(steering->kind_padding)) ||
		    steering->hash_field_padding != 0 ||
		    !kinetum_provider_pointer_count_is_valid(steering->hash_fields, steering->hash_field_count) ||
		    !kinetum_provider_byte_view_is_valid(steering->hash_key) ||
		    !kinetum_provider_pointer_count_is_valid(steering->io_stream_indices, steering->io_stream_count) ||
		    !kinetum_provider_bytes_are_zero(steering->padding, (uint32_t)sizeof(steering->padding))) {
			return 0;
		}
		for (field_index = 0; field_index < steering->hash_field_count; ++field_index) {
			if (!kinetum_provider_text_view_is_valid(steering->hash_fields[field_index])) {
				return 0;
			}
		}
	}
	return 1;
}

/**
 * @brief Validate one compiled packet-storage fact record's ABI shape.
 *
 * @param facts Candidate immutable storage facts.
 * @return One only for a current access mask, canonical optional presence,
 *         and zero padding.
 */
static inline uint8_t kinetum_provider_packet_storage_facts_are_valid(
	const kinetum_provider_packet_storage_facts *facts) KINETUM_PROVIDER_NOEXCEPT
{
	const uint8_t known_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU | KINETUM_PROVIDER_ACCESS_AGENT_NIC_DMA;
	return facts != NULL && facts->has_host_numa_node <= 1 && facts->access_agents != 0 &&
	       (facts->has_host_numa_node != 0 || facts->host_numa_node == 0) &&
	       (facts->has_host_numa_node == 0 || facts->host_numa_node >= 0) &&
	       (facts->access_agents & (uint8_t)~known_access_agents) == 0 &&
	       kinetum_provider_bytes_are_zero(facts->padding, (uint32_t)sizeof(facts->padding));
}

/**
 * @brief Validate one compiled execution fact tree's ABI shape.
 *
 * @param facts Candidate immutable execution facts.
 * @return One only for exact pointer/count pairs, a current access mask, and
 *         zero padding.
 */
static inline uint8_t
kinetum_provider_execution_facts_are_valid(const kinetum_provider_execution_facts *facts) KINETUM_PROVIDER_NOEXCEPT
{
	const uint8_t known_access_agents = KINETUM_PROVIDER_ACCESS_AGENT_CPU | KINETUM_PROVIDER_ACCESS_AGENT_NIC_DMA;
	return facts != NULL && facts->required_access_agents != 0 &&
	       (facts->required_access_agents & (uint8_t)~known_access_agents) == 0 &&
	       kinetum_provider_bytes_are_zero(facts->index_padding, (uint32_t)sizeof(facts->index_padding)) &&
	       kinetum_provider_pointer_count_is_valid(facts->stage_instance_indices, facts->stage_instance_count) &&
	       facts->stage_padding == 0 &&
	       kinetum_provider_pointer_count_is_valid(facts->worker_indices, facts->worker_count) &&
	       facts->worker_padding == 0;
}

/**
 * @brief Validate one compiled storage-transition fact record's ABI shape.
 *
 * @param facts Candidate immutable transition facts.
 * @return One only for current endpoint/mode values, canonical optional
 *         presence, and zero padding.
 */
static inline uint8_t kinetum_provider_storage_transition_facts_are_valid(
	const kinetum_provider_storage_transition_facts *facts) KINETUM_PROVIDER_NOEXCEPT
{
	if (facts == NULL ||
	    (facts->from_endpoint.kind != KINETUM_PROVIDER_ENDPOINT_IO_STREAM &&
	     facts->from_endpoint.kind != KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE) ||
	    (facts->to_endpoint.kind != KINETUM_PROVIDER_ENDPOINT_IO_STREAM &&
	     facts->to_endpoint.kind != KINETUM_PROVIDER_ENDPOINT_STAGE_INSTANCE) ||
	    (facts->mode != KINETUM_PROVIDER_TRANSITION_ZERO_COPY_SHARE &&
	     facts->mode != KINETUM_PROVIDER_TRANSITION_BOUNDED_COPY) ||
	    facts->has_staging_numa_node > 1 || (facts->has_staging_numa_node == 0 && facts->staging_numa_node != 0) ||
	    (facts->has_staging_numa_node == 1 && facts->staging_numa_node < 0) ||
	    !kinetum_provider_bytes_are_zero(facts->from_endpoint.padding,
					     (uint32_t)sizeof(facts->from_endpoint.padding)) ||
	    !kinetum_provider_bytes_are_zero(facts->to_endpoint.padding,
					     (uint32_t)sizeof(facts->to_endpoint.padding)) ||
	    !kinetum_provider_bytes_are_zero(facts->padding, (uint32_t)sizeof(facts->padding))) {
		return 0;
	}
	return 1;
}

/**
 * @brief Enforce the role-tagged exactly-one compiled-fact law.
 *
 * @param facts Candidate role-partitioned fact record.
 * @param role Exact request role.
 * @return One only when exactly the role-owned member is non-null.
 */
static inline uint8_t kinetum_provider_compiled_facts_match_role(const kinetum_provider_compiled_fact_record *facts,
								 kinetum_provider_role role) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t present_count;
	if (facts == NULL || !kinetum_provider_role_is_valid(role)) {
		return 0;
	}
	present_count = (facts->process_facility != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(facts->io_driver != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(facts->packet_storage != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(facts->execution != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(facts->storage_transition != NULL ? UINT32_C(1) : UINT32_C(0));
	if (present_count != UINT32_C(1)) {
		return 0;
	}
	switch (role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		return facts->process_facility != NULL;
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		return facts->io_driver != NULL;
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		return facts->packet_storage != NULL;
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		return facts->execution != NULL;
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		return facts->storage_transition != NULL;
	default:
		return 0;
	}
}

/**
 * @brief Validate the selected compiled fact tree against its exact role.
 *
 * @param facts Candidate role-partitioned fact record.
 * @param role Exact request role.
 * @return One only when exactly one role member is present and that complete
 *         fact tree satisfies the C ABI's structural law.
 */
static inline uint8_t
kinetum_provider_compiled_facts_are_valid_for_role(const kinetum_provider_compiled_fact_record *facts,
						   kinetum_provider_role role) KINETUM_PROVIDER_NOEXCEPT
{
	if (!kinetum_provider_compiled_facts_match_role(facts, role)) {
		return 0;
	}
	switch (role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		return kinetum_provider_process_facility_facts_are_valid(facts->process_facility);
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		return kinetum_provider_io_driver_facts_are_valid(facts->io_driver);
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		return kinetum_provider_packet_storage_facts_are_valid(facts->packet_storage);
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		return kinetum_provider_execution_facts_are_valid(facts->execution);
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		return kinetum_provider_storage_transition_facts_are_valid(facts->storage_transition);
	default:
		return 0;
	}
}

/**
 * @brief Enforce the role-tagged exactly-one factory law.
 *
 * @param factories Candidate role-partitioned factory record.
 * @param role Exact descriptor-row role.
 * @return One only when exactly the role-owned callback is non-null.
 */
static inline uint8_t kinetum_provider_factories_match_role(const kinetum_provider_factory_record *factories,
							    kinetum_provider_role role) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t present_count;
	if (factories == NULL || !kinetum_provider_role_is_valid(role)) {
		return 0;
	}
	present_count = (factories->process_facility != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(factories->io_driver != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(factories->packet_storage != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(factories->execution != NULL ? UINT32_C(1) : UINT32_C(0)) +
			(factories->storage_transition != NULL ? UINT32_C(1) : UINT32_C(0));
	if (present_count != UINT32_C(1)) {
		return 0;
	}
	switch (role) {
	case KINETUM_PROVIDER_ROLE_PROCESS_FACILITY:
		return factories->process_facility != NULL;
	case KINETUM_PROVIDER_ROLE_IO_DRIVER:
		return factories->io_driver != NULL;
	case KINETUM_PROVIDER_ROLE_PACKET_STORAGE:
		return factories->packet_storage != NULL;
	case KINETUM_PROVIDER_ROLE_EXECUTION:
		return factories->execution != NULL;
	case KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION:
		return factories->storage_transition != NULL;
	default:
		return 0;
	}
}

/**
 * @brief Validate one already-materialized dependency handle.
 *
 * @param dependency Candidate borrowed dependency.
 * @return One only for exact identity, role, handle, and operation nullability.
 */
static inline uint8_t
kinetum_provider_dependency_is_valid(const kinetum_provider_dependency_handle *dependency) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (dependency == NULL || dependency->instance_id.size == 0 || dependency->type_url.size == 0 ||
	    !kinetum_provider_text_view_is_valid(dependency->instance_id) ||
	    !kinetum_provider_text_view_is_valid(dependency->type_url) || dependency->instance == NULL ||
	    !kinetum_provider_role_is_valid(dependency->role)) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(dependency->padding); ++index) {
		if (dependency->padding[index] != 0) {
			return 0;
		}
	}
	return kinetum_provider_operations_match_role(dependency->role, dependency->operations);
}

/**
 * @brief Validate the exact dependency ordering and array shape.
 *
 * Dependencies are strictly ordered by provider role and then instance ID.
 * This places plan-declared process facilities first and makes duplicate
 * dependency ownership unrepresentable at the callback boundary.
 *
 * @param dependencies Borrowed dependency rows.
 * @param count Exact row count.
 * @return One only for a null/zero pair or a valid strictly ordered array.
 */
static inline uint8_t kinetum_provider_dependencies_are_valid(const kinetum_provider_dependency_handle *dependencies,
							      uint32_t count) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (count == 0) {
		return dependencies == NULL;
	}
	if (dependencies == NULL) {
		return 0;
	}
	for (index = 0; index < count; ++index) {
		if (!kinetum_provider_dependency_is_valid(&dependencies[index])) {
			return 0;
		}
		if (index != 0) {
			const kinetum_provider_dependency_handle *previous = &dependencies[index - 1];
			if (previous->role > dependencies[index].role ||
			    (previous->role == dependencies[index].role &&
			     kinetum_provider_compare_text_views(previous->instance_id,
								 dependencies[index].instance_id) >= 0)) {
				return 0;
			}
		}
	}
	return 1;
}

/**
 * @brief Validate one complete cold factory request before foreign code.
 *
 * This validates only ABI legality. The materializer additionally proves that
 * every identity, contract, compiled fact, and dependency belongs to the one
 * compiled topology and keeps dependency handles alive through dependent
 * destruction.
 *
 * @param request Candidate caller-owned request.
 * @return One only when every structural ABI law is satisfied.
 */
static inline uint8_t
kinetum_provider_factory_request_is_valid(const kinetum_provider_factory_request *request) KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (request == NULL || request->instance_id.size == 0 || request->type_url.size == 0 ||
	    !kinetum_provider_text_view_is_valid(request->instance_id) ||
	    !kinetum_provider_text_view_is_valid(request->type_url) ||
	    !kinetum_provider_byte_view_is_valid(request->canonical_configuration) ||
	    !kinetum_provider_compiled_facts_are_valid_for_role(&request->compiled_facts, request->role) ||
	    request->dependency_padding != 0 || request->runtime_generation == 0 || request->logging.context == NULL ||
	    request->logging.write == NULL ||
	    !kinetum_provider_dependencies_are_valid(request->dependencies, request->dependency_count)) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(request->padding); ++index) {
		if (request->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate one non-materializing host-proof request.
 *
 * @param request Candidate borrowed request.
 * @return One only for canonical borrowed views, one exact role-owned compiled
 *         fact tree, and zero explicit padding.
 */
static inline uint8_t kinetum_provider_host_proof_request_is_valid(const kinetum_provider_host_proof_request *request)
	KINETUM_PROVIDER_NOEXCEPT
{
	uint32_t index;
	if (request == NULL || request->type_url.size == 0 || !kinetum_provider_text_view_is_valid(request->type_url) ||
	    !kinetum_provider_byte_view_is_valid(request->canonical_configuration) ||
	    !kinetum_provider_compiled_facts_are_valid_for_role(&request->compiled_facts, request->role)) {
		return 0;
	}
	for (index = 0; index < (uint32_t)sizeof(request->padding); ++index) {
		if (request->padding[index] != 0) {
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Validate role-specific factory-result nullability for one status.
 *
 * @param role Exact invoked factory role.
 * @param status Callback status.
 * @param result Caller-owned result after callback return.
 * @return One only when failure is empty or success has exact role ownership.
 */
static inline uint8_t
kinetum_provider_factory_result_matches_status(kinetum_provider_role role, kinetum_provider_status status,
					       const kinetum_provider_factory_result *result) KINETUM_PROVIDER_NOEXCEPT
{
	if (result == NULL || !kinetum_provider_role_is_valid(role) || !kinetum_provider_status_is_valid(status)) {
		return 0;
	}
	if (status != KINETUM_PROVIDER_STATUS_OK) {
		return result->instance == NULL && result->operations == NULL && result->destroy == NULL;
	}
	return result->instance != NULL && result->destroy != NULL &&
	       kinetum_provider_operations_match_role(role, result->operations);
}

/** One exact provider-contract implementation row. */
typedef struct kinetum_provider_contract_implementation {
	kinetum_provider_text_view type_url;	    ///< Complete canonical contract type URL.
	kinetum_provider_factory_record factories;  ///< Exactly one role-matching factory member.
	kinetum_provider_host_proof_fn host_proof;  ///< Optional cold proof, null only when catalog permits.
	kinetum_provider_role role;		    ///< Exact structural provider role.
	uint8_t padding[7];			    ///< Zeroed layout padding.
} kinetum_provider_contract_implementation;

/**
 * @brief Immutable exact-release provider component descriptor.
 *
 * Product version, generated ABI identity, component identity, and the sorted
 * unique contract rows must agree exactly with the authenticated inventory and
 * pure contract catalog before a row becomes reachable. The descriptor has no
 * flags or extension area: a changed capability changes the exact ABI identity
 * and all participants rebuild from one tree.
 */
typedef struct kinetum_provider_component_descriptor {
	uint16_t product_version_major;				    ///< Exact Kinetum product major version.
	uint16_t product_version_minor;				    ///< Exact Kinetum product minor version.
	uint16_t product_version_patch;				    ///< Exact Kinetum product patch version.
	uint8_t version_padding[2];				    ///< Zeroed layout padding.
	uint8_t abi_identity[KINETUM_PROVIDER_ABI_IDENTITY_SIZE];   ///< Generated exact ABI identity.
	kinetum_provider_text_view component_id;		    ///< Stable exact component identity.
	const kinetum_provider_contract_implementation *contracts;  ///< Sorted unique implementation rows.
	uint32_t contract_count;				    ///< Exact row count.
	uint8_t tail_padding[4];				    ///< Zeroed layout padding.
} kinetum_provider_component_descriptor;

/** Exact component query function type. */
typedef const kinetum_provider_component_descriptor *(*kinetum_provider_component_query_fn)(void)
	KINETUM_PROVIDER_NOEXCEPT;

/**
 * @brief Return one immutable exact-release component descriptor.
 *
 * A provider component exports exactly this symbol and no other
 * default-visible definition. The function performs no initialization,
 * allocation, registration, or native resource acquisition.
 *
 * @return Process-lifetime immutable descriptor, or null on component failure.
 */
KINETUM_PROVIDER_EXTERN_C KINETUM_PROVIDER_EXPORT const kinetum_provider_component_descriptor *
kinetum_provider_component_query(void) KINETUM_PROVIDER_NOEXCEPT;

KINETUM_PROVIDER_STATIC_ASSERT(sizeof(void *) == 8, "provider ABI requires a 64-bit Linux data model");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_status) == 4, "provider status width changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_role) == 1, "provider role width changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_byte_view) == 16, "provider byte-view layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_byte_view) == 8,
			       "provider byte-view alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_byte_view, data) == 0,
			       "provider byte-view data offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_byte_view, size) == 8,
			       "provider byte-view size offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_byte_view, padding) == 12,
			       "provider byte-view padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_text_view) == 16, "provider text-view layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_text_view) == 8,
			       "provider text-view alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_text_view, data) == 0,
			       "provider text-view data offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_text_view, size) == 8,
			       "provider text-view size offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_text_view, padding) == 12,
			       "provider text-view padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_diagnostic) == 16, "provider diagnostic layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_diagnostic) == 8,
			       "provider diagnostic alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_diagnostic, data) == 0,
			       "provider diagnostic data offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_diagnostic, capacity) == 8,
			       "provider diagnostic capacity offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_diagnostic, size) == 12,
			       "provider diagnostic size offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_private) == KINETUM_PACKET_PRIVATE_SIZE,
			       "packet metadata must remain two cache lines");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_private) == 64,
			       "packet metadata alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, timestamp_ns) == 0, "packet timestamp offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, epoch) == 8, "packet epoch offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, user_meta) == 16,
			       "packet user metadata offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, flow_hash) == 24, "packet flow-hash offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, platform_flags) == 28,
			       "packet platform-flags offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, user_flags) == 32, "packet user-flags offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, ingress_port) == 36,
			       "packet ingress-port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, egress_port) == 38,
			       "packet egress-port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, next_stage) == 40, "packet next-stage offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, current_stage) == 42,
			       "packet current-stage offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, next_stage_instance) == 44,
			       "packet next-stage-instance offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, current_stage_instance) == 46,
			       "packet current-stage-instance offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, module_next_stage) == 48,
			       "packet module-next-stage offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, user_meta_valid) == 50,
			       "packet user-metadata-presence offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, padding_hot) == 51,
			       "packet hot-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, src_ipv4) == 64, "packet source-IPv4 offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, dst_ipv4) == 68,
			       "packet destination-IPv4 offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, src_port) == 72, "packet source-port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, dst_port) == 74,
			       "packet destination-port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, eth_type) == 76, "packet Ethernet-type offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, ip_offset) == 78, "packet IP-offset field changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, l4_offset) == 80, "packet L4-offset field changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, ip_header_len) == 82,
			       "packet IP-header-length offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, ip_total_len) == 84,
			       "packet IP-total-length offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, l4_proto) == 86, "packet L4-protocol offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, dscp) == 87, "packet DSCP offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_private, padding_parsed) == 88,
			       "packet parsed-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_origin_view) == 16, "packet-origin layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_origin_view) == 8,
			       "packet-origin alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_origin_view, data) == 0, "packet-origin data offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_origin_view, length) == 8,
			       "packet-origin length offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_origin_view, padding) == 12,
			       "packet-origin padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_storage_observation) == 64,
			       "provider storage observation must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_storage_observation) == 64,
			       "provider storage-observation alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_observation, runtime_generation) == 0,
			       "provider storage-observation generation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_observation, storage_domain_index) == 8,
			       "provider storage-observation domain offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_observation, state) == 12,
			       "provider storage-observation state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_observation, identity_padding) == 13,
			       "provider storage-observation identity-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_observation, in_use) == 16,
			       "provider storage-observation in-use offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_observation, available) == 24,
			       "provider storage-observation available offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_observation, padding) == 32,
			       "provider storage-observation padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_port_observation) == 128,
			       "provider port observation must remain two cache lines");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_port_observation) == 64,
			       "provider port-observation alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, port_index) == 0,
			       "provider port-observation identity offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, state) == 4,
			       "provider port-observation state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, identity_padding) == 5,
			       "provider port-observation identity-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, rx_packets) == 8,
			       "provider port-observation RX-packet offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, tx_packets) == 16,
			       "provider port-observation TX-packet offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, rx_bytes) == 24,
			       "provider port-observation RX-byte offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, tx_bytes) == 32,
			       "provider port-observation TX-byte offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, rx_missed) == 40,
			       "provider port-observation RX-miss offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, rx_errors) == 48,
			       "provider port-observation RX-error offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, tx_errors) == 56,
			       "provider port-observation TX-error offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, rx_no_buffer) == 64,
			       "provider port-observation no-buffer offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_port_observation, padding) == 72,
			       "provider port-observation padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_io_observation_batch) == 64,
			       "provider I/O observation batch must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_io_observation_batch) == 64,
			       "provider I/O observation-batch alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_observation_batch, ports) == 0,
			       "provider I/O observation port-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_observation_batch, port_count) == 8,
			       "provider I/O observation port-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_observation_batch, port_padding) == 12,
			       "provider I/O observation port-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_observation_batch, padding) == 16,
			       "provider I/O observation padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_storage_domain_operations) == 64,
			       "storage operation table must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_storage_domain_operations) == 64,
			       "storage operation-table alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, state) == 0,
			       "storage state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, acquire_burst) == 8,
			       "storage acquire offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, clone_writable) == 16,
			       "storage clone offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, copy_origins_burst) == 24,
			       "storage origin-copy offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, release_burst) == 32,
			       "storage release offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, observe_statistics) == 40,
			       "storage observation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, generation) == 48,
			       "storage generation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, domain_index) == 52,
			       "storage domain-index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, maximum_packet_length) == 54,
			       "storage maximum-length offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, capabilities) == 56,
			       "storage capability offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_domain_operations, padding) == 60,
			       "storage padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_storage_descriptor) == 64,
			       "storage descriptor must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_storage_descriptor) == 64,
			       "storage descriptor alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, native_handle) == 0,
			       "storage native-handle offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, data) == 8, "storage data offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, operations) == 16,
			       "storage operations offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, length) == 24,
			       "storage length offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, contiguous_length) == 28,
			       "storage contiguous-length offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, generation) == 32,
			       "storage generation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, domain_index) == 36,
			       "storage domain-index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, segment_count) == 38,
			       "storage segment-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, capabilities) == 40,
			       "storage capabilities offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_storage_descriptor, padding) == 44,
			       "storage descriptor padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_record) == KINETUM_PACKET_RECORD_SIZE,
			       "packet record must remain three cache lines");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_record) == 64,
			       "packet record alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_record, metadata) == 0, "packet metadata offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_record, storage) == KINETUM_PACKET_PRIVATE_SIZE,
			       "packet storage offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_rx_burst_result) == 4, "RX result size changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_rx_burst_result) == 2,
			       "RX result alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_rx_burst_result, transferred_count) == 0,
			       "RX transferred-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_rx_burst_result, rejected_count) == 2,
			       "RX rejected-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_rx_burst_operations) == 64,
			       "RX operation table must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_rx_burst_operations) == 64,
			       "RX operation-table alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_rx_burst_operations, state) == 0, "RX state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_rx_burst_operations, receive_burst) == 8,
			       "RX burst offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_rx_burst_operations, maximum_burst) == 16,
			       "RX maximum-burst offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_rx_burst_operations, logical_port) == 18,
			       "RX logical-port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_rx_burst_operations, padding) == 20,
			       "RX padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_packet_tx_burst_operations) == 64,
			       "TX operation table must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_packet_tx_burst_operations) == 64,
			       "TX operation-table alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_tx_burst_operations, state) == 0, "TX state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_tx_burst_operations, transmit_burst) == 8,
			       "TX burst offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_tx_burst_operations, flush) == 16, "TX flush offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_tx_burst_operations, maybe_flush) == 24,
			       "TX conditional-flush offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_tx_burst_operations, maximum_burst) == 32,
			       "TX maximum-burst offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_tx_burst_operations, logical_port) == 34,
			       "TX logical-port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_packet_tx_burst_operations, padding) == 36,
			       "TX padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_cpu_assignment) == 16, "provider CPU-assignment layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_cpu_assignment) == 4,
			       "provider CPU-assignment alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_cpu_assignment, owner_index) == 0,
			       "provider CPU-assignment owner offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_cpu_assignment, cpu_core_id) == 4,
			       "provider CPU-assignment core offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_cpu_assignment, numa_node) == 8,
			       "provider CPU-assignment NUMA offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_cpu_assignment, kind) == 12,
			       "provider CPU-assignment kind offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_cpu_assignment, padding) == 13,
			       "provider CPU-assignment padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_driver_attachment_fact) == 48,
			       "provider attachment-fact layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_driver_attachment_fact) == 8,
			       "provider attachment-fact alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_driver_attachment_fact, driver_port_id) == 0,
			       "provider attachment port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_driver_attachment_fact, attachment_identity) == 16,
			       "provider attachment identity offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_driver_attachment_fact, io_driver_index) == 32,
			       "provider attachment driver offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_driver_attachment_fact, endpoint_port) == 36,
			       "provider attachment endpoint-port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_driver_attachment_fact, kind) == 40,
			       "provider attachment kind offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_driver_attachment_fact, padding) == 41,
			       "provider attachment padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_memory_domain_fact) == 32,
			       "provider memory-domain fact layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_memory_domain_fact) == 4,
			       "provider memory-domain fact alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, storage_domain_index) == 0,
			       "provider memory-domain index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, buffer_count) == 4,
			       "provider memory-domain buffer offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, data_room_bytes) == 8,
			       "provider memory-domain data-room offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, headroom_bytes) == 12,
			       "provider memory-domain headroom offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, alignment_bytes) == 16,
			       "provider memory-domain alignment offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, cache_size_per_worker) == 20,
			       "provider memory-domain cache offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, host_numa_node) == 24,
			       "provider memory-domain NUMA offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, has_host_numa_node) == 28,
			       "provider memory-domain NUMA-presence offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_memory_domain_fact, padding) == 29,
			       "provider memory-domain padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_process_facility_facts) == 64,
			       "provider facility-facts layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_process_facility_facts) == 8,
			       "provider facility-facts alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, facility_index) == 0,
			       "provider facility index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, main_core_id) == 4,
			       "provider facility main-core offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, cpu_assignments) == 8,
			       "provider facility CPU-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, cpu_assignment_count) == 16,
			       "provider facility CPU-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, cpu_assignment_padding) == 20,
			       "provider facility CPU-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, attachments) == 24,
			       "provider facility attachment-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, attachment_count) == 32,
			       "provider facility attachment-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, attachment_padding) == 36,
			       "provider facility attachment-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, memory_domains) == 40,
			       "provider facility memory-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, memory_domain_count) == 48,
			       "provider facility memory-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_facts, padding) == 52,
			       "provider facility padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_io_port_fact) == 32, "provider I/O-port fact layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_io_port_fact) == 4,
			       "provider I/O-port fact alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, port_index) == 0,
			       "provider I/O-port index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, driver_port_index) == 4,
			       "provider I/O-port driver index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, logical_port_id) == 8,
			       "provider I/O-port logical identity offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, mtu) == 12,
			       "provider I/O-port MTU offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, host_numa_node) == 16,
			       "provider I/O-port NUMA offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, direction) == 20,
			       "provider I/O-port direction offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, has_host_numa_node) == 21,
			       "provider I/O-port NUMA-presence offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, has_resolved_mac_address) == 22,
			       "provider I/O-port MAC-presence offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, direction_padding) == 23,
			       "provider I/O-port direction-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, resolved_mac_address) == 24,
			       "provider I/O-port MAC offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_port_fact, padding) == 30,
			       "provider I/O-port padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_io_stream_fact) == 48,
			       "provider I/O-stream fact layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_io_stream_fact) == 8,
			       "provider I/O-stream fact alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, io_stream_index) == 0,
			       "provider I/O-stream index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, port_index) == 4,
			       "provider I/O-stream port offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, stage_instance_index) == 8,
			       "provider I/O-stream stage offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, worker_index) == 12,
			       "provider I/O-stream worker offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, driver_queue_id) == 16,
			       "provider I/O-stream queue offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, descriptor_count) == 20,
			       "provider I/O-stream descriptor offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, steering_profile_index) == 24,
			       "provider I/O-stream steering offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, direction) == 28,
			       "provider I/O-stream direction offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, has_steering_profile) == 29,
			       "provider I/O-stream steering-presence offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, padding) == 30,
			       "provider I/O-stream padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, storage_domain_indices) == 32,
			       "provider I/O-stream storage pointer offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, storage_domain_count) == 40,
			       "provider I/O-stream storage count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_stream_fact, storage_padding) == 44,
			       "provider I/O-stream storage padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_steering_fact) == 64, "provider steering-fact layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_steering_fact) == 8,
			       "provider steering-fact alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, steering_profile_index) == 0,
			       "provider steering index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, kind) == 4,
			       "provider steering kind offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, symmetric) == 5,
			       "provider steering symmetric offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, kind_padding) == 6,
			       "provider steering kind-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, hash_fields) == 8,
			       "provider steering fields offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, hash_field_count) == 16,
			       "provider steering field-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, hash_field_padding) == 20,
			       "provider steering field-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, hash_key) == 24,
			       "provider steering key offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, io_stream_indices) == 40,
			       "provider steering stream-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, io_stream_count) == 48,
			       "provider steering stream-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_steering_fact, padding) == 52,
			       "provider steering padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_io_driver_facts) == 72,
			       "provider I/O-driver facts layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_io_driver_facts) == 8,
			       "provider I/O-driver facts alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, io_driver_index) == 0,
			       "provider I/O-driver index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, index_padding) == 4,
			       "provider I/O-driver index-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, attachments) == 8,
			       "provider I/O-driver attachment-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, attachment_count) == 16,
			       "provider I/O-driver attachment-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, attachment_padding) == 20,
			       "provider I/O-driver attachment-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, ports) == 24,
			       "provider I/O-driver port-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, port_count) == 32,
			       "provider I/O-driver port-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, port_padding) == 36,
			       "provider I/O-driver port-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, streams) == 40,
			       "provider I/O-driver stream-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, stream_count) == 48,
			       "provider I/O-driver stream-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, stream_padding) == 52,
			       "provider I/O-driver stream-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, steering_profiles) == 56,
			       "provider I/O-driver steering-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, steering_profile_count) == 64,
			       "provider I/O-driver steering-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_facts, steering_padding) == 68,
			       "provider I/O-driver steering-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_packet_storage_facts) == 48,
			       "provider packet-storage facts layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_packet_storage_facts) == 4,
			       "provider packet-storage facts alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, storage_domain_index) == 0,
			       "provider packet-storage index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, buffer_count) == 4,
			       "provider packet-storage buffer offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, data_room_bytes) == 8,
			       "provider packet-storage data-room offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, headroom_bytes) == 12,
			       "provider packet-storage headroom offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, alignment_bytes) == 16,
			       "provider packet-storage alignment offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, cache_size_per_worker) == 20,
			       "provider packet-storage cache offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, required_buffer_count) == 24,
			       "provider packet-storage required-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, safety_margin) == 28,
			       "provider packet-storage safety offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, host_numa_node) == 32,
			       "provider packet-storage NUMA offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, maximum_packet_length) == 36,
			       "provider packet-storage maximum-length offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, access_agents) == 38,
			       "provider packet-storage access offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, has_host_numa_node) == 39,
			       "provider packet-storage NUMA-presence offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_packet_storage_facts, padding) == 40,
			       "provider packet-storage padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_execution_facts) == 40,
			       "provider execution facts layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_execution_facts) == 8,
			       "provider execution facts alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, execution_provider_index) == 0,
			       "provider execution index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, required_access_agents) == 4,
			       "provider execution access offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, index_padding) == 5,
			       "provider execution index-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, stage_instance_indices) == 8,
			       "provider execution stage-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, stage_instance_count) == 16,
			       "provider execution stage-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, stage_padding) == 20,
			       "provider execution stage-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, worker_indices) == 24,
			       "provider execution worker-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, worker_count) == 32,
			       "provider execution worker-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_facts, worker_padding) == 36,
			       "provider execution worker-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_endpoint_fact) == 8, "provider endpoint fact layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_endpoint_fact) == 4,
			       "provider endpoint fact alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_endpoint_fact, kind) == 0,
			       "provider endpoint kind offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_endpoint_fact, padding) == 1,
			       "provider endpoint padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_endpoint_fact, endpoint_index) == 4,
			       "provider endpoint index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_storage_transition_facts) == 48,
			       "provider transition facts layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_storage_transition_facts) == 4,
			       "provider transition facts alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, transition_index) == 0,
			       "provider transition index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, from_endpoint) == 4,
			       "provider transition source offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, to_endpoint) == 12,
			       "provider transition destination offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, from_storage_domain_index) == 20,
			       "provider transition source-domain offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, to_storage_domain_index) == 24,
			       "provider transition destination-domain offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, staging_capacity) == 28,
			       "provider transition capacity offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, staging_numa_node) == 32,
			       "provider transition NUMA offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, mode) == 36,
			       "provider transition mode offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, has_staging_numa_node) == 37,
			       "provider transition NUMA-presence offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_facts, padding) == 38,
			       "provider transition padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_compiled_fact_record) == 40,
			       "provider compiled-fact record layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_compiled_fact_record) == 8,
			       "provider compiled-fact record alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_compiled_fact_record, process_facility) == 0,
			       "provider compiled facility-fact offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_compiled_fact_record, io_driver) == 8,
			       "provider compiled I/O-fact offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_compiled_fact_record, packet_storage) == 16,
			       "provider compiled storage-fact offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_compiled_fact_record, execution) == 24,
			       "provider compiled execution-fact offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_compiled_fact_record, storage_transition) == 32,
			       "provider compiled transition-fact offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_process_facility_operations) == 64,
			       "provider process-facility operations must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_process_facility_operations) == 64,
			       "provider process-facility operations alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, state) == 0,
			       "provider process-facility state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, register_worker_thread) == 8,
			       "provider process-facility worker-register offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, unregister_worker_thread) == 16,
			       "provider process-facility worker-unregister offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations,
					bind_runtime_service_coordinator) == 24,
			       "provider process-facility coordinator-bind offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, launch_runtime_service) == 32,
			       "provider process-facility service-launch offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, join_runtime_service) == 40,
			       "provider process-facility service-join offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, generation) == 48,
			       "provider process-facility generation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, facility_index) == 56,
			       "provider process-facility index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_process_facility_operations, padding) == 60,
			       "provider process-facility padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_io_driver_operations) == 64,
			       "provider I/O-driver operations must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_io_driver_operations) == 64,
			       "provider I/O-driver operations alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, state) == 0,
			       "provider I/O-driver state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, activate_packet_io) == 8,
			       "provider I/O-driver activation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, deactivate_packet_io) == 16,
			       "provider I/O-driver deactivation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, rx_queues) == 24,
			       "provider I/O-driver RX-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, tx_queues) == 32,
			       "provider I/O-driver TX-array offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, observe_statistics) == 40,
			       "provider I/O-driver observation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, rx_queue_count) == 48,
			       "provider I/O-driver RX-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, tx_queue_count) == 52,
			       "provider I/O-driver TX-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, io_driver_index) == 56,
			       "provider I/O-driver operation index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_io_driver_operations, padding) == 60,
			       "provider I/O-driver operation padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_execution_operations) == 64,
			       "provider execution operations must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_execution_operations) == 64,
			       "provider execution operations alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_operations, state) == 0,
			       "provider execution state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_operations, execution_provider_index) == 8,
			       "provider execution operation index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_operations, required_access_agents) == 12,
			       "provider execution operation access offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_execution_operations, padding) == 13,
			       "provider execution operation padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_storage_transition_operations) == 64,
			       "provider transition operations must remain one cache line");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_storage_transition_operations) == 64,
			       "provider transition operations alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, state) == 0,
			       "provider transition state offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, transfer_burst) == 8,
			       "provider transition burst offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, generation) == 16,
			       "provider transition generation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, transition_index) == 20,
			       "provider transition operation index offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, from_storage_domain_index) ==
				       24,
			       "provider transition operation source-domain offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, to_storage_domain_index) == 28,
			       "provider transition operation destination-domain offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, mode) == 32,
			       "provider transition operation mode offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_storage_transition_operations, padding) == 33,
			       "provider transition operation padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_dependency_handle) == 56,
			       "provider dependency-handle layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_dependency_handle) == 8,
			       "provider dependency-handle alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_dependency_handle, instance_id) == 0,
			       "provider dependency instance offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_dependency_handle, type_url) == 16,
			       "provider dependency type-URL offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_dependency_handle, instance) == 32,
			       "provider dependency instance-handle offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_dependency_handle, operations) == 40,
			       "provider dependency operation-handle offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_dependency_handle, role) == 48,
			       "provider dependency role offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_dependency_handle, padding) == 49,
			       "provider dependency padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_log_level) == 1, "provider log level width changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_cold_log) == 16, "provider cold log layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_cold_log) == 8,
			       "provider cold log alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_cold_log, context) == 0,
			       "provider cold log context offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_cold_log, write) == 8,
			       "provider cold log write offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_factory_request) == 136,
			       "provider factory-request layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_factory_request) == 8,
			       "provider factory-request alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, instance_id) == 0,
			       "provider factory instance offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, type_url) == 16,
			       "provider factory type-URL offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, canonical_configuration) == 32,
			       "provider factory configuration offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, compiled_facts) == 48,
			       "provider factory facts offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, dependencies) == 88,
			       "provider factory dependencies offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, dependency_count) == 96,
			       "provider factory dependency-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, dependency_padding) == 100,
			       "provider factory dependency-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, runtime_generation) == 104,
			       "provider factory generation offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, role) == 112,
			       "provider factory role offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, padding) == 113,
			       "provider factory padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_request, logging) == 120,
			       "provider factory logging offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_factory_result) == 24, "provider factory-result layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_factory_result) == 8,
			       "provider factory-result alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_result, instance) == 0,
			       "provider factory-result instance offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_result, operations) == 8,
			       "provider factory-result operations offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_result, destroy) == 16,
			       "provider factory-result destroy offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_host_proof_request) == 80,
			       "provider host-proof request layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_host_proof_request) == 8,
			       "provider host-proof alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_host_proof_request, type_url) == 0,
			       "provider host-proof type-URL offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_host_proof_request, canonical_configuration) == 16,
			       "provider host-proof configuration offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_host_proof_request, compiled_facts) == 32,
			       "provider host-proof facts offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_host_proof_request, role) == 72,
			       "provider host-proof role offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_host_proof_request, padding) == 73,
			       "provider host-proof padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_factory_record) == 40, "provider factory-record layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_factory_record) == 8,
			       "provider factory-record alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_record, process_facility) == 0,
			       "provider process-facility factory offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_record, io_driver) == 8,
			       "provider I/O-driver factory offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_record, packet_storage) == 16,
			       "provider packet-storage factory offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_record, execution) == 24,
			       "provider execution factory offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_record, storage_transition) == 32,
			       "provider storage-transition factory offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ROLE_PROCESS_FACILITY == UINT8_C(1) &&
				       KINETUM_PROVIDER_ROLE_IO_DRIVER == UINT8_C(2) &&
				       KINETUM_PROVIDER_ROLE_PACKET_STORAGE == UINT8_C(3) &&
				       KINETUM_PROVIDER_ROLE_EXECUTION == UINT8_C(4) &&
				       KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION == UINT8_C(5),
			       "provider roles must remain contiguous structural indices");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_compiled_fact_record, storage_transition) ==
				       (KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION - UINT8_C(1)) * sizeof(const void *),
			       "provider role-to-compiled-fact mapping changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_factory_record, storage_transition) ==
				       (KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION - UINT8_C(1)) *
					       sizeof(kinetum_provider_factory_fn),
			       "provider role-to-factory mapping changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_contract_implementation) == 72,
			       "provider contract-row layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_contract_implementation) == 8,
			       "provider contract-row alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_contract_implementation, type_url) == 0,
			       "provider contract-row URL offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_contract_implementation, factories) == 16,
			       "provider contract-row factories offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_contract_implementation, host_proof) == 56,
			       "provider contract-row proof offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_contract_implementation, role) == 64,
			       "provider contract-row role offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_contract_implementation, padding) == 65,
			       "provider contract-row padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(sizeof(kinetum_provider_component_descriptor) == 72,
			       "provider component-descriptor layout changed");
KINETUM_PROVIDER_STATIC_ASSERT(KINETUM_PROVIDER_ALIGNOF(kinetum_provider_component_descriptor) == 8,
			       "provider component-descriptor alignment changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, product_version_major) == 0,
			       "provider descriptor major-version offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, product_version_minor) == 2,
			       "provider descriptor minor-version offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, product_version_patch) == 4,
			       "provider descriptor patch-version offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, version_padding) == 6,
			       "provider descriptor version-padding offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, abi_identity) == 8,
			       "provider descriptor ABI-identity offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, component_id) == 40,
			       "provider descriptor component-id offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, contracts) == 56,
			       "provider descriptor contract pointer offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, contract_count) == 64,
			       "provider descriptor contract-count offset changed");
KINETUM_PROVIDER_STATIC_ASSERT(offsetof(kinetum_provider_component_descriptor, tail_padding) == 68,
			       "provider descriptor tail-padding offset changed");

KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_byte_view);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_text_view);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_diagnostic);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_storage_observation);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_port_observation);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_io_observation_batch);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_private);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_origin_view);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_storage_domain_operations);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_storage_descriptor);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_record);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_rx_burst_result);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_rx_burst_operations);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_packet_tx_burst_operations);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_cpu_assignment);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_driver_attachment_fact);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_memory_domain_fact);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_process_facility_facts);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_io_port_fact);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_io_stream_fact);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_steering_fact);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_io_driver_facts);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_packet_storage_facts);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_execution_facts);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_endpoint_fact);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_storage_transition_facts);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_compiled_fact_record);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_process_facility_operations);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_io_driver_operations);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_execution_operations);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_storage_transition_operations);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_dependency_handle);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_cold_log);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_factory_request);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_factory_result);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_host_proof_request);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_factory_record);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_contract_implementation);
KINETUM_PROVIDER_TYPE_TRAITS_ASSERT(kinetum_provider_component_descriptor);

#undef KINETUM_PROVIDER_EXTERN_C
#undef KINETUM_PROVIDER_NOEXCEPT
#undef KINETUM_PROVIDER_STATIC_ASSERT
#undef KINETUM_PROVIDER_ALIGNOF
#undef KINETUM_PROVIDER_ALIGNAS
#undef KINETUM_PROVIDER_EXPORT
#undef KINETUM_PROVIDER_TYPE_TRAITS_ASSERT
