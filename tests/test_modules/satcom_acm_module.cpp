// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file satcom_acm_module.cpp
 * @brief SATCOM Adaptive Coding and Modulation (ACM) Module
 * @author Fleming Patel
 *
 * Test/example module demonstrating SATCOM modem integration using the
 * mechanism-focused SDK design. This module defines its own domain-specific
 * types (SATCOM metadata) rather than relying on SDK-provided structures.
 *
 * This demonstrates the mechanism vs policy separation:
 * - SDK provides: exact lifecycle, telemetry, epoch arenas, packet iteration
 * - Module defines: SATCOM metadata, ModCod thresholds, ACM logic
 *
 * Features:
 * - DVB-S2/S2X ACM decisions based on SNR/Es-N0
 * - ModCod adaptation with hysteresis
 * - FEC type handling (LDPC, Turbo, BCH)
 * - Per-carrier telemetry with HDR histograms
 * - Exact epoch-arena policy ownership
 *
 * This module would be used in a SATCOM gateway/modem to:
 * 1. Monitor link quality (SNR, Es/N0)
 * 2. Track packets per ModCod for ACM statistics
 * 3. Drop packets when link quality falls below threshold
 * 4. Report latency percentiles for SLA compliance
 */

#include <kinetum/kinetum_sdk.h>

#include <array>
#include <bit>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <optional>
#include <string_view>
#include <utility>
#include <system_error>

// =============================================================================
// User-Defined Domain Types (SATCOM-Specific)
//
// These types are DEFINED BY THE USER, not provided by the SDK.
// This follows the mechanism vs policy separation principle.
// =============================================================================

/**
 * @brief User-defined packet flag for SATCOM packets.
 *
 * Uses one bit in the SDK's separate persistent user-flags word.
 */
#define SATCOM_PKT_FLAG (KINETUM_USER_F_BASE << 0)

/**
 * @brief User-defined SATCOM metadata structure.
 *
 * This structure is defined by the SATCOM domain module, not the SDK.
 * The SDK provides the mechanism to attach this metadata to packets.
 */
struct satcom_meta {
	uint8_t modcod_id;     ///< DVB-S2/S2X ModCod index (0-255).
	uint8_t fec_type;      ///< FEC type (0=LDPC, 1=Turbo, 2=BCH).
	uint16_t carrier_id;   ///< Carrier/beam ID.
	int16_t snr_db_fp8;    ///< SNR in dB, Q8.8 fixed point.
	int16_t es_no_db_fp8;  ///< Es/N0 in dB, Q8.8 fixed point.
	uint8_t modulation;    ///< Modulation type (0=BPSK, 1=QPSK, etc.).
};

/**
 * @brief Decode the module's compact persistent packet word.
 *
 * The SDK deliberately carries one exact user word rather than an untyped
 * private byte array. This domain module owns its bit allocation and can move
 * larger state into its admitted context when one word is insufficient.
 *
 * @param word Exact module-owned persistent packet word.
 * @return Decoded SATCOM metadata fields.
 */
[[nodiscard]] satcom_meta decode_satcom_meta(uint64_t word) noexcept
{
	return satcom_meta{
		.modcod_id = static_cast<uint8_t>(word & 0xffu),
		.fec_type = static_cast<uint8_t>((word >> 56u) & 0x3u),
		.carrier_id = static_cast<uint16_t>((word >> 8u) & 0xffffu),
		.snr_db_fp8 = std::bit_cast<int16_t>(static_cast<uint16_t>((word >> 24u) & 0xffffu)),
		.es_no_db_fp8 = std::bit_cast<int16_t>(static_cast<uint16_t>((word >> 40u) & 0xffffu)),
		.modulation = static_cast<uint8_t>((word >> 58u) & 0xfu),
	};
}

/**
 * @brief Check if packet in batch has SATCOM metadata (SoA API).
 *
 * @param batch SoA batch pointer
 * @param idx Packet index in batch
 * @return true when the packet carries SATCOM metadata.
 */
#define BATCH_PKT_IS_SATCOM(batch, idx) \
	((batch)->user_meta_valid[idx] != 0 && (((batch)->user_flags[idx] & SATCOM_PKT_FLAG) != 0))

// =============================================================================
// Configuration
// =============================================================================

/**
 * @brief ModCod threshold entry for ACM decisions.
 *
 * Thresholds based on DVB-S2 specification Table 13.
 */
struct modcod_threshold {
	uint8_t modcod_id;     ///< ModCod index
	int16_t min_snr_fp8;   ///< Minimum SNR in Q8.8 (-128.0 to 127.996 dB)
	uint8_t modulation;    ///< Modulation type
	uint8_t fec_rate_num;  ///< FEC numerator
	uint8_t fec_rate_den;  ///< FEC denominator
};

/**
 * @brief Module configuration with ACM parameters.
 */
struct satcom_acm_config {
	int16_t min_snr_threshold_fp8;	///< Minimum SNR to forward (Q8.8)
	int16_t hysteresis_fp8;		///< Hysteresis for mode changes (Q8.8)
	uint16_t carrier_id_filter;	///< Only process this carrier (0 = all)
	bool drop_below_threshold;	///< Drop packets below SNR threshold
	bool track_per_modcod;		///< Track stats per ModCod
};

/**
 * @brief Module state with pre-registered telemetry.
 */
struct satcom_acm_state {
	// Pre-registered counters
	kinetum_counter_t cnt_total;		///< Packets inspected by the module.
	kinetum_counter_t cnt_forwarded;	///< Packets admitted by SATCOM policy.
	kinetum_counter_t cnt_dropped_snr;	///< Packets rejected below the SNR threshold.
	kinetum_counter_t cnt_dropped_carrier;	///< Packets rejected while the carrier is down.
	kinetum_counter_t cnt_acm_changes;	///< Accepted modulation/coding mode changes.

	// Per-ModCod counters (first 28 ModCods of DVB-S2)
	kinetum_counter_t cnt_modcod[28];  ///< Packet count by selected ModCod index.

	// HDR histograms
	kinetum_histogram_t hist_snr;	 ///< SNR distribution
	kinetum_histogram_t hist_es_no;	 ///< Es/N0 distribution

	// Last seen ModCod for change detection
	uint8_t last_modcod;  ///< Most recently selected ModCod index.
};

// =============================================================================
// Fixed-Point Helpers
// =============================================================================

/**
 * @brief Convert integer to Q8.8 fixed-point.
 *
 * @param val Integer value to convert (range -128 to +127)
 * @return Q8.8 fixed-point representation (fractional portion is zero)
 *
 * @note Input values outside [-128, 127] will overflow
 */
static inline int16_t int_to_fp8(int16_t val)
{
	return static_cast<int16_t>(static_cast<int32_t>(val) * 256);
}

/**
 * @brief Convert Q8.8 to unsigned for histogram (shift to positive range).
 *
 * @param fp8 Q8.8 fixed-point value (range -128.0 to +127.996 dB)
 * @return Unsigned 64-bit value suitable for histogram bucketing
 *
 * @note Shifts the signed Q8.8 range to unsigned [0, 65535] by adding 32768.
 *       This maps -128.0 dB to 0 and +127.996 dB to 65535.
 */
static inline uint64_t fp8_to_histogram(int16_t fp8)
{
	// Shift range from [-128, 127.996] to [0, 65535] for histogram
	return static_cast<uint64_t>(static_cast<uint16_t>(fp8 + 32768));
}

// =============================================================================
// Module Callbacks
// =============================================================================

/**
 * @brief Locate one bounded JSON value without assuming NUL termination.
 *
 * @param payload Exact borrowed configuration bytes.
 * @param key Quoted JSON key to locate.
 * @return Value token, nullopt when absent, or an empty token when malformed.
 */
[[nodiscard]] static std::optional<std::string_view> json_value(std::string_view payload, std::string_view key) noexcept
{
	const std::size_t key_position = payload.find(key);
	if (key_position == std::string_view::npos) {
		return std::nullopt;
	}
	const std::size_t colon = payload.find(':', key_position + key.size());
	if (colon == std::string_view::npos) {
		return std::string_view{};
	}
	const std::size_t begin = payload.find_first_not_of(" \t\r\n", colon + 1);
	if (begin == std::string_view::npos) {
		return std::string_view{};
	}
	const std::size_t end = payload.find_first_of(",}\r\n\t ", begin);
	return std::string_view(payload.data() + begin,
				end == std::string_view::npos ? payload.size() - begin : end - begin);
}

/**
 * @brief Parse one optional strict JSON boolean.
 *
 * @param payload Exact borrowed configuration bytes.
 * @param key Quoted JSON key.
 * @param value Existing/default value updated when the key is present.
 * @return true when absent or valid; false for malformed input.
 */
[[nodiscard]] static bool parse_optional_bool(std::string_view payload, std::string_view key, bool &value) noexcept
{
	const auto token = json_value(payload, key);
	if (!token.has_value()) {
		return true;
	}
	if (*token == "true") {
		value = true;
		return true;
	}
	if (*token == "false") {
		value = false;
		return true;
	}
	return false;
}

/**
 * @brief Parse one optional uint16 JSON value.
 *
 * @param payload Exact borrowed configuration bytes.
 * @param key Quoted JSON key.
 * @param value Existing/default value updated when the key is present.
 * @return true when absent or valid; false for malformed/range input.
 */
[[nodiscard]] static bool parse_optional_uint16(std::string_view payload, std::string_view key,
						uint16_t &value) noexcept
{
	const auto token = json_value(payload, key);
	if (!token.has_value()) {
		return true;
	}
	uint32_t parsed = 0;
	const auto result = std::from_chars(token->data(), token->data() + token->size(), parsed);
	if (token->empty() || result.ec != std::errc{} || result.ptr != token->data() + token->size() ||
	    parsed > UINT16_MAX) {
		return false;
	}
	value = static_cast<uint16_t>(parsed);
	return true;
}

/**
 * @brief Parse one optional signed decimal into Q8.8 representation.
 *
 * @param payload Exact borrowed configuration bytes.
 * @param key Quoted JSON key.
 * @param value Existing/default value updated when the key is present.
 * @return true when absent or representable; false for malformed/range input.
 */
[[nodiscard]] static bool parse_optional_fp8(std::string_view payload, std::string_view key, int16_t &value) noexcept
{
	const auto token = json_value(payload, key);
	if (!token.has_value()) {
		return true;
	}
	if (token->empty()) {
		return false;
	}
	std::size_t position = 0;
	const bool negative = (*token)[position] == '-';
	if (negative && ++position == token->size()) {
		return false;
	}
	uint32_t whole = 0;
	bool saw_digit = false;
	while (position < token->size() && (*token)[position] >= '0' && (*token)[position] <= '9') {
		saw_digit = true;
		whole = whole * 10u + static_cast<uint32_t>((*token)[position] - '0');
		if (whole > 128u) {
			return false;
		}
		++position;
	}
	uint32_t fraction = 0;
	uint32_t scale = 1;
	if (position < token->size() && (*token)[position] == '.') {
		++position;
		bool saw_fraction = false;
		while (position < token->size() && (*token)[position] >= '0' && (*token)[position] <= '9') {
			saw_fraction = true;
			if (scale <= 100000u) {
				fraction = fraction * 10u + static_cast<uint32_t>((*token)[position] - '0');
				scale *= 10u;
			}
			++position;
		}
		if (!saw_fraction) {
			return false;
		}
	}
	if (!saw_digit || position != token->size()) {
		return false;
	}
	int32_t fixed = static_cast<int32_t>(whole * 256u + (fraction * 256u + scale / 2u) / scale);
	if (negative) {
		fixed = -fixed;
	}
	if (fixed < INT16_MIN || fixed > INT16_MAX) {
		return false;
	}
	value = static_cast<int16_t>(fixed);
	return true;
}

/**
 * @brief Allocate context state and register all owner-local telemetry.
 * @param lifecycle Exact context-lifetime service table.
 * @param out_state Output receiving the initialized context state.
 * @return KINETUM_OK on complete initialization or one exact ABI error.
 */
[[nodiscard]] static kinetum_error satcom_acm_init(const kinetum_lifecycle_ctx *lifecycle, void **out_state) noexcept
{
	if (!lifecycle || !out_state) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_state = nullptr;
	void *storage = nullptr;
	kinetum_error error = kinetum_lifecycle_allocate_context(
		lifecycle, sizeof(satcom_acm_state), alignof(satcom_acm_state), KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (error != KINETUM_OK) {
		return error;
	}
	auto *state = static_cast<satcom_acm_state *>(storage);
	state->last_modcod = UINT8_MAX;

	const auto release_failed_state = [&](kinetum_error failure) noexcept {
		const auto release_error = kinetum_lifecycle_release_context(lifecycle, state);
		return release_error == KINETUM_OK ? failure : release_error;
	};
	const std::array<std::pair<const char *, kinetum_counter_t *>, 5> counters{{
		{"satcom_acm.packets", &state->cnt_total},
		{"satcom_acm.forwarded", &state->cnt_forwarded},
		{"satcom_acm.dropped_snr", &state->cnt_dropped_snr},
		{"satcom_acm.dropped_carrier", &state->cnt_dropped_carrier},
		{"satcom_acm.acm_changes", &state->cnt_acm_changes},
	}};
	for (const auto &[name, output] : counters) {
		error = kinetum_lifecycle_register_counter(lifecycle, name, output);
		if (error != KINETUM_OK) {
			return release_failed_state(error);
		}
	}

	char name[64];
	for (std::size_t index = 0; index < 28; ++index) {
		const int written = std::snprintf(name, sizeof(name), "satcom_acm.modcod_%02zu", index);
		if (written < 0 || static_cast<std::size_t>(written) >= sizeof(name)) {
			return release_failed_state(KINETUM_ERR_INTERNAL);
		}
		error = kinetum_lifecycle_register_counter(lifecycle, name, &state->cnt_modcod[index]);
		if (error != KINETUM_OK) {
			return release_failed_state(error);
		}
	}
	const std::array<std::pair<const char *, kinetum_histogram_t *>, 2> histograms{{
		{"satcom_acm.snr_distribution", &state->hist_snr},
		{"satcom_acm.es_no_distribution", &state->hist_es_no},
	}};
	for (const auto &[histogram_name, output] : histograms) {
		error = kinetum_lifecycle_register_histogram(lifecycle, histogram_name, 65536u, 2u, output);
		if (error != KINETUM_OK) {
			return release_failed_state(error);
		}
	}

	*out_state = state;
	return KINETUM_OK;
}

/**
 * @brief Release detached context state after owner-worker join.
 * @param lifecycle Exact context-lifetime service table.
 * @param state Exact detached context state.
 */
static void satcom_acm_fini(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
{
	if (!lifecycle || !state || kinetum_lifecycle_release_context(lifecycle, state) != KINETUM_OK) {
		std::terminate();
	}
}

/**
 * @brief Prepare one immutable SATCOM policy in the exact epoch arena.
 * @param lifecycle Exact context and epoch service table.
 * @param epoch Exact advancing target epoch.
 * @param config_data Borrowed bounded JSON bytes, or null when empty.
 * @param config_len Exact configuration byte count.
 * @param out_prepared Output receiving the immutable prepared view.
 * @return KINETUM_OK on complete preparation or one exact ABI error.
 */
[[nodiscard]] static kinetum_error satcom_acm_prepare(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
						      const void *config_data, std::size_t config_len,
						      kinetum_prepared_config *out_prepared) noexcept
{
	if (!lifecycle || epoch == 0 || (!config_data && config_len != 0) || !out_prepared) {
		return KINETUM_ERR_INVALID_ARG;
	}
	*out_prepared = {};
	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		return KINETUM_ERR_CANCELLED;
	}

	satcom_acm_config config{
		.min_snr_threshold_fp8 = int_to_fp8(-3),
		.hysteresis_fp8 = int_to_fp8(1),
		.carrier_id_filter = 0,
		.drop_below_threshold = true,
		.track_per_modcod = true,
	};
	const std::string_view payload =
		config_data ? std::string_view(static_cast<const char *>(config_data), config_len) : std::string_view{};
	if (!parse_optional_fp8(payload, "\"min_snr_db\"", config.min_snr_threshold_fp8) ||
	    !parse_optional_fp8(payload, "\"hysteresis_db\"", config.hysteresis_fp8) || config.hysteresis_fp8 < 0 ||
	    !parse_optional_uint16(payload, "\"carrier_id\"", config.carrier_id_filter) ||
	    !parse_optional_bool(payload, "\"drop_below_threshold\"", config.drop_below_threshold) ||
	    !parse_optional_bool(payload, "\"track_per_modcod\"", config.track_per_modcod)) {
		return KINETUM_ERR_CONFIG_INVALID;
	}

	void *storage = nullptr;
	const auto allocation_error = kinetum_lifecycle_allocate_epoch(
		lifecycle, sizeof(config), alignof(satcom_acm_config), KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (allocation_error != KINETUM_OK) {
		return allocation_error;
	}
	std::memcpy(storage, &config, sizeof(config));
	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		return KINETUM_ERR_CANCELLED;
	}
	out_prepared->packet_config = storage;
	return KINETUM_OK;
}

/**
 * @brief Validate the exact SATCOM view during bounded activation.
 * @param ctx Sole-owner live context.
 * @param epoch Exact target epoch.
 * @param prepared Exact immutable prepared view.
 */
static void satcom_acm_activate(kinetum_ctx *ctx, uint64_t epoch, const kinetum_prepared_config *prepared) noexcept
{
	if (!ctx || epoch == 0 || !prepared || prepared->owner_handle || !prepared->packet_config) {
		std::terminate();
	}
}

/**
 * @brief Complete retirement; the platform reclaims the exact epoch arena.
 * @param lifecycle Exact context and epoch service table.
 * @param epoch Exact retiring epoch.
 * @param retired Exact immutable view being retired.
 */
static void satcom_acm_retire(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
			      kinetum_prepared_config retired) noexcept
{
	if (!lifecycle || epoch == 0 || retired.owner_handle || !retired.packet_config) {
		std::terminate();
	}
}

/**
 * @brief Process SATCOM packets with ACM decisions using SoA batch API.
 *
 * @param batch Packet batch supplied by the runtime.
 * @return Sole packet-forward mask.
 */
KINETUM_HOT static uint64_t satcom_acm_process(kinetum_batch_t *batch) noexcept
{
	kinetum_ctx *ctx = batch->ctx;
	auto *state = static_cast<satcom_acm_state *>(ctx->state);
	const auto *config = static_cast<const satcom_acm_config *>(batch->epoch_config);
	if (KINETUM_UNLIKELY(!state || !config)) {
		// Exact configuration is mandatory; a missing view is an internal
		// publication failure and must never fall back to mutable defaults.
		return 0;
	}

	const uint16_t count = batch->count;
	uint64_t forward_mask = KINETUM_FORWARD_MASK(count);
	uint64_t local_forwarded = 0;
	uint64_t local_dropped_snr = 0;
	uint64_t local_dropped_carrier = 0;
	uint64_t local_acm_changes = 0;

	const int16_t snr_threshold = config->min_snr_threshold_fp8;
	const uint16_t carrier_filter = config->carrier_id_filter;
	const bool drop_below = config->drop_below_threshold;
	const bool track_modcod = config->track_per_modcod;

	// Process each packet using SoA batch API
	for (uint16_t i = 0; i < count; i++) {
		// Prefetch next SoA elements
		if (i + 2 < count) {
			__builtin_prefetch(&batch->user_meta[i + 2], 0, 3);
			__builtin_prefetch(&batch->user_flags[i + 2], 0, 3);
		}

		if (KINETUM_UNLIKELY(!BATCH_PKT_IS_SATCOM(batch, i))) {
			local_forwarded++;
			continue;
		}

		const satcom_meta sat = decode_satcom_meta(batch->user_meta[i]);

		// Carrier filtering
		if (carrier_filter != 0 && sat.carrier_id != carrier_filter) {
			KINETUM_DROP(forward_mask, i);
			local_dropped_carrier++;
			continue;  // Drop: wrong carrier
		}

		// SNR threshold check
		if (drop_below && sat.snr_db_fp8 < snr_threshold) {
			KINETUM_DROP(forward_mask, i);
			local_dropped_snr++;
			continue;  // Drop: SNR too low
		}

		// Record SNR/Es-N0 in histograms
		if (state->hist_snr) {
			KINETUM_HISTOGRAM_RECORD_FAST(state->hist_snr, fp8_to_histogram(sat.snr_db_fp8));
		}
		if (state->hist_es_no) {
			KINETUM_HISTOGRAM_RECORD_FAST(state->hist_es_no, fp8_to_histogram(sat.es_no_db_fp8));
		}

		// Track per-ModCod statistics
		if (track_modcod && sat.modcod_id < 28) {
			if (state->cnt_modcod[sat.modcod_id]) {
				KINETUM_COUNTER_INC(state->cnt_modcod[sat.modcod_id]);
			}
		}

		// Detect ModCod changes (ACM events)
		if (sat.modcod_id != state->last_modcod) {
			if (state->last_modcod != 255) {  // Not first packet
				local_acm_changes++;
			}
			state->last_modcod = sat.modcod_id;
		}

		// Forward the packet by retaining its bit in the return mask.
		local_forwarded++;
	}

	// Batched counter updates
	KINETUM_COUNTER_ADD(state->cnt_total, count);
	KINETUM_COUNTER_ADD(state->cnt_forwarded, local_forwarded);
	if (local_dropped_snr > 0) {
		KINETUM_COUNTER_ADD(state->cnt_dropped_snr, local_dropped_snr);
	}
	if (local_dropped_carrier > 0) {
		KINETUM_COUNTER_ADD(state->cnt_dropped_carrier, local_dropped_carrier);
	}
	if (local_acm_changes > 0) {
		KINETUM_COUNTER_ADD(state->cnt_acm_changes, local_acm_changes);
	}

	return forward_mask;
}

// =============================================================================
// Module Registration
// =============================================================================

/**
 * @brief Passive SATCOM ACM module descriptor.
 */
static const kinetum_module satcom_acm_module_desc = {
	.module_id = "satcom_acm",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
	.mode = KINETUM_MODULE_PASSIVE,
	.prepare_config = satcom_acm_prepare,
	.activate_config = satcom_acm_activate,
	.retire_config = satcom_acm_retire,
	.process = satcom_acm_process,
	.ingest = nullptr,
	.run = nullptr,
	.on_control = nullptr,
	.init = satcom_acm_init,
	.fini = satcom_acm_fini,
	.health_check = nullptr,
	.select_contexts = nullptr,
};

/**
 * @brief Module entry point for the SATCOM ACM test/example module.
 *
 * @return Static module descriptor for this module.
 */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &satcom_acm_module_desc;
}
