// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_module.cpp
 * @brief Exact-lifecycle passive module used by SDK and dataplane tests.
 * @author Fleming Patel
 *
 * The module demonstrates the customer-facing C ABI without privileged
 * platform headers: INIT registers fixed owner-local telemetry, PREPARE builds
 * an immutable epoch-arena policy, ACTIVATE is bounded validation, packet
 * execution consumes only the batch's exact config pointer, and RETIRE leaves
 * arena reclamation to the platform-owned prepared token. Its optional health
 * callback reads the same exact context/config view and returns bounded policy
 * only; platform tests own provenance and publication.
 */

#include <kinetum/kinetum_sdk.h>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <string_view>
#include <system_error>

namespace
{

/** @brief Immutable packet policy prepared for one exact epoch. */
struct test_module_config {
	bool drop_all{false};				    ///< Drop every packet when true.
	bool rewrite_metadata{false};			    ///< Rewrite all documented mutable lanes when true.
	bool corrupt_packet_facts{false};		    ///< Exercise parser-fact coherence enforcement.
	uint8_t dscp_drop{UINT8_MAX};			    ///< DSCP value selected for conditional drop.
	uint8_t corrupt_authority{0};			    ///< Test-only immutable-authority corruption selector.
	uint16_t route_to_stage{KINETUM_NEXT_STAGE_UNSET};  ///< Optional module-selected logical stage.
	uint16_t output_port{KINETUM_PORT_UNSET};	    ///< Optional exact logical egress selection.
};

/** @brief Context-local mutable telemetry handles owned by one worker. */
struct test_module_state {
	kinetum_counter_t checked{nullptr};	    ///< Packets inspected by this context.
	kinetum_counter_t dropped{nullptr};	    ///< Packets rejected by policy.
	kinetum_counter_t forwarded{nullptr};	    ///< Packets retained in the forward mask.
	kinetum_counter_t dscp_drops{nullptr};	    ///< Packets rejected by the DSCP selector.
	kinetum_counter_t batches{nullptr};	    ///< Callback batches observed by this context.
	kinetum_histogram_t packet_bytes{nullptr};  ///< Distribution used by the three-bank canary.
};

/**
 * @brief Locate one bounded JSON value without assuming NUL termination.
 * @param payload Borrowed flat JSON fixture bytes.
 * @param key Quoted fixture field name to locate.
 * @return Borrowed scalar token, an empty token for a malformed value, or nullopt when the key is absent.
 */
[[nodiscard]] std::optional<std::string_view> json_value(std::string_view payload, std::string_view key) noexcept
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
 * @brief Parse one optional strict JSON boolean into an existing value.
 * @param payload Borrowed flat JSON fixture bytes.
 * @param key Quoted optional field name.
 * @param value Existing value updated only when a valid boolean is present.
 * @return true for an absent or valid field; false for a malformed token.
 */
[[nodiscard]] bool parse_optional_bool(std::string_view payload, std::string_view key, bool &value) noexcept
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
 * @brief Parse one optional bounded unsigned JSON integer.
 * @param payload Borrowed flat JSON fixture bytes.
 * @param key Quoted optional field name.
 * @param maximum Inclusive admitted numeric ceiling.
 * @param value Existing value updated only when a valid bounded integer is present.
 * @return true for an absent or valid field; false for malformed or out-of-range input.
 * @tparam integer_type Unsigned destination type matching the supplied bound.
 */
template <typename integer_type>
[[nodiscard]] bool parse_optional_unsigned(std::string_view payload, std::string_view key, integer_type maximum,
					   integer_type &value) noexcept
{
	const auto token = json_value(payload, key);
	if (!token.has_value()) {
		return true;
	}
	if (token->empty()) {
		return false;
	}
	uint32_t parsed = 0;
	const auto result = std::from_chars(token->data(), token->data() + token->size(), parsed);
	if (result.ec != std::errc{} || result.ptr != token->data() + token->size() || parsed > maximum) {
		return false;
	}
	value = static_cast<integer_type>(parsed);
	return true;
}

/**
 * @brief Initialize context state and owner-local telemetry.
 * @param lifecycle Borrowed INIT services and identity.
 * @param out_state Output initialized to null after argument admission and set to owned state on success.
 * @return KINETUM_OK with state ownership, or the exact allocation/registration error.
 */
[[nodiscard]] kinetum_error test_init(const kinetum_lifecycle_ctx *lifecycle, void **out_state) noexcept
{
	if (!lifecycle || !out_state) {
		return KINETUM_ERR_INVALID_ARG;
	}
	kinetum_lifecycle_log(lifecycle, KINETUM_LIFECYCLE_LOG_DEBUG, "test_module.init");
	*out_state = nullptr;
	void *storage = nullptr;
	kinetum_error error = kinetum_lifecycle_allocate_context(lifecycle, sizeof(test_module_state),
								 alignof(test_module_state),
								 KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (error != KINETUM_OK) {
		return error;
	}
	auto *state = static_cast<test_module_state *>(storage);
	const auto registration_failure = [&](kinetum_error failure) noexcept {
		const kinetum_error release_error = kinetum_lifecycle_release_context(lifecycle, state);
		return release_error == KINETUM_OK ? failure : release_error;
	};
	error = kinetum_lifecycle_register_counter(lifecycle, "test_module.checked", &state->checked);
	if (error != KINETUM_OK) {
		return registration_failure(error);
	}
	error = kinetum_lifecycle_register_counter(lifecycle, "test_module.dropped", &state->dropped);
	if (error != KINETUM_OK) {
		return registration_failure(error);
	}
	error = kinetum_lifecycle_register_counter(lifecycle, "test_module.forwarded", &state->forwarded);
	if (error != KINETUM_OK) {
		return registration_failure(error);
	}
	error = kinetum_lifecycle_register_counter(lifecycle, "test_module.dscp_drops", &state->dscp_drops);
	if (error != KINETUM_OK) {
		return registration_failure(error);
	}
	error = kinetum_lifecycle_register_counter(lifecycle, "test_module.batches", &state->batches);
	if (error != KINETUM_OK) {
		return registration_failure(error);
	}
	error = kinetum_lifecycle_register_histogram(lifecycle, "test_module.packet_bytes", 2048u, 1,
						     &state->packet_bytes);
	if (error != KINETUM_OK) {
		return registration_failure(error);
	}

	*out_state = state;
	return KINETUM_OK;
}

/**
 * @brief Release detached context state after owner-worker join.
 * @param lifecycle Borrowed FINI services for the context.
 * @param state Exact non-null context allocation returned by INIT.
 */
void test_fini(const kinetum_lifecycle_ctx *lifecycle, void *state) noexcept
{
	if (!lifecycle || !state || kinetum_lifecycle_release_context(lifecycle, state) != KINETUM_OK) {
		std::terminate();
	}
	kinetum_lifecycle_log(lifecycle, KINETUM_LIFECYCLE_LOG_DEBUG, "test_module.fini");
}

/**
 * @brief Prepare one immutable bounded test policy in the exact epoch arena.
 * @param lifecycle Borrowed PREPARE allocation and cancellation services.
 * @param epoch Exact nonzero target epoch.
 * @param config_data Borrowed fixture policy bytes, or nullptr for an empty policy.
 * @param config_len Exact policy byte count.
 * @param out_prepared Output cleared after argument admission and populated with the arena view on success.
 * @return KINETUM_OK with an immutable arena view, or a precise argument/configuration/cancellation/allocation error.
 */
[[nodiscard]] kinetum_error test_prepare(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch,
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

	test_module_config candidate;
	const std::string_view payload =
		config_data ? std::string_view(static_cast<const char *>(config_data), config_len) : std::string_view{};
	if (!parse_optional_bool(payload, "\"drop\"", candidate.drop_all) ||
	    !parse_optional_bool(payload, "\"rewrite_metadata\"", candidate.rewrite_metadata) ||
	    !parse_optional_bool(payload, "\"corrupt_packet_facts\"", candidate.corrupt_packet_facts) ||
	    !parse_optional_unsigned(payload, "\"dscp_drop\"", static_cast<uint8_t>(63), candidate.dscp_drop) ||
	    !parse_optional_unsigned(payload, "\"corrupt_authority\"", static_cast<uint8_t>(11),
				     candidate.corrupt_authority) ||
	    !parse_optional_unsigned(payload, "\"route_to_stage\"", static_cast<uint16_t>(KINETUM_NEXT_STAGE_UNSET - 1),
				     candidate.route_to_stage) ||
	    !parse_optional_unsigned(payload, "\"output_port\"", static_cast<uint16_t>(KINETUM_PORT_DROP - 1),
				     candidate.output_port)) {
		return KINETUM_ERR_CONFIG_INVALID;
	}

	void *storage = nullptr;
	const kinetum_error allocation_error = kinetum_lifecycle_allocate_epoch(
		lifecycle, sizeof(candidate), alignof(test_module_config), KINETUM_LIFECYCLE_ALLOC_ZERO, &storage);
	if (allocation_error != KINETUM_OK) {
		return allocation_error;
	}
	std::memcpy(storage, &candidate, sizeof(candidate));
	if (kinetum_lifecycle_cancellation_requested(lifecycle)) {
		return KINETUM_ERR_CANCELLED;
	}
	out_prepared->packet_config = storage;
	return KINETUM_OK;
}

/**
 * @brief Validate the exact prepared view during bounded activation.
 * @param ctx Non-null live module context.
 * @param epoch Exact nonzero activating epoch.
 * @param prepared Borrowed arena-backed policy view with no module-owned heap handle.
 */
void test_activate(kinetum_ctx *ctx, uint64_t epoch, const kinetum_prepared_config *prepared) noexcept
{
	if (!ctx || epoch == 0 || !prepared || prepared->owner_handle || !prepared->packet_config) {
		std::terminate();
	}
}

/**
 * @brief Complete module retirement; the platform owns epoch-arena release.
 * @param lifecycle Borrowed RETIRE lifecycle shell.
 * @param epoch Exact nonzero retired epoch.
 * @param retired Arena-backed policy view returned for retirement validation.
 */
void test_retire(const kinetum_lifecycle_ctx *lifecycle, uint64_t epoch, kinetum_prepared_config retired) noexcept
{
	if (!lifecycle || epoch == 0 || retired.owner_handle || !retired.packet_config) {
		std::terminate();
	}
}

/**
 * @brief Process one exact-config packet batch without allocation or locking.
 * @param batch Borrowed valid callback batch carrying the exact context and epoch configuration.
 * @return Forward mask after the selected test policy and corruption probes have run.
 */
KINETUM_HOT uint64_t test_process(kinetum_batch_t *batch) noexcept
{
	if (!batch || !batch->ctx || !batch->ctx->state) {
		std::terminate();
	}
	auto *state = static_cast<test_module_state *>(batch->ctx->state);
	const auto *config = static_cast<const test_module_config *>(batch->epoch_config);
	if (!config) {
		return 0;
	}

	const uint16_t count = batch->count;
	for (uint16_t index = 0u; index < count; ++index) {
		KINETUM_HISTOGRAM_RECORD_FAST(state->packet_bytes, batch->len[index]);
	}
	uint64_t forward_mask = KINETUM_FORWARD_MASK(count);
	if (KINETUM_UNLIKELY(config->drop_all)) {
		KINETUM_COUNTER_ADD(state->dropped, count);
		KINETUM_COUNTER_ADD(state->checked, count);
		KINETUM_COUNTER_INC(state->batches);
		return 0;
	}

	uint64_t dropped = 0;
	for (uint16_t index = 0; index < count; ++index) {
		if (KINETUM_LIKELY(index + 2 < count)) {
			__builtin_prefetch(&batch->dscp[index + 2], 0, 3);
		}
		if (config->dscp_drop != UINT8_MAX && batch->dscp[index] == config->dscp_drop) {
			KINETUM_DROP(forward_mask, index);
			++dropped;
		} else if (config->route_to_stage != KINETUM_NEXT_STAGE_UNSET) {
			batch->next_stage[index] = config->route_to_stage;
		}
		if (config->output_port != KINETUM_PORT_UNSET) {
			batch->output_port[index] = config->output_port;
		}
		if (KINETUM_UNLIKELY(config->rewrite_metadata)) {
			batch->l3_off[index] = 14;
			batch->l4_off[index] = 34;
			batch->src_ip[index] = UINT32_C(0xc0000201);
			batch->dst_ip[index] = UINT32_C(0xc6336402);
			batch->src_port[index] = 4321;
			batch->dst_port[index] = 443;
			batch->proto[index] = 6;
			batch->dscp[index] = 46;
			batch->platform_flags[index] = KINETUM_PKT_F_L3_IPV4 | KINETUM_PKT_F_L4_TCP;
			batch->user_flags[index] = UINT32_C(0xa5a55a5a);
			batch->flow_hash[index] = UINT32_C(0x10203040);
			batch->output_port[index] = 7;
			batch->user_meta[index] = UINT64_C(0x1122334455667788);
			batch->user_meta_valid[index] = 1;
		}
	}
	if (KINETUM_UNLIKELY(config->corrupt_authority != 0 && count != 0u)) {
		// Test-only faults exercise each runtime-owned callback lane. Production
		// modules have no reason to branch on this private test configuration.
		const uint16_t last = static_cast<uint16_t>(count - 1u);
		switch (config->corrupt_authority) {
		case 1:
			batch->data[last] = nullptr;
			break;
		case 2:
			++batch->len[last];
			break;
		case 3:
			++batch->input_port[last];
			break;
		case 4:
			++batch->ts_ns[last];
			break;
		case 5:
			batch->count = static_cast<uint16_t>(count + 1);
			break;
		case 6:
			++batch->region_id;
			break;
		case 7:
			batch->padding = 1;
			break;
		case 8:
			++batch->epoch;
			break;
		case 9:
			batch->epoch_config = nullptr;
			break;
		case 10:
			batch->ctx = nullptr;
			break;
		case 11:
			if (count < KINETUM_MAX_BURST) {
				forward_mask |= UINT64_C(1) << count;
			}
			break;
		default:
			break;
		}
	}
	if (KINETUM_UNLIKELY(config->corrupt_packet_facts && count != 0)) {
		// Test-only contract fault: a TCP protocol fact cannot coexist with UDP's
		// protocol number. The runtime must fail stop rather than publish it.
		batch->platform_flags[0] = KINETUM_PKT_F_L3_IPV4 | KINETUM_PKT_F_L4_TCP;
		batch->proto[0] = 17;
	}

	KINETUM_COUNTER_ADD(state->checked, count);
	KINETUM_COUNTER_ADD(state->forwarded, count - dropped);
	KINETUM_COUNTER_ADD(state->dropped, dropped);
	KINETUM_COUNTER_ADD(state->dscp_drops, dropped);
	KINETUM_COUNTER_INC(state->batches);
	return forward_mask;
}

/**
 * @brief Return bounded policy health from the exact owner-worker view.
 * @param ctx Sole-owner live module context.
 * @param active_epoch Exact nonzero active epoch.
 * @param active_packet_config Exact immutable test policy.
 * @return Bounded deterministic assessment without provenance fields.
 */
[[nodiscard]] kinetum_health_assessment test_health(kinetum_ctx *ctx, uint64_t active_epoch,
						    const void *active_packet_config) noexcept
{
	if (ctx == nullptr || ctx->state == nullptr || active_epoch == 0u || active_packet_config == nullptr) {
		std::terminate();
	}
	const auto *config = static_cast<const test_module_config *>(active_packet_config);
	kinetum_health_assessment assessment{};
	if (config->drop_all) {
		assessment.health_score = 25u;
		assessment.flags = static_cast<uint32_t>(KINETUM_HEALTH_F_CRITICAL | KINETUM_HEALTH_F_CONFIG_ISSUE);
		constexpr char REASON[] = "drop policy active";
		std::memcpy(assessment.reason, REASON, sizeof(REASON));
		return assessment;
	}
	assessment.health_score = 100u;
	constexpr char REASON[] = "ready";
	std::memcpy(assessment.reason, REASON, sizeof(REASON));
	return assessment;
}

/** @brief Exact passive test-module descriptor. */
const kinetum_module TEST_MODULE{
	.module_id = "test_module",
	.module_version = "1.0.0",
	.abi_version = KINETUM_MODULE_ABI_VERSION,
	.flags = KINETUM_MOD_F_REPLICABLE_CONTEXTS | KINETUM_MOD_F_LIVE_EPOCH_TRANSITION,
	.mode = KINETUM_MODULE_PASSIVE,
	.prepare_config = test_prepare,
	.activate_config = test_activate,
	.retire_config = test_retire,
	.process = test_process,
	.ingest = nullptr,
	.run = nullptr,
	.on_control = nullptr,
	.init = test_init,
	.fini = test_fini,
	.health_check = test_health,
	.select_contexts = nullptr,
};

}  // namespace

/** @return Immutable passive test-module descriptor retained for the image lifetime. */
extern "C" KINETUM_MODULE_EXPORT const kinetum_module *kinetum_module_register(void)
{
	return &TEST_MODULE;
}
