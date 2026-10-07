// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file logging_status.cpp
 * @brief Exact logging-health projection with no inferred counters or readiness coupling.
 * @author Fleming Patel
 */

#include "src/common/logging_status.hpp"

#include <algorithm>

#include "src/common/log_service.hpp"
#include "src/common/protobuf_contract.hpp"

namespace kinetum::common
{

void project_process_logging_status(kinetum::common::v1::LoggingStatus &output)
{
	const auto observed = process_log_health();
	output.Clear();
	using wire = kinetum::common::v1::LoggingStatus;
	switch (observed.destination) {
	case log_destination_state::AVAILABLE:
		output.set_destination(wire::DESTINATION_STATE_AVAILABLE);
		break;
	case log_destination_state::UNAVAILABLE:
		output.set_destination(wire::DESTINATION_STATE_UNAVAILABLE);
		break;
	case log_destination_state::CLOSED:
		output.set_destination(wire::DESTINATION_STATE_CLOSED);
		break;
	}
	output.set_accepted_records(observed.accepted_records);
	output.set_queue_rejections(observed.queue_rejections);
	output.set_format_rejections(observed.format_rejections);
	output.set_unavailable_rejections(observed.unavailable_rejections);
	output.set_undelivered_records(observed.undelivered_records);
	output.set_write_failures(observed.write_failures);
	output.set_console_failures(observed.console_failures);
	output.set_truncated_records(observed.truncated_records);
	output.set_packet_thread_rejections(observed.packet_thread_rejections);
	output.set_delivery_timeouts(observed.delivery_timeouts);
	output.set_failure(observed.failure.data());
}

status validate_logging_status(const kinetum::common::v1::LoggingStatus &input)
{
	using wire = kinetum::common::v1::LoggingStatus;
	const auto unknown = reject_unknown_protobuf_fields_recursive(input, "LoggingStatus");
	if (!unknown.is_ok()) {
		return status::data_loss(static_status_text("logging status contains unknown fields"));
	}
	if (!input.has_accepted_records() || !input.has_queue_rejections() || !input.has_format_rejections() ||
	    !input.has_unavailable_rejections() || !input.has_undelivered_records() || !input.has_write_failures() ||
	    !input.has_console_failures() || !input.has_truncated_records() || !input.has_packet_thread_rejections() ||
	    !input.has_delivery_timeouts()) {
		return status::data_loss(static_status_text("logging status omits required counter presence"));
	}
	if (input.failure().size() > 255 ||
	    !std::all_of(input.failure().begin(), input.failure().end(),
			 [](unsigned char byte) { return byte >= 32 && byte <= 126; })) {
		return status::data_loss(static_status_text("logging status has an invalid failure diagnostic"));
	}
	const auto state = input.destination();
	if (state != wire::DESTINATION_STATE_AVAILABLE && state != wire::DESTINATION_STATE_UNAVAILABLE &&
	    state != wire::DESTINATION_STATE_CLOSED) {
		return status::data_loss(static_status_text("logging status has no declared destination state"));
	}
	if ((state == wire::DESTINATION_STATE_AVAILABLE && !input.failure().empty()) ||
	    (state == wire::DESTINATION_STATE_UNAVAILABLE &&
	     (input.failure().empty() || input.write_failures() == 0))) {
		return status::data_loss(static_status_text("logging destination contradicts its failure evidence"));
	}
	return status::ok();
}

}  // namespace kinetum::common
