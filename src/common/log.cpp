// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file log.cpp
 * @brief Bounded cold logging, synchronous command delivery, and service writer ownership.
 * @author Fleming Patel
 */

#include "src/common/log.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <new>
#include <system_error>
#include <thread>
#include <utility>

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <kinetum/algo/atomic_index_pool.hpp>
#include <kinetum/algo/queue.hpp>

#include "src/common/linux_cpu_set.hpp"
#include "src/common/log_file.hpp"
#include "src/common/log_service.hpp"
#include "src/common/packet_thread_log_guard.hpp"
#include "src/common/process_output.hpp"

namespace kinetum::common
{
namespace
{

/** Number of ordinary record owners; the fatal record has separate storage. */
constexpr uint16_t LOG_RECORD_COUNT = 256;
/** Whole-service retirement allows a bounded final drain after producers join. */
constexpr auto LOG_DRAIN_TIMEOUT = std::chrono::seconds(2);
/** Per-record file-confirmation wait; emergency I/O has its own best-effort fate. */
constexpr auto LOG_DELIVERY_TIMEOUT = std::chrono::milliseconds(100);

/** The process owner publishes once before emitters and clears only after they retire. */
std::atomic<log_service *> ACTIVE_SERVICE{nullptr};
/** A retired service never silently resumes synchronous command logging. */
std::atomic<bool> SERVICE_STARTED{false};
/** Serializes only complete finite-command records, never message construction. */
std::mutex COMMAND_MUTEX;
/** Sticky finite diagnostic failure checked before result publication. */
std::atomic<bool> COMMAND_FAILED{false};
/** Explicit finite executable identity; unavailable before the entry point supplies it. */
std::array<char, 49> COMMAND_APPLICATION{};

/** @brief Fail stop using a static raw breadcrumb, independent of logger state. */
[[noreturn]] void logging_invariant_failure() noexcept
{
	std::fputs("Kinetum logging ownership invariant failed\n", stderr);
	(void)std::fflush(stderr);
	std::abort();
}

/**
 * @param value Complete header token.
 * @param maximum Maximum permitted byte count.
 * @return True for a bounded nonempty PRINTUSASCII token.
 */
[[nodiscard]] bool valid_token(std::string_view value, std::size_t maximum) noexcept
{
	return !value.empty() && value.size() <= maximum &&
	       std::all_of(value.begin(), value.end(), [](unsigned char byte) { return byte >= 33 && byte <= 126; });
}

/** @return Cached host identity; process/thread/time facts belong to each emitter. */
[[nodiscard]] const std::array<char, 256> &hostname() noexcept
{
	static const auto HOSTNAME = [] {
		std::array<char, 256> result{};
		if (::gethostname(result.data(), result.size()) != 0 || result.back() != '\0') {
			result.fill('\0');
		}
		return result;
	}();
	return HOSTNAME;
}

/**
 * @brief Copy actual metadata before invoking any possibly foreign formatter.
 * @param record Exclusively owned raw record slot.
 * @param site Borrowed emitter facts.
 * @param application Immutable admitted process role.
 */
void stamp(log_record &record, log_site site, std::string_view application) noexcept
{
	record.level = site.level;
	record.native_severity = site.native_severity;
	record.truncated = site.truncated;
	record.message_size = 0;
	record.hostname = hostname();
	record.process_id = static_cast<uint64_t>(::getpid());
	const long thread_id = ::syscall(SYS_gettid);
	record.thread_id = thread_id > 0 ? static_cast<uint64_t>(thread_id) : 0;
	struct timespec now{};
	record.realtime_us =
		::clock_gettime(CLOCK_REALTIME, &now) == 0 ?
			static_cast<int64_t>(now.tv_sec) * 1000000 + static_cast<int64_t>(now.tv_nsec / 1000) :
			0;
	const bool application_complete = copy_log_field(record.application, application);
	const bool component_complete = copy_log_field(record.component, site.component);
	const bool event_complete = copy_log_field(record.event, site.event);
	const bool function_complete = copy_log_field(record.function, site.function);
	record.truncated = record.truncated ||
			   !(application_complete && component_complete && event_complete && function_complete);
}

/**
 * @brief Construct all owned bytes; format failure never escapes into the described operation.
 * @param record Exclusively owned destination slot.
 * @param site Complete borrowed emitter facts.
 * @param application Immutable process role.
 * @param context Borrowed synchronous formatter state.
 * @param builder Formatter invoked without a logger lock and never retained.
 * @return True with a complete bounded record; false before publication on failure.
 */
[[nodiscard]] bool construct(log_record &record, log_site site, std::string_view application, void *context,
			     log_message_builder builder) noexcept
{
	if (!valid_token(site.event, 32) || site.function.find('\0') != std::string_view::npos || builder == nullptr ||
	    (site.native_severity.has_value() && *site.native_severity > 7)) {
		return false;
	}
	stamp(record, site, application);
	try {
		const auto full_size = builder(context, record.message);
		record.message_size = std::min(full_size, record.message.size());
		record.truncated = record.truncated || full_size > record.message.size();
		return true;
	} catch (...) {
		return false;
	}
}

/**
 * @param record Complete encoded record borrowed for the write.
 * @return True after checked stderr delivery of every byte.
 */
[[nodiscard]] bool write_console(std::string_view record) noexcept
{
	return detail::write_process_output(STDERR_FILENO, record);
}

/**
 * @brief Attempt emergency stderr without entering another logger lock or queue.
 * @param record Complete encoded bytes retained by this caller.
 * @return Complete byte delivery, or failure without exposing this write's SIGPIPE.
 * @note The write may block and may interleave with other stderr writers.
 *       Only this call's newly generated SIGPIPE is consumed before mask restoration.
 */
[[nodiscard]] bool write_emergency(std::string_view record) noexcept
{
	sigset_t blocked{};
	sigset_t previous{};
	sigset_t pending{};
	if (::sigemptyset(&blocked) != 0 || ::sigaddset(&blocked, SIGPIPE) != 0 ||
	    ::pthread_sigmask(SIG_BLOCK, &blocked, &previous) != 0) {
		return false;
	}
	const bool inspected = ::sigpending(&pending) == 0;
	const bool previously_pending = inspected && ::sigismember(&pending, SIGPIPE) == 1;
	const bool written = inspected && write_console(record);
	const int write_error = errno;
	if (inspected && !written && write_error == EPIPE && !previously_pending) {
		const timespec immediate{};
		int signal;
		do {
			signal = ::sigtimedwait(&blocked, nullptr, &immediate);
		} while (signal < 0 && errno == EINTR);
		if (signal != SIGPIPE && !(signal < 0 && errno == EAGAIN)) {
			logging_invariant_failure();
		}
	}
	if (::pthread_sigmask(SIG_SETMASK, &previous, nullptr) != 0) {
		logging_invariant_failure();
	}
	return written;
}

/**
 * @brief Keep synchronous record and encoding storage off the asynchronous caller's stack.
 * @param site Complete borrowed emitter identity.
 * @param context Borrowed formatter state.
 * @param builder Synchronous formatter, invoked before the serialization lock.
 */
[[gnu::noinline]] void submit_command_log(log_site site, void *context, log_message_builder builder) noexcept
{
	log_record record;
	if (!construct(record, site, COMMAND_APPLICATION.data(), context, builder)) {
		COMMAND_FAILED.store(true, std::memory_order_relaxed);
		return;
	}
	std::array<char, LOG_ENCODED_BYTES> encoded{};
	const auto size = encode_log_record(record, encoded);
	std::lock_guard lock(COMMAND_MUTEX);
	if (size == 0 || !write_console(std::string_view(encoded.data(), size))) {
		COMMAND_FAILED.store(true, std::memory_order_relaxed);
	}
}

}  // namespace

/** @brief All service state has one lifetime, independent of queued foreign code. */
class log_service::implementation final {
    private:
	/** @brief Exact file outcome, separate from queue consumption and console delivery. */
	enum class file_outcome : uint8_t {
		PENDING = 0,  ///< Writer still owns an unresolved append.
		DELIVERED,    ///< Every encoded byte was accepted by the file write.
		FAILED,	      ///< No complete file delivery; loss is already accounted.
	};
	/** @brief Fixed-slot completion ownership protected by completion_mutex_. */
	struct delivery_receipt {
		bool requested{false};	   ///< Immutable for one published slot lease.
		bool caller_owned{false};  ///< Caller retains this receipt through observation or timeout.
		bool writer_owned{false};  ///< Writer retains record bytes through file and mirror delivery.
		file_outcome outcome{file_outcome::PENDING};  ///< Written once under the predicate mutex.
	};

    public:
	/**
	 * @param options Immutable configuration copied into this owner.
	 * @param application Exact process role copied into this owner.
	 * @param cpu Compiled DP coordinator placement, absent for CP/Photon.
	 */
	implementation(const log_options &options, std::string_view application, std::optional<int32_t> cpu)
		: options_(options)
		, application_(application)
		, cpu_(cpu)
	{
	}
	/** @brief Retire the writer before freeing any arena, descriptor, or condition variable. */
	~implementation()
	{
		if (writer_.joinable()) {
			closing_.store(true, std::memory_order_release);
			wake();
			std::unique_lock lock(lifecycle_mutex_);
			if (!lifecycle_cv_.wait_for(lock, LOG_DRAIN_TIMEOUT, [this] { return finished_; })) {
				logging_invariant_failure();
			}
			lock.unlock();
			writer_.join();
		}
		if (wake_fd_ >= 0) {
			(void)::close(wake_fd_);
		}
	}
	/** @return Complete file and writer-placement admission, or a pre-publication startup failure. */
	[[nodiscard]] status start()
	{
		auto opened = file_.open(options_, application_);
		if (!opened.is_ok()) {
			return opened;
		}
		wake_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (wake_fd_ < 0) {
			return status::unavailable("logging eventfd: " + std::string(std::strerror(errno)));
		}
		writer_ = std::thread([this] { run(); });
		std::unique_lock lock(lifecycle_mutex_);
		lifecycle_cv_.wait(lock, [this] { return ready_; });
		if (startup_error_ != 0) {
			return status::unavailable("logging writer startup: " +
						   std::string(std::strerror(startup_error_)));
		}
		return status::ok();
	}
	/**
	 * @param level Declared candidate severity.
	 * @param component Already admitted component index.
	 * @return Immutable filter decision, with mandatory startup-error visibility.
	 */
	[[nodiscard]] bool enabled(log_level level, std::size_t component) const noexcept
	{
		return (startup_.load(std::memory_order_acquire) && level >= log_level::ERROR) ||
		       level >= options_.component_levels[component].value_or(options_.level);
	}
	/**
	 * @brief Claim one bounded record, format without locks, and publish only owned bytes.
	 * @param site Exact emitter identity borrowed until return.
	 * @param context Borrowed synchronous formatter state.
	 * @param builder Formatter invoked without a logger lock and never retained.
	 */
	void submit(log_site site, void *context, log_message_builder builder) noexcept
	{
		if (closing_.load(std::memory_order_acquire)) {
			logging_invariant_failure();
		}
		const bool console = options_.console ||
				     (startup_.load(std::memory_order_acquire) && site.level >= log_level::ERROR);
		if (destination_.load(std::memory_order_acquire) != log_destination_state::AVAILABLE && !console) {
			unavailable_rejections_.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		uint32_t index = 0;
		if (!free_.try_acquire(index)) {
			queue_rejections_.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		outstanding_.fetch_add(1, std::memory_order_relaxed);
		completions_[index] = {};
		records_[index].console = console;
		if (!construct(records_[index], site, application_, context, builder)) {
			format_rejections_.fetch_add(1, std::memory_order_relaxed);
			return_record(index);
			return;
		}
		if (records_[index].truncated) {
			truncated_records_.fetch_add(1, std::memory_order_relaxed);
		}
		accepted_records_.fetch_add(1, std::memory_order_relaxed);
		if (!ready_records_.try_enqueue(static_cast<uint16_t>(index))) {
			// Every ready cell has a unique arena owner; a leased slot proves space.
			logging_invariant_failure();
		}
		wake();
	}
	/**
	 * @brief Preserve a native ERROR+ record through its own bounded file wait.
	 * @param site Exact foreign emitter identity; severity filtering has already been bypassed.
	 * @param context Borrowed synchronous formatter state.
	 * @param builder Formatter evaluated once before any queue or completion lock.
	 * @note The caller owns an independent bounded copy for emergency output;
	 *       queued bytes and receipt remain in the fixed arena after timeout.
	 */
	[[gnu::noinline]] void submit_foreign_error(log_site site, void *context, log_message_builder builder) noexcept
	{
		if (closing_.load(std::memory_order_acquire)) {
			logging_invariant_failure();
		}
		log_record incoming;
		if (!construct(incoming, site, application_, context, builder)) {
			reject();
			stamp(incoming, {log_level::ERROR, "logging", "logging.native.rejected", __func__},
			      application_);
			constexpr std::string_view MESSAGE = "foreign ERROR record could not be constructed";
			std::copy(MESSAGE.begin(), MESSAGE.end(), incoming.message.begin());
			incoming.message_size = MESSAGE.size();
			emergency(incoming);
			return;
		}
		incoming.console = options_.console || startup_.load(std::memory_order_acquire);
		if (destination_.load(std::memory_order_acquire) != log_destination_state::AVAILABLE) {
			unavailable_rejections_.fetch_add(1, std::memory_order_relaxed);
			emergency(incoming);
			return;
		}
		uint32_t index = 0;
		if (!free_.try_acquire(index)) {
			queue_rejections_.fetch_add(1, std::memory_order_relaxed);
			emergency(incoming);
			return;
		}
		outstanding_.fetch_add(1, std::memory_order_relaxed);
		records_[index] = incoming;
		// Exclusive slot ownership precedes publication. Every later predicate
		// update and observation uses completion_mutex_ until both claims retire.
		completions_[index] = {.requested = true, .caller_owned = true, .writer_owned = true};
		accepted_records_.fetch_add(1, std::memory_order_relaxed);
		if (incoming.truncated) {
			truncated_records_.fetch_add(1, std::memory_order_relaxed);
		}
		const auto deadline = std::chrono::steady_clock::now() + LOG_DELIVERY_TIMEOUT;
		if (!ready_records_.try_enqueue(static_cast<uint16_t>(index))) {
			logging_invariant_failure();
		}
		wake();
		if (!wait_for_file(index, deadline)) {
			emergency(incoming);
		}
	}
	/**
	 * @brief Offer one separately owned fatal record; never wait for ordinary capacity.
	 * @param site Actual terminal emitter metadata.
	 * @param message Preformatted borrowed raw breadcrumb, copied before waiting.
	 */
	void offer_fatal(log_site site, std::string_view message) noexcept
	{
		if (!valid_token(site.event, 32) || (site.native_severity.has_value() && *site.native_severity > 7)) {
			reject();
			return;
		}
		uint8_t expected = 0;
		if (destination_.load(std::memory_order_acquire) != log_destination_state::AVAILABLE) {
			unavailable_rejections_.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		if (!fatal_state_.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) {
			queue_rejections_.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		stamp(fatal_record_, site, application_);
		fatal_record_.console = options_.console;
		fatal_record_.level = log_level::FATAL;
		fatal_record_.message_size = std::min(message.size(), fatal_record_.message.size());
		if (fatal_record_.message_size != 0) {
			std::memcpy(fatal_record_.message.data(), message.data(), fatal_record_.message_size);
		}
		fatal_record_.truncated = fatal_record_.truncated || message.size() > fatal_record_.message.size();
		accepted_records_.fetch_add(1, std::memory_order_relaxed);
		if (fatal_record_.truncated) {
			truncated_records_.fetch_add(1, std::memory_order_relaxed);
		}
		fatal_state_.store(2, std::memory_order_release);
		wake();
		const auto deadline = std::chrono::steady_clock::now() + LOG_DELIVERY_TIMEOUT;
		while (fatal_state_.load(std::memory_order_acquire) != 3 &&
		       std::chrono::steady_clock::now() < deadline) {
			std::this_thread::yield();
		}
		if (fatal_state_.load(std::memory_order_acquire) != 3) {
			delivery_timeouts_.fetch_add(1, std::memory_order_relaxed);
		}
	}
	/** @brief Publish a coalescing request; eventfd is notification, never record ownership. */
	void request_reopen() noexcept
	{
		reopen_requested_.store(true, std::memory_order_release);
		wake();
	}
	/** @brief Retire startup-only error mirroring without changing configured live filters. */
	void startup_complete() noexcept
	{
		startup_.store(false, std::memory_order_release);
	}
	/** @brief Count one malformed native record before queue admission. */
	void reject() noexcept
	{
		format_rejections_.fetch_add(1, std::memory_order_relaxed);
	}
	/** @return Independent counters and coherent destination/cause without waiting for file I/O. */
	[[nodiscard]] log_health health() const noexcept
	{
		log_health result;
		{
			std::lock_guard lock(health_mutex_);
			result.destination = destination_.load(std::memory_order_relaxed);
			result.failure = failure_;
		}
		result.accepted_records = accepted_records_.load(std::memory_order_relaxed);
		result.queue_rejections = queue_rejections_.load(std::memory_order_relaxed);
		result.format_rejections = format_rejections_.load(std::memory_order_relaxed);
		result.unavailable_rejections = unavailable_rejections_.load(std::memory_order_relaxed);
		result.undelivered_records = undelivered_records_.load(std::memory_order_relaxed);
		result.write_failures = write_failures_.load(std::memory_order_relaxed);
		result.console_failures = console_failures_.load(std::memory_order_relaxed);
		result.truncated_records = truncated_records_.load(std::memory_order_relaxed);
		result.packet_thread_rejections = packet_thread_log_rejections();
		result.delivery_timeouts = delivery_timeouts_.load(std::memory_order_relaxed);
		return result;
	}
	/** @return Whether the accepted prefix has completed without any recorded loss. */
	[[nodiscard]] bool delivered() const noexcept
	{
		const auto fatal = fatal_state_.load(std::memory_order_acquire);
		return outstanding_.load(std::memory_order_acquire) == 0 && (fatal == 0 || fatal == 3) &&
		       undelivered_records_.load(std::memory_order_relaxed) == 0 &&
		       format_rejections_.load(std::memory_order_relaxed) == 0 &&
		       queue_rejections_.load(std::memory_order_relaxed) == 0 &&
		       unavailable_rejections_.load(std::memory_order_relaxed) == 0;
	}

    private:
	/**
	 * @param record Complete caller-owned record, independent of writer progress.
	 * @note No completion, writer, health, or command lock spans emergency I/O.
	 */
	[[gnu::noinline]] void emergency(const log_record &record) noexcept
	{
		std::array<char, LOG_ENCODED_BYTES> encoded{};
		const auto size = encode_log_record(record, encoded);
		if (size == 0 || !write_emergency(std::string_view(encoded.data(), size))) {
			console_failures_.fetch_add(1, std::memory_order_relaxed);
		}
	}
	/**
	 * @param index Exact leased arena index; cannot be reused while either claim exists.
	 * @param deadline Absolute steady-clock end of this record's writer wait.
	 * @return True only for confirmed complete file delivery; consumes the caller's claim.
	 */
	[[nodiscard]] bool wait_for_file(uint32_t index, std::chrono::steady_clock::time_point deadline) noexcept
	{
		std::unique_lock lock(completion_mutex_);
		auto &receipt = completions_[index];
		const bool completed = completion_cv_.wait_until(lock, deadline, [&receipt] {
			return receipt.outcome != file_outcome::PENDING;
		});
		if (!completed) {
			delivery_timeouts_.fetch_add(1, std::memory_order_relaxed);
		}
		const bool delivered = completed && receipt.outcome == file_outcome::DELIVERED;
		receipt.caller_owned = false;
		if (!receipt.writer_owned) {
			return_record(index);
		}
		return delivered;
	}
	/**
	 * @param receipt Published receipt, or null for ordinary records.
	 * @param delivered Complete file-write outcome; console fate is independent.
	 */
	void complete_file(delivery_receipt *receipt, bool delivered) noexcept
	{
		if (receipt == nullptr) {
			return;
		}
		{
			std::lock_guard lock(completion_mutex_);
			receipt->outcome = delivered ? file_outcome::DELIVERED : file_outcome::FAILED;
		}
		// Do not leave a completed caller asleep behind the next record's I/O.
		completion_cv_.notify_all();
	}
	/** @param index Record whose writer-side file and mirror work has finished. */
	void finish_writer(uint32_t index) noexcept
	{
		auto &receipt = completions_[index];
		if (!receipt.requested) {
			return_record(index);
			return;
		}
		std::lock_guard lock(completion_mutex_);
		receipt.writer_owned = false;
		if (!receipt.caller_owned) {
			return_record(index);
		}
	}

	/** @brief Wake the sole writer; an unexpected descriptor failure is an ownership defect. */
	void wake() noexcept
	{
		const uint64_t token = 1;
		ssize_t result;
		do {
			result = ::write(wake_fd_, &token, sizeof(token));
		} while (result < 0 && errno == EINTR);
		if (result != static_cast<ssize_t>(sizeof(token)) && !(result < 0 && errno == EAGAIN)) {
			logging_invariant_failure();
		}
	}
	/** @param index Unique arena lease retired after construction rejection or final delivery fate. */
	void return_record(uint32_t index) noexcept
	{
		free_.release(index);
		outstanding_.fetch_sub(1, std::memory_order_release);
	}
	/** @param failure Exact failed file operation; preserves first cause and increments failure evidence. */
	void failed(log_io_result failure) noexcept
	{
		write_failures_.fetch_add(1, std::memory_order_relaxed);
		std::lock_guard lock(health_mutex_);
		if (failure_[0] == '\0') {
			(void)std::snprintf(failure_.data(), failure_.size(), "%s: errno=%d", failure.operation,
					    failure.error);
		}
		destination_.store(log_destination_state::UNAVAILABLE, std::memory_order_release);
	}
	/**
	 * @param record Accepted immutable record receiving one file fate and independent optional mirror fate.
	 * @param receipt Optional fixed completion state; file outcome publishes before mirror I/O.
	 */
	void deliver(const log_record &record, delivery_receipt *receipt = nullptr) noexcept
	{
		const auto size = encode_log_record(record, encoded_);
		if (size == 0) {
			logging_invariant_failure();
		}
		const std::string_view bytes(encoded_.data(), size);
		bool file_delivered = false;
		if (destination_.load(std::memory_order_acquire) == log_destination_state::AVAILABLE) {
			const auto written = file_.append(bytes);
			if (!written.is_ok()) {
				failed(written);
				undelivered_records_.fetch_add(1, std::memory_order_relaxed);
			} else {
				file_delivered = true;
			}
		} else {
			undelivered_records_.fetch_add(1, std::memory_order_relaxed);
		}
		complete_file(receipt, file_delivered);
		if (record.console && !write_console(bytes)) {
			console_failures_.fetch_add(1, std::memory_order_relaxed);
		}
	}
	/** @brief Readmit the same files and record cumulative loss before advertising recovery. */
	void reopen() noexcept
	{
		std::array<char, 256> previous_failure{};
		{
			std::lock_guard lock(health_mutex_);
			previous_failure = failure_;
		}
		const auto reopened = file_.reopen();
		if (!reopened.is_ok()) {
			failed(reopened);
			return;
		}
		log_record recovery;
		stamp(recovery, {log_level::INFO, "logging", "logging.reopened", __func__}, application_);
		const int size = std::snprintf(
			recovery.message.data(), recovery.message.size(),
			"destination reopened; queue_rejections=%llu format_rejections=%llu unavailable_rejections=%llu undelivered_records=%llu write_failures=%llu previous_failure=%s",
			static_cast<unsigned long long>(queue_rejections_.load(std::memory_order_relaxed)),
			static_cast<unsigned long long>(format_rejections_.load(std::memory_order_relaxed)),
			static_cast<unsigned long long>(unavailable_rejections_.load(std::memory_order_relaxed)),
			static_cast<unsigned long long>(undelivered_records_.load(std::memory_order_relaxed)),
			static_cast<unsigned long long>(write_failures_.load(std::memory_order_relaxed)),
			previous_failure.data());
		if (size < 0 || static_cast<std::size_t>(size) >= recovery.message.size()) {
			logging_invariant_failure();
		}
		recovery.message_size = static_cast<std::size_t>(size);
		const auto encoded_size = encode_log_record(recovery, encoded_);
		accepted_records_.fetch_add(1, std::memory_order_relaxed);
		const auto result = file_.append(std::string_view(encoded_.data(), encoded_size));
		if (!result.is_ok()) {
			failed(result);
			undelivered_records_.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		if (options_.console && !write_console(std::string_view(encoded_.data(), encoded_size))) {
			console_failures_.fetch_add(1, std::memory_order_relaxed);
		}
		std::lock_guard lock(health_mutex_);
		failure_.fill('\0');
		destination_.store(log_destination_state::AVAILABLE, std::memory_order_release);
	}
	/** @return Zero after placement and thread-local SIGPIPE blocking, otherwise the exact native error. */
	[[nodiscard]] int prepare_writer() noexcept
	{
		sigset_t signals{};
		if (::sigemptyset(&signals) != 0 || ::sigaddset(&signals, SIGPIPE) != 0) {
			return errno;
		}
		const int blocked = ::pthread_sigmask(SIG_BLOCK, &signals, nullptr);
		if (blocked != 0) {
			return blocked;
		}
		if (cpu_.has_value()) {
			linux_cpu_set placement;
			const int prepared = linux_cpu_set::single_cpu(*cpu_, placement);
			return prepared != 0 ? prepared : placement.apply_to_current_thread();
		}
		return 0;
	}
	/** @brief Own draining, encoding, rotation, reopen, and descriptor retirement. */
	void run() noexcept
	{
		const int startup = prepare_writer();
		{
			std::lock_guard lock(lifecycle_mutex_);
			startup_error_ = startup;
			ready_ = true;
		}
		lifecycle_cv_.notify_all();
		if (startup == 0) {
			for (;;) {
				uint64_t notifications = 0;
				ssize_t read;
				do {
					read = ::read(wake_fd_, &notifications, sizeof(notifications));
				} while (read < 0 && errno == EINTR);
				if (read != static_cast<ssize_t>(sizeof(notifications)) &&
				    !(read < 0 && errno == EAGAIN)) {
					logging_invariant_failure();
				}
				if (fatal_state_.load(std::memory_order_acquire) == 2) {
					deliver(fatal_record_);
					fatal_state_.store(3, std::memory_order_release);
				}
				uint16_t index = 0;
				for (uint16_t count = 0; count < LOG_RECORD_COUNT && ready_records_.try_dequeue(index);
				     ++count) {
					deliver(records_[index],
						completions_[index].requested ? &completions_[index] : nullptr);
					finish_writer(index);
				}
				if (reopen_requested_.exchange(false, std::memory_order_acq_rel)) {
					reopen();
				}
				if (closing_.load(std::memory_order_acquire) &&
				    outstanding_.load(std::memory_order_acquire) == 0) {
					break;
				}
				struct pollfd wait{wake_fd_, POLLIN, 0};
				int waited;
				do {
					waited = ::poll(&wait, 1, -1);
				} while (waited < 0 && errno == EINTR);
				if (waited < 0 || (wait.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
					logging_invariant_failure();
				}
			}
		}
		const auto closed = file_.close();
		if (!closed.is_ok()) {
			failed(closed);
		}
		{
			std::lock_guard lock(health_mutex_);
			destination_.store(log_destination_state::CLOSED, std::memory_order_release);
		}
		{
			std::lock_guard lock(lifecycle_mutex_);
			finished_ = true;
		}
		lifecycle_cv_.notify_all();
	}

	const log_options options_;			  ///< Immutable operator selection.
	const std::string application_;			  ///< Exact fixed executable role.
	const std::optional<int32_t> cpu_;		  ///< DP's sole compiled cold coordinator placement.
	log_file file_;					  ///< Sole file ownership; writer-owned after launch.
	int wake_fd_{-1};				  ///< Coalescing writer notification only.
	std::thread writer_;				  ///< Must join before any referenced state is reclaimed.
	algo::atomic_index_pool<LOG_RECORD_COUNT> free_;  ///< Independently returned arena leases.
	algo::mpmc_queue<uint16_t, LOG_RECORD_COUNT> ready_records_;  ///< Published complete record indices.
	std::array<log_record, LOG_RECORD_COUNT> records_;	      ///< Fixed ordinary record arena.
	log_record fatal_record_{};				      ///< Independently reserved terminal diagnostic.
	std::atomic<uint8_t> fatal_state_{0};			      ///< Empty, constructing, ready, or completed.
	std::array<char, LOG_ENCODED_BYTES> encoded_{};		      ///< Sole writer's reusable expansion buffer.
	std::atomic<uint64_t> outstanding_{0};			      ///< Leased or published ordinary arena owners.
	std::atomic<bool> closing_{false};  ///< Published only after all external emitters retire.
	std::atomic<bool> startup_{true};   ///< Startup errors remain visible before the existing service startup gate.
	std::atomic<bool> reopen_requested_{false};  ///< Coalescing explicit reopen request.
	std::mutex lifecycle_mutex_;		     ///< Protects both startup and retirement wait predicates.
	std::condition_variable lifecycle_cv_;	     ///< Predicate-closed owner wakeup.
	bool ready_{false};			     ///< Writer placement has completed under lifecycle_mutex_.
	bool finished_{false};			     ///< Writer closed files under lifecycle_mutex_.
	int startup_error_{0};			     ///< Exact writer preparation errno.
	mutable std::mutex health_mutex_;	     ///< Protects destination/cause together, never file I/O.
	std::atomic<log_destination_state> destination_{log_destination_state::AVAILABLE};  ///< Admission state.
	std::array<char, 256> failure_{};		   ///< First current outage cause under health_mutex_.
	std::atomic<uint64_t> accepted_records_{0};	   ///< Published complete records.
	std::atomic<uint64_t> queue_rejections_{0};	   ///< Refused ordinary reservations.
	std::atomic<uint64_t> format_rejections_{0};	   ///< Construction failures before publication.
	std::atomic<uint64_t> unavailable_rejections_{0};  ///< Refused records during file outage.
	std::atomic<uint64_t> undelivered_records_{0};	   ///< Accepted records without complete delivery.
	std::atomic<uint64_t> write_failures_{0};	   ///< Failed destination operations.
	std::atomic<uint64_t> console_failures_{0};	   ///< Failed independent mirror operations.
	std::atomic<uint64_t> truncated_records_{0};	   ///< Admitted records marked as incomplete text.
	std::mutex completion_mutex_;  ///< Protects every published receipt predicate and both ownership claims.
	std::condition_variable completion_cv_;	 ///< Wakes all callers whose exact record may now be complete.
	std::array<delivery_receipt, LOG_RECORD_COUNT> completions_{};	///< Fixed receipt storage follows arena leases.
	std::atomic<uint64_t> delivery_timeouts_{0};  ///< Expired confirmation waits, never inferred file loss.
};

log_service::log_service(std::unique_ptr<implementation> state) noexcept
	: state_(std::move(state))
{
}

status_or<std::unique_ptr<log_service>> log_service::start(const log_options &options, std::string_view application,
							   std::optional<int32_t> writer_cpu)
{
	if (ACTIVE_SERVICE.load(std::memory_order_acquire) != nullptr ||
	    SERVICE_STARTED.load(std::memory_order_acquire)) {
		return status::failed_precondition(static_status_text("process already owns a service logger"));
	}
	if ((application == "kinetum_dp") != writer_cpu.has_value() || (writer_cpu.has_value() && *writer_cpu < 0)) {
		return status::invalid_argument(static_status_text("DP logging requires its compiled coordinator CPU"));
	}
	try {
		auto state = std::make_unique<implementation>(options, application, writer_cpu);
		const auto started = state->start();
		if (!started.is_ok()) {
			return started;
		}
		auto owner = std::unique_ptr<log_service>(new log_service(std::move(state)));
		log_service *expected = nullptr;
		if (!ACTIVE_SERVICE.compare_exchange_strong(expected, owner.get(), std::memory_order_release)) {
			return status::failed_precondition(static_status_text("concurrent service logger admission"));
		}
		SERVICE_STARTED.store(true, std::memory_order_release);
		return owner;
	} catch (const std::bad_alloc &) {
		return status::resource_exhausted(static_status_text("service logging allocation failed"));
	} catch (const std::system_error &error) {
		return status::unavailable("service logging thread startup failed: " + std::string(error.what()));
	}
}

log_service::~log_service()
{
	// External emitters have retired; keep the published owner until its writer joins.
	state_.reset();
	log_service *expected = this;
	(void)ACTIVE_SERVICE.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
}

void log_service::request_reopen() noexcept
{
	state_->request_reopen();
}

void log_service::startup_complete() noexcept
{
	state_->startup_complete();
}

log_health log_service::health() const noexcept
{
	return state_->health();
}

log_health process_log_health() noexcept
{
	const auto *owner = ACTIVE_SERVICE.load(std::memory_order_acquire);
	if (owner != nullptr) {
		return owner->health();
	}
	log_health result;
	result.packet_thread_rejections = packet_thread_log_rejections();
	return result;
}

void set_command_log_identity(std::string_view application) noexcept
{
	if (!valid_token(application, 48) || ACTIVE_SERVICE.load(std::memory_order_acquire) != nullptr ||
	    SERVICE_STARTED.load(std::memory_order_acquire)) {
		logging_invariant_failure();
	}
	(void)copy_log_field(COMMAND_APPLICATION, application);
}

bool log_enabled(log_level level, std::string_view component) noexcept
{
	const auto index = log_component_index(component);
	if (!valid_log_level(level) || !index.has_value()) {
		logging_invariant_failure();
	}
	const auto *owner = ACTIVE_SERVICE.load(std::memory_order_acquire);
	if (owner != nullptr) {
		return owner->state_->enabled(level, *index);
	}
	// Finite commands keep native RPC startup chatter out of their result
	// diagnostics. Native errors still reach the synchronous checked sink.
	return level >= (component == "grpc" ? log_level::ERROR : log_level::INFO);
}

void submit_log(log_site site, void *context, log_message_builder builder) noexcept
{
	if (!log_enabled(site.level, site.component)) {
		return;
	}
	auto *owner = ACTIVE_SERVICE.load(std::memory_order_acquire);
	if (owner != nullptr) {
		owner->state_->submit(site, context, builder);
		return;
	}
	if (SERVICE_STARTED.load(std::memory_order_acquire)) {
		logging_invariant_failure();
	}
	submit_command_log(site, context, builder);
}

void submit_foreign_log(log_site site, void *context, log_message_builder builder) noexcept
{
	if (reject_packet_thread_log()) {
		return;
	}
	if (!valid_log_level(site.level) || !log_component_index(site.component).has_value()) {
		logging_invariant_failure();
	}
	if (site.level < log_level::ERROR) {
		submit_log(site, context, builder);
		return;
	}
	auto *owner = ACTIVE_SERVICE.load(std::memory_order_acquire);
	if (owner != nullptr) {
		owner->state_->submit_foreign_error(site, context, builder);
		return;
	}
	if (SERVICE_STARTED.load(std::memory_order_acquire)) {
		logging_invariant_failure();
	}
	// Finite tools have no file writer; their existing synchronous stderr
	// contract applies without an asynchronous delivery claim.
	submit_command_log(site, context, builder);
}

void log_text(log_site site, std::string_view message) noexcept
{
	log_lazy(site, [message](std::span<char> output) -> std::size_t {
		const auto size = std::min(output.size(), message.size());
		if (size != 0) {
			std::memcpy(output.data(), message.data(), size);
		}
		return message.size();
	});
}

void reject_log_record() noexcept
{
	if (reject_packet_thread_log()) {
		return;
	}
	auto *owner = ACTIVE_SERVICE.load(std::memory_order_acquire);
	if (owner != nullptr) {
		owner->state_->reject();
	} else {
		COMMAND_FAILED.store(true, std::memory_order_relaxed);
	}
}

bool flush_logs() noexcept
{
	const auto *owner = ACTIVE_SERVICE.load(std::memory_order_acquire);
	if (owner != nullptr) {
		return owner->state_->delivered();
	}
	std::lock_guard lock(COMMAND_MUTEX);
	return !COMMAND_FAILED.load(std::memory_order_relaxed);
}

void offer_fatal_log(log_site site, std::string_view message) noexcept
{
	if (reject_packet_thread_log()) {
		return;
	}
	auto *owner = ACTIVE_SERVICE.load(std::memory_order_acquire);
	if (owner != nullptr) {
		owner->state_->offer_fatal(site, message);
	}
}

}  // namespace kinetum::common
