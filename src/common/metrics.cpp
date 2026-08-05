#include "pqtls/metrics.hpp"

#include <filesystem>
#include <utility>

#include "pqtls/security_profile.hpp"

#if defined(_WIN32)
#include <windows.h>
// psapi.h must follow windows.h.
#include <psapi.h>
#else
#include <sys/resource.h>
#include <sys/time.h>
#endif

namespace pqtls {

std::string_view to_string(Role role) noexcept {
    return role == Role::Client ? "client" : "server";
}

nlohmann::json ConnectionMetrics::to_json() const {
    nlohmann::json doc;
    doc["schema_version"] = schema_version;
    doc["experiment_id"] = experiment_id;
    doc["connection_id"] = connection_id;
    doc["role"] = to_string(role);

    doc["requested_profile"] = requested_profile;
    doc["negotiated_profile"] = negotiated_profile;
    doc["tls_version"] = tls_version;
    doc["negotiated_group"] = negotiated_group;
    doc["cipher_suite"] = cipher_suite;
    doc["authentication"] = authentication;

    doc["handshake_ms"] = handshake_ms;
    doc["connection_ms"] = connection_ms;

    doc["application_bytes_sent"] = application_bytes_sent;
    doc["application_bytes_received"] = application_bytes_received;
    doc["transport_bytes_sent"] =
        transport_bytes_sent.has_value() ? nlohmann::json(*transport_bytes_sent) : nlohmann::json();
    doc["transport_bytes_received"] = transport_bytes_received.has_value()
                                          ? nlohmann::json(*transport_bytes_received)
                                          : nlohmann::json();

    doc["session_reused"] = session_reused;
    doc["success"] = success;
    doc["error_category"] = error_category == ErrorCategory::None
                                ? nlohmann::json()
                                : nlohmann::json(std::string(to_string(error_category)));
    doc["error_message"] =
        error_message.has_value() ? nlohmann::json(*error_message) : nlohmann::json();

    doc["peer_address"] = peer_address;
    doc["protocol_message_count"] = protocol_message_count;

    doc["process_cpu_user_ms"] =
        process_cpu_user_ms.has_value() ? nlohmann::json(*process_cpu_user_ms) : nlohmann::json();
    doc["process_cpu_system_ms"] = process_cpu_system_ms.has_value()
                                       ? nlohmann::json(*process_cpu_system_ms)
                                       : nlohmann::json();
    doc["peak_memory_kib"] =
        peak_memory_kib.has_value() ? nlohmann::json(*peak_memory_kib) : nlohmann::json();

    doc["timestamp"] = timestamp;

    // Three separate booleans, never collapsed into one "post_quantum" flag.
    // Analysis code and readers must not be able to mistake a hybrid key
    // exchange for post-quantum authentication.
    doc["pq_key_establishment"] = pq_key_establishment;
    doc["hybrid_key_establishment"] = hybrid_key_establishment;
    doc["pq_authentication"] = pq_authentication;

    return doc;
}

std::string ConnectionMetrics::to_jsonl_line() const {
    // dump() with no indent: one record must occupy exactly one line for the
    // file to remain valid JSON Lines.
    return to_json().dump();
}

MetricsWriter::MetricsWriter(const std::string& path) {
    if (path.empty()) {
        return;
    }

    const std::filesystem::path file_path(path);
    if (file_path.has_parent_path() && !file_path.parent_path().empty()) {
        std::error_code ec;
        std::filesystem::create_directories(file_path.parent_path(), ec);
        if (ec) {
            throw ConfigurationError("cannot create the directory for the metrics file '" + path +
                                     "': " + ec.message());
        }
    }

    // Append, never truncate. A benchmark run must not destroy the results of
    // an earlier one (spec section 13).
    stream_.open(path, std::ios::app);
    if (!stream_.is_open()) {
        throw ConfigurationError("cannot open the metrics file '" + path + "' for appending");
    }
}

MetricsWriter::~MetricsWriter() {
    // Destructors must not throw; a failure to flush at teardown is reported by
    // the stream state, not by an exception escaping into stack unwinding.
    if (stream_.is_open()) {
        stream_.flush();
        stream_.close();
    }
}

void MetricsWriter::write(const ConnectionMetrics& metrics) {
    if (!stream_.is_open()) {
        return;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    stream_ << metrics.to_jsonl_line() << '\n';
    // Flush per record: a run that is interrupted, killed, or crashes should
    // still leave behind every measurement it had already taken.
    stream_.flush();
}

void MetricsWriter::flush() {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (stream_.is_open()) {
        stream_.flush();
    }
}

ResourceUsage ResourceUsage::sample() {
    ResourceUsage usage;

#if defined(_WIN32)
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user) != 0) {
        const auto to_ms = [](const FILETIME& ft) {
            ULARGE_INTEGER value;
            value.LowPart = ft.dwLowDateTime;
            value.HighPart = ft.dwHighDateTime;
            return static_cast<double>(value.QuadPart) / 10000.0;  // 100 ns units
        };
        usage.cpu_user_ms = to_ms(user);
        usage.cpu_system_ms = to_ms(kernel);
    }

    PROCESS_MEMORY_COUNTERS counters{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)) != 0) {
        usage.peak_memory_kib = static_cast<std::uint64_t>(counters.PeakWorkingSetSize / 1024);
    }
#else
    rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        usage.cpu_user_ms = static_cast<double>(ru.ru_utime.tv_sec) * 1000.0 +
                            static_cast<double>(ru.ru_utime.tv_usec) / 1000.0;
        usage.cpu_system_ms = static_cast<double>(ru.ru_stime.tv_sec) * 1000.0 +
                              static_cast<double>(ru.ru_stime.tv_usec) / 1000.0;
#if defined(__APPLE__)
        // macOS reports ru_maxrss in bytes, Linux in kibibytes. Getting this
        // wrong silently scales every memory figure by 1024.
        usage.peak_memory_kib = static_cast<std::uint64_t>(ru.ru_maxrss) / 1024U;
#else
        usage.peak_memory_kib = static_cast<std::uint64_t>(ru.ru_maxrss);
#endif
    }
#endif

    return usage;
}

}  // namespace pqtls
