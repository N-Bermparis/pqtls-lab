#pragma once

#include <chrono>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "pqtls/error.hpp"

namespace pqtls {

/// Schema version of the JSONL metric records. Bump on any breaking change and
/// update schemas/metrics.schema.json together with it.
inline constexpr int kMetricsSchemaVersion = 1;

enum class Role { Client, Server };

[[nodiscard]] std::string_view to_string(Role role) noexcept;

/// One record per connection (spec section 12).
///
/// SECURITY: this structure is serialised to disk. It must never gain a field
/// holding key material, session secrets, or unredacted payload bytes. Byte
/// *counts* are recorded; byte *contents* are not.
struct ConnectionMetrics {
    int schema_version = kMetricsSchemaVersion;
    std::string experiment_id;
    std::string connection_id;
    Role role = Role::Client;

    std::string requested_profile;
    std::string negotiated_profile;
    std::string tls_version;
    std::string negotiated_group;
    std::string cipher_suite;
    std::string authentication;

    double handshake_ms = 0.0;
    double connection_ms = 0.0;

    std::uint64_t application_bytes_sent = 0;
    std::uint64_t application_bytes_received = 0;
    std::optional<std::uint64_t> transport_bytes_sent;
    std::optional<std::uint64_t> transport_bytes_received;

    bool session_reused = false;
    bool success = false;
    ErrorCategory error_category = ErrorCategory::None;
    std::optional<std::string> error_message;

    std::string peer_address;
    std::uint32_t protocol_message_count = 0;

    std::optional<double> process_cpu_user_ms;
    std::optional<double> process_cpu_system_ms;
    std::optional<std::uint64_t> peak_memory_kib;

    std::string timestamp;  ///< ISO-8601 UTC, when the connection started.

    /// True only when the negotiated group actually provides post-quantum key
    /// establishment. Derived, never taken on trust from the requested profile:
    /// requesting a hybrid profile does not prove one was negotiated.
    bool pq_key_establishment = false;
    bool hybrid_key_establishment = false;
    /// Distinct from the two above. A hybrid key exchange with an ECDSA
    /// certificate is *not* post-quantum authentication.
    bool pq_authentication = false;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] std::string to_jsonl_line() const;
};

/// Append-only JSON Lines writer.
///
/// Opens in append mode and never truncates: benchmark results from an earlier
/// run are not the current run's to destroy (spec section 13).
class MetricsWriter {
  public:
    MetricsWriter() = default;

    /// @throws ConfigurationError when the path cannot be opened for appending.
    explicit MetricsWriter(const std::string& path);

    MetricsWriter(const MetricsWriter&) = delete;
    MetricsWriter& operator=(const MetricsWriter&) = delete;
    MetricsWriter(MetricsWriter&&) = delete;
    MetricsWriter& operator=(MetricsWriter&&) = delete;
    ~MetricsWriter();

    [[nodiscard]] bool enabled() const noexcept { return stream_.is_open(); }

    /// Write one record. Thread-safe; flushed immediately so that a crashed or
    /// killed run still leaves the measurements it already took.
    void write(const ConnectionMetrics& metrics);

    void flush();

  private:
    std::mutex mutex_;
    std::ofstream stream_;
};

/// Monotonic stopwatch for handshake and connection timing.
class Stopwatch {
  public:
    Stopwatch() : start_(std::chrono::steady_clock::now()) {}

    void reset() noexcept { start_ = std::chrono::steady_clock::now(); }

    [[nodiscard]] double elapsed_ms() const noexcept {
        const auto delta = std::chrono::steady_clock::now() - start_;
        return std::chrono::duration<double, std::milli>(delta).count();
    }

  private:
    std::chrono::steady_clock::time_point start_;
};

/// Process resource usage sample. Fields are optional because not every
/// platform exposes them; an absent value is reported as null rather than zero,
/// so analysis cannot mistake "not measured" for "measured as nothing".
struct ResourceUsage {
    std::optional<double> cpu_user_ms;
    std::optional<double> cpu_system_ms;
    std::optional<std::uint64_t> peak_memory_kib;

    [[nodiscard]] static ResourceUsage sample();
};

}  // namespace pqtls
