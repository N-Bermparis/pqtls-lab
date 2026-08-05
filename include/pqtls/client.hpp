#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pqtls/application_protocol.hpp"
#include "pqtls/config.hpp"
#include "pqtls/metrics.hpp"
#include "pqtls/tls_context.hpp"

namespace pqtls {

/// Result of a single client connection.
struct ClientResult {
    ConnectionMetrics metrics;
    std::vector<Message> responses;
    bool ok = false;
};

/// TLS 1.3 client.
///
/// One instance owns one TlsContext and may be used for many connections,
/// which is what makes the session-resumption and persistent-connection
/// experiments (RQ6) possible without rebuilding policy each time.
class PqTlsClient {
  public:
    /// @throws ConfigurationError / CapabilityError when the profile cannot be
    ///         satisfied on this host.
    PqTlsClient(ClientConfig config, const ProfileRegistry& registry);

    PqTlsClient(const PqTlsClient&) = delete;
    PqTlsClient& operator=(const PqTlsClient&) = delete;
    ~PqTlsClient();

    /// Open one connection, send `messages`, collect the replies, close.
    ///
    /// Never throws: every failure is captured in the returned metrics with an
    /// error category, because a benchmark run must record failures rather than
    /// abort on them (spec section 13).
    [[nodiscard]] ClientResult run_once(const std::vector<Message>& messages);

    /// Convenience wrapper around run_once for a single message.
    [[nodiscard]] ClientResult run_once(const Message& message);

    /// Attach a writer that receives one record per connection.
    void set_metrics_writer(std::shared_ptr<MetricsWriter> writer);

    [[nodiscard]] const SecurityProfile& profile() const noexcept { return context_.profile(); }
    [[nodiscard]] const ClientConfig& config() const noexcept { return config_; }

    /// Discard any cached session so the next connection is a full handshake.
    void clear_cached_session();

  private:
    ClientResult connect_and_exchange(const std::vector<Message>& messages);

    ClientConfig config_;
    TlsContext context_;
    std::shared_ptr<MetricsWriter> metrics_writer_;

    /// Cached session for resumption experiments. Only used when
    /// ClientConfig::reuse_session is set.
    ossl::SslSessionPtr cached_session_;
};

/// Aggregated outcome of a benchmark run. Raw per-connection records are
/// written to the metrics file; this is only the summary printed to a terminal.
struct BenchmarkSummary {
    std::string profile_id;
    std::uint32_t requested_connections = 0;
    std::uint32_t successful = 0;
    std::uint32_t failed = 0;
    std::vector<double> handshake_ms;
    std::vector<double> connection_ms;
    std::vector<std::string> failure_categories;

    [[nodiscard]] nlohmann::json to_json() const;
};

/// Run `config.connections` connections at `config.concurrency`.
///
/// Every connection, successful or not, produces a metrics record. Failures are
/// preserved and counted, never dropped to make a run look clean.
[[nodiscard]] BenchmarkSummary run_benchmark(ClientConfig config, const ProfileRegistry& registry,
                                             const std::shared_ptr<MetricsWriter>& writer);

}  // namespace pqtls
