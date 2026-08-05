#include "pqtls/client.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <thread>
#include <utility>

#include <openssl/ssl.h>
#include <spdlog/spdlog.h>

#include "pqtls/capabilities.hpp"
#include "pqtls/error.hpp"
#include "pqtls/transport.hpp"

namespace pqtls {
namespace {

/// Read buffer size. Large enough that a typical response arrives in one read,
/// small enough that a bounded pool of connections cannot exhaust memory.
constexpr std::size_t kReadChunk = 16 * 1024;

void populate_negotiation_fields(ConnectionMetrics& metrics, const SecurityProfile& profile,
                                 const HandshakeOutcome& outcome) {
    metrics.tls_version = outcome.tls_version;
    metrics.negotiated_group = outcome.negotiated_group;
    metrics.cipher_suite = outcome.cipher_suite;
    metrics.session_reused = outcome.session_reused;

    // Authentication is reported from what the peer actually signed with, not
    // from what the profile asked for. Falling back to the profile's nominal
    // type only when the peer signature is unavailable (for example on a
    // resumed session, where no signature is exchanged).
    metrics.authentication = outcome.peer_signature_algorithm.empty()
                                 ? std::string(to_string(profile.authentication()))
                                 : outcome.peer_signature_algorithm;

    // Derived from the negotiated group, never from the requested profile.
    // Asking for a hybrid profile does not prove a hybrid group was agreed.
    metrics.pq_key_establishment = is_post_quantum_group(outcome.negotiated_group);
    metrics.hybrid_key_establishment = is_hybrid_group(outcome.negotiated_group);

    // Post-quantum authentication is a separate question with a separate
    // answer: it depends on the certificate's signature algorithm.
    const std::string& sig = outcome.peer_signature_algorithm;
    metrics.pq_authentication =
        sig.find("mldsa") != std::string::npos || sig.find("ML-DSA") != std::string::npos ||
        sig.find("dilithium") != std::string::npos;
}

}  // namespace

PqTlsClient::PqTlsClient(ClientConfig config, const ProfileRegistry& registry)
    : config_(std::move(config)),
      context_(TlsContext::create_client(registry.get(config_.common.profile_id), config_.common)) {
    ignore_sigpipe();

    if (context_.profile().experimental()) {
        spdlog::warn("profile '{}' is EXPERIMENTAL: {}", context_.profile().id(),
                     context_.profile().description());
    }
}

PqTlsClient::~PqTlsClient() = default;

void PqTlsClient::set_metrics_writer(std::shared_ptr<MetricsWriter> writer) {
    metrics_writer_ = std::move(writer);
}

void PqTlsClient::clear_cached_session() {
    cached_session_.reset();
}

ClientResult PqTlsClient::run_once(const Message& message) {
    return run_once(std::vector<Message>{message});
}

ClientResult PqTlsClient::run_once(const std::vector<Message>& messages) {
    ClientResult result;
    try {
        result = connect_and_exchange(messages);
    } catch (const Error& e) {
        // A benchmark must record failures, not abort on them. Everything that
        // can go wrong is turned into a metrics record with a category.
        result.ok = false;
        result.metrics.success = false;
        result.metrics.error_category = e.category();
        result.metrics.error_message = e.message();
        spdlog::debug("connection failed ({}): {}", to_string(e.category()), e.message());
    } catch (const std::exception& e) {
        result.ok = false;
        result.metrics.success = false;
        result.metrics.error_category = ErrorCategory::Internal;
        result.metrics.error_message = e.what();
        spdlog::error("unexpected exception in the client: {}", e.what());
    }

    // Fields that must be present whether or not the connection succeeded.
    if (result.metrics.connection_id.empty()) {
        result.metrics.connection_id = generate_uuid_v4();
    }
    if (result.metrics.timestamp.empty()) {
        result.metrics.timestamp = iso8601_now();
    }
    result.metrics.role = Role::Client;
    result.metrics.requested_profile = config_.common.profile_id;
    result.metrics.experiment_id = config_.common.experiment_id;

    if (metrics_writer_ && metrics_writer_->enabled()) {
        metrics_writer_->write(result.metrics);
    }

    return result;
}

ClientResult PqTlsClient::connect_and_exchange(const std::vector<Message>& messages) {
    ClientResult result;
    ConnectionMetrics& metrics = result.metrics;

    metrics.connection_id = generate_uuid_v4();
    metrics.timestamp = iso8601_now();
    metrics.role = Role::Client;
    metrics.requested_profile = config_.common.profile_id;
    metrics.experiment_id = config_.common.experiment_id;

    const Stopwatch connection_timer;

    Socket socket = tcp_connect(config_.host, config_.port, config_.common.handshake_timeout_ms);
    metrics.peer_address = socket.peer_address();
    socket.set_timeouts(config_.common.io_timeout_ms, config_.common.io_timeout_ms);

    ossl::SslPtr ssl = context_.new_ssl();

    if (SSL_set_fd(ssl.get(), socket.fd()) != 1) {
        throw openssl_error(ErrorCategory::Internal, "SSL_set_fd failed");
    }

    const std::string& server_name = config_.effective_server_name();

    // SNI. Sent regardless of verification mode so that a virtual-hosted server
    // selects the right certificate.
    if (SSL_set_tlsext_host_name(ssl.get(), server_name.c_str()) != 1) {
        throw openssl_error(ErrorCategory::Configuration,
                            "failed to set the TLS SNI hostname to '" + server_name + "'");
    }

    if (!config_.common.insecure_development_mode) {
        // Hostname verification. SSL_set1_host makes libssl check the peer
        // certificate's subjectAltName during chain verification, so a
        // mismatch fails the handshake instead of being something we have to
        // remember to check afterwards.
        SSL_set_hostflags(ssl.get(), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(ssl.get(), server_name.c_str()) != 1) {
            throw openssl_error(ErrorCategory::Configuration,
                                "failed to enable hostname verification for '" + server_name + "'");
        }
    }

    // Session resumption for RQ6. Only attempted when explicitly requested.
    if (config_.reuse_session && cached_session_) {
        if (SSL_set_session(ssl.get(), cached_session_.get()) != 1) {
            (void)drain_openssl_errors();
            spdlog::debug("cached TLS session was rejected; falling back to a full handshake");
        }
    }

    const Stopwatch handshake_timer;
    const int handshake_result = SSL_connect(ssl.get());
    metrics.handshake_ms = handshake_timer.elapsed_ms();

    if (handshake_result != 1) {
        const int ssl_error = SSL_get_error(ssl.get(), handshake_result);
        auto details = drain_openssl_errors();

        // A verification failure surfaces as SSL_ERROR_SSL. Reporting it as a
        // certificate error rather than a generic handshake error is what makes
        // "unknown CA" and "wrong hostname" distinguishable in the results.
        const long verify_result = SSL_get_verify_result(ssl.get());
        if (verify_result != X509_V_OK) {
            throw CertificateError(
                "TLS handshake failed during certificate verification: " +
                    describe_verify_result(verify_result),
                std::move(details));
        }

        if (ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_ZERO_RETURN) {
            throw NetworkError("TLS handshake failed: the connection was closed by the peer",
                               std::move(details));
        }

        throw HandshakeError(
            "TLS handshake failed against " + config_.host + ":" + std::to_string(config_.port),
            std::move(details));
    }

    const HandshakeOutcome outcome = TlsContext::inspect(ssl.get());
    populate_negotiation_fields(metrics, context_.profile(), outcome);
    metrics.negotiated_profile = context_.profile().id();

    // --- Post-handshake policy enforcement, in this order -------------------
    //
    // Certificate verification first: an unauthenticated peer's claims about
    // the negotiated group are not worth checking.
    TlsContext::enforce_peer_verification(ssl.get(), config_.common,
                                          /*require_peer_certificate=*/true);

    // Then the downgrade check. Throws if the negotiated group violates the
    // profile, before any application data is sent.
    TlsContext::enforce_group_policy(context_.profile(), outcome);

    spdlog::debug("handshake complete: {} group={} cipher={} auth={} resumed={}",
                  outcome.tls_version, outcome.negotiated_group, outcome.cipher_suite,
                  metrics.authentication, outcome.session_reused);

    if (config_.reuse_session) {
        if (SSL_SESSION* session = SSL_get1_session(ssl.get()); session != nullptr) {
            cached_session_.reset(session);
        }
    }

    // --- Application exchange ----------------------------------------------
    IoCounters counters;
    framing::Decoder decoder(config_.common.max_frame_size);

    for (const auto& message : messages) {
        const std::string payload = message.serialize();
        const auto frame = framing::encode(payload, config_.common.max_frame_size);
        ssl_write_all(ssl.get(), frame.data(), frame.size(), counters, config_.common.io_timeout_ms);
        metrics.protocol_message_count += 1;

        if (message.type == MessageType::Close) {
            break;  // No response expected.
        }

        // Read until a complete frame is assembled. One SSL_read is not one
        // message: the response may be split across reads or share a read with
        // the next one.
        std::optional<std::string> response_text;
        std::array<unsigned char, kReadChunk> buffer{};
        while (!(response_text = decoder.next_frame()).has_value()) {
            const std::size_t read = ssl_read_some(ssl.get(), buffer.data(), buffer.size(),
                                                   counters, config_.common.io_timeout_ms);
            if (read == 0) {
                throw ProtocolError(
                    "the server closed the connection before a complete response frame arrived");
            }
            decoder.feed(std::span<const std::uint8_t>(buffer.data(), read));
        }

        result.responses.push_back(Message::parse(*response_text));
        metrics.protocol_message_count += 1;
    }

    ssl_graceful_shutdown(ssl.get());

    metrics.application_bytes_sent = counters.bytes_sent;
    metrics.application_bytes_received = counters.bytes_received;
    metrics.connection_ms = connection_timer.elapsed_ms();

    const ResourceUsage usage = ResourceUsage::sample();
    metrics.process_cpu_user_ms = usage.cpu_user_ms;
    metrics.process_cpu_system_ms = usage.cpu_system_ms;
    metrics.peak_memory_kib = usage.peak_memory_kib;

    metrics.success = true;
    metrics.error_category = ErrorCategory::None;
    result.ok = true;

    return result;
}

// ---------------------------------------------------------------------------
// Benchmarking
// ---------------------------------------------------------------------------

nlohmann::json BenchmarkSummary::to_json() const {
    nlohmann::json doc;
    doc["profile"] = profile_id;
    doc["requested_connections"] = requested_connections;
    doc["successful"] = successful;
    doc["failed"] = failed;
    doc["success_rate"] =
        requested_connections == 0
            ? 0.0
            : static_cast<double>(successful) / static_cast<double>(requested_connections);
    doc["handshake_ms_samples"] = handshake_ms.size();
    doc["connection_ms_samples"] = connection_ms.size();
    doc["failure_categories"] = failure_categories;
    // Deliberately no derived statistics here. Summary statistics are computed
    // by scripts/analyze-results.py from the raw JSONL, so there is exactly one
    // implementation of the maths and it operates on preserved raw data.
    doc["note"] =
        "Raw per-connection records are in the metrics file. Use scripts/analyze-results.py "
        "for summary statistics.";
    return doc;
}

BenchmarkSummary run_benchmark(ClientConfig config, const ProfileRegistry& registry,
                               const std::shared_ptr<MetricsWriter>& writer) {
    BenchmarkSummary summary;
    summary.profile_id = config.common.profile_id;
    summary.requested_connections = config.connections;

    const std::uint32_t concurrency = std::min(config.concurrency, config.connections);
    std::atomic<std::uint32_t> remaining{config.connections};
    std::atomic<std::uint32_t> warmup_remaining{config.warmup_connections};

    // Claim one unit of work, or report that the pool is empty. A plain
    // fetch_sub would wrap an unsigned counter past zero, so the decrement is
    // conditional.
    const auto claim = [](std::atomic<std::uint32_t>& counter) {
        std::uint32_t current = counter.load(std::memory_order_relaxed);
        while (current > 0) {
            if (counter.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel,
                                              std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    };

    std::mutex summary_mutex;

    const auto worker = [&]() {
        // Each thread owns its own client, and therefore its own SSL_CTX and
        // session cache. Sharing one client across threads would serialise on
        // its session cache and distort the concurrency measurements.
        std::unique_ptr<PqTlsClient> client;
        try {
            client = std::make_unique<PqTlsClient>(config, registry);
        } catch (const std::exception& e) {
            // Setting up a client failed (typically an unavailable profile).
            // Claim the outstanding work so the other threads stop, and record
            // every unrun connection as a failure rather than silently
            // shrinking the sample size.
            const std::uint32_t abandoned = remaining.exchange(0);
            const std::lock_guard<std::mutex> lock(summary_mutex);
            summary.failed += abandoned;
            summary.failure_categories.emplace_back(std::string("client-setup: ") + e.what());
            return;
        }
        client->set_metrics_writer(writer);

        const Message request = Message::make_request(MessageType::Ping);

        // Warm-up connections exercise the code paths and let caches settle;
        // their results are discarded rather than mixed into the measurements.
        while (claim(warmup_remaining)) {
            (void)client->run_once(request);
        }
        client->clear_cached_session();

        while (claim(remaining)) {
            std::vector<Message> messages;
            messages.reserve(config.messages_per_connection);
            for (std::uint32_t i = 0; i < config.messages_per_connection; ++i) {
                messages.push_back(Message::make_request(MessageType::Ping));
            }

            const ClientResult result = client->run_once(messages);

            const std::lock_guard<std::mutex> lock(summary_mutex);
            if (result.ok) {
                summary.successful += 1;
                summary.handshake_ms.push_back(result.metrics.handshake_ms);
                summary.connection_ms.push_back(result.metrics.connection_ms);
            } else {
                summary.failed += 1;
                summary.failure_categories.emplace_back(
                    std::string(to_string(result.metrics.error_category)));
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(concurrency);
    for (std::uint32_t i = 0; i < concurrency; ++i) {
        threads.emplace_back([&worker]() noexcept {
            // No exception may escape a thread entry point (spec section 26).
            try {
                worker();
            } catch (const std::exception& e) {
                spdlog::error("benchmark worker terminated unexpectedly: {}", e.what());
            } catch (...) {
                spdlog::error("benchmark worker terminated with an unknown exception");
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return summary;
}

}  // namespace pqtls
