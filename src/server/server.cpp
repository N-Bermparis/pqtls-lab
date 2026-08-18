#include "pqtls/server.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include <openssl/ssl.h>
#include <spdlog/spdlog.h>

#include "pqtls/application_protocol.hpp"
#include "pqtls/capabilities.hpp"
#include "pqtls/error.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
#else
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#endif

namespace pqtls {
namespace {

constexpr std::size_t kReadChunk = 16 * 1024;

/// How long the acceptor waits for a connection before re-checking the stop
/// flag. Short enough that shutdown feels immediate, long enough that an idle
/// server is not spinning.
constexpr int kAcceptPollMs = 200;

nlohmann::json build_capabilities_payload(const SecurityProfile& profile,
                                          const HandshakeOutcome& outcome) {
    nlohmann::json payload;
    payload["server_profile"] = profile.id();
    payload["tls_version"] = outcome.tls_version;
    payload["negotiated_group"] = outcome.negotiated_group;
    payload["cipher_suite"] = outcome.cipher_suite;
    // Reported separately and named unambiguously so a client cannot read a
    // hybrid key exchange as post-quantum authentication.
    payload["pq_key_establishment"] = is_post_quantum_group(outcome.negotiated_group);
    payload["hybrid_key_establishment"] = is_hybrid_group(outcome.negotiated_group);
    payload["authentication"] = std::string(to_string(profile.authentication()));
    payload["pq_authentication"] = is_post_quantum_authentication(profile.authentication());
    return payload;
}

/// Produce the reply for a validated request, or nullopt for `close`.
std::optional<Message> handle_message(const Message& request, const SecurityProfile& profile,
                                      const HandshakeOutcome& outcome) {
    switch (request.type) {
        case MessageType::Ping: {
            Message reply = Message::make_acknowledgement(request, "accepted");
            reply.type = MessageType::Pong;
            return reply;
        }

        case MessageType::Echo: {
            Message reply = Message::make_acknowledgement(request, "accepted");
            // The payload is echoed exactly as received. It has already passed
            // UTF-8, JSON, depth and size validation, and it is never
            // interpreted as anything other than data.
            reply.payload = request.payload;
            return reply;
        }

        case MessageType::Telemetry:
            return Message::make_acknowledgement(request, "accepted");

        case MessageType::Capabilities: {
            Message reply = Message::make_acknowledgement(request, "accepted");
            reply.payload = build_capabilities_payload(profile, outcome);
            return reply;
        }

        case MessageType::Close:
            return std::nullopt;

        case MessageType::Acknowledgement:
        case MessageType::Pong:
        case MessageType::Error:
            // These are response types. A client sending one is either
            // confused or probing; reject rather than guess.
            return Message::make_error(&request,
                                       "message type '" + std::string(to_string(request.type)) +
                                           "' is a response type and is not accepted from a client");
    }

    return Message::make_error(&request, "unhandled message type");
}

}  // namespace

PqTlsServer::PqTlsServer(ServerConfig config, const ProfileRegistry& registry)
    : config_(std::move(config)),
      context_(TlsContext::create_server(registry.get(config_.common.profile_id), config_.common,
                                         config_.require_client_certificate)) {
    ignore_sigpipe();

    if (context_.profile().experimental()) {
        spdlog::warn("profile '{}' is EXPERIMENTAL: {}", context_.profile().id(),
                     context_.profile().description());
    }
}

PqTlsServer::~PqTlsServer() {
    stop();
    // Wake any worker still blocked on the queue so join() below can complete.
    queue_cv_.notify_all();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void PqTlsServer::set_metrics_writer(std::shared_ptr<MetricsWriter> writer) {
    metrics_writer_ = std::move(writer);
}

void PqTlsServer::stop() noexcept {
    stopping_.store(true);
    running_.store(false);
    queue_cv_.notify_all();
}

void PqTlsServer::run() {
    listener_ = tcp_listen(config_.listen_address, config_.port, config_.backlog);

    // Report the port actually bound. With port 0 the kernel picks one, which
    // is how the integration tests avoid colliding on a fixed port.
    sockaddr_storage bound{};
    socklen_t bound_length = sizeof(bound);
    if (::getsockname(listener_.fd(), reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0) {
        if (bound.ss_family == AF_INET) {
            bound_port_.store(ntohs(reinterpret_cast<const sockaddr_in*>(&bound)->sin_port));
        } else if (bound.ss_family == AF_INET6) {
            bound_port_.store(ntohs(reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port));
        }
    }

    running_.store(true);
    stopping_.store(false);

    const std::uint32_t worker_count = std::max(1U, config_.max_connections);
    workers_.reserve(worker_count);
    for (std::uint32_t i = 0; i < worker_count; ++i) {
        workers_.emplace_back([this]() noexcept {
            // Catch-all: a protocol violation from one client must never take
            // the whole server down (spec section 26).
            try {
                worker_loop();
            } catch (const std::exception& e) {
                spdlog::error("worker thread terminated unexpectedly: {}", e.what());
            } catch (...) {
                spdlog::error("worker thread terminated with an unknown exception");
            }
        });
    }

    spdlog::info("pqtls-server listening on {}:{} with profile '{}' ({} workers)",
                 config_.listen_address, bound_port_.load(), context_.profile().id(), worker_count);
    spdlog::info("permitted TLS groups: {}", context_.profile().openssl_groups_list());

    while (!stopping_.load()) {
#if !defined(_WIN32)
        // Poll before accept so the stop flag is observed within
        // kAcceptPollMs even when no client ever connects.
        pollfd poll_fd{};
        poll_fd.fd = listener_.fd();
        poll_fd.events = POLLIN;
        const int ready = ::poll(&poll_fd, 1, kAcceptPollMs);
        if (ready <= 0) {
            continue;
        }
#else
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(static_cast<SOCKET>(listener_.fd()), &read_set);
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = kAcceptPollMs * 1000;
        if (::select(0, &read_set, nullptr, nullptr, &timeout) <= 0) {
            continue;
        }
#endif

        sockaddr_storage peer{};
        socklen_t peer_length = sizeof(peer);
        const int client_fd =
            ::accept(listener_.fd(), reinterpret_cast<sockaddr*>(&peer), &peer_length);
        if (client_fd < 0) {
            continue;
        }

        Socket client(client_fd);
        PendingConnection pending;
        pending.peer_address = client.peer_address();

        {
            const std::lock_guard<std::mutex> lock(queue_mutex_);
            if (queue_.size() >= config_.max_connections) {
                // Bounded queue. Closing immediately is a deliberate choice:
                // an unbounded queue would let a connection burst grow memory
                // without limit, and a client that is refused quickly can
                // retry, whereas one queued indefinitely just times out.
                connections_rejected_.fetch_add(1);
                spdlog::warn("connection from {} refused: {} connections already queued",
                             pending.peer_address, queue_.size());
                continue;  // `client` closes on scope exit.
            }
            pending.fd = client.release();
            queue_.push_back(std::move(pending));
        }

        connections_accepted_.fetch_add(1);
        queue_cv_.notify_one();
    }

    running_.store(false);
    listener_.close();
    queue_cv_.notify_all();

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();

    // Close anything still queued when the stop arrived.
    const std::lock_guard<std::mutex> lock(queue_mutex_);
    for (auto& pending : queue_) {
        Socket reclaim(pending.fd);
    }
    queue_.clear();

    spdlog::info("pqtls-server stopped after {} accepted and {} refused connections",
                 connections_accepted_.load(), connections_rejected_.load());
}

void PqTlsServer::worker_loop() {
    while (true) {
        PendingConnection pending;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { return stopping_.load() || !queue_.empty(); });

            if (queue_.empty()) {
                if (stopping_.load()) {
                    return;
                }
                continue;  // Spurious wakeup.
            }

            pending = std::move(queue_.front());
            queue_.erase(queue_.begin());
        }

        handle_connection(std::move(pending));
    }
}

void PqTlsServer::handle_connection(PendingConnection pending) {
    Socket socket(pending.fd);

    ConnectionMetrics metrics;
    metrics.connection_id = generate_uuid_v4();
    metrics.timestamp = iso8601_now();
    metrics.role = Role::Server;
    metrics.requested_profile = config_.common.profile_id;
    metrics.negotiated_profile = context_.profile().id();
    metrics.experiment_id = config_.common.experiment_id;
    metrics.peer_address = pending.peer_address;

    const Stopwatch connection_timer;

    try {
        socket.set_timeouts(config_.common.io_timeout_ms, config_.common.io_timeout_ms);
        socket.set_tcp_nodelay(true);

        ossl::SslPtr ssl = context_.new_ssl();
        if (SSL_set_fd(ssl.get(), socket.fd()) != 1) {
            throw openssl_error(ErrorCategory::Internal, "SSL_set_fd failed on an accepted socket");
        }

        const Stopwatch handshake_timer;
        const int handshake_result = SSL_accept(ssl.get());
        metrics.handshake_ms = handshake_timer.elapsed_ms();

        if (handshake_result != 1) {
            auto details = drain_openssl_errors();
            const long verify_result = SSL_get_verify_result(ssl.get());
            if (verify_result != X509_V_OK) {
                throw CertificateError("client certificate verification failed: " +
                                           describe_verify_result(verify_result),
                                       std::move(details));
            }
            throw HandshakeError("TLS handshake with " + pending.peer_address + " failed",
                                 std::move(details));
        }

        const HandshakeOutcome outcome = TlsContext::inspect(ssl.get());
        metrics.tls_version = outcome.tls_version;
        metrics.negotiated_group = outcome.negotiated_group;
        metrics.cipher_suite = outcome.cipher_suite;
        metrics.session_reused = outcome.session_reused;
        metrics.authentication = std::string(to_string(context_.profile().authentication()));
        metrics.pq_key_establishment = is_post_quantum_group(outcome.negotiated_group);
        metrics.hybrid_key_establishment = is_hybrid_group(outcome.negotiated_group);
        metrics.pq_authentication =
            is_post_quantum_authentication(context_.profile().authentication());

        // The server enforces the same downgrade policy as the client. Relying
        // on the client to check would leave a server that quietly serves
        // classical connections under a hybrid profile.
        TlsContext::enforce_group_policy(context_.profile(), outcome);

        const bool want_client_cert =
            config_.require_client_certificate || context_.profile().require_client_certificate();
        TlsContext::enforce_peer_verification(ssl.get(), config_.common, want_client_cert);

        spdlog::info("connection from {}: {} group={} cipher={} resumed={}", pending.peer_address,
                     outcome.tls_version, outcome.negotiated_group, outcome.cipher_suite,
                     outcome.session_reused);

        // --- Application loop ----------------------------------------------
        IoCounters counters;
        framing::Decoder decoder(config_.common.max_frame_size);
        std::array<unsigned char, kReadChunk> buffer{};
        std::uint32_t handled = 0;
        bool closing = false;

        while (!closing && !stopping_.load() && handled < config_.max_messages_per_connection) {
            std::optional<std::string> frame = decoder.next_frame();

            if (!frame.has_value()) {
                const std::size_t read = ssl_read_some(ssl.get(), buffer.data(), buffer.size(),
                                                       counters, config_.common.io_timeout_ms);
                if (read == 0) {
                    break;  // Clean peer shutdown.
                }
                decoder.feed(std::span<const std::uint8_t>(buffer.data(), read));
                continue;
            }

            handled += 1;
            metrics.protocol_message_count += 1;

            std::optional<Message> reply;
            try {
                const Message request = Message::parse(*frame);
                reply = handle_message(request, context_.profile(), outcome);
                if (!reply.has_value()) {
                    closing = true;  // `close` message.
                }
            } catch (const ProtocolError& e) {
                // A malformed message is the client's problem, not a reason to
                // drop the connection without explanation. Reply with a
                // structured error, then close: continuing would let a peer
                // keep feeding us garbage indefinitely.
                spdlog::warn("protocol violation from {}: {}", pending.peer_address, e.message());
                reply = Message::make_error(nullptr, e.message());
                closing = true;
            }

            if (reply.has_value()) {
                const std::string payload = reply->serialize();
                const auto out_frame = framing::encode(payload, config_.common.max_frame_size);
                ssl_write_all(ssl.get(), out_frame.data(), out_frame.size(), counters,
                              config_.common.io_timeout_ms);
                metrics.protocol_message_count += 1;
            }
        }

        if (handled >= config_.max_messages_per_connection) {
            spdlog::info("connection from {} reached the per-connection message limit of {}",
                         pending.peer_address, config_.max_messages_per_connection);
        }

        ssl_graceful_shutdown(ssl.get());

        metrics.application_bytes_sent = counters.bytes_sent;
        metrics.application_bytes_received = counters.bytes_received;
        metrics.success = true;
        metrics.error_category = ErrorCategory::None;

    } catch (const Error& e) {
        metrics.success = false;
        metrics.error_category = e.category();
        metrics.error_message = e.message();
        // Logged at warn, not error: a client failing verification or violating
        // policy is an expected event for a research server, and the server
        // continues serving everyone else.
        spdlog::warn("connection from {} ended with a {} error: {}", pending.peer_address,
                     to_string(e.category()), e.message());
    } catch (const std::exception& e) {
        metrics.success = false;
        metrics.error_category = ErrorCategory::Internal;
        metrics.error_message = e.what();
        spdlog::error("unexpected exception handling {}: {}", pending.peer_address, e.what());
    }

    metrics.connection_ms = connection_timer.elapsed_ms();

    const ResourceUsage usage = ResourceUsage::sample();
    metrics.process_cpu_user_ms = usage.cpu_user_ms;
    metrics.process_cpu_system_ms = usage.cpu_system_ms;
    metrics.peak_memory_kib = usage.peak_memory_kib;

    if (metrics_writer_ && metrics_writer_->enabled()) {
        metrics_writer_->write(metrics);
    }
}

}  // namespace pqtls
