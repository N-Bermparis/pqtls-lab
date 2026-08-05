#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "pqtls/config.hpp"
#include "pqtls/metrics.hpp"
#include "pqtls/tls_context.hpp"
#include "pqtls/transport.hpp"

namespace pqtls {

/// TLS 1.3 server.
///
/// Concurrency model (documented per spec section 6): a bounded thread pool.
/// The acceptor thread hands accepted sockets to a fixed set of worker threads
/// through a queue capped at `ServerConfig::max_connections`. When the queue is
/// full the connection is closed immediately rather than queued without limit,
/// so a burst of connections cannot grow memory without bound. Each worker
/// handles one connection at a time from accept to close.
///
/// Every worker wraps its body in a catch-all: an exception must never escape a
/// thread entry point (spec section 26), and one client's protocol violation
/// must not take the server down.
class PqTlsServer {
  public:
    PqTlsServer(ServerConfig config, const ProfileRegistry& registry);

    PqTlsServer(const PqTlsServer&) = delete;
    PqTlsServer& operator=(const PqTlsServer&) = delete;
    ~PqTlsServer();

    void set_metrics_writer(std::shared_ptr<MetricsWriter> writer);

    /// Bind, listen and serve until `stop()` is called. Blocks the caller.
    void run();

    /// Ask the server to stop. Safe to call from a signal handler context via
    /// an atomic flag, and safe to call more than once.
    void stop() noexcept;

    [[nodiscard]] bool running() const noexcept { return running_.load(); }

    /// Port actually bound. Differs from the configured port when port 0 was
    /// requested, which the integration tests rely on to avoid port collisions.
    [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_.load(); }

    [[nodiscard]] std::uint64_t connections_accepted() const noexcept {
        return connections_accepted_.load();
    }

    [[nodiscard]] std::uint64_t connections_rejected() const noexcept {
        return connections_rejected_.load();
    }

    [[nodiscard]] const SecurityProfile& profile() const noexcept { return context_.profile(); }

  private:
    struct PendingConnection {
        int fd = -1;
        std::string peer_address;
    };

    void worker_loop();
    void handle_connection(PendingConnection pending);

    ServerConfig config_;
    TlsContext context_;
    std::shared_ptr<MetricsWriter> metrics_writer_;

    Socket listener_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<std::uint16_t> bound_port_{0};
    std::atomic<std::uint64_t> connections_accepted_{0};
    std::atomic<std::uint64_t> connections_rejected_{0};

    std::vector<std::thread> workers_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::vector<PendingConnection> queue_;
};

}  // namespace pqtls
