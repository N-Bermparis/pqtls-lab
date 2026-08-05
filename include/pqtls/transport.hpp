#pragma once

#include <cstdint>
#include <string>

#include <openssl/ssl.h>

namespace pqtls {

/// A connected TCP socket.
///
/// Thin RAII wrapper: the point is that no code path can forget to close a
/// descriptor, not to abstract sockets away.
class Socket {
  public:
    Socket() = default;
    explicit Socket(int fd) noexcept : fd_(fd) {}

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    ~Socket();

    [[nodiscard]] int fd() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

    /// Relinquish ownership without closing.
    [[nodiscard]] int release() noexcept;

    void close() noexcept;

    /// Apply SO_RCVTIMEO / SO_SNDTIMEO.
    /// @throws NetworkError when the option cannot be set.
    void set_timeouts(std::uint32_t recv_timeout_ms, std::uint32_t send_timeout_ms) const;

    void set_tcp_nodelay(bool enable) const;

    /// Peer endpoint as "address:port", or "unknown" if it cannot be read.
    [[nodiscard]] std::string peer_address() const;

  private:
    int fd_ = -1;
};

/// Connect to `host`:`port`, honouring `timeout_ms` for the connect itself.
///
/// Tries every address getaddrinfo returns, in order, so a host with both AAAA
/// and A records still connects when only one family is routable.
/// @throws NetworkError when no address could be reached in time.
[[nodiscard]] Socket tcp_connect(const std::string& host, std::uint16_t port,
                                 std::uint32_t timeout_ms);

/// Create a listening socket bound to `address`:`port`.
/// @throws NetworkError on bind or listen failure.
[[nodiscard]] Socket tcp_listen(const std::string& address, std::uint16_t port,
                                std::uint32_t backlog);

/// Byte counters shared by the read/write helpers.
struct IoCounters {
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
};

/// Write the whole buffer, looping over partial writes.
/// @throws NetworkError or TimeoutError.
void ssl_write_all(SSL* ssl, const void* data, std::size_t length, IoCounters& counters,
                   std::uint32_t timeout_ms);

/// Read up to `capacity` bytes. Returns 0 on a clean peer shutdown.
/// @throws NetworkError or TimeoutError.
[[nodiscard]] std::size_t ssl_read_some(SSL* ssl, void* buffer, std::size_t capacity,
                                        IoCounters& counters, std::uint32_t timeout_ms);

/// Perform the TLS closure alert exchange, tolerating a peer that has already
/// gone away. A truncation-attack-resistant shutdown matters for research
/// fidelity: we want to record clean closes as clean.
void ssl_graceful_shutdown(SSL* ssl) noexcept;

/// Ignore SIGPIPE process-wide so that writing to a closed socket surfaces as
/// an error return rather than killing the process. No-op on Windows.
void ignore_sigpipe() noexcept;

}  // namespace pqtls
