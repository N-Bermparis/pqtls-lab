#include "pqtls/transport.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <utility>

#include <openssl/err.h>

#include "pqtls/error.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
#else
#include <arpa/inet.h>
#include <csignal>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace pqtls {
namespace {

#if defined(_WIN32)
void close_fd(int fd) noexcept {
    ::closesocket(static_cast<SOCKET>(fd));
}

std::string last_socket_error() {
    return "winsock error " + std::to_string(WSAGetLastError());
}

/// Winsock needs explicit process-wide initialisation, unlike POSIX sockets.
struct WinsockInit {
    WinsockInit() {
        WSADATA data{};
        WSAStartup(MAKEWORD(2, 2), &data);
    }
    ~WinsockInit() { WSACleanup(); }
};
const WinsockInit g_winsock_init;
#else
void close_fd(int fd) noexcept {
    ::close(fd);
}

std::string last_socket_error() {
    return std::strerror(errno);
}
#endif

}  // namespace

Socket::Socket(Socket&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

Socket::~Socket() {
    close();
}

int Socket::release() noexcept {
    const int fd = fd_;
    fd_ = -1;
    return fd;
}

void Socket::close() noexcept {
    if (fd_ >= 0) {
        close_fd(fd_);
        fd_ = -1;
    }
}

void Socket::set_timeouts(std::uint32_t recv_timeout_ms, std::uint32_t send_timeout_ms) const {
    if (fd_ < 0) {
        return;
    }

#if defined(_WIN32)
    const DWORD recv_ms = recv_timeout_ms;
    const DWORD send_ms = send_timeout_ms;
    const auto* recv_ptr = reinterpret_cast<const char*>(&recv_ms);
    const auto* send_ptr = reinterpret_cast<const char*>(&send_ms);
    const int recv_len = sizeof(recv_ms);
    const int send_len = sizeof(send_ms);
#else
    timeval recv_tv{};
    recv_tv.tv_sec = static_cast<time_t>(recv_timeout_ms / 1000);
    recv_tv.tv_usec = static_cast<suseconds_t>((recv_timeout_ms % 1000) * 1000);
    timeval send_tv{};
    send_tv.tv_sec = static_cast<time_t>(send_timeout_ms / 1000);
    send_tv.tv_usec = static_cast<suseconds_t>((send_timeout_ms % 1000) * 1000);
    const auto* recv_ptr = reinterpret_cast<const char*>(&recv_tv);
    const auto* send_ptr = reinterpret_cast<const char*>(&send_tv);
    const socklen_t recv_len = sizeof(recv_tv);
    const socklen_t send_len = sizeof(send_tv);
#endif

    if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, recv_ptr, recv_len) != 0) {
        throw NetworkError("failed to set the receive timeout: " + last_socket_error());
    }
    if (::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, send_ptr, send_len) != 0) {
        throw NetworkError("failed to set the send timeout: " + last_socket_error());
    }
}

void Socket::set_tcp_nodelay(bool enable) const {
    if (fd_ < 0) {
        return;
    }
    const int flag = enable ? 1 : 0;
    // Best effort: Nagle's algorithm affects latency measurements but its
    // absence is not a correctness problem, so a failure here is not fatal.
    (void)::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag),
                       sizeof(flag));
}

std::string Socket::peer_address() const {
    if (fd_ < 0) {
        return "unknown";
    }

    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    if (::getpeername(fd_, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        return "unknown";
    }

    std::array<char, INET6_ADDRSTRLEN> host{};
    std::uint16_t port = 0;

    if (address.ss_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&address);
        ::inet_ntop(AF_INET, &v4->sin_addr, host.data(), host.size());
        port = ntohs(v4->sin_port);
    } else if (address.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&address);
        ::inet_ntop(AF_INET6, &v6->sin6_addr, host.data(), host.size());
        port = ntohs(v6->sin6_port);
        return std::string("[") + host.data() + "]:" + std::to_string(port);
    } else {
        return "unknown";
    }

    return std::string(host.data()) + ":" + std::to_string(port);
}

Socket tcp_connect(const std::string& host, std::uint16_t port, std::uint32_t timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;  // Accept both IPv4 and IPv6.
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* results = nullptr;
    const std::string port_text = std::to_string(port);
    const int rc = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &results);
    if (rc != 0 || results == nullptr) {
        throw NetworkError("cannot resolve '" + host + "': " + ::gai_strerror(rc));
    }

    // RAII for the addrinfo list so an early throw below cannot leak it.
    struct AddrInfoGuard {
        addrinfo* list;
        ~AddrInfoGuard() { ::freeaddrinfo(list); }
    } guard{results};

    std::string last_error = "no addresses were returned";

    // Try every address in turn. A host with both AAAA and A records still
    // connects when only one family is actually routable.
    for (const addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
        const int fd =
            ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (fd < 0) {
            last_error = last_socket_error();
            continue;
        }

        Socket socket(fd);
        try {
            // The blocking connect() below is bounded by SO_SNDTIMEO on the
            // platforms we target. Setting it before connecting is what makes
            // an unreachable host fail in bounded time rather than hanging.
            socket.set_timeouts(timeout_ms, timeout_ms);
        } catch (const Error&) {
            last_error = "could not apply a connect timeout";
            continue;
        }

        if (::connect(fd, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen)) == 0) {
            socket.set_tcp_nodelay(true);
            return socket;
        }

        last_error = last_socket_error();
    }

    throw NetworkError("cannot connect to " + host + ":" + port_text + ": " + last_error);
}

Socket tcp_listen(const std::string& address, std::uint16_t port, std::uint32_t backlog) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    addrinfo* results = nullptr;
    const std::string port_text = std::to_string(port);
    const int rc = ::getaddrinfo(address.c_str(), port_text.c_str(), &hints, &results);
    if (rc != 0 || results == nullptr) {
        throw NetworkError("cannot resolve the listen address '" + address +
                           "': " + ::gai_strerror(rc));
    }

    struct AddrInfoGuard {
        addrinfo* list;
        ~AddrInfoGuard() { ::freeaddrinfo(list); }
    } guard{results};

    std::string last_error = "no addresses were returned";

    for (const addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
        const int fd =
            ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (fd < 0) {
            last_error = last_socket_error();
            continue;
        }

        Socket socket(fd);

        const int reuse = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                           sizeof(reuse));

#if defined(IPV6_V6ONLY)
        if (candidate->ai_family == AF_INET6) {
            // Dual-stack behaviour differs between platforms. Pinning it to
            // v6-only keeps the bound address unambiguous, which matters when
            // an experiment records which interface it ran over.
            const int v6only = 1;
            (void)::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                               reinterpret_cast<const char*>(&v6only), sizeof(v6only));
        }
#endif

        if (::bind(fd, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen)) != 0) {
            last_error = last_socket_error();
            continue;
        }

        if (::listen(fd, static_cast<int>(backlog)) != 0) {
            last_error = last_socket_error();
            continue;
        }

        return socket;
    }

    throw NetworkError("cannot listen on " + address + ":" + port_text + ": " + last_error);
}

namespace {

/// Translate an SSL_get_error result into a project error.
///
/// SSL_ERROR_SYSCALL with errno EAGAIN/EWOULDBLOCK is how a socket timeout
/// surfaces on a blocking socket with SO_RCVTIMEO set, so it maps to
/// TimeoutError rather than a generic network failure. Getting this wrong makes
/// every stalled connection look like a transport error in the results.
[[noreturn]] void throw_ssl_error(SSL* ssl, int result, const char* operation) {
    const int error = SSL_get_error(ssl, result);
    auto details = drain_openssl_errors();

    switch (error) {
        case SSL_ERROR_ZERO_RETURN:
            throw NetworkError(std::string(operation) + ": the peer closed the TLS connection",
                               std::move(details));
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            throw TimeoutError(std::string(operation) + ": timed out waiting for the peer",
                               std::move(details));
        case SSL_ERROR_SYSCALL: {
#if !defined(_WIN32)
            if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
                || errno == EWOULDBLOCK
#endif
            ) {
                throw TimeoutError(std::string(operation) + ": socket timeout elapsed",
                                   std::move(details));
            }
            if (errno != 0) {
                details.emplace_back(std::string("errno: ") + std::strerror(errno));
            }
#else
            const int wsa = WSAGetLastError();
            if (wsa == WSAETIMEDOUT) {
                throw TimeoutError(std::string(operation) + ": socket timeout elapsed",
                                   std::move(details));
            }
            if (wsa != 0) {
                details.emplace_back("winsock error " + std::to_string(wsa));
            }
#endif
            throw NetworkError(std::string(operation) + ": the transport failed",
                               std::move(details));
        }
        case SSL_ERROR_SSL:
        default:
            throw HandshakeError(std::string(operation) + ": TLS protocol failure",
                                 std::move(details));
    }
}

}  // namespace

void ssl_write_all(SSL* ssl, const void* data, std::size_t length, IoCounters& counters,
                   std::uint32_t /*timeout_ms*/) {
    const auto* cursor = static_cast<const unsigned char*>(data);
    std::size_t remaining = length;

    // SSL_write may write fewer bytes than requested when
    // SSL_MODE_ENABLE_PARTIAL_WRITE is set, so loop rather than assuming one
    // call drains the buffer.
    while (remaining > 0) {
        const int chunk =
            static_cast<int>(remaining > 0x7FFFFFFFU ? 0x7FFFFFFF : remaining);
        const int written = SSL_write(ssl, cursor, chunk);
        if (written <= 0) {
            throw_ssl_error(ssl, written, "SSL_write");
        }
        const auto written_size = static_cast<std::size_t>(written);
        cursor += written_size;
        remaining -= written_size;
        counters.bytes_sent += written_size;
    }
}

std::size_t ssl_read_some(SSL* ssl, void* buffer, std::size_t capacity, IoCounters& counters,
                          std::uint32_t /*timeout_ms*/) {
    if (capacity == 0) {
        return 0;
    }

    const int chunk = static_cast<int>(capacity > 0x7FFFFFFFU ? 0x7FFFFFFF : capacity);
    const int read = SSL_read(ssl, buffer, chunk);
    if (read > 0) {
        const auto read_size = static_cast<std::size_t>(read);
        counters.bytes_received += read_size;
        return read_size;
    }

    // A clean close_notify is a normal end of stream, not an error.
    if (SSL_get_error(ssl, read) == SSL_ERROR_ZERO_RETURN) {
        (void)drain_openssl_errors();
        return 0;
    }

    throw_ssl_error(ssl, read, "SSL_read");
}

void ssl_graceful_shutdown(SSL* ssl) noexcept {
    if (ssl == nullptr) {
        return;
    }

    // First call sends our close_notify. A return of 0 means the peer's
    // close_notify has not arrived yet; one more call gives it a chance without
    // blocking indefinitely. Beyond that the peer is simply gone, which is
    // common in benchmarks and is not worth reporting as a failure.
    const int first = SSL_shutdown(ssl);
    if (first == 0) {
        (void)SSL_shutdown(ssl);
    }
    (void)drain_openssl_errors();
}

void ignore_sigpipe() noexcept {
#if !defined(_WIN32)
    // Without this, writing to a socket the peer has closed terminates the
    // process instead of returning an error we can record.
    (void)std::signal(SIGPIPE, SIG_IGN);
#endif
}

}  // namespace pqtls
