#pragma once

#include <exception>
#include <string>
#include <string_view>
#include <vector>

namespace pqtls {

/// Project error taxonomy (spec section 26).
///
/// The category is deliberately coarse. It is what gets written into metrics
/// records and what maps onto process exit codes, so it must stay stable across
/// releases; the free-form message carries the detail.
enum class ErrorCategory {
    None = 0,
    Configuration,   ///< Bad config file, bad flag, contradictory options.
    Capability,      ///< The runtime cannot provide something the profile needs.
    Certificate,     ///< Chain, validity dates, hostname, trust anchor.
    TlsPolicy,       ///< Handshake succeeded but violated our own policy.
    Handshake,       ///< The TLS handshake itself failed.
    Network,         ///< DNS, connect, reset, unreachable.
    Protocol,        ///< Application framing or JSON message violation.
    Timeout,         ///< A configured deadline elapsed.
    Internal,        ///< A bug in this project.
};

[[nodiscard]] std::string_view to_string(ErrorCategory category) noexcept;

[[nodiscard]] ErrorCategory error_category_from_string(std::string_view name) noexcept;

/// Process exit codes. Stable and documented so that benchmark orchestration
/// can distinguish "the peer rejected us on policy" from "we could not even
/// parse the config".
enum class ExitCode : int {
    Success = 0,
    ConfigurationError = 2,
    CapabilityError = 3,
    CertificateError = 4,
    TlsPolicyError = 5,
    HandshakeError = 6,
    NetworkError = 7,
    ProtocolError = 8,
    TimeoutError = 9,
    InternalError = 70,
};

[[nodiscard]] ExitCode exit_code_for(ErrorCategory category) noexcept;

/// Base exception for every deliberate failure raised by this project.
///
/// SECURITY: the message is user-facing and may be logged. Implementations must
/// never place key material, session secrets or raw credential bytes in it.
class Error : public std::exception {
  public:
    Error(ErrorCategory category, std::string message);
    Error(ErrorCategory category, std::string message, std::vector<std::string> details);

    [[nodiscard]] const char* what() const noexcept override;
    [[nodiscard]] ErrorCategory category() const noexcept { return category_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }

    /// Additional context lines, typically the translated OpenSSL error stack.
    [[nodiscard]] const std::vector<std::string>& details() const noexcept { return details_; }

    /// Multi-line rendering suitable for a terminal.
    [[nodiscard]] std::string format() const;

  private:
    ErrorCategory category_;
    std::string message_;
    std::vector<std::string> details_;
    std::string what_;
};

#define PQTLS_DEFINE_ERROR(Name, Category)                                     \
    class Name final : public Error {                                          \
      public:                                                                  \
        explicit Name(std::string message)                                     \
            : Error(Category, std::move(message)) {}                           \
        Name(std::string message, std::vector<std::string> details)            \
            : Error(Category, std::move(message), std::move(details)) {}       \
    }

PQTLS_DEFINE_ERROR(ConfigurationError, ErrorCategory::Configuration);
PQTLS_DEFINE_ERROR(CapabilityError, ErrorCategory::Capability);
PQTLS_DEFINE_ERROR(CertificateError, ErrorCategory::Certificate);
PQTLS_DEFINE_ERROR(TlsPolicyError, ErrorCategory::TlsPolicy);
PQTLS_DEFINE_ERROR(HandshakeError, ErrorCategory::Handshake);
PQTLS_DEFINE_ERROR(NetworkError, ErrorCategory::Network);
PQTLS_DEFINE_ERROR(ProtocolError, ErrorCategory::Protocol);
PQTLS_DEFINE_ERROR(TimeoutError, ErrorCategory::Timeout);
PQTLS_DEFINE_ERROR(InternalError, ErrorCategory::Internal);

#undef PQTLS_DEFINE_ERROR

/// Drain the calling thread's OpenSSL error queue into readable strings.
///
/// Always call this immediately after a failing OpenSSL call: the queue is
/// per-thread and any later OpenSSL call may clear or add to it. The queue is
/// left empty afterwards so a subsequent failure cannot inherit stale entries.
[[nodiscard]] std::vector<std::string> drain_openssl_errors();

/// Convenience: build an error of `category` and attach the OpenSSL error queue.
[[nodiscard]] Error openssl_error(ErrorCategory category, std::string message);

}  // namespace pqtls
