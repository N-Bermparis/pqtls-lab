#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pqtls/application_protocol.hpp"
#include "pqtls/security_profile.hpp"

namespace pqtls {

/// How the process reports results to a terminal.
enum class OutputFormat { Human, Json };

[[nodiscard]] std::optional<OutputFormat> output_format_from_string(std::string_view name) noexcept;

/// Settings shared by both binaries.
struct CommonConfig {
    std::string profile_id = "classical-x25519";
    std::string profiles_file;  ///< Optional override of the built-in catalogue.

    std::string certificate_file;
    std::string private_key_file;
    std::string ca_certificate_file;

    std::string metrics_file;
    std::string experiment_id;

    std::uint32_t max_frame_size = framing::kDefaultMaxFrameSize;
    std::uint32_t handshake_timeout_ms = 10'000;
    std::uint32_t io_timeout_ms = 30'000;

    OutputFormat output_format = OutputFormat::Human;
    std::string log_level = "info";

    /// Development-only escape hatch (spec section 9).
    ///
    /// Disables peer verification and hostname checking. Off by default,
    /// requires an explicit flag, prints a banner, and is refused outright when
    /// PQTLS_ENV=production.
    bool insecure_development_mode = false;

    /// Development-only TLS key logging. Same rules as above; additionally the
    /// destination is git-ignored.
    std::string keylog_file;
};

struct ClientConfig {
    CommonConfig common;

    std::string host = "localhost";
    std::uint16_t port = 8443;
    std::string server_name;  ///< SNI + hostname verification. Defaults to host.

    std::string message;       ///< Inline JSON message body.
    std::string message_file;  ///< Alternative source for the message body.

    std::uint32_t connections = 1;
    std::uint32_t concurrency = 1;
    std::uint32_t warmup_connections = 0;
    bool reuse_session = false;
    std::uint32_t messages_per_connection = 1;
    std::string benchmark_output;

    /// Resolved SNI / verification name.
    [[nodiscard]] const std::string& effective_server_name() const noexcept {
        return server_name.empty() ? host : server_name;
    }
};

struct ServerConfig {
    CommonConfig common;

    std::string listen_address = "0.0.0.0";
    std::uint16_t port = 8443;

    std::uint32_t max_connections = 256;      ///< Bounded worker pool size.
    std::uint32_t backlog = 128;
    std::uint32_t idle_timeout_ms = 60'000;
    std::uint32_t max_messages_per_connection = 1024;
    bool require_client_certificate = false;  ///< mTLS. May also come from profile.
};

/// Precedence, lowest to highest: built-in defaults, config file, environment,
/// command line. Documented and unit-tested (tests/unit/test_config.cpp).
class ConfigLoader {
  public:
    /// Parse a YAML file into `config`.
    ///
    /// Unknown keys are collected into `warnings` rather than ignored, so a
    /// typo in a profile name cannot silently leave a weaker policy in effect.
    /// @throws ConfigurationError on malformed YAML or an invalid value.
    static void load_common_yaml(const std::string& path, CommonConfig& config,
                                 std::vector<std::string>& warnings);

    static void load_client_yaml(const std::string& path, ClientConfig& config,
                                 std::vector<std::string>& warnings);

    static void load_server_yaml(const std::string& path, ServerConfig& config,
                                 std::vector<std::string>& warnings);

    /// Enforce cross-field rules that no single field can check on its own.
    /// @throws ConfigurationError when the combination is not permitted.
    static void validate(const ClientConfig& config);
    static void validate(const ServerConfig& config);

    /// True when PQTLS_ENV is set to "production".
    [[nodiscard]] static bool production_environment();

    /// Refuse insecure development options outside development.
    /// @throws ConfigurationError in a production environment.
    static void enforce_insecure_mode_policy(const CommonConfig& config);
};

}  // namespace pqtls
