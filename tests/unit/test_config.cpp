#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "pqtls/config.hpp"
#include "pqtls/error.hpp"

using namespace pqtls;

namespace {

/// A YAML file that removes itself when the test ends.
class TempYaml {
  public:
    TempYaml(std::string name, std::string_view contents)
        : path_(std::filesystem::temp_directory_path() / std::move(name)) {
        std::ofstream stream(path_);
        stream << contents;
    }

    TempYaml(const TempYaml&) = delete;
    TempYaml& operator=(const TempYaml&) = delete;

    ~TempYaml() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    [[nodiscard]] std::string string() const { return path_.string(); }

  private:
    std::filesystem::path path_;
};

/// RAII guard for PQTLS_ENV so a test cannot leak process state into another.
class EnvGuard {
  public:
    explicit EnvGuard(const char* value) {
        if (const char* previous = std::getenv("PQTLS_ENV")) {
            had_previous_ = true;
            previous_ = previous;
        }
        set(value);
    }

    ~EnvGuard() {
        if (had_previous_) {
            set(previous_.c_str());
        } else {
            unset();
        }
    }

    EnvGuard(const EnvGuard&) = delete;
    EnvGuard& operator=(const EnvGuard&) = delete;

  private:
    static void set(const char* value) {
#if defined(_WIN32)
        _putenv_s("PQTLS_ENV", value);
#else
        ::setenv("PQTLS_ENV", value, 1);
#endif
    }

    static void unset() {
#if defined(_WIN32)
        _putenv_s("PQTLS_ENV", "");
#else
        ::unsetenv("PQTLS_ENV");
#endif
    }

    bool had_previous_ = false;
    std::string previous_;
};

ClientConfig valid_client_config() {
    ClientConfig config;
    config.host = "localhost";
    config.port = 8443;
    config.server_name = "localhost";
    config.common.profile_id = "hybrid-x25519-mlkem768";
    config.common.ca_certificate_file = "certs/classical/ca.crt";
    return config;
}

ServerConfig valid_server_config() {
    ServerConfig config;
    config.listen_address = "127.0.0.1";
    config.port = 8443;
    config.common.profile_id = "hybrid-x25519-mlkem768";
    config.common.certificate_file = "certs/classical/server.crt";
    config.common.private_key_file = "certs/classical/server.key";
    return config;
}

}  // namespace

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------
TEST_CASE("defaults are safe out of the box", "[config][security]") {
    const CommonConfig config;

    // The two development escape hatches must both be off unless asked for.
    CHECK_FALSE(config.insecure_development_mode);
    CHECK(config.keylog_file.empty());

    // A default frame limit prevents an unconfigured deployment from accepting
    // arbitrarily large frames.
    CHECK(config.max_frame_size == framing::kDefaultMaxFrameSize);

    // Non-zero timeouts: a zero timeout would let a stalled peer hold a
    // connection open forever.
    CHECK(config.handshake_timeout_ms > 0);
    CHECK(config.io_timeout_ms > 0);
}

TEST_CASE("the default client profile is the classical baseline", "[config]") {
    // Deliberate: the default must be something that works everywhere. A
    // default of hybrid would fail on an older OpenSSL and invite someone to
    // "fix" it by loosening the policy.
    const ClientConfig config;
    CHECK(config.common.profile_id == "classical-x25519");
}

TEST_CASE("server_name falls back to host", "[config]") {
    ClientConfig config;
    config.host = "example.test";
    config.server_name.clear();
    CHECK(config.effective_server_name() == "example.test");

    config.server_name = "other.test";
    CHECK(config.effective_server_name() == "other.test");
}

// ---------------------------------------------------------------------------
// YAML loading
// ---------------------------------------------------------------------------
TEST_CASE("a client YAML file is loaded", "[config][yaml]") {
    const TempYaml file("pqtls-client-test.yaml", R"(
common:
  profile: hybrid-p256-mlkem768
  ca_certificate: /tmp/ca.crt
  max_frame_size: 2048
  handshake_timeout_ms: 5000
client:
  host: example.test
  port: 9443
  server_name: example.test
  connections: 50
  concurrency: 5
)");

    ClientConfig config;
    std::vector<std::string> warnings;
    ConfigLoader::load_client_yaml(file.string(), config, warnings);

    CHECK(config.common.profile_id == "hybrid-p256-mlkem768");
    CHECK(config.common.ca_certificate_file == "/tmp/ca.crt");
    CHECK(config.common.max_frame_size == 2048);
    CHECK(config.common.handshake_timeout_ms == 5000);
    CHECK(config.host == "example.test");
    CHECK(config.port == 9443);
    CHECK(config.connections == 50);
    CHECK(config.concurrency == 5);
}

TEST_CASE("a server YAML file is loaded", "[config][yaml]") {
    const TempYaml file("pqtls-server-test.yaml", R"(
common:
  profile: hybrid-x25519-mlkem768
  certificate: /tmp/server.crt
  private_key: /tmp/server.key
server:
  listen: 0.0.0.0
  port: 8443
  max_connections: 64
  require_client_certificate: false
)");

    ServerConfig config;
    std::vector<std::string> warnings;
    ConfigLoader::load_server_yaml(file.string(), config, warnings);

    CHECK(config.common.profile_id == "hybrid-x25519-mlkem768");
    CHECK(config.listen_address == "0.0.0.0");
    CHECK(config.port == 8443);
    CHECK(config.max_connections == 64);
}

TEST_CASE("unknown configuration keys produce a warning", "[config][yaml]") {
    // Warned about, not silently swallowed. A user who mistyped a key needs to
    // find out before they draw conclusions from the run.
    const TempYaml file("pqtls-unknown-key.yaml", R"(
common:
  profile: classical-x25519
client:
  host: localhost
  hsot: typo-here
)");

    ClientConfig config;
    std::vector<std::string> warnings;
    ConfigLoader::load_client_yaml(file.string(), config, warnings);

    REQUIRE_FALSE(warnings.empty());
    bool mentions_typo = false;
    for (const auto& warning : warnings) {
        if (warning.find("hsot") != std::string::npos) {
            mentions_typo = true;
        }
    }
    CHECK(mentions_typo);
}

TEST_CASE("a missing configuration file is a configuration error", "[config][yaml]") {
    ClientConfig config;
    std::vector<std::string> warnings;
    CHECK_THROWS_AS(
        ConfigLoader::load_client_yaml("/nonexistent/path/to/config.yaml", config, warnings),
        ConfigurationError);
}

TEST_CASE("malformed YAML is a configuration error", "[config][yaml]") {
    const TempYaml file("pqtls-broken.yaml", "common:\n  profile: [unclosed\n");
    ClientConfig config;
    std::vector<std::string> warnings;
    CHECK_THROWS_AS(ConfigLoader::load_client_yaml(file.string(), config, warnings),
                    ConfigurationError);
}

TEST_CASE("an out-of-range port is rejected", "[config][yaml]") {
    const TempYaml file("pqtls-bad-port.yaml", "client:\n  port: 70000\n");
    ClientConfig config;
    std::vector<std::string> warnings;
    CHECK_THROWS_AS(ConfigLoader::load_client_yaml(file.string(), config, warnings),
                    ConfigurationError);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------
TEST_CASE("a valid client configuration passes validation", "[config][validation]") {
    CHECK_NOTHROW(ConfigLoader::validate(valid_client_config()));
}

TEST_CASE("a client needs a host and a port", "[config][validation]") {
    auto config = valid_client_config();
    config.host.clear();
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);

    config = valid_client_config();
    config.port = 0;
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

TEST_CASE("concurrency cannot exceed the connection count", "[config][validation]") {
    auto config = valid_client_config();
    config.connections = 10;
    config.concurrency = 50;
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

TEST_CASE("--message and --message-file are mutually exclusive", "[config][validation]") {
    auto config = valid_client_config();
    config.message = R"({"type":"ping"})";
    config.message_file = "/tmp/message.json";
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

TEST_CASE("a zero timeout is rejected", "[config][validation][security]") {
    auto config = valid_client_config();
    config.common.handshake_timeout_ms = 0;
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);

    config = valid_client_config();
    config.common.io_timeout_ms = 0;
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

TEST_CASE("a frame size above the absolute ceiling is rejected",
          "[config][validation][security]") {
    auto config = valid_client_config();
    config.common.max_frame_size = framing::kAbsoluteMaxFrameSize + 1;
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);

    config.common.max_frame_size = 0;
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

TEST_CASE("a certificate without a key is rejected, and vice versa",
          "[config][validation]") {
    auto config = valid_client_config();
    config.common.certificate_file = "/tmp/client.crt";
    config.common.private_key_file.clear();
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);

    config = valid_client_config();
    config.common.certificate_file.clear();
    config.common.private_key_file = "/tmp/client.key";
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

TEST_CASE("a server requires a certificate and a key", "[config][validation]") {
    auto config = valid_server_config();
    config.common.certificate_file.clear();
    config.common.private_key_file.clear();
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

TEST_CASE("mutual TLS requires a CA certificate", "[config][validation][security]") {
    // Without a trust anchor the server could not verify client certificates,
    // so requiring one and having no way to check it would be worse than not
    // requiring one at all.
    auto config = valid_server_config();
    config.require_client_certificate = true;
    config.common.ca_certificate_file.clear();
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);

    config.common.ca_certificate_file = "certs/classical/ca.crt";
    CHECK_NOTHROW(ConfigLoader::validate(config));
}

TEST_CASE("hostname verification requires a name to verify against",
          "[config][validation][security]") {
    auto config = valid_client_config();
    config.host.clear();
    config.server_name.clear();
    CHECK_THROWS_AS(ConfigLoader::validate(config), ConfigurationError);
}

// ---------------------------------------------------------------------------
// Production environment policy
// ---------------------------------------------------------------------------
TEST_CASE("PQTLS_ENV=production is detected", "[config][security]") {
    {
        const EnvGuard guard("production");
        CHECK(ConfigLoader::production_environment());
    }
    {
        const EnvGuard guard("development");
        CHECK_FALSE(ConfigLoader::production_environment());
    }
}

TEST_CASE("insecure development mode is refused in production",
          "[config][security]") {
    const EnvGuard guard("production");

    CommonConfig config;
    config.insecure_development_mode = true;
    CHECK_THROWS_AS(ConfigLoader::enforce_insecure_mode_policy(config), ConfigurationError);
}

TEST_CASE("key logging is refused in production", "[config][security]") {
    const EnvGuard guard("production");

    CommonConfig config;
    config.keylog_file = "/tmp/keys.log";
    CHECK_THROWS_AS(ConfigLoader::enforce_insecure_mode_policy(config), ConfigurationError);
}

TEST_CASE("a safe configuration is permitted in production", "[config][security]") {
    const EnvGuard guard("production");

    const CommonConfig config;  // defaults: neither escape hatch enabled
    CHECK_NOTHROW(ConfigLoader::enforce_insecure_mode_policy(config));
}

TEST_CASE("development options are permitted outside production", "[config]") {
    const EnvGuard guard("development");

    CommonConfig config;
    config.insecure_development_mode = true;
    config.keylog_file = "/tmp/keys.log";
    CHECK_NOTHROW(ConfigLoader::enforce_insecure_mode_policy(config));
}

TEST_CASE("output format parsing", "[config]") {
    CHECK(output_format_from_string("human").value() == OutputFormat::Human);
    CHECK(output_format_from_string("json").value() == OutputFormat::Json);
    CHECK_FALSE(output_format_from_string("xml").has_value());
}
