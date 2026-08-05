#include <atomic>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>

#include "pqtls/capabilities.hpp"
#include "pqtls/config.hpp"
#include "pqtls/error.hpp"
#include "pqtls/server.hpp"
#include "pqtls/version.hpp"

#include "../common/cli_support.hpp"

namespace {

/// Set by the signal handler and polled by main.
///
/// Only an atomic flag is touched from the handler; everything else, including
/// the actual shutdown, happens on the main thread where it is safe.
std::atomic<bool> g_shutdown_requested{false};
pqtls::PqTlsServer* g_server = nullptr;

extern "C" void handle_signal(int /*signal*/) {
    g_shutdown_requested.store(true);
    if (g_server != nullptr) {
        g_server->stop();  // stop() is noexcept and only sets atomics.
    }
}

void print_usage() {
    std::puts(R"(pqtls-server - TLS 1.3 research server with selectable key-establishment profiles

USAGE
  pqtls-server serve [options]
  pqtls-server capabilities [--json]
  pqtls-server validate-config --config <file>
  pqtls-server --version
  pqtls-server --help

COMMANDS
  serve             Listen for TLS 1.3 connections and answer framed JSON messages.
  capabilities      Report what this OpenSSL build can actually do, and which
                    project profiles are usable as a result.
  validate-config   Parse and validate a configuration file without listening.

SERVE OPTIONS
  --listen <addr>            Bind address (default 0.0.0.0)
  --port <n>                 Bind port (default 8443; 0 lets the kernel choose)
  --profile <id>             Security profile (default classical-x25519)
  --profiles-file <path>     YAML file extending the built-in profile catalogue
  --certificate <path>       Server certificate chain, PEM (required)
  --private-key <path>       Server private key, PEM (required)
  --ca-certificate <path>    CA bundle used to verify client certificates
  --require-client-cert      Require a client certificate (mutual TLS)
  --metrics <path>           Append one JSONL record per connection
  --experiment-id <id>       Value recorded in the experiment_id metric field
  --max-connections <n>      Worker pool size and accept-queue bound (default 256)
  --backlog <n>              TCP listen backlog (default 128)
  --max-frame-size <bytes>   Maximum accepted application frame (default 1048576)
  --handshake-timeout <ms>   Handshake deadline (default 10000)
  --io-timeout <ms>          Per-read/write deadline (default 30000)
  --max-messages <n>         Messages accepted per connection (default 1024)
  --config <path>            YAML configuration file; flags override it
  --log-level <level>        trace|debug|info|warn|error|off (default info)
  --json                     Machine-readable output on stdout

DEVELOPMENT-ONLY OPTIONS
  --insecure-development-mode  Disable peer verification. Prints a warning and is
                               refused when PQTLS_ENV=production.
  --keylog-file <path>         Write TLS secrets for Wireshark. Same restrictions.

EXIT CODES
  0 success   2 configuration   3 capability   4 certificate   5 tls-policy
  6 handshake 7 network         8 protocol     9 timeout      70 internal)");
}

const std::vector<std::string> kFlags{"json", "help", "version", "insecure-development-mode",
                                      "require-client-cert"};

const std::vector<std::string> kAcceptedOptions{
    "listen",         "port",         "profile",        "profiles-file",
    "certificate",    "private-key",  "ca-certificate", "require-client-cert",
    "metrics",        "experiment-id","max-connections","backlog",
    "max-frame-size", "handshake-timeout", "io-timeout", "max-messages",
    "config",         "log-level",    "json",           "help",
    "version",        "insecure-development-mode",      "keylog-file"};

pqtls::ProfileRegistry load_registry(const std::string& profiles_file) {
    if (profiles_file.empty()) {
        return pqtls::ProfileRegistry::builtin();
    }
    return pqtls::ProfileRegistry::from_yaml_file(profiles_file);
}

pqtls::ServerConfig build_config(const pqtls::cli::Arguments& args) {
    pqtls::ServerConfig config;

    // Precedence: defaults, then the config file, then the command line.
    if (const auto config_file = args.value("config")) {
        std::vector<std::string> warnings;
        pqtls::ConfigLoader::load_server_yaml(*config_file, config, warnings);
        for (const auto& warning : warnings) {
            spdlog::warn("{}", warning);
        }
    }

    args.apply_string("listen", config.listen_address);
    args.apply_integer("port", config.port);
    args.apply_string("profile", config.common.profile_id);
    args.apply_string("profiles-file", config.common.profiles_file);
    args.apply_string("certificate", config.common.certificate_file);
    args.apply_string("private-key", config.common.private_key_file);
    args.apply_string("ca-certificate", config.common.ca_certificate_file);
    args.apply_string("metrics", config.common.metrics_file);
    args.apply_string("experiment-id", config.common.experiment_id);
    args.apply_string("log-level", config.common.log_level);
    args.apply_string("keylog-file", config.common.keylog_file);

    args.apply_bool("require-client-cert", config.require_client_certificate);
    args.apply_bool("insecure-development-mode", config.common.insecure_development_mode);

    args.apply_integer("max-connections", config.max_connections);
    args.apply_integer("backlog", config.backlog);
    args.apply_integer("max-frame-size", config.common.max_frame_size);
    args.apply_integer("handshake-timeout", config.common.handshake_timeout_ms);
    args.apply_integer("io-timeout", config.common.io_timeout_ms);
    args.apply_integer("max-messages", config.max_messages_per_connection);

    if (args.has("json")) {
        config.common.output_format = pqtls::OutputFormat::Json;
    }

    return config;
}

int command_capabilities(const pqtls::cli::Arguments& args) {
    const auto registry = load_registry(args.value("profiles-file").value_or(""));
    const auto capabilities = pqtls::Capabilities::detect(registry);

    if (args.has("json")) {
        std::cout << capabilities.to_json().dump(2) << '\n';
    } else {
        std::cout << capabilities.to_human_readable();
    }
    return static_cast<int>(pqtls::ExitCode::Success);
}

int command_validate_config(const pqtls::cli::Arguments& args) {
    const auto config_file = args.value("config");
    if (!config_file) {
        throw pqtls::ConfigurationError("validate-config requires --config <file>");
    }

    const pqtls::ServerConfig config = build_config(args);
    pqtls::ConfigLoader::validate(config);

    // Validation is not complete until the named profile actually exists and
    // this host can provide it. A config that parses but names an unavailable
    // profile is not a valid config.
    const auto registry = load_registry(config.common.profiles_file);
    const auto& profile = registry.get(config.common.profile_id);

    const auto capabilities = pqtls::Capabilities::detect(registry);
    const auto* availability = capabilities.profile(profile.id());

    if (args.has("json")) {
        nlohmann::json doc;
        doc["config"] = *config_file;
        doc["valid"] = true;
        doc["profile"] = profile.id();
        doc["profile_usable"] = availability != nullptr && availability->usable;
        if (availability != nullptr && !availability->usable) {
            doc["blocking_reason"] = availability->blocking_reason;
        }
        std::cout << doc.dump(2) << '\n';
    } else {
        std::cout << "configuration '" << *config_file << "' is valid\n";
        std::cout << "  profile      : " << profile.id() << "\n";
        std::cout << "  description  : " << profile.description() << "\n";
        std::cout << "  groups       : " << profile.openssl_groups_list() << "\n";
        std::cout << "  cipher suites: " << profile.openssl_ciphersuites_list() << "\n";
        std::cout << "  usable here  : "
                  << (availability != nullptr && availability->usable ? "yes" : "NO") << "\n";
        if (availability != nullptr && !availability->usable) {
            std::cout << "  reason       : " << availability->blocking_reason << "\n";
        }
    }

    if (availability == nullptr || !availability->usable) {
        return static_cast<int>(pqtls::ExitCode::CapabilityError);
    }
    return static_cast<int>(pqtls::ExitCode::Success);
}

int command_serve(const pqtls::cli::Arguments& args) {
    pqtls::ServerConfig config = build_config(args);
    pqtls::ConfigLoader::validate(config);

    if (config.common.insecure_development_mode) {
        pqtls::cli::print_insecure_mode_banner();
    }

    const auto registry = load_registry(config.common.profiles_file);

    // Fail before binding when the requested profile cannot be honoured. A
    // server that starts and then cannot complete a single handshake is worse
    // than one that refuses to start with a clear reason.
    const auto capabilities = pqtls::Capabilities::detect(registry);
    if (const auto* availability = capabilities.profile(config.common.profile_id);
        availability != nullptr && !availability->usable) {
        throw pqtls::CapabilityError(
            "profile '" + config.common.profile_id + "' cannot be used on this host: " +
                availability->blocking_reason,
            {"run 'pqtls-server capabilities' for the full picture"});
    }

    std::shared_ptr<pqtls::MetricsWriter> writer;
    if (!config.common.metrics_file.empty()) {
        writer = std::make_shared<pqtls::MetricsWriter>(config.common.metrics_file);
    }

    pqtls::PqTlsServer server(config, registry);
    server.set_metrics_writer(writer);

    g_server = &server;
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    server.run();
    g_server = nullptr;

    return static_cast<int>(pqtls::ExitCode::Success);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const pqtls::cli::Arguments args = pqtls::cli::parse(argc, argv, kFlags);

        if (args.has("help") || args.command == "help" || args.command.empty()) {
            print_usage();
            return static_cast<int>(args.command.empty() && !args.has("help")
                                        ? pqtls::ExitCode::ConfigurationError
                                        : pqtls::ExitCode::Success);
        }

        if (args.has("version")) {
            std::cout << pqtls::version_banner() << '\n';
            return static_cast<int>(pqtls::ExitCode::Success);
        }

        pqtls::cli::reject_unknown_options(args, kAcceptedOptions);

        std::string log_level = "info";
        args.apply_string("log-level", log_level);
        pqtls::cli::configure_logging(log_level, args.has("json"));

        if (args.command == "capabilities") {
            return command_capabilities(args);
        }
        if (args.command == "validate-config") {
            return command_validate_config(args);
        }
        if (args.command == "serve") {
            return command_serve(args);
        }

        throw pqtls::ConfigurationError("unknown command '" + args.command +
                                        "'. Expected serve, capabilities or validate-config.");

    } catch (const pqtls::Error& e) {
        std::fputs((e.format() + "\n").c_str(), stderr);
        return static_cast<int>(pqtls::exit_code_for(e.category()));
    } catch (const std::exception& e) {
        std::fputs((std::string("error(internal): ") + e.what() + "\n").c_str(), stderr);
        return static_cast<int>(pqtls::ExitCode::InternalError);
    }
}
