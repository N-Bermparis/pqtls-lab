#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>

#include "pqtls/capabilities.hpp"
#include "pqtls/client.hpp"
#include "pqtls/config.hpp"
#include "pqtls/error.hpp"
#include "pqtls/version.hpp"

#include "../common/cli_support.hpp"

namespace {

void print_usage() {
    std::puts(R"(pqtls-client - TLS 1.3 research client with selectable key-establishment profiles

USAGE
  pqtls-client connect [options]
  pqtls-client benchmark [options]
  pqtls-client capabilities [--json]
  pqtls-client --version
  pqtls-client --help

COMMANDS
  connect        Open one connection, send a message, print the response.
  benchmark      Open many connections and append one JSONL record per connection.
  capabilities   Report what this OpenSSL build can actually do, and which
                 project profiles are usable as a result.

CONNECTION OPTIONS
  --host <host>              Destination host (default localhost)
  --port <n>                 Destination port (default 8443)
  --server-name <name>       SNI and hostname-verification name (defaults to --host)
  --profile <id>             Security profile (default classical-x25519)
  --profiles-file <path>     YAML file extending the built-in profile catalogue
  --ca-certificate <path>    CA bundle used to verify the server certificate
  --certificate <path>       Client certificate for mutual TLS
  --private-key <path>       Client private key for mutual TLS
  --message <json>           Inline JSON message body
  --message-file <path>      Read the JSON message body from a file
  --metrics <path>           Append one JSONL record per connection
  --experiment-id <id>       Value recorded in the experiment_id metric field
  --max-frame-size <bytes>   Maximum accepted application frame (default 1048576)
  --handshake-timeout <ms>   Handshake deadline (default 10000)
  --io-timeout <ms>          Per-read/write deadline (default 30000)
  --config <path>            YAML configuration file; flags override it
  --log-level <level>        trace|debug|info|warn|error|off (default info)
  --json                     Machine-readable output on stdout

BENCHMARK OPTIONS
  --connections <n>          Total connections to open (default 1)
  --concurrency <n>          Connections in flight at once (default 1)
  --warmup <n>               Discarded warm-up connections (default 0)
  --messages-per-connection <n>  Messages per connection (default 1)
  --reuse-session            Attempt TLS session resumption
  --output <path>            Metrics destination for this run

DEVELOPMENT-ONLY OPTIONS
  --insecure-development-mode  Disable peer verification. Prints a warning and is
                               refused when PQTLS_ENV=production.
  --keylog-file <path>         Write TLS secrets for Wireshark. Same restrictions.

EXIT CODES
  0 success   2 configuration   3 capability   4 certificate   5 tls-policy
  6 handshake 7 network         8 protocol     9 timeout      70 internal)");
}

const std::vector<std::string> kFlags{"json", "help", "version", "insecure-development-mode",
                                      "reuse-session"};

const std::vector<std::string> kAcceptedOptions{
    "host",          "port",           "server-name",   "profile",
    "profiles-file", "ca-certificate", "certificate",   "private-key",
    "message",       "message-file",   "metrics",       "experiment-id",
    "max-frame-size","handshake-timeout", "io-timeout", "config",
    "log-level",     "json",           "help",          "version",
    "insecure-development-mode",       "keylog-file",   "connections",
    "concurrency",   "warmup",         "messages-per-connection",
    "reuse-session", "output"};

pqtls::ProfileRegistry load_registry(const std::string& profiles_file) {
    if (profiles_file.empty()) {
        return pqtls::ProfileRegistry::builtin();
    }
    return pqtls::ProfileRegistry::from_yaml_file(profiles_file);
}

pqtls::ClientConfig build_config(const pqtls::cli::Arguments& args) {
    pqtls::ClientConfig config;

    if (const auto config_file = args.value("config")) {
        std::vector<std::string> warnings;
        pqtls::ConfigLoader::load_client_yaml(*config_file, config, warnings);
        for (const auto& warning : warnings) {
            spdlog::warn("{}", warning);
        }
    }

    args.apply_string("host", config.host);
    args.apply_integer("port", config.port);
    args.apply_string("server-name", config.server_name);
    args.apply_string("profile", config.common.profile_id);
    args.apply_string("profiles-file", config.common.profiles_file);
    args.apply_string("ca-certificate", config.common.ca_certificate_file);
    args.apply_string("certificate", config.common.certificate_file);
    args.apply_string("private-key", config.common.private_key_file);
    args.apply_string("message", config.message);
    args.apply_string("message-file", config.message_file);
    args.apply_string("metrics", config.common.metrics_file);
    args.apply_string("experiment-id", config.common.experiment_id);
    args.apply_string("log-level", config.common.log_level);
    args.apply_string("keylog-file", config.common.keylog_file);
    args.apply_string("output", config.benchmark_output);

    args.apply_bool("insecure-development-mode", config.common.insecure_development_mode);
    args.apply_bool("reuse-session", config.reuse_session);

    args.apply_integer("max-frame-size", config.common.max_frame_size);
    args.apply_integer("handshake-timeout", config.common.handshake_timeout_ms);
    args.apply_integer("io-timeout", config.common.io_timeout_ms);
    args.apply_integer("connections", config.connections);
    args.apply_integer("concurrency", config.concurrency);
    args.apply_integer("warmup", config.warmup_connections);
    args.apply_integer("messages-per-connection", config.messages_per_connection);

    if (args.has("json")) {
        config.common.output_format = pqtls::OutputFormat::Json;
    }

    // --output is benchmark shorthand for the metrics destination.
    if (!config.benchmark_output.empty() && config.common.metrics_file.empty()) {
        config.common.metrics_file = config.benchmark_output;
    }

    return config;
}

/// Build the message to send from --message, --message-file, or the default ping.
pqtls::Message build_message(const pqtls::ClientConfig& config) {
    std::string body = config.message;

    if (!config.message_file.empty()) {
        std::ifstream file(config.message_file, std::ios::binary);
        if (!file) {
            throw pqtls::ConfigurationError("cannot read the message file '" +
                                            config.message_file + "'");
        }
        std::ostringstream buffer;
        buffer << file.rdbuf();
        body = buffer.str();
    }

    if (body.empty()) {
        return pqtls::Message::make_request(pqtls::MessageType::Ping);
    }

    // Accept a convenience form such as {"type":"ping"} by filling in the
    // mandatory envelope fields, then validating the completed document
    // through the same parser the wire path uses. No separate, laxer code path.
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(body);
    } catch (const nlohmann::json::parse_error& e) {
        throw pqtls::ConfigurationError(std::string("--message is not valid JSON: ") + e.what());
    }
    if (!doc.is_object()) {
        throw pqtls::ConfigurationError("--message must be a JSON object");
    }
    if (!doc.contains("protocol_version")) {
        doc["protocol_version"] = pqtls::kProtocolVersion;
    }
    if (!doc.contains("message_id")) {
        doc["message_id"] = pqtls::generate_uuid_v4();
    }
    if (!doc.contains("timestamp")) {
        doc["timestamp"] = pqtls::iso8601_now();
    }

    return pqtls::Message::parse(doc.dump());
}

void print_connection_result(const pqtls::ClientResult& result, const pqtls::ClientConfig& config) {
    if (config.common.output_format == pqtls::OutputFormat::Json) {
        nlohmann::json doc;
        doc["metrics"] = result.metrics.to_json();
        doc["responses"] = nlohmann::json::array();
        for (const auto& response : result.responses) {
            doc["responses"].push_back(response.to_json());
        }
        std::cout << doc.dump(2) << '\n';
        return;
    }

    const auto& metrics = result.metrics;
    std::cout << "connection " << (result.ok ? "succeeded" : "FAILED") << "\n";
    std::cout << "  peer              : " << metrics.peer_address << "\n";
    std::cout << "  requested profile : " << metrics.requested_profile << "\n";
    std::cout << "  TLS version       : " << metrics.tls_version << "\n";
    std::cout << "  negotiated group  : " << metrics.negotiated_group << "\n";
    std::cout << "  cipher suite      : " << metrics.cipher_suite << "\n";
    std::cout << "  authentication    : " << metrics.authentication << "\n";
    std::cout << "  session reused    : " << (metrics.session_reused ? "yes" : "no") << "\n";
    std::cout << "  handshake         : " << metrics.handshake_ms << " ms\n";
    std::cout << "  connection        : " << metrics.connection_ms << " ms\n";
    std::cout << "  bytes sent/recv   : " << metrics.application_bytes_sent << " / "
              << metrics.application_bytes_received << "\n";

    // The three properties are printed separately and labelled precisely.
    std::cout << "  PQ key establishment : " << (metrics.pq_key_establishment ? "yes" : "no");
    if (metrics.pq_key_establishment) {
        std::cout << (metrics.hybrid_key_establishment ? " (hybrid)" : " (pure ML-KEM)");
    }
    std::cout << "\n";
    std::cout << "  PQ authentication    : " << (metrics.pq_authentication ? "yes" : "no") << "\n";

    if (metrics.pq_key_establishment && !metrics.pq_authentication) {
        std::cout << "  note: the key exchange is post-quantum but the server authenticated with a\n"
                     "        classical signature. This connection is not end-to-end quantum-safe.\n";
    }

    if (!result.ok) {
        std::cout << "  error category    : " << pqtls::to_string(metrics.error_category) << "\n";
        if (metrics.error_message) {
            std::cout << "  error             : " << *metrics.error_message << "\n";
        }
    }

    for (const auto& response : result.responses) {
        std::cout << "  response          : " << response.serialize() << "\n";
    }
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

int command_connect(const pqtls::cli::Arguments& args) {
    pqtls::ClientConfig config = build_config(args);
    pqtls::ConfigLoader::validate(config);

    if (config.common.insecure_development_mode) {
        pqtls::cli::print_insecure_mode_banner();
    }

    const auto registry = load_registry(config.common.profiles_file);
    const pqtls::Message message = build_message(config);

    std::shared_ptr<pqtls::MetricsWriter> writer;
    if (!config.common.metrics_file.empty()) {
        writer = std::make_shared<pqtls::MetricsWriter>(config.common.metrics_file);
    }

    pqtls::PqTlsClient client(config, registry);
    client.set_metrics_writer(writer);

    std::vector<pqtls::Message> messages;
    messages.reserve(config.messages_per_connection);
    for (std::uint32_t i = 0; i < config.messages_per_connection; ++i) {
        messages.push_back(message);
    }

    const pqtls::ClientResult result = client.run_once(messages);
    print_connection_result(result, config);

    // A failed connection exits with the category's code, so a script can tell
    // a policy rejection from a network problem without parsing text.
    return static_cast<int>(result.ok ? pqtls::ExitCode::Success
                                      : pqtls::exit_code_for(result.metrics.error_category));
}

int command_benchmark(const pqtls::cli::Arguments& args) {
    pqtls::ClientConfig config = build_config(args);

    if (config.connections < 1) {
        config.connections = 1;
    }
    pqtls::ConfigLoader::validate(config);

    if (config.common.metrics_file.empty()) {
        throw pqtls::ConfigurationError(
            "benchmark requires --output (or --metrics) so that raw per-connection measurements "
            "are preserved. Summary statistics without the underlying data are not reproducible.");
    }

    const auto registry = load_registry(config.common.profiles_file);
    auto writer = std::make_shared<pqtls::MetricsWriter>(config.common.metrics_file);

    spdlog::info("benchmarking profile '{}': {} connections at concurrency {}",
                 config.common.profile_id, config.connections, config.concurrency);

    const pqtls::BenchmarkSummary summary = pqtls::run_benchmark(config, registry, writer);
    writer->flush();

    if (config.common.output_format == pqtls::OutputFormat::Json) {
        std::cout << summary.to_json().dump(2) << '\n';
    } else {
        std::cout << "benchmark complete\n";
        std::cout << "  profile     : " << summary.profile_id << "\n";
        std::cout << "  requested   : " << summary.requested_connections << "\n";
        std::cout << "  successful  : " << summary.successful << "\n";
        std::cout << "  failed      : " << summary.failed << "\n";
        std::cout << "  raw records : " << config.common.metrics_file << "\n";
        std::cout << "\n";
        std::cout << "Summary statistics are computed from the raw records:\n";
        std::cout << "  python3 scripts/analyze-results.py " << config.common.metrics_file << "\n";
    }

    // A run in which every connection failed is a failed run, whatever the
    // records say. Reporting success here would let CI pass on an empty result.
    if (summary.successful == 0) {
        return static_cast<int>(pqtls::ExitCode::HandshakeError);
    }
    return static_cast<int>(pqtls::ExitCode::Success);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const pqtls::cli::Arguments args = pqtls::cli::parse(argc, argv, kFlags);

        if (args.has("version")) {
            std::cout << pqtls::version_banner() << '\n';
            return static_cast<int>(pqtls::ExitCode::Success);
        }

        if (args.has("help") || args.command == "help" || args.command.empty()) {
            print_usage();
            return static_cast<int>(args.command.empty() && !args.has("help")
                                        ? pqtls::ExitCode::ConfigurationError
                                        : pqtls::ExitCode::Success);
        }

        pqtls::cli::reject_unknown_options(args, kAcceptedOptions);

        std::string log_level = "info";
        args.apply_string("log-level", log_level);
        pqtls::cli::configure_logging(log_level, args.has("json"));

        if (args.command == "capabilities") {
            return command_capabilities(args);
        }
        if (args.command == "connect") {
            return command_connect(args);
        }
        if (args.command == "benchmark") {
            return command_benchmark(args);
        }

        throw pqtls::ConfigurationError("unknown command '" + args.command +
                                        "'. Expected connect, benchmark or capabilities.");

    } catch (const pqtls::Error& e) {
        std::fputs((e.format() + "\n").c_str(), stderr);
        return static_cast<int>(pqtls::exit_code_for(e.category()));
    } catch (const std::exception& e) {
        std::fputs((std::string("error(internal): ") + e.what() + "\n").c_str(), stderr);
        return static_cast<int>(pqtls::ExitCode::InternalError);
    }
}
