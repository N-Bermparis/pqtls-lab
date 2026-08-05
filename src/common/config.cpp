#include "pqtls/config.hpp"

#include <cstdlib>
#include <set>
#include <string>

#include <yaml-cpp/yaml.h>

#include "pqtls/error.hpp"

namespace pqtls {
namespace {

void reject_unknown_keys(const YAML::Node& node, const std::set<std::string>& known,
                         const std::string& context, std::vector<std::string>& warnings) {
    if (!node || !node.IsMap()) {
        return;
    }
    for (const auto& entry : node) {
        const auto key = entry.first.as<std::string>();
        if (!known.contains(key)) {
            // Warning rather than a hard error for the *runtime* config: an
            // unknown key here cannot silently weaken a security policy the way
            // an unknown key in a profile definition can, and forward
            // compatibility is worth something. Profiles are stricter.
            warnings.push_back("unknown configuration key '" + key + "' in " + context +
                               " was ignored");
        }
    }
}

template <typename T>
void assign_if_present(const YAML::Node& node, const char* key, T& target) {
    if (node && node[key]) {
        target = node[key].as<T>();
    }
}

void assign_string_if_present(const YAML::Node& node, const char* key, std::string& target) {
    if (node && node[key]) {
        target = node[key].as<std::string>();
    }
}

std::uint16_t parse_port(const YAML::Node& node, const char* key, std::uint16_t fallback) {
    if (!node || !node[key]) {
        return fallback;
    }
    const auto value = node[key].as<int>();
    if (value < 0 || value > 65535) {
        throw ConfigurationError("'" + std::string(key) + "' must be in [0, 65535], got " +
                                 std::to_string(value));
    }
    return static_cast<std::uint16_t>(value);
}

YAML::Node load_yaml(const std::string& path) {
    try {
        return YAML::LoadFile(path);
    } catch (const YAML::BadFile&) {
        throw ConfigurationError("configuration file '" + path + "' could not be opened");
    } catch (const YAML::Exception& e) {
        throw ConfigurationError("configuration file '" + path + "' is not valid YAML: " + e.what());
    }
}

}  // namespace

std::optional<OutputFormat> output_format_from_string(std::string_view name) noexcept {
    if (name == "human") return OutputFormat::Human;
    if (name == "json")  return OutputFormat::Json;
    return std::nullopt;
}

void ConfigLoader::load_common_yaml(const std::string& path, CommonConfig& config,
                                    std::vector<std::string>& warnings) {
    const YAML::Node root = load_yaml(path);
    const YAML::Node node = root["common"] ? root["common"] : root;

    reject_unknown_keys(node,
                        {"profile", "profiles_file", "certificate", "private_key", "ca_certificate",
                         "metrics", "experiment_id", "max_frame_size", "handshake_timeout_ms",
                         "io_timeout_ms", "output_format", "log_level", "insecure_development_mode",
                         "keylog_file",
                         // Keys owned by the client/server sections; present at
                         // the top level in the flat form of the file.
                         "host", "port", "server_name", "message", "message_file", "connections",
                         "concurrency", "warmup_connections", "reuse_session",
                         "messages_per_connection", "benchmark_output", "listen", "listen_address",
                         "max_connections", "backlog", "idle_timeout_ms",
                         "max_messages_per_connection", "require_client_certificate", "client",
                         "server", "common"},
                        "'" + path + "'", warnings);

    assign_string_if_present(node, "profile", config.profile_id);
    assign_string_if_present(node, "profiles_file", config.profiles_file);
    assign_string_if_present(node, "certificate", config.certificate_file);
    assign_string_if_present(node, "private_key", config.private_key_file);
    assign_string_if_present(node, "ca_certificate", config.ca_certificate_file);
    assign_string_if_present(node, "metrics", config.metrics_file);
    assign_string_if_present(node, "experiment_id", config.experiment_id);
    assign_string_if_present(node, "log_level", config.log_level);
    assign_string_if_present(node, "keylog_file", config.keylog_file);

    assign_if_present(node, "max_frame_size", config.max_frame_size);
    assign_if_present(node, "handshake_timeout_ms", config.handshake_timeout_ms);
    assign_if_present(node, "io_timeout_ms", config.io_timeout_ms);
    assign_if_present(node, "insecure_development_mode", config.insecure_development_mode);

    if (node["output_format"]) {
        const auto raw = node["output_format"].as<std::string>();
        const auto parsed = output_format_from_string(raw);
        if (!parsed) {
            throw ConfigurationError("unknown output_format '" + raw + "'; expected human or json");
        }
        config.output_format = *parsed;
    }
}

void ConfigLoader::load_client_yaml(const std::string& path, ClientConfig& config,
                                    std::vector<std::string>& warnings) {
    load_common_yaml(path, config.common, warnings);

    const YAML::Node root = load_yaml(path);
    const YAML::Node node = root["client"] ? root["client"] : root;

    assign_string_if_present(node, "host", config.host);
    assign_string_if_present(node, "server_name", config.server_name);
    assign_string_if_present(node, "message", config.message);
    assign_string_if_present(node, "message_file", config.message_file);
    assign_string_if_present(node, "benchmark_output", config.benchmark_output);

    config.port = parse_port(node, "port", config.port);

    assign_if_present(node, "connections", config.connections);
    assign_if_present(node, "concurrency", config.concurrency);
    assign_if_present(node, "warmup_connections", config.warmup_connections);
    assign_if_present(node, "reuse_session", config.reuse_session);
    assign_if_present(node, "messages_per_connection", config.messages_per_connection);

    if (root["client"]) {
        reject_unknown_keys(root["client"],
                            {"host", "port", "server_name", "message", "message_file",
                             "connections", "concurrency", "warmup_connections", "reuse_session",
                             "messages_per_connection", "benchmark_output"},
                            "the 'client' section of '" + path + "'", warnings);
    }
}

void ConfigLoader::load_server_yaml(const std::string& path, ServerConfig& config,
                                    std::vector<std::string>& warnings) {
    load_common_yaml(path, config.common, warnings);

    const YAML::Node root = load_yaml(path);
    const YAML::Node node = root["server"] ? root["server"] : root;

    if (node["listen"]) {
        config.listen_address = node["listen"].as<std::string>();
    }
    assign_string_if_present(node, "listen_address", config.listen_address);

    config.port = parse_port(node, "port", config.port);

    assign_if_present(node, "max_connections", config.max_connections);
    assign_if_present(node, "backlog", config.backlog);
    assign_if_present(node, "idle_timeout_ms", config.idle_timeout_ms);
    assign_if_present(node, "max_messages_per_connection", config.max_messages_per_connection);
    assign_if_present(node, "require_client_certificate", config.require_client_certificate);

    if (root["server"]) {
        reject_unknown_keys(root["server"],
                            {"listen", "listen_address", "port", "max_connections", "backlog",
                             "idle_timeout_ms", "max_messages_per_connection",
                             "require_client_certificate"},
                            "the 'server' section of '" + path + "'", warnings);
    }
}

namespace {

void validate_common(const CommonConfig& config) {
    if (config.profile_id.empty()) {
        throw ConfigurationError("no security profile was selected");
    }

    if (config.max_frame_size == 0 || config.max_frame_size > framing::kAbsoluteMaxFrameSize) {
        throw ConfigurationError("max_frame_size must be in [1, " +
                                 std::to_string(framing::kAbsoluteMaxFrameSize) + "], got " +
                                 std::to_string(config.max_frame_size));
    }

    if (config.handshake_timeout_ms == 0) {
        throw ConfigurationError(
            "handshake_timeout_ms must be greater than zero; a zero timeout would let a stalled "
            "peer hold the connection open indefinitely");
    }

    if (config.io_timeout_ms == 0) {
        throw ConfigurationError("io_timeout_ms must be greater than zero");
    }

    if (!config.certificate_file.empty() && config.private_key_file.empty()) {
        throw ConfigurationError("a certificate was given without a matching private key");
    }
    if (config.certificate_file.empty() && !config.private_key_file.empty()) {
        throw ConfigurationError("a private key was given without a matching certificate");
    }
}

}  // namespace

void ConfigLoader::validate(const ClientConfig& config) {
    validate_common(config.common);

    if (config.host.empty()) {
        throw ConfigurationError("no host was given");
    }

    if (config.port == 0) {
        throw ConfigurationError("port 0 is not a valid destination for a client");
    }

    if (config.connections == 0) {
        throw ConfigurationError("connections must be at least 1");
    }

    if (config.concurrency == 0) {
        throw ConfigurationError("concurrency must be at least 1");
    }

    if (config.concurrency > config.connections) {
        throw ConfigurationError("concurrency (" + std::to_string(config.concurrency) +
                                 ") cannot exceed the number of connections (" +
                                 std::to_string(config.connections) + ")");
    }

    if (config.messages_per_connection == 0) {
        throw ConfigurationError("messages_per_connection must be at least 1");
    }

    if (!config.message.empty() && !config.message_file.empty()) {
        throw ConfigurationError(
            "--message and --message-file are mutually exclusive; give exactly one");
    }

    // Verification uses the SNI name. Requiring it to be non-empty when
    // verification is on prevents a connection that silently skips the hostname
    // check because there was no name to check against.
    if (!config.common.insecure_development_mode && config.effective_server_name().empty()) {
        throw ConfigurationError(
            "hostname verification is enabled but no server name is available; pass --server-name");
    }

    enforce_insecure_mode_policy(config.common);
}

void ConfigLoader::validate(const ServerConfig& config) {
    validate_common(config.common);

    if (config.common.certificate_file.empty() || config.common.private_key_file.empty()) {
        throw ConfigurationError(
            "a server requires --certificate and --private-key. Generate a development pair with "
            "scripts/generate-classical-certs.sh.");
    }

    if (config.listen_address.empty()) {
        throw ConfigurationError("no listen address was given");
    }

    if (config.max_connections == 0) {
        throw ConfigurationError(
            "max_connections must be at least 1; it bounds the worker pool and the accept queue");
    }

    if (config.max_messages_per_connection == 0) {
        throw ConfigurationError("max_messages_per_connection must be at least 1");
    }

    if (config.require_client_certificate && config.common.ca_certificate_file.empty()) {
        throw ConfigurationError(
            "mutual TLS requires --ca-certificate so that client certificates can be verified");
    }

    enforce_insecure_mode_policy(config.common);
}

bool ConfigLoader::production_environment() {
    const char* env = std::getenv("PQTLS_ENV");
    return env != nullptr && std::string_view(env) == "production";
}

void ConfigLoader::enforce_insecure_mode_policy(const CommonConfig& config) {
    if (!config.insecure_development_mode && config.keylog_file.empty()) {
        return;
    }

    if (production_environment()) {
        // Fail closed. This is the guard that stops a development convenience
        // from reaching an environment someone has declared to be production.
        throw ConfigurationError(
            "PQTLS_ENV=production forbids development-only options. "
            "--insecure-development-mode disables peer authentication and --keylog-file writes "
            "session secrets in the clear; neither is permitted in a production environment.");
    }
}

}  // namespace pqtls
