// Internal command-line helpers shared by the two binaries.
//
// Not part of the public include/pqtls API: this is CLI plumbing, not something
// a consumer of the library should depend on.
#pragma once

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "pqtls/error.hpp"

namespace pqtls::cli {

/// Parsed command line: a subcommand plus `--key value` / `--flag` options.
///
/// Unknown options are an error rather than being ignored. A mistyped
/// `--profile` that silently left the default in place would be exactly the
/// kind of silent downgrade this project exists to prevent.
struct Arguments {
    std::string command;
    std::map<std::string, std::string> options;
    std::vector<std::string> positional;

    [[nodiscard]] bool has(std::string_view name) const {
        return options.find(std::string(name)) != options.end();
    }

    [[nodiscard]] std::optional<std::string> value(std::string_view name) const {
        const auto it = options.find(std::string(name));
        if (it == options.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void apply_string(std::string_view name, std::string& target) const {
        if (const auto v = value(name)) {
            target = *v;
        }
    }

    void apply_bool(std::string_view name, bool& target) const {
        if (const auto v = value(name)) {
            if (*v == "true" || *v == "1" || v->empty()) {
                target = true;
            } else if (*v == "false" || *v == "0") {
                target = false;
            } else {
                throw ConfigurationError("--" + std::string(name) +
                                         " expects true or false, got '" + *v + "'");
            }
        }
    }

    template <typename T>
    void apply_integer(std::string_view name, T& target) const {
        const auto v = value(name);
        if (!v) {
            return;
        }
        std::uint64_t parsed = 0;
        const char* begin = v->data();
        const char* end = begin + v->size();
        const auto result = std::from_chars(begin, end, parsed);
        if (result.ec != std::errc{} || result.ptr != end) {
            throw ConfigurationError("--" + std::string(name) +
                                     " expects a non-negative integer, got '" + *v + "'");
        }
        if (parsed > static_cast<std::uint64_t>(std::numeric_limits<T>::max())) {
            throw ConfigurationError("--" + std::string(name) + " value " + *v +
                                     " is out of range");
        }
        target = static_cast<T>(parsed);
    }
};

/// Parse argv.
///
/// Accepts `--name value`, `--name=value` and bare `--flag`. `known_flags`
/// lists the options that take no value, so `--json --profile x` parses the way
/// a reader expects.
inline Arguments parse(int argc, char** argv, const std::vector<std::string>& known_flags) {
    Arguments args;

    const auto is_flag = [&known_flags](const std::string& name) {
        return std::find(known_flags.begin(), known_flags.end(), name) != known_flags.end();
    };

    int index = 1;
    if (index < argc && argv[index] != nullptr && std::string_view(argv[index]).substr(0, 2) != "--") {
        args.command = argv[index];
        ++index;
    }

    for (; index < argc; ++index) {
        std::string token = argv[index];

        if (!token.starts_with("--")) {
            args.positional.push_back(std::move(token));
            continue;
        }

        token.erase(0, 2);

        if (const auto equals = token.find('='); equals != std::string::npos) {
            const std::string name = token.substr(0, equals);
            args.options[name] = token.substr(equals + 1);
            continue;
        }

        if (is_flag(token)) {
            args.options[token] = "true";
            continue;
        }

        if (index + 1 >= argc) {
            throw ConfigurationError("option --" + token + " requires a value");
        }
        args.options[token] = argv[++index];
    }

    return args;
}

/// Reject any option the caller did not declare.
inline void reject_unknown_options(const Arguments& args,
                                   const std::vector<std::string>& accepted) {
    for (const auto& [name, unused] : args.options) {
        (void)unused;
        if (std::find(accepted.begin(), accepted.end(), name) == accepted.end()) {
            throw ConfigurationError(
                "unknown option --" + name +
                ". Run with --help for the accepted options; unknown options are rejected so "
                "that a typo cannot leave a different security policy in effect.");
        }
    }
}

/// Configure spdlog from a level name.
inline void configure_logging(const std::string& level, bool json_output) {
    if (json_output) {
        // Keep stdout clean for machine-readable output; diagnostics go to
        // stderr so a caller can pipe stdout into a JSON parser.
        spdlog::set_default_logger(spdlog::stderr_color_mt("pqtls"));
    }
    spdlog::set_pattern("[%Y-%m-%dT%H:%M:%S.%e%z] [%^%l%$] %v");

    if (level == "trace")       spdlog::set_level(spdlog::level::trace);
    else if (level == "debug")  spdlog::set_level(spdlog::level::debug);
    else if (level == "info")   spdlog::set_level(spdlog::level::info);
    else if (level == "warn")   spdlog::set_level(spdlog::level::warn);
    else if (level == "error")  spdlog::set_level(spdlog::level::err);
    else if (level == "off")    spdlog::set_level(spdlog::level::off);
    else throw ConfigurationError("unknown log level '" + level +
                                  "'; expected trace, debug, info, warn, error or off");
}

/// The banner printed whenever authentication is disabled.
inline void print_insecure_mode_banner() {
    std::fputs(
        "\n"
        "  ############################################################\n"
        "  #  WARNING: INSECURE DEVELOPMENT MODE                       #\n"
        "  #                                                          #\n"
        "  #  Certificate and hostname verification are DISABLED.     #\n"
        "  #  This connection is NOT authenticated and offers NO      #\n"
        "  #  protection against an active man-in-the-middle.         #\n"
        "  #                                                          #\n"
        "  #  Never use this outside local development.               #\n"
        "  ############################################################\n"
        "\n",
        stderr);
}

}  // namespace pqtls::cli
