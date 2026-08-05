#include "pqtls/error.hpp"

#include <array>
#include <sstream>
#include <utility>

#include <openssl/err.h>

#include "pqtls/version.hpp"

namespace pqtls {

std::string_view to_string(ErrorCategory category) noexcept {
    switch (category) {
        case ErrorCategory::None:          return "none";
        case ErrorCategory::Configuration: return "configuration";
        case ErrorCategory::Capability:    return "capability";
        case ErrorCategory::Certificate:   return "certificate";
        case ErrorCategory::TlsPolicy:     return "tls-policy";
        case ErrorCategory::Handshake:     return "handshake";
        case ErrorCategory::Network:       return "network";
        case ErrorCategory::Protocol:      return "protocol";
        case ErrorCategory::Timeout:       return "timeout";
        case ErrorCategory::Internal:      return "internal";
    }
    return "internal";
}

ErrorCategory error_category_from_string(std::string_view name) noexcept {
    if (name == "none")          return ErrorCategory::None;
    if (name == "configuration") return ErrorCategory::Configuration;
    if (name == "capability")    return ErrorCategory::Capability;
    if (name == "certificate")   return ErrorCategory::Certificate;
    if (name == "tls-policy")    return ErrorCategory::TlsPolicy;
    if (name == "handshake")     return ErrorCategory::Handshake;
    if (name == "network")       return ErrorCategory::Network;
    if (name == "protocol")      return ErrorCategory::Protocol;
    if (name == "timeout")       return ErrorCategory::Timeout;
    return ErrorCategory::Internal;
}

ExitCode exit_code_for(ErrorCategory category) noexcept {
    switch (category) {
        case ErrorCategory::None:          return ExitCode::Success;
        case ErrorCategory::Configuration: return ExitCode::ConfigurationError;
        case ErrorCategory::Capability:    return ExitCode::CapabilityError;
        case ErrorCategory::Certificate:   return ExitCode::CertificateError;
        case ErrorCategory::TlsPolicy:     return ExitCode::TlsPolicyError;
        case ErrorCategory::Handshake:     return ExitCode::HandshakeError;
        case ErrorCategory::Network:       return ExitCode::NetworkError;
        case ErrorCategory::Protocol:      return ExitCode::ProtocolError;
        case ErrorCategory::Timeout:       return ExitCode::TimeoutError;
        case ErrorCategory::Internal:      return ExitCode::InternalError;
    }
    return ExitCode::InternalError;
}

Error::Error(ErrorCategory category, std::string message)
    : Error(category, std::move(message), {}) {}

Error::Error(ErrorCategory category, std::string message, std::vector<std::string> details)
    : category_(category), message_(std::move(message)), details_(std::move(details)) {
    what_.reserve(message_.size() + 16);
    what_.append("[").append(to_string(category_)).append("] ").append(message_);
}

const char* Error::what() const noexcept {
    return what_.c_str();
}

std::string Error::format() const {
    std::ostringstream out;
    out << "error(" << to_string(category_) << "): " << message_;
    for (const auto& detail : details_) {
        out << "\n  - " << detail;
    }
    return out.str();
}

std::vector<std::string> drain_openssl_errors() {
    std::vector<std::string> messages;
    // ERR_get_error pops entries, so the queue is empty when this returns and a
    // later unrelated failure cannot inherit these lines.
    while (const unsigned long code = ERR_get_error()) {
        std::array<char, 256> buffer{};
        ERR_error_string_n(code, buffer.data(), buffer.size());
        messages.emplace_back(buffer.data());
    }
    return messages;
}

Error openssl_error(ErrorCategory category, std::string message) {
    return Error(category, std::move(message), drain_openssl_errors());
}

std::string version_banner() {
    std::ostringstream out;
    out << "pqtls-lab " << build_info::kVersion << " (commit " << build_info::kGitCommit << ", "
        << build_info::kBuildType << ", " << build_info::kCompilerId << " "
        << build_info::kCompilerVersion << ")";
    return out.str();
}

}  // namespace pqtls
