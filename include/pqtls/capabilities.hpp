#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqtls {

class ProfileRegistry;

/// Why a profile cannot be used on this host, if it cannot.
struct ProfileAvailability {
    std::string profile_id;
    bool usable = false;
    bool experimental = false;
    std::vector<std::string> missing_groups;
    std::vector<std::string> missing_cipher_suites;
    std::string blocking_reason;  ///< Empty when `usable` is true.
};

/// A snapshot of what the *running* OpenSSL can actually do.
///
/// Compile-time detection (cmake/OpenSSLFeatures.cmake) is not sufficient: a
/// binary can be shipped to a host whose libssl differs from the one it was
/// built against. Everything here is probed at run time.
struct Capabilities {
    std::string openssl_compile_time_version;
    std::string openssl_runtime_version;
    std::string openssl_runtime_version_number;
    std::vector<std::string> providers;

    bool tls13_available = false;

    std::vector<std::string> tls_groups;
    std::vector<std::string> signature_algorithms;
    std::vector<std::string> cipher_suites;

    bool mlkem_available = false;   ///< PQ *key establishment* primitive.
    bool mldsa_available = false;   ///< PQ *authentication* primitive. Distinct.

    std::vector<ProfileAvailability> profiles;

    /// Detect capabilities and evaluate every profile in `registry`.
    [[nodiscard]] static Capabilities detect(const ProfileRegistry& registry);

    [[nodiscard]] bool has_group(std::string_view group) const noexcept;
    [[nodiscard]] bool has_cipher_suite(std::string_view suite) const noexcept;
    [[nodiscard]] const ProfileAvailability* profile(std::string_view id) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] std::string to_human_readable() const;
};

/// Ask libssl directly whether it recognises `group`.
///
/// Implemented by asking a throwaway SSL_CTX to accept the name, which is the
/// same code path a real connection would take. This is the check that stops us
/// from claiming a group exists because its name appears in a table.
[[nodiscard]] bool openssl_supports_group(const std::string& group);

/// Ask libcrypto whether an algorithm can be instantiated by name, e.g.
/// "ML-KEM-768" or "ML-DSA-65".
[[nodiscard]] bool openssl_supports_algorithm(const std::string& algorithm);

}  // namespace pqtls
