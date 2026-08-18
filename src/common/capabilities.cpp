#include "pqtls/capabilities.hpp"

#include <algorithm>
#include <array>
#include <sstream>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include "pqtls/error.hpp"
#include "pqtls/security_profile.hpp"
#include "pqtls/tls_context.hpp"

namespace pqtls {
namespace {

/// Candidate TLS groups we probe for.
///
/// Deliberately a probe rather than a lookup table. OpenSSL 3.5 does expose an
/// enumeration API, but probing with the same call a real connection would make
/// means the answer reflects what libssl will actually accept on this host,
/// including provider configuration and distribution patches. A name printed
/// here has been proven to work, not merely to exist in a header.
constexpr std::array<const char*, 13> kCandidateGroups{
    "X25519",           "secp256r1",          "secp384r1",     "secp521r1",  "X448",
    "ffdhe2048",        "ffdhe3072",          "MLKEM512",      "MLKEM768",   "MLKEM1024",
    "X25519MLKEM768",   "SecP256r1MLKEM768",  "SecP384r1MLKEM1024",
};

constexpr std::array<const char*, 8> kCandidateSignatureAlgorithms{
    "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512",
    "ed25519",                "rsa_pss_rsae_sha256",    "rsa_pkcs1_sha256",
    "mldsa65",                "mldsa87",
};

constexpr std::array<const char*, 3> kCandidateCipherSuites{
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
};

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto lhs = static_cast<unsigned char>(a[i]);
        const auto rhs = static_cast<unsigned char>(b[i]);
        const auto l = (lhs >= 'A' && lhs <= 'Z') ? static_cast<unsigned char>(lhs + 32) : lhs;
        const auto r = (rhs >= 'A' && rhs <= 'Z') ? static_cast<unsigned char>(rhs + 32) : rhs;
        if (l != r) {
            return false;
        }
    }
    return true;
}

std::string join(const std::vector<std::string>& values, std::string_view separator) {
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            out.append(separator);
        }
        out.append(values[i]);
    }
    return out;
}

bool probe_signature_algorithm(SSL_CTX* ctx, const char* name) {
    const long result = SSL_CTX_set1_sigalgs_list(ctx, name);
    // The probe leaves entries in the error queue on failure; drain them so a
    // later, genuine failure is not reported with someone else's errors.
    if (result != 1) {
        (void)drain_openssl_errors();
        return false;
    }
    return true;
}

bool probe_cipher_suite(SSL_CTX* ctx, const char* name) {
    if (SSL_CTX_set_ciphersuites(ctx, name) != 1) {
        (void)drain_openssl_errors();
        return false;
    }
    return true;
}

}  // namespace

bool openssl_supports_group(const std::string& group) {
    TlsContext::initialize_openssl();

    const ossl::SslCtxPtr ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx) {
        (void)drain_openssl_errors();
        return false;
    }

    // SSL_CTX_set1_groups_list returns 1 only when every name in the list
    // resolves. This is the same call the real connection path uses.
    const bool supported = SSL_CTX_set1_groups_list(ctx.get(), group.c_str()) == 1;
    if (!supported) {
        (void)drain_openssl_errors();
    }
    return supported;
}

bool openssl_supports_algorithm(const std::string& algorithm) {
    TlsContext::initialize_openssl();

    EVP_PKEY_CTX* raw = EVP_PKEY_CTX_new_from_name(nullptr, algorithm.c_str(), nullptr);
    if (raw == nullptr) {
        (void)drain_openssl_errors();
        return false;
    }

    // Fetching the context is not proof the algorithm is usable; ask it to
    // initialise a key generation, which forces the provider to be resolved.
    const bool usable = EVP_PKEY_keygen_init(raw) == 1;
    EVP_PKEY_CTX_free(raw);
    if (!usable) {
        (void)drain_openssl_errors();
    }
    return usable;
}

Capabilities Capabilities::detect(const ProfileRegistry& registry) {
    TlsContext::initialize_openssl();

    Capabilities caps;

    caps.openssl_compile_time_version = OPENSSL_VERSION_TEXT;
    if (const char* runtime = OpenSSL_version(OPENSSL_VERSION); runtime != nullptr) {
        caps.openssl_runtime_version = runtime;
    }
    {
        std::ostringstream number;
        number << "0x" << std::hex << OpenSSL_version_num();
        caps.openssl_runtime_version_number = number.str();
    }

    caps.providers = TlsContext::loaded_providers();

    const ossl::SslCtxPtr probe_ctx(SSL_CTX_new(TLS_client_method()));
    if (!probe_ctx) {
        throw openssl_error(ErrorCategory::Internal,
                            "could not create a probe SSL_CTX for capability detection");
    }

    caps.tls13_available = SSL_CTX_set_min_proto_version(probe_ctx.get(), TLS1_3_VERSION) == 1 &&
                           SSL_CTX_set_max_proto_version(probe_ctx.get(), TLS1_3_VERSION) == 1;
    if (!caps.tls13_available) {
        (void)drain_openssl_errors();
    }

    for (const char* group : kCandidateGroups) {
        if (SSL_CTX_set1_groups_list(probe_ctx.get(), group) == 1) {
            caps.tls_groups.emplace_back(group);
        } else {
            (void)drain_openssl_errors();
        }
    }

    for (const char* sigalg : kCandidateSignatureAlgorithms) {
        if (probe_signature_algorithm(probe_ctx.get(), sigalg)) {
            caps.signature_algorithms.emplace_back(sigalg);
        }
    }

    for (const char* suite : kCandidateCipherSuites) {
        if (probe_cipher_suite(probe_ctx.get(), suite)) {
            caps.cipher_suites.emplace_back(suite);
        }
    }

    // Key establishment and authentication are probed separately and reported
    // separately. Conflating them is the single most common way a project ends
    // up claiming "post-quantum TLS" when only half of it is.
    caps.mlkem_available = openssl_supports_algorithm("ML-KEM-768");
    caps.mldsa_available = openssl_supports_algorithm("ML-DSA-65");

    for (const auto& profile : registry.all()) {
        ProfileAvailability availability;
        availability.profile_id = profile.id();
        availability.experimental = profile.experimental();

        for (const auto& group : profile.groups()) {
            if (!caps.has_group(group)) {
                availability.missing_groups.push_back(group);
            }
        }
        for (const auto& suite : profile.cipher_suites()) {
            if (!caps.has_cipher_suite(suite)) {
                availability.missing_cipher_suites.push_back(suite);
            }
        }

        std::ostringstream reason;
        if (!caps.tls13_available) {
            reason << "TLS 1.3 is not available in this OpenSSL build. ";
        }
        if (!availability.missing_groups.empty()) {
            reason << "missing TLS groups: " << join(availability.missing_groups, ", ") << ". ";
        }
        if (!availability.missing_cipher_suites.empty()) {
            reason << "missing cipher suites: " << join(availability.missing_cipher_suites, ", ")
                   << ". ";
        }
        if (profile.authentication() == AuthenticationType::MlDsa65 && !caps.mldsa_available) {
            reason << "ML-DSA-65 is not available, so this profile's post-quantum authentication "
                      "cannot be used. ";
        }

        availability.blocking_reason = reason.str();
        if (!availability.blocking_reason.empty() && availability.blocking_reason.back() == ' ') {
            availability.blocking_reason.pop_back();
        }
        availability.usable = availability.blocking_reason.empty();

        caps.profiles.push_back(std::move(availability));
    }

    return caps;
}

bool Capabilities::has_group(std::string_view group) const noexcept {
    return std::any_of(tls_groups.begin(), tls_groups.end(),
                       [group](const std::string& known) { return iequals(known, group); });
}

bool Capabilities::has_cipher_suite(std::string_view suite) const noexcept {
    return std::any_of(cipher_suites.begin(), cipher_suites.end(),
                       [suite](const std::string& known) { return known == suite; });
}

const ProfileAvailability* Capabilities::profile(std::string_view id) const noexcept {
    const auto it = std::find_if(profiles.begin(), profiles.end(),
                                 [id](const ProfileAvailability& p) { return p.profile_id == id; });
    return it == profiles.end() ? nullptr : &*it;
}

nlohmann::json Capabilities::to_json() const {
    nlohmann::json doc;
    doc["openssl"]["compile_time_version"] = openssl_compile_time_version;
    doc["openssl"]["runtime_version"] = openssl_runtime_version;
    doc["openssl"]["runtime_version_number"] = openssl_runtime_version_number;
    doc["openssl"]["providers"] = providers;

    doc["tls13_available"] = tls13_available;
    doc["tls_groups"] = tls_groups;
    doc["signature_algorithms"] = signature_algorithms;
    doc["cipher_suites"] = cipher_suites;

    // Named to keep the two properties apart in every consumer of this file.
    doc["post_quantum"]["key_establishment"]["mlkem_available"] = mlkem_available;
    doc["post_quantum"]["authentication"]["mldsa_available"] = mldsa_available;

    nlohmann::json profiles_json = nlohmann::json::array();
    for (const auto& availability : profiles) {
        nlohmann::json entry;
        entry["id"] = availability.profile_id;
        entry["usable"] = availability.usable;
        entry["experimental"] = availability.experimental;
        entry["missing_groups"] = availability.missing_groups;
        entry["missing_cipher_suites"] = availability.missing_cipher_suites;
        if (availability.blocking_reason.empty()) {
            entry["blocking_reason"] = nullptr;
        } else {
            entry["blocking_reason"] = availability.blocking_reason;
        }
        profiles_json.push_back(std::move(entry));
    }
    doc["profiles"] = std::move(profiles_json);

    return doc;
}

std::string Capabilities::to_human_readable() const {
    std::ostringstream out;
    out << "OpenSSL\n";
    out << "  compile-time : " << openssl_compile_time_version << "\n";
    out << "  runtime      : " << openssl_runtime_version << " (" << openssl_runtime_version_number
        << ")\n";
    out << "  providers    : " << (providers.empty() ? "<none>" : join(providers, ", ")) << "\n";
    out << "\n";

    out << "TLS\n";
    out << "  TLS 1.3      : " << (tls13_available ? "available" : "NOT AVAILABLE") << "\n";
    out << "  groups       : " << (tls_groups.empty() ? "<none>" : join(tls_groups, ", ")) << "\n";
    out << "  signatures   : "
        << (signature_algorithms.empty() ? "<none>" : join(signature_algorithms, ", ")) << "\n";
    out << "  cipher suites: " << (cipher_suites.empty() ? "<none>" : join(cipher_suites, ", "))
        << "\n";
    out << "\n";

    out << "Post-quantum primitives\n";
    out << "  ML-KEM  (key establishment) : " << (mlkem_available ? "available" : "not available")
        << "\n";
    out << "  ML-DSA  (authentication)    : " << (mldsa_available ? "available" : "not available")
        << "\n";
    out << "  note: post-quantum key establishment and post-quantum authentication are\n";
    out << "        independent properties. A hybrid key exchange with an ECDSA certificate\n";
    out << "        is not post-quantum authentication.\n";
    out << "\n";

    out << "Profiles\n";
    for (const auto& availability : profiles) {
        out << "  " << (availability.usable ? "[usable]     " : "[unavailable]") << " "
            << availability.profile_id;
        if (availability.experimental) {
            out << "  (EXPERIMENTAL)";
        }
        out << "\n";
        if (!availability.blocking_reason.empty()) {
            out << "      reason: " << availability.blocking_reason << "\n";
        }
    }

    return out.str();
}

}  // namespace pqtls
