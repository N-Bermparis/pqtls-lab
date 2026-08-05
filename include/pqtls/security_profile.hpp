#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pqtls {

/// TLS protocol version. TLS 1.3 is the only version this project negotiates;
/// the enum exists so that a configuration asking for anything older can be
/// rejected explicitly rather than by accident.
enum class TlsVersion {
    Tls13,
};

[[nodiscard]] std::string_view to_string(TlsVersion version) noexcept;
[[nodiscard]] std::optional<TlsVersion> tls_version_from_string(std::string_view name) noexcept;

/// The certificate/signature scheme used for endpoint authentication.
///
/// This is NOT the key-establishment mechanism. A profile may use post-quantum
/// key establishment while still authenticating with a classical signature, and
/// that combination must never be described as "post-quantum authentication".
enum class AuthenticationType {
    EcdsaP256,
    EcdsaP384,
    MlDsa65,  ///< Experimental. Requires ML-DSA support in the runtime OpenSSL.
};

[[nodiscard]] std::string_view to_string(AuthenticationType type) noexcept;
[[nodiscard]] std::optional<AuthenticationType> authentication_type_from_string(
    std::string_view name) noexcept;

/// True when the authentication scheme itself resists a cryptographically
/// relevant quantum computer. Used to keep reporting honest.
[[nodiscard]] bool is_post_quantum_authentication(AuthenticationType type) noexcept;

/// True when the named TLS group provides post-quantum key establishment,
/// either hybrid or pure.
[[nodiscard]] bool is_post_quantum_group(std::string_view group) noexcept;

/// True when the named TLS group is a hybrid construction, i.e. combines a
/// classical ECDH share with an ML-KEM share.
[[nodiscard]] bool is_hybrid_group(std::string_view group) noexcept;

/// An immutable TLS policy.
///
/// Construction goes through `SecurityProfile::create`, which validates the
/// whole policy. There is no way to build a partially-validated profile, so any
/// SecurityProfile a TlsContext receives is already known to be internally
/// consistent.
class SecurityProfile {
  public:
    struct Definition {
        std::string id;
        std::string description;
        TlsVersion minimum_version = TlsVersion::Tls13;
        TlsVersion maximum_version = TlsVersion::Tls13;
        std::vector<std::string> groups;
        std::vector<std::string> cipher_suites;
        AuthenticationType authentication = AuthenticationType::EcdsaP256;
        bool require_client_certificate = false;
        bool allow_classical_fallback = false;
        bool experimental = false;
    };

    /// Validate `definition` and produce a profile.
    /// @throws ConfigurationError when the definition is not self-consistent.
    [[nodiscard]] static SecurityProfile create(Definition definition);

    [[nodiscard]] const std::string& id() const noexcept { return def_.id; }
    [[nodiscard]] const std::string& description() const noexcept { return def_.description; }
    [[nodiscard]] TlsVersion minimum_version() const noexcept { return def_.minimum_version; }
    [[nodiscard]] TlsVersion maximum_version() const noexcept { return def_.maximum_version; }
    [[nodiscard]] const std::vector<std::string>& groups() const noexcept { return def_.groups; }

    [[nodiscard]] const std::vector<std::string>& cipher_suites() const noexcept {
        return def_.cipher_suites;
    }

    [[nodiscard]] AuthenticationType authentication() const noexcept { return def_.authentication; }

    [[nodiscard]] bool require_client_certificate() const noexcept {
        return def_.require_client_certificate;
    }

    [[nodiscard]] bool allow_classical_fallback() const noexcept {
        return def_.allow_classical_fallback;
    }

    [[nodiscard]] bool experimental() const noexcept { return def_.experimental; }

    /// Colon-separated group list in the form OpenSSL's
    /// SSL_CTX_set1_groups_list expects, preserving preference order.
    [[nodiscard]] std::string openssl_groups_list() const;

    /// Colon-separated TLS 1.3 ciphersuite list for SSL_CTX_set_ciphersuites.
    [[nodiscard]] std::string openssl_ciphersuites_list() const;

    /// True when at least one configured group offers PQ key establishment.
    [[nodiscard]] bool offers_post_quantum_key_establishment() const noexcept;

    /// Enforcement hook used after every handshake (spec section 9).
    ///
    /// Returns true when `negotiated_group` is permitted by this profile. A
    /// group that is not in the configured list is always a violation; so is a
    /// classical group when the profile forbids classical fallback.
    [[nodiscard]] bool permits_negotiated_group(std::string_view negotiated_group) const noexcept;

    /// Human-readable reason a negotiated group was rejected. Only meaningful
    /// when `permits_negotiated_group` returned false.
    [[nodiscard]] std::string explain_group_rejection(std::string_view negotiated_group) const;

    [[nodiscard]] const Definition& definition() const noexcept { return def_; }

  private:
    explicit SecurityProfile(Definition definition) : def_(std::move(definition)) {}

    Definition def_;
};

/// The built-in profile catalogue (spec section 4).
///
/// These are compiled in so that the binaries are usable without a config file
/// and so that tests have a fixed reference set. config/profiles.yaml mirrors
/// them and may extend or override them.
class ProfileRegistry {
  public:
    /// Registry populated with the built-in profiles.
    [[nodiscard]] static ProfileRegistry builtin();

    /// Load profiles from a YAML file, starting from the built-in set.
    /// @throws ConfigurationError on a malformed or contradictory file.
    [[nodiscard]] static ProfileRegistry from_yaml_file(const std::string& path);

    [[nodiscard]] const SecurityProfile* find(std::string_view id) const noexcept;

    /// @throws ConfigurationError when no profile with that id exists.
    [[nodiscard]] const SecurityProfile& get(std::string_view id) const;

    [[nodiscard]] std::vector<std::string> ids() const;
    [[nodiscard]] const std::vector<SecurityProfile>& all() const noexcept { return profiles_; }

    void add_or_replace(SecurityProfile profile);

  private:
    std::vector<SecurityProfile> profiles_;
};

/// Default TLS 1.3 ciphersuite allowlist (spec section 9).
[[nodiscard]] const std::vector<std::string>& default_cipher_suites();

}  // namespace pqtls
