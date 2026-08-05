#include "pqtls/security_profile.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <sstream>
#include <utility>

#include <yaml-cpp/yaml.h>

#include "pqtls/error.hpp"

namespace pqtls {
namespace {

/// Groups whose name identifies a hybrid ECDH + ML-KEM construction.
///
/// Kept as an explicit list rather than a substring rule: "MLKEM768" contains
/// no ECDH share and must not be classified as hybrid just because the name
/// contains "MLKEM".
constexpr std::array<std::string_view, 3> kHybridGroups{
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
};

/// Pure ML-KEM groups. Experimental: at the time of writing these are not
/// covered by a finalised TLS specification for use as a standalone group.
constexpr std::array<std::string_view, 3> kPureMlKemGroups{
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
};

/// ASCII case-insensitive comparison.
///
/// This matters more than it looks. OpenSSL's canonical group names are not
/// uniformly capitalised: `openssl list -tls-groups` reports "x25519" and
/// "secp256r1" in lower case but "X25519MLKEM768" in mixed case, and
/// SSL_get0_group_name returns the canonical spelling rather than the one we
/// asked for. Comparing case-sensitively would make the post-handshake policy
/// check reject a perfectly compliant connection, or worse, fail to recognise a
/// group it should have matched.
bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto lhs = static_cast<unsigned char>(a[i]);
        const auto rhs = static_cast<unsigned char>(b[i]);
        const auto lhs_lower = (lhs >= 'A' && lhs <= 'Z') ? static_cast<unsigned char>(lhs + 32) : lhs;
        const auto rhs_lower = (rhs >= 'A' && rhs <= 'Z') ? static_cast<unsigned char>(rhs + 32) : rhs;
        if (lhs_lower != rhs_lower) {
            return false;
        }
    }
    return true;
}

bool contains(const std::vector<std::string>& haystack, std::string_view needle) {
    return std::any_of(haystack.begin(), haystack.end(),
                       [needle](const std::string& candidate) { return iequals(candidate, needle); });
}

std::string join(const std::vector<std::string>& values, char separator) {
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            out.push_back(separator);
        }
        out.append(values[i]);
    }
    return out;
}

}  // namespace

std::string_view to_string(TlsVersion version) noexcept {
    switch (version) {
        case TlsVersion::Tls13: return "TLS1.3";
    }
    return "TLS1.3";
}

std::optional<TlsVersion> tls_version_from_string(std::string_view name) noexcept {
    if (name == "TLS1.3" || name == "TLSv1.3" || name == "1.3") {
        return TlsVersion::Tls13;
    }
    return std::nullopt;
}

std::string_view to_string(AuthenticationType type) noexcept {
    switch (type) {
        case AuthenticationType::EcdsaP256: return "ecdsa-p256";
        case AuthenticationType::EcdsaP384: return "ecdsa-p384";
        case AuthenticationType::MlDsa65:   return "ml-dsa-65";
    }
    return "ecdsa-p256";
}

std::optional<AuthenticationType> authentication_type_from_string(std::string_view name) noexcept {
    if (name == "ecdsa-p256" || name == "ECDSA-P256") return AuthenticationType::EcdsaP256;
    if (name == "ecdsa-p384" || name == "ECDSA-P384") return AuthenticationType::EcdsaP384;
    if (name == "ml-dsa-65" || name == "ML-DSA-65")   return AuthenticationType::MlDsa65;
    return std::nullopt;
}

bool is_post_quantum_authentication(AuthenticationType type) noexcept {
    return type == AuthenticationType::MlDsa65;
}

bool is_hybrid_group(std::string_view group) noexcept {
    return std::any_of(kHybridGroups.begin(), kHybridGroups.end(),
                       [group](std::string_view known) { return iequals(known, group); });
}

bool is_post_quantum_group(std::string_view group) noexcept {
    if (is_hybrid_group(group)) {
        return true;
    }
    return std::any_of(kPureMlKemGroups.begin(), kPureMlKemGroups.end(),
                       [group](std::string_view known) { return iequals(known, group); });
}

const std::vector<std::string>& default_cipher_suites() {
    // Explicit allowlist (spec section 9). Order is a preference, not a policy
    // relaxation: every entry here is an AEAD suite we are willing to use.
    static const std::vector<std::string> suites{
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    };
    return suites;
}

SecurityProfile SecurityProfile::create(Definition definition) {
    if (definition.id.empty()) {
        throw ConfigurationError("security profile is missing an 'id'");
    }

    if (definition.groups.empty()) {
        throw ConfigurationError("profile '" + definition.id +
                                 "' defines no TLS groups; an empty group list would let OpenSSL "
                                 "choose its own defaults, which defeats the purpose of a profile");
    }

    // Duplicate group names would make the negotiated-group policy check
    // ambiguous and usually indicate a copy-paste error in the YAML.
    const std::set<std::string> unique_groups(definition.groups.begin(), definition.groups.end());
    if (unique_groups.size() != definition.groups.size()) {
        throw ConfigurationError("profile '" + definition.id + "' lists a TLS group more than once");
    }

    if (definition.cipher_suites.empty()) {
        definition.cipher_suites = default_cipher_suites();
    }

    for (const auto& suite : definition.cipher_suites) {
        if (!suite.starts_with("TLS_")) {
            throw ConfigurationError(
                "profile '" + definition.id + "' lists '" + suite +
                "' as a cipher suite. TLS 1.3 cipher suites are named TLS_*; note that TLS groups "
                "(key establishment) and cipher suites (record protection) are different things.");
        }
    }

    for (const auto& group : definition.groups) {
        if (group.starts_with("TLS_")) {
            throw ConfigurationError(
                "profile '" + definition.id + "' lists '" + group +
                "' as a TLS group, but that is a cipher suite name. Groups control key "
                "establishment; cipher suites control record protection.");
        }
    }

    if (definition.minimum_version != TlsVersion::Tls13 ||
        definition.maximum_version != TlsVersion::Tls13) {
        throw ConfigurationError("profile '" + definition.id +
                                 "' requests a TLS version other than 1.3; this project negotiates "
                                 "TLS 1.3 only");
    }

    // A profile that forbids classical fallback but lists only classical groups
    // is contradictory: there is nothing for the policy to protect.
    const bool has_pq = std::any_of(definition.groups.begin(), definition.groups.end(),
                                    [](const std::string& g) { return is_post_quantum_group(g); });
    const bool has_classical =
        std::any_of(definition.groups.begin(), definition.groups.end(),
                    [](const std::string& g) { return !is_post_quantum_group(g); });

    if (has_pq && has_classical && !definition.allow_classical_fallback) {
        throw ConfigurationError(
            "profile '" + definition.id +
            "' offers both post-quantum and classical groups while setting "
            "fallback.allow_classical=false. That combination would advertise a classical group we "
            "would then refuse after the handshake. Either remove the classical groups or set "
            "allow_classical=true and accept the weaker guarantee.");
    }

    // Pure ML-KEM groups have no classical component; using one is an
    // experiment, not a deployment choice.
    const bool has_pure_pq =
        std::any_of(definition.groups.begin(), definition.groups.end(), [](const std::string& g) {
            return is_post_quantum_group(g) && !is_hybrid_group(g);
        });
    if (has_pure_pq && !definition.experimental) {
        throw ConfigurationError(
            "profile '" + definition.id +
            "' uses a pure ML-KEM group but is not marked experimental. Standalone ML-KEM groups "
            "are not covered by a finalised TLS specification; mark the profile experimental to "
            "acknowledge that.");
    }

    if (definition.authentication == AuthenticationType::MlDsa65 && !definition.experimental) {
        throw ConfigurationError(
            "profile '" + definition.id +
            "' requests ML-DSA authentication but is not marked experimental. Post-quantum "
            "certificate authentication is a capability-gated experiment in this project.");
    }

    if (definition.description.empty()) {
        definition.description = definition.id;
    }

    return SecurityProfile(std::move(definition));
}

std::string SecurityProfile::openssl_groups_list() const {
    return join(def_.groups, ':');
}

std::string SecurityProfile::openssl_ciphersuites_list() const {
    return join(def_.cipher_suites, ':');
}

bool SecurityProfile::offers_post_quantum_key_establishment() const noexcept {
    return std::any_of(def_.groups.begin(), def_.groups.end(),
                       [](const std::string& g) { return is_post_quantum_group(g); });
}

bool SecurityProfile::permits_negotiated_group(std::string_view negotiated_group) const noexcept {
    if (negotiated_group.empty()) {
        // We could not determine what was negotiated. Failing closed is the
        // only safe reading: an unverifiable claim is not a verified one.
        return false;
    }

    if (!contains(def_.groups, negotiated_group)) {
        return false;
    }

    if (!def_.allow_classical_fallback && !is_post_quantum_group(negotiated_group) &&
        offers_post_quantum_key_establishment()) {
        return false;
    }

    return true;
}

std::string SecurityProfile::explain_group_rejection(std::string_view negotiated_group) const {
    std::ostringstream out;
    if (negotiated_group.empty()) {
        out << "the negotiated TLS group could not be determined; profile '" << def_.id
            << "' requires one of [" << join(def_.groups, ' ')
            << "] and cannot confirm the connection satisfies its policy";
        return out.str();
    }

    if (!contains(def_.groups, negotiated_group)) {
        out << "negotiated TLS group '" << negotiated_group << "' is not permitted by profile '"
            << def_.id << "', which allows only [" << join(def_.groups, ' ') << "]";
        return out.str();
    }

    out << "negotiated TLS group '" << negotiated_group
        << "' provides classical key establishment only, and profile '" << def_.id
        << "' sets fallback.allow_classical=false";
    return out.str();
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

ProfileRegistry ProfileRegistry::builtin() {
    ProfileRegistry registry;

    const auto add = [&registry](SecurityProfile::Definition def) {
        registry.profiles_.push_back(SecurityProfile::create(std::move(def)));
    };

    add({.id = "classical-x25519",
         .description = "Classical TLS 1.3 baseline using X25519 key establishment",
         .groups = {"X25519"},
         .cipher_suites = default_cipher_suites(),
         .authentication = AuthenticationType::EcdsaP256,
         .allow_classical_fallback = true,
         .experimental = false});

    add({.id = "classical-p256",
         .description = "Classical TLS 1.3 baseline using NIST P-256 key establishment",
         .groups = {"secp256r1"},
         .cipher_suites = default_cipher_suites(),
         .authentication = AuthenticationType::EcdsaP256,
         .allow_classical_fallback = true,
         .experimental = false});

    add({.id = "hybrid-x25519-mlkem768",
         .description = "Primary profile: hybrid X25519 + ML-KEM-768 key establishment, "
                        "ECDSA P-256 authentication",
         .groups = {"X25519MLKEM768"},
         .cipher_suites = default_cipher_suites(),
         .authentication = AuthenticationType::EcdsaP256,
         .allow_classical_fallback = false,
         .experimental = false});

    add({.id = "hybrid-p256-mlkem768",
         .description = "Secondary profile: hybrid NIST P-256 + ML-KEM-768 key establishment",
         .groups = {"SecP256r1MLKEM768"},
         .cipher_suites = default_cipher_suites(),
         .authentication = AuthenticationType::EcdsaP256,
         .allow_classical_fallback = false,
         .experimental = false});

    add({.id = "hybrid-p384-mlkem1024",
         .description = "High-security experiment: hybrid P-384 + ML-KEM-1024, ECDSA P-384",
         .groups = {"SecP384r1MLKEM1024"},
         .cipher_suites = {"TLS_AES_256_GCM_SHA384"},
         .authentication = AuthenticationType::EcdsaP384,
         .allow_classical_fallback = false,
         .experimental = false});

    add({.id = "pure-mlkem768",
         .description = "EXPERIMENTAL: standalone ML-KEM-768 key establishment, no classical "
                        "component. Disabled by default.",
         .groups = {"MLKEM768"},
         .cipher_suites = default_cipher_suites(),
         .authentication = AuthenticationType::EcdsaP256,
         .allow_classical_fallback = false,
         .experimental = true});

    add({.id = "hybrid-pq-auth",
         .description = "EXPERIMENTAL: hybrid X25519 + ML-KEM-768 key establishment with ML-DSA-65 "
                        "authentication. Capability-gated.",
         .groups = {"X25519MLKEM768"},
         .cipher_suites = default_cipher_suites(),
         .authentication = AuthenticationType::MlDsa65,
         .allow_classical_fallback = false,
         .experimental = true});

    return registry;
}

const SecurityProfile* ProfileRegistry::find(std::string_view id) const noexcept {
    const auto it = std::find_if(profiles_.begin(), profiles_.end(),
                                 [id](const SecurityProfile& p) { return p.id() == id; });
    return it == profiles_.end() ? nullptr : &*it;
}

const SecurityProfile& ProfileRegistry::get(std::string_view id) const {
    if (const SecurityProfile* profile = find(id)) {
        return *profile;
    }
    std::ostringstream out;
    out << "unknown security profile '" << id << "'. Available profiles: " << join(ids(), ' ');
    throw ConfigurationError(out.str());
}

std::vector<std::string> ProfileRegistry::ids() const {
    std::vector<std::string> out;
    out.reserve(profiles_.size());
    for (const auto& profile : profiles_) {
        out.push_back(profile.id());
    }
    return out;
}

void ProfileRegistry::add_or_replace(SecurityProfile profile) {
    const auto it = std::find_if(profiles_.begin(), profiles_.end(),
                                 [&profile](const SecurityProfile& p) {
                                     return p.id() == profile.id();
                                 });
    if (it == profiles_.end()) {
        profiles_.push_back(std::move(profile));
    } else {
        *it = std::move(profile);
    }
}

namespace {

/// Reject YAML keys we do not understand instead of ignoring them. A silently
/// ignored key in a security policy is how a profile ends up weaker than the
/// author believed.
void reject_unknown_keys(const YAML::Node& node, const std::set<std::string>& known,
                         const std::string& context) {
    if (!node.IsMap()) {
        return;
    }
    for (const auto& entry : node) {
        const auto key = entry.first.as<std::string>();
        if (!known.contains(key)) {
            throw ConfigurationError("unknown key '" + key + "' in " + context +
                                     ". Remove it or correct the spelling; unknown keys are "
                                     "rejected so that a typo cannot silently weaken a policy.");
        }
    }
}

SecurityProfile parse_profile_node(const YAML::Node& node) {
    reject_unknown_keys(node,
                        {"id", "description", "tls", "groups", "cipher_suites", "authentication",
                         "fallback", "experimental"},
                        "profile definition");

    SecurityProfile::Definition def;

    if (!node["id"]) {
        throw ConfigurationError("profile definition is missing the mandatory 'id' key");
    }
    def.id = node["id"].as<std::string>();

    if (node["description"]) {
        def.description = node["description"].as<std::string>();
    }

    if (const YAML::Node tls = node["tls"]) {
        reject_unknown_keys(tls, {"minimum_version", "maximum_version"},
                            "profile '" + def.id + "' tls section");
        if (tls["minimum_version"]) {
            const auto raw = tls["minimum_version"].as<std::string>();
            const auto parsed = tls_version_from_string(raw);
            if (!parsed) {
                throw ConfigurationError("profile '" + def.id + "': unsupported tls.minimum_version '" +
                                         raw + "'. Only TLS1.3 is supported.");
            }
            def.minimum_version = *parsed;
        }
        if (tls["maximum_version"]) {
            const auto raw = tls["maximum_version"].as<std::string>();
            const auto parsed = tls_version_from_string(raw);
            if (!parsed) {
                throw ConfigurationError("profile '" + def.id + "': unsupported tls.maximum_version '" +
                                         raw + "'. Only TLS1.3 is supported.");
            }
            def.maximum_version = *parsed;
        }
    }

    if (const YAML::Node groups = node["groups"]) {
        if (!groups.IsSequence()) {
            throw ConfigurationError("profile '" + def.id + "': 'groups' must be a list");
        }
        for (const auto& g : groups) {
            def.groups.push_back(g.as<std::string>());
        }
    }

    if (const YAML::Node suites = node["cipher_suites"]) {
        if (!suites.IsSequence()) {
            throw ConfigurationError("profile '" + def.id + "': 'cipher_suites' must be a list");
        }
        for (const auto& s : suites) {
            def.cipher_suites.push_back(s.as<std::string>());
        }
    }

    if (const YAML::Node auth = node["authentication"]) {
        reject_unknown_keys(auth, {"type", "require_client_certificate"},
                            "profile '" + def.id + "' authentication section");
        if (auth["type"]) {
            const auto raw = auth["type"].as<std::string>();
            const auto parsed = authentication_type_from_string(raw);
            if (!parsed) {
                throw ConfigurationError("profile '" + def.id + "': unknown authentication.type '" +
                                         raw + "'");
            }
            def.authentication = *parsed;
        }
        if (auth["require_client_certificate"]) {
            def.require_client_certificate = auth["require_client_certificate"].as<bool>();
        }
    }

    if (const YAML::Node fallback = node["fallback"]) {
        reject_unknown_keys(fallback, {"allow_classical"},
                            "profile '" + def.id + "' fallback section");
        if (fallback["allow_classical"]) {
            def.allow_classical_fallback = fallback["allow_classical"].as<bool>();
        }
    }

    if (node["experimental"]) {
        def.experimental = node["experimental"].as<bool>();
    }

    return SecurityProfile::create(std::move(def));
}

}  // namespace

ProfileRegistry ProfileRegistry::from_yaml_file(const std::string& path) {
    ProfileRegistry registry = builtin();

    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw ConfigurationError("failed to parse profiles file '" + path + "': " + e.what());
    }

    reject_unknown_keys(root, {"profiles", "schema_version"}, "profiles file '" + path + "'");

    const YAML::Node profiles = root["profiles"];
    if (!profiles || !profiles.IsSequence()) {
        throw ConfigurationError("profiles file '" + path +
                                 "' must contain a top-level 'profiles' list");
    }

    for (const auto& node : profiles) {
        registry.add_or_replace(parse_profile_node(node));
    }

    return registry;
}

}  // namespace pqtls
