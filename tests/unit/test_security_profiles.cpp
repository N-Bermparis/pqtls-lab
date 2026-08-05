#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

#include "pqtls/error.hpp"
#include "pqtls/security_profile.hpp"

using namespace pqtls;

namespace {

SecurityProfile::Definition hybrid_definition() {
    return SecurityProfile::Definition{
        .id = "test-hybrid",
        .description = "test",
        .groups = {"X25519MLKEM768"},
        .cipher_suites = default_cipher_suites(),
        .authentication = AuthenticationType::EcdsaP256,
        .allow_classical_fallback = false,
        .experimental = false,
    };
}

}  // namespace

// ---------------------------------------------------------------------------
// Group classification
// ---------------------------------------------------------------------------
TEST_CASE("hybrid groups are recognised", "[profile][classification]") {
    CHECK(is_hybrid_group("X25519MLKEM768"));
    CHECK(is_hybrid_group("SecP256r1MLKEM768"));
    CHECK(is_hybrid_group("SecP384r1MLKEM1024"));
}

TEST_CASE("pure ML-KEM groups are post-quantum but not hybrid", "[profile][classification]") {
    // The distinction matters: a pure ML-KEM group has no classical component,
    // so it carries a different risk profile from a hybrid one.
    CHECK(is_post_quantum_group("MLKEM768"));
    CHECK_FALSE(is_hybrid_group("MLKEM768"));
    CHECK(is_post_quantum_group("MLKEM1024"));
    CHECK_FALSE(is_hybrid_group("MLKEM512"));
}

TEST_CASE("classical groups are not post-quantum", "[profile][classification]") {
    CHECK_FALSE(is_post_quantum_group("X25519"));
    CHECK_FALSE(is_post_quantum_group("secp256r1"));
    CHECK_FALSE(is_post_quantum_group("secp384r1"));
    CHECK_FALSE(is_post_quantum_group("ffdhe2048"));
    CHECK_FALSE(is_post_quantum_group(""));
}

TEST_CASE("group classification is case-insensitive", "[profile][classification]") {
    // OpenSSL's canonical spellings are inconsistent: `openssl list -tls-groups`
    // reports "x25519" in lower case but "X25519MLKEM768" in mixed case, and
    // SSL_get0_group_name returns the canonical form rather than the one we
    // asked for. A case-sensitive comparison would reject a compliant
    // connection, or fail to classify one it should have matched.
    CHECK(is_hybrid_group("x25519mlkem768"));
    CHECK(is_hybrid_group("X25519MLKEM768"));
    CHECK(is_post_quantum_group("mlkem768"));
    CHECK_FALSE(is_post_quantum_group("X25519"));
    CHECK_FALSE(is_post_quantum_group("x25519"));
}

TEST_CASE("post-quantum authentication is tracked separately from key establishment",
          "[profile][classification]") {
    // The single most important distinction in this project.
    CHECK(is_post_quantum_authentication(AuthenticationType::MlDsa65));
    CHECK_FALSE(is_post_quantum_authentication(AuthenticationType::EcdsaP256));
    CHECK_FALSE(is_post_quantum_authentication(AuthenticationType::EcdsaP384));
}

// ---------------------------------------------------------------------------
// Profile validation
// ---------------------------------------------------------------------------
TEST_CASE("a valid profile is accepted", "[profile][validation]") {
    CHECK_NOTHROW(SecurityProfile::create(hybrid_definition()));
}

TEST_CASE("a profile must have an id", "[profile][validation]") {
    auto definition = hybrid_definition();
    definition.id.clear();
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);
}

TEST_CASE("a profile must name at least one group", "[profile][validation]") {
    // An empty list would let OpenSSL fall back to its own defaults, which
    // defeats the entire point of an explicit profile.
    auto definition = hybrid_definition();
    definition.groups.clear();
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);
}

TEST_CASE("duplicate groups are rejected", "[profile][validation]") {
    auto definition = hybrid_definition();
    definition.groups = {"X25519MLKEM768", "X25519MLKEM768"};
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);
}

TEST_CASE("a cipher suite in the group list is rejected", "[profile][validation]") {
    // Confusing groups with cipher suites is the most common configuration
    // error in this area, so it is caught with a message that explains it.
    auto definition = hybrid_definition();
    definition.groups = {"TLS_AES_256_GCM_SHA384"};
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);
}

TEST_CASE("a group in the cipher suite list is rejected", "[profile][validation]") {
    auto definition = hybrid_definition();
    definition.cipher_suites = {"X25519MLKEM768"};
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);
}

TEST_CASE("mixing PQ and classical groups without allowing fallback is rejected",
          "[profile][validation][security]") {
    // Advertising a classical group we would then refuse after the handshake
    // is a contradiction, and it would show up as a mysterious policy failure
    // rather than a configuration error.
    auto definition = hybrid_definition();
    definition.groups = {"X25519MLKEM768", "X25519"};
    definition.allow_classical_fallback = false;
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);
}

TEST_CASE("mixing PQ and classical groups is allowed when fallback is explicit",
          "[profile][validation]") {
    auto definition = hybrid_definition();
    definition.groups = {"X25519MLKEM768", "X25519"};
    definition.allow_classical_fallback = true;
    CHECK_NOTHROW(SecurityProfile::create(std::move(definition)));
}

TEST_CASE("a pure ML-KEM profile must be marked experimental", "[profile][validation]") {
    auto definition = hybrid_definition();
    definition.groups = {"MLKEM768"};
    definition.experimental = false;
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);

    auto experimental = hybrid_definition();
    experimental.groups = {"MLKEM768"};
    experimental.experimental = true;
    CHECK_NOTHROW(SecurityProfile::create(std::move(experimental)));
}

TEST_CASE("an ML-DSA profile must be marked experimental", "[profile][validation]") {
    auto definition = hybrid_definition();
    definition.authentication = AuthenticationType::MlDsa65;
    definition.experimental = false;
    CHECK_THROWS_AS(SecurityProfile::create(std::move(definition)), ConfigurationError);
}

TEST_CASE("cipher suites default to the allowlist when omitted", "[profile][validation]") {
    auto definition = hybrid_definition();
    definition.cipher_suites.clear();
    const auto profile = SecurityProfile::create(std::move(definition));
    CHECK(profile.cipher_suites() == default_cipher_suites());
}

// ---------------------------------------------------------------------------
// Downgrade policy - the core security property
// ---------------------------------------------------------------------------
TEST_CASE("a hybrid profile permits its own group", "[profile][downgrade][security]") {
    const auto profile = SecurityProfile::create(hybrid_definition());
    CHECK(profile.permits_negotiated_group("X25519MLKEM768"));
    CHECK(profile.permits_negotiated_group("x25519mlkem768"));  // OpenSSL casing
}

TEST_CASE("a hybrid profile rejects a classical group", "[profile][downgrade][security]") {
    // This is the downgrade rejection. A server that negotiated X25519 under a
    // hybrid profile must not have its connection accepted.
    const auto profile = SecurityProfile::create(hybrid_definition());
    CHECK_FALSE(profile.permits_negotiated_group("X25519"));
    CHECK_FALSE(profile.permits_negotiated_group("secp256r1"));
}

TEST_CASE("a hybrid profile rejects a different PQ group", "[profile][downgrade][security]") {
    // Not a downgrade in strength, but still outside policy. A profile that
    // silently accepted a group it did not ask for would make the negotiated
    // group unpredictable, and unpredictable is not measurable.
    const auto profile = SecurityProfile::create(hybrid_definition());
    CHECK_FALSE(profile.permits_negotiated_group("SecP384r1MLKEM1024"));
    CHECK_FALSE(profile.permits_negotiated_group("MLKEM768"));
}

TEST_CASE("an unknown negotiated group is rejected", "[profile][downgrade][security]") {
    // Fail closed: an unverifiable claim is not a verified one.
    const auto profile = SecurityProfile::create(hybrid_definition());
    CHECK_FALSE(profile.permits_negotiated_group(""));
    CHECK_FALSE(profile.permits_negotiated_group("something-else"));
}

TEST_CASE("a classical profile permits its own classical group", "[profile][downgrade]") {
    auto definition = hybrid_definition();
    definition.id = "test-classical";
    definition.groups = {"X25519"};
    definition.allow_classical_fallback = true;
    const auto profile = SecurityProfile::create(std::move(definition));

    CHECK(profile.permits_negotiated_group("X25519"));
    CHECK_FALSE(profile.permits_negotiated_group("secp256r1"));
}

TEST_CASE("the rejection explanation names the profile and the group",
          "[profile][downgrade]") {
    const auto profile = SecurityProfile::create(hybrid_definition());

    const std::string classical = profile.explain_group_rejection("X25519");
    CHECK(classical.find("X25519") != std::string::npos);
    CHECK(classical.find("test-hybrid") != std::string::npos);

    const std::string unknown = profile.explain_group_rejection("");
    CHECK(unknown.find("could not be determined") != std::string::npos);
}

// ---------------------------------------------------------------------------
// OpenSSL string formatting
// ---------------------------------------------------------------------------
TEST_CASE("groups are rendered as a colon-separated list in preference order",
          "[profile][openssl]") {
    auto definition = hybrid_definition();
    definition.groups = {"X25519MLKEM768", "SecP256r1MLKEM768"};
    const auto profile = SecurityProfile::create(std::move(definition));
    CHECK(profile.openssl_groups_list() == "X25519MLKEM768:SecP256r1MLKEM768");
}

TEST_CASE("cipher suites are rendered as a colon-separated list", "[profile][openssl]") {
    const auto profile = SecurityProfile::create(hybrid_definition());
    CHECK(profile.openssl_ciphersuites_list() ==
          "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
}

// ---------------------------------------------------------------------------
// The built-in catalogue
// ---------------------------------------------------------------------------
TEST_CASE("the built-in registry contains every documented profile", "[profile][registry]") {
    const auto registry = ProfileRegistry::builtin();

    for (const auto* id : {"classical-x25519", "classical-p256", "hybrid-x25519-mlkem768",
                           "hybrid-p256-mlkem768", "hybrid-p384-mlkem1024", "pure-mlkem768",
                           "hybrid-pq-auth"}) {
        INFO("profile: " << id);
        CHECK(registry.find(id) != nullptr);
    }
}

TEST_CASE("an unknown profile id throws with the available ids listed", "[profile][registry]") {
    const auto registry = ProfileRegistry::builtin();
    CHECK(registry.find("does-not-exist") == nullptr);
    CHECK_THROWS_AS(registry.get("does-not-exist"), ConfigurationError);
}

TEST_CASE("every hybrid profile forbids classical fallback", "[profile][registry][security]") {
    const auto registry = ProfileRegistry::builtin();
    for (const auto& profile : registry.all()) {
        if (profile.id().starts_with("hybrid-") || profile.id().starts_with("pure-")) {
            INFO("profile: " << profile.id());
            CHECK_FALSE(profile.allow_classical_fallback());
            CHECK(profile.offers_post_quantum_key_establishment());
        }
    }
}

TEST_CASE("experimental profiles are flagged", "[profile][registry]") {
    const auto registry = ProfileRegistry::builtin();
    CHECK(registry.get("pure-mlkem768").experimental());
    CHECK(registry.get("hybrid-pq-auth").experimental());
    CHECK_FALSE(registry.get("hybrid-x25519-mlkem768").experimental());
    CHECK_FALSE(registry.get("classical-x25519").experimental());
}

TEST_CASE("the primary profile uses PQ key establishment and classical authentication",
          "[profile][registry][security]") {
    // Guards the headline honesty claim: hybrid-x25519-mlkem768 must not be
    // describable as post-quantum authentication.
    const auto registry = ProfileRegistry::builtin();
    const auto& profile = registry.get("hybrid-x25519-mlkem768");

    CHECK(profile.offers_post_quantum_key_establishment());
    CHECK(is_hybrid_group(profile.groups().front()));
    CHECK_FALSE(is_post_quantum_authentication(profile.authentication()));
}

TEST_CASE("hybrid-pq-auth is the only profile with post-quantum authentication",
          "[profile][registry]") {
    const auto registry = ProfileRegistry::builtin();
    std::vector<std::string> pq_auth_profiles;
    for (const auto& profile : registry.all()) {
        if (is_post_quantum_authentication(profile.authentication())) {
            pq_auth_profiles.push_back(profile.id());
        }
    }
    REQUIRE(pq_auth_profiles.size() == 1);
    CHECK(pq_auth_profiles.front() == "hybrid-pq-auth");
}

TEST_CASE("add_or_replace overwrites an existing profile", "[profile][registry]") {
    auto registry = ProfileRegistry::builtin();
    const auto before = registry.ids().size();

    auto definition = hybrid_definition();
    definition.id = "hybrid-x25519-mlkem768";
    definition.description = "replaced";
    registry.add_or_replace(SecurityProfile::create(std::move(definition)));

    CHECK(registry.ids().size() == before);
    CHECK(registry.get("hybrid-x25519-mlkem768").description() == "replaced");
}

TEST_CASE("TLS version parsing accepts only 1.3", "[profile][validation]") {
    CHECK(tls_version_from_string("TLS1.3").has_value());
    CHECK(tls_version_from_string("TLSv1.3").has_value());
    CHECK_FALSE(tls_version_from_string("TLS1.2").has_value());
    CHECK_FALSE(tls_version_from_string("TLSv1.0").has_value());
}

TEST_CASE("authentication type names round trip", "[profile]") {
    for (const auto type : {AuthenticationType::EcdsaP256, AuthenticationType::EcdsaP384,
                            AuthenticationType::MlDsa65}) {
        const auto parsed = authentication_type_from_string(to_string(type));
        REQUIRE(parsed.has_value());
        CHECK(*parsed == type);
    }
    CHECK_FALSE(authentication_type_from_string("rsa-2048").has_value());
}
