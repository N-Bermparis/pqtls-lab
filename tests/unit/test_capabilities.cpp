#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

#include "pqtls/capabilities.hpp"
#include "pqtls/security_profile.hpp"

using namespace pqtls;

// These tests do not assert that any particular post-quantum group EXISTS,
// because that depends on the OpenSSL the tests were linked against. They
// assert that detection is self-consistent and that an unavailable capability
// is reported as unavailable rather than assumed present.

TEST_CASE("capability detection succeeds and reports the runtime OpenSSL",
          "[capabilities]") {
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    CHECK_FALSE(capabilities.openssl_runtime_version.empty());
    CHECK_FALSE(capabilities.openssl_compile_time_version.empty());
    CHECK_FALSE(capabilities.providers.empty());
}

TEST_CASE("TLS 1.3 and the classical groups are available", "[capabilities]") {
    // The minimum this project needs to do anything at all. If these fail, the
    // OpenSSL build is unusable for the classical baseline, let alone hybrid.
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    CHECK(capabilities.tls13_available);
    CHECK(capabilities.has_group("X25519"));
    CHECK(capabilities.has_group("secp256r1"));
}

TEST_CASE("the mandatory cipher suites are available", "[capabilities]") {
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    for (const auto& suite : default_cipher_suites()) {
        INFO("cipher suite: " << suite);
        CHECK(capabilities.has_cipher_suite(suite));
    }
}

TEST_CASE("group lookup is case-insensitive", "[capabilities]") {
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    CHECK(capabilities.has_group("x25519"));
    CHECK(capabilities.has_group("X25519"));
    CHECK(capabilities.has_group("X25519"));
}

TEST_CASE("every built-in profile is evaluated", "[capabilities]") {
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    CHECK(capabilities.profiles.size() == registry.all().size());
    for (const auto& profile : registry.all()) {
        INFO("profile: " << profile.id());
        CHECK(capabilities.profile(profile.id()) != nullptr);
    }
}

TEST_CASE("an unusable profile always states a reason", "[capabilities]") {
    // "Unavailable" with no explanation is not actionable, and it is the kind
    // of output that invites someone to disable a check to make it go away.
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    for (const auto& availability : capabilities.profiles) {
        INFO("profile: " << availability.profile_id);
        if (availability.usable) {
            CHECK(availability.blocking_reason.empty());
            CHECK(availability.missing_groups.empty());
        } else {
            CHECK_FALSE(availability.blocking_reason.empty());
        }
    }
}

TEST_CASE("profile usability follows from the detected groups", "[capabilities][security]") {
    // The property that stops us from claiming a profile works because its
    // name is in a table.
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    for (const auto& profile : registry.all()) {
        const auto* availability = capabilities.profile(profile.id());
        REQUIRE(availability != nullptr);

        const bool all_groups_present =
            std::all_of(profile.groups().begin(), profile.groups().end(),
                        [&capabilities](const std::string& g) { return capabilities.has_group(g); });

        INFO("profile: " << profile.id());
        if (!all_groups_present) {
            CHECK_FALSE(availability->usable);
        }
        if (availability->usable) {
            CHECK(all_groups_present);
        }
    }
}

TEST_CASE("a profile needing ML-DSA is unusable without ML-DSA",
          "[capabilities][security]") {
    // Post-quantum authentication is gated on its own capability, separately
    // from key establishment.
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    const auto* pq_auth = capabilities.profile("hybrid-pq-auth");
    REQUIRE(pq_auth != nullptr);

    if (!capabilities.mldsa_available) {
        CHECK_FALSE(pq_auth->usable);
        CHECK(pq_auth->blocking_reason.find("ML-DSA") != std::string::npos);
    }
}

TEST_CASE("ML-KEM availability implies the hybrid groups are usable, and conversely",
          "[capabilities]") {
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    const auto* hybrid = capabilities.profile("hybrid-x25519-mlkem768");
    REQUIRE(hybrid != nullptr);

    if (capabilities.has_group("X25519MLKEM768")) {
        CHECK(hybrid->usable);
        // A build that offers the hybrid group must also expose ML-KEM itself.
        CHECK(capabilities.mlkem_available);
    } else {
        CHECK_FALSE(hybrid->usable);
    }
}

TEST_CASE("experimental profiles are flagged in the capability report", "[capabilities]") {
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    const auto* pure = capabilities.profile("pure-mlkem768");
    REQUIRE(pure != nullptr);
    CHECK(pure->experimental);

    const auto* primary = capabilities.profile("hybrid-x25519-mlkem768");
    REQUIRE(primary != nullptr);
    CHECK_FALSE(primary->experimental);
}

TEST_CASE("direct group probing agrees with the capability snapshot", "[capabilities]") {
    const auto registry = ProfileRegistry::builtin();
    const auto capabilities = Capabilities::detect(registry);

    for (const auto* group : {"X25519", "secp256r1", "X25519MLKEM768", "MLKEM768"}) {
        INFO("group: " << group);
        CHECK(openssl_supports_group(group) == capabilities.has_group(group));
    }
}

TEST_CASE("probing a nonsense group returns false rather than throwing",
          "[capabilities]") {
    CHECK_FALSE(openssl_supports_group("NotARealGroup12345"));
    CHECK_FALSE(openssl_supports_algorithm("NotARealAlgorithm12345"));
}

TEST_CASE("the JSON report keeps key establishment and authentication apart",
          "[capabilities][security]") {
    const auto registry = ProfileRegistry::builtin();
    const auto json = Capabilities::detect(registry).to_json();

    REQUIRE(json.contains("post_quantum"));
    CHECK(json["post_quantum"].contains("key_establishment"));
    CHECK(json["post_quantum"].contains("authentication"));
    CHECK(json["post_quantum"]["key_establishment"].contains("mlkem_available"));
    CHECK(json["post_quantum"]["authentication"].contains("mldsa_available"));

    // There must be no single flag that a reader could take to mean "this is
    // post-quantum TLS" without qualification.
    CHECK_FALSE(json.contains("post_quantum_ready"));
    CHECK_FALSE(json.contains("quantum_safe"));
}

TEST_CASE("the human-readable report explains the distinction",
          "[capabilities][security]") {
    const auto registry = ProfileRegistry::builtin();
    const auto text = Capabilities::detect(registry).to_human_readable();

    CHECK(text.find("key establishment") != std::string::npos);
    CHECK(text.find("authentication") != std::string::npos);
    CHECK(text.find("independent properties") != std::string::npos);
}
