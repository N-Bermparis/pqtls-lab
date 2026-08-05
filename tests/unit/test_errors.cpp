#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "pqtls/error.hpp"
#include "pqtls/tls_context.hpp"
#include "pqtls/version.hpp"

using namespace pqtls;

// ---------------------------------------------------------------------------
// Category mapping
// ---------------------------------------------------------------------------
TEST_CASE("error category names round trip", "[error]") {
    for (const auto category :
         {ErrorCategory::None, ErrorCategory::Configuration, ErrorCategory::Capability,
          ErrorCategory::Certificate, ErrorCategory::TlsPolicy, ErrorCategory::Handshake,
          ErrorCategory::Network, ErrorCategory::Protocol, ErrorCategory::Timeout,
          ErrorCategory::Internal}) {
        const auto name = to_string(category);
        INFO("category: " << name);
        CHECK(error_category_from_string(name) == category);
    }
}

TEST_CASE("an unknown category name maps to internal", "[error]") {
    // Fail towards "this is our bug" rather than towards a category that
    // suggests the peer was at fault.
    CHECK(error_category_from_string("not-a-category") == ErrorCategory::Internal);
}

TEST_CASE("exit codes are stable and distinct", "[error]") {
    // Benchmark orchestration branches on these, so they are part of the
    // interface and must not drift.
    CHECK(exit_code_for(ErrorCategory::None) == ExitCode::Success);
    CHECK(exit_code_for(ErrorCategory::Configuration) == ExitCode::ConfigurationError);
    CHECK(exit_code_for(ErrorCategory::Capability) == ExitCode::CapabilityError);
    CHECK(exit_code_for(ErrorCategory::Certificate) == ExitCode::CertificateError);
    CHECK(exit_code_for(ErrorCategory::TlsPolicy) == ExitCode::TlsPolicyError);
    CHECK(exit_code_for(ErrorCategory::Handshake) == ExitCode::HandshakeError);
    CHECK(exit_code_for(ErrorCategory::Network) == ExitCode::NetworkError);
    CHECK(exit_code_for(ErrorCategory::Protocol) == ExitCode::ProtocolError);
    CHECK(exit_code_for(ErrorCategory::Timeout) == ExitCode::TimeoutError);
    CHECK(exit_code_for(ErrorCategory::Internal) == ExitCode::InternalError);

    CHECK(static_cast<int>(ExitCode::Success) == 0);
    CHECK(static_cast<int>(ExitCode::ConfigurationError) == 2);
    CHECK(static_cast<int>(ExitCode::TlsPolicyError) == 5);
}

TEST_CASE("a tls-policy failure is distinguishable from a handshake failure",
          "[error][security]") {
    // "The peer rejected us on policy" and "the handshake broke" are different
    // outcomes for a research result, and a script must be able to tell them
    // apart without parsing text.
    CHECK(exit_code_for(ErrorCategory::TlsPolicy) != exit_code_for(ErrorCategory::Handshake));
    CHECK(exit_code_for(ErrorCategory::Certificate) != exit_code_for(ErrorCategory::Handshake));
}

// ---------------------------------------------------------------------------
// Error objects
// ---------------------------------------------------------------------------
TEST_CASE("an error carries its category and message", "[error]") {
    const TlsPolicyError error("downgrade policy violation");
    CHECK(error.category() == ErrorCategory::TlsPolicy);
    CHECK(error.message() == "downgrade policy violation");
    CHECK(std::string(error.what()).find("tls-policy") != std::string::npos);
}

TEST_CASE("error details are preserved and rendered", "[error]") {
    const HandshakeError error("handshake failed",
                               {"first detail", "second detail"});
    REQUIRE(error.details().size() == 2);

    const std::string formatted = error.format();
    CHECK(formatted.find("handshake failed") != std::string::npos);
    CHECK(formatted.find("first detail") != std::string::npos);
    CHECK(formatted.find("second detail") != std::string::npos);
}

TEST_CASE("errors are catchable as the base type", "[error]") {
    const auto throw_certificate_error = [] {
        throw CertificateError("unknown certificate authority");
    };

    try {
        throw_certificate_error();
        FAIL("expected an exception");
    } catch (const Error& error) {
        CHECK(error.category() == ErrorCategory::Certificate);
    }
}

// ---------------------------------------------------------------------------
// OpenSSL error translation
// ---------------------------------------------------------------------------
TEST_CASE("draining an empty OpenSSL error queue yields nothing", "[error][openssl]") {
    ERR_clear_error();
    CHECK(drain_openssl_errors().empty());
}

TEST_CASE("draining the OpenSSL error queue empties it", "[error][openssl]") {
    // Critical property: the queue is per-thread and shared, so a later
    // unrelated failure must not inherit these entries.
    TlsContext::initialize_openssl();
    ERR_clear_error();

    // Provoke a real error: an unknown group name.
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    (void)SSL_CTX_set1_groups_list(ctx, "ThisGroupDoesNotExist");
    SSL_CTX_free(ctx);

    const auto first = drain_openssl_errors();
    const auto second = drain_openssl_errors();

    CHECK(second.empty());  // whether or not `first` had entries, the queue is now clear
    (void)first;
}

TEST_CASE("openssl_error attaches the queue to the message", "[error][openssl]") {
    TlsContext::initialize_openssl();
    ERR_clear_error();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    (void)SSL_CTX_set1_groups_list(ctx, "AnotherNonexistentGroup");
    SSL_CTX_free(ctx);

    const Error error = openssl_error(ErrorCategory::Capability, "group configuration failed");
    CHECK(error.category() == ErrorCategory::Capability);
    CHECK(error.message() == "group configuration failed");
    CHECK(drain_openssl_errors().empty());  // openssl_error consumed the queue
}

// ---------------------------------------------------------------------------
// Certificate verification messages
// ---------------------------------------------------------------------------
TEST_CASE("verification failures produce actionable text", "[error][certificate]") {
    // An operator reading this should know what to do next, not just that
    // something failed.
    const std::string unknown_ca =
        describe_verify_result(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    CHECK(unknown_ca.find("--ca-certificate") != std::string::npos);

    const std::string expired = describe_verify_result(X509_V_ERR_CERT_HAS_EXPIRED);
    CHECK(expired.find("clock") != std::string::npos);

    const std::string hostname = describe_verify_result(X509_V_ERR_HOSTNAME_MISMATCH);
    CHECK(hostname.find("subjectAltName") != std::string::npos);
}

TEST_CASE("a successful verification result describes success", "[error][certificate]") {
    const std::string ok = describe_verify_result(X509_V_OK);
    CHECK_FALSE(ok.empty());
}

// ---------------------------------------------------------------------------
// Version banner
// ---------------------------------------------------------------------------
TEST_CASE("the version banner names the project and the commit", "[version]") {
    const std::string banner = version_banner();
    CHECK(banner.find("pqtls-lab") != std::string::npos);
    CHECK(banner.find("commit") != std::string::npos);
    CHECK_FALSE(std::string(version()).empty());
    CHECK_FALSE(std::string(git_commit()).empty());
}
