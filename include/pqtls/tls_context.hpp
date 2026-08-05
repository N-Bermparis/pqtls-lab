#pragma once

#include <memory>
#include <string>
#include <vector>

#include <openssl/ssl.h>

#include "pqtls/config.hpp"
#include "pqtls/security_profile.hpp"

namespace pqtls {

/// RAII deleters for OpenSSL types.
///
/// Rule (spec section 26): no raw owning pointers to OpenSSL objects escape
/// this layer. Every handle below is owned by a unique_ptr with the matching
/// free function, so an early return or a thrown exception cannot leak.
namespace ossl {

struct SslCtxDeleter {
    void operator()(SSL_CTX* p) const noexcept { SSL_CTX_free(p); }
};

struct SslDeleter {
    void operator()(SSL* p) const noexcept { SSL_free(p); }
};

struct BioDeleter {
    void operator()(BIO* p) const noexcept { BIO_free_all(p); }
};

struct X509Deleter {
    void operator()(X509* p) const noexcept { X509_free(p); }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};

struct SslSessionDeleter {
    void operator()(SSL_SESSION* p) const noexcept { SSL_SESSION_free(p); }
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using SslSessionPtr = std::unique_ptr<SSL_SESSION, SslSessionDeleter>;

}  // namespace ossl

/// Facts observed about a completed handshake, used for policy enforcement and
/// for metrics. Populated only after SSL_do_handshake has succeeded.
struct HandshakeOutcome {
    std::string tls_version;
    std::string negotiated_group;
    std::string cipher_suite;
    std::string peer_signature_algorithm;
    std::string peer_certificate_subject;
    std::string peer_certificate_issuer;
    bool session_reused = false;
    bool peer_certificate_present = false;
};

/// Owns an SSL_CTX configured from a SecurityProfile.
///
/// The context is built once and shared by every connection it serves. All
/// policy that can be expressed in the context (versions, groups, ciphersuites,
/// verification mode, trust store) is set here, so an individual connection
/// cannot weaken it.
class TlsContext {
  public:
    /// Build a client context.
    /// @throws CapabilityError when the profile needs something this OpenSSL
    ///         does not provide. Never falls back to a weaker group.
    [[nodiscard]] static TlsContext create_client(const SecurityProfile& profile,
                                                  const CommonConfig& config);

    /// Build a server context. Requires a certificate and private key.
    [[nodiscard]] static TlsContext create_server(const SecurityProfile& profile,
                                                  const CommonConfig& config,
                                                  bool require_client_certificate);

    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    TlsContext(TlsContext&&) noexcept = default;
    TlsContext& operator=(TlsContext&&) noexcept = default;
    ~TlsContext() = default;

    [[nodiscard]] SSL_CTX* native_handle() const noexcept { return ctx_.get(); }
    [[nodiscard]] const SecurityProfile& profile() const noexcept { return profile_; }

    /// Create a new SSL object bound to this context.
    [[nodiscard]] ossl::SslPtr new_ssl() const;

    /// Read the negotiated parameters from a completed handshake.
    [[nodiscard]] static HandshakeOutcome inspect(SSL* ssl);

    /// Enforce the profile's group policy against what was actually negotiated
    /// (spec section 9).
    ///
    /// This is the downgrade check. It runs after every handshake, on both
    /// peers, and it throws rather than logging: a connection that negotiated a
    /// group the profile forbids must not be used to carry application data.
    /// @throws TlsPolicyError when the negotiated group violates the profile.
    static void enforce_group_policy(const SecurityProfile& profile,
                                     const HandshakeOutcome& outcome);

    /// Verify the peer certificate chain result and, for clients, that the
    /// hostname matched. Skipped only in insecure development mode, which is
    /// itself refused in production.
    /// @throws CertificateError on any verification failure.
    static void enforce_peer_verification(SSL* ssl, const CommonConfig& config,
                                          bool require_peer_certificate);

    /// One-time process-wide OpenSSL initialisation. Idempotent, thread-safe.
    static void initialize_openssl();

    /// Names of the providers currently loaded in the default library context.
    [[nodiscard]] static std::vector<std::string> loaded_providers();

  private:
    TlsContext(ossl::SslCtxPtr ctx, SecurityProfile profile)
        : ctx_(std::move(ctx)), profile_(std::move(profile)) {}

    static void apply_common_policy(SSL_CTX* ctx, const SecurityProfile& profile,
                                    const CommonConfig& config);
    static void load_certificate_material(SSL_CTX* ctx, const CommonConfig& config,
                                          bool require_certificate);
    static void load_trust_store(SSL_CTX* ctx, const CommonConfig& config);
    static void install_keylog_callback(SSL_CTX* ctx, const CommonConfig& config);

    ossl::SslCtxPtr ctx_;
    SecurityProfile profile_;
};

/// Human-readable text for an X509_verify_cert error code, with a hint about
/// what an operator should actually do about it.
[[nodiscard]] std::string describe_verify_result(long verify_result);

}  // namespace pqtls
