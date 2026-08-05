#include "pqtls/tls_context.hpp"

#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <spdlog/spdlog.h>

#include "pqtls/capabilities.hpp"
#include "pqtls/error.hpp"

namespace pqtls {
namespace {

/// ALPN identifier for this project's framed JSON protocol. Advertising an
/// explicit protocol keeps us from being mistaken for HTTPS by tooling and
/// makes captures easier to read.
constexpr unsigned char kAlpnWire[] = {6, 'p', 'q', 't', 'l', 's', '1'};

/// TLS key logging destination.
///
/// SECURITY: this writes the traffic secrets of every connection in the clear.
/// It exists only for Wireshark-based research on locally generated test
/// traffic, is off unless --keylog-file is passed, is refused when
/// PQTLS_ENV=production, and the destination is git-ignored.
std::mutex g_keylog_mutex;
std::ofstream g_keylog_stream;

void keylog_callback(const SSL* /*ssl*/, const char* line) {
    if (line == nullptr) {
        return;
    }
    const std::lock_guard<std::mutex> lock(g_keylog_mutex);
    if (g_keylog_stream.is_open()) {
        g_keylog_stream << line << '\n';
        g_keylog_stream.flush();
    }
}

int alpn_select_callback(SSL* /*ssl*/, const unsigned char** out, unsigned char* out_len,
                         const unsigned char* in, unsigned int in_len, void* /*arg*/) {
    if (SSL_select_next_proto(const_cast<unsigned char**>(out), out_len, kAlpnWire,
                              static_cast<unsigned int>(sizeof(kAlpnWire)), in,
                              in_len) != OPENSSL_NPN_NEGOTIATED) {
        // No overlap. Refuse rather than silently continuing without ALPN, so
        // a mismatched peer is a visible failure.
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}

std::string subject_name_to_string(X509_NAME* name) {
    if (name == nullptr) {
        return {};
    }
    const ossl::BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        return {};
    }
    // XN_FLAG_RFC2253 escapes control characters, so a certificate with a
    // hostile subject cannot inject terminal escapes into our logs.
    if (X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) < 0) {
        return {};
    }
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || data == nullptr) {
        return {};
    }
    return std::string(data, static_cast<std::size_t>(length));
}

}  // namespace

void TlsContext::initialize_openssl() {
    static std::once_flag once;
    std::call_once(once, [] {
        // OPENSSL_init_ssl is idempotent and thread-safe; the once_flag simply
        // documents that we rely on a single initialisation point.
        if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
                             nullptr) != 1) {
            throw openssl_error(ErrorCategory::Internal, "OpenSSL initialisation failed");
        }
    });
}

std::vector<std::string> TlsContext::loaded_providers() {
    std::vector<std::string> names;
    OSSL_PROVIDER_do_all(
        nullptr,
        [](OSSL_PROVIDER* provider, void* arg) -> int {
            auto* out = static_cast<std::vector<std::string>*>(arg);
            const char* name = OSSL_PROVIDER_get0_name(provider);
            if (name != nullptr) {
                out->emplace_back(name);
            }
            return 1;
        },
        &names);
    return names;
}

void TlsContext::apply_common_policy(SSL_CTX* ctx, const SecurityProfile& profile,
                                     const CommonConfig& config) {
    // --- Protocol version ---------------------------------------------------
    // Both bounds are pinned to TLS 1.3. Setting only the minimum would still
    // allow a future OpenSSL to negotiate a newer version we have not reviewed.
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        throw openssl_error(ErrorCategory::Configuration,
                            "failed to set the minimum TLS version to 1.3");
    }
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        throw openssl_error(ErrorCategory::Configuration,
                            "failed to set the maximum TLS version to 1.3");
    }

    // --- Options ------------------------------------------------------------
    // Belt and braces: the version bounds above already exclude TLS 1.2 and
    // earlier, but stating it in the options makes the intent auditable and
    // survives someone loosening the bounds later.
    const long options = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 |
                         SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION |
                         SSL_OP_CIPHER_SERVER_PREFERENCE;
    SSL_CTX_set_options(ctx, static_cast<std::uint64_t>(options));

    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY | SSL_MODE_ENABLE_PARTIAL_WRITE);

    // --- Groups (key establishment) ----------------------------------------
    //
    // This is the crypto-agility control point (RQ4). Only the groups the
    // profile names are configured, so the peer cannot steer us to anything
    // else: there is nothing else on offer. If a name is unknown to this
    // OpenSSL the call fails and we abort rather than quietly proceeding with
    // whatever OpenSSL's defaults happen to be.
    const std::string groups = profile.openssl_groups_list();
    if (SSL_CTX_set1_groups_list(ctx, groups.c_str()) != 1) {
        auto details = drain_openssl_errors();
        details.emplace_back("run 'pqtls-client capabilities' to list the groups this build offers");
        throw CapabilityError(
            "this OpenSSL build does not support the TLS group list required by profile '" +
                profile.id() + "': " + groups +
                ". Refusing to continue: substituting a different group would silently weaken the "
                "requested profile.",
            std::move(details));
    }

    // --- Cipher suites (record protection) ---------------------------------
    const std::string suites = profile.openssl_ciphersuites_list();
    if (SSL_CTX_set_ciphersuites(ctx, suites.c_str()) != 1) {
        throw openssl_error(ErrorCategory::Configuration,
                            "failed to apply the TLS 1.3 cipher suite allowlist for profile '" +
                                profile.id() + "': " + suites);
    }

    // Clear the TLS 1.2-and-earlier cipher list as well. It is unreachable
    // given the version bounds, but leaving OpenSSL's defaults in place would
    // make an audit of "what can this endpoint negotiate" misleading.
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP") != 1) {
        // Not fatal: no TLS 1.2 handshake can occur anyway.
        (void)drain_openssl_errors();
    }

    // --- ALPN ---------------------------------------------------------------
    if (SSL_CTX_set_alpn_protos(ctx, kAlpnWire, static_cast<unsigned int>(sizeof(kAlpnWire))) != 0) {
        throw openssl_error(ErrorCategory::Configuration, "failed to configure ALPN");
    }

    install_keylog_callback(ctx, config);
}

void TlsContext::install_keylog_callback(SSL_CTX* ctx, const CommonConfig& config) {
    if (config.keylog_file.empty()) {
        return;
    }

    if (ConfigLoader::production_environment()) {
        throw ConfigurationError(
            "TLS key logging was requested but PQTLS_ENV=production. Key logging writes session "
            "secrets in the clear and is refused outside development.");
    }

    const std::lock_guard<std::mutex> lock(g_keylog_mutex);
    if (!g_keylog_stream.is_open()) {
        g_keylog_stream.open(config.keylog_file, std::ios::app);
        if (!g_keylog_stream.is_open()) {
            throw ConfigurationError("cannot open TLS key log file '" + config.keylog_file +
                                     "' for appending");
        }
    }

    spdlog::warn(
        "TLS KEY LOGGING IS ENABLED -> {}. Session secrets are being written in the clear. "
        "Use this only with locally generated test traffic and never commit the file.",
        config.keylog_file);

    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
}

void TlsContext::load_certificate_material(SSL_CTX* ctx, const CommonConfig& config,
                                           bool require_certificate) {
    if (config.certificate_file.empty() || config.private_key_file.empty()) {
        if (require_certificate) {
            throw ConfigurationError(
                "a server requires both --certificate and --private-key. Generate a development "
                "pair with scripts/generate-classical-certs.sh.");
        }
        return;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, config.certificate_file.c_str()) != 1) {
        throw openssl_error(ErrorCategory::Certificate,
                            "failed to load the certificate chain from '" +
                                config.certificate_file + "'");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config.private_key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        throw openssl_error(ErrorCategory::Certificate,
                            "failed to load the private key from '" + config.private_key_file +
                                "'");
    }

    // Catches the classic misconfiguration of a certificate and key from
    // different generations sitting in the same directory.
    if (SSL_CTX_check_private_key(ctx) != 1) {
        throw openssl_error(ErrorCategory::Certificate,
                            "the private key in '" + config.private_key_file +
                                "' does not match the certificate in '" + config.certificate_file +
                                "'");
    }
}

void TlsContext::load_trust_store(SSL_CTX* ctx, const CommonConfig& config) {
    if (!config.ca_certificate_file.empty()) {
        if (SSL_CTX_load_verify_file(ctx, config.ca_certificate_file.c_str()) != 1) {
            throw openssl_error(ErrorCategory::Certificate,
                                "failed to load the CA trust anchor from '" +
                                    config.ca_certificate_file + "'");
        }
        return;
    }

    if (config.insecure_development_mode) {
        return;  // Verification is disabled anyway; the warning is printed elsewhere.
    }

    // No explicit CA given: fall back to the platform trust store. Useful for
    // talking to a public endpoint, useless for our development CA, so say so.
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        throw openssl_error(ErrorCategory::Certificate,
                            "no --ca-certificate was given and the system trust store could not be "
                            "loaded");
    }
    spdlog::debug("no --ca-certificate given; using the system trust store");
}

TlsContext TlsContext::create_client(const SecurityProfile& profile, const CommonConfig& config) {
    initialize_openssl();
    ConfigLoader::enforce_insecure_mode_policy(config);

    ossl::SslCtxPtr ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx) {
        throw openssl_error(ErrorCategory::Internal, "SSL_CTX_new failed for the client context");
    }

    apply_common_policy(ctx.get(), profile, config);
    load_trust_store(ctx.get(), config);

    // Client certificate for mutual TLS. Optional: only loaded when supplied.
    load_certificate_material(ctx.get(), config, /*require_certificate=*/false);

    if (config.insecure_development_mode) {
        // The verify callback is left null; SSL_VERIFY_NONE means the result of
        // chain building is not enforced. This branch is unreachable in
        // production because enforce_insecure_mode_policy already threw.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
        spdlog::error(
            "==================================================================\n"
            "  INSECURE DEVELOPMENT MODE: certificate and hostname verification\n"
            "  are DISABLED. This connection is not authenticated and provides\n"
            "  no protection against an active man-in-the-middle.\n"
            "==================================================================");
    } else {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_verify_depth(ctx.get(), 8);
    }

    return TlsContext(std::move(ctx), profile);
}

TlsContext TlsContext::create_server(const SecurityProfile& profile, const CommonConfig& config,
                                     bool require_client_certificate) {
    initialize_openssl();
    ConfigLoader::enforce_insecure_mode_policy(config);

    ossl::SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
    if (!ctx) {
        throw openssl_error(ErrorCategory::Internal, "SSL_CTX_new failed for the server context");
    }

    apply_common_policy(ctx.get(), profile, config);
    load_certificate_material(ctx.get(), config, /*require_certificate=*/true);

    SSL_CTX_set_alpn_select_cb(ctx.get(), alpn_select_callback, nullptr);

    const bool want_client_cert = require_client_certificate || profile.require_client_certificate();
    if (want_client_cert) {
        load_trust_store(ctx.get(), config);
        if (config.ca_certificate_file.empty()) {
            throw ConfigurationError(
                "mutual TLS was requested but no --ca-certificate was given. Without a trust "
                "anchor the server cannot verify client certificates.");
        }
        // FAIL_IF_NO_PEER_CERT makes an absent client certificate a handshake
        // failure rather than an unauthenticated connection.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        SSL_CTX_set_verify_depth(ctx.get(), 8);

        STACK_OF(X509_NAME)* ca_names = SSL_load_client_CA_file(config.ca_certificate_file.c_str());
        if (ca_names != nullptr) {
            // Transfers ownership to the context.
            SSL_CTX_set_client_CA_list(ctx.get(), ca_names);
        } else {
            (void)drain_openssl_errors();
        }
    } else {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }

    // Session tickets are what make the resumption experiments (RQ6) possible.
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_num_tickets(ctx.get(), 2);

    return TlsContext(std::move(ctx), profile);
}

ossl::SslPtr TlsContext::new_ssl() const {
    ossl::SslPtr ssl(SSL_new(ctx_.get()));
    if (!ssl) {
        throw openssl_error(ErrorCategory::Internal, "SSL_new failed");
    }
    return ssl;
}

HandshakeOutcome TlsContext::inspect(SSL* ssl) {
    HandshakeOutcome outcome;

    if (const char* version = SSL_get_version(ssl); version != nullptr) {
        outcome.tls_version = version;
    }

    if (const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl); cipher != nullptr) {
        if (const char* name = SSL_CIPHER_get_name(cipher); name != nullptr) {
            outcome.cipher_suite = name;
        }
    }

    // Negotiated group.
    //
    // SSL_get0_group_name arrived in OpenSSL 3.2 and is the only API that can
    // name a hybrid group: hybrids have no NID, so the older
    // SSL_get_negotiated_group + OBJ_nid2sn path returns nothing useful for
    // them. Feature-detected rather than assumed.
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    if (const char* group = SSL_get0_group_name(ssl); group != nullptr) {
        outcome.negotiated_group = group;
    }
#else
    if (const int nid = SSL_get_negotiated_group(ssl); nid != NID_undef) {
        if (const char* name = OBJ_nid2sn(nid); name != nullptr) {
            outcome.negotiated_group = name;
        }
    }
#endif

    // Peer signature algorithm, i.e. how the peer authenticated itself. This is
    // the field that tells us whether authentication was post-quantum; it is
    // deliberately separate from the group above.
    int peer_sig_nid = NID_undef;
    if (SSL_get_peer_signature_nid(ssl, &peer_sig_nid) == 1 && peer_sig_nid != NID_undef) {
        if (const char* name = OBJ_nid2sn(peer_sig_nid); name != nullptr) {
            outcome.peer_signature_algorithm = name;
        }
    }

    outcome.session_reused = SSL_session_reused(ssl) == 1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const ossl::X509Ptr peer(SSL_get1_peer_certificate(ssl));
#else
    const ossl::X509Ptr peer(SSL_get_peer_certificate(ssl));
#endif
    if (peer) {
        outcome.peer_certificate_present = true;
        outcome.peer_certificate_subject = subject_name_to_string(X509_get_subject_name(peer.get()));
        outcome.peer_certificate_issuer = subject_name_to_string(X509_get_issuer_name(peer.get()));
    }

    return outcome;
}

void TlsContext::enforce_group_policy(const SecurityProfile& profile,
                                      const HandshakeOutcome& outcome) {
    // The downgrade check (spec section 9).
    //
    // Configuring the group list is necessary but not sufficient: it constrains
    // what we offer, while this confirms what was actually agreed. Both peers
    // run it. It throws rather than logging because a connection outside policy
    // must not carry application data.
    if (profile.permits_negotiated_group(outcome.negotiated_group)) {
        return;
    }

    throw TlsPolicyError(
        "downgrade policy violation: " + profile.explain_group_rejection(outcome.negotiated_group),
        {"requested profile: " + profile.id(),
         "permitted groups: " + profile.openssl_groups_list(),
         "negotiated group: " +
             (outcome.negotiated_group.empty() ? std::string("<unknown>")
                                               : outcome.negotiated_group),
         "the connection has been terminated and recorded as a tls-policy failure"});
}

void TlsContext::enforce_peer_verification(SSL* ssl, const CommonConfig& config,
                                           bool require_peer_certificate) {
    if (config.insecure_development_mode) {
        return;  // Already warned about loudly at context creation.
    }

    const long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        throw CertificateError("peer certificate verification failed: " +
                                   describe_verify_result(verify_result),
                               {"X509_verify_cert code " + std::to_string(verify_result)});
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const ossl::X509Ptr peer(SSL_get1_peer_certificate(ssl));
#else
    const ossl::X509Ptr peer(SSL_get_peer_certificate(ssl));
#endif

    // X509_V_OK with no certificate at all is possible when the peer simply did
    // not send one. For a client that means an unauthenticated server, which is
    // exactly the case we must refuse.
    if (!peer && require_peer_certificate) {
        throw CertificateError(
            "the peer presented no certificate. An unauthenticated peer cannot be distinguished "
            "from an active man-in-the-middle, so the connection is refused.");
    }
}

std::string describe_verify_result(long verify_result) {
    const char* text = X509_verify_cert_error_string(verify_result);
    std::ostringstream out;
    out << (text != nullptr ? text : "unknown verification error");

    switch (verify_result) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            out << ". The issuing CA is not in the configured trust store: pass --ca-certificate "
                   "pointing at the CA that signed the peer certificate.";
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
            out << ". Regenerate the development certificates, or check the system clock.";
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
            out << ". The certificate starts in the future: check the system clock on both hosts.";
            break;
        case X509_V_ERR_HOSTNAME_MISMATCH:
            out << ". The name given with --server-name is not covered by the certificate's "
                   "subjectAltName entries.";
            break;
        default:
            break;
    }

    return out.str();
}

}  // namespace pqtls
