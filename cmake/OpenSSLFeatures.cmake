# OpenSSL feature detection for pqtls-lab.
#
# Design rule (spec section 4): the build system must never *assume* that a
# post-quantum TLS group exists, and must never silently substitute a classical
# group for a requested hybrid one. Detection therefore happens in two layers:
#
#   1. A hard version gate. Below PQTLS_MIN_OPENSSL_FOR_PQ we refuse outright,
#      because the hybrid group names and the ML-KEM implementation only became
#      available in OpenSSL 3.5.
#   2. An actual runtime probe. Even on a new enough OpenSSL, a provider may be
#      missing or a distribution may have disabled algorithms, so we compile and
#      run a small program that asks libssl to accept each group by name.
#
# The probe result is advisory for the build (it enables a compile definition
# and prints a summary); the authoritative check still happens at run time in
# src/common/capabilities.cpp, because the runtime OpenSSL may differ from the
# one we compiled against.

if(NOT DEFINED OPENSSL_VERSION)
    message(FATAL_ERROR "OpenSSLFeatures.cmake must be included after find_package(OpenSSL)")
endif()

set(PQTLS_OPENSSL_HAS_PQ_GROUPS FALSE)
set(PQTLS_DETECTED_PQ_GROUPS "")

# --- Layer 1: version gate --------------------------------------------------
if(OPENSSL_VERSION VERSION_LESS PQTLS_MIN_OPENSSL_FOR_PQ)
    message(STATUS
        "OpenSSL ${OPENSSL_VERSION} is older than ${PQTLS_MIN_OPENSSL_FOR_PQ}: "
        "post-quantum TLS profiles will be built as UNAVAILABLE and will fail "
        "closed at run time. Classical profiles are unaffected.")
    return()
endif()

# --- Layer 2: runtime probe -------------------------------------------------
set(_probe_src "${CMAKE_CURRENT_BINARY_DIR}/pqtls_group_probe.cpp")
file(WRITE "${_probe_src}" [==[
// Probe: report which TLS group names this libssl actually accepts.
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <cstdio>

namespace {
const char* kGroups[] = {
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "MLKEM768",
};
}  // namespace

int main() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        return 2;
    }
    int found = 0;
    for (const char* g : kGroups) {
        // SSL_CTX_set1_groups_list returns 1 only when every name in the list
        // resolves to a group this build knows about.
        if (SSL_CTX_set1_groups_list(ctx, g) == 1) {
            std::printf("%s;", g);
            ++found;
        }
    }
    SSL_CTX_free(ctx);
    return found > 0 ? 0 : 1;
}
]==])

if(CMAKE_CROSSCOMPILING)
    message(STATUS
        "Cross-compiling: skipping the OpenSSL TLS-group probe. PQ profiles are "
        "enabled on the version gate alone and are verified at run time via "
        "'pqtls-client capabilities'.")
    set(PQTLS_OPENSSL_HAS_PQ_GROUPS TRUE)
    set(PQTLS_DETECTED_PQ_GROUPS "not-probed (cross-compiling)")
else()
    try_run(_probe_run_result _probe_compile_result
        "${CMAKE_CURRENT_BINARY_DIR}/pqtls_group_probe"
        "${_probe_src}"
        LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto
        COMPILE_OUTPUT_VARIABLE _probe_compile_output
        RUN_OUTPUT_VARIABLE _probe_run_output)

    if(NOT _probe_compile_result)
        message(WARNING
            "OpenSSL TLS-group probe failed to compile. PQ profiles will be "
            "reported as unavailable.\n${_probe_compile_output}")
    elseif(NOT _probe_run_result EQUAL 0)
        message(STATUS
            "OpenSSL ${OPENSSL_VERSION} exposes no post-quantum TLS groups. "
            "PQ profiles will fail closed at run time.")
    else()
        string(STRIP "${_probe_run_output}" _probe_run_output)
        string(REGEX REPLACE ";$" "" _probe_run_output "${_probe_run_output}")
        set(PQTLS_OPENSSL_HAS_PQ_GROUPS TRUE)
        set(PQTLS_DETECTED_PQ_GROUPS "${_probe_run_output}")
        message(STATUS "OpenSSL post-quantum TLS groups detected: ${PQTLS_DETECTED_PQ_GROUPS}")
    endif()
endif()

# --- ML-DSA (post-quantum *authentication*) probe ---------------------------
#
# Kept separate on purpose. PQ key establishment and PQ authentication are
# different properties and must never be conflated in reporting.
set(PQTLS_OPENSSL_HAS_MLDSA FALSE)
if(NOT CMAKE_CROSSCOMPILING)
    set(_mldsa_src "${CMAKE_CURRENT_BINARY_DIR}/pqtls_mldsa_probe.cpp")
    file(WRITE "${_mldsa_src}" [==[
#include <openssl/evp.h>
int main() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr);
    if (ctx == nullptr) {
        return 1;
    }
    const int ok = EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_free(ctx);
    return ok == 1 ? 0 : 1;
}
]==])
    try_run(_mldsa_run _mldsa_compile
        "${CMAKE_CURRENT_BINARY_DIR}/pqtls_mldsa_probe"
        "${_mldsa_src}"
        LINK_LIBRARIES OpenSSL::Crypto)
    if(_mldsa_compile AND _mldsa_run EQUAL 0)
        set(PQTLS_OPENSSL_HAS_MLDSA TRUE)
        message(STATUS "OpenSSL ML-DSA-65 available (experimental PQ authentication)")
    else()
        message(STATUS "OpenSSL ML-DSA-65 not available; PQ authentication stays disabled")
    endif()
endif()
