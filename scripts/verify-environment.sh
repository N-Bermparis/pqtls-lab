#!/usr/bin/env bash
#
# verify-environment.sh - report what this host can and cannot do.
#
# Prints a table and exits non-zero when a mandatory capability is missing, so
# it can gate a benchmark run. Post-quantum support is reported as a capability,
# never assumed: a missing PQ group is a documented SKIP, not a silent pass.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
MIN_PQ_VERSION="3.5.0"
FAILURES=0
PQ_AVAILABLE=1

pass() { printf '  [ OK ]   %s\n' "$*"; }
skip() { printf '  [SKIP]   %s\n' "$*"; }
fail() { printf '  [FAIL]   %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

version_ge() {
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

echo "pqtls-lab environment report"
echo "============================"
echo
echo "Host"
printf '  os        : %s\n' "$(uname -srm 2>/dev/null || echo unknown)"
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    printf '  distro    : %s\n' "${PRETTY_NAME:-unknown}"
fi
printf '  cpu       : %s\n' "$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || echo unknown)"
printf '  cores     : %s\n' "$(nproc 2>/dev/null || echo unknown)"
printf '  memory    : %s\n' "$(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo 2>/dev/null || echo unknown)"
echo

echo "Mandatory build tooling"
for tool in cmake g++ python3; do
    if have "${tool}"; then
        pass "${tool} ($(command -v "${tool}"))"
    else
        fail "${tool} is missing - run scripts/bootstrap-ubuntu.sh"
    fi
done
if have cmake; then
    CMAKE_VERSION="$(cmake --version | head -1 | awk '{print $3}')"
    if version_ge "${CMAKE_VERSION}" "3.22"; then
        pass "cmake ${CMAKE_VERSION} (>= 3.22 required)"
    else
        fail "cmake ${CMAKE_VERSION} is older than the required 3.22"
    fi
fi
echo

echo "OpenSSL"
if ! have "${OPENSSL_BIN}"; then
    fail "openssl not found"
else
    OPENSSL_FULL="$(${OPENSSL_BIN} version)"
    OPENSSL_VERSION="$(echo "${OPENSSL_FULL}" | awk '{print $2}' | sed 's/[a-z]*$//')"
    pass "${OPENSSL_FULL}"

    if version_ge "${OPENSSL_VERSION}" "${MIN_PQ_VERSION}"; then
        pass "version ${OPENSSL_VERSION} >= ${MIN_PQ_VERSION}: post-quantum profiles are possible"
    else
        PQ_AVAILABLE=0
        skip "version ${OPENSSL_VERSION} < ${MIN_PQ_VERSION}: post-quantum profiles are UNAVAILABLE"
        skip "  classical profiles still work; PQ tests will be reported as SKIP, not PASS"
    fi

    if ${OPENSSL_BIN} s_client -help 2>&1 | grep -q -- "-tls1_3"; then
        pass "TLS 1.3 support present"
    else
        fail "this OpenSSL has no TLS 1.3 support"
    fi
fi
echo

echo "TLS groups (probed, not assumed)"
if have "${OPENSSL_BIN}"; then
    TLS_GROUPS="$(${OPENSSL_BIN} list -tls-groups -tls1_3 2>/dev/null || true)"
    for group in X25519 secp256r1 secp384r1; do
        if echo "${TLS_GROUPS}" | grep -qi "\b${group}\b"; then
            pass "${group} (classical)"
        else
            fail "${group} is missing; the classical baseline needs it"
        fi
    done
    for group in X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024 MLKEM768; do
        if echo "${TLS_GROUPS}" | grep -q "${group}"; then
            pass "${group} (post-quantum)"
        else
            PQ_AVAILABLE=0
            skip "${group} is not available in this build"
        fi
    done
fi
echo

echo "Post-quantum authentication (separate from key establishment)"
if have "${OPENSSL_BIN}"; then
    if ${OPENSSL_BIN} list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA"; then
        pass "ML-DSA available: the experimental hybrid-pq-auth profile can be attempted"
    else
        skip "ML-DSA not available: post-quantum *authentication* is not possible here."
        skip "  This does not affect the hybrid key-establishment profiles."
    fi
fi
echo

echo "Optional experiment tooling"
for tool in tc tcpdump tshark docker; do
    if have "${tool}"; then
        pass "${tool}"
    else
        case "${tool}" in
            tc)      skip "tc (iproute2) missing: network-condition experiments unavailable" ;;
            tcpdump) skip "tcpdump missing: packet capture unavailable" ;;
            tshark)  skip "tshark missing: capture analysis unavailable" ;;
            docker)  skip "docker missing: containerised demo unavailable" ;;
        esac
    fi
done
echo

echo "Development certificates"
if [[ -f "${REPO_ROOT}/certs/classical/server.crt" && -f "${REPO_ROOT}/certs/classical/ca.crt" ]]; then
    if ${OPENSSL_BIN} verify -CAfile "${REPO_ROOT}/certs/classical/ca.crt" \
            "${REPO_ROOT}/certs/classical/server.crt" >/dev/null 2>&1; then
        NOT_AFTER="$(${OPENSSL_BIN} x509 -in "${REPO_ROOT}/certs/classical/server.crt" -noout -enddate | cut -d= -f2)"
        pass "development PKI present and valid (server certificate expires ${NOT_AFTER})"
    else
        fail "development certificates exist but do not verify - regenerate them"
    fi
else
    skip "no development certificates - run scripts/generate-classical-certs.sh"
fi
echo

echo "Summary"
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "  mandatory capabilities : all present"
else
    echo "  mandatory capabilities : ${FAILURES} MISSING"
fi
if [[ "${PQ_AVAILABLE}" -eq 1 ]]; then
    echo "  post-quantum profiles  : available"
else
    echo "  post-quantum profiles  : NOT available on this host"
    echo "                           PQ tests must be recorded as SKIP. Do not report them as PASS."
fi
echo

exit "${FAILURES}"
