#!/usr/bin/env bash
#
# generate-pq-certs.sh - EXPERIMENTAL post-quantum authentication certificates.
#
# ############################################################################
# #  EXPERIMENTAL. CAPABILITY-GATED. NOT A DEPLOYMENT PATH.                  #
# #                                                                         #
# #  This produces ML-DSA-65 keys and certificates for MEASUREMENT: how      #
# #  large are post-quantum certificates and signatures, and does the TLS    #
# #  stack negotiate them at all (RQ5).                                      #
# #                                                                         #
# #  No public certificate authority issues ML-DSA certificates for general  #
# #  use. Nothing here is interoperable with the public web PKI. If the      #
# #  pinned OpenSSL cannot do ML-DSA, this script SKIPS with a reason and    #
# #  exits 0 - it never fakes success.                                       #
# ############################################################################
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${REPO_ROOT}/certs/experimental-pq"
ALGORITHM="ML-DSA-65"
DAYS=365
FORCE=0
MEASURE=1
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

usage() {
    cat <<'EOF'
Generate EXPERIMENTAL post-quantum authentication certificates.

USAGE
  scripts/generate-pq-certs.sh [options]

OPTIONS
  --output-dir <dir>   Destination (default certs/experimental-pq)
  --algorithm <name>   ML-DSA-44 | ML-DSA-65 (default) | ML-DSA-87
  --days <n>           Validity in days (default 365)
  --force              Overwrite existing keys (refused by default)
  --no-measure         Skip the size measurement step
  --openssl <path>     OpenSSL binary to use
  -h, --help           This message

EXIT CODES
  0  certificates generated, OR the capability is absent and the run was skipped
  1  the capability is present but generation failed

WHY SKIP RATHER THAN FAIL
  ML-DSA support depends on the OpenSSL build. Reporting "not available here"
  is an honest outcome; reporting a pass would not be. Check the printed
  status, and see docs/pqc-standards-status.md.
EOF
}

log()  { printf '[pq-certs] %s\n' "$*"; }
warn() { printf '[pq-certs] WARNING: %s\n' "$*" >&2; }
skip() { printf '[pq-certs] SKIPPED: %s\n' "$*" >&2; }
die()  { printf '[pq-certs] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --algorithm)  ALGORITHM="$2"; shift 2 ;;
        --days)       DAYS="$2"; shift 2 ;;
        --force)      FORCE=1; shift ;;
        --no-measure) MEASURE=0; shift ;;
        --openssl)    OPENSSL_BIN="$2"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        *)            die "unknown option '$1'" ;;
    esac
done

case "${ALGORITHM}" in
    ML-DSA-44|ML-DSA-65|ML-DSA-87) ;;
    *) die "unsupported algorithm '${ALGORITHM}'; use ML-DSA-44, ML-DSA-65 or ML-DSA-87" ;;
esac

command -v "${OPENSSL_BIN}" >/dev/null 2>&1 || die "openssl not found"

OPENSSL_VERSION_TEXT="$("${OPENSSL_BIN}" version)"
log "openssl: ${OPENSSL_VERSION_TEXT}"

# --- Capability gate --------------------------------------------------------
#
# Probe by actually generating a key. A name appearing in `openssl list` does
# not prove the provider can instantiate it.
log "probing for ${ALGORITHM} support"
PROBE_DIR="$(mktemp -d)"
trap 'rm -rf "${PROBE_DIR}"' EXIT

if ! "${OPENSSL_BIN}" genpkey -algorithm "${ALGORITHM}" \
        -out "${PROBE_DIR}/probe.key" >/dev/null 2>&1; then
    skip "this OpenSSL build cannot generate ${ALGORITHM} keys."
    skip ""
    skip "  Post-quantum AUTHENTICATION is therefore unavailable on this host."
    skip "  This does NOT affect the hybrid key-establishment profiles, which"
    skip "  depend on ML-KEM and are reported separately."
    skip ""
    skip "  Check with:  pqtls-client capabilities"
    skip "  Background:  docs/pqc-standards-status.md"
    exit 0
fi
log "${ALGORITHM} is available"

mkdir -p "${OUTPUT_DIR}"

for existing in pq-ca.key pq-server.key; do
    if [[ -f "${OUTPUT_DIR}/${existing}" && "${FORCE}" -ne 1 ]]; then
        die "${OUTPUT_DIR}/${existing} already exists. Pass --force to overwrite it deliberately."
    fi
done

umask 077

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${PROBE_DIR}" "${TMP_DIR}"' EXIT

# ---------------------------------------------------------------------------
# Post-quantum CA
# ---------------------------------------------------------------------------
log "generating the ${ALGORITHM} CA key"
"${OPENSSL_BIN}" genpkey -algorithm "${ALGORITHM}" -out "${OUTPUT_DIR}/pq-ca.key" >/dev/null 2>&1

cat > "${TMP_DIR}/pq-ca.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca

[dn]
C  = GR
O  = pqtls-lab EXPERIMENTAL post-quantum
CN = pqtls-lab experimental ${ALGORITHM} CA

[v3_ca]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

log "self-signing the ${ALGORITHM} CA certificate"
# ML-DSA is its own signature algorithm; no -sha256 is passed, because the
# digest is part of the scheme rather than a separate choice.
"${OPENSSL_BIN}" req -x509 -new \
    -key "${OUTPUT_DIR}/pq-ca.key" \
    -days "${DAYS}" \
    -config "${TMP_DIR}/pq-ca.cnf" \
    -out "${OUTPUT_DIR}/pq-ca.crt"

# ---------------------------------------------------------------------------
# Post-quantum server certificate
# ---------------------------------------------------------------------------
log "generating the ${ALGORITHM} server key"
"${OPENSSL_BIN}" genpkey -algorithm "${ALGORITHM}" \
    -out "${OUTPUT_DIR}/pq-server.key" >/dev/null 2>&1

cat > "${TMP_DIR}/pq-server.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt             = no

[dn]
C  = GR
O  = pqtls-lab EXPERIMENTAL post-quantum
CN = localhost
EOF

cat > "${TMP_DIR}/pq-server.ext" <<'EOF'
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName         = DNS:localhost,DNS:pqtls-server,IP:127.0.0.1
EOF

"${OPENSSL_BIN}" req -new \
    -key "${OUTPUT_DIR}/pq-server.key" \
    -config "${TMP_DIR}/pq-server.cnf" \
    -out "${TMP_DIR}/pq-server.csr"

log "signing the ${ALGORITHM} server certificate"
"${OPENSSL_BIN}" x509 -req \
    -in "${TMP_DIR}/pq-server.csr" \
    -CA "${OUTPUT_DIR}/pq-ca.crt" \
    -CAkey "${OUTPUT_DIR}/pq-ca.key" \
    -CAcreateserial -CAserial "${TMP_DIR}/pq.srl" \
    -days "${DAYS}" \
    -extfile "${TMP_DIR}/pq-server.ext" \
    -out "${OUTPUT_DIR}/pq-server.crt" 2>/dev/null

chmod 600 "${OUTPUT_DIR}"/*.key
chmod 644 "${OUTPUT_DIR}"/*.crt

log "verifying the experimental chain"
"${OPENSSL_BIN}" verify -CAfile "${OUTPUT_DIR}/pq-ca.crt" "${OUTPUT_DIR}/pq-server.crt"

# ---------------------------------------------------------------------------
# Size measurement (RQ5)
# ---------------------------------------------------------------------------
if [[ "${MEASURE}" -eq 1 ]]; then
    log ""
    log "size measurement (RQ5)"

    MEASUREMENT_FILE="${OUTPUT_DIR}/size-measurements.json"

    pq_ca_size=$(wc -c < "${OUTPUT_DIR}/pq-ca.crt")
    pq_server_size=$(wc -c < "${OUTPUT_DIR}/pq-server.crt")
    pq_key_size=$(wc -c < "${OUTPUT_DIR}/pq-server.key")

    pq_server_der=$("${OPENSSL_BIN}" x509 -in "${OUTPUT_DIR}/pq-server.crt" -outform DER 2>/dev/null | wc -c)
    pq_ca_der=$("${OPENSSL_BIN}" x509 -in "${OUTPUT_DIR}/pq-ca.crt" -outform DER 2>/dev/null | wc -c)

    classical_server_der="null"
    classical_ca_der="null"
    if [[ -f "${REPO_ROOT}/certs/classical/server.crt" ]]; then
        classical_server_der=$("${OPENSSL_BIN}" x509 -in "${REPO_ROOT}/certs/classical/server.crt" \
            -outform DER 2>/dev/null | wc -c)
        classical_ca_der=$("${OPENSSL_BIN}" x509 -in "${REPO_ROOT}/certs/classical/ca.crt" \
            -outform DER 2>/dev/null | wc -c)
    fi

    cat > "${MEASUREMENT_FILE}" <<EOF
{
  "schema_version": 1,
  "measured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "openssl_version": "${OPENSSL_VERSION_TEXT}",
  "algorithm": "${ALGORITHM}",
  "note": "DER sizes are the ones that matter on the wire; PEM adds base64 overhead. Classical figures are null when no classical PKI has been generated.",
  "post_quantum": {
    "ca_certificate_der_bytes": ${pq_ca_der},
    "server_certificate_der_bytes": ${pq_server_der},
    "ca_certificate_pem_bytes": ${pq_ca_size},
    "server_certificate_pem_bytes": ${pq_server_size},
    "server_private_key_pem_bytes": ${pq_key_size}
  },
  "classical_ecdsa_p256": {
    "ca_certificate_der_bytes": ${classical_ca_der},
    "server_certificate_der_bytes": ${classical_server_der}
  }
}
EOF

    log "  ${ALGORITHM} server certificate : ${pq_server_der} bytes (DER)"
    if [[ "${classical_server_der}" != "null" ]]; then
        log "  ECDSA P-256 server certificate : ${classical_server_der} bytes (DER)"
    else
        log "  ECDSA P-256 comparison         : not measured (no classical PKI present)"
    fi
    log "  measurements written to ${MEASUREMENT_FILE}"
fi

log ""
warn "EXPERIMENTAL material. These certificates chain to a private ML-DSA CA and are"
warn "not accepted by anything outside this project. Use them with the capability-gated"
warn "'hybrid-pq-auth' profile only, and read docs/limitations.md before drawing"
warn "conclusions from any measurement taken with them."
