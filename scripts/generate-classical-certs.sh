#!/usr/bin/env bash
#
# generate-classical-certs.sh - development PKI for pqtls-lab.
#
# Creates an ECDSA P-256 (or P-384) development CA, a server certificate and an
# optional client certificate for mutual TLS.
#
# ############################################################################
# #  THE CERTIFICATES PRODUCED HERE ARE FOR LOCAL DEVELOPMENT AND RESEARCH.  #
# #  The CA private key sits unencrypted next to the certificates it signs.  #
# #  Do not use any of this material outside a test environment, and never   #
# #  commit it: certs/ is git-ignored for exactly this reason.               #
# ############################################################################
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${REPO_ROOT}/certs/classical"
CURVE="prime256v1"
DIGEST="sha256"
DAYS=365
FORCE=0
WITH_CLIENT=0
EXTRA_SANS=""
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

usage() {
    cat <<'EOF'
Generate a development PKI for pqtls-lab.

USAGE
  scripts/generate-classical-certs.sh [options]

OPTIONS
  --output-dir <dir>   Destination (default certs/classical)
  --curve <name>       prime256v1 (P-256, default) or secp384r1 (P-384)
  --days <n>           Validity in days (default 365)
  --with-client        Also issue a client certificate for mutual TLS
  --extra-san <list>   Additional SANs, comma separated, e.g.
                       "DNS:pqtls-server,IP:10.0.0.5"
  --force              Overwrite existing keys (refused by default)
  --openssl <path>     OpenSSL binary to use
  -h, --help           This message

OUTPUT
  ca.key ca.crt                 development certificate authority
  server.key server.crt         server certificate, SAN localhost + 127.0.0.1 + ::1
  client.key client.crt         client certificate (only with --with-client)

NOTES
  The P-384 curve pairs with the hybrid-p384-mlkem1024 profile, which expects
  ECDSA P-384 authentication. Every other profile expects P-256.
EOF
}

log()  { printf '[certs] %s\n' "$*"; }
warn() { printf '[certs] WARNING: %s\n' "$*" >&2; }
die()  { printf '[certs] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --curve)      CURVE="$2"; shift 2 ;;
        --days)       DAYS="$2"; shift 2 ;;
        --with-client) WITH_CLIENT=1; shift ;;
        --extra-san)  EXTRA_SANS="$2"; shift 2 ;;
        --force)      FORCE=1; shift ;;
        --openssl)    OPENSSL_BIN="$2"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        *)            die "unknown option '$1' (try --help)" ;;
    esac
done

case "${CURVE}" in
    prime256v1) DIGEST="sha256" ;;
    secp384r1)  DIGEST="sha384" ;;
    *) die "unsupported curve '${CURVE}'; use prime256v1 or secp384r1" ;;
esac

command -v "${OPENSSL_BIN}" >/dev/null 2>&1 || die "openssl not found (looked for '${OPENSSL_BIN}')"

OPENSSL_VERSION="$("${OPENSSL_BIN}" version)"
log "using ${OPENSSL_BIN}: ${OPENSSL_VERSION}"

mkdir -p "${OUTPUT_DIR}"

# --- Refuse to clobber existing private keys unless told to -----------------
#
# Overwriting a key silently is how a running server ends up with a certificate
# that no longer matches its key. The check is on the key, not the certificate,
# because the key is the part that cannot be regenerated from anything else.
for existing in ca.key server.key client.key; do
    if [[ -f "${OUTPUT_DIR}/${existing}" && "${FORCE}" -ne 1 ]]; then
        die "${OUTPUT_DIR}/${existing} already exists. Pass --force to overwrite it deliberately."
    fi
done

umask 077   # Every file created below starts owner-only.

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Certificate authority
# ---------------------------------------------------------------------------
log "generating the development CA key (${CURVE})"
"${OPENSSL_BIN}" genpkey \
    -algorithm EC \
    -pkeyopt "ec_paramgen_curve:${CURVE}" \
    -pkeyopt ec_param_enc:named_curve \
    -out "${OUTPUT_DIR}/ca.key" >/dev/null 2>&1

cat > "${TMP_DIR}/ca.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca

[dn]
C  = GR
O  = pqtls-lab development
CN = pqtls-lab development CA

[v3_ca]
basicConstraints       = critical, CA:TRUE, pathlen:1
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

log "self-signing the CA certificate (${DAYS} days)"
"${OPENSSL_BIN}" req -x509 -new \
    -key "${OUTPUT_DIR}/ca.key" \
    -"${DIGEST}" \
    -days "${DAYS}" \
    -config "${TMP_DIR}/ca.cnf" \
    -out "${OUTPUT_DIR}/ca.crt"

# ---------------------------------------------------------------------------
# Leaf certificate helper
# ---------------------------------------------------------------------------
issue_leaf() {
    local name="$1" cn="$2" eku="$3" san="$4"

    log "generating the ${name} key (${CURVE})"
    "${OPENSSL_BIN}" genpkey \
        -algorithm EC \
        -pkeyopt "ec_paramgen_curve:${CURVE}" \
        -pkeyopt ec_param_enc:named_curve \
        -out "${OUTPUT_DIR}/${name}.key" >/dev/null 2>&1

    cat > "${TMP_DIR}/${name}.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no

[dn]
C  = GR
O  = pqtls-lab development
CN = ${cn}
EOF

    cat > "${TMP_DIR}/${name}.ext" <<EOF
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = ${eku}
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName         = ${san}
EOF

    "${OPENSSL_BIN}" req -new \
        -key "${OUTPUT_DIR}/${name}.key" \
        -"${DIGEST}" \
        -config "${TMP_DIR}/${name}.cnf" \
        -out "${TMP_DIR}/${name}.csr"

    log "signing the ${name} certificate"
    "${OPENSSL_BIN}" x509 -req \
        -in "${TMP_DIR}/${name}.csr" \
        -CA "${OUTPUT_DIR}/ca.crt" \
        -CAkey "${OUTPUT_DIR}/ca.key" \
        -CAcreateserial \
        -CAserial "${TMP_DIR}/${name}.srl" \
        -"${DIGEST}" \
        -days "${DAYS}" \
        -extfile "${TMP_DIR}/${name}.ext" \
        -out "${OUTPUT_DIR}/${name}.crt" 2>/dev/null
}

# SANs must cover every name a client might verify against. Both the DNS name
# and the literal addresses are listed because the integration tests connect to
# 127.0.0.1 directly, and a certificate without an IP SAN fails that check.
SERVER_SAN="DNS:localhost,DNS:pqtls-server,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1"
if [[ -n "${EXTRA_SANS}" ]]; then
    SERVER_SAN="${SERVER_SAN},${EXTRA_SANS}"
fi

issue_leaf "server" "localhost" "serverAuth" "${SERVER_SAN}"

if [[ "${WITH_CLIENT}" -eq 1 ]]; then
    issue_leaf "client" "pqtls-lab test client" "clientAuth" "DNS:pqtls-client"
fi

# ---------------------------------------------------------------------------
# Permissions and verification
# ---------------------------------------------------------------------------
chmod 600 "${OUTPUT_DIR}"/*.key
chmod 644 "${OUTPUT_DIR}"/*.crt

log "verifying the generated chain"
"${OPENSSL_BIN}" verify -CAfile "${OUTPUT_DIR}/ca.crt" "${OUTPUT_DIR}/server.crt"
if [[ "${WITH_CLIENT}" -eq 1 ]]; then
    "${OPENSSL_BIN}" verify -CAfile "${OUTPUT_DIR}/ca.crt" -purpose sslclient \
        "${OUTPUT_DIR}/client.crt"
fi

# Confirm the SANs really made it into the certificate. A silently missing SAN
# turns into a confusing hostname-verification failure much later.
if ! "${OPENSSL_BIN}" x509 -in "${OUTPUT_DIR}/server.crt" -noout -text \
        | grep -q "DNS:localhost"; then
    die "the server certificate has no 'DNS:localhost' subjectAltName; hostname verification would fail"
fi

log ""
log "development PKI written to ${OUTPUT_DIR}"
log "  CA          : ca.crt / ca.key"
log "  server      : server.crt / server.key"
[[ "${WITH_CLIENT}" -eq 1 ]] && log "  client      : client.crt / client.key"
log "  SANs        : ${SERVER_SAN}"
log "  validity    : ${DAYS} days"
log "  curve       : ${CURVE} (${DIGEST})"
log ""
warn "these keys are unencrypted development material - never commit them and never deploy them"
