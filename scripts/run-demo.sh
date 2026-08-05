#!/usr/bin/env bash
#
# run-demo.sh - end-to-end demonstration: certificates, server, client.
#
# Runs the classical baseline and then, only if this OpenSSL supports it, the
# hybrid post-quantum profile. An unavailable hybrid profile is reported as a
# SKIP with the reason, never as a pass.
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_DIR="${REPO_ROOT}/build/relwithdebinfo"
PORT=18443
CERTS="${REPO_ROOT}/certs/classical"
RESULTS="${REPO_ROOT}/experiments/results"
SERVER_PID=""

usage() {
    cat <<'EOF'
Run the pqtls-lab demonstration.

USAGE
  scripts/run-demo.sh [options]

OPTIONS
  --build-dir <dir>   Build directory (default build/relwithdebinfo)
  --port <n>          Port for the demo server (default 18443)
  -h, --help          This message
EOF
}

log()  { printf '\n[demo] %s\n' "$*"; }
warn() { printf '[demo] WARNING: %s\n' "$*" >&2; }
die()  { printf '[demo] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --port)      PORT="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "unknown option '$1'" ;;
    esac
done

SERVER="${BUILD_DIR}/pqtls-server"
CLIENT="${BUILD_DIR}/pqtls-client"

[[ -x "${SERVER}" ]] || die "${SERVER} not found; run scripts/build.sh first"
[[ -x "${CLIENT}" ]] || die "${CLIENT} not found; run scripts/build.sh first"

cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "${RESULTS}"

# ---------------------------------------------------------------------------
log "1/5  Development certificates"
if [[ ! -f "${CERTS}/server.crt" ]]; then
    "${SCRIPT_DIR}/generate-classical-certs.sh"
else
    log "reusing the existing development PKI in ${CERTS}"
fi

# ---------------------------------------------------------------------------
log "2/5  Runtime capabilities"
"${CLIENT}" capabilities

# ---------------------------------------------------------------------------
run_profile() {
    local profile="$1" description="$2"

    log "${description}"

    # Ask the binary itself whether the profile is usable here. This is the
    # same detection the server performs, so the demo cannot claim a profile
    # works when the server would refuse to start with it.
    if ! "${CLIENT}" capabilities --json \
            | python3 -c "
import json,sys
caps = json.load(sys.stdin)
entry = next((p for p in caps['profiles'] if p['id'] == '${profile}'), None)
sys.exit(0 if entry and entry['usable'] else 1)
" 2>/dev/null; then
        warn "profile '${profile}' is NOT available on this host - SKIPPED"
        warn "  this is a skip, not a pass: the demonstration did not exercise it"
        "${CLIENT}" capabilities | grep -A1 "${profile}" || true
        return 0
    fi

    "${SERVER}" serve \
        --listen 127.0.0.1 \
        --port "${PORT}" \
        --profile "${profile}" \
        --certificate "${CERTS}/server.crt" \
        --private-key "${CERTS}/server.key" \
        --metrics "${RESULTS}/demo-server.jsonl" \
        --experiment-id "demo-${profile}" \
        --log-level info &
    SERVER_PID=$!

    # Wait for the listener rather than sleeping a fixed amount: a fixed sleep
    # is either too slow or flaky depending on the machine.
    for _ in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
            exec 3>&- 3<&-
            break
        fi
        sleep 0.1
    done

    "${CLIENT}" connect \
        --host 127.0.0.1 \
        --port "${PORT}" \
        --server-name localhost \
        --profile "${profile}" \
        --ca-certificate "${CERTS}/ca.crt" \
        --message '{"type":"capabilities"}' \
        --metrics "${RESULTS}/demo-client.jsonl" \
        --experiment-id "demo-${profile}"

    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
    SERVER_PID=""
}

log "3/5  Classical TLS 1.3 baseline"
run_profile "classical-x25519" "classical-x25519 (X25519, ECDSA P-256)"

log "4/5  Hybrid post-quantum key establishment"
run_profile "hybrid-x25519-mlkem768" "hybrid-x25519-mlkem768 (X25519 + ML-KEM-768, ECDSA P-256)"

# ---------------------------------------------------------------------------
log "5/5  Results"
if [[ -f "${RESULTS}/demo-client.jsonl" ]]; then
    log "client records written to ${RESULTS}/demo-client.jsonl"
    tail -n 2 "${RESULTS}/demo-client.jsonl"
    echo
    log "validate them with:"
    log "  python3 tools/result_validator.py ${RESULTS}/demo-client.jsonl"
fi

cat <<'EOF'

[demo] Reminder on what was and was not demonstrated:
[demo]   - The hybrid profile provides post-quantum KEY ESTABLISHMENT.
[demo]   - Server AUTHENTICATION used a classical ECDSA certificate.
[demo]   - The connection is therefore not end-to-end quantum-safe.
[demo]   See docs/security-profiles.md and docs/limitations.md.
EOF
