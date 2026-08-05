#!/usr/bin/env bash
#
# capture-packets.sh - capture pqtls-lab handshake traffic for analysis.
#
# ############################################################################
# #  A packet capture records real traffic. Capture only traffic you         #
# #  generated yourself on a host you control. Captures are git-ignored and  #
# #  must never be committed: even a TLS capture leaks addresses, timing,    #
# #  SNI values and certificate contents.                                    #
# ############################################################################
#
set -Eeuo pipefail

INTERFACE="lo"
PORT=8443
OUTPUT=""
DURATION=30
PACKET_LIMIT=0
SNAPLEN=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Capture pqtls-lab TLS traffic.

USAGE
  sudo scripts/capture-packets.sh --output captures/hybrid.pcap [options]

OPTIONS
  --interface <iface>  Interface to capture on (default lo)
  --port <n>           TCP port filter (default 8443)
  --output <path>      Destination .pcap (required)
  --duration <sec>     Stop after N seconds (default 30)
  --packets <n>        Stop after N packets (0 = unlimited)
  --snaplen <bytes>    Bytes per packet (0 = full packet, needed for size analysis)
  --dry-run            Print the command without running it
  -h, --help           This message

ANALYSIS
  python3 tools/pcap_metrics.py <capture.pcap>

NOTE
  The default snaplen of 0 captures whole packets, which is required to measure
  ClientHello and ServerHello sizes. A truncated capture silently produces
  wrong size figures rather than an error.
EOF
}

log()  { printf '[capture] %s\n' "$*"; }
warn() { printf '[capture] WARNING: %s\n' "$*" >&2; }
die()  { printf '[capture] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface) INTERFACE="$2"; shift 2 ;;
        --port)      PORT="$2"; shift 2 ;;
        --output)    OUTPUT="$2"; shift 2 ;;
        --duration)  DURATION="$2"; shift 2 ;;
        --packets)   PACKET_LIMIT="$2"; shift 2 ;;
        --snaplen)   SNAPLEN="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "unknown option '$1'" ;;
    esac
done

[[ -n "${OUTPUT}" ]] || { usage; die "--output is required"; }

command -v tcpdump >/dev/null 2>&1 || die "tcpdump not found; install it (apt install tcpdump)"

if [[ "${DRY_RUN}" -ne 1 && "$(id -u)" -ne 0 ]]; then
    die "packet capture requires root or CAP_NET_RAW; re-run with sudo"
fi

# Refuse to overwrite an existing capture: a benchmark run that silently
# replaced yesterday's capture would be unreproducible and unnoticed.
[[ -e "${OUTPUT}" ]] && die "'${OUTPUT}' already exists; choose another name or move it aside"

mkdir -p "$(dirname "${OUTPUT}")"

CMD=(tcpdump -i "${INTERFACE}" -w "${OUTPUT}" -s "${SNAPLEN}" -n "tcp port ${PORT}")
[[ "${PACKET_LIMIT}" -gt 0 ]] && CMD+=(-c "${PACKET_LIMIT}")

log "interface : ${INTERFACE}"
log "filter    : tcp port ${PORT}"
log "output    : ${OUTPUT}"
log "duration  : ${DURATION}s"
log "snaplen   : ${SNAPLEN} (0 = full packet)"
echo

if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[capture] DRY-RUN: timeout %s %s\n' "${DURATION}" "${CMD[*]}"
    exit 0
fi

warn "capturing only locally generated test traffic - do not commit the result"
log "starting capture; run the client now"

# `|| true`: timeout kills tcpdump with SIGTERM, which is a non-zero exit and
# is exactly what we asked for.
timeout "${DURATION}" "${CMD[@]}" || true

if [[ -f "${OUTPUT}" ]]; then
    log "captured $(du -h "${OUTPUT}" | cut -f1) to ${OUTPUT}"
    log "analyse with: python3 tools/pcap_metrics.py ${OUTPUT}"
else
    die "no capture file was produced"
fi
