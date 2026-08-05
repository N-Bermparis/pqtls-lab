#!/usr/bin/env bash
#
# apply-netem.sh - apply emulated network conditions with `tc netem`.
#
# ############################################################################
# #  THIS SCRIPT CHANGES KERNEL NETWORK BEHAVIOUR ON A REAL INTERFACE.       #
# #                                                                         #
# #  Applying delay or loss to the interface carrying your SSH session will #
# #  degrade or drop that session. There is no undo other than               #
# #  scripts/reset-netem.sh, which you should be able to run locally.        #
# #  Prefer a dedicated veth pair, a VM, or the loopback interface.          #
# ############################################################################
#
set -Eeuo pipefail

INTERFACE=""
DELAY=""
JITTER=""
LOSS=""
LOSS_CORRELATION=""
DUPLICATE=""
REORDER=""
RATE=""
MTU=""
DRY_RUN=0
ASSUME_YES=0

usage() {
    cat <<'EOF'
Apply emulated network conditions for pqtls-lab experiments.

USAGE
  sudo scripts/apply-netem.sh --interface <iface> [conditions]

REQUIRED
  --interface <iface>    Interface to shape. No default: naming it is deliberate.

CONDITIONS
  --delay <time>         One-way delay, e.g. 20ms, 100ms, 250ms
  --jitter <time>        Delay variation, e.g. 5ms (requires --delay)
  --loss <percent>       Packet loss, e.g. 0.5%, 1%, 5%
  --loss-correlation <p> Burst-loss correlation, e.g. 25%
  --duplicate <percent>  Packet duplication, e.g. 1%
  --reorder <percent>    Packet reordering, e.g. 5% (requires --delay)
  --rate <rate>          Bandwidth cap, e.g. 128kbit, 1mbit, 10mbit, 100mbit
  --mtu <bytes>          Interface MTU, e.g. 576, 1280, 1500, 9000

OTHER
  --dry-run              Print the commands without running them
  -y, --yes              Skip the confirmation prompt
  -h, --help             This message

EXAMPLES
  sudo scripts/apply-netem.sh --interface lo --delay 50ms
  sudo scripts/apply-netem.sh --interface lo --loss 1% --delay 20ms --jitter 5ms
  sudo scripts/apply-netem.sh --interface eth0 --rate 1mbit --mtu 1280

RESET
  sudo scripts/reset-netem.sh --interface <iface>

NOTE ON LOOPBACK
  netem delay on `lo` is applied to the egress path only, so a round trip over
  loopback sees roughly the configured delay once, not twice. Say which
  convention you used when you report results.
EOF
}

log()  { printf '[netem] %s\n' "$*"; }
warn() { printf '[netem] WARNING: %s\n' "$*" >&2; }
die()  { printf '[netem] ERROR: %s\n' "$*" >&2; exit 1; }

run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[netem] DRY-RUN: %s\n' "$*"
    else
        log "running: $*"
        "$@"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface)        INTERFACE="$2"; shift 2 ;;
        --delay)            DELAY="$2"; shift 2 ;;
        --jitter)           JITTER="$2"; shift 2 ;;
        --loss)             LOSS="$2"; shift 2 ;;
        --loss-correlation) LOSS_CORRELATION="$2"; shift 2 ;;
        --duplicate)        DUPLICATE="$2"; shift 2 ;;
        --reorder)          REORDER="$2"; shift 2 ;;
        --rate)             RATE="$2"; shift 2 ;;
        --mtu)              MTU="$2"; shift 2 ;;
        --dry-run)          DRY_RUN=1; shift ;;
        -y|--yes)           ASSUME_YES=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  die "unknown option '$1' (try --help)" ;;
    esac
done

# The interface is mandatory and has no default. Guessing it, or defaulting to
# the primary interface, is how someone shapes the link carrying their own
# remote session.
[[ -n "${INTERFACE}" ]] || { usage; die "--interface is required"; }

command -v tc >/dev/null 2>&1 || die "tc not found; install iproute2"
command -v ip >/dev/null 2>&1 || die "ip not found; install iproute2"

ip link show "${INTERFACE}" >/dev/null 2>&1 \
    || die "interface '${INTERFACE}' does not exist. Available: $(ip -brief link show | awk '{print $1}' | tr '\n' ' ')"

if [[ "${DRY_RUN}" -ne 1 && "$(id -u)" -ne 0 ]]; then
    die "modifying qdiscs requires root; re-run with sudo (or use --dry-run)"
fi

[[ -n "${JITTER}"  && -z "${DELAY}" ]] && die "--jitter requires --delay"
[[ -n "${REORDER}" && -z "${DELAY}" ]] && die "--reorder requires --delay: netem reorders relative to the delay"

# --- Warn loudly when the interface carries the default route ---------------
DEFAULT_INTERFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
if [[ -n "${DEFAULT_INTERFACE}" && "${INTERFACE}" == "${DEFAULT_INTERFACE}" ]]; then
    warn "'${INTERFACE}' carries the default route."
    warn "Shaping it will affect ALL traffic on this host, including any remote"
    warn "session you are using right now."
    if [[ "${ASSUME_YES}" -ne 1 && "${DRY_RUN}" -ne 1 ]]; then
        read -r -p "[netem] Type the interface name again to confirm: " CONFIRM
        [[ "${CONFIRM}" == "${INTERFACE}" ]] || die "confirmation did not match; nothing was changed"
    fi
fi

# --- Save the current state so it can be reported and restored --------------
STATE_DIR="/var/tmp/pqtls-netem"
STATE_FILE="${STATE_DIR}/${INTERFACE}.state"
if [[ "${DRY_RUN}" -ne 1 ]]; then
    mkdir -p "${STATE_DIR}"
    {
        echo "# pqtls-lab netem state for ${INTERFACE}, saved $(date -Iseconds)"
        echo "PREVIOUS_MTU=$(ip link show "${INTERFACE}" | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu") print $(i+1)}')"
        echo "# previous qdisc:"
        tc qdisc show dev "${INTERFACE}" | sed 's/^/# /'
    } > "${STATE_FILE}"
    log "previous configuration saved to ${STATE_FILE}"
fi

log "current qdisc on ${INTERFACE}:"
tc qdisc show dev "${INTERFACE}" | sed 's/^/  /'

# --- Clear any existing root qdisc ------------------------------------------
# `|| true`: there may be no root qdisc to delete, which is not an error here.
if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[netem] DRY-RUN: tc qdisc del dev %s root\n' "${INTERFACE}"
else
    tc qdisc del dev "${INTERFACE}" root 2>/dev/null || true
fi

# --- Build the netem argument list ------------------------------------------
NETEM_ARGS=()
[[ -n "${DELAY}" ]] && { NETEM_ARGS+=(delay "${DELAY}"); [[ -n "${JITTER}" ]] && NETEM_ARGS+=("${JITTER}"); }
if [[ -n "${LOSS}" ]]; then
    NETEM_ARGS+=(loss "${LOSS}")
    [[ -n "${LOSS_CORRELATION}" ]] && NETEM_ARGS+=("${LOSS_CORRELATION}")
fi
[[ -n "${DUPLICATE}" ]] && NETEM_ARGS+=(duplicate "${DUPLICATE}")
[[ -n "${REORDER}" ]]   && NETEM_ARGS+=(reorder "${REORDER}")
[[ -n "${RATE}" ]]      && NETEM_ARGS+=(rate "${RATE}")

if [[ ${#NETEM_ARGS[@]} -gt 0 ]]; then
    run tc qdisc add dev "${INTERFACE}" root netem "${NETEM_ARGS[@]}"
else
    log "no netem conditions requested"
fi

if [[ -n "${MTU}" ]]; then
    run ip link set dev "${INTERFACE}" mtu "${MTU}"
fi

echo
log "active configuration on ${INTERFACE}:"
if [[ "${DRY_RUN}" -ne 1 ]]; then
    tc qdisc show dev "${INTERFACE}" | sed 's/^/  /'
    ip link show "${INTERFACE}" | sed 's/^/  /'
fi

echo
log "record these settings alongside the experiment results:"
printf '  interface=%s delay=%s jitter=%s loss=%s rate=%s mtu=%s\n' \
    "${INTERFACE}" "${DELAY:-none}" "${JITTER:-none}" "${LOSS:-none}" "${RATE:-none}" "${MTU:-unchanged}"
log "reset with: sudo scripts/reset-netem.sh --interface ${INTERFACE}"
