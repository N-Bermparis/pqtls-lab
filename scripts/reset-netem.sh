#!/usr/bin/env bash
#
# reset-netem.sh - remove emulated network conditions applied by apply-netem.sh.
#
# Kept deliberately simple and dependency-free. This is the script someone runs
# when an experiment has made the network unusable, so it must work even when
# very little else does.
#
set -Eeuo pipefail

INTERFACE=""
RESTORE_MTU=1
ALL=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Remove netem shaping from an interface.

USAGE
  sudo scripts/reset-netem.sh --interface <iface>
  sudo scripts/reset-netem.sh --all

OPTIONS
  --interface <iface>  Interface to clear
  --all                Clear every interface that has a saved pqtls-lab state
  --keep-mtu           Do not restore the saved MTU
  --dry-run            Print what would happen
  -h, --help           This message
EOF
}

log() { printf '[netem] %s\n' "$*"; }
die() { printf '[netem] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface) INTERFACE="$2"; shift 2 ;;
        --all)       ALL=1; shift ;;
        --keep-mtu)  RESTORE_MTU=0; shift ;;
        --dry-run)   DRY_RUN=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "unknown option '$1'" ;;
    esac
done

[[ -n "${INTERFACE}" || "${ALL}" -eq 1 ]] || { usage; die "--interface or --all is required"; }

command -v tc >/dev/null 2>&1 || die "tc not found; install iproute2"

if [[ "${DRY_RUN}" -ne 1 && "$(id -u)" -ne 0 ]]; then
    die "modifying qdiscs requires root; re-run with sudo"
fi

STATE_DIR="/var/tmp/pqtls-netem"

reset_one() {
    local iface="$1"

    if ! ip link show "${iface}" >/dev/null 2>&1; then
        log "interface '${iface}' does not exist; skipping"
        return 0
    fi

    log "clearing the root qdisc on ${iface}"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[netem] DRY-RUN: tc qdisc del dev %s root\n' "${iface}"
    else
        # A missing qdisc is the desired end state, so a failure to delete one
        # that is not there is not an error.
        tc qdisc del dev "${iface}" root 2>/dev/null || true
    fi

    local state_file="${STATE_DIR}/${iface}.state"
    if [[ "${RESTORE_MTU}" -eq 1 && -f "${state_file}" ]]; then
        # shellcheck disable=SC1090
        local previous_mtu
        previous_mtu="$(grep '^PREVIOUS_MTU=' "${state_file}" | cut -d= -f2)"
        if [[ -n "${previous_mtu}" ]]; then
            log "restoring MTU ${previous_mtu} on ${iface}"
            if [[ "${DRY_RUN}" -eq 1 ]]; then
                printf '[netem] DRY-RUN: ip link set dev %s mtu %s\n' "${iface}" "${previous_mtu}"
            else
                ip link set dev "${iface}" mtu "${previous_mtu}" || true
            fi
        fi
    fi

    if [[ "${DRY_RUN}" -ne 1 ]]; then
        rm -f "${state_file}"
        log "configuration now on ${iface}:"
        tc qdisc show dev "${iface}" | sed 's/^/  /'
        ip link show "${iface}" | sed 's/^/  /'
    fi
}

if [[ "${ALL}" -eq 1 ]]; then
    shopt -s nullglob
    states=("${STATE_DIR}"/*.state)
    if [[ ${#states[@]} -eq 0 ]]; then
        log "no saved pqtls-lab netem state found; nothing to reset"
        exit 0
    fi
    for state in "${states[@]}"; do
        iface="$(basename "${state}" .state)"
        reset_one "${iface}"
    done
else
    reset_one "${INTERFACE}"
fi

log "reset complete"
