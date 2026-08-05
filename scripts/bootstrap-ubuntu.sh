#!/usr/bin/env bash
#
# bootstrap-ubuntu.sh - install the build dependencies for pqtls-lab on Ubuntu
# or WSL, and optionally build a pinned OpenSSL 3.5.x into /opt.
#
# The distribution OpenSSL is used when it is new enough. Ubuntu 24.04 ships
# 3.0.x, which has no ML-KEM and no hybrid TLS groups, so the post-quantum
# profiles need the pinned build. That build is installed into its own prefix
# and is never allowed to replace the system OpenSSL: overwriting the system
# libssl would affect every program on the machine, including ssh and apt.
#
set -Eeuo pipefail

# Pinned OpenSSL release. The checksum is the value published alongside the
# release tarball; see docker/openssl-checksums.txt for provenance and for the
# date it was last confirmed. Never replace this with a floating version.
OPENSSL_VERSION="3.5.7"
OPENSSL_SHA256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
OPENSSL_PREFIX="/opt/openssl-${OPENSSL_VERSION}"
MIN_PQ_VERSION="3.5.0"

BUILD_OPENSSL=auto
ASSUME_YES=0
JOBS="$(nproc 2>/dev/null || echo 2)"

usage() {
    cat <<'EOF'
Install pqtls-lab build dependencies on Ubuntu / WSL.

USAGE
  scripts/bootstrap-ubuntu.sh [options]

OPTIONS
  --build-openssl        Always build the pinned OpenSSL into /opt
  --no-build-openssl     Never build it; use whatever the distribution provides
  --jobs <n>             Parallel make jobs (default: nproc)
  -y, --yes              Do not prompt before installing packages
  -h, --help             This message

By default the pinned OpenSSL is built only when the system one is older than
3.5.0, i.e. only when it is actually needed for the post-quantum profiles.
EOF
}

log()  { printf '[bootstrap] %s\n' "$*"; }
warn() { printf '[bootstrap] WARNING: %s\n' "$*" >&2; }
die()  { printf '[bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-openssl)    BUILD_OPENSSL=yes; shift ;;
        --no-build-openssl) BUILD_OPENSSL=no; shift ;;
        --jobs)             JOBS="$2"; shift 2 ;;
        -y|--yes)           ASSUME_YES=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  die "unknown option '$1'" ;;
    esac
done

[[ -f /etc/os-release ]] || die "this script targets Ubuntu / Debian systems"
# shellcheck disable=SC1091
. /etc/os-release
log "detected ${PRETTY_NAME:-unknown} on $(uname -m)"

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "not running as root and sudo is not available"
    SUDO="sudo"
fi

APT_FLAGS=""
[[ "${ASSUME_YES}" -eq 1 ]] && APT_FLAGS="-y"

log "installing build dependencies"
${SUDO} apt-get update
# shellcheck disable=SC2086
${SUDO} apt-get install ${APT_FLAGS} \
    build-essential \
    cmake \
    ninja-build \
    git \
    pkg-config \
    perl \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    libssl-dev \
    iproute2 \
    tcpdump \
    tshark \
    clang-tidy \
    cppcheck

version_ge() {
    # Returns success when $1 >= $2 under version ordering.
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

SYSTEM_OPENSSL="$(openssl version | awk '{print $2}' | sed 's/[a-z]*$//')"
log "system OpenSSL: ${SYSTEM_OPENSSL}"

NEED_OPENSSL=0
if [[ "${BUILD_OPENSSL}" == "yes" ]]; then
    NEED_OPENSSL=1
elif [[ "${BUILD_OPENSSL}" == "auto" ]]; then
    if version_ge "${SYSTEM_OPENSSL}" "${MIN_PQ_VERSION}"; then
        log "system OpenSSL is new enough for the post-quantum profiles"
    else
        warn "system OpenSSL ${SYSTEM_OPENSSL} is older than ${MIN_PQ_VERSION}:"
        warn "  the hybrid and pure post-quantum profiles will be UNAVAILABLE."
        warn "  Building the pinned OpenSSL ${OPENSSL_VERSION} into ${OPENSSL_PREFIX}."
        NEED_OPENSSL=1
    fi
fi

if [[ "${NEED_OPENSSL}" -eq 1 ]]; then
    if [[ -x "${OPENSSL_PREFIX}/bin/openssl" ]]; then
        log "pinned OpenSSL already present at ${OPENSSL_PREFIX}"
    else
        WORK_DIR="$(mktemp -d)"
        trap 'rm -rf "${WORK_DIR}"' EXIT

        TARBALL="openssl-${OPENSSL_VERSION}.tar.gz"
        URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${TARBALL}"

        log "downloading ${URL}"
        curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK_DIR}/${TARBALL}" "${URL}"

        # Verify before extracting, not after. An archive that fails this check
        # is never unpacked, let alone compiled and installed.
        log "verifying the source archive checksum"
        echo "${OPENSSL_SHA256}  ${WORK_DIR}/${TARBALL}" | sha256sum -c - \
            || die "checksum mismatch for ${TARBALL}: refusing to build. Expected ${OPENSSL_SHA256}."

        log "building OpenSSL ${OPENSSL_VERSION} (this takes a while; longer on a Raspberry Pi)"
        tar -xzf "${WORK_DIR}/${TARBALL}" -C "${WORK_DIR}"
        pushd "${WORK_DIR}/openssl-${OPENSSL_VERSION}" >/dev/null

        ./Configure \
            --prefix="${OPENSSL_PREFIX}" \
            --openssldir="${OPENSSL_PREFIX}/ssl" \
            --libdir=lib \
            shared \
            no-ssl3 no-weak-ssl-ciphers

        make -j"${JOBS}"
        # install_sw skips the man pages, which are large and irrelevant here.
        ${SUDO} make install_sw

        popd >/dev/null
    fi

    log ""
    log "pinned OpenSSL installed to ${OPENSSL_PREFIX}"
    log "configure the project against it with:"
    log "  cmake -S . -B build -DOPENSSL_ROOT_DIR=${OPENSSL_PREFIX}"
    log "and run the binaries with:"
    log "  LD_LIBRARY_PATH=${OPENSSL_PREFIX}/lib ./build/pqtls-client capabilities"
    log ""
    warn "${OPENSSL_PREFIX} is a private prefix. The system OpenSSL is untouched;"
    warn "do not add it to /etc/ld.so.conf.d, or every program on the host would"
    warn "silently start using it."
fi

log "installing Python tooling for the benchmark scripts"
python3 -m pip install --user --upgrade pytest jsonschema 2>/dev/null \
    || warn "pip install failed; run 'python3 -m pip install --user pytest jsonschema' manually"

log ""
log "bootstrap complete. Next:"
log "  scripts/verify-environment.sh"
log "  scripts/generate-classical-certs.sh"
log "  scripts/build.sh"
