#!/usr/bin/env bash
#
# build.sh - configure and build pqtls-lab.
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_TYPE="RelWithDebInfo"
BUILD_DIR=""
OPENSSL_ROOT="${OPENSSL_ROOT_DIR:-}"
RUN_TESTS=0
SANITIZERS=""
WERROR="OFF"
CLANG_TIDY="OFF"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
CLEAN=0

usage() {
    cat <<'EOF'
Configure and build pqtls-lab.

USAGE
  scripts/build.sh [options]

OPTIONS
  --debug                Debug build
  --release              Release build
  --build-dir <dir>      Build directory (default build/<lowercase build type>)
  --openssl-root <dir>   OpenSSL prefix, e.g. /opt/openssl-3.5.4
  --sanitize <list>      Comma separated: address,undefined,thread
  --werror               Treat compiler warnings as errors
  --clang-tidy           Run clang-tidy during the build
  --test                 Run ctest after building
  --clean                Delete the build directory first
  --jobs <n>             Parallel build jobs
  -h, --help             This message

NOTES
  ThreadSanitizer cannot be combined with AddressSanitizer; use a separate
  build directory for it.
EOF
}

log() { printf '[build] %s\n' "$*"; }
die() { printf '[build] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)        BUILD_TYPE="Debug"; shift ;;
        --release)      BUILD_TYPE="Release"; shift ;;
        --build-dir)    BUILD_DIR="$2"; shift 2 ;;
        --openssl-root) OPENSSL_ROOT="$2"; shift 2 ;;
        --sanitize)     SANITIZERS="$2"; shift 2 ;;
        --werror)       WERROR="ON"; shift ;;
        --clang-tidy)   CLANG_TIDY="ON"; shift ;;
        --test)         RUN_TESTS=1; shift ;;
        --clean)        CLEAN=1; shift ;;
        --jobs)         JOBS="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown option '$1'" ;;
    esac
done

if [[ -z "${BUILD_DIR}" ]]; then
    BUILD_DIR="${REPO_ROOT}/build/$(echo "${BUILD_TYPE}" | tr '[:upper:]' '[:lower:]')"
fi

ASAN=OFF; UBSAN=OFF; TSAN=OFF
if [[ -n "${SANITIZERS}" ]]; then
    IFS=',' read -ra REQUESTED <<< "${SANITIZERS}"
    for sanitizer in "${REQUESTED[@]}"; do
        case "${sanitizer}" in
            address)   ASAN=ON ;;
            undefined) UBSAN=ON ;;
            thread)    TSAN=ON ;;
            *)         die "unknown sanitizer '${sanitizer}'" ;;
        esac
    done
fi

if [[ "${TSAN}" == "ON" && ( "${ASAN}" == "ON" || "${UBSAN}" == "ON" ) ]]; then
    die "ThreadSanitizer cannot be combined with AddressSanitizer or UBSan; use a separate build directory"
fi

command -v cmake >/dev/null 2>&1 || die "cmake not found; run scripts/bootstrap-ubuntu.sh first"

if [[ "${CLEAN}" -eq 1 && -d "${BUILD_DIR}" ]]; then
    log "removing ${BUILD_DIR}"
    rm -rf "${BUILD_DIR}"
fi

CMAKE_ARGS=(
    -S "${REPO_ROOT}"
    -B "${BUILD_DIR}"
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
    -DPQTLS_ENABLE_WERROR="${WERROR}"
    -DPQTLS_ENABLE_ASAN="${ASAN}"
    -DPQTLS_ENABLE_UBSAN="${UBSAN}"
    -DPQTLS_ENABLE_TSAN="${TSAN}"
    -DPQTLS_ENABLE_CLANG_TIDY="${CLANG_TIDY}"
)

if [[ -n "${OPENSSL_ROOT}" ]]; then
    [[ -d "${OPENSSL_ROOT}" ]] || die "OpenSSL prefix '${OPENSSL_ROOT}' does not exist"
    CMAKE_ARGS+=(-DOPENSSL_ROOT_DIR="${OPENSSL_ROOT}")
    log "using OpenSSL from ${OPENSSL_ROOT}"
fi

if command -v ninja >/dev/null 2>&1; then
    CMAKE_ARGS+=(-G Ninja)
fi

log "configuring (${BUILD_TYPE})"
cmake "${CMAKE_ARGS[@]}"

log "building with ${JOBS} jobs"
cmake --build "${BUILD_DIR}" --parallel "${JOBS}"

if [[ "${RUN_TESTS}" -eq 1 ]]; then
    log "running unit tests"
    ctest --test-dir "${BUILD_DIR}" --output-on-failure
fi

log ""
log "binaries:"
log "  ${BUILD_DIR}/pqtls-server"
log "  ${BUILD_DIR}/pqtls-client"
log ""
log "check what this build can actually do:"
if [[ -n "${OPENSSL_ROOT}" ]]; then
    log "  LD_LIBRARY_PATH=${OPENSSL_ROOT}/lib ${BUILD_DIR}/pqtls-client capabilities"
else
    log "  ${BUILD_DIR}/pqtls-client capabilities"
fi
