#!/usr/bin/env bash
#
# Runs once after the development container is created.
#
set -Eeuo pipefail

echo "==> pqtls-lab development container"
echo

echo "--> environment"
scripts/verify-environment.sh || true
echo

echo "--> development certificates"
if [[ -f certs/classical/server.crt ]]; then
    echo "already present in certs/classical"
else
    scripts/generate-classical-certs.sh --with-client
fi
echo

echo "--> configuring the build"
cmake -S . -B build/relwithdebinfo -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DOPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl}" \
    -DPQTLS_BUILD_TESTS=ON

cat <<'EOF'

Ready. Common commands:

  scripts/build.sh --test              build and run the unit tests
  ./build/relwithdebinfo/pqtls-client capabilities
  scripts/run-demo.sh                  end-to-end demonstration
  python3 -m pytest tests/integration -v

Network experiments work inside this container (NET_ADMIN is granted), so
shaping stays contained rather than affecting your host:

  sudo scripts/apply-netem.sh --interface lo --delay 50ms
  sudo scripts/reset-netem.sh --interface lo

Note: PQTLS_ENV=development is set here, which is what allows the
development-only options to run at all.

EOF
