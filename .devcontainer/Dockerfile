# Development container for pqtls-lab.
#
# Includes the pinned OpenSSL, the build toolchain, the analysis tooling and the
# network-experiment tools. Larger than the runtime image on purpose: this is
# where the work happens, not what gets deployed.

# ubuntu:24.04, pinned by digest (see docker/Dockerfile.openssl).
FROM ubuntu@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

ARG OPENSSL_VERSION=3.5.7
ARG OPENSSL_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
ARG OPENSSL_PREFIX=/opt/openssl
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git pkg-config perl make \
        clang clang-format clang-tidy cppcheck gdb valgrind \
        curl ca-certificates sudo less nano vim \
        python3 python3-pip python3-venv \
        iproute2 iputils-ping net-tools tcpdump \
        jq shellcheck \
    && rm -rf /var/lib/apt/lists/*

# tshark asks an interactive question about non-root capture; preseed the
# answer so the image builds unattended.
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Pinned OpenSSL, installed into its own prefix so the system one is untouched.
# ---------------------------------------------------------------------------
WORKDIR /tmp/openssl-build
RUN curl -fsSL --proto '=https' --tlsv1.2 -o openssl.tar.gz \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - \
    && tar -xzf openssl.tar.gz \
    && cd "openssl-${OPENSSL_VERSION}" \
    && ./Configure --prefix="${OPENSSL_PREFIX}" --openssldir="${OPENSSL_PREFIX}/ssl" \
        --libdir=lib shared no-ssl3 no-weak-ssl-ciphers \
    && make -j"$(nproc)" \
    && make install_sw \
    && cd / && rm -rf /tmp/openssl-build

RUN set -eux; \
    export LD_LIBRARY_PATH="${OPENSSL_PREFIX}/lib"; \
    "${OPENSSL_PREFIX}/bin/openssl" list -tls-groups | grep -q X25519MLKEM768 \
        || { echo "FATAL: the pinned OpenSSL lacks X25519MLKEM768" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Non-root development user.
#
# uid 1000 usually matches the host user, which keeps bind-mounted file
# ownership sane.
# ---------------------------------------------------------------------------
RUN if ! getent group ${USER_GID} >/dev/null; then groupadd --gid ${USER_GID} ${USERNAME}; fi \
    && if ! id -u ${USERNAME} >/dev/null 2>&1; then \
         useradd --uid ${USER_UID} --gid ${USER_GID} -m -s /bin/bash ${USERNAME}; \
       fi \
    && echo "${USERNAME} ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME}

USER ${USERNAME}

RUN python3 -m pip install --user --break-system-packages --no-warn-script-location \
        pytest jsonschema pyyaml

ENV OPENSSL_ROOT_DIR=${OPENSSL_PREFIX}
ENV LD_LIBRARY_PATH=${OPENSSL_PREFIX}/lib
ENV PATH=${OPENSSL_PREFIX}/bin:/home/${USERNAME}/.local/bin:$PATH

# Development, not production: this is what lets --insecure-development-mode and
# --keylog-file work at all inside the container.
ENV PQTLS_ENV=development

WORKDIR /workspaces/pqtls-lab
