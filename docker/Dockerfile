# syntax=docker/dockerfile:1.7
#
# pqtls-lab application image.
#
# Multi-stage:
#   1. openssl  - pinned OpenSSL 3.5.x, checksum-verified, group-verified
#   2. build    - compile the project against that OpenSSL
#   3. runtime  - minimal image, non-root, no build tools, no keys
#
# The image contains NO certificates or private keys. Development certificates
# are mounted at run time; see docker/docker-compose.yml.

# ---------------------------------------------------------------------------
# Stage 1: OpenSSL
# ---------------------------------------------------------------------------
ARG OPENSSL_VERSION=3.5.7
ARG OPENSSL_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
ARG OPENSSL_PREFIX=/opt/openssl

# ubuntu:24.04, pinned by manifest-list digest (see docker/Dockerfile.openssl).
FROM ubuntu@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03 AS openssl

ARG OPENSSL_VERSION
ARG OPENSSL_SHA256
ARG OPENSSL_PREFIX
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl perl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSL --proto '=https' --tlsv1.2 \
        -o "openssl.tar.gz" \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - \
    && tar -xzf openssl.tar.gz \
    && rm openssl.tar.gz

RUN cd "openssl-${OPENSSL_VERSION}" \
    && ./Configure --prefix="${OPENSSL_PREFIX}" --openssldir="${OPENSSL_PREFIX}/ssl" \
        --libdir=lib shared no-ssl3 no-weak-ssl-ciphers \
    && make -j"$(nproc)" \
    && make install_sw \
    && cd / && rm -rf /build

# Fail the build now if the hybrid groups are missing, rather than shipping an
# image whose post-quantum profiles are all unavailable.
RUN set -eux; \
    export LD_LIBRARY_PATH="${OPENSSL_PREFIX}/lib"; \
    groups="$("${OPENSSL_PREFIX}/bin/openssl" list -tls-groups)"; \
    for required in X25519MLKEM768 SecP256r1MLKEM768; do \
        echo "$groups" | grep -q "$required" \
            || { echo "FATAL: pinned OpenSSL lacks TLS group $required" >&2; exit 1; }; \
    done

# ---------------------------------------------------------------------------
# Stage 2: build
# ---------------------------------------------------------------------------
FROM openssl AS build

ARG OPENSSL_PREFIX
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build git pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy the build inputs only. Copying the whole tree would invalidate the layer
# cache on any documentation change, and would risk pulling in local
# certificates that must never enter an image.
COPY CMakeLists.txt VERSION ./
COPY cmake/ ./cmake/
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/

RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR="${OPENSSL_PREFIX}" \
        -DPQTLS_BUILD_TESTS=ON \
        -DPQTLS_ENABLE_HARDENING=ON \
    && cmake --build build --parallel "$(nproc)"

# Run the unit tests inside the image. An image that ships a binary whose own
# tests fail is not a reproducible artefact.
RUN ctest --test-dir build --output-on-failure

# ---------------------------------------------------------------------------
# Stage 3: runtime
# ---------------------------------------------------------------------------
FROM ubuntu@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03 AS runtime

ARG OPENSSL_PREFIX=/opt/openssl
ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=${OPENSSL_PREFIX}/lib
ENV PATH=${OPENSSL_PREFIX}/bin:$PATH

LABEL org.opencontainers.image.title="pqtls-lab"
LABEL org.opencontainers.image.description="Crypto-agile TLS 1.3 research prototype for hybrid post-quantum key establishment"
LABEL org.opencontainers.image.source="https://github.com/nbermparis/pqtls-lab"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.pqtls.status="research-prototype-not-production"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user. A TLS endpoint has no reason to run as root, and a
# fixed uid/gid keeps mounted volume permissions predictable.
RUN groupadd --system --gid 10001 pqtls \
    && useradd --system --uid 10001 --gid pqtls --no-create-home --shell /usr/sbin/nologin pqtls

# Only the runtime pieces: the shared libraries, the openssl tool for
# diagnostics, and our two binaries. No compilers, no source, no keys.
COPY --from=openssl ${OPENSSL_PREFIX}/lib/ ${OPENSSL_PREFIX}/lib/
COPY --from=openssl ${OPENSSL_PREFIX}/bin/openssl ${OPENSSL_PREFIX}/bin/openssl
COPY --from=openssl ${OPENSSL_PREFIX}/ssl/ ${OPENSSL_PREFIX}/ssl/

COPY --from=build /src/build/pqtls-server /usr/local/bin/pqtls-server
COPY --from=build /src/build/pqtls-client /usr/local/bin/pqtls-client

COPY --chown=root:root config/ /etc/pqtls/

# Mount points for development certificates and for results. Both are volumes:
# nothing sensitive is baked into the image.
RUN mkdir -p /certs /results \
    && chown pqtls:pqtls /results \
    && chmod 755 /certs

USER pqtls
WORKDIR /

EXPOSE 8443

# The health check asks the binary whether the profile it was built for is
# actually usable, which is a real statement about the image rather than a
# process-is-alive check.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/pqtls-client", "capabilities", "--json"]

ENTRYPOINT ["/usr/local/bin/pqtls-server"]
CMD ["capabilities"]
