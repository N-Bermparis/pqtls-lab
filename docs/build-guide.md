# Build guide

## Requirements

| | Minimum | Notes |
|---|---|---|
| C++ compiler | GCC 11+ / Clang 14+ | C++20 |
| CMake | 3.22 | |
| OpenSSL | 3.0 to build | **3.5+ for post-quantum profiles** |
| Python | 3.9+ | Benchmarks and analysis |
| Ninja | optional | Used automatically when present |

Below OpenSSL 3.5 the project still builds and the classical baseline works;
every post-quantum profile reports itself unavailable **with a reason**. It never
silently substitutes a classical group.

## Quick build

```bash
scripts/bootstrap-ubuntu.sh     # toolchain, and pinned OpenSSL only if needed
scripts/verify-environment.sh   # what can this host actually do?
scripts/generate-classical-certs.sh --with-client
scripts/build.sh --test
```

## Manual build

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DPQTLS_BUILD_TESTS=ON
cmake --build build --parallel "$(nproc)"
ctest --test-dir build --output-on-failure
```

Against a pinned OpenSSL in its own prefix:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DOPENSSL_ROOT_DIR=/opt/openssl-3.5.7 \
  -DPQTLS_BUILD_TESTS=ON
cmake --build build --parallel "$(nproc)"

LD_LIBRARY_PATH=/opt/openssl-3.5.7/lib ./build/pqtls-client capabilities
```

`LD_LIBRARY_PATH` is needed because the binary links against a library outside
the default search path. Do **not** add that prefix to `/etc/ld.so.conf.d`:
every program on the host would silently start using it, including `ssh`.

## CMake options

| Option | Default | Effect |
|---|---|---|
| `PQTLS_BUILD_TESTS` | `ON` | Build the Catch2 unit tests |
| `PQTLS_ENABLE_WERROR` | `OFF` | Warnings become errors. `ON` in CI |
| `PQTLS_ENABLE_HARDENING` | `ON` | Stack protector, FORTIFY, RELRO, PIE |
| `PQTLS_ENABLE_ASAN` | `OFF` | AddressSanitizer |
| `PQTLS_ENABLE_UBSAN` | `OFF` | UndefinedBehaviorSanitizer |
| `PQTLS_ENABLE_TSAN` | `OFF` | ThreadSanitizer. **Cannot combine with ASan** |
| `PQTLS_ENABLE_CLANG_TIDY` | `OFF` | Run clang-tidy during the build |
| `PQTLS_MIN_OPENSSL_FOR_PQ` | `3.5.0` | Version gate below which PQ profiles are refused |

Requesting TSan together with ASan or UBSan fails at configure time rather than
producing a confusing link error.

## Sanitizer builds

```bash
scripts/build.sh --debug --sanitize address,undefined --test
scripts/build.sh --debug --sanitize thread --build-dir build/tsan --test
```

Recommended environment when running them:

```bash
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
```

`halt_on_error=1` matters: a sanitizer report is a failure, not a log line, and
without it CI will happily pass over one.

## Building OpenSSL from source

Only needed when the system OpenSSL is older than 3.5.

```bash
OPENSSL_VERSION=3.5.7
curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

# Verify BEFORE extracting. The expected value is in docker/openssl-checksums.txt.
grep "openssl-${OPENSSL_VERSION}.tar.gz$" docker/openssl-checksums.txt | sha256sum -c -

tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"
cd "openssl-${OPENSSL_VERSION}"
./Configure --prefix=/opt/openssl-${OPENSSL_VERSION} \
            --openssldir=/opt/openssl-${OPENSSL_VERSION}/ssl \
            --libdir=lib shared no-ssl3 no-weak-ssl-ciphers
make -j"$(nproc)"
sudo make install_sw
```

Confirm it has what is needed:

```bash
export LD_LIBRARY_PATH=/opt/openssl-3.5.7/lib
/opt/openssl-3.5.7/bin/openssl list -tls-groups | grep MLKEM
```

**Never install it over the system OpenSSL.** Use a private prefix; every other
program on the host depends on the system one.

## Dependencies

All pinned by commit. `FETCHCONTENT_UPDATES_DISCONNECTED` is set, so no
dependency updates during a normal build — a benchmark result is only meaningful
alongside the exact libraries that produced it.

| Dependency | Version | Pinned commit | Licence | Used for |
|---|---|---|---|---|
| OpenSSL | 3.5.7 | sha256 verified | Apache-2.0 | **All cryptography and TLS** |
| nlohmann/json | 3.11.3 | `9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03` | MIT | JSON messages and metrics |
| yaml-cpp | 0.8.0 | `f7320141120f720aecc4c32be25586e7da9eb978` | MIT | YAML configuration |
| spdlog | 1.14.1 | `27cb4c76708608465c413f6d0e6b8d99a4d84302` | MIT | Structured logging |
| Catch2 | 3.5.2 | `05e10dfccc28c7f973727c54f850237d07d5e10f` | BSL-1.0 | Unit tests |

Each is used from the system if a suitable version is installed; otherwise it is
fetched at the pinned commit. **No cryptographic algorithm is implemented in this
project** — everything comes from OpenSSL through its high-level APIs.

Python (benchmarks and analysis only, not required to build):

| Package | Purpose | Required |
|---|---|---|
| `pytest` | Integration and interoperability tests | For testing |
| `jsonschema` | Full schema validation of results | Optional; a built-in checker is used otherwise |

## Hardening flags

Applied when `PQTLS_ENABLE_HARDENING=ON` (the default) **and** the toolchain
accepts them. Availability is platform- and compiler-dependent, which is why they
are applied conditionally rather than assumed.

| Flag | Platform | Effect |
|---|---|---|
| `-fstack-protector-strong` | GCC, Clang | Detects stack buffer overflows |
| `-D_FORTIFY_SOURCE=2` | GCC, Clang, non-Debug | Compile- and run-time buffer checks. Needs optimisation, so it is skipped in Debug builds |
| `-Wl,-z,relro` | Linux ELF | Read-only relocations |
| `-Wl,-z,now` | Linux ELF | Immediate binding, which makes RELRO effective |
| `-Wl,-z,noexecstack` | Linux ELF | Non-executable stack |
| `POSITION_INDEPENDENT_CODE` | most | PIE, enabling ASLR |
| `/fsanitize=address` | MSVC | ASan only |

macOS and Windows support a different subset. Verify what actually landed:

```bash
# Linux
checksec --file=build/pqtls-server
readelf -d build/pqtls-server | grep -E 'BIND_NOW|RELRO'
```

Compiler warnings are enabled aggressively — including `-Wconversion`,
`-Wsign-conversion`, `-Wold-style-cast` and `-Wshadow` — and are errors in CI.
**Do not disable a warning to make a build green.**

## Troubleshooting

### `Could NOT find OpenSSL`

```bash
sudo apt-get install libssl-dev
# or point at a private prefix
cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/openssl-3.5.7
```

### The hybrid profile is reported unavailable

Expected on OpenSSL below 3.5. Confirm:

```bash
openssl version
openssl list -tls-groups | grep MLKEM
./build/pqtls-client capabilities
```

The capability output names the missing groups. If they are absent, build the
pinned OpenSSL as above.

### `error while loading shared libraries: libssl.so.3`

The binary is linked against an OpenSSL outside the default search path:

```bash
LD_LIBRARY_PATH=/opt/openssl-3.5.7/lib ./build/pqtls-client capabilities
```

### `hostname verification is enabled but no server name is available`

Verification needs a name to check against. Connecting to an address while
verifying a name requires saying so:

```bash
pqtls-client connect --host 127.0.0.1 --server-name localhost ...
```

### `unable to get local issuer certificate`

The client does not trust the CA that signed the server certificate:

```bash
pqtls-client connect --ca-certificate certs/classical/ca.crt ...
```

### FetchContent tries to reach the network in an offline build

Install the dependencies system-wide first, or pre-populate the source
directory:

```bash
sudo apt-get install nlohmann-json3-dev libyaml-cpp-dev libspdlog-dev catch2
```

### Tests fail with `pqtls-client not found`

```bash
PQTLS_BUILD_DIR=/path/to/build python3 -m pytest tests/integration -v
```

## Cross-compiling

Not currently supported as a first-class path. When `CMAKE_CROSSCOMPILING` is
set, the OpenSSL group probe cannot run, so post-quantum profiles are enabled on
the version gate alone and verified at run time by `pqtls-client capabilities`.

For Raspberry Pi, **build on the device.** It avoids an entire class of "is the
toolchain the difference?" questions when interpreting results. See
[`raspberry-pi.md`](raspberry-pi.md).

## Verifying a build

```bash
./build/pqtls-client --version
./build/pqtls-client capabilities
ctest --test-dir build --output-on-failure
PQTLS_BUILD_DIR=$PWD/build python3 -m pytest tests/integration -v -ra
scripts/run-demo.sh
```

`-ra` on pytest is deliberate: it reports skips as well as passes, so a
capability-gated test that skipped is visible rather than hidden inside a green
summary.
