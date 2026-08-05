# Changelog

All notable changes to pqtls-lab are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note on results.** Version entries describe *capabilities*, not
> *measurements*. No benchmark figure appears in this file, or anywhere else in
> the repository, unless it was actually measured on identified hardware.

---

## [Unreleased]

### Planned
- Raspberry Pi evaluation on identified hardware (RQ3)
- Fuzzing of the frame decoder and the JSON message parser
- Technical report and reproducibility package
- `v1.0.0-research`

---

## [0.2.0] — 2026-08-05

Milestones 0 through 5 implemented. Measurement campaigns not yet run.

### Added

**Milestone 0 — repository foundation**
- CMake build for C++20 with an OpenSSL feature-detection module that gates
  post-quantum profiles on a version check *and* a runtime probe.
- Compiler-warning and sanitizer modules; ASan, UBSan and TSan builds.
- Hardening flags applied conditionally on toolchain support: stack protector,
  FORTIFY_SOURCE, RELRO, immediate binding, non-executable stack, PIE.
- `.clang-format`, `.clang-tidy`, `.editorconfig`.
- Dependencies pinned by exact commit, with `FETCHCONTENT_UPDATES_DISCONNECTED`
  so nothing updates during a normal build.
- GitHub Actions: build, tests, security, docker.
- Development container with the pinned OpenSSL and `NET_ADMIN`.

**Milestone 1 — classical TLS 1.3 baseline**
- `PqTlsServer` with a bounded thread pool that also bounds the accept queue.
- `PqTlsClient` with full chain, validity-date and hostname verification.
- Development PKI generation: ECDSA P-256 or P-384, correct SANs, restrictive
  key permissions, refusal to overwrite keys without `--force`, and verification
  of the generated chain.
- Framed application protocol: 4-byte big-endian length prefix and validated
  UTF-8 JSON, with independent checks for overlong encodings and surrogates.
- Error taxonomy of nine categories mapped to stable exit codes.
- Catch2 unit tests and a pytest integration suite.

**Milestone 2 — hybrid post-quantum key establishment**
- Runtime capability detection that probes libssl with the same call a real
  connection makes, rather than consulting a table.
- Profiles `hybrid-x25519-mlkem768`, `hybrid-p256-mlkem768` and
  `hybrid-p384-mlkem1024`.
- Explicit group policy: only the profile's groups are configured, and an
  unknown group name aborts rather than falling back to OpenSSL's defaults.
- **Post-handshake negotiated-group verification on both peers.** A violation
  terminates the connection before any application data is sent and is recorded
  as `tls-policy`, distinct from `handshake`.
- Downgrade-rejection tests, including against `openssl s_client`/`s_server` so
  the result does not depend on our own client also being correct.

**Milestone 3 — measurement**
- JSONL metrics with a published schema, appended never truncated, flushed per
  record so an interrupted run keeps what it took.
- `scripts/run-benchmarks.py`: capability gating, warm-up, a manifest written
  before the run and rewritten after each cell, preserved failures.
- `scripts/analyze-results.py`: count, success and failure rate, mean, median,
  min, max, standard deviation, p50/p90/p95/p99 and a Student's-*t* confidence
  interval. Statistics that cannot be computed are reported as `null`.
- `tools/result_validator.py`: rejects records claiming post-quantum protection
  their negotiated group does not provide.

**Milestone 4 — network experiments**
- `apply-netem.sh` and `reset-netem.sh`: mandatory explicit interface, a warning
  and confirmation before shaping the default route, dry-run mode, saved
  previous state.
- `capture-packets.sh` and `tools/pcap_metrics.py` for ClientHello size, segment
  counts, retransmissions and fragmentation.
- Experiment definitions for baseline, latency, packet loss, MTU, concurrency
  and Raspberry Pi.

**Milestone 5 — advanced authentication**
- Mutual TLS, with `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` so an absent client
  certificate fails the handshake rather than connecting unauthenticated.
- `scripts/generate-pq-certs.sh` for experimental ML-DSA certificates, which
  **skips with a reason** when the runtime OpenSSL cannot provide ML-DSA rather
  than reporting a false pass.
- Certificate and signature size measurement.
- Experimental, capability-gated `hybrid-pq-auth` profile.

**PQAudit integration**
- Adapter format with input and output JSON schemas, a stub conversion script
  and worked examples. Deliberately a documented boundary, not a coupling.

**Documentation**
- Architecture, protocol, threat model, security profiles, standards status,
  build guide, experiment guide, Raspberry Pi guide, packet-capture guide,
  PQAudit integration, limitations.

### Security
- TLS 1.3 only; TLS 1.2 and earlier disabled at both the version bounds and the
  option flags. No compression, no renegotiation.
- Explicit AEAD cipher-suite allowlist.
- Certificate and hostname verification enabled by default;
  `--insecure-development-mode` is off by default, prints a prominent banner, and
  is **refused when `PQTLS_ENV=production`**.
- TLS key logging carries the same restrictions and its destination is
  git-ignored.
- `.gitignore` plus a CI job that fails on any tracked private key, packet
  capture or key log — checking both file extensions and file contents.
- Container runs non-root with a read-only root filesystem, all capabilities
  dropped, and no key material baked in.
- CI asserts that the documentation makes no production-readiness claim and no
  unqualified end-to-end quantum-safe claim.

### Verified
Against **OpenSSL 3.5.7**, by completing real TLS 1.3 handshakes rather than by
reading a capability table:

- `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` and standalone
  `MLKEM768` all negotiate successfully with a verified certificate chain.
- A client and server with no overlapping group correctly fail to handshake.
- ML-DSA-65 key generation, certificate issuance, chain verification and TLS
  authentication succeed, with the peer signature reported as `mldsa65`.
- Measured certificate sizes: ML-DSA-65 end-entity **5732 bytes** DER against
  ECDSA P-256 **586 bytes** DER, a factor of roughly 9.8. Certificate size
  depends on the extensions present, so this is one data point rather than a
  constant.

### Known limitations
- **Not audited.** Research prototype only.
- Non-experimental profiles provide post-quantum key establishment with
  **classical authentication**. They are not end-to-end quantum-safe.
- ML-DSA certificates chain to a private CA and are accepted by nothing else.
- Hybrid TLS group definitions are in-progress specification work, not finalised
  RFCs. Names and code points may change.
- **No benchmark campaign has been run.** Every experiment definition says
  `Results not yet measured`.
- Application-level replay across connections is not prevented.
- No fuzzing, no revocation checking, no rate limiting.

---

## [0.1.0] — unreleased

Superseded by 0.2.0, which was the first tagged release. The classical baseline
described under Milestone 1 above corresponds to what 0.1.0 would have been.

---

## Versioning policy

| Version | Scope |
|---|---|
| `0.1.0` | Classical TLS 1.3 client and server |
| `0.2.0` | Hybrid post-quantum key establishment, measurement, experiments |
| `0.3.0` | First measured results on identified hardware |
| `0.4.0` | Network-condition campaign results |
| `0.5.0` | Post-quantum authentication evaluation results |
| `1.0.0-research` | Reproducible research release with a technical report |

Note that `0.3.0` onwards are defined by **measurements**, not by features. The
tooling for them already exists; what does not yet exist is the data.

A dependency or OpenSSL version bump is a notable change and is recorded here,
because it invalidates comparisons with results recorded earlier.

[Unreleased]: https://github.com/nbermparis/pqtls-lab/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/nbermparis/pqtls-lab/releases/tag/v0.2.0
