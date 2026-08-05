# Limitations

Read this before citing anything from this project.

Everything here is a real constraint, not a disclaimer. Where a limitation could
be mistaken for a result, it is stated plainly.

---

## 1. Research-prototype status

**This is not production software and must not be deployed to protect anything
real.**

- **No independent security audit** has been performed.
- No formal verification, no external cryptographic review, no fuzzing.
- The API and the metrics schema may change between releases.
- It is optimised for *measurability and clarity*, not for throughput,
  robustness under attack, or operational maturity.

What it *is*: a carefully built instrument for asking specific questions about
post-quantum TLS, with enough discipline about honesty that the answers can be
trusted as far as their stated limits.

## 2. Post-quantum scope

**The non-experimental profiles provide post-quantum key establishment only.**

Server authentication uses a classical ECDSA signature. Such a connection:

- **is** protected against harvest-now-decrypt-later;
- **is not** protected against a quantum adversary able to forge signatures
  *during* a live handshake;
- **is not** end-to-end quantum-safe.

`hybrid-pq-auth` is the only profile with post-quantum authentication, and it is
experimental, capability-gated, and uses certificates that nothing outside this
project accepts.

See [`security-profiles.md`](security-profiles.md#the-three-properties).

## 3. OpenSSL dependence

Behaviour is determined by the OpenSSL build, not by this project.

- **OpenSSL 3.5+ is required** for any post-quantum profile. Below that, the
  classical baseline works and every PQ profile reports itself unavailable.
- **Group names have changed between releases** and may change again while the
  TLS specifications settle. A group name is not a stable interface.
- **Availability is not implied by a version number.** A distribution may build
  OpenSSL with algorithms disabled, which is why every capability is probed with
  the same call a real connection makes.
- **A result is tied to the OpenSSL that produced it.** Comparing figures across
  OpenSSL versions compares two different implementations.

Always run `pqtls-client capabilities` on the host you are measuring.

## 4. Draft standards

ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are finalised NIST standards. **How they
are used inside TLS is not.** Hybrid group definitions are in-progress
specification work; standalone ML-KEM groups are more experimental still.

Consequences: code points and names may change; interoperability with other
implementations may vary; results may not be reproducible on a future OpenSSL
without adjustment.

See [`pqc-standards-status.md`](pqc-standards-status.md), and check its
last-reviewed date.

## 5. Benchmarking limitations

These are the ones most likely to lead to a wrong conclusion.

### Client and server share a host by default
They compete for the same cores. This inflates both figures, especially at high
concurrency. Run the peers on separate machines before quoting absolute
throughput.

### Loopback is not a network
No NIC, no driver, no switch, no real queueing. Loopback removes exactly the
components that a large ClientHello interacts with. Latency and MTU results from
loopback are **indicative of handshake structure**, not predictive of a real
path.

### netem is an approximation
`netem` loss is uniformly random unless a correlation is configured; real
networks lose packets in bursts. Delay on `lo` is applied to egress only, so a
round trip sees the configured delay roughly once, not twice — state which
convention you used.

### The surviving population changes under loss
Mean handshake time at 10% loss describes *the connections that succeeded*,
which are a different population from those at 0%. **Never report a mean without
the success rate beside it.**

### Timing measurement
`std::chrono::steady_clock` resolution and scheduling jitter bound the
precision. Sub-millisecond differences on a loaded machine are not meaningful.
Warm-up connections are discarded, but caches, CPU frequency scaling and
turbo behaviour still vary between runs.

### Memory measurement
`peak_memory_kib` is sampled from the **whole process**, not per connection.
Under concurrency it describes the process, and the value is a high-water mark
that never decreases. `ru_maxrss` units differ between Linux and macOS, which the
code handles but which is worth knowing.

### Thermal throttling on constrained devices
A Raspberry Pi that throttles produces timings for a throttled device. Always
record `vcgencmd get_throttled` before and after, and the cooling arrangement.
An undervolted Pi throttles regardless of temperature.

### Energy is not measured
No software-only energy figure is trustworthy. Energy measurement requires
external instrumentation, and any energy number must name the instrument used.

### No results are published
**Every experiment definition currently says `Results not yet measured`.** That
is accurate, not an oversight. The tooling is implemented and tested; the
measurements have not been taken on identified hardware.

## 6. Platform limitations

| | |
|---|---|
| **Linux** | Fully supported. Network experiments require `NET_ADMIN`. |
| **WSL2** | Builds and runs. Networking is virtualised, so netem results are less representative than on native Linux. |
| **Raspberry Pi** | Supported, ARM64. The pinned OpenSSL build on-device is slow. |
| **macOS** | Should build; not tested. `ru_maxrss` units are handled. No netem. |
| **Windows (native)** | The code has Winsock paths and compiles conceptually, but **is not tested**, has no netem or `tcpdump`, and is not a supported platform. Use WSL2 or Docker. |

## 7. Certificate ecosystem limitations

- The development PKI is a **two-level private CA** with unencrypted keys. Real
  chains have intermediates, revocation, OCSP stapling and Certificate
  Transparency, none of which is modelled.
- **No revocation checking** of any kind: no CRL, no OCSP.
- **No certificate pinning**, no CAA, no CT verification.
- ML-DSA certificates chain to a private CA and are accepted by nothing else.
- Certificate size varies with the extensions present, so a single measured size
  is one data point, not a constant.

## 8. Protocol limitations

- **Application-level replay is not prevented.** Messages carry a UUID and a
  timestamp, but the server keeps no seen-identifier cache. TLS prevents replay
  within a connection; across connections is the application's problem.
- The application protocol is a **research vehicle**, deliberately minimal. It is
  not a general-purpose messaging protocol.
- Only protocol version 1 exists; there is no negotiation to exercise yet.
- Frames are fully buffered before parsing, bounded by `max_frame_size`. A 1 MiB
  default multiplied by many concurrent connections is a real memory figure to
  account for.

## 9. Concurrency model limitations

- A **bounded thread pool**, one connection per worker at a time. Simple and
  auditable, not the highest-throughput design. An event-driven server would
  scale further; it would also be much harder to reason about, and throughput is
  not what this project measures.
- Connections beyond `max_connections` are **closed immediately**, not queued.
  Under a concurrency sweep this shows up as client-side failures, which is
  correct behaviour and must not be read as a post-quantum performance result.
- Each benchmark thread owns its own client, `SSL_CTX` and session cache. A
  resumption rate below 100% at high concurrency is expected.

## 10. Measurement scope

**Measured:** handshake duration, total connection duration, application bytes,
process CPU time, peak process memory, negotiated parameters, session reuse,
success and failure with categories.

**Not measured, though sometimes assumed:**

- **Transport bytes.** `transport_bytes_sent` and `transport_bytes_received` are
  currently `null` — TLS record overhead is not counted at the socket layer.
  Handshake size comes from packet capture instead.
- **ClientHello size** — requires `tools/pcap_metrics.py` and a capture taken
  with `--snaplen 0`.
- **Server-side CPU attributable to one connection** — the sample is
  process-wide.
- **Time to first application byte, precisely.** Under TLS 1.3 the encrypted
  handshake shares content type 23 with application data, so the capture-derived
  figure is a lower bound.

## 11. Statistical limitations

- Standard deviation and confidence intervals need at least two samples; with
  one, they are reported as `null` rather than `0`.
- Confidence intervals assume approximately normal sampling and use Student's
  *t*. Handshake times are typically right-skewed, so **percentiles are more
  informative than a mean plus an interval**.
- No hypothesis testing, no multiple-comparison correction, no outlier removal —
  the raw data is preserved so any of that can be done deliberately, downstream.

## 12. What this project cannot tell you

Stated explicitly, because these are the questions people will want answered:

- **Whether hybrid post-quantum TLS is "fast enough" for your system.** That
  depends on your hardware, your traffic and your requirements. This project
  measures; it does not judge.
- **Whether to migrate.** A cost measurement is one input to that decision.
- **Whether ML-KEM is secure.** That is a question for cryptanalysis, not for a
  TLS harness.
- **How a specific middlebox or CDN will behave** with a larger ClientHello.
- **What a real deployment costs.** Certificate management, client compatibility
  and operations dominate, and none of them are modelled here.

---

*Last reviewed: 2026-08-05.*
