# Post-quantum standards status

> **Last reviewed: 2026-08-05.**
>
> This area moves. Check the date above before relying on anything here, and
> verify against the primary sources rather than this summary. If the date is
> more than a few months old, treat this page as history rather than as current
> status.

The single most important distinction on this page:

> **A standardised algorithm is not the same as a standardised way of using it
> in TLS.** ML-KEM is a finished NIST standard. How ML-KEM is carried inside a
> TLS 1.3 handshake is separate specification work with its own, different
> maturity.

---

## Layer 1: the primitives

### ML-KEM — key encapsulation

| | |
|---|---|
| Standard | **NIST FIPS 203**, Module-Lattice-Based Key-Encapsulation Mechanism |
| Status | **Finalised.** |
| Derived from | CRYSTALS-Kyber, selected in NIST's post-quantum standardisation process |
| Parameter sets | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| Used here | ML-KEM-768 (primary), ML-KEM-1024 (high-security profile) |

ML-KEM-768 is the parameter set most commonly chosen for TLS: it targets a
security category comparable with AES-192 while keeping the key share small
enough to remain practical in a ClientHello.

**Note on naming.** "Kyber" and "ML-KEM" are not interchangeable. Kyber was the
submission; ML-KEM is the standardised algorithm, and it differs from the
original Kyber specification. Code, group names and documentation that still say
"Kyber" may refer to a pre-standard variant that is **not interoperable** with
ML-KEM.

### ML-DSA — digital signatures

| | |
|---|---|
| Standard | **NIST FIPS 204**, Module-Lattice-Based Digital Signature Algorithm |
| Status | **Finalised.** |
| Derived from | CRYSTALS-Dilithium |
| Parameter sets | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| Used here | ML-DSA-65, **experimental only** |

The algorithm being standardised does not make it deployable. See
[the certificate ecosystem](#the-certificate-ecosystem-is-the-real-obstacle)
below.

### SLH-DSA

**NIST FIPS 205**, a hash-based signature scheme, is also finalised. It is not
used in this project: its signatures are far larger than ML-DSA's, which makes
it a poor fit for TLS handshakes, though its different security assumptions make
it valuable elsewhere.

---

## Layer 2: TLS integration

This is where maturity differs sharply from Layer 1.

### Hybrid key exchange in TLS 1.3

The approach: perform a classical ECDH exchange **and** an ML-KEM encapsulation,
then combine both shared secrets so that the result is secure if *either*
component is secure.

The rationale is conservative and worth stating plainly. ML-KEM is new, its
implementations are newer, and a lattice cryptanalysis result would be
catastrophic if it were the only protection. A hybrid costs bandwidth and CPU to
buy insurance against exactly that.

| | |
|---|---|
| Status | **In-progress specification work.** Not a finalised RFC. |
| Nature | The framework for hybrid key exchange in TLS 1.3, plus specific code points and names for the combinations |
| Consequence | Group names, code points and encodings **can still change** |

**This is why the README, this document and the code refer to hybrid groups as
draft work rather than as an RFC.** Describing `X25519MLKEM768` as
"RFC-standardised" would be wrong.

### The groups this project uses

| Group | Classical half | PQ half | Notes |
|---|---|---|---|
| `X25519MLKEM768` | X25519 | ML-KEM-768 | The most widely deployed hybrid; the primary profile here |
| `SecP256r1MLKEM768` | NIST P-256 | ML-KEM-768 | For deployments constrained to the NIST curve family |
| `SecP384r1MLKEM1024` | NIST P-384 | ML-KEM-1024 | Higher security margin, larger handshake |

Note the naming inconsistency between OpenSSL's own spellings — `x25519` and
`secp256r1` are reported in lower case while the hybrids are mixed case. This is
not cosmetic: it is why all group comparison in this project is
case-insensitive.

### Standalone ML-KEM groups

`MLKEM512`, `MLKEM768` and `MLKEM1024` used as TLS groups **without** a classical
component are more experimental than the hybrids and are not covered by a
finalised TLS specification. This project marks `pure-mlkem768` as experimental
and disables it by default.

It is included for one reason: measuring the pure profile against the hybrid one
isolates the cost of the classical half. That is a useful research quantity and
not a deployment recommendation.

---

## OpenSSL support

| Version | ML-KEM | Hybrid TLS groups | ML-DSA | Usable here |
|---|---|---|---|---|
| 3.0.x | no | no | no | Classical profiles only |
| 3.1.x, 3.2.x | no | no | no | Classical profiles only |
| 3.3.x, 3.4.x | no | no | no | Classical profiles only |
| **3.5.x** | **yes** | **yes** | **yes** | **All profiles** |

**OpenSSL 3.5 is the minimum for any post-quantum profile in this project.** On
anything older the build succeeds, the classical baseline works, and every PQ
profile reports itself unavailable with a reason. It never silently substitutes a
classical group.

`SSL_get0_group_name` (OpenSSL 3.2+) is the only API that can name a hybrid
group: hybrids have no NID, so the older `SSL_get_negotiated_group` +
`OBJ_nid2sn` path returns nothing useful for them. The code feature-detects this
rather than assuming it.

### Verified on this project's pinned build

Confirmed against **OpenSSL 3.5.7** on 2026-08-05, by completing real TLS 1.3
handshakes rather than by reading a table:

| Group | Handshake completed | Reported as |
|---|---|---|
| `X25519MLKEM768` | yes | `X25519MLKEM768` |
| `SecP256r1MLKEM768` | yes | `SecP256r1MLKEM768` |
| `SecP384r1MLKEM1024` | yes | `SecP384r1MLKEM1024` |
| `MLKEM768` (standalone) | yes | `MLKEM768` |

ML-DSA-65 certificate generation and TLS authentication also completed against
that build, with the peer signature algorithm reported as `mldsa65`.

**Always confirm on your own host** — the pinned build is not the build you may
be running:

```bash
pqtls-client capabilities
openssl list -tls-groups
```

---

## The certificate ecosystem is the real obstacle

Post-quantum **key establishment** can be deployed today, unilaterally, by
anyone who controls both ends or whose peers support the hybrid groups.

Post-quantum **authentication** cannot, and the reasons have little to do with
cryptography:

1. **No public CA issues ML-DSA certificates for general use.** The Web PKI's
   root programmes, audit regimes and browser trust stores have not adopted
   them.
2. **Size.** An ML-DSA-65 certificate is roughly an order of magnitude larger
   than an ECDSA P-256 one. On this project's pinned build, a generated
   ML-DSA-65 end-entity certificate measured **5732 bytes** in DER against
   **586 bytes** for the equivalent ECDSA P-256 certificate — a factor of about
   9.8. A real chain multiplies that.
   *(Measured on OpenSSL 3.5.7, 2026-08-05, using
   `scripts/generate-pq-certs.sh`. Certificate size varies with the extensions
   present, so treat this as one data point, not a constant.)*
3. **Handshake growth.** Larger certificates and larger signatures compound the
   larger key share, pushing the handshake further past comfortable MTU
   boundaries — the interaction RQ2 exists to measure.
4. **Intermediates, OCSP, Certificate Transparency.** All of it grows, and none
   of it is modelled by this project's private two-level test PKI.

This is why every non-experimental profile here uses ECDSA, and why the metrics
schema keeps `pq_authentication` as a separate field that is honestly `false`
for those profiles.

---

## What this means for reading results from this project

- A `hybrid-*` profile result describes **post-quantum key establishment with
  classical authentication**. Cite it that way.
- Only `hybrid-pq-auth` results involve post-quantum authentication, and those
  use certificates that nothing outside this project trusts.
- Group names may change in future OpenSSL releases as the specifications
  settle. A result is tied to the OpenSSL version that produced it, which is why
  every experiment manifest records it.
- `pure-mlkem768` results are a research measurement of the classical half's
  cost, not a recommendation.

## Primary sources

Verify against these rather than against this page:

- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — <https://csrc.nist.gov/>
- IETF TLS working group documents on hybrid key exchange — <https://datatracker.ietf.org/wg/tls/documents/>
- OpenSSL release notes and `CHANGES.md` — <https://github.com/openssl/openssl>
- Your own host: `openssl list -tls-groups`, `pqtls-client capabilities`

## Review log

| Date | Change |
|---|---|
| 2026-08-05 | Page created. Hybrid group support verified by real handshakes against OpenSSL 3.5.7; ML-DSA-65 certificate generation and TLS authentication verified against the same build; certificate size measured. |
