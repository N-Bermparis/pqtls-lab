# Security policy

## ⚠️ Status: research prototype

**pqtls-lab is not production software. Do not deploy it to protect anything
real.**

It has **not been independently audited**. It exists to measure the cost and
behaviour of post-quantum TLS, not to secure production traffic. Please
calibrate expectations accordingly — including when reporting issues.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting:

1. Go to the **Security** tab of this repository.
2. Choose **Report a vulnerability**.
3. Include the details below.

If private vulnerability reporting is unavailable, do not publish sensitive
details in an issue. Open a minimal, non-sensitive issue asking the maintainer
to enable a private reporting channel, or use the contact information published
on the maintainer's GitHub profile.

### What to include

- What the issue is, and what an attacker gains from it.
- Steps to reproduce, with exact commands.
- The affected version (`pqtls-client --version`).
- The OpenSSL version, and whether it is the system one or a pinned build.
- The security profile involved.
- The output of `pqtls-client capabilities`.
- Any proof of concept.

**Never include private keys, session secrets or the contents of a TLS key-log
file in a report.**

### What to expect

| | |
|---|---|
| Acknowledgement | Within a few days |
| Initial assessment | Within two weeks |
| Fix or mitigation | Depends on severity and on maintainer availability |

This is a research project maintained by a small number of people. Response
times are best-effort, and honesty about that is more useful than a service-level
promise that would not be met.

Coordinated disclosure is welcome and appreciated. Reporters are credited in
`CHANGELOG.md` unless they prefer otherwise.

## In scope

Issues in **this project's own code**:

- Memory safety: buffer overflows, use-after-free, uninitialised reads.
- **Downgrade-protection bypass** — anything that lets a connection complete
  under a post-quantum profile while having negotiated a classical group.
- Certificate-validation bypass: chain, hostname, expiry or trust anchor.
- Anything that allows TLS 1.2 or earlier to be negotiated.
- Application-protocol flaws: frame or message parsing, size-limit bypass.
- Leakage of key material, session secrets or credentials into logs, metrics or
  error messages.
- A development-only option that is reachable when `PQTLS_ENV=production`.
- A capability being reported as available when it is not, or a profile reported
  usable when it is not.
- Metrics that misreport what was negotiated.

That last group matters more than it might appear. **In this project, a false
claim about a security property is a security bug.** A metrics record asserting
post-quantum protection over a classical group is exactly as serious as a code
defect, because downstream decisions get made on it.

## Out of scope

- **Vulnerabilities in OpenSSL.** Report those to the OpenSSL project. This
  project implements no cryptographic primitives.
- **Missing hardening against threats already documented as out of scope** in
  [`docs/threat-model.md`](docs/threat-model.md) — host compromise, hardware
  implants, malicious toolchains, physical capture, global traffic analysis.
- **The development PKI being insecure.** It is deliberately unencrypted test
  material, git-ignored, and documented as such.
- **`--insecure-development-mode` disabling verification.** That is its stated
  purpose. A *bypass* of the production guard, or a way to reach it without the
  flag, **is** in scope.
- **Denial of service** beyond the documented limits. The threat model states
  that DoS is only partially addressed and that post-quantum handshake cost
  changes the economics of a handshake flood. A concrete, novel amplification is
  still worth reporting.
- **Automated scanner output without a demonstrated impact.**
- Anything in `experiments/`, `certs/` or generated test material.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Older releases | ❌ |

This is a research prototype under active development. Only the latest release
receives fixes. There are no long-term-support branches.

## Security measures in place

Not a claim of security — a description of what has been done.

| | |
|---|---|
| Cryptography | OpenSSL only. No primitive is implemented here |
| TLS versions | 1.3 only, enforced at both the version bounds and the option flags |
| Cipher suites | Explicit AEAD allowlist |
| Downgrade protection | Only the profile's groups are offered, **and** the negotiated group is verified afterwards on both peers |
| Certificate validation | Chain, validity dates and hostname, enabled by default |
| Memory safety | RAII for every OpenSSL object; no raw owning pointers; ASan, UBSan and TSan builds in CI |
| Hardening | Stack protector, FORTIFY_SOURCE, RELRO, immediate binding, non-executable stack, PIE, where supported |
| Static analysis | CodeQL, clang-tidy, cppcheck |
| Warnings | Aggressive, and errors in CI |
| Dependencies | Pinned by exact commit; OpenSSL pinned with a verified checksum; no silent updates |
| Key material | `.gitignore` plus a CI check that fails on any tracked private key, capture or key log |
| Container | Non-root, read-only root filesystem, all capabilities dropped, no key material in the image |
| Development options | Off by default, warned about loudly, refused when `PQTLS_ENV=production` |

### Not in place

Stated so that absence is not mistaken for coverage:

- **No fuzzing.** The frame decoder and the JSON message parser are the obvious
  targets and are future work.
- **No independent audit.**
- **No formal verification.**
- **No reproducible builds.** Dependencies are pinned, which makes a build
  identifiable, not verified.
- **No revocation checking**, no certificate pinning, no CT verification.
- **No rate limiting** or per-source connection quotas.

## After a fix

Every security fix gets:

1. A regression test that fails before the fix and passes after it.
2. A `CHANGELOG.md` entry.
3. Credit to the reporter, unless they decline.
4. A documentation update where the fix changes what the project guarantees.

Requirement 1 is not negotiable. A security bug without a test is a security bug
waiting to return.
