# Contributing to pqtls-lab

Contributions are welcome — especially measurements on hardware the maintainer
does not have, and corrections to anything that overstates what this project
provides.

## Two rules that matter more than the rest

**1. Never commit a number you did not measure.**

An absent result is fine. `Results not yet measured` is a correct and useful
value. A plausible-looking invented number is worse than nothing, because a
reader has no way to tell it apart from a real one, and everything that later
cites it inherits the problem.

**2. Never describe post-quantum key establishment as post-quantum
authentication.**

They are different properties with different threat models. A hybrid key
exchange with an ECDSA certificate is *not* end-to-end quantum-safe. This is
enforced in the code, the metrics schema, the validator and CI — and it should
be enforced in your prose too.

## Getting set up

```bash
git clone https://github.com/nbermparis/pqtls-lab.git
cd pqtls-lab
scripts/bootstrap-ubuntu.sh
scripts/verify-environment.sh
scripts/generate-classical-certs.sh --with-client
scripts/build.sh --test
```

Or open the repository in the dev container, which has the pinned OpenSSL, the
analysis tooling and `NET_ADMIN` for network experiments.

## Before opening a pull request

```bash
# Build with warnings as errors, as CI does
scripts/build.sh --werror --test

# Sanitizers
scripts/build.sh --debug --sanitize address,undefined --test

# Integration tests. -ra reports skips, which is the point.
PQTLS_BUILD_DIR=$PWD/build/relwithdebinfo python3 -m pytest tests/integration -v -ra

# Interoperability against OpenSSL's own tools
PQTLS_BUILD_DIR=$PWD/build/relwithdebinfo python3 -m pytest tests/interoperability -v -ra

# Formatting
clang-format -i $(git ls-files '*.cpp' '*.hpp')

# Shell scripts
shellcheck scripts/*.sh

# Documentation claims. CI runs this; run it before pushing.
python3 scripts/check-claims.py
```

`check-claims.py` rejects production-readiness claims, unqualified end-to-end
quantum-safe claims, describing a draft as an RFC, and any statement that the
project has been audited. It understands negation in context, so
"it is **not** end-to-end quantum-safe" passes while the bare claim does not.

## Coding standards

C++20, and:

- **RAII everywhere.** No raw owning pointers, least of all to OpenSSL objects.
- **Const-correctness.**
- **No C-style casts.** `-Wold-style-cast` is on.
- **Every OpenSSL call that can fail is checked.** No exceptions to this.
- **No exception escapes a thread entry point.** Every worker body has a
  catch-all.
- **No `using namespace` in a header.**
- **No secret in a log**, an error message, or a metrics record.
- **No cryptographic primitive implemented here.** Use OpenSSL's high-level APIs.
- **No deprecated OpenSSL API** where a modern one exists.

### Comments

Comment on **why**, not **what**. `// increment i` is noise. This is not:

```cpp
// Rejected here, before any allocation of that size. An attacker who can write
// four bytes must not be able to make us reserve gigabytes.
if (length > max_frame_size) {
```

Security decisions deserve a comment explaining the reasoning. Someone will
eventually wonder whether a check is necessary, and the comment is what stops
them removing it.

## Testing

| Change | Tests required |
|---|---|
| Any code change | Unit tests for the new behaviour |
| A security fix | **A regression test that fails before the fix.** Not optional |
| A new profile | Profile validation *and* downgrade behaviour |
| A protocol change | Adversarial tests for the new rejection cases |
| A capability change | Confirmation that unavailability is reported with a reason |

### Capability gating

A test that cannot run because the OpenSSL build lacks a capability must
**SKIP with the reason recorded**:

```python
require_profile("hybrid-x25519-mlkem768")   # skips with the blocking reason
```

Never convert a failure into a skip. A skip that hides a real failure is worse
than a red build, and CI has a step specifically to catch a hybrid test skipping
on a PQ-capable build.

Outcomes: **PASS** (capability present, behaviour correct), **FAIL** (capability
present, behaviour wrong), **SKIP** (capability absent, reason recorded),
**XFAIL** (a documented, temporary limitation).

## Adding a security profile

1. Add it to `config/profiles.yaml` and/or the built-in catalogue in
   `src/common/security_profile.cpp`.
2. Add tests, including downgrade behaviour.
3. Confirm it on a real host with `pqtls-client capabilities`.
4. Document it in `docs/security-profiles.md` and the README table.
5. If it is experimental, mark it experimental — in the definition, in the docs,
   and in any result that uses it.

## Contributing measurements

The most valuable contribution: run the experiments on hardware nobody here has.

Include everything from the reproducibility checklist in
[`docs/experiment-guide.md`](docs/experiment-guide.md): raw JSONL, the manifest,
`capabilities` output, `verify-environment.sh` output, the git commit, the
OpenSSL version, the CPU, and every confounder you are aware of.

Validate before submitting:

```bash
python3 tools/result_validator.py experiments/results/*.jsonl
```

State the limits of what you measured. "Client and server shared a host" or
"the Pi throttled during the run" makes a result *more* useful, not less.

## Dependencies

Any new dependency must be pinned to an exact version or commit, documented in
`docs/build-guide.md` with its licence, and not fetched from an untrusted
source. `FETCHCONTENT_UPDATES_DISCONNECTED` is set so nothing updates silently:
a benchmark result is only meaningful alongside the exact libraries that produced
it.

The bar for a new dependency is high. Prefer the standard library, or OpenSSL.

## Commits and pull requests

Conventional-style prefixes, imperative mood:

```
feat(profiles): add SecP384r1MLKEM1024 high-security profile
fix(tls): reject an empty negotiated group name
security(protocol): bound frame length before allocating
docs(standards): update the ML-KEM standardisation status
test(downgrade): cover a classical fallback under a hybrid profile
```

Keep pull requests small and reviewable. A change to TLS policy should not
arrive alongside a documentation reflow.

The pull-request template includes claims, security, results and testing
checklists. They are there because this project's failure modes are subtle:
please actually work through them.

## What will not be merged

- A benchmark number that was not measured.
- A security check disabled, loosened or bypassed to make a test pass.
- A compiler warning suppressed to make CI green.
- A hand-rolled cryptographic primitive.
- A private key, certificate, packet capture or TLS key log.
- Text describing post-quantum key establishment as post-quantum
  authentication.
- Text describing an Internet-Draft as a finalised RFC.
- A claim that the project is production-ready.
- A profile that silently permits a weaker group than it advertises.

## Reporting security issues

**Not through a pull request or a public issue.** See
[`SECURITY.md`](SECURITY.md).

## Code of conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Questions

Open a discussion or an issue. A question that reveals the documentation is
unclear is a useful contribution in itself — please say so rather than working
around it.
