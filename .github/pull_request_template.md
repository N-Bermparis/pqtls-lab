# Summary

<!-- What does this change do, and why? One or two paragraphs. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security fix
- [ ] Experiment definition or results
- [ ] Documentation
- [ ] Build, CI or tooling
- [ ] Refactoring (no behaviour change)

## Milestone

<!-- M0 foundation / M1 classical / M2 hybrid / M3 measurement /
     M4 network / M5 authentication / M6 research release -->

---

## Claims checklist

Wrong statements about security properties are a security problem in this
project, so these are checked on every pull request.

- [ ] No text describes post-quantum **key establishment** as post-quantum
      **authentication**, or the reverse.
- [ ] No text claims end-to-end quantum-safe protection for a profile that
      authenticates with a classical signature.
- [ ] No text claims the project is production-ready.
- [ ] No Internet-Draft is described as a finalised RFC.
- [ ] Experimental features remain clearly labelled as experimental.
- [ ] If standards status is discussed, `docs/pqc-standards-status.md` has been
      reviewed and its "last reviewed" date updated.

## Security checklist

- [ ] No private keys, certificates, packet captures or TLS key logs are added.
- [ ] No security check was disabled, loosened or bypassed to make a test pass.
- [ ] No compiler warning was suppressed to make CI green.
- [ ] Every OpenSSL call that can fail is checked.
- [ ] No secret, key or session material can reach a log or a metrics record.
- [ ] Development-only options remain off by default and still refuse to run
      when `PQTLS_ENV=production`.
- [ ] If a security bug is fixed, a regression test accompanies the fix.

## Results and measurement checklist

- [ ] No benchmark number appears anywhere unless it was actually measured.
- [ ] Any figure quoted names the hardware, the OpenSSL version and the commit
      it came from.
- [ ] Raw per-connection records are preserved; nothing filters out failures.
- [ ] Unmeasured experiments still say `Results not yet measured`.

## Testing

<!-- What did you run? Paste the commands and the outcome. -->

```
```

- [ ] Unit tests pass (`ctest --test-dir build --output-on-failure`)
- [ ] Classical integration tests pass
- [ ] Hybrid integration tests pass **or** are correctly reported as SKIP with a
      recorded reason
- [ ] Interoperability tests against `openssl s_client` / `s_server` pass or skip
      with a reason

**Capability-gated tests:** list any test that skipped and why. A skip that
hides a real failure is worse than a red build.

<!-- e.g. "test_p384_hybrid: SKIPPED, system OpenSSL 3.0.13 has no SecP384r1MLKEM1024" -->

## Reproducibility

- [ ] Any new dependency is pinned to an exact version or commit, documented,
      and its licence recorded.
- [ ] No dependency updates silently during a normal build.
- [ ] `CHANGELOG.md` is updated for a meaningful change.

## Reviewer notes

<!-- Anything a reviewer should look at closely, or anything you are unsure of.
     Naming a weakness here is more useful than a clean-looking checklist. -->
