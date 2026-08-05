# Experiment guide

How to run a measurement whose result can be trusted and reproduced.

## Principles

These are enforced by the tooling, not merely recommended.

1. **Verify capabilities before measuring.** A profile that is unavailable is
   recorded as SKIPPED with a reason. It is never quietly dropped and never
   counted as a pass.
2. **Preserve every raw record, including failures.** A benchmark that reports
   only its successes overstates reliability. `analyze-results.py` recomputes
   everything from the raw JSONL, so no summary is ever the only copy.
3. **Never delete previous results.** The metrics writer appends; it never
   truncates.
4. **Record the system.** A latency figure without the CPU, the OpenSSL version
   and the commit is not a measurement.
5. **Report what was negotiated, not what was requested.** Every derived flag
   comes from the observed group.
6. **An unmeasured experiment says so.** `Results not yet measured` is a correct
   value. An invented number is not.

## Before running anything

```bash
scripts/verify-environment.sh
./build/relwithdebinfo/pqtls-client capabilities
```

Save that output alongside the results. It is what lets someone else tell
whether their environment matched yours.

Reduce noise on the measuring machine:

```bash
# Pin the CPU governor (results vary considerably with frequency scaling)
sudo cpupower frequency-set -g performance

# Check for thermal throttling on a Raspberry Pi
vcgencmd get_throttled     # 0x0 means it has not throttled
```

Close other workloads. Record anything you could not close.

## Running a benchmark

```bash
python3 scripts/run-benchmarks.py \
  --experiment-id baseline-2026-001 \
  --profiles classical-x25519 hybrid-x25519-mlkem768 \
  --connections 100 \
  --concurrency 1 10 50 \
  --payloads 100 1024 \
  --warmup 10
```

See what would run without running it:

```bash
python3 scripts/run-benchmarks.py --dry-run
```

Outputs, per experiment id:

| File | Contents |
|---|---|
| `<id>-manifest.json` | System metadata, the full argument set, the config hash, and per-cell outcomes |
| `<id>-<cell>.jsonl` | Raw client records, one per connection |
| `<id>-<cell>-server.jsonl` | Raw server records |
| `<id>-<cell>-server.log` | Server output for that cell |

The manifest is written **before** the runs start and rewritten after each cell,
so an interrupted run still leaves the context needed to interpret whatever
completed.

## Analysing

```bash
python3 scripts/analyze-results.py experiments/results \
  --experiment-id baseline-2026-001 \
  --csv summary.csv \
  --json summary.json
```

Reported per group: count, success rate, failure rate, mean, median, min, max,
standard deviation, p50/p90/p95/p99, and a 95% confidence interval using
Student's *t*.

A statistic that cannot be computed is reported as `null`. With a single sample
there is no standard deviation, and printing `0.0` would imply a precision that
does not exist.

The default grouping is by `requested_profile`, `negotiated_group` and `role` —
so a downgrade would appear as a **separate row** rather than being averaged into
the profile it was requested under. The script also warns explicitly when a
post-quantum profile produced successful connections that were not post-quantum.

## Validating

```bash
python3 tools/result_validator.py experiments/results/*.jsonl
```

Run this before drawing any conclusion. It rejects records that claim
post-quantum protection their negotiated group does not provide, records that
report a non-TLS-1.3 version as successful, and records whose success and error
fields contradict each other.

Install `jsonschema` for full schema coverage; without it a built-in structural
checker is used and says so.

## Network-condition experiments

**These change kernel networking.** Prefer a container with `NET_ADMIN`, a VM, or
loopback. The scripts demand an explicit `--interface`, warn before touching the
default route, support `--dry-run`, and save the previous state.

```bash
sudo scripts/apply-netem.sh --interface lo --delay 50ms --jitter 5ms
python3 scripts/run-benchmarks.py --experiment-id latency-50ms ...
sudo scripts/reset-netem.sh --interface lo
```

**Always reset between conditions.** A leftover qdisc contaminates the next
measurement, and the contamination is invisible in the results.

A sweep:

```bash
for delay in 0ms 20ms 50ms 100ms 250ms 500ms; do
  sudo scripts/apply-netem.sh --interface lo --delay "$delay" --yes
  python3 scripts/run-benchmarks.py \
    --experiment-id "latency-${delay}" \
    --profiles classical-x25519 hybrid-x25519-mlkem768 \
    --connections 100 --concurrency 1
  sudo scripts/reset-netem.sh --interface lo
done
```

Definitions for the standard sweeps are in `experiments/definitions/`.

## Packet capture

```bash
sudo scripts/capture-packets.sh \
  --interface lo --port 18443 \
  --output captures/hybrid.pcap --snaplen 0 &

python3 scripts/run-benchmarks.py --experiment-id capture-run --connections 10

python3 tools/pcap_metrics.py captures/hybrid.pcap --json experiments/results/pcap.json
```

**Capture with `--snaplen 0`.** A truncated capture produces wrong ClientHello
sizes rather than an error — the one failure mode that silently invalidates a
size experiment.

Captures are git-ignored. Never commit one, and never capture traffic that is
not yours.

## Interpreting results honestly

### Report the success rate beside every mean
Under packet loss the surviving population changes. A mean at 10% loss describes
the connections that succeeded, which are not the same population as at 0%.

### Distinguish policy rejections from failures
`error_category: "tls-policy"` means the peer was rejected on policy — that is
the downgrade protection working. It is not a network failure and must not be
counted as one.

### Do not compare across OpenSSL versions
A result belongs to the OpenSSL that produced it. The manifest records it.

### Percentiles beat means
Handshake times are right-skewed. p50, p95 and p99 describe the distribution
better than a mean and a confidence interval.

### State what the environment was
Client and server on the same host compete for cores. Loopback is not a network.
Say so.

### Never write a number you did not measure
If an experiment has not been run, its definition says `Results not yet
measured`. Leave it that way.

## Reproducibility checklist

Before publishing any figure:

- [ ] Raw JSONL records preserved and archived
- [ ] Manifest with system metadata included
- [ ] `pqtls-client capabilities` output saved
- [ ] `scripts/verify-environment.sh` output saved
- [ ] Git commit recorded, and the tree clean (`git_dirty: false`)
- [ ] OpenSSL version recorded, and whether it was system or pinned
- [ ] CPU model, core count and memory recorded
- [ ] Build type and compiler recorded
- [ ] Network conditions recorded, including "none"
- [ ] Results validated with `result_validator.py`
- [ ] At least 100 connections per cell
- [ ] Failures included in the analysis
- [ ] Any confounder stated (shared host, loopback, thermal state)

## Current status

**No experiment in this repository has been run.**

Every definition in `experiments/definitions/` says `Results not yet measured`,
and `experiments/results/` contains only `.gitkeep`. The tooling is implemented
and its own tests pass; the measurements await identified hardware.

This is deliberate. A repository with plausible-looking numbers of unknown
provenance is worse than one with none, because a reader cannot tell them apart.
