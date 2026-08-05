# Raspberry Pi support

RQ3 asks whether hybrid post-quantum TLS is feasible on constrained devices. The
Raspberry Pi is a reasonable stand-in for the class of hardware that actually
terminates TLS at the edge, and it is also where the slowest links and smallest
MTUs live.

## Supported platforms

| | |
|---|---|
| OS | Raspberry Pi OS **64-bit** (Bookworm or later), or Ubuntu Server 24.04 ARM64 |
| Architecture | **ARM64 (aarch64) only.** 32-bit builds are not supported |
| Model | Pi 4 or Pi 5 recommended. A Pi 3 will work but is slow to build on |
| Memory | 2 GB minimum; **4 GB or more strongly recommended** if OpenSSL must be built on-device |
| Storage | 8 GB free. A good SD card or, better, USB SSD |

Confirm the architecture before starting — a 32-bit userland on 64-bit hardware
is a common surprise:

```bash
uname -m          # must print aarch64
getconf LONG_BIT  # must print 64
```

## Setup

```bash
sudo apt-get update && sudo apt-get upgrade -y

git clone https://github.com/nbermparis/pqtls-lab.git
cd pqtls-lab

scripts/bootstrap-ubuntu.sh
```

The bootstrap installs the toolchain and, **only if the system OpenSSL is older
than 3.5**, builds a pinned OpenSSL into `/opt`.

### On the OpenSSL build time

Building OpenSSL on a Pi is the slow step, by a wide margin. It is a full
compile of a large C codebase on a low-power ARM core.

**No duration is quoted here**, because a figure that was not measured on the
hardware being described is worthless — it varies enormously with the model, the
storage medium, the cooling and the swap configuration. Measure it yourself and
record it with your results:

```bash
/usr/bin/time -v scripts/bootstrap-ubuntu.sh --build-openssl 2>&1 | tee openssl-build.log
```

Practical advice while it runs:

- Use `--jobs 2` on a 2 GB Pi. Four parallel compiler jobs can exhaust memory
  and trigger the OOM killer partway through.
- Prefer a USB SSD over an SD card.
- Ensure adequate cooling. A throttled build is slower and, more importantly, a
  throttled *benchmark* is meaningless.

### Alternative: cross-compile, or build in a container

Cross-compilation is deliberately **not** part of the supported path. Building
on the device removes an entire class of "is the toolchain the difference?"
questions when interpreting results, which matters more here than build
convenience does.

If build time is prohibitive, run the Docker image on the Pi instead — the
Dockerfile builds for the host architecture and pins everything:

```bash
docker build -f docker/Dockerfile -t pqtls-lab:local .
```

## Build

```bash
scripts/build.sh --release --jobs 2
```

Release, not RelWithDebInfo: on constrained hardware the difference is worth
having, and debug information is rarely what you want on the device.

If a pinned OpenSSL was installed:

```bash
scripts/build.sh --release --openssl-root /opt/openssl-3.5.7 --jobs 2
export LD_LIBRARY_PATH=/opt/openssl-3.5.7/lib
```

## Verify before measuring

```bash
scripts/verify-environment.sh
./build/release/pqtls-client capabilities
```

If the post-quantum groups are absent, the hybrid rows in every result must be
recorded as **SKIPPED with the reason** — never as passes, and never omitted.

## Measuring

### Record the thermal and power state first

This is not optional. A Pi that throttles produces timings for a throttled
device, and nothing in the timing data itself reveals that.

```bash
# Raspberry Pi OS
vcgencmd measure_temp
vcgencmd measure_clock arm
vcgencmd get_throttled        # 0x0 = has not throttled

# Any Linux
cat /sys/class/thermal/thermal_zone0/temp   # millidegrees Celsius
```

`get_throttled` bits worth knowing:

| Bit | Meaning |
|---|---|
| 0 | Under-voltage **now** |
| 1 | ARM frequency capped now |
| 2 | Currently throttled |
| 16 | Under-voltage **has occurred** |
| 18 | Throttling **has occurred** |

Bit 16 set means the power supply is inadequate, and the device will throttle
regardless of temperature. Fix that before measuring anything.

### Run

```bash
scripts/generate-classical-certs.sh --with-client

python3 scripts/run-benchmarks.py \
  --experiment-id rpi5-baseline \
  --build-dir build/release \
  --profiles classical-x25519 hybrid-x25519-mlkem768 hybrid-p256-mlkem768 \
  --connections 100 \
  --concurrency 1 4 \
  --payloads 100 1024
```

Keep concurrency at or below the core count. Beyond that the measurement is
dominated by scheduling rather than by cryptography.

### Record the thermal state again

```bash
vcgencmd measure_temp
vcgencmd get_throttled
```

**If throttling occurred during the run, say so in the results.** The numbers are
still real; they describe a throttled device, which is a different claim.

### Monitor during a long run

```bash
while true; do
  printf '%s temp=%s clock=%s throttled=%s\n' \
    "$(date -Iseconds)" \
    "$(vcgencmd measure_temp)" \
    "$(vcgencmd measure_clock arm)" \
    "$(vcgencmd get_throttled)"
  sleep 5
done | tee experiments/results/rpi-thermal.log
```

## What to measure

| Quantity | How |
|---|---|
| Handshake duration | `handshake_ms` in the metrics records |
| CPU time | `process_cpu_user_ms`, `process_cpu_system_ms` |
| Peak memory | `peak_memory_kib` (process-wide, a high-water mark) |
| Temperature | `vcgencmd measure_temp` before and after |
| Throttling | `vcgencmd get_throttled` before and after |
| Clock frequency | `vcgencmd measure_clock arm` |
| Build duration | `/usr/bin/time -v`, measured not estimated |

### Energy

Energy consumption **cannot be measured from software on the device.** It
requires external instrumentation:

- an inline USB power meter, for a whole-device figure;
- a bench supply with current logging, for better resolution;
- a shunt resistor and a data logger, for the best resolution.

Any energy figure must name the instrument used. A number without one is not a
measurement.

## The comparison experiment

`experiments/definitions/raspberry-pi.yaml` defines a three-platform comparison:

| Platform | Role |
|---|---|
| Desktop x86-64 | Reference |
| VM on the same host | Isolates virtualisation overhead |
| Raspberry Pi | The constrained target |

Run the identical matrix on each, from a clean checkout, and record the platform
metadata for every one. The interesting quantity is not the absolute Pi timing —
it is whether the **relative** hybrid overhead is larger on constrained hardware
than on a desktop. That is the actual research question, and it is not assumed.

## Confounders specific to a Pi

| Confounder | Effect | Mitigation |
|---|---|---|
| **Thermal throttling** | Dominant. Silently changes every timing | Record `get_throttled`; use active cooling; state the arrangement |
| **Under-voltage** | Throttles regardless of temperature | Use the official supply; check bit 16 |
| **SD card variance** | I/O-bound timings become card measurements | Use a USB SSD; report the medium |
| **Swap** | A swapping benchmark measures storage | Ensure enough RAM; disable swap or report it |
| **Background services** | Steal CPU on a small core count | Minimal install; record what runs |
| **Wi-Fi versus Ethernet** | Very different latency and loss | Use Ethernet; report which |
| **`cpufreq` governor** | Frequency scaling adds variance | `sudo cpupower frequency-set -g performance` |

## Reporting

Include with any Pi result:

- Model and revision (`cat /proc/cpuinfo | grep -E 'Model|Revision'`)
- Memory
- OS and kernel (`uname -a`, `/etc/os-release`)
- Storage medium
- Cooling arrangement
- Power supply
- `vcgencmd get_throttled` before and after
- Temperature before and after
- OpenSSL version, and whether system or pinned
- Git commit and build type
- Whether the network was Ethernet or Wi-Fi

## Current status

**No Raspberry Pi measurements exist in this repository.**

`experiments/definitions/raspberry-pi.yaml` says `Results not yet measured`, and
that is accurate. Inventing plausible figures for a constrained device would be
worse than having none: a reader has no way to distinguish a real Pi timing from
a guess, and edge-device feasibility is precisely the kind of claim people
propagate without checking.
