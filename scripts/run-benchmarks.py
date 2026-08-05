#!/usr/bin/env python3
"""Benchmark orchestration for pqtls-lab.

Runs a matrix of TLS profiles, concurrency levels and payload sizes, preserving
every raw measurement.

Design rules that this script exists to enforce:

  * Capabilities are verified before anything runs. A profile that this OpenSSL
    cannot provide is recorded as SKIPPED with the reason. It is never quietly
    dropped and never counted as a pass.
  * Raw per-connection records are never deleted, overwritten or filtered.
    Summary statistics are derived from them by analyze-results.py, which can
    always be re-run against the originals.
  * Failed connections are kept. A benchmark that reports only its successes
    overstates reliability.
  * System metadata is captured with the results, because a latency figure
    without the CPU, the OpenSSL version and the commit it came from is not a
    reproducible measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD_DIR = REPO_ROOT / "build" / "relwithdebinfo"
DEFAULT_RESULTS_DIR = REPO_ROOT / "experiments" / "results"
DEFAULT_CERTS_DIR = REPO_ROOT / "certs" / "classical"

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class RunSpec:
    """One cell of the benchmark matrix."""

    profile: str
    connections: int
    concurrency: int
    payload_bytes: int
    reuse_session: bool = False
    messages_per_connection: int = 1

    def label(self) -> str:
        suffix = "-resume" if self.reuse_session else ""
        return (
            f"{self.profile}-c{self.connections}"
            f"-p{self.concurrency}-b{self.payload_bytes}{suffix}"
        )


@dataclass
class RunOutcome:
    spec: RunSpec
    status: str  # "completed" | "skipped" | "failed"
    reason: str = ""
    metrics_file: str = ""
    exit_code: int | None = None
    wall_clock_s: float = 0.0
    stdout_tail: str = ""


@dataclass
class SystemMetadata:
    """Everything needed to interpret a measurement later."""

    timestamp: str
    hostname: str
    platform: str
    machine: str
    processor: str
    cpu_model: str
    cpu_cores_logical: int | None
    cpu_cores_physical: int | None
    memory_total_kib: int | None
    kernel: str
    os_release: str
    python_version: str
    openssl_runtime: str
    openssl_providers: list[str]
    git_commit: str
    git_dirty: bool
    build_type: str
    compiler: str
    binary_version: str
    config_hash: str


# ---------------------------------------------------------------------------
# Metadata collection
# ---------------------------------------------------------------------------
def _read_cpu_model() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
            if line.lower().startswith("hardware"):  # Raspberry Pi reports this
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def _read_memory_kib() -> int | None:
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                try:
                    return int(line.split()[1])
                except (IndexError, ValueError):
                    return None
    return None


def _physical_cores() -> int | None:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists():
        return None
    ids = set()
    physical_id = core_id = None
    for line in cpuinfo.read_text(errors="replace").splitlines():
        if line.startswith("physical id"):
            physical_id = line.split(":", 1)[1].strip()
        elif line.startswith("core id"):
            core_id = line.split(":", 1)[1].strip()
            if physical_id is not None:
                ids.add((physical_id, core_id))
    return len(ids) or None


def _os_release() -> str:
    path = Path("/etc/os-release")
    if not path.exists():
        return platform.platform()
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.platform()


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s: {' '.join(cmd)}"


def _git_info() -> tuple[str, bool]:
    code, out, _ = _run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"])
    commit = out.strip() if code == 0 and out.strip() else "unknown"
    code, out, _ = _run(["git", "-C", str(REPO_ROOT), "status", "--porcelain"])
    dirty = bool(out.strip()) if code == 0 else False
    return commit, dirty


def collect_metadata(client_bin: Path, config_hash: str, build_type: str) -> SystemMetadata:
    openssl_runtime = "unknown"
    providers: list[str] = []
    binary_version = "unknown"

    code, out, _ = _run([str(client_bin), "capabilities", "--json"])
    if code == 0:
        try:
            caps = json.loads(out)
            openssl_runtime = caps["openssl"]["runtime_version"]
            providers = caps["openssl"]["providers"]
        except (json.JSONDecodeError, KeyError):
            pass

    code, out, _ = _run([str(client_bin), "--version"])
    if code == 0:
        binary_version = out.strip()

    compiler = "unknown"
    code, out, _ = _run(["g++", "--version"])
    if code == 0 and out:
        compiler = out.splitlines()[0]

    commit, dirty = _git_info()

    return SystemMetadata(
        timestamp=datetime.now(timezone.utc).isoformat(),
        hostname=socket.gethostname(),
        platform=platform.platform(),
        machine=platform.machine(),
        processor=platform.processor(),
        cpu_model=_read_cpu_model(),
        cpu_cores_logical=os.cpu_count(),
        cpu_cores_physical=_physical_cores(),
        memory_total_kib=_read_memory_kib(),
        kernel=platform.release(),
        os_release=_os_release(),
        python_version=platform.python_version(),
        openssl_runtime=openssl_runtime,
        openssl_providers=providers,
        git_commit=commit,
        git_dirty=dirty,
        build_type=build_type,
        compiler=compiler,
        binary_version=binary_version,
        config_hash=config_hash,
    )


# ---------------------------------------------------------------------------
# Capability gating
# ---------------------------------------------------------------------------
def usable_profiles(client_bin: Path) -> dict[str, tuple[bool, str]]:
    """Map profile id -> (usable, blocking reason)."""
    code, out, err = _run([str(client_bin), "capabilities", "--json"])
    if code != 0:
        raise SystemExit(
            f"cannot determine capabilities: '{client_bin} capabilities' exited {code}\n{err}"
        )
    try:
        caps = json.loads(out)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"capabilities output was not valid JSON: {exc}") from exc

    return {
        entry["id"]: (bool(entry["usable"]), entry.get("blocking_reason") or "")
        for entry in caps.get("profiles", [])
    }


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
def wait_for_port(host: str, port: int, timeout_s: float = 15.0) -> bool:
    """Poll until the listener accepts, rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class ServerProcess:
    """Context manager owning a pqtls-server child process."""

    def __init__(self, argv: list[str], host: str, port: int, log_path: Path) -> None:
        self.argv = argv
        self.host = host
        self.port = port
        self.log_path = log_path
        self.proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> ServerProcess:
        self.log_handle = self.log_path.open("ab")
        self.proc = subprocess.Popen(
            self.argv, stdout=self.log_handle, stderr=subprocess.STDOUT
        )
        if not wait_for_port(self.host, self.port):
            self.__exit__(None, None, None)
            raise RuntimeError(
                f"the server did not start listening on {self.host}:{self.port}. "
                f"See {self.log_path}."
            )
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log_handle.close()


# ---------------------------------------------------------------------------
# Benchmark execution
# ---------------------------------------------------------------------------
def build_payload_message(payload_bytes: int) -> str:
    """A telemetry message padded to approximately `payload_bytes`."""
    if payload_bytes <= 0:
        return '{"type":"ping"}'

    envelope = {
        "protocol_version": 1,
        "type": "telemetry",
        "payload": {"device_id": "bench-001", "temperature": 24.6, "status": "normal", "pad": ""},
    }
    overhead = len(json.dumps(envelope))
    padding = max(0, payload_bytes - overhead)
    envelope["payload"]["pad"] = "x" * padding
    return json.dumps(envelope)


def run_one(
    spec: RunSpec,
    args: argparse.Namespace,
    client_bin: Path,
    server_bin: Path,
    results_dir: Path,
    experiment_id: str,
) -> RunOutcome:
    metrics_file = results_dir / f"{experiment_id}-{spec.label()}.jsonl"
    server_metrics = results_dir / f"{experiment_id}-{spec.label()}-server.jsonl"
    server_log = results_dir / f"{experiment_id}-{spec.label()}-server.log"

    message = build_payload_message(spec.payload_bytes)
    message_file = results_dir / f".message-{spec.label()}.json"
    message_file.write_text(message, encoding="utf-8")

    server_argv = [
        str(server_bin), "serve",
        "--listen", args.host,
        "--port", str(args.port),
        "--profile", spec.profile,
        "--certificate", str(args.certificate),
        "--private-key", str(args.private_key),
        "--metrics", str(server_metrics),
        "--experiment-id", experiment_id,
        "--max-connections", str(max(spec.concurrency * 2, 16)),
        "--log-level", "warn",
    ]

    client_argv = [
        str(client_bin), "benchmark",
        "--host", args.host,
        "--port", str(args.port),
        "--server-name", args.server_name,
        "--profile", spec.profile,
        "--ca-certificate", str(args.ca_certificate),
        "--connections", str(spec.connections),
        "--concurrency", str(spec.concurrency),
        "--warmup", str(args.warmup),
        "--messages-per-connection", str(spec.messages_per_connection),
        "--message-file", str(message_file),
        "--output", str(metrics_file),
        "--experiment-id", experiment_id,
        "--json",
    ]
    if spec.reuse_session:
        client_argv.append("--reuse-session")

    started = time.monotonic()
    try:
        with ServerProcess(server_argv, args.host, args.port, server_log):
            code, out, err = _run(client_argv, timeout=args.timeout)
    except RuntimeError as exc:
        return RunOutcome(
            spec=spec, status="failed", reason=str(exc),
            metrics_file=str(metrics_file), wall_clock_s=time.monotonic() - started,
        )
    finally:
        message_file.unlink(missing_ok=True)

    elapsed = time.monotonic() - started
    tail = (out or err or "").strip()[-800:]

    if code != 0:
        # A non-zero exit is recorded, not swallowed. The raw records that were
        # written before the failure stay on disk.
        return RunOutcome(
            spec=spec, status="failed",
            reason=f"the client exited {code}",
            metrics_file=str(metrics_file), exit_code=code,
            wall_clock_s=elapsed, stdout_tail=tail,
        )

    return RunOutcome(
        spec=spec, status="completed", metrics_file=str(metrics_file),
        exit_code=0, wall_clock_s=elapsed, stdout_tail=tail,
    )


def build_matrix(args: argparse.Namespace) -> list[RunSpec]:
    specs: list[RunSpec] = []
    for profile in args.profiles:
        for concurrency in args.concurrency:
            for payload in args.payloads:
                if concurrency > args.connections:
                    continue
                specs.append(
                    RunSpec(
                        profile=profile,
                        connections=args.connections,
                        concurrency=concurrency,
                        payload_bytes=payload,
                        messages_per_connection=args.messages_per_connection,
                    )
                )
                if args.session_resumption:
                    specs.append(
                        RunSpec(
                            profile=profile,
                            connections=args.connections,
                            concurrency=concurrency,
                            payload_bytes=payload,
                            reuse_session=True,
                            messages_per_connection=args.messages_per_connection,
                        )
                    )
    return specs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the pqtls-lab benchmark matrix and preserve every raw measurement.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Compare classical and hybrid at 100 connections
  scripts/run-benchmarks.py --profiles classical-x25519 hybrid-x25519-mlkem768

  # Full matrix from the spec: concurrency 1/10/50, four payload sizes
  scripts/run-benchmarks.py --connections 100 --concurrency 1 10 50 \\
      --payloads 100 1024 1048576 10485760

  # See what would run without running it
  scripts/run-benchmarks.py --dry-run
""",
    )
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--certificate", type=Path, default=DEFAULT_CERTS_DIR / "server.crt")
    parser.add_argument("--private-key", type=Path, default=DEFAULT_CERTS_DIR / "server.key")
    parser.add_argument("--ca-certificate", type=Path, default=DEFAULT_CERTS_DIR / "ca.crt")
    parser.add_argument(
        "--profiles", nargs="+",
        default=["classical-x25519", "classical-p256",
                 "hybrid-x25519-mlkem768", "hybrid-p256-mlkem768"],
    )
    parser.add_argument("--connections", type=int, default=100,
                        help="connections per cell (spec minimum: 100)")
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1, 10, 50])
    parser.add_argument("--payloads", nargs="+", type=int, default=[100, 1024],
                        help="application payload sizes in bytes")
    parser.add_argument("--messages-per-connection", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=10,
                        help="discarded warm-up connections per cell")
    parser.add_argument("--session-resumption", action="store_true",
                        help="also measure each cell with session resumption")
    parser.add_argument("--timeout", type=int, default=900,
                        help="per-cell timeout in seconds")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-experimental", action="store_true",
                        help="permit profiles marked experimental")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    client_bin = args.build_dir / "pqtls-client"
    server_bin = args.build_dir / "pqtls-server"
    for binary in (client_bin, server_bin):
        if not binary.exists():
            # Also accept a Windows-style name so the script is usable from a
            # cross-platform checkout.
            if binary.with_suffix(".exe").exists():
                continue
            print(f"error: {binary} not found. Run scripts/build.sh first.", file=sys.stderr)
            return 2

    for path in (args.certificate, args.private_key, args.ca_certificate):
        if not path.exists():
            print(
                f"error: {path} not found. "
                "Run scripts/generate-classical-certs.sh first.",
                file=sys.stderr,
            )
            return 2

    args.results_dir.mkdir(parents=True, exist_ok=True)

    experiment_id = args.experiment_id or datetime.now(timezone.utc).strftime(
        "bench-%Y%m%dT%H%M%SZ"
    )

    # The configuration hash ties a set of results to the exact matrix that
    # produced them, so two runs cannot be confused for one another.
    config_blob = json.dumps(
        {k: (str(v) if isinstance(v, Path) else v) for k, v in sorted(vars(args).items())},
        sort_keys=True,
    )
    config_hash = hashlib.sha256(config_blob.encode()).hexdigest()[:16]

    print(f"experiment id : {experiment_id}")
    print(f"config hash   : {config_hash}")
    print(f"results dir   : {args.results_dir}")
    print()

    # --- Capability gate ----------------------------------------------------
    availability = usable_profiles(client_bin)

    specs = build_matrix(args)
    runnable: list[RunSpec] = []
    skipped: list[RunOutcome] = []

    for spec in specs:
        usable, reason = availability.get(spec.profile, (False, "profile is not defined"))
        if not usable:
            skipped.append(
                RunOutcome(spec=spec, status="skipped",
                           reason=reason or "the profile is not usable on this host")
            )
            continue
        runnable.append(spec)

    print(f"matrix        : {len(specs)} cells ({len(runnable)} runnable, {len(skipped)} skipped)")
    for outcome in skipped:
        print(f"  SKIP {outcome.spec.label()}: {outcome.reason}")
    print()

    if args.dry_run:
        for spec in runnable:
            print(f"  would run {spec.label()}")
        return 0

    if not runnable:
        print("error: no runnable cells. Check 'pqtls-client capabilities'.", file=sys.stderr)
        return 3

    metadata = collect_metadata(client_bin, config_hash, "unknown")

    # Metadata is written before the runs, so an interrupted benchmark still
    # leaves behind the context needed to interpret whatever completed.
    manifest_path = args.results_dir / f"{experiment_id}-manifest.json"
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "config_hash": config_hash,
        "started": datetime.now(timezone.utc).isoformat(),
        "arguments": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
        "system": asdict(metadata),
        "runs": [],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    outcomes: list[RunOutcome] = list(skipped)

    for index, spec in enumerate(runnable, start=1):
        print(f"[{index}/{len(runnable)}] {spec.label()}", flush=True)
        outcome = run_one(spec, args, client_bin, server_bin, args.results_dir, experiment_id)
        outcomes.append(outcome)
        status = outcome.status.upper()
        print(f"    {status} in {outcome.wall_clock_s:.1f}s -> {outcome.metrics_file}")
        if outcome.status == "failed":
            print(f"    reason: {outcome.reason}")

        # Rewrite the manifest after every cell so a crash loses at most the
        # cell in flight.
        manifest["runs"] = [
            {**asdict(o), "spec": asdict(o.spec)} for o in outcomes
        ]
        manifest["finished"] = datetime.now(timezone.utc).isoformat()
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    completed = sum(1 for o in outcomes if o.status == "completed")
    failed = sum(1 for o in outcomes if o.status == "failed")
    skipped_count = sum(1 for o in outcomes if o.status == "skipped")

    print()
    print("summary")
    print(f"  completed : {completed}")
    print(f"  failed    : {failed}")
    print(f"  skipped   : {skipped_count}")
    print(f"  manifest  : {manifest_path}")
    print()
    print("next:")
    print(f"  python3 scripts/analyze-results.py {args.results_dir} "
          f"--experiment-id {experiment_id}")

    if completed == 0:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
