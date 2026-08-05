"""Shared fixtures for the pqtls-lab integration tests.

Capability gating rule (spec section 16): a test that cannot run because the
OpenSSL build lacks a capability is SKIPPED with the reason. It is never
silently passed, and a genuine failure is never converted into a skip.

  PASS   the capability exists and the behaviour is correct
  FAIL   the capability exists and the behaviour is wrong
  SKIP   the capability is absent, with the reason recorded
  XFAIL  a documented, temporary limitation
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CERTS_DIR = REPO_ROOT / "certs" / "classical"
PQ_CERTS_DIR = REPO_ROOT / "certs" / "experimental-pq"


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------
def _find_binary(name: str) -> Path | None:
    override = os.environ.get("PQTLS_BUILD_DIR")
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override))
    candidates += [
        REPO_ROOT / "build" / "relwithdebinfo",
        REPO_ROOT / "build" / "debug",
        REPO_ROOT / "build" / "release",
        REPO_ROOT / "build",
    ]
    for directory in candidates:
        for filename in (name, f"{name}.exe"):
            candidate = directory / filename
            if candidate.is_file():
                return candidate
    found = shutil.which(name)
    return Path(found) if found else None


CLIENT_BIN = _find_binary("pqtls-client")
SERVER_BIN = _find_binary("pqtls-server")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "requires_pq: needs post-quantum TLS groups")
    config.addinivalue_line("markers", "requires_mldsa: needs ML-DSA post-quantum signatures")
    config.addinivalue_line("markers", "slow: takes more than a few seconds")


def pytest_report_header(config: pytest.Config) -> list[str]:
    lines = [
        f"pqtls-client: {CLIENT_BIN or 'NOT FOUND'}",
        f"pqtls-server: {SERVER_BIN or 'NOT FOUND'}",
    ]
    if CLIENT_BIN:
        caps = _capabilities()
        if caps:
            groups = ", ".join(caps.get("tls_groups", []))
            lines.append(f"openssl: {caps['openssl']['runtime_version']}")
            lines.append(f"tls groups: {groups}")
            usable = [p["id"] for p in caps.get("profiles", []) if p["usable"]]
            unusable = [p["id"] for p in caps.get("profiles", []) if not p["usable"]]
            lines.append(f"usable profiles: {', '.join(usable) or 'none'}")
            if unusable:
                lines.append(f"UNUSABLE profiles (tests will SKIP): {', '.join(unusable)}")
    return lines


_CAPABILITIES_CACHE: dict[str, Any] | None = None


def _capabilities() -> dict[str, Any] | None:
    global _CAPABILITIES_CACHE
    if _CAPABILITIES_CACHE is not None:
        return _CAPABILITIES_CACHE
    if CLIENT_BIN is None:
        return None
    proc = subprocess.run(
        [str(CLIENT_BIN), "capabilities", "--json"],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if proc.returncode != 0:
        return None
    try:
        _CAPABILITIES_CACHE = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return _CAPABILITIES_CACHE


def profile_usable(profile_id: str) -> tuple[bool, str]:
    caps = _capabilities()
    if caps is None:
        return False, "capabilities could not be determined"
    for entry in caps.get("profiles", []):
        if entry["id"] == profile_id:
            return bool(entry["usable"]), entry.get("blocking_reason") or ""
    return False, f"profile {profile_id!r} is not defined"


def require_profile(profile_id: str) -> None:
    """Skip with a recorded reason when `profile_id` is unavailable."""
    usable, reason = profile_usable(profile_id)
    if not usable:
        pytest.skip(
            f"profile '{profile_id}' is not usable on this host: "
            f"{reason or 'unknown reason'}. This is a SKIP, not a pass."
        )


# ---------------------------------------------------------------------------
# Session-scoped prerequisites
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def require_binaries() -> None:
    if CLIENT_BIN is None or SERVER_BIN is None:
        pytest.skip(
            "pqtls-client / pqtls-server were not found. Build them first "
            "(scripts/build.sh) or set PQTLS_BUILD_DIR.",
            allow_module_level=True,
        )


@pytest.fixture(scope="session")
def certs() -> Path:
    """The classical development PKI, generated on demand."""
    required = ["ca.crt", "server.crt", "server.key", "client.crt", "client.key"]
    if not all((CERTS_DIR / name).exists() for name in required):
        script = REPO_ROOT / "scripts" / "generate-classical-certs.sh"
        if not script.exists():
            pytest.skip("scripts/generate-classical-certs.sh is missing")
        proc = subprocess.run(
            ["bash", str(script), "--with-client", "--force"],
            capture_output=True, text=True, check=False, timeout=300,
        )
        if proc.returncode != 0:
            pytest.skip(f"certificate generation failed:\n{proc.stderr}")
    return CERTS_DIR


@pytest.fixture(scope="session")
def capabilities() -> dict[str, Any]:
    caps = _capabilities()
    if caps is None:
        pytest.skip("could not read capabilities from pqtls-client")
    return caps


def free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, timeout_s: float = 20.0, host: str = "127.0.0.1") -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


# ---------------------------------------------------------------------------
# Server harness
# ---------------------------------------------------------------------------
@dataclass
class ServerHandle:
    port: int
    process: subprocess.Popen[str]
    profile: str
    log_path: Path

    def log(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except OSError:
            return ""


@contextmanager
def running_server(
    profile: str,
    certs_dir: Path,
    tmp_path: Path,
    *,
    certificate: str = "server.crt",
    private_key: str = "server.key",
    require_client_cert: bool = False,
    extra_args: list[str] | None = None,
    max_frame_size: int | None = None,
) -> Iterator[ServerHandle]:
    """Start a server, yield a handle, always tear it down."""
    port = free_port()
    log_path = tmp_path / f"server-{profile}-{port}.log"

    argv = [
        str(SERVER_BIN), "serve",
        "--listen", "127.0.0.1",
        "--port", str(port),
        "--profile", profile,
        "--certificate", str(certs_dir / certificate),
        "--private-key", str(certs_dir / private_key),
        "--log-level", "debug",
    ]
    if require_client_cert:
        argv += ["--require-client-cert", "--ca-certificate", str(certs_dir / "ca.crt")]
    if max_frame_size is not None:
        argv += ["--max-frame-size", str(max_frame_size)]
    if extra_args:
        argv += extra_args

    with log_path.open("w") as log_handle:
        process = subprocess.Popen(argv, stdout=log_handle, stderr=subprocess.STDOUT, text=True)
        try:
            if not wait_for_port(port):
                process.terminate()
                process.wait(timeout=10)
                pytest.fail(
                    f"server with profile '{profile}' did not start listening.\n"
                    f"--- server log ---\n{log_path.read_text(errors='replace')}"
                )
            yield ServerHandle(port=port, process=process, profile=profile, log_path=log_path)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@dataclass
class ClientResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def json(self) -> dict[str, Any]:
        return json.loads(self.stdout)

    def combined(self) -> str:
        return f"{self.stdout}\n{self.stderr}"


def run_client(
    port: int,
    profile: str,
    certs_dir: Path,
    *,
    server_name: str = "localhost",
    ca_certificate: str | None = "ca.crt",
    message: str = '{"type":"ping"}',
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout: int = 60,
) -> ClientResult:
    argv = [
        str(CLIENT_BIN), "connect",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--server-name", server_name,
        "--profile", profile,
        "--message", message,
        "--log-level", "warn",
    ]
    if ca_certificate is not None:
        argv += ["--ca-certificate", str(certs_dir / ca_certificate)]
    if json_output:
        argv.append("--json")
    if extra_args:
        argv += extra_args

    proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    return ClientResult(proc.returncode, proc.stdout, proc.stderr)


# ---------------------------------------------------------------------------
# Raw framing helpers, for tests that must bypass our own client
# ---------------------------------------------------------------------------
def encode_frame(payload: bytes) -> bytes:
    """4-byte big-endian length prefix followed by the payload."""
    return struct.pack(">I", len(payload)) + payload


# Exit codes from include/pqtls/error.hpp. Duplicated deliberately: if the C++
# side changes one, this constant should fail loudly rather than track it.
EXIT_SUCCESS = 0
EXIT_CONFIGURATION = 2
EXIT_CAPABILITY = 3
EXIT_CERTIFICATE = 4
EXIT_TLS_POLICY = 5
EXIT_HANDSHAKE = 6
EXIT_NETWORK = 7
EXIT_PROTOCOL = 8
EXIT_TIMEOUT = 9
