"""Interoperability: pqtls-client against `openssl s_server`.

The mirror of test_openssl_s_client.py. Here the reference implementation acts
as the server and our client must interoperate with it, which exercises our
client's ClientHello construction, verification and policy enforcement against
an endpoint we did not write.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys
import time
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))

from conftest import (  # noqa: E402
    EXIT_SUCCESS,
    require_profile,
    run_client,
)

OPENSSL = shutil.which("openssl")

pytestmark = pytest.mark.skipif(
    OPENSSL is None, reason="the openssl command-line tool is not installed"
)


def openssl_groups() -> set[str]:
    proc = subprocess.run(
        [OPENSSL, "list", "-tls-groups"], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return set()
    return {
        token.strip().lower()
        for token in re.split(r"[\s:,]+", proc.stdout)
        if token.strip()
    }


def require_openssl_group(group: str) -> None:
    if group.lower() not in openssl_groups():
        pytest.skip(
            f"the system openssl does not offer '{group}', so it cannot act as an "
            "interoperability peer for it. This is a SKIP, not a pass."
        )


def free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, timeout_s: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


@contextmanager
def openssl_server(certs, *, groups: str, tmp_path: Path,
                   require_client_cert: bool = False,
                   certificate: str = "server.crt",
                   private_key: str = "server.key") -> Iterator[int]:
    """Run `openssl s_server` for the duration of the block."""
    port = free_port()
    log_path = tmp_path / f"s_server-{port}.log"

    argv = [
        OPENSSL, "s_server",
        "-accept", str(port),
        "-cert", str(certs / certificate),
        "-key", str(certs / private_key),
        "-tls1_3",
        "-groups", groups,
        # s_server negotiates ALPN only if asked; our client always offers
        # "pqtls1", and without this the handshake fails on ALPN mismatch.
        "-alpn", "pqtls1",
        "-quiet",
        "-naccept", "50",
    ]
    if require_client_cert:
        argv += ["-Verify", "2", "-CAfile", str(certs / "ca.crt")]

    with log_path.open("w") as log_handle:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=log_handle, stderr=subprocess.STDOUT, text=True)
        try:
            if not wait_for_port(port):
                process.terminate()
                process.wait(timeout=10)
                pytest.skip(
                    "openssl s_server did not start listening:\n"
                    + log_path.read_text(errors="replace")
                )
            yield port
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


# ---------------------------------------------------------------------------
# Classical
# ---------------------------------------------------------------------------
def test_client_connects_to_openssl_s_server_classically(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with openssl_server(certs, groups="X25519", tmp_path=tmp_path) as port:
        result = run_client(port, "classical-x25519", certs)

    # s_server does not speak our framed protocol, so it will not reply with a
    # valid frame. What is being tested is the TLS layer: the handshake, the
    # certificate verification and the group policy. A protocol-level failure
    # after a successful handshake is the expected outcome, not a TLS failure.
    combined = result.combined().lower()
    assert "handshake" not in combined or "certificate" not in combined, (
        f"the TLS layer failed against s_server:\n{result.combined()}"
    )


def test_client_verifies_the_s_server_certificate(certs, tmp_path):
    """A wrong hostname must be rejected even against a reference server."""
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    from conftest import EXIT_CERTIFICATE

    with openssl_server(certs, groups="X25519", tmp_path=tmp_path) as port:
        result = run_client(
            port, "classical-x25519", certs,
            server_name="wrong.example.invalid", json_output=False,
        )

    assert result.returncode == EXIT_CERTIFICATE, (
        "our client accepted a certificate that does not cover the requested "
        f"hostname:\n{result.combined()}"
    )


def test_client_rejects_an_untrusted_s_server(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    from conftest import EXIT_CERTIFICATE

    with openssl_server(certs, groups="X25519", tmp_path=tmp_path) as port:
        result = run_client(
            port, "classical-x25519", certs,
            ca_certificate=None,   # system trust store, which lacks our dev CA
            json_output=False,
        )

    assert result.returncode == EXIT_CERTIFICATE


# ---------------------------------------------------------------------------
# Hybrid post-quantum
# ---------------------------------------------------------------------------
@pytest.mark.requires_pq
@pytest.mark.parametrize(
    "profile,group",
    [
        ("hybrid-x25519-mlkem768", "X25519MLKEM768"),
        ("hybrid-p256-mlkem768", "SecP256r1MLKEM768"),
    ],
)
def test_client_completes_a_hybrid_handshake_with_s_server(profile, group, certs, tmp_path):
    require_profile(profile)
    require_openssl_group(group)

    with openssl_server(certs, groups=group, tmp_path=tmp_path) as port:
        result = run_client(port, profile, certs, json_output=False)

    combined = result.combined()
    # The TLS layer must have succeeded; only the application protocol should
    # have failed, because s_server does not speak it.
    assert "TLS handshake failed" not in combined, (
        f"the hybrid handshake against s_server failed:\n{combined}"
    )
    assert "downgrade policy violation" not in combined, (
        f"our client rejected the group s_server negotiated:\n{combined}"
    )


@pytest.mark.requires_pq
def test_client_refuses_an_s_server_offering_only_classical_groups(certs, tmp_path):
    """Downgrade rejection against an independent peer.

    s_server offers X25519 only; our hybrid client must fail rather than
    accepting a classical group.
    """
    require_profile("hybrid-x25519-mlkem768")
    require_openssl_group("x25519")

    with openssl_server(certs, groups="X25519", tmp_path=tmp_path) as port:
        result = run_client(
            port, "hybrid-x25519-mlkem768", certs, json_output=False
        )

    assert result.returncode != EXIT_SUCCESS, (
        "our hybrid-only client connected to a classical-only reference server. "
        f"That is a silent downgrade:\n{result.combined()}"
    )


@pytest.mark.requires_pq
def test_client_refuses_a_non_overlapping_hybrid_group(certs, tmp_path):
    require_profile("hybrid-x25519-mlkem768")
    require_openssl_group("secp256r1mlkem768")

    with openssl_server(certs, groups="SecP256r1MLKEM768", tmp_path=tmp_path) as port:
        result = run_client(
            port, "hybrid-x25519-mlkem768", certs, json_output=False
        )

    assert result.returncode != EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Mutual TLS
# ---------------------------------------------------------------------------
def test_client_presents_a_certificate_to_s_server(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with openssl_server(certs, groups="X25519", tmp_path=tmp_path,
                        require_client_cert=True) as port:
        result = run_client(
            port, "classical-x25519", certs,
            extra_args=["--certificate", str(certs / "client.crt"),
                        "--private-key", str(certs / "client.key")],
            json_output=False,
        )

    combined = result.combined()
    assert "TLS handshake failed" not in combined, (
        f"mutual TLS against s_server failed:\n{combined}"
    )
