"""Interoperability: `openssl s_client` against pqtls-server.

Testing against an independent implementation is what turns "our client and our
server agree" into "our server speaks TLS". A bug present in both of our
endpoints would be invisible to the integration suite.

Capability gating: when the system `openssl` does not know a group, the test
SKIPS with that reason. It is never reported as a pass.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))

from conftest import (  # noqa: E402
    require_profile,
    running_server,
)

OPENSSL = shutil.which("openssl")

pytestmark = pytest.mark.skipif(
    OPENSSL is None, reason="the openssl command-line tool is not installed"
)


def openssl_version() -> str:
    proc = subprocess.run([OPENSSL, "version"], capture_output=True, text=True, check=False)
    return proc.stdout.strip()


def openssl_groups() -> set[str]:
    """Groups the system openssl advertises, lower-cased for comparison."""
    proc = subprocess.run(
        [OPENSSL, "list", "-tls-groups"], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return set()
    names: set[str] = set()
    for token in re.split(r"[\s:,]+", proc.stdout):
        cleaned = token.strip()
        if cleaned:
            names.add(cleaned.lower())
    return names


def require_openssl_group(group: str) -> None:
    if group.lower() not in openssl_groups():
        pytest.skip(
            f"the system openssl ({openssl_version()}) does not offer the group "
            f"'{group}', so it cannot act as an interoperability peer for it. "
            "This is a SKIP, not a pass."
        )


def s_client(port: int, certs, *, groups: str, server_name: str = "localhost",
             extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    argv = [
        OPENSSL, "s_client",
        "-connect", f"127.0.0.1:{port}",
        "-tls1_3",
        "-groups", groups,
        "-CAfile", str(certs / "ca.crt"),
        "-servername", server_name,
        "-verify_hostname", server_name,
        "-verify_return_error",
    ]
    if extra:
        argv += extra
    return subprocess.run(
        argv, input="Q\n", capture_output=True, text=True, check=False, timeout=60
    )


def parse_negotiated_group(output: str) -> str | None:
    match = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", output)
    if match and match.group(1) != "<NULL>":
        return match.group(1)
    # Classical groups are reported through "Server Temp Key" instead.
    match = re.search(r"Server Temp Key:\s*([^,\n]+)", output)
    return match.group(1).strip() if match else None


def parse_cipher(output: str) -> str | None:
    match = re.search(r"New,\s+TLSv1\.3,\s+Cipher is\s+(\S+)", output)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Classical
# ---------------------------------------------------------------------------
def test_s_client_completes_a_classical_handshake(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        proc = s_client(server.port, certs, groups="X25519")

    output = proc.stdout + proc.stderr
    assert "New, TLSv1.3" in output, f"handshake failed:\n{output}"
    assert "Verify return code: 0 (ok)" in output, (
        f"certificate verification failed:\n{output}"
    )


def test_s_client_reports_tls13_and_an_allowlisted_cipher(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    allowed = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    }

    with running_server("classical-x25519", certs, tmp_path) as server:
        proc = s_client(server.port, certs, groups="X25519")

    output = proc.stdout + proc.stderr
    cipher = parse_cipher(output)
    assert cipher is not None, f"no cipher suite was reported:\n{output}"
    assert cipher in allowed


def test_s_client_verifies_the_certificate_chain(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        proc = s_client(server.port, certs, groups="X25519", extra=["-showcerts"])

    output = proc.stdout + proc.stderr
    assert "Verify return code: 0 (ok)" in output
    assert "pqtls-lab development CA" in output


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
def test_s_client_completes_a_hybrid_handshake(profile, group, certs, tmp_path):
    require_profile(profile)
    require_openssl_group(group)

    with running_server(profile, certs, tmp_path) as server:
        proc = s_client(server.port, certs, groups=group)

    output = proc.stdout + proc.stderr
    assert "New, TLSv1.3" in output, f"hybrid handshake failed:\n{output}"
    assert "Verify return code: 0 (ok)" in output

    negotiated = parse_negotiated_group(output)
    assert negotiated is not None, f"no negotiated group was reported:\n{output}"
    assert negotiated.lower() == group.lower(), (
        f"expected group {group}, s_client reported {negotiated}"
    )


@pytest.mark.requires_pq
def test_s_client_is_refused_when_group_policies_do_not_overlap(certs, tmp_path):
    """Independent confirmation of the server's downgrade policy."""
    require_profile("hybrid-x25519-mlkem768")
    require_openssl_group("x25519")

    with running_server("hybrid-x25519-mlkem768", certs, tmp_path) as server:
        proc = s_client(server.port, certs, groups="X25519")

    output = (proc.stdout + proc.stderr).lower()
    completed = "new, tlsv1.3" in output and "cipher is" in output
    assert not completed, (
        "a classical-only s_client completed a handshake with a hybrid-only "
        f"server:\n{proc.stdout}\n{proc.stderr}"
    )


# ---------------------------------------------------------------------------
# Protocol version enforcement
# ---------------------------------------------------------------------------
def test_s_client_cannot_negotiate_tls12(certs, tmp_path):
    require_profile("classical-x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        proc = subprocess.run(
            [OPENSSL, "s_client", "-connect", f"127.0.0.1:{server.port}",
             "-tls1_2", "-CAfile", str(certs / "ca.crt"), "-servername", "localhost"],
            input="Q\n", capture_output=True, text=True, check=False, timeout=60,
        )

    output = (proc.stdout + proc.stderr).lower()
    assert "new, tlsv1.2" not in output, (
        f"the server accepted TLS 1.2:\n{proc.stdout}\n{proc.stderr}"
    )


def test_s_client_hostname_mismatch_is_rejected(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        proc = s_client(server.port, certs, groups="X25519",
                        server_name="wrong.example.invalid")

    output = proc.stdout + proc.stderr
    assert "Verify return code: 0 (ok)" not in output, (
        f"a hostname mismatch was accepted:\n{output}"
    )


def test_s_client_without_the_ca_is_rejected(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        proc = subprocess.run(
            [OPENSSL, "s_client", "-connect", f"127.0.0.1:{server.port}",
             "-tls1_3", "-groups", "X25519", "-servername", "localhost",
             "-verify_return_error", "-verify", "2"],
            input="Q\n", capture_output=True, text=True, check=False, timeout=60,
        )

    output = proc.stdout + proc.stderr
    assert "Verify return code: 0 (ok)" not in output, (
        "the development certificate verified without its CA being trusted"
    )


# ---------------------------------------------------------------------------
# Mutual TLS
# ---------------------------------------------------------------------------
def test_s_client_mutual_tls(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with running_server("classical-x25519", certs, tmp_path,
                        require_client_cert=True) as server:
        proc = s_client(
            server.port, certs, groups="X25519",
            extra=["-cert", str(certs / "client.crt"),
                   "-key", str(certs / "client.key")],
        )

    output = proc.stdout + proc.stderr
    assert "New, TLSv1.3" in output, f"mutual TLS handshake failed:\n{output}"


def test_s_client_without_a_certificate_is_refused_under_mtls(certs, tmp_path):
    require_profile("classical-x25519")
    require_openssl_group("x25519")

    with running_server("classical-x25519", certs, tmp_path,
                        require_client_cert=True) as server:
        argv = [
            OPENSSL, "s_client",
            "-connect", f"127.0.0.1:{server.port}",
            "-tls1_3",
            "-groups", "X25519",
            "-CAfile", str(certs / "ca.crt"),
            "-servername", "localhost",
            "-verify_hostname", "localhost",
            "-verify_return_error",
            "-ign_eof",
        ]

        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            pytest.fail(
                "a client without a certificate was not rejected under mutual TLS "
                "within 5 seconds.\n"
                f"--- s_client output ---\n{stdout}{stderr}\n"
                f"--- server log ---\n{server.log()}"
            )

    output = stdout + stderr
    rejected = (
        proc.returncode != 0
        or "certificate required" in output.lower()
        or "alert" in output.lower()
    )

    assert rejected, (
        f"a client with no certificate was accepted under mutual TLS:\n{output}"
    )
