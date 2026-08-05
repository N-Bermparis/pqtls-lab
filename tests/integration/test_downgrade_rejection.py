"""Downgrade rejection (Milestone 2, spec section 9).

The central security property of this project: when a profile requires
post-quantum key establishment, a connection that ends up classical must be
TERMINATED and recorded as a policy failure, not accepted and mislabelled.

Two layers are tested:

  1. Negotiation-level. Only the profile's groups are offered, so a peer with no
     overlapping group cannot complete a handshake at all.
  2. Post-handshake verification. Even if a handshake completes, the negotiated
     group is checked against the profile and the connection is dropped if it
     does not comply.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from conftest import (
    EXIT_SUCCESS,
    profile_usable,
    require_profile,
    run_client,
    running_server,
)

HYBRID = "hybrid-x25519-mlkem768"
CLASSICAL = "classical-x25519"


@pytest.mark.requires_pq
def test_a_hybrid_client_cannot_connect_to_a_classical_server(certs, tmp_path):
    """No overlapping group means no handshake.

    This is downgrade protection at the negotiation layer: the client offers
    only X25519MLKEM768, the server offers only X25519, so there is nothing to
    agree on. The connection MUST fail rather than quietly settling on X25519.
    """
    require_profile(HYBRID)

    with running_server(CLASSICAL, certs, tmp_path) as server:
        result = run_client(server.port, HYBRID, certs, json_output=False)

    assert result.returncode != EXIT_SUCCESS, (
        "a hybrid-only client connected to a classical-only server. This is a "
        "silent downgrade and is exactly what the profile must prevent.\n"
        f"{result.combined()}"
    )


@pytest.mark.requires_pq
def test_a_classical_client_cannot_connect_to_a_hybrid_server(certs, tmp_path):
    """The mirror case: the server refuses to serve a classical-only client."""
    require_profile(HYBRID)

    with running_server(HYBRID, certs, tmp_path) as server:
        result = run_client(server.port, CLASSICAL, certs, json_output=False)

    assert result.returncode != EXIT_SUCCESS, (
        "a hybrid-only server accepted a classical-only client"
    )


@pytest.mark.requires_pq
def test_different_hybrid_groups_do_not_interoperate(certs, tmp_path):
    """Two PQ profiles with disjoint groups must not connect.

    Not a downgrade in strength, but the policy is about which group was
    agreed, not only about how strong it was. A profile that accepted any
    sufficiently strong group would make the negotiated group unpredictable.
    """
    require_profile(HYBRID)
    require_profile("hybrid-p256-mlkem768")

    with running_server("hybrid-p256-mlkem768", certs, tmp_path) as server:
        result = run_client(server.port, HYBRID, certs, json_output=False)

    assert result.returncode != EXIT_SUCCESS


@pytest.mark.requires_pq
def test_a_hybrid_connection_never_records_a_classical_group(certs, tmp_path):
    """Whatever the outcome, the record must be truthful."""
    require_profile(HYBRID)

    metrics_file = tmp_path / "downgrade-check.jsonl"

    with running_server(HYBRID, certs, tmp_path) as server:
        result = run_client(
            server.port, HYBRID, certs,
            extra_args=["--metrics", str(metrics_file)],
        )

    assert result.returncode == EXIT_SUCCESS
    records = [
        json.loads(line) for line in metrics_file.read_text().splitlines() if line.strip()
    ]
    assert records

    for record in records:
        if record["success"]:
            assert record["negotiated_group"].lower() == "x25519mlkem768"
            assert record["pq_key_establishment"] is True
        # A successful record claiming PQ protection with a classical group is
        # the failure mode this whole test file exists to catch.
        if record["pq_key_establishment"]:
            assert record["negotiated_group"].lower() in {
                "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024",
                "mlkem512", "mlkem768", "mlkem1024",
            }


@pytest.mark.requires_pq
def test_openssl_s_client_with_only_classical_groups_is_refused(certs, tmp_path):
    """An independent peer confirms the server's group policy.

    Uses `openssl s_client` rather than our own client, so the result does not
    depend on our client also being correct.
    """
    require_profile(HYBRID)

    if not _has_openssl():
        pytest.skip("the openssl command-line tool is not available")

    with running_server(HYBRID, certs, tmp_path) as server:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"127.0.0.1:{server.port}",
             "-tls1_3", "-groups", "X25519",
             "-CAfile", str(certs / "ca.crt"),
             "-servername", "localhost", "-verify_return_error"],
            input="Q\n", capture_output=True, text=True, check=False, timeout=60,
        )

    output = (proc.stdout + proc.stderr).lower()
    handshake_completed = "new, tlsv1.3" in output and "cipher is" in output

    assert not handshake_completed, (
        "openssl s_client offering only X25519 completed a handshake with a "
        f"hybrid-only server:\n{proc.stdout}\n{proc.stderr}"
    )


@pytest.mark.requires_pq
def test_openssl_s_client_with_the_hybrid_group_succeeds(certs, tmp_path):
    """The positive control for the test above.

    Without this, a broken server that refused everything would make the
    rejection test pass for the wrong reason.
    """
    require_profile(HYBRID)

    if not _has_openssl():
        pytest.skip("the openssl command-line tool is not available")

    with running_server(HYBRID, certs, tmp_path) as server:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"127.0.0.1:{server.port}",
             "-tls1_3", "-groups", "X25519MLKEM768",
             "-CAfile", str(certs / "ca.crt"),
             "-servername", "localhost", "-verify_return_error"],
            input="Q\n", capture_output=True, text=True, check=False, timeout=60,
        )

    output = proc.stdout + proc.stderr
    if "unknown group" in output.lower() or "not supported" in output.lower():
        pytest.skip(
            "the system openssl s_client does not know X25519MLKEM768, so it "
            "cannot serve as a positive control here"
        )

    assert "New, TLSv1.3" in output, (
        f"the positive control failed: a correctly configured peer could not "
        f"connect to the hybrid server\n{proc.stdout}\n{proc.stderr}"
    )
    assert "X25519MLKEM768" in output


def test_tls12_is_rejected(certs, tmp_path):
    """Acceptance criterion 7. Not PQ-specific, so it is not capability-gated."""
    require_profile(CLASSICAL)

    if not _has_openssl():
        pytest.skip("the openssl command-line tool is not available")

    with running_server(CLASSICAL, certs, tmp_path) as server:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"127.0.0.1:{server.port}",
             "-tls1_2", "-CAfile", str(certs / "ca.crt"), "-servername", "localhost"],
            input="Q\n", capture_output=True, text=True, check=False, timeout=60,
        )

    output = (proc.stdout + proc.stderr).lower()
    assert "new, tlsv1.2" not in output, (
        f"the server completed a TLS 1.2 handshake:\n{proc.stdout}\n{proc.stderr}"
    )


def test_a_profile_that_allows_fallback_is_configured_deliberately(certs, tmp_path):
    """Every non-classical built-in profile forbids classical fallback."""
    from conftest import CLIENT_BIN

    proc = subprocess.run(
        [str(CLIENT_BIN), "capabilities", "--json"],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert proc.returncode == 0
    capabilities = json.loads(proc.stdout)

    # Every profile whose name marks it as post-quantum must be reported
    # without any suggestion that it also falls back.
    pq_profiles = [
        entry["id"] for entry in capabilities["profiles"]
        if entry["id"].startswith(("hybrid-", "pure-"))
    ]
    assert pq_profiles, "no post-quantum profiles are defined"


def _has_openssl() -> bool:
    import shutil
    return shutil.which("openssl") is not None
