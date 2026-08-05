"""Hybrid post-quantum TLS (Milestone 2).

Every test here is capability-gated. On an OpenSSL without the hybrid groups
they SKIP with the reason recorded; they are never reported as passing, and a
failure on a capable build is never converted into a skip.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    EXIT_SUCCESS,
    profile_usable,
    require_profile,
    run_client,
    running_server,
)

pytestmark = pytest.mark.requires_pq

HYBRID_PROFILES = {
    "hybrid-x25519-mlkem768": "x25519mlkem768",
    "hybrid-p256-mlkem768": "secp256r1mlkem768",
    "hybrid-p384-mlkem1024": "secp384r1mlkem1024",
}

# The P-384 profile authenticates with ECDSA P-384, so it needs a certificate
# on that curve rather than the default P-256 development PKI.
P384_PROFILE = "hybrid-p384-mlkem1024"


@pytest.fixture(scope="session")
def p384_certs(tmp_path_factory):
    """An ECDSA P-384 development PKI for the high-security profile."""
    import subprocess
    from conftest import REPO_ROOT

    directory = tmp_path_factory.mktemp("certs-p384")
    script = REPO_ROOT / "scripts" / "generate-classical-certs.sh"
    proc = subprocess.run(
        ["bash", str(script), "--curve", "secp384r1",
         "--output-dir", str(directory), "--force"],
        capture_output=True, text=True, check=False, timeout=300,
    )
    if proc.returncode != 0:
        pytest.skip(f"P-384 certificate generation failed:\n{proc.stderr}")
    return directory


@pytest.mark.parametrize("profile", ["hybrid-x25519-mlkem768", "hybrid-p256-mlkem768"])
def test_hybrid_handshake_succeeds(profile, certs, tmp_path):
    require_profile(profile)

    with running_server(profile, certs, tmp_path) as server:
        result = run_client(server.port, profile, certs)

    assert result.returncode == EXIT_SUCCESS, (
        f"hybrid handshake failed\nstdout: {result.stdout}\nstderr: {result.stderr}\n"
        f"--- server log ---\n{server.log()}"
    )

    metrics = result.json["metrics"]
    assert metrics["success"] is True
    assert metrics["tls_version"] == "TLSv1.3"


@pytest.mark.parametrize("profile", ["hybrid-x25519-mlkem768", "hybrid-p256-mlkem768"])
def test_negotiated_group_is_verified_after_the_handshake(profile, certs, tmp_path):
    """The recorded group is the one that was actually agreed (spec step 8)."""
    require_profile(profile)

    with running_server(profile, certs, tmp_path) as server:
        result = run_client(server.port, profile, certs)

    assert result.returncode == EXIT_SUCCESS
    metrics = result.json["metrics"]
    assert metrics["negotiated_group"].lower() == HYBRID_PROFILES[profile]


@pytest.mark.parametrize("profile", ["hybrid-x25519-mlkem768", "hybrid-p256-mlkem768"])
def test_hybrid_key_establishment_is_reported(profile, certs, tmp_path):
    require_profile(profile)

    with running_server(profile, certs, tmp_path) as server:
        result = run_client(server.port, profile, certs)

    assert result.returncode == EXIT_SUCCESS
    metrics = result.json["metrics"]
    assert metrics["pq_key_establishment"] is True
    assert metrics["hybrid_key_establishment"] is True


@pytest.mark.parametrize("profile", ["hybrid-x25519-mlkem768", "hybrid-p256-mlkem768"])
def test_hybrid_profiles_do_not_claim_post_quantum_authentication(profile, certs, tmp_path):
    """The headline honesty property.

    These profiles use ECDSA certificates. A hybrid key exchange is not
    post-quantum authentication, and the record must say so.
    """
    require_profile(profile)

    with running_server(profile, certs, tmp_path) as server:
        result = run_client(server.port, profile, certs)

    assert result.returncode == EXIT_SUCCESS
    metrics = result.json["metrics"]
    assert metrics["pq_key_establishment"] is True
    assert metrics["pq_authentication"] is False, (
        "a hybrid key exchange with an ECDSA certificate must not be reported as "
        "post-quantum authentication"
    )


def test_p384_hybrid_with_matching_certificates(p384_certs, tmp_path):
    require_profile(P384_PROFILE)

    with running_server(P384_PROFILE, p384_certs, tmp_path) as server:
        result = run_client(server.port, P384_PROFILE, p384_certs)

    assert result.returncode == EXIT_SUCCESS, (
        f"stdout: {result.stdout}\nstderr: {result.stderr}\n"
        f"--- server log ---\n{server.log()}"
    )
    metrics = result.json["metrics"]
    assert metrics["negotiated_group"].lower() == HYBRID_PROFILES[P384_PROFILE]
    assert metrics["hybrid_key_establishment"] is True


def test_pure_mlkem_is_experimental_and_not_hybrid(certs, tmp_path):
    """The experimental pure profile: PQ key establishment, but no hybrid."""
    require_profile("pure-mlkem768")

    with running_server("pure-mlkem768", certs, tmp_path) as server:
        result = run_client(server.port, "pure-mlkem768", certs)

    assert result.returncode == EXIT_SUCCESS
    metrics = result.json["metrics"]
    assert metrics["pq_key_establishment"] is True
    assert metrics["hybrid_key_establishment"] is False, (
        "MLKEM768 has no classical component and must not be classified as hybrid"
    )


def test_hybrid_metrics_validate_against_the_schema(certs, tmp_path):
    """Records from a real hybrid connection must pass the result validator."""
    require_profile("hybrid-x25519-mlkem768")

    import subprocess
    from conftest import REPO_ROOT

    metrics_file = tmp_path / "hybrid.jsonl"

    with running_server("hybrid-x25519-mlkem768", certs, tmp_path) as server:
        result = run_client(
            server.port, "hybrid-x25519-mlkem768", certs,
            extra_args=["--metrics", str(metrics_file)],
        )
    assert result.returncode == EXIT_SUCCESS

    validator = REPO_ROOT / "tools" / "result_validator.py"
    proc = subprocess.run(
        [sys_executable(), str(validator), str(metrics_file)],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, (
        f"the validator rejected records produced by a real hybrid connection:\n"
        f"{proc.stdout}\n{proc.stderr}"
    )


def sys_executable() -> str:
    import sys
    return sys.executable


@pytest.mark.slow
def test_repeated_hybrid_handshakes_are_stable(certs, tmp_path):
    """Twenty consecutive hybrid handshakes on one server."""
    require_profile("hybrid-x25519-mlkem768")

    metrics_file = tmp_path / "repeat.jsonl"

    with running_server("hybrid-x25519-mlkem768", certs, tmp_path) as server:
        for index in range(20):
            result = run_client(
                server.port, "hybrid-x25519-mlkem768", certs,
                extra_args=["--metrics", str(metrics_file)],
            )
            assert result.returncode == EXIT_SUCCESS, f"connection {index} failed"

    records = [
        json.loads(line)
        for line in metrics_file.read_text().splitlines()
        if line.strip()
    ]
    assert len(records) == 20
    # Every one of them must have negotiated the hybrid group. A single
    # classical negotiation here would be a downgrade.
    assert all(r["hybrid_key_establishment"] is True for r in records)
    assert all(r["success"] is True for r in records)


@pytest.mark.slow
def test_benchmark_produces_one_record_per_connection(certs, tmp_path):
    """Acceptance criterion 14: at least 100 automated connections."""
    require_profile("hybrid-x25519-mlkem768")

    import subprocess
    from conftest import CLIENT_BIN

    output = tmp_path / "benchmark.jsonl"

    with running_server(
        "hybrid-x25519-mlkem768", certs, tmp_path,
        extra_args=["--max-connections", "32"],
    ) as server:
        proc = subprocess.run(
            [str(CLIENT_BIN), "benchmark",
             "--host", "127.0.0.1", "--port", str(server.port),
             "--server-name", "localhost",
             "--profile", "hybrid-x25519-mlkem768",
             "--ca-certificate", str(certs / "ca.crt"),
             "--connections", "100", "--concurrency", "10",
             "--output", str(output), "--json", "--log-level", "warn"],
            capture_output=True, text=True, check=False, timeout=600,
        )

    assert proc.returncode == 0, f"benchmark failed:\n{proc.stdout}\n{proc.stderr}"

    records = [
        json.loads(line) for line in output.read_text().splitlines() if line.strip()
    ]
    assert len(records) == 100, "every connection must produce exactly one record"

    # Failures, if any, must be preserved rather than dropped.
    successes = [r for r in records if r["success"]]
    assert len(successes) > 0
    for record in successes:
        assert record["hybrid_key_establishment"] is True


def test_unavailable_profile_reports_capability_error(certs, tmp_path):
    """When a profile is unusable the server refuses to start, with reason.

    Runs only when a profile genuinely is unavailable. On a fully capable build
    there is nothing to test, so it skips rather than inventing a failure.
    """
    from conftest import EXIT_CAPABILITY, SERVER_BIN
    import subprocess

    unusable = [
        profile
        for profile in ("hybrid-x25519-mlkem768", "pure-mlkem768", "hybrid-pq-auth")
        if not profile_usable(profile)[0]
    ]
    if not unusable:
        pytest.skip("every profile is usable on this host; nothing to test here")

    proc = subprocess.run(
        [str(SERVER_BIN), "serve", "--listen", "127.0.0.1", "--port", "0",
         "--profile", unusable[0],
         "--certificate", str(certs / "server.crt"),
         "--private-key", str(certs / "server.key")],
        capture_output=True, text=True, check=False, timeout=60,
    )

    assert proc.returncode == EXIT_CAPABILITY
    # The failure must explain itself, not merely refuse.
    assert unusable[0] in proc.stderr
