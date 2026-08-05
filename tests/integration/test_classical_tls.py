"""Classical TLS 1.3 baseline (Milestone 1).

These tests must pass on every supported host. They do not depend on any
post-quantum capability, so a failure here is a real failure and never a skip.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    EXIT_SUCCESS,
    require_profile,
    run_client,
    running_server,
)

CLASSICAL_PROFILES = ["classical-x25519", "classical-p256"]


@pytest.mark.parametrize("profile", CLASSICAL_PROFILES)
def test_classical_handshake_succeeds(profile, certs, tmp_path):
    """A client connects, exchanges a ping and closes cleanly."""
    require_profile(profile)

    with running_server(profile, certs, tmp_path) as server:
        result = run_client(server.port, profile, certs)

    assert result.returncode == EXIT_SUCCESS, (
        f"connection failed\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    metrics = result.json["metrics"]
    assert metrics["success"] is True
    assert metrics["tls_version"] == "TLSv1.3"
    assert metrics["error_category"] is None


@pytest.mark.parametrize("profile", CLASSICAL_PROFILES)
def test_negotiated_group_matches_the_profile(profile, certs, tmp_path):
    """The group actually agreed is the one the profile asked for."""
    require_profile(profile)

    expected = {"classical-x25519": "x25519", "classical-p256": "secp256r1"}[profile]

    with running_server(profile, certs, tmp_path) as server:
        result = run_client(server.port, profile, certs)

    assert result.returncode == EXIT_SUCCESS
    metrics = result.json["metrics"]
    # OpenSSL reports canonical names in lower case for classical groups.
    assert metrics["negotiated_group"].lower() == expected


@pytest.mark.parametrize("profile", CLASSICAL_PROFILES)
def test_classical_profiles_are_not_reported_as_post_quantum(profile, certs, tmp_path):
    """A classical connection must never carry a post-quantum claim."""
    require_profile(profile)

    with running_server(profile, certs, tmp_path) as server:
        result = run_client(server.port, profile, certs)

    assert result.returncode == EXIT_SUCCESS
    metrics = result.json["metrics"]
    assert metrics["pq_key_establishment"] is False
    assert metrics["hybrid_key_establishment"] is False
    assert metrics["pq_authentication"] is False


def test_cipher_suite_is_from_the_allowlist(certs, tmp_path):
    require_profile("classical-x25519")

    allowed = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    }

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(server.port, "classical-x25519", certs)

    assert result.returncode == EXIT_SUCCESS
    assert result.json["metrics"]["cipher_suite"] in allowed


def test_ping_receives_a_pong(certs, tmp_path):
    require_profile("classical-x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(server.port, "classical-x25519", certs,
                            message='{"type":"ping"}')

    assert result.returncode == EXIT_SUCCESS
    responses = result.json["responses"]
    assert len(responses) == 1
    assert responses[0]["type"] == "pong"
    assert responses[0]["status"] == "accepted"


def test_echo_returns_the_payload(certs, tmp_path):
    require_profile("classical-x25519")

    message = json.dumps({
        "protocol_version": 1,
        "type": "echo",
        "payload": {"marker": "round-trip-value", "count": 42},
    })

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(server.port, "classical-x25519", certs, message=message)

    assert result.returncode == EXIT_SUCCESS
    response = result.json["responses"][0]
    assert response["payload"]["marker"] == "round-trip-value"
    assert response["payload"]["count"] == 42


def test_telemetry_is_acknowledged(certs, tmp_path):
    require_profile("classical-x25519")

    message = json.dumps({
        "protocol_version": 1,
        "type": "telemetry",
        "payload": {"device_id": "sensor-001", "temperature": 24.6, "status": "normal"},
    })

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(server.port, "classical-x25519", certs, message=message)

    assert result.returncode == EXIT_SUCCESS
    response = result.json["responses"][0]
    assert response["type"] == "acknowledgement"
    assert response["status"] == "accepted"


def test_capabilities_message_separates_key_exchange_from_authentication(certs, tmp_path):
    """The server's capabilities reply must not conflate the two properties."""
    require_profile("classical-x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(server.port, "classical-x25519", certs,
                            message='{"type":"capabilities"}')

    assert result.returncode == EXIT_SUCCESS
    payload = result.json["responses"][0]["payload"]

    assert "pq_key_establishment" in payload
    assert "pq_authentication" in payload
    assert payload["pq_key_establishment"] is False
    assert payload["pq_authentication"] is False


def test_message_id_is_echoed_for_correlation(certs, tmp_path):
    require_profile("classical-x25519")

    message_id = "11111111-1111-4111-8111-111111111111"
    message = json.dumps({
        "protocol_version": 1,
        "type": "ping",
        "message_id": message_id,
    })

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(server.port, "classical-x25519", certs, message=message)

    assert result.returncode == EXIT_SUCCESS
    assert result.json["responses"][0]["message_id"] == message_id


def test_metrics_are_written_as_valid_jsonl(certs, tmp_path):
    require_profile("classical-x25519")

    metrics_file = tmp_path / "client.jsonl"

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(
            server.port, "classical-x25519", certs,
            extra_args=["--metrics", str(metrics_file),
                        "--experiment-id", "integration-test"],
        )

    assert result.returncode == EXIT_SUCCESS
    assert metrics_file.exists()

    lines = [line for line in metrics_file.read_text().splitlines() if line.strip()]
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["schema_version"] == 1
    assert record["experiment_id"] == "integration-test"
    assert record["role"] == "client"
    assert record["success"] is True


def test_metrics_are_appended_not_truncated(certs, tmp_path):
    """A second run must not destroy the first run's records."""
    require_profile("classical-x25519")

    metrics_file = tmp_path / "appended.jsonl"

    with running_server("classical-x25519", certs, tmp_path) as server:
        for _ in range(3):
            result = run_client(server.port, "classical-x25519", certs,
                                extra_args=["--metrics", str(metrics_file)])
            assert result.returncode == EXIT_SUCCESS

    lines = [line for line in metrics_file.read_text().splitlines() if line.strip()]
    assert len(lines) == 3


def test_several_messages_on_one_connection(certs, tmp_path):
    require_profile("classical-x25519")

    with running_server("classical-x25519", certs, tmp_path) as server:
        result = run_client(server.port, "classical-x25519", certs,
                            extra_args=["--messages-per-connection", "5"])

    assert result.returncode == EXIT_SUCCESS
    assert len(result.json["responses"]) == 5


def test_server_reports_its_bound_profile_in_metrics(certs, tmp_path):
    require_profile("classical-x25519")

    server_metrics = tmp_path / "server.jsonl"

    with running_server(
        "classical-x25519", certs, tmp_path,
        extra_args=["--metrics", str(server_metrics)],
    ) as server:
        result = run_client(server.port, "classical-x25519", certs)
        assert result.returncode == EXIT_SUCCESS

    # The server flushes per record, but give the process a moment to finish
    # writing before the harness tears it down.
    import time
    for _ in range(50):
        if server_metrics.exists() and server_metrics.read_text().strip():
            break
        time.sleep(0.1)

    lines = [line for line in server_metrics.read_text().splitlines() if line.strip()]
    assert lines, "the server wrote no metrics record"
    record = json.loads(lines[0])
    assert record["role"] == "server"
    assert record["requested_profile"] == "classical-x25519"


def test_version_and_help_exit_cleanly(certs, tmp_path):
    """Basic CLI hygiene, checked because scripts depend on it."""
    import subprocess
    from conftest import CLIENT_BIN, SERVER_BIN

    for binary in (CLIENT_BIN, SERVER_BIN):
        version = subprocess.run([str(binary), "--version"],
                                 capture_output=True, text=True, check=False)
        assert version.returncode == 0
        assert "pqtls-lab" in version.stdout

        help_output = subprocess.run([str(binary), "--help"],
                                     capture_output=True, text=True, check=False)
        assert help_output.returncode == 0
        assert "USAGE" in help_output.stdout


def test_unknown_option_is_rejected(certs, tmp_path):
    """A mistyped flag must fail, not fall back to a default policy."""
    import subprocess
    from conftest import CLIENT_BIN, EXIT_CONFIGURATION

    proc = subprocess.run(
        [str(CLIENT_BIN), "connect", "--profiel", "hybrid-x25519-mlkem768"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == EXIT_CONFIGURATION
    assert "profiel" in proc.stderr
