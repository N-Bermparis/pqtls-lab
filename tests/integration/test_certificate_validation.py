"""Certificate and hostname validation.

The properties here are what separate an authenticated connection from an
encrypted conversation with an unknown party. Each test asserts a specific
REJECTION, and asserts the error category too: a connection that fails for the
wrong reason is not evidence that the right check exists.
"""

from __future__ import annotations

import subprocess

import pytest

from conftest import (
    EXIT_CERTIFICATE,
    EXIT_SUCCESS,
    REPO_ROOT,
    require_profile,
    run_client,
    running_server,
)

PROFILE = "classical-x25519"


@pytest.fixture(scope="module")
def foreign_ca(tmp_path_factory):
    """A second, unrelated development CA. Nothing it signs should be trusted."""
    directory = tmp_path_factory.mktemp("certs-foreign")
    script = REPO_ROOT / "scripts" / "generate-classical-certs.sh"
    proc = subprocess.run(
        ["bash", str(script), "--output-dir", str(directory), "--with-client", "--force"],
        capture_output=True, text=True, check=False, timeout=300,
    )
    if proc.returncode != 0:
        pytest.skip(f"could not generate the foreign CA:\n{proc.stderr}")
    return directory


def test_a_valid_certificate_is_accepted(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        result = run_client(server.port, PROFILE, certs, server_name="localhost")

    assert result.returncode == EXIT_SUCCESS
    assert result.json["metrics"]["success"] is True


def test_an_unknown_ca_is_rejected(certs, foreign_ca, tmp_path):
    """The server's certificate chains to a CA the client does not trust."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        # Correct server, but the client is given the WRONG trust anchor.
        result = run_client(
            server.port, PROFILE, foreign_ca,
            ca_certificate="ca.crt", server_name="localhost",
            json_output=False,
        )

    assert result.returncode == EXIT_CERTIFICATE, (
        f"an unknown CA must be rejected with a certificate error, got "
        f"{result.returncode}\n{result.combined()}"
    )
    combined = result.combined().lower()
    assert any(
        phrase in combined
        for phrase in ("unable to get local issuer", "self-signed", "self signed",
                       "certificate verify failed", "certificate")
    )


def test_a_wrong_hostname_is_rejected(certs, tmp_path):
    """The certificate is valid but does not cover the requested name."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        result = run_client(
            server.port, PROFILE, certs,
            server_name="wrong.example.invalid",
            json_output=False,
        )

    assert result.returncode == EXIT_CERTIFICATE, (
        f"a hostname mismatch must be rejected, got {result.returncode}\n"
        f"{result.combined()}"
    )


def test_hostname_verification_covers_the_ip_san(certs, tmp_path):
    """127.0.0.1 is in the SAN list, so verifying against it must succeed."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        result = run_client(server.port, PROFILE, certs, server_name="127.0.0.1")

    assert result.returncode == EXIT_SUCCESS, (
        "the development certificate includes IP:127.0.0.1 in its SAN, so this "
        f"should verify\n{result.combined()}"
    )


def test_no_ca_certificate_falls_back_to_the_system_store_and_fails(certs, tmp_path):
    """Without --ca-certificate the development CA is not trusted.

    The development CA is not in any system trust store, so this must fail.
    A pass here would mean verification was skipped.
    """
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        result = run_client(
            server.port, PROFILE, certs,
            ca_certificate=None, server_name="localhost", json_output=False,
        )

    assert result.returncode == EXIT_CERTIFICATE, (
        "a development certificate must not verify against the system trust store"
    )


def test_insecure_mode_is_refused_in_a_production_environment(certs, tmp_path):
    """PQTLS_ENV=production must veto --insecure-development-mode."""
    from conftest import CLIENT_BIN, EXIT_CONFIGURATION

    environment = dict(**__import__("os").environ)
    environment["PQTLS_ENV"] = "production"

    proc = subprocess.run(
        [str(CLIENT_BIN), "connect", "--host", "127.0.0.1", "--port", "1",
         "--server-name", "localhost", "--profile", PROFILE,
         "--insecure-development-mode"],
        capture_output=True, text=True, check=False, env=environment, timeout=60,
    )

    assert proc.returncode == EXIT_CONFIGURATION, (
        "insecure development mode must be refused when PQTLS_ENV=production"
    )
    assert "production" in proc.stderr.lower()


def test_keylog_is_refused_in_a_production_environment(certs, tmp_path):
    from conftest import CLIENT_BIN, EXIT_CONFIGURATION

    environment = dict(**__import__("os").environ)
    environment["PQTLS_ENV"] = "production"

    proc = subprocess.run(
        [str(CLIENT_BIN), "connect", "--host", "127.0.0.1", "--port", "1",
         "--server-name", "localhost", "--profile", PROFILE,
         "--keylog-file", str(tmp_path / "keys.log")],
        capture_output=True, text=True, check=False, env=environment, timeout=60,
    )

    assert proc.returncode == EXIT_CONFIGURATION
    assert "production" in proc.stderr.lower()


def test_insecure_mode_prints_a_warning(certs, tmp_path):
    """Development mode is allowed outside production, but must be loud."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        result = run_client(
            server.port, PROFILE, certs,
            ca_certificate=None,
            server_name="wrong.example.invalid",   # would fail if verification ran
            extra_args=["--insecure-development-mode"],
            json_output=False,
        )

    # It connects despite the wrong name, which is the whole point of the flag,
    # and the warning must be unmissable.
    assert result.returncode == EXIT_SUCCESS
    assert "INSECURE" in result.combined().upper()


def test_a_server_without_a_certificate_refuses_to_start(certs, tmp_path):
    from conftest import EXIT_CONFIGURATION, SERVER_BIN

    proc = subprocess.run(
        [str(SERVER_BIN), "serve", "--listen", "127.0.0.1", "--port", "0",
         "--profile", PROFILE],
        capture_output=True, text=True, check=False, timeout=60,
    )

    assert proc.returncode == EXIT_CONFIGURATION
    assert "certificate" in proc.stderr.lower()


def test_a_mismatched_certificate_and_key_are_rejected(certs, foreign_ca, tmp_path):
    """A certificate paired with a key from a different generation."""
    from conftest import EXIT_CERTIFICATE, SERVER_BIN

    proc = subprocess.run(
        [str(SERVER_BIN), "serve", "--listen", "127.0.0.1", "--port", "0",
         "--profile", PROFILE,
         "--certificate", str(certs / "server.crt"),
         "--private-key", str(foreign_ca / "server.key")],
        capture_output=True, text=True, check=False, timeout=60,
    )

    assert proc.returncode == EXIT_CERTIFICATE
    assert "does not match" in proc.stderr.lower() or "key" in proc.stderr.lower()


def test_mutual_tls_succeeds_with_a_client_certificate(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path, require_client_cert=True) as server:
        result = run_client(
            server.port, PROFILE, certs,
            extra_args=["--certificate", str(certs / "client.crt"),
                        "--private-key", str(certs / "client.key")],
        )

    assert result.returncode == EXIT_SUCCESS, (
        f"mutual TLS failed\n{result.combined()}\n--- server log ---\n{server.log()}"
    )
    assert result.json["metrics"]["success"] is True


def test_mutual_tls_rejects_a_client_without_a_certificate(certs, tmp_path):
    """SSL_VERIFY_FAIL_IF_NO_PEER_CERT: no certificate means no connection."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path, require_client_cert=True) as server:
        result = run_client(server.port, PROFILE, certs, json_output=False)

    assert result.returncode != EXIT_SUCCESS, (
        "a server requiring mutual TLS must not accept an unauthenticated client"
    )


def test_mutual_tls_rejects_a_client_certificate_from_another_ca(
    certs, foreign_ca, tmp_path
):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path, require_client_cert=True) as server:
        result = run_client(
            server.port, PROFILE, certs,
            extra_args=["--certificate", str(foreign_ca / "client.crt"),
                        "--private-key", str(foreign_ca / "client.key")],
            json_output=False,
        )

    assert result.returncode != EXIT_SUCCESS, (
        "a client certificate from an untrusted CA must be rejected"
    )
