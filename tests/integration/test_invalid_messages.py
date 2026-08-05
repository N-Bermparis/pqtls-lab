"""Application-protocol robustness.

These tests speak the wire protocol directly with a raw TLS socket rather than
going through pqtls-client, because the point is to send things our own client
would refuse to construct. The server must reject each of them without
crashing, and must keep serving other clients afterwards.
"""

from __future__ import annotations

import json
import socket
import ssl
import struct
import time

import pytest

from conftest import (
    EXIT_SUCCESS,
    encode_frame,
    require_profile,
    run_client,
    running_server,
)

PROFILE = "classical-x25519"


def tls_connect(port: int, certs, *, server_name: str = "localhost",
                timeout: float = 15.0) -> ssl.SSLSocket:
    """A raw TLS 1.3 client socket, using the standard library rather than ours."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(certs / "ca.crt"))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # The server negotiates ALPN "pqtls1"; offering it avoids a mismatch alert.
    context.set_alpn_protocols(["pqtls1"])

    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return context.wrap_socket(raw, server_hostname=server_name)


def read_frame(sock: ssl.SSLSocket, timeout: float = 15.0) -> bytes | None:
    """Read one length-prefixed frame, or None if the peer closed."""
    sock.settimeout(timeout)

    header = b""
    while len(header) < 4:
        try:
            chunk = sock.recv(4 - len(header))
        except (socket.timeout, ssl.SSLError, OSError):
            return None
        if not chunk:
            return None
        header += chunk

    (length,) = struct.unpack(">I", header)
    if length == 0 or length > 64 * 1024 * 1024:
        return None

    body = b""
    while len(body) < length:
        try:
            chunk = sock.recv(min(65536, length - len(body)))
        except (socket.timeout, ssl.SSLError, OSError):
            return None
        if not chunk:
            return None
        body += chunk
    return body


def send_and_read(port: int, certs, payload: bytes) -> dict | None:
    """Send one raw frame body and return the parsed reply, if any."""
    with tls_connect(port, certs) as sock:
        sock.sendall(encode_frame(payload))
        reply = read_frame(sock)
    if reply is None:
        return None
    try:
        return json.loads(reply)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Malformed payloads
# ---------------------------------------------------------------------------
def test_invalid_json_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(server.port, certs, b"{this is not json")

    # Either a structured error reply or a closed connection is acceptable.
    # Accepting the message is not.
    if reply is not None:
        assert reply["type"] == "error"
        assert reply["status"] == "rejected"


def test_a_non_object_document_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(server.port, certs, b'["not", "an", "object"]')

    if reply is not None:
        assert reply["type"] == "error"


def test_a_missing_protocol_version_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(server.port, certs, b'{"type":"ping"}')

    if reply is not None:
        assert reply["type"] == "error"


def test_an_unsupported_protocol_version_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(
            server.port, certs, b'{"protocol_version":99,"type":"ping"}'
        )

    if reply is not None:
        assert reply["type"] == "error"


def test_an_unknown_message_type_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(
            server.port, certs, b'{"protocol_version":1,"type":"exec_shell"}'
        )

    if reply is not None:
        assert reply["type"] == "error"


def test_invalid_utf8_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    # A lone continuation byte inside a JSON string.
    payload = b'{"protocol_version":1,"type":"echo","payload":{"x":"\xc3"}}'

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(server.port, certs, payload)

    if reply is not None:
        assert reply["type"] == "error"


def test_deeply_nested_json_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    depth = 200
    payload = (
        b'{"protocol_version":1,"type":"echo","payload":'
        + b'{"a":' * depth + b"1" + b"}" * depth
        + b"}"
    )

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(server.port, certs, payload)

    if reply is not None:
        assert reply["type"] == "error"


def test_a_response_type_from_a_client_is_rejected(certs, tmp_path):
    """A client sending `acknowledgement` is confused or probing."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(
            server.port, certs, b'{"protocol_version":1,"type":"acknowledgement"}'
        )

    if reply is not None:
        assert reply["type"] == "error"


def test_telemetry_without_a_device_id_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        reply = send_and_read(
            server.port, certs,
            b'{"protocol_version":1,"type":"telemetry","payload":{"temperature":20}}',
        )

    if reply is not None:
        assert reply["type"] == "error"


# ---------------------------------------------------------------------------
# Framing violations
# ---------------------------------------------------------------------------
def test_an_oversized_frame_is_rejected(certs, tmp_path):
    """Acceptance criterion 9.

    The header announces far more than the configured maximum. The server must
    refuse on the strength of the header alone, without buffering the body.
    """
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path, max_frame_size=4096) as server:
        with tls_connect(server.port, certs) as sock:
            # Announce 16 MiB against a 4 KiB limit, then send nothing more.
            sock.sendall(struct.pack(">I", 16 * 1024 * 1024))
            reply = read_frame(sock)

        if reply is not None:
            document = json.loads(reply)
            assert document["type"] == "error"

        # The decisive check: the server survived and still serves others.
        result = run_client(server.port, PROFILE, certs)
        assert result.returncode == EXIT_SUCCESS, (
            "the server stopped serving after an oversized frame"
        )


def test_a_zero_length_frame_is_rejected(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        with tls_connect(server.port, certs) as sock:
            sock.sendall(struct.pack(">I", 0))
            read_frame(sock)

        result = run_client(server.port, PROFILE, certs)
        assert result.returncode == EXIT_SUCCESS


def test_a_truncated_frame_does_not_hang_the_server(certs, tmp_path):
    """A header promising more than is sent, then a disconnect."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        with tls_connect(server.port, certs) as sock:
            sock.sendall(struct.pack(">I", 1000) + b"only ten b")

        result = run_client(server.port, PROFILE, certs)
        assert result.returncode == EXIT_SUCCESS


def test_a_frame_split_across_writes_is_reassembled(certs, tmp_path):
    """One SSL_read is not one message; the server must reassemble."""
    require_profile(PROFILE)

    payload = json.dumps({
        "protocol_version": 1,
        "type": "echo",
        "payload": {"marker": "split-across-writes"},
    }).encode()
    frame = encode_frame(payload)

    with running_server(PROFILE, certs, tmp_path) as server:
        with tls_connect(server.port, certs) as sock:
            for index in range(0, len(frame), 3):
                sock.sendall(frame[index:index + 3])
                time.sleep(0.01)
            reply = read_frame(sock)

    assert reply is not None, "the server did not reassemble a fragmented frame"
    document = json.loads(reply)
    assert document["type"] == "acknowledgement"
    assert document["payload"]["marker"] == "split-across-writes"


def test_several_frames_in_one_write_are_all_handled(certs, tmp_path):
    require_profile(PROFILE)

    combined = b""
    for index in range(3):
        payload = json.dumps({
            "protocol_version": 1,
            "type": "echo",
            "message_id": f"1111111{index}-1111-4111-8111-111111111111",
            "payload": {"index": index},
        }).encode()
        combined += encode_frame(payload)

    with running_server(PROFILE, certs, tmp_path) as server:
        with tls_connect(server.port, certs) as sock:
            sock.sendall(combined)
            replies = [read_frame(sock) for _ in range(3)]

    documents = [json.loads(r) for r in replies if r is not None]
    assert len(documents) == 3
    assert [d["payload"]["index"] for d in documents] == [0, 1, 2]


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------
def test_the_server_survives_an_abrupt_disconnect(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        for _ in range(5):
            sock = tls_connect(server.port, certs)
            sock.close()   # no close_notify, no application data

        result = run_client(server.port, PROFILE, certs)
        assert result.returncode == EXIT_SUCCESS


def test_the_server_recovers_from_a_failed_handshake(certs, tmp_path):
    """Acceptance: a failed handshake must not take the server down."""
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        # Plain TCP garbage where a ClientHello is expected.
        for _ in range(5):
            with socket.create_connection(("127.0.0.1", server.port), timeout=10) as raw:
                raw.sendall(b"this is not a TLS ClientHello\n")
                time.sleep(0.05)

        result = run_client(server.port, PROFILE, certs)
        assert result.returncode == EXIT_SUCCESS, (
            "the server did not recover after failed handshakes"
        )


@pytest.mark.slow
def test_concurrent_clients(certs, tmp_path):
    """Acceptance: several clients at once."""
    require_profile(PROFILE)

    import concurrent.futures

    with running_server(PROFILE, certs, tmp_path,
                        extra_args=["--max-connections", "16"]) as server:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [
                pool.submit(run_client, server.port, PROFILE, certs)
                for _ in range(20)
            ]
            results = [future.result() for future in futures]

    successes = sum(1 for r in results if r.returncode == EXIT_SUCCESS)
    assert successes == len(results), (
        f"only {successes}/{len(results)} concurrent connections succeeded"
    )


def test_a_close_message_ends_the_connection_cleanly(certs, tmp_path):
    require_profile(PROFILE)

    with running_server(PROFILE, certs, tmp_path) as server:
        with tls_connect(server.port, certs) as sock:
            sock.sendall(encode_frame(b'{"protocol_version":1,"type":"close"}'))
            # No reply is expected for `close`.
            assert read_frame(sock, timeout=3.0) is None

        result = run_client(server.port, PROFILE, certs)
        assert result.returncode == EXIT_SUCCESS
