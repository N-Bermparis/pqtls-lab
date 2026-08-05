#!/usr/bin/env python3
"""Extract handshake metrics from a pqtls-lab packet capture.

Measures the quantities that matter for RQ2, where a larger ClientHello caused
by a post-quantum key share interacts with MTU, fragmentation and loss:

  * ClientHello and ServerHello sizes
  * number of TCP segments carrying the handshake
  * total handshake bytes on the wire
  * retransmissions
  * IP fragmentation
  * time from SYN to the first application record

Uses `tshark` when available, because reimplementing TLS record parsing would be
another thing to get wrong. Without tshark the script explains what to install
rather than producing approximate numbers that look authoritative.

Captures are never committed; see scripts/capture-packets.sh.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

# TLS handshake message type numbers (RFC 8446 section 4).
HANDSHAKE_CLIENT_HELLO = "1"
HANDSHAKE_SERVER_HELLO = "2"


@dataclass
class FlowMetrics:
    """One TCP connection."""

    stream_id: str
    client_hello_bytes: int | None = None
    server_hello_bytes: int | None = None
    handshake_segments: int = 0
    handshake_bytes: int = 0
    retransmissions: int = 0
    ip_fragments: int = 0
    syn_time: float | None = None
    first_application_time: float | None = None
    tls_version: str = ""
    negotiated_group: str = ""

    @property
    def time_to_first_application_byte_ms(self) -> float | None:
        if self.syn_time is None or self.first_application_time is None:
            return None
        return (self.first_application_time - self.syn_time) * 1000.0


@dataclass
class CaptureReport:
    capture: str
    tshark_version: str
    packets_examined: int = 0
    flows: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def require_tshark() -> str:
    if shutil.which("tshark") is None:
        raise SystemExit(
            "error: tshark was not found.\n"
            "  Install it with:  sudo apt install tshark\n"
            "\n"
            "  This script does not fall back to an approximate parser: an\n"
            "  approximate ClientHello size reported as a measurement would be\n"
            "  worse than no measurement at all."
        )
    proc = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=False)
    return proc.stdout.splitlines()[0] if proc.stdout else "unknown"


TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "tcp.stream",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.len",
    "tcp.analysis.retransmission",
    "ip.flags.mf",
    "ip.frag_offset",
    "tls.record.content_type",
    "tls.record.length",
    "tls.handshake.type",
    "tls.handshake.length",
    "tls.record.version",
    "tls.handshake.extensions.supported_group",
]


def run_tshark(capture: Path) -> list[dict[str, str]]:
    argv = ["tshark", "-r", str(capture), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for name in TSHARK_FIELDS:
        argv += ["-e", name]

    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"error: tshark failed on {capture}:\n{proc.stderr.strip()}")

    rows: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        values = line.split("\t")
        # Pad short rows so a missing trailing field does not shift the columns.
        values += [""] * (len(TSHARK_FIELDS) - len(values))
        rows.append(dict(zip(TSHARK_FIELDS, values)))
    return rows


def to_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def to_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def analyse(rows: list[dict[str, str]]) -> tuple[list[FlowMetrics], list[str]]:
    flows: dict[str, FlowMetrics] = {}
    notes: list[str] = []

    for row in rows:
        stream = row.get("tcp.stream", "")
        if not stream:
            continue

        flow = flows.setdefault(stream, FlowMetrics(stream_id=stream))
        timestamp = to_float(row.get("frame.time_epoch", ""))

        # SYN without ACK marks the start of the connection.
        if row.get("tcp.flags.syn") == "1" and row.get("tcp.flags.ack") != "1":
            if flow.syn_time is None and timestamp is not None:
                flow.syn_time = timestamp

        if row.get("tcp.analysis.retransmission"):
            flow.retransmissions += 1

        if row.get("ip.flags.mf") == "1" or to_int(row.get("ip.frag_offset", "")) > 0:
            flow.ip_fragments += 1

        content_type = row.get("tls.record.content_type", "")
        handshake_type = row.get("tls.handshake.type", "")
        record_length = to_int(row.get("tls.record.length", ""))

        # Content type 22 is `handshake`.
        if content_type == "22":
            flow.handshake_segments += 1
            flow.handshake_bytes += to_int(row.get("frame.len", ""))

            if handshake_type == HANDSHAKE_CLIENT_HELLO and flow.client_hello_bytes is None:
                # The record length excludes the 5-byte TLS record header.
                flow.client_hello_bytes = record_length + 5
            elif handshake_type == HANDSHAKE_SERVER_HELLO and flow.server_hello_bytes is None:
                flow.server_hello_bytes = record_length + 5
                group = row.get("tls.handshake.extensions.supported_group", "")
                if group:
                    flow.negotiated_group = group

        # Content type 23 is `application_data`. Under TLS 1.3 the encrypted
        # handshake also appears as type 23, so this is a lower bound on the
        # time to first application byte rather than an exact figure.
        if content_type == "23" and flow.first_application_time is None:
            flow.first_application_time = timestamp

        version = row.get("tls.record.version", "")
        if version and not flow.tls_version:
            flow.tls_version = version

    if any(f.client_hello_bytes is None for f in flows.values()):
        notes.append(
            "some flows have no ClientHello. The capture may have started after the "
            "handshake, or the snaplen may have truncated it (capture with --snaplen 0)."
        )

    notes.append(
        "Under TLS 1.3 the encrypted portion of the handshake is carried in records with "
        "content type 23, the same as application data. time_to_first_application_byte_ms is "
        "therefore a lower bound, not an exact application-layer figure."
    )

    return list(flows.values()), notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract TLS handshake metrics from a pqtls-lab packet capture."
    )
    parser.add_argument("capture", type=Path, help="a .pcap or .pcapng file")
    parser.add_argument("--json", type=Path, default=None, help="write the report here")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if not args.capture.exists():
        print(f"error: {args.capture} does not exist", file=sys.stderr)
        return 2

    tshark_version = require_tshark()
    rows = run_tshark(args.capture)
    flows, notes = analyse(rows)

    report = CaptureReport(
        capture=str(args.capture),
        tshark_version=tshark_version,
        packets_examined=len(rows),
        flows=[
            {**asdict(flow),
             "time_to_first_application_byte_ms": flow.time_to_first_application_byte_ms}
            for flow in flows
        ],
        notes=notes,
    )

    if not args.quiet:
        print(f"capture  : {report.capture}")
        print(f"tshark   : {report.tshark_version}")
        print(f"packets  : {report.packets_examined}")
        print(f"flows    : {len(flows)}")
        print()
        header = (
            f"{'stream':>6} {'CH bytes':>9} {'SH bytes':>9} {'hs segs':>8} "
            f"{'hs bytes':>9} {'retx':>5} {'frag':>5} {'ttfab ms':>9}"
        )
        print(header)
        print("-" * len(header))
        for flow in sorted(flows, key=lambda f: int(f.stream_id)):
            ttfab = flow.time_to_first_application_byte_ms

            def fmt(value: Any, width: int) -> str:
                if value is None:
                    return f"{'n/a':>{width}}"
                if isinstance(value, float):
                    return f"{value:>{width}.2f}"
                return f"{value:>{width}}"

            print(
                f"{flow.stream_id:>6} {fmt(flow.client_hello_bytes, 9)} "
                f"{fmt(flow.server_hello_bytes, 9)} {fmt(flow.handshake_segments, 8)} "
                f"{fmt(flow.handshake_bytes, 9)} {fmt(flow.retransmissions, 5)} "
                f"{fmt(flow.ip_fragments, 5)} {fmt(ttfab, 9)}"
            )
        print()
        for note in notes:
            print(f"note: {note}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"\nJSON report written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
