#!/usr/bin/env python3
"""Validate pqtls-lab JSONL result files.

Two layers of checking:

  1. Structural, against schemas/metrics.schema.json. Uses `jsonschema` when it
     is installed; otherwise falls back to a built-in checker that covers the
     required fields, types and enums. The fallback is deliberately explicit
     rather than silently skipping validation, because a validator that passes
     because it did nothing is worse than no validator.

  2. Semantic, covering invariants a JSON schema cannot express well. The
     important one: a record must not claim post-quantum protection that the
     negotiated group does not provide.

Exit codes:  0 valid   1 violations found   2 usage or I/O error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "metrics.schema.json"

UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# Group classification. Must stay in step with src/common/security_profile.cpp;
# tests/unit/test_security_profiles.cpp pins the C++ side.
HYBRID_GROUPS = {"x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024"}
PURE_PQ_GROUPS = {"mlkem512", "mlkem768", "mlkem1024"}
PQ_GROUPS = HYBRID_GROUPS | PURE_PQ_GROUPS

ERROR_CATEGORIES = {
    None, "none", "configuration", "capability", "certificate", "tls-policy",
    "handshake", "network", "protocol", "timeout", "internal",
}

REQUIRED_FIELDS = {
    "schema_version": int,
    "connection_id": str,
    "role": str,
    "requested_profile": str,
    "tls_version": str,
    "negotiated_group": str,
    "cipher_suite": str,
    "handshake_ms": (int, float),
    "connection_ms": (int, float),
    "success": bool,
    "timestamp": str,
}


@dataclass
class Violation:
    path: str
    line: int
    kind: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line} [{self.kind}] {self.message}"


@dataclass
class Report:
    files: int = 0
    records: int = 0
    violations: list[Violation] = field(default_factory=list)
    schema_backend: str = "builtin"

    @property
    def ok(self) -> bool:
        return not self.violations


def iter_lines(path: Path) -> Iterator[tuple[int, str]]:
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if stripped:
                yield number, stripped


def builtin_structural_check(record: dict[str, Any]) -> list[str]:
    """Structural checks that do not require the jsonschema package."""
    problems: list[str] = []

    for name, expected in REQUIRED_FIELDS.items():
        if name not in record:
            problems.append(f"missing required field '{name}'")
            continue
        value = record[name]
        # bool is a subclass of int in Python; check it first so a boolean in a
        # numeric field is not accepted.
        if expected is int and isinstance(value, bool):
            problems.append(f"'{name}' must be an integer, got a boolean")
        elif expected is bool and not isinstance(value, bool):
            problems.append(f"'{name}' must be a boolean, got {type(value).__name__}")
        elif expected is not bool and not isinstance(value, expected):
            names = expected.__name__ if isinstance(expected, type) else "/".join(
                t.__name__ for t in expected
            )
            problems.append(f"'{name}' must be {names}, got {type(value).__name__}")

    if record.get("schema_version") != 1:
        problems.append(
            f"unsupported schema_version {record.get('schema_version')!r}; this validator "
            "understands version 1"
        )

    if isinstance(record.get("connection_id"), str) and not UUID_V4.match(record["connection_id"]):
        problems.append("'connection_id' is not an RFC 4122 version 4 UUID")

    if record.get("role") not in {"client", "server"}:
        problems.append(f"'role' must be 'client' or 'server', got {record.get('role')!r}")

    if record.get("error_category") not in ERROR_CATEGORIES:
        problems.append(f"unknown error_category {record.get('error_category')!r}")

    for name in ("handshake_ms", "connection_ms"):
        value = record.get(name)
        if isinstance(value, (int, float)) and value < 0:
            problems.append(f"'{name}' is negative ({value})")

    return problems


def semantic_check(record: dict[str, Any]) -> list[str]:
    """Invariants about what the record is allowed to claim."""
    problems: list[str] = []

    group = str(record.get("negotiated_group", "")).lower()
    success = record.get("success") is True

    claims_pq = record.get("pq_key_establishment") is True
    claims_hybrid = record.get("hybrid_key_establishment") is True
    claims_pq_auth = record.get("pq_authentication") is True

    if success:
        if not record.get("tls_version"):
            problems.append("a successful connection has no tls_version")
        if not group:
            problems.append("a successful connection has no negotiated_group")
        if record.get("error_category") not in (None, "none"):
            problems.append(
                f"a successful connection carries error_category "
                f"{record.get('error_category')!r}"
            )
        if record.get("tls_version") and record["tls_version"] not in ("TLSv1.3", "TLS1.3"):
            problems.append(
                f"negotiated {record['tls_version']!r}; this project permits TLS 1.3 only"
            )

    # The central honesty check: the post-quantum claims must follow from the
    # group that was actually negotiated, not from what was requested.
    if group:
        actually_pq = group in PQ_GROUPS
        actually_hybrid = group in HYBRID_GROUPS

        if claims_pq and not actually_pq:
            problems.append(
                f"record claims pq_key_establishment=true but negotiated group "
                f"{record.get('negotiated_group')!r} is classical"
            )
        if actually_pq and success and not claims_pq:
            problems.append(
                f"negotiated group {record.get('negotiated_group')!r} is post-quantum but "
                "pq_key_establishment is not true"
            )
        if claims_hybrid and not actually_hybrid:
            problems.append(
                f"record claims hybrid_key_establishment=true but negotiated group "
                f"{record.get('negotiated_group')!r} is not a hybrid construction"
            )

    if claims_hybrid and not claims_pq:
        problems.append("hybrid_key_establishment=true requires pq_key_establishment=true")

    # A hybrid key exchange authenticated by ECDSA is not post-quantum
    # authentication, and a record must not say otherwise.
    auth = str(record.get("authentication", "")).lower()
    if claims_pq_auth and auth and not any(
        marker in auth for marker in ("mldsa", "ml-dsa", "dilithium", "falcon", "sphincs")
    ):
        problems.append(
            f"record claims pq_authentication=true but the authentication algorithm is "
            f"{record.get('authentication')!r}, which is not post-quantum"
        )

    profile = str(record.get("requested_profile", ""))
    if success and profile.startswith(("hybrid-", "pure-")) and group and group not in PQ_GROUPS:
        problems.append(
            f"profile {profile!r} requires post-quantum key establishment but the connection "
            f"negotiated {record.get('negotiated_group')!r}. This is a downgrade and the "
            "connection should have been rejected."
        )

    return problems


def load_schema_validator() -> tuple[Any, str]:
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        return None, "builtin"

    if not SCHEMA_PATH.exists():
        return None, "builtin (schema file not found)"

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)

    # importlib.metadata rather than jsonschema.__version__: the latter is
    # deprecated and emits a DeprecationWarning, which CI treats as an error.
    try:
        from importlib.metadata import version as _package_version

        installed = _package_version("jsonschema")
    except Exception:  # noqa: BLE001 - the version is cosmetic, never fatal
        installed = "unknown version"

    return validator_class(schema), f"jsonschema {installed}"


def validate_file(path: Path, validator: Any, report: Report) -> None:
    report.files += 1

    for line_number, line in iter_lines(path):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            report.violations.append(
                Violation(str(path), line_number, "json", f"not valid JSON: {exc.msg}")
            )
            continue

        if not isinstance(record, dict):
            report.violations.append(
                Violation(str(path), line_number, "json",
                          "each JSONL line must be a JSON object")
            )
            continue

        report.records += 1

        if validator is not None:
            for error in sorted(validator.iter_errors(record), key=lambda e: list(e.path)):
                location = "/".join(str(p) for p in error.path) or "<root>"
                report.violations.append(
                    Violation(str(path), line_number, "schema", f"{location}: {error.message}")
                )
        else:
            for problem in builtin_structural_check(record):
                report.violations.append(
                    Violation(str(path), line_number, "structure", problem)
                )

        for problem in semantic_check(record):
            report.violations.append(Violation(str(path), line_number, "semantic", problem))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate pqtls-lab JSONL result files."
    )
    parser.add_argument("paths", nargs="+", type=Path,
                        help=".jsonl files or directories containing them")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the summary line")
    parser.add_argument("--max-violations", type=int, default=50,
                        help="stop listing after this many violations (0 = no limit)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    files: list[Path] = []
    for path in args.paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.jsonl")))
        elif path.is_file():
            files.append(path)
        else:
            print(f"error: {path} does not exist", file=sys.stderr)
            return 2

    if not files:
        print("error: no .jsonl files to validate", file=sys.stderr)
        return 2

    validator, backend = load_schema_validator()
    report = Report(schema_backend=backend)

    if backend == "builtin" and not args.quiet:
        print(
            "note: the 'jsonschema' package is not installed; using the built-in structural\n"
            "      checker. Install it with 'pip install jsonschema' for full schema coverage.",
            file=sys.stderr,
        )

    for path in files:
        try:
            validate_file(path, validator, report)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2

    if not args.quiet:
        limit = args.max_violations or len(report.violations)
        for violation in report.violations[:limit]:
            print(violation, file=sys.stderr)
        if len(report.violations) > limit:
            print(
                f"... and {len(report.violations) - limit} more",
                file=sys.stderr,
            )

    print(
        f"validated {report.records} record(s) in {report.files} file(s) "
        f"using {report.schema_backend}: "
        f"{'OK' if report.ok else str(len(report.violations)) + ' violation(s)'}"
    )

    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
