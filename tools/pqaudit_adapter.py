#!/usr/bin/env python3
"""PQAudit -> pqtls-lab profile recommendation adapter (stub).

Scope, stated plainly: this maps an asset's *currently observed* TLS
configuration onto a pqtls-lab profile to test it against, and lists the tests
that ought to be run before anyone changes anything. It is a starting point for
an experiment plan.

It is not a migration tool, and it does not certify anything. Specifically it
does NOT:

  * assert that the recommended profile will work with the asset's existing
    clients (that is what the legacy-client-compatibility test is for);
  * assert that migrating will preserve availability;
  * make any claim about post-quantum *authentication*, which stays classical
    in every non-experimental recommendation.

Formats are defined in schemas/pqaudit-input.schema.json and
schemas/pqaudit-output.schema.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

VALID_HNDL_LEVELS = {"low", "medium", "high", "critical"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}

# Baseline tests every recommendation carries. The MTU and packet-loss entries
# are there because a post-quantum key share enlarges the ClientHello, which is
# exactly where path-MTU and loss problems appear.
BASE_TESTS = [
    "certificate-validation",
    "mtu",
    "packet-loss",
    "legacy-client-compatibility",
]


@dataclass
class Recommendation:
    asset_id: str
    recommended_profile: str
    current_authentication: str
    recommended_initial_authentication: str
    recommended_experimental_authentication: str
    classical_fallback_allowed: bool
    required_tests: list[str]
    rationale: list[str]
    caveats: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "asset_id": self.asset_id,
            "recommended_profile": self.recommended_profile,
            "authentication_transition": {
                "current": self.current_authentication,
                "recommended_initial": self.recommended_initial_authentication,
                "recommended_experimental": self.recommended_experimental_authentication,
            },
            "classical_fallback_allowed": self.classical_fallback_allowed,
            "required_tests": self.required_tests,
            "rationale": self.rationale,
            "caveats": self.caveats,
        }


class InputError(ValueError):
    """The PQAudit document is not usable."""


def validate_input(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise InputError("the input must be a JSON object")

    if document.get("schema_version") != SCHEMA_VERSION:
        raise InputError(
            f"unsupported schema_version {document.get('schema_version')!r}; "
            f"this adapter understands version {SCHEMA_VERSION}"
        )

    if not document.get("asset_id"):
        raise InputError("'asset_id' is required")

    tls = document.get("tls")
    if not isinstance(tls, dict):
        raise InputError("'tls' must be an object describing the observed configuration")

    for required in ("minimum_version", "key_exchange", "certificate_algorithm"):
        if not tls.get(required):
            raise InputError(f"'tls.{required}' is required")

    risk = document.get("quantum_risk", {})
    if risk and not isinstance(risk, dict):
        raise InputError("'quantum_risk' must be an object when present")

    level = risk.get("hndl_level")
    if level is not None and level not in VALID_HNDL_LEVELS:
        raise InputError(
            f"unknown quantum_risk.hndl_level {level!r}; expected one of "
            f"{sorted(VALID_HNDL_LEVELS)}"
        )

    priority = risk.get("migration_priority")
    if priority is not None and priority not in VALID_PRIORITIES:
        raise InputError(
            f"unknown quantum_risk.migration_priority {priority!r}; expected one of "
            f"{sorted(VALID_PRIORITIES)}"
        )

    return document


def recommend(document: dict[str, Any], allow_experimental: bool = False) -> Recommendation:
    tls = document["tls"]
    risk = document.get("quantum_risk", {}) or {}

    asset_id = str(document["asset_id"])
    key_exchange = str(tls["key_exchange"])
    cert_algorithm = str(tls["certificate_algorithm"])
    minimum_version = str(tls["minimum_version"])
    hndl = str(risk.get("hndl_level", "medium"))

    rationale: list[str] = []
    caveats: list[str] = []
    tests = list(BASE_TESTS)

    # --- Choose the hybrid group -------------------------------------------
    #
    # Match the curve family the asset already uses. Keeping the classical half
    # of the hybrid familiar reduces the number of things changing at once,
    # which matters when something later fails and has to be attributed.
    key_exchange_lower = key_exchange.lower()
    if "p-384" in key_exchange_lower or "secp384" in key_exchange_lower:
        profile = "hybrid-p384-mlkem1024"
        rationale.append(
            "the asset already uses a P-384 key exchange, so the P-384 + ML-KEM-1024 hybrid "
            "keeps the classical component at the security level already in use"
        )
    elif "p-256" in key_exchange_lower or "secp256" in key_exchange_lower:
        profile = "hybrid-p256-mlkem768"
        rationale.append(
            "the asset uses a NIST P-256 key exchange, so the P-256 + ML-KEM-768 hybrid is the "
            "smallest change from the current configuration"
        )
    else:
        profile = "hybrid-x25519-mlkem768"
        rationale.append(
            "no specific curve family was indicated, so the primary X25519 + ML-KEM-768 profile "
            "is recommended as the default hybrid"
        )

    # --- Authentication -----------------------------------------------------
    #
    # Always classical initially. The certificate ecosystem, not the TLS stack,
    # is the constraint here: there is no public CA issuing ML-DSA certificates
    # for general use.
    recommended_initial = "ECDSA-P384" if profile == "hybrid-p384-mlkem1024" else "ECDSA-P256"

    if "rsa" in cert_algorithm.lower():
        rationale.append(
            f"the current certificate uses {cert_algorithm}; moving to {recommended_initial} "
            "reduces handshake size, which partly offsets the larger post-quantum key share"
        )
        tests.append("certificate-rollover")

    caveats.append(
        "This recommendation changes KEY ESTABLISHMENT only. Authentication stays classical, so "
        "the asset is protected against harvest-now-decrypt-later but is NOT protected against "
        "an adversary with a quantum computer who is able to forge signatures at connection time."
    )

    # --- Fallback policy ----------------------------------------------------
    #
    # High HNDL exposure is precisely the case where a classical fallback
    # defeats the purpose: an attacker recording traffic only needs the
    # connections that fell back.
    if hndl in ("high", "critical"):
        classical_fallback = False
        rationale.append(
            f"harvest-now-decrypt-later exposure is '{hndl}', so classical fallback is disallowed: "
            "a connection that falls back is exactly the one an attacker would record"
        )
        caveats.append(
            "With fallback disabled, clients that do not support the hybrid group will FAIL to "
            "connect rather than downgrade. Run the legacy-client-compatibility test and plan the "
            "client rollout before enforcing this."
        )
        tests.append("downgrade-rejection")
    else:
        classical_fallback = True
        rationale.append(
            f"harvest-now-decrypt-later exposure is '{hndl}', so a classical fallback is "
            "tolerable during migration; revisit once client coverage is known"
        )
        caveats.append(
            "Classical fallback is permitted here. Any connection that falls back provides NO "
            "post-quantum protection, and the results must not be reported as if it did."
        )

    if minimum_version not in ("TLS1.3", "TLSv1.3"):
        rationale.append(
            f"the asset currently permits {minimum_version}; every pqtls-lab profile is TLS 1.3 "
            "only, so TLS 1.2 clients will need to be identified first"
        )
        tests.append("tls12-client-inventory")

    if risk.get("migration_priority") in ("high", "critical"):
        tests.append("concurrency")
        tests.append("latency")

    experimental_auth = "ML-DSA-65"
    if not allow_experimental:
        caveats.append(
            "ML-DSA-65 is listed as the experimental authentication target only. It is "
            "capability-gated in pqtls-lab, has no public CA support, and must not be treated as "
            "a deployment option."
        )

    return Recommendation(
        asset_id=asset_id,
        recommended_profile=profile,
        current_authentication=cert_algorithm,
        recommended_initial_authentication=recommended_initial,
        recommended_experimental_authentication=experimental_auth,
        classical_fallback_allowed=classical_fallback,
        required_tests=sorted(set(tests)),
        rationale=rationale,
        caveats=caveats,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a PQAudit asset record into a pqtls-lab profile recommendation."
    )
    parser.add_argument("input", type=Path, nargs="?", default=None,
                        help="PQAudit JSON document (default: stdin)")
    parser.add_argument("--output", type=Path, default=None,
                        help="write the recommendation here (default: stdout)")
    parser.add_argument("--allow-experimental", action="store_true",
                        help="permit experimental profiles in the recommendation")
    args = parser.parse_args(argv)

    try:
        raw = args.input.read_text(encoding="utf-8") if args.input else sys.stdin.read()
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    try:
        document = validate_input(json.loads(raw))
    except json.JSONDecodeError as exc:
        print(f"error: input is not valid JSON: {exc}", file=sys.stderr)
        return 2
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    recommendation = recommend(document, allow_experimental=args.allow_experimental)
    payload = json.dumps(recommendation.to_json(), indent=2)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
        print(f"recommendation written to {args.output}")
    else:
        print(payload)

    return 0


if __name__ == "__main__":
    sys.exit(main())
