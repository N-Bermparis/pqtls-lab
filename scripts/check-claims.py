#!/usr/bin/env python3
"""Check that the documentation does not overstate what pqtls-lab provides.

In this project a false claim about a security property is a security problem:
downstream decisions get made on it. So the claims policy is enforced by a
checker rather than left to review.

Why this is not a set of greps. A line-based grep cannot tell

    "...is protected against harvest-now-decrypt-later, but it is **not**
     end-to-end quantum-safe."

from an actual claim of end-to-end quantum safety. The negation sits on the
previous line, and it is wrapped in markdown emphasis. This checker therefore
normalises markdown emphasis away and inspects a window of surrounding context
before deciding.

Exit codes:  0 clean   1 a forbidden claim was found   2 usage error
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Lines of context searched for a negation on either side of a hit.
CONTEXT_LINES = 2

# Word-boundary anchored on purpose. A bare substring list would match "no"
# inside "normal" or "not" inside "notably", silently suppressing a real
# violation — the one failure mode a claims checker must not have.
NEGATION_PATTERN = re.compile(
    r"\b(?:not|never|no|cannot|can't|without|neither|nor|avoids?|refus\w*"
    r"|forbid\w*|reject\w*|beware|warning|prohibit\w*|must\s+not|does\s+not"
    r"|is\s+not|are\s+not|has\s+not|have\s+not)\b",
    re.I,
)


@dataclass
class Rule:
    name: str
    pattern: re.Pattern[str]
    explanation: str
    negatable: bool = True


RULES = [
    Rule(
        name="production-readiness",
        pattern=re.compile(r"production[ -]ready|ready for production", re.I),
        explanation=(
            "pqtls-lab is a research prototype. Claiming production readiness would be false."
        ),
    ),
    Rule(
        name="end-to-end-quantum-safe",
        pattern=re.compile(
            r"quantum[- ]safe end[- ]to[- ]end"
            r"|end[- ]to[- ]end quantum[- ]safe"
            r"|quantum[- ]safe authentication"
            r"|post[- ]quantum authentication is provided",
            re.I,
        ),
        explanation=(
            "The hybrid profiles provide post-quantum KEY ESTABLISHMENT with CLASSICAL "
            "authentication. Describing that as end-to-end quantum-safe is false."
        ),
    ),
    Rule(
        name="draft-called-rfc",
        # Matches either ordering: the RFC number before or after the group
        # name. "X25519MLKEM768 is defined in RFC 9999" and "RFC 9999 defines
        # X25519MLKEM768" are the same false claim.
        pattern=re.compile(
            r"RFC\s*\d+[^.\n]{0,80}?"
            r"(?:X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|hybrid key exchange)"
            r"|(?:X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|hybrid key exchange)"
            r"[^.\n]{0,80}?RFC\s*\d+",
            re.I,
        ),
        explanation=(
            "Hybrid TLS group definitions are in-progress specification work, not finalised "
            "RFCs. See docs/pqc-standards-status.md."
        ),
    ),
    Rule(
        name="audited",
        pattern=re.compile(
            r"\b(has been|was|is) (independently )?audited"
            r"|\bsecurity[- ]audited\b"
            r"|\bpassed (a|an) (security )?audit",
            re.I,
        ),
        explanation="No independent security audit has been performed.",
    ),
]

# Requirements the documentation must positively satisfy.
REQUIRED = [
    ("README.md", re.compile(r"research prototype", re.I),
     "the README must identify the project as a research prototype"),
    ("README.md",
     re.compile(r"has not been.*audit|no independent security audit|not been independently audited",
                re.I),
     "the README must state that the project has not been independently audited"),
    ("README.md", re.compile(r"post-quantum \*\*key establishment\*\*|key establishment", re.I),
     "the README must distinguish key establishment from authentication"),
]


def normalise(text: str) -> str:
    """Strip markdown emphasis so `**not**` reads as `not`."""
    text = re.sub(r"[*_`]+", "", text)
    return re.sub(r"\s+", " ", text)


def is_negated(lines: list[str], index: int) -> bool:
    """True when a negation appears near `lines[index]`.

    The window matters: a negation frequently sits on the line before a
    wrapped sentence, which is precisely the case a grep gets wrong.
    """
    start = max(0, index - CONTEXT_LINES)
    end = min(len(lines), index + CONTEXT_LINES + 1)
    window = normalise(" ".join(lines[start:end]))
    return NEGATION_PATTERN.search(window) is not None


def check_file(path: Path, strict: bool) -> list[str]:
    problems: list[str] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"{path}: cannot read ({exc})"]

    lines = raw.splitlines()

    for rule in RULES:
        for index, line in enumerate(lines):
            if not rule.pattern.search(normalise(line)):
                continue
            if rule.negatable and is_negated(lines, index):
                continue  # correctly negated in context
            # ASCII arrow: this runs in CI logs and on Windows terminals whose
            # code page mangles non-ASCII output.
            problems.append(
                f"{path}:{index + 1}: [{rule.name}] {line.strip()[:110]}\n"
                f"    -> {rule.explanation}"
            )

    if strict:
        for filename, pattern, message in REQUIRED:
            if path.name == filename and not pattern.search(raw):
                problems.append(f"{path}: missing required statement — {message}")

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check pqtls-lab documentation for overstated claims."
    )
    parser.add_argument(
        "paths", nargs="*", type=Path,
        default=[REPO_ROOT / "README.md", REPO_ROOT / "docs"],
        help="files or directories to check (default: README.md and docs/)",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    files: list[Path] = []
    for path in args.paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.md")))
        elif path.is_file():
            files.append(path)
        else:
            print(f"error: {path} does not exist", file=sys.stderr)
            return 2

    if not files:
        print("error: nothing to check", file=sys.stderr)
        return 2

    problems: list[str] = []
    for path in files:
        problems.extend(check_file(path, strict=True))

    if problems:
        print("Forbidden or missing claims:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}\n", file=sys.stderr)
        print(f"{len(problems)} problem(s) in {len(files)} file(s)", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"claims check passed: {len(files)} file(s), no overstated claims")
    return 0


if __name__ == "__main__":
    sys.exit(main())
