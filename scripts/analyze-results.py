#!/usr/bin/env python3
"""Summary statistics for pqtls-lab JSONL results.

Reads raw per-connection records and produces CSV and JSON summaries. The raw
files are opened read-only and are never modified: every number here can be
recomputed from data that stays on disk.

What this script will not do:
  * Invent a value. A statistic that cannot be computed from the input is
    reported as null, not as zero.
  * Hide failures. Failure counts and error categories are part of the summary.
  * Merge post-quantum key establishment and post-quantum authentication into
    one column. They are separate properties and stay in separate columns.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

# Student's t critical values at 95% confidence, indexed by degrees of freedom.
# Used instead of a flat 1.96 so that small samples are not reported with a
# falsely narrow interval.
_T95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
    15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    25: 2.060, 30: 2.042, 40: 2.021, 60: 2.000, 120: 1.980,
}


def t_critical_95(degrees_of_freedom: int) -> float:
    if degrees_of_freedom < 1:
        return float("nan")
    if degrees_of_freedom in _T95:
        return _T95[degrees_of_freedom]
    for threshold in sorted(_T95):
        if degrees_of_freedom <= threshold:
            return _T95[threshold]
    return 1.960  # Normal approximation for large samples.


def percentile(sorted_values: list[float], fraction: float) -> float | None:
    """Linear-interpolation percentile (the 'exclusive-free' type 7 method)."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = fraction * (len(sorted_values) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[int(position)]
    weight = position - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


@dataclass
class Distribution:
    count: int
    mean: float | None
    median: float | None
    minimum: float | None
    maximum: float | None
    stdev: float | None
    p50: float | None
    p90: float | None
    p95: float | None
    p99: float | None
    ci95_low: float | None
    ci95_high: float | None

    @classmethod
    def of(cls, values: Iterable[float]) -> Distribution:
        data = sorted(float(v) for v in values)
        count = len(data)

        if count == 0:
            return cls(0, None, None, None, None, None, None, None, None, None, None, None)

        mean = statistics.fmean(data)
        # A standard deviation needs at least two observations; reporting 0.0
        # for a single sample would imply a precision that does not exist.
        stdev = statistics.stdev(data) if count >= 2 else None

        ci_low = ci_high = None
        if stdev is not None and count >= 2:
            margin = t_critical_95(count - 1) * stdev / math.sqrt(count)
            ci_low, ci_high = mean - margin, mean + margin

        return cls(
            count=count,
            mean=mean,
            median=statistics.median(data),
            minimum=data[0],
            maximum=data[-1],
            stdev=stdev,
            p50=percentile(data, 0.50),
            p90=percentile(data, 0.90),
            p95=percentile(data, 0.95),
            p99=percentile(data, 0.99),
            ci95_low=ci_low,
            ci95_high=ci_high,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": self.count, "mean": self.mean, "median": self.median,
            "min": self.minimum, "max": self.maximum, "stdev": self.stdev,
            "p50": self.p50, "p90": self.p90, "p95": self.p95, "p99": self.p99,
            "ci95_low": self.ci95_low, "ci95_high": self.ci95_high,
        }


def iter_records(paths: Iterable[Path]) -> Iterator[tuple[Path, int, dict[str, Any]]]:
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(
                        f"warning: {path}:{line_number} is not valid JSON and was skipped ({exc})",
                        file=sys.stderr,
                    )
                    continue
                if not isinstance(record, dict):
                    print(f"warning: {path}:{line_number} is not a JSON object; skipped",
                          file=sys.stderr)
                    continue
                yield path, line_number, record


def collect_files(target: Path, experiment_id: str | None) -> list[Path]:
    if target.is_file():
        return [target]
    if not target.is_dir():
        raise SystemExit(f"error: {target} is neither a file nor a directory")

    pattern = f"{experiment_id}-*.jsonl" if experiment_id else "*.jsonl"
    files = sorted(p for p in target.glob(pattern) if p.is_file())
    if not files:
        raise SystemExit(f"error: no .jsonl files matching '{pattern}' under {target}")
    return files


def group_key(record: dict[str, Any], by: list[str]) -> tuple[str, ...]:
    return tuple(str(record.get(field, "")) for field in by)


def summarise(records: list[dict[str, Any]], by: list[str]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[group_key(record, by)].append(record)

    summaries: list[dict[str, Any]] = []

    for key, group in sorted(groups.items()):
        successes = [r for r in group if r.get("success") is True]
        failures = [r for r in group if r.get("success") is not True]

        handshake = Distribution.of(
            r["handshake_ms"] for r in successes if isinstance(r.get("handshake_ms"), (int, float))
        )
        connection = Distribution.of(
            r["connection_ms"] for r in successes
            if isinstance(r.get("connection_ms"), (int, float))
        )

        error_counter = Counter(
            str(r.get("error_category") or "unknown") for r in failures
        )

        # Derived from the negotiated group recorded per connection, never from
        # the requested profile. A run in which the hybrid group was requested
        # but not negotiated must not be summarised as post-quantum.
        pq_ke = sum(1 for r in successes if r.get("pq_key_establishment") is True)
        hybrid_ke = sum(1 for r in successes if r.get("hybrid_key_establishment") is True)
        pq_auth = sum(1 for r in successes if r.get("pq_authentication") is True)
        resumed = sum(1 for r in successes if r.get("session_reused") is True)

        negotiated_groups = Counter(
            str(r.get("negotiated_group") or "unknown") for r in successes
        )

        summary: dict[str, Any] = dict(zip(by, key))
        summary.update(
            {
                "total": len(group),
                "successful": len(successes),
                "failed": len(failures),
                "success_rate": len(successes) / len(group) if group else 0.0,
                "failure_rate": len(failures) / len(group) if group else 0.0,
                "handshake_ms": handshake.as_dict(),
                "connection_ms": connection.as_dict(),
                "error_categories": dict(error_counter),
                "negotiated_groups": dict(negotiated_groups),
                "sessions_resumed": resumed,
                # Three counts, three columns, never collapsed into one.
                "pq_key_establishment_count": pq_ke,
                "hybrid_key_establishment_count": hybrid_ke,
                "pq_authentication_count": pq_auth,
            }
        )
        summaries.append(summary)

    return summaries


CSV_COLUMNS = [
    "requested_profile", "negotiated_group", "role", "total", "successful", "failed",
    "success_rate", "handshake_count", "handshake_mean_ms", "handshake_median_ms",
    "handshake_min_ms", "handshake_max_ms", "handshake_stdev_ms", "handshake_p50_ms",
    "handshake_p90_ms", "handshake_p95_ms", "handshake_p99_ms",
    "handshake_ci95_low_ms", "handshake_ci95_high_ms",
    "connection_mean_ms", "connection_median_ms", "connection_p95_ms",
    "sessions_resumed", "pq_key_establishment_count", "hybrid_key_establishment_count",
    "pq_authentication_count",
]


def flatten_for_csv(summary: dict[str, Any], by: list[str]) -> dict[str, Any]:
    handshake = summary["handshake_ms"]
    connection = summary["connection_ms"]
    row = {column: "" for column in CSV_COLUMNS}
    for field in by:
        row[field] = summary.get(field, "")
    row.update(
        {
            "total": summary["total"],
            "successful": summary["successful"],
            "failed": summary["failed"],
            "success_rate": round(summary["success_rate"], 6),
            "handshake_count": handshake["count"],
            "handshake_mean_ms": handshake["mean"],
            "handshake_median_ms": handshake["median"],
            "handshake_min_ms": handshake["min"],
            "handshake_max_ms": handshake["max"],
            "handshake_stdev_ms": handshake["stdev"],
            "handshake_p50_ms": handshake["p50"],
            "handshake_p90_ms": handshake["p90"],
            "handshake_p95_ms": handshake["p95"],
            "handshake_p99_ms": handshake["p99"],
            "handshake_ci95_low_ms": handshake["ci95_low"],
            "handshake_ci95_high_ms": handshake["ci95_high"],
            "connection_mean_ms": connection["mean"],
            "connection_median_ms": connection["median"],
            "connection_p95_ms": connection["p95"],
            "sessions_resumed": summary["sessions_resumed"],
            "pq_key_establishment_count": summary["pq_key_establishment_count"],
            "hybrid_key_establishment_count": summary["hybrid_key_establishment_count"],
            "pq_authentication_count": summary["pq_authentication_count"],
        }
    )
    return row


def print_table(summaries: list[dict[str, Any]], by: list[str]) -> None:
    header = f"{'group':<52} {'n':>5} {'ok':>5} {'fail':>5} {'mean':>9} {'p50':>9} {'p95':>9} {'p99':>9}"
    print(header)
    print("-" * len(header))
    for summary in summaries:
        label = " / ".join(str(summary.get(field, "")) for field in by)
        handshake = summary["handshake_ms"]

        def fmt(value: float | None) -> str:
            return f"{value:9.3f}" if isinstance(value, (int, float)) else f"{'n/a':>9}"

        print(
            f"{label[:52]:<52} {summary['total']:>5} {summary['successful']:>5} "
            f"{summary['failed']:>5} {fmt(handshake['mean'])} {fmt(handshake['p50'])} "
            f"{fmt(handshake['p95'])} {fmt(handshake['p99'])}"
        )
    print()
    print("handshake times in milliseconds; 'n/a' means the statistic could not be")
    print("computed from the available samples, not that it is zero.")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarise pqtls-lab JSONL results without modifying them."
    )
    parser.add_argument("path", type=Path,
                        help="a .jsonl file or a directory containing them")
    parser.add_argument("--experiment-id", default=None,
                        help="only consider files for this experiment id")
    parser.add_argument("--group-by", nargs="+",
                        default=["requested_profile", "negotiated_group", "role"])
    parser.add_argument("--csv", type=Path, default=None, help="write a CSV summary here")
    parser.add_argument("--json", type=Path, default=None, help="write a JSON summary here")
    parser.add_argument("--role", default=None, choices=["client", "server"],
                        help="restrict the analysis to one role")
    parser.add_argument("--include-failures", action="store_true", default=True,
                        help="(default) include failed connections in the counts")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    files = collect_files(args.path, args.experiment_id)
    print(f"reading {len(files)} file(s)")

    records: list[dict[str, Any]] = []
    for _path, _line, record in iter_records(files):
        if args.role and record.get("role") != args.role:
            continue
        records.append(record)

    if not records:
        print("error: no usable records were found", file=sys.stderr)
        return 1

    print(f"records: {len(records)}")
    print()

    summaries = summarise(records, args.group_by)
    print_table(summaries, args.group_by)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "source_files": [str(p) for p in files],
            "record_count": len(records),
            "group_by": args.group_by,
            "summaries": summaries,
        }
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"JSON summary written to {args.json}")

    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        columns = list(dict.fromkeys(args.group_by + CSV_COLUMNS))
        with args.csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for summary in summaries:
                writer.writerow(flatten_for_csv(summary, args.group_by))
        print(f"CSV summary written to {args.csv}")

    # Surface any group where a post-quantum profile did not actually negotiate
    # a post-quantum group. That is a downgrade, and it must not be buried in a
    # table someone skims.
    for summary in summaries:
        profile = str(summary.get("requested_profile", ""))
        if profile.startswith(("hybrid-", "pure-")) and summary["successful"] > 0:
            if summary["pq_key_establishment_count"] < summary["successful"]:
                print(
                    f"\nWARNING: profile '{profile}' had {summary['successful']} successful "
                    f"connections but only {summary['pq_key_establishment_count']} used a "
                    "post-quantum group. Investigate before using these results.",
                    file=sys.stderr,
                )

    return 0


if __name__ == "__main__":
    sys.exit(main())
