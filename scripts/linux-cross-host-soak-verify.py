#!/usr/bin/env python3
"""Validate cross-host TrustIX production soak artifacts.

The single-host production matrix intentionally skips full-kmod and route-GSO
throughput gates because a netns-only topology is not representative for those
paths. This verifier turns cross-host result directories into a simple pass/fail
artifact gate: result marker, bidirectional iperf3 JSON, minimum throughput and
duration, plus log scanning for kernel crash signatures.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CRASH_RE = re.compile(
    r"(?i)("
    r"kernel panic|"
    r"\bpanic\b|"
    r"\boops\b|"
    r"\bBUG:|"
    r"\bCall Trace:\b|"
    r"\bRIP:\b|"
    r"general protection fault|"
    r"kernel NULL pointer dereference|"
    r"unable to handle kernel paging request|"
    r"\bpage fault\b|"
    r"soft lockup|"
    r"hard lockup|"
    r"watchdog: BUG|"
    r"rcu: .*stall|"
    r"blocked for more than [0-9]+ seconds"
    r")"
)

LOG_SUFFIXES = {".log", ".err", ".txt", ".out"}


@dataclass
class CaseSpec:
    name: str
    path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate cross-host TrustIX soak result directories."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="result directories; case name defaults to the directory name",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="named result directory; may be repeated",
    )
    parser.add_argument(
        "--min-gbps",
        type=float,
        default=4.0,
        help="minimum sent and received iperf3 throughput per direction",
    )
    parser.add_argument(
        "--min-seconds",
        type=float,
        default=120.0,
        help="minimum iperf3 measured seconds per direction",
    )
    parser.add_argument(
        "--seconds-slop",
        type=float,
        default=1.0,
        help="allowed iperf3 timer rounding slop below --min-seconds",
    )
    parser.add_argument(
        "--min-iperf-json",
        type=int,
        default=2,
        help="minimum number of iperf3 JSON files expected per case",
    )
    parser.add_argument(
        "--summary",
        help="optional JSONL summary output path",
    )
    parser.add_argument(
        "--no-result-marker",
        action="store_true",
        help="do not require a *.result file containing pass",
    )
    parser.add_argument(
        "--no-log-scan",
        action="store_true",
        help="skip panic/oops/lockup log signature scanning",
    )
    return parser.parse_args()


def parse_cases(args: argparse.Namespace) -> list[CaseSpec]:
    cases: list[CaseSpec] = []
    for raw in args.case:
        name, sep, path = raw.partition("=")
        if not sep or not name.strip() or not path.strip():
            raise SystemExit(f"invalid --case {raw!r}; expected NAME=PATH")
        cases.append(CaseSpec(name=name.strip(), path=Path(path.strip())))
    for raw in args.paths:
        path = Path(raw)
        cases.append(CaseSpec(name=path.name, path=path))
    if not cases:
        raise SystemExit("at least one result directory is required")
    return cases


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def iperf_sums(path: Path) -> tuple[float, float, float]:
    payload = read_json(path)
    end = payload.get("end") or {}
    sent = end.get("sum_sent") or {}
    received = end.get("sum_received") or {}
    sent_bps = float(sent.get("bits_per_second") or 0)
    received_bps = float(received.get("bits_per_second") or 0)
    seconds = float(received.get("seconds") or sent.get("seconds") or 0)
    return sent_bps / 1e9, received_bps / 1e9, seconds


def result_markers_pass(case_dir: Path) -> tuple[bool, list[str]]:
    markers = sorted(case_dir.glob("*.result"))
    values: list[str] = []
    for marker in markers:
        try:
            values.append(marker.read_text(encoding="utf-8", errors="replace").strip())
        except OSError as exc:
            values.append(f"read_error:{exc}")
    return bool(markers) and all(value == "pass" for value in values), values


def scan_logs(case_dir: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path.suffix not in LOG_SUFFIXES:
            continue
        try:
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                if CRASH_RE.search(line):
                    rel = path.relative_to(case_dir)
                    findings.append(f"{rel}:{lineno}:{line[:240]}")
        except OSError as exc:
            rel = path.relative_to(case_dir)
            findings.append(f"{rel}:read_error:{exc}")
    return findings


def validate_case(
    case: CaseSpec,
    *,
    min_gbps: float,
    min_seconds: float,
    seconds_slop: float,
    min_iperf_json: int,
    require_result_marker: bool,
    log_scan: bool,
) -> dict[str, Any]:
    errors: list[str] = []
    if not case.path.is_dir():
        return {
            "case": case.name,
            "path": str(case.path),
            "status": "fail",
            "errors": [f"result directory not found: {case.path}"],
        }

    marker_ok, marker_values = result_markers_pass(case.path)
    if require_result_marker and not marker_ok:
        errors.append(f"missing or non-pass result marker: {marker_values!r}")

    iperf_files = sorted(case.path.rglob("*iperf*.json"))
    if len(iperf_files) < min_iperf_json:
        errors.append(f"found {len(iperf_files)} iperf JSON files, want >= {min_iperf_json}")

    iperf_results: list[dict[str, Any]] = []
    for path in iperf_files:
        try:
            sent_gbps, received_gbps, seconds = iperf_sums(path)
        except Exception as exc:  # noqa: BLE001 - artifact validation should report and continue.
            errors.append(f"{path.relative_to(case.path)}: parse iperf JSON: {exc}")
            continue
        rel = str(path.relative_to(case.path))
        iperf_results.append(
            {
                "file": rel,
                "sent_gbps": round(sent_gbps, 6),
                "received_gbps": round(received_gbps, 6),
                "seconds": round(seconds, 6),
            }
        )
        if sent_gbps < min_gbps:
            errors.append(f"{rel}: sent {sent_gbps:.3f}Gbps < {min_gbps:.3f}Gbps")
        if received_gbps < min_gbps:
            errors.append(f"{rel}: received {received_gbps:.3f}Gbps < {min_gbps:.3f}Gbps")
        if seconds + seconds_slop < min_seconds:
            errors.append(
                f"{rel}: seconds {seconds:.3f} + slop {seconds_slop:.3f} < {min_seconds:.3f}"
            )

    log_findings = scan_logs(case.path) if log_scan else []
    if log_findings:
        errors.extend(f"log crash signature: {finding}" for finding in log_findings)

    min_sent = min((item["sent_gbps"] for item in iperf_results), default=0)
    min_received = min((item["received_gbps"] for item in iperf_results), default=0)
    min_duration = min((item["seconds"] for item in iperf_results), default=0)
    return {
        "case": case.name,
        "path": str(case.path),
        "status": "fail" if errors else "pass",
        "min_gbps_required": min_gbps,
        "min_seconds_required": min_seconds,
        "seconds_slop": seconds_slop,
        "iperf_json_count": len(iperf_files),
        "min_sent_gbps": round(min_sent, 6),
        "min_received_gbps": round(min_received, 6),
        "min_seconds": round(min_duration, 6),
        "result_markers": marker_values,
        "iperf": iperf_results,
        "log_findings": log_findings,
        "errors": errors,
    }


def write_summary(path: str, rows: list[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    if args.min_gbps < 0:
        raise SystemExit("--min-gbps must be non-negative")
    if args.min_seconds < 0:
        raise SystemExit("--min-seconds must be non-negative")
    if args.seconds_slop < 0:
        raise SystemExit("--seconds-slop must be non-negative")
    if args.min_iperf_json < 0:
        raise SystemExit("--min-iperf-json must be non-negative")

    rows = [
        validate_case(
            case,
            min_gbps=args.min_gbps,
            min_seconds=args.min_seconds,
            seconds_slop=args.seconds_slop,
            min_iperf_json=args.min_iperf_json,
            require_result_marker=not args.no_result_marker,
            log_scan=not args.no_log_scan,
        )
        for case in parse_cases(args)
    ]
    if args.summary:
        write_summary(args.summary, rows)
    for row in rows:
        print(json.dumps(row, sort_keys=True))
    return 1 if any(row["status"] != "pass" for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
