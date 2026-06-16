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
import hashlib
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
    parser.add_argument(
        "--require-build-identity",
        action="store_true",
        help="require at least two collected status.json build blocks and verify they match",
    )
    parser.add_argument(
        "--require-strong-build-identity",
        action="store_true",
        help="also reject placeholder or missing commit/time build metadata",
    )
    parser.add_argument(
        "--require-binary-identity",
        action="store_true",
        help="require at least two collected binary-identity.json files and verify their sha256 values match",
    )
    parser.add_argument(
        "--require-datapath-stat",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected datapath.json to contain PATH with VALUE; may be repeated",
    )
    parser.add_argument(
        "--min-datapath-json",
        type=int,
        default=0,
        help="minimum number of datapath.json files expected; defaults to 2 when --require-datapath-stat is used",
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


def iperf_sums(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path)
    end = payload.get("end") or {}
    rows: list[dict[str, Any]] = []

    def append_pair(
        direction: str,
        sent_key: str,
        received_key: str,
        *,
        default_require_received: bool,
    ) -> None:
        sent = end.get(sent_key) or {}
        received = end.get(received_key) or {}
        if not sent and not received:
            return
        sent_bps = float(sent.get("bits_per_second") or 0)
        received_bps = float(received.get("bits_per_second") or 0)
        seconds = float(received.get("seconds") or sent.get("seconds") or 0)
        sent_sender = sent.get("sender")
        received_sender = received.get("sender")
        sent_required = sent_bps > 0 or sent_sender is True or sent_sender is None
        received_required = default_require_received
        if direction == "reverse" and received_bps == 0 and received_sender is True and sent_bps > 0:
            # iperf3 server-side --bidir JSON reports the reverse sender stream
            # without a local receive aggregate. The client JSON still carries the
            # receiver aggregate, so do not reject a sender-only server artifact.
            received_required = False
        rows.append(
            {
                "direction": direction,
                "sent_gbps": sent_bps / 1e9,
                "received_gbps": received_bps / 1e9,
                "seconds": seconds,
                "sent_required": sent_required,
                "received_required": received_required,
            }
        )

    append_pair("forward", "sum_sent", "sum_received", default_require_received=True)
    append_pair(
        "reverse",
        "sum_sent_bidir_reverse",
        "sum_received_bidir_reverse",
        default_require_received=True,
    )
    return rows


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


def stable_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def collect_status_build_identities(case_dir: Path) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    for path in sorted(case_dir.rglob("status.json")):
        try:
            payload = read_json(path)
        except Exception:
            continue
        build = payload.get("build")
        if not isinstance(build, dict):
            continue
        identity = {
            "source": str(path.relative_to(case_dir)),
            "version": str(build.get("version") or ""),
            "commit": str(build.get("commit") or ""),
            "built_at": str(build.get("built_at") or ""),
            "go_version": str(build.get("go_version") or ""),
            "goos": str(build.get("goos") or ""),
            "goarch": str(build.get("goarch") or ""),
            "assets_sha256": stable_digest(build.get("assets") or {}),
        }
        identity["strong"] = all(
            identity.get(field) not in {"", "unknown"}
            for field in ("commit", "built_at")
        )
        identities.append(identity)
    return identities


def collect_binary_identities(case_dir: Path) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    for path in sorted(case_dir.rglob("binary-identity.json")):
        try:
            payload = read_json(path)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        sha256 = str(payload.get("sha256") or payload.get("trustixd_sha256") or "")
        if not sha256:
            continue
        identities.append(
            {
                "source": str(path.relative_to(case_dir)),
                "sha256": sha256,
                "path": str(payload.get("path") or ""),
                "version": payload.get("version"),
            }
        )
    return identities


def identity_key(identity: dict[str, Any], fields: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(identity.get(field) or "") for field in fields)


def parse_required_datapath_stats(raw_items: list[str]) -> list[tuple[str, str]]:
    required: list[tuple[str, str]] = []
    for raw in raw_items:
        path, sep, value = raw.partition("=")
        path = path.strip()
        value = value.strip()
        if not sep or not path:
            raise SystemExit(f"invalid --require-datapath-stat {raw!r}; expected PATH=VALUE")
        required.append((path, value))
    return required


def datapath_value(payload: Any, dotted_path: str) -> Any:
    current = payload
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        raise KeyError(dotted_path)
    return current


def datapath_value_matches(actual: Any, expected: str) -> bool:
    expected_lower = expected.lower()
    if isinstance(actual, bool):
        return expected_lower in {"1", "true", "yes", "on"} if actual else expected_lower in {
            "0",
            "false",
            "no",
            "off",
        }
    if isinstance(actual, (int, float)):
        try:
            return float(actual) == float(expected)
        except ValueError:
            return str(actual) == expected
    return str(actual) == expected


def validate_datapath_stats(
    case_dir: Path,
    *,
    required: list[tuple[str, str]],
    min_datapath_json: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    datapath_files = sorted(case_dir.rglob("datapath.json"))
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    if len(datapath_files) < min_datapath_json:
        errors.append(
            f"found {len(datapath_files)} datapath.json files, want >= {min_datapath_json}"
        )
    if required and not datapath_files:
        return rows, errors, len(datapath_files)
    for path in datapath_files:
        rel = str(path.relative_to(case_dir))
        try:
            payload = read_json(path)
        except Exception as exc:  # noqa: BLE001 - artifact validation should report and continue.
            errors.append(f"{rel}: parse datapath JSON: {exc}")
            continue
        values: dict[str, Any] = {}
        for dotted_path, expected in required:
            try:
                actual = datapath_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing datapath stat {dotted_path!r}")
                continue
            values[dotted_path] = actual
            if not datapath_value_matches(actual, expected):
                errors.append(
                    f"{rel}: datapath stat {dotted_path}={actual!r}, want {expected!r}"
                )
        if values:
            rows.append({"file": rel, "values": values})
    return rows, errors, len(datapath_files)


def validate_case(
    case: CaseSpec,
    *,
    min_gbps: float,
    min_seconds: float,
    seconds_slop: float,
    min_iperf_json: int,
    require_result_marker: bool,
    log_scan: bool,
    require_build_identity: bool,
    require_strong_build_identity: bool,
    require_binary_identity: bool,
    required_datapath_stats: list[tuple[str, str]],
    min_datapath_json: int,
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

    iperf_results: list[dict[str, Any]] = []
    for path in iperf_files:
        try:
            sums = iperf_sums(path)
        except Exception as exc:  # noqa: BLE001 - artifact validation should report and continue.
            errors.append(f"{path.relative_to(case.path)}: parse iperf JSON: {exc}")
            continue
        if not sums:
            errors.append(f"{path.relative_to(case.path)}: no iperf summary aggregates found")
            continue
        rel = str(path.relative_to(case.path))
        for item in sums:
            direction = str(item["direction"])
            sent_gbps = float(item["sent_gbps"])
            received_gbps = float(item["received_gbps"])
            seconds = float(item["seconds"])
            sent_required = bool(item["sent_required"])
            received_required = bool(item["received_required"])
            iperf_results.append(
                {
                    "file": rel,
                    "direction": direction,
                    "sent_gbps": round(sent_gbps, 6),
                    "received_gbps": round(received_gbps, 6),
                    "seconds": round(seconds, 6),
                    "sent_required": sent_required,
                    "received_required": received_required,
                }
            )
            label = rel if direction == "forward" else f"{rel}:{direction}"
            if sent_required and sent_gbps < min_gbps:
                errors.append(f"{label}: sent {sent_gbps:.3f}Gbps < {min_gbps:.3f}Gbps")
            if received_required and received_gbps < min_gbps:
                errors.append(f"{label}: received {received_gbps:.3f}Gbps < {min_gbps:.3f}Gbps")
            if seconds + seconds_slop < min_seconds:
                errors.append(
                    f"{label}: seconds {seconds:.3f} + slop {seconds_slop:.3f} < {min_seconds:.3f}"
                )
    if len(iperf_files) < min_iperf_json and len(iperf_results) < min_iperf_json:
        errors.append(
            f"found {len(iperf_files)} iperf JSON files / {len(iperf_results)} validated "
            f"directions, want >= {min_iperf_json}"
        )

    log_findings = scan_logs(case.path) if log_scan else []
    if log_findings:
        errors.extend(f"log crash signature: {finding}" for finding in log_findings)

    build_identities = collect_status_build_identities(case.path)
    build_identity_fields = (
        "version",
        "commit",
        "built_at",
        "go_version",
        "goos",
        "goarch",
        "assets_sha256",
    )
    build_identity_keys = {identity_key(item, build_identity_fields) for item in build_identities}
    if require_build_identity and len(build_identities) < 2:
        errors.append(
            f"found {len(build_identities)} collected status build identities, want >= 2"
        )
    if len(build_identity_keys) > 1:
        errors.append("collected status build identity mismatch across hosts")
    if require_strong_build_identity:
        if len(build_identities) < 2:
            errors.append(
                f"found {len(build_identities)} collected status build identities, want >= 2"
            )
        for item in build_identities:
            if not item.get("strong"):
                errors.append(
                    f"{item['source']}: weak build identity "
                    f"version={item['version']!r} commit={item['commit']!r} "
                    f"built_at={item['built_at']!r}"
                )

    binary_identities = collect_binary_identities(case.path)
    binary_sha256s = {str(item.get("sha256") or "") for item in binary_identities}
    if require_binary_identity and len(binary_identities) < 2:
        errors.append(
            f"found {len(binary_identities)} binary identities, want >= 2"
        )
    if len(binary_sha256s) > 1:
        errors.append("binary identity sha256 mismatch across hosts")

    datapath_stat_results, datapath_stat_errors, datapath_json_count = validate_datapath_stats(
        case.path,
        required=required_datapath_stats,
        min_datapath_json=min_datapath_json,
    )
    errors.extend(datapath_stat_errors)

    min_sent = min(
        (item["sent_gbps"] for item in iperf_results if item.get("sent_required")),
        default=0,
    )
    min_received = min((item["received_gbps"] for item in iperf_results), default=0)
    min_required_received = min(
        (item["received_gbps"] for item in iperf_results if item.get("received_required")),
        default=0,
    )
    min_duration = min((item["seconds"] for item in iperf_results), default=0)
    return {
        "case": case.name,
        "path": str(case.path),
        "status": "fail" if errors else "pass",
        "min_gbps_required": min_gbps,
        "min_seconds_required": min_seconds,
        "seconds_slop": seconds_slop,
        "iperf_json_count": len(iperf_files),
        "iperf_direction_count": len(iperf_results),
        "min_sent_gbps": round(min_sent, 6),
        "min_received_gbps": round(min_received, 6),
        "min_required_received_gbps": round(min_required_received, 6),
        "min_seconds": round(min_duration, 6),
        "result_markers": marker_values,
        "iperf": iperf_results,
        "log_findings": log_findings,
        "build_identities": build_identities,
        "binary_identities": binary_identities,
        "datapath_json_count": datapath_json_count,
        "datapath_stats": datapath_stat_results,
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
    required_datapath_stats = parse_required_datapath_stats(args.require_datapath_stat)
    if args.min_datapath_json < 0:
        raise SystemExit("--min-datapath-json must be non-negative")
    min_datapath_json = args.min_datapath_json
    if required_datapath_stats and min_datapath_json == 0:
        min_datapath_json = 2

    rows = [
        validate_case(
            case,
            min_gbps=args.min_gbps,
            min_seconds=args.min_seconds,
            seconds_slop=args.seconds_slop,
            min_iperf_json=args.min_iperf_json,
            require_result_marker=not args.no_result_marker,
            log_scan=not args.no_log_scan,
            require_build_identity=args.require_build_identity,
            require_strong_build_identity=args.require_strong_build_identity,
            require_binary_identity=args.require_binary_identity,
            required_datapath_stats=required_datapath_stats,
            min_datapath_json=min_datapath_json,
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
