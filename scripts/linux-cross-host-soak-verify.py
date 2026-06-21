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
    r"blocked for more than [0-9]+ seconds|"
    r"tx_queue_len zero|"
    r"Caught tx_queue_len"
    r")"
)

LOG_SUFFIXES = {".log", ".err", ".txt", ".out"}

KERNEL_LOG_COLLECTION_FAILURE_RE = re.compile(
    r"(?i)("
    r"^-- No entries --$|"
    r"^No journal files were found\.?$|"
    r"^(?:.*\b(?:journalctl|dmesg|sh|bash):\s*).*\b(?:command not found|not found|permission denied|operation not permitted)\b|"
    r"^Failed to .*Operation not permitted\b|"
    r"^dmesg:\s+read kernel buffer failed\b|"
    r"^dmesg:\s+cannot read kernel buffer\b|"
    r"^.*\b(?:journalctl|dmesg):\s+(?:unrecognized|invalid) option\b"
    r")"
)


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
        "--min-iperf-intervals",
        type=int,
        default=0,
        help="minimum number of throughput interval samples expected per validated iperf direction",
    )
    parser.add_argument(
        "--min-iperf-interval-gbps-ratio",
        type=float,
        default=0.0,
        help="minimum interval throughput as a ratio of --min-gbps for each validated iperf direction",
    )
    parser.add_argument(
        "--require-iperf-pair-directions",
        action="store_true",
        help="require usable iperf artifacts covering both a-to-b and b-to-a traffic pairs",
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
        "--require-kernel-log-artifacts",
        action="store_true",
        help="require collected kernel/dmesg log artifacts for each case",
    )
    parser.add_argument(
        "--min-kernel-log-artifacts",
        type=int,
        default=2,
        help="minimum collected kernel/dmesg log artifacts when --require-kernel-log-artifacts is set",
    )
    parser.add_argument(
        "--min-kernel-log-nodes",
        type=int,
        default=2,
        help="minimum distinct nodes with usable kernel/dmesg log artifacts when --require-kernel-log-artifacts is set",
    )
    parser.add_argument(
        "--require-uname-artifacts",
        action="store_true",
        help="require collected uname-before/after artifacts for each case",
    )
    parser.add_argument(
        "--min-uname-nodes",
        type=int,
        default=2,
        help="minimum distinct nodes with matching before/after uname artifacts when --require-uname-artifacts is set",
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
        "--require-stable-boot-id",
        action="store_true",
        help="require before/after boot-id artifacts for at least two nodes and verify they did not change",
    )
    parser.add_argument(
        "--require-status-stat",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected status.json to contain PATH with VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-status-min",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected status.json to contain numeric PATH >= VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-status-max",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected status.json to contain numeric PATH <= VALUE; may be repeated",
    )
    parser.add_argument(
        "--min-status-json",
        type=int,
        default=0,
        help="minimum number of status.json files expected; defaults to 2 when status requirements are used",
    )
    parser.add_argument(
        "--require-datapath-stat",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected datapath.json to contain PATH with VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-datapath-min",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected datapath.json to contain numeric PATH >= VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-datapath-any-min",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require at least one collected datapath.json to contain numeric PATH >= VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-datapath-max",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected datapath.json to contain numeric PATH <= VALUE; may be repeated",
    )
    parser.add_argument(
        "--min-datapath-json",
        type=int,
        default=0,
        help="minimum number of datapath.json files expected; defaults to 2 when datapath requirements are used",
    )
    parser.add_argument(
        "--require-module-param-min",
        action="append",
        default=[],
        metavar="MODULE.PARAM=VALUE",
        help="require every collected module-parameters.txt to contain numeric MODULE.PARAM >= VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-module-param-any-min",
        action="append",
        default=[],
        metavar="MODULE.PARAM=VALUE",
        help="require at least one collected module-parameters.txt to contain numeric MODULE.PARAM >= VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-module-param-max",
        action="append",
        default=[],
        metavar="MODULE.PARAM=VALUE",
        help="require every collected module-parameters.txt to contain numeric MODULE.PARAM <= VALUE; may be repeated",
    )
    parser.add_argument(
        "--min-module-parameters",
        type=int,
        default=0,
        help="minimum number of module-parameters.txt files expected; defaults to 2 when module-parameter requirements are used",
    )
    parser.add_argument(
        "--require-transport-policy-min",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected transports.json policy to contain numeric PATH >= VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-transport-policy-stat",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require every collected transports.json policy to contain PATH with VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-transport-sessions-min",
        type=int,
        default=0,
        help="require every collected transports.json to report at least this many sessions",
    )
    parser.add_argument(
        "--min-transports-json",
        type=int,
        default=0,
        help="minimum number of transports.json files expected; defaults to 2 when transport requirements are used",
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

    def interval_stats() -> dict[str, Any]:
        intervals = payload.get("intervals") or []
        values: list[float] = []
        retransmits = 0
        for interval in intervals:
            if not isinstance(interval, dict):
                continue
            summary = interval.get("sum") or {}
            if not isinstance(summary, dict):
                continue
            values.append(float(summary.get("bits_per_second") or 0) / 1e9)
            retransmits += int(summary.get("retransmits") or 0)
        if not values:
            return {
                "intervals": 0,
                "min_gbps": 0.0,
                "max_gbps": 0.0,
                "first_10_avg_gbps": 0.0,
                "last_10_avg_gbps": 0.0,
                "retransmits": retransmits,
            }
        first = values[:10]
        last = values[-10:]
        return {
            "intervals": len(values),
            "min_gbps": min(values),
            "max_gbps": max(values),
            "first_10_avg_gbps": sum(first) / len(first),
            "last_10_avg_gbps": sum(last) / len(last),
            "retransmits": retransmits,
        }

    stats = interval_stats()

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
        sent_required = sent_bps > 0 or sent_sender is True
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
                "intervals": stats["intervals"],
                "interval_min_gbps": stats["min_gbps"],
                "interval_max_gbps": stats["max_gbps"],
                "interval_first_10_avg_gbps": stats["first_10_avg_gbps"],
                "interval_last_10_avg_gbps": stats["last_10_avg_gbps"],
                "retransmits": int(sent.get("retransmits") or stats["retransmits"]),
                "interval_retransmits": stats["retransmits"],
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


def infer_iperf_pair_directions(path: Path, case_dir: Path, sums: list[dict[str, Any]]) -> set[str]:
    rel = path.relative_to(case_dir)
    rel_text = str(rel).replace("\\", "/").lower()
    directions: set[str] = set()
    if "a-to-b" in rel_text or "a2b" in rel_text:
        directions.add("a-to-b")
    if "b-to-a" in rel_text or "b2a" in rel_text:
        directions.add("b-to-a")
    if path.name.lower().startswith("iperf3-server"):
        node_key = transport_node_key(path, case_dir)
        if node_key == "a":
            directions.add("b-to-a")
        elif node_key == "b":
            directions.add("a-to-b")
    sum_directions = {str(item.get("direction") or "") for item in sums}
    if "bidir" in rel_text and {"forward", "reverse"}.issubset(sum_directions):
        directions.update({"a-to-b", "b-to-a"})
    return directions


def iperf_missing_server_results_only(path: Path) -> bool:
    payload = read_json(path)
    error = str(payload.get("error") or "")
    if "unable to receive results" not in error:
        return False
    intervals = payload.get("intervals") or []
    for interval in intervals:
        if not isinstance(interval, dict):
            continue
        summary = interval.get("sum")
        if isinstance(summary, dict) and float(summary.get("bits_per_second") or 0) > 0:
            return True
    return False


def iperf_top_level_error(path: Path) -> str:
    payload = read_json(path)
    return str(payload.get("error") or "")


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


def kernel_log_artifacts(case_dir: Path) -> tuple[list[str], list[str], list[str]]:
    artifacts: list[str] = []
    rejected: list[str] = []
    nodes: set[str] = set()
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() != ".log":
            continue
        name = path.name.lower()
        if "kernel" not in name and "dmesg" not in name:
            continue
        rel = path.relative_to(case_dir)
        try:
            if path.stat().st_size <= 0:
                rejected.append(f"{rel}:empty")
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            rejected.append(f"{rel}:read_error")
            continue
        if not any(line.strip() for line in lines):
            rejected.append(f"{rel}:empty")
            continue
        collection_error = ""
        for lineno, line in enumerate(lines, 1):
            if KERNEL_LOG_COLLECTION_FAILURE_RE.search(line.strip()):
                collection_error = f"{rel}:{lineno}:collection_error:{line[:240]}"
                break
        if collection_error:
            rejected.append(collection_error)
            continue
        artifacts.append(str(rel))
        nodes.add(transport_node_key(path, case_dir))
    return artifacts, rejected, sorted(nodes)


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


def validate_status_stats(
    case_dir: Path,
    *,
    required: list[tuple[str, str]],
    required_minima: list[tuple[str, float]],
    required_maxima: list[tuple[str, float]],
    min_status_json: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    status_files = sorted(case_dir.rglob("status.json"))
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    if len(status_files) < min_status_json:
        errors.append(
            f"found {len(status_files)} status.json files, want >= {min_status_json}"
        )
    if (required or required_minima or required_maxima) and not status_files:
        return rows, errors, len(status_files)
    for path in status_files:
        rel = str(path.relative_to(case_dir))
        try:
            payload = read_json(path)
        except Exception as exc:  # noqa: BLE001 - artifact validation should report and continue.
            errors.append(f"{rel}: parse status JSON: {exc}")
            continue
        values: dict[str, Any] = {}
        for dotted_path, expected in required:
            try:
                actual = datapath_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing status stat {dotted_path!r}")
                continue
            values[dotted_path] = actual
            if not datapath_value_matches(actual, expected):
                errors.append(
                    f"{rel}: status stat {dotted_path}={actual!r}, want {expected!r}"
                )
        for dotted_path, minimum in required_minima:
            try:
                actual = datapath_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing status stat {dotted_path!r}")
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: status stat {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number < minimum:
                errors.append(
                    f"{rel}: status stat {dotted_path}={actual_number:g}, want >= {minimum:g}"
                )
        for dotted_path, maximum in required_maxima:
            try:
                actual = datapath_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing status stat {dotted_path!r}")
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: status stat {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number > maximum:
                errors.append(
                    f"{rel}: status stat {dotted_path}={actual_number:g}, want <= {maximum:g}"
                )
        if values:
            rows.append({"file": rel, "values": values})
    return rows, errors, len(status_files)


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


def collect_boot_ids(case_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pattern = re.compile(r"^boot-id-([A-Za-z0-9_.-]+)[.]txt$")
    for path in sorted(case_dir.rglob("boot-id-*.txt")):
        match = pattern.match(path.name)
        if not match:
            continue
        try:
            value = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            value = ""
        rows.append(
            {
                "source": str(path.relative_to(case_dir)),
                "node": transport_node_key(path, case_dir),
                "phase": match.group(1),
                "boot_id": value,
            }
        )
    return rows


def validate_stable_boot_ids(
    case_dir: Path,
    *,
    required: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    rows = collect_boot_ids(case_dir)
    errors: list[str] = []
    if not required:
        return rows, errors
    by_node: dict[str, dict[str, list[str]]] = {}
    for row in rows:
        node = str(row["node"])
        phase = str(row["phase"])
        boot_id = str(row["boot_id"])
        by_node.setdefault(node, {}).setdefault(phase, []).append(boot_id)
        if not boot_id:
            errors.append(f"{row['source']}: empty boot-id artifact")
    complete_nodes = 0
    for node, phases in sorted(by_node.items()):
        before_values = {value for value in phases.get("before", []) if value}
        after_values = {value for value in phases.get("after", []) if value}
        if before_values and after_values:
            complete_nodes += 1
        if len(before_values) > 1:
            errors.append(f"{node}: multiple before boot IDs: {sorted(before_values)}")
        if len(after_values) > 1:
            errors.append(f"{node}: multiple after boot IDs: {sorted(after_values)}")
        if not before_values:
            errors.append(f"{node}: missing before boot-id artifact")
            continue
        if not after_values:
            errors.append(f"{node}: missing after boot-id artifact")
            continue
        if before_values != after_values:
            errors.append(
                f"{node}: boot-id changed before={sorted(before_values)} after={sorted(after_values)}"
            )
    if complete_nodes < 2:
        errors.append(f"found stable boot-id pairs for {complete_nodes} nodes, want >= 2")
    return rows, errors


def uname_kernel_release(value: str) -> str:
    fields = value.split()
    if len(fields) >= 3 and fields[0] == "Linux":
        return fields[2]
    return ""


def collect_uname_artifacts(case_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pattern = re.compile(r"^uname-([A-Za-z0-9_.-]+)[.]txt$")
    for path in sorted(case_dir.rglob("uname-*.txt")):
        match = pattern.match(path.name)
        if not match:
            continue
        try:
            value = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            value = ""
        rows.append(
            {
                "source": str(path.relative_to(case_dir)),
                "node": transport_node_key(path, case_dir),
                "phase": match.group(1),
                "uname": value,
                "kernel_release": uname_kernel_release(value),
            }
        )
    return rows


def validate_uname_artifacts(
    case_dir: Path,
    *,
    required: bool,
    min_nodes: int,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    rows = collect_uname_artifacts(case_dir)
    errors: list[str] = []
    if not required:
        nodes = sorted({str(row["node"]) for row in rows if row.get("kernel_release")})
        return rows, errors, nodes

    by_node: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for row in rows:
        node = str(row["node"])
        phase = str(row["phase"])
        by_node.setdefault(node, {}).setdefault(phase, []).append(row)
        if not str(row.get("uname") or ""):
            errors.append(f"{row['source']}: empty uname artifact")
        elif not row.get("kernel_release"):
            errors.append(f"{row['source']}: invalid Linux uname artifact {row['uname']!r}")

    complete_nodes: set[str] = set()
    for node, phases in sorted(by_node.items()):
        before_releases = {
            str(row.get("kernel_release") or "")
            for row in phases.get("before", [])
            if row.get("kernel_release")
        }
        after_releases = {
            str(row.get("kernel_release") or "")
            for row in phases.get("after", [])
            if row.get("kernel_release")
        }
        if before_releases and after_releases:
            complete_nodes.add(node)
        if len(before_releases) > 1:
            errors.append(f"{node}: multiple before kernel releases: {sorted(before_releases)}")
        if len(after_releases) > 1:
            errors.append(f"{node}: multiple after kernel releases: {sorted(after_releases)}")
        if not before_releases:
            errors.append(f"{node}: missing before uname artifact")
            continue
        if not after_releases:
            errors.append(f"{node}: missing after uname artifact")
            continue
        if before_releases != after_releases:
            errors.append(
                f"{node}: kernel release changed before={sorted(before_releases)} "
                f"after={sorted(after_releases)}"
            )
    if len(complete_nodes) < min_nodes:
        errors.append(
            f"found matching before/after uname artifacts for {len(complete_nodes)} nodes, "
            f"want >= {min_nodes}"
        )
    return rows, errors, sorted(complete_nodes)


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


def parse_required_numeric_limits(raw_items: list[str], flag: str) -> list[tuple[str, float]]:
    required: list[tuple[str, float]] = []
    for raw in raw_items:
        path, sep, value = raw.partition("=")
        path = path.strip()
        value = value.strip()
        if not sep or not path:
            raise SystemExit(f"invalid {flag} {raw!r}; expected PATH=VALUE")
        try:
            minimum = float(value)
        except ValueError as exc:
            raise SystemExit(f"invalid {flag} {raw!r}; VALUE must be numeric") from exc
        required.append((path, minimum))
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


def numeric_value(actual: Any) -> float:
    if isinstance(actual, bool):
        return 1.0 if actual else 0.0
    if isinstance(actual, (int, float)):
        return float(actual)
    text = str(actual).strip()
    truthy = {"y", "yes", "true", "on", "enabled"}
    falsey = {"n", "no", "false", "off", "disabled"}
    lower = text.lower()
    if lower in truthy:
        return 1.0
    if lower in falsey or text == "":
        return 0.0
    return float(text)


def validate_datapath_stats(
    case_dir: Path,
    *,
    required: list[tuple[str, str]],
    required_minima: list[tuple[str, float]],
    required_any_minima: list[tuple[str, float]],
    required_maxima: list[tuple[str, float]],
    min_datapath_json: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    datapath_files = sorted(case_dir.rglob("datapath.json"))
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    any_hits = {dotted_path: False for dotted_path, _ in required_any_minima}
    if len(datapath_files) < min_datapath_json:
        errors.append(
            f"found {len(datapath_files)} datapath.json files, want >= {min_datapath_json}"
        )
    if (required or required_minima or required_any_minima or required_maxima) and not datapath_files:
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
        for dotted_path, minimum in required_minima:
            try:
                actual = datapath_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing datapath stat {dotted_path!r}")
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: datapath stat {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number < minimum:
                errors.append(
                    f"{rel}: datapath stat {dotted_path}={actual_number:g}, want >= {minimum:g}"
                )
        for dotted_path, minimum in required_any_minima:
            try:
                actual = datapath_value(payload, dotted_path)
            except KeyError:
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: datapath stat {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number >= minimum:
                any_hits[dotted_path] = True
        for dotted_path, maximum in required_maxima:
            try:
                actual = datapath_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing datapath stat {dotted_path!r}")
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: datapath stat {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number > maximum:
                errors.append(
                    f"{rel}: datapath stat {dotted_path}={actual_number:g}, want <= {maximum:g}"
                )
        if values:
            rows.append({"file": rel, "values": values})
    for dotted_path, minimum in required_any_minima:
        if not any_hits.get(dotted_path, False):
            errors.append(
                f"no collected datapath stat {dotted_path!r} reached >= {minimum:g}"
            )
    return rows, errors, len(datapath_files)


def parse_module_parameters(path: Path) -> dict[str, dict[str, str]]:
    modules: dict[str, dict[str, str]] = {}
    current = ""
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("=====") and line.endswith("====="):
            current = line.strip("= ").strip()
            modules.setdefault(current, {})
            continue
        if not current or "=" not in line:
            continue
        name, value = line.split("=", 1)
        modules.setdefault(current, {})[name.strip()] = value.strip()
    return modules


def module_parameter_value(modules: dict[str, dict[str, str]], dotted_path: str) -> str:
    module, sep, param = dotted_path.partition(".")
    if not sep or not module or not param:
        raise KeyError(dotted_path)
    return modules[module][param]


def validate_module_parameters(
    case_dir: Path,
    *,
    required_minima: list[tuple[str, float]],
    required_any_minima: list[tuple[str, float]],
    required_maxima: list[tuple[str, float]],
    min_module_parameters: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    files = sorted(case_dir.rglob("module-parameters.txt"))
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    any_hits: dict[str, bool] = {
        dotted_path: False for dotted_path, _ in required_any_minima
    }
    if len(files) < min_module_parameters:
        errors.append(
            f"found {len(files)} module-parameters.txt files, want >= {min_module_parameters}"
        )
    if (required_minima or required_any_minima or required_maxima) and not files:
        return rows, errors, len(files)
    for path in files:
        rel = str(path.relative_to(case_dir))
        try:
            modules = parse_module_parameters(path)
        except OSError as exc:
            errors.append(f"{rel}: read module parameters: {exc}")
            continue
        values: dict[str, Any] = {}
        for dotted_path, minimum in required_minima:
            try:
                actual = module_parameter_value(modules, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing module parameter {dotted_path!r}")
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: module parameter {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number < minimum:
                errors.append(
                    f"{rel}: module parameter {dotted_path}={actual_number:g}, want >= {minimum:g}"
                )
        for dotted_path, minimum in required_any_minima:
            try:
                actual = module_parameter_value(modules, dotted_path)
            except KeyError:
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: module parameter {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number >= minimum:
                any_hits[dotted_path] = True
        for dotted_path, maximum in required_maxima:
            try:
                actual = module_parameter_value(modules, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing module parameter {dotted_path!r}")
                continue
            values[dotted_path] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(f"{rel}: module parameter {dotted_path}={actual!r} is not numeric")
                continue
            if actual_number > maximum:
                errors.append(
                    f"{rel}: module parameter {dotted_path}={actual_number:g}, want <= {maximum:g}"
                )
        if values:
            rows.append({"file": rel, "values": values})
    for dotted_path, minimum in required_any_minima:
        if not any_hits.get(dotted_path, False):
            errors.append(
                f"no collected module parameter {dotted_path!r} reached >= {minimum:g}"
            )
    return rows, errors, len(files)


def collect_transports_json(case_dir: Path) -> list[tuple[Path, Any]]:
    payloads: list[tuple[Path, Any]] = []
    for path in sorted(case_dir.rglob("transports*.json")):
        try:
            payloads.append((path, read_json(path)))
        except Exception:
            payloads.append((path, None))
    return payloads


def transport_policy_value(payload: Any, dotted_path: str) -> Any:
    policy = datapath_value(payload, "policy")
    return datapath_value(policy, dotted_path)


def transport_node_key(path: Path, case_dir: Path) -> str:
    parts = path.relative_to(case_dir).parts
    for part in parts[:-1]:
        if part in {"a", "b"}:
            return part
    return "__all__"


def validate_transports(
    case_dir: Path,
    *,
    required_policy_stats: list[tuple[str, str]],
    required_policy_minima: list[tuple[str, float]],
    required_sessions_min: int,
    min_transports_json: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    payloads = collect_transports_json(case_dir)
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    session_counts_by_node: dict[str, list[tuple[str, int]]] = {}
    if len(payloads) < min_transports_json:
        errors.append(
            f"found {len(payloads)} transports.json files, want >= {min_transports_json}"
        )
    if (
        required_policy_stats
        or required_policy_minima
        or required_sessions_min > 0
    ) and not payloads:
        return rows, errors, len(payloads)
    for path, payload in payloads:
        rel = str(path.relative_to(case_dir))
        if payload is None:
            errors.append(f"{rel}: parse transports JSON failed")
            continue
        values: dict[str, Any] = {}
        for dotted_path, expected in required_policy_stats:
            try:
                actual = transport_policy_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing transport policy stat {dotted_path!r}")
                continue
            values[f"policy.{dotted_path}"] = actual
            if not datapath_value_matches(actual, expected):
                errors.append(
                    f"{rel}: transport policy {dotted_path}={actual!r}, want {expected!r}"
                )
        for dotted_path, minimum in required_policy_minima:
            try:
                actual = transport_policy_value(payload, dotted_path)
            except KeyError:
                errors.append(f"{rel}: missing transport policy stat {dotted_path!r}")
                continue
            values[f"policy.{dotted_path}"] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(
                    f"{rel}: transport policy {dotted_path}={actual!r} is not numeric"
                )
                continue
            if actual_number < minimum:
                errors.append(
                    f"{rel}: transport policy {dotted_path}={actual_number:g}, want >= {minimum:g}"
                )
        if required_sessions_min > 0:
            sessions = payload.get("sessions") if isinstance(payload, dict) else None
            count = len(sessions) if isinstance(sessions, list) else 0
            values["sessions"] = count
            node_key = transport_node_key(path, case_dir)
            session_counts_by_node.setdefault(node_key, []).append((rel, count))
        if values:
            rows.append({"file": rel, "values": values})
    if required_sessions_min > 0:
        for node_key, counts in sorted(session_counts_by_node.items()):
            if not counts:
                continue
            best_rel, best_count = max(counts, key=lambda item: item[1])
            if best_count < required_sessions_min:
                errors.append(
                    f"{best_rel}: transport sessions={best_count}, want >= {required_sessions_min}"
                )
    return rows, errors, len(payloads)


def validate_case(
    case: CaseSpec,
    *,
    min_gbps: float,
    min_seconds: float,
    seconds_slop: float,
    min_iperf_json: int,
    min_iperf_intervals: int,
    min_iperf_interval_gbps_ratio: float,
    require_iperf_pair_directions: bool,
    require_result_marker: bool,
    log_scan: bool,
    require_kernel_log_artifacts: bool,
    min_kernel_log_artifacts: int,
    min_kernel_log_nodes: int,
    require_uname_artifacts: bool,
    min_uname_nodes: int,
    require_build_identity: bool,
    require_strong_build_identity: bool,
    require_binary_identity: bool,
    require_stable_boot_id: bool,
    required_status_stats: list[tuple[str, str]],
    required_status_minima: list[tuple[str, float]],
    required_status_maxima: list[tuple[str, float]],
    min_status_json: int,
    required_datapath_stats: list[tuple[str, str]],
    required_datapath_minima: list[tuple[str, float]],
    required_datapath_any_minima: list[tuple[str, float]],
    required_datapath_maxima: list[tuple[str, float]],
    min_datapath_json: int,
    required_module_param_minima: list[tuple[str, float]],
    required_module_param_any_minima: list[tuple[str, float]],
    required_module_param_maxima: list[tuple[str, float]],
    min_module_parameters: int,
    required_transport_policy_stats: list[tuple[str, str]],
    required_transport_policy_minima: list[tuple[str, float]],
    required_transport_sessions_min: int,
    min_transports_json: int,
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

    iperf_files = sorted(
        path
        for path in case.path.rglob("*iperf*.json")
        if not path.name.startswith("transports")
    )

    iperf_results: list[dict[str, Any]] = []
    skipped_iperf_files: list[str] = []
    iperf_pair_directions: set[str] = set()
    for path in iperf_files:
        rel = str(path.relative_to(case.path))
        try:
            sums = iperf_sums(path)
        except Exception as exc:  # noqa: BLE001 - artifact validation should report and continue.
            errors.append(f"{rel}: parse iperf JSON: {exc}")
            continue
        if not sums:
            try:
                if iperf_missing_server_results_only(path):
                    skipped_iperf_files.append(rel)
                    continue
            except Exception as exc:  # noqa: BLE001 - report the original missing-summary error.
                errors.append(
                    f"{rel}: parse iperf JSON for benign error check: {exc}"
                )
            errors.append(f"{rel}: no iperf summary aggregates found")
            continue
        try:
            iperf_error = iperf_top_level_error(path)
        except Exception as exc:  # noqa: BLE001 - artifact validation should report and continue.
            errors.append(f"{rel}: parse iperf JSON for top-level error check: {exc}")
            continue
        if iperf_error:
            errors.append(f"{rel}: iperf JSON contains error: {iperf_error[:200]}")
            continue
        iperf_pair_directions.update(infer_iperf_pair_directions(path, case.path, sums))
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
                    "intervals": int(item.get("intervals") or 0),
                    "interval_min_gbps": round(float(item.get("interval_min_gbps") or 0), 6),
                    "interval_max_gbps": round(float(item.get("interval_max_gbps") or 0), 6),
                    "interval_first_10_avg_gbps": round(
                        float(item.get("interval_first_10_avg_gbps") or 0), 6
                    ),
                    "interval_last_10_avg_gbps": round(
                        float(item.get("interval_last_10_avg_gbps") or 0), 6
                    ),
                    "retransmits": int(item.get("retransmits") or 0),
                    "interval_retransmits": int(item.get("interval_retransmits") or 0),
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
            intervals = int(item.get("intervals") or 0)
            interval_min_gbps = float(item.get("interval_min_gbps") or 0)
            if min_iperf_intervals > 0 and intervals < min_iperf_intervals:
                errors.append(
                    f"{label}: interval count {intervals}, want >= {min_iperf_intervals}"
                )
            interval_floor = min_gbps * min_iperf_interval_gbps_ratio
            if min_iperf_interval_gbps_ratio > 0 and interval_min_gbps < interval_floor:
                errors.append(
                    f"{label}: interval min {interval_min_gbps:.3f}Gbps < "
                    f"{interval_floor:.3f}Gbps"
                )
    if len(iperf_files) < min_iperf_json and len(iperf_results) < min_iperf_json:
        errors.append(
            f"found {len(iperf_files)} iperf JSON files / {len(iperf_results)} validated "
            f"directions, want >= {min_iperf_json}"
        )
    if require_iperf_pair_directions:
        required_pairs = {"a-to-b", "b-to-a"}
        missing_pairs = sorted(required_pairs - iperf_pair_directions)
        if missing_pairs:
            errors.append(
                "missing iperf traffic pair directions: "
                f"{','.join(missing_pairs)}; found {','.join(sorted(iperf_pair_directions)) or 'none'}"
            )

    log_findings = scan_logs(case.path) if log_scan else []
    if log_findings:
        errors.extend(f"log crash signature: {finding}" for finding in log_findings)
    collected_kernel_logs, rejected_kernel_logs, kernel_log_nodes = kernel_log_artifacts(case.path)
    if require_kernel_log_artifacts:
        errors.extend(
            f"kernel/dmesg log artifact unusable: {finding}"
            for finding in rejected_kernel_logs
        )
    if require_kernel_log_artifacts and len(collected_kernel_logs) < min_kernel_log_artifacts:
        errors.append(
            f"found {len(collected_kernel_logs)} kernel/dmesg log artifacts, "
            f"want >= {min_kernel_log_artifacts}"
        )
    if require_kernel_log_artifacts and len(kernel_log_nodes) < min_kernel_log_nodes:
        errors.append(
            f"found usable kernel/dmesg log artifacts for {len(kernel_log_nodes)} nodes, "
            f"want >= {min_kernel_log_nodes}"
        )

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

    boot_ids, boot_id_errors = validate_stable_boot_ids(
        case.path,
        required=require_stable_boot_id,
    )
    errors.extend(boot_id_errors)
    uname_artifacts, uname_errors, uname_nodes = validate_uname_artifacts(
        case.path,
        required=require_uname_artifacts,
        min_nodes=min_uname_nodes,
    )
    errors.extend(uname_errors)

    status_stat_results, status_stat_errors, status_json_count = validate_status_stats(
        case.path,
        required=required_status_stats,
        required_minima=required_status_minima,
        required_maxima=required_status_maxima,
        min_status_json=min_status_json,
    )
    errors.extend(status_stat_errors)
    datapath_stat_results, datapath_stat_errors, datapath_json_count = validate_datapath_stats(
        case.path,
        required=required_datapath_stats,
        required_minima=required_datapath_minima,
        required_any_minima=required_datapath_any_minima,
        required_maxima=required_datapath_maxima,
        min_datapath_json=min_datapath_json,
    )
    errors.extend(datapath_stat_errors)
    module_param_results, module_param_errors, module_param_count = validate_module_parameters(
        case.path,
        required_minima=required_module_param_minima,
        required_any_minima=required_module_param_any_minima,
        required_maxima=required_module_param_maxima,
        min_module_parameters=min_module_parameters,
    )
    errors.extend(module_param_errors)
    transport_results, transport_errors, transports_json_count = validate_transports(
        case.path,
        required_policy_stats=required_transport_policy_stats,
        required_policy_minima=required_transport_policy_minima,
        required_sessions_min=required_transport_sessions_min,
        min_transports_json=min_transports_json,
    )
    errors.extend(transport_errors)

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
        "min_iperf_intervals_required": min_iperf_intervals,
        "min_iperf_interval_gbps_ratio_required": min_iperf_interval_gbps_ratio,
        "iperf_json_count": len(iperf_files),
        "iperf_direction_count": len(iperf_results),
        "iperf_pair_directions": sorted(iperf_pair_directions),
        "iperf_skipped_missing_server_results": skipped_iperf_files,
        "min_sent_gbps": round(min_sent, 6),
        "min_received_gbps": round(min_received, 6),
        "min_required_received_gbps": round(min_required_received, 6),
        "min_seconds": round(min_duration, 6),
        "result_markers": marker_values,
        "iperf": iperf_results,
        "log_findings": log_findings,
        "kernel_log_artifacts": collected_kernel_logs,
        "kernel_log_rejected_artifacts": rejected_kernel_logs,
        "kernel_log_nodes": kernel_log_nodes,
        "build_identities": build_identities,
        "binary_identities": binary_identities,
        "boot_ids": boot_ids,
        "uname_artifacts": uname_artifacts,
        "uname_nodes": uname_nodes,
        "status_json_count": status_json_count,
        "status_stats": status_stat_results,
        "datapath_json_count": datapath_json_count,
        "datapath_stats": datapath_stat_results,
        "module_parameters_count": module_param_count,
        "module_parameters": module_param_results,
        "transports_json_count": transports_json_count,
        "transports": transport_results,
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
    if args.min_iperf_intervals < 0:
        raise SystemExit("--min-iperf-intervals must be non-negative")
    if args.min_iperf_interval_gbps_ratio < 0:
        raise SystemExit("--min-iperf-interval-gbps-ratio must be non-negative")
    if args.min_kernel_log_artifacts < 0:
        raise SystemExit("--min-kernel-log-artifacts must be non-negative")
    if args.min_kernel_log_nodes < 0:
        raise SystemExit("--min-kernel-log-nodes must be non-negative")
    if args.min_uname_nodes < 0:
        raise SystemExit("--min-uname-nodes must be non-negative")
    required_status_stats = parse_required_datapath_stats(args.require_status_stat)
    required_status_minima = parse_required_numeric_limits(
        args.require_status_min,
        "--require-status-min",
    )
    required_status_maxima = parse_required_numeric_limits(
        args.require_status_max,
        "--require-status-max",
    )
    required_datapath_stats = parse_required_datapath_stats(args.require_datapath_stat)
    required_datapath_minima = parse_required_numeric_limits(
        args.require_datapath_min,
        "--require-datapath-min",
    )
    required_datapath_any_minima = parse_required_numeric_limits(
        args.require_datapath_any_min,
        "--require-datapath-any-min",
    )
    required_datapath_maxima = parse_required_numeric_limits(
        args.require_datapath_max,
        "--require-datapath-max",
    )
    required_module_param_minima = parse_required_numeric_limits(
        args.require_module_param_min,
        "--require-module-param-min",
    )
    required_module_param_any_minima = parse_required_numeric_limits(
        args.require_module_param_any_min,
        "--require-module-param-any-min",
    )
    required_module_param_maxima = parse_required_numeric_limits(
        args.require_module_param_max,
        "--require-module-param-max",
    )
    required_transport_policy_stats = parse_required_datapath_stats(
        args.require_transport_policy_stat
    )
    required_transport_policy_minima = parse_required_numeric_limits(
        args.require_transport_policy_min,
        "--require-transport-policy-min",
    )
    if args.min_status_json < 0:
        raise SystemExit("--min-status-json must be non-negative")
    if args.min_datapath_json < 0:
        raise SystemExit("--min-datapath-json must be non-negative")
    if args.min_module_parameters < 0:
        raise SystemExit("--min-module-parameters must be non-negative")
    if args.min_transports_json < 0:
        raise SystemExit("--min-transports-json must be non-negative")
    if args.require_transport_sessions_min < 0:
        raise SystemExit("--require-transport-sessions-min must be non-negative")
    min_status_json = args.min_status_json
    if (
        required_status_stats
        or required_status_minima
        or required_status_maxima
    ) and min_status_json == 0:
        min_status_json = 2
    min_datapath_json = args.min_datapath_json
    if (
        required_datapath_stats
        or required_datapath_minima
        or required_datapath_any_minima
        or required_datapath_maxima
    ) and min_datapath_json == 0:
        min_datapath_json = 2
    min_module_parameters = args.min_module_parameters
    if (
        required_module_param_minima
        or required_module_param_any_minima
        or required_module_param_maxima
    ) and min_module_parameters == 0:
        min_module_parameters = 2
    min_transports_json = args.min_transports_json
    if (
        required_transport_policy_stats
        or required_transport_policy_minima
        or args.require_transport_sessions_min > 0
    ) and min_transports_json == 0:
        min_transports_json = 2

    rows = [
        validate_case(
            case,
            min_gbps=args.min_gbps,
            min_seconds=args.min_seconds,
            seconds_slop=args.seconds_slop,
            min_iperf_json=args.min_iperf_json,
            min_iperf_intervals=args.min_iperf_intervals,
            min_iperf_interval_gbps_ratio=args.min_iperf_interval_gbps_ratio,
            require_iperf_pair_directions=args.require_iperf_pair_directions,
            require_result_marker=not args.no_result_marker,
            log_scan=not args.no_log_scan,
            require_kernel_log_artifacts=args.require_kernel_log_artifacts,
            min_kernel_log_artifacts=args.min_kernel_log_artifacts,
            min_kernel_log_nodes=args.min_kernel_log_nodes,
            require_uname_artifacts=args.require_uname_artifacts,
            min_uname_nodes=args.min_uname_nodes,
            require_build_identity=args.require_build_identity,
            require_strong_build_identity=args.require_strong_build_identity,
            require_binary_identity=args.require_binary_identity,
            require_stable_boot_id=args.require_stable_boot_id,
            required_status_stats=required_status_stats,
            required_status_minima=required_status_minima,
            required_status_maxima=required_status_maxima,
            min_status_json=min_status_json,
            required_datapath_stats=required_datapath_stats,
            required_datapath_minima=required_datapath_minima,
            required_datapath_any_minima=required_datapath_any_minima,
            required_datapath_maxima=required_datapath_maxima,
            min_datapath_json=min_datapath_json,
            required_module_param_minima=required_module_param_minima,
            required_module_param_any_minima=required_module_param_any_minima,
            required_module_param_maxima=required_module_param_maxima,
            min_module_parameters=min_module_parameters,
            required_transport_policy_stats=required_transport_policy_stats,
            required_transport_policy_minima=required_transport_policy_minima,
            required_transport_sessions_min=args.require_transport_sessions_min,
            min_transports_json=min_transports_json,
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
