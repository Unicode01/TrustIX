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
    r"unregister_netdevice: waiting for .* to become free|"
    r"tx_queue_len zero|"
    r"Caught tx_queue_len"
    r")"
)

LOG_SUFFIXES = {".log", ".err", ".txt", ".out"}

KERNEL_LOG_COLLECTION_FAILURE_RE = re.compile(
    r"(?i)("
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
        "--require-run-timing",
        action="store_true",
        help="require run-timing.json showing the measured long-test wall-clock window",
    )
    parser.add_argument(
        "--require-run-timing-stat",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="require every run-timing.json artifact to contain KEY equal to VALUE; may be repeated",
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
        "--require-pstore-artifacts",
        action="store_true",
        help="require collected pstore inspection artifacts for each case",
    )
    parser.add_argument(
        "--min-pstore-nodes",
        type=int,
        default=2,
        help="minimum distinct nodes with collected pstore artifacts when --require-pstore-artifacts is set",
    )
    parser.add_argument(
        "--require-lsmod-artifacts",
        action="store_true",
        help="require collected lsmod artifacts for each case",
    )
    parser.add_argument(
        "--min-lsmod-nodes",
        type=int,
        default=2,
        help="minimum distinct nodes with collected lsmod artifacts when --require-lsmod-artifacts is set",
    )
    parser.add_argument(
        "--require-lsmod-module",
        action="append",
        default=[],
        metavar="MODULE",
        help="require every collected lsmod artifact to include MODULE; may be repeated",
    )
    parser.add_argument(
        "--forbid-lsmod-module",
        action="append",
        default=[],
        metavar="MODULE",
        help="reject collected lsmod artifacts that include MODULE; may be repeated",
    )
    parser.add_argument(
        "--forbid-lsmod-prefix",
        action="append",
        default=[],
        metavar="PREFIX",
        help="reject collected lsmod artifacts containing modules with PREFIX; may be repeated",
    )
    parser.add_argument(
        "--require-lan-state-artifacts",
        action="store_true",
        help="require collected LAN interface state artifacts for each case",
    )
    parser.add_argument(
        "--min-lan-state-nodes",
        type=int,
        default=2,
        help="minimum distinct nodes with valid LAN state artifacts when --require-lan-state-artifacts is set",
    )
    parser.add_argument(
        "--min-lan-tx-queue-len",
        type=int,
        default=1,
        help="minimum tx_queue_len accepted in LAN state artifacts",
    )
    parser.add_argument(
        "--require-host-state-artifacts",
        action="store_true",
        help="require collected host resource/state artifacts for each case",
    )
    parser.add_argument(
        "--min-host-state-nodes",
        type=int,
        default=2,
        help="minimum distinct nodes with valid host state artifacts when --require-host-state-artifacts is set",
    )
    parser.add_argument(
        "--min-host-cpus",
        type=int,
        default=1,
        help="minimum online CPU count accepted in host state artifacts",
    )
    parser.add_argument(
        "--forbid-host-net-driver",
        action="append",
        default=[],
        metavar="DRIVER",
        help="reject host state artifacts containing network DRIVER; may be repeated",
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
        "--require-os-release-artifacts",
        action="store_true",
        help="require collected os-release-before/after artifacts for each case",
    )
    parser.add_argument(
        "--min-os-release-nodes",
        type=int,
        default=2,
        help="minimum distinct nodes with matching before/after os-release artifacts when --require-os-release-artifacts is set",
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
        "--require-datapath-ratio-max",
        action="append",
        default=[],
        metavar="NUMERATOR_PATH/DENOMINATOR_PATH=VALUE",
        help="require every collected datapath.json to have numeric NUMERATOR_PATH / DENOMINATOR_PATH <= VALUE; may be repeated",
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
        "--require-module-param-node-max",
        action="append",
        default=[],
        metavar="NODE.MODULE.PARAM=VALUE",
        help="require module-parameters.txt for NODE to contain numeric MODULE.PARAM <= VALUE; may be repeated",
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
        "--require-transport-local-endpoint-stat",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require each node to have a local endpoint matching PATH with VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-transport-peer-endpoint-stat",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require each node to have a peer endpoint matching PATH with VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-transport-session-stat",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require each node to have transport sessions matching PATH with VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-transport-session-any-min",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="require each node to have at least one matching transport session with numeric PATH >= VALUE; may be repeated",
    )
    parser.add_argument(
        "--require-transport-session-endpoint-suffix",
        action="append",
        default=[],
        metavar="SUFFIX",
        help="require each node to have transport sessions whose endpoint ends with SUFFIX; may be repeated",
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


def run_timing_artifacts(
    case_dir: Path,
    *,
    required: bool,
    min_seconds: float,
    seconds_slop: float,
    required_stats: list[tuple[str, str]],
) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    errors: list[str] = []
    paths = sorted(case_dir.glob("run-timing*.json"))
    if required and not paths:
        errors.append("missing run-timing.json artifact")
        return artifacts, errors
    for path in paths:
        rel = str(path.relative_to(case_dir))
        try:
            payload = read_json(path)
        except Exception as exc:  # noqa: BLE001 - artifact validation should report and continue.
            errors.append(f"{rel}: parse run timing JSON: {exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{rel}: run timing artifact is not a JSON object")
            continue
        row = {"source": rel, **payload}
        artifacts.append(row)
        if not required:
            continue
        for key, want in required_stats:
            got = payload.get(key)
            if str(got) != want:
                errors.append(f"{rel}: run timing {key}={got!r}, want {want!r}")
        try:
            start_epoch = numeric_value(payload.get("start_epoch"))
            end_epoch = numeric_value(payload.get("end_epoch"))
            elapsed = numeric_value(payload.get("elapsed_seconds"))
            requested = numeric_value(payload.get("iperf_seconds_requested"))
        except (TypeError, ValueError) as exc:
            errors.append(f"{rel}: invalid run timing numeric field: {exc}")
            continue
        if end_epoch < start_epoch:
            errors.append(f"{rel}: end_epoch {end_epoch:g} < start_epoch {start_epoch:g}")
        computed_elapsed = end_epoch - start_epoch
        if abs(computed_elapsed - elapsed) > max(2.0, seconds_slop):
            errors.append(
                f"{rel}: elapsed_seconds {elapsed:g} does not match end-start "
                f"{computed_elapsed:g}"
            )
        if elapsed + seconds_slop < min_seconds:
            errors.append(
                f"{rel}: elapsed_seconds {elapsed:.3f} + slop {seconds_slop:.3f} "
                f"< {min_seconds:.3f}"
            )
        if requested + seconds_slop < min_seconds:
            errors.append(
                f"{rel}: iperf_seconds_requested {requested:.3f} + slop "
                f"{seconds_slop:.3f} < {min_seconds:.3f}"
            )
    return artifacts, errors


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


def pstore_artifacts(case_dir: Path) -> tuple[list[str], list[str], list[str]]:
    artifacts: list[str] = []
    rejected: list[str] = []
    nodes: set[str] = set()
    for path in sorted(case_dir.rglob("*pstore*.txt")):
        if not path.is_file():
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


def collect_lsmod_artifacts(case_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    rejected: list[str] = []
    for path in sorted(case_dir.rglob("*lsmod.txt")):
        if not path.is_file():
            continue
        rel = path.relative_to(case_dir)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            rejected.append(f"{rel}:read_error")
            continue
        modules: list[str] = []
        collection_error = ""
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            if KERNEL_LOG_COLLECTION_FAILURE_RE.search(stripped):
                collection_error = f"{rel}:{lineno}:collection_error:{line[:240]}"
                break
            modules.append(stripped.split()[0])
        if collection_error:
            rejected.append(collection_error)
            continue
        rows.append(
            {
                "source": str(rel),
                "node": transport_node_key(path, case_dir),
                "modules": modules,
            }
        )
    return rows, rejected


def validate_lsmod_artifacts(
    case_dir: Path,
    *,
    required: bool,
    min_nodes: int,
    required_modules: list[str],
    forbidden_modules: list[str],
    forbidden_prefixes: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    rows, rejected = collect_lsmod_artifacts(case_dir)
    errors: list[str] = []
    nodes = sorted({str(row["node"]) for row in rows})
    if required:
        errors.extend(f"lsmod artifact unusable: {finding}" for finding in rejected)
    if required and len(nodes) < min_nodes:
        errors.append(f"found lsmod artifacts for {len(nodes)} nodes, want >= {min_nodes}")

    for row in rows:
        modules = {str(module) for module in row.get("modules", [])}
        source = str(row["source"])
        for module in required_modules:
            if module not in modules:
                errors.append(f"{source}: missing loaded module {module!r}")
        for module in forbidden_modules:
            if module in modules:
                errors.append(f"{source}: forbidden loaded module {module!r}")
        for prefix in forbidden_prefixes:
            blocked = sorted(module for module in modules if module.startswith(prefix))
            if blocked:
                errors.append(f"{source}: forbidden loaded modules with prefix {prefix!r}: {blocked}")
    if (required_modules or forbidden_modules or forbidden_prefixes) and not rows:
        errors.append("missing lsmod artifacts for module state validation")
    return rows, errors, nodes


def parse_key_value_lines(value: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in value.splitlines():
        line = raw.strip()
        if not line or line.startswith("=====") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if key:
            parsed[key] = val.strip()
    return parsed


def collect_lan_state_artifacts(case_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(case_dir.rglob("*lan-state.txt")):
        if not path.is_file():
            continue
        rel = path.relative_to(case_dir)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        parsed = parse_key_value_lines(text)
        tx_queue_raw = parsed.get("tx_queue_len", "")
        tx_queue_len: int | None = None
        if re.fullmatch(r"[0-9]+", tx_queue_raw):
            tx_queue_len = int(tx_queue_raw)
        rows.append(
            {
                "source": str(rel),
                "node": transport_node_key(path, case_dir),
                "interface": parsed.get("interface", ""),
                "tx_queue_len": tx_queue_len,
                "tx_queue_len_raw": tx_queue_raw,
            }
        )
    return rows


def validate_lan_state_artifacts(
    case_dir: Path,
    *,
    required: bool,
    min_nodes: int,
    min_tx_queue_len: int,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    rows = collect_lan_state_artifacts(case_dir)
    errors: list[str] = []
    valid_nodes: set[str] = set()
    for row in rows:
        source = str(row["source"])
        interface = str(row.get("interface") or "")
        tx_queue_len = row.get("tx_queue_len")
        if not interface:
            errors.append(f"{source}: missing LAN interface name")
        if not isinstance(tx_queue_len, int):
            errors.append(
                f"{source}: invalid LAN tx_queue_len {row.get('tx_queue_len_raw')!r}"
            )
            continue
        if tx_queue_len < min_tx_queue_len:
            errors.append(
                f"{source}: LAN tx_queue_len={tx_queue_len}, want >= {min_tx_queue_len}"
            )
            continue
        valid_nodes.add(str(row["node"]))
    if required and len(valid_nodes) < min_nodes:
        errors.append(
            f"found valid LAN state artifacts for {len(valid_nodes)} nodes, "
            f"want >= {min_nodes}"
        )
    return rows, errors, sorted(valid_nodes)


def collect_host_state_artifacts(case_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(case_dir.rglob("*host-state.txt")):
        if not path.is_file():
            continue
        rel = path.relative_to(case_dir)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        parsed = parse_key_value_lines(text)
        cpu_count_raw = parsed.get("cpu_count", "")
        cpu_count: int | None = None
        if re.fullmatch(r"[0-9]+", cpu_count_raw):
            cpu_count = int(cpu_count_raw)
        net_drivers: dict[str, str] = {}
        for key, value in parsed.items():
            match = re.fullmatch(r"net_driver\[([^\]]+)\]", key)
            if match:
                net_drivers[match.group(1)] = value
        rows.append(
            {
                "source": str(rel),
                "node": transport_node_key(path, case_dir),
                "cpu_count": cpu_count,
                "cpu_count_raw": cpu_count_raw,
                "machine": parsed.get("machine", ""),
                "kernel_release": parsed.get("kernel_release", ""),
                "underlay_interface": parsed.get("underlay_interface", ""),
                "underlay_driver": parsed.get("underlay_driver", ""),
                "net_drivers": net_drivers,
            }
        )
    return rows


def validate_host_state_artifacts(
    case_dir: Path,
    *,
    required: bool,
    min_nodes: int,
    min_cpus: int,
    forbidden_net_drivers: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    rows = collect_host_state_artifacts(case_dir)
    errors: list[str] = []
    valid_nodes: set[str] = set()
    forbidden = {driver.strip().lower() for driver in forbidden_net_drivers if driver.strip()}
    for row in rows:
        source = str(row["source"])
        row_ok = True
        cpu_count = row.get("cpu_count")
        if not isinstance(cpu_count, int):
            errors.append(
                f"{source}: invalid host cpu_count {row.get('cpu_count_raw')!r}"
            )
            row_ok = False
        elif cpu_count < min_cpus:
            errors.append(f"{source}: host cpu_count={cpu_count}, want >= {min_cpus}")
            row_ok = False
        if not str(row.get("machine") or ""):
            errors.append(f"{source}: missing host machine")
            row_ok = False
        drivers: dict[str, str] = dict(row.get("net_drivers") or {})
        underlay_driver = str(row.get("underlay_driver") or "")
        if underlay_driver:
            drivers.setdefault("underlay", underlay_driver)
        for iface, driver in sorted(drivers.items()):
            normalized = str(driver).strip().lower()
            if normalized and normalized in forbidden:
                errors.append(
                    f"{source}: forbidden host net driver {driver!r} on {iface}"
                )
                row_ok = False
        if row_ok:
            valid_nodes.add(str(row["node"]))
    if required and len(valid_nodes) < min_nodes:
        errors.append(
            f"found valid host state artifacts for {len(valid_nodes)} nodes, "
            f"want >= {min_nodes}"
        )
    return rows, errors, sorted(valid_nodes)


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


def parse_os_release_text(value: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in value.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        key = key.strip()
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
            raw = raw[1:-1]
        if key:
            parsed[key] = raw
    return parsed


def os_release_identity(parsed: dict[str, str]) -> str:
    os_id = parsed.get("ID", "").strip()
    version_id = parsed.get("VERSION_ID", "").strip()
    if not os_id or not version_id or os_id == "unknown" or version_id == "unknown":
        return ""
    return f"{os_id}:{version_id}"


def collect_os_release_artifacts(case_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pattern = re.compile(r"^os-release-([A-Za-z0-9_.-]+)[.]txt$")
    for path in sorted(case_dir.rglob("os-release-*.txt")):
        match = pattern.match(path.name)
        if not match:
            continue
        try:
            value = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            value = ""
        parsed = parse_os_release_text(value)
        rows.append(
            {
                "source": str(path.relative_to(case_dir)),
                "node": transport_node_key(path, case_dir),
                "phase": match.group(1),
                "id": parsed.get("ID", ""),
                "version_id": parsed.get("VERSION_ID", ""),
                "pretty_name": parsed.get("PRETTY_NAME", parsed.get("NAME", "")),
                "identity": os_release_identity(parsed),
            }
        )
    return rows


def validate_os_release_artifacts(
    case_dir: Path,
    *,
    required: bool,
    min_nodes: int,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    rows = collect_os_release_artifacts(case_dir)
    errors: list[str] = []
    if not required:
        nodes = sorted({str(row["node"]) for row in rows if row.get("identity")})
        return rows, errors, nodes

    by_node: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for row in rows:
        node = str(row["node"])
        phase = str(row["phase"])
        by_node.setdefault(node, {}).setdefault(phase, []).append(row)
        if not row.get("identity"):
            errors.append(
                f"{row['source']}: invalid os-release artifact "
                f"ID={row.get('id')!r} VERSION_ID={row.get('version_id')!r}"
            )

    complete_nodes: set[str] = set()
    for node, phases in sorted(by_node.items()):
        before_identities = {
            str(row.get("identity") or "")
            for row in phases.get("before", [])
            if row.get("identity")
        }
        after_identities = {
            str(row.get("identity") or "")
            for row in phases.get("after", [])
            if row.get("identity")
        }
        if before_identities and after_identities:
            complete_nodes.add(node)
        if len(before_identities) > 1:
            errors.append(f"{node}: multiple before os-release identities: {sorted(before_identities)}")
        if len(after_identities) > 1:
            errors.append(f"{node}: multiple after os-release identities: {sorted(after_identities)}")
        if not before_identities:
            errors.append(f"{node}: missing before os-release artifact")
            continue
        if not after_identities:
            errors.append(f"{node}: missing after os-release artifact")
            continue
        if before_identities != after_identities:
            errors.append(
                f"{node}: os-release changed before={sorted(before_identities)} "
                f"after={sorted(after_identities)}"
            )
    if len(complete_nodes) < min_nodes:
        errors.append(
            f"found matching before/after os-release artifacts for {len(complete_nodes)} nodes, "
            f"want >= {min_nodes}"
        )
    return rows, errors, sorted(complete_nodes)


def identity_key(identity: dict[str, Any], fields: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(identity.get(field) or "") for field in fields)


def parse_required_datapath_stats(
    raw_items: list[str],
    flag: str = "--require-datapath-stat",
) -> list[tuple[str, str]]:
    required: list[tuple[str, str]] = []
    for raw in raw_items:
        path, sep, value = raw.partition("=")
        path = path.strip()
        value = value.strip()
        if not sep or not path:
            raise SystemExit(f"invalid {flag} {raw!r}; expected PATH=VALUE")
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


def parse_required_ratio_limits(raw_items: list[str], flag: str) -> list[tuple[str, str, float]]:
    required: list[tuple[str, str, float]] = []
    for raw in raw_items:
        ratio_path, sep, value = raw.partition("=")
        ratio_path = ratio_path.strip()
        value = value.strip()
        numerator, slash, denominator = ratio_path.partition("/")
        numerator = numerator.strip()
        denominator = denominator.strip()
        if not sep or not slash or not numerator or not denominator:
            raise SystemExit(
                f"invalid {flag} {raw!r}; expected NUMERATOR_PATH/DENOMINATOR_PATH=VALUE"
            )
        try:
            maximum = float(value)
        except ValueError as exc:
            raise SystemExit(f"invalid {flag} {raw!r}; VALUE must be numeric") from exc
        if maximum < 0:
            raise SystemExit(f"invalid {flag} {raw!r}; VALUE must be non-negative")
        required.append((numerator, denominator, maximum))
    return required


def parse_required_node_numeric_limits(
    raw_items: list[str], flag: str
) -> list[tuple[str, str, float]]:
    required: list[tuple[str, str, float]] = []
    for raw in raw_items:
        path, sep, value = raw.partition("=")
        path = path.strip()
        value = value.strip()
        node, dot, dotted_path = path.partition(".")
        node = node.strip()
        dotted_path = dotted_path.strip()
        if not sep or not dot or not node or not dotted_path:
            raise SystemExit(
                f"invalid {flag} {raw!r}; expected NODE.MODULE.PARAM=VALUE"
            )
        try:
            numeric = float(value)
        except ValueError as exc:
            raise SystemExit(f"invalid {flag} {raw!r}; VALUE must be numeric") from exc
        required.append((node, dotted_path, numeric))
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
    if isinstance(actual, (list, tuple)):
        return any(datapath_value_matches(item, expected) for item in actual)
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
    required_ratio_maxima: list[tuple[str, str, float]],
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
    if (
        required
        or required_minima
        or required_any_minima
        or required_maxima
        or required_ratio_maxima
    ) and not datapath_files:
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
        for numerator_path, denominator_path, maximum in required_ratio_maxima:
            ratio_key = f"{numerator_path}/{denominator_path}"
            try:
                numerator = datapath_value(payload, numerator_path)
            except KeyError:
                errors.append(f"{rel}: missing datapath ratio numerator {numerator_path!r}")
                continue
            try:
                denominator = datapath_value(payload, denominator_path)
            except KeyError:
                errors.append(f"{rel}: missing datapath ratio denominator {denominator_path!r}")
                continue
            values[numerator_path] = numerator
            values[denominator_path] = denominator
            try:
                numerator_number = numeric_value(numerator)
            except (TypeError, ValueError):
                errors.append(
                    f"{rel}: datapath ratio numerator {numerator_path}={numerator!r} is not numeric"
                )
                continue
            try:
                denominator_number = numeric_value(denominator)
            except (TypeError, ValueError):
                errors.append(
                    f"{rel}: datapath ratio denominator {denominator_path}={denominator!r} is not numeric"
                )
                continue
            if denominator_number <= 0:
                errors.append(
                    f"{rel}: datapath ratio denominator {denominator_path}={denominator_number:g}, want > 0"
                )
                continue
            ratio = numerator_number / denominator_number
            values[ratio_key] = {
                "numerator": numerator_number,
                "denominator": denominator_number,
                "ratio": ratio,
                "maximum": maximum,
            }
            if ratio > maximum:
                errors.append(
                    f"{rel}: datapath ratio {ratio_key}={ratio:.9g}, want <= {maximum:.9g} "
                    f"({numerator_number:g}/{denominator_number:g})"
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
    required_node_maxima: list[tuple[str, str, float]],
    min_module_parameters: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    files = sorted(case_dir.rglob("module-parameters.txt"))
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    any_hits: dict[str, bool] = {
        dotted_path: False for dotted_path, _ in required_any_minima
    }
    node_hits: dict[tuple[str, str], bool] = {
        (node, dotted_path): False for node, dotted_path, _ in required_node_maxima
    }
    if len(files) < min_module_parameters:
        errors.append(
            f"found {len(files)} module-parameters.txt files, want >= {min_module_parameters}"
        )
    if (
        required_minima
        or required_any_minima
        or required_maxima
        or required_node_maxima
    ) and not files:
        return rows, errors, len(files)
    for path in files:
        rel = str(path.relative_to(case_dir))
        node = transport_node_key(path, case_dir)
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
        for required_node, dotted_path, maximum in required_node_maxima:
            if node != required_node:
                continue
            node_hits[(required_node, dotted_path)] = True
            try:
                actual = module_parameter_value(modules, dotted_path)
            except KeyError:
                errors.append(
                    f"{rel}: missing module parameter {required_node}.{dotted_path!r}"
                )
                continue
            values[f"{required_node}.{dotted_path}"] = actual
            try:
                actual_number = numeric_value(actual)
            except (TypeError, ValueError):
                errors.append(
                    f"{rel}: module parameter {required_node}.{dotted_path}={actual!r} is not numeric"
                )
                continue
            if actual_number > maximum:
                errors.append(
                    f"{rel}: module parameter {required_node}.{dotted_path}={actual_number:g}, want <= {maximum:g}"
                )
        if values:
            rows.append({"file": rel, "values": values})
    for dotted_path, minimum in required_any_minima:
        if not any_hits.get(dotted_path, False):
            errors.append(
                f"no collected module parameter {dotted_path!r} reached >= {minimum:g}"
            )
    for node, dotted_path, _ in required_node_maxima:
        if not node_hits.get((node, dotted_path), False):
            errors.append(
                f"no collected module parameters for node {node!r} contained {dotted_path!r}"
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


def transport_endpoint_matches(
    endpoint: Any,
    *,
    required_endpoint_stats: list[tuple[str, str]],
) -> bool:
    if not isinstance(endpoint, dict):
        return False
    for dotted_path, expected in required_endpoint_stats:
        try:
            actual = datapath_value(endpoint, dotted_path)
        except KeyError:
            return False
        if not datapath_value_matches(actual, expected):
            return False
    return True


def transport_stats_requirement_description(required_stats: list[tuple[str, str]]) -> str:
    return ", ".join(f"{path}={value}" for path, value in required_stats) if required_stats else "any"


def transport_session_matches(
    session: Any,
    *,
    required_session_stats: list[tuple[str, str]],
    required_endpoint_suffixes: list[str],
) -> bool:
    if not isinstance(session, dict):
        return False
    for dotted_path, expected in required_session_stats:
        try:
            actual = datapath_value(session, dotted_path)
        except KeyError:
            return False
        if not datapath_value_matches(actual, expected):
            return False
    if required_endpoint_suffixes:
        endpoint = str(session.get("endpoint") or "")
        if not any(endpoint.endswith(suffix) for suffix in required_endpoint_suffixes):
            return False
    return True


def transport_session_requirement_description(
    required_session_stats: list[tuple[str, str]],
    required_endpoint_suffixes: list[str],
) -> str:
    parts = [transport_stats_requirement_description(required_session_stats)]
    if parts == ["any"]:
        parts = []
    if required_endpoint_suffixes:
        suffixes = ",".join(required_endpoint_suffixes)
        parts.append(f"endpoint_suffix={suffixes}")
    return ", ".join(parts) if parts else "any session"


def validate_transports(
    case_dir: Path,
    *,
    required_policy_stats: list[tuple[str, str]],
    required_policy_minima: list[tuple[str, float]],
    required_sessions_min: int,
    required_local_endpoint_stats: list[tuple[str, str]],
    required_peer_endpoint_stats: list[tuple[str, str]],
    required_session_stats: list[tuple[str, str]],
    required_session_any_minima: list[tuple[str, float]],
    required_session_endpoint_suffixes: list[str],
    min_transports_json: int,
) -> tuple[list[dict[str, Any]], list[str], int]:
    payloads = collect_transports_json(case_dir)
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    endpoint_counts_by_group: dict[str, dict[str, list[tuple[str, int]]]] = {
        "local_endpoints": {},
        "peer_endpoints": {},
    }
    session_counts_by_node: dict[str, list[tuple[str, int]]] = {}
    session_any_max_by_node: dict[str, dict[str, tuple[str, float]]] = {}
    endpoint_requirements_enabled = bool(
        required_local_endpoint_stats or required_peer_endpoint_stats
    )
    session_requirements_enabled = bool(
        required_session_stats
        or required_session_any_minima
        or required_session_endpoint_suffixes
    )
    if len(payloads) < min_transports_json:
        errors.append(
            f"found {len(payloads)} transports.json files, want >= {min_transports_json}"
        )
    if (
        required_policy_stats
        or required_policy_minima
        or required_sessions_min > 0
        or endpoint_requirements_enabled
        or session_requirements_enabled
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
        node_key = transport_node_key(path, case_dir)
        for group_name, required_endpoint_stats in (
            ("local_endpoints", required_local_endpoint_stats),
            ("peer_endpoints", required_peer_endpoint_stats),
        ):
            if not required_endpoint_stats:
                continue
            endpoints = payload.get(group_name) if isinstance(payload, dict) else None
            endpoint_rows = endpoints if isinstance(endpoints, list) else []
            matching_count = sum(
                1
                for endpoint in endpoint_rows
                if transport_endpoint_matches(
                    endpoint,
                    required_endpoint_stats=required_endpoint_stats,
                )
            )
            values[f"{group_name}.matching"] = matching_count
            endpoint_counts_by_group[group_name].setdefault(node_key, []).append(
                (rel, matching_count)
            )
        if required_sessions_min > 0 or session_requirements_enabled:
            sessions = payload.get("sessions") if isinstance(payload, dict) else None
            session_rows = sessions if isinstance(sessions, list) else []
            count = len(session_rows)
            matching_count = count
            if session_requirements_enabled:
                matching_count = 0
                matching_sessions = []
                for session in session_rows:
                    if transport_session_matches(
                        session,
                        required_session_stats=required_session_stats,
                        required_endpoint_suffixes=required_session_endpoint_suffixes,
                    ):
                        matching_count += 1
                        matching_sessions.append(session)
                values["matching_sessions"] = matching_count
                node_key = transport_node_key(path, case_dir)
                node_max = session_any_max_by_node.setdefault(node_key, {})
                for dotted_path, _ in required_session_any_minima:
                    best = node_max.get(dotted_path)
                    for session in matching_sessions:
                        try:
                            actual = datapath_value(session, dotted_path)
                            actual_number = numeric_value(actual)
                        except (KeyError, TypeError, ValueError):
                            continue
                        if best is None or actual_number > best[1]:
                            best = (rel, actual_number)
                    if best is not None:
                        node_max[dotted_path] = best
                        values[f"matching_session_max.{dotted_path}"] = best[1]
            values["sessions"] = count
            session_counts_by_node.setdefault(node_key, []).append((rel, matching_count))
        if values:
            rows.append({"file": rel, "values": values})
    if endpoint_requirements_enabled:
        for group_name, required_endpoint_stats in (
            ("local_endpoints", required_local_endpoint_stats),
            ("peer_endpoints", required_peer_endpoint_stats),
        ):
            if not required_endpoint_stats:
                continue
            requirement = transport_stats_requirement_description(required_endpoint_stats)
            for node_key, counts in sorted(endpoint_counts_by_group[group_name].items()):
                if not counts:
                    continue
                best_rel, best_count = max(counts, key=lambda item: item[1])
                if best_count < 1:
                    errors.append(
                        f"{best_rel}: matching transport {group_name}=0, "
                        f"want >= 1 ({requirement})"
                    )
    if required_sessions_min > 0 or session_requirements_enabled:
        minimum = required_sessions_min
        if session_requirements_enabled and minimum == 0:
            minimum = 1
        requirement = transport_session_requirement_description(
            required_session_stats,
            required_session_endpoint_suffixes,
        )
        for node_key, counts in sorted(session_counts_by_node.items()):
            if not counts:
                continue
            best_rel, best_count = max(counts, key=lambda item: item[1])
            if best_count < minimum:
                label = "matching transport sessions" if session_requirements_enabled else "transport sessions"
                errors.append(
                    f"{best_rel}: {label}={best_count}, want >= {minimum} ({requirement})"
                )
        for node_key in sorted(session_counts_by_node):
            for dotted_path, minimum in required_session_any_minima:
                best = session_any_max_by_node.get(node_key, {}).get(dotted_path)
                if best is None:
                    errors.append(
                        f"node {node_key}: no matching transport session stat "
                        f"{dotted_path!r} reached >= {minimum:g} ({requirement})"
                    )
                    continue
                best_rel, best_value = best
                if best_value < minimum:
                    errors.append(
                        f"{best_rel}: matching transport session stat "
                        f"{dotted_path}={best_value:g}, want >= {minimum:g} ({requirement})"
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
    require_run_timing: bool,
    required_run_timing_stats: list[tuple[str, str]],
    require_iperf_pair_directions: bool,
    require_result_marker: bool,
    log_scan: bool,
    require_kernel_log_artifacts: bool,
    min_kernel_log_artifacts: int,
    min_kernel_log_nodes: int,
    require_pstore_artifacts: bool,
    min_pstore_nodes: int,
    require_lsmod_artifacts: bool,
    min_lsmod_nodes: int,
    required_lsmod_modules: list[str],
    forbidden_lsmod_modules: list[str],
    forbidden_lsmod_prefixes: list[str],
    require_lan_state_artifacts: bool,
    min_lan_state_nodes: int,
    min_lan_tx_queue_len: int,
    require_host_state_artifacts: bool,
    min_host_state_nodes: int,
    min_host_cpus: int,
    forbidden_host_net_drivers: list[str],
    require_uname_artifacts: bool,
    min_uname_nodes: int,
    require_os_release_artifacts: bool,
    min_os_release_nodes: int,
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
    required_datapath_ratio_maxima: list[tuple[str, str, float]],
    min_datapath_json: int,
    required_module_param_minima: list[tuple[str, float]],
    required_module_param_any_minima: list[tuple[str, float]],
    required_module_param_maxima: list[tuple[str, float]],
    required_module_param_node_maxima: list[tuple[str, str, float]],
    min_module_parameters: int,
    required_transport_policy_stats: list[tuple[str, str]],
    required_transport_policy_minima: list[tuple[str, float]],
    required_transport_sessions_min: int,
    required_transport_local_endpoint_stats: list[tuple[str, str]],
    required_transport_peer_endpoint_stats: list[tuple[str, str]],
    required_transport_session_stats: list[tuple[str, str]],
    required_transport_session_any_minima: list[tuple[str, float]],
    required_transport_session_endpoint_suffixes: list[str],
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
    run_timing, run_timing_errors = run_timing_artifacts(
        case.path,
        required=require_run_timing or bool(required_run_timing_stats),
        min_seconds=min_seconds,
        seconds_slop=seconds_slop,
        required_stats=required_run_timing_stats,
    )
    errors.extend(run_timing_errors)

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
    collected_pstore, rejected_pstore, pstore_nodes = pstore_artifacts(case.path)
    if require_pstore_artifacts:
        errors.extend(
            f"pstore artifact unusable: {finding}"
            for finding in rejected_pstore
        )
    if require_pstore_artifacts and len(pstore_nodes) < min_pstore_nodes:
        errors.append(
            f"found pstore artifacts for {len(pstore_nodes)} nodes, "
            f"want >= {min_pstore_nodes}"
        )
    lsmod_artifacts, lsmod_errors, lsmod_nodes = validate_lsmod_artifacts(
        case.path,
        required=require_lsmod_artifacts,
        min_nodes=min_lsmod_nodes,
        required_modules=required_lsmod_modules,
        forbidden_modules=forbidden_lsmod_modules,
        forbidden_prefixes=forbidden_lsmod_prefixes,
    )
    errors.extend(lsmod_errors)
    lan_state_artifacts, lan_state_errors, lan_state_nodes = validate_lan_state_artifacts(
        case.path,
        required=require_lan_state_artifacts,
        min_nodes=min_lan_state_nodes,
        min_tx_queue_len=min_lan_tx_queue_len,
    )
    errors.extend(lan_state_errors)
    host_state_artifacts, host_state_errors, host_state_nodes = validate_host_state_artifacts(
        case.path,
        required=require_host_state_artifacts,
        min_nodes=min_host_state_nodes,
        min_cpus=min_host_cpus,
        forbidden_net_drivers=forbidden_host_net_drivers,
    )
    errors.extend(host_state_errors)

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
    os_release_artifacts, os_release_errors, os_release_nodes = validate_os_release_artifacts(
        case.path,
        required=require_os_release_artifacts,
        min_nodes=min_os_release_nodes,
    )
    errors.extend(os_release_errors)

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
        required_ratio_maxima=required_datapath_ratio_maxima,
        min_datapath_json=min_datapath_json,
    )
    errors.extend(datapath_stat_errors)
    module_param_results, module_param_errors, module_param_count = validate_module_parameters(
        case.path,
        required_minima=required_module_param_minima,
        required_any_minima=required_module_param_any_minima,
        required_maxima=required_module_param_maxima,
        required_node_maxima=required_module_param_node_maxima,
        min_module_parameters=min_module_parameters,
    )
    errors.extend(module_param_errors)
    transport_results, transport_errors, transports_json_count = validate_transports(
        case.path,
        required_policy_stats=required_transport_policy_stats,
        required_policy_minima=required_transport_policy_minima,
        required_sessions_min=required_transport_sessions_min,
        required_local_endpoint_stats=required_transport_local_endpoint_stats,
        required_peer_endpoint_stats=required_transport_peer_endpoint_stats,
        required_session_stats=required_transport_session_stats,
        required_session_any_minima=required_transport_session_any_minima,
        required_session_endpoint_suffixes=required_transport_session_endpoint_suffixes,
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
        "run_timing": run_timing,
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
        "pstore_artifacts": collected_pstore,
        "pstore_rejected_artifacts": rejected_pstore,
        "pstore_nodes": pstore_nodes,
        "lsmod_artifacts": lsmod_artifacts,
        "lsmod_nodes": lsmod_nodes,
        "lan_state_artifacts": lan_state_artifacts,
        "lan_state_nodes": lan_state_nodes,
        "host_state_artifacts": host_state_artifacts,
        "host_state_nodes": host_state_nodes,
        "build_identities": build_identities,
        "binary_identities": binary_identities,
        "boot_ids": boot_ids,
        "uname_artifacts": uname_artifacts,
        "uname_nodes": uname_nodes,
        "os_release_artifacts": os_release_artifacts,
        "os_release_nodes": os_release_nodes,
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
    if args.min_pstore_nodes < 0:
        raise SystemExit("--min-pstore-nodes must be non-negative")
    if args.min_lsmod_nodes < 0:
        raise SystemExit("--min-lsmod-nodes must be non-negative")
    if args.min_lan_state_nodes < 0:
        raise SystemExit("--min-lan-state-nodes must be non-negative")
    if args.min_lan_tx_queue_len < 0:
        raise SystemExit("--min-lan-tx-queue-len must be non-negative")
    if args.min_host_state_nodes < 0:
        raise SystemExit("--min-host-state-nodes must be non-negative")
    if args.min_host_cpus < 0:
        raise SystemExit("--min-host-cpus must be non-negative")
    if any(not item.strip() for item in args.forbid_host_net_driver):
        raise SystemExit("--forbid-host-net-driver must not be empty")
    if args.min_uname_nodes < 0:
        raise SystemExit("--min-uname-nodes must be non-negative")
    if args.min_os_release_nodes < 0:
        raise SystemExit("--min-os-release-nodes must be non-negative")
    required_status_stats = parse_required_datapath_stats(
        args.require_status_stat,
        "--require-status-stat",
    )
    required_status_minima = parse_required_numeric_limits(
        args.require_status_min,
        "--require-status-min",
    )
    required_status_maxima = parse_required_numeric_limits(
        args.require_status_max,
        "--require-status-max",
    )
    required_datapath_stats = parse_required_datapath_stats(
        args.require_datapath_stat,
        "--require-datapath-stat",
    )
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
    required_datapath_ratio_maxima = parse_required_ratio_limits(
        args.require_datapath_ratio_max,
        "--require-datapath-ratio-max",
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
    required_module_param_node_maxima = parse_required_node_numeric_limits(
        args.require_module_param_node_max,
        "--require-module-param-node-max",
    )
    required_transport_policy_stats = parse_required_datapath_stats(
        args.require_transport_policy_stat,
        "--require-transport-policy-stat",
    )
    required_transport_policy_minima = parse_required_numeric_limits(
        args.require_transport_policy_min,
        "--require-transport-policy-min",
    )
    required_transport_local_endpoint_stats = parse_required_datapath_stats(
        args.require_transport_local_endpoint_stat,
        "--require-transport-local-endpoint-stat",
    )
    required_transport_peer_endpoint_stats = parse_required_datapath_stats(
        args.require_transport_peer_endpoint_stat,
        "--require-transport-peer-endpoint-stat",
    )
    required_transport_session_stats = parse_required_datapath_stats(
        args.require_transport_session_stat,
        "--require-transport-session-stat",
    )
    required_transport_session_any_minima = parse_required_numeric_limits(
        args.require_transport_session_any_min,
        "--require-transport-session-any-min",
    )
    required_transport_session_endpoint_suffixes = [
        item.strip() for item in args.require_transport_session_endpoint_suffix
    ]
    if any(not item for item in required_transport_session_endpoint_suffixes):
        raise SystemExit("--require-transport-session-endpoint-suffix must not be empty")
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
        or required_datapath_ratio_maxima
    ) and min_datapath_json == 0:
        min_datapath_json = 2
    min_module_parameters = args.min_module_parameters
    if (
        required_module_param_minima
        or required_module_param_any_minima
        or required_module_param_maxima
        or required_module_param_node_maxima
    ) and min_module_parameters == 0:
        min_module_parameters = 2
    min_transports_json = args.min_transports_json
    if (
        required_transport_policy_stats
        or required_transport_policy_minima
        or args.require_transport_sessions_min > 0
        or required_transport_local_endpoint_stats
        or required_transport_peer_endpoint_stats
        or required_transport_session_stats
        or required_transport_session_any_minima
        or required_transport_session_endpoint_suffixes
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
            require_run_timing=args.require_run_timing,
            required_run_timing_stats=parse_required_datapath_stats(
                args.require_run_timing_stat,
                "--require-run-timing-stat",
            ),
            require_iperf_pair_directions=args.require_iperf_pair_directions,
            require_result_marker=not args.no_result_marker,
            log_scan=not args.no_log_scan,
            require_kernel_log_artifacts=args.require_kernel_log_artifacts,
            min_kernel_log_artifacts=args.min_kernel_log_artifacts,
            min_kernel_log_nodes=args.min_kernel_log_nodes,
            require_pstore_artifacts=args.require_pstore_artifacts,
            min_pstore_nodes=args.min_pstore_nodes,
            require_lsmod_artifacts=args.require_lsmod_artifacts,
            min_lsmod_nodes=args.min_lsmod_nodes,
            required_lsmod_modules=args.require_lsmod_module,
            forbidden_lsmod_modules=args.forbid_lsmod_module,
            forbidden_lsmod_prefixes=args.forbid_lsmod_prefix,
            require_lan_state_artifacts=args.require_lan_state_artifacts,
            min_lan_state_nodes=args.min_lan_state_nodes,
            min_lan_tx_queue_len=args.min_lan_tx_queue_len,
            require_host_state_artifacts=args.require_host_state_artifacts,
            min_host_state_nodes=args.min_host_state_nodes,
            min_host_cpus=args.min_host_cpus,
            forbidden_host_net_drivers=args.forbid_host_net_driver,
            require_uname_artifacts=args.require_uname_artifacts,
            min_uname_nodes=args.min_uname_nodes,
            require_os_release_artifacts=args.require_os_release_artifacts,
            min_os_release_nodes=args.min_os_release_nodes,
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
            required_datapath_ratio_maxima=required_datapath_ratio_maxima,
            min_datapath_json=min_datapath_json,
            required_module_param_minima=required_module_param_minima,
            required_module_param_any_minima=required_module_param_any_minima,
            required_module_param_maxima=required_module_param_maxima,
            required_module_param_node_maxima=required_module_param_node_maxima,
            min_module_parameters=min_module_parameters,
            required_transport_policy_stats=required_transport_policy_stats,
            required_transport_policy_minima=required_transport_policy_minima,
            required_transport_sessions_min=args.require_transport_sessions_min,
            required_transport_local_endpoint_stats=required_transport_local_endpoint_stats,
            required_transport_peer_endpoint_stats=required_transport_peer_endpoint_stats,
            required_transport_session_stats=required_transport_session_stats,
            required_transport_session_any_minima=required_transport_session_any_minima,
            required_transport_session_endpoint_suffixes=required_transport_session_endpoint_suffixes,
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
