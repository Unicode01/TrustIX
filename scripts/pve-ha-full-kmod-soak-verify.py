#!/usr/bin/env python3
"""Verify evidence emitted by pve-ha-full-kmod-soak.sh."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


PING_RE = re.compile(r"^\[([0-9]+(?:\.[0-9]+)?)\].*icmp_seq=([0-9]+)")
TRAFFIC_FILES = {
    "tcp_forward": ("tcp-forward.tsv", "tcp"),
    "tcp_reverse": ("tcp-reverse.tsv", "tcp"),
    "udp_forward": ("udp-forward.tsv", "udp"),
    "udp_reverse": ("udp-reverse.tsv", "udp"),
}
WORKER_STDERR_FILES = (
    "tcp-forward.stderr.log",
    "tcp-reverse.stderr.log",
    "udp-forward.stderr.log",
    "udp-reverse.stderr.log",
    "ping.stderr.log",
    "remote-module.stderr.log",
    "pve-state.stderr.log",
)
MODULE_SNAPSHOT_FILES = (
    "module-master-after.txt",
    "module-remote-after.txt",
)
MODULE_REQUIRED_PARAMETERS = {
    "enable_features": "128",
    "features": "128",
    "rx_worker_inject": "Y",
    "selftest_failures": "0",
    "selftests": "1023",
    "tx_plaintext": "Y",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--min-duration", type=float, default=3600.0)
    parser.add_argument("--duration-slop", type=float, default=2.0)
    parser.add_argument("--min-transitions", type=int, default=6)
    parser.add_argument("--max-ready-seconds", type=float, default=10.0)
    parser.add_argument("--max-ping-outage-seconds", type=float, default=10.0)
    parser.add_argument("--transition-failure-grace-seconds", type=float, default=30.0)
    parser.add_argument("--max-traffic-gap-seconds", type=float, default=30.0)
    parser.add_argument("--traffic-coverage-slop-seconds", type=float, default=15.0)
    parser.add_argument("--max-module-gap-seconds", type=float, default=10.0)
    parser.add_argument("--max-pve-state-gap-seconds", type=float, default=10.0)
    parser.add_argument("--tcp-min-bps", type=float, default=1_000_000_000.0)
    parser.add_argument("--udp-min-bps", type=float, default=150_000_000.0)
    parser.add_argument("--min-traffic-successes", type=int, default=0)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def read_text(path: Path, errors: list[str]) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"read {path.name}: {exc}")
        return ""


def read_epoch(path: Path, errors: list[str]) -> float | None:
    raw = read_text(path, errors).strip()
    try:
        value = float(raw)
    except ValueError:
        errors.append(f"{path.name} is not an epoch: {raw!r}")
        return None
    if not math.isfinite(value) or value <= 0:
        errors.append(f"{path.name} is not a positive finite epoch: {raw!r}")
        return None
    return value


def read_manifest(path: Path, errors: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, line in enumerate(read_text(path, errors).splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2 or not parts[0]:
            errors.append(f"manifest.tsv:{number}: malformed row")
            continue
        if parts[0] in result:
            errors.append(f"manifest.tsv:{number}: duplicate key {parts[0]!r}")
            continue
        result[parts[0]] = parts[1]
    return result


def read_transitions(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    text = read_text(path, errors)
    if not text:
        return []
    rows: list[dict[str, Any]] = []
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    required = {
        "index",
        "type",
        "old_master",
        "new_master",
        "trigger_epoch",
        "ready_epoch",
        "recovery_seconds",
        "rejoin_epoch",
    }
    if set(reader.fieldnames or ()) != required:
        errors.append(f"transitions.tsv has unexpected columns: {reader.fieldnames!r}")
        return []
    for number, row in enumerate(reader, 2):
        try:
            parsed = {
                "index": int(row["index"]),
                "type": row["type"],
                "old_master": int(row["old_master"]),
                "new_master": int(row["new_master"]),
                "trigger": float(row["trigger_epoch"]),
                "ready": float(row["ready_epoch"]),
                "recovery": float(row["recovery_seconds"]),
                "rejoin": float(row["rejoin_epoch"]),
            }
        except (TypeError, ValueError) as exc:
            errors.append(f"transitions.tsv:{number}: invalid numeric field: {exc}")
            continue
        rows.append(parsed)
    return rows


def transition_windows(
    transitions: list[dict[str, Any]], before: float, after: float
) -> list[tuple[float, float]]:
    return [(row["trigger"] - before, row["ready"] + after) for row in transitions]


def overlaps(start: float, end: float, windows: list[tuple[float, float]]) -> bool:
    return any(start <= right and end >= left for left, right in windows)


def verify_transitions(
    transitions: list[dict[str, Any]],
    start_epoch: float | None,
    end_epoch: float | None,
    args: argparse.Namespace,
    errors: list[str],
) -> dict[str, Any]:
    if len(transitions) < args.min_transitions:
        errors.append(
            f"transitions={len(transitions)}, want at least {args.min_transitions}"
        )
    expected_index = 1
    previous_new: int | None = None
    previous_rejoin: float | None = None
    kinds: set[str] = set()
    maximum = 0.0
    for row in transitions:
        numeric = (row["trigger"], row["ready"], row["recovery"], row["rejoin"])
        if not all(math.isfinite(value) for value in numeric):
            errors.append(f"transition {row['index']}: timestamps must be finite")
            continue
        if row["index"] != expected_index:
            errors.append(
                f"transition index={row['index']}, want contiguous index {expected_index}"
            )
        expected_index += 1
        kinds.add(row["type"])
        expected_type = "host_stop" if row["index"] % 2 == 1 else "vrrp_partition"
        if row["type"] != expected_type:
            errors.append(
                f"transition {row['index']}: type={row['type']!r}, "
                f"want {expected_type!r}"
            )
        if row["old_master"] == row["new_master"]:
            errors.append(f"transition {row['index']}: old and new MASTER are identical")
        if previous_new is not None and row["old_master"] != previous_new:
            errors.append(
                f"transition {row['index']}: old MASTER {row['old_master']} "
                f"does not match previous new MASTER {previous_new}"
            )
        previous_new = row["new_master"]
        calculated = row["ready"] - row["trigger"]
        if abs(calculated - row["recovery"]) > 0.05:
            errors.append(
                f"transition {row['index']}: recovery={row['recovery']:.6f}, "
                f"timestamps imply {calculated:.6f}"
            )
        if calculated <= 0 or calculated > args.max_ready_seconds:
            errors.append(
                f"transition {row['index']}: ready recovery {calculated:.3f}s "
                f"exceeds 0..{args.max_ready_seconds:.3f}s"
            )
        if row["rejoin"] < row["ready"]:
            errors.append(f"transition {row['index']}: rejoin precedes readiness")
        if previous_rejoin is not None and row["trigger"] <= previous_rejoin:
            errors.append(
                f"transition {row['index']}: trigger does not follow the previous rejoin"
            )
        if start_epoch is not None and row["trigger"] < start_epoch:
            errors.append(f"transition {row['index']}: trigger precedes soak start")
        if end_epoch is not None and row["rejoin"] > end_epoch:
            errors.append(f"transition {row['index']}: rejoin follows soak end")
        previous_rejoin = row["rejoin"]
        maximum = max(maximum, calculated)
    if transitions and not {"host_stop", "vrrp_partition"}.issubset(kinds):
        errors.append("transition matrix must include host_stop and vrrp_partition")
    return {"count": len(transitions), "types": sorted(kinds), "max_ready_seconds": maximum}


def verify_manifest_ha_chain(
    manifest: dict[str, str], transitions: list[dict[str, Any]], errors: list[str]
) -> None:
    required = ("vm_a", "vm_b", "initial_master", "final_master", "final_backup")
    values: dict[str, int] = {}
    for name in required:
        raw = manifest.get(name, "")
        try:
            values[name] = int(raw)
        except ValueError:
            errors.append(f"manifest {name} is not an integer: {raw!r}")
    if len(values) != len(required):
        return
    ha_vms = {values["vm_a"], values["vm_b"]}
    if len(ha_vms) != 2:
        errors.append("manifest vm_a and vm_b must be distinct")
    if values["initial_master"] not in ha_vms:
        errors.append("manifest initial_master is not one of the HA VMs")
    if {values["final_master"], values["final_backup"]} != ha_vms:
        errors.append("manifest final MASTER/BACKUP do not match the HA VM pair")
    for row in transitions:
        if {row["old_master"], row["new_master"]} != ha_vms:
            errors.append(
                f"transition {row['index']}: MASTER pair does not match manifest HA VMs"
            )
    if transitions and transitions[0]["old_master"] != values["initial_master"]:
        errors.append("first transition old MASTER does not match manifest initial_master")
    if transitions and transitions[-1]["new_master"] != values["final_master"]:
        errors.append("last transition new MASTER does not match manifest final_master")


def verify_ping(
    path: Path,
    transitions: list[dict[str, Any]],
    start_epoch: float | None,
    end_epoch: float | None,
    args: argparse.Namespace,
    errors: list[str],
) -> dict[str, Any]:
    successes: list[tuple[float, int]] = []
    for line in read_text(path, errors).splitlines():
        match = PING_RE.match(line)
        if match and "bytes from" in line:
            successes.append((float(match.group(1)), int(match.group(2))))
    if len(successes) < 2:
        errors.append("ping.log has fewer than two successful replies")
        return {"successes": len(successes), "gaps": []}
    if start_epoch is not None and successes[0][0] > start_epoch + 5:
        errors.append("ping coverage starts more than 5s after soak start")
    if end_epoch is not None and successes[-1][0] < end_epoch - 5:
        errors.append("ping coverage ends more than 5s before soak end")
    windows = transition_windows(transitions, 2.0, 5.0)
    gaps: list[dict[str, Any]] = []
    max_outage = 0.0
    for left, right in zip(successes, successes[1:]):
        delta = right[0] - left[0]
        if delta <= 0:
            errors.append(f"ping timestamps are not increasing at seq {right[1]}")
            continue
        if right[1] <= left[1]:
            errors.append(f"ping sequence is not increasing: {left[1]} -> {right[1]}")
            continue
        if delta <= 0.5:
            continue
        outage = max(0.0, delta - 0.2)
        gap = {
            "last_time": left[0],
            "next_time": right[0],
            "last_seq": left[1],
            "next_seq": right[1],
            "missing": right[1] - left[1] - 1,
            "outage_seconds": outage,
        }
        gaps.append(gap)
        max_outage = max(max_outage, outage)
        if outage > args.max_ping_outage_seconds:
            errors.append(
                f"ping outage {outage:.3f}s exceeds {args.max_ping_outage_seconds:.3f}s"
            )
        if not overlaps(left[0], right[0], windows):
            errors.append(
                f"ping gap {left[0]:.6f}..{right[0]:.6f} is outside a transition"
            )
    return {
        "successes": len(successes),
        "first_epoch": successes[0][0],
        "last_epoch": successes[-1][0],
        "max_outage_seconds": max_outage,
        "gaps": gaps,
    }


def parse_traffic(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(read_text(path, errors).splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t", 5)
        if len(parts) != 6:
            errors.append(f"{path.name}:{number}: malformed traffic row")
            continue
        try:
            row = {
                "start": float(parts[0]),
                "end": float(parts[1]),
                "rc": int(parts[2]),
                "sent": float(parts[3]),
                "received": float(parts[4]),
                "error": parts[5].strip(),
            }
        except ValueError as exc:
            errors.append(f"{path.name}:{number}: invalid numeric field: {exc}")
            continue
        numeric = (row["start"], row["end"], row["sent"], row["received"])
        if not all(math.isfinite(value) for value in numeric):
            errors.append(f"{path.name}:{number}: numeric fields must be finite")
            continue
        if row["end"] < row["start"]:
            errors.append(f"{path.name}:{number}: end precedes start")
            continue
        rows.append(row)
    return rows


def verify_traffic(
    evidence: Path,
    transitions: list[dict[str, Any]],
    start_epoch: float | None,
    end_epoch: float | None,
    args: argparse.Namespace,
    errors: list[str],
) -> dict[str, Any]:
    windows = transition_windows(
        transitions, 2.0, args.transition_failure_grace_seconds
    )
    minimum_successes = args.min_traffic_successes
    if minimum_successes <= 0:
        minimum_successes = max(1, int(args.min_duration / 30.0))
    result: dict[str, Any] = {}
    for name, (filename, family) in TRAFFIC_FILES.items():
        rows = parse_traffic(evidence / filename, errors)
        minimum = args.tcp_min_bps if family == "tcp" else args.udp_min_bps
        successes = 0
        failures = 0
        outside_speeds: list[float] = []
        if (
            rows
            and start_epoch is not None
            and rows[0]["start"] > start_epoch + args.traffic_coverage_slop_seconds
        ):
            errors.append(
                f"{filename}: coverage starts more than "
                f"{args.traffic_coverage_slop_seconds:.3f}s after soak start"
            )
        if (
            rows
            and end_epoch is not None
            and rows[-1]["end"] < end_epoch - args.traffic_coverage_slop_seconds
        ):
            errors.append(
                f"{filename}: coverage ends more than "
                f"{args.traffic_coverage_slop_seconds:.3f}s before soak end"
            )
        for previous, current in zip(rows, rows[1:]):
            if current["start"] < previous["start"]:
                errors.append(f"{filename}: sample timestamps are not increasing")
                break
            gap = current["start"] - previous["end"]
            if gap > args.max_traffic_gap_seconds and not overlaps(
                previous["end"], current["start"], windows
            ):
                errors.append(
                    f"{filename}: sample gap {gap:.3f}s exceeds "
                    f"{args.max_traffic_gap_seconds:.3f}s outside transition"
                )
        for row in rows:
            success = row["rc"] == 0 and not row["error"]
            in_transition = overlaps(row["start"], row["end"], windows)
            if success:
                successes += 1
                speed = min(row["sent"], row["received"])
                if not in_transition:
                    outside_speeds.append(speed)
                    if speed < minimum:
                        errors.append(
                            f"{filename}: throughput {speed:.0f} bps below {minimum:.0f} "
                            "outside transition"
                        )
            else:
                failures += 1
                if not in_transition:
                    errors.append(
                        f"{filename}: rc={row['rc']} error={row['error']!r} outside transition"
                    )
        if successes < minimum_successes:
            errors.append(
                f"{filename}: successes={successes}, want at least {minimum_successes}"
            )
        if not outside_speeds:
            errors.append(f"{filename}: no successful sample outside transitions")
        result[name] = {
            "rows": len(rows),
            "successes": successes,
            "failures": failures,
            "min_bps_outside_transitions": min(outside_speeds)
            if outside_speeds
            else 0,
            "average_bps_outside_transitions": sum(outside_speeds)
            / len(outside_speeds)
            if outside_speeds
            else 0,
        }
    return result


def verify_module_monitor(
    path: Path,
    transitions: list[dict[str, Any]],
    start_epoch: float | None,
    end_epoch: float | None,
    args: argparse.Namespace,
    errors: list[str],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(read_text(path, errors).splitlines(), 1):
        parts = line.split("\t")
        if len(parts) < 9:
            errors.append(f"{path.name}:{number}: malformed module row")
            continue
        try:
            rows.append(
                {
                    "time": float(parts[0]),
                    "packets": int(parts[1]),
                    "hits": int(parts[2]),
                    "misses": int(parts[3]),
                    "invalidations": int(parts[4]),
                    "neigh_misses": int(parts[5]),
                    "stale_wires": int(parts[6]),
                    "rx": int(parts[7]),
                    "neigh": parts[8],
                }
            )
        except ValueError as exc:
            errors.append(f"{path.name}:{number}: invalid numeric field: {exc}")
    if len(rows) < 2:
        errors.append("remote-module.tsv has fewer than two samples")
        return {"rows": len(rows)}
    if start_epoch is not None and rows[0]["time"] > start_epoch + 5:
        errors.append("module monitor coverage starts more than 5s after soak start")
    if end_epoch is not None and rows[-1]["time"] < end_epoch - 5:
        errors.append("module monitor coverage ends more than 5s before soak end")
    for previous, current in zip(rows, rows[1:]):
        gap = current["time"] - previous["time"]
        if gap <= 0:
            errors.append("remote-module.tsv timestamps are not increasing")
            break
        if gap > args.max_module_gap_seconds:
            errors.append(
                f"remote-module.tsv sample gap {gap:.3f}s exceeds "
                f"{args.max_module_gap_seconds:.3f}s"
            )
        for name in (
            "packets",
            "hits",
            "misses",
            "invalidations",
            "neigh_misses",
            "stale_wires",
            "rx",
        ):
            if current[name] < previous[name]:
                errors.append(
                    f"remote-module.tsv counter {name} regressed at {current['time']:.6f}"
                )
                break
    for transition in transitions:
        before = [row for row in rows if row["time"] < transition["trigger"]]
        after = [
            row
            for row in rows
            if transition["trigger"] <= row["time"] <= transition["ready"] + 5
        ]
        if not before or not after:
            errors.append(
                f"transition {transition['index']}: missing module monitor coverage"
            )
            continue
        if max(row["invalidations"] for row in after) <= before[-1]["invalidations"]:
            errors.append(
                f"transition {transition['index']}: no destination MAC cache invalidation"
            )
    if rows[-1]["neigh_misses"] > rows[0]["neigh_misses"]:
        errors.append(
            "plaintext direct-xmit neighbour misses increased during the soak"
        )
    if rows[-1]["stale_wires"] > rows[0]["stale_wires"]:
        errors.append("plaintext stale wire counter increased during the soak")
    packet_delta = rows[-1]["packets"] - rows[0]["packets"]
    cache_hit_delta = rows[-1]["hits"] - rows[0]["hits"]
    invalidation_delta = rows[-1]["invalidations"] - rows[0]["invalidations"]
    rx_delta = rows[-1]["rx"] - rows[0]["rx"]
    if packet_delta <= 0:
        errors.append("full-kmod plaintext packet counter did not increase")
    if cache_hit_delta <= 0:
        errors.append("full-kmod destination-MAC cache hit counter did not increase")
    if invalidation_delta < len(transitions):
        errors.append(
            f"destination-MAC cache invalidations={invalidation_delta}, "
            f"want at least {len(transitions)}"
        )
    if rx_delta <= 0:
        errors.append("full-kmod RX worker injected counter did not increase")
    return {
        "rows": len(rows),
        "packet_delta": packet_delta,
        "cache_hit_delta": cache_hit_delta,
        "cache_miss_delta": rows[-1]["misses"] - rows[0]["misses"],
        "cache_invalidation_delta": invalidation_delta,
        "neighbour_miss_delta": rows[-1]["neigh_misses"]
        - rows[0]["neigh_misses"],
        "stale_wire_delta": rows[-1]["stale_wires"] - rows[0]["stale_wires"],
        "rx_injected_delta": rx_delta,
    }


def read_module_parameters(path: Path, errors: list[str]) -> dict[str, str]:
    parameters: dict[str, str] = {}
    prefix = "/sys/module/trustix_datapath/parameters/"
    for number, line in enumerate(read_text(path, errors).splitlines(), 1):
        if not line.strip():
            continue
        left, separator, value = line.partition(":")
        if not separator or not left.startswith(prefix):
            errors.append(f"{path.name}:{number}: malformed module parameter row")
            continue
        name = left[len(prefix) :]
        if not name or name in parameters:
            errors.append(f"{path.name}:{number}: duplicate or empty parameter {name!r}")
            continue
        parameters[name] = value.strip()
    return parameters


def verify_module_snapshots(
    evidence: Path, manifest: dict[str, str], errors: list[str]
) -> dict[str, Any]:
    expected_sha256 = manifest.get("module_sha256", "")
    result: dict[str, Any] = {}
    for filename in MODULE_SNAPSHOT_FILES:
        parameters = read_module_parameters(evidence / filename, errors)
        expected = dict(MODULE_REQUIRED_PARAMETERS)
        expected["build_sha256"] = expected_sha256
        mismatches: list[str] = []
        for name, value in expected.items():
            actual = parameters.get(name)
            if actual != value:
                mismatches.append(f"{name}={actual!r}, want {value!r}")
        if mismatches:
            errors.append(f"{filename}: " + "; ".join(mismatches))
        result[filename] = {
            "build_sha256": parameters.get("build_sha256", ""),
            "features": parameters.get("features", ""),
            "selftests": parameters.get("selftests", ""),
            "selftest_failures": parameters.get("selftest_failures", ""),
        }
    return result


def verify_pve_state(
    path: Path,
    transitions: list[dict[str, Any]],
    start_epoch: float | None,
    end_epoch: float | None,
    args: argparse.Namespace,
    errors: list[str],
) -> dict[str, Any]:
    rows: list[tuple[float, str, str]] = []
    for number, line in enumerate(read_text(path, errors).splitlines(), 1):
        parts = line.split("\t")
        if len(parts) != 3:
            errors.append(f"{path.name}:{number}: malformed PVE state row")
            continue
        try:
            epoch = float(parts[0])
        except ValueError as exc:
            errors.append(f"{path.name}:{number}: invalid epoch: {exc}")
            continue
        if not math.isfinite(epoch):
            errors.append(f"{path.name}:{number}: epoch must be finite")
            continue
        if parts[1] not in {"running", "stopped"} or parts[2] not in {
            "running",
            "stopped",
        }:
            errors.append(f"{path.name}:{number}: invalid VM state")
            continue
        rows.append((epoch, parts[1], parts[2]))
    if len(rows) < 2:
        errors.append("pve-state.tsv has fewer than two samples")
        return {"rows": len(rows)}
    if start_epoch is not None and rows[0][0] > start_epoch + 5:
        errors.append("PVE state coverage starts more than 5s after soak start")
    if end_epoch is not None and rows[-1][0] < end_epoch - 5:
        errors.append("PVE state coverage ends more than 5s before soak end")
    windows = [
        (transition["trigger"] - 2.0, transition["rejoin"] + 5.0)
        for transition in transitions
    ]
    degraded = 0
    for previous, current in zip(rows, rows[1:]):
        gap = current[0] - previous[0]
        if gap <= 0:
            errors.append("pve-state.tsv timestamps are not increasing")
            break
        if gap > args.max_pve_state_gap_seconds:
            errors.append(
                f"pve-state.tsv sample gap {gap:.3f}s exceeds "
                f"{args.max_pve_state_gap_seconds:.3f}s"
            )
    for epoch, state_a, state_b in rows:
        if state_a == "stopped" and state_b == "stopped":
            errors.append(f"pve-state.tsv: both HA VMs stopped at {epoch:.6f}")
            continue
        if state_a != "running" or state_b != "running":
            degraded += 1
            if not overlaps(epoch, epoch, windows):
                errors.append(
                    f"pve-state.tsv: HA VM stopped outside transition at {epoch:.6f}"
                )
    return {"rows": len(rows), "degraded_rows": degraded}


def verify_worker_stderr(evidence: Path, errors: list[str]) -> dict[str, int]:
    allowed = {"Terminated", "Killed"}
    expected_terminations = 0
    nonempty_files = 0
    for name in WORKER_STDERR_FILES:
        lines = [
            line.strip()
            for line in read_text(evidence / name, errors).splitlines()
            if line.strip()
        ]
        if lines:
            nonempty_files += 1
        for line in lines:
            if line in allowed:
                expected_terminations += 1
                continue
            errors.append(f"{name}: unexpected worker stderr: {line!r}")
    return {
        "files": len(WORKER_STDERR_FILES),
        "nonempty_files": nonempty_files,
        "expected_terminations": expected_terminations,
    }


def verify_empty_fault_artifacts(
    evidence: Path, transitions: list[dict[str, Any]], errors: list[str]
) -> dict[str, int]:
    kernel = sorted(evidence.glob("kernel-*.log"))
    pstore = sorted(evidence.glob("pstore-*.log"))
    minimum = 4 + len(transitions)
    if len(kernel) < minimum:
        errors.append(f"kernel fault artifacts={len(kernel)}, want at least {minimum}")
    if len(pstore) < minimum:
        errors.append(f"pstore artifacts={len(pstore)}, want at least {minimum}")
    for path in kernel + pstore:
        body = read_text(path, errors).strip()
        if body:
            errors.append(f"{path.name} is not empty")
    return {"kernel_logs": len(kernel), "pstore_logs": len(pstore)}


def verify_ready(path: Path, errors: list[str]) -> None:
    try:
        payload = json.loads(read_text(path, errors))
    except json.JSONDecodeError as exc:
        errors.append(f"{path.name}: invalid JSON: {exc}")
        return
    if payload.get("ready") is not True or payload.get("status") != "ready":
        errors.append(f"{path.name}: endpoint is not semantically ready")


def main() -> int:
    args = parse_args()
    evidence = args.evidence.resolve()
    errors: list[str] = []
    if not evidence.is_dir():
        print(json.dumps({"ok": False, "errors": [f"not a directory: {evidence}"]}))
        return 1
    if read_text(evidence / "result", errors).strip() != "runner_pass":
        errors.append("runner result is not runner_pass")
    manifest = read_manifest(evidence / "manifest.tsv", errors)
    if manifest.get("schema") != "trustix-pve-ha-full-kmod-soak-v1":
        errors.append(f"unexpected evidence schema: {manifest.get('schema')!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest.get("module_sha256", "")):
        errors.append("manifest module_sha256 is invalid")
    if not re.fullmatch(r"[0-9A-F]+", manifest.get("module_srcversion", "")):
        errors.append("manifest module_srcversion is invalid")
    if not re.fullmatch(
        r"trustix-ha-soak-[A-Za-z0-9._-]+", manifest.get("run_id", "")
    ):
        errors.append("manifest run_id is invalid")
    for prefix in ("remote", "client"):
        before = manifest.get(f"{prefix}_boot_before")
        after = manifest.get(f"{prefix}_boot_after")
        if not before or before != after:
            errors.append(f"{prefix} boot ID changed or is missing: {before!r} -> {after!r}")
    start_epoch = read_epoch(evidence / "start.epoch", errors)
    end_epoch = read_epoch(evidence / "end.epoch", errors)
    measured_duration = 0.0
    if start_epoch is not None and end_epoch is not None:
        measured_duration = end_epoch - start_epoch
        if measured_duration + args.duration_slop < args.min_duration:
            errors.append(
                f"duration={measured_duration:.3f}s, want at least {args.min_duration:.3f}s"
            )
    transitions = read_transitions(evidence / "transitions.tsv", errors)
    transition_summary = verify_transitions(
        transitions, start_epoch, end_epoch, args, errors
    )
    verify_manifest_ha_chain(manifest, transitions, errors)
    ping_summary = verify_ping(
        evidence / "ping.log", transitions, start_epoch, end_epoch, args, errors
    )
    traffic_summary = verify_traffic(
        evidence, transitions, start_epoch, end_epoch, args, errors
    )
    module_summary = verify_module_monitor(
        evidence / "remote-module.tsv",
        transitions,
        start_epoch,
        end_epoch,
        args,
        errors,
    )
    module_snapshot_summary = verify_module_snapshots(evidence, manifest, errors)
    pve_summary = verify_pve_state(
        evidence / "pve-state.tsv", transitions, start_epoch, end_epoch, args, errors
    )
    worker_stderr_summary = verify_worker_stderr(evidence, errors)
    artifact_summary = verify_empty_fault_artifacts(evidence, transitions, errors)
    verify_ready(evidence / "master-ready-after.json", errors)
    verify_ready(evidence / "remote-ready-after.json", errors)
    summary = {
        "schema": "trustix-pve-ha-full-kmod-soak-verification-v1",
        "ok": not errors,
        "evidence": str(evidence),
        "duration_seconds": measured_duration,
        "module_sha256": manifest.get("module_sha256", ""),
        "module_srcversion": manifest.get("module_srcversion", ""),
        "transitions": transition_summary,
        "ping": ping_summary,
        "traffic": traffic_summary,
        "module_monitor": module_summary,
        "module_snapshots": module_snapshot_summary,
        "pve_state": pve_summary,
        "worker_stderr": worker_stderr_summary,
        "artifacts": artifact_summary,
        "errors": errors,
    }
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
