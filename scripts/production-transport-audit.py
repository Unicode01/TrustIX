#!/usr/bin/env python3
"""Audit production transport defaults against recorded gate evidence."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


PRODUCTION_GATE_SCHEMA = "trustix-cross-host-production-gate-manifest-v1"
DEFAULT_COLUMNS = [
    "transport",
    "encryption",
    "profile",
    "datapath",
    "crypto_placement",
    "validation_scope",
    "gate_family",
    "min_gbps",
    "min_seconds",
    "note",
]
EVIDENCE_COLUMNS = [
    "gate_family",
    "transport",
    "encryption",
    "profile",
    "datapath",
    "crypto_placement",
    "validation_scope",
    "os_matrix",
    "kernel_matrix",
    "result",
    "min_gbps",
    "min_seconds",
    "gate_manifest_schema",
    "production_gate_sha256",
    "verifier_sha256",
    "artifact",
    "evidence_note",
]
KEY_FIELDS = [
    "transport",
    "encryption",
    "profile",
    "datapath",
    "crypto_placement",
    "validation_scope",
    "gate_family",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check that production transport defaults are backed by passing "
            "production gate evidence at or above each default threshold."
        )
    )
    parser.add_argument(
        "--defaults",
        default="production-transport-defaults.tsv",
        help="production defaults TSV",
    )
    parser.add_argument(
        "--evidence",
        default="production-transport-evidence.tsv",
        help="production evidence TSV",
    )
    parser.add_argument(
        "--scope",
        default="cross_host",
        help="validation_scope to audit; use 'all' to audit every scope",
    )
    parser.add_argument(
        "--require-manifest",
        action="store_true",
        help="only accept trustix-cross-host-production-gate-manifest-v1 evidence",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON instead of compact text",
    )
    parser.add_argument(
        "--fail-on-missing",
        action="store_true",
        help="exit nonzero if any audited default lacks matching evidence",
    )
    return parser.parse_args()


def read_tsv(path: Path, columns: list[str], min_fields: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = next(csv.reader([raw.rstrip("\n")], delimiter="\t"))
            if len(fields) < min_fields:
                raise SystemExit(f"{path}:{lineno}: expected >= {min_fields} TSV fields")
            row = {name: fields[idx] if idx < len(fields) else "" for idx, name in enumerate(columns)}
            if len(fields) > len(columns):
                row[columns[-1]] = "\t".join(fields[len(columns) - 1 :])
            row["_source_line"] = str(lineno)
            rows.append(row)
    return rows


def row_key(row: dict[str, str]) -> str:
    return ":".join(row[field] for field in KEY_FIELDS)


def parse_float(value: str, label: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise SystemExit(f"{label} must be numeric, got {value!r}") from exc


def parse_seconds(value: str, label: str) -> float:
    return parse_float(value, label)


def evidence_candidate(
    evidence: dict[str, str],
    default: dict[str, str],
    *,
    require_manifest: bool,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if evidence["result"] != "pass":
        reasons.append(f"result={evidence['result']}")
    if require_manifest and evidence["gate_manifest_schema"] != PRODUCTION_GATE_SCHEMA:
        reasons.append(f"schema={evidence['gate_manifest_schema']}")
    required_gbps = parse_float(default["min_gbps"], "default min_gbps")
    required_seconds = parse_seconds(default["min_seconds"], "default min_seconds")
    got_gbps = parse_float(evidence["min_gbps"], "evidence min_gbps")
    got_seconds = parse_seconds(evidence["min_seconds"], "evidence min_seconds")
    if got_gbps < required_gbps:
        reasons.append(f"min_gbps={got_gbps:.6f}<{required_gbps:.6f}")
    if got_seconds < required_seconds:
        reasons.append(f"min_seconds={got_seconds:g}<{required_seconds:g}")
    return not reasons, reasons


def compact_evidence(row: dict[str, str], reasons: list[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "os_matrix": row["os_matrix"],
        "kernel_matrix": row["kernel_matrix"],
        "result": row["result"],
        "min_gbps": row["min_gbps"],
        "min_seconds": row["min_seconds"],
        "gate_manifest_schema": row["gate_manifest_schema"],
        "artifact": row["artifact"],
    }
    if reasons:
        out["reasons"] = reasons
    return out


def audit(args: argparse.Namespace) -> list[dict[str, Any]]:
    defaults = read_tsv(Path(args.defaults), DEFAULT_COLUMNS, 9)
    evidence_rows = read_tsv(Path(args.evidence), EVIDENCE_COLUMNS, 17)
    evidence_by_key: dict[str, list[dict[str, str]]] = {}
    for evidence in evidence_rows:
        evidence_by_key.setdefault(row_key(evidence), []).append(evidence)

    results: list[dict[str, Any]] = []
    for default in defaults:
        if args.scope != "all" and default["validation_scope"] != args.scope:
            continue
        candidates = evidence_by_key.get(row_key(default), [])
        accepted: list[dict[str, str]] = []
        rejected: list[dict[str, Any]] = []
        for candidate in candidates:
            ok, reasons = evidence_candidate(
                candidate,
                default,
                require_manifest=args.require_manifest,
            )
            if ok:
                accepted.append(candidate)
            elif len(rejected) < 5:
                rejected.append(compact_evidence(candidate, reasons))
        accepted.sort(
            key=lambda row: (
                parse_seconds(row["min_seconds"], "evidence min_seconds"),
                int(row["_source_line"]),
                parse_float(row["min_gbps"], "evidence min_gbps"),
            ),
            reverse=True,
        )
        result: dict[str, Any] = {
            "status": "pass" if accepted else "missing",
            "key": row_key(default),
            "default": {
                field: default[field]
                for field in DEFAULT_COLUMNS
                if field in default and field != "note"
            },
            "source_line": int(default["_source_line"]),
        }
        if accepted:
            result["evidence"] = compact_evidence(accepted[0])
        if rejected:
            result["rejected_candidates"] = rejected
        results.append(result)
    return results


def emit_text(results: list[dict[str, Any]]) -> None:
    for row in results:
        evidence = row.get("evidence") or {}
        print(
            "\t".join(
                [
                    row["status"],
                    row["key"],
                    str(evidence.get("min_gbps", "")),
                    str(evidence.get("min_seconds", "")),
                    str(evidence.get("gate_manifest_schema", "")),
                    str(evidence.get("artifact", "")),
                ]
            )
        )


def main() -> int:
    args = parse_args()
    results = audit(args)
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        emit_text(results)
    missing = [row for row in results if row["status"] != "pass"]
    if args.fail_on_missing and missing:
        print(
            f"production transport audit failed: {len(missing)} default(s) lack matching evidence",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
