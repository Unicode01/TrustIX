#!/usr/bin/env python3
"""Audit production transport defaults against recorded gate evidence."""

from __future__ import annotations

import argparse
import csv
import json
import re
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
    "binary_sha256",
    "build_version",
    "build_commit",
    "build_built_at",
    "build_go_version",
]
CURRENT_REQUIREMENT_COLUMNS = [
    "transport",
    "encryption",
    "profile",
    "datapath",
    "crypto_placement",
    "validation_scope",
    "gate_family",
    "os_matrix",
    "kernel_matrix",
    "gate_manifest_schema",
    "production_gate_sha256",
    "verifier_sha256",
    "artifact",
    "note",
    "binary_sha256",
    "build_version",
    "build_commit",
    "build_built_at",
    "build_go_version",
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
CURRENT_IDENTITY_FIELDS = [
    "os_matrix",
    "kernel_matrix",
    "gate_manifest_schema",
    "production_gate_sha256",
    "verifier_sha256",
    "artifact",
    "binary_sha256",
    "build_version",
    "build_commit",
    "build_built_at",
    "build_go_version",
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
        "--require-current",
        action="store_true",
        help=(
            "only accept evidence matching production-transport-current-evidence.tsv "
            "for each audited default"
        ),
    )
    parser.add_argument(
        "--require-artifact-reference",
        action="store_true",
        help="only accept evidence whose local markdown artifact path and anchor exist",
    )
    parser.add_argument(
        "--current-requirements",
        default="",
        help=(
            "current evidence requirement TSV; defaults to "
            "production-transport-current-evidence.tsv beside --defaults"
        ),
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
    if not path.exists():
        raise SystemExit(f"{path}: file not found")
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
        "production_gate_sha256": row["production_gate_sha256"],
        "verifier_sha256": row["verifier_sha256"],
        "artifact": row["artifact"],
        "binary_sha256": row["binary_sha256"],
        "build_version": row["build_version"],
        "build_commit": row["build_commit"],
        "build_built_at": row["build_built_at"],
        "build_go_version": row["build_go_version"],
    }
    if reasons:
        out["reasons"] = reasons
    return out


def compact_current_requirement(row: dict[str, str]) -> dict[str, str]:
    return {
        "os_matrix": row["os_matrix"],
        "kernel_matrix": row["kernel_matrix"],
        "gate_manifest_schema": row["gate_manifest_schema"],
        "production_gate_sha256": row["production_gate_sha256"],
        "verifier_sha256": row["verifier_sha256"],
        "artifact": row["artifact"],
        "binary_sha256": row["binary_sha256"],
        "build_version": row["build_version"],
        "build_commit": row["build_commit"],
        "build_built_at": row["build_built_at"],
        "build_go_version": row["build_go_version"],
    }


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def resolve_input_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or path.exists():
        return path
    script_relative = script_dir() / path
    if script_relative.exists():
        return script_relative
    return path


def current_requirements_path(args: argparse.Namespace, defaults_path: Path) -> Path:
    if args.current_requirements:
        return resolve_input_path(args.current_requirements)
    return defaults_path.with_name("production-transport-current-evidence.tsv")


def repo_root() -> Path:
    return script_dir().parent


def path_is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def markdown_anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    anchors: set[str] = set()
    for match in re.finditer(r"""<a\s+(?:[^>]*?\s)?(?:id|name)=["']([^"']+)["']""", text):
        anchors.add(match.group(1))
    return anchors


def artifact_reference_errors(artifact: str) -> list[str]:
    artifact = artifact.strip()
    if not artifact:
        return ["artifact is empty"]
    if "://" in artifact:
        return [f"artifact={artifact!r} is not a local markdown reference"]
    path_part, sep, anchor = artifact.partition("#")
    if sep == "" or not path_part or not anchor:
        return [f"artifact={artifact!r} must be path.md#anchor"]
    artifact_path = Path(path_part)
    if artifact_path.is_absolute():
        return [f"artifact path {path_part!r} must be repo-relative"]
    root = repo_root().resolve()
    resolved = (root / artifact_path).resolve()
    if not path_is_relative_to(resolved, root):
        return [f"artifact path {path_part!r} escapes repo root"]
    if resolved.suffix.lower() != ".md":
        return [f"artifact path {path_part!r} must be markdown"]
    if not resolved.exists():
        return [f"artifact path {path_part!r} does not exist"]
    if anchor not in markdown_anchors(resolved):
        return [f"artifact anchor {anchor!r} not found in {path_part!r}"]
    return []


def read_current_requirements(args: argparse.Namespace, defaults_path: Path) -> dict[str, dict[str, str]]:
    rows = read_tsv(
        current_requirements_path(args, defaults_path),
        CURRENT_REQUIREMENT_COLUMNS,
        len(CURRENT_REQUIREMENT_COLUMNS),
    )
    requirements: dict[str, dict[str, str]] = {}
    for row in rows:
        key = row_key(row)
        if key in requirements:
            raise SystemExit(f"duplicate current evidence requirement for {key}")
        requirements[key] = row
    return requirements


def audit(args: argparse.Namespace) -> list[dict[str, Any]]:
    defaults_path = resolve_input_path(args.defaults)
    evidence_path = resolve_input_path(args.evidence)
    defaults = read_tsv(defaults_path, DEFAULT_COLUMNS, 9)
    evidence_rows = read_tsv(evidence_path, EVIDENCE_COLUMNS, 17)
    current_requirements = read_current_requirements(args, defaults_path) if args.require_current else {}
    audited_defaults = [
        default
        for default in defaults
        if args.scope == "all" or default["validation_scope"] == args.scope
    ]
    if args.require_current:
        audited_keys = {row_key(default) for default in audited_defaults}
        requirement_keys = set(current_requirements)
        missing_requirements = sorted(audited_keys - requirement_keys)
        extra_requirements = sorted(requirement_keys - audited_keys)
        if missing_requirements or extra_requirements:
            raise SystemExit(
                "current evidence requirements do not match audited defaults: "
                f"missing={missing_requirements} extra={extra_requirements}"
            )
    evidence_by_key: dict[str, list[dict[str, str]]] = {}
    for evidence in evidence_rows:
        evidence_by_key.setdefault(row_key(evidence), []).append(evidence)

    results: list[dict[str, Any]] = []
    for default in audited_defaults:
        current_requirement = current_requirements.get(row_key(default))
        candidates = evidence_by_key.get(row_key(default), [])
        accepted: list[dict[str, str]] = []
        rejected: list[dict[str, Any]] = []
        for candidate in candidates:
            ok, reasons = evidence_candidate(
                candidate,
                default,
                require_manifest=args.require_manifest,
            )
            if ok and args.require_current:
                if current_requirement is None:
                    reasons.append("missing current evidence requirement")
                    ok = False
                else:
                    for field in CURRENT_IDENTITY_FIELDS:
                        if candidate[field] != current_requirement[field]:
                            reasons.append(f"{field}={candidate[field]!r}!={current_requirement[field]!r}")
                    ok = not reasons
            if ok and args.require_artifact_reference:
                reasons.extend(artifact_reference_errors(candidate["artifact"]))
                ok = not reasons
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
        if current_requirement is not None:
            result["current_requirement"] = compact_current_requirement(current_requirement)
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


def emit_missing_diagnostics(missing: list[dict[str, Any]]) -> None:
    for row in missing:
        for rejected in row.get("rejected_candidates") or []:
            reasons = rejected.get("reasons") or []
            if not reasons:
                continue
            print(
                "\t".join(["rejected", row["key"], "; ".join(str(reason) for reason in reasons)]),
                file=sys.stderr,
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
        emit_missing_diagnostics(missing)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
