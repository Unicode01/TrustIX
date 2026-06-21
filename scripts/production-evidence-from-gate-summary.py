#!/usr/bin/env python3
"""Emit production transport evidence rows from selected-gate summaries."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "trustix-cross-host-production-gate-manifest-v1"
COLUMNS = [
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
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert linux-cross-host-transport-matrix summary.jsonl plus "
            "selected production-gate summary files into production evidence TSV rows."
        )
    )
    parser.add_argument("--matrix-summary", required=True, help="matrix summary.jsonl")
    parser.add_argument(
        "--gate-summary-dir",
        required=True,
        help="directory containing production-gate-manifest.json and verifier *.jsonl summaries",
    )
    parser.add_argument("--os-matrix", required=True)
    parser.add_argument("--kernel-matrix", required=True)
    parser.add_argument(
        "--artifact",
        required=True,
        help="local docs markdown anchor, for example docs/trustix-performance-log.md#run-id",
    )
    parser.add_argument(
        "--note-template",
        default="{case} production gate evidence",
        help="Python format string using case, runner_case, transport, encryption, profile, datapath, crypto_placement, gate_family",
    )
    parser.add_argument(
        "--include-fail",
        action="store_true",
        help="also emit verifier failures as result=fail; pass rows are emitted by default",
    )
    parser.add_argument(
        "--header",
        action="store_true",
        help="emit a TSV header comment before evidence rows",
    )
    return parser.parse_args()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno}: invalid JSONL row: {exc}") from exc
            if not isinstance(value, dict):
                raise SystemExit(f"{path}:{lineno}: JSONL row is not an object")
            rows.append(value)
    return rows


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise SystemExit(f"{label} must be a 64-character lowercase SHA256")
    return value


def load_manifest(gate_summary_dir: Path) -> dict[str, str]:
    manifest_path = gate_summary_dir / "production-gate-manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"missing production gate manifest: {manifest_path}")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise SystemExit(f"{manifest_path}: manifest is not an object")
    if manifest.get("schema") != SCHEMA:
        raise SystemExit(
            f"{manifest_path}: schema={manifest.get('schema')!r}, want {SCHEMA!r}"
        )
    production_gate = manifest.get("production_gate")
    verifier = manifest.get("verifier")
    if not isinstance(production_gate, dict) or not isinstance(verifier, dict):
        raise SystemExit(f"{manifest_path}: manifest lacks production_gate/verifier objects")
    return {
        "schema": SCHEMA,
        "production_gate_sha256": require_sha256(
            production_gate.get("sha256"), "production_gate.sha256"
        ),
        "verifier_sha256": require_sha256(verifier.get("sha256"), "verifier.sha256"),
    }


def load_matrix_rows(path: Path) -> dict[str, dict[str, Any]]:
    rows_by_case: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        case = str(row.get("case") or "")
        if not case:
            raise SystemExit(f"{path}: matrix row lacks case: {row}")
        if case in rows_by_case:
            raise SystemExit(f"{path}: duplicate matrix case {case!r}")
        rows_by_case[case] = row
    return rows_by_case


def load_gate_rows(gate_summary_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(gate_summary_dir.glob("*.jsonl")):
        rows.extend(read_jsonl(path))
    if not rows:
        raise SystemExit(f"no gate verifier JSONL summaries found in {gate_summary_dir}")
    return rows


def evidence_result(status: Any, include_fail: bool) -> str | None:
    if status == "pass":
        return "pass"
    if status == "fail" and include_fail:
        return "fail"
    return None


def metric_gbps(row: dict[str, Any]) -> str:
    for key in ("min_required_received_gbps", "min_received_gbps"):
        value = row.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return f"{float(value):.6f}"
    raise SystemExit(
        f"gate summary case {row.get('case')!r} lacks positive measured received throughput"
    )


def metric_seconds(row: dict[str, Any]) -> str:
    value = row.get("min_seconds_required")
    if isinstance(value, (int, float)) and value > 0:
        as_float = float(value)
        if as_float.is_integer():
            return str(int(as_float))
        return f"{as_float:.6f}".rstrip("0").rstrip(".")
    raise SystemExit(f"gate summary case {row.get('case')!r} lacks min_seconds_required")


def validate_artifact(value: str) -> None:
    if not value.startswith("docs/") or "#" not in value:
        raise SystemExit("--artifact must be a local docs markdown anchor")


def tsv_escape(value: Any) -> str:
    text = str(value)
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def evidence_row(
    *,
    gate_row: dict[str, Any],
    matrix_row: dict[str, Any],
    manifest: dict[str, str],
    args: argparse.Namespace,
    result: str,
) -> list[str]:
    if matrix_row.get("status") != "pass":
        raise SystemExit(
            f"gate summary case {gate_row.get('case')!r} matched non-pass matrix row: "
            f"{matrix_row.get('status')!r}"
        )
    note = args.note_template.format(**{key: str(matrix_row.get(key) or "") for key in [
        "case",
        "runner_case",
        "transport",
        "encryption",
        "profile",
        "datapath",
        "crypto_placement",
        "gate_family",
    ]})
    return [
        str(matrix_row.get("gate_family") or ""),
        str(matrix_row.get("transport") or ""),
        str(matrix_row.get("encryption") or ""),
        str(matrix_row.get("profile") or ""),
        str(matrix_row.get("datapath") or ""),
        str(matrix_row.get("crypto_placement") or ""),
        str(matrix_row.get("validation_scope") or ""),
        args.os_matrix,
        args.kernel_matrix,
        result,
        metric_gbps(gate_row),
        metric_seconds(gate_row),
        manifest["schema"],
        manifest["production_gate_sha256"],
        manifest["verifier_sha256"],
        args.artifact,
        note,
    ]


def main() -> int:
    args = parse_args()
    validate_artifact(args.artifact)
    matrix_rows = load_matrix_rows(Path(args.matrix_summary))
    gate_summary_dir = Path(args.gate_summary_dir)
    manifest = load_manifest(gate_summary_dir)
    gate_rows = load_gate_rows(gate_summary_dir)

    output_rows: list[list[str]] = []
    seen: set[str] = set()
    for gate_row in gate_rows:
        result = evidence_result(gate_row.get("status"), args.include_fail)
        if result is None:
            continue
        case = str(gate_row.get("case") or "")
        if not case:
            raise SystemExit(f"gate summary row lacks case: {gate_row}")
        if case in seen:
            raise SystemExit(f"duplicate gate summary case {case!r}")
        seen.add(case)
        matrix_row = matrix_rows.get(case)
        if matrix_row is None:
            raise SystemExit(f"gate summary case {case!r} not found in matrix summary")
        output_rows.append(
            evidence_row(
                gate_row=gate_row,
                matrix_row=matrix_row,
                manifest=manifest,
                args=args,
                result=result,
            )
        )

    if not output_rows:
        raise SystemExit("no passing gate summary rows produced evidence")
    if args.header:
        print("# " + "\t".join(COLUMNS))
    for row in output_rows:
        print("\t".join(tsv_escape(value) for value in row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
