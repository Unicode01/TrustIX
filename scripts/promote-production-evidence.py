#!/usr/bin/env python3
"""Promote generated production gate evidence into TrustIX evidence TSVs."""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


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
    "runner_sha256",
    "transport_matrix_sha256",
    "evidence_generator_sha256",
]
CURRENT_COLUMNS = [
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
    "runner_sha256",
    "transport_matrix_sha256",
    "evidence_generator_sha256",
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
            "Append generated production evidence rows and replace matching "
            "current evidence requirement rows."
        )
    )
    parser.add_argument("--generated", required=True, help="generated evidence.tsv")
    parser.add_argument(
        "--defaults",
        default="production-transport-defaults.tsv",
        help="production defaults TSV",
    )
    parser.add_argument(
        "--evidence",
        default="production-transport-evidence.tsv",
        help="production evidence TSV to append",
    )
    parser.add_argument(
        "--current",
        default="production-transport-current-evidence.tsv",
        help="current evidence requirement TSV to update",
    )
    parser.add_argument("--dry-run", action="store_true", help="validate and print actions only")
    parser.add_argument(
        "--skip-post-audit",
        action="store_true",
        help="skip strict production-transport-audit.py validation of the updated TSVs",
    )
    return parser.parse_args()


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or path.exists():
        return path
    script_relative = script_dir() / path
    if script_relative.exists():
        return script_relative
    return path


def read_tsv(path: Path, columns: list[str], min_fields: int) -> tuple[list[str], list[dict[str, str]]]:
    comments: list[str] = []
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.rstrip("\n")
            if not line:
                comments.append(raw)
                continue
            if line.startswith("#"):
                comments.append(raw)
                continue
            fields = next(csv.reader([line], delimiter="\t"))
            if len(fields) < min_fields:
                raise SystemExit(f"{path}:{lineno}: expected >= {min_fields} TSV fields")
            row = {name: fields[idx] if idx < len(fields) else "" for idx, name in enumerate(columns)}
            if len(fields) > len(columns):
                row[columns[-1]] = "\t".join(fields[len(columns) - 1 :])
            row["_raw"] = line
            row["_source_line"] = str(lineno)
            rows.append(row)
    return comments, rows


def write_tsv(path: Path, comments: list[str], rows: list[dict[str, str]], columns: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as handle:
        for comment in comments:
            handle.write(comment if comment.endswith("\n") else comment + "\n")
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        for row in rows:
            raw = row.get("_preserve_raw")
            if raw:
                handle.write(raw)
                handle.write("\n")
                continue
            writer.writerow([row.get(column, "") for column in columns])
    tmp.replace(path)


def append_raw_rows(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    needs_newline = False
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            if handle.tell() > 0:
                handle.seek(-1, 2)
                needs_newline = handle.read(1) != b"\n"
    except FileNotFoundError as exc:
        raise SystemExit(f"{path}: evidence file does not exist") from exc

    with path.open("a", encoding="utf-8", newline="") as handle:
        if needs_newline:
            handle.write("\n")
        for row in rows:
            handle.write(row["_raw"])
            handle.write("\n")


def key(row: dict[str, str]) -> str:
    return ":".join(row[field] for field in KEY_FIELDS)


def to_float(value: str, label: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise SystemExit(f"{label} must be numeric, got {value!r}") from exc


def evidence_to_current(row: dict[str, str]) -> dict[str, str]:
    return {
        "transport": row["transport"],
        "encryption": row["encryption"],
        "profile": row["profile"],
        "datapath": row["datapath"],
        "crypto_placement": row["crypto_placement"],
        "validation_scope": row["validation_scope"],
        "gate_family": row["gate_family"],
        "os_matrix": row["os_matrix"],
        "kernel_matrix": row["kernel_matrix"],
        "gate_manifest_schema": row["gate_manifest_schema"],
        "production_gate_sha256": row["production_gate_sha256"],
        "verifier_sha256": row["verifier_sha256"],
        "artifact": row["artifact"],
        "note": row["evidence_note"],
        "binary_sha256": row["binary_sha256"],
        "build_version": row["build_version"],
        "build_commit": row["build_commit"],
        "build_built_at": row["build_built_at"],
        "build_go_version": row["build_go_version"],
        "runner_sha256": row["runner_sha256"],
        "transport_matrix_sha256": row["transport_matrix_sha256"],
        "evidence_generator_sha256": row["evidence_generator_sha256"],
    }


def validate_generated(
    rows: list[dict[str, str]],
    defaults_by_key: dict[str, dict[str, str]],
    current_by_key: dict[str, dict[str, str]],
) -> None:
    if not rows:
        raise SystemExit("generated evidence contains no rows")
    seen: set[str] = set()
    for row in rows:
        row_key = key(row)
        if row_key in seen:
            raise SystemExit(f"generated evidence contains duplicate key {row_key}")
        seen.add(row_key)
        if row_key not in defaults_by_key:
            raise SystemExit(f"generated evidence key is not a production default: {row_key}")
        if row_key not in current_by_key:
            raise SystemExit(f"generated evidence key has no current requirement row: {row_key}")
        if row["result"] != "pass":
            raise SystemExit(f"{row_key}: result must be pass, got {row['result']!r}")
        if row["gate_manifest_schema"] != PRODUCTION_GATE_SCHEMA:
            raise SystemExit(f"{row_key}: gate_manifest_schema must be {PRODUCTION_GATE_SCHEMA}")
        default = defaults_by_key[row_key]
        got_gbps = to_float(row["min_gbps"], f"{row_key} evidence min_gbps")
        want_gbps = to_float(default["min_gbps"], f"{row_key} default min_gbps")
        got_seconds = to_float(row["min_seconds"], f"{row_key} evidence min_seconds")
        want_seconds = to_float(default["min_seconds"], f"{row_key} default min_seconds")
        if got_gbps < want_gbps:
            raise SystemExit(f"{row_key}: evidence min_gbps {got_gbps} < default {want_gbps}")
        if got_seconds < want_seconds:
            raise SystemExit(f"{row_key}: evidence min_seconds {got_seconds:g} < default {want_seconds:g}")
        for field in (
            "production_gate_sha256",
            "verifier_sha256",
            "binary_sha256",
            "build_version",
            "build_commit",
            "build_built_at",
            "build_go_version",
            "runner_sha256",
            "transport_matrix_sha256",
            "evidence_generator_sha256",
        ):
            if not row[field].strip():
                raise SystemExit(f"{row_key}: generated evidence field {field} is empty")


def run_post_audit(
    defaults_path: Path,
    evidence_path: Path,
    current_comments: list[str],
    updated_current_rows: list[dict[str, str]],
    append_rows: list[dict[str, str]],
) -> None:
    audit_path = script_dir() / "production-transport-audit.py"
    if not audit_path.exists():
        raise SystemExit(f"{audit_path}: production audit script not found")

    with tempfile.TemporaryDirectory(prefix="trustix-promote-evidence.") as temp:
        temp_dir = Path(temp)
        temp_evidence = temp_dir / "production-transport-evidence.tsv"
        temp_current = temp_dir / "production-transport-current-evidence.tsv"
        shutil.copyfile(evidence_path, temp_evidence)
        append_raw_rows(temp_evidence, append_rows)
        write_tsv(temp_current, current_comments, updated_current_rows, CURRENT_COLUMNS)

        cmd = [
            sys.executable,
            str(audit_path),
            "--scope",
            "cross_host",
            "--require-manifest",
            "--require-current",
            "--require-artifact-reference",
            "--require-current-build-ancestor",
            "--require-current-gate-tools",
            "--require-current-runtime-tree",
            "--fail-on-missing",
            "--defaults",
            str(defaults_path),
            "--evidence",
            str(temp_evidence),
            "--current-requirements",
            str(temp_current),
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(script_dir()),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if completed.returncode != 0:
            output = completed.stdout.strip()
            if len(output) > 6000:
                output = output[-6000:]
            raise SystemExit("post-promotion strict audit failed:\n" + output)


def main() -> int:
    args = parse_args()
    generated_path = resolve_path(args.generated)
    defaults_path = resolve_path(args.defaults)
    evidence_path = resolve_path(args.evidence)
    current_path = resolve_path(args.current)

    _, defaults = read_tsv(defaults_path, DEFAULT_COLUMNS, 9)
    evidence_comments, evidence_rows = read_tsv(evidence_path, EVIDENCE_COLUMNS, 17)
    current_comments, current_rows = read_tsv(current_path, CURRENT_COLUMNS, 19)
    _, generated = read_tsv(generated_path, EVIDENCE_COLUMNS, 17)

    defaults_by_key = {key(row): row for row in defaults if row["validation_scope"] == "cross_host"}
    current_by_key = {key(row): row for row in current_rows}
    validate_generated(generated, defaults_by_key, current_by_key)

    existing_raw = {row["_raw"] for row in evidence_rows}
    append_rows = [row for row in generated if row["_raw"] not in existing_raw]
    replace_by_key = {key(row): evidence_to_current(row) for row in generated}
    updated_current_rows = []
    for row in current_rows:
        replacement = replace_by_key.get(key(row))
        if replacement:
            updated_current_rows.append(replacement)
            continue
        preserved = dict(row)
        preserved["_preserve_raw"] = row["_raw"]
        updated_current_rows.append(preserved)

    print(f"generated_rows={len(generated)}")
    print(f"append_evidence_rows={len(append_rows)}")
    print("replace_current_keys=" + ",".join(sorted(replace_by_key)))
    if not args.skip_post_audit:
        run_post_audit(
            defaults_path,
            evidence_path,
            current_comments,
            updated_current_rows,
            append_rows,
        )
        print("post_audit=pass")
    if args.dry_run:
        return 0

    append_raw_rows(evidence_path, append_rows)
    write_tsv(current_path, current_comments, updated_current_rows, CURRENT_COLUMNS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
