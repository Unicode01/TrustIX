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
MIN_PRODUCTION_PASS_SECONDS = 3600
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
    parser.add_argument(
        "--os-matrix",
        help="override OS matrix; defaults to inferred os-release identities from gate summary",
    )
    parser.add_argument(
        "--kernel-matrix",
        help="override kernel matrix; defaults to inferred uname releases from gate summary",
    )
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


def metric_seconds_value(row: dict[str, Any]) -> float:
    value = row.get("min_seconds_required")
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    raise SystemExit(f"gate summary case {row.get('case')!r} lacks min_seconds_required")


def observed_seconds_value(row: dict[str, Any]) -> float:
    value = row.get("min_seconds")
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    raise SystemExit(f"gate summary case {row.get('case')!r} lacks measured min_seconds")


def seconds_slop_value(row: dict[str, Any]) -> float:
    value = row.get("seconds_slop")
    if value is None:
        return 0.0
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    raise SystemExit(f"gate summary case {row.get('case')!r} has invalid seconds_slop")


def format_metric_seconds(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")


def require_long_soak_for_pass(
    row: dict[str, Any],
    result: str,
    required_seconds: float,
    observed_seconds: float,
    seconds_slop: float,
) -> None:
    if result != "pass":
        return
    if required_seconds < MIN_PRODUCTION_PASS_SECONDS:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} pass evidence requires at least "
            f"{MIN_PRODUCTION_PASS_SECONDS}s production soak; got "
            f"{format_metric_seconds(required_seconds)}s"
        )
    if observed_seconds + seconds_slop >= required_seconds:
        return
    raise SystemExit(
        f"gate summary case {row.get('case')!r} measured soak is shorter than required: "
        f"min_seconds={format_metric_seconds(observed_seconds)}s + "
        f"seconds_slop={format_metric_seconds(seconds_slop)}s < "
        f"required={format_metric_seconds(required_seconds)}s"
    )


def numeric_field(
    row: dict[str, Any],
    key: str,
    context: str,
    *,
    case: str | None = None,
) -> float:
    value = row.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    case_name = case or str(row.get("case") or "")
    raise SystemExit(
        f"gate summary case {case_name!r} has invalid {context} {key}: {value!r}"
    )


def list_field(row: dict[str, Any], key: str) -> list[Any]:
    value = row.get(key)
    if isinstance(value, list):
        return value
    raise SystemExit(f"gate summary case {row.get('case')!r} lacks list field {key}")


def require_empty_list(row: dict[str, Any], key: str) -> None:
    values = list_field(row, key)
    if values:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has non-empty {key}: {values!r}"
        )


def require_min_list_items(row: dict[str, Any], key: str, minimum: int) -> None:
    values = list_field(row, key)
    if len(values) < minimum:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has {len(values)} {key}, "
            f"want >= {minimum}"
        )


def require_stable_boot_ids(row: dict[str, Any]) -> None:
    values = list_field(row, "boot_ids")
    by_node: dict[str, dict[str, set[str]]] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        node = str(item.get("node") or "")
        phase = str(item.get("phase") or "")
        boot_id = str(item.get("boot_id") or "")
        if not node or phase not in {"before", "after"} or not boot_id:
            continue
        by_node.setdefault(node, {}).setdefault(phase, set()).add(boot_id)
    complete = 0
    for node, phases in sorted(by_node.items()):
        before = phases.get("before") or set()
        after = phases.get("after") or set()
        if len(before) != 1 or before != after:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has unstable boot-id "
                f"for node {node}: before={sorted(before)} after={sorted(after)}"
            )
        complete += 1
    if complete < 2:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has stable boot-id coverage "
            f"for {complete} nodes, want >= 2"
        )


def require_run_timing_for_pass(
    row: dict[str, Any],
    result: str,
    required_seconds: float,
    seconds_slop: float,
) -> None:
    if result != "pass":
        return
    timings = list_field(row, "run_timing")
    if not timings:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has 0 run_timing artifacts, want >= 1"
        )
    for item in timings:
        if not isinstance(item, dict):
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has invalid run_timing item: {item!r}"
            )
        source = str(item.get("source") or "run_timing")
        for key, want in {
            "iperf_mode": "forward",
            "iperf_directions": "both",
        }.items():
            got = str(item.get(key) or "")
            if got != want:
                raise SystemExit(
                    f"gate summary case {row.get('case')!r} {source} {key}={got!r}, "
                    f"want {want!r}"
                )
        case = str(row.get("case") or "")
        start_epoch = numeric_field(item, "start_epoch", source, case=case)
        end_epoch = numeric_field(item, "end_epoch", source, case=case)
        elapsed = numeric_field(item, "elapsed_seconds", source, case=case)
        requested = numeric_field(item, "iperf_seconds_requested", source, case=case)
        if end_epoch < start_epoch:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {source} end_epoch "
                f"{format_metric_seconds(end_epoch)} < start_epoch "
                f"{format_metric_seconds(start_epoch)}"
            )
        computed_elapsed = end_epoch - start_epoch
        if abs(computed_elapsed - elapsed) > max(2.0, seconds_slop):
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {source} elapsed_seconds "
                f"{format_metric_seconds(elapsed)} does not match end-start "
                f"{format_metric_seconds(computed_elapsed)}"
            )
        if elapsed + seconds_slop < required_seconds:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {source} elapsed_seconds "
                f"{format_metric_seconds(elapsed)}s + "
                f"seconds_slop={format_metric_seconds(seconds_slop)}s < "
                f"required={format_metric_seconds(required_seconds)}s"
            )
        if requested + seconds_slop < required_seconds:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {source} "
                f"iperf_seconds_requested {format_metric_seconds(requested)}s + "
                f"seconds_slop={format_metric_seconds(seconds_slop)}s < "
                f"required={format_metric_seconds(required_seconds)}s"
            )


def require_crash_stability_for_pass(row: dict[str, Any], result: str) -> None:
    if result != "pass":
        return
    require_empty_list(row, "errors")
    require_empty_list(row, "log_findings")
    require_empty_list(row, "kernel_log_rejected_artifacts")
    require_empty_list(row, "pstore_rejected_artifacts")
    require_stable_boot_ids(row)
    require_min_list_items(row, "kernel_log_nodes", 2)
    require_min_list_items(row, "kernel_log_artifacts", 2)
    require_min_list_items(row, "pstore_nodes", 2)
    require_min_list_items(row, "pstore_artifacts", 2)


def normalize_matrix_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.+_-]+", "", value).lower()


def os_label(identity: str) -> str:
    if ":" in identity:
        os_id, version = identity.split(":", 1)
        return normalize_matrix_token(f"{os_id}{version}")
    return normalize_matrix_token(identity)


def stable_node_values(row: dict[str, Any], artifact_key: str, value_key: str) -> dict[str, str]:
    artifacts = row.get(artifact_key)
    if not isinstance(artifacts, list) or not artifacts:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} lacks {artifact_key}; "
            "rerun with the production gate so uname/os-release artifacts are required"
        )
    values: dict[str, dict[str, set[str]]] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        node = str(item.get("node") or "")
        phase = str(item.get("phase") or "")
        value = str(item.get(value_key) or "")
        if not node or phase not in {"before", "after"} or not value:
            continue
        values.setdefault(node, {}).setdefault(phase, set()).add(value)
    stable: dict[str, str] = {}
    for node, phases in sorted(values.items()):
        before = phases.get("before") or set()
        after = phases.get("after") or set()
        if len(before) != 1 or before != after:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has unstable {artifact_key} "
                f"for node {node}: before={sorted(before)} after={sorted(after)}"
            )
        stable[node] = next(iter(before))
    if len(stable) < 2:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has {len(stable)} stable {artifact_key} nodes, want >= 2"
        )
    return stable


def infer_os_matrix(row: dict[str, Any]) -> str:
    by_node = stable_node_values(row, "os_release_artifacts", "identity")
    return "-".join(os_label(by_node[node]) for node in sorted(by_node))


def infer_kernel_matrix(row: dict[str, Any]) -> str:
    by_node = stable_node_values(row, "uname_artifacts", "kernel_release")
    return "_to_".join(by_node[node] for node in sorted(by_node))


def resolved_matrix_value(
    row: dict[str, Any],
    *,
    override: str | None,
    inferred: str,
    label: str,
) -> str:
    if override and override != inferred:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} {label} override {override!r} "
            f"does not match inferred value {inferred!r}"
        )
    return override or inferred


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
    seconds = metric_seconds_value(gate_row)
    seconds_slop = seconds_slop_value(gate_row)
    require_long_soak_for_pass(
        gate_row,
        result,
        seconds,
        observed_seconds_value(gate_row),
        seconds_slop,
    )
    require_run_timing_for_pass(gate_row, result, seconds, seconds_slop)
    require_crash_stability_for_pass(gate_row, result)
    os_matrix = resolved_matrix_value(
        gate_row,
        override=args.os_matrix,
        inferred=infer_os_matrix(gate_row),
        label="OS matrix",
    )
    kernel_matrix = resolved_matrix_value(
        gate_row,
        override=args.kernel_matrix,
        inferred=infer_kernel_matrix(gate_row),
        label="kernel matrix",
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
        os_matrix,
        kernel_matrix,
        result,
        metric_gbps(gate_row),
        format_metric_seconds(seconds),
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
