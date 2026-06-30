#!/usr/bin/env python3
"""Audit production transport defaults against recorded gate evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


PRODUCTION_GATE_SCHEMA = "trustix-cross-host-production-gate-manifest-v1"
LEGACY_GATE_SCHEMA = "legacy-pre-manifest"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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
CURRENT_RUNTIME_TREE_PATHS = [
    "cmd",
    "internal",
    "kernel",
    "configs",
    "go.mod",
    "go.sum",
    "scripts/build-embedded-bpf.sh",
    "scripts/build-release-linux.sh",
    "scripts/trustix-build.sh",
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
        "--require-current-build-ancestor",
        action="store_true",
        help=(
            "require current evidence build_commit values to resolve in this "
            "repository and be ancestors of HEAD"
        ),
    )
    parser.add_argument(
        "--require-current-gate-tools",
        action="store_true",
        help=(
            "require current evidence production_gate_sha256/verifier_sha256 "
            "to match the current repository production gate and verifier scripts"
        ),
    )
    parser.add_argument(
        "--require-current-runtime-tree",
        action="store_true",
        help=(
            "require current evidence build_commit..HEAD to have no changes "
            "under TrustIX runtime/dataplane/build input paths"
        ),
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


def gate_family_class(gate_family: str) -> str:
    if gate_family in {
        "full_kmod",
        "dd_full_kmod",
        "owdeb_full_kmod",
    }:
        return "full_kmod"
    if gate_family in {
        "exp_tcp_full_kmod",
        "dd_exp_tcp_full_kmod",
        "owdeb_exp_tcp_full_kmod",
    }:
        return "exp_tcp_full_kmod"
    if gate_family in {"secure_kudp", "dd_secure_kudp", "owdeb_secure_kudp"}:
        return "secure_kudp"
    if gate_family in {
        "secure_exp_tcp_kernel",
        "dd_secure_exp_tcp_kernel",
        "owdeb_secure_exp_tcp_kernel",
    }:
        return "secure_exp_tcp_kernel"
    if gate_family in {"route_gso", "dd_route_gso", "owdeb_route_gso"}:
        return "route_gso"
    return gate_family


def gate_family_semantic_errors(row: dict[str, str]) -> list[str]:
    errors: list[str] = []
    gate_family = row["gate_family"]
    gate_class = gate_family_class(gate_family)
    transport = row["transport"]
    encryption = row["encryption"]
    datapath = row["datapath"]
    placement = row["crypto_placement"]

    def require(field: str, got: str, want: str) -> None:
        if got != want:
            errors.append(f"gate_family={gate_family} requires {field}={want}; got {field}={got}")

    def require_transport(*allowed: str) -> None:
        if transport not in allowed:
            errors.append(f"gate_family={gate_family} does not allow transport={transport}")

    if gate_class == "userspace":
        require_transport("udp", "tcp", "quic", "websocket", "http_connect", "experimental_tcp")
        require("datapath", datapath, "userspace")
        require("crypto_placement", placement, "userspace")
    elif gate_class == "userspace_tc":
        require_transport("gre", "ipip", "vxlan")
        require("datapath", datapath, "tc_xdp")
        require("crypto_placement", placement, "userspace")
    elif gate_class == "tc_direct":
        require("transport", transport, "kernel_udp")
        require("encryption", encryption, "plaintext")
        require("datapath", datapath, "tc_xdp")
        require("crypto_placement", placement, "userspace")
    elif gate_class == "full_kmod":
        require("transport", transport, "udp")
        require("encryption", encryption, "plaintext")
        require("datapath", datapath, "kernel_module")
        require("crypto_placement", placement, "userspace")
    elif gate_class == "exp_tcp_full_kmod":
        require("transport", transport, "experimental_tcp")
        require("encryption", encryption, "plaintext")
        require("datapath", datapath, "kernel_module")
        require("crypto_placement", placement, "userspace")
    elif gate_class == "secure_kudp":
        require("transport", transport, "kernel_udp")
        require("encryption", encryption, "secure")
        require("datapath", datapath, "tc_xdp")
        require("crypto_placement", placement, "kernel")
    elif gate_class == "secure_exp_tcp_kernel":
        require("transport", transport, "experimental_tcp")
        require("encryption", encryption, "secure")
        require("datapath", datapath, "kernel_module")
        require("crypto_placement", placement, "kernel")
    elif gate_class == "route_gso":
        require("transport", transport, "experimental_tcp")
        require("encryption", encryption, "plaintext")
        require("datapath", datapath, "kernel_module")
        require("crypto_placement", placement, "userspace")
    else:
        errors.append(f"unsupported gate_family={gate_family}")
    return errors


def validate_gate_family_semantics(rows: list[dict[str, str]], label: str) -> None:
    for row in rows:
        errors = gate_family_semantic_errors(row)
        if errors:
            raise SystemExit(f"{label}:{row['_source_line']}: " + "; ".join(errors))


def current_requirement_identity_errors(row: dict[str, str]) -> list[str]:
    errors: list[str] = []
    if row["gate_manifest_schema"] != PRODUCTION_GATE_SCHEMA:
        errors.append(
            f"gate_manifest_schema must be {PRODUCTION_GATE_SCHEMA}; got {row['gate_manifest_schema']!r}"
        )
    for field in ("production_gate_sha256", "verifier_sha256", "binary_sha256"):
        value = row[field]
        if not SHA256_RE.fullmatch(value):
            errors.append(f"{field} must be 64 lowercase hex; got {value!r}")
    for field in ("build_version", "build_commit", "build_built_at", "build_go_version"):
        value = row[field].strip()
        if not value or value == LEGACY_GATE_SCHEMA:
            errors.append(f"{field} must be non-empty current build metadata; got {row[field]!r}")
    return errors


def validate_current_requirement_identity(
    rows: list[dict[str, str]],
    label: str,
    *,
    require_artifact_reference: bool,
    require_build_ancestor: bool,
    require_current_gate_tools: bool,
    require_current_runtime_tree: bool,
) -> None:
    for row in rows:
        errors = current_requirement_identity_errors(row)
        if require_artifact_reference:
            errors.extend(artifact_reference_errors(row["artifact"]))
        if require_build_ancestor:
            errors.extend(build_commit_ancestor_errors(row["build_commit"]))
        if require_current_runtime_tree:
            errors.extend(current_runtime_tree_errors(row["build_commit"]))
        if require_current_gate_tools:
            errors.extend(current_gate_tool_identity_errors(row))
        if errors:
            raise SystemExit(f"{label}:{row['_source_line']}: " + "; ".join(errors))


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


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_gate_tool_identity_errors(row: dict[str, str]) -> list[str]:
    root = repo_root()
    gate_path = root / "scripts" / "linux-cross-host-production-gate.sh"
    verifier_path = root / "scripts" / "linux-cross-host-soak-verify.py"
    want_gate_sha = file_sha256(gate_path)
    want_verifier_sha = file_sha256(verifier_path)
    errors: list[str] = []
    if row["production_gate_sha256"] != want_gate_sha:
        errors.append(
            "production_gate_sha256 must match current "
            f"scripts/linux-cross-host-production-gate.sh sha256 {want_gate_sha}; "
            f"got {row['production_gate_sha256']!r}"
        )
    if row["verifier_sha256"] != want_verifier_sha:
        errors.append(
            "verifier_sha256 must match current "
            f"scripts/linux-cross-host-soak-verify.py sha256 {want_verifier_sha}; "
            f"got {row['verifier_sha256']!r}"
        )
    return errors


def run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_root()), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def build_commit_ancestor_errors(build_commit: str) -> list[str]:
    value = build_commit.strip()
    if not value or value == LEGACY_GATE_SCHEMA:
        return []
    try:
        resolved = run_git(["rev-parse", "--verify", f"{value}^{{commit}}"])
    except FileNotFoundError:
        return ["build_commit cannot be verified because git is not installed"]
    if resolved.returncode != 0:
        detail = (resolved.stderr or resolved.stdout).strip()
        suffix = f": {detail}" if detail else ""
        return [f"build_commit={value!r} must resolve to a commit in this repository{suffix}"]
    resolved_commit = resolved.stdout.strip()
    ancestor = run_git(["merge-base", "--is-ancestor", resolved_commit, "HEAD"])
    if ancestor.returncode != 0:
        detail = (ancestor.stderr or ancestor.stdout).strip()
        suffix = f": {detail}" if detail else ""
        return [
            f"build_commit={value!r} ({resolved_commit}) must be an ancestor of HEAD{suffix}"
        ]
    return []


def current_runtime_tree_errors(build_commit: str) -> list[str]:
    value = build_commit.strip()
    if not value or value == LEGACY_GATE_SCHEMA:
        return []
    resolved = run_git(["rev-parse", "--verify", f"{value}^{{commit}}"])
    if resolved.returncode != 0:
        detail = (resolved.stderr or resolved.stdout).strip()
        suffix = f": {detail}" if detail else ""
        return [f"build_commit={value!r} must resolve before runtime tree audit{suffix}"]
    resolved_commit = resolved.stdout.strip()
    diff = run_git(["diff", "--name-only", f"{resolved_commit}..HEAD", "--", *CURRENT_RUNTIME_TREE_PATHS])
    if diff.returncode != 0:
        detail = (diff.stderr or diff.stdout).strip()
        suffix = f": {detail}" if detail else ""
        return [f"build_commit={value!r} runtime tree diff failed{suffix}"]
    changed = [line for line in diff.stdout.splitlines() if line.strip()]
    if not changed:
        return []
    shown = ", ".join(changed[:12])
    if len(changed) > 12:
        shown += f", ... ({len(changed)} files total)"
    return [
        "current evidence build_commit does not cover runtime/dataplane tree changes "
        f"since {value!r}: {shown}"
    ]


def read_current_requirements(args: argparse.Namespace, defaults_path: Path) -> dict[str, dict[str, str]]:
    rows = read_tsv(
        current_requirements_path(args, defaults_path),
        CURRENT_REQUIREMENT_COLUMNS,
        len(CURRENT_REQUIREMENT_COLUMNS),
    )
    validate_gate_family_semantics(rows, "current evidence requirements")
    validate_current_requirement_identity(
        rows,
        "current evidence requirements",
        require_artifact_reference=args.require_artifact_reference,
        require_build_ancestor=args.require_current_build_ancestor,
        require_current_gate_tools=args.require_current_gate_tools,
        require_current_runtime_tree=args.require_current_runtime_tree,
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
    validate_gate_family_semantics(defaults, "production defaults")
    validate_gate_family_semantics(evidence_rows, "production evidence")
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
