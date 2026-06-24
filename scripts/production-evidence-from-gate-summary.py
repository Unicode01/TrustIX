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
MIN_PRODUCTION_IPERF_INTERVALS = 600
MIN_PRODUCTION_INTERVAL_GBPS_RATIO = 0.25
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


def load_manifest(gate_summary_dir: Path) -> dict[str, Any]:
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
    loaded: dict[str, Any] = {
        "schema": SCHEMA,
        "production_gate_sha256": require_sha256(
            production_gate.get("sha256"), "production_gate.sha256"
        ),
        "verifier_sha256": require_sha256(verifier.get("sha256"), "verifier.sha256"),
    }
    for key in ("cases", "case_min_gbps", "case_min_seconds"):
        if key in manifest:
            loaded[key] = manifest[key]
    return loaded


def load_matrix_rows(path: Path) -> dict[str, dict[str, Any]]:
    rows_by_case: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        case = str(row.get("case") or "")
        if not case:
            raise SystemExit(f"{path}: matrix row lacks case: {row}")
        keys = unique_nonempty_strings([case, str(row.get("runner_case") or "")])
        for key in keys:
            if key in rows_by_case and rows_by_case[key] is not row:
                raise SystemExit(f"{path}: duplicate matrix case lookup key {key!r}")
            rows_by_case[key] = row
    return rows_by_case


def unique_nonempty_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = value.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


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


def matrix_string_field(row: dict[str, Any], key: str, case: str) -> str:
    value = str(row.get(key) or "")
    if not value:
        raise SystemExit(f"matrix summary case {case!r} lacks {key}")
    return value


def gate_family_class(gate_family: str) -> str:
    if gate_family in {"full_kmod", "dd_full_kmod", "owdeb_full_kmod"}:
        return "full_kmod"
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


def require_matrix_value(
    *,
    row: dict[str, Any],
    key: str,
    got: str,
    want: str,
    gate_family: str,
) -> None:
    if got == want:
        return
    case = str(row.get("case") or "")
    raise SystemExit(
        f"matrix summary case {case!r} gate_family={gate_family} requires "
        f"{key}={want!r}; got {got!r}"
    )


def require_transport_in(
    *,
    row: dict[str, Any],
    transport: str,
    allowed: set[str],
    gate_family: str,
    label: str,
) -> None:
    if transport in allowed:
        return
    case = str(row.get("case") or "")
    allowed_text = ",".join(sorted(allowed))
    raise SystemExit(
        f"matrix summary case {case!r} gate_family={gate_family} requires "
        f"{label} transport ({allowed_text}); got transport={transport!r}"
    )


def transport_token(transport: str) -> str:
    if transport == "kernel_udp":
        return "udp"
    return transport


def expected_runner_case(
    *,
    transport: str,
    encryption: str,
    datapath: str,
    gate_family: str,
) -> str:
    if gate_family in {"full_kmod", "dd_full_kmod"}:
        return "dd-fullkmod"
    if gate_family == "owdeb_full_kmod":
        return "owdeb-fullkmod"
    if gate_family in {"secure_kudp", "dd_secure_kudp"}:
        return "secure-kudp"
    if gate_family == "owdeb_secure_kudp":
        return "owdeb-secure-kudp"
    if gate_family in {
        "secure_exp_tcp_kernel",
        "dd_secure_exp_tcp_kernel",
        "owdeb_secure_exp_tcp_kernel",
    }:
        return "secure-exp-tcp-kernel"
    if gate_family in {"route_gso", "dd_route_gso"}:
        return "dd-routegso"
    if gate_family == "owdeb_route_gso":
        return "owdeb-routegso"
    kind = "tc" if datapath == "tc_xdp" or transport == "kernel_udp" else "userspace"
    return f"{kind}-{transport_token(transport)}-{encryption}"


def expected_matrix_case(
    *,
    transport: str,
    encryption: str,
    profile: str,
    datapath: str,
    crypto_placement: str,
    gate_family: str,
) -> str:
    base = "-".join(
        [
            transport_token(transport),
            encryption,
            profile,
            datapath,
            crypto_placement,
        ]
    )
    if gate_family.startswith("owdeb_"):
        return base + "-owdeb"
    if gate_family.startswith("dd_"):
        return base + "-dd"
    return base


def require_matrix_semantics(row: dict[str, Any]) -> None:
    case = str(row.get("case") or "")
    if not case:
        raise SystemExit(f"matrix summary row lacks case: {row}")
    transport = matrix_string_field(row, "transport", case)
    encryption = matrix_string_field(row, "encryption", case)
    profile = matrix_string_field(row, "profile", case)
    datapath = matrix_string_field(row, "datapath", case)
    crypto_placement = matrix_string_field(row, "crypto_placement", case)
    gate_family = matrix_string_field(row, "gate_family", case)
    gate_class = gate_family_class(gate_family)

    if gate_class == "userspace":
        require_transport_in(
            row=row,
            transport=transport,
            allowed={"udp", "tcp", "quic", "websocket", "http_connect", "experimental_tcp"},
            gate_family=gate_family,
            label="a userspace",
        )
        require_matrix_value(
            row=row,
            key="datapath",
            got=datapath,
            want="userspace",
            gate_family=gate_family,
        )
        require_matrix_value(
            row=row,
            key="crypto_placement",
            got=crypto_placement,
            want="userspace",
            gate_family=gate_family,
        )
    elif gate_class == "userspace_tc":
        require_transport_in(
            row=row,
            transport=transport,
            allowed={"gre", "ipip", "vxlan"},
            gate_family=gate_family,
            label="a tunnel",
        )
        require_matrix_value(
            row=row,
            key="datapath",
            got=datapath,
            want="tc_xdp",
            gate_family=gate_family,
        )
        require_matrix_value(
            row=row,
            key="crypto_placement",
            got=crypto_placement,
            want="userspace",
            gate_family=gate_family,
        )
    elif gate_class == "tc_direct":
        for key, got, want in [
            ("transport", transport, "kernel_udp"),
            ("encryption", encryption, "plaintext"),
            ("datapath", datapath, "tc_xdp"),
            ("crypto_placement", crypto_placement, "userspace"),
        ]:
            require_matrix_value(
                row=row,
                key=key,
                got=got,
                want=want,
                gate_family=gate_family,
            )
    elif gate_class == "full_kmod":
        for key, got, want in [
            ("transport", transport, "udp"),
            ("encryption", encryption, "plaintext"),
            ("datapath", datapath, "kernel_module"),
            ("crypto_placement", crypto_placement, "userspace"),
        ]:
            require_matrix_value(
                row=row,
                key=key,
                got=got,
                want=want,
                gate_family=gate_family,
            )
    elif gate_class == "secure_kudp":
        for key, got, want in [
            ("transport", transport, "kernel_udp"),
            ("encryption", encryption, "secure"),
            ("datapath", datapath, "tc_xdp"),
            ("crypto_placement", crypto_placement, "kernel"),
        ]:
            require_matrix_value(
                row=row,
                key=key,
                got=got,
                want=want,
                gate_family=gate_family,
            )
    elif gate_class == "secure_exp_tcp_kernel":
        for key, got, want in [
            ("transport", transport, "experimental_tcp"),
            ("encryption", encryption, "secure"),
            ("profile", profile, "performance"),
            ("datapath", datapath, "kernel_module"),
            ("crypto_placement", crypto_placement, "kernel"),
        ]:
            require_matrix_value(
                row=row,
                key=key,
                got=got,
                want=want,
                gate_family=gate_family,
            )
    elif gate_class == "route_gso":
        for key, got, want in [
            ("transport", transport, "experimental_tcp"),
            ("encryption", encryption, "plaintext"),
            ("datapath", datapath, "kernel_module"),
            ("crypto_placement", crypto_placement, "userspace"),
        ]:
            require_matrix_value(
                row=row,
                key=key,
                got=got,
                want=want,
                gate_family=gate_family,
            )
    else:
        raise SystemExit(
            f"matrix summary case {case!r} has unsupported gate_family={gate_family!r}"
        )

    want_runner = expected_runner_case(
        transport=transport,
        encryption=encryption,
        datapath=datapath,
        gate_family=gate_family,
    )
    require_matrix_value(
        row=row,
        key="runner_case",
        got=matrix_string_field(row, "runner_case", case),
        want=want_runner,
        gate_family=gate_family,
    )
    want_case = expected_matrix_case(
        transport=transport,
        encryption=encryption,
        profile=profile,
        datapath=datapath,
        crypto_placement=crypto_placement,
        gate_family=gate_family,
    )
    require_matrix_value(
        row=row,
        key="case",
        got=case,
        want=want_case,
        gate_family=gate_family,
    )


def manifest_section(
    manifest: dict[str, Any],
    section: str,
    *,
    require_complete_maps: bool,
) -> dict[str, Any] | None:
    value = manifest.get(section)
    if value is None and not require_complete_maps:
        return None
    if not isinstance(value, dict):
        raise SystemExit(f"production gate manifest lacks object section {section!r}")
    return value


def manifest_has_case_maps(manifest: dict[str, Any]) -> bool:
    present = [key in manifest for key in ("cases", "case_min_gbps", "case_min_seconds")]
    if not all(present):
        raise SystemExit(
            "production gate manifest must include cases, case_min_gbps, and "
            "case_min_seconds together"
        )
    return True


def parse_manifest_token_map(raw: Any, label: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, str):
        raise SystemExit(f"production gate manifest {label} must be a string")
    parsed: dict[str, str] = {}
    for token in raw.split():
        if "=" not in token:
            raise SystemExit(
                f"production gate manifest {label} has invalid token {token!r}"
            )
        name, value = token.split("=", 1)
        if not name or not value:
            raise SystemExit(
                f"production gate manifest {label} has invalid token {token!r}"
            )
        if name in parsed:
            raise SystemExit(
                f"production gate manifest {label} duplicates case {name!r}"
            )
        parsed[name] = value
    return parsed


def normalize_path_text(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized


def path_match_keys(value: Any, label: str, case: str) -> set[str]:
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"{label} case {case!r} lacks path")
    raw = value.strip()
    keys = {normalize_path_text(raw)}
    try:
        keys.add(normalize_path_text(str(Path(raw).expanduser().resolve(strict=False))))
    except (OSError, RuntimeError, ValueError):
        pass
    return keys


def require_same_path(
    *,
    case: str,
    family_class: str,
    manifest_path: str,
    observed_path: Any,
    observed_label: str,
) -> None:
    manifest_keys = path_match_keys(
        manifest_path,
        f"production gate manifest cases.{family_class}",
        case,
    )
    observed_keys = path_match_keys(observed_path, observed_label, case)
    if manifest_keys & observed_keys:
        return
    raise SystemExit(
        f"production gate manifest cases.{family_class} case {case!r} path "
        f"{manifest_path!r} does not match {observed_label} path "
        f"{str(observed_path or '')!r}"
    )


def manifest_family_map(
    manifest: dict[str, Any],
    section: str,
    family_class: str,
) -> dict[str, str]:
    maps_are_present = manifest_has_case_maps(manifest)
    section_map = manifest_section(
        manifest,
        section,
        require_complete_maps=maps_are_present,
    )
    if section_map is None:
        return {}
    return parse_manifest_token_map(
        section_map.get(family_class),
        f"{section}.{family_class}",
    )


def require_manifest_case_alignment(
    gate_row: dict[str, Any],
    matrix_row: dict[str, Any],
    manifest: dict[str, Any],
    result: str,
    required_seconds: float,
) -> None:
    if result != "pass" or not manifest_has_case_maps(manifest):
        return
    case = str(gate_row.get("case") or matrix_row.get("case") or "")
    case_aliases = unique_nonempty_strings([
        str(gate_row.get("case") or ""),
        str(matrix_row.get("case") or ""),
        str(matrix_row.get("runner_case") or ""),
    ])
    gate_family = matrix_string_field(matrix_row, "gate_family", case)
    family_class = gate_family_class(gate_family)

    cases = manifest_family_map(manifest, "cases", family_class)
    manifest_case = ""
    for alias in case_aliases:
        if alias in cases:
            manifest_case = alias
            break
    if not manifest_case:
        raise SystemExit(
            f"production gate manifest cases.{family_class} does not include "
            f"case {case!r} or aliases {case_aliases!r}"
        )
    manifest_case_path = cases[manifest_case]
    require_same_path(
        case=manifest_case,
        family_class=family_class,
        manifest_path=manifest_case_path,
        observed_path=gate_row.get("path"),
        observed_label="gate summary",
    )
    require_same_path(
        case=manifest_case,
        family_class=family_class,
        manifest_path=manifest_case_path,
        observed_path=matrix_row.get("workdir"),
        observed_label="matrix summary workdir",
    )

    min_gbps_by_case = manifest_family_map(manifest, "case_min_gbps", family_class)
    if manifest_case not in min_gbps_by_case:
        raise SystemExit(
            f"production gate manifest case_min_gbps.{family_class} lacks "
            f"case {manifest_case!r}"
        )
    try:
        manifest_min_gbps = float(min_gbps_by_case[manifest_case])
    except ValueError as exc:
        raise SystemExit(
            f"production gate manifest case_min_gbps.{family_class} case "
            f"{manifest_case!r} has invalid value {min_gbps_by_case[manifest_case]!r}"
        ) from exc
    gate_min_gbps = numeric_field(gate_row, "min_gbps_required", "gate summary")
    matrix_min_gbps = matrix_numeric_field(matrix_row, "min_gbps", case)
    if gate_min_gbps < manifest_min_gbps:
        raise SystemExit(
            f"gate summary case {case!r} min_gbps_required={gate_min_gbps:.6f} "
            f"is below production gate manifest case_min_gbps.{family_class}="
            f"{manifest_min_gbps:.6f}"
        )
    if manifest_min_gbps < matrix_min_gbps:
        raise SystemExit(
            f"production gate manifest case_min_gbps.{family_class} case "
            f"{case!r}={manifest_min_gbps:.6f} is below matrix requirement "
            f"{matrix_min_gbps:.6f}"
        )

    min_seconds_by_case = manifest_family_map(manifest, "case_min_seconds", family_class)
    if manifest_case not in min_seconds_by_case:
        raise SystemExit(
            f"production gate manifest case_min_seconds.{family_class} lacks "
            f"case {manifest_case!r}"
        )
    try:
        manifest_min_seconds = float(min_seconds_by_case[manifest_case])
    except ValueError as exc:
        raise SystemExit(
            f"production gate manifest case_min_seconds.{family_class} case "
            f"{manifest_case!r} has invalid value {min_seconds_by_case[manifest_case]!r}"
        ) from exc
    matrix_min_seconds = matrix_numeric_field(matrix_row, "min_seconds", case)
    if required_seconds < manifest_min_seconds:
        raise SystemExit(
            f"gate summary case {case!r} min_seconds_required="
            f"{format_metric_seconds(required_seconds)}s is below production gate "
            f"manifest case_min_seconds.{family_class}="
            f"{format_metric_seconds(manifest_min_seconds)}s"
        )
    if manifest_min_seconds < matrix_min_seconds:
        raise SystemExit(
            f"production gate manifest case_min_seconds.{family_class} case "
            f"{case!r}={format_metric_seconds(manifest_min_seconds)}s is below "
            f"matrix requirement {format_metric_seconds(matrix_min_seconds)}s"
        )


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


def matrix_numeric_field(row: dict[str, Any], key: str, case: str) -> float:
    value = row.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError as exc:
            raise SystemExit(
                f"matrix summary case {case!r} has invalid {key}: {value!r}"
            ) from exc
    raise SystemExit(f"matrix summary case {case!r} lacks numeric {key}")


def require_matrix_gate_alignment(
    gate_row: dict[str, Any],
    matrix_row: dict[str, Any],
    result: str,
    required_seconds: float,
) -> None:
    if result != "pass":
        return
    case = str(gate_row.get("case") or matrix_row.get("case") or "")
    if matrix_row.get("validation_scope") != "cross_host":
        raise SystemExit(
            f"matrix summary case {case!r} validation_scope="
            f"{matrix_row.get('validation_scope')!r}, want 'cross_host'"
        )
    matrix_min_gbps = matrix_numeric_field(matrix_row, "min_gbps", case)
    matrix_min_seconds = matrix_numeric_field(matrix_row, "min_seconds", case)
    gate_min_gbps = numeric_field(gate_row, "min_gbps_required", "gate summary")
    if gate_min_gbps < matrix_min_gbps:
        raise SystemExit(
            f"gate summary case {case!r} min_gbps_required="
            f"{gate_min_gbps:.6f} is below matrix min_gbps={matrix_min_gbps:.6f}"
        )
    if required_seconds < matrix_min_seconds:
        raise SystemExit(
            f"gate summary case {case!r} min_seconds_required="
            f"{format_metric_seconds(required_seconds)}s is below matrix "
            f"min_seconds={format_metric_seconds(matrix_min_seconds)}s"
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


def require_throughput_for_pass(row: dict[str, Any], result: str) -> None:
    if result != "pass":
        return
    required = numeric_field(row, "min_gbps_required", "gate summary")
    if required <= 0:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has invalid min_gbps_required: "
            f"{format_metric_seconds(required)}"
        )
    for key in ("min_sent_gbps", "min_required_received_gbps"):
        observed = numeric_field(row, key, "gate summary")
        if observed < required:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {key}="
                f"{observed:.6f} < min_gbps_required={required:.6f}"
            )


def require_iperf_coverage_for_pass(
    row: dict[str, Any],
    result: str,
    required_seconds: float,
    seconds_slop: float,
) -> None:
    if result != "pass":
        return
    min_intervals = numeric_field(
        row,
        "min_iperf_intervals_required",
        "gate summary",
    )
    if min_intervals < MIN_PRODUCTION_IPERF_INTERVALS:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} requires only "
            f"{format_metric_seconds(min_intervals)} iperf intervals, "
            f"want >= {MIN_PRODUCTION_IPERF_INTERVALS}"
        )
    ratio = numeric_field(
        row,
        "min_iperf_interval_gbps_ratio_required",
        "gate summary",
    )
    if ratio < MIN_PRODUCTION_INTERVAL_GBPS_RATIO:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} interval throughput ratio "
            f"{format_metric_seconds(ratio)} < {MIN_PRODUCTION_INTERVAL_GBPS_RATIO}"
        )
    for key in ("iperf_json_count", "iperf_direction_count"):
        count = numeric_field(row, key, "gate summary")
        if count < 2:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has {format_metric_seconds(count)} "
                f"{key}, want >= 2"
            )
    pair_directions = {str(item) for item in list_field(row, "iperf_pair_directions")}
    missing = {"a-to-b", "b-to-a"} - pair_directions
    if missing:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} missing iperf_pair_directions: "
            f"{','.join(sorted(missing))}"
        )
    iperf_items = list_field(row, "iperf")
    if len(iperf_items) < 2:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has {len(iperf_items)} iperf "
            "result items, want >= 2"
        )
    interval_floor = numeric_field(row, "min_gbps_required", "gate summary") * ratio
    for index, item in enumerate(iperf_items):
        if not isinstance(item, dict):
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has invalid iperf item: {item!r}"
            )
        source = f"iperf[{index}]"
        case = str(row.get("case") or "")
        seconds = numeric_field(item, "seconds", source, case=case)
        intervals = numeric_field(item, "intervals", source, case=case)
        interval_min = numeric_field(item, "interval_min_gbps", source, case=case)
        if seconds + seconds_slop < required_seconds:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {source} seconds "
                f"{format_metric_seconds(seconds)}s + "
                f"seconds_slop={format_metric_seconds(seconds_slop)}s < "
                f"required={format_metric_seconds(required_seconds)}s"
            )
        if intervals < min_intervals:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {source} intervals "
                f"{format_metric_seconds(intervals)}, want >= "
                f"{format_metric_seconds(min_intervals)}"
            )
        if interval_min < interval_floor:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} {source} interval_min_gbps "
                f"{interval_min:.6f} < floor {interval_floor:.6f}"
            )


def require_result_marker_for_pass(row: dict[str, Any], result: str) -> None:
    if result != "pass":
        return
    markers = list_field(row, "result_markers")
    if not markers:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has 0 result_markers, want >= 1"
        )
    bad = [str(item) for item in markers if str(item) != "pass"]
    if bad:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has non-pass result_markers: {bad!r}"
        )


def require_binary_identity_for_pass(row: dict[str, Any], result: str) -> None:
    if result != "pass":
        return
    identities = list_field(row, "binary_identities")
    if len(identities) < 2:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has {len(identities)} "
            "binary_identities, want >= 2"
        )
    hashes: set[str] = set()
    for item in identities:
        if not isinstance(item, dict):
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has invalid binary identity: {item!r}"
            )
        sha256 = str(item.get("sha256") or "")
        if not SHA256_RE.fullmatch(sha256):
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has invalid binary sha256: "
                f"{sha256!r}"
            )
        hashes.add(sha256)
    if len(hashes) != 1:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has mismatched binary sha256s: "
            f"{sorted(hashes)}"
        )


def require_runtime_artifacts_for_pass(row: dict[str, Any], result: str) -> None:
    if result != "pass":
        return
    require_min_list_items(row, "lsmod_nodes", 2)
    require_min_list_items(row, "lsmod_artifacts", 2)
    require_min_list_items(row, "lan_state_nodes", 2)
    lan_states = list_field(row, "lan_state_artifacts")
    if len(lan_states) < 2:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has {len(lan_states)} "
            "lan_state_artifacts, want >= 2"
        )
    valid_nodes: set[str] = set()
    for item in lan_states:
        if not isinstance(item, dict):
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has invalid LAN state: {item!r}"
            )
        node = str(item.get("node") or "")
        iface = str(item.get("interface") or "")
        tx_queue_len = item.get("tx_queue_len")
        if not node or not iface or not isinstance(tx_queue_len, int) or tx_queue_len < 1:
            raise SystemExit(
                f"gate summary case {row.get('case')!r} has invalid LAN state: {item!r}"
            )
        valid_nodes.add(node)
    if len(valid_nodes) < 2:
        raise SystemExit(
            f"gate summary case {row.get('case')!r} has valid LAN state coverage "
            f"for {len(valid_nodes)} nodes, want >= 2"
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
    manifest: dict[str, Any],
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
    require_throughput_for_pass(gate_row, result)
    require_iperf_coverage_for_pass(gate_row, result, seconds, seconds_slop)
    require_result_marker_for_pass(gate_row, result)
    require_binary_identity_for_pass(gate_row, result)
    require_runtime_artifacts_for_pass(gate_row, result)
    require_crash_stability_for_pass(gate_row, result)
    require_matrix_semantics(matrix_row)
    require_manifest_case_alignment(gate_row, matrix_row, manifest, result, seconds)
    require_matrix_gate_alignment(gate_row, matrix_row, result, seconds)
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
