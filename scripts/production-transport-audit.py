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
    "runner_sha256",
    "transport_matrix_sha256",
    "evidence_generator_sha256",
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
    "runner_sha256",
    "transport_matrix_sha256",
    "evidence_generator_sha256",
]
CURRENT_REQUIREMENT_MIN_FIELDS = 19
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
    "runner_sha256",
    "transport_matrix_sha256",
    "evidence_generator_sha256",
]
TOOLCHAIN_SHA256_FIELDS = [
    "runner_sha256",
    "transport_matrix_sha256",
    "evidence_generator_sha256",
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
EXPERIMENTAL_TCP_FULL_KMOD_RUNTIME_FAMILIES = {
    "exp_tcp_full_kmod",
    "dd_exp_tcp_full_kmod",
    "owdeb_exp_tcp_full_kmod",
}
LOW_LEVEL_RUNTIME_GATE_CLASSES = {
    "userspace_tc",
    "tc_direct",
    "full_kmod",
    "exp_tcp_full_kmod",
    "secure_kudp",
    "secure_exp_tcp_kernel",
    "route_gso",
}
EBPF_RUNTIME_GATE_CLASSES = {
    "tc_direct",
    "secure_kudp",
    "secure_exp_tcp_kernel",
    "route_gso",
}
KERNEL_MODULE_RUNTIME_GATE_CLASSES = {
    "full_kmod",
    "exp_tcp_full_kmod",
    "secure_kudp",
    "secure_exp_tcp_kernel",
    "route_gso",
}
FULL_DATAPATH_MODULE_GATE_CLASSES = {
    "full_kmod",
    "exp_tcp_full_kmod",
}
CRYPTO_MODULE_GATE_CLASSES = {
    "secure_kudp",
    "secure_exp_tcp_kernel",
}
DATAPATH_HELPERS_MODULE_GATE_CLASSES = {
    "secure_kudp",
    "secure_exp_tcp_kernel",
    "route_gso",
}
KERNEL_UDP_DIRECT_POLICY_GATE_CLASSES = {
    "tc_direct",
    "secure_kudp",
    "secure_exp_tcp_kernel",
    "route_gso",
}
DAEMON_DATAPATH_SESSION_GATE_CLASSES = {
    "full_kmod",
    "exp_tcp_full_kmod",
    "secure_kudp",
    "secure_exp_tcp_kernel",
    "route_gso",
}
CURRENT_RUNTIME_TREE_PROVISION_ONLY_PATHS = {
    # Provision output changes do not alter already-soaked datapath/runtime behavior.
    "internal/daemon/ix_provision_resource.go",
}
OPENWRT_ONLY_RUNTIME_CHANGE_COMMITS_BY_PATH = {
    # 9235159 only changes the OpenWrt rx_worker_single_coalesce default behind
    # runtimeLooksLikeOpenWrt(). It does not invalidate non-OpenWrt current
    # kernel-module evidence rows.
    "internal/daemon/kernel_modules.go": {
        "9235159503ed1746a41af9a86cbe9baebd67ed8f",
    },
}
ROUTE_GSO_ONLY_RUNTIME_CHANGE_COMMITS_BY_PATH = {
    # add2971 only changes the selected route-GSO helper defaults/gate
    # contract and the route TCP GSO helper's stopped-TXQ handling. It does
    # not invalidate full-kmod, secure-kUDP, or secure experimental TCP kernel
    # evidence rows.
    "internal/daemon/kernel_modules.go": {
        "add2971946b4948fbdd49d973aa94581b2e87a50",
    },
    "kernel/trustix_datapath_helpers/trustix_datapath_helpers_kfuncs.c": {
        "add2971946b4948fbdd49d973aa94581b2e87a50",
    },
}
RUNTIME_GATE_ADVERTISEMENT_COMMITS_BY_PATH = {
    # aee1046 only adds selected runtime-gate feature names to local endpoint,
    # membership, and status metadata. The selected datapath/crypto code paths
    # and hard compatibility feature requirements are unchanged, so it does not
    # make already-soaked steady-state transport gate evidence stale by itself.
    "internal/daemon/daemon.go": {
        "aee1046d917c97dddbc800d6a4fb203491c057f6",
    },
    "internal/daemon/membership.go": {
        "aee1046d917c97dddbc800d6a4fb203491c057f6",
    },
    "internal/daemon/transport_profile_policy.go": {
        "aee1046d917c97dddbc800d6a4fb203491c057f6",
    },
    "internal/daemon/transports_status.go": {
        "aee1046d917c97dddbc800d6a4fb203491c057f6",
    },
}
CAPTURE_FORWARDER_DEFAULT_COMMITS_BY_PATH = {
    # 1dfaf51 changes only the userspace capture-forwarder worker defaults and
    # cross-host runner capture-forwarder env injection. Current full plaintext
    # and secure-kUDP production rows below have artifacts proving the capture
    # forwarder was suppressed, so their steady-state datapath is unchanged.
    "internal/daemon/datapath.go": {
        "1dfaf51caac8bc03177de4ec428e23659db69173",
    },
}
CAPTURE_FORWARDER_SUPPRESSED_GATE_CLASSES = {
    "full_kmod",
    "exp_tcp_full_kmod",
    "secure_kudp",
}
USERSPACE_UDP_DEFAULT_ONLY_COMMITS_BY_PATH = {
    # dd8da09 caps the default userspace UDP datagram payload below MTU. It
    # does not affect full-kmod production rows whose verifier artifacts prove
    # capture_forwarder_suppressed=true and kernel_datapath_full_plaintext was
    # the provider; userspace UDP rows still need fresh evidence for this
    # runtime/default change.
    "internal/transport/udp/udp_read_packet_size_linux.go": {
        "dd8da09cfc73e14cc7dcc771d08505f850deae94",
    },
}
GATE_TOOL_COMPATIBLE_SHA256_BY_FAMILY = {
    # This manifest-v1 gate predates the exp_tcp_full_kmod family. The existing
    # families below kept equivalent verifier semantics when the dedicated
    # experimental TCP full-kmod gate was added, so their current evidence rows
    # do not need to be re-minted with a different historical tool hash.
    "6150d4ccadd3b0614d389442c4a1084fcad2d0748700ad9d5eea9900e7d7a242": {
        "userspace",
        "userspace_tc",
        "tc_direct",
        "full_kmod",
        "owdeb_full_kmod",
        "secure_kudp",
        "secure_exp_tcp_kernel",
        "route_gso",
    },
    # This gate predates the OpenWrt-Debian single-coalesce verifier split.
    # Non-OpenWrt kernel families kept equivalent verifier semantics.
    "662c176c1888bd3c89d775ef61e2cff70b2c0be39d929e35d18a6e11b78f7446": {
        "tc_direct",
        "full_kmod",
        "exp_tcp_full_kmod",
        "secure_kudp",
        "secure_exp_tcp_kernel",
        "route_gso",
    },
    # OpenWrt-Debian current rows were minted with this gate before the
    # netdev-unregister verifier hardening. Keep the tool identity explicit
    # until a fresh OpenWrt-Debian run replaces or demotes those rows.
    "89d4f86eb164603d22678bfa8636042bb7be4c1040de8dbf9d151211962906c9": {
        "owdeb_full_kmod",
        "owdeb_exp_tcp_full_kmod",
    },
    # This gate is equivalent for OpenWrt-Debian full-kmod families after the
    # route-TCP helper capability check was added for route-GSO and secure
    # kernel families only.
    "f10f2307e6c4d0b3282616acb8ecf3cf1dc45aa481902c5aa3a38ed8c4124faf": {
        "owdeb_full_kmod",
        "owdeb_exp_tcp_full_kmod",
    },
    # This gate predates secure_exp_tcp_kernel direct-error clamp and replay
    # ratio hardening. Existing pass evidence remains equivalent: the default
    # direct-error budget was already zero, replay drops were already max-zero,
    # and non-secure_exp_tcp_kernel family checks were unchanged.
    "e6e2c7c69807adaa8bd171b59225ce15b307c668c280b12b027baab19f12f029": {
        "full_kmod",
        "owdeb_full_kmod",
        "exp_tcp_full_kmod",
        "owdeb_exp_tcp_full_kmod",
        "secure_kudp",
        "secure_exp_tcp_kernel",
        "route_gso",
    },
}
VERIFIER_TOOL_COMPATIBLE_SHA256_BY_FAMILY = {
    # This verifier predates the node-specific module-parameter requirement.
    # Existing non-OpenWrt current rows do not depend on that new predicate.
    "039cb91ef61fa4187baf16ed279e2dc09faf5aaaa69c0e7d1b2b597905e8eb9b": {
        "tc_direct",
        "full_kmod",
        "exp_tcp_full_kmod",
        "secure_kudp",
        "secure_exp_tcp_kernel",
        "route_gso",
    },
    # Historical current rows that have not yet been re-minted with the
    # stricter netdev-unregister verifier.
    "bd01ec1a0cd9463e401e73c570e8e688d6126d5891626367895979aa4d9ec26b": {
        "userspace",
        "userspace_tc",
        "owdeb_full_kmod",
        "owdeb_exp_tcp_full_kmod",
    },
}
TOOLCHAIN_COMPATIBLE_SHA256_BY_FIELD_AND_FAMILY = {
    "evidence_generator_sha256": {
        # 524a170 only adds direct production-gate short-case alias support
        # (`gate_case`). Evidence rows generated from canonical matrix/gate
        # case names keep the same verification semantics.
        "6c5ab13a29f7a2cb0e0b6b941bfa8abd749c464ac792a771baf63f70b40da0fb": {
            "userspace_tc",
            "tc_direct",
            "full_kmod",
            "owdeb_full_kmod",
            "exp_tcp_full_kmod",
            "owdeb_exp_tcp_full_kmod",
            "secure_kudp",
            "secure_exp_tcp_kernel",
            "route_gso",
        },
    },
    "runner_sha256": {
        # These rows were re-gated from existing 3600s artifacts; the verifier,
        # matrix, and evidence generator are current, but the soak runner hash
        # records the original long run that produced the artifacts.
        "adcff9cfd21254c429f340d94de2293e3cbfb58b11d1d7fd2f799f5c351f52d0": {
            "full_kmod",
            "exp_tcp_full_kmod",
            "route_gso",
            "owdeb_full_kmod",
            "owdeb_exp_tcp_full_kmod",
        },
        "80836a54f5ecc4b66bdf447372ff15f7703c61f0430368379c7fa7d3be04a82e": {
            "full_kmod",
            "exp_tcp_full_kmod",
            "route_gso",
            "owdeb_full_kmod",
            "owdeb_exp_tcp_full_kmod",
            "secure_kudp",
            "secure_exp_tcp_kernel",
            "tc_direct",
            "userspace_tc",
        },
    },
}
CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS = {
    "udp:secure:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-udp-userspace-rerun2-2026-06-29",
    "udp:plaintext:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-udp-userspace-rerun2-2026-06-29",
    "tcp:secure:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-tcp-userspace-rerun-2026-06-29",
    "tcp:plaintext:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-tcp-userspace-rerun-2026-06-29",
    "quic:secure:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-quic-userspace-rerun-2026-06-29",
    "quic:plaintext:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-quic-userspace-rerun-2026-06-29",
    "websocket:secure:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-websocket-userspace-rerun-2026-06-29",
    "websocket:plaintext:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-websocket-userspace-rerun-2026-06-29",
    "http_connect:secure:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-http-connect-userspace-rerun-2026-06-29",
    "http_connect:plaintext:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-5fa2ba1-http-connect-userspace-rerun-2026-06-29",
    "experimental_tcp:secure:stable:userspace:userspace:cross_host:userspace|docs/trustix-performance-log.md#pve-debian13-current-userspace-b-2026-06-28",
}


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
            "and generated evidence toolchain hashes to match current repository scripts"
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
    parser.add_argument(
        "--report-refresh-gaps",
        action="store_true",
        help=(
            "include diagnostics for current evidence rows that still rely on "
            "legacy/unpinned tooling, non-HEAD builds, or relevant runtime tree "
            "changes since the recorded build"
        ),
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
    for field in TOOLCHAIN_SHA256_FIELDS:
        value = row[field].strip()
        if value and not SHA256_RE.fullmatch(value):
            errors.append(f"{field} must be empty or 64 lowercase hex; got {value!r}")
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
            errors.extend(current_runtime_tree_errors(row))
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
        "runner_sha256": row["runner_sha256"],
        "transport_matrix_sha256": row["transport_matrix_sha256"],
        "evidence_generator_sha256": row["evidence_generator_sha256"],
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
        "runner_sha256": row["runner_sha256"],
        "transport_matrix_sha256": row["transport_matrix_sha256"],
        "evidence_generator_sha256": row["evidence_generator_sha256"],
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


def current_toolchain_legacy_key(row: dict[str, str]) -> str:
    return f"{row_key(row)}|{row['artifact']}"


def is_current_toolchain_legacy(row: dict[str, str]) -> bool:
    if current_toolchain_legacy_key(row) not in CURRENT_TOOLCHAIN_LEGACY_REQUIREMENTS:
        return False
    return not any(row[field].strip() for field in TOOLCHAIN_SHA256_FIELDS)


def current_gate_tool_identity_errors(row: dict[str, str]) -> list[str]:
    root = repo_root()
    gate_path = root / "scripts" / "linux-cross-host-production-gate.sh"
    verifier_path = root / "scripts" / "linux-cross-host-soak-verify.py"
    runner_path = root / "scripts" / "linux-cross-host-soak-runner.sh"
    matrix_path = root / "scripts" / "linux-cross-host-transport-matrix.sh"
    evidence_generator_path = root / "scripts" / "production-evidence-from-gate-summary.py"
    want_gate_sha = file_sha256(gate_path)
    want_verifier_sha = file_sha256(verifier_path)
    want_runner_sha = file_sha256(runner_path)
    want_matrix_sha = file_sha256(matrix_path)
    want_evidence_generator_sha = file_sha256(evidence_generator_path)
    gate_family = row["gate_family"]
    allowed_gate_shas = {want_gate_sha}
    for sha, families in GATE_TOOL_COMPATIBLE_SHA256_BY_FAMILY.items():
        if gate_family in families:
            allowed_gate_shas.add(sha)
    allowed_verifier_shas = {want_verifier_sha}
    for sha, families in VERIFIER_TOOL_COMPATIBLE_SHA256_BY_FAMILY.items():
        if gate_family in families:
            allowed_verifier_shas.add(sha)
    errors: list[str] = []
    if row["production_gate_sha256"] not in allowed_gate_shas:
        allowed = ", ".join(sorted(allowed_gate_shas))
        errors.append(
            "production_gate_sha256 must match current or compatible "
            f"scripts/linux-cross-host-production-gate.sh sha256 values [{allowed}]; "
            f"got {row['production_gate_sha256']!r}"
        )
    if row["verifier_sha256"] not in allowed_verifier_shas:
        allowed = ", ".join(sorted(allowed_verifier_shas))
        errors.append(
            "verifier_sha256 must match current or compatible "
            f"scripts/linux-cross-host-soak-verify.py sha256 values [{allowed}]; "
            f"got {row['verifier_sha256']!r}"
        )
    toolchain_values = {field: row[field].strip() for field in TOOLCHAIN_SHA256_FIELDS}
    if is_current_toolchain_legacy(row):
        return errors
    if not any(toolchain_values.values()):
        errors.append(
            "runner_sha256/transport_matrix_sha256/evidence_generator_sha256 "
            "are required for new current evidence rows"
        )
        return errors
    expected_toolchain = {
        "runner_sha256": (
            want_runner_sha,
            "scripts/linux-cross-host-soak-runner.sh",
        ),
        "transport_matrix_sha256": (
            want_matrix_sha,
            "scripts/linux-cross-host-transport-matrix.sh",
        ),
        "evidence_generator_sha256": (
            want_evidence_generator_sha,
            "scripts/production-evidence-from-gate-summary.py",
        ),
    }
    for field, (want_sha, label) in expected_toolchain.items():
        allowed_shas = {want_sha}
        for sha, families in TOOLCHAIN_COMPATIBLE_SHA256_BY_FIELD_AND_FAMILY.get(field, {}).items():
            if gate_family in families:
                allowed_shas.add(sha)
        if toolchain_values[field] not in allowed_shas:
            allowed = ", ".join(sorted(allowed_shas))
            errors.append(
                f"{field} must match current or compatible {label} sha256 values [{allowed}]; "
                f"got {row[field]!r}"
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


def current_runtime_path_relevant(row: dict[str, str], path: str) -> bool:
    normalized = path.replace("\\", "/")
    if normalized.endswith("_test.go"):
        return False
    if normalized in CURRENT_RUNTIME_TREE_PROVISION_ONLY_PATHS:
        return False
    gate_class = gate_family_class(row["gate_family"])
    transport = row.get("transport", "")
    if normalized.startswith("internal/dataplane/ebpf/"):
        return gate_class in EBPF_RUNTIME_GATE_CLASSES
    if normalized.startswith("internal/kernelmodule/"):
        return gate_class in KERNEL_MODULE_RUNTIME_GATE_CLASSES
    if normalized.startswith("kernel/bpf/"):
        return gate_class in EBPF_RUNTIME_GATE_CLASSES
    if normalized.startswith("kernel/trustix_crypto/"):
        return gate_class in CRYPTO_MODULE_GATE_CLASSES
    if normalized.startswith("kernel/trustix_datapath/"):
        return gate_class in FULL_DATAPATH_MODULE_GATE_CLASSES
    if normalized.startswith("kernel/trustix_datapath_helpers/"):
        return gate_class in DATAPATH_HELPERS_MODULE_GATE_CLASSES
    if normalized.startswith("kernel/trustix_"):
        return gate_class in KERNEL_MODULE_RUNTIME_GATE_CLASSES
    if normalized == "scripts/build-embedded-bpf.sh":
        return gate_class in EBPF_RUNTIME_GATE_CLASSES
    if normalized.startswith("internal/transport/experimentaltcp/"):
        return transport == "experimental_tcp" or gate_class in {
            "exp_tcp_full_kmod",
            "secure_exp_tcp_kernel",
            "route_gso",
        }
    if normalized.startswith("internal/transport/udp/"):
        return transport in {"udp", "kernel_udp"} or gate_class == "full_kmod"
    if normalized.startswith("internal/transport/quic/"):
        return transport == "quic"
    if normalized.startswith("internal/daemon/"):
        if normalized == "internal/daemon/kernel_modules.go":
            return gate_class in KERNEL_MODULE_RUNTIME_GATE_CLASSES
        if normalized == "internal/daemon/kernel_udp_direct_policy.go":
            return gate_class in KERNEL_UDP_DIRECT_POLICY_GATE_CLASSES
        if normalized == "internal/daemon/datapath.go":
            return (
                gate_class in DAEMON_DATAPATH_SESSION_GATE_CLASSES
                or transport == "experimental_tcp"
            )
        return gate_class in LOW_LEVEL_RUNTIME_GATE_CLASSES
    return True


def row_targets_openwrt(row: dict[str, str]) -> bool:
    return "openwrt" in row.get("os_matrix", "").lower() or row.get(
        "gate_family", ""
    ).startswith("owdeb_")


def path_changed_only_by(resolved_commit: str, normalized_path: str, allowed_commits: set[str]) -> bool:
    path_log = run_git(["log", "--format=%H", f"{resolved_commit}..HEAD", "--", normalized_path])
    if path_log.returncode != 0:
        return False
    changed_commits = {line.strip() for line in path_log.stdout.splitlines() if line.strip()}
    return bool(changed_commits) and changed_commits.issubset(allowed_commits)


def current_runtime_path_change_irrelevant(
    row: dict[str, str], resolved_commit: str, path: str
) -> bool:
    normalized = path.replace("\\", "/")
    gate_class = gate_family_class(row["gate_family"])
    allowed_change_commits: set[str] = set()
    allowed_commits = RUNTIME_GATE_ADVERTISEMENT_COMMITS_BY_PATH.get(normalized)
    if allowed_commits and gate_class in LOW_LEVEL_RUNTIME_GATE_CLASSES:
        allowed_change_commits.update(allowed_commits)
    allowed_commits = ROUTE_GSO_ONLY_RUNTIME_CHANGE_COMMITS_BY_PATH.get(normalized)
    if allowed_commits and gate_class != "route_gso":
        allowed_change_commits.update(allowed_commits)
    if not row_targets_openwrt(row):
        allowed_commits = OPENWRT_ONLY_RUNTIME_CHANGE_COMMITS_BY_PATH.get(normalized)
        if allowed_commits:
            allowed_change_commits.update(allowed_commits)
    allowed_commits = CAPTURE_FORWARDER_DEFAULT_COMMITS_BY_PATH.get(normalized)
    if allowed_commits and gate_class in CAPTURE_FORWARDER_SUPPRESSED_GATE_CLASSES:
        allowed_change_commits.update(allowed_commits)
    allowed_commits = USERSPACE_UDP_DEFAULT_ONLY_COMMITS_BY_PATH.get(normalized)
    if allowed_commits and (
        gate_class in FULL_DATAPATH_MODULE_GATE_CLASSES
        or gate_class in KERNEL_UDP_DIRECT_POLICY_GATE_CLASSES
    ):
        allowed_change_commits.update(allowed_commits)
    if not allowed_change_commits:
        return False
    return path_changed_only_by(resolved_commit, normalized, allowed_change_commits)


def current_runtime_tree_errors(
    row: dict[str, str],
    *,
    allow_legacy_skip: bool = True,
) -> list[str]:
    if allow_legacy_skip and is_current_toolchain_legacy(row):
        return []
    build_commit = row["build_commit"]
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
    changed = [
        line
        for line in diff.stdout.splitlines()
        if line.strip()
        and current_runtime_path_relevant(row, line.strip())
        and not current_runtime_path_change_irrelevant(row, resolved_commit, line.strip())
    ]
    if not changed:
        return []
    shown = ", ".join(changed[:12])
    if len(changed) > 12:
        shown += f", ... ({len(changed)} files total)"
    return [
        "current evidence build_commit does not cover runtime/dataplane tree changes "
        f"since {value!r}: {shown}"
    ]


def current_refresh_gap_reasons(row: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    for field in TOOLCHAIN_SHA256_FIELDS:
        if not row[field].strip():
            reasons.append(f"{field} is empty; refresh with generated current-tool evidence")
    reasons.extend(
        current_runtime_tree_errors(
            row,
            allow_legacy_skip=False,
        )
    )
    return reasons


def read_current_requirements(args: argparse.Namespace, defaults_path: Path) -> dict[str, dict[str, str]]:
    rows = read_tsv(
        current_requirements_path(args, defaults_path),
        CURRENT_REQUIREMENT_COLUMNS,
        CURRENT_REQUIREMENT_MIN_FIELDS,
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
            if args.report_refresh_gaps:
                refresh_reasons = current_refresh_gap_reasons(current_requirement)
                result["current_refresh"] = {
                    "status": "refresh_needed" if refresh_reasons else "current",
                    "reasons": refresh_reasons,
                }
        if rejected:
            result["rejected_candidates"] = rejected
        results.append(result)
    return results


def emit_text(results: list[dict[str, Any]], *, report_refresh_gaps: bool = False) -> None:
    for row in results:
        evidence = row.get("evidence") or {}
        fields = [
            row["status"],
            row["key"],
            str(evidence.get("min_gbps", "")),
            str(evidence.get("min_seconds", "")),
            str(evidence.get("gate_manifest_schema", "")),
            str(evidence.get("artifact", "")),
        ]
        if report_refresh_gaps:
            refresh = row.get("current_refresh") or {}
            fields.extend(
                [
                    str(refresh.get("status", "")),
                    "; ".join(str(reason) for reason in refresh.get("reasons", [])),
                ]
            )
        print("\t".join(fields))


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
        emit_text(results, report_refresh_gaps=args.report_refresh_gaps)
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
