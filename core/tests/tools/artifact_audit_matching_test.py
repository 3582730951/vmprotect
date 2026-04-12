#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path


def load_artifact_audit_module():
    module_path = Path(__file__).resolve().parents[2] / "tools" / "artifact_audit.py"
    spec = importlib.util.spec_from_file_location("artifact_audit", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load artifact_audit module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    module = load_artifact_audit_module()

    for benign_value in (
        "_ZN12_GLOBAL__N_1L14kApiCandidatesE",
        "_ZN12_GLOBAL__N_117resolve_candidateERKNS_12ApiCandidateE",
        "_ZN5eippf7runtime7backend15validate_policyERKNS1_6PolicyE",
        "libgdbus-2.0.so",
    ):
        assert_true(
            not module.contains_analysis_import(benign_value),
            f"expected benign value to stay clean: {benign_value}",
        )

    for suspicious_value in (
        "ida64.exe",
        "idapro.exe",
        "gdb.exe",
        "gdbserver",
        "lldb-server",
        "liblldb.so",
        "libfrida-gadget.so",
    ):
        assert_true(
            module.contains_analysis_import(suspicious_value),
            f"expected suspicious value to match: {suspicious_value}",
        )

    benign_hits = module.find_denylist_hits(
        [
            "kApiCandidates",
            "resolve_candidate",
            "validate_policy",
            "libgdbus-2.0.so",
        ],
        ["ida", "gdb", "lldb"],
        "symbol",
    )
    assert_true(benign_hits == [], f"expected no short-token false positives, got: {benign_hits}")

    suspicious_hits = module.find_denylist_hits(
        [
            "ida64.exe",
            "gdb.exe",
            "liblldb.so",
            "libfrida-gadget.so",
        ],
        ["ida", "gdb", "lldb", "frida"],
        "string",
    )
    hit_pairs = {(entry["pattern"], entry["value"]) for entry in suspicious_hits}
    for expected_hit in (
        ("ida", "ida64.exe"),
        ("gdb", "gdb.exe"),
        ("lldb", "liblldb.so"),
        ("frida", "libfrida-gadget.so"),
    ):
        assert_true(expected_hit in hit_pairs, f"missing expected hit: {expected_hit}, got: {hit_pairs}")
    assert_true(
        ("ida", "libfrida-gadget.so") not in hit_pairs,
        f"unexpected ida false positive on frida artifact: {hit_pairs}",
    )

    semantic_hits = module.find_semantic_symbol_hits(
        [
            "resolve_candidate",
            "anti_tamper_check_passed",
            "ensure_runtime_initialized",
            "eippf_sd0",
            "std::call_once",
        ]
    )
    semantic_values = {entry["value"] for entry in semantic_hits}
    for expected_value in (
        "resolve_candidate",
        "anti_tamper_check_passed",
        "ensure_runtime_initialized",
    ):
        assert_true(expected_value in semantic_values, f"missing semantic symbol hit: {expected_value}")
    assert_true("eippf_sd0" not in semantic_values, f"short runtime alias should not look semantic: {semantic_values}")
    assert_true("std::call_once" not in semantic_values, f"unexpected semantic symbol hit: {semantic_values}")

    entrypoint_hits = module.find_entrypoint_symbol_hits(
        [
            "main",
            "DllMain",
            "DriverEntry",
            "JNI_OnLoad",
            "__libc_start_main",
        ]
    )
    entrypoint_values = {entry["value"] for entry in entrypoint_hits}
    for expected_value in ("main", "DllMain", "DriverEntry", "JNI_OnLoad"):
        assert_true(expected_value in entrypoint_values, f"missing entrypoint symbol hit: {expected_value}")
    assert_true(
        "__libc_start_main" not in entrypoint_values,
        f"unexpected libc entrypoint false positive: {entrypoint_values}",
    )

    for name in (".debug_info", ".symtab", ".strtab", ".comment"):
        assert_true(module.is_debug_section_name(name), f"expected debug metadata section match: {name}")
    for name in (".text", ".rdata", ".rodata", "__TEXT"):
        assert_true(not module.is_debug_section_name(name), f"unexpected debug metadata match: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
