#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


def load_redteam_harness_module():
    module_path = Path(__file__).resolve().parents[2] / "tools" / "redteam_harness.py"
    spec = importlib.util.spec_from_file_location("redteam_harness", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load redteam_harness module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def build_valid_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-04-12T00:00:00+00:00",
        "samples": [
            {
                "artifact_id": "linux_elf",
                "platform": "linux",
                "format": "elf",
                "protection_profile": "desktop_native_strict",
                "static_leak_pass": True,
                "dynamic_probe_pass": True,
                "runtime_dump_pass": True,
                "signature_policy_pass": True,
                "perf_budget_pass": True,
                "perf_delta_pct": 4.25,
                "failure_reasons": [],
                "evidence_paths": ["reports/linux_elf/static.json"],
                "final_verdict": "pass",
            }
        ],
    }


def main() -> int:
    module = load_redteam_harness_module()

    report = build_valid_report()
    errors = module.validate_redteam_report(report)
    assert_true(errors == [], f"expected valid redteam report, got: {errors}")

    bad_missing_verdict = build_valid_report()
    bad_missing_verdict["samples"] = [dict(bad_missing_verdict["samples"][0])]
    bad_missing_verdict["samples"][0].pop("final_verdict")
    errors = module.validate_redteam_report(bad_missing_verdict)
    assert_true(
        any("final_verdict" in entry for entry in errors),
        f"expected final_verdict validation error, got: {errors}",
    )

    bad_perf_budget = build_valid_report()
    bad_perf_budget["samples"] = [dict(bad_perf_budget["samples"][0])]
    bad_perf_budget["samples"][0]["perf_delta_pct"] = 12.5
    bad_perf_budget["samples"][0]["perf_budget_pass"] = True
    errors = module.validate_redteam_report(bad_perf_budget)
    assert_true(
        any("perf_budget_pass" in entry for entry in errors),
        f"expected perf budget validation error, got: {errors}",
    )

    denylist_path = Path(__file__).resolve().parents[2] / "tools" / "lexical_anchor_denylist.txt"
    keywords = module.build_keyword_denylist(denylist_path)
    lowered_keywords = {entry.lower() for entry in keywords}
    assert_true("ida" in lowered_keywords, "expected ida token in keyword denylist")
    assert_true("cheat engine" in lowered_keywords, "expected cheat engine token in keyword denylist")
    assert_true("ollydbg" in lowered_keywords, "expected ollydbg token in keyword denylist")

    with tempfile.TemporaryDirectory(prefix="eippf_redteam_contract_") as tmp_dir:
        sample_path = Path(tmp_dir) / "sample.bin"
        sample_path.write_bytes(b"\x00hidden\x00IDA Pro anchor\x00")
        findings = module.scan_artifact_for_keywords(sample_path, keywords)
    assert_true(findings, "expected static keyword findings for ida-labeled sample")
    assert_true(
        any("ida" in entry.lower() for entry in findings),
        f"expected ida finding, got: {findings}",
    )

    with tempfile.TemporaryDirectory(prefix="eippf_redteam_contract_fp_") as tmp_dir:
        sample_path = Path(tmp_dir) / "sample.bin"
        sample_path.write_bytes(
            b"\x00kApiCandidates\x00resolve_candidate\x00libgdbus-2.0.so\x00"
        )
        findings = module.scan_artifact_for_keywords(sample_path, keywords)
    assert_true(findings == [], f"expected no false positives for short keywords, got: {findings}")

    with tempfile.TemporaryDirectory(prefix="eippf_redteam_contract_tp_") as tmp_dir:
        sample_path = Path(tmp_dir) / "sample.bin"
        sample_path.write_bytes(b"\x00ida64.exe\x00gdbserver\x00liblldb.so\x00")
        findings = module.scan_artifact_for_keywords(sample_path, keywords)
    lowered_findings = {entry.lower() for entry in findings}
    assert_true(any("ida:ida64.exe" == entry for entry in lowered_findings), f"missing ida finding: {findings}")
    assert_true(
        any("gdbserver:gdbserver" == entry for entry in lowered_findings),
        f"missing gdbserver finding: {findings}",
    )
    assert_true(any("lldb:liblldb.so" == entry for entry in lowered_findings), f"missing lldb finding: {findings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
