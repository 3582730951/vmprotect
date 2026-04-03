#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
from pathlib import Path


SIGNED_POLICY_IDS = {"windows_sys", "linux_ko", "android_ko", "ios_macho"}
SAMPLE_IDS = [
    "windows_exe",
    "windows_dll",
    "windows_sys",
    "linux_elf",
    "linux_so",
    "linux_ko",
    "android_so",
    "android_dex",
    "android_ko",
    "ios_macho",
    "shell_script",
]


def load_protect_and_evaluate_module():
    module_path = Path(__file__).resolve().parents[2] / "tools" / "sample_suite" / "protect_and_evaluate.py"
    spec = importlib.util.spec_from_file_location("protect_and_evaluate", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load protect_and_evaluate module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_summary_samples() -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for sample_id in SAMPLE_IDS:
        item: dict[str, object] = {
            "id": sample_id,
            "target_kind": "desktop_native",
            "protect_via": "post_link_mutator",
            "build_mode": "wrapper",
            "requires_signed_policy": sample_id in SIGNED_POLICY_IDS,
            "signature_fixture_kind": (
                "pe_win_certificate_stub"
                if sample_id == "windows_sys"
                else (
                    "elf_module_signature_stub"
                    if sample_id in {"linux_ko", "android_ko"}
                    else ("ios_trusted_verifier_only" if sample_id == "ios_macho" else "none")
                )
            ),
            "input_relpath": f"{sample_id}/input.bin",
            "protected_relpath": f"protected/{sample_id}/output.bin",
            "input_sha256": "1" * 64,
            "output_sha256": "2" * 64,
            "original_size": 10,
            "protected_size": 12,
            "original_file_desc": "fixture-original",
            "protected_file_desc": "fixture-protected",
            "anchor_strings": [f"EIPPF_SAMPLE_ANCHOR_{sample_id.upper()}"],
            "original_anchor_visible": True,
            "protected_anchor_visible": False,
            "original_string_count": 10,
            "protected_string_count": 2,
            "artifact_shape": {
                "audit_relpath": f"audit/{sample_id}.artifact_shape.audit.json",
                "strict_failures": [],
            },
            "failure_classification": {
                "implementation_defects": [],
                "policy_only_unsigned": [],
            },
            "validation_scope": "fixture scope",
            "known_limits": "fixture limits",
        }
        if sample_id in {"windows_sys", "linux_ko", "android_ko"}:
            item["artifact_shape"] = {
                "audit_relpath": f"audit/{sample_id}.artifact_shape.audit.json",
                "strict_failures": ["signature_missing"],
            }
            item["failure_classification"] = {
                "implementation_defects": [],
                "policy_only_unsigned": ["signature_missing"],
            }
        if sample_id in SIGNED_POLICY_IDS:
            item["signed_policy_relpath"] = f"signed_policy/{sample_id}/output.bin"
            item["signed_policy_sha256"] = "3" * 64
            item["signed_policy"] = {
                "audit_relpath": f"audit/{sample_id}.signed_policy.audit.json",
                "audited_relpath": f"signed_policy/{sample_id}/output.bin",
                "strict_failures": [],
                "verifier_relpath": "logs/verifiers/trusted_verifier_success.py",
                "verifier_sha256": "4" * 64,
            }
        if sample_id == "linux_so":
            item["failure_classification"] = {
                "implementation_defects": ["imports_policy_failed"],
                "policy_only_unsigned": [],
            }
        items.append(item)
    return items


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    module = load_protect_and_evaluate_module()
    samples = build_summary_samples()
    summary_payload = {
        "schema_version": 2,
        "generated_at_utc": "2026-04-03T00:00:00+00:00",
        "samples": samples,
    }

    errors = module.validate_summary_contract(summary_payload)
    assert_true(errors == [], f"expected valid summary contract, got: {errors}")

    bad_payload = copy.deepcopy(summary_payload)
    for item in bad_payload["samples"]:
        if item["id"] == "ios_macho":
            item.pop("signed_policy", None)
            break
    bad_errors = module.validate_summary_contract(bad_payload)
    assert_true(
        any("ios_macho" in entry for entry in bad_errors),
        f"expected ios_macho contract violation, got: {bad_errors}",
    )

    bad_hash_payload = copy.deepcopy(summary_payload)
    for item in bad_hash_payload["samples"]:
        if item["id"] == "android_so":
            item["input_sha256"] = "1234"
            break
    bad_hash_errors = module.validate_summary_contract(bad_hash_payload)
    assert_true(
        any("input_sha256" in entry for entry in bad_hash_errors),
        f"expected input_sha256 contract violation, got: {bad_hash_errors}",
    )

    bad_missing_id_payload = copy.deepcopy(summary_payload)
    bad_missing_id_payload["samples"] = [
        item for item in bad_missing_id_payload["samples"] if item["id"] != "shell_script"
    ]
    bad_missing_id_errors = module.validate_summary_contract(bad_missing_id_payload)
    assert_true(
        any("missing sample ids" in entry for entry in bad_missing_id_errors),
        f"expected missing sample id violation, got: {bad_missing_id_errors}",
    )

    template_path = Path(__file__).resolve().parents[2] / "tools" / "sample_suite" / "report_template.html"
    with tempfile.TemporaryDirectory(prefix="eippf_report_contract_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        summary_path = tmp_root / "summary.json"
        summary_path.write_text(json.dumps(summary_payload, indent=2, sort_keys=True), encoding="utf-8")
        report_path = tmp_root / "report.html"
        module.render_report(template_path, report_path, summary_payload["generated_at_utc"], samples)
        report_html = report_path.read_text(encoding="utf-8")

    assert_true("Artifact Shape" in report_html, "report missing Artifact Shape section")
    assert_true("Signed Policy" in report_html, "report missing Signed Policy section")
    assert_true("Implementation Defects" in report_html, "report missing Implementation Defects section")
    assert_true("Validation Scope" in report_html, "report missing validation_scope rendering")
    assert_true("Known Limits" in report_html, "report missing known_limits rendering")
    assert_true("Input SHA256" in report_html, "report missing input_sha256 rendering")
    assert_true("Output SHA256" in report_html, "report missing output_sha256 rendering")
    for signed_sample in sorted(SIGNED_POLICY_IDS):
        assert_true(signed_sample in report_html, f"report missing signed sample row: {signed_sample}")
    assert_true("imports_policy_failed" in report_html, "report missing implementation defect rendering")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
