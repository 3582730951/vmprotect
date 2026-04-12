#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any


MANDATORY_KEYWORDS = (
    "ida",
    "idapro",
    "cheatengine",
    "cheat engine",
    "ollydbg",
    "x64dbg",
    "gdb",
    "gdbserver",
    "frida",
    "frida gadget",
    "xposed",
    "lsposed",
    "magisk",
    "zygisk",
    "jdwp",
    "tracerpid",
    "lldb",
    "substrate",
    "substitute",
)

REQUIRED_REPORT_FIELDS = (
    "artifact_id",
    "platform",
    "format",
    "protection_profile",
    "static_leak_pass",
    "dynamic_probe_pass",
    "runtime_dump_pass",
    "signature_policy_pass",
    "perf_budget_pass",
    "perf_delta_pct",
    "failure_reasons",
    "evidence_paths",
    "final_verdict",
)


def load_artifact_audit_module():
    module_path = Path(__file__).resolve().with_name("artifact_audit.py")
    spec = importlib.util.spec_from_file_location("artifact_audit", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load artifact_audit module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_keyword_denylist(denylist_path: Path) -> list[str]:
    artifact_audit = load_artifact_audit_module()
    entries, _ = artifact_audit.load_denylist(denylist_path)
    ordered: list[str] = []
    seen: set[str] = set()
    for item in list(entries) + list(MANDATORY_KEYWORDS):
        lowered = item.strip().lower()
        if not lowered or lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(item.strip())
    return ordered


def scan_artifact_for_keywords(artifact_path: Path, keywords: list[str]) -> list[str]:
    artifact_audit = load_artifact_audit_module()
    strings = artifact_audit.extract_strings(artifact_path.read_bytes())
    hits = artifact_audit.find_denylist_hits(strings, keywords, "string")
    findings: list[str] = []
    seen: set[str] = set()
    for hit in hits:
        keyword = str(hit.get("pattern", ""))
        line = str(hit.get("value", ""))
        finding = f"{keyword}:{line}"
        if finding.lower() in seen:
            continue
        seen.add(finding.lower())
        findings.append(finding)
    return findings


def calculate_perf_delta_pct(baseline_ms: float, protected_ms: float) -> float:
    if baseline_ms <= 0.0:
        return 100.0
    if protected_ms <= baseline_ms:
        return 0.0
    return ((protected_ms - baseline_ms) * 100.0) / baseline_ms


def validate_redteam_report(report_payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(report_payload, dict):
        return ["report must be an object"]
    if report_payload.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    generated_at = report_payload.get("generated_at_utc")
    if not isinstance(generated_at, str) or not generated_at:
        errors.append("generated_at_utc must be non-empty string")
    samples = report_payload.get("samples")
    if not isinstance(samples, list) or not samples:
        errors.append("samples must be a non-empty list")
        return errors

    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            errors.append(f"samples[{index}] must be object")
            continue
        sample_id = sample.get("artifact_id", f"index_{index}")
        for field in REQUIRED_REPORT_FIELDS:
            if field not in sample:
                errors.append(f"sample[{sample_id}] missing {field}")
        for field in (
            "artifact_id",
            "platform",
            "format",
            "protection_profile",
            "final_verdict",
        ):
            if field in sample and (not isinstance(sample[field], str) or not sample[field]):
                errors.append(f"sample[{sample_id}] {field} must be non-empty string")
        for field in (
            "static_leak_pass",
            "dynamic_probe_pass",
            "runtime_dump_pass",
            "signature_policy_pass",
            "perf_budget_pass",
        ):
            if field in sample and not isinstance(sample[field], bool):
                errors.append(f"sample[{sample_id}] {field} must be boolean")
        if not isinstance(sample.get("failure_reasons"), list):
            errors.append(f"sample[{sample_id}] failure_reasons must be list")
        if not isinstance(sample.get("evidence_paths"), list):
            errors.append(f"sample[{sample_id}] evidence_paths must be list")
        perf_delta_pct = sample.get("perf_delta_pct")
        if not isinstance(perf_delta_pct, (int, float)):
            errors.append(f"sample[{sample_id}] perf_delta_pct must be numeric")
        else:
            perf_budget_pass = sample.get("perf_budget_pass")
            if perf_budget_pass is True and float(perf_delta_pct) > 10.0:
                errors.append(
                    f"sample[{sample_id}] perf_budget_pass cannot be true when perf_delta_pct > 10"
                )
        final_verdict = sample.get("final_verdict")
        hard_failures = (
            sample.get("static_leak_pass") is False
            or sample.get("dynamic_probe_pass") is False
            or sample.get("runtime_dump_pass") is False
            or sample.get("signature_policy_pass") is False
            or sample.get("perf_budget_pass") is False
        )
        if final_verdict == "pass" and hard_failures:
            errors.append(f"sample[{sample_id}] final_verdict cannot be pass with failed hard gate")
        if final_verdict not in ("pass", "fail"):
            errors.append(f"sample[{sample_id}] final_verdict must be pass or fail")
    return errors


def load_json_or_empty(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def pick_artifact_relpath(sample: dict[str, Any]) -> str | None:
    signed_policy_relpath = sample.get("signed_policy_relpath")
    if isinstance(signed_policy_relpath, str) and signed_policy_relpath:
        return signed_policy_relpath
    protected_relpath = sample.get("protected_relpath")
    if isinstance(protected_relpath, str) and protected_relpath:
        return protected_relpath
    return None


def runtime_probe_required(sample: dict[str, Any]) -> bool:
    runtime_probe = sample.get("runtime_probe")
    if isinstance(runtime_probe, dict):
        required = runtime_probe.get("required")
        if isinstance(required, bool):
            return required
    sample_id = str(sample.get("id", ""))
    return sample_id in {"windows_exe", "linux_elf"}


def build_sample_report(
    sample: dict[str, Any],
    summary_root: Path,
    keywords: list[str],
    probe_results: dict[str, Any],
    perf_results: dict[str, Any],
) -> dict[str, Any]:
    sample_id = str(sample.get("id", "unknown"))
    artifact_relpath = pick_artifact_relpath(sample)
    evidence_paths: list[str] = []
    failure_reasons: list[str] = []
    static_leak_pass = True
    signature_policy_pass = True

    findings: list[str] = []
    if artifact_relpath is None:
        static_leak_pass = False
        failure_reasons.append("missing_artifact_relpath")
    else:
        artifact_path = (summary_root / artifact_relpath).resolve()
        evidence_paths.append(str(artifact_path))
        if not artifact_path.exists():
            static_leak_pass = False
            failure_reasons.append("artifact_missing")
        else:
            findings = scan_artifact_for_keywords(artifact_path, keywords)
            if findings:
                static_leak_pass = False
                failure_reasons.extend(f"static_keyword:{entry}" for entry in findings)

    if bool(sample.get("protected_anchor_visible", False)):
        static_leak_pass = False
        failure_reasons.append("protected_anchor_visible")

    artifact_shape = sample.get("artifact_shape", {})
    strict_failures = artifact_shape.get("strict_failures", []) if isinstance(artifact_shape, dict) else []
    if isinstance(strict_failures, list) and strict_failures:
        static_leak_pass = False
        failure_reasons.extend(f"artifact_shape:{item}" for item in strict_failures)

    signed_policy = sample.get("signed_policy")
    if isinstance(signed_policy, dict):
        signed_failures = signed_policy.get("strict_failures", [])
        if isinstance(signed_failures, list) and signed_failures:
            signature_policy_pass = False
            failure_reasons.extend(f"signed_policy:{item}" for item in signed_failures)

    sample_probe = probe_results.get(sample_id, {})
    if isinstance(sample_probe, dict) and sample_probe:
        dynamic_probe_pass = bool(sample_probe.get("dynamic_probe_pass", False))
        runtime_dump_pass = bool(sample_probe.get("runtime_dump_pass", False))
        if not dynamic_probe_pass:
            failure_reasons.append("dynamic_probe_failed")
        if not runtime_dump_pass:
            failure_reasons.append("runtime_dump_failed")
        if isinstance(sample_probe.get("failure_reasons"), list):
            failure_reasons.extend(str(item) for item in sample_probe["failure_reasons"])
        if isinstance(sample_probe.get("evidence_paths"), list):
            evidence_paths.extend(str(item) for item in sample_probe["evidence_paths"])
    else:
        if runtime_probe_required(sample):
            dynamic_probe_pass = False
            runtime_dump_pass = False
            failure_reasons.append("dynamic_probe_missing")
            failure_reasons.append("runtime_dump_missing")
        else:
            dynamic_probe_pass = True
            runtime_dump_pass = True

    perf_entry = perf_results.get(sample_id, {})
    perf_delta_pct = 100.0
    if isinstance(perf_entry, dict):
        if "perf_delta_pct" in perf_entry and isinstance(perf_entry["perf_delta_pct"], (int, float)):
            perf_delta_pct = float(perf_entry["perf_delta_pct"])
        elif (
            isinstance(perf_entry.get("baseline_ms"), (int, float))
            and isinstance(perf_entry.get("protected_ms"), (int, float))
        ):
            perf_delta_pct = calculate_perf_delta_pct(
                float(perf_entry["baseline_ms"]),
                float(perf_entry["protected_ms"]),
            )
    perf_budget_pass = perf_delta_pct <= 10.0
    if not perf_budget_pass:
        failure_reasons.append("perf_budget_exceeded")

    final_verdict = (
        "pass"
        if static_leak_pass
        and dynamic_probe_pass
        and runtime_dump_pass
        and signature_policy_pass
        and perf_budget_pass
        else "fail"
    )

    return {
        "artifact_id": sample_id,
        "platform": str(sample.get("platform", "")),
        "format": str(sample.get("artifact_kind", "")),
        "protection_profile": str(sample.get("target_kind", "")),
        "static_leak_pass": static_leak_pass,
        "dynamic_probe_pass": dynamic_probe_pass,
        "runtime_dump_pass": runtime_dump_pass,
        "signature_policy_pass": signature_policy_pass,
        "perf_budget_pass": perf_budget_pass,
        "perf_delta_pct": perf_delta_pct,
        "failure_reasons": failure_reasons,
        "evidence_paths": evidence_paths,
        "final_verdict": final_verdict,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a redteam gate report for protected artifacts.")
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--denylist", type=Path, required=True)
    parser.add_argument("--probe-results", type=Path)
    parser.add_argument("--perf-results", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary_payload = json.loads(args.summary.read_text(encoding="utf-8"))
    samples = summary_payload.get("samples", [])
    if not isinstance(samples, list) or not samples:
        raise SystemExit("summary missing samples")

    summary_root = args.summary.resolve().parent
    keywords = build_keyword_denylist(args.denylist.resolve())
    probe_results = load_json_or_empty(args.probe_results.resolve() if args.probe_results else None)
    perf_results = load_json_or_empty(args.perf_results.resolve() if args.perf_results else None)

    report = {
        "schema_version": 1,
        "generated_at_utc": summary_payload.get("generated_at_utc", ""),
        "samples": [
            build_sample_report(sample, summary_root, keywords, probe_results, perf_results)
            for sample in samples
        ],
    }
    errors = validate_redteam_report(report)
    if errors:
      report["contract_errors"] = errors
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
