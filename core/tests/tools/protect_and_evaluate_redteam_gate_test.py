#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path


def load_protect_and_evaluate_module():
    module_path = Path(__file__).resolve().parents[2] / "tools" / "sample_suite" / "protect_and_evaluate.py"
    spec = importlib.util.spec_from_file_location("protect_and_evaluate", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load protect_and_evaluate module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def build_summary(protected_name: str) -> dict[str, object]:
    return {
        "schema_version": 2,
        "generated_at_utc": "2026-04-12T00:00:00+00:00",
        "samples": [
            {
                "id": "linux_elf",
                "platform": "linux",
                "artifact_kind": "elf",
                "target_kind": "desktop_native",
                "protect_via": "post_link_mutator",
                "build_mode": "wrapper_pass_pipeline",
                "requires_signed_policy": False,
                "signature_fixture_kind": "none",
                "input_relpath": "linux_elf/sample_linux_elf",
                "output_name": protected_name,
                "protected_relpath": protected_name,
                "input_sha256": "1" * 64,
                "output_sha256": "2" * 64,
                "original_size": 10,
                "protected_size": 12,
                "original_file_desc": "fixture-original",
                "protected_file_desc": "fixture-protected",
                "anchor_strings": ["EIPPF_SAMPLE_ANCHOR_LINUX_ELF"],
                "original_anchor_visible": True,
                "protected_anchor_visible": False,
                "original_string_count": 10,
                "protected_string_count": 2,
                "artifact_shape": {"strict_failures": []},
                "failure_classification": {
                    "implementation_defects": [],
                    "policy_only_unsigned": [],
                },
                "validation_scope": "fixture scope",
                "known_limits": "fixture limits",
                "runtime_probe": {
                    "required": True,
                    "host": "linux",
                    "hold_ms": 3000,
                    "startup_delay_ms": 300,
                    "guard_exit_code": 120,
                },
            }
        ],
    }


def main() -> int:
    module = load_protect_and_evaluate_module()
    denylist_path = Path(__file__).resolve().parents[2] / "tools" / "lexical_anchor_denylist.txt"

    with tempfile.TemporaryDirectory(prefix="eippf_protect_eval_gate_") as tmp_dir:
        root = Path(tmp_dir)
        summary_path = root / "summary.json"
        report_path = root / "redteam.json"
        probe_path = root / "probe.json"
        perf_path = root / "perf.json"
        protected_path = root / "protected.bin"

        protected_path.write_bytes(b"\x00IDA Pro anchor\x00")
        summary_path.write_text(json.dumps(build_summary("protected.bin"), indent=2) + "\n", encoding="utf-8")
        probe_path.write_text(
            json.dumps(
                {
                    "linux_elf": {
                        "dynamic_probe_pass": True,
                        "runtime_dump_pass": True,
                        "failure_reasons": [],
                        "evidence_paths": [],
                    }
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        perf_path.write_text(json.dumps({"linux_elf": {"perf_delta_pct": 0.0}}, indent=2) + "\n", encoding="utf-8")

        raised = False
        try:
            module.maybe_generate_redteam_report(summary_path, report_path, denylist_path, probe_path, perf_path)
        except RuntimeError as exc:
            raised = "redteam gate failed" in str(exc)
        assert_true(raised, "expected failing redteam report to raise runtime error")

        protected_path.write_bytes(b"\x00EIPPF_SAFE_RUNTIME_PAYLOAD\x00")
        module.maybe_generate_redteam_report(summary_path, report_path, denylist_path, probe_path, perf_path)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert_true(report["samples"][0]["final_verdict"] == "pass", f"expected passing report, got: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
