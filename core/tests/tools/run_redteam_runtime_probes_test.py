#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    tool_path = Path(__file__).resolve().parents[2] / "tools" / "sample_suite" / "run_redteam_runtime_probes.py"
    with tempfile.TemporaryDirectory(prefix="eippf_runtime_probe_runner_") as tmp_dir:
        root = Path(tmp_dir)
        manifest_path = root / "manifest.json"
        evidence_root = root / "evidence"
        protected_root = evidence_root / "protected"
        protected_root.mkdir(parents=True, exist_ok=True)
        output_path = root / "probe_results.json"
        fake_probe_tool = root / "fake_probe_tool"
        fake_probe_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_probe_tool.chmod(0o755)

        manifest = {
            "schema_version": 2,
            "samples": [
                {
                    "id": "linux_elf",
                    "platform": "linux",
                    "artifact_kind": "elf",
                    "target_kind": "desktop_native",
                    "protect_via": "post_link_mutator",
                    "input_relpath": "linux_elf/sample_linux_elf",
                    "output_name": "sample_linux_elf",
                    "anchor_strings": ["EIPPF_SAMPLE_ANCHOR_LINUX_ELF"],
                    "validation_scope": "fixture scope",
                    "known_limits": "fixture limits",
                    "build_mode": "wrapper_pass_pipeline",
                    "requires_signed_policy": False,
                    "signature_fixture_kind": "none",
                    "runtime_probe": {
                        "required": True,
                        "host": "linux",
                        "hold_ms": 3000,
                        "startup_delay_ms": 300,
                        "guard_exit_code": 120,
                    },
                },
                {
                    "id": "windows_exe",
                    "platform": "windows",
                    "artifact_kind": "pe",
                    "target_kind": "desktop_native",
                    "protect_via": "post_link_mutator",
                    "input_relpath": "windows_exe/sample_windows.exe",
                    "output_name": "sample_windows.exe",
                    "anchor_strings": ["EIPPF_SAMPLE_ANCHOR_WINDOWS_EXE"],
                    "validation_scope": "fixture scope",
                    "known_limits": "fixture limits",
                    "build_mode": "wrapper_pass_pipeline",
                    "requires_signed_policy": False,
                    "signature_fixture_kind": "none",
                    "runtime_probe": {
                        "required": True,
                        "host": "windows",
                        "hold_ms": 3000,
                        "startup_delay_ms": 300,
                        "guard_exit_code": 120,
                    },
                },
            ],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        completed = subprocess.run(
            [
                "python3",
                str(tool_path),
                "--manifest",
                str(manifest_path),
                "--evidence-root",
                str(evidence_root),
                "--probe-tool",
                str(fake_probe_tool),
                "--host",
                "linux",
                "--output",
                str(output_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert_true(completed.returncode == 0, f"runtime probe runner should succeed, got: {completed.stderr}")
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert_true("linux_elf" in payload, f"expected linux probe result, got: {payload}")
        assert_true("windows_exe" not in payload, f"expected host filtering to skip windows sample, got: {payload}")
        result = payload["linux_elf"]
        assert_true(result["dynamic_probe_pass"] is False, f"missing artifact must fail closed: {result}")
        assert_true(result["runtime_dump_pass"] is False, f"missing artifact must fail closed: {result}")
        assert_true(
            "probe_target_missing" in result["failure_reasons"],
            f"expected missing target reason, got: {result}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
