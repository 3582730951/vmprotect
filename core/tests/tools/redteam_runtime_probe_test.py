#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    probe_tool = os.environ.get("EIPPF_REDTEAM_HOST_PROBE", "").strip()
    assert_true(probe_tool != "", "EIPPF_REDTEAM_HOST_PROBE must be set")

    runtime_probe = Path(__file__).resolve().parents[2] / "tools" / "redteam_runtime_probe.py"
    with tempfile.TemporaryDirectory(prefix="eippf_runtime_probe_test_") as tmp_dir:
        output_path = Path(tmp_dir) / "probe_results.json"
        completed = subprocess.run(
            [
                "python3",
                str(runtime_probe),
                "--sample-id",
                "linux_elf",
                "--command",
                f"{probe_tool} --hold-anchor EIPPF_REVERSE_ANCHOR_SELF_TEST --hold-seconds 10",
                "--anchor",
                "EIPPF_REVERSE_ANCHOR_SELF_TEST",
                "--probe-tool",
                probe_tool,
                "--output",
                str(output_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert_true(completed.returncode == 0, f"runtime probe should succeed, got: {completed.stderr}")
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        sample = payload["linux_elf"]
        assert_true(sample["dynamic_probe_pass"] is False, f"attach should succeed in self-probe: {sample}")
        assert_true(sample["runtime_dump_pass"] is False, f"anchor dump should succeed in self-probe: {sample}")

        failing_script = Path(tmp_dir) / "exit_1.sh"
        failing_script.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        failing_script.chmod(0o755)
        unexpected_output_path = Path(tmp_dir) / "unexpected_probe_results.json"
        completed = subprocess.run(
            [
                "python3",
                str(runtime_probe),
                "--sample-id",
                "linux_elf",
                "--command",
                str(failing_script),
                "--anchor",
                "EIPPF_REVERSE_ANCHOR_SELF_TEST",
                "--probe-tool",
                probe_tool,
                "--output",
                str(unexpected_output_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert_true(completed.returncode == 0, f"runtime probe should still emit failure payload, got: {completed.stderr}")
        payload = json.loads(unexpected_output_path.read_text(encoding="utf-8"))
        sample = payload["linux_elf"]
        assert_true(sample["dynamic_probe_pass"] is False, f"unexpected target exit must fail probe gate: {sample}")
        assert_true(sample["runtime_dump_pass"] is False, f"unexpected target exit must fail dump gate: {sample}")
        assert_true(
            "probe_attach_not_established" in sample["failure_reasons"],
            f"expected attach failure reason, got: {sample}",
        )
        assert_true(
            "probe_target_exit:1" in sample["failure_reasons"],
            f"expected target exit reason, got: {sample}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
