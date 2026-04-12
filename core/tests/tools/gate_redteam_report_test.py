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
    tool_path = Path(__file__).resolve().parents[2] / "tools" / "sample_suite" / "gate_redteam_report.py"
    with tempfile.TemporaryDirectory(prefix="eippf_redteam_gate_") as tmp_dir:
        report_path = Path(tmp_dir) / "redteam.json"
        report_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at_utc": "2026-04-12T00:00:00+00:00",
                    "samples": [
                        {
                            "artifact_id": "linux_elf",
                            "final_verdict": "pass",
                            "failure_reasons": [],
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            ["python3", str(tool_path), "--report", str(report_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert_true(completed.returncode == 0, f"expected pass report to succeed, got: {completed.stderr}")

        report_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at_utc": "2026-04-12T00:00:00+00:00",
                    "samples": [
                        {
                            "artifact_id": "linux_elf",
                            "final_verdict": "fail",
                            "failure_reasons": ["perf_budget_exceeded"],
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            ["python3", str(tool_path), "--report", str(report_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert_true(completed.returncode != 0, "expected failing report to trip the gate")
        assert_true(
            "linux_elf:perf_budget_exceeded" in completed.stderr,
            f"expected sample failure in stderr, got: {completed.stderr}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
