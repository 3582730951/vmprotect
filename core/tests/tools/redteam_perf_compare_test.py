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
    tool_path = Path(__file__).resolve().parents[2] / "tools" / "redteam_perf_compare.py"
    with tempfile.TemporaryDirectory(prefix="eippf_redteam_perf_") as tmp_dir:
        output_path = Path(tmp_dir) / "perf.json"
        completed = subprocess.run(
            [
                "python3",
                str(tool_path),
                "--sample-id",
                "linux_elf",
                "--baseline-cmd",
                "python3 -c 'import time; time.sleep(0.01)'",
                "--protected-cmd",
                "python3 -c 'import time; time.sleep(0.02)'",
                "--iterations",
                "3",
                "--output",
                str(output_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert_true(completed.returncode == 0, f"perf compare should succeed, got: {completed.stderr}")
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert_true("linux_elf" in payload, f"missing linux_elf in perf payload: {payload}")
        result = payload["linux_elf"]
        assert_true(result["baseline_ms"] > 0.0, f"baseline_ms must be positive: {result}")
        assert_true(result["protected_ms"] > result["baseline_ms"], f"protected must be slower: {result}")
        assert_true(result["perf_delta_pct"] > 0.0, f"perf_delta_pct must be positive: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
