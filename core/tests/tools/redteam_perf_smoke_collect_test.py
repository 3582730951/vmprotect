#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    current = path.stat().st_mode
    path.chmod(current | stat.S_IXUSR)


def main() -> int:
    tool_path = Path(__file__).resolve().parents[2] / "tools" / "redteam_perf_smoke_collect.py"
    with tempfile.TemporaryDirectory(prefix="eippf_perf_collect_") as tmp_dir:
        root = Path(tmp_dir)
        perf_dir = root / "tests" / "perf"
        perf_dir.mkdir(parents=True, exist_ok=True)

        write_executable(
            perf_dir / "user_mode_perf_smoke_test",
            """#!/bin/sh
printf '%s\n' '[PERF] lane=windows_exe_dll baseline_ms=1 compared_ms=1.05 budget_pct=10 result_pct=5 status=PASS'
printf '%s\n' '[PERF] lane=linux_elf_so baseline_ms=1 compared_ms=1.07 budget_pct=10 result_pct=7 status=PASS'
printf '%s\n' '[PERF] lane=android_so_vs_linux_so baseline_ms=1 compared_ms=1.09 budget_pct=10 result_pct=9 status=PASS'
""",
        )
        write_executable(
            perf_dir / "windows_driver_perf_smoke_test",
            "#!/bin/sh\nprintf '%s\n' 'lane=windows_driver hot_path_overhead_pct=4.0 overall_overhead_pct=6.5 status=PASS'\n",
        )
        write_executable(
            perf_dir / "linux_kernel_module_perf_smoke_test",
            "#!/bin/sh\nprintf '%s\n' 'lane=linux_kernel_module hot_path_overhead_pct=4.0 overall_overhead_pct=6.0 status=PASS'\n",
        )
        write_executable(
            perf_dir / "android_kernel_module_perf_smoke_test",
            "#!/bin/sh\nprintf '%s\n' 'lane=android_kernel_module hot_path_overhead_pct=4.0 overall_overhead_pct=5.5 status=PASS'\n",
        )
        write_executable(
            perf_dir / "ios_safe_perf_smoke_test",
            "#!/bin/sh\nprintf '%s\n' 'lane=ios_safe hot_path_overhead_pct=3.0 overall_overhead_pct=4.5 status=PASS'\n",
        )
        write_executable(
            perf_dir / "dex_loader_perf_smoke_test",
            "#!/bin/sh\nprintf '%s\n' 'startup_overhead_ms=15.0'\nprintf '%s\n' 'overall_overhead_percent=8.5'\n",
        )
        write_executable(
            perf_dir / "shell_launcher_perf_smoke_test",
            "#!/bin/sh\nprintf '%s\n' 'startup_overhead_ms=20.0'\nprintf '%s\n' 'overall_overhead_percent=7.5'\n",
        )

        output_path = root / "perf.json"
        completed = subprocess.run(
            ["python3", str(tool_path), "--build-root", str(root), "--output", str(output_path)],
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ},
        )
        assert_true(completed.returncode == 0, f"collector failed: {completed.stderr}")

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert_true(payload["windows_exe"]["perf_delta_pct"] == 5.0, "windows_exe perf mismatch")
        assert_true(payload["windows_dll"]["perf_delta_pct"] == 5.0, "windows_dll perf mismatch")
        assert_true(payload["linux_elf"]["perf_delta_pct"] == 7.0, "linux_elf perf mismatch")
        assert_true(payload["linux_so"]["perf_delta_pct"] == 7.0, "linux_so perf mismatch")
        assert_true(payload["android_so"]["perf_delta_pct"] == 9.0, "android_so perf mismatch")
        assert_true(payload["windows_sys"]["perf_delta_pct"] == 6.5, "windows_sys perf mismatch")
        assert_true(payload["linux_ko"]["perf_delta_pct"] == 6.0, "linux_ko perf mismatch")
        assert_true(payload["android_ko"]["perf_delta_pct"] == 5.5, "android_ko perf mismatch")
        assert_true(payload["ios_macho"]["perf_delta_pct"] == 4.5, "ios_macho perf mismatch")
        assert_true(payload["android_dex"]["perf_delta_pct"] == 8.5, "android_dex perf mismatch")
        assert_true(payload["shell_script"]["perf_delta_pct"] == 7.5, "shell_script perf mismatch")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
