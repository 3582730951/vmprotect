#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


USER_MODE_LANE_TO_SAMPLES = {
    "windows_exe_dll": ("windows_exe", "windows_dll"),
    "linux_elf_so": ("linux_elf", "linux_so"),
    "android_so_vs_linux_so": ("android_so",),
}

RUNTIME_PERF_TARGETS = {
    "windows_driver_perf_smoke_test": ("windows_sys",),
    "linux_kernel_module_perf_smoke_test": ("linux_ko",),
    "android_kernel_module_perf_smoke_test": ("android_ko",),
    "ios_safe_perf_smoke_test": ("ios_macho",),
}

SINGLE_OUTPUT_TARGETS = {
    "dex_loader_perf_smoke_test": ("android_dex",),
    "shell_launcher_perf_smoke_test": ("shell_script",),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect perf smoke outputs into redteam perf results.")
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def find_executable(build_root: Path, executable_name: str) -> Path:
    candidates = sorted(build_root.rglob(executable_name))
    if not candidates:
        raise FileNotFoundError(f"missing executable: {executable_name}")
    return candidates[0]


def run_executable(path: Path) -> str:
    completed = subprocess.run(
        [str(path.resolve())],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{path.name} failed rc={completed.returncode}\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return completed.stdout


def parse_user_mode_output(stdout: str) -> dict[str, dict[str, float | str]]:
    results: dict[str, dict[str, float | str]] = {}
    pattern = re.compile(r"^\[PERF\]\s+lane=(?P<lane>\S+)\s+.*result_pct=(?P<delta>[0-9.]+)\s+", re.MULTILINE)
    for match in pattern.finditer(stdout):
        lane = match.group("lane")
        if lane not in USER_MODE_LANE_TO_SAMPLES:
            continue
        delta = float(match.group("delta"))
        for sample_id in USER_MODE_LANE_TO_SAMPLES[lane]:
            results[sample_id] = {
                "perf_delta_pct": delta,
                "source": f"user_mode_perf_smoke_test:{lane}",
            }
    return results


def parse_runtime_lane_output(executable_name: str, stdout: str) -> dict[str, dict[str, float | str]]:
    targets = RUNTIME_PERF_TARGETS[executable_name]
    match = re.search(r"overall_overhead_pct=(?P<delta>[0-9.]+)", stdout)
    if match is None:
        raise ValueError(f"{executable_name} missing overall_overhead_pct")
    delta = float(match.group("delta"))
    return {
        sample_id: {
            "perf_delta_pct": delta,
            "source": executable_name,
        }
        for sample_id in targets
    }


def parse_single_output(executable_name: str, stdout: str) -> dict[str, dict[str, float | str]]:
    targets = SINGLE_OUTPUT_TARGETS[executable_name]
    match = re.search(r"overall_overhead_percent=(?P<delta>[0-9.]+)", stdout)
    if match is None:
        raise ValueError(f"{executable_name} missing overall_overhead_percent")
    delta = float(match.group("delta"))
    return {
        sample_id: {
            "perf_delta_pct": delta,
            "source": executable_name,
        }
        for sample_id in targets
    }


def merge_results(dest: dict[str, dict[str, float | str]], src: dict[str, dict[str, float | str]]) -> None:
    for sample_id, payload in src.items():
        dest[sample_id] = payload


def main() -> int:
    args = parse_args()
    build_root = args.build_root.resolve()

    result: dict[str, dict[str, float | str]] = {}

    user_mode_path = find_executable(build_root, "user_mode_perf_smoke_test")
    merge_results(result, parse_user_mode_output(run_executable(user_mode_path)))

    for executable_name in sorted(RUNTIME_PERF_TARGETS):
        path = find_executable(build_root, executable_name)
        merge_results(result, parse_runtime_lane_output(executable_name, run_executable(path)))

    for executable_name in sorted(SINGLE_OUTPUT_TARGETS):
        path = find_executable(build_root, executable_name)
        merge_results(result, parse_single_output(executable_name, run_executable(path)))

    expected_sample_ids = {
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
    }
    missing = sorted(expected_sample_ids - set(result))
    if missing:
        raise SystemExit("missing perf results for: " + ",".join(missing))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
