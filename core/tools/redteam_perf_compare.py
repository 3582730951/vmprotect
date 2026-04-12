#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measure baseline/protected perf delta for one sample.")
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--baseline-cmd", required=True)
    parser.add_argument("--protected-cmd", required=True)
    parser.add_argument("--iterations", type=int, default=15)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def run_command(command: str) -> float:
    start = time.perf_counter()
    completed = subprocess.run(command, shell=True, text=True, capture_output=True, check=False)
    end = time.perf_counter()
    if completed.returncode != 0:
      raise RuntimeError(
          f"command failed rc={completed.returncode}: {command}\nstdout={completed.stdout}\nstderr={completed.stderr}"
      )
    return (end - start) * 1000.0


def measure_best_ms(command: str, iterations: int) -> float:
    best = None
    for _ in range(max(iterations, 1)):
        current = run_command(command)
        best = current if best is None else min(best, current)
    return float(best if best is not None else 0.0)


def calculate_delta_pct(baseline_ms: float, protected_ms: float) -> float:
    if baseline_ms <= 0.0:
        return 100.0
    if protected_ms <= baseline_ms:
        return 0.0
    return ((protected_ms - baseline_ms) * 100.0) / baseline_ms


def main() -> int:
    args = parse_args()
    baseline_ms = measure_best_ms(args.baseline_cmd, args.iterations)
    protected_ms = measure_best_ms(args.protected_cmd, args.iterations)
    result = {
        args.sample_id: {
            "baseline_ms": baseline_ms,
            "protected_ms": protected_ms,
            "perf_delta_pct": calculate_delta_pct(baseline_ms, protected_ms),
        }
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
