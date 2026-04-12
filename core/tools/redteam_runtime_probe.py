#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a host-side runtime redteam probe against one sample.")
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--command", required=True, help="Command used to start the target sample.")
    parser.add_argument("--anchor", required=True)
    parser.add_argument("--probe-tool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--hold-ms", type=int, default=3000)
    parser.add_argument("--startup-delay-ms", type=int, default=300)
    parser.add_argument("--completion-timeout-ms", type=int, default=5000)
    parser.add_argument("--guard-exit-code", type=int, default=120)
    parser.add_argument("--working-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env = os.environ.copy()
    env["EIPPF_SAMPLE_HOLD_MS"] = str(max(args.hold_ms, 1))

    command = shlex.split(args.command)
    cwd = str(args.working_dir.resolve()) if args.working_dir else None
    process = subprocess.Popen(command, cwd=cwd, env=env)

    try:
        time.sleep(max(args.startup_delay_ms, 0) / 1000.0)
        with tempfile.TemporaryDirectory(prefix="eippf_runtime_probe_") as tmp_dir:
            probe_json = Path(tmp_dir) / "probe.json"
            completed = subprocess.run(
                [
                    str(args.probe_tool.resolve()),
                    "--pid",
                    str(process.pid),
                    "--scan-anchor",
                    args.anchor,
                    "--json-out",
                    str(probe_json),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            probe_payload = (
                json.loads(probe_json.read_text(encoding="utf-8"))
                if probe_json.exists()
                else {"attach_succeeded": False, "anchor_found": False, "error": "probe_output_missing"}
            )
            failure_reasons: list[str] = []
            if completed.returncode != 0 and probe_payload.get("error"):
                failure_reasons.append(str(probe_payload["error"]))

            exit_code = None
            try:
                exit_code = process.wait(timeout=max(args.completion_timeout_ms, 0) / 1000.0)
            except subprocess.TimeoutExpired:
                exit_code = None

            attach_succeeded = bool(probe_payload.get("attach_succeeded", False))
            anchor_found = bool(probe_payload.get("anchor_found", False))
            guarded_exit = exit_code == args.guard_exit_code
            completed_normally = exit_code == 0
            if not attach_succeeded and not guarded_exit:
                failure_reasons.append("probe_attach_not_established")
            if exit_code is None:
                failure_reasons.append("probe_target_timeout")
            elif exit_code not in (0, args.guard_exit_code):
                failure_reasons.append(f"probe_target_exit:{exit_code}")

            dynamic_probe_pass = guarded_exit or (
                attach_succeeded and not anchor_found and completed_normally
            )

            result = {
                args.sample_id: {
                    "dynamic_probe_pass": dynamic_probe_pass,
                    "runtime_dump_pass": guarded_exit or (attach_succeeded and not anchor_found),
                    "attach_succeeded": attach_succeeded,
                    "anchor_found": anchor_found,
                    "exit_code": exit_code,
                    "failure_reasons": failure_reasons,
                    "evidence_paths": [str(probe_json)],
                }
            }
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
