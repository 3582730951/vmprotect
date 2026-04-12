#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run host-specific runtime probes for sample-suite evidence.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--probe-tool", type=Path, required=True)
    parser.add_argument("--host", choices=("linux", "windows"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_manifest(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    samples = payload.get("samples")
    if not isinstance(samples, list):
        raise ValueError("manifest samples must be a list")
    return [sample for sample in samples if isinstance(sample, dict)]


def probe_config_for_host(sample: dict[str, Any], host: str) -> dict[str, Any] | None:
    runtime_probe = sample.get("runtime_probe")
    if not isinstance(runtime_probe, dict):
        return None
    if runtime_probe.get("required") is not True:
        return None
    if runtime_probe.get("host") != host:
        return None
    return runtime_probe


def missing_probe_result(sample_id: str, artifact_path: Path, reason: str) -> dict[str, Any]:
    return {
        sample_id: {
            "anchor_found": False,
            "attach_succeeded": False,
            "dynamic_probe_pass": False,
            "runtime_dump_pass": False,
            "exit_code": -1,
            "failure_reasons": [reason],
            "evidence_paths": [str(artifact_path.resolve())],
        }
    }


def run_single_probe(
    sample: dict[str, Any],
    runtime_probe: dict[str, Any],
    evidence_root: Path,
    probe_tool: Path,
) -> dict[str, Any]:
    sample_id = str(sample["id"])
    output_name = str(sample.get("output_name", ""))
    anchors = sample.get("anchor_strings")
    if not output_name or not isinstance(anchors, list) or not anchors or not isinstance(anchors[0], str):
        return missing_probe_result(sample_id, evidence_root / "protected" / sample_id / output_name, "probe_manifest_invalid")

    artifact_path = (evidence_root / "protected" / sample_id / output_name).resolve()
    if not artifact_path.exists():
        return missing_probe_result(sample_id, artifact_path, "probe_target_missing")

    runtime_probe_tool = Path(__file__).resolve().parents[1] / "redteam_runtime_probe.py"
    if not runtime_probe_tool.exists():
        raise FileNotFoundError(f"missing runtime probe tool: {runtime_probe_tool}")

    hold_ms = int(runtime_probe.get("hold_ms", 3000))
    startup_delay_ms = int(runtime_probe.get("startup_delay_ms", 300))
    guard_exit_code = int(runtime_probe.get("guard_exit_code", 120))

    with tempfile.TemporaryDirectory(prefix=f"eippf_runtime_probe_{sample_id}_") as tmp_dir:
        result_path = Path(tmp_dir) / f"{sample_id}.json"
        command = [
            sys.executable,
            str(runtime_probe_tool),
            "--sample-id",
            sample_id,
            "--command",
            str(artifact_path),
            "--anchor",
            anchors[0],
            "--probe-tool",
            str(probe_tool.resolve()),
            "--output",
            str(result_path),
            "--hold-ms",
            str(hold_ms),
            "--startup-delay-ms",
            str(startup_delay_ms),
            "--guard-exit-code",
            str(guard_exit_code),
        ]
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        if completed.returncode != 0:
            return {
                sample_id: {
                    "anchor_found": False,
                    "attach_succeeded": False,
                    "dynamic_probe_pass": False,
                    "runtime_dump_pass": False,
                    "exit_code": completed.returncode,
                    "failure_reasons": [
                        "runtime_probe_invocation_failed",
                        completed.stderr.strip() or completed.stdout.strip() or "probe subprocess failed",
                    ],
                    "evidence_paths": [str(artifact_path)],
                }
            }
        return json.loads(result_path.read_text(encoding="utf-8"))


def main() -> int:
    args = parse_args()
    samples = load_manifest(args.manifest.resolve())
    combined: dict[str, Any] = {}

    for sample in samples:
        runtime_probe = probe_config_for_host(sample, args.host)
        if runtime_probe is None:
            continue
        combined.update(
            run_single_probe(sample, runtime_probe, args.evidence_root.resolve(), args.probe_tool.resolve())
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(combined, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
