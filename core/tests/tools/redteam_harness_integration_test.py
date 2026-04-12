#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_summary(
    sample_id: str,
    platform: str,
    artifact_kind: str,
    protected_relpath: str,
    protected_anchor_visible: bool = False,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "generated_at_utc": "2026-04-12T00:00:00+00:00",
        "samples": [
            {
                "id": sample_id,
                "platform": platform,
                "artifact_kind": artifact_kind,
                "target_kind": "desktop_native_strict",
                "protected_relpath": protected_relpath,
                "protected_anchor_visible": protected_anchor_visible,
                "artifact_shape": {"strict_failures": []},
                "signed_policy": {"strict_failures": []},
            }
        ],
    }


def run_harness(summary_path: Path, output_path: Path, probe_path: Path, perf_path: Path) -> subprocess.CompletedProcess[str]:
    tool_path = Path(__file__).resolve().parents[2] / "tools" / "redteam_harness.py"
    denylist_path = Path(__file__).resolve().parents[2] / "tools" / "lexical_anchor_denylist.txt"
    return subprocess.run(
        [
            "python3",
            str(tool_path),
            "--summary",
            str(summary_path),
            "--output",
            str(output_path),
            "--denylist",
            str(denylist_path),
            "--probe-results",
            str(probe_path),
            "--perf-results",
            str(perf_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="eippf_redteam_harness_") as tmp_dir:
        root = Path(tmp_dir)

        protected_dir = root / "protected"
        protected_dir.mkdir(parents=True, exist_ok=True)

        clean_artifact = protected_dir / "clean.bin"
        clean_artifact.write_bytes(b"\x00EIPPF_SAFE_RUNTIME_PAYLOAD\x00")

        summary_path = root / "summary.json"
        output_path = root / "redteam.json"
        probe_path = root / "probes.json"
        perf_path = root / "perf.json"

        write_json(summary_path, build_summary("linux_elf", "linux", "elf", "protected/clean.bin"))
        write_json(
            probe_path,
            {
                "linux_elf": {
                    "dynamic_probe_pass": True,
                    "runtime_dump_pass": True,
                    "failure_reasons": [],
                    "evidence_paths": ["logs/linux_elf.dynamic.json"],
                }
            },
        )
        write_json(perf_path, {"linux_elf": {"perf_delta_pct": 4.5}})

        completed = run_harness(summary_path, output_path, probe_path, perf_path)
        assert_true(completed.returncode == 0, f"expected harness success, got: {completed.stderr}")
        report = json.loads(output_path.read_text(encoding="utf-8"))
        sample = report["samples"][0]
        assert_true(sample["final_verdict"] == "pass", f"expected pass verdict, got: {sample}")

        flagged_artifact = protected_dir / "flagged.bin"
        flagged_artifact.write_bytes(b"\x00IDA Pro anchor\x00")
        write_json(summary_path, build_summary("linux_elf", "linux", "elf", "protected/flagged.bin"))

        completed = run_harness(summary_path, output_path, probe_path, perf_path)
        assert_true(completed.returncode == 0, f"expected harness output generation on failure, got: {completed.stderr}")
        report = json.loads(output_path.read_text(encoding="utf-8"))
        sample = report["samples"][0]
        assert_true(sample["final_verdict"] == "fail", f"expected fail verdict, got: {sample}")
        assert_true(
            any("static_keyword" in entry for entry in sample["failure_reasons"]),
            f"expected static keyword failure reason, got: {sample['failure_reasons']}",
        )

        write_json(summary_path, build_summary("windows_dll", "windows", "pe", "protected/clean.bin"))
        write_json(probe_path, {})
        write_json(perf_path, {"windows_dll": {"perf_delta_pct": 4.0}})
        completed = run_harness(summary_path, output_path, probe_path, perf_path)
        assert_true(completed.returncode == 0, f"expected optional probe sample to pass, got: {completed.stderr}")
        report = json.loads(output_path.read_text(encoding="utf-8"))
        sample = report["samples"][0]
        assert_true(sample["dynamic_probe_pass"] is True, f"expected optional probe pass, got: {sample}")
        assert_true(sample["runtime_dump_pass"] is True, f"expected optional dump pass, got: {sample}")

        false_positive_artifact = protected_dir / "false_positive.bin"
        false_positive_artifact.write_bytes(
            b"\x00kApiCandidates\x00resolve_candidate\x00libgdbus-2.0.so\x00"
        )
        write_json(summary_path, build_summary("windows_dll", "windows", "pe", "protected/false_positive.bin"))
        completed = run_harness(summary_path, output_path, probe_path, perf_path)
        assert_true(completed.returncode == 0, f"expected false-positive sample to stay pass, got: {completed.stderr}")
        report = json.loads(output_path.read_text(encoding="utf-8"))
        sample = report["samples"][0]
        assert_true(sample["final_verdict"] == "pass", f"expected pass for false-positive artifact, got: {sample}")

        true_positive_artifact = protected_dir / "true_positive.bin"
        true_positive_artifact.write_bytes(b"\x00ida64.exe\x00liblldb.so\x00")
        write_json(summary_path, build_summary("windows_dll", "windows", "pe", "protected/true_positive.bin"))
        completed = run_harness(summary_path, output_path, probe_path, perf_path)
        assert_true(completed.returncode == 0, f"expected harness output generation on fail, got: {completed.stderr}")
        report = json.loads(output_path.read_text(encoding="utf-8"))
        sample = report["samples"][0]
        assert_true(sample["final_verdict"] == "fail", f"expected fail for true-positive artifact, got: {sample}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
