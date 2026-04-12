#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail closed when a redteam report contains any failing sample.")
    parser.add_argument("--report", type=Path, required=True)
    return parser.parse_args()


def load_report(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("redteam report must be a JSON object")
    return payload


def main() -> int:
    args = parse_args()
    payload = load_report(args.report.resolve())

    contract_errors = payload.get("contract_errors", [])
    if isinstance(contract_errors, list) and contract_errors:
        raise SystemExit("redteam contract errors: " + "; ".join(str(item) for item in contract_errors))

    samples = payload.get("samples")
    if not isinstance(samples, list) or not samples:
        raise SystemExit("redteam report missing samples")

    failures: list[str] = []
    for sample in samples:
        if not isinstance(sample, dict):
            failures.append("malformed_sample")
            continue
        if sample.get("final_verdict") == "pass":
            continue
        sample_id = str(sample.get("artifact_id", "unknown"))
        reasons = sample.get("failure_reasons", [])
        if isinstance(reasons, list) and reasons:
            failures.append(sample_id + ":" + ",".join(str(item) for item in reasons))
        else:
            failures.append(sample_id + ":redteam_failed")

    if failures:
        raise SystemExit("redteam gate failed: " + "; ".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
