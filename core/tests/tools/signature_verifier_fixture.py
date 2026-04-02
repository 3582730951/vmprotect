#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="EIPPF signature verifier fixture.")
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--artifact-kind", required=True)
    parser.add_argument("--target-kind", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--manifest")
    parser.add_argument(
        "--mode",
        required=True,
        choices=(
            "success",
            "reject",
            "invalid-json",
            "bad-schema",
            "digest-mismatch",
            "nonzero",
            "empty",
            "timeout",
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.mode == "success":
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "verified": True,
                    "reason": "fixture_success",
                    "artifact_sha256": args.artifact_sha256,
                }
            )
        )
        return 0

    if args.mode == "reject":
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "verified": False,
                    "reason": "fixture_reject",
                    "artifact_sha256": args.artifact_sha256,
                }
            )
        )
        return 0

    if args.mode == "invalid-json":
        sys.stdout.write("not json\n")
        return 0

    if args.mode == "bad-schema":
        print(
            json.dumps(
                {
                    "schema_version": "1",
                    "verified": "wrong",
                    "reason": 7,
                }
            )
        )
        return 0

    if args.mode == "digest-mismatch":
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "verified": True,
                    "reason": "fixture_digest_mismatch",
                    "artifact_sha256": "0" * 64,
                }
            )
        )
        return 0

    if args.mode == "nonzero":
        return 7

    if args.mode == "empty":
        return 0

    if args.mode == "timeout":
        time.sleep(2.0)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
