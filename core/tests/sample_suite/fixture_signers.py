#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import stat
from pathlib import Path


MODULE_SIGNATURE_MAGIC = b"~Module signature appended~\n"


def patch_pe_win_certificate_stub(in_path: str | Path, out_path: str | Path) -> None:
    source = Path(in_path)
    target = Path(out_path)
    data = bytearray(source.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("input is not PE-like MZ artifact")

    pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little", signed=False)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("input is not valid PE header")

    optional_offset = pe_offset + 24
    optional_magic = int.from_bytes(data[optional_offset : optional_offset + 2], "little")
    if optional_magic == 0x10B:
        data_directory_offset = optional_offset + 96
    elif optional_magic == 0x20B:
        data_directory_offset = optional_offset + 112
    else:
        raise ValueError("unsupported PE optional header magic")

    security_entry_offset = data_directory_offset + (4 * 8)
    if security_entry_offset + 8 > len(data):
        raise ValueError("truncated PE data directory")

    cert_offset = (len(data) + 7) & ~7
    if cert_offset > len(data):
        data.extend(b"\0" * (cert_offset - len(data)))
    cert_blob = (
        (8).to_bytes(4, "little")
        + (0x0200).to_bytes(2, "little")
        + (0x0002).to_bytes(2, "little")
    )
    data.extend(cert_blob)
    data[security_entry_offset : security_entry_offset + 4] = cert_offset.to_bytes(4, "little")
    data[security_entry_offset + 4 : security_entry_offset + 8] = len(cert_blob).to_bytes(4, "little")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def append_elf_module_signature_stub(in_path: str | Path, out_path: str | Path) -> None:
    source = Path(in_path)
    target = Path(out_path)
    data = source.read_bytes()
    signer = b"EIPPF"
    key_id = b"SAMPLE"
    signature = b"\x01\x02\x03\x04"
    payload = signer + key_id + signature
    footer = bytearray(12)
    footer[3] = len(signer)
    footer[4] = len(key_id)
    footer[8:12] = len(signature).to_bytes(4, byteorder="big")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data + payload + bytes(footer) + MODULE_SIGNATURE_MAGIC)


def make_trusted_verifier_wrapper(out_dir: str | Path, mode: str) -> Path:
    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = re.sub(r"[^a-zA-Z0-9_-]+", "_", mode.strip().lower())
    if not safe_mode:
        safe_mode = "success"
    wrapper_path = output_dir / f"trusted_verifier_{safe_mode}.py"
    wrapper = f"""#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys

MODE = {safe_mode!r}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="sample-suite trusted verifier wrapper")
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--artifact-kind", required=True)
    parser.add_argument("--target-kind", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--manifest")
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    if MODE == "nonzero":
        return 7
    if MODE == "empty":
        return 0
    if MODE == "invalid_json":
        sys.stdout.write("invalid json\\n")
        return 0
    if MODE == "digest_mismatch":
        print(
            json.dumps(
                {{
                    "schema_version": 1,
                    "verified": True,
                    "reason": "fixture_digest_mismatch",
                    "artifact_sha256": "0" * 64,
                }}
            )
        )
        return 0
    if MODE == "reject":
        print(
            json.dumps(
                {{
                    "schema_version": 1,
                    "verified": False,
                    "reason": "fixture_reject",
                    "artifact_sha256": args.artifact_sha256,
                }}
            )
        )
        return 0
    print(
        json.dumps(
            {{
                "schema_version": 1,
                "verified": True,
                "reason": "fixture_success",
                "artifact_sha256": args.artifact_sha256,
            }}
        )
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
"""
    wrapper_path.write_text(wrapper, encoding="utf-8")
    current_mode = wrapper_path.stat().st_mode
    wrapper_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper_path.resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="sample-suite fixture signers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    patch_pe = subparsers.add_parser("patch_pe_win_certificate_stub")
    patch_pe.add_argument("--in-path", required=True)
    patch_pe.add_argument("--out-path", required=True)

    patch_elf = subparsers.add_parser("append_elf_module_signature_stub")
    patch_elf.add_argument("--in-path", required=True)
    patch_elf.add_argument("--out-path", required=True)

    verifier = subparsers.add_parser("make_trusted_verifier_wrapper")
    verifier.add_argument("--out-dir", required=True)
    verifier.add_argument("--mode", required=True)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "patch_pe_win_certificate_stub":
        patch_pe_win_certificate_stub(args.in_path, args.out_path)
        print(str(Path(args.out_path).resolve()))
        return 0
    if args.command == "append_elf_module_signature_stub":
        append_elf_module_signature_stub(args.in_path, args.out_path)
        print(str(Path(args.out_path).resolve()))
        return 0
    wrapper_path = make_trusted_verifier_wrapper(args.out_dir, args.mode)
    print(str(wrapper_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
