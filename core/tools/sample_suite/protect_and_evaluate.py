#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import json
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROVIDER_PROTOCOL = "eippf.external_key.v1"
EXPECTED_SAMPLE_COUNT = 11

REQUIRED_SAMPLE_FIELDS = (
    "id",
    "platform",
    "artifact_kind",
    "target_kind",
    "protect_via",
    "input_relpath",
    "output_name",
    "anchor_strings",
    "validation_scope",
    "known_limits",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Protect sample-suite artifacts and generate reverse-view report."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str, executable: bool = False) -> None:
    path.write_text(text, encoding="utf-8")
    if executable:
        current = path.stat().st_mode
        path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def run_command(command: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def write_log(path: Path, command: list[str], rc: int, stdout: str, stderr: str) -> None:
    lines = [
        "command:",
        " ".join(command),
        f"return_code: {rc}",
        "",
        "stdout:",
        stdout,
        "",
        "stderr:",
        stderr,
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def load_manifest(path: Path) -> tuple[int, list[dict[str, Any]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("manifest must be a top-level object")
    if "schema_version" not in raw or "samples" not in raw:
        raise ValueError("manifest must contain schema_version and samples")
    schema_version = raw["schema_version"]
    if not isinstance(schema_version, int):
        raise ValueError("manifest schema_version must be an integer")
    samples = raw["samples"]
    if not isinstance(samples, list):
        raise ValueError("manifest samples must be a list")
    if len(samples) != EXPECTED_SAMPLE_COUNT:
        raise ValueError(
            f"manifest samples count must be {EXPECTED_SAMPLE_COUNT}, got {len(samples)}"
        )

    ids: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise ValueError(f"sample #{index} must be an object")
        for field in REQUIRED_SAMPLE_FIELDS:
            if field not in sample:
                raise ValueError(f"sample #{index} missing required field: {field}")
        for field in (
            "id",
            "platform",
            "artifact_kind",
            "target_kind",
            "protect_via",
            "input_relpath",
            "output_name",
            "validation_scope",
            "known_limits",
        ):
            if not isinstance(sample[field], str) or not sample[field].strip():
                raise ValueError(f"sample #{index} field {field} must be a non-empty string")
        if not isinstance(sample["anchor_strings"], list) or any(
            not isinstance(item, str) for item in sample["anchor_strings"]
        ):
            raise ValueError(f"sample #{index} field anchor_strings must be list[str]")
        sample_id = sample["id"]
        if sample_id in ids:
            raise ValueError(f"duplicate sample id: {sample_id}")
        ids.add(sample_id)
    return schema_version, samples


def locate_tool(path: Path, description: str) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"{description} is missing: {path}")
    return path


def detect_binary_kind(path: Path) -> str:
    data = path.read_bytes()[:8]
    if len(data) >= 2 and data[:2] == b"MZ":
        return "pe"
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "elf"
    if data.startswith(
        (
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
        )
    ):
        return "macho"
    return "other"


def build_key_provider(path: Path, key_id: str) -> None:
    payload = (
        "#!/bin/sh\n"
        "cat <<'__EIPPF_PROVIDER_EOF__'\n"
        f"protocol={PROVIDER_PROTOCOL}\n"
        "status=ok\n"
        f"key_id={key_id}\n"
        "key_u8=42\n"
        "__EIPPF_PROVIDER_EOF__\n"
    )
    write_text(path, payload, executable=True)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def choose_objdump_command() -> tuple[list[str], str]:
    if command_exists("llvm-objdump"):
        return (["llvm-objdump", "-p", "-h"], "llvm-objdump")
    if command_exists("objdump"):
        return (["objdump", "-x"], "objdump")
    return ([], "missing")


def collect_reverse_view(
    artifact_path: Path,
    output_prefix: Path,
    objdump_base: list[str],
    logs_dir: Path,
) -> dict[str, Any]:
    file_txt = output_prefix.with_suffix(".file.txt")
    strings_txt = output_prefix.with_suffix(".strings.txt")
    readelf_txt = output_prefix.with_suffix(".readelf.txt")
    objdump_txt = output_prefix.with_suffix(".objdump.txt")

    file_rc, file_stdout, file_stderr = run_command(["file", "-b", str(artifact_path)])
    write_log(
        logs_dir / f"{output_prefix.stem}.file.log",
        ["file", "-b", str(artifact_path)],
        file_rc,
        file_stdout,
        file_stderr,
    )
    write_text(file_txt, file_stdout if file_stdout else file_stderr)
    file_desc = first_line(file_stdout if file_stdout else file_stderr) or "unavailable"

    strings_rc, strings_stdout, strings_stderr = run_command(["strings", "-a", str(artifact_path)])
    write_log(
        logs_dir / f"{output_prefix.stem}.strings.log",
        ["strings", "-a", str(artifact_path)],
        strings_rc,
        strings_stdout,
        strings_stderr,
    )
    write_text(strings_txt, strings_stdout if strings_stdout else strings_stderr)
    strings_lines = [line for line in strings_stdout.splitlines() if line.strip()] if strings_rc == 0 else []

    binary_kind = detect_binary_kind(artifact_path)
    if binary_kind == "elf":
        readelf_cmd = ["readelf", "-h", "-S", "-s", str(artifact_path)]
        readelf_rc, readelf_stdout, readelf_stderr = run_command(readelf_cmd)
        write_log(logs_dir / f"{output_prefix.stem}.readelf.log", readelf_cmd, readelf_rc, readelf_stdout, readelf_stderr)
        write_text(readelf_txt, readelf_stdout if readelf_stdout else readelf_stderr)
    elif binary_kind in ("pe", "macho") and objdump_base:
        objdump_cmd = [*objdump_base, str(artifact_path)]
        objdump_rc, objdump_stdout, objdump_stderr = run_command(objdump_cmd)
        write_log(logs_dir / f"{output_prefix.stem}.objdump.log", objdump_cmd, objdump_rc, objdump_stdout, objdump_stderr)
        write_text(objdump_txt, objdump_stdout if objdump_stdout else objdump_stderr)

    return {
        "file_desc": file_desc,
        "strings": strings_lines,
        "string_count": len(strings_lines),
        "binary_kind": binary_kind,
    }


def run_artifact_audit(
    artifact_audit_path: Path,
    artifact_path: Path,
    target_kind: str,
    output_json: Path,
    logs_dir: Path,
    manifest_path: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    command = [
        sys.executable,
        str(artifact_audit_path),
        "--input",
        str(artifact_path),
        "--target-kind",
        target_kind,
        "--output",
        str(output_json),
    ]
    if manifest_path is not None:
        command.extend(["--manifest", str(manifest_path)])

    rc, stdout, stderr = run_command(command)
    write_log(logs_dir / f"{output_json.stem}.audit.log", command, rc, stdout, stderr)

    if output_json.exists():
        try:
            report = json.loads(output_json.read_text(encoding="utf-8"))
        except Exception:
            report = {"strict_failures": [f"audit_output_parse_failed_rc_{rc}"]}
    else:
        report = {"strict_failures": [f"audit_output_missing_rc_{rc}"]}

    strict_failures = report.get("strict_failures")
    if not isinstance(strict_failures, list):
        report["strict_failures"] = [f"audit_strict_failures_invalid_rc_{rc}"]
    if rc != 0:
        report.setdefault("strict_failures", [])
        if isinstance(report["strict_failures"], list):
            report["strict_failures"].append(f"audit_failed_rc_{rc}")
    return rc, report


def anchor_visible(strings_lines: list[str], anchors: list[str]) -> bool:
    lower_strings = [item.lower() for item in strings_lines]
    for anchor in anchors:
        needle = anchor.lower()
        if any(needle in line for line in lower_strings):
            return True
    return False


def safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def tool_version(command: list[str]) -> str:
    rc, stdout, stderr = run_command(command)
    text = stdout if rc == 0 else stderr
    line = first_line(text)
    if line:
        return line
    return f"unavailable(rc={rc})"


def render_report(
    template_path: Path,
    output_path: Path,
    generated_at: str,
    samples: list[dict[str, Any]],
) -> None:
    summary_rows: list[str] = []
    scope_rows: list[str] = []

    for sample in samples:
        original_badge = '<span class="flag yes">yes</span>' if sample["original_anchor_visible"] else '<span class="flag no">no</span>'
        protected_badge = '<span class="flag yes">yes</span>' if sample["protected_anchor_visible"] else '<span class="flag no">no</span>'
        strict_failures = sample["protected_strict_failures"]
        strict_text = ", ".join(strict_failures) if strict_failures else "none"
        summary_rows.append(
            "<tr>"
            f"<td><code>{html.escape(sample['id'])}</code></td>"
            f"<td>{html.escape(sample['target_kind'])}</td>"
            f"<td>{html.escape(sample['protect_via'])}</td>"
            f"<td>{original_badge}</td>"
            f"<td>{protected_badge}</td>"
            f"<td>{sample['original_string_count']}</td>"
            f"<td>{sample['protected_string_count']}</td>"
            f"<td><code>{html.escape(strict_text)}</code></td>"
            "</tr>"
        )
        scope_rows.append(
            "<tr>"
            f"<td><code>{html.escape(sample['id'])}</code></td>"
            f"<td>{html.escape(sample['validation_scope'])}</td>"
            f"<td>{html.escape(sample['known_limits'])}</td>"
            "</tr>"
        )

    template = template_path.read_text(encoding="utf-8")
    report = (
        template.replace("{{generated_at}}", html.escape(generated_at))
        .replace("{{summary_table_rows}}", "".join(summary_rows))
        .replace("{{scope_rows}}", "".join(scope_rows))
    )
    output_path.write_text(report, encoding="utf-8")


def main() -> int:
    args = parse_args()

    schema_version, samples = load_manifest(args.manifest)

    output_root = args.output_root.resolve()
    original_root = output_root / "original"
    protected_root = output_root / "protected"
    manifests_root = output_root / "manifests"
    audit_root = output_root / "audit"
    reverse_root = output_root / "reverse"
    logs_root = output_root / "logs"
    providers_root = logs_root / "providers"
    for path in (
        output_root,
        original_root,
        protected_root,
        manifests_root,
        audit_root,
        reverse_root,
        logs_root,
        providers_root,
    ):
        ensure_dir(path)

    manifest_copy_path = output_root / "sample_manifest.json"
    shutil.copy2(args.manifest, manifest_copy_path)

    build_root = args.build_root.resolve()
    post_link_tool = locate_tool(
        build_root / "post_link_mutator" / "eippf_post_link_mutator",
        "eippf_post_link_mutator",
    )
    dex_tool = locate_tool(
        build_root / "dex_toolchain" / "eippf_dex_toolchain",
        "eippf_dex_toolchain",
    )
    script_guard_tool = locate_tool(
        build_root / "script_guard" / "eippf_script_guard",
        "eippf_script_guard",
    )
    artifact_audit_path = locate_tool(
        Path(__file__).resolve().parents[1] / "artifact_audit.py",
        "artifact_audit.py",
    )

    objdump_base, objdump_tool_name = choose_objdump_command()

    summary_items: list[dict[str, Any]] = []
    processed_ids: set[str] = set()
    had_errors = False

    input_root = args.input_root.resolve()
    for sample in samples:
        sample_id = sample["id"]
        processed_ids.add(sample_id)

        target_kind = sample["target_kind"]
        protect_via = sample["protect_via"]
        input_relpath = sample["input_relpath"]
        output_name = sample["output_name"]
        anchors = list(sample["anchor_strings"])
        validation_scope = sample["validation_scope"]
        known_limits = sample["known_limits"]

        sample_logs_dir = logs_root / sample_id
        sample_reverse_dir = reverse_root / sample_id
        sample_original_dir = original_root / sample_id
        sample_protected_dir = protected_root / sample_id
        for path in (
            sample_logs_dir,
            sample_reverse_dir,
            sample_original_dir,
            sample_protected_dir,
        ):
            ensure_dir(path)

        input_path = input_root / input_relpath
        original_copy = sample_original_dir / input_path.name
        protected_path = sample_protected_dir / output_name
        protection_manifest_path = manifests_root / f"{sample_id}.manifest.json"

        protect_rc = 0
        protect_stdout = ""
        protect_stderr = ""

        if not input_path.exists():
            had_errors = True
            write_text(sample_logs_dir / "missing_input.log", f"missing input: {input_path}\n")
        else:
            shutil.copy2(input_path, original_copy)
            if protect_via == "post_link_mutator":
                command = [
                    str(post_link_tool),
                    "--input",
                    str(original_copy),
                    "--output",
                    str(protected_path),
                    "--manifest",
                    str(protection_manifest_path),
                    "--target",
                    sample_id,
                    "--target-kind",
                    target_kind,
                ]
                protect_rc, protect_stdout, protect_stderr = run_command(command)
                write_log(sample_logs_dir / "protect.log", command, protect_rc, protect_stdout, protect_stderr)
            elif protect_via in ("dex_toolchain", "script_guard"):
                provider_key_id = f"{sample_id}-key"
                provider_path = providers_root / f"{sample_id}.provider.sh"
                build_key_provider(provider_path, provider_key_id)
                if protect_via == "dex_toolchain":
                    command = [
                        str(dex_tool),
                        f"--input={original_copy}",
                        f"--output-bundle={protected_path}",
                        f"--manifest={protection_manifest_path}",
                        f"--key-provider={provider_path}",
                        f"--key-id={provider_key_id}",
                    ]
                else:
                    command = [
                        str(script_guard_tool),
                        f"--input-script={original_copy}",
                        f"--output-bundle={protected_path}",
                        f"--manifest={protection_manifest_path}",
                        f"--key-provider={provider_path}",
                        f"--key-id={provider_key_id}",
                    ]
                protect_rc, protect_stdout, protect_stderr = run_command(command)
                write_log(sample_logs_dir / "protect.log", command, protect_rc, protect_stdout, protect_stderr)
            else:
                had_errors = True
                write_text(
                    sample_logs_dir / "protect.log",
                    f"unsupported protect_via value: {protect_via}\n",
                )
                protect_rc = 2

        if protect_rc != 0:
            had_errors = True

        input_exists = original_copy.exists()
        protected_exists = protected_path.exists()
        if not input_exists or not protected_exists or not protection_manifest_path.exists():
            had_errors = True

        if input_exists:
            input_sha = sha256_file(original_copy)
            input_size = original_copy.stat().st_size
            original_reverse = collect_reverse_view(
                original_copy,
                sample_reverse_dir / "original",
                objdump_base,
                sample_logs_dir,
            )
            original_audit_path = audit_root / f"{sample_id}.original.audit.json"
            _, original_audit_report = run_artifact_audit(
                artifact_audit_path,
                original_copy,
                target_kind,
                original_audit_path,
                sample_logs_dir,
                None,
            )
        else:
            input_sha = ""
            input_size = 0
            original_reverse = {
                "file_desc": "missing original artifact",
                "strings": [],
                "string_count": 0,
                "binary_kind": "other",
            }
            original_audit_report = {"strict_failures": ["original_missing"]}
            write_json(audit_root / f"{sample_id}.original.audit.json", original_audit_report)

        if protected_exists:
            output_sha = sha256_file(protected_path)
            output_size = protected_path.stat().st_size
            protected_reverse = collect_reverse_view(
                protected_path,
                sample_reverse_dir / "protected",
                objdump_base,
                sample_logs_dir,
            )
            protected_audit_path = audit_root / f"{sample_id}.protected.audit.json"
            protected_audit_rc, protected_audit_report = run_artifact_audit(
                artifact_audit_path,
                protected_path,
                target_kind,
                protected_audit_path,
                sample_logs_dir,
                protection_manifest_path if protection_manifest_path.exists() else None,
            )
            if protected_audit_rc != 0:
                had_errors = True
        else:
            output_sha = ""
            output_size = 0
            protected_reverse = {
                "file_desc": "missing protected artifact",
                "strings": [],
                "string_count": 0,
                "binary_kind": "other",
            }
            protected_audit_report = {"strict_failures": [f"protection_failed_rc_{protect_rc}"]}
            write_json(audit_root / f"{sample_id}.protected.audit.json", protected_audit_report)

        strict_failures = protected_audit_report.get("strict_failures", [])
        if not isinstance(strict_failures, list):
            strict_failures = ["strict_failures_invalid"]
        if protect_rc != 0:
            strict_failures = [*strict_failures, f"protection_failed_rc_{protect_rc}"]

        summary_items.append(
            {
                "id": sample_id,
                "target_kind": target_kind,
                "protect_via": protect_via,
                "input_relpath": input_relpath,
                "protected_relpath": safe_relative(protected_path, output_root),
                "input_sha256": input_sha,
                "output_sha256": output_sha,
                "original_size": input_size,
                "protected_size": output_size,
                "original_file_desc": original_reverse["file_desc"],
                "protected_file_desc": protected_reverse["file_desc"],
                "anchor_strings": anchors,
                "original_anchor_visible": anchor_visible(original_reverse["strings"], anchors),
                "protected_anchor_visible": anchor_visible(protected_reverse["strings"], anchors),
                "original_string_count": int(original_reverse["string_count"]),
                "protected_string_count": int(protected_reverse["string_count"]),
                "protected_strict_failures": strict_failures,
                "validation_scope": validation_scope,
                "known_limits": known_limits,
            }
        )

    if len(summary_items) != EXPECTED_SAMPLE_COUNT or len(processed_ids) != EXPECTED_SAMPLE_COUNT:
        had_errors = True

    generated_at = datetime.now(timezone.utc).isoformat()
    summary_payload = {
        "schema_version": schema_version,
        "generated_at_utc": generated_at,
        "samples": summary_items,
    }
    summary_path = output_root / "summary.json"
    write_json(summary_path, summary_payload)

    tool_versions_payload = {
        "python": sys.version.split()[0],
        "file": tool_version(["file", "--version"]),
        "strings": tool_version(["strings", "--version"]),
        "readelf": tool_version(["readelf", "--version"]),
        "objdump_tool": objdump_tool_name,
        "objdump": tool_version(([objdump_tool_name, "--version"] if objdump_tool_name != "missing" else ["sh", "-c", "echo missing"])),
        "artifact_audit_path": str(artifact_audit_path),
        "post_link_mutator_path": str(post_link_tool),
        "dex_toolchain_path": str(dex_tool),
        "script_guard_path": str(script_guard_tool),
    }
    tool_versions_path = output_root / "tool_versions.json"
    write_json(tool_versions_path, tool_versions_payload)

    template_path = Path(__file__).with_name("report_template.html")
    report_path = output_root / "report.html"
    render_report(template_path, report_path, generated_at, summary_items)

    required_paths = (
        output_root / "sample_manifest.json",
        output_root / "original",
        output_root / "protected",
        output_root / "manifests",
        output_root / "audit",
        output_root / "reverse",
        output_root / "logs",
        report_path,
        summary_path,
        tool_versions_path,
    )
    for path in required_paths:
        if not path.exists():
            had_errors = True

    return 1 if had_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
