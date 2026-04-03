#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROVIDER_PROTOCOL = "eippf.external_key.v1"
EXPECTED_SAMPLE_COUNT = 11
EXPECTED_MANIFEST_SCHEMA_VERSION = 2
EXPECTED_SAMPLE_IDS = (
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
)

SIGNED_POLICY_SAMPLE_IDS = {
    "windows_sys",
    "linux_ko",
    "android_ko",
    "ios_macho",
}

SIGNED_POLICY_POLICY_ONLY_FAILURES = {
    "signature_missing",
    "signature_authenticity_missing",
}

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
    "build_mode",
    "requires_signed_policy",
    "signature_fixture_kind",
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


def run_command(
    command: list[str],
    env_overrides: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    env = None
    if env_overrides is not None:
        env = os.environ.copy()
        env.update(env_overrides)
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        env=env,
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
    if schema_version != EXPECTED_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            "manifest schema_version must be "
            f"{EXPECTED_MANIFEST_SCHEMA_VERSION}, got {schema_version}"
        )
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
            "build_mode",
            "signature_fixture_kind",
        ):
            if not isinstance(sample[field], str) or not sample[field].strip():
                raise ValueError(f"sample #{index} field {field} must be a non-empty string")
        if not isinstance(sample["requires_signed_policy"], bool):
            raise ValueError(f"sample #{index} field requires_signed_policy must be a boolean")
        if not isinstance(sample["anchor_strings"], list) or any(
            not isinstance(item, str) for item in sample["anchor_strings"]
        ):
            raise ValueError(f"sample #{index} field anchor_strings must be list[str]")
        sample_id = sample["id"]
        if sample_id in ids:
            raise ValueError(f"duplicate sample id: {sample_id}")
        ids.add(sample_id)
        requires_signed_policy = bool(sample["requires_signed_policy"])
        if sample_id in SIGNED_POLICY_SAMPLE_IDS and not requires_signed_policy:
            raise ValueError(f"sample #{index} {sample_id} must require signed_policy")
        if sample_id not in SIGNED_POLICY_SAMPLE_IDS and requires_signed_policy:
            raise ValueError(f"sample #{index} {sample_id} cannot require signed_policy")
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
    signature_verifier: Path | None = None,
    strict: bool = False,
    env_overrides: dict[str, str] | None = None,
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
    if signature_verifier is not None:
        command.extend(["--signature-verifier", str(signature_verifier)])
    if strict:
        command.append("--strict")

    rc, stdout, stderr = run_command(command, env_overrides=env_overrides)
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


def strict_failures_from_report(report: dict[str, Any]) -> list[str]:
    strict_failures = report.get("strict_failures")
    if not isinstance(strict_failures, list):
        return ["strict_failures_invalid"]
    return [item for item in strict_failures if isinstance(item, str)]


def unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) != 64:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in value)


def write_reverse_compat_layout(
    sample_reverse_dir: Path,
    sample_id: str,
    protected_strings: list[str],
    input_relpath: str,
    protected_relpath: str,
    input_sha256: str,
    output_sha256: str,
    validation_scope: str,
    known_limits: str,
) -> None:
    strings_text = "\n".join(protected_strings)
    if strings_text:
        strings_text += "\n"
    write_text(sample_reverse_dir / "strings.txt", strings_text)
    metadata_lines = [
        f"sample_id={sample_id}",
        f"input_relpath={input_relpath}",
        f"protected_relpath={protected_relpath}",
        f"input_sha256={input_sha256}",
        f"output_sha256={output_sha256}",
        f"validation_scope={validation_scope}",
        f"known_limits={known_limits}",
        "",
    ]
    write_text(sample_reverse_dir / "metadata.txt", "\n".join(metadata_lines))


def classify_artifact_shape_failures(
    sample_id: str,
    requires_signed_policy: bool,
    report: dict[str, Any],
) -> dict[str, Any]:
    strict_failures = strict_failures_from_report(report)
    signature_details = report.get("signature_details")
    structure_present = False
    format_valid = False
    if isinstance(signature_details, dict):
        structure_present = bool(signature_details.get("structure_present", False))
        format_valid = bool(signature_details.get("format_valid", False))

    implementation_defects: list[str] = []
    policy_only_unsigned: list[str] = []
    for failure in strict_failures:
        if not requires_signed_policy:
            implementation_defects.append(failure)
            continue
        if sample_id != "ios_macho" and failure in SIGNED_POLICY_POLICY_ONLY_FAILURES:
            policy_only_unsigned.append(failure)
            continue
        if (
            sample_id == "ios_macho"
            and failure == "signature_authenticity_missing"
            and structure_present
            and format_valid
        ):
            policy_only_unsigned.append(failure)
            continue
        implementation_defects.append(failure)

    return {
        "strict_failures": strict_failures,
        "implementation_defects": implementation_defects,
        "policy_only_unsigned": policy_only_unsigned,
        "signature_structure_present": structure_present,
        "signature_format_valid": format_valid,
    }


def normalize_fixture_kind(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def signed_policy_fixture_recipe(sample_id: str, signature_fixture_kind: str) -> tuple[str | None, str]:
    normalized = normalize_fixture_kind(signature_fixture_kind)
    if sample_id == "windows_sys":
        if normalized not in {"pe_win_certificate_stub", "windows_pe_stub", "pe_stub"}:
            raise ValueError(
                f"windows_sys signature_fixture_kind must be pe_win_certificate_stub-compatible, got {signature_fixture_kind}"
            )
        return "patch_pe_win_certificate_stub", "success"
    if sample_id in {"linux_ko", "android_ko"}:
        if normalized not in {"elf_module_signature_stub", "module_signature_stub", "elf_signature_stub"}:
            raise ValueError(
                f"{sample_id} signature_fixture_kind must be elf_module_signature_stub-compatible, got {signature_fixture_kind}"
            )
        return "append_elf_module_signature_stub", "success"
    if sample_id == "ios_macho":
        if normalized not in {"ios_trusted_verifier_only", "existing_codesig", "none"}:
            raise ValueError(
                f"ios_macho signature_fixture_kind must be ios_trusted_verifier_only-compatible, got {signature_fixture_kind}"
            )
        return None, "success"
    raise ValueError(f"unsupported signed_policy sample id: {sample_id}")


def run_fixture_signer(
    fixture_signers_path: Path,
    command_name: str,
    sample_logs_dir: Path,
    **kwargs: str,
) -> tuple[int, str, str]:
    command = [sys.executable, str(fixture_signers_path), command_name]
    for key, value in kwargs.items():
        command.extend([f"--{key.replace('_', '-')}", value])
    rc, stdout, stderr = run_command(command)
    write_log(
        sample_logs_dir / f"{command_name}.log",
        command,
        rc,
        stdout,
        stderr,
    )
    return rc, stdout, stderr


def trusted_verifier_env(verifiers_dir: Path, verifier_sha256: str) -> dict[str, str]:
    return {
        "EIPPF_SIGNATURE_VERIFIER_TRUSTED_PREFIXES": str(verifiers_dir.resolve()),
        "EIPPF_SIGNATURE_VERIFIER_TRUSTED_SHA256": verifier_sha256,
    }


def validate_summary_contract(summary_payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(summary_payload, dict):
        return ["summary payload must be an object"]
    if summary_payload.get("schema_version") != EXPECTED_MANIFEST_SCHEMA_VERSION:
        errors.append(
            f"summary schema_version must be {EXPECTED_MANIFEST_SCHEMA_VERSION}"
        )
    samples = summary_payload.get("samples")
    if not isinstance(samples, list):
        errors.append("summary samples must be a list")
        return errors
    if len(samples) != EXPECTED_SAMPLE_COUNT:
        errors.append(
            f"summary samples count must be {EXPECTED_SAMPLE_COUNT}, got {len(samples)}"
        )
    expected_ids = set(EXPECTED_SAMPLE_IDS)
    seen_ids: list[str] = []
    seen_set: set[str] = set()
    seen_signed_policy_ids: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            errors.append(f"sample[{index}] must be an object")
            continue
        sample_id = sample.get("id")
        if not isinstance(sample_id, str):
            errors.append(f"sample[{index}] missing id")
            continue
        seen_ids.append(sample_id)
        if sample_id in seen_set:
            errors.append(f"sample[{sample_id}] duplicate id")
        seen_set.add(sample_id)
        artifact_shape = sample.get("artifact_shape")
        if not isinstance(artifact_shape, dict):
            errors.append(f"sample[{sample_id}] missing artifact_shape object")
        elif not isinstance(artifact_shape.get("strict_failures"), list):
            errors.append(f"sample[{sample_id}] artifact_shape.strict_failures must be list")
        if not is_sha256_hex(sample.get("input_sha256")):
            errors.append(f"sample[{sample_id}] input_sha256 must be 64 hex chars")
        if not is_sha256_hex(sample.get("output_sha256")):
            errors.append(f"sample[{sample_id}] output_sha256 must be 64 hex chars")
        if not isinstance(sample.get("validation_scope"), str) or not sample.get("validation_scope"):
            errors.append(f"sample[{sample_id}] validation_scope must be non-empty string")
        if not isinstance(sample.get("known_limits"), str) or not sample.get("known_limits"):
            errors.append(f"sample[{sample_id}] known_limits must be non-empty string")
        failure_classification = sample.get("failure_classification")
        if not isinstance(failure_classification, dict):
            errors.append(f"sample[{sample_id}] missing failure_classification object")
        else:
            if not isinstance(failure_classification.get("implementation_defects"), list):
                errors.append(
                    f"sample[{sample_id}] failure_classification.implementation_defects must be list"
                )
            if not isinstance(failure_classification.get("policy_only_unsigned"), list):
                errors.append(
                    f"sample[{sample_id}] failure_classification.policy_only_unsigned must be list"
                )
        if sample_id in SIGNED_POLICY_SAMPLE_IDS:
            seen_signed_policy_ids.add(sample_id)
            if not isinstance(sample.get("signed_policy"), dict):
                errors.append(f"sample[{sample_id}] missing signed_policy object")
            if not isinstance(sample.get("signed_policy_relpath"), str):
                errors.append(f"sample[{sample_id}] missing signed_policy_relpath")
            if not is_sha256_hex(sample.get("signed_policy_sha256")):
                errors.append(f"sample[{sample_id}] signed_policy_sha256 must be 64 hex chars")
    missing = SIGNED_POLICY_SAMPLE_IDS - seen_signed_policy_ids
    if missing:
        errors.append(
            "summary missing signed_policy targets: "
            + ",".join(sorted(missing))
        )
    seen_id_set = set(seen_ids)
    missing_ids = expected_ids - seen_id_set
    if missing_ids:
        errors.append("summary missing sample ids: " + ",".join(sorted(missing_ids)))
    extra_ids = seen_id_set - expected_ids
    if extra_ids:
        errors.append("summary contains unexpected sample ids: " + ",".join(sorted(extra_ids)))
    return errors


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
    artifact_shape_rows: list[str] = []
    signed_policy_rows: list[str] = []
    implementation_defect_rows: list[str] = []

    for sample in samples:
        artifact_shape = sample.get("artifact_shape", {})
        failure_classification = sample.get("failure_classification", {})
        artifact_shape_failures = artifact_shape.get("strict_failures", [])
        impl_defects = failure_classification.get("implementation_defects", [])
        policy_only_unsigned = failure_classification.get("policy_only_unsigned", [])

        original_badge = (
            '<span class="flag yes">yes</span>'
            if bool(sample.get("original_anchor_visible", False))
            else '<span class="flag no">no</span>'
        )
        protected_badge = (
            '<span class="flag yes">yes</span>'
            if bool(sample.get("protected_anchor_visible", False))
            else '<span class="flag no">no</span>'
        )
        strict_text = (
            ", ".join(str(item) for item in artifact_shape_failures)
            if isinstance(artifact_shape_failures, list) and artifact_shape_failures
            else "none"
        )
        policy_only_text = (
            ", ".join(str(item) for item in policy_only_unsigned)
            if isinstance(policy_only_unsigned, list) and policy_only_unsigned
            else "none"
        )
        artifact_shape_rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(sample.get('id', '')))}</code></td>"
            f"<td>{html.escape(str(sample.get('target_kind', '')))}</td>"
            f"<td>{html.escape(str(sample.get('protect_via', '')))}</td>"
            f"<td><code>{html.escape(str(sample.get('validation_scope', '')))}</code></td>"
            f"<td><code>{html.escape(str(sample.get('known_limits', '')))}</code></td>"
            f"<td><code>{html.escape(str(sample.get('input_sha256', '')))}</code></td>"
            f"<td><code>{html.escape(str(sample.get('output_sha256', '')))}</code></td>"
            f"<td>{original_badge}</td>"
            f"<td>{protected_badge}</td>"
            f"<td>{int(sample.get('original_string_count', 0))}</td>"
            f"<td>{int(sample.get('protected_string_count', 0))}</td>"
            f"<td><code>{html.escape(strict_text)}</code></td>"
            f"<td><code>{html.escape(policy_only_text)}</code></td>"
            "</tr>"
        )

        if isinstance(sample.get("signed_policy"), dict):
            signed_policy = sample["signed_policy"]
            signed_failures = signed_policy.get("strict_failures", [])
            signed_failures_text = (
                ", ".join(str(item) for item in signed_failures)
                if isinstance(signed_failures, list) and signed_failures
                else "none"
            )
            signed_policy_rows.append(
                "<tr>"
                f"<td><code>{html.escape(str(sample.get('id', '')))}</code></td>"
                f"<td><code>{html.escape(str(sample.get('signed_policy_relpath', '')))}</code></td>"
                f"<td><code>{html.escape(str(sample.get('signed_policy_sha256', '')))}</code></td>"
                f"<td><code>{html.escape(str(signed_policy.get('verifier_relpath', '')))}</code></td>"
                f"<td><code>{html.escape(signed_failures_text)}</code></td>"
                "</tr>"
            )

        if isinstance(impl_defects, list) and impl_defects:
            implementation_defect_rows.append(
                "<tr>"
                f"<td><code>{html.escape(str(sample.get('id', '')))}</code></td>"
                f"<td><code>{html.escape(', '.join(str(item) for item in impl_defects))}</code></td>"
                "</tr>"
            )

    if not signed_policy_rows:
        signed_policy_rows.append(
            "<tr><td colspan=\"5\"><code>none</code></td></tr>"
        )
    if not implementation_defect_rows:
        implementation_defect_rows.append(
            "<tr><td colspan=\"2\"><code>none</code></td></tr>"
        )

    template = template_path.read_text(encoding="utf-8")
    report = (
        template.replace("{{generated_at}}", html.escape(generated_at))
        .replace("{{artifact_shape_rows}}", "".join(artifact_shape_rows))
        .replace("{{signed_policy_rows}}", "".join(signed_policy_rows))
        .replace("{{implementation_defect_rows}}", "".join(implementation_defect_rows))
    )
    output_path.write_text(report, encoding="utf-8")


def main() -> int:
    args = parse_args()

    schema_version, samples = load_manifest(args.manifest)

    output_root = args.output_root.resolve()
    original_root = output_root / "original"
    protected_root = output_root / "protected"
    signed_policy_root = output_root / "signed_policy"
    manifests_root = output_root / "manifests"
    audit_root = output_root / "audit"
    reverse_root = output_root / "reverse"
    logs_root = output_root / "logs"
    providers_root = logs_root / "providers"
    verifiers_root = logs_root / "verifiers"
    for path in (
        output_root,
        original_root,
        protected_root,
        signed_policy_root,
        manifests_root,
        audit_root,
        reverse_root,
        logs_root,
        providers_root,
        verifiers_root,
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
    fixture_signers_path = locate_tool(
        Path(__file__).resolve().parents[2] / "tests" / "sample_suite" / "fixture_signers.py",
        "fixture_signers.py",
    )

    objdump_base, objdump_tool_name = choose_objdump_command()

    summary_items: list[dict[str, Any]] = []
    processed_ids: set[str] = set()
    hard_fail = False
    verifier_wrappers: dict[str, Path] = {}

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
        build_mode = sample["build_mode"]
        requires_signed_policy = bool(sample["requires_signed_policy"])
        signature_fixture_kind = sample["signature_fixture_kind"]

        sample_logs_dir = logs_root / sample_id
        sample_reverse_dir = reverse_root / sample_id
        sample_original_dir = original_root / sample_id
        sample_protected_dir = protected_root / sample_id
        sample_signed_policy_dir = signed_policy_root / sample_id
        for path in (
            sample_logs_dir,
            sample_reverse_dir,
            sample_original_dir,
            sample_protected_dir,
        ):
            ensure_dir(path)
        if requires_signed_policy:
            ensure_dir(sample_signed_policy_dir)

        input_path = input_root / input_relpath
        original_copy = sample_original_dir / input_path.name
        protected_path = sample_protected_dir / output_name
        signed_policy_path = sample_signed_policy_dir / output_name
        protection_manifest_path = manifests_root / f"{sample_id}.manifest.json"

        protect_rc = 0
        protect_stdout = ""
        protect_stderr = ""

        if not input_path.exists():
            hard_fail = True
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
                hard_fail = True
                write_text(
                    sample_logs_dir / "protect.log",
                    f"unsupported protect_via value: {protect_via}\n",
                )
                protect_rc = 2

        input_exists = original_copy.exists()
        protected_exists = protected_path.exists()
        if not input_exists or not protected_exists or not protection_manifest_path.exists():
            hard_fail = True

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
            artifact_shape_audit_path = audit_root / f"{sample_id}.artifact_shape.audit.json"
            _, artifact_shape_report = run_artifact_audit(
                artifact_audit_path,
                protected_path,
                target_kind,
                artifact_shape_audit_path,
                sample_logs_dir,
                protection_manifest_path if protection_manifest_path.exists() else None,
            )
        else:
            output_sha = ""
            output_size = 0
            protected_reverse = {
                "file_desc": "missing protected artifact",
                "strings": [],
                "string_count": 0,
                "binary_kind": "other",
            }
            artifact_shape_audit_path = audit_root / f"{sample_id}.artifact_shape.audit.json"
            artifact_shape_report = {"strict_failures": [f"protection_failed_rc_{protect_rc}"]}
            write_json(artifact_shape_audit_path, artifact_shape_report)

        artifact_shape_classification = classify_artifact_shape_failures(
            sample_id,
            requires_signed_policy,
            artifact_shape_report,
        )
        artifact_shape_strict_failures = list(artifact_shape_classification["strict_failures"])
        implementation_defects = list(artifact_shape_classification["implementation_defects"])
        policy_only_unsigned = list(artifact_shape_classification["policy_only_unsigned"])
        if protect_rc != 0:
            failure = f"protection_failed_rc_{protect_rc}"
            artifact_shape_strict_failures = unique_strings([*artifact_shape_strict_failures, failure])
            implementation_defects = unique_strings([*implementation_defects, failure])
            hard_fail = True

        signed_policy_item: dict[str, Any] | None = None
        signed_policy_relpath = ""
        signed_policy_sha256 = ""
        if requires_signed_policy:
            signed_policy_audit_path = audit_root / f"{sample_id}.signed_policy.audit.json"
            signed_policy_report: dict[str, Any] = {"strict_failures": []}
            signed_policy_verifier_path: Path | None = None
            signed_policy_verifier_sha256 = ""
            audited_signed_policy_artifact = signed_policy_path
            recipe_error = ""
            signer_command: str | None = None
            wrapper_mode = ""
            try:
                signer_command, wrapper_mode = signed_policy_fixture_recipe(
                    sample_id,
                    signature_fixture_kind,
                )
            except ValueError as error:
                recipe_error = str(error)
                implementation_defects = unique_strings(
                    [*implementation_defects, "signed_policy_fixture_recipe_invalid"]
                )
                hard_fail = True

            if protected_exists and not recipe_error:
                if sample_id == "ios_macho":
                    shutil.copy2(protected_path, signed_policy_path)
                elif signer_command is not None:
                    signer_rc, _, _ = run_fixture_signer(
                        fixture_signers_path,
                        signer_command,
                        sample_logs_dir,
                        in_path=str(protected_path),
                        out_path=str(signed_policy_path),
                    )
                    if signer_rc != 0 or not signed_policy_path.exists():
                        implementation_defects = unique_strings(
                            [*implementation_defects, "signed_policy_fixture_patch_failed"]
                        )
                        hard_fail = True
                else:
                    shutil.copy2(protected_path, signed_policy_path)
            elif not protected_exists:
                implementation_defects = unique_strings(
                    [*implementation_defects, "signed_policy_input_missing"]
                )
                hard_fail = True

            if signed_policy_path.exists():
                signed_policy_relpath = safe_relative(signed_policy_path, output_root)
                signed_policy_sha256 = sha256_file(signed_policy_path)
            else:
                signed_policy_relpath = safe_relative(signed_policy_path, output_root)
                signed_policy_sha256 = ""

            if not recipe_error:
                if wrapper_mode not in verifier_wrappers:
                    wrapper_rc, wrapper_stdout, _ = run_fixture_signer(
                        fixture_signers_path,
                        "make_trusted_verifier_wrapper",
                        sample_logs_dir,
                        out_dir=str(verifiers_root),
                        mode=wrapper_mode,
                    )
                    if wrapper_rc == 0:
                        wrapper_path_line = first_line(wrapper_stdout)
                        if wrapper_path_line:
                            wrapper_candidate = Path(wrapper_path_line)
                            if not wrapper_candidate.is_absolute():
                                wrapper_candidate = verifiers_root / wrapper_candidate
                        else:
                            wrapper_candidate = verifiers_root / f"trusted_verifier_{wrapper_mode}.py"
                        if wrapper_candidate.exists():
                            verifier_wrappers[wrapper_mode] = wrapper_candidate.resolve()
                        else:
                            implementation_defects = unique_strings(
                                [*implementation_defects, "trusted_verifier_wrapper_missing"]
                            )
                            hard_fail = True
                    else:
                        implementation_defects = unique_strings(
                            [*implementation_defects, "trusted_verifier_wrapper_build_failed"]
                        )
                        hard_fail = True

                if wrapper_mode in verifier_wrappers:
                    signed_policy_verifier_path = verifier_wrappers[wrapper_mode]
                    signed_policy_verifier_sha256 = sha256_file(signed_policy_verifier_path)

            ios_signature_structure_ok = bool(
                artifact_shape_classification.get("signature_structure_present", False)
            ) and bool(
                artifact_shape_classification.get("signature_format_valid", False)
            )

            if sample_id == "ios_macho" and not ios_signature_structure_ok:
                signed_policy_report = {
                    "strict_failures": ["ios_codesig_structure_invalid"],
                    "skipped": True,
                    "reason": "ios_codesig_structure_invalid",
                }
                write_json(signed_policy_audit_path, signed_policy_report)
                implementation_defects = unique_strings(
                    [*implementation_defects, "ios_codesig_structure_invalid"]
                )
            else:
                if sample_id == "ios_macho":
                    audited_signed_policy_artifact = protected_path
                if (
                    signed_policy_verifier_path is not None
                    and signed_policy_verifier_sha256
                    and audited_signed_policy_artifact.exists()
                ):
                    signed_policy_env = trusted_verifier_env(
                        verifiers_root,
                        signed_policy_verifier_sha256,
                    )
                    _, signed_policy_report = run_artifact_audit(
                        artifact_audit_path,
                        audited_signed_policy_artifact,
                        target_kind,
                        signed_policy_audit_path,
                        sample_logs_dir,
                        protection_manifest_path if protection_manifest_path.exists() else None,
                        signature_verifier=signed_policy_verifier_path,
                        strict=True,
                        env_overrides=signed_policy_env,
                    )
                else:
                    signed_policy_report = {"strict_failures": ["signed_policy_verifier_or_input_missing"]}
                    write_json(signed_policy_audit_path, signed_policy_report)
                    implementation_defects = unique_strings(
                        [*implementation_defects, "signed_policy_verifier_or_input_missing"]
                    )
                    hard_fail = True

            if not signed_policy_audit_path.exists():
                write_json(signed_policy_audit_path, signed_policy_report)

            signed_policy_failures = strict_failures_from_report(signed_policy_report)
            if signed_policy_failures:
                implementation_defects = unique_strings(
                    [*implementation_defects, *[f"signed_policy:{item}" for item in signed_policy_failures]]
                )

            signed_policy_item = {
                "audit_relpath": safe_relative(signed_policy_audit_path, output_root),
                "audited_relpath": safe_relative(audited_signed_policy_artifact, output_root),
                "strict_failures": signed_policy_failures,
                "verifier_relpath": (
                    safe_relative(signed_policy_verifier_path, output_root)
                    if signed_policy_verifier_path is not None
                    else ""
                ),
                "verifier_sha256": signed_policy_verifier_sha256,
            }

        implementation_defects = unique_strings(implementation_defects)
        policy_only_unsigned = unique_strings(policy_only_unsigned)

        summary_item: dict[str, Any] = {
            "id": sample_id,
            "target_kind": target_kind,
            "protect_via": protect_via,
            "build_mode": build_mode,
            "requires_signed_policy": requires_signed_policy,
            "signature_fixture_kind": signature_fixture_kind,
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
            "artifact_shape": {
                "audit_relpath": safe_relative(artifact_shape_audit_path, output_root),
                "strict_failures": artifact_shape_strict_failures,
            },
            "failure_classification": {
                "implementation_defects": implementation_defects,
                "policy_only_unsigned": policy_only_unsigned,
            },
            "validation_scope": validation_scope,
            "known_limits": known_limits,
        }

        if signed_policy_item is not None:
            summary_item["signed_policy"] = signed_policy_item
            summary_item["signed_policy_relpath"] = signed_policy_relpath
            summary_item["signed_policy_sha256"] = signed_policy_sha256

        write_reverse_compat_layout(
            sample_reverse_dir=sample_reverse_dir,
            sample_id=sample_id,
            protected_strings=protected_reverse["strings"],
            input_relpath=input_relpath,
            protected_relpath=safe_relative(protected_path, output_root),
            input_sha256=input_sha,
            output_sha256=output_sha,
            validation_scope=validation_scope,
            known_limits=known_limits,
        )
        summary_items.append(summary_item)

    if len(summary_items) != EXPECTED_SAMPLE_COUNT or len(processed_ids) != EXPECTED_SAMPLE_COUNT:
        hard_fail = True

    generated_at = datetime.now(timezone.utc).isoformat()
    summary_payload = {
        "schema_version": schema_version,
        "generated_at_utc": generated_at,
        "samples": summary_items,
    }
    summary_contract_errors = validate_summary_contract(summary_payload)
    if summary_contract_errors:
        hard_fail = True
        write_json(
            logs_root / "summary_contract_errors.json",
            {"errors": summary_contract_errors},
        )
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
        "fixture_signers_path": str(fixture_signers_path),
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
        output_root / "signed_policy",
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
            hard_fail = True

    for sample_id in EXPECTED_SAMPLE_IDS:
        compat_strings = reverse_root / sample_id / "strings.txt"
        compat_metadata = reverse_root / sample_id / "metadata.txt"
        if not compat_strings.exists() or not compat_metadata.exists():
            hard_fail = True

    return 1 if hard_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
