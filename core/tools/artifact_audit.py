#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import string
import subprocess
import sys
from pathlib import Path


PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10

PF_X = 0x1
PF_W = 0x2

SHT_SYMTAB = 2
SHT_DYNSYM = 11

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_SECURITY = 4

VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_LOAD_UPWARD_DYLIB = 0x23 | 0x80000000
LC_REEXPORT_DYLIB = 0x1F | 0x80000000
LC_CODE_SIGNATURE = 0x1D

SUSPICIOUS_IMPORT_TOKENS = (
    "dbghelp",
    "symsrv",
    "frida",
    "lldb",
    "ghidra",
    "x64dbg",
    "ollydbg",
)

MODULE_SIGNATURE_MAGIC = b"~Module signature appended~\n"
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_DETACHED_SIGNATURE = 0xFADE0CC1
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172

KNOWN_TARGET_KINDS = {
    "desktop_native",
    "android_so",
    "android_dex",
    "android_dex_research",
    "ios_appstore",
    "windows_driver",
    "linux_kernel_module",
    "android_kernel_module",
    "shell_ephemeral",
}

USER_MODE_TARGET_KINDS = {
    "desktop_native",
    "android_so",
}

PE_USER_MODE_MARKER = b"EIPPF_PE_USERMODE_V1"
ELF_USER_MODE_MARKER = b"EIPPF_ELF_USERMODE_V1"

SIGNED_TARGET_KINDS = {
    "ios_appstore",
    "windows_driver",
    "linux_kernel_module",
    "android_kernel_module",
}

SIGNED_ARTIFACT_KINDS = {
    "windows_driver_sys",
    "linux_kernel_module_ko",
}

DEX_BUNDLE_MAGIC = b"EDXB"
SHELL_BUNDLE_MAGIC = b"ESHB"

DEX_BUNDLE_HEADER_FORMAT_VERSION_OFFSET = 4
DEX_BUNDLE_HEADER_FLAGS_OFFSET = 5
DEX_BUNDLE_HEADER_DEX_VERSION_OFFSET = 6
DEX_BUNDLE_HEADER_DEX_VERSION_LENGTH = 3
DEX_BUNDLE_HEADER_KEY_MATERIAL_MARKER_OFFSET = (
    DEX_BUNDLE_HEADER_DEX_VERSION_OFFSET + DEX_BUNDLE_HEADER_DEX_VERSION_LENGTH
)
DEX_BUNDLE_INVARIANT_MIN_BYTES = 18

SHELL_BUNDLE_HEADER_FORMAT_VERSION_OFFSET = 4
SHELL_BUNDLE_HEADER_KEY_MATERIAL_MARKER_OFFSET = 5
SHELL_BUNDLE_INVARIANT_MIN_BYTES = 16

DEX_LOADER_PROVIDER_KIND_ALLOWLIST = (
    "executable_adapter",
    "fifo",
    "unix_socket",
)
DEX_REQUIRED_BRIDGE_SURFACE = "allowlist_only"
DEX_REQUIRED_CLASS_LOADER_POLICY = "private_handle_only"
DEX_REQUIRED_ANTI_DEBUG_POLICY = "block_jdwp_attach"
DEX_REQUIRED_ANTI_HOOK_POLICY = "best_effort_frida_xposed_guard"
DEX_BRIDGE_SURFACE_ALLOWLIST = (
    "restricted",
    "allowlist_only",
    "minimized",
)
DEX_CLASS_LOADER_ALLOWLIST = (
    "isolated",
    "in_memory_only",
    "allowlist_only",
)
IOS_PRIVATE_FRAMEWORK_MARKERS = (
    "/system/library/privateframeworks/",
    "privateframeworks/",
)

SIGNATURE_VERIFIER_SCHEMA_VERSION = 1
SIGNATURE_VERIFIER_TIMEOUT_SECONDS = 1.0
SIGNATURE_VERIFIER_STDOUT_LIMIT_BYTES = 64 * 1024
UNTRUSTED_VERIFIER_PREFIXES = ("/tmp", "/var/tmp")


def target_kind_matches_artifact_kind(target_kind: str, artifact_kind: str) -> bool:
    if target_kind == "desktop_native":
        return artifact_kind in ("pe", "elf")
    if target_kind == "android_so":
        return artifact_kind == "elf"
    if target_kind == "ios_appstore":
        return artifact_kind == "macho"
    if target_kind == "windows_driver":
        return artifact_kind == "pe"
    if target_kind in ("linux_kernel_module", "android_kernel_module"):
        return artifact_kind == "elf"
    if target_kind in ("android_dex", "android_dex_research"):
        return artifact_kind in ("dex", "dex_bundle")
    if target_kind == "shell_ephemeral":
        return artifact_kind == "shell_bundle"
    return False


def manifest_artifact_kind_matches(artifact_kind: str, manifest_artifact_kind: str) -> bool:
    if manifest_artifact_kind == "windows_driver_sys":
        return artifact_kind == "pe"
    if manifest_artifact_kind == "linux_kernel_module_ko":
        return artifact_kind == "elf"
    return manifest_artifact_kind == artifact_kind


def detect_artifact_kind(data: bytes) -> str:
    if is_pe_artifact(data):
        return "pe"
    if data.startswith(b"\x7fELF"):
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
    if data.startswith(b"dex\n"):
        return "dex"
    if data.startswith(DEX_BUNDLE_MAGIC):
        return "dex_bundle"
    if data.startswith(SHELL_BUNDLE_MAGIC):
        return "shell_bundle"
    return "unknown"


def is_pe_artifact(data: bytes) -> bool:
    if len(data) < 2 or data[:2] != b"MZ":
        return False
    if len(data) < 0x40:
        return True
    pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little", signed=False)
    if pe_offset + 4 > len(data):
        return True
    return data[pe_offset : pe_offset + 4] == b"PE\0\0"


def extract_strings(data: bytes, minimum_length: int = 4) -> list[str]:
    printable = set(string.printable) - {"\x0b", "\x0c", "\r", "\n", "\t"}
    results: list[str] = []
    current: list[str] = []
    for value in data:
        char = chr(value)
        if char in printable:
            current.append(char)
            continue
        if len(current) >= minimum_length:
            results.append("".join(current))
        current = []
    if len(current) >= minimum_length:
        results.append("".join(current))
    return results


def load_denylist(path: Path) -> tuple[list[str], bool]:
    if not path.exists():
        return [], False
    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries, len(entries) > 0


def unpack_u16(data: bytes, offset: int, little_endian: bool) -> int:
    if offset + 2 > len(data):
        raise ValueError("truncated")
    return int.from_bytes(data[offset : offset + 2], byteorder="little" if little_endian else "big")


def unpack_u32(data: bytes, offset: int, little_endian: bool) -> int:
    if offset + 4 > len(data):
        raise ValueError("truncated")
    return int.from_bytes(data[offset : offset + 4], byteorder="little" if little_endian else "big")


def unpack_u64(data: bytes, offset: int, little_endian: bool) -> int:
    if offset + 8 > len(data):
        raise ValueError("truncated")
    return int.from_bytes(data[offset : offset + 8], byteorder="little" if little_endian else "big")


def read_c_string(data: bytes, offset: int, end: int | None = None) -> str | None:
    if offset < 0 or offset >= len(data):
        return None
    limit = len(data) if end is None else min(end, len(data))
    cursor = offset
    while cursor < limit and data[cursor] != 0:
        cursor += 1
    if cursor >= limit:
        return None
    return data[offset:cursor].decode("utf-8", errors="replace")


def contains_analysis_import(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in SUSPICIOUS_IMPORT_TOKENS)


def find_denylist_hits(values: list[str], denylist: list[str], field_name: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    denylist_lower = [(entry, entry.lower()) for entry in denylist]
    for value in values:
        lowered = value.lower()
        for original, lowered_entry in denylist_lower:
            if lowered_entry in lowered:
                hits.append({"field": field_name, "pattern": original, "value": value})
    return hits


def parse_elf_layout(data: bytes) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    if len(data) < 0x34:
        return None, [{"kind": "malformed_elf", "detail": "truncated_elf_header"}]

    elf_class = data[4]
    elf_data = data[5]
    if elf_class not in (1, 2) or elf_data not in (1, 2):
        return None, [{"kind": "malformed_elf", "detail": "unsupported_elf_header"}]

    little_endian = elf_data == 1
    try:
        if elf_class == 2:
            phoff = unpack_u64(data, 32, little_endian)
            shoff = unpack_u64(data, 40, little_endian)
            phentsize = unpack_u16(data, 54, little_endian)
            phnum = unpack_u16(data, 56, little_endian)
            shentsize = unpack_u16(data, 58, little_endian)
            shnum = unpack_u16(data, 60, little_endian)
            if phentsize < 56 or (shnum != 0 and shentsize < 64):
                return None, [{"kind": "malformed_elf", "detail": "invalid_entry_sizes"}]
        else:
            phoff = unpack_u32(data, 28, little_endian)
            shoff = unpack_u32(data, 32, little_endian)
            phentsize = unpack_u16(data, 42, little_endian)
            phnum = unpack_u16(data, 44, little_endian)
            shentsize = unpack_u16(data, 46, little_endian)
            shnum = unpack_u16(data, 48, little_endian)
            if phentsize < 32 or (shnum != 0 and shentsize < 40):
                return None, [{"kind": "malformed_elf", "detail": "invalid_entry_sizes"}]
    except ValueError:
        return None, [{"kind": "malformed_elf", "detail": "truncated_elf_header"}]

    segments: list[dict[str, int]] = []
    for index in range(phnum):
        entry_offset = phoff + index * phentsize
        if entry_offset + phentsize > len(data):
            return None, [{"kind": "malformed_elf", "detail": "truncated_program_header_table"}]
        try:
            p_type = unpack_u32(data, entry_offset, little_endian)
            if elf_class == 2:
                p_flags = unpack_u32(data, entry_offset + 4, little_endian)
                p_offset = unpack_u64(data, entry_offset + 8, little_endian)
                p_vaddr = unpack_u64(data, entry_offset + 16, little_endian)
                p_filesz = unpack_u64(data, entry_offset + 32, little_endian)
                p_memsz = unpack_u64(data, entry_offset + 40, little_endian)
            else:
                p_offset = unpack_u32(data, entry_offset + 4, little_endian)
                p_vaddr = unpack_u32(data, entry_offset + 8, little_endian)
                p_filesz = unpack_u32(data, entry_offset + 16, little_endian)
                p_memsz = unpack_u32(data, entry_offset + 20, little_endian)
                p_flags = unpack_u32(data, entry_offset + 24, little_endian)
        except ValueError:
            return None, [{"kind": "malformed_elf", "detail": "truncated_program_header"}]
        segments.append(
            {
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
            }
        )

    sections: list[dict[str, int]] = []
    if shnum != 0 and shoff != 0:
        for index in range(shnum):
            entry_offset = shoff + index * shentsize
            if entry_offset + shentsize > len(data):
                return None, [{"kind": "malformed_elf", "detail": "truncated_section_header_table"}]
            try:
                sh_type = unpack_u32(data, entry_offset + 4, little_endian)
                if elf_class == 2:
                    sh_offset = unpack_u64(data, entry_offset + 24, little_endian)
                    sh_size = unpack_u64(data, entry_offset + 32, little_endian)
                    sh_link = unpack_u32(data, entry_offset + 40, little_endian)
                    sh_entsize = unpack_u64(data, entry_offset + 56, little_endian)
                else:
                    sh_offset = unpack_u32(data, entry_offset + 16, little_endian)
                    sh_size = unpack_u32(data, entry_offset + 20, little_endian)
                    sh_link = unpack_u32(data, entry_offset + 24, little_endian)
                    sh_entsize = unpack_u32(data, entry_offset + 36, little_endian)
            except ValueError:
                return None, [{"kind": "malformed_elf", "detail": "truncated_section_header"}]
            sections.append(
                {
                    "type": sh_type,
                    "offset": sh_offset,
                    "size": sh_size,
                    "link": sh_link,
                    "entsize": sh_entsize,
                }
            )

    return {
        "class": elf_class,
        "little_endian": little_endian,
        "segments": segments,
        "sections": sections,
    }, []


def elf_vaddr_to_offset(vaddr: int, segments: list[dict[str, int]]) -> int | None:
    for segment in segments:
        start = segment["vaddr"]
        span = max(segment["filesz"], segment["memsz"], 1)
        if start <= vaddr < start + span:
            return segment["offset"] + (vaddr - start)
    return None


def parse_elf_permission_violations(data: bytes) -> tuple[list[dict[str, object]], bool]:
    layout, errors = parse_elf_layout(data)
    if layout is None:
        return errors, False
    violations: list[dict[str, object]] = []
    for index, segment in enumerate(layout["segments"]):
        p_type = segment["type"]
        p_flags = segment["flags"]
        if p_type == PT_LOAD and (p_flags & PF_X) and (p_flags & PF_W):
            violations.append(
                {
                    "kind": "writable_executable_load_segment",
                    "index": index,
                    "flags": p_flags,
                }
            )
        if p_type == PT_GNU_STACK and (p_flags & PF_X):
            violations.append(
                {
                    "kind": "executable_stack_segment",
                    "index": index,
                    "flags": p_flags,
                }
            )
    return violations, True


def parse_pe_layout(data: bytes) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, [{"kind": "malformed_pe", "detail": "truncated_dos_header"}]

    pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little", signed=False)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None, [{"kind": "malformed_pe", "detail": "invalid_pe_signature"}]

    try:
        number_of_sections = unpack_u16(data, pe_offset + 6, True)
        size_of_optional_header = unpack_u16(data, pe_offset + 20, True)
    except ValueError:
        return None, [{"kind": "malformed_pe", "detail": "truncated_coff_header"}]

    optional_header_offset = pe_offset + 24
    if optional_header_offset + size_of_optional_header > len(data):
        return None, [{"kind": "malformed_pe", "detail": "truncated_optional_header"}]

    try:
        optional_magic = unpack_u16(data, optional_header_offset, True)
    except ValueError:
        return None, [{"kind": "malformed_pe", "detail": "truncated_optional_header"}]

    if optional_magic == 0x20B:
        pe32_plus = True
        number_of_rva_and_sizes_offset = optional_header_offset + 108
        data_directory_offset = optional_header_offset + 112
    elif optional_magic == 0x10B:
        pe32_plus = False
        number_of_rva_and_sizes_offset = optional_header_offset + 92
        data_directory_offset = optional_header_offset + 96
    else:
        return None, [{"kind": "malformed_pe", "detail": "unsupported_optional_header_magic"}]

    try:
        number_of_rva_and_sizes = unpack_u32(data, number_of_rva_and_sizes_offset, True)
    except ValueError:
        return None, [{"kind": "malformed_pe", "detail": "truncated_data_directory_count"}]

    section_table = optional_header_offset + size_of_optional_header
    sections: list[dict[str, int | str]] = []
    for index in range(number_of_sections):
        entry_offset = section_table + index * 40
        if entry_offset + 40 > len(data):
            return None, [{"kind": "malformed_pe", "detail": "truncated_section_table"}]
        name_bytes = data[entry_offset : entry_offset + 8]
        name = name_bytes.split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size = int.from_bytes(data[entry_offset + 8 : entry_offset + 12], "little")
        virtual_address = int.from_bytes(data[entry_offset + 12 : entry_offset + 16], "little")
        raw_size = int.from_bytes(data[entry_offset + 16 : entry_offset + 20], "little")
        raw_pointer = int.from_bytes(data[entry_offset + 20 : entry_offset + 24], "little")
        characteristics = int.from_bytes(data[entry_offset + 36 : entry_offset + 40], "little")
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
                "characteristics": characteristics,
            }
        )

    return {
        "pe_offset": pe_offset,
        "pe32_plus": pe32_plus,
        "data_directory_offset": data_directory_offset,
        "number_of_rva_and_sizes": number_of_rva_and_sizes,
        "sections": sections,
    }, []


def pe_directory(data: bytes, layout: dict[str, object], index: int) -> tuple[int, int] | None:
    if index >= int(layout["number_of_rva_and_sizes"]):
        return None
    entry_offset = int(layout["data_directory_offset"]) + index * 8
    if entry_offset + 8 > len(data):
        return None
    virtual_address = int.from_bytes(data[entry_offset : entry_offset + 4], "little")
    size = int.from_bytes(data[entry_offset + 4 : entry_offset + 8], "little")
    return virtual_address, size


def pe_rva_to_offset(layout: dict[str, object], rva: int) -> int | None:
    for section in layout["sections"]:
        start = int(section["virtual_address"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]), 1)
        if start <= rva < start + span:
            return int(section["raw_pointer"]) + (rva - start)
    if rva < int(layout["pe_offset"]):
        return rva
    return None


def parse_pe_permission_violations(data: bytes) -> tuple[list[dict[str, object]], bool]:
    layout, errors = parse_pe_layout(data)
    if layout is None:
        return errors, False
    violations: list[dict[str, object]] = []
    for index, section in enumerate(layout["sections"]):
        characteristics = int(section["characteristics"])
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) and (characteristics & IMAGE_SCN_MEM_WRITE):
            violations.append(
                {
                    "kind": "writable_executable_section",
                    "index": index,
                    "name": section["name"],
                    "characteristics": characteristics,
                }
            )
    return violations, True


def parse_macho_header(data: bytes) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    if len(data) < 28:
        return None, [{"kind": "malformed_macho", "detail": "truncated_macho_header"}]

    magic = data[:4]
    if magic == b"\xfe\xed\xfa\xce":
        little_endian = False
        is_64 = False
    elif magic == b"\xce\xfa\xed\xfe":
        little_endian = True
        is_64 = False
    elif magic == b"\xfe\xed\xfa\xcf":
        little_endian = False
        is_64 = True
    elif magic == b"\xcf\xfa\xed\xfe":
        little_endian = True
        is_64 = True
    else:
        return None, [{"kind": "malformed_macho", "detail": "unsupported_macho_magic"}]

    header_size = 32 if is_64 else 28
    try:
        ncmds = unpack_u32(data, 16, little_endian)
    except ValueError:
        return None, [{"kind": "malformed_macho", "detail": "truncated_macho_header"}]
    return {"little_endian": little_endian, "is_64": is_64, "header_size": header_size, "ncmds": ncmds}, []


def parse_macho_load_commands(data: bytes) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    header, errors = parse_macho_header(data)
    if header is None:
        return None, errors
    little_endian = bool(header["little_endian"])
    offset = int(header["header_size"])
    commands: list[dict[str, int]] = []
    for index in range(int(header["ncmds"])):
        if offset + 8 > len(data):
            return None, [{"kind": "malformed_macho", "detail": "truncated_load_command"}]
        try:
            cmd = unpack_u32(data, offset, little_endian)
            cmdsize = unpack_u32(data, offset + 4, little_endian)
        except ValueError:
            return None, [{"kind": "malformed_macho", "detail": "truncated_load_command"}]
        if cmdsize < 8 or offset + cmdsize > len(data):
            return None, [{"kind": "malformed_macho", "detail": "invalid_load_command_size"}]
        commands.append({"cmd": cmd, "cmdsize": cmdsize, "offset": offset, "index": index})
        offset += cmdsize
    header["commands"] = commands
    return header, []


def parse_macho_permission_violations(data: bytes) -> tuple[list[dict[str, object]], bool]:
    layout, errors = parse_macho_load_commands(data)
    if layout is None:
        return errors, False
    little_endian = bool(layout["little_endian"])
    violations: list[dict[str, object]] = []
    for command in layout["commands"]:
        cmd = int(command["cmd"])
        offset = int(command["offset"])
        if cmd in (LC_SEGMENT, 0x19):
            maxprot_offset = offset + (60 if cmd == 0x19 else 40)
            initprot_offset = offset + (64 if cmd == 0x19 else 44)
            try:
                maxprot = unpack_u32(data, maxprot_offset, little_endian)
                initprot = unpack_u32(data, initprot_offset, little_endian)
            except ValueError:
                return [{"kind": "malformed_macho", "detail": "truncated_segment_command"}], False
            if (maxprot & VM_PROT_WRITE and maxprot & VM_PROT_EXECUTE) or (
                initprot & VM_PROT_WRITE and initprot & VM_PROT_EXECUTE
            ):
                violations.append(
                    {
                        "kind": "writable_executable_segment",
                        "index": command["index"],
                        "maxprot": maxprot,
                        "initprot": initprot,
                    }
                )
    return violations, True


def audit_native_permissions(data: bytes, artifact_kind: str) -> tuple[bool, list[dict[str, object]], bool]:
    if artifact_kind == "elf":
        violations, parsed = parse_elf_permission_violations(data)
        return len(violations) == 0, violations, parsed
    if artifact_kind == "pe":
        violations, parsed = parse_pe_permission_violations(data)
        return len(violations) == 0, violations, parsed
    if artifact_kind == "macho":
        violations, parsed = parse_macho_permission_violations(data)
        return len(violations) == 0, violations, parsed
    return True, [], True


def audit_bundle_invariants(data: bytes, artifact_kind: str) -> tuple[bool, list[dict[str, object]], bool]:
    if artifact_kind == "dex_bundle":
        if len(data) < DEX_BUNDLE_INVARIANT_MIN_BYTES:
            return False, [{"kind": "malformed_bundle", "detail": "truncated_dex_bundle_header"}], False
        violations: list[dict[str, object]] = []
        if data[DEX_BUNDLE_HEADER_KEY_MATERIAL_MARKER_OFFSET] != 0:
            violations.append({"kind": "embedded_key_material", "detail": "dex_bundle_key_marker_non_zero"})
        return len(violations) == 0, violations, True
    if artifact_kind == "shell_bundle":
        if len(data) < SHELL_BUNDLE_INVARIANT_MIN_BYTES:
            return False, [{"kind": "malformed_bundle", "detail": "truncated_shell_bundle_header"}], False
        violations: list[dict[str, object]] = []
        if data[SHELL_BUNDLE_HEADER_KEY_MATERIAL_MARKER_OFFSET] != 0:
            violations.append({"kind": "embedded_key_material", "detail": "shell_bundle_key_marker_non_zero"})
        return len(violations) == 0, violations, True
    return True, [], True


def audit_pe_imports(data: bytes) -> dict[str, object]:
    layout, errors = parse_pe_layout(data)
    if layout is None:
        return {"parsed": False, "passed": False, "libraries": [], "symbols": [], "violations": errors}

    directory = pe_directory(data, layout, IMAGE_DIRECTORY_ENTRY_IMPORT)
    if directory is None or directory == (0, 0):
        return {"parsed": True, "passed": True, "libraries": [], "symbols": [], "violations": []}

    import_rva, _ = directory
    descriptor_offset = pe_rva_to_offset(layout, import_rva)
    if descriptor_offset is None:
        return {
            "parsed": False,
            "passed": False,
            "libraries": [],
            "symbols": [],
            "violations": [{"kind": "malformed_pe", "detail": "import_directory_out_of_range"}],
        }

    libraries: list[str] = []
    symbols: list[str] = []
    violations: list[dict[str, object]] = []
    thunk_size = 8 if bool(layout["pe32_plus"]) else 4
    ordinal_mask = 0x8000000000000000 if bool(layout["pe32_plus"]) else 0x80000000

    for index in range(256):
        entry_offset = descriptor_offset + index * 20
        if entry_offset + 20 > len(data):
            return {
                "parsed": False,
                "passed": False,
                "libraries": libraries,
                "symbols": symbols,
                "violations": [{"kind": "malformed_pe", "detail": "truncated_import_descriptor_table"}],
            }
        original_first_thunk = int.from_bytes(data[entry_offset : entry_offset + 4], "little")
        name_rva = int.from_bytes(data[entry_offset + 12 : entry_offset + 16], "little")
        first_thunk = int.from_bytes(data[entry_offset + 16 : entry_offset + 20], "little")
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break

        name_offset = pe_rva_to_offset(layout, name_rva)
        dll_name = read_c_string(data, -1 if name_offset is None else name_offset)
        if dll_name is None:
            return {
                "parsed": False,
                "passed": False,
                "libraries": libraries,
                "symbols": symbols,
                "violations": [{"kind": "malformed_pe", "detail": "invalid_import_name_rva"}],
            }
        libraries.append(dll_name)
        if contains_analysis_import(dll_name):
            violations.append({"kind": "analysis_surface_import", "detail": dll_name})

        thunk_rva = original_first_thunk or first_thunk
        if thunk_rva == 0:
            continue
        thunk_offset = pe_rva_to_offset(layout, thunk_rva)
        if thunk_offset is None:
            return {
                "parsed": False,
                "passed": False,
                "libraries": libraries,
                "symbols": symbols,
                "violations": [{"kind": "malformed_pe", "detail": "invalid_import_thunk_rva"}],
            }

        for thunk_index in range(512):
            value_offset = thunk_offset + thunk_index * thunk_size
            if value_offset + thunk_size > len(data):
                return {
                    "parsed": False,
                    "passed": False,
                    "libraries": libraries,
                    "symbols": symbols,
                    "violations": [{"kind": "malformed_pe", "detail": "truncated_import_thunk_table"}],
                }
            if bool(layout["pe32_plus"]):
                value = int.from_bytes(data[value_offset : value_offset + 8], "little")
            else:
                value = int.from_bytes(data[value_offset : value_offset + 4], "little")
            if value == 0:
                break
            if value & ordinal_mask:
                symbols.append(f"ordinal:{value & ~ordinal_mask}")
                continue

            hint_name_offset = pe_rva_to_offset(layout, value)
            symbol_name = read_c_string(data, -1 if hint_name_offset is None else hint_name_offset + 2)
            if symbol_name is None:
                return {
                    "parsed": False,
                    "passed": False,
                    "libraries": libraries,
                    "symbols": symbols,
                    "violations": [{"kind": "malformed_pe", "detail": "invalid_import_hint_name"}],
                }
            symbols.append(symbol_name)

    if len(libraries) > 12 or len(symbols) > 128:
        violations.append(
            {
                "kind": "import_surface_too_large",
                "library_count": len(libraries),
                "symbol_count": len(symbols),
            }
        )
    return {
        "parsed": True,
        "passed": len(violations) == 0,
        "libraries": libraries,
        "symbols": symbols,
        "violations": violations,
    }


def audit_elf_imports(data: bytes) -> dict[str, object]:
    layout, errors = parse_elf_layout(data)
    if layout is None:
        return {"parsed": False, "passed": False, "libraries": [], "symbols": [], "violations": errors}

    segments = list(layout["segments"])
    dynamic_segment = next((segment for segment in segments if segment["type"] == PT_DYNAMIC), None)
    if dynamic_segment is None:
        return {"parsed": True, "passed": True, "libraries": [], "symbols": [], "violations": []}

    dynamic_offset = int(dynamic_segment["offset"])
    dynamic_size = int(dynamic_segment["filesz"])
    little_endian = bool(layout["little_endian"])
    is_64 = int(layout["class"]) == 2
    entry_size = 16 if is_64 else 8

    if dynamic_offset + dynamic_size > len(data):
        return {
            "parsed": False,
            "passed": False,
            "libraries": [],
            "symbols": [],
            "violations": [{"kind": "malformed_elf", "detail": "truncated_dynamic_section"}],
        }

    strtab_vaddr = 0
    strtab_size = 0
    needed_offsets: list[int] = []
    cursor = dynamic_offset
    while cursor + entry_size <= dynamic_offset + dynamic_size:
        if is_64:
            tag = unpack_u64(data, cursor, little_endian)
            value = unpack_u64(data, cursor + 8, little_endian)
        else:
            tag = unpack_u32(data, cursor, little_endian)
            value = unpack_u32(data, cursor + 4, little_endian)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            needed_offsets.append(value)
        elif tag == DT_STRTAB:
            strtab_vaddr = value
        elif tag == DT_STRSZ:
            strtab_size = value
        cursor += entry_size

    if not needed_offsets:
        return {"parsed": True, "passed": True, "libraries": [], "symbols": [], "violations": []}
    if strtab_vaddr == 0 or strtab_size == 0:
        return {
            "parsed": False,
            "passed": False,
            "libraries": [],
            "symbols": [],
            "violations": [{"kind": "malformed_elf", "detail": "dynamic_string_table_missing"}],
        }

    strtab_offset = elf_vaddr_to_offset(strtab_vaddr, segments)
    if strtab_offset is None:
        return {
            "parsed": False,
            "passed": False,
            "libraries": [],
            "symbols": [],
            "violations": [{"kind": "malformed_elf", "detail": "dynamic_string_table_out_of_range"}],
        }

    libraries: list[str] = []
    violations: list[dict[str, object]] = []
    strtab_end = strtab_offset + strtab_size
    for needed_offset in needed_offsets:
        library = read_c_string(data, strtab_offset + needed_offset, strtab_end)
        if library is None:
            return {
                "parsed": False,
                "passed": False,
                "libraries": libraries,
                "symbols": [],
                "violations": [{"kind": "malformed_elf", "detail": "invalid_needed_entry"}],
            }
        libraries.append(library)
        if contains_analysis_import(library):
            violations.append({"kind": "analysis_surface_import", "detail": library})

    if len(libraries) > 12:
        violations.append({"kind": "import_surface_too_large", "library_count": len(libraries)})
    return {
        "parsed": True,
        "passed": len(violations) == 0,
        "libraries": libraries,
        "symbols": [],
        "violations": violations,
    }


def audit_macho_imports(data: bytes) -> dict[str, object]:
    layout, errors = parse_macho_load_commands(data)
    if layout is None:
        return {"parsed": False, "passed": False, "libraries": [], "symbols": [], "violations": errors}

    libraries: list[str] = []
    violations: list[dict[str, object]] = []
    for command in layout["commands"]:
        if command["cmd"] not in (
            LC_LOAD_DYLIB,
            LC_LOAD_WEAK_DYLIB,
            LC_LOAD_UPWARD_DYLIB,
            LC_REEXPORT_DYLIB,
        ):
            continue
        name_offset = unpack_u32(data, int(command["offset"]) + 8, bool(layout["little_endian"]))
        absolute_name_offset = int(command["offset"]) + name_offset
        library = read_c_string(
            data,
            absolute_name_offset,
            int(command["offset"]) + int(command["cmdsize"]),
        )
        if library is None:
            return {
                "parsed": False,
                "passed": False,
                "libraries": libraries,
                "symbols": [],
                "violations": [{"kind": "malformed_macho", "detail": "invalid_dylib_name"}],
            }
        libraries.append(library)
        if contains_analysis_import(library):
            violations.append({"kind": "analysis_surface_import", "detail": library})

    if len(libraries) > 12:
        violations.append({"kind": "import_surface_too_large", "library_count": len(libraries)})
    return {
        "parsed": True,
        "passed": len(violations) == 0,
        "libraries": libraries,
        "symbols": [],
        "violations": violations,
    }


def audit_import_surface(data: bytes, artifact_kind: str) -> dict[str, object]:
    if artifact_kind == "pe":
        return audit_pe_imports(data)
    if artifact_kind == "elf":
        return audit_elf_imports(data)
    if artifact_kind == "macho":
        return audit_macho_imports(data)
    return {"parsed": True, "passed": True, "libraries": [], "symbols": [], "violations": []}


def audit_pe_symbols(data: bytes, denylist: list[str]) -> dict[str, object]:
    layout, errors = parse_pe_layout(data)
    if layout is None:
        return {"parsed": False, "passed": False, "names": [], "violations": errors}

    directory = pe_directory(data, layout, IMAGE_DIRECTORY_ENTRY_EXPORT)
    if directory is None or directory == (0, 0):
        return {"parsed": True, "passed": True, "names": [], "violations": []}

    export_offset = pe_rva_to_offset(layout, directory[0])
    if export_offset is None or export_offset + 40 > len(data):
        return {
            "parsed": False,
            "passed": False,
            "names": [],
            "violations": [{"kind": "malformed_pe", "detail": "invalid_export_directory"}],
        }

    number_of_names = int.from_bytes(data[export_offset + 24 : export_offset + 28], "little")
    address_of_names = int.from_bytes(data[export_offset + 32 : export_offset + 36], "little")
    name_pointer_offset = pe_rva_to_offset(layout, address_of_names)
    if name_pointer_offset is None:
        return {
            "parsed": False,
            "passed": False,
            "names": [],
            "violations": [{"kind": "malformed_pe", "detail": "invalid_export_name_table"}],
        }

    names: list[str] = []
    for index in range(min(number_of_names, 512)):
        entry_offset = name_pointer_offset + index * 4
        if entry_offset + 4 > len(data):
            return {
                "parsed": False,
                "passed": False,
                "names": names,
                "violations": [{"kind": "malformed_pe", "detail": "truncated_export_name_table"}],
            }
        name_rva = int.from_bytes(data[entry_offset : entry_offset + 4], "little")
        name_offset = pe_rva_to_offset(layout, name_rva)
        name = read_c_string(data, -1 if name_offset is None else name_offset)
        if name is None:
            return {
                "parsed": False,
                "passed": False,
                "names": names,
                "violations": [{"kind": "malformed_pe", "detail": "invalid_export_name"}],
            }
        names.append(name)

    violations = find_denylist_hits(names, denylist, "symbol")
    return {"parsed": True, "passed": len(violations) == 0, "names": names, "violations": violations}


def audit_elf_symbols(data: bytes, denylist: list[str]) -> dict[str, object]:
    layout, errors = parse_elf_layout(data)
    if layout is None:
        return {"parsed": False, "passed": False, "names": [], "violations": errors}

    sections = list(layout["sections"])
    if not sections:
        return {"parsed": True, "passed": True, "names": [], "violations": []}

    little_endian = bool(layout["little_endian"])
    is_64 = int(layout["class"]) == 2
    names: list[str] = []
    for section in sections:
        if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if section["entsize"] == 0 or section["size"] == 0:
            continue
        link_index = int(section["link"])
        if link_index < 0 or link_index >= len(sections):
            return {
                "parsed": False,
                "passed": False,
                "names": names,
                "violations": [{"kind": "malformed_elf", "detail": "invalid_symbol_string_table_link"}],
            }
        strtab = sections[link_index]
        strtab_offset = int(strtab["offset"])
        strtab_size = int(strtab["size"])
        entry_size = int(section["entsize"])
        section_offset = int(section["offset"])
        section_size = int(section["size"])
        if section_offset + section_size > len(data) or strtab_offset + strtab_size > len(data):
            return {
                "parsed": False,
                "passed": False,
                "names": names,
                "violations": [{"kind": "malformed_elf", "detail": "symbol_table_out_of_range"}],
            }
        count = section_size // entry_size
        for index in range(min(count, 2048)):
            entry_offset = section_offset + index * entry_size
            name_offset = unpack_u32(data, entry_offset, little_endian)
            if name_offset == 0 or name_offset >= strtab_size:
                continue
            name = read_c_string(data, strtab_offset + name_offset, strtab_offset + strtab_size)
            if name:
                names.append(name)

    violations = find_denylist_hits(names, denylist, "symbol")
    return {"parsed": True, "passed": len(violations) == 0, "names": names, "violations": violations}


def audit_macho_symbols(data: bytes, denylist: list[str]) -> dict[str, object]:
    layout, errors = parse_macho_load_commands(data)
    if layout is None:
        return {"parsed": False, "passed": False, "names": [], "violations": errors}

    symtab = next((command for command in layout["commands"] if command["cmd"] == LC_SYMTAB), None)
    if symtab is None:
        return {"parsed": True, "passed": True, "names": [], "violations": []}

    little_endian = bool(layout["little_endian"])
    is_64 = bool(layout["is_64"])
    symoff = unpack_u32(data, int(symtab["offset"]) + 8, little_endian)
    nsyms = unpack_u32(data, int(symtab["offset"]) + 12, little_endian)
    stroff = unpack_u32(data, int(symtab["offset"]) + 16, little_endian)
    strsize = unpack_u32(data, int(symtab["offset"]) + 20, little_endian)
    entry_size = 16 if is_64 else 12
    if symoff + nsyms * entry_size > len(data) or stroff + strsize > len(data):
        return {
            "parsed": False,
            "passed": False,
            "names": [],
            "violations": [{"kind": "malformed_macho", "detail": "symbol_table_out_of_range"}],
        }

    names: list[str] = []
    for index in range(min(nsyms, 2048)):
        entry_offset = symoff + index * entry_size
        string_index = unpack_u32(data, entry_offset, little_endian)
        if string_index == 0 or string_index >= strsize:
            continue
        name = read_c_string(data, stroff + string_index, stroff + strsize)
        if name:
            names.append(name)

    violations = find_denylist_hits(names, denylist, "symbol")
    return {"parsed": True, "passed": len(violations) == 0, "names": names, "violations": violations}


def audit_symbol_surface(data: bytes, artifact_kind: str, denylist: list[str]) -> dict[str, object]:
    if artifact_kind == "pe":
        return audit_pe_symbols(data, denylist)
    if artifact_kind == "elf":
        return audit_elf_symbols(data, denylist)
    if artifact_kind == "macho":
        return audit_macho_symbols(data, denylist)
    return {"parsed": True, "passed": True, "names": [], "violations": []}


def normalize_target_kind(value: str | None) -> str | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in KNOWN_TARGET_KINDS:
        return lowered
    return None


def load_manifest_metadata(manifest_path: Path | None) -> dict[str, object]:
    if manifest_path is None:
        return {
            "provided": False,
            "path": "",
            "parsed": True,
            "target_kind_raw": None,
            "target_kind": None,
            "target_kind_valid": True,
            "artifact_kind": None,
            "backend_kind": None,
            "runtime_lane": None,
            "mutation_profile": None,
            "signature_policy": None,
            "sign_after_mutate_required": None,
            "allow_jit": None,
            "allow_runtime_executable_pages": None,
            "allow_persistent_plaintext": None,
            "require_fail_closed": None,
            "kernel_compat_profile": None,
            "hvci_profile": None,
            "vermagic_profile": None,
            "gki_kmi_profile": None,
            "execution_model": None,
            "trace_env_scrubbed": None,
            "source_policy": None,
            "unsafe_shell_features": [],
            "loader_format_version": None,
            "external_key_required": None,
            "key_provider_protocol": None,
            "bridge_surface": None,
            "class_loader": None,
            "anti_debug": None,
            "anti_hook": None,
            "key_provider_endpoint_kind": None,
            "key_provider_static_file": None,
            "key_material_embedded": None,
            "plaintext_output": None,
            "no_persistent_plaintext_goal": None,
        }
    if not manifest_path.exists():
        return {
            "provided": True,
            "path": str(manifest_path),
            "parsed": False,
            "error": "manifest_not_found",
            "target_kind_raw": None,
            "target_kind": None,
            "target_kind_valid": False,
            "artifact_kind": None,
            "backend_kind": None,
            "runtime_lane": None,
            "mutation_profile": None,
            "signature_policy": None,
            "sign_after_mutate_required": None,
            "allow_jit": None,
            "allow_runtime_executable_pages": None,
            "allow_persistent_plaintext": None,
            "require_fail_closed": None,
            "kernel_compat_profile": None,
            "hvci_profile": None,
            "vermagic_profile": None,
            "gki_kmi_profile": None,
            "execution_model": None,
            "trace_env_scrubbed": None,
            "source_policy": None,
            "unsafe_shell_features": [],
            "loader_format_version": None,
            "external_key_required": None,
            "key_provider_protocol": None,
            "bridge_surface": None,
            "class_loader": None,
            "anti_debug": None,
            "anti_hook": None,
            "key_provider_endpoint_kind": None,
            "key_provider_static_file": None,
            "key_material_embedded": None,
            "plaintext_output": None,
            "no_persistent_plaintext_goal": None,
        }
    try:
        parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {
            "provided": True,
            "path": str(manifest_path),
            "parsed": False,
            "error": "manifest_invalid_json",
            "target_kind_raw": None,
            "target_kind": None,
            "target_kind_valid": False,
            "artifact_kind": None,
            "backend_kind": None,
            "runtime_lane": None,
            "mutation_profile": None,
            "signature_policy": None,
            "sign_after_mutate_required": None,
            "allow_jit": None,
            "allow_runtime_executable_pages": None,
            "allow_persistent_plaintext": None,
            "require_fail_closed": None,
            "kernel_compat_profile": None,
            "hvci_profile": None,
            "vermagic_profile": None,
            "gki_kmi_profile": None,
            "execution_model": None,
            "trace_env_scrubbed": None,
            "source_policy": None,
            "unsafe_shell_features": [],
            "loader_format_version": None,
            "external_key_required": None,
            "key_provider_protocol": None,
            "bridge_surface": None,
            "class_loader": None,
            "anti_debug": None,
            "anti_hook": None,
            "key_provider_endpoint_kind": None,
            "key_provider_static_file": None,
            "key_material_embedded": None,
            "plaintext_output": None,
            "no_persistent_plaintext_goal": None,
        }
    if not isinstance(parsed, dict):
        return {
            "provided": True,
            "path": str(manifest_path),
            "parsed": False,
            "error": "manifest_not_object",
            "target_kind_raw": None,
            "target_kind": None,
            "target_kind_valid": False,
            "artifact_kind": None,
            "backend_kind": None,
            "runtime_lane": None,
            "mutation_profile": None,
            "signature_policy": None,
            "sign_after_mutate_required": None,
            "allow_jit": None,
            "allow_runtime_executable_pages": None,
            "allow_persistent_plaintext": None,
            "require_fail_closed": None,
            "kernel_compat_profile": None,
            "hvci_profile": None,
            "vermagic_profile": None,
            "gki_kmi_profile": None,
            "execution_model": None,
            "trace_env_scrubbed": None,
            "source_policy": None,
            "unsafe_shell_features": [],
            "loader_format_version": None,
            "external_key_required": None,
            "key_provider_protocol": None,
            "bridge_surface": None,
            "class_loader": None,
            "anti_debug": None,
            "anti_hook": None,
            "key_provider_endpoint_kind": None,
            "key_provider_static_file": None,
            "key_material_embedded": None,
            "plaintext_output": None,
            "no_persistent_plaintext_goal": None,
        }
    target_kind_raw = parsed.get("target_kind")
    artifact_kind_raw = parsed.get("artifact_kind")
    backend_kind_raw = parsed.get("backend_kind")
    target_kind = normalize_target_kind(target_kind_raw if isinstance(target_kind_raw, str) else None)
    target_kind_valid = target_kind_raw is None or target_kind is not None
    runtime_lane_raw = parsed.get("runtime_lane")
    mutation_profile_raw = parsed.get("mutation_profile")
    signature_policy_raw = parsed.get("signature_policy")
    sign_after_mutate_required_raw = parsed.get("sign_after_mutate_required")
    allow_jit_raw = parsed.get("allow_jit")
    allow_runtime_executable_pages_raw = parsed.get("allow_runtime_executable_pages")
    allow_persistent_plaintext_raw = parsed.get("allow_persistent_plaintext")
    require_fail_closed_raw = parsed.get("require_fail_closed")
    kernel_compat_profile_raw = parsed.get("kernel_compat_profile")
    hvci_profile_raw = parsed.get("hvci_profile")
    vermagic_profile_raw = parsed.get("vermagic_profile")
    gki_kmi_profile_raw = parsed.get("gki_kmi_profile")
    execution_model_raw = parsed.get("execution_model")
    trace_env_scrubbed_raw = parsed.get("trace_env_scrubbed")
    source_policy_raw = parsed.get("source_policy")
    unsafe_shell_features_raw = parsed.get("unsafe_shell_features")
    loader_format_version_raw = parsed.get("loader_format_version")
    external_key_required_raw = parsed.get("external_key_required")
    key_provider_protocol_raw = parsed.get("key_provider_protocol")
    bridge_surface_raw = parsed.get("bridge_surface")
    class_loader_policy_raw = parsed.get("class_loader_policy")
    class_loader_exported_raw = parsed.get("class_loader_exported")
    class_loader_raw = parsed.get("class_loader")
    anti_debug_policy_raw = parsed.get("anti_debug_policy")
    anti_hook_policy_raw = parsed.get("anti_hook_policy")
    anti_debug_raw = parsed.get("anti_debug")
    anti_hook_raw = parsed.get("anti_hook")
    key_provider_endpoint_kind_raw = parsed.get("key_provider_endpoint_kind")
    key_provider_static_file_raw = parsed.get("key_provider_static_file")
    key_material_embedded_raw = parsed.get("key_material_embedded")
    plaintext_output_raw = parsed.get("plaintext_output")
    no_persistent_plaintext_goal_raw = parsed.get("no_persistent_plaintext_goal")
    unsafe_shell_features: list[str] = []
    if isinstance(unsafe_shell_features_raw, list):
        for item in unsafe_shell_features_raw:
            if isinstance(item, str):
                unsafe_shell_features.append(item)
    return {
        "provided": True,
        "path": str(manifest_path),
        "parsed": True,
        "target_kind_raw": target_kind_raw,
        "target_kind": target_kind,
        "target_kind_valid": target_kind_valid,
        "artifact_kind": artifact_kind_raw if isinstance(artifact_kind_raw, str) else None,
        "backend_kind": backend_kind_raw if isinstance(backend_kind_raw, str) else None,
        "runtime_lane": runtime_lane_raw if isinstance(runtime_lane_raw, str) else None,
        "mutation_profile": mutation_profile_raw if isinstance(mutation_profile_raw, str) else None,
        "signature_policy": signature_policy_raw if isinstance(signature_policy_raw, str) else None,
        "sign_after_mutate_required": (
            sign_after_mutate_required_raw if isinstance(sign_after_mutate_required_raw, bool) else None
        ),
        "allow_jit": allow_jit_raw if isinstance(allow_jit_raw, bool) else None,
        "allow_runtime_executable_pages": (
            allow_runtime_executable_pages_raw
            if isinstance(allow_runtime_executable_pages_raw, bool)
            else None
        ),
        "allow_persistent_plaintext": (
            allow_persistent_plaintext_raw if isinstance(allow_persistent_plaintext_raw, bool) else None
        ),
        "require_fail_closed": require_fail_closed_raw if isinstance(require_fail_closed_raw, bool) else None,
        "kernel_compat_profile": (
            kernel_compat_profile_raw if isinstance(kernel_compat_profile_raw, str) else None
        ),
        "hvci_profile": hvci_profile_raw if isinstance(hvci_profile_raw, bool) else None,
        "vermagic_profile": vermagic_profile_raw if isinstance(vermagic_profile_raw, bool) else None,
        "gki_kmi_profile": gki_kmi_profile_raw if isinstance(gki_kmi_profile_raw, bool) else None,
        "execution_model": execution_model_raw if isinstance(execution_model_raw, str) else None,
        "trace_env_scrubbed": (
            trace_env_scrubbed_raw if isinstance(trace_env_scrubbed_raw, bool) else None
        ),
        "source_policy": source_policy_raw if isinstance(source_policy_raw, str) else None,
        "unsafe_shell_features": unsafe_shell_features,
        "loader_format_version": (
            loader_format_version_raw
            if isinstance(loader_format_version_raw, int)
            and not isinstance(loader_format_version_raw, bool)
            else None
        ),
        "external_key_required": (
            external_key_required_raw if isinstance(external_key_required_raw, bool) else None
        ),
        "key_provider_protocol": (
            key_provider_protocol_raw if isinstance(key_provider_protocol_raw, str) else None
        ),
        "bridge_surface": (
            bridge_surface_raw
            if isinstance(bridge_surface_raw, (bool, str))
            else None
        ),
        "class_loader_policy": (
            class_loader_policy_raw if isinstance(class_loader_policy_raw, str) else None
        ),
        "class_loader_exported": (
            class_loader_exported_raw if isinstance(class_loader_exported_raw, bool) else None
        ),
        "class_loader": (
            class_loader_raw
            if isinstance(class_loader_raw, (bool, str))
            else None
        ),
        "anti_debug_policy": (
            anti_debug_policy_raw if isinstance(anti_debug_policy_raw, str) else None
        ),
        "anti_hook_policy": anti_hook_policy_raw if isinstance(anti_hook_policy_raw, str) else None,
        "anti_debug": anti_debug_raw if isinstance(anti_debug_raw, bool) else None,
        "anti_hook": anti_hook_raw if isinstance(anti_hook_raw, bool) else None,
        "key_provider_endpoint_kind": (
            key_provider_endpoint_kind_raw if isinstance(key_provider_endpoint_kind_raw, str) else None
        ),
        "key_provider_static_file": (
            key_provider_static_file_raw if isinstance(key_provider_static_file_raw, bool) else None
        ),
        "key_material_embedded": (
            key_material_embedded_raw if isinstance(key_material_embedded_raw, bool) else None
        ),
        "plaintext_output": plaintext_output_raw if isinstance(plaintext_output_raw, bool) else None,
        "no_persistent_plaintext_goal": (
            no_persistent_plaintext_goal_raw
            if isinstance(no_persistent_plaintext_goal_raw, bool)
            else None
        ),
    }


def canonical_path_is_untrusted(path: Path) -> bool:
    canonical = str(path)
    return any(canonical == prefix or canonical.startswith(prefix + "/") for prefix in UNTRUSTED_VERIFIER_PREFIXES)


def canonical_path_has_prefix(path: Path, prefix: Path) -> bool:
    canonical = str(path)
    prefix_canonical = str(prefix)
    return canonical == prefix_canonical or canonical.startswith(prefix_canonical + "/")


def trusted_verifier_prefixes() -> list[Path]:
    prefixes: list[Path] = []
    default_prefix = Path(__file__).resolve().parents[2]
    prefixes.append(default_prefix)

    raw_prefixes = os.environ.get("EIPPF_SIGNATURE_VERIFIER_TRUSTED_PREFIXES", "")
    if raw_prefixes:
        for raw_prefix in raw_prefixes.split(os.pathsep):
            candidate = raw_prefix.strip()
            if not candidate:
                continue
            candidate_path = Path(candidate)
            if not candidate_path.is_absolute():
                continue
            try:
                prefixes.append(candidate_path.resolve(strict=False))
            except OSError:
                continue
    return prefixes


def trusted_verifier_sha256s() -> set[str]:
    values: set[str] = set()
    raw_values = os.environ.get("EIPPF_SIGNATURE_VERIFIER_TRUSTED_SHA256", "")
    for raw_value in raw_values.split(","):
        candidate = raw_value.strip().lower()
        if len(candidate) == 64 and all(ch in string.hexdigits.lower() for ch in candidate):
            values.add(candidate)
    return values


def file_sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def signature_verifier_path_is_trusted(signature_verifier: Path) -> bool:
    if not signature_verifier.is_absolute():
        return False
    if canonical_path_is_untrusted(signature_verifier):
        return False
    try:
        resolved = signature_verifier.resolve(strict=False)
    except OSError:
        return False
    if canonical_path_is_untrusted(resolved):
        return False
    if not resolved.exists() or not resolved.is_file():
        return False
    for prefix in trusted_verifier_prefixes():
        if canonical_path_has_prefix(resolved, prefix):
            return True
    verifier_sha256 = file_sha256(resolved)
    if verifier_sha256 is None:
        return False
    return verifier_sha256 in trusted_verifier_sha256s()


def invoke_signature_verifier(
    signature_verifier: Path,
    artifact_path: Path,
    artifact_kind: str,
    target_kind: str,
    artifact_sha256: str,
    manifest_path: Path | None,
) -> dict[str, object]:
    command = [
        str(signature_verifier),
        "--artifact",
        str(artifact_path),
        "--artifact-kind",
        artifact_kind,
        "--target-kind",
        target_kind,
        "--artifact-sha256",
        artifact_sha256,
    ]
    if manifest_path is not None and manifest_path.exists():
        command.extend(["--manifest", str(manifest_path)])

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=False,
            timeout=SIGNATURE_VERIFIER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "error": "signature_verifier_failed",
            "reason": "timeout",
            "verified": False,
            "artifact_sha256": "",
        }
    except OSError:
        return {
            "error": "signature_verifier_failed",
            "reason": "exec_error",
            "verified": False,
            "artifact_sha256": "",
        }

    if completed.returncode != 0:
        return {
            "error": "signature_verifier_failed",
            "reason": "nonzero_exit",
            "verified": False,
            "artifact_sha256": "",
        }

    stdout = completed.stdout or b""
    if not stdout:
        return {
            "error": "signature_verifier_failed",
            "reason": "stdout_empty",
            "verified": False,
            "artifact_sha256": "",
        }
    if len(stdout) > SIGNATURE_VERIFIER_STDOUT_LIMIT_BYTES:
        return {
            "error": "signature_verifier_failed",
            "reason": "stdout_too_large",
            "verified": False,
            "artifact_sha256": "",
        }

    try:
        parsed = json.loads(stdout.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {
            "error": "signature_verifier_failed",
            "reason": "invalid_json",
            "verified": False,
            "artifact_sha256": "",
        }

    if not isinstance(parsed, dict):
        return {
            "error": "signature_verifier_failed",
            "reason": "invalid_schema",
            "verified": False,
            "artifact_sha256": "",
        }
    expected_keys = {"schema_version", "verified", "reason", "artifact_sha256"}
    if set(parsed.keys()) != expected_keys:
        return {
            "error": "signature_verifier_failed",
            "reason": "invalid_schema",
            "verified": False,
            "artifact_sha256": "",
        }
    if (
        not isinstance(parsed["schema_version"], int)
        or parsed["schema_version"] != SIGNATURE_VERIFIER_SCHEMA_VERSION
        or not isinstance(parsed["verified"], bool)
        or not isinstance(parsed["reason"], str)
        or not isinstance(parsed["artifact_sha256"], str)
    ):
        return {
            "error": "signature_verifier_failed",
            "reason": "invalid_schema",
            "verified": False,
            "artifact_sha256": "",
        }
    if parsed["artifact_sha256"] != artifact_sha256:
        return {
            "error": "signature_verifier_digest_mismatch",
            "reason": "digest_mismatch",
            "verified": False,
            "artifact_sha256": str(parsed["artifact_sha256"]),
        }

    return {
        "error": None,
        "reason": str(parsed["reason"]),
        "verified": bool(parsed["verified"]),
        "artifact_sha256": str(parsed["artifact_sha256"]),
    }


def resolve_signature_requirement(
    artifact_kind: str,
    artifact_path: Path,
    explicit_target_kind: str | None,
    manifest_meta: dict[str, object],
    strict_mode: bool,
) -> dict[str, object]:
    normalized_explicit = normalize_target_kind(explicit_target_kind)
    explicit_valid = explicit_target_kind is None or normalized_explicit is not None

    manifest_target_kind = manifest_meta.get("target_kind")
    manifest_artifact_kind = manifest_meta.get("artifact_kind")
    manifest_parsed = bool(manifest_meta.get("parsed", True))
    manifest_target_valid = bool(manifest_meta.get("target_kind_valid", True))

    required = False
    source = "none"
    resolved_target_kind: str | None = None

    if normalized_explicit is not None:
        resolved_target_kind = normalized_explicit
        source = "explicit_target_kind"
    elif isinstance(manifest_target_kind, str):
        resolved_target_kind = manifest_target_kind
        source = "manifest_target_kind"
    elif isinstance(manifest_artifact_kind, str) and manifest_artifact_kind in SIGNED_ARTIFACT_KINDS:
        source = "manifest_artifact_kind"
        required = True
    elif artifact_path.suffix.lower() in (".sys", ".ko"):
        source = "path_suffix"
        required = True

    if resolved_target_kind is not None and resolved_target_kind in SIGNED_TARGET_KINDS:
        required = True

    policy_parse_ok = explicit_valid and manifest_parsed and manifest_target_valid
    policy_errors: list[str] = []
    if not explicit_valid:
        policy_errors.append("invalid_explicit_target_kind")
    if bool(manifest_meta.get("provided", False)) and not manifest_parsed:
        policy_errors.append(str(manifest_meta.get("error", "manifest_parse_failed")))
    if manifest_parsed and not manifest_target_valid:
        policy_errors.append("invalid_manifest_target_kind")
    if resolved_target_kind is not None and not target_kind_matches_artifact_kind(
        resolved_target_kind, artifact_kind
    ):
        policy_errors.append("target_kind_artifact_kind_mismatch")
    if (
        manifest_parsed
        and isinstance(manifest_artifact_kind, str)
        and not manifest_artifact_kind_matches(artifact_kind, manifest_artifact_kind)
    ):
        policy_errors.append("manifest_artifact_kind_mismatch")
    if strict_mode and required and source not in ("explicit_target_kind", "manifest_target_kind"):
        policy_errors.append("strict_target_kind_required")
    if policy_errors:
        policy_parse_ok = False

    return {
        "required": required,
        "source": source,
        "resolved_target_kind": resolved_target_kind,
        "policy_parse_ok": policy_parse_ok,
        "policy_errors": policy_errors,
        "explicit_target_kind": explicit_target_kind,
        "manifest_path": manifest_meta.get("path", ""),
    }


def pe_signature_info(data: bytes) -> tuple[dict[str, object], bool]:
    layout, _ = parse_pe_layout(data)
    if layout is None:
        return {
            "structure_present": False,
            "format_valid": False,
            "pe_security_directory": False,
            "entry_count": 0,
            "violations": [{"kind": "malformed_pe", "detail": "signature_surface_parse_failed"}],
        }, False
    directory = pe_directory(data, layout, IMAGE_DIRECTORY_ENTRY_SECURITY)
    if directory is None or directory == (0, 0):
        return {
            "structure_present": False,
            "format_valid": False,
            "pe_security_directory": False,
            "entry_count": 0,
            "violations": [],
        }, True
    file_offset, size = directory
    info: dict[str, object] = {
        "structure_present": True,
        "format_valid": False,
        "pe_security_directory": True,
        "entry_count": 0,
        "violations": [],
    }
    if file_offset < 0 or size < 8 or file_offset + size > len(data):
        info["violations"] = [{"kind": "invalid_pe_signature_directory", "detail": "out_of_range"}]
        return info, True

    cursor = file_offset
    end = file_offset + size
    entry_count = 0
    violations: list[dict[str, object]] = []
    while cursor + 8 <= end:
        length = int.from_bytes(data[cursor : cursor + 4], "little")
        revision = int.from_bytes(data[cursor + 4 : cursor + 6], "little")
        cert_type = int.from_bytes(data[cursor + 6 : cursor + 8], "little")
        if length < 8 or cursor + length > end:
            violations.append({"kind": "invalid_win_certificate_length", "offset": cursor, "length": length})
            break
        if revision not in (0x0100, 0x0200):
            violations.append({"kind": "invalid_win_certificate_revision", "offset": cursor, "revision": revision})
            break
        if cert_type == 0:
            violations.append({"kind": "invalid_win_certificate_type", "offset": cursor, "type": cert_type})
            break
        entry_count += 1
        cursor += (length + 7) & ~7
        if cursor == end:
            break
    if entry_count == 0 and not violations:
        violations.append({"kind": "empty_win_certificate_table"})
    info["entry_count"] = entry_count
    info["violations"] = violations
    info["format_valid"] = entry_count > 0 and len(violations) == 0
    return info, True


def macho_signature_info(data: bytes) -> tuple[dict[str, object], bool]:
    layout, _ = parse_macho_load_commands(data)
    if layout is None:
        return {
            "structure_present": False,
            "format_valid": False,
            "macho_codesig_command": False,
            "violations": [{"kind": "malformed_macho", "detail": "signature_surface_parse_failed"}],
        }, False

    code_sig_command = next((command for command in layout["commands"] if command["cmd"] == LC_CODE_SIGNATURE), None)
    if code_sig_command is None:
        return {
            "structure_present": False,
            "format_valid": False,
            "macho_codesig_command": False,
            "violations": [],
        }, True

    info: dict[str, object] = {
        "structure_present": True,
        "format_valid": False,
        "macho_codesig_command": True,
        "violations": [],
    }
    if int(code_sig_command["cmdsize"]) < 16:
        info["violations"] = [{"kind": "invalid_macho_codesig_command_size"}]
        return info, True

    little_endian = bool(layout["little_endian"])
    command_offset = int(code_sig_command["offset"])
    try:
        dataoff = unpack_u32(data, command_offset + 8, little_endian)
        datasize = unpack_u32(data, command_offset + 12, little_endian)
    except ValueError:
        info["violations"] = [{"kind": "malformed_macho", "detail": "truncated_codesig_command"}]
        return info, False
    if dataoff == 0 or datasize < 8 or dataoff + datasize > len(data):
        info["violations"] = [{"kind": "invalid_macho_codesig_blob_bounds"}]
        return info, True

    magic = int.from_bytes(data[dataoff : dataoff + 4], "big")
    if magic not in (
        CSMAGIC_EMBEDDED_SIGNATURE,
        CSMAGIC_DETACHED_SIGNATURE,
        CSMAGIC_CODEDIRECTORY,
        CSMAGIC_EMBEDDED_ENTITLEMENTS,
        CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
    ):
        info["violations"] = [{"kind": "invalid_macho_codesig_magic", "magic": magic}]
        return info, True

    info["format_valid"] = True
    info["codesig_dataoff"] = dataoff
    info["codesig_datasize"] = datasize
    return info, True


def elf_signature_info(data: bytes) -> tuple[dict[str, object], bool]:
    has_trailer = data.endswith(MODULE_SIGNATURE_MAGIC)
    info: dict[str, object] = {
        "structure_present": has_trailer,
        "format_valid": False,
        "module_signature_trailer": has_trailer,
        "violations": [],
    }
    if not has_trailer:
        return info, True

    footer_end = len(data) - len(MODULE_SIGNATURE_MAGIC)
    footer_size = 12
    if footer_end < footer_size:
        info["violations"] = [{"kind": "truncated_module_signature_footer"}]
        return info, True

    footer_offset = footer_end - footer_size
    signer_len = data[footer_offset + 3]
    key_id_len = data[footer_offset + 4]
    sig_len = int.from_bytes(data[footer_offset + 8 : footer_offset + 12], "big")
    payload_len = signer_len + key_id_len + sig_len
    payload_start = footer_offset - payload_len
    if payload_len == 0 or payload_start < 0:
        info["violations"] = [{"kind": "invalid_module_signature_lengths"}]
        return info, True

    info["format_valid"] = True
    info["module_signature_signer_len"] = signer_len
    info["module_signature_key_id_len"] = key_id_len
    info["module_signature_sig_len"] = sig_len
    return info, True


def audit_signature_surface(
    data: bytes,
    artifact_kind: str,
    artifact_path: Path,
    explicit_target_kind: str | None,
    manifest_meta: dict[str, object],
    signature_verifier: Path | None,
    strict_mode: bool,
) -> dict[str, object]:
    if artifact_kind == "pe":
        sig_info, parse_ok = pe_signature_info(data)
    elif artifact_kind == "elf":
        sig_info, parse_ok = elf_signature_info(data)
    elif artifact_kind == "macho":
        sig_info, parse_ok = macho_signature_info(data)
    else:
        sig_info, parse_ok = {"structure_present": False, "format_valid": False, "violations": []}, True

    policy = resolve_signature_requirement(
        artifact_kind,
        artifact_path,
        explicit_target_kind,
        manifest_meta,
        strict_mode,
    )
    required = bool(policy["required"])
    structure_present = bool(sig_info.get("structure_present", False))
    format_valid = bool(sig_info.get("format_valid", False))
    verifier_provided = signature_verifier is not None
    verifier_invoked = False
    verifier_error: str | None = None
    verifier_reason = ""
    verifier_reported_digest = ""
    artifact_sha256 = hashlib.sha256(data).hexdigest()
    authenticity_verified = False
    passed = False

    if not bool(policy["policy_parse_ok"]):
        validation_mode = "policy_unresolved"
    elif not required:
        validation_mode = "optional_verifier_ignored" if verifier_provided else "not_required"
        passed = True
    elif not parse_ok:
        validation_mode = "required_unparseable"
    elif not structure_present:
        validation_mode = "required_missing"
    elif not format_valid:
        validation_mode = "required_format_invalid"
    elif not verifier_provided:
        validation_mode = "required_authenticity_missing"
    else:
        validation_mode = "external_verifier"
        if signature_verifier is None:
            verifier_error = "signature_verifier_failed"
            verifier_reason = "missing_verifier_path"
        elif not signature_verifier_path_is_trusted(signature_verifier):
            verifier_error = "signature_verifier_untrusted"
            verifier_reason = "signature_verifier_untrusted"
        elif policy["resolved_target_kind"] is None:
            verifier_error = "signature_verifier_failed"
            verifier_reason = "missing_target_kind"
        else:
            verifier_invoked = True
            manifest_path_value = policy.get("manifest_path")
            manifest_path = (
                Path(str(manifest_path_value))
                if isinstance(manifest_path_value, str) and manifest_path_value
                else None
            )
            verifier_result = invoke_signature_verifier(
                signature_verifier,
                artifact_path,
                artifact_kind,
                str(policy["resolved_target_kind"]),
                artifact_sha256,
                manifest_path,
            )
            verifier_error = verifier_result["error"] if isinstance(verifier_result["error"], str) else None
            verifier_reason = str(verifier_result["reason"])
            verifier_reported_digest = str(verifier_result["artifact_sha256"])
            if verifier_error is None:
                authenticity_verified = bool(verifier_result["verified"])
                passed = authenticity_verified
                if not authenticity_verified:
                    verifier_error = "signature_authenticity_rejected"

    return {
        "required": required,
        "requirement_source": policy["source"],
        "resolved_target_kind": policy["resolved_target_kind"],
        "policy_parse_ok": bool(policy["policy_parse_ok"]),
        "policy_errors": policy["policy_errors"],
        "manifest_path": policy["manifest_path"],
        "structure_present": structure_present,
        "format_valid": format_valid,
        "parse_ok": parse_ok,
        "validation_mode": validation_mode,
        "capability": "external_verifier" if verifier_provided else "format_validation_only",
        "artifact_sha256": artifact_sha256,
        "verifier_provided": verifier_provided,
        "verifier_invoked": verifier_invoked,
        "verifier_path": str(signature_verifier) if signature_verifier is not None else "",
        "verifier_error": verifier_error,
        "verifier_reason": verifier_reason,
        "verifier_reported_sha256": verifier_reported_digest,
        "authenticity_verified": authenticity_verified,
        "details": sig_info,
        "passed": passed,
    }


def resolve_user_mode_target_kind(
    explicit_target_kind: str | None, manifest_meta: dict[str, object]
) -> tuple[str | None, str]:
    normalized_explicit = normalize_target_kind(explicit_target_kind)
    if normalized_explicit is not None:
        return normalized_explicit, "explicit_target_kind"
    manifest_target_kind = manifest_meta.get("target_kind")
    if isinstance(manifest_target_kind, str):
        return manifest_target_kind, "manifest_target_kind"
    return None, "none"


def audit_user_mode_marker(
    data: bytes,
    artifact_kind: str,
    explicit_target_kind: str | None,
    manifest_meta: dict[str, object],
) -> dict[str, object]:
    target_kind, target_kind_source = resolve_user_mode_target_kind(explicit_target_kind, manifest_meta)
    expected_marker = ""
    marker_present = False

    if artifact_kind == "pe":
        expected_marker = PE_USER_MODE_MARKER.decode("ascii")
        marker_present = PE_USER_MODE_MARKER in data
    elif artifact_kind == "elf":
        expected_marker = ELF_USER_MODE_MARKER.decode("ascii")
        marker_present = ELF_USER_MODE_MARKER in data

    required = (
        target_kind in USER_MODE_TARGET_KINDS
        and artifact_kind in ("pe", "elf")
        and target_kind is not None
        and target_kind_matches_artifact_kind(target_kind, artifact_kind)
    )

    return {
        "required": required,
        "target_kind": target_kind,
        "target_kind_source": target_kind_source,
        "expected_marker": expected_marker,
        "marker_present": marker_present,
        "passed": (not required) or marker_present,
    }


def find_ios_private_api_hits(imports_result: dict[str, object]) -> list[str]:
    hits: list[str] = []
    libraries = imports_result.get("libraries")
    if not isinstance(libraries, list):
        return hits
    for library in libraries:
        if not isinstance(library, str):
            continue
        lowered = library.lower()
        if any(marker in lowered for marker in IOS_PRIVATE_FRAMEWORK_MARKERS):
            hits.append(library)
    return hits


def audit_artifact(
    data: bytes,
    artifact_path: Path,
    denylist: list[str],
    denylist_loaded: bool,
    explicit_target_kind: str | None,
    manifest_meta: dict[str, object],
    signature_verifier: Path | None,
    strict_mode: bool,
) -> dict[str, object]:
    artifact_kind = detect_artifact_kind(data)
    normalized_explicit_target_kind = normalize_target_kind(explicit_target_kind)
    manifest_target_kind = manifest_meta.get("target_kind")
    resolved_target_kind = (
        normalized_explicit_target_kind
        if normalized_explicit_target_kind is not None
        else (manifest_target_kind if isinstance(manifest_target_kind, str) else None)
    )
    runtime_lane = manifest_meta.get("runtime_lane")
    manifest_artifact_kind = manifest_meta.get("artifact_kind")
    backend_kind = manifest_meta.get("backend_kind")
    mutation_profile = manifest_meta.get("mutation_profile")
    signature_policy = manifest_meta.get("signature_policy")
    sign_after_mutate_required = manifest_meta.get("sign_after_mutate_required")
    loader_format_version = manifest_meta.get("loader_format_version")
    external_key_required = manifest_meta.get("external_key_required")
    key_provider_protocol = manifest_meta.get("key_provider_protocol")
    allow_jit = manifest_meta.get("allow_jit")
    allow_runtime_executable_pages = manifest_meta.get("allow_runtime_executable_pages")
    allow_persistent_plaintext = manifest_meta.get("allow_persistent_plaintext")
    require_fail_closed = manifest_meta.get("require_fail_closed")
    bridge_surface = manifest_meta.get("bridge_surface")
    class_loader_policy = manifest_meta.get("class_loader_policy")
    class_loader_exported = manifest_meta.get("class_loader_exported")
    anti_debug_policy = manifest_meta.get("anti_debug_policy")
    anti_hook_policy = manifest_meta.get("anti_hook_policy")
    kernel_compat_profile = manifest_meta.get("kernel_compat_profile")
    hvci_profile = manifest_meta.get("hvci_profile")
    vermagic_profile = manifest_meta.get("vermagic_profile")
    gki_kmi_profile = manifest_meta.get("gki_kmi_profile")
    execution_model = manifest_meta.get("execution_model")
    trace_env_scrubbed = manifest_meta.get("trace_env_scrubbed")
    source_policy = manifest_meta.get("source_policy")
    unsafe_shell_features = manifest_meta.get("unsafe_shell_features")
    key_provider_endpoint_kind = manifest_meta.get("key_provider_endpoint_kind")
    key_provider_static_file = manifest_meta.get("key_provider_static_file")
    key_material_embedded = manifest_meta.get("key_material_embedded")
    plaintext_output = manifest_meta.get("plaintext_output")
    no_persistent_plaintext_goal = manifest_meta.get("no_persistent_plaintext_goal")
    strings_found = extract_strings(data)
    matched_strings = find_denylist_hits(strings_found, denylist, "string")

    section_permission_scan_passed, permission_violations, native_parse_ok = audit_native_permissions(
        data, artifact_kind
    )
    bundle_invariants_passed, bundle_violations, bundle_parse_ok = audit_bundle_invariants(
        data, artifact_kind
    )
    imports_result = audit_import_surface(data, artifact_kind)
    symbols_result = audit_symbol_surface(data, artifact_kind, denylist)
    signature_result = audit_signature_surface(
        data,
        artifact_kind,
        artifact_path,
        explicit_target_kind,
        manifest_meta,
        signature_verifier,
        strict_mode,
    )
    user_mode_marker_result = audit_user_mode_marker(
        data,
        artifact_kind,
        explicit_target_kind,
        manifest_meta,
    )
    ios_compliance_profile = None
    private_api_hits: list[str] = []
    code_signature_state = {
        "present": False,
        "format_valid": False,
        "validation_mode": signature_result["validation_mode"],
    }
    exec_permission_summary = {
        "rwx_detected": False,
        "violation_kinds": [],
    }

    strict_failures: list[str] = []
    if not denylist_loaded:
        strict_failures.append("denylist_unavailable")
    if artifact_kind == "unknown":
        strict_failures.append("unknown_artifact_kind")
    if not native_parse_ok:
        strict_failures.append("native_artifact_parse_failed")
    if not bundle_parse_ok:
        strict_failures.append("bundle_parse_failed")
    if not imports_result["parsed"]:
        strict_failures.append("import_surface_parse_failed")
    if not symbols_result["parsed"]:
        strict_failures.append("symbol_surface_parse_failed")
    if signature_result["required"] and not signature_result["policy_parse_ok"]:
        strict_failures.append("signature_policy_unresolved")
    if signature_result["required"] and not signature_result["parse_ok"]:
        strict_failures.append("signature_parse_failed")
    if matched_strings:
        strict_failures.append("denylisted_strings_present")
    if not section_permission_scan_passed:
        strict_failures.append("writable_executable_native_region_detected")
    if not bundle_invariants_passed:
        strict_failures.append("bundle_invariant_violation")
    if not imports_result["passed"]:
        strict_failures.append("imports_policy_failed")
    if not symbols_result["passed"]:
        strict_failures.append("symbols_policy_failed")
    if signature_result["required"] and not signature_result["structure_present"]:
        strict_failures.append("signature_missing")
    if signature_result["required"] and signature_result["structure_present"] and not signature_result["format_valid"]:
        strict_failures.append("signature_format_invalid")
    if signature_result["required"] and signature_result["validation_mode"] == "required_authenticity_missing":
        strict_failures.append("signature_authenticity_missing")
    verifier_error = signature_result.get("verifier_error")
    if verifier_error == "signature_verifier_untrusted":
        strict_failures.append("signature_verifier_untrusted")
    if verifier_error == "signature_verifier_failed":
        strict_failures.append("signature_verifier_failed")
    if verifier_error == "signature_verifier_digest_mismatch":
        strict_failures.append("signature_verifier_digest_mismatch")
    if verifier_error == "signature_authenticity_rejected":
        strict_failures.append("signature_authenticity_rejected")
    if not user_mode_marker_result["passed"]:
        strict_failures.append("user_mode_marker_missing")

    if resolved_target_kind in ("windows_driver", "linux_kernel_module", "android_kernel_module"):
        expected_kernel_compat_profile = {
            "windows_driver": "hvci_profile",
            "linux_kernel_module": "vermagic_profile",
            "android_kernel_module": "gki_kmi_profile",
        }[resolved_target_kind]
        kernel_gate_failed = (
            runtime_lane != "kernel_safe"
            or mutation_profile != "kernel_module"
            or signature_policy != "sign_after_mutate"
            or sign_after_mutate_required is not True
            or allow_jit is not False
            or allow_runtime_executable_pages is not False
            or allow_persistent_plaintext is not False
            or require_fail_closed is not True
            or kernel_compat_profile != expected_kernel_compat_profile
            or (resolved_target_kind == "windows_driver" and hvci_profile is not True)
        )
        if kernel_gate_failed:
            strict_failures.append("kernel_gate_failed")
        if resolved_target_kind == "linux_kernel_module" and vermagic_profile is not True:
            strict_failures.append("vermagic_mismatch")
        if resolved_target_kind == "android_kernel_module" and gki_kmi_profile is not True:
            strict_failures.append("gki_kmi_mismatch")

    if resolved_target_kind == "shell_ephemeral" or artifact_kind == "shell_bundle":
        shell_gate_failed = (
            resolved_target_kind != "shell_ephemeral"
            or backend_kind != "shell_launcher"
            or runtime_lane != "shell_launcher"
            or mutation_profile != "shell_bundle"
            or signature_policy != "required_verifier"
            or allow_jit is not False
            or allow_runtime_executable_pages is not False
            or allow_persistent_plaintext is not False
            or require_fail_closed is not True
            or execution_model != "pipe_stdin_exec"
            or trace_env_scrubbed is not True
            or source_policy != "self_contained_only"
            or key_provider_endpoint_kind not in ("executable_adapter", "fifo", "unix_socket")
            or key_provider_static_file is not False
        )
        if shell_gate_failed:
            strict_failures.append("shell_gate_failed")
        if isinstance(unsafe_shell_features, list) and len(unsafe_shell_features) > 0:
            strict_failures.append("shell_unsafe_feature_present")
        if (
            key_material_embedded is not False
            or plaintext_output is not False
            or no_persistent_plaintext_goal is not True
        ):
            strict_failures.append("shell_plaintext_leak_indicator")

    if resolved_target_kind == "android_dex" or artifact_kind in ("dex", "dex_bundle"):
        loader_metadata_missing = (
            manifest_target_kind != "android_dex"
            or backend_kind != "dex_loader_vm"
            or runtime_lane != "dex_loader_vm"
            or mutation_profile != "dex_bundle"
            or manifest_artifact_kind != "dex_bundle"
            or loader_format_version != 3
            or external_key_required is not True
            or key_provider_protocol != "eippf.external_key.v1"
        )
        if loader_metadata_missing:
            strict_failures.append("loader_metadata_missing")

        loader_gate_unresolved = (
            allow_jit is not False
            or allow_runtime_executable_pages is not False
            or allow_persistent_plaintext is not False
            or require_fail_closed is not True
            or bridge_surface != DEX_REQUIRED_BRIDGE_SURFACE
            or class_loader_policy != DEX_REQUIRED_CLASS_LOADER_POLICY
            or class_loader_exported is not False
            or anti_debug_policy != DEX_REQUIRED_ANTI_DEBUG_POLICY
            or anti_hook_policy != DEX_REQUIRED_ANTI_HOOK_POLICY
            or key_provider_endpoint_kind not in DEX_LOADER_PROVIDER_KIND_ALLOWLIST
            or key_provider_static_file is not False
        )
        if loader_gate_unresolved:
            strict_failures.append("loader_gate_unresolved")

        dex_bundle_embedded_key_marker = any(
            isinstance(violation, dict) and violation.get("kind") == "embedded_key_material"
            for violation in bundle_violations
        )
        dex_plaintext_leak_detected = (
            artifact_kind == "dex"
            or dex_bundle_embedded_key_marker
            or key_material_embedded is not False
            or plaintext_output is not False
            or no_persistent_plaintext_goal is not True
            or b"SECRET_ANCHOR" in data
        )
        if dex_plaintext_leak_detected:
            strict_failures.append("dex_plaintext_leak_detected")

    if resolved_target_kind == "ios_appstore" or manifest_target_kind == "ios_appstore":
        ios_compliance_profile = "app_store_safe"
        private_api_hits = find_ios_private_api_hits(imports_result)
        rwx_segment_detected = any(
            isinstance(violation, dict) and violation.get("kind") == "writable_executable_segment"
            for violation in permission_violations
        )
        signature_details = signature_result.get("details")
        macho_code_signature_present = (
            isinstance(signature_details, dict)
            and bool(signature_details.get("macho_codesig_command", False))
        )
        ios_gate_failed = (
            artifact_kind != "macho"
            or backend_kind != "ios_safe_aot"
            or runtime_lane != "ios_safe"
            or mutation_profile != "ios_macho"
            or signature_policy != "required_verifier"
            or allow_jit is not False
            or allow_runtime_executable_pages is not False
            or allow_persistent_plaintext is not False
            or require_fail_closed is not True
        )
        if ios_gate_failed:
            strict_failures.append("ios_gate_failed")
        if private_api_hits:
            strict_failures.append("private_api_detected")
        if not macho_code_signature_present:
            strict_failures.append("macho_code_signature_missing")
        if rwx_segment_detected:
            strict_failures.append("rwx_segment_detected")
        code_signature_state = {
            "present": macho_code_signature_present,
            "format_valid": bool(signature_result["format_valid"]),
            "validation_mode": signature_result["validation_mode"],
        }
        exec_permission_summary = {
            "rwx_detected": rwx_segment_detected,
            "violation_kinds": [
                violation.get("kind")
                for violation in permission_violations
                if isinstance(violation, dict) and isinstance(violation.get("kind"), str)
            ],
        }

    return {
        "schema_version": 1,
        "target_kind": resolved_target_kind,
        "backend_kind": backend_kind,
        "runtime_lane": runtime_lane,
        "mutation_profile": mutation_profile,
        "signature_policy": signature_policy,
        "sign_after_mutate_required": sign_after_mutate_required,
        "loader_format_version": loader_format_version,
        "external_key_required": external_key_required,
        "key_provider_protocol": key_provider_protocol,
        "allow_jit": allow_jit,
        "allow_runtime_executable_pages": allow_runtime_executable_pages,
        "allow_persistent_plaintext": allow_persistent_plaintext,
        "require_fail_closed": require_fail_closed,
        "bridge_surface": bridge_surface,
        "class_loader_policy": class_loader_policy,
        "class_loader_exported": class_loader_exported,
        "anti_debug_policy": anti_debug_policy,
        "anti_hook_policy": anti_hook_policy,
        "kernel_compat_profile": kernel_compat_profile,
        "hvci_profile": hvci_profile,
        "vermagic_profile": vermagic_profile,
        "gki_kmi_profile": gki_kmi_profile,
        "execution_model": execution_model,
        "trace_env_scrubbed": trace_env_scrubbed,
        "source_policy": source_policy,
        "unsafe_shell_features": (
            unsafe_shell_features if isinstance(unsafe_shell_features, list) else []
        ),
        "key_provider_endpoint_kind": key_provider_endpoint_kind,
        "key_provider_static_file": key_provider_static_file,
        "key_material_embedded": key_material_embedded,
        "plaintext_output": plaintext_output,
        "no_persistent_plaintext_goal": no_persistent_plaintext_goal,
        "artifact_kind": artifact_kind,
        "file_size_bytes": len(data),
        "denylist_loaded": denylist_loaded,
        "string_anchor_scan_passed": len(matched_strings) == 0,
        "suspicious_string_hits": len(matched_strings),
        "matched_strings": matched_strings,
        "imports_minimized": bool(imports_result["passed"]),
        "imports_summary": {
            "parsed": bool(imports_result["parsed"]),
            "library_count": len(imports_result["libraries"]),
            "symbol_count": len(imports_result["symbols"]),
            "libraries": imports_result["libraries"],
            "symbols": imports_result["symbols"][:64],
            "violations": imports_result["violations"],
        },
        "symbols_sanitized": bool(symbols_result["passed"]),
        "symbol_summary": {
            "parsed": bool(symbols_result["parsed"]),
            "symbol_count": len(symbols_result["names"]),
            "symbols": symbols_result["names"][:64],
            "violations": symbols_result["violations"],
        },
        "section_permission_scan_passed": section_permission_scan_passed,
        "permission_violations": permission_violations,
        "bundle_invariants_passed": bundle_invariants_passed,
        "bundle_violations": bundle_violations,
        "signature_state_passed": bool(signature_result["passed"]),
        "signature_details": signature_result,
        "user_mode_marker_check_passed": bool(user_mode_marker_result["passed"]),
        "user_mode_marker": user_mode_marker_result,
        "ios_compliance_profile": ios_compliance_profile,
        "private_api_hits": private_api_hits,
        "code_signature_state": code_signature_state,
        "exec_permission_summary": exec_permission_summary,
        "strict_failures": strict_failures,
    }


def build_test_pe(
    section_characteristics: int,
    payload: bytes = b"",
    import_dll: str | None = None,
    import_symbol: str | None = None,
    with_signature: bool = False,
) -> bytes:
    pe_offset = 0x80
    optional_header_size = 0xE0
    section_count = 2 if import_dll and import_symbol else 1
    section_table_offset = pe_offset + 4 + 20 + optional_header_size
    text_raw_offset = section_table_offset + (section_count * 40)
    text_raw_size = max(len(payload), 1)
    idata_raw_offset = text_raw_offset + text_raw_size
    idata_raw_size = 0x80 if section_count == 2 else 0
    cert_offset = idata_raw_offset + idata_raw_size
    cert_size = 8 if with_signature else 0

    data = bytearray(cert_offset + cert_size)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, byteorder="little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    data[coff : coff + 2] = (0x014C).to_bytes(2, byteorder="little")
    data[coff + 2 : coff + 4] = section_count.to_bytes(2, byteorder="little")
    data[coff + 16 : coff + 18] = optional_header_size.to_bytes(2, byteorder="little")

    optional = pe_offset + 24
    data[optional : optional + 2] = (0x10B).to_bytes(2, byteorder="little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, byteorder="little")
    data[optional + 96 : optional + 104] = b"\0" * 8

    text_section = section_table_offset
    data[text_section : text_section + 5] = b".text"
    data[text_section + 8 : text_section + 12] = text_raw_size.to_bytes(4, byteorder="little")
    data[text_section + 12 : text_section + 16] = (0x1000).to_bytes(4, byteorder="little")
    data[text_section + 16 : text_section + 20] = text_raw_size.to_bytes(4, byteorder="little")
    data[text_section + 20 : text_section + 24] = text_raw_offset.to_bytes(4, byteorder="little")
    data[text_section + 36 : text_section + 40] = section_characteristics.to_bytes(4, byteorder="little")
    data[text_raw_offset : text_raw_offset + len(payload)] = payload

    if section_count == 2:
        idata_section = text_section + 40
        idata_va = 0x2000
        data[idata_section : idata_section + 6] = b".idata"
        data[idata_section + 8 : idata_section + 12] = idata_raw_size.to_bytes(4, byteorder="little")
        data[idata_section + 12 : idata_section + 16] = idata_va.to_bytes(4, byteorder="little")
        data[idata_section + 16 : idata_section + 20] = idata_raw_size.to_bytes(4, byteorder="little")
        data[idata_section + 20 : idata_section + 24] = idata_raw_offset.to_bytes(4, byteorder="little")
        data[idata_section + 36 : idata_section + 40] = (0x40000040).to_bytes(4, byteorder="little")

        import_descriptor_rva = idata_va
        import_descriptor_off = idata_raw_offset
        int_rva = idata_va + 0x28
        iat_rva = idata_va + 0x30
        hint_name_rva = idata_va + 0x38
        dll_name_bytes = import_dll.encode("ascii") + b"\0"
        symbol_name_bytes = import_symbol.encode("ascii") + b"\0"
        dll_name_off = idata_raw_offset + 0x38 + 2 + len(symbol_name_bytes)
        dll_name_rva = idata_va + (dll_name_off - idata_raw_offset)

        data[optional + 104 : optional + 108] = import_descriptor_rva.to_bytes(4, byteorder="little")
        data[optional + 108 : optional + 112] = (40).to_bytes(4, byteorder="little")

        data[import_descriptor_off : import_descriptor_off + 4] = int_rva.to_bytes(4, byteorder="little")
        data[import_descriptor_off + 12 : import_descriptor_off + 16] = dll_name_rva.to_bytes(4, byteorder="little")
        data[import_descriptor_off + 16 : import_descriptor_off + 20] = iat_rva.to_bytes(4, byteorder="little")
        data[idata_raw_offset + 0x28 : idata_raw_offset + 0x2C] = hint_name_rva.to_bytes(4, byteorder="little")
        data[idata_raw_offset + 0x30 : idata_raw_offset + 0x34] = hint_name_rva.to_bytes(4, byteorder="little")
        data[idata_raw_offset + 0x38 : idata_raw_offset + 0x3A] = (0).to_bytes(2, byteorder="little")
        data[idata_raw_offset + 0x3A : idata_raw_offset + 0x3A + len(symbol_name_bytes)] = symbol_name_bytes
        data[dll_name_off : dll_name_off + len(dll_name_bytes)] = dll_name_bytes

    if with_signature:
        data[optional + 128 : optional + 132] = cert_offset.to_bytes(4, byteorder="little")
        data[optional + 132 : optional + 136] = cert_size.to_bytes(4, byteorder="little")
        data[cert_offset : cert_offset + 4] = (8).to_bytes(4, byteorder="little")
        data[cert_offset + 4 : cert_offset + 6] = (0x0200).to_bytes(2, byteorder="little")
        data[cert_offset + 6 : cert_offset + 8] = (0x0002).to_bytes(2, byteorder="little")

    return bytes(data)


def run_self_test() -> int:
    default_manifest_meta = load_manifest_metadata(None)
    assert detect_artifact_kind(b"MZ\x00\x00") == "pe"
    assert detect_artifact_kind(b"\x7fELF\x02\x01") == "elf"
    assert detect_artifact_kind(DEX_BUNDLE_MAGIC + b"\x01") == "dex_bundle"
    assert "tutorial_anchor" in extract_strings(b"\x00tutorial_anchor\x00")

    good_pe = build_test_pe(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | 0x20, b"clean")
    good_report = audit_artifact(
        good_pe,
        Path("good.bin"),
        ["tutorial_anchor"],
        True,
        None,
        default_manifest_meta,
        None,
        False,
    )
    assert good_report["artifact_kind"] == "pe"
    assert good_report["section_permission_scan_passed"] is True
    assert good_report["imports_minimized"] is True
    assert good_report["strict_failures"] == []

    suspicious_import_pe = build_test_pe(
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | 0x20,
        b"clean",
        import_dll="dbghelp.dll",
        import_symbol="SymInitialize",
    )
    suspicious_import_report = audit_artifact(
        suspicious_import_pe,
        Path("sample.exe"),
        ["tutorial_anchor"],
        True,
        None,
        default_manifest_meta,
        None,
        False,
    )
    assert suspicious_import_report["imports_minimized"] is False
    assert "imports_policy_failed" in suspicious_import_report["strict_failures"]

    unsigned_driver = build_test_pe(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | 0x20, b"clean")
    unsigned_driver_report = audit_artifact(
        unsigned_driver,
        Path("driver.sys"),
        ["tutorial_anchor"],
        True,
        None,
        default_manifest_meta,
        None,
        False,
    )
    assert unsigned_driver_report["signature_state_passed"] is False
    assert "signature_missing" in unsigned_driver_report["strict_failures"]

    bad_pe = build_test_pe(
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | 0x20,
        b"tutorial_anchor",
    )
    bad_report = audit_artifact(
        bad_pe,
        Path("bad.bin"),
        ["tutorial_anchor"],
        True,
        None,
        default_manifest_meta,
        None,
        False,
    )
    assert bad_report["suspicious_string_hits"] == 1
    assert bad_report["section_permission_scan_passed"] is False
    assert "denylisted_strings_present" in bad_report["strict_failures"]
    assert "writable_executable_native_region_detected" in bad_report["strict_failures"]

    print(json.dumps({"self_test": "ok", "artifact_kind": "self"}, sort_keys=True))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit protected artifacts for lexical anchors.")
    parser.add_argument("--input", type=Path, help="Artifact to audit.")
    parser.add_argument("--denylist", type=Path, help="Optional lexical anchor denylist.")
    parser.add_argument("--manifest", type=Path, help="Optional ProtectionManifestV2 JSON for policy hints.")
    parser.add_argument("--target-kind", type=str, help="Optional explicit protection target kind override.")
    parser.add_argument(
        "--signature-verifier",
        type=Path,
        help="Optional external signature authenticity verifier executable.",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    parser.add_argument("--strict", action="store_true", help="Fail if strict audit checks fail.")
    parser.add_argument("--self-test", action="store_true", help="Run the built-in self test.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()

    if args.input is None:
        print("artifact_audit.py: --input is required unless --self-test is used", file=sys.stderr)
        return 2

    if not args.input.exists():
        print(f"artifact_audit.py: input does not exist: {args.input}", file=sys.stderr)
        return 2

    data = args.input.read_bytes()
    denylist_path = args.denylist or Path(__file__).with_name("lexical_anchor_denylist.txt")
    denylist, denylist_loaded = load_denylist(denylist_path)
    manifest_meta = load_manifest_metadata(args.manifest)
    report = audit_artifact(
        data,
        args.input,
        denylist,
        denylist_loaded,
        args.target_kind,
        manifest_meta,
        args.signature_verifier,
        args.strict,
    )

    output_json = json.dumps(report, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.write_text(output_json + "\n", encoding="utf-8")
    else:
        print(output_json)

    if args.strict and len(report["strict_failures"]) > 0:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
