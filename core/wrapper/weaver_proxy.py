#!/usr/bin/env python3
"""Universal polyglot compiler launcher with LLVM bitcode weaving bridge.

Pipeline (compile step):
1) Frontend compile to LLVM bitcode (.bc)
2) IR weaving tool transforms input .bc -> output .bc
3) Lower weaved bitcode to requested output type (object, .bc, or .ll)

For non-compile invocations (linking, archiving, preprocess-only, assembly-only,
PCH generation, etc.) the proxy transparently passes all arguments to the
original compiler process.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence


_C_SOURCES = {".c", ".m"}
_CXX_SOURCES = {".cc", ".cp", ".cxx", ".cpp", ".c++", ".cppm", ".cxxm", ".ixx", ".mm"}
_RUST_SOURCES = {".rs"}
_ASM_SOURCES = {".s", ".S", ".asm"}
_PCH_EXTENSIONS = {".pch", ".gch"}
_MSVC_LINKER_NAMES = {"link", "link.exe"}


class EmitKind(Enum):
    OBJECT = "object"
    LLVM_BC = "llvm-bc"
    LLVM_LL = "llvm-ll"
    LINK = "link"
    PREPROCESS = "preprocess"
    ASSEMBLY = "assembly"


@dataclass(frozen=True)
class SourceInput:
    index: int
    path: Path
    ext: str


def _basename_lower(path: str) -> str:
    return Path(path).name.lower()


def _run(cmd: Sequence[str]) -> int:
    proc = subprocess.run(list(cmd), check=False)
    return int(proc.returncode)


def _strip_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    return token


def _normalize_path(token: str, base_dir: Optional[Path] = None) -> Path:
    value = Path(_strip_quotes(token))
    if base_dir is not None and not value.is_absolute():
        value = (base_dir / value)
    return value.resolve()


def _is_msvc_like(compiler: str) -> bool:
    return _basename_lower(compiler) in {"cl", "cl.exe", "clang-cl", "clang-cl.exe"}


def _is_msvc_linker(compiler: str) -> bool:
    return _basename_lower(compiler) in _MSVC_LINKER_NAMES


def _is_rustc(compiler: str) -> bool:
    return _basename_lower(compiler) in {"rustc", "rustc.exe"}


def _is_compile_db_wrapper(name: str) -> bool:
    return name in {"ccache", "sccache", "distcc"}


def _is_compile_invocation(args: Sequence[str], is_msvc: bool, is_rust: bool) -> bool:
    if is_rust:
        return True
    if is_msvc:
        lowered = [a.lower() for a in args]
        return any(flag in lowered for flag in {"/c", "/e", "/ep", "/p"})
    return any(flag in args for flag in {"-c", "-S", "-E", "-emit-llvm"})


def _detect_emit_kind(args: Sequence[str], is_msvc: bool, is_rust: bool) -> EmitKind:
    if is_rust:
        emit_entries: List[str] = []
        i = 0
        while i < len(args):
            token = args[i]
            if token == "--emit" and i + 1 < len(args):
                emit_entries.extend(part.strip().lower() for part in args[i + 1].split(","))
                i += 2
                continue
            if token.startswith("--emit="):
                emit_entries.extend(part.strip().lower() for part in token.split("=", 1)[1].split(","))
            i += 1
        if not emit_entries:
            return EmitKind.LINK
        if "link" in emit_entries:
            return EmitKind.LINK
        if "obj" in emit_entries:
            return EmitKind.OBJECT
        if "llvm-bc" in emit_entries:
            return EmitKind.LLVM_BC
        if "llvm-ir" in emit_entries:
            return EmitKind.LLVM_LL
        if "asm" in emit_entries:
            return EmitKind.ASSEMBLY
        return EmitKind.LINK

    if is_msvc:
        lowered = [a.lower() for a in args]
        if any(flag in lowered for flag in {"/e", "/ep", "/p"}):
            return EmitKind.PREPROCESS
        return EmitKind.OBJECT

    has_emit_llvm = "-emit-llvm" in args
    has_s = "-S" in args
    has_e = "-E" in args
    if has_e:
        return EmitKind.PREPROCESS
    if has_emit_llvm and has_s:
        return EmitKind.LLVM_LL
    if has_emit_llvm:
        return EmitKind.LLVM_BC
    if has_s:
        return EmitKind.ASSEMBLY
    return EmitKind.OBJECT


def _detect_sources(args: Sequence[str], is_msvc: bool) -> List[SourceInput]:
    sources: List[SourceInput] = []
    skip_next = False
    for index, token in enumerate(args):
        if skip_next:
            skip_next = False
            continue

        lower = token.lower()
        if lower in {"-o", "-x", "-mf", "-mt", "-mq", "/fo", "/fe", "/fi", "/fp", "/tc", "/tp"}:
            skip_next = True
            continue
        if lower in {"-include", "-include-pch", "-isystem", "-iquote", "-isysroot", "-target", "--target", "--sysroot"}:
            skip_next = True
            continue

        if token.startswith("-"):
            continue
        if is_msvc and token.startswith("/"):
            continue

        path = Path(_strip_quotes(token))
        ext = path.suffix
        if ext in (_C_SOURCES | _CXX_SOURCES | _RUST_SOURCES | _ASM_SOURCES | _PCH_EXTENSIONS):
            sources.append(SourceInput(index=index, path=path, ext=ext))
    return sources


def _extract_output_path(args: Sequence[str], is_msvc: bool) -> Optional[Path]:
    i = 0
    while i < len(args):
        token = args[i]
        lower = token.lower()
        if lower == "-o" and i + 1 < len(args):
            return Path(_strip_quotes(args[i + 1]))
        # Only accept the canonical lowercase combined form: -o<path>.
        # Do not treat optimization flags like -O2 as output path.
        if token.startswith("-o") and len(token) > 2:
            return Path(_strip_quotes(token[2:]))
        if is_msvc:
            if lower == "/fo" and i + 1 < len(args):
                return Path(_strip_quotes(args[i + 1]))
            if lower.startswith("/fo") and len(token) > 3:
                return Path(_strip_quotes(token[3:]))
        i += 1
    return None


def _discover_tool(explicit: Optional[str], env_key: str, fallback: str) -> Optional[str]:
    if explicit:
        return explicit
    from_env = os.environ.get(env_key, "").strip()
    if from_env:
        return from_env
    return shutil.which(fallback)


def _discover_optional_path(explicit: Optional[str], env_key: str) -> Optional[str]:
    if explicit:
        return explicit
    from_env = os.environ.get(env_key, "").strip()
    if from_env:
        return from_env
    return None


def _find_compile_commands(explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        candidate = Path(explicit)
        if candidate.is_file():
            return candidate.resolve()
        return None

    from_env = os.environ.get("EIPPF_COMPILE_COMMANDS", "").strip()
    if from_env:
        candidate = Path(from_env)
        if candidate.is_file():
            return candidate.resolve()

    current = Path.cwd().resolve()
    for directory in [current, *current.parents]:
        candidate = directory / "compile_commands.json"
        if candidate.is_file():
            return candidate
    return None


def _load_compile_database(path: Path) -> Dict[Path, List[str]]:
    mapping: Dict[Path, List[str]] = {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return mapping

    if not isinstance(raw, list):
        return mapping

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        file_value = entry.get("file")
        if not isinstance(file_value, str) or not file_value:
            continue
        directory_value = entry.get("directory")
        directory = Path(directory_value) if isinstance(directory_value, str) and directory_value else path.parent

        source_path = _normalize_path(file_value, directory)
        arguments: List[str] = []

        if isinstance(entry.get("arguments"), list):
            arguments = [str(item) for item in entry["arguments"]]
        elif isinstance(entry.get("command"), str):
            try:
                arguments = shlex.split(entry["command"], posix=(os.name != "nt"))
            except ValueError:
                arguments = []

        if arguments:
            mapping[source_path] = arguments
    return mapping


def _sanitize_compile_db_args(arguments: Sequence[str], source_path: Path) -> List[str]:
    if not arguments:
        return []

    tokens = list(arguments)
    while tokens:
        name = _basename_lower(tokens[0])
        if _is_compile_db_wrapper(name):
            tokens = tokens[1:]
            continue
        break

    if tokens:
        tokens = tokens[1:]

    source_abs = source_path.resolve()
    source_name = source_path.name

    sanitized: List[str] = []
    skip_next = False
    i = 0
    while i < len(tokens):
        token = tokens[i]
        lower = token.lower()

        if skip_next:
            skip_next = False
            i += 1
            continue

        if lower in {"-c", "-o", "-x", "-mf", "-mt", "-mq", "/fo", "/fe", "/fi", "/fp"}:
            if lower in {"-o", "-x", "-mf", "-mt", "-mq", "/fo", "/fe", "/fi", "/fp"}:
                skip_next = True
            i += 1
            continue

        if lower in {"-target", "--target", "-isystem", "-iquote", "-isysroot", "--sysroot", "-include", "-include-pch"}:
            sanitized.append(token)
            if i + 1 < len(tokens):
                sanitized.append(tokens[i + 1])
                skip_next = True
            i += 1
            continue

        normalized = _normalize_path(token)
        if normalized == source_abs or Path(token).name == source_name:
            i += 1
            continue

        if token.lower() == "/c":
            i += 1
            continue

        sanitized.append(token)
        i += 1

    return sanitized


def _lookup_compile_db_args(compile_db: Mapping[Path, List[str]], source_path: Path) -> List[str]:
    if not compile_db:
        return []
    source_abs = source_path.resolve()
    entry = compile_db.get(source_abs)
    if entry:
        return _sanitize_compile_db_args(entry, source_path)
    for key, value in compile_db.items():
        if key.name == source_path.name:
            return _sanitize_compile_db_args(value, source_path)
    return []


def _merge_compile_args(cli_args: Sequence[str], compile_db_args: Sequence[str]) -> List[str]:
    if not compile_db_args:
        return list(cli_args)
    # compile_commands provides baseline flags; explicit CLI args are appended so
    # trailing option precedence remains with the actual invocation.
    return [*compile_db_args, *cli_args]


def _is_source_token(token: str, source_path: Path) -> bool:
    value = Path(_strip_quotes(token))
    if value == source_path:
        return True
    if value.name == source_path.name:
        return True
    try:
        return value.resolve() == source_path.resolve()
    except OSError:
        return False


def _collect_forward_args_for_cc(args: Sequence[str], source_path: Path, is_msvc: bool) -> List[str]:
    result: List[str] = []
    skip_next = False
    i = 0

    while i < len(args):
        token = args[i]
        lower = token.lower()

        if skip_next:
            skip_next = False
            i += 1
            continue

        if _is_source_token(token, source_path):
            i += 1
            continue

        if lower in {"-c", "-o"}:
            if lower == "-o":
                skip_next = True
            i += 1
            continue
        if lower.startswith("-o") and len(token) > 2:
            i += 1
            continue

        if lower in {"-mf", "-mt", "-mq", "-x"}:
            skip_next = True
            i += 1
            continue

        if is_msvc:
            if lower == "/c":
                i += 1
                continue
            if lower in {"/fo", "/fe", "/fi", "/fp"}:
                skip_next = True
                i += 1
                continue
            if lower.startswith("/fo") or lower.startswith("/fe"):
                i += 1
                continue
            if lower.startswith("/link"):
                break

        result.append(token)
        i += 1

    return result


def _collect_forward_args_for_rust(args: Sequence[str], source_path: Path) -> List[str]:
    result: List[str] = []
    skip_next = False
    i = 0

    while i < len(args):
        token = args[i]
        if skip_next:
            skip_next = False
            i += 1
            continue

        if _is_source_token(token, source_path):
            i += 1
            continue

        lower = token.lower()
        if lower in {"-o", "--emit"}:
            skip_next = True
            i += 1
            continue
        if lower.startswith("--emit="):
            i += 1
            continue

        result.append(token)
        i += 1

    return result


def _is_codegen_arg(token: str) -> bool:
    if token in {"-fpic", "-fPIC", "-fpie", "-fPIE", "-g", "-g0", "-g1", "-g2", "-g3", "-ffast-math"}:
        return True
    if token.startswith("-o"):
        return False
    return token.startswith(("-O", "-g", "-m", "-f", "-Wl,", "-rtlib=", "-stdlib=", "-unwindlib="))


def _collect_codegen_args(args: Sequence[str], source_path: Path, is_msvc: bool) -> List[str]:
    result: List[str] = []
    skip_next = False
    i = 0

    while i < len(args):
        token = args[i]
        lower = token.lower()

        if skip_next:
            skip_next = False
            i += 1
            continue

        if _is_source_token(token, source_path):
            i += 1
            continue

        if lower in {"-target", "--target"} and i + 1 < len(args):
            result.extend([token, args[i + 1]])
            skip_next = True
            i += 1
            continue

        if token.startswith("--target=") or token.startswith("-target="):
            result.append(token)
            i += 1
            continue

        if lower in {"-o", "-x", "-mf", "-mt", "-mq", "-include", "-include-pch", "-isystem", "-iquote", "-isysroot", "--sysroot"}:
            skip_next = True
            i += 1
            continue

        if token in {"-c", "-S", "-E", "-emit-llvm"} or lower in {"-mmd", "-md"}:
            i += 1
            continue

        if lower.startswith("-o") and len(token) > 2:
            i += 1
            continue

        if lower.startswith("-mf") and len(token) > 3:
            i += 1
            continue

        if is_msvc:
            if lower == "/c":
                i += 1
                continue
            if lower in {"/fo", "/fe", "/fi", "/fp", "/tc", "/tp"}:
                skip_next = True
                i += 1
                continue
            if lower.startswith("/fo") or lower.startswith("/fe"):
                i += 1
                continue
            if lower in {"/gl"} or lower.startswith("/o") or lower.startswith("/arch:"):
                result.append(token)
                i += 1
                continue
            i += 1
            continue

        if token in {"-Winvalid-pch", "-fsyntax-only"}:
            i += 1
            continue

        if _is_codegen_arg(token):
            result.append(token)
            i += 1
            continue

        i += 1

    return result


def _detect_target_flags(args: Sequence[str]) -> List[str]:
    result: List[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in {"-target", "--target"} and i + 1 < len(args):
            result.extend([token, args[i + 1]])
            i += 2
            continue
        if token.startswith("--target="):
            result.append(token)
        i += 1
    return result


def _extract_target_triple(args: Sequence[str]) -> Optional[str]:
    i = 0
    while i < len(args):
        token = args[i]
        if token in {"-target", "--target"} and i + 1 < len(args):
            return args[i + 1]
        if token.startswith("--target="):
            return token.split("=", 1)[1]
        if token.startswith("-target="):
            return token.split("=", 1)[1]
        i += 1
    return None


def _is_pch_generation(args: Sequence[str], source: SourceInput) -> bool:
    if source.ext in _PCH_EXTENSIONS:
        return True

    i = 0
    while i < len(args):
        token = args[i]
        lower = token.lower()
        if token == "-emit-pch":
            return True
        if token == "-x" and i + 1 < len(args):
            lang = args[i + 1].lower()
            if lang in {"c-header", "c++-header", "objective-c-header", "objective-c++-header"}:
                return True
            i += 2
            continue
        if lower.startswith("/yc"):
            return True
        i += 1
    return False


def _is_pch_consumption(args: Sequence[str]) -> bool:
    i = 0
    while i < len(args):
        token = args[i]
        lower = token.lower()
        if token in {"-include-pch", "-include"} and i + 1 < len(args):
            include_target = args[i + 1]
            if Path(_strip_quotes(include_target)).suffix in _PCH_EXTENSIONS:
                return True
            i += 2
            continue
        if lower.startswith("/yu"):
            return True
        if Path(_strip_quotes(token)).suffix in _PCH_EXTENSIONS:
            return True
        i += 1
    return False


def _frontend_for_cc(original_compiler: str, source_ext: str) -> str:
    name = _basename_lower(original_compiler)
    if name in {"clang", "clang.exe", "clang++", "clang++.exe"}:
        return original_compiler
    if name in {"cl", "cl.exe", "clang-cl", "clang-cl.exe"}:
        return os.environ.get("EIPPF_CLANGCL_BIN", "clang-cl")
    if source_ext in _CXX_SOURCES:
        return os.environ.get("EIPPF_CLANGXX_BIN", "clang++")
    return os.environ.get("EIPPF_CLANG_BIN", "clang")


def _build_cc_to_bc_cmd(
    frontend: str,
    source: Path,
    output_bc: Path,
    forwarded_args: Sequence[str],
    is_msvc: bool,
) -> List[str]:
    if _is_msvc_like(frontend) or is_msvc:
        return [frontend, "/c", str(source), f"/Fo{output_bc}", "/clang:-emit-llvm", *forwarded_args]
    return [frontend, "-emit-llvm", "-c", str(source), "-o", str(output_bc), *forwarded_args]


def _build_rust_to_bc_cmd(rustc_bin: str, source: Path, output_bc: Path, forwarded: Sequence[str]) -> List[str]:
    return [rustc_bin, str(source), "--emit=llvm-bc", "-o", str(output_bc), *forwarded]


def _build_ir_weaver_cmd(ir_weaver_bin: str, input_bc: Path, output_bc: Path, extra_args: Sequence[str]) -> List[str]:
    return [ir_weaver_bin, "--input", str(input_bc), "--output", str(output_bc), *extra_args]


def _build_lower_to_object_cmd(clang_bin: str, input_bc: Path, output_obj: Path, codegen_args: Sequence[str]) -> List[str]:
    return [clang_bin, "-c", str(input_bc), "-o", str(output_obj), *codegen_args]


def _build_lower_to_ll_cmd(clang_bin: str, input_bc: Path, output_ll: Path, codegen_args: Sequence[str]) -> List[str]:
    return [clang_bin, "-S", "-emit-llvm", str(input_bc), "-o", str(output_ll), *codegen_args]


def _default_output_for(source: Path, kind: EmitKind, is_msvc: bool) -> Path:
    stem = Path(source.name).stem
    if kind == EmitKind.LLVM_LL:
        return Path(f"{stem}.ll")
    if kind == EmitKind.LLVM_BC:
        return Path(f"{stem}.bc")
    if kind == EmitKind.ASSEMBLY:
        return Path(f"{stem}.s")
    if is_msvc:
        return Path(f"{stem}.obj")
    return Path(f"{stem}.o")


def _ensure_parent(path: Path) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def _contains_path_token(args: Sequence[str], candidate: str) -> bool:
    raw_candidate = _strip_quotes(candidate)
    candidate_path = Path(raw_candidate)
    candidate_name = candidate_path.name
    candidate_resolved: Optional[Path] = None
    try:
        candidate_resolved = candidate_path.resolve()
    except OSError:
        candidate_resolved = None

    for token in args:
        value = _strip_quotes(token)
        if value == raw_candidate:
            return True
        token_path = Path(value)
        if token_path.name == candidate_name:
            return True
        if candidate_resolved is not None:
            try:
                if token_path.resolve() == candidate_resolved:
                    return True
            except OSError:
                pass
    return False


def _append_unique_flag(args: List[str], flag: str) -> None:
    if flag not in args:
        args.append(flag)


def _append_unique_flag_ci(args: List[str], flag: str) -> None:
    lowered = flag.lower()
    for existing in args:
        if existing.lower() == lowered:
            return
    args.append(flag)


def _has_linkable_input(args: Sequence[str], is_msvc: bool) -> bool:
    skip_next = False
    linkable_suffixes = {
        ".o",
        ".obj",
        ".a",
        ".so",
        ".dylib",
        ".lib",
        ".bc",
        ".ll",
        ".lo",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
    }

    i = 0
    while i < len(args):
        token = args[i]
        lower = token.lower()
        if skip_next:
            skip_next = False
            i += 1
            continue

        if lower in {"-o", "/out"}:
            skip_next = True
            i += 1
            continue
        if lower.startswith("/out:"):
            i += 1
            continue

        if token.startswith("-"):
            i += 1
            continue
        if is_msvc and token.startswith("/") and not lower.startswith("/link"):
            i += 1
            continue

        if Path(_strip_quotes(token)).suffix.lower() in linkable_suffixes:
            return True
        i += 1

    return False


def _is_link_phase_invocation(compiler: str, args: Sequence[str], is_msvc: bool, is_rust: bool) -> bool:
    if is_rust:
        return False
    if _is_compile_invocation(args, is_msvc=is_msvc, is_rust=is_rust):
        return False

    lowered = [token.lower() for token in args]
    if is_msvc or _is_msvc_linker(compiler):
        return "/link" in lowered or _is_msvc_linker(compiler) or _has_linkable_input(args, is_msvc=True)

    if any(token in args for token in {"-E", "-S"}):
        return False
    return _has_linkable_input(args, is_msvc=False)


def _inject_vm_runtime_for_gnu_link(args: Sequence[str], vm_runtime_lib: str) -> List[str]:
    injected = list(args)
    if not _contains_path_token(injected, vm_runtime_lib):
        injected.append(vm_runtime_lib)

    _append_unique_flag(injected, "-fvisibility=hidden")
    _append_unique_flag(injected, "-fvisibility-inlines-hidden")
    if "-Wl,--strip-all" not in injected and "-Wl,-s" not in injected:
        injected.append("-Wl,--strip-all")

    if sys.platform == "darwin":
        _append_unique_flag(injected, "-lc++")
    else:
        _append_unique_flag(injected, "-lstdc++")

    _append_unique_flag(injected, "-pthread")
    _append_unique_flag(injected, "-lm")
    if sys.platform.startswith("linux"):
        _append_unique_flag(injected, "-ldl")
    return injected


def _inject_vm_runtime_for_msvc_link(compiler: str, args: Sequence[str], vm_runtime_lib: str) -> List[str]:
    injected = list(args)

    lower_name = _basename_lower(compiler)
    if lower_name in _MSVC_LINKER_NAMES:
        if not _contains_path_token(injected, vm_runtime_lib):
            injected.append(vm_runtime_lib)
        _append_unique_flag_ci(injected, "/DEBUG:NONE")
        _append_unique_flag_ci(injected, "/OPT:REF")
        _append_unique_flag_ci(injected, "/OPT:ICF")
        return injected

    lowered = [token.lower() for token in injected]
    if "/link" in lowered:
        if not _contains_path_token(injected, vm_runtime_lib):
            injected.append(vm_runtime_lib)
    else:
        injected.extend(["/link", vm_runtime_lib])
    _append_unique_flag_ci(injected, "/DEBUG:NONE")
    _append_unique_flag_ci(injected, "/OPT:REF")
    _append_unique_flag_ci(injected, "/OPT:ICF")
    return injected


def _inject_link_runtime_args(compiler: str, args: Sequence[str], is_msvc: bool, vm_runtime_lib: Optional[str]) -> List[str]:
    if not vm_runtime_lib:
        return list(args)
    if is_msvc or _is_msvc_linker(compiler):
        return _inject_vm_runtime_for_msvc_link(compiler, args, vm_runtime_lib)
    return _inject_vm_runtime_for_gnu_link(args, vm_runtime_lib)


def _env_enabled(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    return lowered not in {"0", "false", "off", "no"}


def _sanitize_identifier(value: str) -> str:
    sanitized = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in value)
    if not sanitized:
        return "crate"
    if sanitized[0].isdigit():
        sanitized = f"_{sanitized}"
    return sanitized


def _extract_rust_crate_name(args: Sequence[str], source_path: Path) -> str:
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--crate-name" and i + 1 < len(args):
            return _sanitize_identifier(args[i + 1])
        if token.startswith("--crate-name="):
            return _sanitize_identifier(token.split("=", 1)[1])
        i += 1
    return _sanitize_identifier(source_path.stem)


def _has_rust_link_arg(args: Sequence[str], value: str) -> bool:
    needle = value.strip()
    if not needle:
        return False
    i = 0
    while i < len(args):
        token = args[i]
        if token == "-C" and i + 1 < len(args):
            payload = args[i + 1]
            if payload.startswith("link-arg="):
                if payload.split("=", 1)[1] == needle:
                    return True
            elif payload.startswith("link-args="):
                for part in payload.split("=", 1)[1].split():
                    if part == needle:
                        return True
            i += 2
            continue
        if token.startswith("-Clink-arg="):
            if token.split("=", 1)[1] == needle:
                return True
        elif token.startswith("-Clink-args="):
            for part in token.split("=", 1)[1].split():
                if part == needle:
                    return True
        i += 1
    return False


def _inject_vm_runtime_for_rust_link(args: Sequence[str], vm_runtime_lib: Optional[str]) -> List[str]:
    injected = list(args)
    if not vm_runtime_lib:
        return injected

    link_args: List[str] = [vm_runtime_lib]
    if sys.platform == "darwin":
        link_args.append("-lc++")
    else:
        link_args.append("-lstdc++")
    link_args.extend(["-pthread", "-lm"])
    if sys.platform.startswith("linux"):
        link_args.append("-ldl")

    for link_arg in link_args:
        if _has_rust_link_arg(injected, link_arg):
            continue
        injected.extend(["-C", f"link-arg={link_arg}"])
    return injected


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Polyglot LLVM bitcode weaving compiler launcher")
    parser.add_argument("--ir-weaver-bin", default=None, help="Path to IR weaving binary.")
    parser.add_argument("--vm-runtime-lib", default=None, help="Absolute path to VM runtime static library.")
    parser.add_argument("--compile-commands", default=None, help="Path to compile_commands.json.")
    parser.add_argument("--keep-temps", action="store_true", help="Keep temporary bitcode files.")
    parser.add_argument("--weaver-arg", action="append", default=[], help="Extra arg forwarded to IR weaver.")
    parser.add_argument("compiler_and_args", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(list(argv[1:]))

    compiler_and_args = list(parsed.compiler_and_args)
    if compiler_and_args and compiler_and_args[0] == "--":
        compiler_and_args = compiler_and_args[1:]
    if not compiler_and_args:
        parser.error("expected compiler invocation: weaver_proxy.py <compiler> <args...>")

    compiler = compiler_and_args[0]
    args = compiler_and_args[1:]

    is_msvc = _is_msvc_like(compiler)
    is_rust = _is_rustc(compiler)
    vm_runtime_lib = _discover_optional_path(parsed.vm_runtime_lib, "EIPPF_VM_RUNTIME_LIB")

    if _is_link_phase_invocation(compiler, args, is_msvc=is_msvc, is_rust=is_rust):
        link_args = _inject_link_runtime_args(compiler, args, is_msvc=is_msvc, vm_runtime_lib=vm_runtime_lib)
        return _run([compiler, *link_args])

    sources = _detect_sources(args, is_msvc=is_msvc)
    if not sources:
        return _run([compiler, *args])

    if not _is_compile_invocation(args, is_msvc=is_msvc, is_rust=is_rust):
        return _run([compiler, *args])

    if len(sources) != 1:
        return _run([compiler, *args])

    source = sources[0]
    if source.ext in _ASM_SOURCES:
        return _run([compiler, *args])

    if _is_pch_generation(args, source):
        return _run([compiler, *args])

    emit_kind = _detect_emit_kind(args, is_msvc=is_msvc, is_rust=is_rust)
    if is_rust and emit_kind == EmitKind.LINK:
        rust_link_args = _inject_vm_runtime_for_rust_link(args, vm_runtime_lib)
        return _run([compiler, *rust_link_args])
    if emit_kind in {EmitKind.PREPROCESS, EmitKind.ASSEMBLY}:
        return _run([compiler, *args])

    source_path = source.path
    if not source_path.exists():
        return _run([compiler, *args])

    compile_db_path = _find_compile_commands(parsed.compile_commands)
    compile_db_args: List[str] = []
    if compile_db_path is not None:
        compile_db = _load_compile_database(compile_db_path)
        compile_db_args = _lookup_compile_db_args(compile_db, source_path)

    effective_args = _merge_compile_args(args, compile_db_args)
    target_triple = _extract_target_triple(effective_args)

    requested_output = _extract_output_path(args, is_msvc=is_msvc)
    final_output = requested_output if requested_output is not None else _default_output_for(source_path, emit_kind, is_msvc)

    ir_weaver_bin = _discover_tool(parsed.ir_weaver_bin, "EIPPF_IR_WEAVER_BIN", "ip_weaver_ir")
    if not ir_weaver_bin:
        print("weaver_proxy: IR weaver binary not found (set --ir-weaver-bin or EIPPF_IR_WEAVER_BIN)", file=sys.stderr)
        return 127

    clang_bin = os.environ.get("EIPPF_CLANG_BIN", "clang")
    rustc_bin = os.environ.get("EIPPF_RUSTC_BIN", "rustc")
    consumes_pch = _is_pch_consumption(effective_args)

    temp_dir = Path(tempfile.mkdtemp(prefix="eippf_polyglot_weaver_"))
    input_bc = temp_dir / f"{source_path.name}.input.bc"
    weaved_bc = temp_dir / f"{source_path.name}.weaved.bc"

    try:
        if source.ext in _RUST_SOURCES or is_rust:
            rust_forward = _collect_forward_args_for_rust(effective_args, source_path)
            rust_to_bc = _build_rust_to_bc_cmd(rustc_bin, source_path, input_bc, rust_forward)
            rc = _run(rust_to_bc)
            if rc != 0:
                return rc
            codegen_args = _detect_target_flags(effective_args)
        else:
            frontend = _frontend_for_cc(compiler, source.ext)
            cc_forward = _collect_forward_args_for_cc(effective_args, source_path, is_msvc=is_msvc)
            cc_to_bc = _build_cc_to_bc_cmd(frontend, source_path, input_bc, cc_forward, is_msvc=is_msvc)
            rc = _run(cc_to_bc)
            if rc != 0:
                if consumes_pch:
                    return _run([compiler, *args])
                return rc
            codegen_args = _collect_codegen_args(effective_args, source_path, is_msvc=is_msvc)

        weaver_args = list(parsed.weaver_arg)
        if source.ext in _RUST_SOURCES or is_rust:
            if _env_enabled("EIPPF_RUST_FULL_COVERAGE", True):
                if "--protect-all-functions" not in weaver_args:
                    weaver_args.append("--protect-all-functions")
                crate_name_arg = f"--rust-crate-name={_extract_rust_crate_name(effective_args, source_path)}"
                if crate_name_arg not in weaver_args:
                    weaver_args.append(crate_name_arg)
        if target_triple:
            weaver_args.append(f"--target-triple={target_triple}")
        weave_cmd = _build_ir_weaver_cmd(ir_weaver_bin, input_bc, weaved_bc, weaver_args)
        rc = _run(weave_cmd)
        if rc != 0:
            return rc
        if not weaved_bc.exists():
            print(f"weaver_proxy: IR weaver succeeded but did not produce output: {weaved_bc}", file=sys.stderr)
            return 70

        _ensure_parent(final_output)

        if emit_kind == EmitKind.LLVM_BC:
            shutil.copyfile(weaved_bc, final_output)
            return 0

        if emit_kind == EmitKind.LLVM_LL:
            lower_ll = _build_lower_to_ll_cmd(clang_bin, weaved_bc, final_output, codegen_args)
            return _run(lower_ll)

        lower_obj = _build_lower_to_object_cmd(clang_bin, weaved_bc, final_output, codegen_args)
        return _run(lower_obj)
    finally:
        if parsed.keep_temps:
            print(f"weaver_proxy: kept temporary directory {temp_dir}", file=sys.stderr)
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
